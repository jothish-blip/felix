package compliance

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"sort"
	"strings"
	"time"
)

var (
	// ErrInvalidTimestamps is returned when an episode has a completion timestamp earlier than its start.
	ErrInvalidTimestamps = errors.New("invalid remediation timestamps: completion precedes start")
)

// MTTRService coordinates reliable, verifiable MTTR calculations from authoritative lifecycle data.
type MTTRService struct {
	store ComplianceStore
	clock Clock
}

// NewMTTRService initializes a new MTTRService.
func NewMTTRService(store ComplianceStore, clock Clock) *MTTRService {
	if clock == nil {
		clock = &RealClock{}
	}
	return &MTTRService{
		store: store,
		clock: clock,
	}
}

// CalculateMTTR calculates Mean Time to Remediation and related metrics for the given filter criteria.
func (s *MTTRService) CalculateMTTR(ctx context.Context, filter MTTRFilter) (*MTTRResult, error) {
	if s.store == nil {
		return nil, errors.New("compliance store is not initialized")
	}

	// 1. Query records and their history atomically from storage
	dbFilter := RemediationFilter{
		AssessmentID: filter.AssessmentID,
		ControlID:    filter.ControlID,
		Severity:     filter.Severity,
		PolicyID:     filter.PolicyID,
	}

	records, historyMap, err := s.store.ListRemediationRecordsWithHistory(dbFilter)
	if err != nil {
		return nil, fmt.Errorf("failed retrieving remediation records for MTTR: %w", err)
	}

	var (
		episodes           []RemediationEpisode
		findingSet         = make(map[string]bool)
		durations          []time.Duration
		exclusions         MTTRExclusions
		slaMetrics         = &SLAPerformanceMetrics{}
		evalIntegrityCache = make(map[string]VerificationStatus)
		evalResultCache    = make(map[string]*EvaluationResult)
		remIntegrityCache  = make(map[string]*RemediationIntegrityVerificationResult)
		now                = s.clock.Now().UTC()
	)

	// 2. Process each record and extract valid episodes
	for _, rec := range records {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		// Apply in-memory filters for fields not handled by DB index
		if filter.FindingCategory != "" && !strings.EqualFold(rec.FindingCategory, filter.FindingCategory) {
			continue
		}
		if filter.FindingSource != "" && !strings.EqualFold(rec.FindingSource, filter.FindingSource) {
			continue
		}
		if filter.PolicyVersion != "" && rec.PolicyVersion != filter.PolicyVersion {
			continue
		}

		// 2a. Remediation Record & History Integrity Check:
		// Verify this specific remediation record and its history events directly, cached strictly by rec.ID.
		remVer, ok := remIntegrityCache[rec.ID]
		if !ok {
			v, err := s.store.VerifyRemediationIntegrity(rec.ID, filter.KeyProvider)
			if err != nil {
				remVer = &RemediationIntegrityVerificationResult{
					RemediationID: rec.ID,
					Status:        StatusOperationalFailure,
					Violations:    []string{err.Error()},
				}
			} else {
				remVer = v
			}
			remIntegrityCache[rec.ID] = remVer
		}

		if remVer.Status == StatusIntegrityMismatch {
			if filter.StrictIntegrity {
				return nil, fmt.Errorf("%w: remediation %s failed integrity verification: %v", ErrIntegrityMismatch, rec.ID, remVer.Violations)
			}
			exclusions.IntegrityFailures++
			exclusions.Warnings = append(exclusions.Warnings, fmt.Sprintf("excluded remediation %s: tampering or corruption detected in remediation source data (%v)", rec.ID, remVer.Violations))
			continue
		} else if remVer.Status == StatusUnverifiedLegacy {
			exclusions.UnverifiedLegacy++
		}

		// 2b. Parent Compliance Evaluation Integrity & Association Check
		if rec.AssessmentID != "" && rec.CatalogID != "" {
			cacheKey := rec.AssessmentID + ":" + rec.CatalogID
			evalStatus, ok := evalIntegrityCache[cacheKey]
			if !ok {
				verRes, verErr := s.store.VerifyEvaluationIntegrity(rec.AssessmentID, rec.CatalogID, filter.KeyProvider)
				if verErr != nil {
					if errors.Is(verErr, ErrIntegrityMismatch) || (verRes != nil && verRes.Status == StatusIntegrityMismatch) {
						evalStatus = StatusIntegrityMismatch
					} else {
						evalStatus = StatusOperationalFailure
					}
				} else if verRes != nil {
					evalStatus = verRes.Status
				} else {
					evalStatus = StatusUnverifiedLegacy
				}
				evalIntegrityCache[cacheKey] = evalStatus
			}

			if evalStatus == StatusIntegrityMismatch {
				if filter.StrictIntegrity {
					return nil, fmt.Errorf("%w: parent evaluation %s has integrity mismatch", ErrIntegrityMismatch, cacheKey)
				}
				exclusions.IntegrityFailures++
				exclusions.Warnings = append(exclusions.Warnings, fmt.Sprintf("excluded remediation %s: underlying evaluation %s failed integrity verification", rec.ID, cacheKey))
				continue
			}

			// Validate association: verify that the parent evaluation actually assessed this finding for this control
			evalRes, ok := evalResultCache[cacheKey]
			if !ok {
				er, _ := s.store.GetEvaluationResult(rec.AssessmentID, rec.CatalogID)
				evalResultCache[cacheKey] = er
				evalRes = er
			}

			if evalRes != nil {
				foundAssociation := false
				for _, ce := range evalRes.Evaluations {
					if ce.ControlID == rec.ControlID {
						for _, fid := range ce.FindingIDs {
							if fid == rec.FindingID {
								foundAssociation = true
								break
							}
						}
					}
					if foundAssociation {
						break
					}
				}
				if !foundAssociation {
					if filter.StrictIntegrity {
						return nil, fmt.Errorf("%w: remediation %s association to evaluation %s control %s finding %s is invalid", ErrIntegrityMismatch, rec.ID, rec.AssessmentID, rec.ControlID, rec.FindingID)
					}
					exclusions.IntegrityFailures++
					exclusions.Warnings = append(exclusions.Warnings, fmt.Sprintf("excluded remediation %s: forged or mismatched association to evaluation %s (finding %s not evaluated in control %s)", rec.ID, rec.AssessmentID, rec.FindingID, rec.ControlID))
					continue
				}
			}
		}

		// Track currently open overdue items for SLA metrics
		if rec.Status == RemediationStatusOpen || rec.Status == RemediationStatusInProgress || rec.Status == RemediationStatusReopened {
			if !rec.Deadline.IsZero() && now.After(rec.Deadline.UTC()) {
				slaMetrics.CurrentOpenOverdue++
			}
			exclusions.OpenOrInProgress++
		} else if rec.Status == RemediationStatusAcceptedRisk {
			exclusions.AcceptedRisk++
		}

		// Extract completed episodes from history
		recHistory := historyMap[rec.ID]
		extracted, invalidCount, _ := s.extractRecordEpisodes(&rec, recHistory)
		if invalidCount > 0 {
			exclusions.InvalidTimestamps += invalidCount
			exclusions.Warnings = append(exclusions.Warnings, fmt.Sprintf("remediation %s contained %d episode(s) with invalid timestamps (completion before start)", rec.ID, invalidCount))
		}

		if rec.Status == RemediationStatusRemediated && len(extracted) == 0 {
			if invalidCount == 0 {
				exclusions.MissingHistory++
				exclusions.Warnings = append(exclusions.Warnings, fmt.Sprintf("remediation %s has remediated status but lacks sufficient lifecycle history to establish a valid episode", rec.ID))
			}
			continue
		}

		// Filter extracted episodes by date range
		for _, ep := range extracted {
			ts := ep.CompletionTime
			if filter.DateBasis == DateBasisStart {
				ts = ep.StartTime
			}

			if filter.From != nil && ts.Before(filter.From.UTC()) {
				continue
			}
			if filter.To != nil && ts.After(filter.To.UTC()) {
				continue
			}

			episodes = append(episodes, ep)
			findingSet[ep.FindingID] = true
			durations = append(durations, ep.Duration)

			// SLA performance tracking for completed episode
			if ep.Deadline != nil && !ep.Deadline.IsZero() {
				slaMetrics.VerifiableEpisodes++
				if ep.CompletionTime.Before(*ep.Deadline) || ep.CompletionTime.Equal(*ep.Deadline) {
					slaMetrics.CompletedOnTime++
				} else {
					slaMetrics.CompletedLate++
				}
			} else {
				slaMetrics.MissingDeadlineEpisodes++
			}
		}
	}

	exclusions.TotalExcludedRecords = exclusions.MissingHistory + exclusions.InvalidTimestamps +
		exclusions.IntegrityFailures + exclusions.OpenOrInProgress + exclusions.AcceptedRisk

	// 3. Handle empty population case
	if len(episodes) == 0 {
		return &MTTRResult{
			HasData:             false,
			CoverageStatus:      "NO_DATA",
			FilterApplied:       filter,
			Exclusions:          exclusions,
			SLAPerformance:      slaMetrics,
			CompletedEpisodes:   0,
			UniqueFindings:      0,
			TotalDuration:       0,
			TotalDurationString: "0s",
		}, nil
	}

	// 4. Compute aggregate metrics deterministically
	sort.Slice(durations, func(i, j int) bool {
		return durations[i] < durations[j]
	})

	minDur := durations[0]
	maxDur := durations[len(durations)-1]

	var medianDur time.Duration
	n := len(durations)
	if n%2 == 1 {
		medianDur = durations[n/2]
	} else {
		// Prevent overflow when averaging two durations
		d1 := durations[n/2-1]
		d2 := durations[n/2]
		medianDur = d1/2 + d2/2 + ((d1%2 + d2%2) / 2)
	}

	var totalDuration time.Duration
	for _, d := range durations {
		if math.MaxInt64-int64(totalDuration) < int64(d) {
			return nil, errors.New("total remediation duration arithmetic overflow")
		}
		totalDuration += d
	}

	mttr := totalDuration / time.Duration(len(episodes))

	if slaMetrics.VerifiableEpisodes > 0 {
		slaMetrics.OnTimeRate = (float64(slaMetrics.CompletedOnTime) / float64(slaMetrics.VerifiableEpisodes)) * 100.0
	}

	coverageStatus := "COMPLETE"
	if exclusions.IntegrityFailures > 0 || exclusions.MissingHistory > 0 || exclusions.InvalidTimestamps > 0 {
		coverageStatus = "PARTIAL"
	}

	return &MTTRResult{
		HasData:              true,
		MTTR:                 mttr,
		MTTRString:           FormatDurationHuman(mttr),
		CompletedEpisodes:    len(episodes),
		UniqueFindings:       len(findingSet),
		TotalDuration:        totalDuration,
		TotalDurationString:  FormatDurationHuman(totalDuration),
		MinDuration:          &minDur,
		MinDurationString:    FormatDurationHuman(minDur),
		MaxDuration:          &maxDur,
		MaxDurationString:    FormatDurationHuman(maxDur),
		MedianDuration:       &medianDur,
		MedianDurationString: FormatDurationHuman(medianDur),
		CoverageStatus:       coverageStatus,
		FilterApplied:        filter,
		Exclusions:           exclusions,
		SLAPerformance:       slaMetrics,
		Episodes:             episodes,
	}, nil
}

func historyEventOrder(evt RemediationHistoryEventType) int {
	switch evt {
	case HistoryEventAssigned:
		return 0
	case HistoryEventRiskAccepted:
		return 1
	case HistoryEventRiskRevoked:
		return 2
	case HistoryEventReopened:
		return 3
	case HistoryEventDeadlineRecalculated:
		return 4
	case HistoryEventStatusChanged:
		return 5
	default:
		return 6
	}
}

// extractRecordEpisodes processes the chronological event history of a remediation record
// to reconstruct all discrete completed episodes without double counting.
func (s *MTTRService) extractRecordEpisodes(rec *RemediationRecord, history []RemediationHistoryEvent) ([]RemediationEpisode, int, bool) {
	if len(history) == 0 {
		return nil, 0, false
	}

	// Sort events deterministically by timestamp ascending, causal event type order, then ID ascending
	sortedHistory := make([]RemediationHistoryEvent, len(history))
	copy(sortedHistory, history)
	sort.SliceStable(sortedHistory, func(i, j int) bool {
		if sortedHistory[i].Timestamp.Equal(sortedHistory[j].Timestamp) {
			ordI := historyEventOrder(sortedHistory[i].EventType)
			ordJ := historyEventOrder(sortedHistory[j].EventType)
			if ordI != ordJ {
				return ordI < ordJ
			}
			return sortedHistory[i].ID < sortedHistory[j].ID
		}
		return sortedHistory[i].Timestamp.Before(sortedHistory[j].Timestamp)
	})

	var (
		episodes             []RemediationEpisode
		invalidCount         int
		hasCompletionHistory bool
		hadPriorCompletion   bool
		active               bool
		inRisk               bool
		cycle                = 0
		startTime            time.Time
		currentDeadline      *time.Time
		slaDuration          time.Duration
	)

	if !rec.Deadline.IsZero() {
		dl := rec.Deadline.UTC()
		currentDeadline = &dl
		if !rec.SLAStartTime.IsZero() && rec.Deadline.After(rec.SLAStartTime) {
			slaDuration = rec.Deadline.Sub(rec.SLAStartTime)
		}
	}

	// Determine initial cycle start time
	if !rec.SLAStartTime.IsZero() && !rec.SLAStartTime.After(sortedHistory[0].Timestamp) {
		startTime = rec.SLAStartTime.UTC()
	} else {
		startTime = sortedHistory[0].Timestamp.UTC()
	}

	for _, evt := range sortedHistory {
		t := evt.Timestamp.UTC()
		if t.IsZero() {
			invalidCount++
			continue
		}

		switch evt.EventType {
		case HistoryEventAssigned:
			if !active && !inRisk {
				active = true
				if !rec.SLAStartTime.IsZero() && !rec.SLAStartTime.After(t) {
					startTime = rec.SLAStartTime.UTC()
				} else {
					startTime = t
				}
			}
			if evt.DetailsJSON != "" {
				var det struct {
					Deadline string `json:"deadline"`
					Duration string `json:"duration"`
				}
				if err := json.Unmarshal([]byte(evt.DetailsJSON), &det); err == nil {
					if det.Deadline != "" {
						if parsed, err := time.Parse(time.RFC3339, det.Deadline); err == nil {
							dl := parsed.UTC()
							currentDeadline = &dl
						}
					}
					if det.Duration != "" {
						if dur, err := ParseSLADuration(det.Duration); err == nil {
							slaDuration = dur
						}
					}
				}
			}

		case HistoryEventDeadlineRecalculated:
			if evt.DetailsJSON != "" {
				var det struct {
					NewDeadline string `json:"new_deadline"`
					Duration    string `json:"duration"`
				}
				if err := json.Unmarshal([]byte(evt.DetailsJSON), &det); err == nil {
					if det.NewDeadline != "" {
						if parsed, err := time.Parse(time.RFC3339, det.NewDeadline); err == nil {
							dl := parsed.UTC()
							currentDeadline = &dl
						}
					}
					if det.Duration != "" {
						if dur, err := ParseSLADuration(det.Duration); err == nil {
							slaDuration = dur
						}
					}
				}
			}

		case HistoryEventReopened:
			// Reopening marks the verified start of a new remediation cycle.
			// It is only valid if the finding was previously remediated.
			if active {
				invalidCount++
				continue
			}
			cycle++
			active = true
			inRisk = false
			hadPriorCompletion = false
			startTime = t
			if slaDuration > 0 {
				reopenDl := t.Add(slaDuration)
				currentDeadline = &reopenDl
			}

		case HistoryEventRiskAccepted:
			inRisk = true
			active = false // Risk acceptance is NOT completed remediation

		case HistoryEventRiskRevoked:
			if !inRisk {
				// Contradictory event: cannot revoke risk if not currently in risk
				invalidCount++
				continue
			}
			inRisk = false
			active = true
			hadPriorCompletion = false
			startTime = t
			cycle++

		case HistoryEventStatusChanged:
			if evt.ToStatus == RemediationStatusRemediated {
				hasCompletionHistory = true
				if (!rec.SLAStartTime.IsZero() && t.Before(rec.SLAStartTime.UTC())) ||
					(!rec.AssignedAt.IsZero() && t.Before(rec.AssignedAt.UTC())) ||
					(active && t.Before(startTime)) {
					invalidCount++
					active = false
					continue
				}
				if inRisk {
					// Contradictory event: cannot transition directly from accepted_risk to remediated
					invalidCount++
					continue
				}
				if active {
					if startTime.IsZero() {
						invalidCount++
						active = false
						continue
					}
					duration := t.Sub(startTime)
					ep := RemediationEpisode{
						RemediationID:   rec.ID,
						FindingID:       rec.FindingID,
						FindingTitle:    rec.FindingTitle,
						FindingSource:   rec.FindingSource,
						FindingCategory: rec.FindingCategory,
						AssessmentID:    rec.AssessmentID,
						CatalogID:       rec.CatalogID,
						ControlID:       rec.ControlID,
						Severity:        rec.Severity,
						PolicyID:        rec.PolicyID,
						PolicyVersion:   rec.PolicyVersion,
						Cycle:           cycle,
						StartTime:       startTime,
						CompletionTime:  t,
						Duration:        duration,
						DurationString:  FormatDurationHuman(duration),
					}

					if currentDeadline != nil {
						dl := *currentDeadline
						ep.Deadline = &dl
						met := !t.After(dl)
						ep.MetSLA = &met
					}

					episodes = append(episodes, ep)
					active = false
					hadPriorCompletion = true
				} else {
					if !hadPriorCompletion {
						// Completion event without a prior start event or completed episode
						invalidCount++
					}
					// If hadPriorCompletion is true, duplicate completion event is ignored to avoid inflating counts
				}
			} else if evt.ToStatus == RemediationStatusReopened {
				if active {
					invalidCount++
					continue
				}
				cycle++
				active = true
				inRisk = false
				hadPriorCompletion = false
				startTime = t
				if slaDuration > 0 {
					reopenDl := t.Add(slaDuration)
					currentDeadline = &reopenDl
				}
			} else if evt.ToStatus == RemediationStatusAcceptedRisk {
				inRisk = true
				active = false
			} else if (evt.ToStatus == RemediationStatusInProgress || evt.ToStatus == RemediationStatusOpen) && !active && !inRisk {
				active = true
				hadPriorCompletion = false
				startTime = t
			}
		}
	}

	return episodes, invalidCount, hasCompletionHistory
}
