package assessment

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"felix/pkg/correlation"
	"felix/pkg/report"
)

// ComparabilityStatus constants
const (
	ComparabilityStatusComparable           = "COMPARABLE"
	ComparabilityStatusPartial              = "PARTIAL"
	ComparabilityStatusIncompatibleScope    = "INCOMPATIBLE_SCOPE"
	ComparabilityStatusIncompleteAssessment = "INCOMPLETE_ASSESSMENT"
	ComparabilityStatusIneligibleBaseline   = "INELIGIBLE_BASELINE"
	ComparabilityStatusUnauthorized         = "UNAUTHORIZED"
)

// AssessmentHistoryItem represents a tenant-scoped historical summary of an assessment.
type AssessmentHistoryItem struct {
	ID                  string           `json:"id"`
	Ref                 string           `json:"ref"`
	ClientID            string           `json:"client_id"`
	Name                string           `json:"name"`
	Description         string           `json:"description,omitempty"`
	AssessmentType      string           `json:"assessment_type"`
	Status              AssessmentStatus `json:"status"`
	CreatedAt           time.Time        `json:"created_at"`
	StartedAt           *time.Time       `json:"started_at,omitempty"`
	CompletedAt         *time.Time       `json:"completed_at,omitempty"`
	TargetCount         int              `json:"target_count"`
	Targets             []string         `json:"targets,omitempty"`
	FindingCount        int              `json:"finding_count"`
	SeverityCounts      map[string]int   `json:"severity_counts"`
	IsEligibleBaseline  bool             `json:"is_eligible_baseline"`
	IneligibilityReason string           `json:"ineligibility_reason,omitempty"`
	ExecutionCount      int              `json:"execution_count"`
	LatestExecutionID   string           `json:"latest_execution_id,omitempty"`
	ReportCount         int              `json:"report_count"`
	PredecessorRef      string           `json:"predecessor_ref,omitempty"`
}

// AssessmentComparisonResult represents the complete comparison between a baseline and current assessment.
type AssessmentComparisonResult struct {
	BaselineAssessmentID  string                   `json:"baseline_assessment_id"`
	BaselineAssessmentRef string                   `json:"baseline_assessment_ref,omitempty"`
	BaselineName          string                   `json:"baseline_name,omitempty"`
	BaselineStatus        string                   `json:"baseline_status,omitempty"`
	BaselineCompletedAt   *time.Time               `json:"baseline_completed_at,omitempty"`
	BaselineExecutionID   string                   `json:"baseline_execution_id,omitempty"`
	BaselineSnapshotID    string                   `json:"baseline_snapshot_id,omitempty"`
	BaselineFindingCount  int                      `json:"baseline_finding_count"`
	BaselineTargets       []string                 `json:"baseline_targets,omitempty"`

	CurrentAssessmentID   string                   `json:"current_assessment_id"`
	CurrentAssessmentRef  string                   `json:"current_assessment_ref,omitempty"`
	CurrentName           string                   `json:"current_name,omitempty"`
	CurrentStatus         string                   `json:"current_status,omitempty"`
	CurrentCompletedAt    *time.Time               `json:"current_completed_at,omitempty"`
	CurrentExecutionID    string                   `json:"current_execution_id,omitempty"`
	CurrentSnapshotID     string                   `json:"current_snapshot_id,omitempty"`
	CurrentFindingCount   int                      `json:"current_finding_count"`
	CurrentTargets        []string                 `json:"current_targets,omitempty"`

	ComparisonTimestamp   time.Time                `json:"comparison_timestamp"`
	ComparabilityStatus   string                   `json:"comparability_status"` // COMPARABLE, PARTIAL, INCOMPATIBLE_SCOPE, INCOMPLETE_ASSESSMENT, INELIGIBLE_BASELINE
	ComparabilityReason   string                   `json:"comparability_reason,omitempty"`
	IsReliable            bool                     `json:"is_reliable"`
	ScopeCoverage         string                   `json:"scope_coverage,omitempty"` // FULL_OVERLAP, PARTIAL_OVERLAP, DISJOINT

	// P10.8 Finding Lifecycle Counts
	NewCount               int                      `json:"new_count"`
	ResolvedCount          int                      `json:"resolved_count"`
	PersistentCount        int                      `json:"persistent_count"`
	SeverityIncreasedCount int                      `json:"severity_increased_count"`
	SeverityDecreasedCount int                      `json:"severity_decreased_count"`
	ChangedCount           int                      `json:"changed_count"`
	UnchangedCount         int                      `json:"unchanged_count"`
	UnknownCount           int                      `json:"unknown_count"`
	NetRiskScoreDelta      int                      `json:"net_risk_score_delta"`

	// Severity distributions
	BaselineSeverityDist  map[string]int           `json:"baseline_severity_distribution"`
	CurrentSeverityDist   map[string]int           `json:"current_severity_distribution"`

	// Delta Items
	Items                 []FindingComparisonDelta `json:"items"`
	SummaryHeadline       string                   `json:"summary_headline"`
	SummaryNarrative      []string                 `json:"summary_narrative"`
}

// FindingComparisonDelta captures individual finding changes between assessments.
type FindingComparisonDelta struct {
	Fingerprint        string   `json:"fingerprint"`
	FindingID          string   `json:"finding_id,omitempty"`
	BaselineFindingID  string   `json:"baseline_finding_id,omitempty"`
	Title              string   `json:"title"`
	Severity           string   `json:"severity"`
	BaselineSeverity   string   `json:"baseline_severity,omitempty"`
	Category           string   `json:"category"`
	TargetURL          string   `json:"target_url"`
	Endpoint           string   `json:"endpoint,omitempty"`
	LifecycleStatus    string   `json:"lifecycle_status"`  // new, resolved, persistent, unknown
	SeverityDelta      string   `json:"severity_delta"`   // severity_increased, severity_decreased, unchanged, ""
	CanonicalDelta     string   `json:"canonical_delta"`  // new, resolved, persistent, severity_increased, severity_decreased, changed, unchanged, unknown
	AttributeChanges   []string `json:"attribute_changes,omitempty"`
	StatusChange       string   `json:"status_change,omitempty"`
	SeverityChange     string   `json:"severity_change,omitempty"`
	ConfidenceChange   string   `json:"confidence_change,omitempty"`
	ScoreDelta         int      `json:"score_delta"`
	Explanation        string   `json:"explanation"`
	IdentityBasis      string   `json:"identity_basis,omitempty"` // CANONICAL_FINGERPRINT, EXPLICIT_TRACKING_ID
}

// CheckBaselineEligibility determines if an assessment is eligible to act as a comparison baseline.
func CheckBaselineEligibility(asm *Assessment, targets []AssessmentTarget) (bool, string) {
	if asm == nil {
		return false, "no assessment record provided"
	}
	switch asm.Status {
	case StatusCompleted:
		// Full completion
	case StatusCompletedWithErrors:
		// Acceptable with limitations
	case StatusDraft:
		return false, "assessment is still in draft state"
	case StatusReady:
		return false, "assessment has not been executed yet"
	case StatusRunning, StatusQueued:
		return false, "assessment execution is currently in progress"
	case StatusFailed:
		return false, "assessment execution failed"
	case StatusCancelled:
		return false, "assessment was cancelled"
	case StatusInterrupted:
		return false, "assessment was interrupted"
	default:
		return false, fmt.Sprintf("ineligible assessment status %s", asm.Status)
	}

	if len(targets) == 0 {
		return false, "assessment has no target scope defined"
	}

	hasApproved := false
	for _, t := range targets {
		if t.ScopeStatus == "APPROVED" || t.ScopeStatus == "" {
			hasApproved = true
			break
		}
	}
	if !hasApproved {
		return false, "assessment has no approved in-scope targets"
	}

	return true, ""
}

// ComputeScopeCoverage evaluates target overlap between baseline and current target scopes.
func ComputeScopeCoverage(baseTgts, curTgts []string) (string, []string) {
	if len(baseTgts) == 0 || len(curTgts) == 0 {
		return "UNKNOWN", nil
	}

	curSet := make(map[string]struct{}, len(curTgts))
	for _, t := range curTgts {
		clean := strings.ToLower(strings.TrimRight(strings.TrimSpace(t), "/"))
		if clean != "" {
			curSet[clean] = struct{}{}
		}
	}

	var overlapping []string
	var missing []string
	for _, t := range baseTgts {
		clean := strings.ToLower(strings.TrimRight(strings.TrimSpace(t), "/"))
		if clean == "" {
			continue
		}
		if _, ok := curSet[clean]; ok {
			overlapping = append(overlapping, t)
		} else {
			missing = append(missing, t)
		}
	}

	if len(overlapping) == 0 {
		return "DISJOINT", missing
	}
	if len(missing) == 0 {
		return "FULL_OVERLAP", nil
	}
	return "PARTIAL_OVERLAP", missing
}

// BuildAssessmentComparisonResult compiles an AssessmentComparisonResult from correlation diff and assessment metadata.
func BuildAssessmentComparisonResult(
	baseAsm *Assessment,
	curAsm *Assessment,
	baseExecID, curExecID string,
	baseTgts, curTgts []string,
	cmp *correlation.AssessmentComparison,
	scopeCoverage string,
	missingScope []string,
) *AssessmentComparisonResult {
	if cmp == nil {
		cmp = &correlation.AssessmentComparison{}
	}

	now := time.Now().UTC()
	res := &AssessmentComparisonResult{
		ComparisonTimestamp:   now,
		ScopeCoverage:         scopeCoverage,
		BaselineFindingCount:  cmp.BaselineCount,
		CurrentFindingCount:   cmp.CurrentCount,
		BaselineExecutionID:   baseExecID,
		CurrentExecutionID:    curExecID,
		BaselineTargets:       baseTgts,
		CurrentTargets:        curTgts,
		NewCount:              cmp.NewCount,
		ResolvedCount:         cmp.ResolvedCount,
		PersistentCount:       cmp.PersistentCount,
		SeverityIncreasedCount: cmp.SeverityIncreasedCount,
		SeverityDecreasedCount: cmp.SeverityDecreasedCount,
		ChangedCount:          cmp.ChangedCount,
		UnchangedCount:        cmp.UnchangedCount,
		UnknownCount:          cmp.UnknownCount,
		NetRiskScoreDelta:     cmp.NetRiskScoreDelta,
		BaselineSeverityDist:  make(map[string]int),
		CurrentSeverityDist:   make(map[string]int),
	}

	if baseAsm != nil {
		res.BaselineAssessmentID = baseAsm.ID
		res.BaselineAssessmentRef = baseAsm.Ref
		res.BaselineName = baseAsm.Name
		res.BaselineStatus = string(baseAsm.Status)
		res.BaselineCompletedAt = baseAsm.CompletedAt
	}
	if curAsm != nil {
		res.CurrentAssessmentID = curAsm.ID
		res.CurrentAssessmentRef = curAsm.Ref
		res.CurrentName = curAsm.Name
		res.CurrentStatus = string(curAsm.Status)
		res.CurrentCompletedAt = curAsm.CompletedAt
	}

	// Determine Comparability Status
	if baseAsm != nil && (baseAsm.Status == StatusFailed || baseAsm.Status == StatusCancelled || baseAsm.Status == StatusDraft) {
		res.ComparabilityStatus = ComparabilityStatusIneligibleBaseline
		res.ComparabilityReason = fmt.Sprintf("Baseline assessment %s is ineligible (status: %s)", baseAsm.Ref, baseAsm.Status)
		res.IsReliable = false
	} else if curAsm != nil && (curAsm.Status == StatusFailed || curAsm.Status == StatusCancelled || curAsm.Status == StatusDraft || curAsm.Status == StatusRunning) {
		res.ComparabilityStatus = ComparabilityStatusIncompleteAssessment
		res.ComparabilityReason = fmt.Sprintf("Current assessment %s is incomplete or not in terminal state (status: %s); missing baseline findings cannot be verified resolved", curAsm.Ref, curAsm.Status)
		res.IsReliable = false
	} else if scopeCoverage == "DISJOINT" {
		res.ComparabilityStatus = ComparabilityStatusIncompatibleScope
		res.ComparabilityReason = "No target scope overlap between baseline and current assessments; comparisons across disjoint scopes cannot establish resolution"
		res.IsReliable = false
	} else if scopeCoverage == "PARTIAL_OVERLAP" || cmp.ComparisonStatus == "PARTIAL" || cmp.UnknownCount > 0 {
		res.ComparabilityStatus = ComparabilityStatusPartial
		if len(missingScope) > 0 {
			res.ComparabilityReason = fmt.Sprintf("Assessment scope partially overlaps; %d baseline targets were not re-evaluated (%s); unaffected baseline findings remain unverified", len(missingScope), strings.Join(missingScope, ", "))
		} else if cmp.ComparisonReason != "" {
			res.ComparabilityReason = cmp.ComparisonReason
		} else {
			res.ComparabilityReason = "Comparison is partial due to unassessed targets, skipped categories, or incomplete execution coverage"
		}
		res.IsReliable = false
	} else {
		res.ComparabilityStatus = ComparabilityStatusComparable
		res.ComparabilityReason = "Complete and compatible assessment scopes; findings fully verified"
		res.IsReliable = true
	}

	// Map and sort finding items
	res.Items = make([]FindingComparisonDelta, 0, len(cmp.Items))
	for _, it := range cmp.Items {
		fID := ""
		baseFID := ""
		targetURL := it.TargetEndpoint
		baseSev := ""

		if it.CurrentFinding != nil {
			fID = it.CurrentFinding.ID
			if targetURL == "" {
				targetURL = it.CurrentFinding.Target
			}
			res.CurrentSeverityDist[report.NormalizeSeverity(it.CurrentFinding.Severity)]++
		}
		if it.BaselineFinding != nil {
			baseFID = it.BaselineFinding.ID
			baseSev = report.NormalizeSeverity(it.BaselineFinding.Severity)
			if targetURL == "" {
				targetURL = it.BaselineFinding.Target
			}
			res.BaselineSeverityDist[baseSev]++
		}

		canonicalDelta := it.CanonicalDelta
		if canonicalDelta == "" {
			switch it.Classification {
			case correlation.DeltaNew:
				canonicalDelta = "new"
			case correlation.DeltaResolved:
				canonicalDelta = "resolved"
			case correlation.DeltaRegressed:
				if it.RegressionReason == correlation.RegressionSeverityWorsened {
					canonicalDelta = "severity_increased"
				} else {
					canonicalDelta = "new"
				}
			case correlation.DeltaChanged:
				if it.ChangeReason == correlation.ChangeSeverityDecreased {
					canonicalDelta = "severity_decreased"
				} else {
					canonicalDelta = "changed"
				}
			case correlation.DeltaPersistent:
				canonicalDelta = "unchanged"
			case correlation.DeltaUnverified:
				canonicalDelta = "unknown"
			default:
				canonicalDelta = "persistent"
			}
		}

		lifecycleStatus := "persistent"
		switch canonicalDelta {
		case "new":
			lifecycleStatus = "new"
		case "resolved":
			lifecycleStatus = "resolved"
		case "unknown":
			lifecycleStatus = "unknown"
		default:
			lifecycleStatus = "persistent"
		}

		res.Items = append(res.Items, FindingComparisonDelta{
			Fingerprint:       it.Fingerprint,
			FindingID:         fID,
			BaselineFindingID: baseFID,
			Title:             it.Title,
			Severity:          report.NormalizeSeverity(it.Severity),
			BaselineSeverity:  baseSev,
			Category:          it.Category,
			TargetURL:         targetURL,
			Endpoint:          it.TargetEndpoint,
			LifecycleStatus:   lifecycleStatus,
			SeverityDelta:     it.SeverityDelta,
			CanonicalDelta:    canonicalDelta,
			AttributeChanges:  it.AttributeChanges,
			StatusChange:      it.StatusChange,
			SeverityChange:    it.SeverityChange,
			ConfidenceChange:  it.ConfidenceChange,
			ScoreDelta:        it.ScoreDelta,
			Explanation:       it.Explanation,
			IdentityBasis:     it.IdentityBasis,
		})
	}

	// Deterministic sorting of delta items:
	// Priority: severity_increased > new > severity_decreased > changed > persistent > unknown > resolved > unchanged,
	// then severity descending, then fingerprint ascending
	sort.Slice(res.Items, func(i, j int) bool {
		rankDelta := func(d string) int {
			switch d {
			case "severity_increased":
				return 8
			case "new":
				return 7
			case "severity_decreased":
				return 6
			case "changed":
				return 5
			case "persistent":
				return 4
			case "unknown":
				return 3
			case "resolved":
				return 2
			case "unchanged":
				return 1
			default:
				return 0
			}
		}
		rI := rankDelta(res.Items[i].CanonicalDelta)
		rJ := rankDelta(res.Items[j].CanonicalDelta)
		if rI != rJ {
			return rI > rJ
		}
		sevRankI := report.SeverityRank(res.Items[i].Severity)
		sevRankJ := report.SeverityRank(res.Items[j].Severity)
		if sevRankI != sevRankJ {
			return sevRankI > sevRankJ
		}
		return res.Items[i].Fingerprint < res.Items[j].Fingerprint
	})

	// Construct truthful posture headline and narrative
	headline, narrative := generateTruthfulPostureSummary(res)
	res.SummaryHeadline = headline
	res.SummaryNarrative = narrative

	return res
}

func generateTruthfulPostureSummary(res *AssessmentComparisonResult) (string, []string) {
	var narrative []string

	if !res.IsReliable {
		narrative = append(narrative, fmt.Sprintf("Note: %s", res.ComparabilityReason))
	}

	headline := ""
	if res.NewCount > 0 && res.ResolvedCount > 0 {
		headline = fmt.Sprintf("Assessment identified %d new findings while %d prior findings were resolved.", res.NewCount, res.ResolvedCount)
	} else if res.NewCount > 0 {
		headline = fmt.Sprintf("Assessment identified %d new vulnerabilities.", res.NewCount)
	} else if res.ResolvedCount > 0 {
		headline = fmt.Sprintf("Assessment verified %d previously observed vulnerabilities as resolved.", res.ResolvedCount)
	} else if res.SeverityIncreasedCount > 0 {
		headline = fmt.Sprintf("Assessment identified %d persistent findings with increased severity.", res.SeverityIncreasedCount)
	} else if res.PersistentCount > 0 {
		headline = fmt.Sprintf("Security posture remains stable with %d persistent findings across assessments.", res.PersistentCount)
	} else if res.CurrentFindingCount == 0 && res.BaselineFindingCount == 0 {
		headline = "No findings recorded in current or baseline assessments within verified evaluated scope."
	} else {
		headline = "Assessment delta analysis completed."
	}

	if res.SeverityIncreasedCount > 0 {
		narrative = append(narrative, fmt.Sprintf("%d finding(s) experienced severity escalation.", res.SeverityIncreasedCount))
	}
	if res.SeverityDecreasedCount > 0 {
		narrative = append(narrative, fmt.Sprintf("%d finding(s) had observed severity decrease.", res.SeverityDecreasedCount))
	}
	if res.ChangedCount > 0 {
		narrative = append(narrative, fmt.Sprintf("%d finding(s) had non-severity attribute changes (e.g. endpoint, evidence, or details).", res.ChangedCount))
	}
	if res.UnknownCount > 0 {
		narrative = append(narrative, fmt.Sprintf("%d baseline finding(s) could not be verified due to incomplete execution or scope boundaries.", res.UnknownCount))
	}
	narrative = append(narrative, "Disclaimer: Absence of findings or verified resolution indicates observed state within tested parameters; it does not constitute a guarantee of complete security or certification.")

	return headline, narrative
}
