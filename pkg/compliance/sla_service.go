package compliance

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"felix/pkg/report"
)

// Clock provides an injectable time source to allow deterministic time testing without real-world sleeps.
type Clock interface {
	Now() time.Time
}

// RealClock implements Clock using the system UTC time.
type RealClock struct{}

func (RealClock) Now() time.Time {
	return time.Now().UTC()
}

// MockClock implements Clock with a fixed or manually controllable time for testing.
type MockClock struct {
	currentTime time.Time
}

// NewMockClock creates a MockClock initialized to the provided time.
func NewMockClock(t time.Time) *MockClock {
	return &MockClock{currentTime: t.UTC()}
}

func (m *MockClock) Now() time.Time {
	return m.currentTime
}

// Set updates the mock clock to a new time.
func (m *MockClock) Set(t time.Time) {
	m.currentTime = t.UTC()
}

// Advance shifts the mock clock forward by duration.
func (m *MockClock) Advance(d time.Duration) {
	m.currentTime = m.currentTime.Add(d)
}

// DefaultWarningWindow defines the threshold before deadline expiration to mark an SLA as approaching deadline.
const DefaultWarningWindow = 24 * time.Hour

// RemediationService provides business logic for SLA assignment, deadline calculation, and lifecycle management.
type RemediationService struct {
	clock         Clock
	warningWindow time.Duration
}

// NewRemediationService creates a RemediationService with the specified clock and warning window.
func NewRemediationService(clock Clock, warningWindow time.Duration) *RemediationService {
	if clock == nil {
		clock = RealClock{}
	}
	if warningWindow <= 0 {
		warningWindow = DefaultWarningWindow
	}
	return &RemediationService{
		clock:         clock,
		warningWindow: warningWindow,
	}
}

// CalculateDeadline computes the deterministic UTC deadline from an SLA start time and duration.
func (s *RemediationService) CalculateDeadline(startTime time.Time, duration time.Duration) (time.Time, error) {
	if startTime.IsZero() {
		return time.Time{}, errors.New("startTime cannot be zero")
	}
	if duration <= 0 {
		return time.Time{}, errors.New("SLA duration must be strictly positive")
	}
	utcStart := startTime.UTC()
	deadline := utcStart.Add(duration)
	if deadline.Before(utcStart) {
		return time.Time{}, errors.New("deadline overflowed time bounds")
	}
	return deadline, nil
}

// ComputeSLAStatus evaluates a remediation record against the clock to determine its computed SLA status.
// Boundary Invariant: A deadline is overdue only when clock.Now() is strictly after the deadline.
// Equality (clock.Now().Equal(deadline)) is not overdue.
func (s *RemediationService) ComputeSLAStatus(rec *RemediationRecord) ComputedSLAStatus {
	if rec == nil {
		return SLAStatusNotDue
	}

	now := s.clock.Now().UTC()

	switch rec.Status {
	case RemediationStatusAcceptedRisk:
		return SLAStatusAcceptedRisk

	case RemediationStatusRemediated:
		if rec.CompletedAt != nil && rec.CompletedAt.UTC().After(rec.Deadline.UTC()) {
			return SLAStatusRemediatedLate
		}
		return SLAStatusRemediatedOnTime

	case RemediationStatusOpen, RemediationStatusInProgress, RemediationStatusReopened:
		if now.After(rec.Deadline.UTC()) {
			return SLAStatusOverdue
		}
		if rec.Deadline.UTC().Sub(now) <= s.warningWindow {
			return SLAStatusApproachingDeadline
		}
		return SLAStatusNotDue

	default:
		if now.After(rec.Deadline.UTC()) {
			return SLAStatusOverdue
		}
		return SLAStatusNotDue
	}
}

// PopulateComputedFields updates a RemediationRecord with its dynamic computed fields (ComputedSLAStatus, TimeRemaining, IsOverdue).
func (s *RemediationService) PopulateComputedFields(rec *RemediationRecord) {
	if rec == nil {
		return
	}
	now := s.clock.Now().UTC()
	status := s.ComputeSLAStatus(rec)
	rec.ComputedSLAStatus = status
	rec.IsOverdue = (status == SLAStatusOverdue)

	if rec.Status == RemediationStatusRemediated || rec.Status == RemediationStatusAcceptedRisk {
		rec.TimeRemaining = 0
	} else if now.After(rec.Deadline.UTC()) {
		rec.TimeRemaining = 0
	} else {
		rec.TimeRemaining = rec.Deadline.UTC().Sub(now)
	}
}

// AssignSLAParams contains parameters for creating a new SLA assignment.
type AssignSLAParams struct {
	FindingID          string
	FindingSource      string
	FindingTitle       string
	FindingCategory    string
	AssessmentID       string
	CatalogID          string
	ControlID          string
	EvaluationID       string
	Severity           string
	SeveritySource     string
	Policy             *RemediationSLAPolicy
	SLAStartTime       time.Time
	Actor              string
	EvidenceReferences []string
}

// AssignSLA builds a new RemediationRecord and its initial ASSIGNED history event.
func (s *RemediationService) AssignSLA(params AssignSLAParams) (*RemediationRecord, *RemediationHistoryEvent, error) {
	cleanFindingID := strings.TrimSpace(params.FindingID)
	if cleanFindingID == "" {
		return nil, nil, errors.New("finding ID cannot be empty")
	}

	if params.Policy == nil {
		return nil, nil, errors.New("remediation SLA policy cannot be nil")
	}
	if err := ValidateRemediationPolicy(params.Policy); err != nil {
		return nil, nil, fmt.Errorf("invalid policy: %w", err)
	}

	normSev := report.NormalizeSeverity(params.Severity)
	duration, ruleMatched, err := params.Policy.ResolveDurationForSeverity(normSev)
	if err != nil {
		return nil, nil, err
	}

	now := s.clock.Now().UTC()
	startTime := params.SLAStartTime.UTC()
	if startTime.IsZero() {
		startTime = now
	}

	deadline, err := s.CalculateDeadline(startTime, duration)
	if err != nil {
		return nil, nil, err
	}

	sevSource := params.SeveritySource
	if sevSource == "" {
		sevSource = "finding"
	}

	actor := strings.TrimSpace(params.Actor)
	if actor == "" {
		actor = "system"
	}

	remID := fmt.Sprintf("rem:%s", cleanFindingID)
	if params.AssessmentID != "" {
		remID = fmt.Sprintf("rem:%s:%s", strings.TrimSpace(params.AssessmentID), cleanFindingID)
	}

	rec := &RemediationRecord{
		ID:                 remID,
		FindingID:          cleanFindingID,
		FindingSource:      strings.TrimSpace(params.FindingSource),
		FindingTitle:       strings.TrimSpace(params.FindingTitle),
		FindingCategory:    strings.TrimSpace(params.FindingCategory),
		AssessmentID:       strings.TrimSpace(params.AssessmentID),
		CatalogID:          strings.TrimSpace(params.CatalogID),
		ControlID:          strings.TrimSpace(params.ControlID),
		EvaluationID:       strings.TrimSpace(params.EvaluationID),
		Severity:           normSev,
		SeveritySource:     sevSource,
		PolicyID:           params.Policy.ID,
		PolicyVersion:      params.Policy.Version,
		PolicyRuleMatched:  ruleMatched,
		AssignedAt:         now,
		SLAStartTime:       startTime,
		Deadline:           deadline,
		TimeBasis:          "ELAPSED_TIME",
		Status:             RemediationStatusOpen,
		EvidenceReferences: params.EvidenceReferences,
		CreatedAt:          now,
		UpdatedAt:          now,
	}

	s.PopulateComputedFields(rec)

	details := map[string]any{
		"policy_id":      params.Policy.ID,
		"policy_version": params.Policy.Version,
		"rule_matched":   ruleMatched,
		"duration":       FormatSLADuration(duration),
		"deadline":       deadline.Format(time.RFC3339),
		"severity":       normSev,
	}
	detailsJSON, _ := json.Marshal(details)

	event := &RemediationHistoryEvent{
		ID:            GenerateRemediationEventID(remID),
		RemediationID: remID,
		EventType:     HistoryEventAssigned,
		FromStatus:    "",
		ToStatus:      RemediationStatusOpen,
		Actor:         actor,
		Reason:        "Initial remediation SLA assignment",
		DetailsJSON:   string(detailsJSON),
		Timestamp:     now,
	}

	return rec, event, nil
}

// TransitionStatus transitions a remediation record to a new lifecycle state.
func (s *RemediationService) TransitionStatus(
	rec *RemediationRecord,
	newStatus RemediationLifecycleStatus,
	actor string,
	reason string,
) (*RemediationHistoryEvent, error) {
	if rec == nil {
		return nil, errors.New("remediation record cannot be nil")
	}

	if err := ValidateRemediationTransition(rec.Status, newStatus); err != nil {
		return nil, err
	}

	now := s.clock.Now().UTC()
	prevStatus := rec.Status
	cleanActor := strings.TrimSpace(actor)
	if cleanActor == "" {
		cleanActor = "operator"
	}
	cleanReason := strings.TrimSpace(reason)
	if cleanReason == "" {
		cleanReason = fmt.Sprintf("Transitioned from %s to %s", prevStatus, newStatus)
	}

	rec.Status = newStatus
	rec.UpdatedAt = now

	eventType := HistoryEventStatusChanged

	if newStatus == RemediationStatusRemediated {
		rec.CompletedAt = &now
	} else if newStatus == RemediationStatusReopened {
		rec.ReopenCount++
		rec.ReopenedAt = &now
		rec.CompletedAt = nil
		eventType = HistoryEventReopened
	} else if prevStatus == RemediationStatusAcceptedRisk && newStatus != RemediationStatusAcceptedRisk {
		rec.RiskAcceptance = nil
		eventType = HistoryEventRiskRevoked
	}

	s.PopulateComputedFields(rec)

	details := map[string]any{
		"from_status": string(prevStatus),
		"to_status":   string(newStatus),
	}
	detailsJSON, _ := json.Marshal(details)

	event := &RemediationHistoryEvent{
		ID:            GenerateRemediationEventID(rec.ID),
		RemediationID: rec.ID,
		EventType:     eventType,
		FromStatus:    prevStatus,
		ToStatus:      newStatus,
		Actor:         cleanActor,
		Reason:        cleanReason,
		DetailsJSON:   string(detailsJSON),
		Timestamp:     now,
	}

	return event, nil
}

// AcceptRisk marks a remediation record as AcceptedRisk with mandatory authorization details.
// Invariant: Risk acceptance never counts as remediation completed.
func (s *RemediationService) AcceptRisk(
	rec *RemediationRecord,
	rationale string,
	author string,
	expiresAt *time.Time,
	actor string,
) (*RemediationHistoryEvent, error) {
	if rec == nil {
		return nil, errors.New("remediation record cannot be nil")
	}

	riskRec := &RiskAcceptanceRecord{
		Rationale:  strings.TrimSpace(rationale),
		Author:     strings.TrimSpace(author),
		AcceptedAt: s.clock.Now().UTC(),
		ExpiresAt:  expiresAt,
		Context:    fmt.Sprintf("Risk accepted for finding %s", rec.FindingID),
	}
	if err := riskRec.Validate(); err != nil {
		return nil, err
	}

	if err := ValidateRemediationTransition(rec.Status, RemediationStatusAcceptedRisk); err != nil {
		return nil, err
	}

	now := s.clock.Now().UTC()
	prevStatus := rec.Status
	cleanActor := strings.TrimSpace(actor)
	if cleanActor == "" {
		cleanActor = riskRec.Author
	}

	rec.Status = RemediationStatusAcceptedRisk
	rec.RiskAcceptance = riskRec
	rec.UpdatedAt = now
	s.PopulateComputedFields(rec)

	details := map[string]any{
		"author":     riskRec.Author,
		"rationale":  riskRec.Rationale,
		"expires_at": riskRec.ExpiresAt,
	}
	detailsJSON, _ := json.Marshal(details)

	event := &RemediationHistoryEvent{
		ID:            GenerateRemediationEventID(rec.ID),
		RemediationID: rec.ID,
		EventType:     HistoryEventRiskAccepted,
		FromStatus:    prevStatus,
		ToStatus:      RemediationStatusAcceptedRisk,
		Actor:         cleanActor,
		Reason:        riskRec.Rationale,
		DetailsJSON:   string(detailsJSON),
		Timestamp:     now,
	}

	return event, nil
}

// RecalculateDeadline explicitly recalculates the SLA deadline for an active remediation record.
// Invariant: The original deadline, updated deadline, reason for change, and policy version are auditable.
func (s *RemediationService) RecalculateDeadline(
	rec *RemediationRecord,
	newPolicy *RemediationSLAPolicy,
	reason string,
	actor string,
) (*RemediationHistoryEvent, error) {
	if rec == nil {
		return nil, errors.New("remediation record cannot be nil")
	}
	if newPolicy == nil {
		return nil, errors.New("new policy cannot be nil")
	}
	if err := ValidateRemediationPolicy(newPolicy); err != nil {
		return nil, fmt.Errorf("invalid policy: %w", err)
	}

	cleanReason := strings.TrimSpace(reason)
	if cleanReason == "" {
		return nil, errors.New("reason for recalculation must be provided")
	}

	cleanActor := strings.TrimSpace(actor)
	if cleanActor == "" {
		cleanActor = "operator"
	}

	duration, ruleMatched, err := newPolicy.ResolveDurationForSeverity(rec.Severity)
	if err != nil {
		return nil, err
	}

	baseStart := rec.SLAStartTime
	if rec.Status == RemediationStatusReopened && rec.ReopenedAt != nil && !rec.ReopenedAt.IsZero() {
		baseStart = *rec.ReopenedAt
	}
	newDeadline, err := s.CalculateDeadline(baseStart, duration)
	if err != nil {
		return nil, err
	}

	now := s.clock.Now().UTC()
	oldDeadline := rec.Deadline
	oldPolicyID := rec.PolicyID
	oldPolicyVer := rec.PolicyVersion

	rec.PolicyID = newPolicy.ID
	rec.PolicyVersion = newPolicy.Version
	rec.PolicyRuleMatched = ruleMatched
	rec.Deadline = newDeadline
	rec.UpdatedAt = now
	s.PopulateComputedFields(rec)

	details := map[string]any{
		"old_deadline":       oldDeadline.Format(time.RFC3339),
		"new_deadline":       newDeadline.Format(time.RFC3339),
		"old_policy_id":      oldPolicyID,
		"old_policy_version": oldPolicyVer,
		"new_policy_id":      newPolicy.ID,
		"new_policy_version": newPolicy.Version,
		"rule_matched":       ruleMatched,
		"duration":           FormatSLADuration(duration),
	}
	detailsJSON, _ := json.Marshal(details)

	event := &RemediationHistoryEvent{
		ID:            GenerateRemediationEventID(rec.ID),
		RemediationID: rec.ID,
		EventType:     HistoryEventDeadlineRecalculated,
		FromStatus:    rec.Status,
		ToStatus:      rec.Status,
		Actor:         cleanActor,
		Reason:        cleanReason,
		DetailsJSON:   string(detailsJSON),
		Timestamp:     now,
	}

	return event, nil
}
