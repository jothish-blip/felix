package compliance

import (
	"errors"
	"testing"
	"time"
)

func TestRemediationService_1_DeadlineCalculationAndClockInjection(t *testing.T) {
	baseTime := time.Date(2026, 10, 21, 10, 0, 0, 0, time.UTC)
	clock := NewMockClock(baseTime)
	svc := NewRemediationService(clock, 24*time.Hour)
	policy := DefaultRemediationSLAPolicy()

	rec, event, err := svc.AssignSLA(AssignSLAParams{
		FindingID:    "F-BOLA-01",
		Severity:     "CRITICAL",
		Policy:       policy,
		SLAStartTime: baseTime,
		Actor:        "tester",
	})
	if err != nil {
		t.Fatalf("AssignSLA failed: %v", err)
	}

	expectedDeadline := baseTime.Add(24 * time.Hour)
	if !rec.Deadline.Equal(expectedDeadline) {
		t.Errorf("expected deadline %v, got %v", expectedDeadline, rec.Deadline)
	}
	if rec.Status != RemediationStatusOpen {
		t.Errorf("expected status open, got %s", rec.Status)
	}
	if rec.ComputedSLAStatus != SLAStatusApproachingDeadline { // 24h deadline with 24h warning window
		t.Errorf("expected SLAStatusApproachingDeadline at start, got %s", rec.ComputedSLAStatus)
	}
	if rec.IsOverdue {
		t.Errorf("expected IsOverdue = false at creation")
	}
	if event.EventType != HistoryEventAssigned {
		t.Errorf("expected event ASSIGNED, got %s", event.EventType)
	}
}

func TestRemediationService_2_ExactOverdueBoundaryConditions(t *testing.T) {
	startTime := time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC)
	clock := NewMockClock(startTime)
	svc := NewRemediationService(clock, 12*time.Hour) // 12h warning window

	rec := &RemediationRecord{
		ID:           "rem:test-boundary",
		FindingID:    "F-TEST-BOUNDARY",
		Severity:     "CRITICAL",
		SLAStartTime: startTime,
		Deadline:     startTime.Add(24 * time.Hour), // 2026-10-21 12:00:00 UTC
		Status:       RemediationStatusOpen,
	}

	// 1. 2 hours after start (22h remaining, outside 12h warning window) -> SLAStatusNotDue
	clock.Set(startTime.Add(2 * time.Hour))
	status := svc.ComputeSLAStatus(rec)
	if status != SLAStatusNotDue {
		t.Errorf("expected SLAStatusNotDue at 2h, got %s", status)
	}

	// 2. 18 hours after start (6h remaining, inside 12h warning window) -> SLAStatusApproachingDeadline
	clock.Set(startTime.Add(18 * time.Hour))
	status = svc.ComputeSLAStatus(rec)
	if status != SLAStatusApproachingDeadline {
		t.Errorf("expected SLAStatusApproachingDeadline at 18h, got %s", status)
	}

	// 3. Exact boundary: clock.Now() == deadline (24h) -> strictly NOT overdue!
	clock.Set(rec.Deadline)
	status = svc.ComputeSLAStatus(rec)
	if status == SLAStatusOverdue {
		t.Errorf("boundary condition violated: clock.Now() == deadline must NOT be overdue")
	}
	if status != SLAStatusApproachingDeadline {
		t.Errorf("expected SLAStatusApproachingDeadline at exact deadline, got %s", status)
	}

	// 4. Strictly after deadline: clock.Now() = deadline + 1 nanosecond -> OVERDUE
	clock.Set(rec.Deadline.Add(1 * time.Nanosecond))
	status = svc.ComputeSLAStatus(rec)
	if status != SLAStatusOverdue {
		t.Errorf("expected SLAStatusOverdue when clock.Now() > deadline, got %s", status)
	}
	svc.PopulateComputedFields(rec)
	if !rec.IsOverdue {
		t.Errorf("expected rec.IsOverdue = true")
	}
}

func TestRemediationService_3_LifecycleTransitions(t *testing.T) {
	clock := NewMockClock(time.Date(2026, 10, 20, 10, 0, 0, 0, time.UTC))
	svc := NewRemediationService(clock, 24*time.Hour)

	rec := &RemediationRecord{
		ID:        "rem:test-trans",
		FindingID: "F-TRANS",
		Status:    RemediationStatusOpen,
		Deadline:  clock.Now().Add(7 * 24 * time.Hour),
	}

	// Open -> InProgress
	evt1, err := svc.TransitionStatus(rec, RemediationStatusInProgress, "dev1", "Started investigation")
	if err != nil {
		t.Fatalf("TransitionStatus Open->InProgress failed: %v", err)
	}
	if rec.Status != RemediationStatusInProgress {
		t.Errorf("expected status InProgress, got %s", rec.Status)
	}
	if evt1.FromStatus != RemediationStatusOpen || evt1.ToStatus != RemediationStatusInProgress {
		t.Errorf("unexpected event status pair: %s -> %s", evt1.FromStatus, evt1.ToStatus)
	}

	// InProgress -> Remediated (on-time)
	clock.Advance(24 * time.Hour)
	evt2, err := svc.TransitionStatus(rec, RemediationStatusRemediated, "dev1", "Fixed in PR #42")
	if err != nil {
		t.Fatalf("TransitionStatus InProgress->Remediated failed: %v", err)
	}
	if rec.Status != RemediationStatusRemediated {
		t.Errorf("expected status Remediated, got %s", rec.Status)
	}
	if rec.CompletedAt == nil {
		t.Fatalf("expected non-nil CompletedAt")
	}
	if rec.ComputedSLAStatus != SLAStatusRemediatedOnTime {
		t.Errorf("expected SLAStatusRemediatedOnTime, got %s", rec.ComputedSLAStatus)
	}
	if evt2.EventType != HistoryEventStatusChanged {
		t.Errorf("expected STATUS_CHANGED event, got %s", evt2.EventType)
	}

	// Remediated -> Reopened (vulnerability re-introduced in regression)
	clock.Advance(48 * time.Hour)
	evt3, err := svc.TransitionStatus(rec, RemediationStatusReopened, "qa-scanner", "Re-detected in daily crawl")
	if err != nil {
		t.Fatalf("TransitionStatus Remediated->Reopened failed: %v", err)
	}
	if rec.Status != RemediationStatusReopened {
		t.Errorf("expected status Reopened, got %s", rec.Status)
	}
	if rec.ReopenCount != 1 {
		t.Errorf("expected ReopenCount = 1, got %d", rec.ReopenCount)
	}
	if rec.CompletedAt != nil {
		t.Errorf("expected CompletedAt to be cleared on reopen")
	}
	if evt3.EventType != HistoryEventReopened {
		t.Errorf("expected REOPENED event, got %s", evt3.EventType)
	}

	// Illegal transition: Reopened -> Open must fail
	_, err = svc.TransitionStatus(rec, RemediationStatusOpen, "dev1", "illegal move")
	if !errors.Is(err, ErrInvalidRemediationTransition) {
		t.Errorf("expected ErrInvalidRemediationTransition for Reopened->Open, got %v", err)
	}
}

func TestRemediationService_4_LateRemediationDistinction(t *testing.T) {
	startTime := time.Date(2026, 10, 1, 10, 0, 0, 0, time.UTC)
	clock := NewMockClock(startTime)
	svc := NewRemediationService(clock, 24*time.Hour)

	deadline := startTime.Add(24 * time.Hour) // 2026-10-02 10:00:00 UTC
	rec := &RemediationRecord{
		ID:        "rem:late-test",
		FindingID: "F-LATE",
		Status:    RemediationStatusInProgress,
		Deadline:  deadline,
	}

	// Advance clock PAST deadline to 2026-10-03 (24h overdue)
	clock.Set(deadline.Add(24 * time.Hour))
	_, err := svc.TransitionStatus(rec, RemediationStatusRemediated, "developer", "Fixed after deadline")
	if err != nil {
		t.Fatalf("failed transitioning: %v", err)
	}

	if rec.ComputedSLAStatus != SLAStatusRemediatedLate {
		t.Errorf("expected SLAStatusRemediatedLate, got %s", rec.ComputedSLAStatus)
	}
}

func TestRemediationService_5_RiskAcceptance(t *testing.T) {
	clock := NewMockClock(time.Date(2026, 10, 20, 10, 0, 0, 0, time.UTC))
	svc := NewRemediationService(clock, 24*time.Hour)

	rec := &RemediationRecord{
		ID:        "rem:risk-test",
		FindingID: "F-RISK",
		Status:    RemediationStatusOpen,
		Deadline:  clock.Now().Add(7 * 24 * time.Hour),
	}

	// Risk acceptance with missing author or rationale must fail
	_, err := svc.AcceptRisk(rec, "", "CISO", nil, "CISO")
	if !errors.Is(err, ErrRiskAcceptanceIncomplete) {
		t.Errorf("expected ErrRiskAcceptanceIncomplete for empty rationale, got %v", err)
	}
	_, err = svc.AcceptRisk(rec, "Compensating WAF rule active", "", nil, "")
	if !errors.Is(err, ErrRiskAcceptanceIncomplete) {
		t.Errorf("expected ErrRiskAcceptanceIncomplete for empty author, got %v", err)
	}

	// Valid risk acceptance
	expiry := clock.Now().Add(90 * 24 * time.Hour)
	evt, err := svc.AcceptRisk(rec, "Compensating WAF rate limiting rule deployed", "SecurityDirector", &expiry, "SecurityDirector")
	if err != nil {
		t.Fatalf("AcceptRisk failed: %v", err)
	}

	if rec.Status != RemediationStatusAcceptedRisk {
		t.Errorf("expected status AcceptedRisk, got %s", rec.Status)
	}
	if rec.ComputedSLAStatus != SLAStatusAcceptedRisk {
		t.Errorf("expected computed status SLAStatusAcceptedRisk, got %s", rec.ComputedSLAStatus)
	}
	if rec.RiskAcceptance == nil || rec.RiskAcceptance.Author != "SecurityDirector" {
		t.Errorf("unexpected risk acceptance details: %+v", rec.RiskAcceptance)
	}
	if evt.EventType != HistoryEventRiskAccepted {
		t.Errorf("expected RISK_ACCEPTED event, got %s", evt.EventType)
	}

	// Risk acceptance must NEVER count as completed remediation
	if rec.CompletedAt != nil {
		t.Errorf("Risk acceptance must not set CompletedAt")
	}
}

func TestRemediationService_6_DeadlineRecalculation(t *testing.T) {
	clock := NewMockClock(time.Date(2026, 10, 20, 10, 0, 0, 0, time.UTC))
	svc := NewRemediationService(clock, 24*time.Hour)

	policyV1 := &RemediationSLAPolicy{
		ID:       "policy-corp",
		Version:  "1.0.0",
		Enabled:  true,
		Rules:    map[string]string{"HIGH": "7d"},
		Priority: 10,
	}

	rec := &RemediationRecord{
		ID:                "rem:recalc-test",
		FindingID:         "F-RECALC",
		Severity:          "HIGH",
		PolicyID:          policyV1.ID,
		PolicyVersion:     policyV1.Version,
		PolicyRuleMatched: "rule:HIGH=7d",
		SLAStartTime:      clock.Now(),
		Deadline:          clock.Now().Add(7 * 24 * time.Hour),
		Status:            RemediationStatusOpen,
	}

	// Update policy to v2.0.0 with 3d SLA for HIGH
	policyV2 := &RemediationSLAPolicy{
		ID:       "policy-corp",
		Version:  "2.0.0",
		Enabled:  true,
		Rules:    map[string]string{"HIGH": "3d"},
		Priority: 10,
	}

	// Recalculate without reason must fail
	_, err := svc.RecalculateDeadline(rec, policyV2, "", "sec-ops")
	if err == nil {
		t.Errorf("expected error for empty recalculation reason")
	}

	// Valid recalculation
	evt, err := svc.RecalculateDeadline(rec, policyV2, "Updated company SLA policy from 7d to 3d for High severities", "sec-ops")
	if err != nil {
		t.Fatalf("RecalculateDeadline failed: %v", err)
	}

	expectedNewDeadline := rec.SLAStartTime.Add(3 * 24 * time.Hour)
	if !rec.Deadline.Equal(expectedNewDeadline) {
		t.Errorf("expected new deadline %v, got %v", expectedNewDeadline, rec.Deadline)
	}
	if rec.PolicyVersion != "2.0.0" {
		t.Errorf("expected policy version 2.0.0, got %s", rec.PolicyVersion)
	}
	if evt.EventType != HistoryEventDeadlineRecalculated {
		t.Errorf("expected DEADLINE_RECALCULATED event, got %s", evt.EventType)
	}
}
