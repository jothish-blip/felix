package test

import (
	"database/sql"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"felix/pkg/assessment"
	"felix/pkg/correlation"
	"felix/pkg/report"
	_ "modernc.org/sqlite"
)

// =============================================================================
// PHASE 6.6: FINDING LIFECYCLE MANAGEMENT REGRESSION TEST SUITE
// Validates NEW, ACTIVE, RESOLVED, REGRESSED state machine, resolution safety,
// regression detection, tenant isolation, and atomic SQLite persistence.
// =============================================================================

func helperNewLifecycleTestStore(t *testing.T) (assessment.Store, string, func()) {
	t.Helper()
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, fmt.Sprintf("test_lifecycle_%d.db", time.Now().UnixNano()))
	store, err := assessment.NewSQLiteStore(dbPath)
	if err != nil {
		t.Fatalf("failed to create sqlite store: %v", err)
	}
	cleanup := func() {
		_ = store.Close()
	}
	return store, dbPath, cleanup
}

func timePtr(t time.Time) *time.Time {
	return &t
}

func helperSetupLifecycleRun(t *testing.T, store assessment.Store, clientID, asmID, tenantID, accountID, targetID, targetURL string) (*assessment.Client, *assessment.Assessment, *assessment.AssessmentTarget) {
	t.Helper()
	c, asm := helperSeedClientAndAssessment(t, store, clientID, asmID, tenantID, accountID)
	tgt := helperSeedTarget(t, store, asmID, targetID, targetURL)
	return c, asm, tgt
}

func helperMakeLifecycleFinding(asmID, execID, targetID, id, title, ruleID, severity, conf, verStatus, targetURL, endpoint, method string) assessment.AssessmentFinding {
	rf := report.Finding{
		ID:         id,
		RuleID:     ruleID,
		Title:      title,
		Category:   ruleID,
		Severity:   severity,
		Confidence: conf,
		Target:     targetURL,
		Endpoint:   endpoint,
		Method:     method,
		EvidenceDetails: report.EvidenceDetails{
			Observation: fmt.Sprintf("Observation for %s", title),
			Details:     make(map[string]string),
		},
		Verification: report.VerificationRecord{
			Status: report.VerificationStatus(verStatus),
			Result: fmt.Sprintf("Result for %s", title),
		},
	}
	rf.Fingerprint = correlation.ComputeStableFingerprint(rf)
	rf.Score = report.CalculateFindingScore(rf)

	af := assessment.ToAssessmentFinding(asmID, execID, targetID, rf)
	af.Fingerprint = rf.Fingerprint
	af.Score = rf.Score
	return af
}

// -----------------------------------------------------------------------------
// 1. STATE TRANSITIONS
// -----------------------------------------------------------------------------

// Category 01: First Detection Transitions to NEW
func TestLifecycle_Category01_FirstDetectionIsNew(t *testing.T) {
	store, _, cleanup := helperNewLifecycleTestStore(t)
	defer cleanup()

	clientID, tenantID, accountID, asmID := "cli_c01", "ten_c01", "acc_c01", "asm_c01"
	targetID, targetURL := "tgt_c01", "https://api.example.com"

	_, asm, _ := helperSetupLifecycleRun(t, store, clientID, asmID, tenantID, accountID, targetID, targetURL)
	exec := &assessment.AssessmentExecution{
		ID:           "exec_c01_1",
		AssessmentID: asmID,
		Status:       assessment.StatusCompleted,
		StartedAt:    time.Now().UTC().Add(-time.Hour),
		CompletedAt:  timePtr(time.Now().UTC()),
	}
	_ = store.CreateExecution(exec)

	af := helperMakeLifecycleFinding(asmID, exec.ID, targetID, "fnd_c01", "SQL Injection", "sqli", report.SeverityCritical, report.ConfidenceHigh, string(report.VerificationVerified), targetURL, targetURL+"/users", "GET")

	snap := assessment.BuildAssessmentSnapshot(asm, exec, []string{targetURL}, []assessment.AssessmentFinding{af}, true)
	snap.TenantID = tenantID
	snap.AccountID = accountID

	if err := store.CreateSnapshot(snap, []assessment.AssessmentFinding{af}, nil); err != nil {
		t.Fatalf("CreateSnapshot failed: %v", err)
	}

	authCtx := assessment.NewTenantAuthContext(clientID, tenantID, accountID)
	rec, err := store.GetFindingLifecycle(tenantID, accountID, af.Fingerprint, authCtx)
	if err != nil {
		t.Fatalf("GetFindingLifecycle failed: %v", err)
	}

	if rec.CurrentState != "NEW" {
		t.Fatalf("Expected CurrentState NEW on first observation, got %q", rec.CurrentState)
	}
	if rec.PreviousState != "" {
		t.Fatalf("Expected empty PreviousState on first observation, got %q", rec.PreviousState)
	}
	if rec.RegressionCount != 0 {
		t.Fatalf("Expected RegressionCount 0, got %d", rec.RegressionCount)
	}

	// Verify lifecycle events
	events, err := store.GetFindingLifecycleEvents(af.Fingerprint, authCtx)
	if err != nil {
		t.Fatalf("GetFindingLifecycleEvents failed: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("Expected 1 event, got %d", len(events))
	}
	if events[0].CurrentState != "NEW" || events[0].PreviousState != "" {
		t.Fatalf("Unexpected event state: %+v", events[0])
	}
}

// Category 02: Repeated Detection Transitions NEW -> ACTIVE and ACTIVE -> ACTIVE
func TestLifecycle_Category02_RepeatedDetectionIsActive(t *testing.T) {
	store, _, cleanup := helperNewLifecycleTestStore(t)
	defer cleanup()

	clientID, tenantID, accountID, asmID := "cli_c02", "ten_c02", "acc_c02", "asm_c02"
	targetID, targetURL := "tgt_c02", "https://api.example.com"

	_, asm, _ := helperSetupLifecycleRun(t, store, clientID, asmID, tenantID, accountID, targetID, targetURL)
	authCtx := assessment.NewTenantAuthContext(clientID, tenantID, accountID)

	// Run 1: Discovery (NEW)
	exec1 := &assessment.AssessmentExecution{
		ID:           "exec_c02_1",
		AssessmentID: asmID,
		Status:       assessment.StatusCompleted,
		StartedAt:    time.Now().UTC().Add(-2 * time.Hour),
		CompletedAt:  timePtr(time.Now().UTC().Add(-100 * time.Minute)),
	}
	_ = store.CreateExecution(exec1)
	af1 := helperMakeLifecycleFinding(asmID, exec1.ID, targetID, "fnd_c02", "BOLA Vulnerability", "bola", report.SeverityHigh, report.ConfidenceHigh, string(report.VerificationVerified), targetURL, targetURL+"/orders", "GET")
	snap1 := assessment.BuildAssessmentSnapshot(asm, exec1, []string{targetURL}, []assessment.AssessmentFinding{af1}, true)
	snap1.TenantID = tenantID
	snap1.AccountID = accountID
	if err := store.CreateSnapshot(snap1, []assessment.AssessmentFinding{af1}, nil); err != nil {
		t.Fatalf("Run 1 CreateSnapshot failed: %v", err)
	}

	// Run 2: Re-detected (NEW -> ACTIVE)
	exec2 := &assessment.AssessmentExecution{
		ID:           "exec_c02_2",
		AssessmentID: asmID,
		Status:       assessment.StatusCompleted,
		StartedAt:    time.Now().UTC().Add(-50 * time.Minute),
		CompletedAt:  timePtr(time.Now().UTC().Add(-30 * time.Minute)),
	}
	_ = store.CreateExecution(exec2)
	af2 := helperMakeLifecycleFinding(asmID, exec2.ID, targetID, "fnd_c02_run2", "BOLA Vulnerability", "bola", report.SeverityHigh, report.ConfidenceHigh, string(report.VerificationVerified), targetURL, targetURL+"/orders", "GET")
	snap2 := assessment.BuildAssessmentSnapshot(asm, exec2, []string{targetURL}, []assessment.AssessmentFinding{af2}, true)
	snap2.TenantID = tenantID
	snap2.AccountID = accountID
	if err := store.CreateSnapshot(snap2, []assessment.AssessmentFinding{af2}, nil); err != nil {
		t.Fatalf("Run 2 CreateSnapshot failed: %v", err)
	}

	rec2, err := store.GetFindingLifecycle(tenantID, accountID, af1.Fingerprint, authCtx)
	if err != nil {
		t.Fatalf("GetFindingLifecycle after run 2 failed: %v", err)
	}
	if rec2.CurrentState != "ACTIVE" {
		t.Fatalf("Expected CurrentState ACTIVE on repeated detection, got %q", rec2.CurrentState)
	}
	if rec2.PreviousState != "NEW" {
		t.Fatalf("Expected PreviousState NEW, got %q", rec2.PreviousState)
	}

	// Run 3: Detected again (ACTIVE -> ACTIVE)
	exec3 := &assessment.AssessmentExecution{
		ID:           "exec_c02_3",
		AssessmentID: asmID,
		Status:       assessment.StatusCompleted,
		StartedAt:    time.Now().UTC().Add(-20 * time.Minute),
		CompletedAt:  timePtr(time.Now().UTC().Add(-5 * time.Minute)),
	}
	_ = store.CreateExecution(exec3)
	af3 := helperMakeLifecycleFinding(asmID, exec3.ID, targetID, "fnd_c02_run3", "BOLA Vulnerability", "bola", report.SeverityHigh, report.ConfidenceHigh, string(report.VerificationVerified), targetURL, targetURL+"/orders", "GET")
	snap3 := assessment.BuildAssessmentSnapshot(asm, exec3, []string{targetURL}, []assessment.AssessmentFinding{af3}, true)
	snap3.TenantID = tenantID
	snap3.AccountID = accountID
	if err := store.CreateSnapshot(snap3, []assessment.AssessmentFinding{af3}, nil); err != nil {
		t.Fatalf("Run 3 CreateSnapshot failed: %v", err)
	}

	rec3, err := store.GetFindingLifecycle(tenantID, accountID, af1.Fingerprint, authCtx)
	if err != nil {
		t.Fatalf("GetFindingLifecycle after run 3 failed: %v", err)
	}
	if rec3.CurrentState != "ACTIVE" {
		t.Fatalf("Expected CurrentState to remain ACTIVE, got %q", rec3.CurrentState)
	}
	if rec3.PreviousState != "ACTIVE" {
		t.Fatalf("Expected PreviousState ACTIVE, got %q", rec3.PreviousState)
	}

	// Verify events count: 3 events
	events, err := store.GetFindingLifecycleEvents(af1.Fingerprint, authCtx)
	if err != nil {
		t.Fatalf("GetFindingLifecycleEvents failed: %v", err)
	}
	if len(events) != 3 {
		t.Fatalf("Expected 3 lifecycle events, got %d", len(events))
	}
	if events[1].CurrentState != "ACTIVE" || events[1].PreviousState != "NEW" {
		t.Errorf("Unexpected event 2: %+v", events[1])
	}
	if events[2].CurrentState != "ACTIVE" || events[2].PreviousState != "ACTIVE" {
		t.Errorf("Unexpected event 3: %+v", events[2])
	}
}

// Category 03: Active Finding Absent from Qualifying Completed Assessment is RESOLVED
func TestLifecycle_Category03_ActiveAbsentInQualifyingIsResolved(t *testing.T) {
	store, _, cleanup := helperNewLifecycleTestStore(t)
	defer cleanup()

	clientID, tenantID, accountID, asmID := "cli_c03", "ten_c03", "acc_c03", "asm_c03"
	targetID, targetURL := "tgt_c03", "https://api.example.com"

	_, asm, _ := helperSetupLifecycleRun(t, store, clientID, asmID, tenantID, accountID, targetID, targetURL)
	authCtx := assessment.NewTenantAuthContext(clientID, tenantID, accountID)

	// Run 1: Discovery (NEW)
	exec1 := &assessment.AssessmentExecution{
		ID:           "exec_c03_1",
		AssessmentID: asmID,
		Status:       assessment.StatusCompleted,
		StartedAt:    time.Now().UTC().Add(-2 * time.Hour),
		CompletedAt:  timePtr(time.Now().UTC().Add(-100 * time.Minute)),
	}
	_ = store.CreateExecution(exec1)
	af1 := helperMakeLifecycleFinding(asmID, exec1.ID, targetID, "fnd_c03", "SSRF Vulnerability", "ssrf", report.SeverityHigh, report.ConfidenceHigh, string(report.VerificationVerified), targetURL, targetURL+"/webhook", "POST")
	snap1 := assessment.BuildAssessmentSnapshot(asm, exec1, []string{targetURL}, []assessment.AssessmentFinding{af1}, true)
	snap1.TenantID = tenantID
	snap1.AccountID = accountID
	_ = store.CreateSnapshot(snap1, []assessment.AssessmentFinding{af1}, nil)

	// Run 2: Re-assessment completes successfully, target in scope, finding confirmed absent (0 findings)
	exec2 := &assessment.AssessmentExecution{
		ID:           "exec_c03_2",
		AssessmentID: asmID,
		Status:       assessment.StatusCompleted,
		StartedAt:    time.Now().UTC().Add(-50 * time.Minute),
		CompletedAt:  timePtr(time.Now().UTC().Add(-30 * time.Minute)),
	}
	_ = store.CreateExecution(exec2)
	snap2 := assessment.BuildAssessmentSnapshot(asm, exec2, []string{targetURL}, []assessment.AssessmentFinding{}, true)
	snap2.TenantID = tenantID
	snap2.AccountID = accountID
	if err := store.CreateSnapshot(snap2, []assessment.AssessmentFinding{}, nil); err != nil {
		t.Fatalf("Run 2 CreateSnapshot failed: %v", err)
	}

	rec, err := store.GetFindingLifecycle(tenantID, accountID, af1.Fingerprint, authCtx)
	if err != nil {
		t.Fatalf("GetFindingLifecycle failed: %v", err)
	}
	if rec.CurrentState != "RESOLVED" {
		t.Fatalf("Expected CurrentState RESOLVED, got %q", rec.CurrentState)
	}
	if rec.PreviousState != "NEW" {
		t.Fatalf("Expected PreviousState NEW, got %q", rec.PreviousState)
	}
	if rec.ResolvedAt == nil {
		t.Fatalf("Expected ResolvedAt timestamp to be set")
	}

	// Verify events
	events, err := store.GetFindingLifecycleEvents(af1.Fingerprint, authCtx)
	if err != nil {
		t.Fatalf("GetFindingLifecycleEvents failed: %v", err)
	}
	if len(events) != 2 {
		t.Fatalf("Expected 2 lifecycle events, got %d", len(events))
	}
	if events[1].CurrentState != "RESOLVED" || events[1].PreviousState != "NEW" {
		t.Fatalf("Unexpected event 2: %+v", events[1])
	}
}

// Category 04: Resolved Finding Detected Again Transitions to REGRESSED
func TestLifecycle_Category04_ResolvedDetectedAgainIsRegressed(t *testing.T) {
	store, _, cleanup := helperNewLifecycleTestStore(t)
	defer cleanup()

	clientID, tenantID, accountID, asmID := "cli_c04", "ten_c04", "acc_c04", "asm_c04"
	targetID, targetURL := "tgt_c04", "https://api.example.com"

	_, asm, _ := helperSetupLifecycleRun(t, store, clientID, asmID, tenantID, accountID, targetID, targetURL)
	authCtx := assessment.NewTenantAuthContext(clientID, tenantID, accountID)

	// Run 1: Discovery (NEW)
	exec1 := &assessment.AssessmentExecution{
		ID:           "exec_c04_1",
		AssessmentID: asmID,
		Status:       assessment.StatusCompleted,
		StartedAt:    time.Now().UTC().Add(-3 * time.Hour),
		CompletedAt:  timePtr(time.Now().UTC().Add(-2 * time.Hour)),
	}
	_ = store.CreateExecution(exec1)
	af1 := helperMakeLifecycleFinding(asmID, exec1.ID, targetID, "fnd_c04", "IDOR in Billing", "idor", report.SeverityHigh, report.ConfidenceHigh, string(report.VerificationVerified), targetURL, targetURL+"/invoices", "GET")
	snap1 := assessment.BuildAssessmentSnapshot(asm, exec1, []string{targetURL}, []assessment.AssessmentFinding{af1}, true)
	snap1.TenantID = tenantID
	snap1.AccountID = accountID
	_ = store.CreateSnapshot(snap1, []assessment.AssessmentFinding{af1}, nil)

	// Run 2: Resolved
	exec2 := &assessment.AssessmentExecution{
		ID:           "exec_c04_2",
		AssessmentID: asmID,
		Status:       assessment.StatusCompleted,
		StartedAt:    time.Now().UTC().Add(-90 * time.Minute),
		CompletedAt:  timePtr(time.Now().UTC().Add(-60 * time.Minute)),
	}
	_ = store.CreateExecution(exec2)
	snap2 := assessment.BuildAssessmentSnapshot(asm, exec2, []string{targetURL}, []assessment.AssessmentFinding{}, true)
	snap2.TenantID = tenantID
	snap2.AccountID = accountID
	_ = store.CreateSnapshot(snap2, []assessment.AssessmentFinding{}, nil)

	// Verify it was resolved
	recAfterRun2, _ := store.GetFindingLifecycle(tenantID, accountID, af1.Fingerprint, authCtx)
	if recAfterRun2.CurrentState != "RESOLVED" {
		t.Fatalf("Expected RESOLVED after run 2, got %q", recAfterRun2.CurrentState)
	}

	// Run 3: Detected again -> REGRESSED!
	exec3 := &assessment.AssessmentExecution{
		ID:           "exec_c04_3",
		AssessmentID: asmID,
		Status:       assessment.StatusCompleted,
		StartedAt:    time.Now().UTC().Add(-30 * time.Minute),
		CompletedAt:  timePtr(time.Now().UTC().Add(-10 * time.Minute)),
	}
	_ = store.CreateExecution(exec3)
	af3 := helperMakeLifecycleFinding(asmID, exec3.ID, targetID, "fnd_c04_run3", "IDOR in Billing", "idor", report.SeverityHigh, report.ConfidenceHigh, string(report.VerificationVerified), targetURL, targetURL+"/invoices", "GET")
	snap3 := assessment.BuildAssessmentSnapshot(asm, exec3, []string{targetURL}, []assessment.AssessmentFinding{af3}, true)
	snap3.TenantID = tenantID
	snap3.AccountID = accountID
	if err := store.CreateSnapshot(snap3, []assessment.AssessmentFinding{af3}, nil); err != nil {
		t.Fatalf("Run 3 CreateSnapshot failed: %v", err)
	}

	recAfterRun3, err := store.GetFindingLifecycle(tenantID, accountID, af1.Fingerprint, authCtx)
	if err != nil {
		t.Fatalf("GetFindingLifecycle after run 3 failed: %v", err)
	}
	if recAfterRun3.CurrentState != "REGRESSED" {
		t.Fatalf("Expected CurrentState REGRESSED after re-detection of resolved finding, got %q", recAfterRun3.CurrentState)
	}
	if recAfterRun3.PreviousState != "RESOLVED" {
		t.Fatalf("Expected PreviousState RESOLVED, got %q", recAfterRun3.PreviousState)
	}
	if recAfterRun3.RegressionCount != 1 {
		t.Fatalf("Expected RegressionCount 1, got %d", recAfterRun3.RegressionCount)
	}

	// Verify events
	events, err := store.GetFindingLifecycleEvents(af1.Fingerprint, authCtx)
	if err != nil {
		t.Fatalf("GetFindingLifecycleEvents failed: %v", err)
	}
	if len(events) != 3 {
		t.Fatalf("Expected 3 events, got %d", len(events))
	}
	if events[2].CurrentState != "REGRESSED" || events[2].PreviousState != "RESOLVED" {
		t.Fatalf("Unexpected event 3: %+v", events[2])
	}
}

// Category 05: Repeated Detection After Regression Transitions REGRESSED -> ACTIVE
func TestLifecycle_Category05_RegressedDetectedAgainIsActive(t *testing.T) {
	store, _, cleanup := helperNewLifecycleTestStore(t)
	defer cleanup()

	clientID, tenantID, accountID, asmID := "cli_c05", "ten_c05", "acc_c05", "asm_c05"
	targetID, targetURL := "tgt_c05", "https://api.example.com"

	_, asm, _ := helperSetupLifecycleRun(t, store, clientID, asmID, tenantID, accountID, targetID, targetURL)
	authCtx := assessment.NewTenantAuthContext(clientID, tenantID, accountID)

	// Run 1: NEW
	exec1 := &assessment.AssessmentExecution{ID: "exec_c05_1", AssessmentID: asmID, Status: assessment.StatusCompleted, StartedAt: time.Now().UTC().Add(-4 * time.Hour), CompletedAt: timePtr(time.Now().UTC().Add(-3 * time.Hour))}
	_ = store.CreateExecution(exec1)
	af1 := helperMakeLifecycleFinding(asmID, exec1.ID, targetID, "fnd_c05_1", "XSS in Search", "xss", report.SeverityMedium, report.ConfidenceHigh, string(report.VerificationVerified), targetURL, targetURL+"/search", "GET")
	snap1 := assessment.BuildAssessmentSnapshot(asm, exec1, []string{targetURL}, []assessment.AssessmentFinding{af1}, true)
	snap1.TenantID, snap1.AccountID = tenantID, accountID
	if err := store.CreateSnapshot(snap1, []assessment.AssessmentFinding{af1}, nil); err != nil {
		t.Fatalf("Run 1 CreateSnapshot failed: %v", err)
	}

	// Run 2: RESOLVED
	exec2 := &assessment.AssessmentExecution{ID: "exec_c05_2", AssessmentID: asmID, Status: assessment.StatusCompleted, StartedAt: time.Now().UTC().Add(-150 * time.Minute), CompletedAt: timePtr(time.Now().UTC().Add(-120 * time.Minute))}
	_ = store.CreateExecution(exec2)
	snap2 := assessment.BuildAssessmentSnapshot(asm, exec2, []string{targetURL}, nil, true)
	snap2.TenantID, snap2.AccountID = tenantID, accountID
	if err := store.CreateSnapshot(snap2, nil, nil); err != nil {
		t.Fatalf("Run 2 CreateSnapshot failed: %v", err)
	}

	// Run 3: REGRESSED
	exec3 := &assessment.AssessmentExecution{ID: "exec_c05_3", AssessmentID: asmID, Status: assessment.StatusCompleted, StartedAt: time.Now().UTC().Add(-90 * time.Minute), CompletedAt: timePtr(time.Now().UTC().Add(-60 * time.Minute))}
	_ = store.CreateExecution(exec3)
	af3 := helperMakeLifecycleFinding(asmID, exec3.ID, targetID, "fnd_c05_3", "XSS in Search", "xss", report.SeverityMedium, report.ConfidenceHigh, string(report.VerificationVerified), targetURL, targetURL+"/search", "GET")
	snap3 := assessment.BuildAssessmentSnapshot(asm, exec3, []string{targetURL}, []assessment.AssessmentFinding{af3}, true)
	snap3.TenantID, snap3.AccountID = tenantID, accountID
	if err := store.CreateSnapshot(snap3, []assessment.AssessmentFinding{af3}, nil); err != nil {
		t.Fatalf("Run 3 CreateSnapshot failed: %v", err)
	}

	// Run 4: Detected again while REGRESSED -> transitions to ACTIVE
	exec4 := &assessment.AssessmentExecution{ID: "exec_c05_4", AssessmentID: asmID, Status: assessment.StatusCompleted, StartedAt: time.Now().UTC().Add(-30 * time.Minute), CompletedAt: timePtr(time.Now().UTC().Add(-10 * time.Minute))}
	_ = store.CreateExecution(exec4)
	af4 := helperMakeLifecycleFinding(asmID, exec4.ID, targetID, "fnd_c05_4", "XSS in Search", "xss", report.SeverityMedium, report.ConfidenceHigh, string(report.VerificationVerified), targetURL, targetURL+"/search", "GET")
	snap4 := assessment.BuildAssessmentSnapshot(asm, exec4, []string{targetURL}, []assessment.AssessmentFinding{af4}, true)
	snap4.TenantID, snap4.AccountID = tenantID, accountID
	if err := store.CreateSnapshot(snap4, []assessment.AssessmentFinding{af4}, nil); err != nil {
		t.Fatalf("Run 4 CreateSnapshot failed: %v", err)
	}

	rec4, err := store.GetFindingLifecycle(tenantID, accountID, af1.Fingerprint, authCtx)
	if err != nil {
		t.Fatalf("GetFindingLifecycle failed: %v", err)
	}
	if rec4.CurrentState != "ACTIVE" {
		t.Fatalf("Expected CurrentState ACTIVE after subsequent detection of regressed finding, got %q", rec4.CurrentState)
	}
	if rec4.PreviousState != "REGRESSED" {
		t.Fatalf("Expected PreviousState REGRESSED, got %q", rec4.PreviousState)
	}
	if rec4.RegressionCount != 1 {
		t.Fatalf("Expected RegressionCount to remain 1, got %d", rec4.RegressionCount)
	}
}

// Category 06: Finding Resolved a Second Time After Regression
func TestLifecycle_Category06_FindingResolvedSecondTime(t *testing.T) {
	store, _, cleanup := helperNewLifecycleTestStore(t)
	defer cleanup()

	clientID, tenantID, accountID, asmID := "cli_c06", "ten_c06", "acc_c06", "asm_c06"
	targetID, targetURL := "tgt_c06", "https://api.example.com"

	_, asm, _ := helperSetupLifecycleRun(t, store, clientID, asmID, tenantID, accountID, targetID, targetURL)
	authCtx := assessment.NewTenantAuthContext(clientID, tenantID, accountID)

	// 1: NEW
	e1 := &assessment.AssessmentExecution{ID: "e1", AssessmentID: asmID, Status: assessment.StatusCompleted, StartedAt: time.Now().UTC().Add(-5 * time.Hour), CompletedAt: timePtr(time.Now().UTC().Add(-4 * time.Hour))}
	_ = store.CreateExecution(e1)
	af1 := helperMakeLifecycleFinding(asmID, e1.ID, targetID, "fnd_c06_1", "Open Redirect", "open-redirect", report.SeverityLow, report.ConfidenceHigh, string(report.VerificationVerified), targetURL, targetURL+"/redirect", "GET")
	s1 := assessment.BuildAssessmentSnapshot(asm, e1, []string{targetURL}, []assessment.AssessmentFinding{af1}, true)
	s1.TenantID, s1.AccountID = tenantID, accountID
	if err := store.CreateSnapshot(s1, []assessment.AssessmentFinding{af1}, nil); err != nil {
		t.Fatalf("CreateSnapshot 1 failed: %v", err)
	}

	// 2: RESOLVED
	e2 := &assessment.AssessmentExecution{ID: "e2", AssessmentID: asmID, Status: assessment.StatusCompleted, StartedAt: time.Now().UTC().Add(-3 * time.Hour), CompletedAt: timePtr(time.Now().UTC().Add(-2 * time.Hour))}
	_ = store.CreateExecution(e2)
	s2 := assessment.BuildAssessmentSnapshot(asm, e2, []string{targetURL}, nil, true)
	s2.TenantID, s2.AccountID = tenantID, accountID
	if err := store.CreateSnapshot(s2, nil, nil); err != nil {
		t.Fatalf("CreateSnapshot 2 failed: %v", err)
	}

	// 3: REGRESSED
	e3 := &assessment.AssessmentExecution{ID: "e3", AssessmentID: asmID, Status: assessment.StatusCompleted, StartedAt: time.Now().UTC().Add(-90 * time.Minute), CompletedAt: timePtr(time.Now().UTC().Add(-60 * time.Minute))}
	_ = store.CreateExecution(e3)
	af3 := helperMakeLifecycleFinding(asmID, e3.ID, targetID, "fnd_c06_3", "Open Redirect", "open-redirect", report.SeverityLow, report.ConfidenceHigh, string(report.VerificationVerified), targetURL, targetURL+"/redirect", "GET")
	s3 := assessment.BuildAssessmentSnapshot(asm, e3, []string{targetURL}, []assessment.AssessmentFinding{af3}, true)
	s3.TenantID, s3.AccountID = tenantID, accountID
	if err := store.CreateSnapshot(s3, []assessment.AssessmentFinding{af3}, nil); err != nil {
		t.Fatalf("CreateSnapshot 3 failed: %v", err)
	}

	// 4: Confirmed absent again -> RESOLVED second time!
	e4 := &assessment.AssessmentExecution{ID: "e4", AssessmentID: asmID, Status: assessment.StatusCompleted, StartedAt: time.Now().UTC().Add(-30 * time.Minute), CompletedAt: timePtr(time.Now().UTC().Add(-10 * time.Minute))}
	_ = store.CreateExecution(e4)
	s4 := assessment.BuildAssessmentSnapshot(asm, e4, []string{targetURL}, nil, true)
	s4.TenantID, s4.AccountID = tenantID, accountID
	if err := store.CreateSnapshot(s4, nil, nil); err != nil {
		t.Fatalf("CreateSnapshot 4 failed: %v", err)
	}

	rec, err := store.GetFindingLifecycle(tenantID, accountID, af1.Fingerprint, authCtx)
	if err != nil {
		t.Fatalf("GetFindingLifecycle failed: %v", err)
	}
	if rec.CurrentState != "RESOLVED" {
		t.Fatalf("Expected RESOLVED after second mitigation, got %q", rec.CurrentState)
	}
	if rec.PreviousState != "REGRESSED" {
		t.Fatalf("Expected PreviousState REGRESSED, got %q", rec.PreviousState)
	}
	if rec.RegressionCount != 1 {
		t.Fatalf("Expected RegressionCount 1, got %d", rec.RegressionCount)
	}

	// 4 events total
	events, _ := store.GetFindingLifecycleEvents(af1.Fingerprint, authCtx)
	if len(events) != 4 {
		t.Fatalf("Expected 4 events, got %d", len(events))
	}
}

// Category 07: Two Distinct Findings on Same Target Remain Distinct
func TestLifecycle_Category07_TwoDistinctFindingsOnSameTargetRemainDistinct(t *testing.T) {
	store, _, cleanup := helperNewLifecycleTestStore(t)
	defer cleanup()

	clientID, tenantID, accountID, asmID := "cli_c07", "ten_c07", "acc_c07", "asm_c07"
	targetID, targetURL := "tgt_c07", "https://api.example.com"
	_, asm, _ := helperSetupLifecycleRun(t, store, clientID, asmID, tenantID, accountID, targetID, targetURL)
	authCtx := assessment.NewTenantAuthContext(clientID, tenantID, accountID)

	// Run 1: Detect both
	e1 := &assessment.AssessmentExecution{ID: "e1", AssessmentID: asmID, Status: assessment.StatusCompleted, StartedAt: time.Now().UTC().Add(-2 * time.Hour), CompletedAt: timePtr(time.Now().UTC().Add(-1 * time.Hour))}
	_ = store.CreateExecution(e1)
	afA1 := helperMakeLifecycleFinding(asmID, e1.ID, targetID, "fA_1", "SQL Injection in User ID", "sqli", report.SeverityCritical, report.ConfidenceHigh, string(report.VerificationVerified), targetURL, targetURL+"/users", "GET")
	afB1 := helperMakeLifecycleFinding(asmID, e1.ID, targetID, "fB_1", "BOLA in Order ID", "bola", report.SeverityHigh, report.ConfidenceHigh, string(report.VerificationVerified), targetURL, targetURL+"/users", "GET")

	if afA1.Fingerprint == afB1.Fingerprint {
		t.Fatalf("Test setup failure: fingerprints must be distinct")
	}

	s1 := assessment.BuildAssessmentSnapshot(asm, e1, []string{targetURL}, []assessment.AssessmentFinding{afA1, afB1}, true)
	s1.TenantID, s1.AccountID = tenantID, accountID
	if err := store.CreateSnapshot(s1, []assessment.AssessmentFinding{afA1, afB1}, nil); err != nil {
		t.Fatalf("CreateSnapshot 1 failed: %v", err)
	}

	// Run 2: Only afA detected, afB resolved
	e2 := &assessment.AssessmentExecution{ID: "e2", AssessmentID: asmID, Status: assessment.StatusCompleted, StartedAt: time.Now().UTC().Add(-30 * time.Minute), CompletedAt: timePtr(time.Now().UTC().Add(-10 * time.Minute))}
	_ = store.CreateExecution(e2)
	afA2 := helperMakeLifecycleFinding(asmID, e2.ID, targetID, "fA_2", "SQL Injection in User ID", "sqli", report.SeverityCritical, report.ConfidenceHigh, string(report.VerificationVerified), targetURL, targetURL+"/users", "GET")

	s2 := assessment.BuildAssessmentSnapshot(asm, e2, []string{targetURL}, []assessment.AssessmentFinding{afA2}, true)
	s2.TenantID, s2.AccountID = tenantID, accountID
	if err := store.CreateSnapshot(s2, []assessment.AssessmentFinding{afA2}, nil); err != nil {
		t.Fatalf("CreateSnapshot 2 failed: %v", err)
	}

	recA, _ := store.GetFindingLifecycle(tenantID, accountID, afA1.Fingerprint, authCtx)
	recB, _ := store.GetFindingLifecycle(tenantID, accountID, afB1.Fingerprint, authCtx)

	if recA.CurrentState != "ACTIVE" {
		t.Errorf("Finding A should be ACTIVE, got %q", recA.CurrentState)
	}
	if recB.CurrentState != "RESOLVED" {
		t.Errorf("Finding B should be RESOLVED, got %q", recB.CurrentState)
	}
}

// -----------------------------------------------------------------------------
// 2. RESOLUTION SAFETY
// -----------------------------------------------------------------------------

// Category 08: Failed Assessment Does Not Resolve Findings
func TestLifecycle_Category08_FailedAssessmentDoesNotResolve(t *testing.T) {
	store, _, cleanup := helperNewLifecycleTestStore(t)
	defer cleanup()

	clientID, tenantID, accountID, asmID := "cli_c08", "ten_c08", "acc_c08", "asm_c08"
	targetID, targetURL := "tgt_c08", "https://api.example.com"
	_, asm, _ := helperSetupLifecycleRun(t, store, clientID, asmID, tenantID, accountID, targetID, targetURL)
	authCtx := assessment.NewTenantAuthContext(clientID, tenantID, accountID)

	af := helperMakeLifecycleFinding(asmID, "", targetID, "fnd_c08", "Critical RCE", "rce", report.SeverityCritical, report.ConfidenceHigh, string(report.VerificationVerified), targetURL, targetURL+"/exec", "POST")

	// Run 1: Completed, finding observed (NEW)
	e1 := &assessment.AssessmentExecution{ID: "e1", AssessmentID: asmID, Status: assessment.StatusCompleted, StartedAt: time.Now().UTC().Add(-2 * time.Hour), CompletedAt: timePtr(time.Now().UTC().Add(-1 * time.Hour))}
	_ = store.CreateExecution(e1)
	af.ExecutionID = e1.ID
	s1 := assessment.BuildAssessmentSnapshot(asm, e1, []string{targetURL}, []assessment.AssessmentFinding{af}, true)
	s1.TenantID, s1.AccountID = tenantID, accountID
	_ = store.CreateSnapshot(s1, []assessment.AssessmentFinding{af}, nil)

	// Run 2: Failed assessment (e.g. network timeout)
	e2 := &assessment.AssessmentExecution{ID: "e2", AssessmentID: asmID, Status: assessment.StatusFailed, ErrorMessage: "scanner timed out", StartedAt: time.Now().UTC().Add(-30 * time.Minute), CompletedAt: timePtr(time.Now().UTC().Add(-10 * time.Minute))}
	_ = store.CreateExecution(e2)
	s2 := assessment.BuildAssessmentSnapshot(asm, e2, []string{targetURL}, nil, false) // is_complete = false
	s2.TenantID, s2.AccountID = tenantID, accountID
	if err := store.CreateSnapshot(s2, nil, nil); err != nil {
		t.Fatalf("CreateSnapshot 2 failed: %v", err)
	}

	rec, _ := store.GetFindingLifecycle(tenantID, accountID, af.Fingerprint, authCtx)
	if rec.CurrentState != "NEW" {
		t.Fatalf("CRITICAL DEFECT: Failed assessment must NOT resolve finding, got state %q", rec.CurrentState)
	}
}

// Category 09: Cancelled Assessment Does Not Resolve Findings
func TestLifecycle_Category09_CancelledAssessmentDoesNotResolve(t *testing.T) {
	store, _, cleanup := helperNewLifecycleTestStore(t)
	defer cleanup()

	clientID, tenantID, accountID, asmID := "cli_c09", "ten_c09", "acc_c09", "asm_c09"
	targetID, targetURL := "tgt_c09", "https://api.example.com"
	_, asm, _ := helperSetupLifecycleRun(t, store, clientID, asmID, tenantID, accountID, targetID, targetURL)
	authCtx := assessment.NewTenantAuthContext(clientID, tenantID, accountID)

	af := helperMakeLifecycleFinding(asmID, "", targetID, "fnd_c09", "High Risk SSRF", "ssrf", report.SeverityHigh, report.ConfidenceHigh, string(report.VerificationVerified), targetURL, targetURL+"/api", "GET")

	// Run 1: Active
	e1 := &assessment.AssessmentExecution{ID: "e1", AssessmentID: asmID, Status: assessment.StatusCompleted, StartedAt: time.Now().UTC().Add(-2 * time.Hour), CompletedAt: timePtr(time.Now().UTC().Add(-1 * time.Hour))}
	_ = store.CreateExecution(e1)
	af.ExecutionID = e1.ID
	s1 := assessment.BuildAssessmentSnapshot(asm, e1, []string{targetURL}, []assessment.AssessmentFinding{af}, true)
	s1.TenantID, s1.AccountID = tenantID, accountID
	_ = store.CreateSnapshot(s1, []assessment.AssessmentFinding{af}, nil)

	// Run 2: Cancelled
	e2 := &assessment.AssessmentExecution{ID: "e2", AssessmentID: asmID, Status: assessment.StatusCancelled, StartedAt: time.Now().UTC().Add(-30 * time.Minute), CompletedAt: timePtr(time.Now().UTC().Add(-20 * time.Minute))}
	_ = store.CreateExecution(e2)
	s2 := assessment.BuildAssessmentSnapshot(asm, e2, []string{targetURL}, nil, false)
	s2.TenantID, s2.AccountID = tenantID, accountID
	_ = store.CreateSnapshot(s2, nil, nil)

	rec, _ := store.GetFindingLifecycle(tenantID, accountID, af.Fingerprint, authCtx)
	if rec.CurrentState != "NEW" {
		t.Fatalf("CRITICAL DEFECT: Cancelled assessment must NOT resolve finding, got state %q", rec.CurrentState)
	}
}

// Category 10: Partial or Incomplete Assessment (is_complete = false) Does Not Resolve Findings
func TestLifecycle_Category10_PartialIncompleteAssessmentDoesNotResolve(t *testing.T) {
	store, _, cleanup := helperNewLifecycleTestStore(t)
	defer cleanup()

	clientID, tenantID, accountID, asmID := "cli_c10", "ten_c10", "acc_c10", "asm_c10"
	targetID, targetURL := "tgt_c10", "https://api.example.com"
	_, asm, _ := helperSetupLifecycleRun(t, store, clientID, asmID, tenantID, accountID, targetID, targetURL)
	authCtx := assessment.NewTenantAuthContext(clientID, tenantID, accountID)

	af := helperMakeLifecycleFinding(asmID, "", targetID, "fnd_c10", "CORS Wildcard", "cors", report.SeverityMedium, report.ConfidenceHigh, string(report.VerificationVerified), targetURL, targetURL+"/api", "GET")

	// Run 1: Active
	e1 := &assessment.AssessmentExecution{ID: "e1", AssessmentID: asmID, Status: assessment.StatusCompleted, StartedAt: time.Now().UTC().Add(-2 * time.Hour), CompletedAt: timePtr(time.Now().UTC().Add(-1 * time.Hour))}
	_ = store.CreateExecution(e1)
	af.ExecutionID = e1.ID
	s1 := assessment.BuildAssessmentSnapshot(asm, e1, []string{targetURL}, []assessment.AssessmentFinding{af}, true)
	s1.TenantID, s1.AccountID = tenantID, accountID
	_ = store.CreateSnapshot(s1, []assessment.AssessmentFinding{af}, nil)

	// Run 2: Execution was marked StatusCompleted, but is_complete was false (e.g. rate limit cutoff or aborted early)
	e2 := &assessment.AssessmentExecution{ID: "e2", AssessmentID: asmID, Status: assessment.StatusCompleted, StartedAt: time.Now().UTC().Add(-30 * time.Minute), CompletedAt: timePtr(time.Now().UTC().Add(-20 * time.Minute))}
	_ = store.CreateExecution(e2)
	s2 := assessment.BuildAssessmentSnapshot(asm, e2, []string{targetURL}, nil, false) // isComplete = false
	s2.TenantID, s2.AccountID = tenantID, accountID
	_ = store.CreateSnapshot(s2, nil, nil)

	rec, _ := store.GetFindingLifecycle(tenantID, accountID, af.Fingerprint, authCtx)
	if rec.CurrentState != "NEW" {
		t.Fatalf("CRITICAL DEFECT: Incomplete snapshot must NOT resolve finding, got state %q", rec.CurrentState)
	}
}

// Category 11: Out-of-Scope Target Does Not Resolve Its Findings
func TestLifecycle_Category11_OutOfScopeTargetDoesNotResolve(t *testing.T) {
	store, _, cleanup := helperNewLifecycleTestStore(t)
	defer cleanup()

	clientID, tenantID, accountID, asmID := "cli_c11", "ten_c11", "acc_c11", "asm_c11"
	targetA := "https://app.example.com"
	targetB := "https://admin.example.com"

	_, asm, _ := helperSetupLifecycleRun(t, store, clientID, asmID, tenantID, accountID, "tgt_a", targetA)
	helperSeedTarget(t, store, asmID, "tgt_b", targetB)
	authCtx := assessment.NewTenantAuthContext(clientID, tenantID, accountID)

	// Run 1: Audits target B and finds vulnerability on target B
	afB := helperMakeLifecycleFinding(asmID, "", "tgt_b", "fnd_b", "Admin Bypass", "auth-bypass", report.SeverityCritical, report.ConfidenceHigh, string(report.VerificationVerified), targetB, targetB+"/login", "POST")
	e1 := &assessment.AssessmentExecution{ID: "e1", AssessmentID: asmID, Status: assessment.StatusCompleted, StartedAt: time.Now().UTC().Add(-2 * time.Hour), CompletedAt: timePtr(time.Now().UTC().Add(-1 * time.Hour))}
	_ = store.CreateExecution(e1)
	afB.ExecutionID = e1.ID
	s1 := assessment.BuildAssessmentSnapshot(asm, e1, []string{targetB}, []assessment.AssessmentFinding{afB}, true)
	s1.TenantID, s1.AccountID = tenantID, accountID
	_ = store.CreateSnapshot(s1, []assessment.AssessmentFinding{afB}, nil)

	// Run 2: Completed, but ONLY scopes target A (target B was NOT scanned)
	e2 := &assessment.AssessmentExecution{ID: "e2", AssessmentID: asmID, Status: assessment.StatusCompleted, StartedAt: time.Now().UTC().Add(-30 * time.Minute), CompletedAt: timePtr(time.Now().UTC().Add(-10 * time.Minute))}
	_ = store.CreateExecution(e2)
	s2 := assessment.BuildAssessmentSnapshot(asm, e2, []string{targetA}, nil, true) // ScopedTargets only has targetA
	s2.TenantID, s2.AccountID = tenantID, accountID
	if err := store.CreateSnapshot(s2, nil, nil); err != nil {
		t.Fatalf("CreateSnapshot 2 failed: %v", err)
	}

	// Finding on target B must NOT be marked resolved because target B was out of scope!
	recB, _ := store.GetFindingLifecycle(tenantID, accountID, afB.Fingerprint, authCtx)
	if recB.CurrentState != "NEW" {
		t.Fatalf("CRITICAL DEFECT: Finding on unscanned target B was falsely marked %q instead of remaining NEW", recB.CurrentState)
	}
}

// Category 12: Multi-Target Footprint Partial Rescan Does Not Resolve Finding
func TestLifecycle_Category12_MultiTargetFootprintPartialScanDoesNotResolve(t *testing.T) {
	store, _, cleanup := helperNewLifecycleTestStore(t)
	defer cleanup()

	clientID, tenantID, accountID, asmID := "cli_c12", "ten_c12", "acc_c12", "asm_c12"
	targetA := "https://a.example.com"
	targetB := "https://b.example.com"

	_, asm, _ := helperSetupLifecycleRun(t, store, clientID, asmID, tenantID, accountID, "tgt_a", targetA)
	helperSeedTarget(t, store, asmID, "tgt_b", targetB)
	authCtx := assessment.NewTenantAuthContext(clientID, tenantID, accountID)

	// Finding affects both target A and target B (from multi-target deduplication)
	af := helperMakeLifecycleFinding(asmID, "", "tgt_a", "fnd_shared", "Shared API Key Exposure", "secrets", report.SeverityHigh, report.ConfidenceHigh, string(report.VerificationVerified), targetA, targetA+"/config", "GET")
	af.EvidenceDetails.Details["associated_targets"] = targetA + ", " + targetB

	e1 := &assessment.AssessmentExecution{ID: "e1", AssessmentID: asmID, Status: assessment.StatusCompleted, StartedAt: time.Now().UTC().Add(-2 * time.Hour), CompletedAt: timePtr(time.Now().UTC().Add(-1 * time.Hour))}
	_ = store.CreateExecution(e1)
	af.ExecutionID = e1.ID
	s1 := assessment.BuildAssessmentSnapshot(asm, e1, []string{targetA, targetB}, []assessment.AssessmentFinding{af}, true)
	s1.TenantID, s1.AccountID = tenantID, accountID
	_ = store.CreateSnapshot(s1, []assessment.AssessmentFinding{af}, nil)

	// Run 2: Only target A is rescanned! Target B is omitted from scope.
	// Cross-assessment comparison via CompareSnapshots should categorize finding as UNASSESSED.
	e2 := &assessment.AssessmentExecution{ID: "e2", AssessmentID: asmID, Status: assessment.StatusCompleted, StartedAt: time.Now().UTC().Add(-30 * time.Minute), CompletedAt: timePtr(time.Now().UTC().Add(-10 * time.Minute))}
	_ = store.CreateExecution(e2)
	s2 := assessment.BuildAssessmentSnapshot(asm, e2, []string{targetA}, nil, true)
	s2.TenantID, s2.AccountID = tenantID, accountID
	_ = store.CreateSnapshot(s2, nil, nil)

	comp, err := store.CompareSnapshots(s1.ID, s2.ID, authCtx)
	if err != nil {
		t.Fatalf("CompareSnapshots failed: %v", err)
	}

	if comp.ResolvedCount != 0 {
		t.Fatalf("CRITICAL DEFECT: Multi-target finding must NOT be marked resolved when only Target A was rescanned! Got ResolvedCount=%d", comp.ResolvedCount)
	}
	if comp.UnassessedCount != 1 {
		t.Fatalf("Expected UnassessedCount 1, got %d", comp.UnassessedCount)
	}
}

// Category 13: Detector/Check Adequacy (ScopedCategories) Prevents False Resolution
func TestLifecycle_Category13_ScopedCategoriesCheckAdequacy(t *testing.T) {
	// If a scan only executed crawler checks, api-sec checks must remain UNASSESSED
	fBase := report.Finding{
		ID:          "fnd_apisec",
		Category:    "bola",
		Title:       "BOLA Vulnerability",
		Severity:    report.SeverityHigh,
		Target:      "https://api.example.com",
		Endpoint:    "https://api.example.com/v1/users",
		Fingerprint: "fp_bola_test",
	}

	// Case 1: Assessment ran without bola category evaluated
	optsCrawlerOnly := correlation.ComparisonOptions{
		CurrentCompleted: true,
		ScopedTargets:    []string{"https://api.example.com"},
		ScopedCategories: []string{"crawler", "headers"}, // bola NOT run!
	}
	cmp1 := correlation.CompareFindingsWithOptions([]report.Finding{fBase}, nil, optsCrawlerOnly)
	if cmp1.ResolvedCount != 0 || cmp1.UnassessedCount != 1 {
		t.Fatalf("Expected UNASSESSED when check category was omitted, got resolved=%d unassessed=%d", cmp1.ResolvedCount, cmp1.UnassessedCount)
	}

	// Case 2: Assessment ran with bola category evaluated
	optsWithBola := correlation.ComparisonOptions{
		CurrentCompleted: true,
		ScopedTargets:    []string{"https://api.example.com"},
		ScopedCategories: []string{"crawler", "bola"},
	}
	cmp2 := correlation.CompareFindingsWithOptions([]report.Finding{fBase}, nil, optsWithBola)
	if cmp2.ResolvedCount != 1 || cmp2.UnassessedCount != 0 {
		t.Fatalf("Expected RESOLVED when check category was evaluated, got resolved=%d unassessed=%d", cmp2.ResolvedCount, cmp2.UnassessedCount)
	}
}

// Category 14: Mutable Attribute Changes Preserve Finding Identity
func TestLifecycle_Category14_MutableAttributeChangesPreserveFindingIdentity(t *testing.T) {
	store, _, cleanup := helperNewLifecycleTestStore(t)
	defer cleanup()

	clientID, tenantID, accountID, asmID := "cli_c14", "ten_c14", "acc_c14", "asm_c14"
	targetID, targetURL := "tgt_c14", "https://api.example.com"
	_, asm, _ := helperSetupLifecycleRun(t, store, clientID, asmID, tenantID, accountID, targetID, targetURL)
	authCtx := assessment.NewTenantAuthContext(clientID, tenantID, accountID)

	// Run 1: Initial discovery
	af1 := helperMakeLifecycleFinding(asmID, "", targetID, "fnd_c14_run1", "SQL Injection Candidate", "sqli", report.SeverityHigh, report.ConfidenceMedium, string(report.VerificationObserved), targetURL, targetURL+"/search", "GET")
	fpOriginal := af1.Fingerprint

	e1 := &assessment.AssessmentExecution{ID: "e1", AssessmentID: asmID, Status: assessment.StatusCompleted, StartedAt: time.Now().UTC().Add(-2 * time.Hour), CompletedAt: timePtr(time.Now().UTC().Add(-1 * time.Hour))}
	_ = store.CreateExecution(e1)
	af1.ExecutionID = e1.ID
	s1 := assessment.BuildAssessmentSnapshot(asm, e1, []string{targetURL}, []assessment.AssessmentFinding{af1}, true)
	s1.TenantID, s1.AccountID = tenantID, accountID
	_ = store.CreateSnapshot(s1, []assessment.AssessmentFinding{af1}, nil)

	// Run 2: Title changed, Severity upgraded to Critical, Score increased, Remediation updated
	af2 := helperMakeLifecycleFinding(asmID, "", targetID, "fnd_c14_run2", "Critical Verified SQL Injection in Search API", "sqli", report.SeverityCritical, report.ConfidenceHigh, string(report.VerificationVerified), targetURL, targetURL+"/search", "GET")
	af2.Fingerprint = fpOriginal // Canonical fingerprint remains identical
	af2.Remediation = "Use parameterized queries immediately"
	af2.Score = 40

	e2 := &assessment.AssessmentExecution{ID: "e2", AssessmentID: asmID, Status: assessment.StatusCompleted, StartedAt: time.Now().UTC().Add(-30 * time.Minute), CompletedAt: timePtr(time.Now().UTC().Add(-10 * time.Minute))}
	_ = store.CreateExecution(e2)
	af2.ExecutionID = e2.ID
	s2 := assessment.BuildAssessmentSnapshot(asm, e2, []string{targetURL}, []assessment.AssessmentFinding{af2}, true)
	s2.TenantID, s2.AccountID = tenantID, accountID
	if err := store.CreateSnapshot(s2, []assessment.AssessmentFinding{af2}, nil); err != nil {
		t.Fatalf("CreateSnapshot 2 failed: %v", err)
	}

	// Must transition to ACTIVE, not create a duplicate or reset first_observed_at
	rec, err := store.GetFindingLifecycle(tenantID, accountID, fpOriginal, authCtx)
	if err != nil {
		t.Fatalf("GetFindingLifecycle failed: %v", err)
	}
	if rec.CurrentState != "ACTIVE" {
		t.Fatalf("Expected ACTIVE state, got %q", rec.CurrentState)
	}
	if rec.Severity != report.SeverityCritical {
		t.Fatalf("Expected updated severity CRITICAL, got %q", rec.Severity)
	}
	if rec.Title != "Critical Verified SQL Injection in Search API" {
		t.Fatalf("Expected updated title, got %q", rec.Title)
	}

	// Total unique lifecycle records for tenant must be exactly 1
	list, count, err := store.ListFindingLifecycles(assessment.FindingLifecycleListOptions{Auth: authCtx})
	if err != nil || count != 1 || len(list) != 1 {
		t.Fatalf("Expected exactly 1 lifecycle record, got count=%d, len=%d", count, len(list))
	}
}

// -----------------------------------------------------------------------------
// 3. IDENTITY AND TENANT ISOLATION
// -----------------------------------------------------------------------------

// Category 15: Cross-Tenant and Cross-Account Findings Never Share Lifecycle State
func TestLifecycle_Category15_CrossTenantAndCrossAccountIsolationEnforced(t *testing.T) {
	store, _, cleanup := helperNewLifecycleTestStore(t)
	defer cleanup()

	targetURL := "https://shared-saas.example.com"

	// Tenant Alpha
	clientA, asmA, _ := helperSetupLifecycleRun(t, store, "cli_alpha", "asm_alpha", "ten_alpha", "acc_alpha", "tgt_alpha", targetURL)
	authA := assessment.NewTenantAuthContext(clientA.ID, "ten_alpha", "acc_alpha")

	// Tenant Beta
	clientB, asmB, _ := helperSetupLifecycleRun(t, store, "cli_beta", "asm_beta", "ten_beta", "acc_beta", "tgt_beta", targetURL)
	authB := assessment.NewTenantAuthContext(clientB.ID, "ten_beta", "acc_beta")

	// Same endpoint and vulnerability pattern on both tenants
	afA := helperMakeLifecycleFinding(asmA.ID, "", "tgt_alpha", "f_alpha", "BOLA Endpoint", "bola", report.SeverityHigh, report.ConfidenceHigh, string(report.VerificationVerified), targetURL, targetURL+"/api", "GET")
	afB := helperMakeLifecycleFinding(asmB.ID, "", "tgt_beta", "f_beta", "BOLA Endpoint", "bola", report.SeverityHigh, report.ConfidenceHigh, string(report.VerificationVerified), targetURL, targetURL+"/api", "GET")

	// Run on Tenant Alpha (Active)
	eA := &assessment.AssessmentExecution{ID: "e_alpha", AssessmentID: asmA.ID, Status: assessment.StatusCompleted, StartedAt: time.Now().UTC().Add(-time.Hour), CompletedAt: timePtr(time.Now().UTC().Add(-40 * time.Minute))}
	_ = store.CreateExecution(eA)
	afA.ExecutionID = eA.ID
	sA := assessment.BuildAssessmentSnapshot(asmA, eA, []string{targetURL}, []assessment.AssessmentFinding{afA}, true)
	sA.TenantID, sA.AccountID = "ten_alpha", "acc_alpha"
	_ = store.CreateSnapshot(sA, []assessment.AssessmentFinding{afA}, nil)

	// Run on Tenant Beta (Active) then Resolved
	eB1 := &assessment.AssessmentExecution{ID: "e_beta_1", AssessmentID: asmB.ID, Status: assessment.StatusCompleted, StartedAt: time.Now().UTC().Add(-time.Hour), CompletedAt: timePtr(time.Now().UTC().Add(-40 * time.Minute))}
	_ = store.CreateExecution(eB1)
	afB.ExecutionID = eB1.ID
	sB1 := assessment.BuildAssessmentSnapshot(asmB, eB1, []string{targetURL}, []assessment.AssessmentFinding{afB}, true)
	sB1.TenantID, sB1.AccountID = "ten_beta", "acc_beta"
	_ = store.CreateSnapshot(sB1, []assessment.AssessmentFinding{afB}, nil)

	// Tenant Beta resolves its finding!
	eB2 := &assessment.AssessmentExecution{ID: "e_beta_2", AssessmentID: asmB.ID, Status: assessment.StatusCompleted, StartedAt: time.Now().UTC().Add(-20 * time.Minute), CompletedAt: timePtr(time.Now().UTC().Add(-5 * time.Minute))}
	_ = store.CreateExecution(eB2)
	sB2 := assessment.BuildAssessmentSnapshot(asmB, eB2, []string{targetURL}, nil, true)
	sB2.TenantID, sB2.AccountID = "ten_beta", "acc_beta"
	_ = store.CreateSnapshot(sB2, nil, nil)

	// Verify Tenant Alpha finding is still NEW (not resolved!)
	recA, err := store.GetFindingLifecycle("ten_alpha", "acc_alpha", afA.Fingerprint, authA)
	if err != nil || recA.CurrentState != "NEW" {
		t.Fatalf("Tenant Alpha finding must remain NEW, got state %q, err=%v", recA.CurrentState, err)
	}

	// Verify Tenant Beta finding is RESOLVED
	recB, err := store.GetFindingLifecycle("ten_beta", "acc_beta", afB.Fingerprint, authB)
	if err != nil || recB.CurrentState != "RESOLVED" {
		t.Fatalf("Tenant Beta finding must be RESOLVED, got state %q, err=%v", recB.CurrentState, err)
	}

	// Verify Tenant Alpha CANNOT read Tenant Beta lifecycle
	if _, err := store.GetFindingLifecycle("ten_beta", "acc_beta", afB.Fingerprint, authA); err == nil {
		t.Fatalf("CRITICAL SECURITY DEFECT: Cross-tenant lifecycle read must fail closed!")
	}
}

// -----------------------------------------------------------------------------
// 4. PERSISTENCE AND RELIABILITY
// -----------------------------------------------------------------------------

// Category 16: Lifecycle Survives Database Close and Reopen
func TestLifecycle_Category16_LifecycleSurvivesDatabaseCloseReopen(t *testing.T) {
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "close_reopen_lifecycle.db")

	store1, err := assessment.NewSQLiteStore(dbPath)
	if err != nil {
		t.Fatalf("failed to open store1: %v", err)
	}

	clientID, tenantID, accountID, asmID := "cli_c16", "ten_c16", "acc_c16", "asm_c16"
	targetID, targetURL := "tgt_c16", "https://api.example.com"
	_, asm, _ := helperSetupLifecycleRun(t, store1, clientID, asmID, tenantID, accountID, targetID, targetURL)
	authCtx := assessment.NewTenantAuthContext(clientID, tenantID, accountID)

	af := helperMakeLifecycleFinding(asmID, "", targetID, "fnd_c16", "CSRF Token Missing", "csrf", report.SeverityMedium, report.ConfidenceHigh, string(report.VerificationVerified), targetURL, targetURL+"/profile", "POST")
	e1 := &assessment.AssessmentExecution{ID: "e1", AssessmentID: asmID, Status: assessment.StatusCompleted, StartedAt: time.Now().UTC().Add(-time.Hour), CompletedAt: timePtr(time.Now().UTC().Add(-30 * time.Minute))}
	_ = store1.CreateExecution(e1)
	af.ExecutionID = e1.ID
	s1 := assessment.BuildAssessmentSnapshot(asm, e1, []string{targetURL}, []assessment.AssessmentFinding{af}, true)
	s1.TenantID, s1.AccountID = tenantID, accountID
	_ = store1.CreateSnapshot(s1, []assessment.AssessmentFinding{af}, nil)

	// Close database
	if err := store1.Close(); err != nil {
		t.Fatalf("failed to close store1: %v", err)
	}

	// Reopen database
	store2, err := assessment.NewSQLiteStore(dbPath)
	if err != nil {
		t.Fatalf("failed to reopen store2: %v", err)
	}
	defer store2.Close()

	rec, err := store2.GetFindingLifecycle(tenantID, accountID, af.Fingerprint, authCtx)
	if err != nil {
		t.Fatalf("GetFindingLifecycle on reopened store failed: %v", err)
	}
	if rec.CurrentState != "NEW" || rec.Title != "CSRF Token Missing" {
		t.Fatalf("Data mismatch on reopened store: %+v", rec)
	}

	events, err := store2.GetFindingLifecycleEvents(af.Fingerprint, authCtx)
	if err != nil || len(events) != 1 {
		t.Fatalf("Events failed on reopened store: len=%d, err=%v", len(events), err)
	}
}

// Category 17: Reprocessing Same Execution is Idempotent (No Duplicate Events)
func TestLifecycle_Category17_ReprocessingExecutionIsIdempotent(t *testing.T) {
	store, _, cleanup := helperNewLifecycleTestStore(t)
	defer cleanup()

	clientID, tenantID, accountID, asmID := "cli_c17", "ten_c17", "acc_c17", "asm_c17"
	targetID, targetURL := "tgt_c17", "https://api.example.com"
	_, asm, _ := helperSetupLifecycleRun(t, store, clientID, asmID, tenantID, accountID, targetID, targetURL)
	authCtx := assessment.NewTenantAuthContext(clientID, tenantID, accountID)

	af := helperMakeLifecycleFinding(asmID, "", targetID, "fnd_c17", "Command Injection", "cmdi", report.SeverityCritical, report.ConfidenceHigh, string(report.VerificationVerified), targetURL, targetURL+"/ping", "POST")
	e1 := &assessment.AssessmentExecution{ID: "e1", AssessmentID: asmID, Status: assessment.StatusCompleted, StartedAt: time.Now().UTC().Add(-time.Hour), CompletedAt: timePtr(time.Now().UTC().Add(-30 * time.Minute))}
	_ = store.CreateExecution(e1)
	af.ExecutionID = e1.ID
	s1 := assessment.BuildAssessmentSnapshot(asm, e1, []string{targetURL}, []assessment.AssessmentFinding{af}, true)
	s1.TenantID, s1.AccountID = tenantID, accountID

	// First attempt
	if err := store.CreateSnapshot(s1, []assessment.AssessmentFinding{af}, nil); err != nil {
		t.Fatalf("First CreateSnapshot failed: %v", err)
	}

	// Identical retry for same execution ID
	if err := store.CreateSnapshot(s1, []assessment.AssessmentFinding{af}, nil); err != nil {
		t.Fatalf("Identical retry CreateSnapshot should succeed idempotently, got: %v", err)
	}

	// Verify events count: must remain exactly 1 event (no duplicate event emitted!)
	events, err := store.GetFindingLifecycleEvents(af.Fingerprint, authCtx)
	if err != nil {
		t.Fatalf("GetFindingLifecycleEvents failed: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("CRITICAL DEFECT: Idempotent snapshot retry created duplicate events! Expected 1, got %d", len(events))
	}
}

// Category 18: Conflicting Retries Rejected with ErrSnapshotImmutable
func TestLifecycle_Category18_ConflictingRetriesRejectedWithErrSnapshotImmutable(t *testing.T) {
	store, _, cleanup := helperNewLifecycleTestStore(t)
	defer cleanup()

	clientID, tenantID, accountID, asmID := "cli_c18", "ten_c18", "acc_c18", "asm_c18"
	targetID, targetURL := "tgt_c18", "https://api.example.com"
	_, asm, _ := helperSetupLifecycleRun(t, store, clientID, asmID, tenantID, accountID, targetID, targetURL)

	af := helperMakeLifecycleFinding(asmID, "", targetID, "fnd_c18", "JWT Alg None", "jwt", report.SeverityHigh, report.ConfidenceHigh, string(report.VerificationVerified), targetURL, targetURL+"/auth", "POST")
	e1 := &assessment.AssessmentExecution{ID: "e1", AssessmentID: asmID, Status: assessment.StatusCompleted, StartedAt: time.Now().UTC().Add(-time.Hour), CompletedAt: timePtr(time.Now().UTC().Add(-30 * time.Minute))}
	_ = store.CreateExecution(e1)
	af.ExecutionID = e1.ID
	s1 := assessment.BuildAssessmentSnapshot(asm, e1, []string{targetURL}, []assessment.AssessmentFinding{af}, true)
	s1.TenantID, s1.AccountID = tenantID, accountID

	if err := store.CreateSnapshot(s1, []assessment.AssessmentFinding{af}, nil); err != nil {
		t.Fatalf("Initial snapshot failed: %v", err)
	}

	// Conflicting retry: different status
	s1Conf := *s1
	s1Conf.Status = assessment.StatusFailed
	if err := store.CreateSnapshot(&s1Conf, []assessment.AssessmentFinding{af}, nil); err != assessment.ErrSnapshotImmutable {
		t.Fatalf("Expected ErrSnapshotImmutable on conflicting retry, got: %v", err)
	}
}

// Category 19: Database Migration from V17 to V18 Preserves All Existing Data
func TestLifecycle_Category19_DatabaseMigrationV17ToV18PreservesData(t *testing.T) {
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "migration_v17_v18.db")

	// 1. Setup raw database with tables up to v17
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("failed to open raw sqlite: %v", err)
	}
	defer db.Close()

	// Create schema_migrations at version 17
	_, err = db.Exec(`
		CREATE TABLE schema_migrations (
			version INTEGER PRIMARY KEY,
			applied_at TIMESTAMP NOT NULL
		);
		INSERT INTO schema_migrations (version, applied_at) VALUES (17, CURRENT_TIMESTAMP);

		CREATE TABLE clients (
			id TEXT PRIMARY KEY,
			name TEXT NOT NULL,
			created_at TIMESTAMP NOT NULL,
			updated_at TIMESTAMP NOT NULL,
			archived INTEGER NOT NULL DEFAULT 0
		);

		CREATE TABLE assessments (
			id TEXT PRIMARY KEY,
			ref TEXT UNIQUE NOT NULL,
			client_id TEXT NOT NULL,
			name TEXT NOT NULL,
			assessment_type TEXT NOT NULL,
			status TEXT NOT NULL,
			created_at TIMESTAMP NOT NULL,
			updated_at TIMESTAMP NOT NULL,
			scope_mode TEXT NOT NULL DEFAULT 'same-origin',
			finding_count INTEGER NOT NULL DEFAULT 0
		);

		CREATE TABLE assessment_executions (
			id TEXT PRIMARY KEY,
			assessment_id TEXT NOT NULL,
			status TEXT NOT NULL,
			started_at TIMESTAMP NOT NULL,
			config_snapshot TEXT NOT NULL
		);

		CREATE TABLE assessment_snapshots (
			id TEXT PRIMARY KEY,
			snapshot_ref TEXT UNIQUE NOT NULL,
			assessment_id TEXT NOT NULL,
			execution_id TEXT UNIQUE NOT NULL,
			client_id TEXT NOT NULL,
			tenant_id TEXT,
			account_id TEXT,
			name TEXT NOT NULL,
			assessment_type TEXT NOT NULL,
			status TEXT NOT NULL,
			is_complete INTEGER NOT NULL DEFAULT 1,
			started_at TIMESTAMP NOT NULL,
			completed_at TIMESTAMP,
			duration_ms INTEGER NOT NULL DEFAULT 0,
			request_count INTEGER NOT NULL DEFAULT 0,
			target_count INTEGER NOT NULL DEFAULT 0,
			finding_count INTEGER NOT NULL DEFAULT 0,
			scope_mode TEXT NOT NULL DEFAULT 'same-origin',
			scoped_targets_json TEXT NOT NULL DEFAULT '[]',
			config_snapshot_json TEXT NOT NULL DEFAULT '{}',
			metadata_json TEXT NOT NULL DEFAULT '{}',
			created_at TIMESTAMP NOT NULL
		);

		INSERT INTO clients (id, name, created_at, updated_at) VALUES ('c_mig', 'Migration Client', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP);
		INSERT INTO assessments (id, ref, client_id, name, assessment_type, status, created_at, updated_at)
		VALUES ('asm_mig', 'ASM-MIG', 'c_mig', 'Mig Assessment', 'BLACK_BOX_WEB', 'COMPLETED', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP);
		INSERT INTO assessment_executions (id, assessment_id, status, started_at, config_snapshot)
		VALUES ('exec_mig', 'asm_mig', 'COMPLETED', CURRENT_TIMESTAMP, '{}');
		INSERT INTO assessment_snapshots (id, snapshot_ref, assessment_id, execution_id, client_id, name, assessment_type, status, started_at, created_at)
		VALUES ('snp_mig', 'SNP-MIG', 'asm_mig', 'exec_mig', 'c_mig', 'Mig Snap', 'BLACK_BOX_WEB', 'COMPLETED', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP);
	`)
	if err != nil {
		t.Fatalf("failed inserting raw v17 schema: %v", err)
	}
	db.Close()

	// 2. Open with NewSQLiteStore which will trigger migration 18
	store, err := assessment.NewSQLiteStore(dbPath)
	if err != nil {
		t.Fatalf("NewSQLiteStore failed to run migration v18: %v", err)
	}
	defer store.Close()

	// Verify pre-existing snapshot survived
	auth := assessment.NewClientAuthContext("c_mig")
	snap, err := store.GetSnapshot("snp_mig", auth)
	if err != nil || snap == nil || snap.SnapshotRef != "SNP-MIG" {
		t.Fatalf("Pre-existing snapshot lost or corrupted: snap=%+v, err=%v", snap, err)
	}

	// Verify new tables created by v18 are queryable
	list, count, err := store.ListFindingLifecycles(assessment.FindingLifecycleListOptions{Auth: assessment.NewAdminAuthContext()})
	if err != nil {
		t.Fatalf("ListFindingLifecycles failed on migrated db: %v", err)
	}
	if count != 0 || len(list) != 0 {
		t.Fatalf("Expected 0 initial lifecycles on newly migrated db, got %d", count)
	}
}

// Category 20: ListFindingLifecycles Supports Filtering and Pagination
func TestLifecycle_Category20_ListFindingLifecyclesFilteringAndPagination(t *testing.T) {
	store, _, cleanup := helperNewLifecycleTestStore(t)
	defer cleanup()

	clientID, tenantID, accountID, asmID := "cli_c20", "ten_c20", "acc_c20", "asm_c20"
	targetID, targetURL := "tgt_c20", "https://api.example.com"
	_, asm, _ := helperSetupLifecycleRun(t, store, clientID, asmID, tenantID, accountID, targetID, targetURL)
	authCtx := assessment.NewTenantAuthContext(clientID, tenantID, accountID)

	// Create 5 distinct findings
	var findings []assessment.AssessmentFinding
	for i := 1; i <= 5; i++ {
		af := helperMakeLifecycleFinding(
			asmID,
			"e1",
			targetID,
			fmt.Sprintf("fnd_%d", i),
			fmt.Sprintf("Vulnerability %d", i),
			fmt.Sprintf("rule_%d", i),
			report.SeverityMedium,
			report.ConfidenceHigh,
			string(report.VerificationVerified),
			targetURL,
			fmt.Sprintf("%s/api/%d", targetURL, i),
			"GET",
		)
		findings = append(findings, af)
	}

	e1 := &assessment.AssessmentExecution{ID: "e1", AssessmentID: asmID, Status: assessment.StatusCompleted, StartedAt: time.Now().UTC().Add(-time.Hour), CompletedAt: timePtr(time.Now().UTC().Add(-30 * time.Minute))}
	_ = store.CreateExecution(e1)
	s1 := assessment.BuildAssessmentSnapshot(asm, e1, []string{targetURL}, findings, true)
	s1.TenantID, s1.AccountID = tenantID, accountID
	_ = store.CreateSnapshot(s1, findings, nil)

	// Test pagination: Limit 2, Offset 0
	p1, total, err := store.ListFindingLifecycles(assessment.FindingLifecycleListOptions{
		Auth:   authCtx,
		Limit:  2,
		Offset: 0,
	})
	if err != nil || total != 5 || len(p1) != 2 {
		t.Fatalf("Page 1 failed: total=%d, len=%d, err=%v", total, len(p1), err)
	}

	// Test pagination: Limit 2, Offset 2
	p2, total2, err := store.ListFindingLifecycles(assessment.FindingLifecycleListOptions{
		Auth:   authCtx,
		Limit:  2,
		Offset: 2,
	})
	if err != nil || total2 != 5 || len(p2) != 2 {
		t.Fatalf("Page 2 failed: total=%d, len=%d, err=%v", total2, len(p2), err)
	}

	// Test filter by CurrentState
	pNew, totalNew, err := store.ListFindingLifecycles(assessment.FindingLifecycleListOptions{
		Auth:         authCtx,
		CurrentState: "NEW",
	})
	if err != nil || totalNew != 5 || len(pNew) != 5 {
		t.Fatalf("Filter NEW failed: total=%d, len=%d, err=%v", totalNew, len(pNew), err)
	}

	pResolved, totalRes, err := store.ListFindingLifecycles(assessment.FindingLifecycleListOptions{
		Auth:         authCtx,
		CurrentState: "RESOLVED",
	})
	if err != nil || totalRes != 0 || len(pResolved) != 0 {
		t.Fatalf("Filter RESOLVED should return 0, got total=%d, len=%d", totalRes, len(pResolved))
	}
}
