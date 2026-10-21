package test

import (
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
// PHASE 6.7: INCOMPLETE ASSESSMENT HANDLING REGRESSION TEST SUITE
// Validates that incomplete, cancelled, failed, partial, timed-out, or
// out-of-coverage assessments never falsely mark findings as RESOLVED.
// =============================================================================

func helperNewIncompleteTestStore(t *testing.T) (assessment.Store, string, func()) {
	t.Helper()
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, fmt.Sprintf("test_incomplete_%d.db", time.Now().UnixNano()))
	store, err := assessment.NewSQLiteStore(dbPath)
	if err != nil {
		t.Fatalf("failed to create sqlite store: %v", err)
	}
	cleanup := func() {
		_ = store.Close()
	}
	return store, dbPath, cleanup
}

func helperMakeIncompleteFinding(asmID, execID, targetID, id, title, ruleID, severity, conf, verStatus, targetURL, endpoint, method string) assessment.AssessmentFinding {
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
// SECTION A: EXECUTION OUTCOME TESTS
// -----------------------------------------------------------------------------

// A01: Failed assessment with no findings does not resolve previous findings
func TestIncomplete_A01_FailedAssessmentDoesNotResolve(t *testing.T) {
	store, _, cleanup := helperNewIncompleteTestStore(t)
	defer cleanup()

	clientID, tenantID, accountID, asmID := "cli_a01", "ten_a01", "acc_a01", "asm_a01"
	targetURL := "https://api.example.com"
	_, asm, _ := helperSetupLifecycleRun(t, store, clientID, asmID, tenantID, accountID, "tgt_a01", targetURL)
	authCtx := assessment.NewTenantAuthContext(clientID, tenantID, accountID)

	// Run 1: Normal completed scan finds critical SQLi
	e1 := &assessment.AssessmentExecution{ID: "e1", AssessmentID: asmID, Status: assessment.StatusCompleted, StartedAt: time.Now().UTC().Add(-2 * time.Hour), CompletedAt: timePtr(time.Now().UTC().Add(-1 * time.Hour))}
	_ = store.CreateExecution(e1)
	af1 := helperMakeIncompleteFinding(asmID, e1.ID, "tgt_a01", "fnd_a01_1", "SQL Injection", "sqli", report.SeverityCritical, report.ConfidenceHigh, string(report.VerificationVerified), targetURL, targetURL+"/users", "GET")
	s1 := assessment.BuildAssessmentSnapshot(asm, e1, []string{targetURL}, []assessment.AssessmentFinding{af1}, true)
	s1.TenantID, s1.AccountID = tenantID, accountID
	if err := store.CreateSnapshot(s1, []assessment.AssessmentFinding{af1}, nil); err != nil {
		t.Fatalf("CreateSnapshot 1 failed: %v", err)
	}

	// Verify state is NEW
	rec, _ := store.GetFindingLifecycle(tenantID, accountID, af1.Fingerprint, authCtx)
	if rec.CurrentState != "NEW" {
		t.Fatalf("Expected NEW after run 1, got %q", rec.CurrentState)
	}

	// Run 2: Assessment FAILED (e.g. fatal runtime error, abort) with 0 findings
	e2 := &assessment.AssessmentExecution{ID: "e2", AssessmentID: asmID, Status: assessment.StatusFailed, ErrorMessage: "Engine crashed unexpectedly", StartedAt: time.Now().UTC().Add(-30 * time.Minute), CompletedAt: timePtr(time.Now().UTC().Add(-10 * time.Minute))}
	_ = store.CreateExecution(e2)
	s2 := assessment.BuildAssessmentSnapshot(asm, e2, []string{targetURL}, nil, false)
	s2.TenantID, s2.AccountID = tenantID, accountID
	if err := store.CreateSnapshot(s2, nil, nil); err != nil {
		t.Fatalf("CreateSnapshot 2 failed: %v", err)
	}

	// Invariant: Finding MUST NOT be RESOLVED
	recAfter, _ := store.GetFindingLifecycle(tenantID, accountID, af1.Fingerprint, authCtx)
	if recAfter.CurrentState == "RESOLVED" {
		t.Fatalf("INVARIANT VIOLATION: Failed assessment falsely marked finding as RESOLVED!")
	}
	if recAfter.CurrentState != "NEW" {
		t.Fatalf("Expected state to remain NEW, got %q", recAfter.CurrentState)
	}

	// CompareSnapshots must also report UNASSESSED
	comp, err := store.CompareSnapshots(s1.ID, s2.ID, authCtx)
	if err != nil {
		t.Fatalf("CompareSnapshots failed: %v", err)
	}
	if comp.ResolvedCount != 0 {
		t.Fatalf("Expected ResolvedCount 0 in comparison, got %d", comp.ResolvedCount)
	}
	if comp.UnassessedCount != 1 {
		t.Fatalf("Expected UnassessedCount 1 in comparison, got %d", comp.UnassessedCount)
	}
}

// A02: Cancelled assessment does not resolve previous findings
func TestIncomplete_A02_CancelledAssessmentDoesNotResolve(t *testing.T) {
	store, _, cleanup := helperNewIncompleteTestStore(t)
	defer cleanup()

	clientID, tenantID, accountID, asmID := "cli_a02", "ten_a02", "acc_a02", "asm_a02"
	targetURL := "https://api.example.com"
	_, asm, _ := helperSetupLifecycleRun(t, store, clientID, asmID, tenantID, accountID, "tgt_a02", targetURL)
	authCtx := assessment.NewTenantAuthContext(clientID, tenantID, accountID)

	e1 := &assessment.AssessmentExecution{ID: "e1", AssessmentID: asmID, Status: assessment.StatusCompleted, StartedAt: time.Now().UTC().Add(-2 * time.Hour), CompletedAt: timePtr(time.Now().UTC().Add(-1 * time.Hour))}
	_ = store.CreateExecution(e1)
	af1 := helperMakeIncompleteFinding(asmID, e1.ID, "tgt_a02", "fnd_a02_1", "Remote Code Execution", "rce", report.SeverityCritical, report.ConfidenceHigh, string(report.VerificationVerified), targetURL, targetURL+"/exec", "POST")
	s1 := assessment.BuildAssessmentSnapshot(asm, e1, []string{targetURL}, []assessment.AssessmentFinding{af1}, true)
	s1.TenantID, s1.AccountID = tenantID, accountID
	_ = store.CreateSnapshot(s1, []assessment.AssessmentFinding{af1}, nil)

	// Run 2: Operator cancelled scan before completion
	e2 := &assessment.AssessmentExecution{ID: "e2", AssessmentID: asmID, Status: assessment.StatusCancelled, ErrorMessage: "Execution was cancelled by operator", StartedAt: time.Now().UTC().Add(-30 * time.Minute), CompletedAt: timePtr(time.Now().UTC().Add(-10 * time.Minute))}
	_ = store.CreateExecution(e2)
	s2 := assessment.BuildAssessmentSnapshot(asm, e2, []string{targetURL}, nil, false)
	s2.TenantID, s2.AccountID = tenantID, accountID
	_ = store.CreateSnapshot(s2, nil, nil)

	recAfter, _ := store.GetFindingLifecycle(tenantID, accountID, af1.Fingerprint, authCtx)
	if recAfter.CurrentState == "RESOLVED" {
		t.Fatalf("INVARIANT VIOLATION: Cancelled assessment falsely marked finding as RESOLVED!")
	}
	if recAfter.CurrentState != "NEW" {
		t.Fatalf("Expected state to remain NEW, got %q", recAfter.CurrentState)
	}
}

// A03: Partial assessment does not resolve previous findings without adequate coverage
func TestIncomplete_A03_PartialAssessmentDoesNotResolve(t *testing.T) {
	store, _, cleanup := helperNewIncompleteTestStore(t)
	defer cleanup()

	clientID, tenantID, accountID, asmID := "cli_a03", "ten_a03", "acc_a03", "asm_a03"
	targetURL := "https://api.example.com"
	_, asm, _ := helperSetupLifecycleRun(t, store, clientID, asmID, tenantID, accountID, "tgt_a03", targetURL)
	authCtx := assessment.NewTenantAuthContext(clientID, tenantID, accountID)

	e1 := &assessment.AssessmentExecution{ID: "e1", AssessmentID: asmID, Status: assessment.StatusCompleted, StartedAt: time.Now().UTC().Add(-2 * time.Hour), CompletedAt: timePtr(time.Now().UTC().Add(-1 * time.Hour))}
	_ = store.CreateExecution(e1)
	af1 := helperMakeIncompleteFinding(asmID, e1.ID, "tgt_a03", "fnd_a03_1", "CSRF Vulnerability", "csrf", report.SeverityMedium, report.ConfidenceHigh, string(report.VerificationVerified), targetURL, targetURL+"/transfer", "POST")
	s1 := assessment.BuildAssessmentSnapshot(asm, e1, []string{targetURL}, []assessment.AssessmentFinding{af1}, true)
	s1.TenantID, s1.AccountID = tenantID, accountID
	_ = store.CreateSnapshot(s1, []assessment.AssessmentFinding{af1}, nil)

	// Run 2: is_complete = false (partial run)
	e2 := &assessment.AssessmentExecution{ID: "e2", AssessmentID: asmID, Status: assessment.StatusCompletedWithErrors, StartedAt: time.Now().UTC().Add(-30 * time.Minute), CompletedAt: timePtr(time.Now().UTC().Add(-10 * time.Minute))}
	_ = store.CreateExecution(e2)
	s2 := assessment.BuildAssessmentSnapshot(asm, e2, []string{targetURL}, nil, false)
	s2.TenantID, s2.AccountID = tenantID, accountID
	_ = store.CreateSnapshot(s2, nil, nil)

	recAfter, _ := store.GetFindingLifecycle(tenantID, accountID, af1.Fingerprint, authCtx)
	if recAfter.CurrentState == "RESOLVED" {
		t.Fatalf("INVARIANT VIOLATION: Partial assessment (is_complete=false) falsely marked finding as RESOLVED!")
	}
}

// A04: Timeout does not resolve findings whose checks did not finish
func TestIncomplete_A04_TimeoutDoesNotResolve(t *testing.T) {
	store, _, cleanup := helperNewIncompleteTestStore(t)
	defer cleanup()

	clientID, tenantID, accountID, asmID := "cli_a04", "ten_a04", "acc_a04", "asm_a04"
	targetURL := "https://api.example.com"
	_, asm, _ := helperSetupLifecycleRun(t, store, clientID, asmID, tenantID, accountID, "tgt_a04", targetURL)
	authCtx := assessment.NewTenantAuthContext(clientID, tenantID, accountID)

	e1 := &assessment.AssessmentExecution{ID: "e1", AssessmentID: asmID, Status: assessment.StatusCompleted, StartedAt: time.Now().UTC().Add(-2 * time.Hour), CompletedAt: timePtr(time.Now().UTC().Add(-1 * time.Hour))}
	_ = store.CreateExecution(e1)
	af1 := helperMakeIncompleteFinding(asmID, e1.ID, "tgt_a04", "fnd_a04_1", "Slow SQL Injection", "sqli", report.SeverityHigh, report.ConfidenceHigh, string(report.VerificationVerified), targetURL, targetURL+"/search", "GET")
	s1 := assessment.BuildAssessmentSnapshot(asm, e1, []string{targetURL}, []assessment.AssessmentFinding{af1}, true)
	s1.TenantID, s1.AccountID = tenantID, accountID
	_ = store.CreateSnapshot(s1, []assessment.AssessmentFinding{af1}, nil)

	// Run 2: Timed out
	e2 := &assessment.AssessmentExecution{ID: "e2", AssessmentID: asmID, Status: assessment.StatusFailed, ErrorMessage: "Scan timed out: execution deadline exceeded", StartedAt: time.Now().UTC().Add(-30 * time.Minute), CompletedAt: timePtr(time.Now().UTC().Add(-10 * time.Minute))}
	_ = store.CreateExecution(e2)
	s2 := assessment.BuildAssessmentSnapshot(asm, e2, []string{targetURL}, nil, false)
	s2.TenantID, s2.AccountID = tenantID, accountID
	_ = store.CreateSnapshot(s2, nil, nil)

	recAfter, _ := store.GetFindingLifecycle(tenantID, accountID, af1.Fingerprint, authCtx)
	if recAfter.CurrentState == "RESOLVED" {
		t.Fatalf("INVARIANT VIOLATION: Timed-out assessment falsely marked finding as RESOLVED!")
	}
}

// A05: Inconsistent completion metadata fails closed
func TestIncomplete_A05_InconsistentCompletionMetadataFailsClosed(t *testing.T) {
	store, _, cleanup := helperNewIncompleteTestStore(t)
	defer cleanup()

	clientID, tenantID, accountID, asmID := "cli_a05", "ten_a05", "acc_a05", "asm_a05"
	targetURL := "https://api.example.com"
	_, asm, _ := helperSetupLifecycleRun(t, store, clientID, asmID, tenantID, accountID, "tgt_a05", targetURL)
	authCtx := assessment.NewTenantAuthContext(clientID, tenantID, accountID)

	e1 := &assessment.AssessmentExecution{ID: "e1", AssessmentID: asmID, Status: assessment.StatusCompleted, StartedAt: time.Now().UTC().Add(-2 * time.Hour), CompletedAt: timePtr(time.Now().UTC().Add(-1 * time.Hour))}
	_ = store.CreateExecution(e1)
	af1 := helperMakeIncompleteFinding(asmID, e1.ID, "tgt_a05", "fnd_a05_1", "SSRF Vulnerability", "ssrf", report.SeverityHigh, report.ConfidenceHigh, string(report.VerificationVerified), targetURL, targetURL+"/fetch", "POST")
	s1 := assessment.BuildAssessmentSnapshot(asm, e1, []string{targetURL}, []assessment.AssessmentFinding{af1}, true)
	s1.TenantID, s1.AccountID = tenantID, accountID
	_ = store.CreateSnapshot(s1, []assessment.AssessmentFinding{af1}, nil)

	// Run 2 has inconsistent metadata: IsComplete=true, BUT Status=FAILED
	e2 := &assessment.AssessmentExecution{ID: "e2", AssessmentID: asmID, Status: assessment.StatusFailed, ErrorMessage: "Fatal failure", StartedAt: time.Now().UTC().Add(-30 * time.Minute), CompletedAt: timePtr(time.Now().UTC().Add(-10 * time.Minute))}
	_ = store.CreateExecution(e2)
	s2 := assessment.BuildAssessmentSnapshot(asm, e2, []string{targetURL}, nil, false)
	s2.IsComplete = true // Inconsistent: claims complete while Status=FAILED
	s2.Status = assessment.StatusFailed
	s2.TenantID, s2.AccountID = tenantID, accountID
	_ = store.CreateSnapshot(s2, nil, nil)

	recAfter, _ := store.GetFindingLifecycle(tenantID, accountID, af1.Fingerprint, authCtx)
	if recAfter.CurrentState == "RESOLVED" {
		t.Fatalf("INVARIANT VIOLATION: Inconsistent completion metadata (IsComplete=true, Status=FAILED) falsely marked finding as RESOLVED!")
	}
}

// A06: Missing completion metadata does not imply successful assessment
func TestIncomplete_A06_MissingCompletionMetadataFailsClosed(t *testing.T) {
	store, _, cleanup := helperNewIncompleteTestStore(t)
	defer cleanup()

	clientID, tenantID, accountID, asmID := "cli_a06", "ten_a06", "acc_a06", "asm_a06"
	targetURL := "https://api.example.com"
	_, asm, _ := helperSetupLifecycleRun(t, store, clientID, asmID, tenantID, accountID, "tgt_a06", targetURL)
	authCtx := assessment.NewTenantAuthContext(clientID, tenantID, accountID)

	e1 := &assessment.AssessmentExecution{ID: "e1", AssessmentID: asmID, Status: assessment.StatusCompleted, StartedAt: time.Now().UTC().Add(-2 * time.Hour), CompletedAt: timePtr(time.Now().UTC().Add(-1 * time.Hour))}
	_ = store.CreateExecution(e1)
	af1 := helperMakeIncompleteFinding(asmID, e1.ID, "tgt_a06", "fnd_a06_1", "JWT Secret Exposure", "jwt", report.SeverityHigh, report.ConfidenceHigh, string(report.VerificationVerified), targetURL, targetURL+"/auth", "POST")
	s1 := assessment.BuildAssessmentSnapshot(asm, e1, []string{targetURL}, []assessment.AssessmentFinding{af1}, true)
	s1.TenantID, s1.AccountID = tenantID, accountID
	_ = store.CreateSnapshot(s1, []assessment.AssessmentFinding{af1}, nil)

	// Run 2 has missing CompletedAt timestamp (never finalized)
	e2 := &assessment.AssessmentExecution{ID: "e2", AssessmentID: asmID, Status: assessment.StatusRunning, StartedAt: time.Now().UTC().Add(-30 * time.Minute)}
	_ = store.CreateExecution(e2)
	s2 := assessment.BuildAssessmentSnapshot(asm, e2, []string{targetURL}, nil, false)
	s2.CompletedAt = nil // Missing completion metadata!
	s2.TenantID, s2.AccountID = tenantID, accountID
	_ = store.CreateSnapshot(s2, nil, nil)

	recAfter, _ := store.GetFindingLifecycle(tenantID, accountID, af1.Fingerprint, authCtx)
	if recAfter.CurrentState == "RESOLVED" {
		t.Fatalf("INVARIANT VIOLATION: Missing completion timestamp falsely marked finding as RESOLVED!")
	}
}

// -----------------------------------------------------------------------------
// SECTION B: TARGET COVERAGE TESTS
// -----------------------------------------------------------------------------

// B07: Target omitted from current scope does not cause resolution
func TestIncomplete_B07_TargetOmittedFromScopeDoesNotResolve(t *testing.T) {
	store, _, cleanup := helperNewIncompleteTestStore(t)
	defer cleanup()

	clientID, tenantID, accountID, asmID := "cli_b07", "ten_b07", "acc_b07", "asm_b07"
	targetA := "https://a.example.com"
	targetB := "https://b.example.com"
	_, asm, _ := helperSetupLifecycleRun(t, store, clientID, asmID, tenantID, accountID, "tgt_a", targetA)
	helperSeedTarget(t, store, asmID, "tgt_b", targetB)
	authCtx := assessment.NewTenantAuthContext(clientID, tenantID, accountID)

	e1 := &assessment.AssessmentExecution{ID: "e1", AssessmentID: asmID, Status: assessment.StatusCompleted, StartedAt: time.Now().UTC().Add(-2 * time.Hour), CompletedAt: timePtr(time.Now().UTC().Add(-1 * time.Hour))}
	_ = store.CreateExecution(e1)
	afB := helperMakeIncompleteFinding(asmID, e1.ID, "tgt_b", "fnd_b", "IDOR in Billing", "idor", report.SeverityHigh, report.ConfidenceHigh, string(report.VerificationVerified), targetB, targetB+"/invoices", "GET")
	s1 := assessment.BuildAssessmentSnapshot(asm, e1, []string{targetA, targetB}, []assessment.AssessmentFinding{afB}, true)
	s1.TenantID, s1.AccountID = tenantID, accountID
	_ = store.CreateSnapshot(s1, []assessment.AssessmentFinding{afB}, nil)

	// Run 2: Only target A is in scope. Target B is omitted.
	e2 := &assessment.AssessmentExecution{ID: "e2", AssessmentID: asmID, Status: assessment.StatusCompleted, StartedAt: time.Now().UTC().Add(-30 * time.Minute), CompletedAt: timePtr(time.Now().UTC().Add(-10 * time.Minute))}
	_ = store.CreateExecution(e2)
	s2 := assessment.BuildAssessmentSnapshot(asm, e2, []string{targetA}, nil, true)
	s2.TenantID, s2.AccountID = tenantID, accountID
	_ = store.CreateSnapshot(s2, nil, nil)

	recB, _ := store.GetFindingLifecycle(tenantID, accountID, afB.Fingerprint, authCtx)
	if recB.CurrentState == "RESOLVED" {
		t.Fatalf("INVARIANT VIOLATION: Finding on omitted target B was falsely resolved!")
	}
	if recB.CurrentState != "NEW" {
		t.Fatalf("Expected state to remain NEW, got %q", recB.CurrentState)
	}
}

// B08: Target included in scope but never successfully assessed does not cause resolution
func TestIncomplete_B08_TargetInScopeButUnassessedDoesNotResolve(t *testing.T) {
	store, _, cleanup := helperNewIncompleteTestStore(t)
	defer cleanup()

	clientID, tenantID, accountID, asmID := "cli_b08", "ten_b08", "acc_b08", "asm_b08"
	targetURL := "https://api.example.com"
	_, asm, _ := helperSetupLifecycleRun(t, store, clientID, asmID, tenantID, accountID, "tgt_b08", targetURL)
	authCtx := assessment.NewTenantAuthContext(clientID, tenantID, accountID)

	e1 := &assessment.AssessmentExecution{ID: "e1", AssessmentID: asmID, Status: assessment.StatusCompleted, StartedAt: time.Now().UTC().Add(-2 * time.Hour), CompletedAt: timePtr(time.Now().UTC().Add(-1 * time.Hour))}
	_ = store.CreateExecution(e1)
	af1 := helperMakeIncompleteFinding(asmID, e1.ID, "tgt_b08", "fnd_b08_1", "SQL Injection", "sqli", report.SeverityCritical, report.ConfidenceHigh, string(report.VerificationVerified), targetURL, targetURL+"/users", "GET")
	s1 := assessment.BuildAssessmentSnapshot(asm, e1, []string{targetURL}, []assessment.AssessmentFinding{af1}, true)
	s1.TenantID, s1.AccountID = tenantID, accountID
	_ = store.CreateSnapshot(s1, []assessment.AssessmentFinding{af1}, nil)

	// Run 2: Target is in ScopedTargets, BUT it failed during crawl / was skipped
	e2 := &assessment.AssessmentExecution{ID: "e2", AssessmentID: asmID, Status: assessment.StatusCompletedWithErrors, StartedAt: time.Now().UTC().Add(-30 * time.Minute), CompletedAt: timePtr(time.Now().UTC().Add(-10 * time.Minute))}
	_ = store.CreateExecution(e2)
	s2 := assessment.BuildAssessmentSnapshot(asm, e2, []string{targetURL}, nil, true)
	s2.SetFailedTargets([]string{targetURL}) // Recorded as failed!
	s2.TenantID, s2.AccountID = tenantID, accountID
	_ = store.CreateSnapshot(s2, nil, nil)

	recAfter, _ := store.GetFindingLifecycle(tenantID, accountID, af1.Fingerprint, authCtx)
	if recAfter.CurrentState == "RESOLVED" {
		t.Fatalf("INVARIANT VIOLATION: Target included in scope but failed during execution falsely resolved finding!")
	}
}

// B09: One target succeeds while another fails; lifecycle decisions respect each target's actual coverage
func TestIncomplete_B09_OneTargetSucceedsOneFailsRespectsCoverage(t *testing.T) {
	store, _, cleanup := helperNewIncompleteTestStore(t)
	defer cleanup()

	clientID, tenantID, accountID, asmID := "cli_b09", "ten_b09", "acc_b09", "asm_b09"
	targetA := "https://a.example.com"
	targetB := "https://b.example.com"
	_, asm, _ := helperSetupLifecycleRun(t, store, clientID, asmID, tenantID, accountID, "tgt_a", targetA)
	helperSeedTarget(t, store, asmID, "tgt_b", targetB)
	authCtx := assessment.NewTenantAuthContext(clientID, tenantID, accountID)

	// Run 1: Detect finding on target A and finding on target B
	e1 := &assessment.AssessmentExecution{ID: "e1", AssessmentID: asmID, Status: assessment.StatusCompleted, StartedAt: time.Now().UTC().Add(-2 * time.Hour), CompletedAt: timePtr(time.Now().UTC().Add(-1 * time.Hour))}
	_ = store.CreateExecution(e1)
	afA := helperMakeIncompleteFinding(asmID, e1.ID, "tgt_a", "fnd_a", "SQLi on A", "sqli", report.SeverityCritical, report.ConfidenceHigh, string(report.VerificationVerified), targetA, targetA+"/users", "GET")
	afB := helperMakeIncompleteFinding(asmID, e1.ID, "tgt_b", "fnd_b", "BOLA on B", "bola", report.SeverityHigh, report.ConfidenceHigh, string(report.VerificationVerified), targetB, targetB+"/orders", "GET")
	s1 := assessment.BuildAssessmentSnapshot(asm, e1, []string{targetA, targetB}, []assessment.AssessmentFinding{afA, afB}, true)
	s1.TenantID, s1.AccountID = tenantID, accountID
	_ = store.CreateSnapshot(s1, []assessment.AssessmentFinding{afA, afB}, nil)

	// Run 2: Target A is successfully rescanned and fixed (0 findings on A). Target B fails with transport error!
	e2 := &assessment.AssessmentExecution{ID: "e2", AssessmentID: asmID, Status: assessment.StatusCompletedWithErrors, StartedAt: time.Now().UTC().Add(-30 * time.Minute), CompletedAt: timePtr(time.Now().UTC().Add(-10 * time.Minute))}
	_ = store.CreateExecution(e2)
	s2 := assessment.BuildAssessmentSnapshot(asm, e2, []string{targetA, targetB}, nil, true)
	s2.SetAssessedTargets([]string{targetA})
	s2.SetFailedTargets([]string{targetB})
	s2.TenantID, s2.AccountID = tenantID, accountID
	if err := store.CreateSnapshot(s2, nil, nil); err != nil {
		t.Fatalf("CreateSnapshot 2 failed: %v", err)
	}

	// Finding on target A: Target A had qualifying complete coverage and was absent -> RESOLVED!
	recA, _ := store.GetFindingLifecycle(tenantID, accountID, afA.Fingerprint, authCtx)
	if recA.CurrentState != "RESOLVED" {
		t.Fatalf("Expected finding on successfully assessed target A to be RESOLVED, got %q", recA.CurrentState)
	}

	// Finding on target B: Target B failed -> MUST NOT BE RESOLVED!
	recB, _ := store.GetFindingLifecycle(tenantID, accountID, afB.Fingerprint, authCtx)
	if recB.CurrentState == "RESOLVED" {
		t.Fatalf("INVARIANT VIOLATION: Finding on failed target B was falsely marked RESOLVED!")
	}
	if recB.CurrentState != "NEW" {
		t.Fatalf("Expected finding on target B to remain NEW, got %q", recB.CurrentState)
	}
}

// B10: Multi-target finding is not resolved when required target coverage is incomplete
func TestIncomplete_B10_MultiTargetFindingIncompleteCoverageDoesNotResolve(t *testing.T) {
	store, _, cleanup := helperNewIncompleteTestStore(t)
	defer cleanup()

	clientID, tenantID, accountID, asmID := "cli_b10", "ten_b10", "acc_b10", "asm_b10"
	targetA := "https://a.example.com"
	targetB := "https://b.example.com"
	_, asm, _ := helperSetupLifecycleRun(t, store, clientID, asmID, tenantID, accountID, "tgt_a", targetA)
	helperSeedTarget(t, store, asmID, "tgt_b", targetB)
	authCtx := assessment.NewTenantAuthContext(clientID, tenantID, accountID)

	// Multi-target finding affects both Target A and Target B
	e1 := &assessment.AssessmentExecution{ID: "e1", AssessmentID: asmID, Status: assessment.StatusCompleted, StartedAt: time.Now().UTC().Add(-2 * time.Hour), CompletedAt: timePtr(time.Now().UTC().Add(-1 * time.Hour))}
	_ = store.CreateExecution(e1)
	af := helperMakeIncompleteFinding(asmID, e1.ID, "tgt_a", "fnd_shared", "Shared Auth Secret Leak", "secrets", report.SeverityCritical, report.ConfidenceHigh, string(report.VerificationVerified), targetA, targetA+"/env", "GET")
	af.EvidenceDetails.Details["associated_targets"] = targetA + ", " + targetB

	s1 := assessment.BuildAssessmentSnapshot(asm, e1, []string{targetA, targetB}, []assessment.AssessmentFinding{af}, true)
	s1.TenantID, s1.AccountID = tenantID, accountID
	_ = store.CreateSnapshot(s1, []assessment.AssessmentFinding{af}, nil)

	// Run 2: Target A succeeds, but Target B fails crawl / timeout
	e2 := &assessment.AssessmentExecution{ID: "e2", AssessmentID: asmID, Status: assessment.StatusCompletedWithErrors, StartedAt: time.Now().UTC().Add(-30 * time.Minute), CompletedAt: timePtr(time.Now().UTC().Add(-10 * time.Minute))}
	_ = store.CreateExecution(e2)
	s2 := assessment.BuildAssessmentSnapshot(asm, e2, []string{targetA, targetB}, nil, true)
	s2.SetAssessedTargets([]string{targetA})
	s2.SetFailedTargets([]string{targetB})
	s2.TenantID, s2.AccountID = tenantID, accountID
	_ = store.CreateSnapshot(s2, nil, nil)

	rec, _ := store.GetFindingLifecycle(tenantID, accountID, af.Fingerprint, authCtx)
	if rec.CurrentState == "RESOLVED" {
		t.Fatalf("INVARIANT VIOLATION: Multi-target finding was falsely resolved when Target B failed coverage!")
	}
}

// B11: Target removed from scope is not reported as fixed
func TestIncomplete_B11_TargetRemovedFromScopeNotReportedFixed(t *testing.T) {
	store, _, cleanup := helperNewIncompleteTestStore(t)
	defer cleanup()

	clientID, tenantID, accountID, asmID := "cli_b11", "ten_b11", "acc_b11", "asm_b11"
	targetLegacy := "https://legacy.example.com"
	targetNew := "https://new.example.com"
	_, asm, _ := helperSetupLifecycleRun(t, store, clientID, asmID, tenantID, accountID, "tgt_legacy", targetLegacy)
	helperSeedTarget(t, store, asmID, "tgt_new", targetNew)
	authCtx := assessment.NewTenantAuthContext(clientID, tenantID, accountID)

	e1 := &assessment.AssessmentExecution{ID: "e1", AssessmentID: asmID, Status: assessment.StatusCompleted, StartedAt: time.Now().UTC().Add(-2 * time.Hour), CompletedAt: timePtr(time.Now().UTC().Add(-1 * time.Hour))}
	_ = store.CreateExecution(e1)
	af := helperMakeIncompleteFinding(asmID, e1.ID, "tgt_legacy", "fnd_leg", "Legacy TLS Weakness", "tls", report.SeverityMedium, report.ConfidenceHigh, string(report.VerificationVerified), targetLegacy, targetLegacy+"/login", "GET")
	s1 := assessment.BuildAssessmentSnapshot(asm, e1, []string{targetLegacy}, []assessment.AssessmentFinding{af}, true)
	s1.TenantID, s1.AccountID = tenantID, accountID
	_ = store.CreateSnapshot(s1, []assessment.AssessmentFinding{af}, nil)

	// Run 2: Scope is updated to only scan new target. Legacy target is removed from scope.
	e2 := &assessment.AssessmentExecution{ID: "e2", AssessmentID: asmID, Status: assessment.StatusCompleted, StartedAt: time.Now().UTC().Add(-30 * time.Minute), CompletedAt: timePtr(time.Now().UTC().Add(-10 * time.Minute))}
	_ = store.CreateExecution(e2)
	s2 := assessment.BuildAssessmentSnapshot(asm, e2, []string{targetNew}, nil, true)
	s2.TenantID, s2.AccountID = tenantID, accountID
	_ = store.CreateSnapshot(s2, nil, nil)

	rec, _ := store.GetFindingLifecycle(tenantID, accountID, af.Fingerprint, authCtx)
	if rec.CurrentState == "RESOLVED" {
		t.Fatalf("INVARIANT VIOLATION: Target removed from scope was falsely reported as RESOLVED!")
	}
	if rec.CurrentState != "NEW" {
		t.Fatalf("Expected finding on legacy target to remain NEW, got %q", rec.CurrentState)
	}
}

// B12: Transport failure on one target does not incorrectly erase findings from another successfully assessed target
func TestIncomplete_B12_TransportFailureDoesNotEraseOtherTargetFindings(t *testing.T) {
	store, _, cleanup := helperNewIncompleteTestStore(t)
	defer cleanup()

	clientID, tenantID, accountID, asmID := "cli_b12", "ten_b12", "acc_b12", "asm_b12"
	targetStable := "https://stable.example.com"
	targetFailing := "https://flaky.example.com"
	_, asm, _ := helperSetupLifecycleRun(t, store, clientID, asmID, tenantID, accountID, "tgt_stable", targetStable)
	helperSeedTarget(t, store, asmID, "tgt_flaky", targetFailing)
	authCtx := assessment.NewTenantAuthContext(clientID, tenantID, accountID)

	e1 := &assessment.AssessmentExecution{ID: "e1", AssessmentID: asmID, Status: assessment.StatusCompleted, StartedAt: time.Now().UTC().Add(-2 * time.Hour), CompletedAt: timePtr(time.Now().UTC().Add(-1 * time.Hour))}
	_ = store.CreateExecution(e1)
	afStable := helperMakeIncompleteFinding(asmID, e1.ID, "tgt_stable", "fnd_stable_1", "Stable Finding", "xss", report.SeverityHigh, report.ConfidenceHigh, string(report.VerificationVerified), targetStable, targetStable+"/comments", "POST")
	s1 := assessment.BuildAssessmentSnapshot(asm, e1, []string{targetStable, targetFailing}, []assessment.AssessmentFinding{afStable}, true)
	s1.TenantID, s1.AccountID = tenantID, accountID
	_ = store.CreateSnapshot(s1, []assessment.AssessmentFinding{afStable}, nil)

	// Run 2: Stable target is rescanned and finding is detected again! Flaky target has transport error.
	e2 := &assessment.AssessmentExecution{ID: "e2", AssessmentID: asmID, Status: assessment.StatusCompletedWithErrors, StartedAt: time.Now().UTC().Add(-30 * time.Minute), CompletedAt: timePtr(time.Now().UTC().Add(-10 * time.Minute))}
	_ = store.CreateExecution(e2)
	afStable2 := helperMakeIncompleteFinding(asmID, e2.ID, "tgt_stable", "fnd_stable_2", "Stable Finding", "xss", report.SeverityHigh, report.ConfidenceHigh, string(report.VerificationVerified), targetStable, targetStable+"/comments", "POST")
	s2 := assessment.BuildAssessmentSnapshot(asm, e2, []string{targetStable, targetFailing}, []assessment.AssessmentFinding{afStable2}, true)
	s2.SetAssessedTargets([]string{targetStable})
	s2.SetFailedTargets([]string{targetFailing})
	s2.TenantID, s2.AccountID = tenantID, accountID
	_ = store.CreateSnapshot(s2, []assessment.AssessmentFinding{afStable2}, nil)

	recStable, _ := store.GetFindingLifecycle(tenantID, accountID, afStable.Fingerprint, authCtx)
	if recStable.CurrentState != "ACTIVE" {
		t.Fatalf("Expected stable target finding to be ACTIVE, got %q", recStable.CurrentState)
	}
}

// -----------------------------------------------------------------------------
// SECTION C: DETECTOR AND CATEGORY COVERAGE TESTS
// -----------------------------------------------------------------------------

// C13: Relevant detector never executed: no resolution
func TestIncomplete_C13_RelevantDetectorNeverExecutedNoResolution(t *testing.T) {
	store, _, cleanup := helperNewIncompleteTestStore(t)
	defer cleanup()

	clientID, tenantID, accountID, asmID := "cli_c13", "ten_c13", "acc_c13", "asm_c13"
	targetURL := "https://api.example.com"
	_, asm, _ := helperSetupLifecycleRun(t, store, clientID, asmID, tenantID, accountID, "tgt_c13", targetURL)
	authCtx := assessment.NewTenantAuthContext(clientID, tenantID, accountID)

	e1 := &assessment.AssessmentExecution{ID: "e1", AssessmentID: asmID, Status: assessment.StatusCompleted, StartedAt: time.Now().UTC().Add(-2 * time.Hour), CompletedAt: timePtr(time.Now().UTC().Add(-1 * time.Hour))}
	_ = store.CreateExecution(e1)
	af := helperMakeIncompleteFinding(asmID, e1.ID, "tgt_c13", "fnd_c13_1", "AWS S3 Bucket Public", "cloud", report.SeverityHigh, report.ConfidenceHigh, string(report.VerificationVerified), targetURL, targetURL+"/bucket", "GET")
	s1 := assessment.BuildAssessmentSnapshot(asm, e1, []string{targetURL}, []assessment.AssessmentFinding{af}, true)
	s1.TenantID, s1.AccountID = tenantID, accountID
	_ = store.CreateSnapshot(s1, []assessment.AssessmentFinding{af}, nil)

	// Run 2: Fast scan ran ONLY "crawler" and "headers" detectors. "cloud" detector never executed.
	e2 := &assessment.AssessmentExecution{ID: "e2", AssessmentID: asmID, Status: assessment.StatusCompleted, StartedAt: time.Now().UTC().Add(-30 * time.Minute), CompletedAt: timePtr(time.Now().UTC().Add(-10 * time.Minute))}
	_ = store.CreateExecution(e2)
	s2 := assessment.BuildAssessmentSnapshot(asm, e2, []string{targetURL}, nil, true)
	s2.SetCoveredCategories([]string{"crawler", "headers"}) // cloud is omitted!
	s2.TenantID, s2.AccountID = tenantID, accountID
	_ = store.CreateSnapshot(s2, nil, nil)

	rec, _ := store.GetFindingLifecycle(tenantID, accountID, af.Fingerprint, authCtx)
	if rec.CurrentState == "RESOLVED" {
		t.Fatalf("INVARIANT VIOLATION: Finding was falsely resolved when its detector never executed!")
	}
	if rec.CurrentState != "NEW" {
		t.Fatalf("Expected state to remain NEW, got %q", rec.CurrentState)
	}
}

// C14: Detector execution failed: no resolution
func TestIncomplete_C14_DetectorExecutionFailedNoResolution(t *testing.T) {
	store, _, cleanup := helperNewIncompleteTestStore(t)
	defer cleanup()

	clientID, tenantID, accountID, asmID := "cli_c14", "ten_c14", "acc_c14", "asm_c14"
	targetURL := "https://api.example.com"
	_, asm, _ := helperSetupLifecycleRun(t, store, clientID, asmID, tenantID, accountID, "tgt_c14", targetURL)
	authCtx := assessment.NewTenantAuthContext(clientID, tenantID, accountID)

	e1 := &assessment.AssessmentExecution{ID: "e1", AssessmentID: asmID, Status: assessment.StatusCompleted, StartedAt: time.Now().UTC().Add(-2 * time.Hour), CompletedAt: timePtr(time.Now().UTC().Add(-1 * time.Hour))}
	_ = store.CreateExecution(e1)
	af := helperMakeIncompleteFinding(asmID, e1.ID, "tgt_c14", "fnd_c14_1", "Secret Token in JS", "secrets", report.SeverityHigh, report.ConfidenceHigh, string(report.VerificationVerified), targetURL, targetURL+"/app.js", "GET")
	s1 := assessment.BuildAssessmentSnapshot(asm, e1, []string{targetURL}, []assessment.AssessmentFinding{af}, true)
	s1.TenantID, s1.AccountID = tenantID, accountID
	_ = store.CreateSnapshot(s1, []assessment.AssessmentFinding{af}, nil)

	// Run 2: Secrets detector crashed/failed during execution
	e2 := &assessment.AssessmentExecution{ID: "e2", AssessmentID: asmID, Status: assessment.StatusCompletedWithErrors, StartedAt: time.Now().UTC().Add(-30 * time.Minute), CompletedAt: timePtr(time.Now().UTC().Add(-10 * time.Minute))}
	_ = store.CreateExecution(e2)
	s2 := assessment.BuildAssessmentSnapshot(asm, e2, []string{targetURL}, nil, true)
	s2.SetFailedCategories([]string{"secrets"})
	s2.TenantID, s2.AccountID = tenantID, accountID
	_ = store.CreateSnapshot(s2, nil, nil)

	rec, _ := store.GetFindingLifecycle(tenantID, accountID, af.Fingerprint, authCtx)
	if rec.CurrentState == "RESOLVED" {
		t.Fatalf("INVARIANT VIOLATION: Finding was falsely resolved when its detector failed execution!")
	}
}

// C15: Detector was skipped or disabled: no resolution for findings requiring it
func TestIncomplete_C15_DetectorSkippedOrDisabledNoResolution(t *testing.T) {
	store, _, cleanup := helperNewIncompleteTestStore(t)
	defer cleanup()

	clientID, tenantID, accountID, asmID := "cli_c15", "ten_c15", "acc_c15", "asm_c15"
	targetURL := "https://api.example.com"
	_, asm, _ := helperSetupLifecycleRun(t, store, clientID, asmID, tenantID, accountID, "tgt_c15", targetURL)
	authCtx := assessment.NewTenantAuthContext(clientID, tenantID, accountID)

	e1 := &assessment.AssessmentExecution{ID: "e1", AssessmentID: asmID, Status: assessment.StatusCompleted, StartedAt: time.Now().UTC().Add(-2 * time.Hour), CompletedAt: timePtr(time.Now().UTC().Add(-1 * time.Hour))}
	_ = store.CreateExecution(e1)
	af := helperMakeIncompleteFinding(asmID, e1.ID, "tgt_c15", "fnd_c15_1", "GraphQL Introspection", "api", report.SeverityMedium, report.ConfidenceHigh, string(report.VerificationVerified), targetURL, targetURL+"/graphql", "POST")
	s1 := assessment.BuildAssessmentSnapshot(asm, e1, []string{targetURL}, []assessment.AssessmentFinding{af}, true)
	s1.TenantID, s1.AccountID = tenantID, accountID
	_ = store.CreateSnapshot(s1, []assessment.AssessmentFinding{af}, nil)

	// Run 2: API detector was disabled in config
	e2 := &assessment.AssessmentExecution{ID: "e2", AssessmentID: asmID, Status: assessment.StatusCompleted, StartedAt: time.Now().UTC().Add(-30 * time.Minute), CompletedAt: timePtr(time.Now().UTC().Add(-10 * time.Minute))}
	_ = store.CreateExecution(e2)
	s2 := assessment.BuildAssessmentSnapshot(asm, e2, []string{targetURL}, nil, true)
	s2.SetSkippedCategories([]string{"api"})
	s2.TenantID, s2.AccountID = tenantID, accountID
	_ = store.CreateSnapshot(s2, nil, nil)

	rec, _ := store.GetFindingLifecycle(tenantID, accountID, af.Fingerprint, authCtx)
	if rec.CurrentState == "RESOLVED" {
		t.Fatalf("INVARIANT VIOLATION: Finding was falsely resolved when its detector was disabled/skipped!")
	}
}

// C16: A category completed adequately while an unrelated category failed; resolve only findings whose own required coverage is sufficient
func TestIncomplete_C16_OneCategorySucceedsOneCategoryFailsGranularResolution(t *testing.T) {
	store, _, cleanup := helperNewIncompleteTestStore(t)
	defer cleanup()

	clientID, tenantID, accountID, asmID := "cli_c16", "ten_c16", "acc_c16", "asm_c16"
	targetURL := "https://api.example.com"
	_, asm, _ := helperSetupLifecycleRun(t, store, clientID, asmID, tenantID, accountID, "tgt_c16", targetURL)
	authCtx := assessment.NewTenantAuthContext(clientID, tenantID, accountID)

	e1 := &assessment.AssessmentExecution{ID: "e1", AssessmentID: asmID, Status: assessment.StatusCompleted, StartedAt: time.Now().UTC().Add(-2 * time.Hour), CompletedAt: timePtr(time.Now().UTC().Add(-1 * time.Hour))}
	_ = store.CreateExecution(e1)
	afWeb := helperMakeIncompleteFinding(asmID, e1.ID, "tgt_c16", "fnd_web", "Reflected XSS", "webvuln", report.SeverityHigh, report.ConfidenceHigh, string(report.VerificationVerified), targetURL, targetURL+"/search", "GET")
	afCloud := helperMakeIncompleteFinding(asmID, e1.ID, "tgt_c16", "fnd_cld", "S3 Bucket Permissive", "cloud", report.SeverityHigh, report.ConfidenceHigh, string(report.VerificationVerified), targetURL, targetURL+"/bucket", "GET")
	s1 := assessment.BuildAssessmentSnapshot(asm, e1, []string{targetURL}, []assessment.AssessmentFinding{afWeb, afCloud}, true)
	s1.TenantID, s1.AccountID = tenantID, accountID
	_ = store.CreateSnapshot(s1, []assessment.AssessmentFinding{afWeb, afCloud}, nil)

	// Run 2: webvuln executed successfully and confirmed fixed. cloud detector failed!
	e2 := &assessment.AssessmentExecution{ID: "e2", AssessmentID: asmID, Status: assessment.StatusCompletedWithErrors, StartedAt: time.Now().UTC().Add(-30 * time.Minute), CompletedAt: timePtr(time.Now().UTC().Add(-10 * time.Minute))}
	_ = store.CreateExecution(e2)
	s2 := assessment.BuildAssessmentSnapshot(asm, e2, []string{targetURL}, nil, true)
	s2.SetCoveredCategories([]string{"webvuln"})
	s2.SetFailedCategories([]string{"cloud"})
	s2.TenantID, s2.AccountID = tenantID, accountID
	if err := store.CreateSnapshot(s2, nil, nil); err != nil {
		t.Fatalf("CreateSnapshot 2 failed: %v", err)
	}

	// Web finding had qualifying coverage and was absent -> RESOLVED!
	recWeb, _ := store.GetFindingLifecycle(tenantID, accountID, afWeb.Fingerprint, authCtx)
	if recWeb.CurrentState != "RESOLVED" {
		t.Fatalf("Expected webvuln finding to be RESOLVED, got %q", recWeb.CurrentState)
	}

	// Cloud finding detector failed -> MUST NOT RESOLVE!
	recCloud, _ := store.GetFindingLifecycle(tenantID, accountID, afCloud.Fingerprint, authCtx)
	if recCloud.CurrentState == "RESOLVED" {
		t.Fatalf("INVARIANT VIOLATION: Cloud finding was falsely resolved despite cloud detector failure!")
	}
	if recCloud.CurrentState != "NEW" {
		t.Fatalf("Expected cloud finding to remain NEW, got %q", recCloud.CurrentState)
	}
}

// C17: Missing coverage metadata fails closed when required to prove absence
func TestIncomplete_C17_MissingCoverageMetadataFailsClosedWhenRequired(t *testing.T) {
	store, _, cleanup := helperNewIncompleteTestStore(t)
	defer cleanup()

	clientID, tenantID, accountID, asmID := "cli_c17", "ten_c17", "acc_c17", "asm_c17"
	targetURL := "https://api.example.com"
	_, asm, _ := helperSetupLifecycleRun(t, store, clientID, asmID, tenantID, accountID, "tgt_c17", targetURL)
	authCtx := assessment.NewTenantAuthContext(clientID, tenantID, accountID)

	e1 := &assessment.AssessmentExecution{ID: "e1", AssessmentID: asmID, Status: assessment.StatusCompleted, StartedAt: time.Now().UTC().Add(-2 * time.Hour), CompletedAt: timePtr(time.Now().UTC().Add(-1 * time.Hour))}
	_ = store.CreateExecution(e1)
	af := helperMakeIncompleteFinding(asmID, e1.ID, "tgt_c17", "fnd_c17_1", "Secret Leak", "secrets", report.SeverityHigh, report.ConfidenceHigh, string(report.VerificationVerified), targetURL, targetURL+"/api", "GET")
	s1 := assessment.BuildAssessmentSnapshot(asm, e1, []string{targetURL}, []assessment.AssessmentFinding{af}, true)
	s1.TenantID, s1.AccountID = tenantID, accountID
	_ = store.CreateSnapshot(s1, []assessment.AssessmentFinding{af}, nil)

	// Run 2: Missing required evidence / coverage inconclusive flag
	e2 := &assessment.AssessmentExecution{ID: "e2", AssessmentID: asmID, Status: assessment.StatusCompleted, StartedAt: time.Now().UTC().Add(-30 * time.Minute), CompletedAt: timePtr(time.Now().UTC().Add(-10 * time.Minute))}
	_ = store.CreateExecution(e2)
	s2 := assessment.BuildAssessmentSnapshot(asm, e2, []string{targetURL}, nil, true)
	s2.MarkInconclusive("Missing required proof of negative evidence")
	s2.TenantID, s2.AccountID = tenantID, accountID
	_ = store.CreateSnapshot(s2, nil, nil)

	rec, _ := store.GetFindingLifecycle(tenantID, accountID, af.Fingerprint, authCtx)
	if rec.CurrentState == "RESOLVED" {
		t.Fatalf("INVARIANT VIOLATION: Missing coverage proof falsely marked finding as RESOLVED!")
	}
}

// -----------------------------------------------------------------------------
// SECTION D: LIFECYCLE INTEGRATION TESTS
// -----------------------------------------------------------------------------

// D18: ACTIVE finding survives incomplete assessment without false resolution
func TestIncomplete_D18_ActiveFindingSurvivesIncompleteScan(t *testing.T) {
	store, _, cleanup := helperNewIncompleteTestStore(t)
	defer cleanup()

	clientID, tenantID, accountID, asmID := "cli_d18", "ten_d18", "acc_d18", "asm_d18"
	targetURL := "https://api.example.com"
	_, asm, _ := helperSetupLifecycleRun(t, store, clientID, asmID, tenantID, accountID, "tgt_d18", targetURL)
	authCtx := assessment.NewTenantAuthContext(clientID, tenantID, accountID)

	// Run 1: NEW
	e1 := &assessment.AssessmentExecution{ID: "e1", AssessmentID: asmID, Status: assessment.StatusCompleted, StartedAt: time.Now().UTC().Add(-3 * time.Hour), CompletedAt: timePtr(time.Now().UTC().Add(-2 * time.Hour))}
	_ = store.CreateExecution(e1)
	af1 := helperMakeIncompleteFinding(asmID, e1.ID, "tgt_d18", "fnd_d18_1", "SQL Injection", "sqli", report.SeverityCritical, report.ConfidenceHigh, string(report.VerificationVerified), targetURL, targetURL+"/users", "GET")
	s1 := assessment.BuildAssessmentSnapshot(asm, e1, []string{targetURL}, []assessment.AssessmentFinding{af1}, true)
	s1.TenantID, s1.AccountID = tenantID, accountID
	_ = store.CreateSnapshot(s1, []assessment.AssessmentFinding{af1}, nil)

	// Run 2: ACTIVE
	e2 := &assessment.AssessmentExecution{ID: "e2", AssessmentID: asmID, Status: assessment.StatusCompleted, StartedAt: time.Now().UTC().Add(-90 * time.Minute), CompletedAt: timePtr(time.Now().UTC().Add(-60 * time.Minute))}
	_ = store.CreateExecution(e2)
	af2 := helperMakeIncompleteFinding(asmID, e2.ID, "tgt_d18", "fnd_d18_2", "SQL Injection", "sqli", report.SeverityCritical, report.ConfidenceHigh, string(report.VerificationVerified), targetURL, targetURL+"/users", "GET")
	s2 := assessment.BuildAssessmentSnapshot(asm, e2, []string{targetURL}, []assessment.AssessmentFinding{af2}, true)
	s2.TenantID, s2.AccountID = tenantID, accountID
	_ = store.CreateSnapshot(s2, []assessment.AssessmentFinding{af2}, nil)

	rec2, _ := store.GetFindingLifecycle(tenantID, accountID, af1.Fingerprint, authCtx)
	if rec2.CurrentState != "ACTIVE" {
		t.Fatalf("Expected ACTIVE after run 2, got %q", rec2.CurrentState)
	}

	// Run 3: Incomplete / cancelled run with 0 findings
	e3 := &assessment.AssessmentExecution{ID: "e3", AssessmentID: asmID, Status: assessment.StatusCancelled, StartedAt: time.Now().UTC().Add(-30 * time.Minute), CompletedAt: timePtr(time.Now().UTC().Add(-10 * time.Minute))}
	_ = store.CreateExecution(e3)
	s3 := assessment.BuildAssessmentSnapshot(asm, e3, []string{targetURL}, nil, false)
	s3.TenantID, s3.AccountID = tenantID, accountID
	_ = store.CreateSnapshot(s3, nil, nil)

	// Must remain ACTIVE!
	rec3, _ := store.GetFindingLifecycle(tenantID, accountID, af1.Fingerprint, authCtx)
	if rec3.CurrentState != "ACTIVE" {
		t.Fatalf("Expected state to remain ACTIVE after incomplete scan, got %q", rec3.CurrentState)
	}
}

// D19: NEW finding retains correct lifecycle semantics when follow-up scan is incomplete
func TestIncomplete_D19_NewFindingRetainsStateWhenScanIncomplete(t *testing.T) {
	store, _, cleanup := helperNewIncompleteTestStore(t)
	defer cleanup()

	clientID, tenantID, accountID, asmID := "cli_d19", "ten_d19", "acc_d19", "asm_d19"
	targetURL := "https://api.example.com"
	_, asm, _ := helperSetupLifecycleRun(t, store, clientID, asmID, tenantID, accountID, "tgt_d19", targetURL)
	authCtx := assessment.NewTenantAuthContext(clientID, tenantID, accountID)

	e1 := &assessment.AssessmentExecution{ID: "e1", AssessmentID: asmID, Status: assessment.StatusCompleted, StartedAt: time.Now().UTC().Add(-2 * time.Hour), CompletedAt: timePtr(time.Now().UTC().Add(-1 * time.Hour))}
	_ = store.CreateExecution(e1)
	af1 := helperMakeIncompleteFinding(asmID, e1.ID, "tgt_d19", "fnd_d19_1", "Open Redirect", "open-redirect", report.SeverityLow, report.ConfidenceHigh, string(report.VerificationVerified), targetURL, targetURL+"/redir", "GET")
	s1 := assessment.BuildAssessmentSnapshot(asm, e1, []string{targetURL}, []assessment.AssessmentFinding{af1}, true)
	s1.TenantID, s1.AccountID = tenantID, accountID
	_ = store.CreateSnapshot(s1, []assessment.AssessmentFinding{af1}, nil)

	// Run 2 failed
	e2 := &assessment.AssessmentExecution{ID: "e2", AssessmentID: asmID, Status: assessment.StatusFailed, ErrorMessage: "Target timeout", StartedAt: time.Now().UTC().Add(-30 * time.Minute), CompletedAt: timePtr(time.Now().UTC().Add(-10 * time.Minute))}
	_ = store.CreateExecution(e2)
	s2 := assessment.BuildAssessmentSnapshot(asm, e2, []string{targetURL}, nil, false)
	s2.TenantID, s2.AccountID = tenantID, accountID
	_ = store.CreateSnapshot(s2, nil, nil)

	rec, _ := store.GetFindingLifecycle(tenantID, accountID, af1.Fingerprint, authCtx)
	if rec.CurrentState != "NEW" {
		t.Fatalf("Expected NEW finding to remain NEW after failed scan, got %q", rec.CurrentState)
	}
}

// D20: REGRESSED finding is not falsely resolved by an incomplete scan
func TestIncomplete_D20_RegressedFindingNotFalselyResolved(t *testing.T) {
	store, _, cleanup := helperNewIncompleteTestStore(t)
	defer cleanup()

	clientID, tenantID, accountID, asmID := "cli_d20", "ten_d20", "acc_d20", "asm_d20"
	targetURL := "https://api.example.com"
	_, asm, _ := helperSetupLifecycleRun(t, store, clientID, asmID, tenantID, accountID, "tgt_d20", targetURL)
	authCtx := assessment.NewTenantAuthContext(clientID, tenantID, accountID)

	// Run 1: NEW
	e1 := &assessment.AssessmentExecution{ID: "e1", AssessmentID: asmID, Status: assessment.StatusCompleted, StartedAt: time.Now().UTC().Add(-4 * time.Hour), CompletedAt: timePtr(time.Now().UTC().Add(-3 * time.Hour))}
	_ = store.CreateExecution(e1)
	af1 := helperMakeIncompleteFinding(asmID, e1.ID, "tgt_d20", "fnd_d20_1", "Auth Bypass", "auth", report.SeverityCritical, report.ConfidenceHigh, string(report.VerificationVerified), targetURL, targetURL+"/admin", "GET")
	s1 := assessment.BuildAssessmentSnapshot(asm, e1, []string{targetURL}, []assessment.AssessmentFinding{af1}, true)
	s1.TenantID, s1.AccountID = tenantID, accountID
	_ = store.CreateSnapshot(s1, []assessment.AssessmentFinding{af1}, nil)

	// Run 2: RESOLVED
	e2 := &assessment.AssessmentExecution{ID: "e2", AssessmentID: asmID, Status: assessment.StatusCompleted, StartedAt: time.Now().UTC().Add(-150 * time.Minute), CompletedAt: timePtr(time.Now().UTC().Add(-120 * time.Minute))}
	_ = store.CreateExecution(e2)
	s2 := assessment.BuildAssessmentSnapshot(asm, e2, []string{targetURL}, nil, true)
	s2.TenantID, s2.AccountID = tenantID, accountID
	_ = store.CreateSnapshot(s2, nil, nil)

	// Run 3: REGRESSED
	e3 := &assessment.AssessmentExecution{ID: "e3", AssessmentID: asmID, Status: assessment.StatusCompleted, StartedAt: time.Now().UTC().Add(-90 * time.Minute), CompletedAt: timePtr(time.Now().UTC().Add(-60 * time.Minute))}
	_ = store.CreateExecution(e3)
	af3 := helperMakeIncompleteFinding(asmID, e3.ID, "tgt_d20", "fnd_d20_3", "Auth Bypass", "auth", report.SeverityCritical, report.ConfidenceHigh, string(report.VerificationVerified), targetURL, targetURL+"/admin", "GET")
	s3 := assessment.BuildAssessmentSnapshot(asm, e3, []string{targetURL}, []assessment.AssessmentFinding{af3}, true)
	s3.TenantID, s3.AccountID = tenantID, accountID
	_ = store.CreateSnapshot(s3, []assessment.AssessmentFinding{af3}, nil)

	rec3, _ := store.GetFindingLifecycle(tenantID, accountID, af1.Fingerprint, authCtx)
	if rec3.CurrentState != "REGRESSED" {
		t.Fatalf("Expected REGRESSED after run 3, got %q", rec3.CurrentState)
	}

	// Run 4: Incomplete / transport failure
	e4 := &assessment.AssessmentExecution{ID: "e4", AssessmentID: asmID, Status: assessment.StatusCompletedWithErrors, StartedAt: time.Now().UTC().Add(-30 * time.Minute), CompletedAt: timePtr(time.Now().UTC().Add(-10 * time.Minute))}
	_ = store.CreateExecution(e4)
	s4 := assessment.BuildAssessmentSnapshot(asm, e4, []string{targetURL}, nil, true)
	s4.SetFailedTargets([]string{targetURL}) // target failed
	s4.TenantID, s4.AccountID = tenantID, accountID
	_ = store.CreateSnapshot(s4, nil, nil)

	rec4, _ := store.GetFindingLifecycle(tenantID, accountID, af1.Fingerprint, authCtx)
	if rec4.CurrentState != "REGRESSED" {
		t.Fatalf("Expected REGRESSED finding to retain state after incomplete run, got %q", rec4.CurrentState)
	}
}

// D21: Genuinely resolved finding can still transition to REGRESSED when reliably detected later
func TestIncomplete_D21_GenuinelyResolvedTransitionsToRegressedLater(t *testing.T) {
	store, _, cleanup := helperNewIncompleteTestStore(t)
	defer cleanup()

	clientID, tenantID, accountID, asmID := "cli_d21", "ten_d21", "acc_d21", "asm_d21"
	targetURL := "https://api.example.com"
	_, asm, _ := helperSetupLifecycleRun(t, store, clientID, asmID, tenantID, accountID, "tgt_d21", targetURL)
	authCtx := assessment.NewTenantAuthContext(clientID, tenantID, accountID)

	// Run 1: NEW
	e1 := &assessment.AssessmentExecution{ID: "e1", AssessmentID: asmID, Status: assessment.StatusCompleted, StartedAt: time.Now().UTC().Add(-3 * time.Hour), CompletedAt: timePtr(time.Now().UTC().Add(-2 * time.Hour))}
	_ = store.CreateExecution(e1)
	af1 := helperMakeIncompleteFinding(asmID, e1.ID, "tgt_d21", "fnd_d21_1", "SQL Injection", "sqli", report.SeverityHigh, report.ConfidenceHigh, string(report.VerificationVerified), targetURL, targetURL+"/users", "GET")
	s1 := assessment.BuildAssessmentSnapshot(asm, e1, []string{targetURL}, []assessment.AssessmentFinding{af1}, true)
	s1.TenantID, s1.AccountID = tenantID, accountID
	_ = store.CreateSnapshot(s1, []assessment.AssessmentFinding{af1}, nil)

	// Run 2: Conclusively RESOLVED in qualifying complete scan
	e2 := &assessment.AssessmentExecution{ID: "e2", AssessmentID: asmID, Status: assessment.StatusCompleted, StartedAt: time.Now().UTC().Add(-90 * time.Minute), CompletedAt: timePtr(time.Now().UTC().Add(-60 * time.Minute))}
	_ = store.CreateExecution(e2)
	s2 := assessment.BuildAssessmentSnapshot(asm, e2, []string{targetURL}, nil, true)
	s2.SetAssessedTargets([]string{targetURL})
	s2.SetCoveredCategories([]string{"sqli"})
	s2.TenantID, s2.AccountID = tenantID, accountID
	_ = store.CreateSnapshot(s2, nil, nil)

	rec2, _ := store.GetFindingLifecycle(tenantID, accountID, af1.Fingerprint, authCtx)
	if rec2.CurrentState != "RESOLVED" {
		t.Fatalf("Expected RESOLVED after qualifying run 2, got %q", rec2.CurrentState)
	}

	// Run 3: Vulnerability re-detected -> REGRESSED
	e3 := &assessment.AssessmentExecution{ID: "e3", AssessmentID: asmID, Status: assessment.StatusCompleted, StartedAt: time.Now().UTC().Add(-30 * time.Minute), CompletedAt: timePtr(time.Now().UTC().Add(-10 * time.Minute))}
	_ = store.CreateExecution(e3)
	af3 := helperMakeIncompleteFinding(asmID, e3.ID, "tgt_d21", "fnd_d21_3", "SQL Injection", "sqli", report.SeverityHigh, report.ConfidenceHigh, string(report.VerificationVerified), targetURL, targetURL+"/users", "GET")
	s3 := assessment.BuildAssessmentSnapshot(asm, e3, []string{targetURL}, []assessment.AssessmentFinding{af3}, true)
	s3.TenantID, s3.AccountID = tenantID, accountID
	_ = store.CreateSnapshot(s3, []assessment.AssessmentFinding{af3}, nil)

	rec3, _ := store.GetFindingLifecycle(tenantID, accountID, af1.Fingerprint, authCtx)
	if rec3.CurrentState != "REGRESSED" {
		t.Fatalf("Expected REGRESSED after re-detection, got %q", rec3.CurrentState)
	}
	if rec3.RegressionCount != 1 {
		t.Fatalf("Expected RegressionCount 1, got %d", rec3.RegressionCount)
	}
}

// D22: A qualifying complete assessment can resolve a finding after checks establish absence
func TestIncomplete_D22_QualifyingCompleteAssessmentResolves(t *testing.T) {
	store, _, cleanup := helperNewIncompleteTestStore(t)
	defer cleanup()

	clientID, tenantID, accountID, asmID := "cli_d22", "ten_d22", "acc_d22", "asm_d22"
	targetURL := "https://api.example.com"
	_, asm, _ := helperSetupLifecycleRun(t, store, clientID, asmID, tenantID, accountID, "tgt_d22", targetURL)
	authCtx := assessment.NewTenantAuthContext(clientID, tenantID, accountID)

	e1 := &assessment.AssessmentExecution{ID: "e1", AssessmentID: asmID, Status: assessment.StatusCompleted, StartedAt: time.Now().UTC().Add(-2 * time.Hour), CompletedAt: timePtr(time.Now().UTC().Add(-1 * time.Hour))}
	_ = store.CreateExecution(e1)
	af1 := helperMakeIncompleteFinding(asmID, e1.ID, "tgt_d22", "fnd_d22_1", "Hardcoded API Key", "secrets", report.SeverityCritical, report.ConfidenceHigh, string(report.VerificationVerified), targetURL, targetURL+"/config", "GET")
	s1 := assessment.BuildAssessmentSnapshot(asm, e1, []string{targetURL}, []assessment.AssessmentFinding{af1}, true)
	s1.TenantID, s1.AccountID = tenantID, accountID
	_ = store.CreateSnapshot(s1, []assessment.AssessmentFinding{af1}, nil)

	// Run 2: Full qualifying run with complete coverage -> successfully resolves
	e2 := &assessment.AssessmentExecution{ID: "e2", AssessmentID: asmID, Status: assessment.StatusCompleted, StartedAt: time.Now().UTC().Add(-30 * time.Minute), CompletedAt: timePtr(time.Now().UTC().Add(-10 * time.Minute))}
	_ = store.CreateExecution(e2)
	s2 := assessment.BuildAssessmentSnapshot(asm, e2, []string{targetURL}, nil, true)
	s2.SetAssessedTargets([]string{targetURL})
	s2.SetCoveredCategories([]string{"secrets"})
	s2.TenantID, s2.AccountID = tenantID, accountID
	if err := store.CreateSnapshot(s2, nil, nil); err != nil {
		t.Fatalf("CreateSnapshot 2 failed: %v", err)
	}

	rec, _ := store.GetFindingLifecycle(tenantID, accountID, af1.Fingerprint, authCtx)
	if rec.CurrentState != "RESOLVED" {
		t.Fatalf("Expected RESOLVED after fully qualifying scan, got %q", rec.CurrentState)
	}
}

// D23: Repeated processing does not create duplicate lifecycle events
func TestIncomplete_D23_RepeatedProcessingDoesNotDuplicateEvents(t *testing.T) {
	store, _, cleanup := helperNewIncompleteTestStore(t)
	defer cleanup()

	clientID, tenantID, accountID, asmID := "cli_d23", "ten_d23", "acc_d23", "asm_d23"
	targetURL := "https://api.example.com"
	_, asm, _ := helperSetupLifecycleRun(t, store, clientID, asmID, tenantID, accountID, "tgt_d23", targetURL)
	authCtx := assessment.NewTenantAuthContext(clientID, tenantID, accountID)

	e1 := &assessment.AssessmentExecution{ID: "e1", AssessmentID: asmID, Status: assessment.StatusCompleted, StartedAt: time.Now().UTC().Add(-2 * time.Hour), CompletedAt: timePtr(time.Now().UTC().Add(-1 * time.Hour))}
	_ = store.CreateExecution(e1)
	af1 := helperMakeIncompleteFinding(asmID, e1.ID, "tgt_d23", "fnd_d23_1", "SQL Injection", "sqli", report.SeverityCritical, report.ConfidenceHigh, string(report.VerificationVerified), targetURL, targetURL+"/users", "GET")
	s1 := assessment.BuildAssessmentSnapshot(asm, e1, []string{targetURL}, []assessment.AssessmentFinding{af1}, true)
	s1.TenantID, s1.AccountID = tenantID, accountID
	_ = store.CreateSnapshot(s1, []assessment.AssessmentFinding{af1}, nil)

	// Idempotent retry of identical snapshot
	err := store.CreateSnapshot(s1, []assessment.AssessmentFinding{af1}, nil)
	if err != nil {
		t.Fatalf("Identical retry should succeed idempotently, got: %v", err)
	}

	events, _ := store.GetFindingLifecycleEvents(af1.Fingerprint, authCtx)
	if len(events) != 1 {
		t.Fatalf("Expected exactly 1 event after retry, got %d", len(events))
	}
}

// -----------------------------------------------------------------------------
// SECTION E: PERSISTENCE AND REPORTING TESTS
// -----------------------------------------------------------------------------

// E24: Database reopen preserves incomplete status and coverage information
func TestIncomplete_E24_DatabaseReopenPreservesIncompleteCoverage(t *testing.T) {
	store, dbPath, cleanup := helperNewIncompleteTestStore(t)
	defer cleanup()

	clientID, tenantID, accountID, asmID := "cli_e24", "ten_e24", "acc_e24", "asm_e24"
	targetA := "https://a.example.com"
	targetB := "https://b.example.com"
	_, asm, _ := helperSetupLifecycleRun(t, store, clientID, asmID, tenantID, accountID, "tgt_a", targetA)
	helperSeedTarget(t, store, asmID, "tgt_b", targetB)
	authCtx := assessment.NewTenantAuthContext(clientID, tenantID, accountID)

	e1 := &assessment.AssessmentExecution{ID: "e1", AssessmentID: asmID, Status: assessment.StatusCompletedWithErrors, StartedAt: time.Now().UTC().Add(-2 * time.Hour), CompletedAt: timePtr(time.Now().UTC().Add(-1 * time.Hour))}
	_ = store.CreateExecution(e1)
	s1 := assessment.BuildAssessmentSnapshot(asm, e1, []string{targetA, targetB}, nil, true)
	s1.SetAssessedTargets([]string{targetA})
	s1.SetFailedTargets([]string{targetB})
	s1.SetCoveredCategories([]string{"secrets", "api"})
	s1.SetFailedCategories([]string{"webvuln"})
	s1.TenantID, s1.AccountID = tenantID, accountID
	if err := store.CreateSnapshot(s1, nil, nil); err != nil {
		t.Fatalf("CreateSnapshot failed: %v", err)
	}
	_ = store.Close()

	// Reopen database
	reopenedStore, err := assessment.NewSQLiteStore(dbPath)
	if err != nil {
		t.Fatalf("failed to reopen sqlite store: %v", err)
	}
	defer reopenedStore.Close()

	loadedSnap, err := reopenedStore.GetSnapshot(s1.ID, authCtx)
	if err != nil {
		t.Fatalf("GetSnapshot failed after reopen: %v", err)
	}
	assessed := loadedSnap.GetAssessedTargets()
	if len(assessed) != 1 || assessed[0] != targetA {
		t.Fatalf("Expected AssessedTargets [%s], got %v", targetA, assessed)
	}
	failed := loadedSnap.GetFailedTargets()
	if len(failed) != 1 || failed[0] != targetB {
		t.Fatalf("Expected FailedTargets [%s], got %v", targetB, failed)
	}
	failedCats := loadedSnap.GetFailedCategories()
	if len(failedCats) != 1 || failedCats[0] != "webvuln" {
		t.Fatalf("Expected FailedCategories [webvuln], got %v", failedCats)
	}
}

// E25: Snapshot/lifecycle persistence failure does not leave contradictory state
func TestIncomplete_E25_SnapshotLifecycleAtomicityOnFailure(t *testing.T) {
	store, _, cleanup := helperNewIncompleteTestStore(t)
	defer cleanup()

	clientID, tenantID, accountID, asmID := "cli_e25", "ten_e25", "acc_e25", "asm_e25"
	targetURL := "https://api.example.com"
	_, asm, _ := helperSetupLifecycleRun(t, store, clientID, asmID, tenantID, accountID, "tgt_e25", targetURL)
	authCtx := assessment.NewTenantAuthContext(clientID, tenantID, accountID)

	e1 := &assessment.AssessmentExecution{ID: "e1", AssessmentID: asmID, Status: assessment.StatusCompleted, StartedAt: time.Now().UTC().Add(-2 * time.Hour), CompletedAt: timePtr(time.Now().UTC().Add(-1 * time.Hour))}
	_ = store.CreateExecution(e1)
	af := helperMakeIncompleteFinding(asmID, e1.ID, "tgt_e25", "fnd_e25_1", "SQL Injection", "sqli", report.SeverityCritical, report.ConfidenceHigh, string(report.VerificationVerified), targetURL, targetURL+"/users", "GET")
	s1 := assessment.BuildAssessmentSnapshot(asm, e1, []string{targetURL}, []assessment.AssessmentFinding{af}, true)
	s1.TenantID, s1.AccountID = tenantID, accountID
	_ = store.CreateSnapshot(s1, []assessment.AssessmentFinding{af}, nil)

	// Attempt to create snapshot with invalid execution ID (foreign key failure in SQLite)
	invalidSnap := &assessment.AssessmentSnapshot{
		ID:            "snp_invalid_atomic",
		SnapshotRef:   "SNP-INVALID",
		AssessmentID:  asmID,
		ExecutionID:   "non_existent_exec_id", // Foreign key failure
		ClientID:      clientID,
		TenantID:      tenantID,
		AccountID:     accountID,
		Name:          "Invalid Snap",
		Status:        assessment.StatusCompleted,
		IsComplete:    true,
		StartedAt:     time.Now().UTC(),
		ScopedTargets: []string{targetURL},
	}
	err := store.CreateSnapshot(invalidSnap, nil, nil)
	if err == nil {
		t.Fatalf("Expected error when inserting snapshot with non-existent foreign key")
	}

	// Verify original finding lifecycle state is completely intact
	rec, err := store.GetFindingLifecycle(tenantID, accountID, af.Fingerprint, authCtx)
	if err != nil || rec.CurrentState != "NEW" {
		t.Fatalf("Lifecycle state corrupted after failed transaction: state=%q, err=%v", rec.CurrentState, err)
	}
}

// E26: Retrying an assessment preserves idempotency
func TestIncomplete_E26_RetryingAssessmentPreservesIdempotency(t *testing.T) {
	store, _, cleanup := helperNewIncompleteTestStore(t)
	defer cleanup()

	clientID, tenantID, accountID, asmID := "cli_e26", "ten_e26", "acc_e26", "asm_e26"
	targetURL := "https://api.example.com"
	_, asm, _ := helperSetupLifecycleRun(t, store, clientID, asmID, tenantID, accountID, "tgt_e26", targetURL)
	authCtx := assessment.NewTenantAuthContext(clientID, tenantID, accountID)

	e1 := &assessment.AssessmentExecution{ID: "e1", AssessmentID: asmID, Status: assessment.StatusCompleted, StartedAt: time.Now().UTC().Add(-2 * time.Hour), CompletedAt: timePtr(time.Now().UTC().Add(-1 * time.Hour))}
	_ = store.CreateExecution(e1)
	af := helperMakeIncompleteFinding(asmID, e1.ID, "tgt_e26", "fnd_e26_1", "XSS", "xss", report.SeverityHigh, report.ConfidenceHigh, string(report.VerificationVerified), targetURL, targetURL+"/view", "GET")
	s1 := assessment.BuildAssessmentSnapshot(asm, e1, []string{targetURL}, []assessment.AssessmentFinding{af}, true)
	s1.TenantID, s1.AccountID = tenantID, accountID

	if err := store.CreateSnapshot(s1, []assessment.AssessmentFinding{af}, nil); err != nil {
		t.Fatalf("First CreateSnapshot failed: %v", err)
	}
	if err := store.CreateSnapshot(s1, []assessment.AssessmentFinding{af}, nil); err != nil {
		t.Fatalf("Second CreateSnapshot retry failed: %v", err)
	}

	events, _ := store.GetFindingLifecycleEvents(af.Fingerprint, authCtx)
	if len(events) != 1 {
		t.Fatalf("Expected exactly 1 lifecycle event on retry, got %d", len(events))
	}
}

// E27: Existing immutable snapshots cannot be altered through incomplete assessment handling
func TestIncomplete_E27_ImmutableSnapshotsCannotBeAltered(t *testing.T) {
	store, _, cleanup := helperNewIncompleteTestStore(t)
	defer cleanup()

	clientID, tenantID, accountID, asmID := "cli_e27", "ten_e27", "acc_e27", "asm_e27"
	targetURL := "https://api.example.com"
	_, asm, _ := helperSetupLifecycleRun(t, store, clientID, asmID, tenantID, accountID, "tgt_e27", targetURL)

	e1 := &assessment.AssessmentExecution{ID: "e1", AssessmentID: asmID, Status: assessment.StatusCompleted, StartedAt: time.Now().UTC().Add(-2 * time.Hour), CompletedAt: timePtr(time.Now().UTC().Add(-1 * time.Hour))}
	_ = store.CreateExecution(e1)
	af := helperMakeIncompleteFinding(asmID, e1.ID, "tgt_e27", "fnd_e27_1", "SQL Injection", "sqli", report.SeverityCritical, report.ConfidenceHigh, string(report.VerificationVerified), targetURL, targetURL+"/users", "GET")
	s1 := assessment.BuildAssessmentSnapshot(asm, e1, []string{targetURL}, []assessment.AssessmentFinding{af}, true)
	s1.TenantID, s1.AccountID = tenantID, accountID
	_ = store.CreateSnapshot(s1, []assessment.AssessmentFinding{af}, nil)

	// Attempt conflicting snapshot creation with same execution ID but different status
	sConflict := assessment.BuildAssessmentSnapshot(asm, e1, []string{targetURL}, []assessment.AssessmentFinding{af}, false)
	sConflict.Status = assessment.StatusFailed
	sConflict.TenantID, sConflict.AccountID = tenantID, accountID

	err := store.CreateSnapshot(sConflict, []assessment.AssessmentFinding{af}, nil)
	if err == nil || err != assessment.ErrSnapshotImmutable {
		t.Fatalf("Expected ErrSnapshotImmutable on conflicting retry, got: %v", err)
	}
}

// E28: Report summaries do not count unassessed findings as resolved
func TestIncomplete_E28_ReportSummariesDoNotCountUnassessedAsResolved(t *testing.T) {
	// Baseline findings
	f1 := report.Finding{ID: "f1", Category: "sqli", Severity: report.SeverityCritical, Target: "https://api.example.com", Endpoint: "/users", Fingerprint: "fp_sqli"}
	f2 := report.Finding{ID: "f2", Category: "secrets", Severity: report.SeverityHigh, Target: "https://api.example.com", Endpoint: "/key", Fingerprint: "fp_secrets"}

	// Current assessment only scanned "sqli", omitted "secrets"
	opts := correlation.ComparisonOptions{
		CurrentCompleted: true,
		ScopedCategories: []string{"sqli"},
	}

	comp := correlation.CompareFindingsWithOptions([]report.Finding{f1, f2}, nil, opts)

	if comp.ResolvedCount != 1 {
		t.Fatalf("Expected 1 resolved finding (sqli), got %d", comp.ResolvedCount)
	}
	if comp.UnassessedCount != 1 {
		t.Fatalf("Expected 1 unassessed finding (secrets), got %d", comp.UnassessedCount)
	}

	// Verify report.Summarize behavior with unassessed findings
	findingsWithLifecycle := []report.Finding{
		{ID: "f1", Category: "sqli", LifecycleStatus: "RESOLVED"},
		{ID: "f2", Category: "secrets", LifecycleStatus: "UNASSESSED"},
	}
	sum := report.Summarize(findingsWithLifecycle)
	if sum.ResolvedCount != 1 {
		t.Fatalf("Expected Summary.ResolvedCount 1, got %d", sum.ResolvedCount)
	}
	if sum.UnassessedCount != 1 {
		t.Fatalf("Expected Summary.UnassessedCount 1, got %d", sum.UnassessedCount)
	}
}

// E29: Mixed successful and unsuccessful coverage produces accurate counts
func TestIncomplete_E29_MixedCoverageProducesAccurateSummaryCounts(t *testing.T) {
	fA := report.Finding{ID: "fA", Category: "xss", Severity: report.SeverityHigh, Target: "https://a.example.com", Fingerprint: "fp_a"}
	fB := report.Finding{ID: "fB", Category: "xss", Severity: report.SeverityHigh, Target: "https://b.example.com", Fingerprint: "fp_b"}

	opts := correlation.ComparisonOptions{
		CurrentCompleted: true,
		ScopedTargets:    []string{"https://a.example.com", "https://b.example.com"},
		AssessedTargets:  []string{"https://a.example.com"},
		FailedTargets:    []string{"https://b.example.com"},
	}

	comp := correlation.CompareFindingsWithOptions([]report.Finding{fA, fB}, nil, opts)

	if comp.ResolvedCount != 1 {
		t.Fatalf("Expected exactly 1 resolved finding (target A), got %d", comp.ResolvedCount)
	}
	if comp.UnassessedCount != 1 {
		t.Fatalf("Expected exactly 1 unassessed finding (target B), got %d", comp.UnassessedCount)
	}
}

// D30: ACTIVE finding survives incomplete scan without state alteration, then cleanly resolves in subsequent qualifying scan
func TestIncomplete_D30_ActiveFindingPreservedThroughIncompleteScanThenResolvedInQualifying(t *testing.T) {
	store, _, cleanup := helperNewIncompleteTestStore(t)
	defer cleanup()

	clientID, tenantID, accountID, asmID := "cli_d30", "ten_d30", "acc_d30", "asm_d30"
	targetURL := "https://api.example.com"
	_, asm, _ := helperSetupLifecycleRun(t, store, clientID, asmID, tenantID, accountID, "tgt_d30", targetURL)
	authCtx := assessment.NewTenantAuthContext(clientID, tenantID, accountID)

	// Run 1: NEW
	e1 := &assessment.AssessmentExecution{ID: "e1", AssessmentID: asmID, Status: assessment.StatusCompleted, StartedAt: time.Now().UTC().Add(-4 * time.Hour), CompletedAt: timePtr(time.Now().UTC().Add(-3 * time.Hour))}
	_ = store.CreateExecution(e1)
	af1 := helperMakeIncompleteFinding(asmID, e1.ID, "tgt_d30", "fnd_d30_1", "IDOR Vulnerability", "idor", report.SeverityHigh, report.ConfidenceHigh, string(report.VerificationVerified), targetURL, targetURL+"/user/123", "GET")
	s1 := assessment.BuildAssessmentSnapshot(asm, e1, []string{targetURL}, []assessment.AssessmentFinding{af1}, true)
	s1.TenantID, s1.AccountID = tenantID, accountID
	_ = store.CreateSnapshot(s1, []assessment.AssessmentFinding{af1}, nil)

	// Run 2: ACTIVE
	e2 := &assessment.AssessmentExecution{ID: "e2", AssessmentID: asmID, Status: assessment.StatusCompleted, StartedAt: time.Now().UTC().Add(-150 * time.Minute), CompletedAt: timePtr(time.Now().UTC().Add(-120 * time.Minute))}
	_ = store.CreateExecution(e2)
	af2 := helperMakeIncompleteFinding(asmID, e2.ID, "tgt_d30", "fnd_d30_2", "IDOR Vulnerability", "idor", report.SeverityHigh, report.ConfidenceHigh, string(report.VerificationVerified), targetURL, targetURL+"/user/123", "GET")
	s2 := assessment.BuildAssessmentSnapshot(asm, e2, []string{targetURL}, []assessment.AssessmentFinding{af2}, true)
	s2.TenantID, s2.AccountID = tenantID, accountID
	_ = store.CreateSnapshot(s2, []assessment.AssessmentFinding{af2}, nil)

	rec2, err := store.GetFindingLifecycle(tenantID, accountID, af1.Fingerprint, authCtx)
	if err != nil || rec2.CurrentState != "ACTIVE" {
		t.Fatalf("Expected ACTIVE after run 2, got %q (err: %v)", rec2.CurrentState, err)
	}

	// Run 3: Incomplete assessment (target failed) - finding absent
	e3 := &assessment.AssessmentExecution{ID: "e3", AssessmentID: asmID, Status: assessment.StatusCompletedWithErrors, StartedAt: time.Now().UTC().Add(-90 * time.Minute), CompletedAt: timePtr(time.Now().UTC().Add(-60 * time.Minute))}
	_ = store.CreateExecution(e3)
	s3 := assessment.BuildAssessmentSnapshot(asm, e3, []string{targetURL}, nil, true)
	s3.SetFailedTargets([]string{targetURL})
	s3.TenantID, s3.AccountID = tenantID, accountID
	_ = store.CreateSnapshot(s3, nil, nil)

	// Verify finding remains ACTIVE (not RESOLVED, and not overwritten with UNASSESSED)
	rec3, err := store.GetFindingLifecycle(tenantID, accountID, af1.Fingerprint, authCtx)
	if err != nil || rec3.CurrentState != "ACTIVE" {
		t.Fatalf("Expected state to remain ACTIVE after incomplete run 3, got %q (err: %v)", rec3.CurrentState, err)
	}

	// Run 4: Qualifying completed assessment with full coverage - finding absent -> RESOLVED!
	e4 := &assessment.AssessmentExecution{ID: "e4", AssessmentID: asmID, Status: assessment.StatusCompleted, StartedAt: time.Now().UTC().Add(-30 * time.Minute), CompletedAt: timePtr(time.Now().UTC().Add(-10 * time.Minute))}
	_ = store.CreateExecution(e4)
	s4 := assessment.BuildAssessmentSnapshot(asm, e4, []string{targetURL}, nil, true)
	s4.SetAssessedTargets([]string{targetURL})
	s4.SetCoveredCategories([]string{"idor"})
	s4.TenantID, s4.AccountID = tenantID, accountID
	_ = store.CreateSnapshot(s4, nil, nil)

	rec4, err := store.GetFindingLifecycle(tenantID, accountID, af1.Fingerprint, authCtx)
	if err != nil {
		t.Fatalf("Failed retrieving lifecycle after run 4: %v", err)
	}
	if rec4.CurrentState != "RESOLVED" {
		t.Fatalf("Expected RESOLVED after qualifying run 4, got %q", rec4.CurrentState)
	}
	if rec4.PreviousState != "ACTIVE" {
		t.Fatalf("Expected PreviousState ACTIVE on resolution, got %q", rec4.PreviousState)
	}
}

// D31: REGRESSED finding survives incomplete scan without state alteration, then cleanly resolves in subsequent qualifying scan
func TestIncomplete_D31_RegressedFindingPreservedThroughIncompleteScanThenResolvedInQualifying(t *testing.T) {
	store, _, cleanup := helperNewIncompleteTestStore(t)
	defer cleanup()

	clientID, tenantID, accountID, asmID := "cli_d31", "ten_d31", "acc_d31", "asm_d31"
	targetURL := "https://api.example.com"
	_, asm, _ := helperSetupLifecycleRun(t, store, clientID, asmID, tenantID, accountID, "tgt_d31", targetURL)
	authCtx := assessment.NewTenantAuthContext(clientID, tenantID, accountID)

	// Run 1: NEW
	e1 := &assessment.AssessmentExecution{ID: "e1", AssessmentID: asmID, Status: assessment.StatusCompleted, StartedAt: time.Now().UTC().Add(-5 * time.Hour), CompletedAt: timePtr(time.Now().UTC().Add(-4 * time.Hour))}
	_ = store.CreateExecution(e1)
	af1 := helperMakeIncompleteFinding(asmID, e1.ID, "tgt_d31", "fnd_d31_1", "Stored XSS", "xss", report.SeverityHigh, report.ConfidenceHigh, string(report.VerificationVerified), targetURL, targetURL+"/comment", "POST")
	s1 := assessment.BuildAssessmentSnapshot(asm, e1, []string{targetURL}, []assessment.AssessmentFinding{af1}, true)
	s1.TenantID, s1.AccountID = tenantID, accountID
	_ = store.CreateSnapshot(s1, []assessment.AssessmentFinding{af1}, nil)

	// Run 2: RESOLVED (qualifying complete scan)
	e2 := &assessment.AssessmentExecution{ID: "e2", AssessmentID: asmID, Status: assessment.StatusCompleted, StartedAt: time.Now().UTC().Add(-3 * time.Hour), CompletedAt: timePtr(time.Now().UTC().Add(-2 * time.Hour))}
	_ = store.CreateExecution(e2)
	s2 := assessment.BuildAssessmentSnapshot(asm, e2, []string{targetURL}, nil, true)
	s2.SetAssessedTargets([]string{targetURL})
	s2.SetCoveredCategories([]string{"xss"})
	s2.TenantID, s2.AccountID = tenantID, accountID
	_ = store.CreateSnapshot(s2, nil, nil)

	rec2, _ := store.GetFindingLifecycle(tenantID, accountID, af1.Fingerprint, authCtx)
	if rec2.CurrentState != "RESOLVED" {
		t.Fatalf("Expected RESOLVED after run 2, got %q", rec2.CurrentState)
	}

	// Run 3: REGRESSED (detected again)
	e3 := &assessment.AssessmentExecution{ID: "e3", AssessmentID: asmID, Status: assessment.StatusCompleted, StartedAt: time.Now().UTC().Add(-90 * time.Minute), CompletedAt: timePtr(time.Now().UTC().Add(-60 * time.Minute))}
	_ = store.CreateExecution(e3)
	af3 := helperMakeIncompleteFinding(asmID, e3.ID, "tgt_d31", "fnd_d31_3", "Stored XSS", "xss", report.SeverityHigh, report.ConfidenceHigh, string(report.VerificationVerified), targetURL, targetURL+"/comment", "POST")
	s3 := assessment.BuildAssessmentSnapshot(asm, e3, []string{targetURL}, []assessment.AssessmentFinding{af3}, true)
	s3.TenantID, s3.AccountID = tenantID, accountID
	_ = store.CreateSnapshot(s3, []assessment.AssessmentFinding{af3}, nil)

	rec3, _ := store.GetFindingLifecycle(tenantID, accountID, af1.Fingerprint, authCtx)
	if rec3.CurrentState != "REGRESSED" {
		t.Fatalf("Expected REGRESSED after run 3, got %q", rec3.CurrentState)
	}

	// Run 4: Incomplete assessment (detector skipped category xss) - finding absent
	e4 := &assessment.AssessmentExecution{ID: "e4", AssessmentID: asmID, Status: assessment.StatusCompleted, StartedAt: time.Now().UTC().Add(-45 * time.Minute), CompletedAt: timePtr(time.Now().UTC().Add(-30 * time.Minute))}
	_ = store.CreateExecution(e4)
	s4 := assessment.BuildAssessmentSnapshot(asm, e4, []string{targetURL}, nil, true)
	s4.SetAssessedTargets([]string{targetURL})
	s4.SetSkippedCategories([]string{"xss"})
	s4.TenantID, s4.AccountID = tenantID, accountID
	_ = store.CreateSnapshot(s4, nil, nil)

	// Verify finding remains REGRESSED (not resolved)
	rec4, err := store.GetFindingLifecycle(tenantID, accountID, af1.Fingerprint, authCtx)
	if err != nil || rec4.CurrentState != "REGRESSED" {
		t.Fatalf("Expected state to remain REGRESSED after incomplete run 4, got %q (err: %v)", rec4.CurrentState, err)
	}

	// Run 5: Qualifying completed assessment with category xss assessed - finding absent -> RESOLVED!
	e5 := &assessment.AssessmentExecution{ID: "e5", AssessmentID: asmID, Status: assessment.StatusCompleted, StartedAt: time.Now().UTC().Add(-20 * time.Minute), CompletedAt: timePtr(time.Now().UTC().Add(-5 * time.Minute))}
	_ = store.CreateExecution(e5)
	s5 := assessment.BuildAssessmentSnapshot(asm, e5, []string{targetURL}, nil, true)
	s5.SetAssessedTargets([]string{targetURL})
	s5.SetCoveredCategories([]string{"xss"})
	s5.TenantID, s5.AccountID = tenantID, accountID
	_ = store.CreateSnapshot(s5, nil, nil)

	rec5, err := store.GetFindingLifecycle(tenantID, accountID, af1.Fingerprint, authCtx)
	if err != nil {
		t.Fatalf("Failed retrieving lifecycle after run 5: %v", err)
	}
	if rec5.CurrentState != "RESOLVED" {
		t.Fatalf("Expected RESOLVED after qualifying run 5, got %q", rec5.CurrentState)
	}
	if rec5.PreviousState != "REGRESSED" {
		t.Fatalf("Expected PreviousState REGRESSED on resolution, got %q", rec5.PreviousState)
	}
}

// D32: Finding reliably detected during partial/incomplete assessment updates according to lifecycle rules
func TestIncomplete_D32_FindingDetectedDuringPartialScanUpdatesLifecycleRules(t *testing.T) {
	store, _, cleanup := helperNewIncompleteTestStore(t)
	defer cleanup()

	clientID, tenantID, accountID, asmID := "cli_d32", "ten_d32", "acc_d32", "asm_d32"
	targetURL := "https://api.example.com"
	_, asm, _ := helperSetupLifecycleRun(t, store, clientID, asmID, tenantID, accountID, "tgt_d32", targetURL)
	authCtx := assessment.NewTenantAuthContext(clientID, tenantID, accountID)

	// Run 1: NEW
	e1 := &assessment.AssessmentExecution{ID: "e1", AssessmentID: asmID, Status: assessment.StatusCompleted, StartedAt: time.Now().UTC().Add(-4 * time.Hour), CompletedAt: timePtr(time.Now().UTC().Add(-3 * time.Hour))}
	_ = store.CreateExecution(e1)
	af1 := helperMakeIncompleteFinding(asmID, e1.ID, "tgt_d32", "fnd_d32_1", "Exposed Secret", "secrets", report.SeverityCritical, report.ConfidenceHigh, string(report.VerificationVerified), targetURL, targetURL+"/config.json", "GET")
	s1 := assessment.BuildAssessmentSnapshot(asm, e1, []string{targetURL}, []assessment.AssessmentFinding{af1}, true)
	s1.TenantID, s1.AccountID = tenantID, accountID
	_ = store.CreateSnapshot(s1, []assessment.AssessmentFinding{af1}, nil)

	// Run 2: Conclusively RESOLVED
	e2 := &assessment.AssessmentExecution{ID: "e2", AssessmentID: asmID, Status: assessment.StatusCompleted, StartedAt: time.Now().UTC().Add(-2 * time.Hour), CompletedAt: timePtr(time.Now().UTC().Add(-90 * time.Minute))}
	_ = store.CreateExecution(e2)
	s2 := assessment.BuildAssessmentSnapshot(asm, e2, []string{targetURL}, nil, true)
	s2.SetAssessedTargets([]string{targetURL})
	s2.SetCoveredCategories([]string{"secrets"})
	s2.TenantID, s2.AccountID = tenantID, accountID
	_ = store.CreateSnapshot(s2, nil, nil)

	rec2, _ := store.GetFindingLifecycle(tenantID, accountID, af1.Fingerprint, authCtx)
	if rec2.CurrentState != "RESOLVED" {
		t.Fatalf("Expected RESOLVED after run 2, got %q", rec2.CurrentState)
	}

	// Run 3: Incomplete/partial execution (e.g. deadline exceeded on other targets), BUT finding is reliably detected!
	e3 := &assessment.AssessmentExecution{ID: "e3", AssessmentID: asmID, Status: assessment.StatusFailed, ErrorMessage: "Target deadline exceeded", StartedAt: time.Now().UTC().Add(-60 * time.Minute), CompletedAt: timePtr(time.Now().UTC().Add(-40 * time.Minute))}
	_ = store.CreateExecution(e3)
	af3 := helperMakeIncompleteFinding(asmID, e3.ID, "tgt_d32", "fnd_d32_3", "Exposed Secret", "secrets", report.SeverityCritical, report.ConfidenceHigh, string(report.VerificationVerified), targetURL, targetURL+"/config.json", "GET")
	s3 := assessment.BuildAssessmentSnapshot(asm, e3, []string{targetURL}, []assessment.AssessmentFinding{af3}, false)
	s3.Metadata["inconclusive"] = "true"
	s3.Metadata["is_partial"] = "true"
	s3.TenantID, s3.AccountID = tenantID, accountID
	_ = store.CreateSnapshot(s3, []assessment.AssessmentFinding{af3}, nil)

	// Finding was detected! It must transition from RESOLVED to REGRESSED according to lifecycle rules!
	rec3, err := store.GetFindingLifecycle(tenantID, accountID, af1.Fingerprint, authCtx)
	if err != nil {
		t.Fatalf("Failed retrieving lifecycle after run 3: %v", err)
	}
	if rec3.CurrentState != "REGRESSED" {
		t.Fatalf("Expected finding reliably detected in partial scan to transition to REGRESSED, got %q", rec3.CurrentState)
	}
	if rec3.PreviousState != "RESOLVED" {
		t.Fatalf("Expected PreviousState RESOLVED, got %q", rec3.PreviousState)
	}
	if rec3.RegressionCount != 1 {
		t.Fatalf("Expected RegressionCount 1, got %d", rec3.RegressionCount)
	}

	// Run 4: Qualifying completed assessment where finding is absent -> RESOLVED again!
	e4 := &assessment.AssessmentExecution{ID: "e4", AssessmentID: asmID, Status: assessment.StatusCompleted, StartedAt: time.Now().UTC().Add(-30 * time.Minute), CompletedAt: timePtr(time.Now().UTC().Add(-10 * time.Minute))}
	_ = store.CreateExecution(e4)
	s4 := assessment.BuildAssessmentSnapshot(asm, e4, []string{targetURL}, nil, true)
	s4.SetAssessedTargets([]string{targetURL})
	s4.SetCoveredCategories([]string{"secrets"})
	s4.TenantID, s4.AccountID = tenantID, accountID
	_ = store.CreateSnapshot(s4, nil, nil)

	rec4, err := store.GetFindingLifecycle(tenantID, accountID, af1.Fingerprint, authCtx)
	if err != nil {
		t.Fatalf("Failed retrieving lifecycle after run 4: %v", err)
	}
	if rec4.CurrentState != "RESOLVED" {
		t.Fatalf("Expected RESOLVED after qualifying run 4, got %q", rec4.CurrentState)
	}
	if rec4.PreviousState != "REGRESSED" {
		t.Fatalf("Expected PreviousState REGRESSED, got %q", rec4.PreviousState)
	}
}
