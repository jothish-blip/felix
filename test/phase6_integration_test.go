package test

import (
	"errors"
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
// PHASE 6 — FINAL INTEGRATION VERIFICATION SUITE
// Verifies end-to-end consistency across all Phase 6 subphases:
//   6.1 Risk Scoring
//   6.2 Finding Correlation & Asset Association
//   6.3 Stable Finding Fingerprints
//   6.4 Finding Deduplication
//   6.5 Assessment Snapshots & Historical Evidence
//   6.6 Finding Lifecycle Management
//   6.7 Incomplete Assessment Handling
// =============================================================================

func helperNewPhase6IntegrationStore(t *testing.T) (assessment.Store, string, func()) {
	t.Helper()
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, fmt.Sprintf("phase6_integration_%d.db", time.Now().UnixNano()))
	store, err := assessment.NewSQLiteStore(dbPath)
	if err != nil {
		t.Fatalf("failed to create sqlite store: %v", err)
	}
	cleanup := func() {
		_ = store.Close()
	}
	return store, dbPath, cleanup
}

func helperMakePhase6Finding(asmID, execID, targetID, id, title, ruleID, severity, conf, verStatus, targetURL, endpoint, method, observation string) assessment.AssessmentFinding {
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
			Observation: observation,
			Details:     make(map[string]string),
		},
		Verification: report.VerificationRecord{
			Status: report.VerificationStatus(verStatus),
			Result: fmt.Sprintf("Verification result for %s", title),
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
// SCENARIO A: Repeated Assessment Stability
// -----------------------------------------------------------------------------
// Run two equivalent assessments containing the same underlying findings,
// allowing mutable attributes (timestamps, evidence details, observation) to vary.
// Verifies stable identity, deduplication, consistent risk score, lifecycle continuity,
// and accurate historical comparison.
func TestPhase6_Integration_ScenarioA_RepeatedAssessmentStability(t *testing.T) {
	store, _, cleanup := helperNewPhase6IntegrationStore(t)
	defer cleanup()

	clientID, tenantID, accountID, asmID := "cli_scen_a", "ten_scen_a", "acc_scen_a", "asm_scen_a"
	targetURL := "https://app.example.com"
	_, asm, tgt := helperSetupLifecycleRun(t, store, clientID, asmID, tenantID, accountID, "tgt_a", targetURL)
	authCtx := assessment.NewTenantAuthContext(clientID, tenantID, accountID)

	// Run 1: Two duplicate findings with different observations on same endpoint
	e1 := &assessment.AssessmentExecution{
		ID:           "exec_a_1",
		AssessmentID: asmID,
		Status:       assessment.StatusCompleted,
		StartedAt:    time.Now().UTC().Add(-2 * time.Hour),
		CompletedAt:  timePtr(time.Now().UTC().Add(-90 * time.Minute)),
	}
	_ = store.CreateExecution(e1)

	af1a := helperMakePhase6Finding(asmID, e1.ID, tgt.ID, "fnd_a1", "SQL Injection in Login", "sqli", report.SeverityCritical, report.ConfidenceHigh, string(report.VerificationVerified), targetURL, targetURL+"/api/login", "POST", "Observation at T1: admin' OR '1'='1")
	af1b := helperMakePhase6Finding(asmID, e1.ID, tgt.ID, "fnd_a2", "SQL Injection in Login", "sqli", report.SeverityCritical, report.ConfidenceHigh, string(report.VerificationVerified), targetURL, targetURL+"/api/login", "POST", "Observation at T2: ' UNION SELECT 1--")

	// Deduplicate
	dedup1 := correlation.NewDeduplicator(nil).Deduplicate([]report.Finding{
		assessment.ToReportFinding(af1a),
		assessment.ToReportFinding(af1b),
	})
	if dedup1.TotalInputCount != 2 || dedup1.DeduplicatedCount != 1 {
		t.Fatalf("Expected 2 findings to consolidate into 1, got input %d, dedup %d", dedup1.TotalInputCount, dedup1.DeduplicatedCount)
	}

	canonicalAF1 := assessment.ToAssessmentFinding(asmID, e1.ID, tgt.ID, dedup1.CanonicalFindings[0])
	s1 := assessment.BuildAssessmentSnapshot(asm, e1, []string{targetURL}, []assessment.AssessmentFinding{canonicalAF1}, true)
	s1.TenantID, s1.AccountID = tenantID, accountID
	s1.SetAssessedTargets([]string{targetURL})
	s1.SetCoveredCategories([]string{"sqli"})

	ev1 := assessment.ExtractHistoricalEvidence(s1.ID, []assessment.AssessmentFinding{canonicalAF1})
	if err := store.CreateSnapshot(s1, []assessment.AssessmentFinding{canonicalAF1}, ev1); err != nil {
		t.Fatalf("CreateSnapshot 1 failed: %v", err)
	}

	// Verify initial lifecycle state is NEW
	rec1, err := store.GetFindingLifecycle(tenantID, accountID, canonicalAF1.Fingerprint, authCtx)
	if err != nil || rec1.CurrentState != "NEW" {
		t.Fatalf("Expected NEW after run 1, got %q (err: %v)", rec1.CurrentState, err)
	}
	initialScore := rec1.Score
	if initialScore <= 0 {
		t.Fatalf("Expected positive score, got %d", initialScore)
	}

	// Run 2: Same underlying finding detected in next assessment with varying mutable details
	e2 := &assessment.AssessmentExecution{
		ID:           "exec_a_2",
		AssessmentID: asmID,
		Status:       assessment.StatusCompleted,
		StartedAt:    time.Now().UTC().Add(-45 * time.Minute),
		CompletedAt:  timePtr(time.Now().UTC().Add(-15 * time.Minute)),
	}
	_ = store.CreateExecution(e2)

	af2 := helperMakePhase6Finding(asmID, e2.ID, tgt.ID, "fnd_a3", "SQL Injection in Login (Updated)", "sqli", report.SeverityCritical, report.ConfidenceHigh, string(report.VerificationVerified), targetURL, targetURL+"/api/login", "POST", "Observation at T3 with altered debug payload")

	// Identity stability check: fingerprint must match exactly despite title and observation changes
	if af2.Fingerprint != canonicalAF1.Fingerprint {
		t.Fatalf("Fingerprint mismatch across runs: run1=%s, run2=%s", canonicalAF1.Fingerprint, af2.Fingerprint)
	}

	s2 := assessment.BuildAssessmentSnapshot(asm, e2, []string{targetURL}, []assessment.AssessmentFinding{af2}, true)
	s2.TenantID, s2.AccountID = tenantID, accountID
	s2.SetAssessedTargets([]string{targetURL})
	s2.SetCoveredCategories([]string{"sqli"})

	ev2 := assessment.ExtractHistoricalEvidence(s2.ID, []assessment.AssessmentFinding{af2})
	if err := store.CreateSnapshot(s2, []assessment.AssessmentFinding{af2}, ev2); err != nil {
		t.Fatalf("CreateSnapshot 2 failed: %v", err)
	}

	// Lifecycle continuity check: transitions to ACTIVE
	rec2, err := store.GetFindingLifecycle(tenantID, accountID, canonicalAF1.Fingerprint, authCtx)
	if err != nil || rec2.CurrentState != "ACTIVE" {
		t.Fatalf("Expected ACTIVE after run 2, got %q (err: %v)", rec2.CurrentState, err)
	}
	if rec2.PreviousState != "NEW" {
		t.Fatalf("Expected PreviousState NEW, got %q", rec2.PreviousState)
	}
	if rec2.Score != initialScore {
		t.Fatalf("Score changed unexpectedly: initial=%d, current=%d", initialScore, rec2.Score)
	}

	// Historical comparison check
	cmp, err := store.CompareSnapshots(s1.ID, s2.ID, authCtx)
	if err != nil {
		t.Fatalf("CompareSnapshots failed: %v", err)
	}
	if cmp.ActiveCount != 1 || cmp.NewCount != 0 || cmp.ResolvedCount != 0 || cmp.NetRiskScoreDelta != 0 {
		t.Fatalf("Comparison mismatch: Active=%d (want 1), New=%d (want 0), Resolved=%d (want 0), Delta=%d (want 0)",
			cmp.ActiveCount, cmp.NewCount, cmp.ResolvedCount, cmp.NetRiskScoreDelta)
	}
}

// -----------------------------------------------------------------------------
// SCENARIO B: Distinct Findings
// -----------------------------------------------------------------------------
// Multiple distinct findings on the same target and related assets.
// Verifies legitimate distinct findings remain separate and all target/asset
// associations survive normalization, deduplication, persistence, and reporting.
func TestPhase6_Integration_ScenarioB_DistinctFindings(t *testing.T) {
	store, _, cleanup := helperNewPhase6IntegrationStore(t)
	defer cleanup()

	clientID, tenantID, accountID, asmID := "cli_scen_b", "ten_scen_b", "acc_scen_b", "asm_scen_b"
	targetURL := "https://api.example.com"
	_, asm, tgt := helperSetupLifecycleRun(t, store, clientID, asmID, tenantID, accountID, "tgt_b", targetURL)
	authCtx := assessment.NewTenantAuthContext(clientID, tenantID, accountID)

	e1 := &assessment.AssessmentExecution{
		ID:           "exec_b_1",
		AssessmentID: asmID,
		Status:       assessment.StatusCompleted,
		StartedAt:    time.Now().UTC().Add(-1 * time.Hour),
		CompletedAt:  timePtr(time.Now().UTC().Add(-30 * time.Minute)),
	}
	_ = store.CreateExecution(e1)

	// 4 distinct findings
	f1 := helperMakePhase6Finding(asmID, e1.ID, tgt.ID, "f_sqli", "SQL Injection", "sqli", report.SeverityCritical, report.ConfidenceHigh, string(report.VerificationVerified), targetURL, targetURL+"/search", "GET", "sqli obs")
	f2 := helperMakePhase6Finding(asmID, e1.ID, tgt.ID, "f_xss", "Stored XSS", "xss", report.SeverityHigh, report.ConfidenceHigh, string(report.VerificationVerified), targetURL, targetURL+"/comments", "POST", "xss obs")
	f3 := helperMakePhase6Finding(asmID, e1.ID, tgt.ID, "f_hdr", "Missing HSTS", "missing-hsts", report.SeverityLow, report.ConfidenceHigh, string(report.VerificationVerified), targetURL, targetURL+"/", "GET", "hsts obs")
	f4 := helperMakePhase6Finding(asmID, e1.ID, tgt.ID, "f_sec", "Hardcoded API Key", "secrets", report.SeverityCritical, report.ConfidenceHigh, string(report.VerificationVerified), targetURL, targetURL+"/config.json", "GET", "secret obs")

	// Verify all fingerprints are distinct
	fpSet := make(map[string]struct{})
	for _, f := range []assessment.AssessmentFinding{f1, f2, f3, f4} {
		if _, exists := fpSet[f.Fingerprint]; exists {
			t.Fatalf("Fingerprint collision detected for distinct finding: %s", f.Fingerprint)
		}
		fpSet[f.Fingerprint] = struct{}{}
	}

	// Deduplication must preserve all 4 distinct findings
	repFindings := []report.Finding{
		assessment.ToReportFinding(f1),
		assessment.ToReportFinding(f2),
		assessment.ToReportFinding(f3),
		assessment.ToReportFinding(f4),
	}
	dedup := correlation.NewDeduplicator(nil).Deduplicate(repFindings)
	if dedup.DeduplicatedCount != 4 {
		t.Fatalf("Expected 4 distinct findings to be preserved, got %d", dedup.DeduplicatedCount)
	}

	var canonicalAFs []assessment.AssessmentFinding
	for _, rf := range dedup.CanonicalFindings {
		canonicalAFs = append(canonicalAFs, assessment.ToAssessmentFinding(asmID, e1.ID, tgt.ID, rf))
	}

	s1 := assessment.BuildAssessmentSnapshot(asm, e1, []string{targetURL}, canonicalAFs, true)
	s1.TenantID, s1.AccountID = tenantID, accountID
	s1.SetAssessedTargets([]string{targetURL})
	s1.SetCoveredCategories([]string{"sqli", "xss", "missing-hsts", "secrets"})

	ev := assessment.ExtractHistoricalEvidence(s1.ID, canonicalAFs)
	if err := store.CreateSnapshot(s1, canonicalAFs, ev); err != nil {
		t.Fatalf("CreateSnapshot failed: %v", err)
	}

	// Verify all 4 lifecycle records created independently
	lifecycles, count, err := store.ListFindingLifecycles(assessment.FindingLifecycleListOptions{
		Auth:     authCtx,
		TenantID: tenantID,
	})
	if err != nil || count != 4 {
		t.Fatalf("Expected 4 lifecycle records, got %d (err: %v)", count, err)
	}
	for _, lc := range lifecycles {
		if lc.CurrentState != "NEW" {
			t.Errorf("Finding %s: expected NEW, got %s", lc.Title, lc.CurrentState)
		}
	}
}

// -----------------------------------------------------------------------------
// SCENARIO C: Remediation
// -----------------------------------------------------------------------------
// Start with an active finding, then run a qualifying assessment with adequate
// target and detector coverage in which that finding is absent.
// Verifies ACTIVE -> RESOLVED transition, preserved historical evidence, and accurate reporting.
func TestPhase6_Integration_ScenarioC_Remediation(t *testing.T) {
	store, _, cleanup := helperNewPhase6IntegrationStore(t)
	defer cleanup()

	clientID, tenantID, accountID, asmID := "cli_scen_c", "ten_scen_c", "acc_scen_c", "asm_scen_c"
	targetURL := "https://api.example.com"
	_, asm, tgt := helperSetupLifecycleRun(t, store, clientID, asmID, tenantID, accountID, "tgt_c", targetURL)
	authCtx := assessment.NewTenantAuthContext(clientID, tenantID, accountID)

	// Run 1: Discovery -> NEW
	e1 := &assessment.AssessmentExecution{
		ID:           "exec_c_1",
		AssessmentID: asmID,
		Status:       assessment.StatusCompleted,
		StartedAt:    time.Now().UTC().Add(-3 * time.Hour),
		CompletedAt:  timePtr(time.Now().UTC().Add(-2 * time.Hour)),
	}
	_ = store.CreateExecution(e1)
	af1 := helperMakePhase6Finding(asmID, e1.ID, tgt.ID, "f_csrf", "Missing CSRF Protection", "csrf", report.SeverityHigh, report.ConfidenceHigh, string(report.VerificationVerified), targetURL, targetURL+"/transfer", "POST", "No anti-CSRF token")
	s1 := assessment.BuildAssessmentSnapshot(asm, e1, []string{targetURL}, []assessment.AssessmentFinding{af1}, true)
	s1.TenantID, s1.AccountID = tenantID, accountID
	s1.SetAssessedTargets([]string{targetURL})
	s1.SetCoveredCategories([]string{"csrf"})
	_ = store.CreateSnapshot(s1, []assessment.AssessmentFinding{af1}, assessment.ExtractHistoricalEvidence(s1.ID, []assessment.AssessmentFinding{af1}))

	// Run 2: Confirmed -> ACTIVE
	e2 := &assessment.AssessmentExecution{
		ID:           "exec_c_2",
		AssessmentID: asmID,
		Status:       assessment.StatusCompleted,
		StartedAt:    time.Now().UTC().Add(-90 * time.Minute),
		CompletedAt:  timePtr(time.Now().UTC().Add(-60 * time.Minute)),
	}
	_ = store.CreateExecution(e2)
	af2 := helperMakePhase6Finding(asmID, e2.ID, tgt.ID, "f_csrf_2", "Missing CSRF Protection", "csrf", report.SeverityHigh, report.ConfidenceHigh, string(report.VerificationVerified), targetURL, targetURL+"/transfer", "POST", "Still no token")
	s2 := assessment.BuildAssessmentSnapshot(asm, e2, []string{targetURL}, []assessment.AssessmentFinding{af2}, true)
	s2.TenantID, s2.AccountID = tenantID, accountID
	s2.SetAssessedTargets([]string{targetURL})
	s2.SetCoveredCategories([]string{"csrf"})
	_ = store.CreateSnapshot(s2, []assessment.AssessmentFinding{af2}, assessment.ExtractHistoricalEvidence(s2.ID, []assessment.AssessmentFinding{af2}))

	rec2, _ := store.GetFindingLifecycle(tenantID, accountID, af1.Fingerprint, authCtx)
	if rec2.CurrentState != "ACTIVE" {
		t.Fatalf("Expected ACTIVE after run 2, got %q", rec2.CurrentState)
	}

	// Run 3: Remediation! Qualifying completed assessment, finding absent
	e3 := &assessment.AssessmentExecution{
		ID:           "exec_c_3",
		AssessmentID: asmID,
		Status:       assessment.StatusCompleted,
		StartedAt:    time.Now().UTC().Add(-30 * time.Minute),
		CompletedAt:  timePtr(time.Now().UTC().Add(-10 * time.Minute)),
	}
	_ = store.CreateExecution(e3)
	s3 := assessment.BuildAssessmentSnapshot(asm, e3, []string{targetURL}, nil, true)
	s3.TenantID, s3.AccountID = tenantID, accountID
	s3.SetAssessedTargets([]string{targetURL})
	s3.SetCoveredCategories([]string{"csrf"})
	if err := store.CreateSnapshot(s3, nil, nil); err != nil {
		t.Fatalf("CreateSnapshot 3 failed: %v", err)
	}

	// Verify transition to RESOLVED
	rec3, err := store.GetFindingLifecycle(tenantID, accountID, af1.Fingerprint, authCtx)
	if err != nil || rec3.CurrentState != "RESOLVED" {
		t.Fatalf("Expected RESOLVED after remediation scan, got %q (err: %v)", rec3.CurrentState, err)
	}
	if rec3.PreviousState != "ACTIVE" {
		t.Fatalf("Expected PreviousState ACTIVE, got %q", rec3.PreviousState)
	}
	if rec3.ResolvedAt == nil || rec3.ResolvedAt.IsZero() {
		t.Fatalf("Expected valid ResolvedAt timestamp")
	}

	// Verify historical comparison confirms resolution
	cmp, err := store.CompareSnapshots(s2.ID, s3.ID, authCtx)
	if err != nil {
		t.Fatalf("CompareSnapshots failed: %v", err)
	}
	if cmp.ResolvedCount != 1 || cmp.ActiveCount != 0 {
		t.Fatalf("Expected ResolvedCount=1, ActiveCount=0; got Resolved=%d, Active=%d", cmp.ResolvedCount, cmp.ActiveCount)
	}

	// Historical evidence for Snapshot 1 and 2 must remain preserved and accessible
	evSnapshot2, err := store.GetHistoricalEvidence(s2.ID, "", authCtx)
	if err != nil || len(evSnapshot2) != 1 {
		t.Fatalf("Expected 1 historical evidence record for Snapshot 2, got %d (err: %v)", len(evSnapshot2), err)
	}
}

// -----------------------------------------------------------------------------
// SCENARIO D: Regression
// -----------------------------------------------------------------------------
// After resolution, detect the same underlying finding again.
// Verifies RESOLVED -> REGRESSED behavior and subsequent lifecycle transitions.
func TestPhase6_Integration_ScenarioD_Regression(t *testing.T) {
	store, _, cleanup := helperNewPhase6IntegrationStore(t)
	defer cleanup()

	clientID, tenantID, accountID, asmID := "cli_scen_d", "ten_scen_d", "acc_scen_d", "asm_scen_d"
	targetURL := "https://api.example.com"
	_, asm, tgt := helperSetupLifecycleRun(t, store, clientID, asmID, tenantID, accountID, "tgt_d", targetURL)
	authCtx := assessment.NewTenantAuthContext(clientID, tenantID, accountID)

	// Step 1: Active -> Resolved
	e1 := &assessment.AssessmentExecution{ID: "e1", AssessmentID: asmID, Status: assessment.StatusCompleted, StartedAt: time.Now().UTC().Add(-4 * time.Hour), CompletedAt: timePtr(time.Now().UTC().Add(-3 * time.Hour))}
	_ = store.CreateExecution(e1)
	af1 := helperMakePhase6Finding(asmID, e1.ID, tgt.ID, "f_idor", "IDOR in Profile", "idor", report.SeverityHigh, report.ConfidenceHigh, string(report.VerificationVerified), targetURL, targetURL+"/profile/100", "GET", "IDOR obs")
	s1 := assessment.BuildAssessmentSnapshot(asm, e1, []string{targetURL}, []assessment.AssessmentFinding{af1}, true)
	s1.TenantID, s1.AccountID = tenantID, accountID
	s1.SetAssessedTargets([]string{targetURL})
	s1.SetCoveredCategories([]string{"idor"})
	_ = store.CreateSnapshot(s1, []assessment.AssessmentFinding{af1}, nil)

	e2 := &assessment.AssessmentExecution{ID: "e2", AssessmentID: asmID, Status: assessment.StatusCompleted, StartedAt: time.Now().UTC().Add(-2 * time.Hour), CompletedAt: timePtr(time.Now().UTC().Add(-90 * time.Minute))}
	_ = store.CreateExecution(e2)
	s2 := assessment.BuildAssessmentSnapshot(asm, e2, []string{targetURL}, nil, true)
	s2.TenantID, s2.AccountID = tenantID, accountID
	s2.SetAssessedTargets([]string{targetURL})
	s2.SetCoveredCategories([]string{"idor"})
	_ = store.CreateSnapshot(s2, nil, nil)

	rec2, _ := store.GetFindingLifecycle(tenantID, accountID, af1.Fingerprint, authCtx)
	if rec2.CurrentState != "RESOLVED" {
		t.Fatalf("Expected RESOLVED, got %q", rec2.CurrentState)
	}

	// Step 2: Re-detection -> REGRESSED
	e3 := &assessment.AssessmentExecution{ID: "e3", AssessmentID: asmID, Status: assessment.StatusCompleted, StartedAt: time.Now().UTC().Add(-60 * time.Minute), CompletedAt: timePtr(time.Now().UTC().Add(-40 * time.Minute))}
	_ = store.CreateExecution(e3)
	af3 := helperMakePhase6Finding(asmID, e3.ID, tgt.ID, "f_idor_reg", "IDOR in Profile", "idor", report.SeverityHigh, report.ConfidenceHigh, string(report.VerificationVerified), targetURL, targetURL+"/profile/100", "GET", "IDOR re-detected")
	s3 := assessment.BuildAssessmentSnapshot(asm, e3, []string{targetURL}, []assessment.AssessmentFinding{af3}, true)
	s3.TenantID, s3.AccountID = tenantID, accountID
	s3.SetAssessedTargets([]string{targetURL})
	s3.SetCoveredCategories([]string{"idor"})
	_ = store.CreateSnapshot(s3, []assessment.AssessmentFinding{af3}, nil)

	rec3, err := store.GetFindingLifecycle(tenantID, accountID, af1.Fingerprint, authCtx)
	if err != nil || rec3.CurrentState != "REGRESSED" {
		t.Fatalf("Expected REGRESSED after re-detection, got %q (err: %v)", rec3.CurrentState, err)
	}
	if rec3.PreviousState != "RESOLVED" {
		t.Fatalf("Expected PreviousState RESOLVED, got %q", rec3.PreviousState)
	}
	if rec3.RegressionCount != 1 {
		t.Fatalf("Expected RegressionCount 1, got %d", rec3.RegressionCount)
	}

	// Step 3: Continued observation after regression -> transitions to ACTIVE
	e4 := &assessment.AssessmentExecution{ID: "e4", AssessmentID: asmID, Status: assessment.StatusCompleted, StartedAt: time.Now().UTC().Add(-30 * time.Minute), CompletedAt: timePtr(time.Now().UTC().Add(-10 * time.Minute))}
	_ = store.CreateExecution(e4)
	af4 := helperMakePhase6Finding(asmID, e4.ID, tgt.ID, "f_idor_act", "IDOR in Profile", "idor", report.SeverityHigh, report.ConfidenceHigh, string(report.VerificationVerified), targetURL, targetURL+"/profile/100", "GET", "IDOR persistent")
	s4 := assessment.BuildAssessmentSnapshot(asm, e4, []string{targetURL}, []assessment.AssessmentFinding{af4}, true)
	s4.TenantID, s4.AccountID = tenantID, accountID
	s4.SetAssessedTargets([]string{targetURL})
	s4.SetCoveredCategories([]string{"idor"})
	_ = store.CreateSnapshot(s4, []assessment.AssessmentFinding{af4}, nil)

	rec4, err := store.GetFindingLifecycle(tenantID, accountID, af1.Fingerprint, authCtx)
	if err != nil || rec4.CurrentState != "ACTIVE" {
		t.Fatalf("Expected ACTIVE after repeated detection of regressed finding, got %q (err: %v)", rec4.CurrentState, err)
	}
	if rec4.PreviousState != "REGRESSED" {
		t.Fatalf("Expected PreviousState REGRESSED, got %q", rec4.PreviousState)
	}
}

// -----------------------------------------------------------------------------
// SCENARIO E: Incomplete Coverage
// -----------------------------------------------------------------------------
// Assessment with failed target, skipped detector, partial execution, or missing coverage.
// Verifies no false resolution, persistent lifecycle state intact, unassessed reported
// accurately, and newly observed evidence follows lifecycle rules.
func TestPhase6_Integration_ScenarioE_IncompleteCoverage(t *testing.T) {
	store, _, cleanup := helperNewPhase6IntegrationStore(t)
	defer cleanup()

	clientID, tenantID, accountID, asmID := "cli_scen_e", "ten_scen_e", "acc_scen_e", "asm_scen_e"
	targetA := "https://svc1.example.com"
	targetB := "https://svc2.example.com"
	_, asm, _ := helperSetupLifecycleRun(t, store, clientID, asmID, tenantID, accountID, "tgt_a", targetA)
	_ = store.AddTarget(&assessment.AssessmentTarget{
		ID:           "tgt_b",
		AssessmentID: asmID,
		TargetURL:    targetB,
		ScopeStatus:  "APPROVED",
	})
	authCtx := assessment.NewTenantAuthContext(clientID, tenantID, accountID)

	// Run 1: Normal completed scan finds vulnerability on Target A
	e1 := &assessment.AssessmentExecution{ID: "e1", AssessmentID: asmID, Status: assessment.StatusCompleted, StartedAt: time.Now().UTC().Add(-2 * time.Hour), CompletedAt: timePtr(time.Now().UTC().Add(-1 * time.Hour))}
	_ = store.CreateExecution(e1)
	af1 := helperMakePhase6Finding(asmID, e1.ID, "tgt_a", "f_a", "API Auth Bypass", "auth", report.SeverityCritical, report.ConfidenceHigh, string(report.VerificationVerified), targetA, targetA+"/admin", "GET", "Bypass on target A")
	s1 := assessment.BuildAssessmentSnapshot(asm, e1, []string{targetA, targetB}, []assessment.AssessmentFinding{af1}, true)
	s1.TenantID, s1.AccountID = tenantID, accountID
	s1.SetAssessedTargets([]string{targetA, targetB})
	s1.SetCoveredCategories([]string{"auth"})
	_ = store.CreateSnapshot(s1, []assessment.AssessmentFinding{af1}, nil)

	rec1, _ := store.GetFindingLifecycle(tenantID, accountID, af1.Fingerprint, authCtx)
	if rec1.CurrentState != "NEW" {
		t.Fatalf("Expected NEW after run 1, got %q", rec1.CurrentState)
	}

	// Run 2: Target A experiences transport failure / timeout!
	// Target B succeeds and discovers a NEW finding on Target B.
	e2 := &assessment.AssessmentExecution{
		ID:           "exec_e_2",
		AssessmentID: asmID,
		Status:       assessment.StatusCompletedWithErrors,
		StartedAt:    time.Now().UTC().Add(-45 * time.Minute),
		CompletedAt:  timePtr(time.Now().UTC().Add(-15 * time.Minute)),
	}
	_ = store.CreateExecution(e2)
	af2 := helperMakePhase6Finding(asmID, e2.ID, "tgt_b", "f_b", "Missing Rate Limit", "ratelimit", report.SeverityMedium, report.ConfidenceHigh, string(report.VerificationVerified), targetB, targetB+"/api/data", "POST", "Rate limit absent")

	s2 := assessment.BuildAssessmentSnapshot(asm, e2, []string{targetA, targetB}, []assessment.AssessmentFinding{af2}, true)
	s2.Status = assessment.StatusCompletedWithErrors
	s2.TenantID, s2.AccountID = tenantID, accountID
	s2.SetAssessedTargets([]string{targetB})
	s2.SetFailedTargets([]string{targetA}) // Target A failed!
	s2.SetCoveredCategories([]string{"auth", "ratelimit"})

	if err := store.CreateSnapshot(s2, []assessment.AssessmentFinding{af2}, nil); err != nil {
		t.Fatalf("CreateSnapshot 2 failed: %v", err)
	}

	// Safety check: Finding on Target A must NOT be resolved! Must remain NEW (or ACTIVE)
	recA, err := store.GetFindingLifecycle(tenantID, accountID, af1.Fingerprint, authCtx)
	if err != nil || recA.CurrentState != "NEW" {
		t.Fatalf("Expected Target A finding to remain NEW after failed target scan, got %q (err: %v)", recA.CurrentState, err)
	}

	// Newly observed finding on Target B is recorded accurately as NEW
	recB, err := store.GetFindingLifecycle(tenantID, accountID, af2.Fingerprint, authCtx)
	if err != nil || recB.CurrentState != "NEW" {
		t.Fatalf("Expected Target B finding to be NEW, got %q (err: %v)", recB.CurrentState, err)
	}

	// Comparison check: Finding on Target A is classified as UNASSESSED, not Resolved
	cmp, err := store.CompareSnapshots(s1.ID, s2.ID, authCtx)
	if err != nil {
		t.Fatalf("CompareSnapshots failed: %v", err)
	}
	if cmp.ResolvedCount != 0 {
		t.Fatalf("Security failure: Incomplete scan reported %d resolved findings (must be 0)", cmp.ResolvedCount)
	}
	if cmp.UnassessedCount != 1 {
		t.Fatalf("Expected exactly 1 Unassessed finding, got %d", cmp.UnassessedCount)
	}
	if cmp.NewCount != 1 {
		t.Fatalf("Expected 1 New finding (from Target B), got %d", cmp.NewCount)
	}
}

// -----------------------------------------------------------------------------
// SCENARIO F: Persistence and Retry
// -----------------------------------------------------------------------------
// Close and reopen the database, reload snapshots and lifecycle records.
// Verify identity, risk data, historical records, and idempotent retries.
func TestPhase6_Integration_ScenarioF_PersistenceAndRetry(t *testing.T) {
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "phase6_persistence.db")

	clientID, tenantID, accountID, asmID := "cli_scen_f", "ten_scen_f", "acc_scen_f", "asm_scen_f"
	targetURL := "https://app.example.com"
	authCtx := assessment.NewTenantAuthContext(clientID, tenantID, accountID)

	var snapID string
	var origFinding assessment.AssessmentFinding

	// Session 1: Create snapshot and findings
	{
		store1, err := assessment.NewSQLiteStore(dbPath)
		if err != nil {
			t.Fatalf("Failed opening store1: %v", err)
		}
		_, asm, tgt := helperSetupLifecycleRun(t, store1, clientID, asmID, tenantID, accountID, "tgt_f", targetURL)

		e1 := &assessment.AssessmentExecution{
			ID:           "exec_f_1",
			AssessmentID: asmID,
			Status:       assessment.StatusCompleted,
			StartedAt:    time.Now().UTC().Add(-1 * time.Hour),
			CompletedAt:  timePtr(time.Now().UTC().Add(-30 * time.Minute)),
		}
		_ = store1.CreateExecution(e1)
		origFinding = helperMakePhase6Finding(asmID, e1.ID, tgt.ID, "f_sqli_f", "Critical SQLi", "sqli", report.SeverityCritical, report.ConfidenceHigh, string(report.VerificationVerified), targetURL, targetURL+"/api", "POST", "Fidelity test obs")

		s1 := assessment.BuildAssessmentSnapshot(asm, e1, []string{targetURL}, []assessment.AssessmentFinding{origFinding}, true)
		s1.TenantID, s1.AccountID = tenantID, accountID
		s1.SetAssessedTargets([]string{targetURL})
		s1.SetCoveredCategories([]string{"sqli"})
		snapID = s1.ID

		ev := assessment.ExtractHistoricalEvidence(s1.ID, []assessment.AssessmentFinding{origFinding})
		if err := store1.CreateSnapshot(s1, []assessment.AssessmentFinding{origFinding}, ev); err != nil {
			t.Fatalf("CreateSnapshot failed in session 1: %v", err)
		}
		_ = store1.Close()
	}

	// Session 2: Reopen database and verify round-trip fidelity
	{
		store2, err := assessment.NewSQLiteStore(dbPath)
		if err != nil {
			t.Fatalf("Failed reopening store2: %v", err)
		}
		defer store2.Close()

		reloadedSnap, err := store2.GetSnapshot(snapID, authCtx)
		if err != nil {
			t.Fatalf("GetSnapshot failed after reopen: %v", err)
		}
		if reloadedSnap.ID != snapID || reloadedSnap.AssessmentID != asmID {
			t.Fatalf("Snapshot metadata corrupted across reload: id=%s", reloadedSnap.ID)
		}

		reloadedEv, err := store2.GetHistoricalEvidence(snapID, "", authCtx)
		if err != nil || len(reloadedEv) != 1 {
			t.Fatalf("Evidence lost across reload: %d records found (err: %v)", len(reloadedEv), err)
		}

		reloadedLC, err := store2.GetFindingLifecycle(tenantID, accountID, origFinding.Fingerprint, authCtx)
		if err != nil || reloadedLC.CurrentState != "NEW" {
			t.Fatalf("Lifecycle corrupted across reload: %v (state: %s)", err, reloadedLC.CurrentState)
		}

		// Idempotency: Identical retry of snapshot persistence must succeed without errors or duplicates
		reloadedFindings, _ := store2.GetSnapshotFindings(snapID, authCtx)
		if err := store2.CreateSnapshot(reloadedSnap, reloadedFindings, reloadedEv); err != nil {
			t.Fatalf("Identical retry should be idempotent, got error: %v", err)
		}

		// Conflicting retry: Changing content must be rejected with ErrSnapshotImmutable
		tamperedSnap := *reloadedSnap
		tamperedSnap.Name = "Tampered Assessment Name"
		if err := store2.CreateSnapshot(&tamperedSnap, reloadedFindings, reloadedEv); err != assessment.ErrSnapshotImmutable {
			t.Fatalf("Conflicting retry must return ErrSnapshotImmutable, got: %v", err)
		}
	}
}

// -----------------------------------------------------------------------------
// SCENARIO G: Tenant and Account Isolation
// -----------------------------------------------------------------------------
// Verify that findings, snapshots, lifecycle records, and comparisons cannot leak
// across tenant/account boundaries.
func TestPhase6_Integration_ScenarioG_TenantAndAccountIsolation(t *testing.T) {
	store, _, cleanup := helperNewPhase6IntegrationStore(t)
	defer cleanup()

	targetURL := "https://shared-target.example.com"

	// Tenant Alpha
	clientA, asmA, _ := helperSetupLifecycleRun(t, store, "cli_alpha", "asm_alpha", "ten_alpha", "acc_alpha", "tgt_alpha", targetURL)
	authA := assessment.NewTenantAuthContext(clientA.ID, "ten_alpha", "acc_alpha")

	eA := &assessment.AssessmentExecution{ID: "exec_alpha", AssessmentID: asmA.ID, Status: assessment.StatusCompleted, StartedAt: time.Now().UTC().Add(-1 * time.Hour), CompletedAt: timePtr(time.Now().UTC().Add(-30 * time.Minute))}
	_ = store.CreateExecution(eA)
	afA := helperMakePhase6Finding(asmA.ID, eA.ID, "tgt_alpha", "f_alpha", "Secret in Alpha", "secrets", report.SeverityHigh, report.ConfidenceHigh, string(report.VerificationVerified), targetURL, targetURL+"/secret", "GET", "Alpha secret")
	sA := assessment.BuildAssessmentSnapshot(asmA, eA, []string{targetURL}, []assessment.AssessmentFinding{afA}, true)
	sA.TenantID, sA.AccountID = "ten_alpha", "acc_alpha"
	_ = store.CreateSnapshot(sA, []assessment.AssessmentFinding{afA}, nil)

	// Tenant Beta
	clientB, asmB, _ := helperSetupLifecycleRun(t, store, "cli_beta", "asm_beta", "ten_beta", "acc_beta", "tgt_beta", targetURL)
	authB := assessment.NewTenantAuthContext(clientB.ID, "ten_beta", "acc_beta")

	eB := &assessment.AssessmentExecution{ID: "exec_beta", AssessmentID: asmB.ID, Status: assessment.StatusCompleted, StartedAt: time.Now().UTC().Add(-1 * time.Hour), CompletedAt: timePtr(time.Now().UTC().Add(-30 * time.Minute))}
	_ = store.CreateExecution(eB)
	afB := helperMakePhase6Finding(asmB.ID, eB.ID, "tgt_beta", "f_beta", "Secret in Beta", "secrets", report.SeverityHigh, report.ConfidenceHigh, string(report.VerificationVerified), targetURL, targetURL+"/secret", "GET", "Beta secret")
	sB := assessment.BuildAssessmentSnapshot(asmB, eB, []string{targetURL}, []assessment.AssessmentFinding{afB}, true)
	sB.TenantID, sB.AccountID = "ten_beta", "acc_beta"
	_ = store.CreateSnapshot(sB, []assessment.AssessmentFinding{afB}, nil)

	// Cross-tenant access denials:
	// 1. Beta cannot read Alpha's snapshot
	if _, err := store.GetSnapshot(sA.ID, authB); !errors.Is(err, assessment.ErrSnapshotUnauthorized) {
		t.Fatalf("Tenant Beta should not access Alpha snapshot, got err: %v", err)
	}

	// 2. Alpha cannot read Beta's snapshot
	if _, err := store.GetSnapshot(sB.ID, authA); !errors.Is(err, assessment.ErrSnapshotUnauthorized) {
		t.Fatalf("Tenant Alpha should not access Beta snapshot, got err: %v", err)
	}

	// 3. Beta cannot compare Alpha's snapshot
	if _, err := store.CompareSnapshots(sA.ID, sB.ID, authB); !errors.Is(err, assessment.ErrSnapshotUnauthorized) {
		t.Fatalf("Cross-tenant CompareSnapshots must return ErrSnapshotUnauthorized, got err: %v", err)
	}

	// 4. Alpha cannot read Beta's lifecycle record
	if _, err := store.GetFindingLifecycle("ten_beta", "acc_beta", afB.Fingerprint, authA); !errors.Is(err, assessment.ErrSnapshotUnauthorized) {
		t.Fatalf("Cross-tenant GetFindingLifecycle must return ErrSnapshotUnauthorized, got err: %v", err)
	}

	// 5. Listing lifecycles with Tenant Alpha context only returns Alpha's records
	lifecyclesA, countA, err := store.ListFindingLifecycles(assessment.FindingLifecycleListOptions{Auth: authA})
	if err != nil || countA != 1 || lifecyclesA[0].TenantID != "ten_alpha" {
		t.Fatalf("Tenant Alpha listed wrong lifecycles: count=%d, err=%v", countA, err)
	}
}

// -----------------------------------------------------------------------------
// SCENARIO H: Reporting Consistency
// -----------------------------------------------------------------------------
// Verify that reports accurately reflect persisted findings, deduplicated records,
// risk values, lifecycle states, and unassessed counts.
func TestPhase6_Integration_ScenarioH_ReportingConsistency(t *testing.T) {
	// 1. Verify report.Summarize accurately distinguishes all lifecycle states
	findings := []report.Finding{
		{ID: "f1", Category: "sqli", Severity: report.SeverityCritical, Score: 95, LifecycleStatus: "ACTIVE"},
		{ID: "f2", Category: "xss", Severity: report.SeverityHigh, Score: 75, LifecycleStatus: "RESOLVED"},
		{ID: "f3", Category: "idor", Severity: report.SeverityHigh, Score: 70, LifecycleStatus: "REGRESSED"},
		{ID: "f4", Category: "csrf", Severity: report.SeverityMedium, Score: 50, LifecycleStatus: "UNASSESSED"},
		{ID: "f5", Category: "info", Severity: report.SeverityLow, Score: 20, LifecycleStatus: "NEW"},
	}

	summary := report.Summarize(findings)

	if summary.TotalFindings != 5 {
		t.Fatalf("Expected TotalFindings 5, got %d", summary.TotalFindings)
	}
	if summary.ActiveCount != 1 {
		t.Fatalf("Expected ActiveCount 1, got %d", summary.ActiveCount)
	}
	if summary.ResolvedCount != 1 {
		t.Fatalf("Expected ResolvedCount 1, got %d", summary.ResolvedCount)
	}
	if summary.RegressedCount != 1 {
		t.Fatalf("Expected RegressedCount 1, got %d", summary.RegressedCount)
	}
	if summary.UnassessedCount != 1 {
		t.Fatalf("Expected UnassessedCount 1, got %d", summary.UnassessedCount)
	}
	if summary.NewCount != 1 {
		t.Fatalf("Expected NewCount 1, got %d", summary.NewCount)
	}

	// 2. Build Multi-Target Report and check consistency
	rep := report.BuildMultiTargetReport([]string{"https://app1.example.com", "https://app2.example.com"}, findings)
	if rep.Summary.TotalFindings != 5 {
		t.Fatalf("Report Summary TotalFindings mismatch: %d", rep.Summary.TotalFindings)
	}
	if rep.Summary.UnassessedCount != 1 {
		t.Fatalf("Report Summary UnassessedCount mismatch: %d", rep.Summary.UnassessedCount)
	}

	// 3. Comparison with mixed coverage producing accurate summary counts
	baseFindings := []report.Finding{
		{ID: "b1", Category: "sqli", Severity: report.SeverityCritical, Target: "https://app1.example.com", Fingerprint: "fp_sqli_1"},
		{ID: "b2", Category: "xss", Severity: report.SeverityHigh, Target: "https://app2.example.com", Fingerprint: "fp_xss_2"},
	}
	opts := correlation.ComparisonOptions{
		CurrentCompleted: true,
		ScopedTargets:    []string{"https://app1.example.com", "https://app2.example.com"},
		AssessedTargets:  []string{"https://app1.example.com"}, // app1 succeeded, app2 failed
		FailedTargets:    []string{"https://app2.example.com"},
	}
	comp := correlation.CompareFindingsWithOptions(baseFindings, nil, opts)

	if comp.ResolvedCount != 1 {
		t.Fatalf("Expected exactly 1 resolved finding from app1, got %d", comp.ResolvedCount)
	}
	if comp.UnassessedCount != 1 {
		t.Fatalf("Expected exactly 1 unassessed finding from app2, got %d", comp.UnassessedCount)
	}
}
