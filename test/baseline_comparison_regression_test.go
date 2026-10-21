package test

import (
	"context"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
	"errors"
	"os/exec"
	"time"

	"felix/pkg/assessment"
	"felix/pkg/clierror"
	"felix/pkg/correlation"
	"felix/pkg/policy"
	"felix/pkg/report"
)

// setupBaselineTestDB creates an isolated SQLite test database with a client, assessment, and target.
func setupBaselineTestDB(t *testing.T) (*assessment.SQLiteStore, *assessment.Client, *assessment.Assessment, *assessment.AssessmentTarget, string) {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "test_baseline.db")
	store, err := assessment.NewSQLiteStore(dbPath)
	if err != nil {
		t.Fatalf("failed opening test store: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })

	client := &assessment.Client{
		ID:   "client-base-1",
		Name: "Baseline Test Corp",
	}
	if err := store.CreateClient(client); err != nil {
		t.Fatalf("CreateClient failed: %v", err)
	}

	asm := &assessment.Assessment{
		ID:             "asm-base-1",
		Ref:            "ASM-BASE-1",
		ClientID:       client.ID,
		Name:           "Baseline Regression Assessment",
		AssessmentType: "web",
		Status:         assessment.StatusReady,
		ScopeMode:      "same-origin",
	}
	if err := store.CreateAssessment(asm); err != nil {
		t.Fatalf("CreateAssessment failed: %v", err)
	}

	tgt := &assessment.AssessmentTarget{
		ID:           "tgt-base-1",
		AssessmentID: asm.ID,
		TargetURL:    "https://api.example.com",
		ScopeStatus:  "APPROVED",
	}
	if err := store.AddTarget(tgt); err != nil {
		t.Fatalf("AddTarget failed: %v", err)
	}

	return store, client, asm, tgt, dbPath
}

// -----------------------------------------------------------------------------
// 1. Correct finding delta classification across all supported types
// -----------------------------------------------------------------------------

func TestPhase84_CorrectFindingDeltaClassifications(t *testing.T) {
	store, client, asm, tgt, _ := setupBaselineTestDB(t)
	authAdmin := assessment.NewAdminAuthContext()

	// 1a. Baseline Execution (Completed)
	now := time.Now().UTC()
	baseCompleted := now.Add(-1 * time.Hour)
	baseExec := &assessment.AssessmentExecution{
		ID:           "exec-base-1",
		AssessmentID: asm.ID,
		ClientID:     client.ID,
		TenantID:     client.ID,
		Status:       assessment.StatusCompleted,
		StartedAt:    now.Add(-2 * time.Hour),
		CompletedAt:  &baseCompleted,
	}
	if err := store.CreateExecution(baseExec); err != nil {
		t.Fatalf("failed creating base execution: %v", err)
	}

	fPersistentBase := report.Finding{
		ID:       "fnd-persistent",
		RuleID:   "WEB_CSRF",
		Category: "csrf",
		Severity: report.SeverityMedium,
		Target:   tgt.TargetURL,
		Endpoint: "/profile/update",
		Method:   "POST",
	}
	correlation.EnsureFindingFingerprint(&fPersistentBase, correlation.TrustPolicyForceRecompute)

	fResolvedBase := report.Finding{
		ID:       "fnd-resolved",
		RuleID:   "WEB_XSS",
		Category: "xss",
		Severity: report.SeverityHigh,
		Target:   tgt.TargetURL,
		Endpoint: "/search",
		Method:   "GET",
	}
	correlation.EnsureFindingFingerprint(&fResolvedBase, correlation.TrustPolicyForceRecompute)

	fChangedBase := report.Finding{
		ID:       "fnd-changed",
		RuleID:   "WEB_INJECTION",
		Category: "sqli",
		Severity: report.SeverityHigh,
		Target:   tgt.TargetURL,
		Endpoint: "/users/query",
		Method:   "GET",
	}
	correlation.EnsureFindingFingerprint(&fChangedBase, correlation.TrustPolicyForceRecompute)

	baseAFs := []assessment.AssessmentFinding{
		assessment.ToAssessmentFinding(asm.ID, baseExec.ID, tgt.ID, fPersistentBase),
		assessment.ToAssessmentFinding(asm.ID, baseExec.ID, tgt.ID, fResolvedBase),
		assessment.ToAssessmentFinding(asm.ID, baseExec.ID, tgt.ID, fChangedBase),
	}
	if err := store.SaveFindings(baseAFs); err != nil {
		t.Fatalf("failed saving baseline findings: %v", err)
	}

	baseSnap := assessment.BuildAssessmentSnapshot(asm, baseExec, []string{tgt.TargetURL}, baseAFs, true)
	baseSnap.SetAssessedTargets([]string{tgt.TargetURL})
	baseSnap.SetCoveredCategories([]string{"csrf", "xss", "sqli", "auth"})
	if err := store.CreateSnapshot(baseSnap, baseAFs, nil); err != nil {
		t.Fatalf("failed creating baseline snapshot: %v", err)
	}
	baseExec.SnapshotID = baseSnap.ID
	_ = store.UpdateExecution(baseExec)

	// Regressed finding: finding with prior verified resolution lifecycle status
	fRegressedCur := report.Finding{
		ID:              "fnd-regressed",
		RuleID:          "AUTH_BYPASS",
		Category:        "auth",
		Severity:        report.SeverityCritical,
		Target:          tgt.TargetURL,
		Endpoint:        "/admin/bypass",
		Method:          "POST",
		LifecycleStatus: string(correlation.LifecycleRegressed),
	}
	correlation.EnsureFindingFingerprint(&fRegressedCur, correlation.TrustPolicyForceRecompute)

	// 1b. Current Execution (Completed)
	curCompleted := now
	curExec := &assessment.AssessmentExecution{
		ID:           "exec-cur-1",
		AssessmentID: asm.ID,
		ClientID:     client.ID,
		TenantID:     client.ID,
		Status:       assessment.StatusCompleted,
		StartedAt:    now.Add(-10 * time.Minute),
		CompletedAt:  &curCompleted,
	}
	if err := store.CreateExecution(curExec); err != nil {
		t.Fatalf("failed creating cur execution: %v", err)
	}

	// Finding 1: Persistent (identical)
	fPersistentCur := fPersistentBase
	fPersistentCur.ID = "fnd-persistent-run2"

	// Finding 2: Changed (severity increased from HIGH to CRITICAL)
	fChangedCur := fChangedBase
	fChangedCur.ID = "fnd-changed-run2"
	fChangedCur.Severity = report.SeverityCritical

	// Finding 3: Genuinely NEW finding
	fNewCur := report.Finding{
		ID:       "fnd-brand-new",
		RuleID:   "WEB_SSRF",
		Category: "ssrf",
		Severity: report.SeverityHigh,
		Target:   tgt.TargetURL,
		Endpoint: "/webhook/test",
		Method:   "POST",
	}
	correlation.EnsureFindingFingerprint(&fNewCur, correlation.TrustPolicyForceRecompute)

	// Finding 4: Duplicate finding with identical fingerprint on same target (should be consolidated)
	fDupCur := fNewCur
	fDupCur.ID = "fnd-brand-new-dup"

	curAFs := []assessment.AssessmentFinding{
		assessment.ToAssessmentFinding(asm.ID, curExec.ID, tgt.ID, fPersistentCur),
		assessment.ToAssessmentFinding(asm.ID, curExec.ID, tgt.ID, fChangedCur),
		assessment.ToAssessmentFinding(asm.ID, curExec.ID, tgt.ID, fNewCur),
		assessment.ToAssessmentFinding(asm.ID, curExec.ID, tgt.ID, fRegressedCur),
		assessment.ToAssessmentFinding(asm.ID, curExec.ID, tgt.ID, fDupCur),
	}
	if err := store.SaveFindings(curAFs); err != nil {
		t.Fatalf("failed saving current findings: %v", err)
	}

	curSnap := assessment.BuildAssessmentSnapshot(asm, curExec, []string{tgt.TargetURL}, curAFs, true)
	curSnap.SetAssessedTargets([]string{tgt.TargetURL})
	curSnap.SetCoveredCategories([]string{"csrf", "xss", "sqli", "auth", "ssrf"})
	if err := store.CreateSnapshot(curSnap, curAFs, nil); err != nil {
		t.Fatalf("failed creating cur snapshot: %v", err)
	}
	curExec.SnapshotID = curSnap.ID
	_ = store.UpdateExecution(curExec)

	// 1c. Run comparison
	summary, err := store.GetAssessmentChangeSummary(asm.ID, baseExec.ID, curExec.ID, authAdmin)
	if err != nil {
		t.Fatalf("GetAssessmentChangeSummary failed: %v", err)
	}

	if !summary.IsReliable {
		t.Errorf("expected summary to be reliable, got reason: %s", summary.ReliabilityReason)
	}

	// Verify exact delta counts:
	// - Total Baseline = 3
	// - Total Comparison = 4 distinct fingerprints (fPersistent, fChanged, fNew, fRegressed)
	// - New = 1 (fNew)
	// - Resolved = 1 (fResolved was in scope and covered, but not found)
	// - Regressed = 2 (fRegressed reappeared; fChanged severity worsened HIGH->CRITICAL)
	if summary.Counts.TotalBaseline != 3 {
		t.Errorf("expected TotalBaseline = 3, got %d", summary.Counts.TotalBaseline)
	}
	if summary.Counts.Resolved != 1 {
		t.Errorf("expected Resolved = 1, got %d", summary.Counts.Resolved)
	}
	if summary.Counts.New != 1 {
		t.Errorf("expected New = 1, got %d", summary.Counts.New)
	}
	if summary.Counts.Regressed != 2 {
		t.Errorf("expected Regressed = 2, got %d", summary.Counts.Regressed)
	}
	if summary.Counts.Unverified != 0 {
		t.Errorf("expected Unverified = 0 for fully complete assessment, got %d", summary.Counts.Unverified)
	}

	// Verify duplicate consolidation: duplicate finding did not inflate count
	newItems := 0
	for _, it := range summary.ImportantChanges {
		if it.Classification == string(correlation.DeltaNew) {
			newItems++
		}
	}
	if newItems != 1 {
		t.Errorf("expected exactly 1 NEW change item despite duplicate, got %d", newItems)
	}
}

// -----------------------------------------------------------------------------
// 2. The No-False-Resolution Invariant under failure, cancellation, and partials
// -----------------------------------------------------------------------------

func TestPhase84_NoFalseResolutionInvariant(t *testing.T) {
	store, client, asm, tgt, _ := setupBaselineTestDB(t)
	authAdmin := assessment.NewAdminAuthContext()

	// 2a. Healthy Baseline with findings on Target 1 and Target 2
	tgt2 := &assessment.AssessmentTarget{
		ID:           "tgt-base-2",
		AssessmentID: asm.ID,
		TargetURL:    "https://admin.example.com",
		ScopeStatus:  "APPROVED",
	}
	_ = store.AddTarget(tgt2)

	now := time.Now().UTC()
	baseSafeCompleted := now.Add(-30 * time.Minute)
	baseExec := &assessment.AssessmentExecution{
		ID:           "exec-base-safe",
		AssessmentID: asm.ID,
		ClientID:     client.ID,
		TenantID:     client.ID,
		Status:       assessment.StatusCompleted,
		StartedAt:    now.Add(-1 * time.Hour),
		CompletedAt:  &baseSafeCompleted,
	}
	_ = store.CreateExecution(baseExec)

	f1 := report.Finding{
		ID:       "fnd-t1",
		RuleID:   "API_KEY",
		Category: "leak",
		Severity: report.SeverityHigh,
		Target:   tgt.TargetURL,
		Endpoint: "/config",
		Method:   "GET",
	}
	correlation.EnsureFindingFingerprint(&f1, correlation.TrustPolicyForceRecompute)

	f2 := report.Finding{
		ID:       "fnd-t2",
		RuleID:   "ADMIN_OPEN",
		Category: "authz",
		Severity: report.SeverityCritical,
		Target:   tgt2.TargetURL,
		Endpoint: "/admin/dashboard",
		Method:   "GET",
	}
	correlation.EnsureFindingFingerprint(&f2, correlation.TrustPolicyForceRecompute)

	baseAFs := []assessment.AssessmentFinding{
		assessment.ToAssessmentFinding(asm.ID, baseExec.ID, tgt.ID, f1),
		assessment.ToAssessmentFinding(asm.ID, baseExec.ID, tgt2.ID, f2),
	}
	_ = store.SaveFindings(baseAFs)

	baseSnap := assessment.BuildAssessmentSnapshot(asm, baseExec, []string{tgt.TargetURL, tgt2.TargetURL}, baseAFs, true)
	baseSnap.SetAssessedTargets([]string{tgt.TargetURL, tgt2.TargetURL})
	baseSnap.SetCoveredCategories([]string{"leak", "authz"})
	_ = store.CreateSnapshot(baseSnap, baseAFs, nil)
	baseExec.SnapshotID = baseSnap.ID
	_ = store.UpdateExecution(baseExec)

	// Sub-test 2.1: Failed current assessment MUST NEVER mark findings as RESOLVED
	t.Run("FailedAssessment_NeverResolves", func(t *testing.T) {
		failExec := &assessment.AssessmentExecution{
			ID:           "exec-cur-failed",
			AssessmentID: asm.ID,
			ClientID:     client.ID,
			TenantID:     client.ID,
			Status:       assessment.StatusFailed,
			ErrorMessage: "Crawl connection timeout to all targets",
			StartedAt:    time.Now().UTC(),
		}
		_ = store.CreateExecution(failExec)

		failSnap := assessment.BuildAssessmentSnapshot(asm, failExec, []string{tgt.TargetURL, tgt2.TargetURL}, nil, false)
		failSnap.Metadata["is_partial"] = "true"
		failSnap.Metadata["inconclusive"] = "true"
		_ = store.CreateSnapshot(failSnap, nil, nil)
		failExec.SnapshotID = failSnap.ID
		_ = store.UpdateExecution(failExec)

		cmp, err := store.CompareExecutionHistory(baseExec.ID, failExec.ID, authAdmin)
		if err != nil {
			t.Fatalf("CompareExecutionHistory failed: %v", err)
		}

		if cmp.ResolvedCount != 0 {
			t.Fatalf("VIOLATION OF NO-FALSE-RESOLUTION INVARIANT: Failed scan marked %d findings as RESOLVED!", cmp.ResolvedCount)
		}
		if cmp.UnassessedCount != 2 && cmp.UnverifiedCount != 2 {
			t.Errorf("expected 2 unassessed/unverified findings on failed run, got unassessed=%d unverified=%d",
				cmp.UnassessedCount, cmp.UnverifiedCount)
		}
	})

	// Sub-test 2.2: Cancelled current assessment MUST NEVER mark findings as RESOLVED
	t.Run("CancelledAssessment_NeverResolves", func(t *testing.T) {
		cancelExec := &assessment.AssessmentExecution{
			ID:           "exec-cur-cancelled",
			AssessmentID: asm.ID,
			ClientID:     client.ID,
			TenantID:     client.ID,
			Status:       assessment.StatusCancelled,
			ErrorMessage: "Execution was cancelled by operator",
			StartedAt:    time.Now().UTC(),
		}
		_ = store.CreateExecution(cancelExec)

		cancelSnap := assessment.BuildAssessmentSnapshot(asm, cancelExec, []string{tgt.TargetURL, tgt2.TargetURL}, nil, false)
		cancelSnap.Metadata["inconclusive"] = "true"
		_ = store.CreateSnapshot(cancelSnap, nil, nil)
		cancelExec.SnapshotID = cancelSnap.ID
		_ = store.UpdateExecution(cancelExec)

		cmp, err := store.CompareExecutionHistory(baseExec.ID, cancelExec.ID, authAdmin)
		if err != nil {
			t.Fatalf("CompareExecutionHistory failed: %v", err)
		}

		if cmp.ResolvedCount != 0 {
			t.Fatalf("VIOLATION: Cancelled scan marked %d findings as RESOLVED!", cmp.ResolvedCount)
		}
		if cmp.UnverifiedCount != 2 {
			t.Errorf("expected 2 unverified findings, got %d", cmp.UnverifiedCount)
		}
	})

	// Sub-test 2.3: Partial assessment (CompletedWithErrors) where Target 2 failed
	t.Run("PartialAssessment_TargetFailed_PreservesUnverified", func(t *testing.T) {
		partCompleted := now
		partExec := &assessment.AssessmentExecution{
			ID:           "exec-cur-partial",
			AssessmentID: asm.ID,
			ClientID:     client.ID,
			TenantID:     client.ID,
			Status:       assessment.StatusCompletedWithErrors,
			ErrorMessage: "1 of 2 targets failed during crawl",
			StartedAt:    now.Add(-5 * time.Minute),
			CompletedAt:  &partCompleted,
		}
		_ = store.CreateExecution(partExec)

		// Target 1 succeeded and finding f1 was fixed (absent).
		// Target 2 failed network request, so finding f2 could not be assessed!
		partSnap := assessment.BuildAssessmentSnapshot(asm, partExec, []string{tgt.TargetURL, tgt2.TargetURL}, nil, true)
		partSnap.SetAssessedTargets([]string{tgt.TargetURL})
		partSnap.SetFailedTargets([]string{tgt2.TargetURL})
		partSnap.SetCoveredCategories([]string{"leak", "authz"})
		_ = store.CreateSnapshot(partSnap, nil, nil)
		partExec.SnapshotID = partSnap.ID
		_ = store.UpdateExecution(partExec)

		cmp, err := store.CompareExecutionHistory(baseExec.ID, partExec.ID, authAdmin)
		if err != nil {
			t.Fatalf("CompareExecutionHistory failed: %v", err)
		}

		// f1 on Target 1 should be legitimately RESOLVED (target was assessed, finding absent)
		// f2 on Target 2 must NOT be resolved (target failed crawl -> UNVERIFIED)
		if cmp.ResolvedCount != 1 {
			t.Fatalf("expected exactly 1 resolved finding (Target 1), got %d", cmp.ResolvedCount)
		}
		if cmp.UnverifiedCount != 1 {
			t.Fatalf("expected exactly 1 unverified finding (Target 2), got %d", cmp.UnverifiedCount)
		}

		for _, item := range cmp.Items {
			if item.Fingerprint == f2.Fingerprint {
				if item.Classification != correlation.DeltaUnverified {
					t.Fatalf("CRITICAL SECURITY DEFECT: finding on failed target was classified as %s instead of UNVERIFIED", item.Classification)
				}
			}
		}
	})

	// Sub-test 2.4: Missing category coverage preserves findings as UNVERIFIED
	t.Run("MissingCategoryCoverage_PreservesUnverified", func(t *testing.T) {
		catCompleted := now
		catExec := &assessment.AssessmentExecution{
			ID:           "exec-cur-cat-missing",
			AssessmentID: asm.ID,
			ClientID:     client.ID,
			TenantID:     client.ID,
			Status:       assessment.StatusCompleted,
			StartedAt:    now.Add(-5 * time.Minute),
			CompletedAt:  &catCompleted,
		}
		_ = store.CreateExecution(catExec)

		catSnap := assessment.BuildAssessmentSnapshot(asm, catExec, []string{tgt.TargetURL, tgt2.TargetURL}, nil, true)
		catSnap.SetAssessedTargets([]string{tgt.TargetURL, tgt2.TargetURL})
		// Only "leak" was run; "authz" was skipped!
		catSnap.SetCoveredCategories([]string{"leak"})
		catSnap.SetSkippedCategories([]string{"authz"})
		_ = store.CreateSnapshot(catSnap, nil, nil)
		catExec.SnapshotID = catSnap.ID
		_ = store.UpdateExecution(catExec)

		cmp, err := store.CompareExecutionHistory(baseExec.ID, catExec.ID, authAdmin)
		if err != nil {
			t.Fatalf("CompareExecutionHistory failed: %v", err)
		}

		// f1 (leak) -> RESOLVED
		// f2 (authz) -> UNVERIFIED because category was skipped
		if cmp.ResolvedCount != 1 {
			t.Fatalf("expected 1 resolved finding, got %d", cmp.ResolvedCount)
		}
		if cmp.UnverifiedCount != 1 {
			t.Fatalf("expected 1 unverified finding for skipped category, got %d", cmp.UnverifiedCount)
		}
	})
}

// -----------------------------------------------------------------------------
// 3. Trusted Baseline Model: Strict Rejections of Ineligible Baselines
// -----------------------------------------------------------------------------

func TestPhase84_TrustedBaselineRejections(t *testing.T) {
	store, client, asm, tgt, _ := setupBaselineTestDB(t)
	authAdmin := assessment.NewAdminAuthContext()

	currExec := &assessment.AssessmentExecution{
		ID:           "exec-valid-curr",
		AssessmentID: asm.ID,
		ClientID:     client.ID,
		TenantID:     client.ID,
		Status:       assessment.StatusCompleted,
		StartedAt:    time.Now().UTC(),
	}
	_ = store.CreateExecution(currExec)

	// 3a. FAILED execution cannot be a baseline
	failedExec := &assessment.AssessmentExecution{
		ID:           "exec-base-failed",
		AssessmentID: asm.ID,
		ClientID:     client.ID,
		TenantID:     client.ID,
		Status:       assessment.StatusFailed,
		StartedAt:    time.Now().UTC().Add(-1 * time.Hour),
	}
	_ = store.CreateExecution(failedExec)

	_, err := store.GetAssessmentChangeSummary(asm.ID, failedExec.ID, currExec.ID, authAdmin)
	if err == nil || !strings.Contains(err.Error(), "ineligible baseline") {
		t.Fatalf("expected error rejecting FAILED baseline, got: %v", err)
	}

	// 3b. CANCELLED execution cannot be a baseline
	cancExec := &assessment.AssessmentExecution{
		ID:           "exec-base-cancelled",
		AssessmentID: asm.ID,
		ClientID:     client.ID,
		TenantID:     client.ID,
		Status:       assessment.StatusCancelled,
		StartedAt:    time.Now().UTC().Add(-1 * time.Hour),
	}
	_ = store.CreateExecution(cancExec)

	_, err = store.GetAssessmentChangeSummary(asm.ID, cancExec.ID, currExec.ID, authAdmin)
	if err == nil || !strings.Contains(err.Error(), "ineligible baseline") {
		t.Fatalf("expected error rejecting CANCELLED baseline, got: %v", err)
	}

	// 3c. Inconclusive snapshot cannot be a baseline
	inconcExec := &assessment.AssessmentExecution{
		ID:           "exec-base-inconc",
		AssessmentID: asm.ID,
		ClientID:     client.ID,
		TenantID:     client.ID,
		Status:       assessment.StatusCompleted,
		StartedAt:    time.Now().UTC().Add(-1 * time.Hour),
	}
	_ = store.CreateExecution(inconcExec)
	inconcSnap := assessment.BuildAssessmentSnapshot(asm, inconcExec, []string{tgt.TargetURL}, nil, false)
	inconcSnap.Metadata["inconclusive"] = "true"
	_ = store.CreateSnapshot(inconcSnap, nil, nil)
	inconcExec.SnapshotID = inconcSnap.ID
	_ = store.UpdateExecution(inconcExec)

	_, err = store.GetAssessmentChangeSummary(asm.ID, inconcExec.ID, currExec.ID, authAdmin)
	if err == nil || !strings.Contains(err.Error(), "inconclusive") {
		t.Fatalf("expected error rejecting inconclusive baseline snapshot, got: %v", err)
	}

	// 3d. Self-comparison rejected
	_, err = store.GetAssessmentChangeSummary(asm.ID, currExec.ID, currExec.ID, authAdmin)
	if err == nil || !strings.Contains(err.Error(), "cannot be compared against itself") {
		t.Fatalf("expected error on self-comparison, got: %v", err)
	}

	// 3e. Non-existent baseline reference rejected
	_, err = store.GetAssessmentChangeSummary(asm.ID, "non-existent-baseline-id", currExec.ID, authAdmin)
	if err == nil || !strings.Contains(err.Error(), "not found") {
		t.Fatalf("expected not-found error on non-existent baseline, got: %v", err)
	}
}

// -----------------------------------------------------------------------------
// 4. Tenant and Target Scope Isolation
// -----------------------------------------------------------------------------

func TestPhase84_TenantAndScopeIsolation(t *testing.T) {
	store, clientA, asmA, _, _ := setupBaselineTestDB(t)
	authAdmin := assessment.NewAdminAuthContext()

	// Client B (Tenant B)
	clientB := &assessment.Client{
		ID:   "client-tenant-b-cross",
		Name: "Tenant B Organization",
	}
	_ = store.CreateClient(clientB)

	asmB := &assessment.Assessment{
		ID:             "asm-tenant-b-cross",
		Ref:            "ASM-TENANT-B-CROSS",
		ClientID:       clientB.ID,
		Name:           "Tenant B Assessment",
		AssessmentType: "web",
		Status:         assessment.StatusReady,
	}
	_ = store.CreateAssessment(asmB)

	execA := &assessment.AssessmentExecution{
		ID:           "exec-tenant-a-iso",
		AssessmentID: asmA.ID,
		ClientID:     clientA.ID,
		TenantID:     clientA.ID,
		Status:       assessment.StatusCompleted,
		StartedAt:    time.Now().UTC().Add(-1 * time.Hour),
	}
	_ = store.CreateExecution(execA)

	execB := &assessment.AssessmentExecution{
		ID:           "exec-tenant-b-iso",
		AssessmentID: asmB.ID,
		ClientID:     clientB.ID,
		TenantID:     clientB.ID,
		Status:       assessment.StatusCompleted,
		StartedAt:    time.Now().UTC(),
	}
	_ = store.CreateExecution(execB)

	// 4a. Cross-tenant baseline comparison must be denied
	_, err := store.GetAssessmentChangeSummary("", execA.ID, execB.ID, authAdmin)
	if err == nil || !strings.Contains(err.Error(), "cross-tenant comparison denied") {
		t.Fatalf("expected cross-tenant denial error, got: %v", err)
	}

	// 4b. Unauthorized tenant context cannot read another tenant's execution
	tenantBAuth := assessment.NewTenantAuthContext(clientB.ID, clientB.ID, "")
	_, err = store.GetAssessmentChangeSummary("", execA.ID, execA.ID, tenantBAuth)
	if err == nil || !strings.Contains(err.Error(), "unauthorized") {
		t.Fatalf("expected unauthorized error for Tenant B attempting to read Tenant A baseline, got: %v", err)
	}
}

// -----------------------------------------------------------------------------
// 5. Baseline-Relative Policy Evaluation (Phase 8.2 Integration)
// -----------------------------------------------------------------------------

func TestPhase84_BaselineRelativePolicyEvaluation(t *testing.T) {
	// Scenario: An assessment finds 1 PERSISTENT Critical vulnerability, and 0 NEW vulnerabilities.
	// - An absolute policy (max_critical: 0) should FAIL (exit 1).
	// - A baseline-relative policy (max_critical: 0, evaluation_scope: "new") should PASS (exit 0).
	// - If a NEW Critical vulnerability is introduced, baseline-relative policy should FAIL (exit 1).

	fPersistentCrit := report.Finding{
		ID:              "fnd-pers-crit",
		RuleID:          "AUTH_BYPASS",
		Category:        "auth",
		Severity:        report.SeverityCritical,
		Target:          "https://app.example.com",
		Endpoint:        "/admin",
		LifecycleStatus: "PERSISTENT",
	}

	changeSummaryClean := &report.ChangeSummary{
		IsReliable: true,
		ImportantChanges: []report.ChangeFindingItem{
			{
				FindingID:      fPersistentCrit.ID,
				Classification: string(correlation.DeltaPersistent),
			},
		},
	}

	// 5a. Absolute Policy evaluation (existing Phase 8.2 behavior)
	absPolicyJSON := `{"version":"1.0","max_critical":0}`
	polAbs, err := policy.LoadPolicyFromBytes([]byte(absPolicyJSON))
	if err != nil {
		t.Fatalf("failed loading absolute policy: %v", err)
	}

	ctx := policy.EvaluationContext{
		AssessmentID:       "asm-1",
		Status:             "COMPLETED",
		BaselineComparison: changeSummaryClean,
	}

	decAbs, err := policy.EvaluatePolicy(polAbs, []report.Finding{fPersistentCrit}, ctx)
	if err != nil {
		t.Fatalf("EvaluatePolicy failed: %v", err)
	}
	if decAbs.Passed {
		t.Fatalf("expected absolute policy to fail due to 1 persistent critical finding, but it passed")
	}
	if decAbs.ExitCode() != clierror.ExitSecurityFail {
		t.Errorf("expected exit code 1, got %d", decAbs.ExitCode())
	}

	// 5b. Baseline-Relative Policy evaluation (evaluation_scope: "new")
	relPolicyJSON := `{"version":"1.0","max_critical":0,"evaluation_scope":"new"}`
	polRel, err := policy.LoadPolicyFromBytes([]byte(relPolicyJSON))
	if err != nil {
		t.Fatalf("failed loading baseline-relative policy: %v", err)
	}

	decRel, err := policy.EvaluatePolicy(polRel, []report.Finding{fPersistentCrit}, ctx)
	if err != nil {
		t.Fatalf("EvaluatePolicy baseline-relative failed: %v", err)
	}
	if !decRel.Passed {
		t.Fatalf("expected baseline-relative policy to PASS with 0 new findings, but failed: %s", decRel.Explanation)
	}
	if decRel.ExitCode() != clierror.ExitSuccess {
		t.Errorf("expected exit code 0 for baseline-relative policy pass, got %d", decRel.ExitCode())
	}

	// 5c. Baseline-Relative Policy fails when NEW critical is detected
	fNewCrit := report.Finding{
		ID:              "fnd-new-crit",
		RuleID:          "RCE",
		Category:        "rce",
		Severity:        report.SeverityCritical,
		Target:          "https://app.example.com",
		Endpoint:        "/exec",
		LifecycleStatus: "NEW",
	}

	changeSummaryWithNew := &report.ChangeSummary{
		IsReliable: true,
		ImportantChanges: []report.ChangeFindingItem{
			{
				FindingID:      fPersistentCrit.ID,
				Classification: string(correlation.DeltaPersistent),
			},
			{
				FindingID:      fNewCrit.ID,
				Classification: string(correlation.DeltaNew),
			},
		},
	}

	ctxWithNew := policy.EvaluationContext{
		AssessmentID:       "asm-1",
		Status:             "COMPLETED",
		BaselineComparison: changeSummaryWithNew,
	}

	decRelWithNew, err := policy.EvaluatePolicy(polRel, []report.Finding{fPersistentCrit, fNewCrit}, ctxWithNew)
	if err != nil {
		t.Fatalf("EvaluatePolicy failed: %v", err)
	}
	if decRelWithNew.Passed {
		t.Fatalf("expected baseline-relative policy to FAIL on new critical finding, but passed")
	}
	if decRelWithNew.ExitCode() != clierror.ExitSecurityFail {
		t.Errorf("expected exit code 1, got %d", decRelWithNew.ExitCode())
	}

	// 5d. Unreliable baseline comparison aborts with ExitOperational (2)
	unreliableSummary := &report.ChangeSummary{
		IsReliable:        false,
		ReliabilityReason: "comparison execution encountered crawl errors on some targets",
	}
	ctxUnreliable := policy.EvaluationContext{
		AssessmentID:       "asm-1",
		Status:             "COMPLETED",
		BaselineComparison: unreliableSummary,
	}

	decUnreliable, err := policy.EvaluatePolicy(polRel, []report.Finding{fNewCrit}, ctxUnreliable)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if decUnreliable.Reliable {
		t.Fatalf("expected decision to be marked unreliable")
	}
	if decUnreliable.ExitCode() != clierror.ExitOperational {
		t.Fatalf("expected ExitOperational (2) when baseline comparison is unreliable, got %d", decUnreliable.ExitCode())
	}
}

// -----------------------------------------------------------------------------
// 6. SARIF 2.1.0 Baseline State Conformance
// -----------------------------------------------------------------------------

func TestPhase84_SARIFBaselineStateConformance(t *testing.T) {
	// Verify that findings with lifecycle statuses map cleanly to SARIF 2.1.0 baselineState:
	// NEW -> "new", PERSISTENT -> "unchanged", CHANGED/REGRESSED -> "updated", RESOLVED -> "absent"
	rep := report.Report{
		Target:           "https://sarif.example.com",
		CompletionStatus: "COMPLETED",
		Metadata: map[string]any{
			"baseline_execution_id": "exec-base-uuid-1234",
		},
		Findings: []report.Finding{
			{
				ID:              "f-new",
				RuleID:          "FELIX_NEW",
				Category:        "csrf",
				Severity:        report.SeverityMedium,
				Target:          "https://sarif.example.com",
				Endpoint:        "/test/new",
				LifecycleStatus: "NEW",
			},
			{
				ID:              "f-unchanged",
				RuleID:          "FELIX_PERSISTENT",
				Category:        "xss",
				Severity:        report.SeverityLow,
				Target:          "https://sarif.example.com",
				Endpoint:        "/test/persist",
				LifecycleStatus: "PERSISTENT",
			},
			{
				ID:              "f-updated",
				RuleID:          "FELIX_CHANGED",
				Category:        "auth",
				Severity:        report.SeverityHigh,
				Target:          "https://sarif.example.com",
				Endpoint:        "/test/changed",
				LifecycleStatus: "CHANGED",
			},
		},
	}

	data, err := report.GenerateSARIF(rep)
	if err != nil {
		t.Fatalf("GenerateSARIF failed: %v", err)
	}

	// Validate against official OASIS SARIF 2.1.0 JSON Schema
	if err := report.ValidateSARIF(data); err != nil {
		t.Fatalf("SARIF with baselineState failed official OASIS schema validation: %v", err)
	}

	var log report.SARIFLog
	if err := json.Unmarshal(data, &log); err != nil {
		t.Fatalf("failed unmarshaling generated SARIF: %v", err)
	}

	if len(log.Runs) == 0 || len(log.Runs[0].Results) != 3 {
		t.Fatalf("expected 3 results, got %d", len(log.Runs[0].Results))
	}

	results := log.Runs[0].Results
	if results[0].BaselineState != "new" {
		t.Errorf("expected baselineState 'new', got %q", results[0].BaselineState)
	}
	if results[1].BaselineState != "unchanged" {
		t.Errorf("expected baselineState 'unchanged', got %q", results[1].BaselineState)
	}
	if results[2].BaselineState != "updated" {
		t.Errorf("expected baselineState 'updated', got %q", results[2].BaselineState)
	}
}

// -----------------------------------------------------------------------------
// 7. CLI End-to-End: Assessment Run with Baseline Flag
// -----------------------------------------------------------------------------

func TestPhase84_CLI_AssessmentRunWithBaseline(t *testing.T) {
	store, client, asm, tgt, _ := setupBaselineTestDB(t)

	// Create valid completed baseline execution
	baseExec := &assessment.AssessmentExecution{
		ID:           "exec-base-cli",
		AssessmentID: asm.ID,
		ClientID:     client.ID,
		TenantID:     client.ID,
		Status:       assessment.StatusCompleted,
		StartedAt:    time.Now().UTC().Add(-1 * time.Hour),
	}
	_ = store.CreateExecution(baseExec)

	fBase := report.Finding{
		ID:       "fnd-cli-base",
		RuleID:   "WEB_CSRF",
		Category: "csrf",
		Severity: report.SeverityLow,
		Target:   tgt.TargetURL,
		Endpoint: "/settings",
		Method:   "POST",
	}
	correlation.EnsureFindingFingerprint(&fBase, correlation.TrustPolicyForceRecompute)
	_ = store.SaveFindings([]assessment.AssessmentFinding{
		assessment.ToAssessmentFinding(asm.ID, baseExec.ID, tgt.ID, fBase),
	})

	controller := assessment.NewController(store)

	// 7a. Run assessment with invalid baseline ID -> must fail operationally (error return)
	_, err := controller.RunAssessment(context.Background(), asm.ID, assessment.ExecutionOptions{
		BaselineRef: "non-existent-baseline-id",
	})
	if err == nil {
		t.Fatalf("expected error running assessment with non-existent baseline")
	}
	if code := clierror.CodeFor(err); code != clierror.ExitOperational {
		t.Fatalf("expected ExitOperational (2) for invalid baseline error, got %d", code)
	}

	// 7b. Run assessment with failed execution as baseline -> must fail operationally
	failedBase := &assessment.AssessmentExecution{
		ID:           "exec-base-cli-failed",
		AssessmentID: asm.ID,
		ClientID:     client.ID,
		TenantID:     client.ID,
		Status:       assessment.StatusFailed,
		StartedAt:    time.Now().UTC().Add(-1 * time.Hour),
	}
	_ = store.CreateExecution(failedBase)

	_, err = controller.RunAssessment(context.Background(), asm.ID, assessment.ExecutionOptions{
		BaselineRef: failedBase.ID,
	})
	if err == nil {
		t.Fatalf("expected error running assessment with failed baseline")
	}
	if code := clierror.CodeFor(err); code != clierror.ExitOperational {
		t.Fatalf("expected ExitOperational (2) for ineligible baseline error, got %d", code)
	}
}

// -----------------------------------------------------------------------------
// 8. Process-Level Exit Codes: Cross-Tenant Baseline & Unauthorized Access = Exit 2
// -----------------------------------------------------------------------------

func TestPhase84_ProcessLevel_ExitCodes(t *testing.T) {
	store, clientA, asmA, tgtA, dbPath := setupBaselineTestDB(t)

	// Tenant B setup
	clientB := &assessment.Client{
		ID:   "client-proc-b",
		Name: "Tenant B Process Corp",
	}
	_ = store.CreateClient(clientB)

	asmB := &assessment.Assessment{
		ID:             "asm-proc-b",
		Ref:            "ASM-PROC-B",
		ClientID:       clientB.ID,
		Name:           "Tenant B Process Assessment",
		AssessmentType: "web",
		Status:         assessment.StatusReady,
	}
	_ = store.CreateAssessment(asmB)

	now := time.Now().UTC()
	execA := &assessment.AssessmentExecution{
		ID:           "exec-proc-a",
		AssessmentID: asmA.ID,
		ClientID:     clientA.ID,
		TenantID:     clientA.ID,
		Status:       assessment.StatusCompleted,
		StartedAt:    now.Add(-1 * time.Hour),
		CompletedAt:  &now,
	}
	_ = store.CreateExecution(execA)

	fA := report.Finding{
		ID:       "fnd-proc-a",
		RuleID:   "WEB_CSRF",
		Category: "csrf",
		Severity: report.SeverityLow,
		Target:   tgtA.TargetURL,
		Endpoint: "/settings",
	}
	correlation.EnsureFindingFingerprint(&fA, correlation.TrustPolicyForceRecompute)
	_ = store.SaveFindings([]assessment.AssessmentFinding{
		assessment.ToAssessmentFinding(asmA.ID, execA.ID, tgtA.ID, fA),
	})

	execB := &assessment.AssessmentExecution{
		ID:           "exec-proc-b",
		AssessmentID: asmB.ID,
		ClientID:     clientB.ID,
		TenantID:     clientB.ID,
		Status:       assessment.StatusCompleted,
		StartedAt:    now,
		CompletedAt:  &now,
	}
	_ = store.CreateExecution(execB)

	// Close store so CLI can open database exclusively
	_ = store.Close()

	binPath := filepath.Join("..", "bin", "felix.exe")
	absBin, err := filepath.Abs(binPath)
	if err != nil {
		t.Fatalf("failed to resolve binary path: %v", err)
	}

	// 8a. Process-level: Cross-tenant baseline diff returns Exit Operational (2), NEVER Exit 1
	cmdDiffCross := exec.Command(absBin, "assessment", "diff", execA.ID, execB.ID, "--db", dbPath)
	errDiff := cmdDiffCross.Run()
	if errDiff == nil {
		t.Fatalf("expected cross-tenant diff to fail with non-zero exit code")
	}
	var exitErr *exec.ExitError
	if errors.As(errDiff, &exitErr) {
		if exitErr.ExitCode() != clierror.ExitOperational {
			t.Fatalf("CRITICAL CONTRACT VIOLATION: cross-tenant baseline comparison returned exit code %d, expected 2 (ExitOperational)", exitErr.ExitCode())
		}
	} else {
		t.Fatalf("unexpected error type: %v", errDiff)
	}

	// 8b. Process-level: Unauthorized baseline summary returns Exit Operational (2), NEVER Exit 1
	cmdSumUnauthorized := exec.Command(absBin, "assessment", "summary",
		"--assessment-id", asmA.ID,
		"--baseline", execB.ID,
		"--execution", execA.ID,
		"--tenant", clientA.ID,
		"--role", "client",
		"--db", dbPath,
	)
	errSum := cmdSumUnauthorized.Run()
	if errSum == nil {
		t.Fatalf("expected unauthorized baseline access to fail")
	}
	if errors.As(errSum, &exitErr) {
		if exitErr.ExitCode() != clierror.ExitOperational {
			t.Fatalf("CRITICAL CONTRACT VIOLATION: unauthorized baseline access returned exit code %d, expected 2 (ExitOperational)", exitErr.ExitCode())
		}
	} else {
		t.Fatalf("unexpected error type: %v", errSum)
	}

	// 8c. Process-level: Valid baseline summary returns Exit Success (0)
	cmdSumValid := exec.Command(absBin, "assessment", "summary",
		"--assessment-id", asmA.ID,
		"--execution", execA.ID,
		"--db", dbPath,
	)
	if out, err := cmdSumValid.CombinedOutput(); err != nil {
		t.Fatalf("expected valid baseline summary to succeed with code 0, got err: %v, out: %s", err, out)
	}
}

// -----------------------------------------------------------------------------
// 9. Explicit Baseline Selection & Compatibility Checks
// -----------------------------------------------------------------------------

func TestPhase84_ExplicitBaselineSelectionAndCompatibility(t *testing.T) {
	store, client, asm, _, _ := setupBaselineTestDB(t)
	authAdmin := assessment.NewAdminAuthContext()

	now := time.Now().UTC()
	t1 := now.Add(-3 * time.Hour)
	base1 := &assessment.AssessmentExecution{
		ID:           "exec-explicit-base-1",
		AssessmentID: asm.ID,
		ClientID:     client.ID,
		TenantID:     client.ID,
		Status:       assessment.StatusCompleted,
		StartedAt:    t1,
		CompletedAt:  &t1,
	}
	_ = store.CreateExecution(base1)

	t2 := now.Add(-2 * time.Hour)
	base2 := &assessment.AssessmentExecution{
		ID:           "exec-explicit-base-2",
		AssessmentID: asm.ID,
		ClientID:     client.ID,
		TenantID:     client.ID,
		Status:       assessment.StatusCompleted,
		StartedAt:    t2,
		CompletedAt:  &t2,
	}
	_ = store.CreateExecution(base2)

	t3 := now.Add(-1 * time.Hour)
	currExec := &assessment.AssessmentExecution{
		ID:           "exec-explicit-curr",
		AssessmentID: asm.ID,
		ClientID:     client.ID,
		TenantID:     client.ID,
		Status:       assessment.StatusCompleted,
		StartedAt:    t3,
		CompletedAt:  &t3,
	}
	_ = store.CreateExecution(currExec)

	// 9a. Explicit baseline selection: must select Base 1 exactly when requested
	sumBase1, err := store.GetAssessmentChangeSummary(asm.ID, base1.ID, currExec.ID, authAdmin)
	if err != nil {
		t.Fatalf("explicit baseline 1 failed: %v", err)
	}
	if sumBase1.BaselineExecutionID != base1.ID {
		t.Errorf("expected explicit baseline ID %s, got %s", base1.ID, sumBase1.BaselineExecutionID)
	}

	// 9b. Non-existent explicit baseline must fail rather than fallback
	_, err = store.GetAssessmentChangeSummary(asm.ID, "non-existent-base-id", currExec.ID, authAdmin)
	if err == nil {
		t.Fatalf("expected error on non-existent explicit baseline, got nil")
	}

	// 9c. Incompatible assessment types rejected
	asmCloud := &assessment.Assessment{
		ID:             "asm-cloud-incompat",
		Ref:            "ASM-CLOUD-INCOMPAT",
		ClientID:       client.ID,
		AssessmentType: "cloudsec",
		Status:         assessment.StatusReady,
	}
	_ = store.CreateAssessment(asmCloud)
	cloudExec := &assessment.AssessmentExecution{
		ID:             "exec-cloud-incompat",
		AssessmentID:   asmCloud.ID,
		ClientID:       client.ID,
		TenantID:       client.ID,
		AssessmentType: "cloudsec",
		Status:         assessment.StatusCompleted,
		StartedAt:      t1,
		CompletedAt:    &t1,
	}
	_ = store.CreateExecution(cloudExec)

	_, err = store.GetAssessmentChangeSummary("", cloudExec.ID, currExec.ID, authAdmin)
	if err == nil || !strings.Contains(err.Error(), "incompatible assessment types") {
		t.Fatalf("expected incompatible assessment types error, got: %v", err)
	}

	// 9d. Incompatible target scopes rejected
	asmOtherScope := &assessment.Assessment{
		ID:             "asm-other-scope",
		Ref:            "ASM-OTHER-SCOPE",
		ClientID:       client.ID,
		AssessmentType: "web",
		Status:         assessment.StatusReady,
	}
	_ = store.CreateAssessment(asmOtherScope)
	_ = store.AddTarget(&assessment.AssessmentTarget{
		ID:           "tgt-other-scope",
		AssessmentID: asmOtherScope.ID,
		TargetURL:    "https://completely-unrelated-internal-system.net",
		ScopeStatus:  "APPROVED",
	})
	otherScopeExec := &assessment.AssessmentExecution{
		ID:           "exec-other-scope",
		AssessmentID: asmOtherScope.ID,
		ClientID:     client.ID,
		TenantID:     client.ID,
		Status:       assessment.StatusCompleted,
		StartedAt:    t1,
		CompletedAt:  &t1,
	}
	_ = store.CreateExecution(otherScopeExec)

	_, err = store.GetAssessmentChangeSummary("", otherScopeExec.ID, currExec.ID, authAdmin)
	if err == nil || !strings.Contains(err.Error(), "incompatible assessment scopes") {
		t.Fatalf("expected incompatible assessment scopes error, got: %v", err)
	}

	// 9e. Automatic baseline selection is deterministic and picks Base 2 (latest prior completed)
	sumAuto, err := store.GetAssessmentChangeSummary(asm.ID, "", currExec.ID, authAdmin)
	if err != nil {
		t.Fatalf("automatic baseline failed: %v", err)
	}
	if sumAuto.BaselineExecutionID != base2.ID {
		t.Errorf("expected automatic baseline selection to pick latest prior completed (%s), got %s", base2.ID, sumAuto.BaselineExecutionID)
	}
}

// -----------------------------------------------------------------------------
// 10. Snapshot Integrity and Coverage Verification
// -----------------------------------------------------------------------------

func TestPhase84_SnapshotIntegrityAndCoverage(t *testing.T) {
	store, client, asm, tgt, _ := setupBaselineTestDB(t)
	authAdmin := assessment.NewAdminAuthContext()

	now := time.Now().UTC()
	currExec := &assessment.AssessmentExecution{
		ID:           "exec-snap-curr",
		AssessmentID: asm.ID,
		ClientID:     client.ID,
		TenantID:     client.ID,
		Status:       assessment.StatusCompleted,
		StartedAt:    now,
		CompletedAt:  &now,
	}
	_ = store.CreateExecution(currExec)

	// 10a. Missing snapshot fails safely
	missingSnapExec := &assessment.AssessmentExecution{
		ID:           "exec-missing-snap",
		AssessmentID: asm.ID,
		ClientID:     client.ID,
		TenantID:     client.ID,
		Status:       assessment.StatusCompleted,
		StartedAt:    now.Add(-2 * time.Hour),
		CompletedAt:  &now,
		SnapshotID:   "snp-does-not-exist",
	}
	_ = store.CreateExecution(missingSnapExec)

	_, err := store.GetAssessmentChangeSummary(asm.ID, missingSnapExec.ID, currExec.ID, authAdmin)
	if err == nil || !strings.Contains(err.Error(), "corrupt or missing baseline snapshot") {
		t.Fatalf("expected corrupt or missing baseline snapshot error, got: %v", err)
	}

	// 10b. Inconclusive snapshot fails safely
	inconclusiveExec := &assessment.AssessmentExecution{
		ID:           "exec-inconc-snap",
		AssessmentID: asm.ID,
		ClientID:     client.ID,
		TenantID:     client.ID,
		Status:       assessment.StatusCompleted,
		StartedAt:    now.Add(-2 * time.Hour),
		CompletedAt:  &now,
	}
	_ = store.CreateExecution(inconclusiveExec)
	inconcSnap := assessment.BuildAssessmentSnapshot(asm, inconclusiveExec, []string{tgt.TargetURL}, nil, false)
	inconcSnap.Metadata["inconclusive"] = "true"
	_ = store.CreateSnapshot(inconcSnap, nil, nil)
	inconclusiveExec.SnapshotID = inconcSnap.ID
	_ = store.UpdateExecution(inconclusiveExec)

	_, err = store.GetAssessmentChangeSummary(asm.ID, inconclusiveExec.ID, currExec.ID, authAdmin)
	if err == nil || !strings.Contains(err.Error(), "inconclusive") {
		t.Fatalf("expected inconclusive baseline snapshot rejection, got: %v", err)
	}

	// 10c. COMPLETED_WITH_ERRORS baseline with intact coverage is accepted
	compWithErrorsIntactExec := &assessment.AssessmentExecution{
		ID:           "exec-cwe-intact",
		AssessmentID: asm.ID,
		ClientID:     client.ID,
		TenantID:     client.ID,
		Status:       assessment.StatusCompletedWithErrors,
		StartedAt:    now.Add(-2 * time.Hour),
		CompletedAt:  &now,
	}
	_ = store.CreateExecution(compWithErrorsIntactExec)
	intactSnap := assessment.BuildAssessmentSnapshot(asm, compWithErrorsIntactExec, []string{tgt.TargetURL}, nil, true)
	intactSnap.SetAssessedTargets([]string{tgt.TargetURL})
	intactSnap.SetCoveredCategories([]string{"csrf", "xss"})
	_ = store.CreateSnapshot(intactSnap, nil, nil)
	compWithErrorsIntactExec.SnapshotID = intactSnap.ID
	_ = store.UpdateExecution(compWithErrorsIntactExec)

	sumIntact, err := store.GetAssessmentChangeSummary(asm.ID, compWithErrorsIntactExec.ID, currExec.ID, authAdmin)
	if err != nil {
		t.Fatalf("expected COMPLETED_WITH_ERRORS baseline with intact coverage to be accepted, got: %v", err)
	}
	if sumIntact.BaselineExecutionID != compWithErrorsIntactExec.ID {
		t.Errorf("expected baseline %s, got %s", compWithErrorsIntactExec.ID, sumIntact.BaselineExecutionID)
	}

	// 10d. COMPLETED_WITH_ERRORS baseline where target failed crawl is rejected
	compWithErrorsFailedTargetExec := &assessment.AssessmentExecution{
		ID:           "exec-cwe-failed-target",
		AssessmentID: asm.ID,
		ClientID:     client.ID,
		TenantID:     client.ID,
		Status:       assessment.StatusCompletedWithErrors,
		StartedAt:    now.Add(-2 * time.Hour),
		CompletedAt:  &now,
	}
	_ = store.CreateExecution(compWithErrorsFailedTargetExec)
	failedTgtSnap := assessment.BuildAssessmentSnapshot(asm, compWithErrorsFailedTargetExec, []string{tgt.TargetURL}, nil, true)
	failedTgtSnap.SetFailedTargets([]string{tgt.TargetURL})
	_ = store.CreateSnapshot(failedTgtSnap, nil, nil)
	compWithErrorsFailedTargetExec.SnapshotID = failedTgtSnap.ID
	_ = store.UpdateExecution(compWithErrorsFailedTargetExec)

	_, err = store.GetAssessmentChangeSummary(asm.ID, compWithErrorsFailedTargetExec.ID, currExec.ID, authAdmin)
	if err == nil || !strings.Contains(err.Error(), "suffered crawl failure") {
		t.Fatalf("expected rejection of baseline whose target failed crawl, got: %v", err)
	}
}
