package test

import (
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"felix/pkg/assessment"
	"felix/pkg/correlation"
	"felix/pkg/report"
)

func TestDelta_1_FindingIdentityAndMatching(t *testing.T) {
	// Findings with different finding IDs, created_at, or volatile evidence order must match reliably by fingerprint.
	baseFinding := report.Finding{
		ID:       "find-101",
		RuleID:   "API_BOLA",
		Category: "broken-object-level-authorization",
		Severity: report.SeverityHigh,
		Confidence: report.ConfidenceHigh,
		Target:   "https://api.example.com",
		Endpoint: "/api/users/{id}",
		Method:   "GET",
		Evidence: "User ID parameter tampered; timestamp: 2026-01-01T00:00:00Z",
		EvidenceDetails: report.EvidenceDetails{
			Observation: "User 123 viewed User 456 profile",
			Location:    "/api/users/{id}",
			Details: map[string]string{
				"parameter": "id",
				"timestamp": "2026-01-01T00:00:00Z",
			},
		},
	}
	correlation.EnsureFindingFingerprint(&baseFinding, correlation.TrustPolicyForceRecompute)

	currFinding := report.Finding{
		ID:       "find-999", // Different DB ID
		RuleID:   "API_BOLA",
		Category: "broken-object-level-authorization",
		Severity: report.SeverityHigh,
		Confidence: report.ConfidenceHigh,
		Target:   "https://api.example.com",
		Endpoint: "/api/users/{id}",
		Method:   "GET",
		Evidence: "User ID parameter tampered; timestamp: 2026-10-20T12:00:00Z", // Different volatile timestamp
		EvidenceDetails: report.EvidenceDetails{
			Observation: "User 123 viewed User 456 profile",
			Location:    "/api/users/{id}",
			Details: map[string]string{
				"parameter": "id",
				"timestamp": "2026-10-20T12:00:00Z", // Different volatile detail
			},
		},
	}
	correlation.EnsureFindingFingerprint(&currFinding, correlation.TrustPolicyForceRecompute)

	if baseFinding.Fingerprint != currFinding.Fingerprint {
		t.Fatalf("expected identical fingerprints, got base=%s curr=%s", baseFinding.Fingerprint, currFinding.Fingerprint)
	}

	cmp := correlation.CompareFindings([]report.Finding{baseFinding}, []report.Finding{currFinding})
	if cmp.PersistentCount != 1 {
		t.Errorf("expected 1 persistent finding, got persistent=%d items=%+v", cmp.PersistentCount, cmp.Items)
	}
	if len(cmp.Items) != 1 || cmp.Items[0].Classification != correlation.DeltaPersistent {
		t.Errorf("expected classification PERSISTENT, got %v", cmp.Items[0].Classification)
	}
}

func TestDelta_2_AllDeltaClassifications(t *testing.T) {
	// Baseline findings
	// 1. Will persist unchanged
	fPersistBase := report.Finding{
		Category: "missing-csp",
		Severity: report.SeverityLow,
		Confidence: report.ConfidenceHigh,
		Target:   "https://example.com",
		Endpoint: "/home",
		Method:   "GET",
	}
	correlation.EnsureFindingFingerprint(&fPersistBase, correlation.TrustPolicyForceRecompute)

	// 2. Will be resolved
	fResolvedBase := report.Finding{
		Category: "cors-wildcard",
		Severity: report.SeverityMedium,
		Confidence: report.ConfidenceHigh,
		Target:   "https://example.com",
		Endpoint: "/api/data",
		Method:   "GET",
	}
	correlation.EnsureFindingFingerprint(&fResolvedBase, correlation.TrustPolicyForceRecompute)

	// 3. Previously resolved finding that will reappear (REGRESSED - REAPPEARED)
	fReappearedBase := report.Finding{
		Category:        "env-exposure",
		Severity:        report.SeverityHigh,
		Confidence:      report.ConfidenceHigh,
		Target:          "https://example.com",
		Endpoint:        "/.env",
		Method:          "GET",
		LifecycleStatus: string(correlation.LifecycleResolved),
		Status:          "RESOLVED",
	}
	correlation.EnsureFindingFingerprint(&fReappearedBase, correlation.TrustPolicyForceRecompute)

	// 4. Finding whose severity will worsen (REGRESSED - SEVERITY_WORSENED)
	fWorsenedBase := report.Finding{
		Category:   "sql-injection",
		Severity:   report.SeverityMedium,
		Confidence: report.ConfidenceHigh,
		Target:     "https://example.com",
		Endpoint:   "/search",
		Method:     "GET",
	}
	correlation.EnsureFindingFingerprint(&fWorsenedBase, correlation.TrustPolicyForceRecompute)

	// 5. Finding whose severity will decrease (CHANGED - SEVERITY_DECREASED)
	fDecreasedBase := report.Finding{
		Category:   "open-redirect",
		Severity:   report.SeverityHigh,
		Confidence: report.ConfidenceHigh,
		Target:     "https://example.com",
		Endpoint:   "/redirect",
		Method:     "GET",
	}
	correlation.EnsureFindingFingerprint(&fDecreasedBase, correlation.TrustPolicyForceRecompute)

	// 6. Finding whose confidence will change (CHANGED - CONFIDENCE_CHANGED)
	fConfChangedBase := report.Finding{
		Category:   "ssrf",
		Severity:   report.SeverityHigh,
		Confidence: report.ConfidenceLow,
		Target:     "https://example.com",
		Endpoint:   "/webhook",
		Method:     "POST",
	}
	correlation.EnsureFindingFingerprint(&fConfChangedBase, correlation.TrustPolicyForceRecompute)

	// 7. Finding whose material evidence changes (CHANGED - EVIDENCE_CHANGED)
	fEvChangedBase := report.Finding{
		Category:   "xss-stored",
		Severity:   report.SeverityHigh,
		Confidence: report.ConfidenceHigh,
		Target:     "https://example.com",
		Endpoint:   "/comment",
		Method:     "POST",
		EvidenceDetails: report.EvidenceDetails{
			Observation: "Payload `<script>1</script>` reflected in response",
		},
	}
	correlation.EnsureFindingFingerprint(&fEvChangedBase, correlation.TrustPolicyForceRecompute)

	baseline := []report.Finding{
		fPersistBase, fResolvedBase, fReappearedBase, fWorsenedBase,
		fDecreasedBase, fConfChangedBase, fEvChangedBase,
	}

	// Current findings
	fPersistCur := fPersistBase
	// fResolvedBase omitted in current -> RESOLVED

	fReappearedCur := fReappearedBase
	fReappearedCur.LifecycleStatus = string(correlation.LifecycleActive)
	fReappearedCur.Status = report.FindingStatusSuspected

	fWorsenedCur := fWorsenedBase
	fWorsenedCur.Severity = report.SeverityCritical // MEDIUM -> CRITICAL

	fDecreasedCur := fDecreasedBase
	fDecreasedCur.Severity = report.SeverityLow // HIGH -> LOW

	fConfChangedCur := fConfChangedBase
	fConfChangedCur.Confidence = report.ConfidenceHigh // LOW -> HIGH

	fEvChangedCur := fEvChangedBase
	fEvChangedCur.EvidenceDetails = report.EvidenceDetails{
		Observation: "Payload `<img src=x onerror=alert(1)>` executed in admin context",
	}

	// 8. Brand new finding (NEW)
	fNewCur := report.Finding{
		Category:   "rce-command-injection",
		Severity:   report.SeverityCritical,
		Confidence: report.ConfidenceHigh,
		Target:     "https://example.com",
		Endpoint:   "/api/exec",
		Method:     "POST",
	}
	correlation.EnsureFindingFingerprint(&fNewCur, correlation.TrustPolicyForceRecompute)

	current := []report.Finding{
		fPersistCur, fReappearedCur, fWorsenedCur, fDecreasedCur,
		fConfChangedCur, fEvChangedCur, fNewCur,
	}

	opts := correlation.DefaultComparisonOptions()
	opts.ScopedTargets = []string{"https://example.com"}
	cmp := correlation.CompareFindingsWithOptions(baseline, current, opts)

	if cmp.ComparisonStatus != "COMPLETE" {
		t.Errorf("expected COMPLETE status, got %s", cmp.ComparisonStatus)
	}
	if cmp.BaselineCount != 7 {
		t.Errorf("expected 7 baseline findings, got %d", cmp.BaselineCount)
	}
	if cmp.CurrentCount != 7 {
		t.Errorf("expected 7 current findings, got %d", cmp.CurrentCount)
	}
	if cmp.NewCount != 1 {
		t.Errorf("expected 1 NEW finding, got %d", cmp.NewCount)
	}
	if cmp.ResolvedCount != 1 {
		t.Errorf("expected 1 RESOLVED finding, got %d", cmp.ResolvedCount)
	}
	if cmp.PersistentCount != 1 {
		t.Errorf("expected 1 PERSISTENT finding, got %d", cmp.PersistentCount)
	}
	if cmp.RegressedCount != 2 {
		t.Errorf("expected 2 REGRESSED findings, got %d", cmp.RegressedCount)
	}
	if cmp.ChangedCount != 3 {
		t.Errorf("expected 3 CHANGED findings, got %d", cmp.ChangedCount)
	}

	// Verify classifications on items
	classMap := make(map[string]correlation.FindingComparisonItem)
	for _, it := range cmp.Items {
		classMap[it.Category] = it
	}

	if it, ok := classMap["rce-command-injection"]; !ok || it.Classification != correlation.DeltaNew {
		t.Errorf("rce-command-injection expected NEW, got %+v", it)
	}
	if it, ok := classMap["cors-wildcard"]; !ok || it.Classification != correlation.DeltaResolved {
		t.Errorf("cors-wildcard expected RESOLVED, got %+v", it)
	}
	if it, ok := classMap["missing-csp"]; !ok || it.Classification != correlation.DeltaPersistent {
		t.Errorf("missing-csp expected PERSISTENT, got %+v", it)
	}
	if it, ok := classMap["env-exposure"]; !ok || it.Classification != correlation.DeltaRegressed || it.RegressionReason != correlation.RegressionReappeared {
		t.Errorf("env-exposure expected REGRESSED (REAPPEARED), got %+v", it)
	}
	if it, ok := classMap["sql-injection"]; !ok || it.Classification != correlation.DeltaRegressed || it.RegressionReason != correlation.RegressionSeverityWorsened {
		t.Errorf("sql-injection expected REGRESSED (SEVERITY_WORSENED), got %+v", it)
	}
	if it, ok := classMap["open-redirect"]; !ok || it.Classification != correlation.DeltaChanged || it.ChangeReason != correlation.ChangeSeverityDecreased {
		t.Errorf("open-redirect expected CHANGED (SEVERITY_DECREASED), got %+v", it)
	}
	if it, ok := classMap["ssrf"]; !ok || it.Classification != correlation.DeltaChanged || it.ChangeReason != correlation.ChangeConfidenceChanged {
		t.Errorf("ssrf expected CHANGED (CONFIDENCE_CHANGED), got %+v", it)
	}
	if it, ok := classMap["xss-stored"]; !ok || it.Classification != correlation.DeltaChanged || it.ChangeReason != correlation.ChangeEvidenceChanged {
		t.Errorf("xss-stored expected CHANGED (EVIDENCE_CHANGED), got %+v", it)
	}
}

func TestDelta_3_SafetyInvariant_NeverResolveOnIncomplete(t *testing.T) {
	// Baseline finding
	baseFinding := report.Finding{
		Category:   "sqli",
		Severity:   report.SeverityCritical,
		Confidence: report.ConfidenceHigh,
		Target:     "https://app.example.com",
		Endpoint:   "/login",
		Method:     "POST",
	}
	correlation.EnsureFindingFingerprint(&baseFinding, correlation.TrustPolicyForceRecompute)

	baseline := []report.Finding{baseFinding}
	currentEmpty := []report.Finding{} // Finding absent in current run

	// Case A: Current run failed / was cancelled / incomplete
	optsFailed := correlation.DefaultComparisonOptions()
	optsFailed.CurrentCompleted = false

	cmpA := correlation.CompareFindingsWithOptions(baseline, currentEmpty, optsFailed)
	if cmpA.ResolvedCount != 0 {
		t.Fatalf("INVARIANT VIOLATION: incomplete run produced %d RESOLVED findings", cmpA.ResolvedCount)
	}
	if cmpA.UnverifiedCount != 1 || cmpA.Items[0].Classification != correlation.DeltaUnverified {
		t.Errorf("expected UNVERIFIED classification, got count=%d classification=%v", cmpA.UnverifiedCount, cmpA.Items[0].Classification)
	}
	if cmpA.ComparisonStatus != "PARTIAL" {
		t.Errorf("expected PARTIAL comparison status, got %s", cmpA.ComparisonStatus)
	}

	// Case B: Current run marked inconclusive
	optsInconclusive := correlation.DefaultComparisonOptions()
	optsInconclusive.CurrentCompleted = true
	optsInconclusive.Inconclusive = true

	cmpB := correlation.CompareFindingsWithOptions(baseline, currentEmpty, optsInconclusive)
	if cmpB.ResolvedCount != 0 {
		t.Fatalf("INVARIANT VIOLATION: inconclusive run produced %d RESOLVED findings", cmpB.ResolvedCount)
	}
	if cmpB.UnverifiedCount != 1 || cmpB.Items[0].Classification != correlation.DeltaUnverified {
		t.Errorf("expected UNVERIFIED on inconclusive run, got %+v", cmpB)
	}

	// Case C: Target out of scope in current run
	optsOutOfScope := correlation.DefaultComparisonOptions()
	optsOutOfScope.CurrentCompleted = true
	optsOutOfScope.ScopedTargets = []string{"https://other.example.com"} // base target not scoped

	cmpC := correlation.CompareFindingsWithOptions(baseline, currentEmpty, optsOutOfScope)
	if cmpC.ResolvedCount != 0 {
		t.Fatalf("INVARIANT VIOLATION: out-of-scope target produced %d RESOLVED findings", cmpC.ResolvedCount)
	}
	if cmpC.UnverifiedCount != 1 || cmpC.Items[0].Classification != correlation.DeltaUnverified {
		t.Errorf("expected UNVERIFIED on out-of-scope target, got %+v", cmpC)
	}

	// Case D: Target encountered network failure / timeout
	optsFailedTarget := correlation.DefaultComparisonOptions()
	optsFailedTarget.CurrentCompleted = true
	optsFailedTarget.ScopedTargets = []string{"https://app.example.com"}
	optsFailedTarget.FailedTargets = []string{"https://app.example.com"}

	cmpD := correlation.CompareFindingsWithOptions(baseline, currentEmpty, optsFailedTarget)
	if cmpD.ResolvedCount != 0 {
		t.Fatalf("INVARIANT VIOLATION: failed target produced %d RESOLVED findings", cmpD.ResolvedCount)
	}
	if cmpD.UnverifiedCount != 1 || cmpD.Items[0].Classification != correlation.DeltaUnverified {
		t.Errorf("expected UNVERIFIED on failed target, got %+v", cmpD)
	}

	// Case E: Detector category failed
	optsFailedCat := correlation.DefaultComparisonOptions()
	optsFailedCat.CurrentCompleted = true
	optsFailedCat.ScopedTargets = []string{"https://app.example.com"}
	optsFailedCat.FailedCategories = []string{"sqli"}

	cmpE := correlation.CompareFindingsWithOptions(baseline, currentEmpty, optsFailedCat)
	if cmpE.ResolvedCount != 0 {
		t.Fatalf("INVARIANT VIOLATION: failed category produced %d RESOLVED findings", cmpE.ResolvedCount)
	}
	if cmpE.UnverifiedCount != 1 || cmpE.Items[0].Classification != correlation.DeltaUnverified {
		t.Errorf("expected UNVERIFIED on failed category, got %+v", cmpE)
	}
}

func TestDelta_4_StoreCompareExecutionHistory(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "test_delta.db")
	store, err := assessment.NewSQLiteStore(dbPath)
	if err != nil {
		t.Fatalf("failed to open store: %v", err)
	}
	defer store.Close()

	authAdmin := assessment.NewAdminAuthContext()

	// 1. Create client and assessment
	client := &assessment.Client{
		ID:   "client-delta-1",
		Name: "Delta Corp",
	}
	if err := store.CreateClient(client); err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	asm := &assessment.Assessment{
		ID:       "asm-delta-1",
		Ref:      "ASM-DELTA-1",
		ClientID: client.ID,
		Name:     "Continuous Web Audit",
		Status:   assessment.StatusReady,
	}
	if err := store.CreateAssessment(asm); err != nil {
		t.Fatalf("failed to create assessment: %v", err)
	}

	// Add approved target
	tgt := &assessment.AssessmentTarget{
		AssessmentID: asm.ID,
		TargetURL:    "https://api.deltacorp.com",
		ScopeStatus:  "APPROVED",
	}
	if err := store.AddTarget(tgt); err != nil {
		t.Fatalf("failed to add target: %v", err)
	}

	now := time.Now().UTC()
	past := now.Add(-24 * time.Hour)

	// 2. Execution 1 (Baseline run)
	exec1 := &assessment.AssessmentExecution{
		ID:               "exec-delta-base",
		AssessmentID:     asm.ID,
		ClientID:         client.ID,
		TenantID:         "tenant-delta-1",
		AccountID:        "acc-1",
		Status:           assessment.StatusCompleted,
		InitiationSource: "scheduled",
		StartedAt:        past,
		CompletedAt:      &past,
	}
	if err := store.CreateExecution(exec1); err != nil {
		t.Fatalf("failed to create exec1: %v", err)
	}

	finding1 := assessment.AssessmentFinding{
		ID:           "f-delta-1",
		AssessmentID: asm.ID,
		ExecutionID:  exec1.ID,
		TargetURL:    "https://api.deltacorp.com",
		Endpoint:     "/api/v1/auth/token",
		Category:     "jwt-none-algorithm",
		Severity:     report.SeverityHigh,
		Confidence:   report.ConfidenceHigh,
		Title:        "JWT None Algorithm Allowed",
	}
	finding2 := assessment.AssessmentFinding{
		ID:           "f-delta-2",
		AssessmentID: asm.ID,
		ExecutionID:  exec1.ID,
		TargetURL:    "https://api.deltacorp.com",
		Endpoint:     "/api/v1/users",
		Category:     "missing-rate-limit",
		Severity:     report.SeverityLow,
		Confidence:   report.ConfidenceMedium,
		Title:        "Missing Rate Limit on Users Endpoint",
	}
	if err := store.SaveFindings([]assessment.AssessmentFinding{finding1, finding2}); err != nil {
		t.Fatalf("failed to save base findings: %v", err)
	}

	// Create snapshot for baseline
	snap1 := &assessment.AssessmentSnapshot{
		ID:            "snap-delta-1",
		AssessmentID:  asm.ID,
		ExecutionID:   exec1.ID,
		ClientID:      client.ID,
		TenantID:      "tenant-delta-1",
		AccountID:     "acc-1",
		Name:          "Baseline Snapshot",
		Status:        "COMPLETED",
		IsComplete:    true,
		CompletedAt:   &past,
		ScopedTargets: []string{"https://api.deltacorp.com"},
	}
	if err := store.CreateSnapshot(snap1, []assessment.AssessmentFinding{finding1, finding2}, nil); err != nil {
		t.Fatalf("failed to create snapshot 1: %v", err)
	}
	exec1.SnapshotID = snap1.ID
	if err := store.UpdateExecution(exec1); err != nil {
		t.Fatalf("failed to update exec1: %v", err)
	}

	// 3. Execution 2 (Current run: finding1 resolved, finding2 persistent, finding3 new)
	exec2 := &assessment.AssessmentExecution{
		ID:               "exec-delta-cur",
		AssessmentID:     asm.ID,
		ClientID:         client.ID,
		TenantID:         "tenant-delta-1",
		AccountID:        "acc-1",
		Status:           assessment.StatusCompleted,
		InitiationSource: "scheduled",
		StartedAt:        now,
		CompletedAt:      &now,
	}
	if err := store.CreateExecution(exec2); err != nil {
		t.Fatalf("failed to create exec2: %v", err)
	}

	finding2Cur := assessment.AssessmentFinding{
		ID:           "f-delta-2-cur",
		AssessmentID: asm.ID,
		ExecutionID:  exec2.ID,
		TargetURL:    "https://api.deltacorp.com",
		Endpoint:     "/api/v1/users",
		Category:     "missing-rate-limit",
		Severity:     report.SeverityLow,
		Confidence:   report.ConfidenceMedium,
		Title:        "Missing Rate Limit on Users Endpoint",
	}
	finding3Cur := assessment.AssessmentFinding{
		ID:           "f-delta-3-cur",
		AssessmentID: asm.ID,
		ExecutionID:  exec2.ID,
		TargetURL:    "https://api.deltacorp.com",
		Endpoint:     "/api/v1/admin/debug",
		Category:     "debug-endpoint-exposed",
		Severity:     report.SeverityCritical,
		Confidence:   report.ConfidenceHigh,
		Title:        "Debug Endpoint Exposed to Public",
	}
	if err := store.SaveFindings([]assessment.AssessmentFinding{finding2Cur, finding3Cur}); err != nil {
		t.Fatalf("failed to save current findings: %v", err)
	}

	snap2 := &assessment.AssessmentSnapshot{
		ID:            "snap-delta-2",
		AssessmentID:  asm.ID,
		ExecutionID:   exec2.ID,
		ClientID:      client.ID,
		TenantID:      "tenant-delta-1",
		AccountID:     "acc-1",
		Name:          "Current Snapshot",
		Status:        "COMPLETED",
		IsComplete:    true,
		CompletedAt:   &now,
		ScopedTargets: []string{"https://api.deltacorp.com"},
	}
	if err := store.CreateSnapshot(snap2, []assessment.AssessmentFinding{finding2Cur, finding3Cur}, nil); err != nil {
		t.Fatalf("failed to create snapshot 2: %v", err)
	}
	exec2.SnapshotID = snap2.ID
	if err := store.UpdateExecution(exec2); err != nil {
		t.Fatalf("failed to update exec2: %v", err)
	}

	// 4. Compare via store
	cmp, err := store.CompareExecutionHistory(exec1.ID, exec2.ID, authAdmin)
	if err != nil {
		t.Fatalf("CompareExecutionHistory failed: %v", err)
	}

	if cmp.ComparisonStatus != "COMPLETE" {
		t.Errorf("expected COMPLETE comparison status, got %s", cmp.ComparisonStatus)
	}
	if cmp.BaselineCount != 2 {
		t.Errorf("expected 2 baseline findings, got %d", cmp.BaselineCount)
	}
	if cmp.CurrentCount != 2 {
		t.Errorf("expected 2 current findings, got %d", cmp.CurrentCount)
	}
	if cmp.NewCount != 1 {
		t.Errorf("expected 1 NEW finding, got %d", cmp.NewCount)
	}
	if cmp.ResolvedCount != 1 {
		t.Errorf("expected 1 RESOLVED finding, got %d", cmp.ResolvedCount)
	}
	if cmp.PersistentCount != 1 {
		t.Errorf("expected 1 PERSISTENT finding, got %d", cmp.PersistentCount)
	}
	if cmp.BaselineExecutionID != exec1.ID || cmp.CurrentExecutionID != exec2.ID {
		t.Errorf("expected execution IDs %s and %s, got %s and %s", exec1.ID, exec2.ID, cmp.BaselineExecutionID, cmp.CurrentExecutionID)
	}

	// 5. Test Tenant Isolation Boundaries
	otherTenantAuth := assessment.NewTenantAuthContext("client-other", "tenant-other-unauthorized", "acc-other")
	_, err = store.CompareExecutionHistory(exec1.ID, exec2.ID, otherTenantAuth)
	if err == nil {
		t.Fatalf("expected authorization failure for cross-tenant access, got nil")
	}

	// Test cross-tenant comparison between two executions from different tenants
	asmOther := &assessment.Assessment{
		ID:       "asm-other-tenant",
		Ref:      "ASM-OTHER-1",
		ClientID: client.ID,
		Name:     "Other Tenant Assessment",
		Status:   assessment.StatusReady,
	}
	if err := store.CreateAssessment(asmOther); err != nil {
		t.Fatalf("failed to create other assessment: %v", err)
	}

	execOtherTenant := &assessment.AssessmentExecution{
		ID:           "exec-other-tenant",
		AssessmentID: asmOther.ID,
		ClientID:     client.ID,
		TenantID:     "tenant-xyz",
		Status:       assessment.StatusCompleted,
		StartedAt:    now,
		CompletedAt:  &now,
	}
	if err := store.CreateExecution(execOtherTenant); err != nil {
		t.Fatalf("failed to create other tenant execution: %v", err)
	}

	_, err = store.CompareExecutionHistory(exec1.ID, execOtherTenant.ID, authAdmin)
	if err == nil {
		t.Fatalf("expected cross-tenant comparison refusal, got nil")
	}
	if !strings.Contains(err.Error(), "cross-tenant comparison denied") {
		t.Errorf("expected 'cross-tenant comparison denied' error, got %v", err)
	}
}

func TestDelta_5_ReopenDBDeterminism(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "deterministic_delta.db")
	authAdmin := assessment.NewAdminAuthContext()

	// Initial store write
	store1, err := assessment.NewSQLiteStore(dbPath)
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}

	clientDet := &assessment.Client{
		ID:   "client-det-1",
		Name: "Deterministic Client",
	}
	if err := store1.CreateClient(clientDet); err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	now := time.Now().UTC()
	past := now.Add(-1 * time.Hour)

	asmDet := &assessment.Assessment{
		ID:       "asm-det-1",
		Ref:      "ASM-DET-1",
		ClientID: clientDet.ID,
		Name:     "Deterministic Assessment",
		Status:   assessment.StatusReady,
	}
	if err := store1.CreateAssessment(asmDet); err != nil {
		t.Fatalf("failed to create assessment: %v", err)
	}

	tgtDet := &assessment.AssessmentTarget{
		ID:           "tgt-det-1",
		AssessmentID: asmDet.ID,
		TargetURL:    "https://target.com",
		ScopeStatus:  "APPROVED",
	}
	if err := store1.AddTarget(tgtDet); err != nil {
		t.Fatalf("failed to add target: %v", err)
	}

	exec1 := &assessment.AssessmentExecution{
		ID:           "exec-det-1",
		AssessmentID: asmDet.ID,
		ClientID:     clientDet.ID,
		TenantID:     "t1",
		Status:       assessment.StatusCompleted,
		StartedAt:    past,
		CompletedAt:  &past,
	}
	exec2 := &assessment.AssessmentExecution{
		ID:           "exec-det-2",
		AssessmentID: asmDet.ID,
		ClientID:     clientDet.ID,
		TenantID:     "t1",
		Status:       assessment.StatusCompleted,
		StartedAt:    now,
		CompletedAt:  &now,
	}
	if err := store1.CreateExecution(exec1); err != nil {
		t.Fatalf("failed to create exec1: %v", err)
	}
	if err := store1.CreateExecution(exec2); err != nil {
		t.Fatalf("failed to create exec2: %v", err)
	}

	f1 := assessment.AssessmentFinding{
		ID:           "f-det-1",
		AssessmentID: asmDet.ID,
		ExecutionID:  exec1.ID,
		TargetID:     tgtDet.ID,
		TargetURL:    "https://target.com",
		Category:     "cat-a",
		Severity:     report.SeverityHigh,
	}
	f2 := assessment.AssessmentFinding{
		ID:           "f-det-2",
		AssessmentID: asmDet.ID,
		ExecutionID:  exec2.ID,
		TargetID:     tgtDet.ID,
		TargetURL:    "https://target.com",
		Category:     "cat-a",
		Severity:     report.SeverityCritical, // Worsened
	}
	if err := store1.SaveFindings([]assessment.AssessmentFinding{f1, f2}); err != nil {
		t.Fatalf("failed to save findings: %v", err)
	}

	cmp1, err := store1.CompareExecutionHistory(exec1.ID, exec2.ID, authAdmin)
	if err != nil {
		t.Fatalf("comparison 1 failed: %v", err)
	}
	store1.Close()

	// Reopen database from disk
	store2, err := assessment.NewSQLiteStore(dbPath)
	if err != nil {
		t.Fatalf("failed to reopen store: %v", err)
	}

	cmp2, err := store2.CompareExecutionHistory(exec1.ID, exec2.ID, authAdmin)
	store2.Close()
	if err != nil {
		t.Fatalf("comparison 2 failed after reopen: %v", err)
	}

	if cmp1.RegressedCount != cmp2.RegressedCount || cmp1.NetRiskScoreDelta != cmp2.NetRiskScoreDelta {
		t.Fatalf("non-deterministic delta between store sessions: cmp1=%+v cmp2=%+v", cmp1, cmp2)
	}
	if len(cmp1.Items) != len(cmp2.Items) || cmp1.Items[0].Classification != cmp2.Items[0].Classification {
		t.Fatalf("mismatched items between store sessions: cmp1=%+v cmp2=%+v", cmp1.Items, cmp2.Items)
	}
}

func TestDelta_6_CLIDiffExecution(t *testing.T) {
	binPath := getFelixBinPath(t)
	dbPath := filepath.Join(t.TempDir(), "cli_delta.db")
	store, err := assessment.NewSQLiteStore(dbPath)
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}

	clientCLI := &assessment.Client{
		ID:   "client-cli-1",
		Name: "CLI Client",
	}
	if err := store.CreateClient(clientCLI); err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	now := time.Now().UTC()
	past := now.Add(-2 * time.Hour)

	asmCLI := &assessment.Assessment{
		ID:       "asm-cli-1",
		Ref:      "ASM-CLI-1",
		ClientID: clientCLI.ID,
		Name:     "CLI Assessment",
		Status:   assessment.StatusReady,
	}
	if err := store.CreateAssessment(asmCLI); err != nil {
		t.Fatalf("failed to create assessment: %v", err)
	}

	tgtCLI := &assessment.AssessmentTarget{
		ID:           "tgt-cli-1",
		AssessmentID: asmCLI.ID,
		TargetURL:    "https://cli.target.com",
		ScopeStatus:  "APPROVED",
	}
	if err := store.AddTarget(tgtCLI); err != nil {
		t.Fatalf("failed to add target: %v", err)
	}

	exec1 := &assessment.AssessmentExecution{
		ID:           "exec-cli-1",
		AssessmentID: asmCLI.ID,
		ClientID:     clientCLI.ID,
		Status:       assessment.StatusCompleted,
		StartedAt:    past,
		CompletedAt:  &past,
	}
	exec2 := &assessment.AssessmentExecution{
		ID:           "exec-cli-2",
		AssessmentID: asmCLI.ID,
		ClientID:     clientCLI.ID,
		Status:       assessment.StatusCompleted,
		StartedAt:    now,
		CompletedAt:  &now,
	}
	if err := store.CreateExecution(exec1); err != nil {
		t.Fatalf("failed to create exec1: %v", err)
	}
	if err := store.CreateExecution(exec2); err != nil {
		t.Fatalf("failed to create exec2: %v", err)
	}

	f1 := assessment.AssessmentFinding{
		ID:           "f-cli-1",
		AssessmentID: asmCLI.ID,
		ExecutionID:  exec1.ID,
		TargetID:     tgtCLI.ID,
		TargetURL:    "https://cli.target.com",
		Endpoint:     "/api/login",
		Category:     "weak-password-policy",
		Severity:     report.SeverityLow,
		Title:        "Weak Password Policy",
	}
	f2 := assessment.AssessmentFinding{
		ID:           "f-cli-2",
		AssessmentID: asmCLI.ID,
		ExecutionID:  exec2.ID,
		TargetID:     tgtCLI.ID,
		TargetURL:    "https://cli.target.com",
		Endpoint:     "/api/login",
		Category:     "weak-password-policy",
		Severity:     report.SeverityLow,
		Title:        "Weak Password Policy",
	}
	f3 := assessment.AssessmentFinding{
		ID:           "f-cli-3",
		AssessmentID: asmCLI.ID,
		ExecutionID:  exec2.ID,
		TargetID:     tgtCLI.ID,
		TargetURL:    "https://cli.target.com",
		Endpoint:     "/api/admin",
		Category:     "unauth-admin",
		Severity:     report.SeverityCritical,
		Title:        "Unauthorized Admin Access",
	}
	if err := store.SaveFindings([]assessment.AssessmentFinding{f1, f2, f3}); err != nil {
		t.Fatalf("failed to save findings: %v", err)
	}
	store.Close()

	// 1. Run CLI diff command with JSON
	cmdJSON := exec.Command(binPath, "diff", exec1.ID, exec2.ID, "--db", dbPath, "--json")
	outJSONBytes, err := cmdJSON.CombinedOutput()
	if err != nil {
		t.Fatalf("cli diff --json failed: %v, out=%s", err, string(outJSONBytes))
	}
	outJSON := string(outJSONBytes)

	if !strings.Contains(outJSON, `"new_count": 1`) {
		t.Errorf("expected JSON output containing '\"new_count\": 1', got:\n%s", outJSON)
	}
	if !strings.Contains(outJSON, `"persistent_count": 1`) {
		t.Errorf("expected JSON output containing '\"persistent_count\": 1', got:\n%s", outJSON)
	}

	// 2. Run CLI diff command via `felix assessment diff` with summary-only
	cmdSummary := exec.Command(binPath, "assessment", "diff", exec1.ID, exec2.ID, "--db", dbPath, "--summary-only")
	outSummaryBytes, err := cmdSummary.CombinedOutput()
	if err != nil {
		t.Fatalf("cli assessment diff --summary-only failed: %v, out=%s", err, string(outSummaryBytes))
	}
	outSummary := string(outSummaryBytes)

	if !strings.Contains(outSummary, "FELIX ASSESSMENT FINDING DELTA") {
		t.Errorf("expected table header in output, got:\n%s", outSummary)
	}
	if !strings.Contains(outSummary, "New Findings:        1") {
		t.Errorf("expected 'New Findings:        1' in summary, got:\n%s", outSummary)
	}
	if !strings.Contains(outSummary, "Persistent Findings: 1") {
		t.Errorf("expected 'Persistent Findings: 1' in summary, got:\n%s", outSummary)
	}
}

func TestDelta_7_EndpointChangeMatchingAndDistinctSeparation(t *testing.T) {
	// 1. Normalization differences: Default port (:443) and URL scheme/host canonicalization
	// Baseline: https://api.example.com:443/auth/login
	// Current:  https://api.example.com/auth/login
	// Must produce identical canonical fingerprint because default port 443 is normalized out.
	// Raw endpoints differ -> CHANGED (ENDPOINT_CHANGED).
	fNormBase := report.Finding{
		Category:   "sql-injection",
		Severity:   report.SeverityHigh,
		Confidence: report.ConfidenceHigh,
		Target:     "https://api.example.com",
		Endpoint:   "https://api.example.com:443/auth/login",
		Method:     "POST",
	}
	fNormCur := report.Finding{
		Category:   "sql-injection",
		Severity:   report.SeverityHigh,
		Confidence: report.ConfidenceHigh,
		Target:     "https://api.example.com",
		Endpoint:   "https://api.example.com/auth/login",
		Method:     "POST",
	}
	correlation.EnsureFindingFingerprint(&fNormBase, correlation.TrustPolicyForceRecompute)
	correlation.EnsureFindingFingerprint(&fNormCur, correlation.TrustPolicyForceRecompute)

	if fNormBase.Fingerprint != fNormCur.Fingerprint {
		t.Fatalf("expected normalization differences to yield identical fingerprints, got base=%s cur=%s", fNormBase.Fingerprint, fNormCur.Fingerprint)
	}

	cmpNorm := correlation.CompareFindings([]report.Finding{fNormBase}, []report.Finding{fNormCur})
	if cmpNorm.ChangedCount != 1 || len(cmpNorm.Items) != 1 {
		t.Fatalf("expected 1 changed finding for normalization change, got changed=%d", cmpNorm.ChangedCount)
	}
	if cmpNorm.Items[0].Classification != correlation.DeltaChanged || cmpNorm.Items[0].ChangeReason != correlation.ChangeEndpointChanged {
		t.Errorf("expected CHANGED (ENDPOINT_CHANGED), got %s (%s)", cmpNorm.Items[0].Classification, cmpNorm.Items[0].ChangeReason)
	}

	// 1b. Secrets line-number normalization:
	// Baseline: src/auth.go:42
	// Current:  src/auth.go:99
	// Line numbers are normalized away in fingerprinting, but raw locations differ -> CHANGED (ENDPOINT_CHANGED).
	fSecBase := report.Finding{
		PrimaryAssetID: "repo-felix",
		Source:         report.SourceSecrets,
		Category:       "hardcoded-credentials",
		Severity:       report.SeverityCritical,
		Confidence:     report.ConfidenceHigh,
		Target:         "repo://felix",
		Endpoint:       "src/auth.go:42",
		Method:         "GET",
	}
	fSecCur := report.Finding{
		PrimaryAssetID: "repo-felix",
		Source:         report.SourceSecrets,
		Category:       "hardcoded-credentials",
		Severity:       report.SeverityCritical,
		Confidence:     report.ConfidenceHigh,
		Target:         "repo://felix",
		Endpoint:       "src/auth.go:99",
		Method:         "GET",
	}
	correlation.EnsureFindingFingerprint(&fSecBase, correlation.TrustPolicyForceRecompute)
	correlation.EnsureFindingFingerprint(&fSecCur, correlation.TrustPolicyForceRecompute)

	if fSecBase.Fingerprint != fSecCur.Fingerprint {
		t.Fatalf("expected secret line-number difference to yield identical fingerprints, got base=%s cur=%s", fSecBase.Fingerprint, fSecCur.Fingerprint)
	}
	cmpSec := correlation.CompareFindings([]report.Finding{fSecBase}, []report.Finding{fSecCur})
	if cmpSec.ChangedCount != 1 || cmpSec.Items[0].ChangeReason != correlation.ChangeEndpointChanged {
		t.Errorf("expected secret line shift to be CHANGED (ENDPOINT_CHANGED), got %s (%s)", cmpSec.Items[0].Classification, cmpSec.Items[0].ChangeReason)
	}

	// 2. Path change with explicit tracking ID (e.g. API version migration):
	// Baseline: /api/v1/users (tracking_id = "trk-user-idor")
	// Current:  /api/v2/users (tracking_id = "trk-user-idor")
	// Canonical fingerprints differ because path changed, but secondary tracking rule safely matches them.
	fTrackBase := report.Finding{
		Category:   "broken-object-level-authorization",
		Severity:   report.SeverityHigh,
		Confidence: report.ConfidenceHigh,
		Target:     "https://api.example.com",
		Endpoint:   "/api/v1/users",
		Method:     "GET",
		EvidenceDetails: report.EvidenceDetails{
			Details: map[string]string{
				"tracking_id": "trk-user-idor",
			},
		},
	}
	fTrackCur := report.Finding{
		Category:   "broken-object-level-authorization",
		Severity:   report.SeverityHigh,
		Confidence: report.ConfidenceHigh,
		Target:     "https://api.example.com",
		Endpoint:   "/api/v2/users",
		Method:     "GET",
		EvidenceDetails: report.EvidenceDetails{
			Details: map[string]string{
				"tracking_id": "trk-user-idor",
			},
		},
	}
	correlation.EnsureFindingFingerprint(&fTrackBase, correlation.TrustPolicyForceRecompute)
	correlation.EnsureFindingFingerprint(&fTrackCur, correlation.TrustPolicyForceRecompute)

	if fTrackBase.Fingerprint == fTrackCur.Fingerprint {
		t.Fatalf("expected different fingerprints for different paths, got identical %s", fTrackBase.Fingerprint)
	}

	cmpTrack := correlation.CompareFindings([]report.Finding{fTrackBase}, []report.Finding{fTrackCur})
	if cmpTrack.ChangedCount != 1 {
		t.Fatalf("expected 1 changed finding via secondary tracking match, got changed=%d (new=%d resolved=%d)", cmpTrack.ChangedCount, cmpTrack.NewCount, cmpTrack.ResolvedCount)
	}
	if cmpTrack.Items[0].Classification != correlation.DeltaChanged || cmpTrack.Items[0].ChangeReason != correlation.ChangeEndpointChanged {
		t.Errorf("expected CHANGED (ENDPOINT_CHANGED) for tracking ID migration, got %s (%s)", cmpTrack.Items[0].Classification, cmpTrack.Items[0].ChangeReason)
	}

	// 3. Distinct endpoints without tracking ID must NEVER be accidentally merged!
	// Baseline: POST /api/v1/users (sql-injection)
	// Current:  POST /api/v1/orders (sql-injection)
	// These are genuinely distinct findings. Old must be resolved, new must be new.
	fDistinctBase := report.Finding{
		Category:   "sql-injection",
		Severity:   report.SeverityCritical,
		Confidence: report.ConfidenceHigh,
		Target:     "https://api.example.com",
		Endpoint:   "/api/v1/users",
		Method:     "POST",
	}
	fDistinctCur := report.Finding{
		Category:   "sql-injection",
		Severity:   report.SeverityCritical,
		Confidence: report.ConfidenceHigh,
		Target:     "https://api.example.com",
		Endpoint:   "/api/v1/orders",
		Method:     "POST",
	}
	correlation.EnsureFindingFingerprint(&fDistinctBase, correlation.TrustPolicyForceRecompute)
	correlation.EnsureFindingFingerprint(&fDistinctCur, correlation.TrustPolicyForceRecompute)

	if fDistinctBase.Fingerprint == fDistinctCur.Fingerprint {
		t.Fatalf("distinct endpoints must have distinct fingerprints")
	}

	optsDistinct := correlation.DefaultComparisonOptions()
	optsDistinct.ScopedTargets = []string{"https://api.example.com"}
	cmpDistinct := correlation.CompareFindingsWithOptions([]report.Finding{fDistinctBase}, []report.Finding{fDistinctCur}, optsDistinct)

	if cmpDistinct.ChangedCount != 0 {
		t.Errorf("CRITICAL SECURITY DEFECT: Distinct endpoints without tracking ID were falsely merged into CHANGED!")
	}
	if cmpDistinct.ResolvedCount != 1 {
		t.Errorf("expected baseline distinct finding to be RESOLVED (1), got %d", cmpDistinct.ResolvedCount)
	}
	if cmpDistinct.NewCount != 1 {
		t.Errorf("expected current distinct finding to be NEW (1), got %d", cmpDistinct.NewCount)
	}
}

func TestDelta_8_ReappearanceRegressionSemantics(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "felix_reappearance_test.db")
	store, err := assessment.NewSQLiteStore(dbPath)
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}
	defer store.Close()

	auth := assessment.NewAdminAuthContext()
	client := &assessment.Client{ID: "client-reapp", Name: "Reappearance Test Client"}
	if err := store.CreateClient(client); err != nil {
		t.Fatalf("create client: %v", err)
	}

	target := &assessment.AssessmentTarget{
		ID:           "tgt-reapp",
		AssessmentID: "asm-reapp",
		TargetURL:    "https://service.corp.internal",
		TargetType:   assessment.TargetWebsite,
		ScopeStatus:  "APPROVED",
	}
	asm := &assessment.Assessment{ID: "asm-reapp", ClientID: client.ID, Name: "Reappearance Assessment", Status: assessment.StatusRunning}
	if err := store.CreateAssessment(asm); err != nil {
		t.Fatalf("create assessment: %v", err)
	}
	if err := store.AddTarget(target); err != nil {
		t.Fatalf("add target: %v", err)
	}

	now := time.Now().UTC()

	// -------------------------------------------------------------------------
	// Scenario 1: Finding in Exec A -> absent in complete Exec B -> reappears in Exec C
	// Must produce REGRESSED: REAPPEARED
	// -------------------------------------------------------------------------
	execA := &assessment.AssessmentExecution{ID: "exec-A", AssessmentID: asm.ID, Status: assessment.StatusCompleted, StartedAt: now}
	_ = store.CreateExecution(execA)
	finding1 := assessment.AssessmentFinding{
		ID:           "fnd-1",
		AssessmentID: asm.ID,
		ExecutionID:  execA.ID,
		TargetID:     target.ID,
		TargetURL:    target.TargetURL,
		Endpoint:     "/api/secret",
		Category:     "secrets-leak",
		Severity:     report.SeverityHigh,
		Title:        "Leaked API Secret Token",
	}
	rf1 := assessment.ToReportFinding(finding1)
	finding1.Fingerprint = correlation.ComputeStableFingerprint(rf1)
	_ = store.SaveFindings([]assessment.AssessmentFinding{finding1})
	snapA := &assessment.AssessmentSnapshot{
		ID:            "snap-A",
		AssessmentID:  asm.ID,
		ExecutionID:   execA.ID,
		ClientID:      client.ID,
		TenantID:      client.ID,
		Status:        assessment.StatusCompleted,
		IsComplete:    true,
		StartedAt:     now,
		CompletedAt:   &now,
		ScopedTargets: []string{target.TargetURL},
	}
	_ = store.CreateSnapshot(snapA, []assessment.AssessmentFinding{finding1}, nil)

	// Exec B: Complete, comparable assessment. Target in scope. Finding 1 is absent!
	completedBTime := now.Add(1 * time.Hour)
	execB := &assessment.AssessmentExecution{ID: "exec-B", AssessmentID: asm.ID, Status: assessment.StatusCompleted, StartedAt: completedBTime, CompletedAt: &completedBTime}
	_ = store.CreateExecution(execB)
	snapB := &assessment.AssessmentSnapshot{
		ID:            "snap-B",
		AssessmentID:  asm.ID,
		ExecutionID:   execB.ID,
		ClientID:      client.ID,
		TenantID:      client.ID,
		Status:        assessment.StatusCompleted,
		IsComplete:    true,
		StartedAt:     completedBTime,
		CompletedAt:   &completedBTime,
		ScopedTargets: []string{target.TargetURL},
	}
	// 0 findings detected in Exec B -> recordFindingLifecycleTx resolves Finding 1
	_ = store.CreateSnapshot(snapB, []assessment.AssessmentFinding{}, nil)

	// Verify lifecycle transitioned to RESOLVED
	flRec, err := store.GetFindingLifecycle(client.ID, "", finding1.Fingerprint, auth)
	if err != nil || flRec.CurrentState != "RESOLVED" {
		t.Fatalf("expected Finding 1 to be RESOLVED after Exec B, got err=%v state=%v", err, flRec)
	}

	// Exec C: Finding 1 is re-detected!
	completedCTime := now.Add(2 * time.Hour)
	execC := &assessment.AssessmentExecution{ID: "exec-C", AssessmentID: asm.ID, Status: assessment.StatusCompleted, StartedAt: completedCTime, CompletedAt: &completedCTime}
	_ = store.CreateExecution(execC)
	finding1Cur := finding1
	finding1Cur.ID = "fnd-1-c"
	finding1Cur.ExecutionID = execC.ID
	_ = store.SaveFindings([]assessment.AssessmentFinding{finding1Cur})

	// Compare Exec B and Exec C
	cmpBC, err := store.CompareExecutionHistory(execB.ID, execC.ID, auth)
	if err != nil {
		t.Fatalf("CompareExecutionHistory B->C failed: %v", err)
	}
	if cmpBC.RegressedCount != 1 {
		t.Errorf("Scenario 1: Expected 1 REGRESSED finding after verified resolution, got %d (new=%d)", cmpBC.RegressedCount, cmpBC.NewCount)
	}
	if len(cmpBC.Items) != 1 || cmpBC.Items[0].Classification != correlation.DeltaRegressed || cmpBC.Items[0].RegressionReason != correlation.RegressionReappeared {
		t.Errorf("Scenario 1: Expected REGRESSED: REAPPEARED, got %+v", cmpBC.Items)
	}

	// -------------------------------------------------------------------------
	// Scenario 2: Finding absent in baseline X and present in current Y, NO prior resolution.
	// Must produce NEW, never REAPPEARED.
	// -------------------------------------------------------------------------
	execX := &assessment.AssessmentExecution{ID: "exec-X", AssessmentID: asm.ID, Status: assessment.StatusCompleted, StartedAt: now.Add(3 * time.Hour)}
	_ = store.CreateExecution(execX)
	// 0 findings in X

	execY := &assessment.AssessmentExecution{ID: "exec-Y", AssessmentID: asm.ID, Status: assessment.StatusCompleted, StartedAt: now.Add(4 * time.Hour)}
	_ = store.CreateExecution(execY)
	finding2 := assessment.AssessmentFinding{
		ID:           "fnd-2-new",
		AssessmentID: asm.ID,
		ExecutionID:  execY.ID,
		TargetID:     target.ID,
		TargetURL:    target.TargetURL,
		Endpoint:     "/api/new-vuln",
		Category:     "ssrf",
		Severity:     report.SeverityCritical,
		Title:        "Brand New SSRF Flaw",
	}
	rf2 := assessment.ToReportFinding(finding2)
	finding2.Fingerprint = correlation.ComputeStableFingerprint(rf2)
	_ = store.SaveFindings([]assessment.AssessmentFinding{finding2})

	cmpXY, err := store.CompareExecutionHistory(execX.ID, execY.ID, auth)
	if err != nil {
		t.Fatalf("CompareExecutionHistory X->Y failed: %v", err)
	}
	if cmpXY.NewCount != 1 {
		t.Errorf("Scenario 2: Expected 1 NEW finding with no prior resolution, got %d", cmpXY.NewCount)
	}
	if cmpXY.RegressedCount != 0 {
		t.Errorf("Scenario 2: Finding without prior resolution was falsely marked REGRESSED (%d)!", cmpXY.RegressedCount)
	}

	// -------------------------------------------------------------------------
	// Scenario 3: Incomplete or failed assessment between two successful assessments.
	// Must NOT establish resolution, and must NOT produce REGRESSED: REAPPEARED.
	// -------------------------------------------------------------------------
	// Run 1: Finding 3 detected
	exec1 := &assessment.AssessmentExecution{ID: "exec-1", AssessmentID: asm.ID, Status: assessment.StatusCompleted, StartedAt: now.Add(5 * time.Hour)}
	_ = store.CreateExecution(exec1)
	finding3 := assessment.AssessmentFinding{
		ID:           "fnd-3",
		AssessmentID: asm.ID,
		ExecutionID:  exec1.ID,
		TargetID:     target.ID,
		TargetURL:    target.TargetURL,
		Endpoint:     "/api/flaw",
		Category:     "xss",
		Severity:     report.SeverityMedium,
		Title:        "Stored XSS",
	}
	rf3 := assessment.ToReportFinding(finding3)
	finding3.Fingerprint = correlation.ComputeStableFingerprint(rf3)
	_ = store.SaveFindings([]assessment.AssessmentFinding{finding3})
	snap1 := &assessment.AssessmentSnapshot{
		ID:            "snap-1",
		AssessmentID:  asm.ID,
		ExecutionID:   exec1.ID,
		ClientID:      client.ID,
		TenantID:      client.ID,
		Status:        assessment.StatusCompleted,
		IsComplete:    true,
		StartedAt:     now.Add(5 * time.Hour),
		CompletedAt:   &now,
		ScopedTargets: []string{target.TargetURL},
	}
	_ = store.CreateSnapshot(snap1, []assessment.AssessmentFinding{finding3}, nil)

	// Run 2: Failed/incomplete run!
	exec2 := &assessment.AssessmentExecution{
		ID:           "exec-2-failed",
		AssessmentID: asm.ID,
		Status:       assessment.StatusFailed,
		StartedAt:    now.Add(6 * time.Hour),
		ErrorMessage: "scanner timeout",
	}
	_ = store.CreateExecution(exec2)
	// Run 2 failed: NO resolution is established!

	// Run 3: Finding 3 detected again
	exec3 := &assessment.AssessmentExecution{ID: "exec-3", AssessmentID: asm.ID, Status: assessment.StatusCompleted, StartedAt: now.Add(7 * time.Hour)}
	_ = store.CreateExecution(exec3)
	finding3Cur := finding3
	finding3Cur.ID = "fnd-3-c"
	finding3Cur.ExecutionID = exec3.ID
	_ = store.SaveFindings([]assessment.AssessmentFinding{finding3Cur})

	// Comparing Failed Run 2 and Run 3: F3 must NOT be classified as REAPPEARED
	cmp23, err := store.CompareExecutionHistory(exec2.ID, exec3.ID, auth)
	if err != nil {
		t.Fatalf("CompareExecutionHistory 2->3 failed: %v", err)
	}
	if cmp23.RegressedCount != 0 {
		t.Errorf("Scenario 3: Incomplete assessment falsely established resolution leading to REGRESSED (%d)!", cmp23.RegressedCount)
	}

	// Comparing Run 1 and Run 3: F3 must be classified as PERSISTENT
	cmp13, err := store.CompareExecutionHistory(exec1.ID, exec3.ID, auth)
	if err != nil {
		t.Fatalf("CompareExecutionHistory 1->3 failed: %v", err)
	}
	if cmp13.PersistentCount != 1 {
		t.Errorf("Scenario 3: Expected 1 PERSISTENT finding between Run 1 and Run 3, got %d", cmp13.PersistentCount)
	}
	if cmp13.RegressedCount != 0 {
		t.Errorf("Scenario 3: Finding was falsely marked REGRESSED between Run 1 and Run 3 (%d)!", cmp13.RegressedCount)
	}
}
