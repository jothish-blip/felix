package test

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"felix/pkg/assessment"
	"felix/pkg/correlation"
	"felix/pkg/report"
)

// Helper to set up a clean, isolated SQLite test store
func setupSummaryTestDB(t *testing.T) (*assessment.SQLiteStore, *assessment.Client, *assessment.Assessment, *assessment.AssessmentTarget, string) {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "test_summary.db")
	store, err := assessment.NewSQLiteStore(dbPath)
	if err != nil {
		t.Fatalf("failed opening test store: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })

	client := &assessment.Client{
		ID:   "client-sum-1",
		Name: "Summary Corp",
	}
	if err := store.CreateClient(client); err != nil {
		t.Fatalf("CreateClient failed: %v", err)
	}

	asm := &assessment.Assessment{
		ID:             "asm-sum-1",
		Ref:            "ASM-SUM-1",
		ClientID:       client.ID,
		Name:           "Summary Test Assessment",
		AssessmentType: "web",
		Status:         assessment.StatusReady,
		ScopeMode:      "same-origin",
	}
	if err := store.CreateAssessment(asm); err != nil {
		t.Fatalf("CreateAssessment failed: %v", err)
	}

	tgt := &assessment.AssessmentTarget{
		ID:           "tgt-sum-1",
		AssessmentID: asm.ID,
		TargetURL:    "https://api.summarycorp.com",
		ScopeStatus:  "APPROVED",
	}
	if err := store.AddTarget(tgt); err != nil {
		t.Fatalf("AddTarget failed: %v", err)
	}

	return store, client, asm, tgt, dbPath
}

// 1. All supported delta classifications produce correct counts
func TestChangeSummary_1_ClassificationCounts_AllSupported(t *testing.T) {
	store, client, asm, tgt, _ := setupSummaryTestDB(t)
	authAdmin := assessment.NewAdminAuthContext()

	// 1. Baseline Execution (Completed)
	now := time.Now().UTC().Add(-2 * time.Hour)
	baseExec := &assessment.AssessmentExecution{
		ID:           "exec-base-1",
		AssessmentID: asm.ID,
		ClientID:     client.ID,
		TenantID:     client.ID,
		Status:       assessment.StatusCompleted,
		StartedAt:    now,
		CompletedAt:  &now,
	}
	if err := store.CreateExecution(baseExec); err != nil {
		t.Fatalf("CreateExecution base failed: %v", err)
	}

	// Baseline findings:
	// - fPersistent (will stay identical)
	// - fResolved (will be absent in current)
	// - fChanged (will decrease severity from HIGH to MEDIUM)
	// - fRegressed (will increase severity from MEDIUM to CRITICAL)
	fPersistent := report.Finding{
		ID:       "bf-persist",
		RuleID:   "API_BOLA",
		Category: "broken-object-level-authorization",
		Severity: report.SeverityHigh,
		Target:   tgt.TargetURL,
		Endpoint: "/api/users/{id}",
		Method:   "GET",
		Evidence: "Persistent vulnerability",
	}
	correlation.EnsureFindingFingerprint(&fPersistent, correlation.TrustPolicyForceRecompute)

	fResolved := report.Finding{
		ID:       "bf-resolved",
		RuleID:   "SECRETS_KEY",
		Category: "hardcoded-credentials",
		Severity: report.SeverityCritical,
		Target:   tgt.TargetURL,
		Endpoint: "/config.json",
		Method:   "GET",
		Evidence: "Secret API token exposed",
	}
	correlation.EnsureFindingFingerprint(&fResolved, correlation.TrustPolicyForceRecompute)

	fChangedBase := report.Finding{
		ID:       "bf-changed",
		RuleID:   "CORS_MISCONFIG",
		Category: "cors-misconfiguration",
		Severity: report.SeverityHigh, // HIGH in baseline
		Target:   tgt.TargetURL,
		Endpoint: "/v1/data",
		Method:   "GET",
		Evidence: "Wildcard origin allowed",
	}
	correlation.EnsureFindingFingerprint(&fChangedBase, correlation.TrustPolicyForceRecompute)

	fRegressedBase := report.Finding{
		ID:       "bf-regressed",
		RuleID:   "SQL_INJECTION",
		Category: "sql-injection",
		Severity: report.SeverityMedium, // MEDIUM in baseline
		Target:   tgt.TargetURL,
		Endpoint: "/items",
		Method:   "GET",
		Evidence: "Potential SQL injection",
	}
	correlation.EnsureFindingFingerprint(&fRegressedBase, correlation.TrustPolicyForceRecompute)

	// Save baseline findings
	afP := assessment.ToAssessmentFinding(asm.ID, baseExec.ID, tgt.ID, fPersistent)
	afR := assessment.ToAssessmentFinding(asm.ID, baseExec.ID, tgt.ID, fResolved)
	afC := assessment.ToAssessmentFinding(asm.ID, baseExec.ID, tgt.ID, fChangedBase)
	afReg := assessment.ToAssessmentFinding(asm.ID, baseExec.ID, tgt.ID, fRegressedBase)
	if err := store.SaveFindings([]assessment.AssessmentFinding{afP, afR, afC, afReg}); err != nil {
		t.Fatalf("SaveFindings base failed: %v", err)
	}

	// 2. Comparison Execution (Completed)
	currTime := time.Now().UTC()
	currExec := &assessment.AssessmentExecution{
		ID:           "exec-curr-1",
		AssessmentID: asm.ID,
		ClientID:     client.ID,
		TenantID:     client.ID,
		Status:       assessment.StatusCompleted,
		StartedAt:    currTime,
		CompletedAt:  &currTime,
	}
	if err := store.CreateExecution(currExec); err != nil {
		t.Fatalf("CreateExecution curr failed: %v", err)
	}

	// Current findings:
	// - fPersistent (same)
	// - fNew (new finding)
	// - fChangedCurr (severity decreased to MEDIUM -> CHANGED)
	// - fRegressedCurr (severity increased to CRITICAL -> REGRESSED)
	fNew := report.Finding{
		ID:       "cf-new",
		RuleID:   "AUTH_BYPASS",
		Category: "authentication",
		Severity: report.SeverityCritical,
		Target:   tgt.TargetURL,
		Endpoint: "/search",
		Method:   "GET",
		Evidence: "Auth bypass observed",
	}
	correlation.EnsureFindingFingerprint(&fNew, correlation.TrustPolicyForceRecompute)

	fChangedCurr := fChangedBase
	fChangedCurr.ID = "cf-changed"
	fChangedCurr.Severity = report.SeverityMedium // Decreased severity

	fRegressedCurr := fRegressedBase
	fRegressedCurr.ID = "cf-regressed"
	fRegressedCurr.Severity = report.SeverityCritical // Worsened severity

	afP2 := assessment.ToAssessmentFinding(asm.ID, currExec.ID, tgt.ID, fPersistent)
	afN := assessment.ToAssessmentFinding(asm.ID, currExec.ID, tgt.ID, fNew)
	afC2 := assessment.ToAssessmentFinding(asm.ID, currExec.ID, tgt.ID, fChangedCurr)
	afReg2 := assessment.ToAssessmentFinding(asm.ID, currExec.ID, tgt.ID, fRegressedCurr)
	if err := store.SaveFindings([]assessment.AssessmentFinding{afP2, afN, afC2, afReg2}); err != nil {
		t.Fatalf("SaveFindings curr failed: %v", err)
	}

	// 3. Compute Change Summary
	summary, err := store.GetAssessmentChangeSummary(asm.ID, baseExec.ID, currExec.ID, authAdmin)
	if err != nil {
		t.Fatalf("GetAssessmentChangeSummary failed: %v", err)
	}

	// Verify all counts
	if summary.Counts.New != 1 {
		t.Errorf("expected 1 NEW finding, got %d", summary.Counts.New)
	}
	if summary.Counts.Resolved != 1 {
		t.Errorf("expected 1 RESOLVED finding, got %d", summary.Counts.Resolved)
	}
	if summary.Counts.Persistent != 1 {
		t.Errorf("expected 1 PERSISTENT finding, got %d", summary.Counts.Persistent)
	}
	if summary.Counts.Regressed != 1 {
		t.Errorf("expected 1 REGRESSED finding, got %d", summary.Counts.Regressed)
	}
	if summary.Counts.Changed != 1 {
		t.Errorf("expected 1 CHANGED finding, got %d", summary.Counts.Changed)
	}
	if summary.Counts.TotalBaseline != 4 {
		t.Errorf("expected 4 baseline findings, got %d", summary.Counts.TotalBaseline)
	}
	if summary.Counts.TotalComparison != 4 {
		t.Errorf("expected 4 comparison findings, got %d", summary.Counts.TotalComparison)
	}
	if !summary.IsReliable {
		t.Errorf("expected comparison to be reliable, got false (reason: %s)", summary.ReliabilityReason)
	}
}

// 2. Summary counts agree with the returned finding lists
func TestChangeSummary_2_CountsAgreeWithFindingLists(t *testing.T) {
	store, client, asm, tgt, _ := setupSummaryTestDB(t)
	authAdmin := assessment.NewAdminAuthContext()

	baseExec := &assessment.AssessmentExecution{
		ID:           "exec-agree-b",
		AssessmentID: asm.ID,
		ClientID:     client.ID,
		TenantID:     client.ID,
		Status:       assessment.StatusCompleted,
		StartedAt:    time.Now().UTC().Add(-1 * time.Hour),
	}
	_ = store.CreateExecution(baseExec)

	currExec := &assessment.AssessmentExecution{
		ID:           "exec-agree-c",
		AssessmentID: asm.ID,
		ClientID:     client.ID,
		TenantID:     client.ID,
		Status:       assessment.StatusCompleted,
		StartedAt:    time.Now().UTC(),
	}
	_ = store.CreateExecution(currExec)

	// Save 3 new findings in current
	for i := 1; i <= 3; i++ {
		rf := report.Finding{
			ID:       fmt.Sprintf("cf-%d", i),
			RuleID:   "API_RULE",
			Category: "api-security",
			Severity: report.SeverityHigh,
			Target:   tgt.TargetURL,
			Endpoint: fmt.Sprintf("/api/endpoint-%d", i),
			Method:   "GET",
		}
		correlation.EnsureFindingFingerprint(&rf, correlation.TrustPolicyForceRecompute)
		_ = store.SaveFindings([]assessment.AssessmentFinding{assessment.ToAssessmentFinding(asm.ID, currExec.ID, tgt.ID, rf)})
	}

	summary, err := store.GetAssessmentChangeSummary(asm.ID, baseExec.ID, currExec.ID, authAdmin)
	if err != nil {
		t.Fatalf("GetAssessmentChangeSummary failed: %v", err)
	}

	// Verify counts agree with items list
	var (
		newCt, resCt, persCt, regCt, chgCt, unvCt int
	)
	for _, it := range summary.ImportantChanges {
		switch it.Classification {
		case "NEW":
			newCt++
		case "RESOLVED":
			resCt++
		case "PERSISTENT":
			persCt++
		case "REGRESSED":
			regCt++
		case "CHANGED":
			chgCt++
		case "UNVERIFIED":
			unvCt++
		}
	}

	if summary.Counts.New != newCt {
		t.Errorf("New count mismatch: count=%d, list=%d", summary.Counts.New, newCt)
	}
	if summary.Counts.Resolved != resCt {
		t.Errorf("Resolved count mismatch: count=%d, list=%d", summary.Counts.Resolved, resCt)
	}
	if summary.Counts.Persistent != persCt {
		t.Errorf("Persistent count mismatch: count=%d, list=%d", summary.Counts.Persistent, persCt)
	}
	if summary.Counts.Regressed != regCt {
		t.Errorf("Regressed count mismatch: count=%d, list=%d", summary.Counts.Regressed, regCt)
	}
	if summary.Counts.Changed != chgCt {
		t.Errorf("Changed count mismatch: count=%d, list=%d", summary.Counts.Changed, chgCt)
	}
	if summary.Counts.Unverified != unvCt {
		t.Errorf("Unverified count mismatch: count=%d, list=%d", summary.Counts.Unverified, unvCt)
	}
	if len(summary.ImportantChanges) != (newCt + resCt + persCt + regCt + chgCt + unvCt) {
		t.Errorf("Total items does not equal sum of classifications")
	}
}

// 3. New findings receive evidence-backed explanations
func TestChangeSummary_3_NewFindings_EvidenceBackedExplanations(t *testing.T) {
	store, client, asm, tgt, _ := setupSummaryTestDB(t)
	authAdmin := assessment.NewAdminAuthContext()

	baseExec := &assessment.AssessmentExecution{
		ID:           "exec-exp-b",
		AssessmentID: asm.ID,
		ClientID:     client.ID,
		TenantID:     client.ID,
		Status:       assessment.StatusCompleted,
		StartedAt:    time.Now().UTC().Add(-1 * time.Hour),
	}
	_ = store.CreateExecution(baseExec)

	currExec := &assessment.AssessmentExecution{
		ID:           "exec-exp-c",
		AssessmentID: asm.ID,
		ClientID:     client.ID,
		TenantID:     client.ID,
		Status:       assessment.StatusCompleted,
		StartedAt:    time.Now().UTC(),
	}
	_ = store.CreateExecution(currExec)

	rf := report.Finding{
		ID:       "cf-ssrf",
		RuleID:   "WEB_SSRF",
		Title:    "Server-Side Request Forgery",
		Category: "ssrf",
		Severity: report.SeverityCritical,
		Target:   tgt.TargetURL,
		Endpoint: "/webhook/test",
		Method:   "POST",
	}
	correlation.EnsureFindingFingerprint(&rf, correlation.TrustPolicyForceRecompute)
	_ = store.SaveFindings([]assessment.AssessmentFinding{assessment.ToAssessmentFinding(asm.ID, currExec.ID, tgt.ID, rf)})

	summary, err := store.GetAssessmentChangeSummary(asm.ID, baseExec.ID, currExec.ID, authAdmin)
	if err != nil {
		t.Fatalf("GetAssessmentChangeSummary failed: %v", err)
	}

	// Verify narrative contains evidence-backed statement
	foundNarrative := false
	for _, n := range summary.Narrative {
		if strings.Contains(n, "1 new finding detected") {
			foundNarrative = true
			break
		}
	}
	if !foundNarrative {
		t.Errorf("expected narrative mentioning 1 new finding, got: %v", summary.Narrative)
	}

	if len(summary.ImportantChanges) != 1 {
		t.Fatalf("expected 1 important change item, got %d", len(summary.ImportantChanges))
	}
	item := summary.ImportantChanges[0]
	if !strings.Contains(item.Explanation, "New") && !strings.Contains(item.Explanation, "CRITICAL") {
		t.Errorf("unexpected explanation: %s", item.Explanation)
	}
}

// 4. Verified resolutions are reported correctly
func TestChangeSummary_4_VerifiedResolutions(t *testing.T) {
	store, client, asm, tgt, _ := setupSummaryTestDB(t)
	authAdmin := assessment.NewAdminAuthContext()

	baseExec := &assessment.AssessmentExecution{
		ID:           "exec-res-b",
		AssessmentID: asm.ID,
		ClientID:     client.ID,
		TenantID:     client.ID,
		Status:       assessment.StatusCompleted,
		StartedAt:    time.Now().UTC().Add(-2 * time.Hour),
	}
	_ = store.CreateExecution(baseExec)

	rf := report.Finding{
		ID:       "bf-xss",
		RuleID:   "WEB_XSS",
		Title:    "Reflected Cross-Site Scripting",
		Category: "cross-site-scripting",
		Severity: report.SeverityHigh,
		Target:   tgt.TargetURL,
		Endpoint: "/profile",
		Method:   "GET",
	}
	correlation.EnsureFindingFingerprint(&rf, correlation.TrustPolicyForceRecompute)
	_ = store.SaveFindings([]assessment.AssessmentFinding{assessment.ToAssessmentFinding(asm.ID, baseExec.ID, tgt.ID, rf)})

	// Completed comparison run without this finding
	currExec := &assessment.AssessmentExecution{
		ID:           "exec-res-c",
		AssessmentID: asm.ID,
		ClientID:     client.ID,
		TenantID:     client.ID,
		Status:       assessment.StatusCompleted,
		StartedAt:    time.Now().UTC(),
	}
	_ = store.CreateExecution(currExec)

	summary, err := store.GetAssessmentChangeSummary(asm.ID, baseExec.ID, currExec.ID, authAdmin)
	if err != nil {
		t.Fatalf("GetAssessmentChangeSummary failed: %v", err)
	}

	if summary.Counts.Resolved != 1 {
		t.Fatalf("expected 1 resolved finding, got %d", summary.Counts.Resolved)
	}

	foundNarrative := false
	for _, n := range summary.Narrative {
		if strings.Contains(n, "verified as resolved") {
			foundNarrative = true
			break
		}
	}
	if !foundNarrative {
		t.Errorf("expected narrative with 'verified as resolved', got: %v", summary.Narrative)
	}
}

// 5. Persistent findings are not described as new or resolved
func TestChangeSummary_5_PersistentFindingsNotDescribedAsNewOrResolved(t *testing.T) {
	store, client, asm, tgt, _ := setupSummaryTestDB(t)
	authAdmin := assessment.NewAdminAuthContext()

	baseExec := &assessment.AssessmentExecution{
		ID:           "exec-pers-b",
		AssessmentID: asm.ID,
		ClientID:     client.ID,
		TenantID:     client.ID,
		Status:       assessment.StatusCompleted,
		StartedAt:    time.Now().UTC().Add(-1 * time.Hour),
	}
	_ = store.CreateExecution(baseExec)

	currExec := &assessment.AssessmentExecution{
		ID:           "exec-pers-c",
		AssessmentID: asm.ID,
		ClientID:     client.ID,
		TenantID:     client.ID,
		Status:       assessment.StatusCompleted,
		StartedAt:    time.Now().UTC(),
	}
	_ = store.CreateExecution(currExec)

	rf := report.Finding{
		ID:       "bf-persistent-id",
		RuleID:   "SECRETS_TOKEN",
		Title:    "Hardcoded Token",
		Category: "secrets",
		Severity: report.SeverityMedium,
		Target:   tgt.TargetURL,
		Endpoint: "/auth.js",
		Method:   "GET",
	}
	correlation.EnsureFindingFingerprint(&rf, correlation.TrustPolicyForceRecompute)

	_ = store.SaveFindings([]assessment.AssessmentFinding{assessment.ToAssessmentFinding(asm.ID, baseExec.ID, tgt.ID, rf)})
	_ = store.SaveFindings([]assessment.AssessmentFinding{assessment.ToAssessmentFinding(asm.ID, currExec.ID, tgt.ID, rf)})

	summary, err := store.GetAssessmentChangeSummary(asm.ID, baseExec.ID, currExec.ID, authAdmin)
	if err != nil {
		t.Fatalf("GetAssessmentChangeSummary failed: %v", err)
	}

	if summary.Counts.Persistent != 1 {
		t.Errorf("expected Persistent=1, got %d", summary.Counts.Persistent)
	}
	if summary.Counts.New != 0 {
		t.Errorf("expected New=0, got %d", summary.Counts.New)
	}
	if summary.Counts.Resolved != 0 {
		t.Errorf("expected Resolved=0, got %d", summary.Counts.Resolved)
	}

	foundNarrative := false
	for _, n := range summary.Narrative {
		if strings.Contains(n, "remain present") || strings.Contains(n, "remain unchanged") {
			foundNarrative = true
			break
		}
	}
	if !foundNarrative {
		t.Errorf("expected narrative describing persistent findings, got: %v", summary.Narrative)
	}
}

// 6. Regressed findings are distinguished from ordinary new findings
func TestChangeSummary_6_RegressedFindingsDistinguishedFromNew(t *testing.T) {
	store, client, asm, tgt, _ := setupSummaryTestDB(t)
	authAdmin := assessment.NewAdminAuthContext()
	now := time.Now().UTC()

	// Exec A: Finding 1 present
	execA := &assessment.AssessmentExecution{
		ID:           "exec-snap-A",
		AssessmentID: asm.ID,
		ClientID:     client.ID,
		TenantID:     client.ID,
		Status:       assessment.StatusCompleted,
		StartedAt:    now,
		CompletedAt:  &now,
	}
	if err := store.CreateExecution(execA); err != nil {
		t.Fatalf("CreateExecution A failed: %v", err)
	}

	finding1 := assessment.AssessmentFinding{
		ID:           "fnd-reappear-1",
		AssessmentID: asm.ID,
		ExecutionID:  execA.ID,
		TargetID:     tgt.ID,
		TargetURL:    tgt.TargetURL,
		Endpoint:     "/api/order/{id}",
		Category:     "broken-object-level-authorization",
		Severity:     report.SeverityHigh,
		Title:        "BOLA in /api/order/{id}",
	}
	rf1 := assessment.ToReportFinding(finding1)
	finding1.Fingerprint = correlation.ComputeStableFingerprint(rf1)
	if err := store.SaveFindings([]assessment.AssessmentFinding{finding1}); err != nil {
		t.Fatalf("SaveFindings A failed: %v", err)
	}

	snapA := &assessment.AssessmentSnapshot{
		ID:            "snap-reappear-A",
		AssessmentID:  asm.ID,
		ExecutionID:   execA.ID,
		ClientID:      client.ID,
		TenantID:      client.ID,
		Status:        assessment.StatusCompleted,
		IsComplete:    true,
		StartedAt:     now,
		CompletedAt:   &now,
		ScopedTargets: []string{tgt.TargetURL},
	}
	if err := store.CreateSnapshot(snapA, []assessment.AssessmentFinding{finding1}, nil); err != nil {
		t.Fatalf("CreateSnapshot A failed: %v", err)
	}

	// Exec B & Snap B: Complete, Finding 1 is absent -> automatically transitioned to RESOLVED!
	completedBTime := now.Add(1 * time.Hour)
	execB := &assessment.AssessmentExecution{
		ID:           "exec-snap-B",
		AssessmentID: asm.ID,
		ClientID:     client.ID,
		TenantID:     client.ID,
		Status:       assessment.StatusCompleted,
		StartedAt:    completedBTime,
		CompletedAt:  &completedBTime,
		SnapshotID:   "snap-reappear-B",
	}
	if err := store.CreateExecution(execB); err != nil {
		t.Fatalf("CreateExecution B failed: %v", err)
	}

	snapB := &assessment.AssessmentSnapshot{
		ID:            "snap-reappear-B",
		AssessmentID:  asm.ID,
		ExecutionID:   execB.ID,
		ClientID:      client.ID,
		TenantID:      client.ID,
		Status:        assessment.StatusCompleted,
		IsComplete:    true,
		StartedAt:     completedBTime,
		CompletedAt:   &completedBTime,
		ScopedTargets: []string{tgt.TargetURL},
	}
	if err := store.CreateSnapshot(snapB, []assessment.AssessmentFinding{}, nil); err != nil {
		t.Fatalf("CreateSnapshot B failed: %v", err)
	}

	// Exec C: Finding 1 re-detected!
	completedCTime := now.Add(2 * time.Hour)
	execC := &assessment.AssessmentExecution{
		ID:           "exec-snap-C",
		AssessmentID: asm.ID,
		ClientID:     client.ID,
		TenantID:     client.ID,
		Status:       assessment.StatusCompleted,
		StartedAt:    completedCTime,
		CompletedAt:  &completedCTime,
	}
	if err := store.CreateExecution(execC); err != nil {
		t.Fatalf("CreateExecution C failed: %v", err)
	}

	finding1Cur := finding1
	finding1Cur.ID = "fnd-reappear-C"
	finding1Cur.ExecutionID = execC.ID
	if err := store.SaveFindings([]assessment.AssessmentFinding{finding1Cur}); err != nil {
		t.Fatalf("SaveFindings C failed: %v", err)
	}

	// Get change summary between Exec B and Exec C
	summary, err := store.GetAssessmentChangeSummary(asm.ID, execB.ID, execC.ID, authAdmin)
	if err != nil {
		t.Fatalf("GetAssessmentChangeSummary failed: %v", err)
	}

	if summary.Counts.Regressed != 1 {
		t.Errorf("expected Regressed=1, got %d (new=%d)", summary.Counts.Regressed, summary.Counts.New)
	}
	if summary.Counts.New != 0 {
		t.Errorf("expected New=0, got %d", summary.Counts.New)
	}

	foundNarrative := false
	for _, n := range summary.Narrative {
		if strings.Contains(n, "reappeared after verified earlier resolution") {
			foundNarrative = true
			break
		}
	}
	if !foundNarrative {
		t.Errorf("expected narrative mentioning reappearance, got: %v", summary.Narrative)
	}
}

// 7. Materially changed findings retain their existing identity and classification semantics
func TestChangeSummary_7_MateriallyChangedFindingsSemantics(t *testing.T) {
	store, client, asm, tgt, _ := setupSummaryTestDB(t)
	authAdmin := assessment.NewAdminAuthContext()

	baseExec := &assessment.AssessmentExecution{
		ID:           "exec-chg-b",
		AssessmentID: asm.ID,
		ClientID:     client.ID,
		TenantID:     client.ID,
		Status:       assessment.StatusCompleted,
		StartedAt:    time.Now().UTC().Add(-1 * time.Hour),
	}
	_ = store.CreateExecution(baseExec)

	currExec := &assessment.AssessmentExecution{
		ID:           "exec-chg-c",
		AssessmentID: asm.ID,
		ClientID:     client.ID,
		TenantID:     client.ID,
		Status:       assessment.StatusCompleted,
		StartedAt:    time.Now().UTC(),
	}
	_ = store.CreateExecution(currExec)

	fBase := report.Finding{
		ID:         "f-endpoint-1",
		RuleID:     "SECRETS_TOKEN",
		Title:      "API Key Exposure",
		Category:   "secrets",
		Severity:   report.SeverityHigh, // High in baseline
		Confidence: report.ConfidenceHigh,
		Target:     tgt.TargetURL,
		Endpoint:   "/v1/keys",
		Method:     "GET",
	}
	correlation.EnsureFindingFingerprint(&fBase, correlation.TrustPolicyForceRecompute)

	fCurr := fBase
	fCurr.ID = "f-endpoint-2"
	fCurr.Severity = report.SeverityMedium // Decreased severity -> DeltaChanged

	_ = store.SaveFindings([]assessment.AssessmentFinding{assessment.ToAssessmentFinding(asm.ID, baseExec.ID, tgt.ID, fBase)})
	_ = store.SaveFindings([]assessment.AssessmentFinding{assessment.ToAssessmentFinding(asm.ID, currExec.ID, tgt.ID, fCurr)})

	summary, err := store.GetAssessmentChangeSummary(asm.ID, baseExec.ID, currExec.ID, authAdmin)
	if err != nil {
		t.Fatalf("GetAssessmentChangeSummary failed: %v", err)
	}

	if summary.Counts.Changed != 1 {
		t.Errorf("expected Changed=1, got %d", summary.Counts.Changed)
	}
	if summary.Counts.Persistent != 0 {
		t.Errorf("expected Persistent=0, got %d", summary.Counts.Persistent)
	}

	foundNarrative := false
	for _, n := range summary.Narrative {
		if strings.Contains(n, "changed materially compared with the baseline") {
			foundNarrative = true
			break
		}
	}
	if !foundNarrative {
		t.Errorf("expected narrative mentioning material change, got: %v", summary.Narrative)
	}
}

// 8. Incomplete assessments never cause false resolution claims
func TestChangeSummary_8_IncompleteAssessments_NoFalseResolutions(t *testing.T) {
	store, client, asm, tgt, _ := setupSummaryTestDB(t)
	authAdmin := assessment.NewAdminAuthContext()

	baseExec := &assessment.AssessmentExecution{
		ID:           "exec-incomp-b",
		AssessmentID: asm.ID,
		ClientID:     client.ID,
		TenantID:     client.ID,
		Status:       assessment.StatusCompleted,
		StartedAt:    time.Now().UTC().Add(-2 * time.Hour),
	}
	_ = store.CreateExecution(baseExec)

	rf := report.Finding{
		ID:       "bf-critical-vuln",
		RuleID:   "WEB_RCE",
		Title:    "Remote Code Execution",
		Category: "command-injection",
		Severity: report.SeverityCritical,
		Target:   tgt.TargetURL,
		Endpoint: "/exec",
		Method:   "POST",
	}
	correlation.EnsureFindingFingerprint(&rf, correlation.TrustPolicyForceRecompute)
	_ = store.SaveFindings([]assessment.AssessmentFinding{assessment.ToAssessmentFinding(asm.ID, baseExec.ID, tgt.ID, rf)})

	// Current run CANCELLED
	currExec := &assessment.AssessmentExecution{
		ID:           "exec-incomp-c",
		AssessmentID: asm.ID,
		ClientID:     client.ID,
		TenantID:     client.ID,
		Status:       assessment.StatusCancelled, // Cancelled / incomplete
		StartedAt:    time.Now().UTC(),
	}
	_ = store.CreateExecution(currExec)

	summary, err := store.GetAssessmentChangeSummary(asm.ID, baseExec.ID, currExec.ID, authAdmin)
	if err != nil {
		t.Fatalf("GetAssessmentChangeSummary failed: %v", err)
	}

	// MUST NOT report finding as RESOLVED!
	if summary.Counts.Resolved != 0 {
		t.Errorf("FALSE RESOLUTION DEFECT: expected Resolved=0 on cancelled run, got %d", summary.Counts.Resolved)
	}
	if summary.Counts.Unverified != 1 {
		t.Errorf("expected Unverified=1 on cancelled run, got %d", summary.Counts.Unverified)
	}
	if summary.IsReliable {
		t.Errorf("expected IsReliable=false on cancelled run")
	}

	foundNarrative := false
	for _, n := range summary.Narrative {
		if strings.Contains(n, "could not be confirmed as resolved because the new assessment was incomplete") {
			foundNarrative = true
			break
		}
	}
	if !foundNarrative {
		t.Errorf("expected narrative explaining incomplete uncertainty, got: %v", summary.Narrative)
	}
}

// 9. Failed, cancelled, interrupted executions handled safely
func TestChangeSummary_9_FailedCancelledInterruptedExecutions(t *testing.T) {
	store, client, asm, tgt, _ := setupSummaryTestDB(t)
	authAdmin := assessment.NewAdminAuthContext()

	baseExec := &assessment.AssessmentExecution{
		ID:           "exec-status-b",
		AssessmentID: asm.ID,
		ClientID:     client.ID,
		TenantID:     client.ID,
		Status:       assessment.StatusCompleted,
		StartedAt:    time.Now().UTC().Add(-2 * time.Hour),
	}
	_ = store.CreateExecution(baseExec)

	rf := report.Finding{
		ID:       "bf-status-vuln",
		RuleID:   "API_BFLA",
		Category: "broken-function-level-authorization",
		Severity: report.SeverityHigh,
		Target:   tgt.TargetURL,
		Endpoint: "/admin/delete",
		Method:   "DELETE",
	}
	correlation.EnsureFindingFingerprint(&rf, correlation.TrustPolicyForceRecompute)
	_ = store.SaveFindings([]assessment.AssessmentFinding{assessment.ToAssessmentFinding(asm.ID, baseExec.ID, tgt.ID, rf)})

	statuses := []assessment.AssessmentStatus{
		assessment.StatusFailed,
		assessment.StatusCancelled,
		assessment.StatusInterrupted,
	}

	for _, st := range statuses {
		curExec := &assessment.AssessmentExecution{
			ID:           fmt.Sprintf("exec-status-%s", st),
			AssessmentID: asm.ID,
			ClientID:     client.ID,
			TenantID:     client.ID,
			Status:       st,
			StartedAt:    time.Now().UTC(),
		}
		_ = store.CreateExecution(curExec)

		summary, err := store.GetAssessmentChangeSummary(asm.ID, baseExec.ID, curExec.ID, authAdmin)
		if err != nil {
			t.Fatalf("status %s failed: %v", st, err)
		}
		if summary.IsReliable {
			t.Errorf("status %s: expected IsReliable=false", st)
		}
		if summary.Counts.Resolved != 0 {
			t.Errorf("status %s: expected Resolved=0, got %d", st, summary.Counts.Resolved)
		}
		if summary.Counts.Unverified != 1 {
			t.Errorf("status %s: expected Unverified=1, got %d", st, summary.Counts.Unverified)
		}
	}
}

// 10. Missing baselines produce a clear error or explicit incomplete state
func TestChangeSummary_10_MissingBaselines(t *testing.T) {
	store, client, asm, tgt, _ := setupSummaryTestDB(t)
	authAdmin := assessment.NewAdminAuthContext()

	// Initial execution: zero prior baseline executions exist
	currExec := &assessment.AssessmentExecution{
		ID:           "exec-initial-1",
		AssessmentID: asm.ID,
		ClientID:     client.ID,
		TenantID:     client.ID,
		Status:       assessment.StatusCompleted,
		StartedAt:    time.Now().UTC(),
	}
	_ = store.CreateExecution(currExec)

	rf := report.Finding{
		ID:       "cf-init",
		RuleID:   "WEB_CSRF",
		Category: "csrf",
		Severity: report.SeverityMedium,
		Target:   tgt.TargetURL,
		Endpoint: "/form",
		Method:   "POST",
	}
	correlation.EnsureFindingFingerprint(&rf, correlation.TrustPolicyForceRecompute)
	_ = store.SaveFindings([]assessment.AssessmentFinding{assessment.ToAssessmentFinding(asm.ID, currExec.ID, tgt.ID, rf)})

	// 10a. Automatic baseline with no prior executions returns initial baseline state
	summary, err := store.GetAssessmentChangeSummary(asm.ID, "", currExec.ID, authAdmin)
	if err != nil {
		t.Fatalf("expected successful initial summary, got err: %v", err)
	}
	if summary.BaselineExecutionID != "" {
		t.Errorf("expected empty baseline execution ID, got %s", summary.BaselineExecutionID)
	}
	if summary.Counts.TotalComparison != 1 {
		t.Errorf("expected 1 comparison finding, got %d", summary.Counts.TotalComparison)
	}

	// 10b. Explicit non-existent baseline returns clear error
	_, err = store.GetAssessmentChangeSummary(asm.ID, "exec-does-not-exist", currExec.ID, authAdmin)
	if err == nil || !strings.Contains(err.Error(), "not found") {
		t.Errorf("expected 'not found' error on non-existent baseline, got: %v", err)
	}
}

// 11. Incompatible assessment scopes are rejected
func TestChangeSummary_11_IncompatibleAssessmentScopes(t *testing.T) {
	store, client, asm1, _, _ := setupSummaryTestDB(t)
	authAdmin := assessment.NewAdminAuthContext()

	// Second assessment with completely disjoint target scope
	asm2 := &assessment.Assessment{
		ID:             "asm-disjoint-2",
		Ref:            "ASM-DISJOINT-2",
		ClientID:       client.ID,
		Name:           "Disjoint Scope Assessment",
		AssessmentType: "web",
		Status:         assessment.StatusReady,
	}
	_ = store.CreateAssessment(asm2)
	_ = store.AddTarget(&assessment.AssessmentTarget{
		ID:           "tgt-disjoint-2",
		AssessmentID: asm2.ID,
		TargetURL:    "https://completely-different-domain.org",
		ScopeStatus:  "APPROVED",
	})

	exec1 := &assessment.AssessmentExecution{
		ID:           "exec-scope-1",
		AssessmentID: asm1.ID,
		ClientID:     client.ID,
		TenantID:     client.ID,
		Status:       assessment.StatusCompleted,
		StartedAt:    time.Now().UTC().Add(-1 * time.Hour),
	}
	_ = store.CreateExecution(exec1)

	exec2 := &assessment.AssessmentExecution{
		ID:           "exec-scope-2",
		AssessmentID: asm2.ID,
		ClientID:     client.ID,
		TenantID:     client.ID,
		Status:       assessment.StatusCompleted,
		StartedAt:    time.Now().UTC(),
	}
	_ = store.CreateExecution(exec2)

	_, err := store.GetAssessmentChangeSummary("", exec1.ID, exec2.ID, authAdmin)
	if err == nil || !strings.Contains(err.Error(), "incompatible assessment scopes") {
		t.Errorf("expected incompatible assessment scopes error, got: %v", err)
	}
}

// 12. Cross-tenant comparisons are prevented
func TestChangeSummary_12_CrossTenantComparisonPrevented(t *testing.T) {
	store, clientA, asmA, _, _ := setupSummaryTestDB(t)
	authAdmin := assessment.NewAdminAuthContext()

	// Client B (Tenant B)
	clientB := &assessment.Client{
		ID:   "client-tenant-b",
		Name: "Tenant B Corp",
	}
	_ = store.CreateClient(clientB)

	asmB := &assessment.Assessment{
		ID:             "asm-tenant-b",
		Ref:            "ASM-TENANT-B",
		ClientID:       clientB.ID,
		Name:           "Tenant B Assessment",
		AssessmentType: "web",
		Status:         assessment.StatusReady,
	}
	_ = store.CreateAssessment(asmB)

	execA := &assessment.AssessmentExecution{
		ID:           "exec-tenant-a",
		AssessmentID: asmA.ID,
		ClientID:     clientA.ID,
		TenantID:     "tenant-alpha",
		Status:       assessment.StatusCompleted,
		StartedAt:    time.Now().UTC().Add(-1 * time.Hour),
	}
	_ = store.CreateExecution(execA)

	execB := &assessment.AssessmentExecution{
		ID:           "exec-tenant-b",
		AssessmentID: asmB.ID,
		ClientID:     clientB.ID,
		TenantID:     "tenant-beta",
		Status:       assessment.StatusCompleted,
		StartedAt:    time.Now().UTC(),
	}
	_ = store.CreateExecution(execB)

	_, err := store.GetAssessmentChangeSummary("", execA.ID, execB.ID, authAdmin)
	if err == nil || !strings.Contains(err.Error(), "cross-tenant comparison denied") {
		t.Errorf("expected cross-tenant denial error, got: %v", err)
	}
}

// 13. Severity ordering is consistent with existing severity conventions
func TestChangeSummary_13_SeverityOrdering_ConsistentWithConventions(t *testing.T) {
	store, client, asm, tgt, _ := setupSummaryTestDB(t)
	authAdmin := assessment.NewAdminAuthContext()

	baseExec := &assessment.AssessmentExecution{
		ID:           "exec-ord-b",
		AssessmentID: asm.ID,
		ClientID:     client.ID,
		TenantID:     client.ID,
		Status:       assessment.StatusCompleted,
		StartedAt:    time.Now().UTC().Add(-1 * time.Hour),
	}
	_ = store.CreateExecution(baseExec)

	currExec := &assessment.AssessmentExecution{
		ID:           "exec-ord-c",
		AssessmentID: asm.ID,
		ClientID:     client.ID,
		TenantID:     client.ID,
		Status:       assessment.StatusCompleted,
		StartedAt:    time.Now().UTC(),
	}
	_ = store.CreateExecution(currExec)

	sevs := []string{
		report.SeverityInfo,
		report.SeverityLow,
		report.SeverityCritical,
		report.SeverityMedium,
		report.SeverityHigh,
	}

	for i, s := range sevs {
		rf := report.Finding{
			ID:       fmt.Sprintf("cf-sev-%d", i),
			RuleID:   fmt.Sprintf("RULE_%s", s),
			Title:    fmt.Sprintf("Title %s", s),
			Category: "web",
			Severity: s,
			Target:   tgt.TargetURL,
			Endpoint: fmt.Sprintf("/endpoint/%s", s),
			Method:   "GET",
		}
		correlation.EnsureFindingFingerprint(&rf, correlation.TrustPolicyForceRecompute)
		_ = store.SaveFindings([]assessment.AssessmentFinding{assessment.ToAssessmentFinding(asm.ID, currExec.ID, tgt.ID, rf)})
	}

	summary, err := store.GetAssessmentChangeSummary(asm.ID, baseExec.ID, currExec.ID, authAdmin)
	if err != nil {
		t.Fatalf("GetAssessmentChangeSummary failed: %v", err)
	}

	if len(summary.ImportantChanges) != 5 {
		t.Fatalf("expected 5 items, got %d", len(summary.ImportantChanges))
	}

	// Verify order: CRITICAL > HIGH > MEDIUM > LOW > INFO
	expectedOrder := []string{
		report.SeverityCritical,
		report.SeverityHigh,
		report.SeverityMedium,
		report.SeverityLow,
		report.SeverityInfo,
	}

	for i, expected := range expectedOrder {
		actual := summary.ImportantChanges[i].Severity
		if actual != expected {
			t.Errorf("item %d: expected severity %s, got %s", i, expected, actual)
		}
	}
}

// 14. Empty comparisons produce sensible output
func TestChangeSummary_14_EmptyComparisons(t *testing.T) {
	store, client, asm, _, _ := setupSummaryTestDB(t)
	authAdmin := assessment.NewAdminAuthContext()

	baseExec := &assessment.AssessmentExecution{
		ID:           "exec-empty-b",
		AssessmentID: asm.ID,
		ClientID:     client.ID,
		TenantID:     client.ID,
		Status:       assessment.StatusCompleted,
		StartedAt:    time.Now().UTC().Add(-1 * time.Hour),
	}
	_ = store.CreateExecution(baseExec)

	currExec := &assessment.AssessmentExecution{
		ID:           "exec-empty-c",
		AssessmentID: asm.ID,
		ClientID:     client.ID,
		TenantID:     client.ID,
		Status:       assessment.StatusCompleted,
		StartedAt:    time.Now().UTC(),
	}
	_ = store.CreateExecution(currExec)

	summary, err := store.GetAssessmentChangeSummary(asm.ID, baseExec.ID, currExec.ID, authAdmin)
	if err != nil {
		t.Fatalf("GetAssessmentChangeSummary failed: %v", err)
	}

	if summary.Counts.TotalBaseline != 0 || summary.Counts.TotalComparison != 0 {
		t.Errorf("expected 0 totals, got base=%d comp=%d", summary.Counts.TotalBaseline, summary.Counts.TotalComparison)
	}
	if len(summary.ImportantChanges) != 0 {
		t.Errorf("expected 0 important changes, got %d", len(summary.ImportantChanges))
	}

	text := summary.FormatText()
	if !strings.Contains(text, "FELIX ASSESSMENT CHANGE SUMMARY") {
		t.Errorf("expected formatted text, got: %s", text)
	}
}

// 15. Large finding sets are handled without unnecessary repeated queries
func TestChangeSummary_15_LargeFindingSets_Performance(t *testing.T) {
	store, client, asm, tgt, _ := setupSummaryTestDB(t)
	authAdmin := assessment.NewAdminAuthContext()

	baseExec := &assessment.AssessmentExecution{
		ID:           "exec-large-b",
		AssessmentID: asm.ID,
		ClientID:     client.ID,
		TenantID:     client.ID,
		Status:       assessment.StatusCompleted,
		StartedAt:    time.Now().UTC().Add(-1 * time.Hour),
	}
	_ = store.CreateExecution(baseExec)

	currExec := &assessment.AssessmentExecution{
		ID:           "exec-large-c",
		AssessmentID: asm.ID,
		ClientID:     client.ID,
		TenantID:     client.ID,
		Status:       assessment.StatusCompleted,
		StartedAt:    time.Now().UTC(),
	}
	_ = store.CreateExecution(currExec)

	const count = 250
	baseBatch := make([]assessment.AssessmentFinding, count)
	currBatch := make([]assessment.AssessmentFinding, count)

	for i := 0; i < count; i++ {
		rf := report.Finding{
			ID:       fmt.Sprintf("f-large-%d", i),
			RuleID:   "API_TEST",
			Category: "api",
			Severity: report.SeverityMedium,
			Target:   tgt.TargetURL,
			Endpoint: fmt.Sprintf("/endpoint/%d", i),
			Method:   "GET",
		}
		correlation.EnsureFindingFingerprint(&rf, correlation.TrustPolicyForceRecompute)
		baseBatch[i] = assessment.ToAssessmentFinding(asm.ID, baseExec.ID, tgt.ID, rf)
		currBatch[i] = assessment.ToAssessmentFinding(asm.ID, currExec.ID, tgt.ID, rf)
	}

	_ = store.SaveFindings(baseBatch)
	_ = store.SaveFindings(currBatch)

	start := time.Now()
	summary, err := store.GetAssessmentChangeSummary(asm.ID, baseExec.ID, currExec.ID, authAdmin)
	duration := time.Since(start)

	if err != nil {
		t.Fatalf("GetAssessmentChangeSummary failed on large set: %v", err)
	}
	if summary.Counts.Persistent != count {
		t.Errorf("expected %d persistent findings, got %d", count, summary.Counts.Persistent)
	}
	t.Logf("Computed change summary for %d findings in %v", count*2, duration)
	if duration > 5*time.Second {
		t.Errorf("performance regression: took %v (expected < 5s)", duration)
	}
}

// 16. CLI text output contains expected summary
func TestChangeSummary_16_CLITextOutput(t *testing.T) {
	store, _, asm, tgt, dbPath := setupSummaryTestDB(t)

	// Build felix binary for CLI execution test
	binPath := filepath.Join(t.TempDir(), "felix_test.exe")
	buildCmd := exec.Command("go", "build", "-o", binPath, "./cmd/felix")
	buildCmd.Dir = ".."
	if out, err := buildCmd.CombinedOutput(); err != nil {
		t.Fatalf("failed building felix for CLI test: %v, out: %s", err, out)
	}

	// Add execution via store
	now := time.Now().UTC()
	execRec := &assessment.AssessmentExecution{
		ID:           "exec-cli-text-1",
		AssessmentID: asm.ID,
		Status:       assessment.StatusCompleted,
		StartedAt:    now,
		CompletedAt:  &now,
	}
	_ = store.CreateExecution(execRec)
	rf := report.Finding{
		ID:       "cf-cli-1",
		RuleID:   "API_BOLA",
		Title:    "BOLA in /users",
		Category: "broken-object-level-authorization",
		Severity: report.SeverityHigh,
		Target:   tgt.TargetURL,
		Endpoint: "/users",
		Method:   "GET",
	}
	correlation.EnsureFindingFingerprint(&rf, correlation.TrustPolicyForceRecompute)
	_ = store.SaveFindings([]assessment.AssessmentFinding{assessment.ToAssessmentFinding(asm.ID, execRec.ID, tgt.ID, rf)})
	_ = store.Close()

	cmd := exec.Command(binPath, "assessment", "summary", "--assessment-id", asm.ID, "--db", dbPath)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("CLI execution failed: %v, out: %s", err, out)
	}

	outStr := string(out)
	if !strings.Contains(outStr, "FELIX ASSESSMENT CHANGE SUMMARY") {
		t.Errorf("expected header in output: %s", outStr)
	}
	if !strings.Contains(outStr, asm.ID) {
		t.Errorf("expected assessment ID in output: %s", outStr)
	}
}

// 17. CLI JSON output is valid, stable, and machine-readable
func TestChangeSummary_17_CLIJSONOutput(t *testing.T) {
	store, _, asm, tgt, dbPath := setupSummaryTestDB(t)

	binPath := filepath.Join(t.TempDir(), "felix_test.exe")
	buildCmd := exec.Command("go", "build", "-o", binPath, "./cmd/felix")
	buildCmd.Dir = ".."
	if out, err := buildCmd.CombinedOutput(); err != nil {
		t.Fatalf("failed building felix for CLI test: %v, out: %s", err, out)
	}
	now := time.Now().UTC()
	execRec := &assessment.AssessmentExecution{
		ID:           "exec-cli-json-1",
		AssessmentID: asm.ID,
		Status:       assessment.StatusCompleted,
		StartedAt:    now,
		CompletedAt:  &now,
	}
	_ = store.CreateExecution(execRec)
	rf := report.Finding{
		ID:       "cf-cli-json",
		RuleID:   "API_BOLA",
		Title:    "BOLA Test",
		Category: "broken-object-level-authorization",
		Severity: report.SeverityHigh,
		Target:   tgt.TargetURL,
		Endpoint: "/users/1",
		Method:   "GET",
	}
	correlation.EnsureFindingFingerprint(&rf, correlation.TrustPolicyForceRecompute)
	_ = store.SaveFindings([]assessment.AssessmentFinding{assessment.ToAssessmentFinding(asm.ID, execRec.ID, tgt.ID, rf)})
	_ = store.Close()

	cmd := exec.Command(binPath, "assessment", "summary", "--assessment-id", asm.ID, "--format", "json", "--db", dbPath)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("CLI json execution failed: %v, out: %s", err, out)
	}

	var parsed report.ChangeSummary
	if err := json.Unmarshal(out, &parsed); err != nil {
		t.Fatalf("failed parsing CLI JSON output: %v, out:\n%s", err, out)
	}

	if parsed.AssessmentID != asm.ID {
		t.Errorf("expected assessment_id %s, got %s", asm.ID, parsed.AssessmentID)
	}
	if parsed.ComparisonExecutionID != execRec.ID {
		t.Errorf("expected comparison_execution_id %s, got %s", execRec.ID, parsed.ComparisonExecutionID)
	}
	if parsed.Counts.TotalComparison != 1 {
		t.Errorf("expected total_comparison=1, got %d", parsed.Counts.TotalComparison)
	}
}

// 18. CLI errors and exit codes follow existing conventions
func TestChangeSummary_18_CLIErrorsAndExitCodes(t *testing.T) {
	_, _, _, _, dbPath := setupSummaryTestDB(t)

	binPath := filepath.Join(t.TempDir(), "felix_test.exe")
	buildCmd := exec.Command("go", "build", "-o", binPath, "./cmd/felix")
	buildCmd.Dir = ".."
	if out, err := buildCmd.CombinedOutput(); err != nil {
		t.Fatalf("failed building felix for CLI test: %v, out: %s", err, out)
	}

	// 18a. Missing required arguments: exit code 1
	cmd := exec.Command(binPath, "assessment", "summary", "--db", dbPath)
	if err := cmd.Run(); err == nil {
		t.Errorf("expected non-zero exit code when missing arguments")
	}

	// 18b. Help flag: exit code 0
	cmdHelp := exec.Command(binPath, "assessment", "summary", "--help")
	if out, err := cmdHelp.CombinedOutput(); err != nil {
		t.Errorf("expected exit code 0 for --help, got: %v (out: %s)", err, out)
	}

	// 18c. Non-existent assessment: exit code 1
	cmdNonExistent := exec.Command(binPath, "assessment", "summary", "--assessment-id", "asm-does-not-exist", "--db", dbPath)
	if err := cmdNonExistent.Run(); err == nil {
		t.Errorf("expected exit code 1 for non-existent assessment")
	}
}

// 19. Report integration preserves existing output behavior and deduplication
func TestChangeSummary_19_ReportIntegrationAndDeduplication(t *testing.T) {
	store, _, asm, tgt, dbPath := setupSummaryTestDB(t)

	baseExec := &assessment.AssessmentExecution{
		ID:           "exec-rep-b",
		AssessmentID: asm.ID,
		Status:       assessment.StatusCompleted,
		StartedAt:    time.Now().UTC().Add(-2 * time.Hour),
	}
	_ = store.CreateExecution(baseExec)

	currExec := &assessment.AssessmentExecution{
		ID:           "exec-rep-c",
		AssessmentID: asm.ID,
		Status:       assessment.StatusCompleted,
		StartedAt:    time.Now().UTC(),
	}
	_ = store.CreateExecution(currExec)

	rf := report.Finding{
		ID:       "f-report-integration",
		RuleID:   "API_BOLA",
		Title:    "BOLA Finding",
		Category: "broken-object-level-authorization",
		Severity: report.SeverityHigh,
		Target:   tgt.TargetURL,
		Endpoint: "/users/123",
		Method:   "GET",
	}
	correlation.EnsureFindingFingerprint(&rf, correlation.TrustPolicyForceRecompute)
	af := assessment.ToAssessmentFinding(asm.ID, currExec.ID, tgt.ID, rf)
	_ = store.SaveFindings([]assessment.AssessmentFinding{af})

	// Review finding as APPROVED_FOR_REPORT
	_ = store.SaveFindingReview(&assessment.FindingReview{
		FindingID:    af.ID,
		AssessmentID: asm.ID,
		ReviewStatus: assessment.ReviewStatusApproved,
		ReviewedBy:   "lead-auditor",
		ReviewedAt:   time.Now().UTC(),
	})

	// Generate curated commercial report with ChangeSummary
	htmlOut := filepath.Join(t.TempDir(), "commercial.html")
	jsonOut := filepath.Join(t.TempDir(), "commercial.json")
	opts := assessment.CuratedReportOptions{
		AllowDraft:           false,
		ExecutionID:          currExec.ID,
		BaselineExecutionID:  baseExec.ID,
		IncludeChangeSummary: true,
		ExportHTMLPath:       htmlOut,
		ExportJSONPath:       jsonOut,
	}

	res, err := assessment.GenerateCuratedCommercialReport(store, asm.ID, "auditor-1", opts)
	if err != nil {
		t.Fatalf("GenerateCuratedCommercialReport failed: %v", err)
	}

	if res.ChangeSummary == nil {
		t.Fatalf("expected ChangeSummary on result, got nil")
	}
	if res.Report.ChangeSummary == nil {
		t.Fatalf("expected ChangeSummary on Report, got nil")
	}
	if res.ChangeSummary.Counts.New != 1 {
		t.Errorf("expected 1 new finding in change summary, got %d", res.ChangeSummary.Counts.New)
	}

	// Repeat report generation: must update existing record without creating duplicates
	res2, err := assessment.GenerateCuratedCommercialReport(store, asm.ID, "auditor-1", opts)
	if err != nil {
		t.Fatalf("second GenerateCuratedCommercialReport failed: %v", err)
	}
	if res2.Report.ChangeSummary == nil {
		t.Errorf("expected ChangeSummary on second report")
	}

	// Verify only 2 report records exist (1 HTML, 1 JSON) in assessment_reports
	var count int
	rawDB19, _ := sql.Open("sqlite", dbPath)
	_ = rawDB19.QueryRow(`SELECT COUNT(*) FROM assessment_reports WHERE execution_id = ?`, currExec.ID).Scan(&count)
	_ = rawDB19.Close()
	if count != 2 {
		t.Errorf("expected exactly 2 report records (HTML & JSON), got %d (deduplication failed)", count)
	}
}

// 20. Repeated summary generation does not mutate execution history or finding lifecycle state
func TestChangeSummary_20_ReadonlyNoMutation(t *testing.T) {
	store, _, asm, tgt, dbPath := setupSummaryTestDB(t)
	authAdmin := assessment.NewAdminAuthContext()

	baseExec := &assessment.AssessmentExecution{
		ID:           "exec-mut-b",
		AssessmentID: asm.ID,
		Status:       assessment.StatusCompleted,
		StartedAt:    time.Now().UTC().Add(-1 * time.Hour),
	}
	_ = store.CreateExecution(baseExec)

	currExec := &assessment.AssessmentExecution{
		ID:           "exec-mut-c",
		AssessmentID: asm.ID,
		Status:       assessment.StatusCompleted,
		StartedAt:    time.Now().UTC(),
	}
	_ = store.CreateExecution(currExec)

	rf := report.Finding{
		ID:       "f-mut",
		RuleID:   "API_BOLA",
		Title:    "BOLA Test",
		Category: "broken-object-level-authorization",
		Severity: report.SeverityHigh,
		Target:   tgt.TargetURL,
		Endpoint: "/users",
		Method:   "GET",
	}
	correlation.EnsureFindingFingerprint(&rf, correlation.TrustPolicyForceRecompute)
	_ = store.SaveFindings([]assessment.AssessmentFinding{assessment.ToAssessmentFinding(asm.ID, currExec.ID, tgt.ID, rf)})

	rawDB20, _ := sql.Open("sqlite", dbPath)
	var (
		execsBefore, findingsBefore, eventsBefore int
	)
	_ = rawDB20.QueryRow(`SELECT COUNT(*) FROM assessment_executions`).Scan(&execsBefore)
	_ = rawDB20.QueryRow(`SELECT COUNT(*) FROM assessment_findings`).Scan(&findingsBefore)
	_ = rawDB20.QueryRow(`SELECT COUNT(*) FROM finding_lifecycle_events`).Scan(&eventsBefore)

	// Call GetAssessmentChangeSummary multiple times
	for i := 0; i < 5; i++ {
		_, err := store.GetAssessmentChangeSummary(asm.ID, baseExec.ID, currExec.ID, authAdmin)
		if err != nil {
			t.Fatalf("call %d failed: %v", i, err)
		}
	}

	var (
		execsAfter, findingsAfter, eventsAfter int
	)
	_ = rawDB20.QueryRow(`SELECT COUNT(*) FROM assessment_executions`).Scan(&execsAfter)
	_ = rawDB20.QueryRow(`SELECT COUNT(*) FROM assessment_findings`).Scan(&findingsAfter)
	_ = rawDB20.QueryRow(`SELECT COUNT(*) FROM finding_lifecycle_events`).Scan(&eventsAfter)
	_ = rawDB20.Close()

	if execsBefore != execsAfter {
		t.Errorf("executions mutated: before=%d after=%d", execsBefore, execsAfter)
	}
	if findingsBefore != findingsAfter {
		t.Errorf("findings mutated: before=%d after=%d", findingsBefore, findingsAfter)
	}
	if eventsBefore != eventsAfter {
		t.Errorf("lifecycle events mutated: before=%d after=%d", eventsBefore, eventsAfter)
	}
}

// 21. Automatic baseline selection skips failed, cancelled, and ineligible executions
func TestChangeSummary_21_AutomaticBaselineSelection_SkipsFailedAndIneligible(t *testing.T) {
	store, client, asm, tgt, _ := setupSummaryTestDB(t)
	authAdmin := assessment.NewAdminAuthContext()
	now := time.Now().UTC()

	// Exec 1: COMPLETED (eligible baseline)
	t1 := now.Add(-3 * time.Hour)
	exec1 := &assessment.AssessmentExecution{
		ID:           "exec-auto-1-comp",
		AssessmentID: asm.ID,
		ClientID:     client.ID,
		TenantID:     client.ID,
		Status:       assessment.StatusCompleted,
		StartedAt:    t1,
		CompletedAt:  &t1,
	}
	_ = store.CreateExecution(exec1)
	f1 := report.Finding{
		ID:       "f-auto-1",
		RuleID:   "API_BOLA",
		Category: "broken-object-level-authorization",
		Severity: report.SeverityHigh,
		Target:   tgt.TargetURL,
		Endpoint: "/users/1",
		Method:   "GET",
	}
	correlation.EnsureFindingFingerprint(&f1, correlation.TrustPolicyForceRecompute)
	_ = store.SaveFindings([]assessment.AssessmentFinding{assessment.ToAssessmentFinding(asm.ID, exec1.ID, tgt.ID, f1)})

	// Exec 2: FAILED (ineligible - must be skipped by automatic baseline selection)
	t2 := now.Add(-2 * time.Hour)
	exec2 := &assessment.AssessmentExecution{
		ID:           "exec-auto-2-failed",
		AssessmentID: asm.ID,
		ClientID:     client.ID,
		TenantID:     client.ID,
		Status:       assessment.StatusFailed,
		StartedAt:    t2,
	}
	_ = store.CreateExecution(exec2)

	// Exec 3: COMPLETED (current comparison run)
	t3 := now
	exec3 := &assessment.AssessmentExecution{
		ID:           "exec-auto-3-current",
		AssessmentID: asm.ID,
		ClientID:     client.ID,
		TenantID:     client.ID,
		Status:       assessment.StatusCompleted,
		StartedAt:    t3,
		CompletedAt:  &t3,
	}
	_ = store.CreateExecution(exec3)
	f1Curr := f1
	f1Curr.ID = "f-auto-1-c3"
	_ = store.SaveFindings([]assessment.AssessmentFinding{assessment.ToAssessmentFinding(asm.ID, exec3.ID, tgt.ID, f1Curr)})

	// Automatic baseline selection for exec3: must select exec1 (skipping exec2)
	summary, err := store.GetAssessmentChangeSummary(asm.ID, "", exec3.ID, authAdmin)
	if err != nil {
		t.Fatalf("GetAssessmentChangeSummary failed: %v", err)
	}

	if summary.BaselineExecutionID != exec1.ID {
		t.Errorf("expected baseline to be %s (skipping failed exec2), got %s", exec1.ID, summary.BaselineExecutionID)
	}
	if summary.Counts.Persistent != 1 {
		t.Errorf("expected 1 persistent finding from exec1, got %d", summary.Counts.Persistent)
	}

	// Sub-case: when ONLY ineligible executions exist prior to comparison, explicit no-baseline result is produced
	asmIneligible := &assessment.Assessment{
		ID:             "asm-ineligible-only",
		Ref:            "ASM-INELIGIBLE",
		ClientID:       client.ID,
		Name:           "Ineligible Only",
		AssessmentType: "web",
		Status:         assessment.StatusReady,
	}
	_ = store.CreateAssessment(asmIneligible)
	_ = store.CreateExecution(&assessment.AssessmentExecution{
		ID:           "exec-ineligible-failed",
		AssessmentID: asmIneligible.ID,
		ClientID:     client.ID,
		TenantID:     client.ID,
		Status:       assessment.StatusFailed,
		StartedAt:    t1,
	})
	execCurrentOnly := &assessment.AssessmentExecution{
		ID:           "exec-current-only",
		AssessmentID: asmIneligible.ID,
		ClientID:     client.ID,
		TenantID:     client.ID,
		Status:       assessment.StatusCompleted,
		StartedAt:    t3,
		CompletedAt:  &t3,
	}
	_ = store.CreateExecution(execCurrentOnly)

	sumIneligible, err := store.GetAssessmentChangeSummary(asmIneligible.ID, "", execCurrentOnly.ID, authAdmin)
	if err != nil {
		t.Fatalf("expected initial summary when only failed runs exist, got err: %v", err)
	}
	if sumIneligible.BaselineExecutionID != "" {
		t.Errorf("expected empty baseline ID when only failed runs exist, got %s", sumIneligible.BaselineExecutionID)
	}
}

// 22. Unresolved critical findings are never buried beneath lower-severity findings
func TestChangeSummary_22_CriticalFindingsNeverBuriedByLowerSeverities(t *testing.T) {
	store, client, asm, tgt, _ := setupSummaryTestDB(t)
	authAdmin := assessment.NewAdminAuthContext()

	baseExec := &assessment.AssessmentExecution{
		ID:           "exec-bury-b",
		AssessmentID: asm.ID,
		ClientID:     client.ID,
		TenantID:     client.ID,
		Status:       assessment.StatusCompleted,
		StartedAt:    time.Now().UTC().Add(-1 * time.Hour),
	}
	_ = store.CreateExecution(baseExec)

	currExec := &assessment.AssessmentExecution{
		ID:           "exec-bury-c",
		AssessmentID: asm.ID,
		ClientID:     client.ID,
		TenantID:     client.ID,
		Status:       assessment.StatusCompleted,
		StartedAt:    time.Now().UTC(),
	}
	_ = store.CreateExecution(currExec)

	// Finding A: Critical Persistent (Unresolved critical issue)
	fCritPersist := report.Finding{
		ID:       "f-crit-persist",
		RuleID:   "SECRETS_PRIVKEY",
		Title:    "Private Key Leak",
		Category: "secrets",
		Severity: report.SeverityCritical,
		Target:   tgt.TargetURL,
		Endpoint: "/keys/id_rsa",
		Method:   "GET",
	}
	correlation.EnsureFindingFingerprint(&fCritPersist, correlation.TrustPolicyForceRecompute)

	// Finding B: Info New finding
	fInfoNew := report.Finding{
		ID:       "f-info-new",
		RuleID:   "HEADER_NOTE",
		Title:    "Informational Header Note",
		Category: "headers",
		Severity: report.SeverityInfo,
		Target:   tgt.TargetURL,
		Endpoint: "/public",
		Method:   "GET",
	}
	correlation.EnsureFindingFingerprint(&fInfoNew, correlation.TrustPolicyForceRecompute)

	// Finding C: High Regressed finding (Severity worsened)
	fHighRegressBase := report.Finding{
		ID:       "f-high-regress-b",
		RuleID:   "API_BOLA",
		Title:    "BOLA Severity Worsened",
		Category: "broken-object-level-authorization",
		Severity: report.SeverityMedium,
		Target:   tgt.TargetURL,
		Endpoint: "/api/order",
		Method:   "GET",
	}
	correlation.EnsureFindingFingerprint(&fHighRegressBase, correlation.TrustPolicyForceRecompute)
	fHighRegressCurr := fHighRegressBase
	fHighRegressCurr.ID = "f-high-regress-c"
	fHighRegressCurr.Severity = report.SeverityHigh

	_ = store.SaveFindings([]assessment.AssessmentFinding{
		assessment.ToAssessmentFinding(asm.ID, baseExec.ID, tgt.ID, fCritPersist),
		assessment.ToAssessmentFinding(asm.ID, baseExec.ID, tgt.ID, fHighRegressBase),
	})
	_ = store.SaveFindings([]assessment.AssessmentFinding{
		assessment.ToAssessmentFinding(asm.ID, currExec.ID, tgt.ID, fCritPersist),
		assessment.ToAssessmentFinding(asm.ID, currExec.ID, tgt.ID, fInfoNew),
		assessment.ToAssessmentFinding(asm.ID, currExec.ID, tgt.ID, fHighRegressCurr),
	})

	summary, err := store.GetAssessmentChangeSummary(asm.ID, baseExec.ID, currExec.ID, authAdmin)
	if err != nil {
		t.Fatalf("GetAssessmentChangeSummary failed: %v", err)
	}

	if len(summary.ImportantChanges) != 3 {
		t.Fatalf("expected 3 items, got %d", len(summary.ImportantChanges))
	}

	// CRITICAL persistent finding MUST be at index 0 (top of important changes), ahead of HIGH and INFO
	if summary.ImportantChanges[0].Severity != report.SeverityCritical {
		t.Errorf("critical finding buried! Item 0 severity is %s (expected CRITICAL)", summary.ImportantChanges[0].Severity)
	}
	if summary.ImportantChanges[1].Severity != report.SeverityHigh {
		t.Errorf("Item 1 severity is %s (expected HIGH)", summary.ImportantChanges[1].Severity)
	}
	if summary.ImportantChanges[2].Severity != report.SeverityInfo {
		t.Errorf("Item 2 severity is %s (expected INFO)", summary.ImportantChanges[2].Severity)
	}
}
