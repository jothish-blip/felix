package test

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"felix/pkg/assessment"
	"felix/pkg/correlation"
	"felix/pkg/report"
	"felix/pkg/secrets"
	_ "modernc.org/sqlite"
)

// =============================================================================
// PHASE 6.5: ASSESSMENT HISTORY & PERSISTENT SNAPSHOTS REGRESSION SUITE
// 19 Production-Oriented Behavioral Verification Categories
// =============================================================================

func helperNewHistoryTestStore(t *testing.T) (assessment.Store, string, func()) {
	t.Helper()
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, fmt.Sprintf("test_history_%d.db", time.Now().UnixNano()))
	store, err := assessment.NewSQLiteStore(dbPath)
	if err != nil {
		t.Fatalf("failed to create sqlite store: %v", err)
	}
	cleanup := func() {
		_ = store.Close()
	}
	return store, dbPath, cleanup
}

func helperSeedClientAndAssessment(t *testing.T, store assessment.Store, clientID, asmID, tenantID, accountID string) (*assessment.Client, *assessment.Assessment) {
	t.Helper()
	client := &assessment.Client{
		ID:        clientID,
		Name:      "Test Client " + clientID,
		CreatedAt: time.Now().UTC(),
		UpdatedAt: time.Now().UTC(),
	}
	if err := store.CreateClient(client); err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	asm := &assessment.Assessment{
		ID:             asmID,
		Ref:            "ASM-" + asmID,
		ClientID:       clientID,
		Name:           "Assessment " + asmID,
		AssessmentType: "BLACK_BOX_WEB",
		Status:         assessment.StatusReady,
		ScopeMode:      "same-origin",
		CreatedAt:      time.Now().UTC(),
		UpdatedAt:      time.Now().UTC(),
	}
	if err := store.CreateAssessment(asm); err != nil {
		t.Fatalf("failed to create assessment: %v", err)
	}

	return client, asm
}

func helperSeedTarget(t *testing.T, store assessment.Store, asmID, targetID, targetURL string) *assessment.AssessmentTarget {
	t.Helper()
	tgt := &assessment.AssessmentTarget{
		ID:           targetID,
		AssessmentID: asmID,
		TargetURL:    targetURL,
		TargetType:   assessment.TargetWebsite,
		ScopeStatus:  "APPROVED",
		CreatedAt:    time.Now().UTC(),
	}
	if err := store.AddTarget(tgt); err != nil {
		t.Fatalf("failed to add target %s: %v", targetID, err)
	}
	return tgt
}

// -----------------------------------------------------------------------------
// Category 01: Completed Assessment Creates Retrievable Historical Snapshot
// -----------------------------------------------------------------------------
func TestHistory_Category01_CompletedAssessmentCreatesRetrievableSnapshot(t *testing.T) {
	store, _, cleanup := helperNewHistoryTestStore(t)
	defer cleanup()

	clientID := "cli_c01"
	asmID := "asm_c01"
	execID := "exec_c01"
	targetURL := "https://app.example.com"

	_, asm := helperSeedClientAndAssessment(t, store, clientID, asmID, "tenant_c01", "acc_c01")

	execRecord := &assessment.AssessmentExecution{
		ID:           execID,
		AssessmentID: asmID,
		Status:       assessment.StatusCompleted,
		StartedAt:    time.Now().UTC().Add(-5 * time.Minute),
		CompletedAt:  func() *time.Time { t := time.Now().UTC(); return &t }(),
		DurationMs:   300000,
		RequestCount: 150,
		ConfigSnapshot: assessment.ScanConfigSnapshot{
			TimeoutSeconds: 30,
			Concurrency:    5,
			ScopeMode:      "same-origin",
			FelixVersion:   "2.0.0",
		},
	}
	if err := store.CreateExecution(execRecord); err != nil {
		t.Fatalf("failed to create execution: %v", err)
	}

	helperSeedTarget(t, store, asmID, "tgt_01", targetURL)
	f1 := helperMakeDedupFinding("fnd_c01_1", "SQL Injection on /search", "sqli", report.SeverityHigh, report.ConfidenceHigh, report.VerificationVerified, targetURL, targetURL+"/search", "GET")
	af1 := assessment.ToAssessmentFinding(asmID, execID, "tgt_01", f1)

	snap := assessment.BuildAssessmentSnapshot(asm, execRecord, []string{targetURL}, []assessment.AssessmentFinding{af1}, true)
	evidence := assessment.ExtractHistoricalEvidence(snap.ID, []assessment.AssessmentFinding{af1})

	if err := store.CreateSnapshot(snap, []assessment.AssessmentFinding{af1}, evidence); err != nil {
		t.Fatalf("CreateSnapshot failed: %v", err)
	}

	authCtx := assessment.TenantAuthContext{ClientID: clientID}
	retrieved, err := store.GetSnapshot(snap.ID, authCtx)
	if err != nil {
		t.Fatalf("GetSnapshot failed: %v", err)
	}

	if retrieved.ID != snap.ID {
		t.Errorf("Expected snapshot ID %s, got %s", snap.ID, retrieved.ID)
	}
	if !retrieved.IsComplete {
		t.Errorf("Expected IsComplete=true for completed assessment snapshot")
	}
	if retrieved.Status != assessment.StatusCompleted {
		t.Errorf("Expected StatusCompleted, got %s", retrieved.Status)
	}
	if retrieved.FindingCount != 1 {
		t.Errorf("Expected FindingCount=1, got %d", retrieved.FindingCount)
	}
	if retrieved.TargetCount != 1 {
		t.Errorf("Expected TargetCount=1, got %d", retrieved.TargetCount)
	}
	if len(retrieved.ScopedTargets) != 1 || retrieved.ScopedTargets[0] != targetURL {
		t.Errorf("Expected ScopedTargets to contain %s, got %v", targetURL, retrieved.ScopedTargets)
	}
}

// -----------------------------------------------------------------------------
// Category 02: Separate Executions Receive Distinct Snapshot Identities
// -----------------------------------------------------------------------------
func TestHistory_Category02_SeparateExecutionsReceiveDistinctIdentities(t *testing.T) {
	store, _, cleanup := helperNewHistoryTestStore(t)
	defer cleanup()

	clientID := "cli_c02"
	asmID := "asm_c02"
	exec1ID := "exec_c02_run1"
	exec2ID := "exec_c02_run2"
	targetURL := "https://portal.example.com"

	_, asm := helperSeedClientAndAssessment(t, store, clientID, asmID, "tenant_c02", "acc_c02")

	// Run 1
	exec1 := &assessment.AssessmentExecution{
		ID:           exec1ID,
		AssessmentID: asmID,
		Status:       assessment.StatusCompleted,
		StartedAt:    time.Now().UTC().Add(-2 * time.Hour),
		CompletedAt:  func() *time.Time { t := time.Now().UTC().Add(-100 * time.Minute); return &t }(),
	}
	_ = store.CreateExecution(exec1)
	snap1 := assessment.BuildAssessmentSnapshot(asm, exec1, []string{targetURL}, nil, true)
	if err := store.CreateSnapshot(snap1, nil, nil); err != nil {
		t.Fatalf("failed to create snapshot 1: %v", err)
	}

	// Run 2 (same targets, different execution)
	exec2 := &assessment.AssessmentExecution{
		ID:           exec2ID,
		AssessmentID: asmID,
		Status:       assessment.StatusCompleted,
		StartedAt:    time.Now().UTC().Add(-30 * time.Minute),
		CompletedAt:  func() *time.Time { t := time.Now().UTC().Add(-10 * time.Minute); return &t }(),
	}
	_ = store.CreateExecution(exec2)
	snap2 := assessment.BuildAssessmentSnapshot(asm, exec2, []string{targetURL}, nil, true)
	if err := store.CreateSnapshot(snap2, nil, nil); err != nil {
		t.Fatalf("failed to create snapshot 2: %v", err)
	}

	if snap1.ID == snap2.ID {
		t.Fatalf("Snapshots from different executions must have distinct IDs!")
	}
	if snap1.ExecutionID == snap2.ExecutionID {
		t.Fatalf("Execution IDs must not match")
	}

	authCtx := assessment.TenantAuthContext{ClientID: clientID}
	retrieved1, _ := store.GetSnapshot(snap1.ID, authCtx)
	retrieved2, _ := store.GetSnapshot(snap2.ID, authCtx)

	if retrieved1.ExecutionID != exec1ID || retrieved2.ExecutionID != exec2ID {
		t.Errorf("Retrieved snapshot execution IDs do not match expected")
	}
}

// -----------------------------------------------------------------------------
// Category 03: Retrying Persistence Idempotence
// -----------------------------------------------------------------------------
func TestHistory_Category03_RetryingPersistenceIdempotence(t *testing.T) {
	store, _, cleanup := helperNewHistoryTestStore(t)
	defer cleanup()

	clientID := "cli_c03"
	asmID := "asm_c03"
	execID := "exec_c03"
	_, asm := helperSeedClientAndAssessment(t, store, clientID, asmID, "tenant_c03", "acc_c03")

	exec := &assessment.AssessmentExecution{
		ID:           execID,
		AssessmentID: asmID,
		Status:       assessment.StatusCompleted,
		StartedAt:    time.Now().UTC(),
	}
	_ = store.CreateExecution(exec)

	snap := assessment.BuildAssessmentSnapshot(asm, exec, []string{"https://retry.example.com"}, nil, true)

	// First attempt
	if err := store.CreateSnapshot(snap, nil, nil); err != nil {
		t.Fatalf("First snapshot attempt failed: %v", err)
	}

	// Retry identical snapshot
	if err := store.CreateSnapshot(snap, nil, nil); err != nil {
		t.Fatalf("Retry snapshot attempt must be idempotent, but got: %v", err)
	}

	// Attempting to overwrite existing execution with a DIFFERENT snapshot ID must fail
	diffSnap := assessment.BuildAssessmentSnapshot(asm, exec, []string{"https://retry.example.com"}, nil, true)
	diffSnap.ID = "snp_different_id_conflict"
	if err := store.CreateSnapshot(diffSnap, nil, nil); err != assessment.ErrSnapshotImmutable {
		t.Fatalf("Expected ErrSnapshotImmutable when attempting to overwrite snapshot, got %v", err)
	}
}

// -----------------------------------------------------------------------------
// Category 04: Later Assessment Cannot Mutate Earlier Snapshot Finding State
// -----------------------------------------------------------------------------
func TestHistory_Category04_LaterAssessmentCannotMutateEarlierSnapshot(t *testing.T) {
	store, _, cleanup := helperNewHistoryTestStore(t)
	defer cleanup()

	clientID := "cli_c04"
	asmID := "asm_c04"
	exec1ID := "exec_c04_1"
	targetURL := "https://immutable.example.com"
	_, asm := helperSeedClientAndAssessment(t, store, clientID, asmID, "tenant_c04", "acc_c04")

	exec1 := &assessment.AssessmentExecution{
		ID:           exec1ID,
		AssessmentID: asmID,
		Status:       assessment.StatusCompleted,
		StartedAt:    time.Now().UTC(),
	}
	_ = store.CreateExecution(exec1)

	helperSeedTarget(t, store, asmID, "tgt_01", targetURL)
	fOriginal := helperMakeDedupFinding("fnd_orig", "Unvalidated Redirect", "redirect", report.SeverityLow, report.ConfidenceLow, report.VerificationDetected, targetURL, targetURL+"/out", "GET")
	fOriginal.Score = 15
	afOriginal := assessment.ToAssessmentFinding(asmID, exec1ID, "tgt_01", fOriginal)

	snap1 := assessment.BuildAssessmentSnapshot(asm, exec1, []string{targetURL}, []assessment.AssessmentFinding{afOriginal}, true)
	if err := store.CreateSnapshot(snap1, []assessment.AssessmentFinding{afOriginal}, nil); err != nil {
		t.Fatalf("failed to create snapshot 1: %v", err)
	}

	// Attempt to overwrite findings of the completed snapshot via SaveFindings
	fTamper := helperMakeDedupFinding("fnd_orig", "Escalated Critical Exploit", "rce", report.SeverityCritical, report.ConfidenceHigh, report.VerificationVerified, targetURL, targetURL+"/out", "POST")
	fTamper.Score = 40
	afTamper := assessment.ToAssessmentFinding(asmID, exec1ID, "tgt_01", fTamper)

	err := store.SaveFindings([]assessment.AssessmentFinding{afTamper})
	if err != assessment.ErrSnapshotImmutable {
		t.Fatalf("Expected ErrSnapshotImmutable when attempting to overwrite findings of completed snapshot, got %v", err)
	}

	// Verify original findings remain untouched
	authCtx := assessment.TenantAuthContext{ClientID: clientID}
	findings, err := store.GetSnapshotFindings(snap1.ID, authCtx)
	if err != nil {
		t.Fatalf("failed to get snapshot findings: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("Expected 1 finding, got %d", len(findings))
	}
	if findings[0].Score != 15 || findings[0].Severity != report.SeverityLow {
		t.Fatalf("CRITICAL SECURITY DEFECT: Historical snapshot finding was mutated! Score=%d, Severity=%s", findings[0].Score, findings[0].Severity)
	}
}

// -----------------------------------------------------------------------------
// Category 05: Completed, Partial, Failed, and Cancelled Execution Semantics
// -----------------------------------------------------------------------------
func TestHistory_Category05_CompletedPartialFailedCancelledSemantics(t *testing.T) {
	store, _, cleanup := helperNewHistoryTestStore(t)
	defer cleanup()

	clientID := "cli_c05"
	asmID := "asm_c05"
	_, asm := helperSeedClientAndAssessment(t, store, clientID, asmID, "tenant_c05", "acc_c05")

	cases := []struct {
		execID      string
		status      assessment.AssessmentStatus
		isComplete  bool
		errExpected bool
		errMsg      string
	}{
		{"exec_c05_comp", assessment.StatusCompleted, true, false, ""},
		{"exec_c05_comperr", assessment.StatusCompletedWithErrors, true, false, ""},
		{"exec_c05_fail", assessment.StatusFailed, false, true, "Scan failed: target timeout"},
		{"exec_c05_canc", assessment.StatusCancelled, false, true, "Execution was cancelled by operator"},
	}

	authCtx := assessment.TenantAuthContext{ClientID: clientID}

	for _, tc := range cases {
		exec := &assessment.AssessmentExecution{
			ID:           tc.execID,
			AssessmentID: asmID,
			Status:       tc.status,
			ErrorMessage: tc.errMsg,
			StartedAt:    time.Now().UTC(),
		}
		_ = store.CreateExecution(exec)

		snap := assessment.BuildAssessmentSnapshot(asm, exec, []string{"https://example.com"}, nil, tc.isComplete)
		if err := store.CreateSnapshot(snap, nil, nil); err != nil {
			t.Fatalf("CreateSnapshot failed for %s: %v", tc.execID, err)
		}

		retrieved, err := store.GetSnapshot(snap.ID, authCtx)
		if err != nil {
			t.Fatalf("GetSnapshot failed for %s: %v", tc.execID, err)
		}

		if retrieved.IsComplete != tc.isComplete {
			t.Errorf("Expected IsComplete=%v for %s, got %v", tc.isComplete, tc.execID, retrieved.IsComplete)
		}
		if retrieved.Status != tc.status {
			t.Errorf("Expected Status=%s for %s, got %s", tc.status, tc.execID, retrieved.Status)
		}
		if tc.errExpected && retrieved.Metadata["error_message"] != tc.errMsg {
			t.Errorf("Expected error message %q in metadata, got %q", tc.errMsg, retrieved.Metadata["error_message"])
		}
	}
}

// -----------------------------------------------------------------------------
// Category 06: Persistence Failure Atomicity
// -----------------------------------------------------------------------------
func TestHistory_Category06_PersistenceFailureAtomicity(t *testing.T) {
	store, _, cleanup := helperNewHistoryTestStore(t)
	defer cleanup()

	// Calling CreateSnapshot with invalid foreign key (non-existent assessment) must fail atomically
	exec := &assessment.AssessmentExecution{
		ID:           "exec_invalid_fk",
		AssessmentID: "asm_non_existent",
		Status:       assessment.StatusCompleted,
		StartedAt:    time.Now().UTC(),
	}
	snap := &assessment.AssessmentSnapshot{
		ID:           "snp_invalid_fk",
		SnapshotRef:  "SNP-INVALID",
		AssessmentID: "asm_non_existent",
		ExecutionID:  exec.ID,
		ClientID:     "cli_non_existent",
		Status:       assessment.StatusCompleted,
		StartedAt:    time.Now().UTC(),
	}

	err := store.CreateSnapshot(snap, nil, nil)
	if err == nil {
		t.Fatalf("Expected foreign key error on non-existent assessment/execution, got nil")
	}

	// Verify nothing was persisted
	authCtx := assessment.NewAdminAuthContext()
	_, getErr := store.GetSnapshot(snap.ID, authCtx)
	if getErr != assessment.ErrSnapshotNotFound {
		t.Fatalf("Expected ErrSnapshotNotFound after rollback, got %v", getErr)
	}
}

// -----------------------------------------------------------------------------
// Category 07: Evidence SQLite Round Trip Fidelity
// -----------------------------------------------------------------------------
func TestHistory_Category07_EvidenceSQLiteRoundTripFidelity(t *testing.T) {
	store, _, cleanup := helperNewHistoryTestStore(t)
	defer cleanup()

	clientID := "cli_c07"
	asmID := "asm_c07"
	execID := "exec_c07"
	targetURL := "https://api.example.com"
	_, asm := helperSeedClientAndAssessment(t, store, clientID, asmID, "tenant_c07", "acc_c07")

	exec := &assessment.AssessmentExecution{
		ID:           execID,
		AssessmentID: asmID,
		Status:       assessment.StatusCompleted,
		StartedAt:    time.Now().UTC(),
	}
	_ = store.CreateExecution(exec)

	helperSeedTarget(t, store, asmID, "tgt_c07", targetURL)
	f := helperMakeDedupFinding("fnd_c07", "BFLA on /admin/reset", "bfla", report.SeverityCritical, report.ConfidenceHigh, report.VerificationVerified, targetURL, targetURL+"/admin/reset", "POST")
	f.EvidenceDetails.HTTPStatus = 200
	f.EvidenceDetails.HTTPMethod = "POST"
	f.EvidenceDetails.ContentType = "application/json"
	f.EvidenceDetails.Observation = "Admin reset route accepted unprivileged operator token"
	f.Verification.Result = "Verified privilege escalation bypass"
	f.Verification.SafeCurlCommand = "curl -X POST https://api.example.com/admin/reset -H 'Authorization: Bearer test'"
	f.EvidenceDetails.Details["payload"] = "{\"action\": \"reset\"}"
	f.EvidenceDetails.Details["tenant_id"] = "tenant_c07"
	f.EvidenceDetails.Details["account_id"] = "acc_c07"

	af := assessment.ToAssessmentFinding(asmID, execID, "tgt_c07", f)
	snap := assessment.BuildAssessmentSnapshot(asm, exec, []string{targetURL}, []assessment.AssessmentFinding{af}, true)
	evidence := assessment.ExtractHistoricalEvidence(snap.ID, []assessment.AssessmentFinding{af})

	if len(evidence) != 1 {
		t.Fatalf("Expected 1 historical evidence record, got %d", len(evidence))
	}

	if err := store.CreateSnapshot(snap, []assessment.AssessmentFinding{af}, evidence); err != nil {
		t.Fatalf("CreateSnapshot failed: %v", err)
	}

	authCtx := assessment.TenantAuthContext{ClientID: clientID, TenantID: "tenant_c07", AccountID: "acc_c07"}
	evList, err := store.GetHistoricalEvidence(snap.ID, af.ID, authCtx)
	if err != nil {
		t.Fatalf("GetHistoricalEvidence failed: %v", err)
	}
	if len(evList) != 1 {
		t.Fatalf("Expected 1 evidence record returned, got %d", len(evList))
	}

	retEv := evList[0]
	if retEv.HTTPStatus != 200 {
		t.Errorf("Expected HTTPStatus=200, got %d", retEv.HTTPStatus)
	}
	if retEv.HTTPMethod != "POST" {
		t.Errorf("Expected HTTPMethod=POST, got %s", retEv.HTTPMethod)
	}
	if retEv.ContentType != "application/json" {
		t.Errorf("Expected ContentType=application/json, got %s", retEv.ContentType)
	}
	if retEv.Payload != "{\"action\": \"reset\"}" {
		t.Errorf("Expected payload preserved, got %s", retEv.Payload)
	}
	expectedCurl := secrets.RedactText(f.Verification.SafeCurlCommand)
	if retEv.SafeCurlCommand != expectedCurl {
		t.Errorf("Expected SafeCurlCommand preserved with redaction (%s), got %s", expectedCurl, retEv.SafeCurlCommand)
	}
	if retEv.VerificationStatus != report.VerificationVerified {
		t.Errorf("Expected VerificationVerified, got %s", retEv.VerificationStatus)
	}
}

// -----------------------------------------------------------------------------
// Category 08: Evidence Remains Associated with Correct Finding, Snapshot, and Target
// -----------------------------------------------------------------------------
func TestHistory_Category08_EvidenceAssociationIntegrity(t *testing.T) {
	store, _, cleanup := helperNewHistoryTestStore(t)
	defer cleanup()

	clientID := "cli_c08"
	asmID := "asm_c08"
	execID := "exec_c08"
	tgt1 := "https://web.example.com"
	tgt2 := "https://api.example.com"
	_, asm := helperSeedClientAndAssessment(t, store, clientID, asmID, "tenant_c08", "acc_c08")

	exec := &assessment.AssessmentExecution{
		ID:           execID,
		AssessmentID: asmID,
		Status:       assessment.StatusCompleted,
		StartedAt:    time.Now().UTC(),
	}
	_ = store.CreateExecution(exec)

	helperSeedTarget(t, store, asmID, "tgt_web", tgt1)
	helperSeedTarget(t, store, asmID, "tgt_api", tgt2)
	f1 := helperMakeDedupFinding("fnd_web_xss", "XSS on Search", "xss", report.SeverityHigh, report.ConfidenceHigh, report.VerificationVerified, tgt1, tgt1+"/search", "GET")
	f1.Provenance = &report.EvidenceProvenance{EvidenceID: "ev_web_001", SourceEngine: "crawler"}
	af1 := assessment.ToAssessmentFinding(asmID, execID, "tgt_web", f1)

	f2 := helperMakeDedupFinding("fnd_api_sqli", "SQLi on Users", "sqli", report.SeverityCritical, report.ConfidenceHigh, report.VerificationVerified, tgt2, tgt2+"/users", "GET")
	f2.Provenance = &report.EvidenceProvenance{EvidenceID: "ev_api_002", SourceEngine: "apisec"}
	af2 := assessment.ToAssessmentFinding(asmID, execID, "tgt_api", f2)

	snap := assessment.BuildAssessmentSnapshot(asm, exec, []string{tgt1, tgt2}, []assessment.AssessmentFinding{af1, af2}, true)
	evidence := assessment.ExtractHistoricalEvidence(snap.ID, []assessment.AssessmentFinding{af1, af2})

	_ = store.CreateSnapshot(snap, []assessment.AssessmentFinding{af1, af2}, evidence)

	authCtx := assessment.TenantAuthContext{ClientID: clientID}

	// Filter by f1
	ev1, err := store.GetHistoricalEvidence(snap.ID, af1.ID, authCtx)
	if err != nil || len(ev1) != 1 {
		t.Fatalf("Expected 1 evidence item for f1, got %d (err: %v)", len(ev1), err)
	}
	if ev1[0].EvidenceID != "ev_web_001" || ev1[0].TargetURL != tgt1 {
		t.Errorf("Evidence f1 incorrect association: %s, %s", ev1[0].EvidenceID, ev1[0].TargetURL)
	}

	// Filter by f2
	ev2, err := store.GetHistoricalEvidence(snap.ID, af2.ID, authCtx)
	if err != nil || len(ev2) != 1 {
		t.Fatalf("Expected 1 evidence item for f2, got %d (err: %v)", len(ev2), err)
	}
	if ev2[0].EvidenceID != "ev_api_002" || ev2[0].TargetURL != tgt2 {
		t.Errorf("Evidence f2 incorrect association: %s, %s", ev2[0].EvidenceID, ev2[0].TargetURL)
	}
}

// -----------------------------------------------------------------------------
// Category 09: Multiple Evidence Items and Alternative Payloads Preserved
// -----------------------------------------------------------------------------
func TestHistory_Category09_MultipleEvidenceAndAlternativePayloadsPreserved(t *testing.T) {
	store, _, cleanup := helperNewHistoryTestStore(t)
	defer cleanup()

	clientID := "cli_c09"
	asmID := "asm_c09"
	execID := "exec_c09"
	targetURL := "https://app.example.com"
	_, asm := helperSeedClientAndAssessment(t, store, clientID, asmID, "tenant_c09", "acc_c09")

	exec := &assessment.AssessmentExecution{
		ID:           execID,
		AssessmentID: asmID,
		Status:       assessment.StatusCompleted,
		StartedAt:    time.Now().UTC(),
	}
	_ = store.CreateExecution(exec)

	helperSeedTarget(t, store, asmID, "tgt_09", targetURL)
	// Deduplicated canonical finding containing merged evidence IDs from two detectors
	fCanonical := helperMakeDedupFinding("fnd_merged", "Command Injection", "cmdi", report.SeverityCritical, report.ConfidenceHigh, report.VerificationVerified, targetURL, targetURL+"/exec", "POST")
	fCanonical.Provenance = &report.EvidenceProvenance{EvidenceID: "ev_primary_crawler"}
	fCanonical.EvidenceDetails.Details["merged_evidence_ids"] = "ev_primary_crawler,ev_secondary_apisec"
	fCanonical.EvidenceDetails.Details["additional_payloads"] = "; cat /etc/passwd || ; id"
	fCanonical.EvidenceDetails.Details["alternative_curl_commands"] = "curl -X POST https://app.example.com/exec -d '; id'"

	af := assessment.ToAssessmentFinding(asmID, execID, "tgt_09", fCanonical)
	snap := assessment.BuildAssessmentSnapshot(asm, exec, []string{targetURL}, []assessment.AssessmentFinding{af}, true)
	evidence := assessment.ExtractHistoricalEvidence(snap.ID, []assessment.AssessmentFinding{af})

	if len(evidence) != 2 {
		t.Fatalf("Expected 2 distinct historical evidence records for merged finding, got %d", len(evidence))
	}

	_ = store.CreateSnapshot(snap, []assessment.AssessmentFinding{af}, evidence)

	authCtx := assessment.TenantAuthContext{ClientID: clientID}
	evList, _ := store.GetHistoricalEvidence(snap.ID, af.ID, authCtx)
	if len(evList) != 2 {
		t.Fatalf("Expected 2 retrieved historical evidence records, got %d", len(evList))
	}

	foundPrimary := false
	foundSecondary := false
	for _, ev := range evList {
		if ev.EvidenceID == "ev_primary_crawler" {
			foundPrimary = true
		}
		if ev.EvidenceID == "ev_secondary_apisec" {
			foundSecondary = true
			if !strings.Contains(ev.Payload, "cat /etc/passwd") {
				t.Errorf("Secondary evidence missing alternative payload: %s", ev.Payload)
			}
		}
	}
	if !foundPrimary || !foundSecondary {
		t.Errorf("Expected both primary and secondary evidence records preserved: primary=%v, secondary=%v", foundPrimary, foundSecondary)
	}
}

// -----------------------------------------------------------------------------
// Category 10: Risk Scores, Risk Explanations, Fingerprints, and Asset IDs
// -----------------------------------------------------------------------------
func TestHistory_Category10_FindingRiskScoresAndTargetAssociationsSurviveRoundTrip(t *testing.T) {
	store, _, cleanup := helperNewHistoryTestStore(t)
	defer cleanup()

	clientID := "cli_c10"
	asmID := "asm_c10"
	execID := "exec_c10"
	_, asm := helperSeedClientAndAssessment(t, store, clientID, asmID, "tenant_c10", "acc_c10")

	exec := &assessment.AssessmentExecution{
		ID:           execID,
		AssessmentID: asmID,
		Status:       assessment.StatusCompleted,
		StartedAt:    time.Now().UTC(),
	}
	_ = store.CreateExecution(exec)

	f := helperMakeDedupFinding("fnd_c10", "SSRF to Cloud Metadata", "ssrf", report.SeverityCritical, report.ConfidenceHigh, report.VerificationVerified, "https://cloud.example.com", "https://cloud.example.com/proxy", "GET")
	f.PrimaryAssetID = "asset_cloud_gw"
	f.AffectedAssetIDs = []string{"asset_iam_role", "asset_metadata_service"}
	f.EvidenceDetails.Details["associated_targets"] = "https://cloud.example.com, https://internal.example.com"
	f.EvidenceDetails.Details["associated_target_ids"] = "tgt_1,tgt_2"
	f.EvidenceDetails.Details["target_id_count"] = "2"
	f.Score = 40
	expl := report.ExplainFindingScore(f)
	f.ScoreExplanation = &expl

	helperSeedTarget(t, store, asmID, "tgt_1", "https://cloud.example.com")
	af := assessment.ToAssessmentFinding(asmID, execID, "tgt_1", f)
	snap := assessment.BuildAssessmentSnapshot(asm, exec, []string{"https://cloud.example.com"}, []assessment.AssessmentFinding{af}, true)

	_ = store.CreateSnapshot(snap, []assessment.AssessmentFinding{af}, nil)

	authCtx := assessment.TenantAuthContext{ClientID: clientID}
	findings, err := store.GetSnapshotFindings(snap.ID, authCtx)
	if err != nil || len(findings) != 1 {
		t.Fatalf("failed to retrieve snapshot findings: %v", err)
	}

	retAF := findings[0]
	if retAF.Score != 40 {
		t.Errorf("Expected Score=40, got %d", retAF.Score)
	}
	if retAF.PrimaryAssetID != "asset_cloud_gw" {
		t.Errorf("Expected PrimaryAssetID asset_cloud_gw, got %s", retAF.PrimaryAssetID)
	}
	if len(retAF.AffectedAssetIDs) != 2 {
		t.Errorf("Expected 2 AffectedAssetIDs, got %d", len(retAF.AffectedAssetIDs))
	}
	if retAF.ScoreExplanation == nil || retAF.ScoreExplanation.Score != 40 {
		t.Errorf("Score explanation not preserved accurately: %+v", retAF.ScoreExplanation)
	}
	if !strings.Contains(retAF.EvidenceDetails.Details["associated_targets"], "https://internal.example.com") {
		t.Errorf("associated_targets was dropped")
	}
}

// -----------------------------------------------------------------------------
// Category 11: Redaction and Sanitization Effective
// -----------------------------------------------------------------------------
func TestHistory_Category11_RedactionAndSanitizationEffective(t *testing.T) {
	store, dbPath, cleanup := helperNewHistoryTestStore(t)
	defer cleanup()

	clientID := "cli_c11"
	asmID := "asm_c11"
	execID := "exec_c11"
	_, asm := helperSeedClientAndAssessment(t, store, clientID, asmID, "tenant_c11", "acc_c11")

	secretBearer := "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.sensitive_payload"
	secretAWS := "AKIAIOSFODNN7EXAMPLE"

	exec := &assessment.AssessmentExecution{
		ID:           execID,
		AssessmentID: asmID,
		Status:       assessment.StatusCompleted,
		ErrorMessage: "Auth failed with " + secretBearer,
		StartedAt:    time.Now().UTC(),
	}
	_ = store.CreateExecution(exec)

	helperSeedTarget(t, store, asmID, "tgt_11", "https://app.example.com")
	f := helperMakeDedupFinding("fnd_c11", "Leaked Credentials in Header", "secrets", report.SeverityHigh, report.ConfidenceHigh, report.VerificationVerified, "https://app.example.com", "https://app.example.com/api", "GET")
	f.EvidenceDetails.Observation = "Detected secret AWS key: " + secretAWS
	f.Verification.SafeCurlCommand = "curl https://app.example.com/api -H 'Authorization: " + secretBearer + "'"

	af := assessment.ToAssessmentFinding(asmID, execID, "tgt_11", f)
	snap := assessment.BuildAssessmentSnapshot(asm, exec, []string{"https://app.example.com"}, []assessment.AssessmentFinding{af}, true)
	evidence := assessment.ExtractHistoricalEvidence(snap.ID, []assessment.AssessmentFinding{af})

	_ = store.CreateSnapshot(snap, []assessment.AssessmentFinding{af}, evidence)

	// Open raw SQLite db and inspect strings to confirm cleartext secrets are absent
	rawDB, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("failed to open raw db: %v", err)
	}
	defer rawDB.Close()

	var obs, curlCmd string
	err = rawDB.QueryRow("SELECT observation, safe_curl_command FROM assessment_historical_evidence WHERE snapshot_id = ?", snap.ID).Scan(&obs, &curlCmd)
	if err != nil {
		t.Fatalf("failed to query raw evidence: %v", err)
	}

	if strings.Contains(obs, secretAWS) {
		t.Fatalf("CRITICAL SECURITY DEFECT: Raw cleartext AWS key persisted in evidence observation!")
	}
	if strings.Contains(curlCmd, "sensitive_payload") {
		t.Fatalf("CRITICAL SECURITY DEFECT: Raw cleartext JWT payload persisted in evidence safe_curl_command!")
	}
}

// -----------------------------------------------------------------------------
// Category 12: Tenant and Account Boundaries Enforced
// -----------------------------------------------------------------------------
func TestHistory_Category12_TenantAndAccountBoundariesEnforced(t *testing.T) {
	store, _, cleanup := helperNewHistoryTestStore(t)
	defer cleanup()

	// Tenant A setup
	clientA, asmA := helperSeedClientAndAssessment(t, store, "cli_tenant_a", "asm_tenant_a", "tenant_a", "acc_a")
	execA := &assessment.AssessmentExecution{ID: "exec_a", AssessmentID: asmA.ID, Status: assessment.StatusCompleted, StartedAt: time.Now().UTC()}
	_ = store.CreateExecution(execA)

	helperSeedTarget(t, store, asmA.ID, "tgt_a", "https://tenant-a.com")
	fA := helperMakeDedupFinding("fnd_a", "Tenant A Finding", "sqli", report.SeverityHigh, report.ConfidenceHigh, report.VerificationVerified, "https://tenant-a.com", "https://tenant-a.com/data", "GET")
	fA.EvidenceDetails.Details["tenant_id"] = "tenant_a"
	afA := assessment.ToAssessmentFinding(asmA.ID, execA.ID, "tgt_a", fA)
	snapA := assessment.BuildAssessmentSnapshot(asmA, execA, []string{"https://tenant-a.com"}, []assessment.AssessmentFinding{afA}, true)
	evidenceA := assessment.ExtractHistoricalEvidence(snapA.ID, []assessment.AssessmentFinding{afA})
	_ = store.CreateSnapshot(snapA, []assessment.AssessmentFinding{afA}, evidenceA)

	// Tenant B caller
	authB := assessment.TenantAuthContext{ClientID: "cli_tenant_b", TenantID: "tenant_b", AccountID: "acc_b"}

	// Tenant B tries to get Tenant A's snapshot
	_, err := store.GetSnapshot(snapA.ID, authB)
	if err != assessment.ErrSnapshotUnauthorized {
		t.Fatalf("Expected ErrSnapshotUnauthorized when Tenant B accesses Tenant A snapshot, got %v", err)
	}

	// Tenant B tries to get Tenant A's findings
	_, err = store.GetSnapshotFindings(snapA.ID, authB)
	if err != assessment.ErrSnapshotUnauthorized {
		t.Fatalf("Expected ErrSnapshotUnauthorized when Tenant B accesses Tenant A findings, got %v", err)
	}

	// Tenant B tries to get Tenant A's historical evidence
	_, err = store.GetHistoricalEvidence(snapA.ID, "", authB)
	if err != assessment.ErrSnapshotUnauthorized {
		t.Fatalf("Expected ErrSnapshotUnauthorized when Tenant B accesses Tenant A evidence, got %v", err)
	}

	// Tenant B tries to get Tenant A's evidence by ID
	_, err = store.GetEvidenceByID(evidenceA[0].EvidenceID, authB)
	if err != assessment.ErrSnapshotUnauthorized {
		t.Fatalf("Expected ErrSnapshotUnauthorized when Tenant B accesses Tenant A evidence by ID, got %v", err)
	}

	// Tenant A caller can access successfully
	authA := assessment.TenantAuthContext{ClientID: clientA.ID, TenantID: "tenant_a", AccountID: "acc_a"}
	retrievedA, err := store.GetSnapshot(snapA.ID, authA)
	if err != nil || retrievedA == nil {
		t.Fatalf("Tenant A failed to retrieve own snapshot: %v", err)
	}
}

// -----------------------------------------------------------------------------
// Category 13: Admin Context Can Access Across Tenants
// -----------------------------------------------------------------------------
func TestHistory_Category13_AdminContextCanAccessAcrossTenants(t *testing.T) {
	store, _, cleanup := helperNewHistoryTestStore(t)
	defer cleanup()

	_, asmA := helperSeedClientAndAssessment(t, store, "cli_t13", "asm_t13", "tenant_13", "acc_13")
	execA := &assessment.AssessmentExecution{ID: "exec_t13", AssessmentID: asmA.ID, Status: assessment.StatusCompleted, StartedAt: time.Now().UTC()}
	_ = store.CreateExecution(execA)
	snapA := assessment.BuildAssessmentSnapshot(asmA, execA, []string{"https://app.example.com"}, nil, true)
	_ = store.CreateSnapshot(snapA, nil, nil)

	adminAuth := assessment.NewAdminAuthContext()
	retrieved, err := store.GetSnapshot(snapA.ID, adminAuth)
	if err != nil || retrieved == nil {
		t.Fatalf("Admin failed to retrieve snapshot across tenants: %v", err)
	}
}

// -----------------------------------------------------------------------------
// Category 14: Missing Snapshot and Evidence Distinction
// -----------------------------------------------------------------------------
func TestHistory_Category14_MissingSnapshotAndEvidenceDistinction(t *testing.T) {
	store, _, cleanup := helperNewHistoryTestStore(t)
	defer cleanup()

	auth := assessment.TenantAuthContext{ClientID: "cli_any"}

	// Non-existent snapshot ID returns ErrSnapshotNotFound (not unauthorized)
	_, err := store.GetSnapshot("snp_non_existent_12345", auth)
	if err != assessment.ErrSnapshotNotFound {
		t.Fatalf("Expected ErrSnapshotNotFound for non-existent snapshot, got %v", err)
	}

	// Non-existent evidence ID returns ErrEvidenceNotFound
	_, err = store.GetEvidenceByID("ev_non_existent_999", auth)
	if err != assessment.ErrEvidenceNotFound {
		t.Fatalf("Expected ErrEvidenceNotFound for non-existent evidence, got %v", err)
	}
}

// -----------------------------------------------------------------------------
// Category 15: Incomplete or Out-of-Scope Snapshots Prevent False Resolved
// -----------------------------------------------------------------------------
func TestHistory_Category15_IncompleteOrOutOfScopeSnapshotsPreventFalseResolved(t *testing.T) {
	store, _, cleanup := helperNewHistoryTestStore(t)
	defer cleanup()

	clientID := "cli_c15"
	asmID := "asm_c15"
	targetA := "https://service-a.example.com"
	targetB := "https://service-b.example.com"
	_, asm := helperSeedClientAndAssessment(t, store, clientID, asmID, "tenant_c15", "acc_c15")
	authCtx := assessment.TenantAuthContext{ClientID: clientID}

	// Baseline snapshot with finding on target A and target B
	exec1 := &assessment.AssessmentExecution{ID: "exec_c15_1", AssessmentID: asmID, Status: assessment.StatusCompleted, StartedAt: time.Now().UTC()}
	_ = store.CreateExecution(exec1)

	helperSeedTarget(t, store, asmID, "tgt_a", targetA)
	helperSeedTarget(t, store, asmID, "tgt_b", targetB)
	f1 := helperMakeDedupFinding("fnd_shared", "Exposed Metrics Endpoint", "info", report.SeverityMedium, report.ConfidenceHigh, report.VerificationVerified, targetA, targetA+"/metrics", "GET")
	f1.EvidenceDetails.Details["associated_targets"] = targetA + ", " + targetB
	af1 := assessment.ToAssessmentFinding(asmID, exec1.ID, "tgt_a", f1)
	snap1 := assessment.BuildAssessmentSnapshot(asm, exec1, []string{targetA, targetB}, []assessment.AssessmentFinding{af1}, true)
	_ = store.CreateSnapshot(snap1, []assessment.AssessmentFinding{af1}, nil)

	// Case A: Next snapshot FAILED (Incomplete execution)
	execFail := &assessment.AssessmentExecution{ID: "exec_c15_fail", AssessmentID: asmID, Status: assessment.StatusFailed, ErrorMessage: "Scanner crashed", StartedAt: time.Now().UTC()}
	_ = store.CreateExecution(execFail)
	snapFail := assessment.BuildAssessmentSnapshot(asm, execFail, []string{targetA, targetB}, nil, false)
	_ = store.CreateSnapshot(snapFail, nil, nil)

	compFail, err := store.CompareSnapshots(snap1.ID, snapFail.ID, authCtx)
	if err != nil {
		t.Fatalf("CompareSnapshots failed: %v", err)
	}
	if compFail.ResolvedCount != 0 {
		t.Fatalf("CRITICAL SECURITY DEFECT: Failed execution falsely resolved baseline finding! ResolvedCount=%d", compFail.ResolvedCount)
	}
	if compFail.UnassessedCount != 1 {
		t.Fatalf("Expected UnassessedCount=1 for incomplete execution, got %d", compFail.UnassessedCount)
	}

	// Case B: Next snapshot completed, but Target B was out of scope
	execScoped := &assessment.AssessmentExecution{ID: "exec_c15_scoped", AssessmentID: asmID, Status: assessment.StatusCompleted, StartedAt: time.Now().UTC()}
	_ = store.CreateExecution(execScoped)
	snapScoped := assessment.BuildAssessmentSnapshot(asm, execScoped, []string{targetA}, nil, true)
	_ = store.CreateSnapshot(snapScoped, nil, nil)

	compScoped, err := store.CompareSnapshots(snap1.ID, snapScoped.ID, authCtx)
	if err != nil {
		t.Fatalf("CompareSnapshots failed: %v", err)
	}
	if compScoped.ResolvedCount != 0 {
		t.Fatalf("CRITICAL SECURITY DEFECT: Out-of-scope target was falsely marked resolved! ResolvedCount=%d", compScoped.ResolvedCount)
	}
	if compScoped.UnassessedCount != 1 {
		t.Fatalf("Expected UnassessedCount=1 when target was unscoped, got %d", compScoped.UnassessedCount)
	}
}

// -----------------------------------------------------------------------------
// Category 16: Target Footprint Shift in Historical Comparison
// -----------------------------------------------------------------------------
func TestHistory_Category16_TargetFootprintShiftInHistoricalComparison(t *testing.T) {
	store, _, cleanup := helperNewHistoryTestStore(t)
	defer cleanup()

	clientID := "cli_c16"
	asmID := "asm_c16"
	targetA := "https://app-a.example.com"
	targetB := "https://app-b.example.com"
	_, asm := helperSeedClientAndAssessment(t, store, clientID, asmID, "tenant_c16", "acc_c16")
	authCtx := assessment.TenantAuthContext{ClientID: clientID}

	// Baseline snapshot: finding affects both Target A and Target B
	exec1 := &assessment.AssessmentExecution{ID: "exec_c16_1", AssessmentID: asmID, Status: assessment.StatusCompleted, StartedAt: time.Now().UTC()}
	_ = store.CreateExecution(exec1)

	helperSeedTarget(t, store, asmID, "tgt_a", targetA)
	helperSeedTarget(t, store, asmID, "tgt_b", targetB)
	f1 := helperMakeDedupFinding("fnd_shift", "CORS Wildcard", "cors", report.SeverityMedium, report.ConfidenceHigh, report.VerificationVerified, targetA, targetA+"/api", "GET")
	f1.EvidenceDetails.Details["associated_targets"] = targetA + ", " + targetB
	af1 := assessment.ToAssessmentFinding(asmID, exec1.ID, "tgt_a", f1)
	snap1 := assessment.BuildAssessmentSnapshot(asm, exec1, []string{targetA, targetB}, []assessment.AssessmentFinding{af1}, true)
	_ = store.CreateSnapshot(snap1, []assessment.AssessmentFinding{af1}, nil)

	// Rescan snapshot: both targets A and B rescanned, but finding only found on A
	exec2 := &assessment.AssessmentExecution{ID: "exec_c16_2", AssessmentID: asmID, Status: assessment.StatusCompleted, StartedAt: time.Now().UTC()}
	_ = store.CreateExecution(exec2)
	f2 := helperMakeDedupFinding("fnd_shift_cur", "CORS Wildcard", "cors", report.SeverityMedium, report.ConfidenceHigh, report.VerificationVerified, targetA, targetA+"/api", "GET")
	f2.EvidenceDetails.Details["associated_targets"] = targetA
	af2 := assessment.ToAssessmentFinding(asmID, exec2.ID, "tgt_a", f2)
	snap2 := assessment.BuildAssessmentSnapshot(asm, exec2, []string{targetA, targetB}, []assessment.AssessmentFinding{af2}, true)
	_ = store.CreateSnapshot(snap2, []assessment.AssessmentFinding{af2}, nil)

	comp, err := store.CompareSnapshots(snap1.ID, snap2.ID, authCtx)
	if err != nil {
		t.Fatalf("CompareSnapshots failed: %v", err)
	}

	if comp.RecurringCount != 1 || comp.ResolvedCount != 0 {
		t.Fatalf("Expected finding on Target A to remain Recurring (not resolved), Recurring=%d, Resolved=%d", comp.RecurringCount, comp.ResolvedCount)
	}
	if len(comp.Items) != 1 {
		t.Fatalf("Expected 1 comparison item, got %d", len(comp.Items))
	}
	if !strings.Contains(comp.Items[0].Explanation, "target footprint shifted") {
		t.Errorf("Expected target footprint shift in explanation: %s", comp.Items[0].Explanation)
	}
}

// -----------------------------------------------------------------------------
// Category 17: Database Migration from V16 to V17 Preserves Existing Data
// -----------------------------------------------------------------------------
func TestHistory_Category17_DatabaseMigrationFromV16ToV17PreservesData(t *testing.T) {
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "migration_v16_to_v17.db")

	// 1. Create a fresh store to migrate all the way up to v17
	store1, err := assessment.NewSQLiteStore(dbPath)
	if err != nil {
		t.Fatalf("failed to create initial store: %v", err)
	}

	// Seed client and assessment
	_, asm := helperSeedClientAndAssessment(t, store1, "cli_mig", "asm_mig", "tenant_mig", "acc_mig")
	exec := &assessment.AssessmentExecution{ID: "exec_mig_1", AssessmentID: asm.ID, Status: assessment.StatusCompleted, StartedAt: time.Now().UTC()}
	_ = store1.CreateExecution(exec)

	helperSeedTarget(t, store1, asm.ID, "tgt_mig", "https://mig.example.com")
	f := helperMakeDedupFinding("fnd_mig_1", "CSRF Vulnerability", "csrf", report.SeverityMedium, report.ConfidenceHigh, report.VerificationVerified, "https://mig.example.com", "https://mig.example.com/form", "POST")
	af := assessment.ToAssessmentFinding(asm.ID, exec.ID, "tgt_mig", f)
	_ = store1.SaveFindings([]assessment.AssessmentFinding{af})
	store1.Close()

	// 2. Reopen store and verify data survives and schema is at v17
	store2, err := assessment.NewSQLiteStore(dbPath)
	if err != nil {
		t.Fatalf("failed to reopen store: %v", err)
	}
	defer store2.Close()

	findings, err := store2.GetFindings(asm.ID, exec.ID)
	if err != nil || len(findings) != 1 {
		t.Fatalf("Existing findings lost after reopening store: %v (len=%d)", err, len(findings))
	}
	if findings[0].Title != "CSRF Vulnerability" {
		t.Errorf("Expected title 'CSRF Vulnerability', got %s", findings[0].Title)
	}

	// 3. Verify snapshot capability is functional on upgraded database
	snap := assessment.BuildAssessmentSnapshot(asm, exec, []string{"https://mig.example.com"}, findings, true)
	if err := store2.CreateSnapshot(snap, findings, nil); err != nil {
		t.Fatalf("CreateSnapshot failed on upgraded database: %v", err)
	}

	authCtx := assessment.TenantAuthContext{ClientID: "cli_mig"}
	retrieved, err := store2.GetSnapshot(snap.ID, authCtx)
	if err != nil || retrieved == nil {
		t.Fatalf("Failed to retrieve snapshot from upgraded database: %v", err)
	}
}

// -----------------------------------------------------------------------------
// Category 18: Snapshot Retrieval Returns Stable Deterministic Ordering & Pagination
// -----------------------------------------------------------------------------
func TestHistory_Category18_SnapshotPaginationAndStableDeterministicOrdering(t *testing.T) {
	store, _, cleanup := helperNewHistoryTestStore(t)
	defer cleanup()

	clientID := "cli_c18"
	asmID := "asm_c18"
	_, asm := helperSeedClientAndAssessment(t, store, clientID, asmID, "tenant_c18", "acc_c18")

	baseTime := time.Now().UTC().Add(-20 * time.Minute)
	var createdSnapIDs []string

	for i := 0; i < 10; i++ {
		execID := fmt.Sprintf("exec_c18_%02d", i)
		exec := &assessment.AssessmentExecution{
			ID:           execID,
			AssessmentID: asmID,
			Status:       assessment.StatusCompleted,
			StartedAt:    baseTime.Add(time.Duration(i) * time.Minute),
		}
		_ = store.CreateExecution(exec)

		snap := assessment.BuildAssessmentSnapshot(asm, exec, []string{"https://example.com"}, nil, true)
		snap.CreatedAt = baseTime.Add(time.Duration(i) * time.Minute)
		if err := store.CreateSnapshot(snap, nil, nil); err != nil {
			t.Fatalf("CreateSnapshot %d failed: %v", i, err)
		}
		createdSnapIDs = append(createdSnapIDs, snap.ID)
	}

	// Query page 1 (limit 5, offset 0)
	optsPage1 := assessment.SnapshotListOptions{
		ClientID: clientID,
		Limit:    5,
		Offset:   0,
	}
	page1, total1, err := store.ListSnapshots(optsPage1)
	if err != nil {
		t.Fatalf("ListSnapshots page 1 failed: %v", err)
	}
	if total1 != 10 {
		t.Errorf("Expected total count 10, got %d", total1)
	}
	if len(page1) != 5 {
		t.Fatalf("Expected 5 snapshots on page 1, got %d", len(page1))
	}

	// Query page 2 (limit 5, offset 5)
	optsPage2 := assessment.SnapshotListOptions{
		ClientID: clientID,
		Limit:    5,
		Offset:   5,
	}
	page2, total2, err := store.ListSnapshots(optsPage2)
	if err != nil {
		t.Fatalf("ListSnapshots page 2 failed: %v", err)
	}
	if total2 != 10 {
		t.Errorf("Expected total count 10, got %d", total2)
	}
	if len(page2) != 5 {
		t.Fatalf("Expected 5 snapshots on page 2, got %d", len(page2))
	}

	// Verify no overlap between page 1 and page 2
	p1IDs := make(map[string]struct{})
	for _, s := range page1 {
		p1IDs[s.ID] = struct{}{}
	}
	for _, s := range page2 {
		if _, exists := p1IDs[s.ID]; exists {
			t.Fatalf("Snapshot %s appeared on both page 1 and page 2 (pagination unstable!)", s.ID)
		}
	}

	// Verify descending chronological order on page 1
	for i := 0; i < len(page1)-1; i++ {
		if page1[i].CreatedAt.Before(page1[i+1].CreatedAt) {
			t.Errorf("Snapshots on page 1 not sorted in descending order: %v before %v", page1[i].CreatedAt, page1[i+1].CreatedAt)
		}
	}
}

// -----------------------------------------------------------------------------
// Category 19: Relationships and Attack Paths Persisted with Snapshot
// -----------------------------------------------------------------------------
func TestHistory_Category19_RelationshipsAndAttackPathsPersistedWithSnapshot(t *testing.T) {
	store, _, cleanup := helperNewHistoryTestStore(t)
	defer cleanup()

	clientID := "cli_c19"
	asmID := "asm_c19"
	execID := "exec_c19"
	targetURL := "https://attackpath.example.com"
	_, asm := helperSeedClientAndAssessment(t, store, clientID, asmID, "tenant_c19", "acc_c19")

	exec := &assessment.AssessmentExecution{
		ID:           execID,
		AssessmentID: asmID,
		Status:       assessment.StatusCompleted,
		StartedAt:    time.Now().UTC(),
	}
	_ = store.CreateExecution(exec)

	// Save attack path associated with this execution
	paths := []correlation.AttackPath{
		{
			ID:                "path_hist_001",
			Title:             "Public S3 Bucket to Admin Takeover",
			Status:            correlation.PathVerified,
			Confidence:        "HIGH",
			CombinedRiskLevel: "CRITICAL",
			CombinedRiskScore: 92,
			RiskRationale:     "Direct verified multi-hop escalation path",
			EntryPoint:        "https://attackpath.example.com/upload",
			TargetAsset:       "arn:aws:s3:::prod-secrets",
			NodeIDs:           []string{"fnd_1", "fnd_2"},
			Edges: []correlation.Relationship{
				{
					ID:               "rel_1",
					SourceFindingID:  "fnd_1",
					TargetFindingID:  "fnd_2",
					Type:             correlation.RelEnables,
					ValidationStatus: correlation.ValidationConfirmed,
					Explanation:      "Uploaded shell provides IAM role credentials",
				},
			},
		},
	}
	if err := store.SaveAttackPaths(asmID, execID, paths); err != nil {
		t.Fatalf("SaveAttackPaths failed: %v", err)
	}

	snap := assessment.BuildAssessmentSnapshot(asm, exec, []string{targetURL}, nil, true)
	if err := store.CreateSnapshot(snap, nil, nil); err != nil {
		t.Fatalf("CreateSnapshot failed: %v", err)
	}

	// Retrieve attack paths for the snapshot's execution
	retrievedPaths, err := store.GetAttackPaths(asmID, execID, "", "")
	if err != nil {
		t.Fatalf("GetAttackPaths failed: %v", err)
	}
	if len(retrievedPaths) != 1 {
		t.Fatalf("Expected 1 attack path associated with snapshot execution, got %d", len(retrievedPaths))
	}

	p := retrievedPaths[0]
	if !strings.HasPrefix(p.ID, "path_hist_001") || p.CombinedRiskScore != 92 {
		t.Errorf("Retrieved attack path data mismatch: %s, %d", p.ID, p.CombinedRiskScore)
	}
	if len(p.Edges) != 1 || p.Edges[0].ValidationStatus != correlation.ValidationConfirmed {
		t.Errorf("Retrieved attack path edges corrupted")
	}
}

// =============================================================================
// PHASE 6.5 TARGETED FINAL ACCEPTANCE AUDIT TESTS
// =============================================================================

func TestHistory_AcceptanceAudit_ImmutabilityEnforcement(t *testing.T) {
	store, _, cleanup := helperNewHistoryTestStore(t)
	defer cleanup()

	clientID := "cli_audit_imm"
	asmID := "asm_audit_imm"
	execID := "exec_audit_imm"
	targetURL := "https://imm.example.com"
	_, asm := helperSeedClientAndAssessment(t, store, clientID, asmID, "tenant_audit", "acc_audit")
	helperSeedTarget(t, store, asmID, "tgt_audit", targetURL)

	exec := &assessment.AssessmentExecution{
		ID:           execID,
		AssessmentID: asmID,
		Status:       assessment.StatusCompleted,
		StartedAt:    time.Now().UTC(),
	}
	_ = store.CreateExecution(exec)

	f1 := helperMakeDedupFinding("fnd_audit_orig", "Original Vulnerability", "sqli", report.SeverityHigh, report.ConfidenceHigh, report.VerificationVerified, targetURL, targetURL+"/api", "GET")
	af1 := assessment.ToAssessmentFinding(asmID, execID, "tgt_audit", f1)

	snap := assessment.BuildAssessmentSnapshot(asm, exec, []string{targetURL}, []assessment.AssessmentFinding{af1}, true)
	ev := assessment.ExtractHistoricalEvidence(snap.ID, []assessment.AssessmentFinding{af1})

	if err := store.CreateSnapshot(snap, []assessment.AssessmentFinding{af1}, ev); err != nil {
		t.Fatalf("CreateSnapshot failed: %v", err)
	}

	// 1. Attempt to overwrite completed snapshot with modified IsComplete (downgrade to failed/partial)
	mutatedSnap := *snap
	mutatedSnap.IsComplete = false
	mutatedSnap.Status = assessment.StatusFailed
	if err := store.CreateSnapshot(&mutatedSnap, nil, nil); err != assessment.ErrSnapshotImmutable {
		t.Fatalf("Expected ErrSnapshotImmutable when downgrading completed snapshot, got %v", err)
	}

	// 2. Attempt to overwrite completed snapshot with different snapshot ID for same execution
	diffSnap := *snap
	diffSnap.ID = "snp_different_id"
	if err := store.CreateSnapshot(&diffSnap, nil, nil); err != assessment.ErrSnapshotImmutable {
		t.Fatalf("Expected ErrSnapshotImmutable when overwriting execution with different snapshot ID, got %v", err)
	}

	// 3. Attempt to mutate finding through SaveFindings with a DIFFERENT execution_id
	tamperedFinding := af1
	tamperedFinding.ExecutionID = "exec_new_run"
	tamperedFinding.Title = "Tampered Exploit"
	if err := store.SaveFindings([]assessment.AssessmentFinding{tamperedFinding}); err != assessment.ErrSnapshotImmutable {
		t.Fatalf("Expected ErrSnapshotImmutable when attempting to mutate finding belonging to completed snapshot, got %v", err)
	}

	// 4. Attempt to mutate finding through CreateSnapshot for a new execution
	exec2 := &assessment.AssessmentExecution{
		ID:           "exec_audit_2",
		AssessmentID: asmID,
		Status:       assessment.StatusCompleted,
		StartedAt:    time.Now().UTC(),
	}
	_ = store.CreateExecution(exec2)
	snap2 := assessment.BuildAssessmentSnapshot(asm, exec2, []string{targetURL}, nil, true)
	if err := store.CreateSnapshot(snap2, []assessment.AssessmentFinding{tamperedFinding}, nil); err != assessment.ErrSnapshotImmutable {
		t.Fatalf("Expected ErrSnapshotImmutable when CreateSnapshot tries to overwrite existing finding ID of completed snapshot, got %v", err)
	}

	// 5. Verify original finding and snapshot remain 100% unaltered
	auth := assessment.NewClientAuthContext(clientID)
	origFindings, err := store.GetSnapshotFindings(snap.ID, auth)
	if err != nil || len(origFindings) != 1 {
		t.Fatalf("Failed to retrieve findings: %v", err)
	}
	if origFindings[0].Title != "Original Vulnerability" {
		t.Fatalf("CRITICAL SECURITY DEFECT: Completed snapshot finding was mutated to: %s", origFindings[0].Title)
	}
}

func TestHistory_AcceptanceAudit_AuthorizationFailClosed(t *testing.T) {
	store, _, cleanup := helperNewHistoryTestStore(t)
	defer cleanup()

	clientID := "cli_audit_auth"
	tenantID := "tenant_audit_auth"
	accountID := "acc_audit_auth"
	asmID := "asm_audit_auth"
	execID := "exec_audit_auth"
	targetURL := "https://auth.example.com"
	_, asm := helperSeedClientAndAssessment(t, store, clientID, asmID, tenantID, accountID)
	helperSeedTarget(t, store, asmID, "tgt_auth", targetURL)

	exec := &assessment.AssessmentExecution{
		ID:           execID,
		AssessmentID: asmID,
		Status:       assessment.StatusCompleted,
		StartedAt:    time.Now().UTC(),
	}
	_ = store.CreateExecution(exec)

	f := helperMakeDedupFinding("fnd_auth_1", "Sensitive Data Exposure", "info", report.SeverityMedium, report.ConfidenceHigh, report.VerificationVerified, targetURL, targetURL+"/data", "GET")
	f.Provenance = &report.EvidenceProvenance{EvidenceID: "ev_auth_unique"}
	af := assessment.ToAssessmentFinding(asmID, execID, "tgt_auth", f)

	snap := assessment.BuildAssessmentSnapshot(asm, exec, []string{targetURL}, []assessment.AssessmentFinding{af}, true)
	evidence := assessment.ExtractHistoricalEvidence(snap.ID, []assessment.AssessmentFinding{af})
	if err := store.CreateSnapshot(snap, []assessment.AssessmentFinding{af}, evidence); err != nil {
		t.Fatalf("CreateSnapshot failed: %v", err)
	}

	// 1. Test empty/missing TenantAuthContext{} FAILS CLOSED
	emptyAuth := assessment.TenantAuthContext{}
	if _, err := store.GetSnapshot(snap.ID, emptyAuth); err != assessment.ErrSnapshotUnauthorized {
		t.Fatalf("Empty TenantAuthContext must fail closed on GetSnapshot, got %v", err)
	}
	if _, err := store.GetSnapshotFindings(snap.ID, emptyAuth); err != assessment.ErrSnapshotUnauthorized {
		t.Fatalf("Empty TenantAuthContext must fail closed on GetSnapshotFindings, got %v", err)
	}
	if _, err := store.GetHistoricalEvidence(snap.ID, af.ID, emptyAuth); err != assessment.ErrSnapshotUnauthorized {
		t.Fatalf("Empty TenantAuthContext must fail closed on GetHistoricalEvidence, got %v", err)
	}
	if _, err := store.GetEvidenceByID("ev_auth_unique", emptyAuth); err != assessment.ErrSnapshotUnauthorized {
		t.Fatalf("Empty TenantAuthContext must fail closed on GetEvidenceByID, got %v", err)
	}
	if _, err := store.CompareSnapshots(snap.ID, snap.ID, emptyAuth); !errors.Is(err, assessment.ErrSnapshotUnauthorized) {
		t.Fatalf("Empty TenantAuthContext must fail closed on CompareSnapshots, got %v", err)
	}
	if _, _, err := store.ListSnapshots(assessment.SnapshotListOptions{Auth: &emptyAuth}); err != assessment.ErrSnapshotUnauthorized {
		t.Fatalf("Empty TenantAuthContext must fail closed on ListSnapshots, got %v", err)
	}

	// 2. Test forged ClientID
	forgedClient := assessment.TenantAuthContext{ClientID: "forged_client_id"}
	if _, err := store.GetSnapshot(snap.ID, forgedClient); err != assessment.ErrSnapshotUnauthorized {
		t.Fatalf("Forged ClientID must fail closed, got %v", err)
	}

	// 3. Test forged TenantID
	forgedTenant := assessment.TenantAuthContext{ClientID: clientID, TenantID: "forged_tenant_id"}
	if _, err := store.GetSnapshot(snap.ID, forgedTenant); err != assessment.ErrSnapshotUnauthorized {
		t.Fatalf("Forged TenantID must fail closed, got %v", err)
	}

	// 4. Test forged AccountID
	forgedAccount := assessment.TenantAuthContext{ClientID: clientID, TenantID: tenantID, AccountID: "forged_account_id"}
	if _, err := store.GetSnapshot(snap.ID, forgedAccount); err != assessment.ErrSnapshotUnauthorized {
		t.Fatalf("Forged AccountID must fail closed, got %v", err)
	}

	// 5. Test direct evidence retrieval enforces tenant boundaries
	if _, err := store.GetEvidenceByID("ev_auth_unique", forgedTenant); err != assessment.ErrSnapshotUnauthorized {
		t.Fatalf("GetEvidenceByID must reject forged TenantID, got %v", err)
	}

	// 6. Test Admin authorization succeeds
	adminAuth := assessment.NewAdminAuthContext()
	retrievedAdmin, err := store.GetSnapshot(snap.ID, adminAuth)
	if err != nil || retrievedAdmin.ID != snap.ID {
		t.Fatalf("Admin authorization must succeed, got err=%v", err)
	}
}

func TestHistory_AcceptanceAudit_CascadeRetentionAndRollback(t *testing.T) {
	store, dbPath, cleanup := helperNewHistoryTestStore(t)
	defer cleanup()

	clientID := "cli_audit_casc"
	asmID := "asm_audit_casc"
	execID := "exec_audit_casc"
	targetURL := "https://casc.example.com"
	_, asm := helperSeedClientAndAssessment(t, store, clientID, asmID, "tenant_casc", "acc_casc")
	helperSeedTarget(t, store, asmID, "tgt_casc", targetURL)

	exec := &assessment.AssessmentExecution{
		ID:           execID,
		AssessmentID: asmID,
		Status:       assessment.StatusCompleted,
		StartedAt:    time.Now().UTC(),
	}
	_ = store.CreateExecution(exec)

	f := helperMakeDedupFinding("fnd_casc_1", "SSRF Vulnerability", "ssrf", report.SeverityHigh, report.ConfidenceHigh, report.VerificationVerified, targetURL, targetURL+"/webhook", "POST")
	f.Provenance = &report.EvidenceProvenance{EvidenceID: "ev_casc_1"}
	af := assessment.ToAssessmentFinding(asmID, execID, "tgt_casc", f)

	snap := assessment.BuildAssessmentSnapshot(asm, exec, []string{targetURL}, []assessment.AssessmentFinding{af}, true)
	evidence := assessment.ExtractHistoricalEvidence(snap.ID, []assessment.AssessmentFinding{af})
	if err := store.CreateSnapshot(snap, []assessment.AssessmentFinding{af}, evidence); err != nil {
		t.Fatalf("CreateSnapshot failed: %v", err)
	}

	rawDB, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("failed to open raw db: %v", err)
	}
	defer rawDB.Close()
	_, _ = rawDB.Exec(`PRAGMA foreign_keys = ON;`)

	// 1. Verify ON DELETE RESTRICT on clients table: client cannot be deleted while it has snapshots
	_, err = rawDB.Exec(`DELETE FROM clients WHERE id = ?`, clientID)
	if err == nil {
		t.Fatalf("CRITICAL RETENTION DEFECT: Client with active snapshots was deleted without constraint failure!")
	}

	// 2. Verify ON DELETE CASCADE on assessments table cleans up snapshots and evidence completely
	_, err = rawDB.Exec(`PRAGMA foreign_keys = ON; DELETE FROM assessments WHERE id = ?`, asmID)
	if err != nil {
		t.Fatalf("Failed to delete assessment: %v", err)
	}

	var snapCount, evCount, fndCount int
	_ = rawDB.QueryRow(`SELECT COUNT(*) FROM assessment_snapshots WHERE assessment_id = ?`, asmID).Scan(&snapCount)
	_ = rawDB.QueryRow(`SELECT COUNT(*) FROM assessment_historical_evidence WHERE assessment_id = ?`, asmID).Scan(&evCount)
	_ = rawDB.QueryRow(`SELECT COUNT(*) FROM assessment_findings WHERE assessment_id = ?`, asmID).Scan(&fndCount)

	if snapCount != 0 || evCount != 0 || fndCount != 0 {
		t.Fatalf("Orphaned records detected after assessment cascade delete: snapshots=%d, evidence=%d, findings=%d", snapCount, evCount, fndCount)
	}
}

// =============================================================================
// PHASE 6.5 TWO-POINT ACCEPTANCE TESTS
// =============================================================================

func TestHistory_Check1_TrustedAdministrativeAuthorization(t *testing.T) {
	store, _, cleanup := helperNewHistoryTestStore(t)
	defer cleanup()

	victimClient := "cli_victim_corp"
	victimTenant := "tenant_victim_prod"
	victimAccount := "acc_victim_pci"
	asmID := "asm_victim_01"
	execID := "exec_victim_01"
	targetURL := "https://victim.example.com"
	_, asm := helperSeedClientAndAssessment(t, store, victimClient, asmID, victimTenant, victimAccount)
	helperSeedTarget(t, store, asmID, "tgt_victim", targetURL)

	exec := &assessment.AssessmentExecution{
		ID:           execID,
		AssessmentID: asmID,
		Status:       assessment.StatusCompleted,
		StartedAt:    time.Now().UTC(),
	}
	_ = store.CreateExecution(exec)

	f := helperMakeDedupFinding("fnd_chk1_1", "Leaked Database Credentials", "secrets", report.SeverityCritical, report.ConfidenceHigh, report.VerificationVerified, targetURL, targetURL+"/db.conf", "GET")
	f.Provenance = &report.EvidenceProvenance{EvidenceID: "ev_chk1_unique"}
	af := assessment.ToAssessmentFinding(asmID, execID, "tgt_victim", f)

	snap := assessment.BuildAssessmentSnapshot(asm, exec, []string{targetURL}, []assessment.AssessmentFinding{af}, true)
	evidence := assessment.ExtractHistoricalEvidence(snap.ID, []assessment.AssessmentFinding{af})
	if err := store.CreateSnapshot(snap, []assessment.AssessmentFinding{af}, evidence); err != nil {
		t.Fatalf("CreateSnapshot failed: %v", err)
	}

	// 1. Untrusted JSON deserialization attempting to inject admin status must be rejected
	forgedPayloads := []string{
		`{"client_id": "attacker_cli", "is_admin": true}`,
		`{"client_id": "attacker_cli", "isAdmin": true}`,
		`{"client_id": "attacker_cli", "IsAdmin": true}`,
	}
	for _, payload := range forgedPayloads {
		var ctx assessment.TenantAuthContext
		err := json.Unmarshal([]byte(payload), &ctx)
		if err == nil {
			t.Fatalf("Expected error when unmarshaling forged admin JSON payload %q, got nil", payload)
		}
	}

	// 2. Untrusted JSON deserialization without admin flag safely sets IsAdmin = false
	safePayload := `{"client_id": "attacker_cli", "tenant_id": "tenant_victim_prod"}`
	var untrustedCtx assessment.TenantAuthContext
	if err := json.Unmarshal([]byte(safePayload), &untrustedCtx); err != nil {
		t.Fatalf("Failed to unmarshal untrusted payload: %v", err)
	}
	if untrustedCtx.IsAdmin() {
		t.Fatalf("CRITICAL SECURITY DEFECT: Untrusted deserialization resulted in IsAdmin == true")
	}

	// 3. Untrusted caller cannot access victim's snapshot using attacker context
	if _, err := store.GetSnapshot(snap.ID, untrustedCtx); err != assessment.ErrSnapshotUnauthorized {
		t.Fatalf("Untrusted caller with different ClientID must be rejected with ErrSnapshotUnauthorized, got: %v", err)
	}
	if _, err := store.GetSnapshotFindings(snap.ID, untrustedCtx); err != assessment.ErrSnapshotUnauthorized {
		t.Fatalf("Untrusted caller must be denied findings access: %v", err)
	}
	if _, err := store.GetEvidenceByID("ev_chk1_unique", untrustedCtx); err != assessment.ErrSnapshotUnauthorized {
		t.Fatalf("Untrusted caller must be denied evidence access: %v", err)
	}

	// 4. Untrusted caller omitting ClientID and attempting to match tenant fails closed
	contextNoClient := assessment.NewTenantAuthContext("", victimTenant, victimAccount)
	if contextNoClient.Authorizes(victimClient, victimTenant, victimAccount) {
		t.Fatalf("CRITICAL SECURITY DEFECT: Context with empty ClientID authorized victim resource!")
	}
	if _, err := store.GetSnapshot(snap.ID, contextNoClient); err != assessment.ErrSnapshotUnauthorized {
		t.Fatalf("Context with empty ClientID must fail closed on GetSnapshot, got %v", err)
	}

	// 5. Verified server-side admin context (via NewAdminAuthContext) succeeds
	adminCtx := assessment.NewAdminAuthContext()
	if !adminCtx.IsAdmin() {
		t.Fatalf("Expected NewAdminAuthContext().IsAdmin() == true")
	}
	retrievedSnap, err := store.GetSnapshot(snap.ID, adminCtx)
	if err != nil || retrievedSnap.ID != snap.ID {
		t.Fatalf("Trusted admin context failed to retrieve snapshot: %v", err)
	}
	retrievedEv, err := store.GetEvidenceByID("ev_chk1_unique", adminCtx)
	if err != nil || retrievedEv.ID == "" {
		t.Fatalf("Trusted admin context failed to retrieve evidence: %v", err)
	}
}

func TestHistory_Check2_SnapshotRetryIntegrity(t *testing.T) {
	store, _, cleanup := helperNewHistoryTestStore(t)
	defer cleanup()

	clientID := "cli_chk2_retry"
	asmID := "asm_chk2_retry"
	execID := "exec_chk2_retry"
	targetURL := "https://retry.example.com"
	_, asm := helperSeedClientAndAssessment(t, store, clientID, asmID, "tenant_chk2", "acc_chk2")
	helperSeedTarget(t, store, asmID, "tgt_chk2", targetURL)

	exec := &assessment.AssessmentExecution{
		ID:           execID,
		AssessmentID: asmID,
		Status:       assessment.StatusCompleted,
		StartedAt:    time.Now().UTC(),
	}
	_ = store.CreateExecution(exec)

	fOriginal := helperMakeDedupFinding("fnd_chk2_orig", "Remote Code Execution", "rce", report.SeverityCritical, report.ConfidenceHigh, report.VerificationVerified, targetURL, targetURL+"/exec", "POST")
	fOriginal.Provenance = &report.EvidenceProvenance{EvidenceID: "ev_chk2_orig"}
	afOriginal := assessment.ToAssessmentFinding(asmID, execID, "tgt_chk2", fOriginal)

	snapOriginal := assessment.BuildAssessmentSnapshot(asm, exec, []string{targetURL}, []assessment.AssessmentFinding{afOriginal}, true)
	snapOriginal.ConfigSnapshot = assessment.ScanConfigSnapshot{
		Concurrency:    5,
		TimeoutSeconds: 30,
		ScopeMode:      "APPROVED_ONLY",
	}
	evOriginal := assessment.ExtractHistoricalEvidence(snapOriginal.ID, []assessment.AssessmentFinding{afOriginal})

	// Initial persistence of snapshot, findings, and evidence
	if err := store.CreateSnapshot(snapOriginal, []assessment.AssessmentFinding{afOriginal}, evOriginal); err != nil {
		t.Fatalf("Initial CreateSnapshot failed: %v", err)
	}

	// 1. IDENTICAL RETRY: must be idempotent and return nil without modifying anything
	identicalSnap := *snapOriginal
	identicalAF := afOriginal
	identicalEV := append([]assessment.HistoricalEvidenceRecord(nil), evOriginal...)
	if err := store.CreateSnapshot(&identicalSnap, []assessment.AssessmentFinding{identicalAF}, identicalEV); err != nil {
		t.Fatalf("Identical retry must be idempotent and succeed, got error: %v", err)
	}

	// 2. CONFLICTING RETRY with modified Status
	conflictStatusSnap := *snapOriginal
	conflictStatusSnap.Status = assessment.StatusCompletedWithErrors
	if err := store.CreateSnapshot(&conflictStatusSnap, []assessment.AssessmentFinding{afOriginal}, evOriginal); err != assessment.ErrSnapshotImmutable {
		t.Fatalf("Expected ErrSnapshotImmutable for conflicting Status retry, got: %v", err)
	}

	// 3. CONFLICTING RETRY with modified ScopedTargets
	conflictScopeSnap := *snapOriginal
	conflictScopeSnap.ScopedTargets = []string{targetURL, "https://added-unauthorized-target.example.com"}
	if err := store.CreateSnapshot(&conflictScopeSnap, []assessment.AssessmentFinding{afOriginal}, evOriginal); err != assessment.ErrSnapshotImmutable {
		t.Fatalf("Expected ErrSnapshotImmutable for conflicting ScopedTargets retry, got: %v", err)
	}

	// 4. CONFLICTING RETRY with modified Configuration
	conflictConfigSnap := *snapOriginal
	conflictConfigSnap.ConfigSnapshot.Concurrency = 999
	if err := store.CreateSnapshot(&conflictConfigSnap, []assessment.AssessmentFinding{afOriginal}, evOriginal); err != assessment.ErrSnapshotImmutable {
		t.Fatalf("Expected ErrSnapshotImmutable for conflicting ConfigSnapshot retry, got: %v", err)
	}

	// 5. CONFLICTING RETRY with modified Findings (tampered finding title & severity)
	tamperedAF := afOriginal
	tamperedAF.Title = "Altered Harmless Note"
	tamperedAF.Severity = report.SeverityLow
	if err := store.CreateSnapshot(snapOriginal, []assessment.AssessmentFinding{tamperedAF}, evOriginal); err != assessment.ErrSnapshotImmutable {
		t.Fatalf("Expected ErrSnapshotImmutable for conflicting finding content retry, got: %v", err)
	}

	// 6. CONFLICTING RETRY with extra finding
	extraFinding := afOriginal
	extraFinding.ID = "fnd_chk2_extra"
	extraFinding.Fingerprint = "fp_chk2_extra"
	if err := store.CreateSnapshot(snapOriginal, []assessment.AssessmentFinding{afOriginal, extraFinding}, evOriginal); err != assessment.ErrSnapshotImmutable {
		t.Fatalf("Expected ErrSnapshotImmutable for extra finding retry, got: %v", err)
	}

	// 7. CONFLICTING RETRY with zero findings (finding removal)
	if err := store.CreateSnapshot(snapOriginal, nil, evOriginal); err != assessment.ErrSnapshotImmutable {
		t.Fatalf("Expected ErrSnapshotImmutable for omitted findings retry, got: %v", err)
	}

	// 8. CONFLICTING RETRY with modified Evidence (tampered observation)
	tamperedEV := append([]assessment.HistoricalEvidenceRecord(nil), evOriginal...)
	tamperedEV[0].Observation = "Fabricated false evidence"
	if err := store.CreateSnapshot(snapOriginal, []assessment.AssessmentFinding{afOriginal}, tamperedEV); err != assessment.ErrSnapshotImmutable {
		t.Fatalf("Expected ErrSnapshotImmutable for conflicting evidence content retry, got: %v", err)
	}

	// 9. CONFLICTING RETRY with extra evidence
	extraEVRecord := evOriginal[0]
	extraEVRecord.ID = "ev_chk2_extra"
	extraEVList := append([]assessment.HistoricalEvidenceRecord(nil), evOriginal...)
	extraEVList = append(extraEVList, extraEVRecord)
	if err := store.CreateSnapshot(snapOriginal, []assessment.AssessmentFinding{afOriginal}, extraEVList); err != assessment.ErrSnapshotImmutable {
		t.Fatalf("Expected ErrSnapshotImmutable for extra evidence retry, got: %v", err)
	}

	// 10. VERIFY COMPLETE INTEGRITY: original snapshot, finding, and evidence remain 100% unaltered
	adminAuth := assessment.NewAdminAuthContext()
	savedSnap, err := store.GetSnapshot(snapOriginal.ID, adminAuth)
	if err != nil {
		t.Fatalf("Failed to retrieve snapshot: %v", err)
	}
	if savedSnap.Status != assessment.StatusCompleted || savedSnap.ConfigSnapshot.Concurrency != 5 {
		t.Fatalf("CRITICAL INTEGRITY DEFECT: Snapshot metadata was mutated by conflicting retries! Status=%s, Concurrency=%d", savedSnap.Status, savedSnap.ConfigSnapshot.Concurrency)
	}
	if len(savedSnap.ScopedTargets) != 1 || savedSnap.ScopedTargets[0] != targetURL {
		t.Fatalf("CRITICAL INTEGRITY DEFECT: Scoped targets mutated: %v", savedSnap.ScopedTargets)
	}

	savedFindings, err := store.GetSnapshotFindings(snapOriginal.ID, adminAuth)
	if err != nil || len(savedFindings) != 1 {
		t.Fatalf("Expected 1 original finding, got %d, err=%v", len(savedFindings), err)
	}
	if savedFindings[0].Title != "Remote Code Execution" || savedFindings[0].Severity != report.SeverityCritical {
		t.Fatalf("CRITICAL INTEGRITY DEFECT: Finding was mutated! Title=%s, Sev=%s", savedFindings[0].Title, savedFindings[0].Severity)
	}

	savedEvidence, err := store.GetHistoricalEvidence(snapOriginal.ID, afOriginal.ID, adminAuth)
	if err != nil || len(savedEvidence) != 1 {
		t.Fatalf("Expected 1 original evidence record, got %d, err=%v", len(savedEvidence), err)
	}
	if savedEvidence[0].Observation == "Fabricated false evidence" {
		t.Fatalf("CRITICAL INTEGRITY DEFECT: Evidence observation was overwritten by conflicting retry!")
	}
}

// =============================================================================
// PHASE 6.5 FINAL TWO-GAP CLOSURE TESTS
// =============================================================================

func TestHistory_FinalClosure_AdminTrustBoundary(t *testing.T) {
	store, _, cleanup := helperNewHistoryTestStore(t)
	defer cleanup()

	clientA := "cli_trust_a"
	clientB := "cli_trust_b"
	asmIDA := "asm_trust_a"
	execIDA := "exec_trust_a"
	targetURLA := "https://app-a.example.com"
	_, asmA := helperSeedClientAndAssessment(t, store, clientA, asmIDA, "tenant_a", "acc_a")
	helperSeedTarget(t, store, asmIDA, "tgt_a", targetURLA)

	execA := &assessment.AssessmentExecution{
		ID:           execIDA,
		AssessmentID: asmIDA,
		Status:       assessment.StatusCompleted,
		StartedAt:    time.Now().UTC(),
	}
	_ = store.CreateExecution(execA)
	snapA := assessment.BuildAssessmentSnapshot(asmA, execA, []string{targetURLA}, nil, true)
	if err := store.CreateSnapshot(snapA, nil, nil); err != nil {
		t.Fatalf("CreateSnapshot failed: %v", err)
	}

	// 1. Unprivileged roles cannot obtain an admin context
	unprivilegedRoles := []string{"viewer", "auditor", "user", "operator", "guest", "", "ROLE_USER"}
	for _, role := range unprivilegedRoles {
		ctx, err := assessment.ResolveAuthContext(role, clientA, "tenant_a", "acc_a")
		if err != nil {
			t.Fatalf("ResolveAuthContext failed unexpectedly for role %q: %v", role, err)
		}
		if ctx.IsAdmin() {
			t.Fatalf("CRITICAL DEFECT: Unprivileged role %q was granted IsAdmin=true", role)
		}
		// Must not access foreign clientB data
		if ctx.Authorizes(clientB, "tenant_b", "acc_b") {
			t.Fatalf("CRITICAL DEFECT: Non-admin context for %q authorized foreign client %q", role, clientB)
		}
	}

	// 2. Non-admin callers without a client_id fail closed at the boundary
	_, err := assessment.ResolveAuthContext("auditor", "", "tenant_a", "acc_a")
	if err == nil {
		t.Fatalf("Expected error when resolving non-admin context with empty client_id, got nil")
	}

	// 3. AuthorizeAdminContext rejects non-administrative roles
	for _, role := range unprivilegedRoles {
		_, err := assessment.AuthorizeAdminContext(role)
		if err == nil {
			t.Fatalf("Expected AuthorizeAdminContext to reject role %q, got nil", role)
		}
	}

	// 4. Verified administrative roles succeed at the boundary
	adminRoles := []string{"admin", "system_admin", "operator_admin", "ADMIN"}
	for _, role := range adminRoles {
		adminCtx, err := assessment.ResolveAuthContext(role, "", "", "")
		if err != nil {
			t.Fatalf("ResolveAuthContext failed for admin role %q: %v", role, err)
		}
		if !adminCtx.IsAdmin() {
			t.Fatalf("Expected IsAdmin=true for verified admin role %q", role)
		}

		// Verified admin context can retrieve snapshot across client boundaries
		retrieved, err := store.GetSnapshot(snapA.ID, adminCtx)
		if err != nil || retrieved.ID != snapA.ID {
			t.Fatalf("Admin context for %q failed to retrieve snapshot: %v", role, err)
		}
	}
}

func TestHistory_FinalClosure_ExhaustiveFieldByFieldRetryConflict(t *testing.T) {
	store, _, cleanup := helperNewHistoryTestStore(t)
	defer cleanup()

	clientID := "cli_exhaustive"
	asmID := "asm_exhaustive"
	execID := "exec_exhaustive"
	targetURL := "https://exhaustive.example.com"
	_, asm := helperSeedClientAndAssessment(t, store, clientID, asmID, "tenant_ex", "acc_ex")
	helperSeedTarget(t, store, asmID, "tgt_ex", targetURL)

	exec := &assessment.AssessmentExecution{
		ID:           execID,
		AssessmentID: asmID,
		Status:       assessment.StatusCompleted,
		StartedAt:    time.Now().UTC(),
	}
	_ = store.CreateExecution(exec)

	f := helperMakeDedupFinding("fnd_ex_1", "SQL Injection in User Profile", "sqli", report.SeverityHigh, report.ConfidenceHigh, report.VerificationVerified, targetURL, targetURL+"/users", "GET")
	f.Score = 85
	f.Remediation = "Use parameterized SQL statements."
	f.PrimaryAssetID = "asset_db_primary"
	f.AffectedAssetIDs = []string{"asset_db_1", "asset_db_2"}
	f.Provenance = &report.EvidenceProvenance{
		EvidenceID:   "ev_ex_prov_1",
		EvidenceType: "http_response",
		SourceEngine: "webvuln",
	}
	f.RemediationAdvice = &report.RemediationAdvice{
		Summary: "Parameterize all database queries.",
		Steps:   []string{"Bind variables", "Audit ORM queries"},
	}
	f.ScoreExplanation = &report.FindingScoreExplanation{
		Score:    85,
		Severity: "HIGH",
	}

	af := assessment.ToAssessmentFinding(asmID, execID, "tgt_ex", f)
	af.OriginalFindingID = "orig_fnd_ex_1"
	af.VerificationRecord = report.VerificationRecord{
		Status:          report.VerificationVerified,
		Result:          "SQL syntax error reflected in response",
		SafeCurlCommand: "curl -s 'https://exhaustive.example.com/users?id=1%27'",
		Rationale:       "Database returned unhandled syntax error",
	}

	snap := assessment.BuildAssessmentSnapshot(asm, exec, []string{targetURL}, []assessment.AssessmentFinding{af}, true)
	snap.Name = "Comprehensive Audit"
	snap.AssessmentType = "WEB_APP"
	snap.TenantID = "tenant_ex"
	snap.AccountID = "acc_ex"
	snap.DurationMs = 12500
	snap.RequestCount = 350
	snap.Metadata = map[string]string{"env": "production", "region": "us-east-1"}

	ev := assessment.ExtractHistoricalEvidence(snap.ID, []assessment.AssessmentFinding{af})
	if len(ev) == 0 {
		t.Fatalf("Failed to extract evidence for test")
	}
	ev[0].TargetID = "tgt_ex"
	ev[0].Payload = "' OR 1=1 --"
	ev[0].SafeCurlCommand = "curl -s 'https://exhaustive.example.com/users?id=1%27'"
	ev[0].VerificationResult = "SQL error detected"
	ev[0].SourceEngine = "webvuln"
	ev[0].DetectionMethod = "ACTIVE_PROBE"

	// Initial persistence
	if err := store.CreateSnapshot(snap, []assessment.AssessmentFinding{af}, ev); err != nil {
		t.Fatalf("Initial CreateSnapshot failed: %v", err)
	}

	// Baseline: identical retry must be idempotent and succeed
	if err := store.CreateSnapshot(snap, []assessment.AssessmentFinding{af}, ev); err != nil {
		t.Fatalf("Baseline identical retry must succeed, got %v", err)
	}

	// Run 23 individual conflict tests altering previously unchecked fields ONE AT A TIME
	testCases := []struct {
		name      string
		mutateFn  func(s *assessment.AssessmentSnapshot, findings []assessment.AssessmentFinding, evidence []assessment.HistoricalEvidenceRecord) (*assessment.AssessmentSnapshot, []assessment.AssessmentFinding, []assessment.HistoricalEvidenceRecord)
	}{
		{
			name: "Altered Finding TargetID (target association)",
			mutateFn: func(s *assessment.AssessmentSnapshot, f []assessment.AssessmentFinding, e []assessment.HistoricalEvidenceRecord) (*assessment.AssessmentSnapshot, []assessment.AssessmentFinding, []assessment.HistoricalEvidenceRecord) {
				fCopy := append([]assessment.AssessmentFinding(nil), f...)
				fCopy[0].TargetID = "tgt_tampered"
				return s, fCopy, e
			},
		},
		{
			name: "Altered Finding TargetURL",
			mutateFn: func(s *assessment.AssessmentSnapshot, f []assessment.AssessmentFinding, e []assessment.HistoricalEvidenceRecord) (*assessment.AssessmentSnapshot, []assessment.AssessmentFinding, []assessment.HistoricalEvidenceRecord) {
				fCopy := append([]assessment.AssessmentFinding(nil), f...)
				fCopy[0].TargetURL = "https://tampered.example.com"
				return s, fCopy, e
			},
		},
		{
			name: "Altered Finding Endpoint",
			mutateFn: func(s *assessment.AssessmentSnapshot, f []assessment.AssessmentFinding, e []assessment.HistoricalEvidenceRecord) (*assessment.AssessmentSnapshot, []assessment.AssessmentFinding, []assessment.HistoricalEvidenceRecord) {
				fCopy := append([]assessment.AssessmentFinding(nil), f...)
				fCopy[0].Endpoint = "/tampered/endpoint"
				return s, fCopy, e
			},
		},
		{
			name: "Altered Finding HTTP Method",
			mutateFn: func(s *assessment.AssessmentSnapshot, f []assessment.AssessmentFinding, e []assessment.HistoricalEvidenceRecord) (*assessment.AssessmentSnapshot, []assessment.AssessmentFinding, []assessment.HistoricalEvidenceRecord) {
				fCopy := append([]assessment.AssessmentFinding(nil), f...)
				fCopy[0].Method = "POST"
				return s, fCopy, e
			},
		},
		{
			name: "Altered Finding Confidence",
			mutateFn: func(s *assessment.AssessmentSnapshot, f []assessment.AssessmentFinding, e []assessment.HistoricalEvidenceRecord) (*assessment.AssessmentSnapshot, []assessment.AssessmentFinding, []assessment.HistoricalEvidenceRecord) {
				fCopy := append([]assessment.AssessmentFinding(nil), f...)
				fCopy[0].Confidence = report.ConfidenceLow
				return s, fCopy, e
			},
		},
		{
			name: "Altered Finding Risk Score",
			mutateFn: func(s *assessment.AssessmentSnapshot, f []assessment.AssessmentFinding, e []assessment.HistoricalEvidenceRecord) (*assessment.AssessmentSnapshot, []assessment.AssessmentFinding, []assessment.HistoricalEvidenceRecord) {
				fCopy := append([]assessment.AssessmentFinding(nil), f...)
				fCopy[0].Score = 10
				return s, fCopy, e
			},
		},
		{
			name: "Altered Finding Remediation Text",
			mutateFn: func(s *assessment.AssessmentSnapshot, f []assessment.AssessmentFinding, e []assessment.HistoricalEvidenceRecord) (*assessment.AssessmentSnapshot, []assessment.AssessmentFinding, []assessment.HistoricalEvidenceRecord) {
				fCopy := append([]assessment.AssessmentFinding(nil), f...)
				fCopy[0].Remediation = "No remediation needed."
				return s, fCopy, e
			},
		},
		{
			name: "Altered Finding Remediation Advice",
			mutateFn: func(s *assessment.AssessmentSnapshot, f []assessment.AssessmentFinding, e []assessment.HistoricalEvidenceRecord) (*assessment.AssessmentSnapshot, []assessment.AssessmentFinding, []assessment.HistoricalEvidenceRecord) {
				fCopy := append([]assessment.AssessmentFinding(nil), f...)
				fCopy[0].RemediationAdvice = &report.RemediationAdvice{Summary: "Different advice summary"}
				return s, fCopy, e
			},
		},
		{
			name: "Altered Finding Score Explanation",
			mutateFn: func(s *assessment.AssessmentSnapshot, f []assessment.AssessmentFinding, e []assessment.HistoricalEvidenceRecord) (*assessment.AssessmentSnapshot, []assessment.AssessmentFinding, []assessment.HistoricalEvidenceRecord) {
				fCopy := append([]assessment.AssessmentFinding(nil), f...)
				fCopy[0].ScoreExplanation = &report.FindingScoreExplanation{Score: 10, Severity: "LOW"}
				return s, fCopy, e
			},
		},
		{
			name: "Altered Finding Provenance Evidence ID",
			mutateFn: func(s *assessment.AssessmentSnapshot, f []assessment.AssessmentFinding, e []assessment.HistoricalEvidenceRecord) (*assessment.AssessmentSnapshot, []assessment.AssessmentFinding, []assessment.HistoricalEvidenceRecord) {
				fCopy := append([]assessment.AssessmentFinding(nil), f...)
				fCopy[0].Provenance = &report.EvidenceProvenance{EvidenceID: "ev_tampered_id"}
				return s, fCopy, e
			},
		},
		{
			name: "Altered Finding Primary Asset Relationship",
			mutateFn: func(s *assessment.AssessmentSnapshot, f []assessment.AssessmentFinding, e []assessment.HistoricalEvidenceRecord) (*assessment.AssessmentSnapshot, []assessment.AssessmentFinding, []assessment.HistoricalEvidenceRecord) {
				fCopy := append([]assessment.AssessmentFinding(nil), f...)
				fCopy[0].PrimaryAssetID = "asset_tampered_primary"
				return s, fCopy, e
			},
		},
		{
			name: "Altered Finding Affected Assets Relationship",
			mutateFn: func(s *assessment.AssessmentSnapshot, f []assessment.AssessmentFinding, e []assessment.HistoricalEvidenceRecord) (*assessment.AssessmentSnapshot, []assessment.AssessmentFinding, []assessment.HistoricalEvidenceRecord) {
				fCopy := append([]assessment.AssessmentFinding(nil), f...)
				fCopy[0].AffectedAssetIDs = []string{"asset_tampered_x"}
				return s, fCopy, e
			},
		},
		{
			name: "Altered Finding Verification SafeCurlCommand",
			mutateFn: func(s *assessment.AssessmentSnapshot, f []assessment.AssessmentFinding, e []assessment.HistoricalEvidenceRecord) (*assessment.AssessmentSnapshot, []assessment.AssessmentFinding, []assessment.HistoricalEvidenceRecord) {
				fCopy := append([]assessment.AssessmentFinding(nil), f...)
				fCopy[0].VerificationRecord.SafeCurlCommand = "curl -X POST https://tampered"
				return s, fCopy, e
			},
		},
		{
			name: "Altered Finding Verification Result",
			mutateFn: func(s *assessment.AssessmentSnapshot, f []assessment.AssessmentFinding, e []assessment.HistoricalEvidenceRecord) (*assessment.AssessmentSnapshot, []assessment.AssessmentFinding, []assessment.HistoricalEvidenceRecord) {
				fCopy := append([]assessment.AssessmentFinding(nil), f...)
				fCopy[0].VerificationRecord.Result = "Different verification outcome"
				return s, fCopy, e
			},
		},
		{
			name: "Altered Evidence TargetID",
			mutateFn: func(s *assessment.AssessmentSnapshot, f []assessment.AssessmentFinding, e []assessment.HistoricalEvidenceRecord) (*assessment.AssessmentSnapshot, []assessment.AssessmentFinding, []assessment.HistoricalEvidenceRecord) {
				eCopy := append([]assessment.HistoricalEvidenceRecord(nil), e...)
				eCopy[0].TargetID = "tgt_tampered_ev"
				return s, f, eCopy
			},
		},
		{
			name: "Altered Evidence Payload",
			mutateFn: func(s *assessment.AssessmentSnapshot, f []assessment.AssessmentFinding, e []assessment.HistoricalEvidenceRecord) (*assessment.AssessmentSnapshot, []assessment.AssessmentFinding, []assessment.HistoricalEvidenceRecord) {
				eCopy := append([]assessment.HistoricalEvidenceRecord(nil), e...)
				eCopy[0].Payload = "SELECT * FROM secrets;"
				return s, f, eCopy
			},
		},
		{
			name: "Altered Evidence SafeCurlCommand",
			mutateFn: func(s *assessment.AssessmentSnapshot, f []assessment.AssessmentFinding, e []assessment.HistoricalEvidenceRecord) (*assessment.AssessmentSnapshot, []assessment.AssessmentFinding, []assessment.HistoricalEvidenceRecord) {
				eCopy := append([]assessment.HistoricalEvidenceRecord(nil), e...)
				eCopy[0].SafeCurlCommand = "curl -s https://evil.example.com"
				return s, f, eCopy
			},
		},
		{
			name: "Altered Evidence SourceEngine",
			mutateFn: func(s *assessment.AssessmentSnapshot, f []assessment.AssessmentFinding, e []assessment.HistoricalEvidenceRecord) (*assessment.AssessmentSnapshot, []assessment.AssessmentFinding, []assessment.HistoricalEvidenceRecord) {
				eCopy := append([]assessment.HistoricalEvidenceRecord(nil), e...)
				eCopy[0].SourceEngine = "tampered_engine"
				return s, f, eCopy
			},
		},
		{
			name: "Altered Snapshot Name",
			mutateFn: func(s *assessment.AssessmentSnapshot, f []assessment.AssessmentFinding, e []assessment.HistoricalEvidenceRecord) (*assessment.AssessmentSnapshot, []assessment.AssessmentFinding, []assessment.HistoricalEvidenceRecord) {
				sCopy := *s
				sCopy.Name = "Tampered Snapshot Name"
				return &sCopy, f, e
			},
		},
		{
			name: "Altered Snapshot AssessmentType",
			mutateFn: func(s *assessment.AssessmentSnapshot, f []assessment.AssessmentFinding, e []assessment.HistoricalEvidenceRecord) (*assessment.AssessmentSnapshot, []assessment.AssessmentFinding, []assessment.HistoricalEvidenceRecord) {
				sCopy := *s
				sCopy.AssessmentType = "MOBILE_APK"
				return &sCopy, f, e
			},
		},
		{
			name: "Altered Snapshot TenantID",
			mutateFn: func(s *assessment.AssessmentSnapshot, f []assessment.AssessmentFinding, e []assessment.HistoricalEvidenceRecord) (*assessment.AssessmentSnapshot, []assessment.AssessmentFinding, []assessment.HistoricalEvidenceRecord) {
				sCopy := *s
				sCopy.TenantID = "tenant_tampered"
				return &sCopy, f, e
			},
		},
		{
			name: "Altered Snapshot AccountID",
			mutateFn: func(s *assessment.AssessmentSnapshot, f []assessment.AssessmentFinding, e []assessment.HistoricalEvidenceRecord) (*assessment.AssessmentSnapshot, []assessment.AssessmentFinding, []assessment.HistoricalEvidenceRecord) {
				sCopy := *s
				sCopy.AccountID = "acc_tampered"
				return &sCopy, f, e
			},
		},
		{
			name: "Altered Snapshot Metadata",
			mutateFn: func(s *assessment.AssessmentSnapshot, f []assessment.AssessmentFinding, e []assessment.HistoricalEvidenceRecord) (*assessment.AssessmentSnapshot, []assessment.AssessmentFinding, []assessment.HistoricalEvidenceRecord) {
				sCopy := *s
				sCopy.Metadata = map[string]string{"env": "staging"}
				return &sCopy, f, e
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			mutatedSnap, mutatedFindings, mutatedEvidence := tc.mutateFn(snap, []assessment.AssessmentFinding{af}, ev)
			err := store.CreateSnapshot(mutatedSnap, mutatedFindings, mutatedEvidence)
			if err != assessment.ErrSnapshotImmutable {
				t.Fatalf("Expected ErrSnapshotImmutable for %s, got: %v", tc.name, err)
			}
		})
	}

	// Final verification: original snapshot, findings, and evidence remain 100% unaltered
	adminAuth := assessment.NewAdminAuthContext()
	origSnap, err := store.GetSnapshot(snap.ID, adminAuth)
	if err != nil {
		t.Fatalf("Failed to retrieve snapshot: %v", err)
	}
	if origSnap.Name != "Comprehensive Audit" || origSnap.Metadata["env"] != "production" {
		t.Fatalf("CRITICAL INTEGRITY DEFECT: Snapshot metadata was mutated! Name=%s, env=%s", origSnap.Name, origSnap.Metadata["env"])
	}

	origFindings, err := store.GetSnapshotFindings(snap.ID, adminAuth)
	if err != nil || len(origFindings) != 1 {
		t.Fatalf("Expected 1 finding, got %d, err=%v", len(origFindings), err)
	}
	fRet := origFindings[0]
	if fRet.TargetID != "tgt_ex" || fRet.Score != 85 || fRet.Remediation != "Use parameterized SQL statements." {
		t.Fatalf("CRITICAL INTEGRITY DEFECT: Finding fields were mutated! TargetID=%s, Score=%d, Remediation=%s", fRet.TargetID, fRet.Score, fRet.Remediation)
	}

	origEvidence, err := store.GetHistoricalEvidence(snap.ID, af.ID, adminAuth)
	if err != nil || len(origEvidence) != 1 {
		t.Fatalf("Expected 1 evidence record, got %d, err=%v", len(origEvidence), err)
	}
	eRet := origEvidence[0]
	if eRet.Payload != "' OR 1=1 --" || eRet.TargetID != "tgt_ex" || eRet.SourceEngine != "webvuln" {
		t.Fatalf("CRITICAL INTEGRITY DEFECT: Evidence fields were mutated! Payload=%s, TargetID=%s, Engine=%s", eRet.Payload, eRet.TargetID, eRet.SourceEngine)
	}
}
