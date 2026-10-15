package assessment

import (
	"path/filepath"
	"strings"
	"testing"
	"time"

	"felix/pkg/report"
)

func TestAssessmentFinding_DeterministicIdentity(t *testing.T) {
	asmID := "asm-audit-2026-001"
	execID := "exec-001"
	targetID := "tgt-001"

	rawFinding := report.Finding{
		ID:          "API-CORS-WILDCARD",
		RuleID:      "API-CORS-WILDCARD",
		Category:    "cors-wildcard",
		Severity:    report.SeverityInfo,
		Confidence:  report.ConfidenceHigh,
		Target:      "https://api.example.com",
		Endpoint:    "https://api.example.com/v1/users",
		Method:      "GET",
		Fingerprint: "fp-cors-users-get",
	}

	f1 := ToAssessmentFinding(asmID, execID, targetID, rawFinding)
	f2 := ToAssessmentFinding(asmID, execID, targetID, rawFinding)

	if f1.ID == "" {
		t.Fatalf("expected non-empty assessment finding ID")
	}
	if !strings.HasPrefix(f1.ID, "fnd_") {
		t.Errorf("expected finding ID prefix 'fnd_', got %s", f1.ID)
	}
	if f1.ID != f2.ID {
		t.Errorf("expected deterministic finding ID across calls: %s != %s", f1.ID, f2.ID)
	}

	// Distinct issue separation: endpoint change
	rawEndpointDiff := rawFinding
	rawEndpointDiff.Endpoint = "https://api.example.com/v1/orders"
	rawEndpointDiff.ID = "API-CORS-ORDERS"
	fEndpointDiff := ToAssessmentFinding(asmID, execID, targetID, rawEndpointDiff)
	if f1.ID == fEndpointDiff.ID {
		t.Errorf("expected different finding IDs for different endpoints")
	}

	// Assessment isolation: different assessment ID produces distinct finding ID
	fAsmDiff := ToAssessmentFinding("asm-audit-2026-002", execID, targetID, rawFinding)
	if f1.ID == fAsmDiff.ID {
		t.Errorf("expected different finding IDs for different assessments")
	}
}

func TestAssessmentFinding_StorePersistenceAndUpsert(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "felix_test.db")
	store, err := NewSQLiteStore(dbPath)
	if err != nil {
		t.Fatalf("NewSQLiteStore failed: %v", err)
	}
	defer store.Close()

	// 1. Setup client and assessment
	now := time.Now().UTC()
	client := Client{
		ID:        "client-1",
		Name:      "Acme Security Test",
		CreatedAt: now,
		UpdatedAt: now,
	}
	if err := store.CreateClient(&client); err != nil {
		t.Fatalf("CreateClient failed: %v", err)
	}

	asm := Assessment{
		ID:        "asm-1",
		Ref:       "ASM-2026-FND-01",
		ClientID:  client.ID,
		Name:      "Finding Model Audit",
		Status:    StatusRunning,
		CreatedAt: now,
		UpdatedAt: now,
	}
	if err := store.CreateAssessment(&asm); err != nil {
		t.Fatalf("CreateAssessment failed: %v", err)
	}

	target := AssessmentTarget{
		ID:           "tgt-1",
		AssessmentID: asm.ID,
		TargetURL:    "https://api.example.com",
		TargetType:   TargetAPIBaseURL,
		ScopeStatus:  "APPROVED",
		CreatedAt:    now,
	}
	if err := store.AddTarget(&target); err != nil {
		t.Fatalf("AddTarget failed: %v", err)
	}

	exec := AssessmentExecution{
		ID:           "exec-1",
		AssessmentID: asm.ID,
		Status:       StatusRunning,
		StartedAt:    now,
	}
	if err := store.CreateExecution(&exec); err != nil {
		t.Fatalf("CreateExecution failed: %v", err)
	}

	// 2. Create AssessmentFinding with Phase 1.3 fields
	rawFinding := report.Finding{
		ID:               "SEC-AWS-KEY-001",
		RuleID:           "SEC-AWS-ACCESS-KEY",
		Status:           report.FindingStatusSuspected,
		PrimaryAssetID:   "ast_host_1234",
		AffectedAssetIDs: []string{"ast_host_1234", "ast_app_5678"},
		Title:            "Hardcoded AWS Key",
		Category:         "aws-access-key",
		Severity:         report.SeverityHigh,
		Confidence:       report.ConfidenceMedium,
		Target:           "https://api.example.com",
		Endpoint:         "https://api.example.com/assets/app.js",
		Method:           "GET",
		Fingerprint:      "fp-aws-key-app-js",
		Score:            50,
		Remediation:      "Revoke and rotate AWS credential in IAM console.",
	}

	fnd := ToAssessmentFinding(asm.ID, exec.ID, target.ID, rawFinding)

	// 3. Initial Save
	if err := store.SaveFindings([]AssessmentFinding{fnd}); err != nil {
		t.Fatalf("initial SaveFindings failed: %v", err)
	}

	fetched, err := store.GetFindings(asm.ID, exec.ID)
	if err != nil {
		t.Fatalf("GetFindings failed: %v", err)
	}
	if len(fetched) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(fetched))
	}

	f := fetched[0]
	if f.ID != fnd.ID {
		t.Errorf("finding ID mismatch: got %s, want %s", f.ID, fnd.ID)
	}
	if f.RuleID != "SEC-AWS-ACCESS-KEY" {
		t.Errorf("RuleID mismatch: got %s, want SEC-AWS-ACCESS-KEY", f.RuleID)
	}
	if f.Status != report.FindingStatusSuspected {
		t.Errorf("Status mismatch: got %s, want SUSPECTED", f.Status)
	}
	if f.PrimaryAssetID != "ast_host_1234" {
		t.Errorf("PrimaryAssetID mismatch: got %s, want ast_host_1234", f.PrimaryAssetID)
	}
	if len(f.AffectedAssetIDs) != 2 || f.AffectedAssetIDs[0] != "ast_host_1234" || f.AffectedAssetIDs[1] != "ast_app_5678" {
		t.Errorf("AffectedAssetIDs mismatch: got %+v", f.AffectedAssetIDs)
	}
	if f.Remediation != rawFinding.Remediation {
		t.Errorf("Remediation mismatch: got %s", f.Remediation)
	}

	// 4. Idempotent Upsert Verification (Verification Engine promotes finding to CONFIRMED / VERIFIED)
	updatedFinding := fnd
	updatedFinding.VerificationStatus = report.VerificationVerified
	updatedFinding.Status = report.FindingStatusConfirmed
	updatedFinding.Confidence = report.ConfidenceHigh
	updatedFinding.Score = 80
	updatedFinding.VerificationRecord = report.VerificationRecord{
		Status: report.VerificationVerified,
		Result: "Token validity confirmed via read-only STS GetCallerIdentity",
	}

	// Re-saving the same deterministic finding ID must NOT fail with UNIQUE constraint
	if err := store.SaveFindings([]AssessmentFinding{updatedFinding}); err != nil {
		t.Fatalf("idempotent re-save of finding failed: %v", err)
	}

	// Verify updated record
	fetchedAfterUpdate, err := store.GetFindings(asm.ID, exec.ID)
	if err != nil {
		t.Fatalf("GetFindings after update failed: %v", err)
	}
	if len(fetchedAfterUpdate) != 1 {
		t.Fatalf("expected 1 finding after update (no duplicates), got %d", len(fetchedAfterUpdate))
	}

	fUpdated := fetchedAfterUpdate[0]
	if fUpdated.VerificationStatus != report.VerificationVerified {
		t.Errorf("expected updated verification status VERIFIED, got %s", fUpdated.VerificationStatus)
	}
	if fUpdated.Status != report.FindingStatusConfirmed {
		t.Errorf("expected updated status CONFIRMED, got %s", fUpdated.Status)
	}
	if fUpdated.Score != 80 {
		t.Errorf("expected updated score 80, got %d", fUpdated.Score)
	}
	if fUpdated.Confidence != report.ConfidenceHigh {
		t.Errorf("expected updated confidence HIGH, got %s", fUpdated.Confidence)
	}
}
