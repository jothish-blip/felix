package assessment

import (
	"path/filepath"
	"strings"
	"testing"
	"time"

	"felix/pkg/report"
)

// TestAssessmentFinding_ProvenanceEnrichment tests that ToAssessmentFinding enriches
// the finding's Provenance with assessment, execution, and target lineage context.
func TestAssessmentFinding_ProvenanceEnrichment(t *testing.T) {
	asmID := "asm-prov-001"
	execID := "exec-prov-001"
	targetID := "tgt-prov-001"

	rawFinding := report.Finding{
		ID:          "fnd_original_123",
		RuleID:      "API-JWT-EXPOSURE",
		Category:    "jwt-exposure",
		Severity:    report.SeverityHigh,
		Confidence:  report.ConfidenceHigh,
		Target:      "https://api.example.com",
		Endpoint:    "https://api.example.com/v1/auth",
		Method:      "GET",
		Description: "JWT token structure exposed in script asset",
		Evidence:    "ey[REDACTED_JWT]",
		Provenance: &report.EvidenceProvenance{
			EvidenceID:       "ev_jwt_original",
			EvidenceType:     "token_artifact",
			SourceEngine:     report.SourceAPI,
			RuleID:           "API-JWT-EXPOSURE",
			FindingID:        "fnd_original_123",
			Location:         "https://api.example.com/v1/auth",
			CollectionMethod: "active_probe",
			ContentDigest:    "sha256:abcdef1234567890",
		},
	}

	af := ToAssessmentFinding(asmID, execID, targetID, rawFinding)

	if af.Provenance == nil {
		t.Fatal("expected AssessmentFinding to have Provenance")
	}
	if af.Provenance.AssessmentID != asmID {
		t.Errorf("expected Provenance.AssessmentID %s, got: %s", asmID, af.Provenance.AssessmentID)
	}
	if af.Provenance.ExecutionID != execID {
		t.Errorf("expected Provenance.ExecutionID %s, got: %s", execID, af.Provenance.ExecutionID)
	}
	if af.Provenance.TargetID != targetID {
		t.Errorf("expected Provenance.TargetID %s, got: %s", targetID, af.Provenance.TargetID)
	}
	if af.Provenance.FindingID != rawFinding.ID {
		t.Errorf("expected Provenance.FindingID %s, got: %s", rawFinding.ID, af.Provenance.FindingID)
	}
	if af.EvidenceDetails.Provenance == nil {
		t.Fatal("expected EvidenceDetails.Provenance to be synchronized")
	}
	if af.EvidenceDetails.Provenance.AssessmentID != asmID {
		t.Errorf("expected EvidenceDetails.Provenance.AssessmentID %s, got: %s", asmID, af.EvidenceDetails.Provenance.AssessmentID)
	}
}

// TestAssessmentFinding_ProvenanceSQLitePersistence tests that Provenance metadata
// round-trips accurately through SQLite persistence and rehydration.
func TestAssessmentFinding_ProvenanceSQLitePersistence(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "felix_prov_test.db")
	store, err := NewSQLiteStore(dbPath)
	if err != nil {
		t.Fatalf("NewSQLiteStore failed: %v", err)
	}
	defer store.Close()

	now := time.Now().UTC()
	client := Client{
		ID:        "client-prov-1",
		Name:      "Provenance Testing Client",
		CreatedAt: now,
		UpdatedAt: now,
	}
	if err := store.CreateClient(&client); err != nil {
		t.Fatalf("CreateClient failed: %v", err)
	}

	asm := Assessment{
		ID:        "asm-prov-99",
		Ref:       "ASM-2026-PROV-99",
		ClientID:  client.ID,
		Name:      "Evidence Provenance Verification",
		Status:    StatusRunning,
		CreatedAt: now,
		UpdatedAt: now,
	}
	if err := store.CreateAssessment(&asm); err != nil {
		t.Fatalf("CreateAssessment failed: %v", err)
	}

	target := AssessmentTarget{
		ID:           "tgt-prov-99",
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
		ID:           "exec-prov-99",
		AssessmentID: asm.ID,
		Status:       StatusRunning,
		StartedAt:    now,
	}
	if err := store.CreateExecution(&exec); err != nil {
		t.Fatalf("CreateExecution failed: %v", err)
	}

	prov := report.NewEvidenceProvenance(
		report.SourceSecrets,
		"SEC-STRIPE-KEY",
		"fnd_prov_test_001",
		"ast_asset_001",
		"secret_pattern",
		"https://api.example.com/assets/app.js:105",
		"static_pattern_analysis",
		"const stripe = 'sk_live_[REDACTED]';",
	)
	prov.AssessmentID = asm.ID
	prov.ExecutionID = exec.ID
	prov.TargetID = target.ID
	prov.VerificationContext = "Safe inspection of client bundle without sending live probe"

	af := AssessmentFinding{
		ID:                 ComputeAssessmentFindingID(asm.ID, "fnd_prov_test_001"),
		AssessmentID:       asm.ID,
		ExecutionID:        exec.ID,
		TargetID:           target.ID,
		OriginalFindingID:  "fnd_prov_test_001",
		RuleID:             "SEC-STRIPE-KEY",
		Status:             report.FindingStatusConfirmed,
		PrimaryAssetID:     "ast_asset_001",
		AffectedAssetIDs:   []string{"ast_asset_001"},
		Title:              "Stripe Secret Key in Client Bundle",
		Category:           "stripe-key",
		Severity:           report.SeverityCritical,
		Confidence:         report.ConfidenceHigh,
		VerificationStatus: report.VerificationVerified,
		TargetURL:          "https://api.example.com",
		Endpoint:           "https://api.example.com/assets/app.js",
		Method:             "GET",
		Fingerprint:        "fp-prov-test-001",
		Score:              90,
		Provenance:         &prov,
		EvidenceDetails: report.EvidenceDetails{
			Observation:     "sk_live_[REDACTED] pattern found",
			Location:        "https://api.example.com/assets/app.js:105",
			DetectionMethod: "static_pattern_analysis",
			Provenance:      &prov,
		},
		CreatedAt: now,
	}

	// 1. Save finding with Provenance
	if err := store.SaveFindings([]AssessmentFinding{af}); err != nil {
		t.Fatalf("SaveFindings failed: %v", err)
	}

	// 2. Retrieve findings from SQLite store
	loaded, err := store.GetFindings(asm.ID, exec.ID)
	if err != nil {
		t.Fatalf("GetFindings failed: %v", err)
	}
	if len(loaded) != 1 {
		t.Fatalf("expected 1 finding loaded, got %d", len(loaded))
	}

	rehydrated := loaded[0]

	// 3. Verify that Provenance was fully rehydrated
	if rehydrated.Provenance == nil {
		t.Fatal("expected rehydrated.Provenance to be non-nil")
	}
	if rehydrated.EvidenceDetails.Provenance == nil {
		t.Fatal("expected rehydrated.EvidenceDetails.Provenance to be non-nil")
	}

	if rehydrated.Provenance.EvidenceID != prov.EvidenceID {
		t.Errorf("expected EvidenceID %s, got: %s", prov.EvidenceID, rehydrated.Provenance.EvidenceID)
	}
	if rehydrated.Provenance.EvidenceType != "secret_pattern" {
		t.Errorf("expected EvidenceType secret_pattern, got: %s", rehydrated.Provenance.EvidenceType)
	}
	if rehydrated.Provenance.SourceEngine != report.SourceSecrets {
		t.Errorf("expected SourceEngine %s, got: %s", report.SourceSecrets, rehydrated.Provenance.SourceEngine)
	}
	if rehydrated.Provenance.RuleID != "SEC-STRIPE-KEY" {
		t.Errorf("expected RuleID SEC-STRIPE-KEY, got: %s", rehydrated.Provenance.RuleID)
	}
	if rehydrated.Provenance.FindingID != "fnd_prov_test_001" {
		t.Errorf("expected FindingID fnd_prov_test_001, got: %s", rehydrated.Provenance.FindingID)
	}
	if rehydrated.Provenance.AssetID != "ast_asset_001" {
		t.Errorf("expected AssetID ast_asset_001, got: %s", rehydrated.Provenance.AssetID)
	}
	if rehydrated.Provenance.AssessmentID != asm.ID {
		t.Errorf("expected AssessmentID %s, got: %s", asm.ID, rehydrated.Provenance.AssessmentID)
	}
	if rehydrated.Provenance.ExecutionID != exec.ID {
		t.Errorf("expected ExecutionID %s, got: %s", exec.ID, rehydrated.Provenance.ExecutionID)
	}
	if rehydrated.Provenance.TargetID != target.ID {
		t.Errorf("expected TargetID %s, got: %s", target.ID, rehydrated.Provenance.TargetID)
	}
	if rehydrated.Provenance.Location != "https://api.example.com/assets/app.js:105" {
		t.Errorf("expected Location https://api.example.com/assets/app.js:105, got: %s", rehydrated.Provenance.Location)
	}
	if rehydrated.Provenance.VerificationContext != "Safe inspection of client bundle without sending live probe" {
		t.Errorf("expected VerificationContext preserved, got: %s", rehydrated.Provenance.VerificationContext)
	}
	if !strings.HasPrefix(rehydrated.Provenance.ContentDigest, "sha256:") {
		t.Errorf("expected ContentDigest with sha256: prefix, got: %s", rehydrated.Provenance.ContentDigest)
	}
}
