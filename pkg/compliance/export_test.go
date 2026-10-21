package compliance

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func createSampleDossierForExport(t *testing.T, assessmentID string) (*ComplianceDossier, ComplianceStore) {
	t.Helper()
	store := setupTestDossierStore(t)

	clock := NewMockClock(time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC))
	svc := NewDossierService(store, clock)
	baseTime := clock.Now().UTC()

	evalRes := sampleEvaluationWithAllStates(assessmentID)
	key, _ := GenerateIntegrityKey("export-test-key")
	kp, _ := NewStaticKeyProvider(key)

	if err := store.SaveEvaluationResultWithKey(evalRes, kp); err != nil {
		t.Fatalf("failed saving evaluation result: %v", err)
	}

	remID := "rem:exp:1"
	rec := &RemediationRecord{
		ID:           remID,
		FindingID:    "F-BOLA-01",
		AssessmentID: assessmentID,
		CatalogID:    "nist-sp800-53-sample:5.1.0",
		ControlID:    "AC-3",
		Severity:     "HIGH",
		AssignedAt:   baseTime,
		SLAStartTime: baseTime,
		Deadline:     baseTime.Add(7 * 24 * time.Hour),
		Status:       RemediationStatusOpen,
		CreatedAt:    baseTime,
	}
	_ = store.SaveRemediationRecordWithKey(rec, &RemediationHistoryEvent{
		ID:            GenerateRemediationEventID(remID),
		RemediationID: remID,
		EventType:     HistoryEventAssigned,
		ToStatus:      RemediationStatusOpen,
		Timestamp:     baseTime,
	}, kp)

	dossierReq := GenerateDossierRequest{
		AssessmentID:       assessmentID,
		CatalogID:          "nist-sp800-53-sample",
		IncludeRemediation: true,
		IncludeSLA:         true,
		IncludeMTTR:        true,
		KeyProvider:        kp,
		FelixVersion:       "1.0.0-test",
		SourceRevision:     "git-commit-abc1234",
	}

	dossier, err := svc.GenerateDossier(context.Background(), dossierReq)
	if err != nil {
		t.Fatalf("failed generating source dossier: %v", err)
	}

	return dossier, store
}

// ============================================================================
// 1. NORMALIZED JSON EXPORT TESTS
// ============================================================================

func TestExport_NormalizedJSON_AllStatesAndComponents(t *testing.T) {
	dossier, store := createSampleDossierForExport(t, "ASM-EXP-NORM-01")
	defer store.Close()

	clock := NewMockClock(time.Date(2026, 10, 21, 14, 0, 0, 0, time.UTC))
	svc := NewExportService(store, clock)

	req := ExportRequest{
		Dossier:            dossier,
		Format:             ExportFormatNormalizedJSON,
		IncludeRemediation: true,
		IncludeSLA:         true,
		IncludeMTTR:        true,
		FelixVersion:       "1.0.0-test",
		SourceRevision:     "git-commit-abc1234",
	}

	exp, err := svc.GenerateNormalizedExport(context.Background(), req)
	if err != nil {
		t.Fatalf("GenerateNormalizedExport failed: %v", err)
	}

	// Schema and Metadata
	if exp.SchemaVersion != CurrentNormalizedExportSchemaVersion {
		t.Errorf("expected schema version %s, got %s", CurrentNormalizedExportSchemaVersion, exp.SchemaVersion)
	}
	if exp.ExportMetadata.Format != ExportFormatNormalizedJSON {
		t.Errorf("expected format %s, got %s", ExportFormatNormalizedJSON, exp.ExportMetadata.Format)
	}
	if exp.ExportMetadata.ExportID == "" {
		t.Error("expected non-empty export ID")
	}

	// All 7 states preserved
	statesSeen := make(map[EvaluationState]bool)
	for _, c := range exp.Controls {
		statesSeen[c.EvaluationState] = true
	}

	expectedStates := []EvaluationState{
		StateCompliant,
		StateNonCompliant,
		StatePartiallyCompliant,
		StateNotAssessed,
		StateInsufficientEvidence,
		StateNotApplicable,
		StateError,
	}

	for _, s := range expectedStates {
		if !statesSeen[s] {
			t.Errorf("missing expected evaluation state %s in exported controls", s)
		}
	}

	// Quantitative summary matches control breakdown
	if exp.Summary.TotalControls != len(exp.Controls) {
		t.Errorf("summary total controls %d != %d", exp.Summary.TotalControls, len(exp.Controls))
	}
	if exp.Summary.CompliantCount != 1 || exp.Summary.NonCompliantCount != 1 || exp.Summary.PartiallyCompliantCount != 1 {
		t.Errorf("unexpected summary counts: compliant=%d, non_compliant=%d, partially_compliant=%d",
			exp.Summary.CompliantCount, exp.Summary.NonCompliantCount, exp.Summary.PartiallyCompliantCount)
	}

	// Evidence & Remediation
	if len(exp.Findings) != 2 {
		t.Errorf("expected 2 findings, got %d", len(exp.Findings))
	}
	if len(exp.Remediation) != 1 {
		t.Errorf("expected 1 remediation record, got %d", len(exp.Remediation))
	}

	// Canonical SHA-256 Digest
	if !strings.HasPrefix(exp.LogicalDigest, "sha256:") || len(exp.LogicalDigest) != 71 {
		t.Errorf("invalid logical digest format %q", exp.LogicalDigest)
	}

	// ValidateNormalizedExport passes
	if err := ValidateNormalizedExport(exp); err != nil {
		t.Fatalf("ValidateNormalizedExport failed: %v", err)
	}
}

// ============================================================================
// 2. LOGICAL DIGEST DETERMINISM & SENSITIVITY
// ============================================================================

func TestExport_NormalizedDigest_DeterminismAndSensitivity(t *testing.T) {
	dossier, store := createSampleDossierForExport(t, "ASM-EXP-DIGEST-01")
	defer store.Close()

	clock := NewMockClock(time.Date(2026, 10, 21, 14, 0, 0, 0, time.UTC))
	svc := NewExportService(store, clock)

	exp, err := svc.GenerateNormalizedExport(context.Background(), ExportRequest{
		Dossier:            dossier,
		IncludeRemediation: true,
	})
	if err != nil {
		t.Fatalf("failed generating export: %v", err)
	}

	origDigest := exp.LogicalDigest

	// 1. Volatile fields mutation must NOT change digest
	volatileMutated := *exp
	volatileMutated.ExportMetadata.ExportID = "EXPORT-NEW-UUID"
	volatileMutated.ExportMetadata.ExportedAt = time.Now().Add(10 * time.Hour)
	volatileMutated.ExportMetadata.FelixVersion = "9.9.9"
	volatileMutated.ExportMetadata.SourceRevision = "rev-xyz987"
	volatileMutated.LogicalDigest = ""

	newDigest := ComputeNormalizedExportDigest(&volatileMutated)
	if newDigest != origDigest {
		t.Errorf("volatile metadata mutation changed logical digest: orig=%s, new=%s", origDigest, newDigest)
	}

	// 2. Material content mutation MUST change digest
	// A: Change evaluation state
	contentMutated1 := *exp
	contentMutated1.Controls = make([]ExportControlRecord, len(exp.Controls))
	copy(contentMutated1.Controls, exp.Controls)
	contentMutated1.Controls[0].EvaluationState = StateError

	mutDigest1 := ComputeNormalizedExportDigest(&contentMutated1)
	if mutDigest1 == origDigest {
		t.Error("changing control evaluation state did not change logical digest")
	}

	// B: Change finding severity
	contentMutated2 := *exp
	contentMutated2.Findings = make([]ExportFindingRecord, len(exp.Findings))
	copy(contentMutated2.Findings, exp.Findings)
	contentMutated2.Findings[0].Severity = "CRITICAL"

	mutDigest2 := ComputeNormalizedExportDigest(&contentMutated2)
	if mutDigest2 == origDigest {
		t.Error("changing finding severity did not change logical digest")
	}
}

// ============================================================================
// 3. OSCAL ASSESSMENT RESULTS TESTS
// ============================================================================

func TestExport_OSCALAssessmentResults_StructureAndDeterminism(t *testing.T) {
	dossier, store := createSampleDossierForExport(t, "ASM-EXP-OSCAL-AR-01")
	defer store.Close()

	clock := NewMockClock(time.Date(2026, 10, 21, 14, 0, 0, 0, time.UTC))
	svc := NewExportService(store, clock)

	req := ExportRequest{
		Dossier:            dossier,
		IncludeRemediation: true,
	}

	doc1, err := svc.GenerateOSCALAssessmentResults(context.Background(), req)
	if err != nil {
		t.Fatalf("GenerateOSCALAssessmentResults failed: %v", err)
	}

	// Validate Root & Metadata
	if doc1.AssessmentResults.Metadata.OSCALVersion != CurrentOSCALVersion {
		t.Errorf("expected OSCAL version %s, got %s", CurrentOSCALVersion, doc1.AssessmentResults.Metadata.OSCALVersion)
	}
	if len(doc1.AssessmentResults.Results) == 0 {
		t.Fatal("expected at least one OSCAL result")
	}

	res1 := doc1.AssessmentResults.Results[0]
	if len(res1.ReviewedControls.ControlObjectiveSelections) != 7 {
		t.Errorf("expected 7 reviewed control objectives, got %d", len(res1.ReviewedControls.ControlObjectiveSelections))
	}

	// Verify UUIDv5 determinism: generating again with same data produces identical UUIDs
	doc2, err := svc.GenerateOSCALAssessmentResults(context.Background(), req)
	if err != nil {
		t.Fatalf("GenerateOSCALAssessmentResults second call failed: %v", err)
	}

	res2 := doc2.AssessmentResults.Results[0]
	if res1.UUID != res2.UUID {
		t.Errorf("result UUID not deterministic: %s != %s", res1.UUID, res2.UUID)
	}
	if len(res1.Observations) != len(res2.Observations) {
		t.Fatalf("observation count mismatch: %d != %d", len(res1.Observations), len(res2.Observations))
	}
	for i := range res1.Observations {
		if res1.Observations[i].UUID != res2.Observations[i].UUID {
			t.Errorf("observation UUID[%d] not deterministic: %s != %s", i, res1.Observations[i].UUID, res2.Observations[i].UUID)
		}
	}
	for i := range res1.Findings {
		if res1.Findings[i].UUID != res2.Findings[i].UUID {
			t.Errorf("finding UUID[%d] not deterministic: %s != %s", i, res1.Findings[i].UUID, res2.Findings[i].UUID)
		}
	}

	// Verify observation-finding links
	for _, f := range res1.Findings {
		for _, ro := range f.RelatedObservations {
			found := false
			for _, obs := range res1.Observations {
				if obs.UUID == ro.ObservationUUID {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("finding %s links to nonexistent observation UUID %s", f.UUID, ro.ObservationUUID)
			}
		}
	}

	// ValidateOSCALAssessmentResults passes
	if err := ValidateOSCALAssessmentResults(doc1); err != nil {
		t.Fatalf("ValidateOSCALAssessmentResults failed: %v", err)
	}
}

// ============================================================================
// 4. OSCAL POA&M TESTS
// ============================================================================

func TestExport_OSCALPOAM_Structure(t *testing.T) {
	dossier, store := createSampleDossierForExport(t, "ASM-EXP-OSCAL-POAM-01")
	defer store.Close()

	clock := NewMockClock(time.Date(2026, 10, 21, 14, 0, 0, 0, time.UTC))
	svc := NewExportService(store, clock)

	req := ExportRequest{
		Dossier:            dossier,
		IncludeRemediation: true,
	}

	doc, err := svc.GenerateOSCALPOAM(context.Background(), req)
	if err != nil {
		t.Fatalf("GenerateOSCALPOAM failed: %v", err)
	}

	poam := doc.PlanOfActionAndMilestones
	if poam.Metadata.OSCALVersion != CurrentOSCALVersion {
		t.Errorf("expected OSCAL version %s, got %s", CurrentOSCALVersion, poam.Metadata.OSCALVersion)
	}
	if len(poam.POAMItems) != 1 {
		t.Fatalf("expected 1 POAM item, got %d", len(poam.POAMItems))
	}

	item := poam.POAMItems[0]
	if len(item.Props) == 0 {
		t.Fatalf("expected props on POAM item, got 0")
	}
	hasDeadline := false
	for _, prop := range item.Props {
		if prop.Name == "scheduled-completion-date" && prop.Value != "" {
			hasDeadline = true
			break
		}
	}
	if !hasDeadline {
		t.Error("expected scheduled-completion-date prop on POAM item")
	}

	// ValidateOSCALPOAM passes
	if err := ValidateOSCALPOAM(doc); err != nil {
		t.Fatalf("ValidateOSCALPOAM failed: %v", err)
	}
}

// ============================================================================
// 5. VALIDATION REPORT & CORRUPTED / HOSTILE INPUTS
// ============================================================================

func TestExport_Validation_RejectionsAndReport(t *testing.T) {
	// A. Malformed JSON
	tempDir := t.TempDir()
	malformedPath := filepath.Join(tempDir, "malformed.json")
	if err := os.WriteFile(malformedPath, []byte(`{ "schema_version": "felix.compliance.export.v1", broken...`), 0600); err != nil {
		t.Fatal(err)
	}

	rep, err := ValidateExportFile(malformedPath)
	if err != nil {
		t.Fatalf("expected no operational error, got: %v", err)
	}
	if rep.SyntaxValid {
		t.Error("expected SyntaxValid = false for malformed JSON")
	}
	if rep.IsValid {
		t.Error("expected IsValid = false for malformed JSON")
	}

	// B. File size exceeds 50MB
	largePath := filepath.Join(tempDir, "large.json")
	f, err := os.Create(largePath)
	if err != nil {
		t.Fatal(err)
	}
	// Write 51MB of whitespace
	buf := make([]byte, 1024*1024)
	for i := range buf {
		buf[i] = ' '
	}
	for i := 0; i < 51; i++ {
		_, _ = f.Write(buf)
	}
	f.Close()

	_, errLarge := ValidateExportFile(largePath)
	if errLarge == nil || !errors.Is(errLarge, ErrExportPayloadTooLarge) {
		t.Errorf("expected ErrExportPayloadTooLarge, got: %v", errLarge)
	}

	// C. Fraudulent verification claims (marked verified=true but verification_status != "VERIFIED")
	dossier, store := createSampleDossierForExport(t, "ASM-EXP-FRAUD-01")
	defer store.Close()

	clock := NewMockClock(time.Date(2026, 10, 21, 14, 0, 0, 0, time.UTC))
	svc := NewExportService(store, clock)

	exp, _ := svc.GenerateNormalizedExport(context.Background(), ExportRequest{
		Dossier: dossier,
	})

	fraudExp := *exp
	fraudExp.Evidence = append([]ExportEvidenceRecord{}, exp.Evidence...)
	fraudExp.Evidence = append(fraudExp.Evidence, ExportEvidenceRecord{
		EvidenceID:         "EV-FRAUD-01",
		ControlID:          "AC-1",
		EvidenceType:       "log",
		ReferenceID:        "REF-001",
		VerificationStatus: "UNVERIFIED",
		Verified:           true, // False claim!
	})
	fraudExp.Summary.TotalEvidenceLinks = len(fraudExp.Evidence)
	fraudExp.LogicalDigest = ComputeNormalizedExportDigest(&fraudExp)

	errFraud := ValidateNormalizedExport(&fraudExp)
	if errFraud == nil || !strings.Contains(errFraud.Error(), "marked verified=true but verification_status is") {
		t.Errorf("expected error rejecting fraudulent verified claim, got: %v", errFraud)
	}

	// D. Tampered Logical Digest
	tamperedExp := *exp
	tamperedExp.LogicalDigest = "sha256:0000000000000000000000000000000000000000000000000000000000000000"
	errTampered := ValidateNormalizedExport(&tamperedExp)
	if errTampered == nil || !errors.Is(errTampered, ErrExportDigestMismatch) {
		t.Errorf("expected ErrExportDigestMismatch on tampered digest, got: %v", errTampered)
	}

	// E. Unsupported schema version
	unsupportedSchemaExp := *exp
	unsupportedSchemaExp.SchemaVersion = "felix.compliance.export.v999"
	errUnsupportedSchema := ValidateNormalizedExport(&unsupportedSchemaExp)
	if errUnsupportedSchema == nil || !strings.Contains(errUnsupportedSchema.Error(), ErrUnsupportedExportSchema.Error()) {
		t.Errorf("expected ErrUnsupportedExportSchema, got: %v", errUnsupportedSchema)
	}

	// F. Unsupported OSCAL version
	docAR, _ := svc.GenerateOSCALAssessmentResults(context.Background(), ExportRequest{Dossier: dossier})
	docAR.AssessmentResults.Metadata.OSCALVersion = "9.9.9"
	errUnsupportedOSCAL := ValidateOSCALAssessmentResults(docAR)
	if errUnsupportedOSCAL == nil || !strings.Contains(errUnsupportedOSCAL.Error(), ErrUnsupportedOSCALVersion.Error()) {
		t.Errorf("expected ErrUnsupportedOSCALVersion, got: %v", errUnsupportedOSCAL)
	}

	// G. Broken referential integrity in OSCAL (finding refers to unknown observation)
	docAR2, _ := svc.GenerateOSCALAssessmentResults(context.Background(), ExportRequest{Dossier: dossier})
	if len(docAR2.AssessmentResults.Results[0].Findings) > 0 {
		docAR2.AssessmentResults.Results[0].Findings[0].RelatedObservations = []OSCALObservationRef{
			{ObservationUUID: "00000000-0000-0000-0000-000000000000"},
		}
		errBrokenRef := ValidateOSCALAssessmentResults(docAR2)
		if errBrokenRef == nil || !strings.Contains(errBrokenRef.Error(), "nonexistent observation UUID") {
			t.Errorf("expected referential error for broken observation link, got: %v", errBrokenRef)
		}
	}
}

// ============================================================================
// 6. STRICT INTEGRITY FAILS CLOSED
// ============================================================================

func TestExport_StrictIntegrity_FailsClosed(t *testing.T) {
	dossier, store := createSampleDossierForExport(t, "ASM-EXP-STRICT-01")
	defer store.Close()

	clock := NewMockClock(time.Date(2026, 10, 21, 14, 0, 0, 0, time.UTC))
	svc := NewExportService(store, clock)

	// Tamper with source dossier integrity
	dossier.Integrity.IntegrityFailures = []string{"corrupted record detected"}

	_, errStrict := svc.GenerateNormalizedExport(context.Background(), ExportRequest{
		Dossier:         dossier,
		StrictIntegrity: true,
	})
	if errStrict == nil || !errors.Is(errStrict, ErrIntegrityMismatch) {
		t.Errorf("expected strict mode to fail closed with ErrIntegrityMismatch, got: %v", errStrict)
	}
}

// ============================================================================
// 7. FILE LOADERS ROUND TRIP
// ============================================================================

func TestExport_FileLoaders_RoundTrip(t *testing.T) {
	dossier, store := createSampleDossierForExport(t, "ASM-EXP-FILES-01")
	defer store.Close()

	clock := NewMockClock(time.Date(2026, 10, 21, 14, 0, 0, 0, time.UTC))
	svc := NewExportService(store, clock)

	tempDir := t.TempDir()

	// 1. Normalized JSON round trip
	normPath := filepath.Join(tempDir, "export_norm.json")
	exp, err := svc.GenerateNormalizedExport(context.Background(), ExportRequest{
		Dossier:            dossier,
		IncludeRemediation: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	normJSON, _ := exp.ToPrettyJSON()
	if err := os.WriteFile(normPath, normJSON, 0600); err != nil {
		t.Fatal(err)
	}

	loadedExp, err := LoadNormalizedExportFromFile(normPath)
	if err != nil {
		t.Fatalf("LoadNormalizedExportFromFile failed: %v", err)
	}
	if loadedExp.LogicalDigest != exp.LogicalDigest {
		t.Errorf("loaded digest %s != original %s", loadedExp.LogicalDigest, exp.LogicalDigest)
	}

	// 2. OSCAL Assessment Results round trip
	arPath := filepath.Join(tempDir, "export_ar.json")
	arDoc, err := svc.GenerateOSCALAssessmentResults(context.Background(), ExportRequest{
		Dossier:            dossier,
		IncludeRemediation: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	arJSON, _ := arDoc.ToPrettyJSON()
	if err := os.WriteFile(arPath, arJSON, 0600); err != nil {
		t.Fatal(err)
	}

	loadedAR, err := LoadOSCALAssessmentResultsFromFile(arPath)
	if err != nil {
		t.Fatalf("LoadOSCALAssessmentResultsFromFile failed: %v", err)
	}
	if loadedAR.AssessmentResults.UUID != arDoc.AssessmentResults.UUID {
		t.Errorf("loaded AR UUID %s != original %s", loadedAR.AssessmentResults.UUID, arDoc.AssessmentResults.UUID)
	}

	// 3. OSCAL POA&M round trip
	poamPath := filepath.Join(tempDir, "export_poam.json")
	poamDoc, err := svc.GenerateOSCALPOAM(context.Background(), ExportRequest{
		Dossier:            dossier,
		IncludeRemediation: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	poamJSON, _ := poamDoc.ToPrettyJSON()
	if err := os.WriteFile(poamPath, poamJSON, 0600); err != nil {
		t.Fatal(err)
	}

	loadedPOAM, err := LoadOSCALPOAMFromFile(poamPath)
	if err != nil {
		t.Fatalf("LoadOSCALPOAMFromFile failed: %v", err)
	}
	if loadedPOAM.PlanOfActionAndMilestones.UUID != poamDoc.PlanOfActionAndMilestones.UUID {
		t.Errorf("loaded POAM UUID %s != original %s", loadedPOAM.PlanOfActionAndMilestones.UUID, poamDoc.PlanOfActionAndMilestones.UUID)
	}
}

// ============================================================================
// 8. OFFICIAL NIST OSCAL v1.1.0 SCHEMA VALIDATION & OBJECTIVE-STATUS TESTS
// ============================================================================

func TestExport_OSCAL_OfficialSchemaValidation_Positive(t *testing.T) {
	dossier, store := createSampleDossierForExport(t, "ASM-EXP-OFFICIAL-SCHEMA-01")
	defer store.Close()

	clock := NewMockClock(time.Date(2026, 10, 21, 14, 0, 0, 0, time.UTC))
	svc := NewExportService(store, clock)

	// 1. Assessment Results against official NIST JSON schema
	arDoc, err := svc.GenerateOSCALAssessmentResults(context.Background(), ExportRequest{
		Dossier:            dossier,
		IncludeRemediation: true,
	})
	if err != nil {
		t.Fatalf("GenerateOSCALAssessmentResults failed: %v", err)
	}
	arJSON, err := json.Marshal(arDoc)
	if err != nil {
		t.Fatalf("json.Marshal failed: %v", err)
	}
	if err := ValidateOSCALAssessmentResultsJSONSchema(arJSON); err != nil {
		t.Fatalf("official NIST OSCAL Assessment Results JSON schema validation failed: %v", err)
	}

	// 2. POA&M against official NIST JSON schema
	poamDoc, err := svc.GenerateOSCALPOAM(context.Background(), ExportRequest{
		Dossier:            dossier,
		IncludeRemediation: true,
	})
	if err != nil {
		t.Fatalf("GenerateOSCALPOAM failed: %v", err)
	}
	poamJSON, err := json.Marshal(poamDoc)
	if err != nil {
		t.Fatalf("json.Marshal failed: %v", err)
	}
	if err := ValidateOSCALPOAMJSONSchema(poamJSON); err != nil {
		t.Fatalf("official NIST OSCAL POA&M JSON schema validation failed: %v", err)
	}
}

func TestExport_OSCAL_NegativeSchemaValidation(t *testing.T) {
	dossier, store := createSampleDossierForExport(t, "ASM-EXP-OFFICIAL-SCHEMA-NEG-01")
	defer store.Close()

	clock := NewMockClock(time.Date(2026, 10, 21, 14, 0, 0, 0, time.UTC))
	svc := NewExportService(store, clock)

	arDoc, err := svc.GenerateOSCALAssessmentResults(context.Background(), ExportRequest{
		Dossier:            dossier,
		IncludeRemediation: true,
	})
	if err != nil {
		t.Fatalf("GenerateOSCALAssessmentResults failed: %v", err)
	}

	// Case 1: Invalid status state ("unsatisfied" is NOT permitted in OSCAL v1.1.0; only "satisfied" or "not-satisfied")
	t.Run("InvalidStatusState_Unsatisfied", func(t *testing.T) {
		arJSON, err := json.Marshal(arDoc)
		if err != nil {
			t.Fatal(err)
		}
		var rawMap map[string]any
		if err := json.Unmarshal(arJSON, &rawMap); err != nil {
			t.Fatal(err)
		}
		// Mutate state to illegal value
		results := rawMap["assessment-results"].(map[string]any)["results"].([]any)
		findings := results[0].(map[string]any)["findings"].([]any)
		findings[0].(map[string]any)["target"].(map[string]any)["status"].(map[string]any)["state"] = "unsatisfied"

		corruptedJSON, _ := json.Marshal(rawMap)
		errSchema := ValidateOSCALAssessmentResultsJSONSchema(corruptedJSON)
		if errSchema == nil {
			t.Errorf("expected official schema validation failure for state='unsatisfied', but got nil")
		}
	})

	// Case 2: Invalid status state ("partially-satisfied")
	t.Run("InvalidStatusState_PartiallySatisfied", func(t *testing.T) {
		arJSON, err := json.Marshal(arDoc)
		if err != nil {
			t.Fatal(err)
		}
		var rawMap map[string]any
		if err := json.Unmarshal(arJSON, &rawMap); err != nil {
			t.Fatal(err)
		}
		results := rawMap["assessment-results"].(map[string]any)["results"].([]any)
		findings := results[0].(map[string]any)["findings"].([]any)
		findings[0].(map[string]any)["target"].(map[string]any)["status"].(map[string]any)["state"] = "partially-satisfied"

		corruptedJSON, _ := json.Marshal(rawMap)
		errSchema := ValidateOSCALAssessmentResultsJSONSchema(corruptedJSON)
		if errSchema == nil {
			t.Errorf("expected official schema validation failure for state='partially-satisfied', but got nil")
		}
	})

	// Case 3: Invalid party type ("tool" is NOT allowed in metadata.parties; only "person" or "organization")
	t.Run("InvalidPartyType_Tool", func(t *testing.T) {
		arJSON, err := json.Marshal(arDoc)
		if err != nil {
			t.Fatal(err)
		}
		var rawMap map[string]any
		if err := json.Unmarshal(arJSON, &rawMap); err != nil {
			t.Fatal(err)
		}
		parties := rawMap["assessment-results"].(map[string]any)["metadata"].(map[string]any)["parties"].([]any)
		parties[0].(map[string]any)["type"] = "tool"

		corruptedJSON, _ := json.Marshal(rawMap)
		errSchema := ValidateOSCALAssessmentResultsJSONSchema(corruptedJSON)
		if errSchema == nil {
			t.Errorf("expected official schema validation failure for party type='tool', but got nil")
		}
	})

	// Case 4: Disallowed additional property (OSCAL schema enforces additionalProperties: false)
	t.Run("DisallowedAdditionalProperty", func(t *testing.T) {
		arJSON, err := json.Marshal(arDoc)
		if err != nil {
			t.Fatal(err)
		}
		var rawMap map[string]any
		if err := json.Unmarshal(arJSON, &rawMap); err != nil {
			t.Fatal(err)
		}
		rawMap["assessment-results"].(map[string]any)["metadata"].(map[string]any)["unauthorized_property"] = "hostile_payload"

		corruptedJSON, _ := json.Marshal(rawMap)
		errSchema := ValidateOSCALAssessmentResultsJSONSchema(corruptedJSON)
		if errSchema == nil {
			t.Errorf("expected official schema validation failure for unauthorized property, but got nil")
		}
	})

	// Case 5: Malformed UUID
	t.Run("MalformedUUID", func(t *testing.T) {
		arJSON, err := json.Marshal(arDoc)
		if err != nil {
			t.Fatal(err)
		}
		var rawMap map[string]any
		if err := json.Unmarshal(arJSON, &rawMap); err != nil {
			t.Fatal(err)
		}
		rawMap["assessment-results"].(map[string]any)["uuid"] = "not-a-valid-uuid"

		corruptedJSON, _ := json.Marshal(rawMap)
		errSchema := ValidateOSCALAssessmentResultsJSONSchema(corruptedJSON)
		if errSchema == nil {
			t.Errorf("expected official schema validation failure for malformed UUID, but got nil")
		}
	})
}

func TestExport_OSCAL_ObjectiveStatusMapping_AllStates(t *testing.T) {
	dossier, store := createSampleDossierForExport(t, "ASM-EXP-ALL-STATES-01")
	defer store.Close()

	clock := NewMockClock(time.Date(2026, 10, 21, 14, 0, 0, 0, time.UTC))
	svc := NewExportService(store, clock)

	arDoc, err := svc.GenerateOSCALAssessmentResults(context.Background(), ExportRequest{
		Dossier:            dossier,
		IncludeRemediation: true,
	})
	if err != nil {
		t.Fatalf("GenerateOSCALAssessmentResults failed: %v", err)
	}

	results := arDoc.AssessmentResults.Results
	if len(results) == 0 {
		t.Fatalf("expected results in OSCAL assessment results")
	}

	// 1. Verify ReviewedControls.ControlObjectiveSelections covers all 7 evaluation states
	// and maps each to valid NIST OSCAL v1.1.0 status ("satisfied" or "not-satisfied") and reason ("pass", "fail", "other").
	stateFound := make(map[string]bool)
	for _, obj := range results[0].ReviewedControls.ControlObjectiveSelections {
		var felixState, oscalState, oscalReason string
		for _, prop := range obj.Props {
			if prop.Name == "felix-evaluation-state" {
				felixState = prop.Value
			}
			if prop.Name == "status" {
				oscalState = prop.Value
			}
			if prop.Name == "reason" {
				oscalReason = prop.Value
			}
		}
		if felixState == "" {
			t.Errorf("objective missing felix-evaluation-state property")
			continue
		}
		stateFound[felixState] = true

		switch EvaluationState(felixState) {
		case StateCompliant:
			if oscalState != "satisfied" {
				t.Errorf("state %s: expected oscal status 'satisfied', got %q", felixState, oscalState)
			}
			if oscalReason != "pass" {
				t.Errorf("state %s: expected oscal reason 'pass', got %q", felixState, oscalReason)
			}
		case StateNonCompliant:
			if oscalState != "not-satisfied" {
				t.Errorf("state %s: expected oscal status 'not-satisfied', got %q", felixState, oscalState)
			}
			if oscalReason != "fail" {
				t.Errorf("state %s: expected oscal reason 'fail', got %q", felixState, oscalReason)
			}
		case StatePartiallyCompliant:
			if oscalState != "not-satisfied" {
				t.Errorf("state %s: expected oscal status 'not-satisfied', got %q", felixState, oscalState)
			}
			if oscalReason != "fail" {
				t.Errorf("state %s: expected oscal reason 'fail', got %q", felixState, oscalReason)
			}
			if !strings.Contains(obj.Remarks, "OSCAL Mapping Notice") {
				t.Errorf("state %s: expected mapping notice in remarks, got %q", felixState, obj.Remarks)
			}
		case StateInsufficientEvidence, StateNotAssessed, StateNotApplicable, StateError:
			// Crucial security requirement: Insufficient evidence, not assessed, not applicable,
			// and error states must NEVER be mapped to "satisfied" or described as verified failure ("fail").
			if oscalState != "not-satisfied" {
				t.Errorf("state %s: expected oscal status 'not-satisfied', got %q (must never be satisfied)", felixState, oscalState)
			}
			if oscalReason != "other" {
				t.Errorf("state %s: expected oscal reason 'other', got %q (must not be 'fail')", felixState, oscalReason)
			}
			if !strings.Contains(obj.Remarks, "OSCAL Mapping Notice") {
				t.Errorf("state %s: expected mapping notice in remarks, got %q", felixState, obj.Remarks)
			}
		default:
			t.Errorf("unexpected felix state: %s", felixState)
		}
	}

	allExpectedStates := []EvaluationState{
		StateCompliant,
		StateNonCompliant,
		StatePartiallyCompliant,
		StateInsufficientEvidence,
		StateNotAssessed,
		StateNotApplicable,
		StateError,
	}
	for _, es := range allExpectedStates {
		if !stateFound[string(es)] {
			t.Errorf("expected state %s was not present in reviewed controls objectives", es)
		}
	}

	// 2. Verify all Finding targets adhere strictly to schema-allowed status states
	for _, f := range results[0].Findings {
		if f.Target.Status.State != "satisfied" && f.Target.Status.State != "not-satisfied" {
			t.Errorf("finding %s has invalid target.status.state %q; only satisfied and not-satisfied are allowed", f.UUID, f.Target.Status.State)
		}
		if f.Target.Type != "objective-id" && f.Target.Type != "statement-id" {
			t.Errorf("finding %s has invalid target.type %q", f.UUID, f.Target.Type)
		}
		if f.Target.Status.Reason != "fail" && f.Target.Status.Reason != "pass" && f.Target.Status.Reason != "other" {
			t.Errorf("finding %s has invalid target.status.reason %q", f.UUID, f.Target.Status.Reason)
		}
	}

	// 3. Verify overarching limitation notice is present in result remarks
	if !strings.Contains(results[0].Remarks, "OSCAL v1.1.0 Binary State Model Limitation") {
		t.Errorf("expected overarching binary state model limitation in result remarks, got: %s", results[0].Remarks)
	}

	// 4. Prove the entire document with all states passes official NIST OSCAL JSON schema validation
	arJSON, err := json.Marshal(arDoc)
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateOSCALAssessmentResultsJSONSchema(arJSON); err != nil {
		t.Fatalf("document with all states failed official NIST schema validation: %v", err)
	}

	// 5. Verify round-trip file persistence preserves exact 7-state fidelity
	tmpFile := filepath.Join(t.TempDir(), "all_states_ar.json")
	if err := os.WriteFile(tmpFile, arJSON, 0600); err != nil {
		t.Fatal(err)
	}
	loadedDoc, err := LoadOSCALAssessmentResultsFromFile(tmpFile)
	if err != nil {
		t.Fatalf("LoadOSCALAssessmentResultsFromFile failed: %v", err)
	}
	loadedStateCount := 0
	for _, obj := range loadedDoc.AssessmentResults.Results[0].ReviewedControls.ControlObjectiveSelections {
		for _, prop := range obj.Props {
			if prop.Name == "felix-evaluation-state" {
				loadedStateCount++
				break
			}
		}
	}
	if loadedStateCount != len(allExpectedStates) {
		t.Errorf("expected %d states surviving round-trip load, got %d", len(allExpectedStates), loadedStateCount)
	}
}
