package test

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"felix/pkg/compliance"
)

// TestPhase99_ComplianceExport_EndToEnd tests the complete Phase 9.9 Export pipeline:
// 1. Normalized JSON export (felix.compliance.export.v1) with full fidelity.
// 2. OSCAL v1.1.0 Assessment Results export with deterministic UUIDv5 identifiers.
// 3. OSCAL v1.1.0 POA&M export with remediation milestones and SLA deadlines.
// 4. Multi-tiered validation: syntax, schema, referential, semantic consistency, and source-integrity.
// 5. Strict integrity mode fail-closed verification under source record tampering.
func TestPhase99_ComplianceExport_EndToEnd(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "compliance_export_e2e.db")

	startTime := time.Date(2026, 10, 21, 10, 0, 0, 0, time.UTC)
	clock := compliance.NewMockClock(startTime)

	// 1. Setup SQLite Store and Integrity Key Provider
	store, err := compliance.NewSQLiteComplianceStore(dbPath)
	if err != nil {
		t.Fatalf("NewSQLiteComplianceStore failed: %v", err)
	}
	defer store.Close()

	key, err := compliance.GenerateIntegrityKey("export-e2e-key")
	if err != nil {
		t.Fatalf("GenerateIntegrityKey failed: %v", err)
	}
	kp, err := compliance.NewStaticKeyProvider(key)
	if err != nil {
		t.Fatalf("NewStaticKeyProvider failed: %v", err)
	}

	// 2. Persist signed compliance evaluation result with 4 distinct control states
	evalRes := &compliance.EvaluationResult{
		AssessmentID:    "ASM-EXPORT-E2E",
		ExecutionID:     "EXEC-EXPORT-001",
		CatalogIdentity: "nist-sp800-53-export-e2e:5.1.0",
		CatalogDigest:   "sha256:1111111111111111111111111111111111111111111111111111111111111111",
		EngineVersion:   "1.0.0",
		Summary: compliance.EvaluationSummary{
			TotalControls:           4,
			CompliantCount:          1,
			NonCompliantCount:       2,
			PartiallyCompliantCount: 1,
			ApplicableControls:      4,
			AssessedControls:        4,
		},
		Evaluations: []compliance.ControlEvaluationRecord{
			{
				EvaluationID:       "eval:ASM-EXPORT-E2E:AC-1",
				ControlID:          "AC-1",
				ControlTitle:       "Access Control Policy and Procedures",
				CatalogID:          "nist-sp800-53-export-e2e",
				CatalogVersion:     "5.1.0",
				AssessmentID:       "ASM-EXPORT-E2E",
				State:              compliance.StateCompliant,
				Rationale:          "Approved access control policy document verified active.",
				SupportingEvidence: []string{"Security Policy v2.4 approved on 2026-01-15"},
				EvaluatedAt:        startTime,
				EngineVersion:      "1.0.0",
			},
			{
				EvaluationID:          "eval:ASM-EXPORT-E2E:AC-3",
				ControlID:             "AC-3",
				ControlTitle:          "Access Enforcement",
				CatalogID:             "nist-sp800-53-export-e2e",
				CatalogVersion:        "5.1.0",
				AssessmentID:          "ASM-EXPORT-E2E",
				State:                 compliance.StateNonCompliant,
				Rationale:             "Authorization bypass discovered in order payment API.",
				FindingIDs:            []string{"F-BOLA-01"},
				ContradictingEvidence: []string{"User B accessed order 104 without authorization"},
				EvaluatedAt:           startTime,
				EngineVersion:         "1.0.0",
			},
			{
				EvaluationID:          "eval:ASM-EXPORT-E2E:SC-8",
				ControlID:             "SC-8",
				ControlTitle:          "Transmission Confidentiality and Integrity",
				CatalogID:             "nist-sp800-53-export-e2e",
				CatalogVersion:        "5.1.0",
				AssessmentID:          "ASM-EXPORT-E2E",
				State:                 compliance.StateNonCompliant,
				Rationale:             "Plaintext HTTP traffic detected on internal gateway service.",
				FindingIDs:            []string{"F-TLS-01"},
				ContradictingEvidence: []string{"Port 80 HTTP open on ingress gateway"},
				EvaluatedAt:           startTime,
				EngineVersion:         "1.0.0",
			},
			{
				EvaluationID:          "eval:ASM-EXPORT-E2E:IA-2",
				ControlID:             "IA-2",
				ControlTitle:          "Identification and Authentication",
				CatalogID:             "nist-sp800-53-export-e2e",
				CatalogVersion:        "5.1.0",
				AssessmentID:          "ASM-EXPORT-E2E",
				State:                 compliance.StatePartiallyCompliant,
				Rationale:             "MFA enforced for human web login but API service accounts use static keys.",
				SupportingEvidence:    []string{"SAML 2.0 with MFA active on dashboard login"},
				ContradictingEvidence: []string{"Service accounts exempt from MFA policy"},
				EvaluatedAt:           startTime,
				EngineVersion:         "1.0.0",
			},
		},
	}
	if err := store.SaveEvaluationResultWithKey(evalRes, kp); err != nil {
		t.Fatalf("SaveEvaluationResultWithKey failed: %v", err)
	}

	// 3. Configure corporate SLA policy & assign SLAs
	policy := &compliance.RemediationSLAPolicy{
		ID:          "corp-export-policy",
		Version:     "1.0.0",
		Enabled:     true,
		Description: "Corporate SLA policy for export testing",
		Priority:    100,
		Rules: map[string]string{
			"CRITICAL": "24h",
			"HIGH":     "7d",
			"MEDIUM":   "30d",
		},
		DefaultRule: "30d",
	}
	if err := store.SaveRemediationPolicy(policy); err != nil {
		t.Fatalf("SaveRemediationPolicy failed: %v", err)
	}

	slaSvc := compliance.NewRemediationService(clock, 0)

	// Finding 1 (HIGH under AC-3): Completed at 24h
	rec1, evt1, err := slaSvc.AssignSLA(compliance.AssignSLAParams{
		FindingID:       "F-BOLA-01",
		FindingTitle:    "Critical BOLA in Payment API",
		FindingSource:   "apisec",
		FindingCategory: "authz",
		AssessmentID:    "ASM-EXPORT-E2E",
		CatalogID:       "nist-sp800-53-export-e2e:5.1.0",
		ControlID:       "AC-3",
		Severity:        "HIGH",
		Policy:          policy,
		SLAStartTime:    startTime,
		Actor:           "pipeline",
	})
	if err != nil {
		t.Fatalf("AssignSLA 1 failed: %v", err)
	}
	if err := store.SaveRemediationRecordWithKey(rec1, evt1, kp); err != nil {
		t.Fatalf("SaveRemediationRecord 1 failed: %v", err)
	}

	clock.Set(startTime.Add(24 * time.Hour))
	evtDone1, err := slaSvc.TransitionStatus(rec1, compliance.RemediationStatusRemediated, "developer", "Hotfix verified")
	if err != nil {
		t.Fatalf("TransitionStatus 1 Remediated failed: %v", err)
	}
	if err := store.SaveRemediationRecordWithKey(rec1, evtDone1, kp); err != nil {
		t.Fatalf("SaveRemediationRecord 1 Remediated failed: %v", err)
	}

	// Finding 2 (CRITICAL under SC-8): Open
	clock.Set(startTime)
	rec2, evt2, err := slaSvc.AssignSLA(compliance.AssignSLAParams{
		FindingID:       "F-TLS-01",
		FindingTitle:    "Cleartext Transmission Over Insecure HTTP",
		FindingSource:   "webvuln",
		FindingCategory: "crypto",
		AssessmentID:    "ASM-EXPORT-E2E",
		CatalogID:       "nist-sp800-53-export-e2e:5.1.0",
		ControlID:       "SC-8",
		Severity:        "CRITICAL",
		Policy:          policy,
		SLAStartTime:    startTime,
		Actor:           "pipeline",
	})
	if err != nil {
		t.Fatalf("AssignSLA 2 failed: %v", err)
	}
	if err := store.SaveRemediationRecordWithKey(rec2, evt2, kp); err != nil {
		t.Fatalf("SaveRemediationRecord 2 failed: %v", err)
	}

	// 5. Initialize ExportService
	exportSvc := compliance.NewExportService(store, clock)

	// ========================================================================
	// Phase A: Normalized JSON Export (felix.compliance.export.v1)
	// ========================================================================
	reqJSON := compliance.ExportRequest{
		AssessmentID:       "ASM-EXPORT-E2E",
		CatalogID:          "nist-sp800-53-export-e2e",
		Format:             compliance.ExportFormatNormalizedJSON,
		IncludeRemediation: true,
		IncludeSLA:         true,
		IncludeMTTR:        true,
		KeyProvider:        kp,
		FelixVersion:       "1.0.0-e2e",
		SourceRevision:     "git-rev-e2e",
	}

	exp, err := exportSvc.GenerateNormalizedExport(context.Background(), reqJSON)
	if err != nil {
		t.Fatalf("GenerateNormalizedExport failed: %v", err)
	}

	if exp.SchemaVersion != compliance.CurrentNormalizedExportSchemaVersion {
		t.Errorf("expected schema version %s, got %s", compliance.CurrentNormalizedExportSchemaVersion, exp.SchemaVersion)
	}
	if exp.Summary.TotalControls != 4 {
		t.Errorf("expected 4 total controls, got %d", exp.Summary.TotalControls)
	}
	if exp.Summary.NonCompliantCount != 2 {
		t.Errorf("expected 2 non-compliant controls, got %d", exp.Summary.NonCompliantCount)
	}
	if len(exp.Remediation) != 2 {
		t.Errorf("expected 2 remediation records in export, got %d", len(exp.Remediation))
	}

	// Validate Normalized JSON in memory
	if err := compliance.ValidateNormalizedExport(exp); err != nil {
		t.Fatalf("ValidateNormalizedExport failed: %v", err)
	}

	// Write to file and validate via File Validator
	normFile := filepath.Join(tmpDir, "normalized_export.json")
	normBytes, err := exp.ToPrettyJSON()
	if err != nil {
		t.Fatalf("ToPrettyJSON failed: %v", err)
	}
	if err := os.WriteFile(normFile, normBytes, 0600); err != nil {
		t.Fatalf("failed writing normalized export file: %v", err)
	}

	normRep, err := compliance.ValidateExportFile(normFile)
	if err != nil {
		t.Fatalf("ValidateExportFile failed: %v", err)
	}
	if !normRep.IsValid || normRep.DetectedFormat != compliance.ExportFormatNormalizedJSON {
		t.Errorf("expected valid normalized export report, got valid=%v, format=%s, errors=%v",
			normRep.IsValid, normRep.DetectedFormat, normRep.Errors)
	}

	// ========================================================================
	// Phase B: OSCAL v1.1.0 Assessment Results Export
	// ========================================================================
	reqOSCAL_AR := compliance.ExportRequest{
		AssessmentID:       "ASM-EXPORT-E2E",
		CatalogID:          "nist-sp800-53-export-e2e",
		Format:             compliance.ExportFormatOSCALAssessmentResults,
		IncludeRemediation: true,
		KeyProvider:        kp,
	}

	docAR, err := exportSvc.GenerateOSCALAssessmentResults(context.Background(), reqOSCAL_AR)
	if err != nil {
		t.Fatalf("GenerateOSCALAssessmentResults failed: %v", err)
	}

	if docAR.AssessmentResults.Metadata.OSCALVersion != compliance.CurrentOSCALVersion {
		t.Errorf("expected OSCAL version %s, got %s", compliance.CurrentOSCALVersion, docAR.AssessmentResults.Metadata.OSCALVersion)
	}
	if len(docAR.AssessmentResults.Results) == 0 {
		t.Fatal("expected at least one OSCAL result")
	}

	arRes := docAR.AssessmentResults.Results[0]
	if len(arRes.ReviewedControls.ControlObjectiveSelections) != 4 {
		t.Errorf("expected 4 reviewed control objectives, got %d", len(arRes.ReviewedControls.ControlObjectiveSelections))
	}
	if len(arRes.Findings) != 2 {
		t.Errorf("expected 2 OSCAL findings, got %d", len(arRes.Findings))
	}

	// Validate in memory
	if err := compliance.ValidateOSCALAssessmentResults(docAR); err != nil {
		t.Fatalf("ValidateOSCALAssessmentResults failed: %v", err)
	}

	// Write to file and validate via File Validator
	arFile := filepath.Join(tmpDir, "oscal_ar_export.json")
	arBytes, err := docAR.ToPrettyJSON()
	if err != nil {
		t.Fatalf("ToPrettyJSON failed: %v", err)
	}
	if err := os.WriteFile(arFile, arBytes, 0600); err != nil {
		t.Fatalf("failed writing OSCAL AR file: %v", err)
	}

	// Direct official NIST OSCAL JSON schema validation
	if err := compliance.ValidateOSCALAssessmentResultsJSONSchema(arBytes); err != nil {
		t.Fatalf("ValidateOSCALAssessmentResultsJSONSchema failed: %v", err)
	}

	arRep, err := compliance.ValidateExportFile(arFile)
	if err != nil {
		t.Fatalf("ValidateExportFile for OSCAL AR failed: %v", err)
	}
	if !arRep.IsValid || arRep.DetectedFormat != compliance.ExportFormatOSCALAssessmentResults {
		t.Errorf("expected valid OSCAL AR report, got valid=%v, format=%s, errors=%v",
			arRep.IsValid, arRep.DetectedFormat, arRep.Errors)
	}

	// ========================================================================
	// Phase C: OSCAL v1.1.0 POA&M Export
	// ========================================================================
	reqOSCAL_POAM := compliance.ExportRequest{
		AssessmentID:       "ASM-EXPORT-E2E",
		CatalogID:          "nist-sp800-53-export-e2e",
		Format:             compliance.ExportFormatOSCALPOAM,
		IncludeRemediation: true,
		KeyProvider:        kp,
	}

	docPOAM, err := exportSvc.GenerateOSCALPOAM(context.Background(), reqOSCAL_POAM)
	if err != nil {
		t.Fatalf("GenerateOSCALPOAM failed: %v", err)
	}

	if docPOAM.PlanOfActionAndMilestones.Metadata.OSCALVersion != compliance.CurrentOSCALVersion {
		t.Errorf("expected OSCAL version %s, got %s", compliance.CurrentOSCALVersion, docPOAM.PlanOfActionAndMilestones.Metadata.OSCALVersion)
	}
	if len(docPOAM.PlanOfActionAndMilestones.POAMItems) != 2 {
		t.Errorf("expected 2 POAM items, got %d", len(docPOAM.PlanOfActionAndMilestones.POAMItems))
	}

	// Validate in memory
	if err := compliance.ValidateOSCALPOAM(docPOAM); err != nil {
		t.Fatalf("ValidateOSCALPOAM failed: %v", err)
	}

	// Write to file and validate via File Validator
	poamFile := filepath.Join(tmpDir, "oscal_poam_export.json")
	poamBytes, err := docPOAM.ToPrettyJSON()
	if err != nil {
		t.Fatalf("ToPrettyJSON failed: %v", err)
	}
	if err := os.WriteFile(poamFile, poamBytes, 0600); err != nil {
		t.Fatalf("failed writing OSCAL POA&M file: %v", err)
	}

	// Direct official NIST OSCAL JSON schema validation
	if err := compliance.ValidateOSCALPOAMJSONSchema(poamBytes); err != nil {
		t.Fatalf("ValidateOSCALPOAMJSONSchema failed: %v", err)
	}

	poamRep, err := compliance.ValidateExportFile(poamFile)
	if err != nil {
		t.Fatalf("ValidateExportFile for OSCAL POA&M failed: %v", err)
	}
	if !poamRep.IsValid || poamRep.DetectedFormat != compliance.ExportFormatOSCALPOAM {
		t.Errorf("expected valid OSCAL POA&M report, got valid=%v, format=%s, errors=%v",
			poamRep.IsValid, poamRep.DetectedFormat, poamRep.Errors)
	}

	// ========================================================================
	// Phase D: Strict Integrity Fails Closed Under Data Tampering
	// ========================================================================
	// Direct SQLite mutation tampering with evaluation record
	rawDB, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("failed opening raw sqlite connection: %v", err)
	}
	defer rawDB.Close()

	_, err = rawDB.Exec(`UPDATE compliance_control_evaluations SET rationale = 'TAMPERED IN DB' WHERE control_id = 'AC-3' AND assessment_id = 'ASM-EXPORT-E2E'`)
	if err != nil {
		t.Fatalf("direct db tamper failed: %v", err)
	}

	// 1. Strict integrity mode fails closed with ErrIntegrityMismatch
	reqStrict := compliance.ExportRequest{
		AssessmentID:    "ASM-EXPORT-E2E",
		CatalogID:       "nist-sp800-53-export-e2e",
		StrictIntegrity: true,
		KeyProvider:     kp,
	}
	_, errStrict := exportSvc.GenerateNormalizedExport(context.Background(), reqStrict)
	if errStrict == nil || !errors.Is(errStrict, compliance.ErrIntegrityMismatch) {
		t.Fatalf("expected strict mode export to fail closed with ErrIntegrityMismatch, got: %v", errStrict)
	}

	// 2. Default mode completes and marks coverage as partial/unverified with limitations notice
	reqDefault := compliance.ExportRequest{
		AssessmentID:    "ASM-EXPORT-E2E",
		CatalogID:       "nist-sp800-53-export-e2e",
		StrictIntegrity: false,
		KeyProvider:     kp,
	}
	expDefault, err := exportSvc.GenerateNormalizedExport(context.Background(), reqDefault)
	if err != nil {
		t.Fatalf("default mode export unexpectedly failed: %v", err)
	}
	if expDefault.ExportMetadata.CompletenessStatus != compliance.DossierCompletenessPartial {
		t.Errorf("expected export marked partial under tampering, got: %s", expDefault.ExportMetadata.CompletenessStatus)
	}
	if len(expDefault.Integrity.IntegrityFailures) == 0 {
		t.Error("expected integrity failures recorded in tampered export")
	}
}
