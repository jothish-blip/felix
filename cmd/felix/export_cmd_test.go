package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"felix/pkg/clierror"
	"felix/pkg/compliance"
)

func TestCLI_Export_Help(t *testing.T) {
	code, out, _ := captureStdoutStderr(func() int {
		return run([]string{"compliance", "export", "--help"})
	})
	if code != clierror.ExitSuccess {
		t.Fatalf("expected ExitSuccess for export --help, got %d", code)
	}
	if !strings.Contains(out, "felix compliance export <subcommand>") {
		t.Errorf("expected usage instructions in help output, got: %s", out)
	}
}

func TestCLI_Export_MissingFlagsReturnsOperationalError(t *testing.T) {
	// Missing subcommand
	codeSub, _, _ := captureStdoutStderr(func() int {
		return run([]string{"compliance", "export"})
	})
	if codeSub != clierror.ExitSuccess {
		t.Fatalf("expected ExitSuccess for export without args (prints help), got %d", codeSub)
	}

	// Missing assessment and catalog for json
	codeJSON, _, _ := captureStdoutStderr(func() int {
		return run([]string{"compliance", "export", "json"})
	})
	if codeJSON != clierror.ExitOperational {
		t.Fatalf("expected ExitOperational (2) for missing flags, got %d", codeJSON)
	}

	// Missing assessment and catalog for oscal
	codeOSCAL, _, _ := captureStdoutStderr(func() int {
		return run([]string{"compliance", "export", "oscal"})
	})
	if codeOSCAL != clierror.ExitOperational {
		t.Fatalf("expected ExitOperational (2) for missing flags, got %d", codeOSCAL)
	}
}

func TestCLI_Export_JSON_Workflow(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "compliance_cli_export.db")

	store, err := compliance.NewSQLiteComplianceStore(dbPath)
	if err != nil {
		t.Fatalf("NewSQLiteComplianceStore failed: %v", err)
	}

	key, _ := compliance.GenerateIntegrityKey("cli-export-key")
	kp, _ := compliance.NewStaticKeyProvider(key)

	evalTime := time.Date(2026, 10, 21, 10, 0, 0, 0, time.UTC)
	evalRes := &compliance.EvaluationResult{
		AssessmentID:    "ASM-EXP-CLI-01",
		ExecutionID:     "EXEC-EXP-CLI-01",
		CatalogIdentity: "nist-sample:1.0.0",
		CatalogDigest:   "sha256:1111111111111111111111111111111111111111111111111111111111111111",
		EngineVersion:   "1.0.0",
		EvaluatedAt:     evalTime,
		Summary: compliance.EvaluationSummary{
			TotalControls:     1,
			NonCompliantCount: 1,
		},
		Evaluations: []compliance.ControlEvaluationRecord{
			{
				EvaluationID:  "eval:ASM-EXP-CLI-01:AC-2",
				ControlID:     "AC-2",
				ControlTitle:  "Account Management",
				CatalogID:     "nist-sample",
				AssessmentID:  "ASM-EXP-CLI-01",
				State:         compliance.StateNonCompliant,
				Rationale:     "Dormant accounts found",
				FindingIDs:    []string{"F-EXP-01"},
				EvaluatedAt:   evalTime,
				EngineVersion: "1.0.0",
			},
		},
	}
	if err := store.SaveEvaluationResultWithKey(evalRes, kp); err != nil {
		t.Fatalf("SaveEvaluationResultWithKey failed: %v", err)
	}
	store.Close()

	exportOut := filepath.Join(tmpDir, "export_out.json")

	// 1. Export normalized JSON to file
	// Since assessment has non-compliant controls, exit code must be ExitSecurityFail (1)
	code, _, errOut := captureStdoutStderr(func() int {
		return run([]string{
			"compliance", "export", "json",
			"--assessment", "ASM-EXP-CLI-01",
			"--catalog", "nist-sample",
			"--db", dbPath,
			"--output", exportOut,
		})
	})
	if code != clierror.ExitSecurityFail {
		t.Fatalf("expected ExitSecurityFail (1) for completed assessment with non-compliant controls, got %d (stderr: %s)", code, errOut)
	}

	// 2. Verify file was written and is valid Normalized JSON
	rawBytes, err := os.ReadFile(exportOut)
	if err != nil {
		t.Fatalf("failed reading output export: %v", err)
	}
	var exp compliance.NormalizedComplianceExport
	if err := json.Unmarshal(rawBytes, &exp); err != nil {
		t.Fatalf("output export is not valid JSON: %v", err)
	}
	if exp.SchemaVersion != compliance.CurrentNormalizedExportSchemaVersion {
		t.Errorf("expected SchemaVersion %s, got %s", compliance.CurrentNormalizedExportSchemaVersion, exp.SchemaVersion)
	}
	if exp.Assessment.AssessmentID != "ASM-EXP-CLI-01" {
		t.Errorf("expected AssessmentID ASM-EXP-CLI-01, got %s", exp.Assessment.AssessmentID)
	}

	// 3. Overwrite protection: running without --overwrite should fail with ExitOperational (2)
	codeOverwriteFail, _, errOverFail := captureStdoutStderr(func() int {
		return run([]string{
			"compliance", "export", "json",
			"--assessment", "ASM-EXP-CLI-01",
			"--catalog", "nist-sample",
			"--db", dbPath,
			"--output", exportOut,
		})
	})
	if codeOverwriteFail != clierror.ExitOperational {
		t.Fatalf("expected ExitOperational (2) without --overwrite, got %d (stderr: %s)", codeOverwriteFail, errOverFail)
	}

	// 4. Running with --overwrite should succeed (code 1 due to non-compliant controls)
	codeOverwriteSuccess, _, errOverSucc := captureStdoutStderr(func() int {
		return run([]string{
			"compliance", "export", "json",
			"--assessment", "ASM-EXP-CLI-01",
			"--catalog", "nist-sample",
			"--db", dbPath,
			"--output", exportOut,
			"--overwrite",
		})
	})
	if codeOverwriteSuccess != clierror.ExitSecurityFail {
		t.Fatalf("expected ExitSecurityFail (1) with --overwrite, got %d (stderr: %s)", codeOverwriteSuccess, errOverSucc)
	}

	// 5. Test CLI validate subcommand
	codeVal, outVal, errVal := captureStdoutStderr(func() int {
		return run([]string{"compliance", "export", "validate", exportOut})
	})
	if codeVal != clierror.ExitSuccess {
		t.Fatalf("expected ExitSuccess (0) for validate, got %d (stdout: %s, stderr: %s)", codeVal, outVal, errVal)
	}
	if !strings.Contains(outVal, "is VALID") {
		t.Errorf("expected 'is VALID' in validate output, got: %s", outVal)
	}

	// 6. Test CLI validate with --json
	codeValJSON, outValJSON, errValJSON := captureStdoutStderr(func() int {
		return run([]string{"compliance", "export", "validate", exportOut, "--json"})
	})
	if codeValJSON != clierror.ExitSuccess {
		t.Fatalf("expected ExitSuccess (0) for validate --json, got %d (stdout: %s, stderr: %s)", codeValJSON, outValJSON, errValJSON)
	}
	var rep compliance.ExportValidationReport
	if err := json.Unmarshal([]byte(outValJSON), &rep); err != nil {
		t.Fatalf("failed unmarshaling validation report JSON: %v (raw: %s)", err, outValJSON)
	}
	if !rep.IsValid || rep.DetectedFormat != compliance.ExportFormatNormalizedJSON {
		t.Errorf("expected IsValid=true and format=%s, got valid=%v, format=%s",
			compliance.ExportFormatNormalizedJSON, rep.IsValid, rep.DetectedFormat)
	}
}

func TestCLI_Export_OSCAL_AssessmentResults_Workflow(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "compliance_cli_oscal.db")

	store, err := compliance.NewSQLiteComplianceStore(dbPath)
	if err != nil {
		t.Fatalf("NewSQLiteComplianceStore failed: %v", err)
	}

	evalTime := time.Date(2026, 10, 21, 10, 0, 0, 0, time.UTC)
	evalRes := &compliance.EvaluationResult{
		AssessmentID:    "ASM-OSCAL-CLI-01",
		CatalogIdentity: "nist-sample:1.0.0",
		CatalogDigest:   "sha256:1111111111111111111111111111111111111111111111111111111111111111",
		EngineVersion:   "1.0.0",
		EvaluatedAt:     evalTime,
		Summary: compliance.EvaluationSummary{
			TotalControls:     1,
			NonCompliantCount: 1,
		},
		Evaluations: []compliance.ControlEvaluationRecord{
			{
				EvaluationID:  "eval:ASM-OSCAL-CLI-01:AC-2",
				ControlID:     "AC-2",
				ControlTitle:  "Account Management",
				CatalogID:     "nist-sample",
				AssessmentID:  "ASM-OSCAL-CLI-01",
				State:         compliance.StateNonCompliant,
				Rationale:     "Dormant accounts found",
				FindingIDs:    []string{"F-OSCAL-01"},
				EvaluatedAt:   evalTime,
				EngineVersion: "1.0.0",
			},
		},
	}
	if err := store.SaveEvaluationResult(evalRes); err != nil {
		t.Fatalf("SaveEvaluationResult failed: %v", err)
	}
	store.Close()

	oscalOut := filepath.Join(tmpDir, "oscal_ar.json")

	// Export OSCAL Assessment Results
	code, _, errOut := captureStdoutStderr(func() int {
		return run([]string{
			"compliance", "export", "oscal",
			"--assessment", "ASM-OSCAL-CLI-01",
			"--catalog", "nist-sample",
			"--oscal-model", "ar",
			"--db", dbPath,
			"--output", oscalOut,
		})
	})
	if code != clierror.ExitSecurityFail {
		t.Fatalf("expected ExitSecurityFail (1) for assessment with findings, got %d (stderr: %s)", code, errOut)
	}

	// Validate written file
	codeVal, outVal, errVal := captureStdoutStderr(func() int {
		return run([]string{"compliance", "export", "validate", oscalOut})
	})
	if codeVal != clierror.ExitSuccess {
		t.Fatalf("expected ExitSuccess (0) validating OSCAL AR, got %d (stdout: %s, stderr: %s)", codeVal, outVal, errVal)
	}
	if !strings.Contains(outVal, "is VALID") || !strings.Contains(outVal, string(compliance.ExportFormatOSCALAssessmentResults)) {
		t.Errorf("expected valid OSCAL AR confirmation, got: %s", outVal)
	}
}

func TestCLI_Export_OSCAL_POAM_Workflow(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "compliance_cli_poam.db")

	store, err := compliance.NewSQLiteComplianceStore(dbPath)
	if err != nil {
		t.Fatalf("NewSQLiteComplianceStore failed: %v", err)
	}

	key, _ := compliance.GenerateIntegrityKey("cli-poam-key")
	kp, _ := compliance.NewStaticKeyProvider(key)

	evalTime := time.Date(2026, 10, 21, 10, 0, 0, 0, time.UTC)
	evalRes := &compliance.EvaluationResult{
		AssessmentID:    "ASM-POAM-CLI-01",
		CatalogIdentity: "nist-sample:1.0.0",
		CatalogDigest:   "sha256:1111111111111111111111111111111111111111111111111111111111111111",
		EngineVersion:   "1.0.0",
		EvaluatedAt:     evalTime,
		Summary: compliance.EvaluationSummary{
			TotalControls:     1,
			NonCompliantCount: 1,
		},
		Evaluations: []compliance.ControlEvaluationRecord{
			{
				EvaluationID:  "eval:ASM-POAM-CLI-01:AC-2",
				ControlID:     "AC-2",
				ControlTitle:  "Account Management",
				CatalogID:     "nist-sample",
				AssessmentID:  "ASM-POAM-CLI-01",
				State:         compliance.StateNonCompliant,
				Rationale:     "Dormant accounts found",
				FindingIDs:    []string{"F-POAM-01"},
				EvaluatedAt:   evalTime,
				EngineVersion: "1.0.0",
			},
		},
	}
	if err := store.SaveEvaluationResultWithKey(evalRes, kp); err != nil {
		t.Fatalf("SaveEvaluationResultWithKey failed: %v", err)
	}

	remID := "rem:cli:poam:1"
	rec := &compliance.RemediationRecord{
		ID:           remID,
		FindingID:    "F-POAM-01",
		AssessmentID: "ASM-POAM-CLI-01",
		CatalogID:    "nist-sample:1.0.0",
		ControlID:    "AC-2",
		Severity:     "HIGH",
		AssignedAt:   evalTime,
		SLAStartTime: evalTime,
		Deadline:     evalTime.Add(7 * 24 * time.Hour),
		Status:       compliance.RemediationStatusOpen,
		CreatedAt:    evalTime,
	}
	_ = store.SaveRemediationRecordWithKey(rec, &compliance.RemediationHistoryEvent{
		ID:            compliance.GenerateRemediationEventID(remID),
		RemediationID: remID,
		EventType:     compliance.HistoryEventAssigned,
		ToStatus:      compliance.RemediationStatusOpen,
		Timestamp:     evalTime,
	}, kp)
	store.Close()

	poamOut := filepath.Join(tmpDir, "oscal_poam.json")

	// Export OSCAL POA&M
	code, _, errOut := captureStdoutStderr(func() int {
		return run([]string{
			"compliance", "export", "oscal",
			"--assessment", "ASM-POAM-CLI-01",
			"--catalog", "nist-sample",
			"--oscal-model", "poam",
			"--include-remediation",
			"--db", dbPath,
			"--output", poamOut,
		})
	})
	if code != clierror.ExitSecurityFail {
		t.Fatalf("expected ExitSecurityFail (1) for open remediation items in POA&M, got %d (stderr: %s)", code, errOut)
	}

	// Validate written file
	codeVal, outVal, errVal := captureStdoutStderr(func() int {
		return run([]string{"compliance", "export", "validate", poamOut})
	})
	if codeVal != clierror.ExitSuccess {
		t.Fatalf("expected ExitSuccess (0) validating OSCAL POA&M, got %d (stdout: %s, stderr: %s)", codeVal, outVal, errVal)
	}
	if !strings.Contains(outVal, "is VALID") || !strings.Contains(outVal, string(compliance.ExportFormatOSCALPOAM)) {
		t.Errorf("expected valid OSCAL POA&M confirmation, got: %s", outVal)
	}
}

func TestCLI_Export_FromDossierFile(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "compliance_dossier_source.db")

	store, err := compliance.NewSQLiteComplianceStore(dbPath)
	if err != nil {
		t.Fatalf("NewSQLiteComplianceStore failed: %v", err)
	}

	evalTime := time.Date(2026, 10, 21, 10, 0, 0, 0, time.UTC)
	evalRes := &compliance.EvaluationResult{
		AssessmentID:    "ASM-FROM-DOSSIER",
		CatalogIdentity: "nist-sample:1.0.0",
		CatalogDigest:   "sha256:1111111111111111111111111111111111111111111111111111111111111111",
		EngineVersion:   "1.0.0",
		EvaluatedAt:     evalTime,
		Summary: compliance.EvaluationSummary{
			TotalControls:  1,
			CompliantCount: 1,
		},
		Evaluations: []compliance.ControlEvaluationRecord{
			{
				EvaluationID:       "eval:ASM-FROM-DOSSIER:AC-1",
				ControlID:          "AC-1",
				ControlTitle:       "Access Policy",
				CatalogID:          "nist-sample",
				AssessmentID:       "ASM-FROM-DOSSIER",
				State:              compliance.StateCompliant,
				Rationale:          "Policy active",
				SupportingEvidence: []string{"Policy approved"},
				EvaluatedAt:        evalTime,
				EngineVersion:      "1.0.0",
			},
		},
	}
	if err := store.SaveEvaluationResult(evalRes); err != nil {
		t.Fatalf("SaveEvaluationResult failed: %v", err)
	}
	store.Close()

	dossierPath := filepath.Join(tmpDir, "source_dossier.json")

	// 1. Generate dossier
	codeGen, _, _ := captureStdoutStderr(func() int {
		return run([]string{
			"compliance", "dossier", "generate",
			"--assessment", "ASM-FROM-DOSSIER",
			"--catalog", "nist-sample",
			"--db", dbPath,
			"--output", dossierPath,
		})
	})
	if codeGen != clierror.ExitSuccess {
		t.Fatalf("expected ExitSuccess generating dossier, got %d", codeGen)
	}

	// 2. Export using --dossier-file directly
	exportFromDossierOut := filepath.Join(tmpDir, "export_from_dossier.json")
	codeExp, _, errExp := captureStdoutStderr(func() int {
		return run([]string{
			"compliance", "export", "json",
			"--dossier-file", dossierPath,
			"--output", exportFromDossierOut,
		})
	})
	if codeExp != clierror.ExitSuccess {
		t.Fatalf("expected ExitSuccess exporting from dossier file, got %d (stderr: %s)", codeExp, errExp)
	}

	// Validate exported file
	codeVal, _, _ := captureStdoutStderr(func() int {
		return run([]string{"compliance", "export", "validate", exportFromDossierOut})
	})
	if codeVal != clierror.ExitSuccess {
		t.Fatalf("expected ExitSuccess validating exported file from dossier, got %d", codeVal)
	}
}

func TestCLI_Export_CleanAssessmentReturnsExitSuccess(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "compliance_cli_clean.db")

	store, err := compliance.NewSQLiteComplianceStore(dbPath)
	if err != nil {
		t.Fatalf("NewSQLiteComplianceStore failed: %v", err)
	}

	evalTime := time.Date(2026, 10, 21, 10, 0, 0, 0, time.UTC)
	evalRes := &compliance.EvaluationResult{
		AssessmentID:    "ASM-CLEAN-CLI-01",
		CatalogIdentity: "nist-sample:1.0.0",
		CatalogDigest:   "sha256:1111111111111111111111111111111111111111111111111111111111111111",
		EngineVersion:   "1.0.0",
		EvaluatedAt:     evalTime,
		Summary: compliance.EvaluationSummary{
			TotalControls:  1,
			CompliantCount: 1,
		},
		Evaluations: []compliance.ControlEvaluationRecord{
			{
				EvaluationID:       "eval:ASM-CLEAN-CLI-01:AC-1",
				ControlID:          "AC-1",
				ControlTitle:       "Access Policy",
				CatalogID:          "nist-sample",
				AssessmentID:       "ASM-CLEAN-CLI-01",
				State:              compliance.StateCompliant,
				Rationale:          "Active access controls verified",
				SupportingEvidence: []string{"Evidence documented"},
				EvaluatedAt:        evalTime,
				EngineVersion:      "1.0.0",
			},
		},
	}
	if err := store.SaveEvaluationResult(evalRes); err != nil {
		t.Fatalf("SaveEvaluationResult failed: %v", err)
	}
	store.Close()

	exportOut := filepath.Join(tmpDir, "clean_export.json")

	// Assessment with 0 non-compliant controls returns ExitSuccess (0)
	code, _, errOut := captureStdoutStderr(func() int {
		return run([]string{
			"compliance", "export", "json",
			"--assessment", "ASM-CLEAN-CLI-01",
			"--catalog", "nist-sample",
			"--db", dbPath,
			"--output", exportOut,
		})
	})
	if code != clierror.ExitSuccess {
		t.Fatalf("expected ExitSuccess (0) for clean compliant assessment, got %d (stderr: %s)", code, errOut)
	}
}

func TestCLI_Export_Validate_CorruptedFileReturnsOperationalError(t *testing.T) {
	tmpDir := t.TempDir()
	badFile := filepath.Join(tmpDir, "corrupted.json")
	if err := os.WriteFile(badFile, []byte(`{"not_an_export": true}`), 0600); err != nil {
		t.Fatal(err)
	}

	code, _, errOut := captureStdoutStderr(func() int {
		return run([]string{"compliance", "export", "validate", badFile})
	})
	if code != clierror.ExitOperational {
		t.Fatalf("expected ExitOperational (2) for corrupted export file, got %d (stderr: %s)", code, errOut)
	}
}
