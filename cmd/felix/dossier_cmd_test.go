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

func TestCLI_Dossier_Help(t *testing.T) {
	code, out, _ := captureStdoutStderr(func() int {
		return run([]string{"compliance", "dossier", "--help"})
	})
	if code != clierror.ExitSuccess {
		t.Fatalf("expected ExitSuccess for dossier --help, got %d", code)
	}
	if !strings.Contains(out, "felix compliance dossier <subcommand>") {
		t.Errorf("expected usage instructions in help output, got: %s", out)
	}
}

func TestCLI_Dossier_MissingFlagsReturnsOperationalError(t *testing.T) {
	// Missing both assessment and catalog
	code, _, errOut := captureStdoutStderr(func() int {
		return run([]string{"compliance", "dossier", "generate"})
	})
	if code != clierror.ExitOperational {
		t.Fatalf("expected ExitOperational (2) for missing flags, got %d (stderr: %s)", code, errOut)
	}

	// Missing catalog
	code2, _, errOut2 := captureStdoutStderr(func() int {
		return run([]string{"compliance", "dossier", "generate", "--assessment", "ASM-1"})
	})
	if code2 != clierror.ExitOperational {
		t.Fatalf("expected ExitOperational (2) for missing catalog, got %d (stderr: %s)", code2, errOut2)
	}
}

func TestCLI_Dossier_GenerateValidateAndView_Workflow(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "compliance_cli_dossier.db")

	store, err := compliance.NewSQLiteComplianceStore(dbPath)
	if err != nil {
		t.Fatalf("NewSQLiteComplianceStore failed: %v", err)
	}

	key, _ := compliance.GenerateIntegrityKey("cli-dossier-key")
	kp, _ := compliance.NewStaticKeyProvider(key)

	// Persist non-compliant evaluation (has violation)
	evalTime := time.Date(2026, 10, 21, 10, 0, 0, 0, time.UTC)
	evalRes := &compliance.EvaluationResult{
		AssessmentID:    "ASM-CLI-01",
		ExecutionID:     "EXEC-CLI-01",
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
				EvaluationID:  "eval:ASM-CLI-01:AC-3",
				ControlID:     "AC-3",
				ControlTitle:  "Access Enforcement",
				CatalogID:     "nist-sample",
				AssessmentID:  "ASM-CLI-01",
				State:         compliance.StateNonCompliant,
				Rationale:     "BOLA vulnerability found",
				FindingIDs:    []string{"F-CLI-01"},
				EvaluatedAt:   evalTime,
				EngineVersion: "1.0.0",
			},
		},
	}
	if err := store.SaveEvaluationResultWithKey(evalRes, kp); err != nil {
		t.Fatalf("SaveEvaluationResultWithKey failed: %v", err)
	}
	store.Close()

	dossierOut := filepath.Join(tmpDir, "dossier_out.json")

	// 1. Generate dossier to file.
	// Since evaluation has non-compliant controls, exit code should be ExitSecurityFail (1)
	code, _, errOut := captureStdoutStderr(func() int {
		return run([]string{
			"compliance", "dossier", "generate",
			"--assessment", "ASM-CLI-01",
			"--catalog", "nist-sample",
			"--db", dbPath,
			"--output", dossierOut,
		})
	})
	if code != clierror.ExitSecurityFail {
		t.Fatalf("expected ExitSecurityFail (1) for completed assessment with non-compliant controls, got %d (stderr: %s)", code, errOut)
	}

	// 2. Verify file was written and is valid JSON
	rawBytes, err := os.ReadFile(dossierOut)
	if err != nil {
		t.Fatalf("failed reading output dossier: %v", err)
	}
	var d compliance.ComplianceDossier
	if err := json.Unmarshal(rawBytes, &d); err != nil {
		t.Fatalf("output file is not valid JSON: %v", err)
	}
	if d.Identity.AssessmentID != "ASM-CLI-01" {
		t.Errorf("expected AssessmentID ASM-CLI-01, got %s", d.Identity.AssessmentID)
	}

	// 3. Overwrite protection: re-running without --overwrite should fail with ExitOperational (2)
	codeOverwriteFail, _, errOverFail := captureStdoutStderr(func() int {
		return run([]string{
			"compliance", "dossier", "generate",
			"--assessment", "ASM-CLI-01",
			"--catalog", "nist-sample",
			"--db", dbPath,
			"--output", dossierOut,
		})
	})
	if codeOverwriteFail != clierror.ExitOperational {
		t.Fatalf("expected ExitOperational (2) when trying to overwrite without --overwrite flag, got %d (stderr: %s)",
			codeOverwriteFail, errOverFail)
	}

	// 4. Re-running with --overwrite should succeed (code 1 due to non-compliant control)
	codeOverwriteSuccess, _, errOverSucc := captureStdoutStderr(func() int {
		return run([]string{
			"compliance", "dossier", "generate",
			"--assessment", "ASM-CLI-01",
			"--catalog", "nist-sample",
			"--db", dbPath,
			"--output", dossierOut,
			"--overwrite",
		})
	})
	if codeOverwriteSuccess != clierror.ExitSecurityFail {
		t.Fatalf("expected ExitSecurityFail (1) with --overwrite, got %d (stderr: %s)",
			codeOverwriteSuccess, errOverSucc)
	}

	// 5. Test CLI validate subcommand
	codeVal, outVal, errVal := captureStdoutStderr(func() int {
		return run([]string{"compliance", "dossier", "validate", dossierOut})
	})
	if codeVal != clierror.ExitSuccess {
		t.Fatalf("expected ExitSuccess (0) for validate, got %d (stdout: %s, stderr: %s)", codeVal, outVal, errVal)
	}
	if !strings.Contains(outVal, "is VALID") {
		t.Errorf("expected 'is VALID' in validate output, got: %s", outVal)
	}

	// 6. Test CLI view subcommand
	codeView, outView, errView := captureStdoutStderr(func() int {
		return run([]string{"compliance", "dossier", "view", dossierOut})
	})
	if codeView != clierror.ExitSuccess {
		t.Fatalf("expected ExitSuccess (0) for view, got %d (stdout: %s, stderr: %s)", codeView, outView, errView)
	}
	if !strings.Contains(outView, "FELIX COMPLIANCE DOSSIER") {
		t.Errorf("expected header in view output, got: %s", outView)
	}
}

func TestCLI_Dossier_CleanAssessmentReturnsExitSuccess(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "compliance_clean.db")

	store, err := compliance.NewSQLiteComplianceStore(dbPath)
	if err != nil {
		t.Fatalf("NewSQLiteComplianceStore failed: %v", err)
	}
	defer store.Close()

	evalTime := time.Date(2026, 10, 21, 10, 0, 0, 0, time.UTC)
	evalRes := &compliance.EvaluationResult{
		AssessmentID:    "ASM-CLEAN-01",
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
				EvaluationID:       "eval:ASM-CLEAN-01:AC-1",
				ControlID:          "AC-1",
				ControlTitle:       "Access Policy",
				CatalogID:          "nist-sample",
				AssessmentID:       "ASM-CLEAN-01",
				State:              compliance.StateCompliant,
				Rationale:          "Policy active and enforced across infrastructure",
				SupportingEvidence: []string{"Access policy signed by CISO on 2026-01-10"},
				EvaluatedAt:        evalTime,
				EngineVersion:      "1.0.0",
			},
		},
	}
	if err := store.SaveEvaluationResult(evalRes); err != nil {
		t.Fatalf("SaveEvaluationResult failed: %v", err)
	}
	_ = store.Close()

	dossierOut := filepath.Join(tmpDir, "clean_dossier.json")

	// Assessment with 0 non-compliant controls returns ExitSuccess (0)
	code, _, errOut := captureStdoutStderr(func() int {
		return run([]string{
			"compliance", "dossier", "generate",
			"--assessment", "ASM-CLEAN-01",
			"--catalog", "nist-sample",
			"--db", dbPath,
			"--output", dossierOut,
		})
	})
	if code != clierror.ExitSuccess {
		t.Fatalf("expected ExitSuccess (0) for compliant assessment, got %d (stderr: %s)", code, errOut)
	}
}
