package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	_ "modernc.org/sqlite"

	"felix/pkg/clierror"
	"felix/pkg/compliance"
)

func setupTestDBWithAssessment(t *testing.T, dbPath string, assessmentID string, compliantOnly bool) {
	t.Helper()
	store, err := compliance.NewSQLiteComplianceStore(dbPath)
	if err != nil {
		t.Fatalf("NewSQLiteComplianceStore failed: %v", err)
	}
	defer store.Close()

	evalTime := time.Date(2026, 10, 21, 10, 0, 0, 0, time.UTC)
	var evals []compliance.ControlEvaluationRecord

	if compliantOnly {
		evals = []compliance.ControlEvaluationRecord{
			{
				EvaluationID:       fmt.Sprintf("eval:%s:AC-1", assessmentID),
				ControlID:          "AC-1",
				ControlTitle:       "Access Control Policy",
				CatalogID:          "nist-sample",
				AssessmentID:       assessmentID,
				State:              compliance.StateCompliant,
				Rationale:          "Access control policy verified and approved by CISO",
				SupportingEvidence: []string{"Approved policy document v2.4"},
				EvaluatedAt:        evalTime,
				EngineVersion:      compliance.CurrentEvaluationEngineVersion,
			},
		}
	} else {
		evals = []compliance.ControlEvaluationRecord{
			{
				EvaluationID:          fmt.Sprintf("eval:%s:AC-2", assessmentID),
				ControlID:             "AC-2",
				ControlTitle:          "Account Management",
				CatalogID:             "nist-sample",
				AssessmentID:          assessmentID,
				State:                 compliance.StateNonCompliant,
				Rationale:             "Dormant privileged accounts found",
				FindingIDs:            []string{"F-DORMANT-01"},
				ContradictingEvidence: []string{"3 admin accounts unused > 90 days"},
				EvaluatedAt:           evalTime,
				EngineVersion:         compliance.CurrentEvaluationEngineVersion,
			},
		}
	}

	summary := compliance.EvaluationSummary{
		TotalControls: len(evals),
	}
	if compliantOnly {
		summary.CompliantCount = 1
	} else {
		summary.NonCompliantCount = 1
	}

	evalRes := &compliance.EvaluationResult{
		AssessmentID:    assessmentID,
		CatalogIdentity: "nist-sample:1.0.0",
		CatalogDigest:   "sha256:1111111111111111111111111111111111111111111111111111111111111111",
		EngineVersion:   compliance.CurrentEvaluationEngineVersion,
		EvaluatedAt:     evalTime,
		Summary:         summary,
		Evaluations:     evals,
	}

	if err := store.SaveEvaluationResult(evalRes); err != nil {
		t.Fatalf("SaveEvaluationResult failed: %v", err)
	}
}

// ============================================================================
// AREA 2: CLI EXIT CODES AND MACHINE-READABLE STDOUT
// ============================================================================

func TestCLI_Dossier_Targeted_ExitCodes(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "compliance_exit_codes.db")

	setupTestDBWithAssessment(t, dbPath, "ASM-NON-COMPLIANT", false)
	setupTestDBWithAssessment(t, dbPath, "ASM-COMPLIANT", true)

	// Sub-case 1: Trustworthy completed dossier containing non-compliant controls -> exit code 1
	codeNC, outNC, errNC := captureStdoutStderr(func() int {
		return run([]string{
			"compliance", "dossier", "generate",
			"--assessment", "ASM-NON-COMPLIANT",
			"--catalog", "nist-sample",
			"--db", dbPath,
		})
	})
	if codeNC != clierror.ExitSecurityFail {
		t.Errorf("expected ExitSecurityFail (1) for non-compliant controls, got %d (stdout: %s, stderr: %s)",
			codeNC, outNC, errNC)
	}

	// Sub-case 2: Trustworthy completed dossier without established policy violations -> exit code 0
	codeC, outC, errC := captureStdoutStderr(func() int {
		return run([]string{
			"compliance", "dossier", "generate",
			"--assessment", "ASM-COMPLIANT",
			"--catalog", "nist-sample",
			"--db", dbPath,
		})
	})
	if codeC != clierror.ExitSuccess {
		t.Errorf("expected ExitSuccess (0) for fully compliant controls, got %d (stdout: %s, stderr: %s)",
			codeC, outC, errC)
	}

	// Sub-case 3: Operational failure: non-existent assessment -> exit code 2
	codeNotFound, _, errNotFound := captureStdoutStderr(func() int {
		return run([]string{
			"compliance", "dossier", "generate",
			"--assessment", "ASM-DOES-NOT-EXIST",
			"--catalog", "nist-sample",
			"--db", dbPath,
		})
	})
	if codeNotFound != clierror.ExitOperational {
		t.Errorf("expected ExitOperational (2) for non-existent assessment, got %d (stderr: %s)",
			codeNotFound, errNotFound)
	}

	// Sub-case 4: Operational failure: validate corrupted dossier file -> exit code 2
	corruptFile := filepath.Join(tmpDir, "corrupted_dossier.json")
	if err := os.WriteFile(corruptFile, []byte("{ malformed json content"), 0600); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}
	codeCorrupt, _, errCorrupt := captureStdoutStderr(func() int {
		return run([]string{
			"compliance", "dossier", "validate", corruptFile,
		})
	})
	if codeCorrupt != clierror.ExitOperational {
		t.Errorf("expected ExitOperational (2) for corrupted dossier validation, got %d (stderr: %s)",
			codeCorrupt, errCorrupt)
	}

	// Sub-case 5: Strict integrity failure -> exit code 2
	// Tamper with SQLite evaluation record directly so integrity check fails
	rawDB, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("failed opening raw sqlite db: %v", err)
	}
	_, _ = rawDB.Exec("UPDATE compliance_control_evaluations SET rationale = 'TAMPERED VIA SQL' WHERE assessment_id = 'ASM-COMPLIANT'")
	_ = rawDB.Close()

	codeStrictFail, _, errStrictFail := captureStdoutStderr(func() int {
		return run([]string{
			"compliance", "dossier", "generate",
			"--assessment", "ASM-COMPLIANT",
			"--catalog", "nist-sample",
			"--db", dbPath,
			"--strict-integrity",
		})
	})
	if codeStrictFail != clierror.ExitOperational {
		t.Errorf("expected ExitOperational (2) for strict integrity failure, got %d (stderr: %s)",
			codeStrictFail, errStrictFail)
	}
	if !strings.Contains(errStrictFail, "integrity") {
		t.Errorf("expected integrity mismatch message in stderr, got: %s", errStrictFail)
	}
}

func TestCLI_Dossier_Targeted_MachineReadableStdout(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "compliance_stdout.db")
	setupTestDBWithAssessment(t, dbPath, "ASM-STDOUT-CLEAN", true)

	// Run generate without --output flag (writing to stdout)
	code, stdoutStr, stderrStr := captureStdoutStderr(func() int {
		return run([]string{
			"compliance", "dossier", "generate",
			"--assessment", "ASM-STDOUT-CLEAN",
			"--catalog", "nist-sample",
			"--db", dbPath,
		})
	})

	if code != clierror.ExitSuccess {
		t.Fatalf("expected ExitSuccess (0), got %d (stderr: %s)", code, stderrStr)
	}

	// Stdout must parse cleanly as JSON
	var parsed compliance.ComplianceDossier
	if err := json.Unmarshal([]byte(stdoutStr), &parsed); err != nil {
		t.Fatalf("stdout failed to parse as valid ComplianceDossier JSON: %v\nOutput was:\n%s", err, stdoutStr)
	}

	if parsed.Identity.AssessmentID != "ASM-STDOUT-CLEAN" {
		t.Errorf("expected assessment_id ASM-STDOUT-CLEAN, got %s", parsed.Identity.AssessmentID)
	}
	if len(parsed.Controls) != 1 {
		t.Errorf("expected 1 control, got %d", len(parsed.Controls))
	}
	if !strings.HasPrefix(parsed.LogicalDigest, "sha256:") {
		t.Errorf("expected sha256 prefix on logical_digest, got: %s", parsed.LogicalDigest)
	}

	// Stdout must NOT contain any log prefixes like "[-]" or "[+]"
	if strings.Contains(stdoutStr, "[-] ") || strings.Contains(stdoutStr, "[+] ") {
		t.Errorf("stdout contains progress or diagnostic noise: %s", stdoutStr)
	}
}

// ============================================================================
// AREA 4: OUTPUT SAFETY AND OVERWRITE BEHAVIOR
// ============================================================================

func TestCLI_Dossier_Targeted_OverwriteProtection(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "compliance_overwrite.db")
	setupTestDBWithAssessment(t, dbPath, "ASM-OVERWRITE-TEST", true)

	targetFile := filepath.Join(tmpDir, "existing_dossier.json")
	initialContent := []byte("ORIGINAL_PROTECTED_CONTENT")
	if err := os.WriteFile(targetFile, initialContent, 0600); err != nil {
		t.Fatalf("failed creating initial target file: %v", err)
	}

	// 1. Attempting to write to existing file WITHOUT --overwrite MUST fail with ExitOperational (2)
	codeNoOverwrite, _, errNoOverwrite := captureStdoutStderr(func() int {
		return run([]string{
			"compliance", "dossier", "generate",
			"--assessment", "ASM-OVERWRITE-TEST",
			"--catalog", "nist-sample",
			"--output", targetFile,
			"--db", dbPath,
		})
	})
	if codeNoOverwrite != clierror.ExitOperational {
		t.Errorf("expected ExitOperational (2) when target file exists and --overwrite not specified, got %d", codeNoOverwrite)
	}
	if !strings.Contains(errNoOverwrite, "already exists") {
		t.Errorf("expected 'already exists' in stderr, got: %s", errNoOverwrite)
	}

	// Verify original file was NOT modified
	currentContent, _ := os.ReadFile(targetFile)
	if string(currentContent) != string(initialContent) {
		t.Errorf("target file content was overwritten despite lack of --overwrite flag!")
	}

	// 2. Writing to existing file WITH --overwrite MUST succeed
	codeWithOverwrite, _, errWithOverwrite := captureStdoutStderr(func() int {
		return run([]string{
			"compliance", "dossier", "generate",
			"--assessment", "ASM-OVERWRITE-TEST",
			"--catalog", "nist-sample",
			"--output", targetFile,
			"--overwrite",
			"--db", dbPath,
		})
	})
	if codeWithOverwrite != clierror.ExitSuccess {
		t.Fatalf("expected ExitSuccess (0) with --overwrite, got %d (stderr: %s)", codeWithOverwrite, errWithOverwrite)
	}

	// Verify target file was replaced with valid dossier JSON
	newContent, _ := os.ReadFile(targetFile)
	if string(newContent) == string(initialContent) {
		t.Errorf("target file was not updated with --overwrite")
	}
	var replacedDossier compliance.ComplianceDossier
	if err := json.Unmarshal(newContent, &replacedDossier); err != nil {
		t.Fatalf("overwritten file does not contain valid ComplianceDossier JSON: %v", err)
	}

	// 3. Verify failed generation leaves NO temporary files
	failTargetFile := filepath.Join(tmpDir, "failed_dossier.json")
	codeFail, _, _ := captureStdoutStderr(func() int {
		return run([]string{
			"compliance", "dossier", "generate",
			"--assessment", "NON-EXISTENT-ASM-999",
			"--catalog", "nist-sample",
			"--output", failTargetFile,
			"--db", dbPath,
		})
	})
	if codeFail != clierror.ExitOperational {
		t.Errorf("expected ExitOperational (2), got %d", codeFail)
	}

	// Target file must not exist
	if _, err := os.Stat(failTargetFile); err == nil {
		t.Errorf("failed generation left partial file at %s", failTargetFile)
	}

	// No .tmp files should exist in directory
	files, _ := os.ReadDir(tmpDir)
	for _, f := range files {
		if strings.Contains(f.Name(), ".tmp.") {
			t.Errorf("failed generation left dangling temporary file: %s", f.Name())
		}
	}
}
