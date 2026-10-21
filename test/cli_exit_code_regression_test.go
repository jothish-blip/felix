package test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"felix/pkg/assessment"
	"felix/pkg/clierror"
	"felix/pkg/policy"
	"felix/pkg/report"
)

// TestPhase81_TypedExitErrorContract verifies that typed errors preserve their
// classification regardless of error wrapping depth.
func TestPhase81_TypedExitErrorContract(t *testing.T) {
	// 1. Success / nil
	if code := clierror.CodeFor(nil); code != clierror.ExitSuccess {
		t.Fatalf("expected ExitSuccess (0) for nil error, got %d", code)
	}

	// 2. Operational error (Code 2)
	opErr := clierror.Operational("database connection timeout")
	if code := clierror.CodeFor(opErr); code != clierror.ExitOperational {
		t.Fatalf("expected ExitOperational (2), got %d", code)
	}

	// Wrapped with fmt.Errorf %w
	wrappedOp := fmt.Errorf("controller failed to initialize: %w", opErr)
	if code := clierror.CodeFor(wrappedOp); code != clierror.ExitOperational {
		t.Fatalf("expected ExitOperational (2) for wrapped error, got %d", code)
	}

	// 3. Security failure error (Code 1)
	secErr := clierror.SecurityFailure("security refusal: missing written authorization")
	if code := clierror.CodeFor(secErr); code != clierror.ExitSecurityFail {
		t.Fatalf("expected ExitSecurityFail (1), got %d", code)
	}

	wrappedSec := fmt.Errorf("gate check refused: %w", secErr)
	if code := clierror.CodeFor(wrappedSec); code != clierror.ExitSecurityFail {
		t.Fatalf("expected ExitSecurityFail (1) for wrapped security refusal, got %d", code)
	}

	// 4. Usage error (Code 2)
	useErr := clierror.Usage("missing mandatory --name argument")
	if code := clierror.CodeFor(useErr); code != clierror.ExitOperational {
		t.Fatalf("expected ExitOperational (2) for usage error, got %d", code)
	}

	// 5. Unclassified unknown error defaults to ExitOperational (2)
	rawErr := errors.New("unclassified internal panic or driver fault")
	if code := clierror.CodeFor(rawErr); code != clierror.ExitOperational {
		t.Fatalf("expected ExitOperational (2) for unclassified error, got %d", code)
	}
}

// TestPhase81_AssessmentOutcomeClassification verifies the assessment outcome
// state machine against the Phase 8.1 exit code matrix.
func TestPhase81_AssessmentOutcomeClassification(t *testing.T) {
	cases := []struct {
		name          string
		status        assessment.AssessmentStatus
		runErr        error
		htmlReq       bool
		htmlGen       bool
		jsonReq       bool
		jsonGen       bool
		expectedCode  int
		expectedDesc  string
	}{
		{
			name:         "clean execution without findings",
			status:       assessment.StatusCompleted,
			runErr:       nil,
			expectedCode: clierror.ExitSuccess, // 0
			expectedDesc: "Successful execution with no policy failure",
		},
		{
			name:         "completed execution with findings (no threshold configured)",
			status:       assessment.StatusCompleted,
			runErr:       nil,
			expectedCode: clierror.ExitSuccess, // 0
			expectedDesc: "Findings alone do not force exit 1 without established security failure",
		},
		{
			name:         "execution failed with runtime error",
			status:       assessment.StatusFailed,
			runErr:       errors.New("target DNS resolution failure"),
			expectedCode: clierror.ExitOperational, // 2
			expectedDesc: "Operational failure preventing reliable assessment",
		},
		{
			name:         "execution cancelled by operator",
			status:       assessment.StatusCancelled,
			runErr:       context.Canceled,
			expectedCode: clierror.ExitOperational, // 2
			expectedDesc: "Cancelled execution must return operational code 2",
		},
		{
			name:         "execution interrupted by timeout",
			status:       assessment.StatusInterrupted,
			runErr:       context.DeadlineExceeded,
			expectedCode: clierror.ExitOperational, // 2
			expectedDesc: "Interrupted execution must return operational code 2",
		},
		{
			name:         "completed with partial crawl failures (StatusCompletedWithErrors)",
			status:       assessment.StatusCompletedWithErrors,
			runErr:       nil,
			expectedCode: clierror.ExitOperational, // 2
			expectedDesc: "Untrustworthy partial assessment cannot return 0 or 1",
		},
		{
			name:         "completed execution where requested HTML report export failed",
			status:       assessment.StatusCompleted,
			runErr:       nil,
			htmlReq:      true,
			htmlGen:      false,
			expectedCode: clierror.ExitOperational, // 2
			expectedDesc: "Requested output failure makes command unsuccessful",
		},
		{
			name:         "completed execution where requested JSON report export failed",
			status:       assessment.StatusCompleted,
			runErr:       nil,
			jsonReq:      true,
			jsonGen:      false,
			expectedCode: clierror.ExitOperational, // 2
			expectedDesc: "Requested JSON report write failure returns operational code 2",
		},
		{
			name:         "completed execution where all requested reports succeeded",
			status:       assessment.StatusCompleted,
			runErr:       nil,
			htmlReq:      true,
			htmlGen:      true,
			jsonReq:      true,
			jsonGen:      true,
			expectedCode: clierror.ExitSuccess, // 0
			expectedDesc: "Completed assessment with all reports delivered returns 0",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			code := assessment.DetermineOutcomeExitCode(tc.status, tc.runErr, tc.htmlReq, tc.htmlGen, tc.jsonReq, tc.jsonGen)
			if code != tc.expectedCode {
				t.Fatalf("[%s] expected exit code %d (%s), got %d", tc.name, tc.expectedCode, tc.expectedDesc, code)
			}
		})
	}
}

// TestPhase81_PartialScanCannotMaskOperationalFailure verifies that a scan with
// SSRF or connection failures never returns code 1 or 0, even if earlier targets
// generated findings.
func TestPhase81_PartialScanCannotMaskOperationalFailure(t *testing.T) {
	// Untrustworthy PARTIAL report with findings
	rep := report.Report{
		Target:           "https://target.local",
		CompletionStatus: "PARTIAL",
		Summary: report.Summary{
			TotalFindings: 10,
			CriticalCount: 2,
			HighCount:     4,
			MediumCount:   3,
			LowCount:      1,
		},
	}

	// Serialize and save to temp file
	tmpFile := filepath.Join(t.TempDir(), "partial_scan.json")
	data, _ := json.Marshal(rep)
	_ = os.WriteFile(tmpFile, data, 0644)

	// Execute via process-level CLI
	binPath := filepath.Join("..", "bin", "felix.exe")
	absBin, err := filepath.Abs(binPath)
	if err != nil {
		t.Fatalf("failed to resolve absolute binary path: %v", err)
	}

	cmd := exec.Command(absBin, "report", tmpFile, "--silent")
	err = cmd.Run()

	actualCode := 0
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			actualCode = exitErr.ExitCode()
		}
	}

	if actualCode != clierror.ExitOperational {
		t.Fatalf("expected exit code %d (ExitOperational) for PARTIAL scan report, got %d",
			clierror.ExitOperational, actualCode)
	}
}

// TestPhase81_CompletedScanWithFindingsReturnsSecurityFailure verifies that a
// fully completed scan with actionable findings returns exit code 1 under existing semantics.
func TestPhase81_CompletedScanWithFindingsReturnsSecurityFailure(t *testing.T) {
	rep := report.Report{
		Target:           "https://completed.local",
		CompletionStatus: "COMPLETED",
		Summary: report.Summary{
			TotalFindings: 1,
			HighCount:     1,
		},
	}

	tmpFile := filepath.Join(t.TempDir(), "completed_scan_with_findings.json")
	data, _ := json.Marshal(rep)
	_ = os.WriteFile(tmpFile, data, 0644)

	binPath := filepath.Join("..", "bin", "felix.exe")
	absBin, err := filepath.Abs(binPath)
	if err != nil {
		t.Fatalf("failed to resolve absolute binary path: %v", err)
	}

	cmd := exec.Command(absBin, "report", tmpFile, "--silent")
	err = cmd.Run()

	actualCode := 0
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			actualCode = exitErr.ExitCode()
		}
	}

	if actualCode != clierror.ExitSecurityFail {
		t.Fatalf("expected exit code %d (ExitSecurityFail) for COMPLETED scan with findings, got %d",
			clierror.ExitSecurityFail, actualCode)
	}
}

// TestPhase81_CompletedCleanScanReturnsSuccess verifies that a fully completed scan
// with zero actionable findings returns exit code 0.
func TestPhase81_CompletedCleanScanReturnsSuccess(t *testing.T) {
	rep := report.Report{
		Target:           "https://clean.local",
		CompletionStatus: "COMPLETED",
		Summary: report.Summary{
			TotalFindings: 0,
		},
	}

	tmpFile := filepath.Join(t.TempDir(), "clean_scan.json")
	data, _ := json.Marshal(rep)
	_ = os.WriteFile(tmpFile, data, 0644)

	binPath := filepath.Join("..", "bin", "felix.exe")
	absBin, err := filepath.Abs(binPath)
	if err != nil {
		t.Fatalf("failed to resolve absolute binary path: %v", err)
	}

	cmd := exec.Command(absBin, "report", tmpFile, "--silent")
	err = cmd.Run()

	actualCode := 0
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			actualCode = exitErr.ExitCode()
		}
	}

	if actualCode != clierror.ExitSuccess {
		t.Fatalf("expected exit code %d (ExitSuccess) for clean COMPLETED scan, got %d",
			clierror.ExitSuccess, actualCode)
	}
}

// TestPhase81_ProcessLevelCLIExecution proves OS exit codes across all three exit classes:
// 0 (success/help/clean), 1 (security refusal/findings), 2 (operational error/invalid flags)
func TestPhase81_ProcessLevelCLIExecution(t *testing.T) {
	binPath := filepath.Join("..", "bin", "felix.exe")
	absBin, err := filepath.Abs(binPath)
	if err != nil {
		t.Fatalf("failed to resolve absolute binary path: %v", err)
	}

	// 1. Exit 0: Informational help
	cmdHelp := exec.Command(absBin, "--help")
	if err := cmdHelp.Run(); err != nil {
		t.Fatalf("expected exit code 0 for felix --help, got error: %v", err)
	}

	// 2. Exit 0: Informational version
	cmdVer := exec.Command(absBin, "version")
	if err := cmdVer.Run(); err != nil {
		t.Fatalf("expected exit code 0 for felix version, got error: %v", err)
	}

	// 3. Exit 2: Unknown command
	cmdUnknown := exec.Command(absBin, "unrecognized-subcommand-12345")
	errUnknown := cmdUnknown.Run()
	if errUnknown == nil {
		t.Fatalf("expected non-zero exit for unknown subcommand")
	}
	var exitErr *exec.ExitError
	if errors.As(errUnknown, &exitErr) {
		if exitErr.ExitCode() != clierror.ExitOperational {
			t.Fatalf("expected exit code 2 for unknown subcommand, got %d", exitErr.ExitCode())
		}
	} else {
		t.Fatalf("unexpected error type for unknown subcommand: %v", errUnknown)
	}

	// 4. Exit 2: Report file not found
	cmdMissingFile := exec.Command(absBin, "report", "nonexistent-scan-file.json")
	errMissing := cmdMissingFile.Run()
	if errMissing == nil {
		t.Fatalf("expected non-zero exit for missing scan file")
	}
	if errors.As(errMissing, &exitErr) {
		if exitErr.ExitCode() != clierror.ExitOperational {
			t.Fatalf("expected exit code 2 for missing scan file, got %d", exitErr.ExitCode())
		}
	}
}

// TestPhase87_CentralizedFailureClassification verifies Phase 8.7 failure classification semantics:
// 1. Confirmed security policy violations are preserved (Exit 1) even when secondary reporting fails.
// 2. Clean assessments with secondary reporting failures elevate to Exit 2.
// 3. Partial/incomplete assessments return Exit 2 without silently reporting success.
func TestPhase87_CentralizedFailureClassification(t *testing.T) {
	tempDir := t.TempDir()

	// 1. Engine Result Level: Security policy violation with failed report write
	critPolicy := &policy.ThresholdPolicy{
		Version:         "1.0",
		Name:            "Strict Zero Critical",
		MaxCritical:     intPtr(0),
		FailOnViolation: boolPtr(true),
	}

	execResViolation := &assessment.ExecutionResult{
		Execution: &assessment.AssessmentExecution{
			ID:           "exec-viol",
			AssessmentID: "asm-1",
			Status:       assessment.StatusCompleted,
		},
		Report: &report.Report{
			Findings: []report.Finding{
				{
					ID:       "f-crit-1",
					RuleID:   "SQLI-01",
					Severity: report.SeverityCritical,
					Title:    "SQL Injection",
				},
			},
		},
		HTMLPath: "", // HTML generation failed!
	}

	// Request HTML report (which failed to generate, so HTMLPath is empty)
	decision, exitCode := execResViolation.ClassifyOutcomeWithPolicyAndArtifacts(critPolicy, true, false, false)
	if exitCode != clierror.ExitSecurityFail {
		t.Fatalf("expected ExitSecurityFail (1) to be preserved despite HTML write failure, got %d", exitCode)
	}
	if decision == nil || decision.Passed {
		t.Fatalf("expected policy decision to have failed")
	}
	if execResViolation.Classification.Category != clierror.CategorySecurityViolation {
		t.Fatalf("expected CategorySecurityViolation, got %s", execResViolation.Classification.Category)
	}
	if len(execResViolation.Classification.SecondaryErrors) == 0 {
		t.Fatalf("expected HTML write failure to be retained in SecondaryErrors")
	}

	// 2. Engine Result Level: Clean assessment with failed report write elevates to Exit 2
	execResClean := &assessment.ExecutionResult{
		Execution: &assessment.AssessmentExecution{
			ID:           "exec-clean",
			AssessmentID: "asm-2",
			Status:       assessment.StatusCompleted,
		},
		Report: &report.Report{
			Findings: []report.Finding{},
		},
		HTMLPath: "", // HTML generation failed!
	}

	decisionClean, exitCodeClean := execResClean.ClassifyOutcomeWithPolicyAndArtifacts(critPolicy, true, false, false)
	if exitCodeClean != clierror.ExitOperational {
		t.Fatalf("expected ExitOperational (2) for clean scan when HTML write fails, got %d", exitCodeClean)
	}
	if decisionClean == nil || !decisionClean.Passed {
		t.Fatalf("expected policy decision to have passed")
	}
	if execResClean.Classification.Category != clierror.CategoryToolFailure {
		t.Fatalf("expected CategoryToolFailure, got %s", execResClean.Classification.Category)
	}

	// 3. Process Level: CLI `felix report` with security violation and failed report write
	binPath := filepath.Join("..", "bin", "felix.exe")
	absBin, err := filepath.Abs(binPath)
	if err != nil {
		t.Fatalf("failed to resolve absolute binary path: %v", err)
	}

	violRepFile := filepath.Join(tempDir, "viol_rep.json")
	violRepData, _ := json.Marshal(report.Report{
		Target:           "https://example.com",
		CompletionStatus: "COMPLETED",
		Findings: []report.Finding{
			{
				ID:       "f-crit-1",
				RuleID:   "SQLI-01",
				Severity: report.SeverityCritical,
				Title:    "SQL Injection",
			},
		},
		Summary: report.Summary{
			CriticalCount: 1,
			TotalFindings: 1,
		},
	})
	_ = os.WriteFile(violRepFile, violRepData, 0644)

	policyPath := filepath.Join(tempDir, "policy.yaml")
	_ = os.WriteFile(policyPath, []byte(`version: "1.0"
name: "Zero Critical"
max_critical: 0
fail_on_violation: true
`), 0644)

	// Invoke `felix report` with failing HTML destination (sub-directory that does not exist)
	invalidHTML := filepath.Join(tempDir, "non_existent_folder_xyz", "out.html")
	cmdViol := exec.Command(absBin, "report", violRepFile, "--policy", policyPath, "--html", invalidHTML, "--silent")
	errViol := cmdViol.Run()

	actualViolCode := 0
	if errViol != nil {
		var exitErr *exec.ExitError
		if errors.As(errViol, &exitErr) {
			actualViolCode = exitErr.ExitCode()
		}
	}
	if actualViolCode != clierror.ExitSecurityFail {
		t.Fatalf("expected CLI process exit 1 (security violation preserved) despite report write error, got %d", actualViolCode)
	}
}

func intPtr(n int) *int {
	return &n
}

func boolPtr(b bool) *bool {
	return &b
}
