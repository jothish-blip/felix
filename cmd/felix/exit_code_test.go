package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"felix/pkg/assessment"
	"felix/pkg/clierror"
	"felix/pkg/report"
	"github.com/google/uuid"
)

// 1. Help and Version commands retain expected exit code 0
func TestCLI_ExitCode_HelpAndVersion(t *testing.T) {
	testCases := []struct {
		name string
		args []string
	}{
		{"empty args shows root help", []string{}},
		{"flag --help", []string{"--help"}},
		{"flag -h", []string{"-h"}},
		{"command help", []string{"help"}},
		{"subcommand help scan", []string{"help", "scan"}},
		{"subcommand help assessment", []string{"help", "assessment"}},
		{"subcommand help report", []string{"help", "report"}},
		{"subcommand help apk", []string{"help", "apk"}},
		{"subcommand flag --help", []string{"assessment", "--help"}},
		{"command version", []string{"version"}},
		{"flag --version", []string{"--version"}},
		{"flag -V", []string{"-V"}},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			code, _, _ := captureStdoutStderr(func() int {
				return run(tc.args)
			})
			if code != clierror.ExitSuccess {
				t.Fatalf("expected exit code %d for %v, got %d", clierror.ExitSuccess, tc.args, code)
			}
		})
	}
}

// 2. Invalid commands, arguments, and configuration failures return exit code 2 (ExitOperational)
func TestCLI_ExitCode_OperationalArguments(t *testing.T) {
	testCases := []struct {
		name string
		args []string
	}{
		{"unknown command", []string{"nonexistent-command-xyz"}},
		{"scan conflicting flags", []string{"scan", "--quiet", "--verbose", "http://127.0.0.1:8080"}},
		{"scan invalid timeout", []string{"scan", "--timeout", "invalid", "http://127.0.0.1:8080"}},
		{"scan negative concurrency", []string{"scan", "--concurrency", "-5", "http://127.0.0.1:8080"}},
		{"scan malformed url", []string{"scan", "http://"}},
		{"scan embedded credentials", []string{"scan", "http://user:pass@example.com"}},
		{"assessment run missing ref", []string{"assessment", "run"}},
		{"assessment run invalid timeout", []string{"assessment", "run", "asm-123", "--timeout", "not-a-duration"}},
		{"report missing arg", []string{"report"}},
		{"report nonexistent file", []string{"report", "does-not-exist.json"}},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			code, _, errOut := captureStdoutStderr(func() int {
				return run(tc.args)
			})
			if code != clierror.ExitOperational {
				t.Fatalf("expected exit code %d for %v, got %d (stderr: %s)", clierror.ExitOperational, tc.args, code, errOut)
			}
		})
	}
}

// 3. Completed assessment with findings but no established security-failure decision returns 0
func TestCLI_ExitCode_CompletedAssessmentWithFindingsReturnsZero(t *testing.T) {
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "felix_test.db")
	t.Setenv("FELIX_DB_PATH", dbPath)

	store, err := assessment.NewSQLiteStore(dbPath)
	if err != nil {
		t.Fatalf("failed to create test store: %v", err)
	}
	defer store.Close()

	// Setup client and assessment
	c := &assessment.Client{
		ID:        uuid.New().String(),
		Name:      "Test Client",
		CreatedAt: time.Now().UTC(),
		UpdatedAt: time.Now().UTC(),
	}
	_ = store.CreateClient(c)

	asm := &assessment.Assessment{
		ID:             uuid.New().String(),
		Ref:            "ASM-EXIT-001",
		ClientID:       c.ID,
		Name:           "Exit Code Test Assessment",
		AssessmentType: assessment.AssessmentTypeWebSecurity,
		Status:         assessment.StatusReady,
		ScopeMode:      "same-origin",
		CreatedAt:      time.Now().UTC(),
		UpdatedAt:      time.Now().UTC(),
	}
	_ = store.CreateAssessment(asm)

	// Local test server
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`<html><body><h1>Felix Audit Target</h1></body></html>`))
	}))
	defer ts.Close()

	normTarget, _ := assessment.NormalizeTargetURL(ts.URL)
	_ = store.AddTarget(&assessment.AssessmentTarget{
		ID:           uuid.New().String(),
		AssessmentID: asm.ID,
		TargetURL:    normTarget,
		TargetType:   assessment.TargetWebsite,
		ScopeStatus:  "APPROVED",
		CreatedAt:    time.Now().UTC(),
	})

	now := time.Now().UTC()
	future := now.Add(24 * time.Hour)
	past := now.Add(-24 * time.Hour)
	_ = store.SetAuthorization(&assessment.AuthorizationRecord{
		ID:                  uuid.New().String(),
		AssessmentID:        asm.ID,
		AuthorizingParty:    "Security Lead",
		AuthorizationMethod: "WRITTEN_CONSENT",
		DateReceived:        past,
		ValidFrom:           &past,
		ValidUntil:          &future,
		Status:              assessment.AuthApproved,
	})

	t.Setenv("FELIX_ALLOW_LOOPBACK", "true")

	// Execute assessment run
	code, out, errOut := captureStdoutStderr(func() int {
		return runAssessmentRun([]string{asm.Ref, "--quiet"})
	})

	if code != clierror.ExitSuccess {
		t.Fatalf("expected exit code %d for completed assessment without policy threshold, got %d (stdout: %s, stderr: %s)",
			clierror.ExitSuccess, code, out, errOut)
	}
}

// 4. Assessment execution with crawl failures (StatusCompletedWithErrors) returns 2
func TestCLI_ExitCode_CompletedWithErrorsReturnsTwo(t *testing.T) {
	// A completed-with-errors assessment means partial coverage due to crawl defects
	// Verify that DetermineOutcomeExitCode classifies StatusCompletedWithErrors as ExitOperational (2)
	code := assessment.DetermineOutcomeExitCode(assessment.StatusCompletedWithErrors, nil, false, false, false, false)
	if code != clierror.ExitOperational {
		t.Fatalf("expected ExitOperational (2) for StatusCompletedWithErrors, got %d", code)
	}

	// Verify failed, cancelled, and interrupted statuses also return 2
	for _, st := range []assessment.AssessmentStatus{
		assessment.StatusFailed,
		assessment.StatusCancelled,
		assessment.StatusInterrupted,
	} {
		c := assessment.DetermineOutcomeExitCode(st, nil, false, false, false, false)
		if c != clierror.ExitOperational {
			t.Fatalf("expected ExitOperational (2) for status %s, got %d", st, c)
		}
	}
}

// 5. Scan & Report Exit Code Semantics:
// - Clean / INFO only -> 0
// - Findings on completed scan -> 1 (established security failure under existing scan semantics)
// - Partial / Blocked / Failed / Interrupted -> 2 (untrustworthy result, even if findings exist!)
func TestCLI_ExitCode_ReportAndScanOutcomeMapping(t *testing.T) {
	// A: Clean completed scan -> 0
	cleanRep := report.Report{
		CompletionStatus: "COMPLETED",
		Summary: report.Summary{
			TotalFindings: 0,
		},
	}
	if code := determineExitCode(cleanRep); code != clierror.ExitSuccess {
		t.Fatalf("expected ExitSuccess (0) for clean scan, got %d", code)
	}

	// B: Completed scan with actionable findings -> 1
	findingRep := report.Report{
		CompletionStatus: "COMPLETED",
		Summary: report.Summary{
			TotalFindings: 2,
			HighCount:     1,
			LowCount:      1,
		},
	}
	if code := determineExitCode(findingRep); code != clierror.ExitSecurityFail {
		t.Fatalf("expected ExitSecurityFail (1) for completed scan with high finding, got %d", code)
	}

	// C: Untrustworthy PARTIAL assessment with findings -> MUST RETURN 2, NEVER 1
	partialRepWithFindings := report.Report{
		CompletionStatus: "PARTIAL",
		Summary: report.Summary{
			TotalFindings: 5,
			CriticalCount: 1,
			HighCount:     2,
		},
	}
	if code := determineExitCode(partialRepWithFindings); code != clierror.ExitOperational {
		t.Fatalf("expected ExitOperational (2) for partial scan despite findings, got %d", code)
	}

	// D: Blocked, Failed, Cancelled, Interrupted, CompletedWithErrors -> MUST RETURN 2
	for _, status := range []string{
		"BLOCKED",
		"FAILED",
		"CANCELLED",
		"INTERRUPTED",
		"COMPLETED_WITH_ERRORS",
		"INCOMPLETE",
		"INSUFFICIENT_COVERAGE",
	} {
		rep := report.Report{
			CompletionStatus: status,
			Summary: report.Summary{
				TotalFindings: 3,
				HighCount:     2,
			},
		}
		if code := determineExitCode(rep); code != clierror.ExitOperational {
			t.Fatalf("expected ExitOperational (2) for status %s despite findings, got %d", status, code)
		}
	}
}

// 6. Report generation failures (HTML, JSON, SARIF) return exit code 2
func TestCLI_ExitCode_ReportWriteFailureReturnsTwo(t *testing.T) {
	tempDir := t.TempDir()
	validJSON := filepath.Join(tempDir, "scan_result.json")

	rep := report.Report{
		Target:           "https://example.com",
		CompletionStatus: "COMPLETED",
		Timestamp:        time.Now().UTC().Format(time.RFC3339),
		Duration:         "1s",
	}
	data, _ := json.Marshal(rep)
	_ = os.WriteFile(validJSON, data, 0644)

	testCases := []struct {
		name string
		flag string
		file string
	}{
		{"HTML write failure", "--html", "report.html"},
		{"JSON write failure", "--json", "report.json"},
		{"SARIF write failure", "--sarif", "report.sarif"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			invalidDest := filepath.Join(tempDir, "nonexistent_dir_123", "sub", tc.file)
			code, _, errOut := captureStdoutStderr(func() int {
				return runReport([]string{validJSON, tc.flag, invalidDest})
			})

			if code != clierror.ExitOperational {
				t.Fatalf("expected ExitOperational (2) for %s, got %d (stderr: %s)", tc.name, code, errOut)
			}
		})
	}
}

// 6b. Scan SARIF export failure returns exit code 2
func TestCLI_ExitCode_ScanSARIFWriteFailureReturnsTwo(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`<html><body><h1>Target</h1></body></html>`))
	}))
	defer ts.Close()

	tempDir := t.TempDir()
	invalidDest := filepath.Join(tempDir, "nonexistent_sub_dir", "out.sarif")

	code, _, errOut := captureStdoutStderr(func() int {
		return runScan([]string{"--allow-loopback", "--quiet", "--sarif", invalidDest, ts.URL})
	})

	if code != clierror.ExitOperational {
		t.Fatalf("expected ExitOperational (2) for scan SARIF write failure, got %d (stderr: %s)", code, errOut)
	}
}

// 7. Security refusal explicitly returns 1
func TestCLI_ExitCode_SecurityRefusalReturnsOne(t *testing.T) {
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "refusal_test.db")
	t.Setenv("FELIX_DB_PATH", dbPath)

	store, err := assessment.NewSQLiteStore(dbPath)
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}
	defer store.Close()

	c := &assessment.Client{
		ID:        uuid.New().String(),
		Name:      "Refusal Client",
		CreatedAt: time.Now().UTC(),
		UpdatedAt: time.Now().UTC(),
	}
	_ = store.CreateClient(c)

	asm := &assessment.Assessment{
		ID:             uuid.New().String(),
		Ref:            "ASM-REFUSE-01",
		ClientID:       c.ID,
		Name:           "Refusal Assessment",
		AssessmentType: assessment.AssessmentTypeAPISecurity,
		Status:         assessment.StatusDraft,
		CreatedAt:      time.Now().UTC(),
		UpdatedAt:      time.Now().UTC(),
	}
	_ = store.CreateAssessment(asm)

	_ = store.AddTarget(&assessment.AssessmentTarget{
		ID:           uuid.New().String(),
		AssessmentID: asm.ID,
		TargetURL:    "http://127.0.0.1:8080",
		TargetType:   assessment.TargetAPIBaseURL,
		ScopeStatus:  "APPROVED",
		CreatedAt:    time.Now().UTC(),
	})

	// Do NOT authorize the assessment
	// Running active assessment must result in security refusal -> exit code 1
	code, _, errOut := captureStdoutStderr(func() int {
		return runAssessmentAPISec([]string{asm.Ref, "--run"})
	})

	if code != clierror.ExitSecurityFail {
		t.Fatalf("expected ExitSecurityFail (1) for unauthorized active assessment, got %d (stderr: %s)", code, errOut)
	}
	if !strings.Contains(errOut, "Security refusal") {
		t.Fatalf("expected security refusal message in stderr, got: %s", errOut)
	}
}

// 8. Real Process-Level Binary Verification
// Proves that the actual compiled binary returns the expected OS exit code to the shell
func TestCLI_ExitCode_RealExecutableOSCodes(t *testing.T) {
	binPath := filepath.Join("..", "..", "bin", "felix.exe")
	if _, err := os.Stat(binPath); os.IsNotExist(err) {
		// Build binary for testing if not yet built
		buildCmd := exec.Command("go", "build", "-o", binPath, ".")
		if out, err := buildCmd.CombinedOutput(); err != nil {
			t.Fatalf("failed to build binary for OS exit code test: %v (output: %s)", err, string(out))
		}
	}

	absBin, err := filepath.Abs(binPath)
	if err != nil {
		t.Fatalf("failed to get absolute path: %v", err)
	}

	tempDir := t.TempDir()
	sampleScan := filepath.Join(tempDir, "sample_scan.json")
	rep := report.Report{
		Target:           "https://example.com",
		CompletionStatus: "COMPLETED",
		Timestamp:        time.Now().UTC().Format(time.RFC3339),
		Duration:         "1s",
		Findings: []report.Finding{
			{ID: "f1", Title: "H1", Severity: "HIGH", Category: "v1", Endpoint: "/1", Method: "GET"},
		},
	}
	report.RecalculateReportRisk(&rep)
	data, _ := json.Marshal(rep)
	_ = os.WriteFile(sampleScan, data, 0644)

	strictPolicy := filepath.Join(tempDir, "strict.json")
	_ = os.WriteFile(strictPolicy, []byte(`{"version":"1.0","max_high":0,"fail_on_violation":true}`), 0644)

	permPolicy := filepath.Join(tempDir, "permissive.json")
	_ = os.WriteFile(permPolicy, []byte(`{"version":"1.0","max_high":5,"fail_on_violation":true}`), 0644)

	testCases := []struct {
		name         string
		args         []string
		expectedCode int
	}{
		{"OS exit code 0 for --help", []string{"--help"}, 0},
		{"OS exit code 0 for --version", []string{"--version"}, 0},
		{"OS exit code 2 for unknown command", []string{"nonexistent-command-xyz"}, 2},
		{"OS exit code 2 for report nonexistent file", []string{"report", "completely_missing_scan.json"}, 2},
		{"OS exit code 1 for policy threshold violation", []string{"report", sampleScan, "--policy", strictPolicy}, 1},
		{"OS exit code 0 for policy threshold satisfied", []string{"report", sampleScan, "--policy", permPolicy}, 0},
		{"OS exit code 2 for unreadable policy file", []string{"report", sampleScan, "--policy", filepath.Join(tempDir, "missing.json")}, 2},
		{"OS exit code 0 for report with valid --sarif", []string{"report", sampleScan, "--sarif", filepath.Join(tempDir, "out.sarif")}, 0},
		{"OS exit code 2 for report with unwritable --sarif path", []string{"report", sampleScan, "--sarif", filepath.Join(tempDir, "nonexistent_dir", "out.sarif")}, 2},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			cmd := exec.Command(absBin, tc.args...)
			err := cmd.Run()

			actualExitCode := 0
			if err != nil {
				if exitErr, ok := err.(*exec.ExitError); ok {
					actualExitCode = exitErr.ExitCode()
				} else {
					t.Fatalf("failed to execute binary %s: %v", absBin, err)
				}
			}

			if actualExitCode != tc.expectedCode {
				t.Fatalf("expected OS exit code %d for %v, got %d", tc.expectedCode, tc.args, actualExitCode)
			}
		})
	}
}

// 9. Phase 8.2 Security Threshold Policy CLI Integration:
// - Report evaluation with policy:
//   - Satisfied thresholds -> exit code 0
//   - Violated thresholds -> exit code 1
//   - Missing or malformed policy file -> exit code 2
//   - Untrustworthy status -> exit code 2
func TestCLI_ExitCode_SecurityThresholdPolicy_Report(t *testing.T) {
	tempDir := t.TempDir()

	// Create test scan result with 2 High findings and 0 Critical
	scanFile := filepath.Join(tempDir, "scan_findings.json")
	rep := report.Report{
		Target:           "https://example.com",
		CompletionStatus: "COMPLETED",
		Timestamp:        time.Now().UTC().Format(time.RFC3339),
		Duration:         "1s",
		Findings: []report.Finding{
			{ID: "f1", Title: "High 1", Severity: "HIGH", Category: "vuln-1", Endpoint: "/api/1", Method: "GET"},
			{ID: "f2", Title: "High 2", Severity: "HIGH", Category: "vuln-2", Endpoint: "/api/2", Method: "GET"},
		},
	}
	report.RecalculateReportRisk(&rep)
	data, _ := json.Marshal(rep)
	_ = os.WriteFile(scanFile, data, 0644)

	// Strict Policy: MaxHigh = 0 -> MUST FAIL (observed 2 > allowed 0) -> ExitSecurityFail (1)
	strictPolicyPath := filepath.Join(tempDir, "strict_policy.json")
	_ = os.WriteFile(strictPolicyPath, []byte(`{
		"version": "1.0",
		"name": "strict-gate",
		"max_critical": 0,
		"max_high": 0,
		"fail_on_violation": true
	}`), 0644)

	codeStrict, outStrict, _ := captureStdoutStderr(func() int {
		return runReport([]string{scanFile, "--policy", strictPolicyPath})
	})
	if codeStrict != clierror.ExitSecurityFail {
		t.Fatalf("expected ExitSecurityFail (1) for violated policy threshold, got %d (out: %s)", codeStrict, outStrict)
	}
	if !strings.Contains(outStrict, "FAILED (Threshold Exceeded)") {
		t.Fatalf("expected FAILED verdict in policy terminal summary, got: %s", outStrict)
	}
	if !strings.Contains(outStrict, "[VIOLATION]") {
		t.Fatalf("expected [VIOLATION] marker in summary, got: %s", outStrict)
	}

	// Permissive Policy: MaxHigh = 5 -> MUST PASS (observed 2 <= allowed 5) -> ExitSuccess (0)
	permissivePolicyPath := filepath.Join(tempDir, "permissive_policy.json")
	_ = os.WriteFile(permissivePolicyPath, []byte(`{
		"version": "1.0",
		"name": "permissive-gate",
		"max_critical": 0,
		"max_high": 5,
		"fail_on_violation": true
	}`), 0644)

	codePerm, outPerm, _ := captureStdoutStderr(func() int {
		return runReport([]string{scanFile, "--policy", permissivePolicyPath})
	})
	if codePerm != clierror.ExitSuccess {
		t.Fatalf("expected ExitSuccess (0) for satisfied policy threshold, got %d (out: %s)", codePerm, outPerm)
	}
	if !strings.Contains(outPerm, "PASSED") {
		t.Fatalf("expected PASSED verdict in summary, got: %s", outPerm)
	}

	// Invalid / Malformed policy file -> MUST RETURN ExitOperational (2)
	malformedPolicyPath := filepath.Join(tempDir, "malformed.json")
	_ = os.WriteFile(malformedPolicyPath, []byte(`{ invalid json`), 0644)
	codeMalformed, _, errMalformed := captureStdoutStderr(func() int {
		return runReport([]string{scanFile, "--policy", malformedPolicyPath})
	})
	if codeMalformed != clierror.ExitOperational {
		t.Fatalf("expected ExitOperational (2) for malformed policy, got %d (stderr: %s)", codeMalformed, errMalformed)
	}

	// Nonexistent policy file -> MUST RETURN ExitOperational (2)
	codeMissing, _, errMissing := captureStdoutStderr(func() int {
		return runReport([]string{scanFile, "--policy", filepath.Join(tempDir, "does-not-exist.json")})
	})
	if codeMissing != clierror.ExitOperational {
		t.Fatalf("expected ExitOperational (2) for missing policy, got %d (stderr: %s)", codeMissing, errMissing)
	}
}

// 10. Scan evaluation with policy
func TestCLI_ExitCode_SecurityThresholdPolicy_Scan(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`<html><body><h1>Target</h1></body></html>`))
	}))
	defer ts.Close()

	tempDir := t.TempDir()

	// Clean target with 0 Critical, 0 High findings
	policyPath := filepath.Join(tempDir, "zero_crit_gate.json")
	_ = os.WriteFile(policyPath, []byte(`{
		"version": "1.0",
		"name": "zero-crit-gate",
		"max_critical": 0,
		"max_high": 0,
		"fail_on_violation": true
	}`), 0644)

	// A: Valid policy and clean scan -> returns 0
	codeClean, outClean, _ := captureStdoutStderr(func() int {
		return runScan([]string{"--allow-loopback", "--quiet", "--policy", policyPath, ts.URL})
	})
	if codeClean != clierror.ExitSuccess {
		t.Fatalf("expected ExitSuccess (0) for clean scan satisfying policy, got %d (stdout: %s)", codeClean, outClean)
	}

	// B: Missing policy file -> returns 2
	codeMissing, _, _ := captureStdoutStderr(func() int {
		return runScan([]string{"--allow-loopback", "--quiet", "--policy", filepath.Join(tempDir, "missing.json"), ts.URL})
	})
	if codeMissing != clierror.ExitOperational {
		t.Fatalf("expected ExitOperational (2) for missing policy on scan, got %d", codeMissing)
	}
}

// 11. Assessment run with policy
func TestCLI_ExitCode_SecurityThresholdPolicy_AssessmentRun(t *testing.T) {
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "felix_asm_pol.db")
	t.Setenv("FELIX_DB_PATH", dbPath)

	store, err := assessment.NewSQLiteStore(dbPath)
	if err != nil {
		t.Fatalf("failed to create test store: %v", err)
	}
	defer store.Close()

	c := &assessment.Client{
		ID:        uuid.New().String(),
		Name:      "Policy Test Client",
		CreatedAt: time.Now().UTC(),
		UpdatedAt: time.Now().UTC(),
	}
	_ = store.CreateClient(c)

	asm := &assessment.Assessment{
		ID:             uuid.New().String(),
		Ref:            "ASM-POL-001",
		ClientID:       c.ID,
		Name:           "Policy Test Assessment",
		AssessmentType: assessment.AssessmentTypeWebSecurity,
		Status:         assessment.StatusReady,
		ScopeMode:      "same-origin",
		CreatedAt:      time.Now().UTC(),
		UpdatedAt:      time.Now().UTC(),
	}
	_ = store.CreateAssessment(asm)

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`<html><body><h1>Audit</h1></body></html>`))
	}))
	defer ts.Close()

	normTarget, _ := assessment.NormalizeTargetURL(ts.URL)
	_ = store.AddTarget(&assessment.AssessmentTarget{
		ID:           uuid.New().String(),
		AssessmentID: asm.ID,
		TargetURL:    normTarget,
		TargetType:   assessment.TargetWebsite,
		ScopeStatus:  "APPROVED",
		CreatedAt:    time.Now().UTC(),
	})

	now := time.Now().UTC()
	future := now.Add(24 * time.Hour)
	past := now.Add(-24 * time.Hour)
	_ = store.SetAuthorization(&assessment.AuthorizationRecord{
		ID:                  uuid.New().String(),
		AssessmentID:        asm.ID,
		AuthorizingParty:    "Lead",
		AuthorizationMethod: "CONSENT",
		DateReceived:        past,
		ValidFrom:           &past,
		ValidUntil:          &future,
		Status:              assessment.AuthApproved,
	})

	t.Setenv("FELIX_ALLOW_LOOPBACK", "true")

	// Valid policy: MaxCritical = 0, MaxHigh = 0
	policyPath := filepath.Join(tempDir, "asm_policy.json")
	_ = os.WriteFile(policyPath, []byte(`{
		"version": "1.0",
		"name": "asm-gate",
		"max_critical": 0,
		"max_high": 0,
		"fail_on_violation": true
	}`), 0644)

	// Clean assessment satisfying policy returns 0
	code, out, errOut := captureStdoutStderr(func() int {
		return runAssessmentRun([]string{asm.Ref, "--policy", policyPath, "--quiet"})
	})
	if code != clierror.ExitSuccess {
		t.Fatalf("expected ExitSuccess (0) for completed assessment satisfying policy, got %d (stdout: %s, stderr: %s)", code, out, errOut)
	}

	// Missing policy returns ExitOperational (2)
	codeMiss, _, errMiss := captureStdoutStderr(func() int {
		return runAssessmentRun([]string{asm.Ref, "--policy", filepath.Join(tempDir, "missing.json"), "--quiet"})
	})
	if codeMiss != clierror.ExitOperational {
		t.Fatalf("expected ExitOperational (2) for missing policy on assessment run, got %d (stderr: %s)", codeMiss, errMiss)
	}
}

// 12. Policy Configuration Precedence: CLI flag overrides configuration file setting
func TestCLI_ExitCode_SecurityThresholdPolicy_Precedence(t *testing.T) {
	tempDir := t.TempDir()

	// Create test report with 2 High findings
	scanFile := filepath.Join(tempDir, "scan_precedence.json")
	rep := report.Report{
		Target:           "https://example.com",
		CompletionStatus: "COMPLETED",
		Timestamp:        time.Now().UTC().Format(time.RFC3339),
		Duration:         "1s",
		Findings: []report.Finding{
			{ID: "f1", Title: "High 1", Severity: "HIGH", Category: "v1", Endpoint: "/1", Method: "GET"},
			{ID: "f2", Title: "High 2", Severity: "HIGH", Category: "v2", Endpoint: "/2", Method: "GET"},
		},
	}
	report.RecalculateReportRisk(&rep)
	data, _ := json.Marshal(rep)
	_ = os.WriteFile(scanFile, data, 0644)

	// Strict policy (would fail with exit code 1)
	strictPolicy := filepath.Join(tempDir, "strict.json")
	_ = os.WriteFile(strictPolicy, []byte(`{"version":"1.0","max_high":0,"fail_on_violation":true}`), 0644)

	// Permissive policy (would pass with exit code 0)
	permPolicy := filepath.Join(tempDir, "permissive.json")
	_ = os.WriteFile(permPolicy, []byte(`{"version":"1.0","max_high":5,"fail_on_violation":true}`), 0644)

	// Set FELIX_POLICY_PATH environment variable to strict policy
	t.Setenv("FELIX_POLICY_PATH", strictPolicy)

	// 1. Without CLI override: uses configured strict policy -> fails with 1
	codeEnv, _, _ := captureStdoutStderr(func() int {
		return runReport([]string{scanFile})
	})
	if codeEnv != clierror.ExitSecurityFail {
		t.Fatalf("expected configured policy to trigger ExitSecurityFail (1), got %d", codeEnv)
	}

	// 2. With CLI --policy override: overrides configured policy with permissive policy -> passes with 0!
	codeOverride, _, _ := captureStdoutStderr(func() int {
		return runReport([]string{scanFile, "--policy", permPolicy})
	})
	if codeOverride != clierror.ExitSuccess {
		t.Fatalf("expected CLI flag override to pass with ExitSuccess (0), got %d", codeOverride)
	}
}
