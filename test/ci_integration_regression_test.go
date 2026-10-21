package test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"felix/pkg/assessment"
	"felix/pkg/ci"
	"felix/pkg/clierror"
	"felix/pkg/report"
)

// -----------------------------------------------------------------------------
// 1. Process-Level CLI & Exit-Code Semantics Tests
// -----------------------------------------------------------------------------

func TestPhase85_CLI_CleanAssessment_Exit0(t *testing.T) {
	// Clean HTTP server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("<!DOCTYPE html><html><head><title>Clean Portal</title></head><body><h1>Welcome</h1></body></html>"))
	}))
	defer server.Close()

	tmpDir := t.TempDir()
	policyPath := filepath.Join(tmpDir, "gate.yaml")
	_ = os.WriteFile(policyPath, []byte(`version: "1.0"
name: "Clean Assessment Gate"
max_critical: 0
max_high: 0
max_medium: 0
fail_on_violation: true
`), 0644)

	reportsDir := filepath.Join(tmpDir, "reports")
	summaryFile := filepath.Join(tmpDir, "step_summary.md")
	outputFile := filepath.Join(tmpDir, "step_output.env")

	out, code := runFelix(t, "ci", "run",
		"--target", server.URL,
		"--policy", policyPath,
		"--output-dir", reportsDir,
		"--sarif", "audit.sarif",
		"--json", "audit.json",
		"--html", "audit.html",
		"--summary-path", summaryFile,
		"--output-path", outputFile,
		"--timeout", "5s",
		"--quiet",
	)

	if code != clierror.ExitSuccess {
		t.Fatalf("expected ExitSuccess (0) for clean scan, got %d. Output:\n%s", code, out)
	}

	// 1. Verify SARIF report generation and official schema validity
	sarifPath := filepath.Join(reportsDir, "audit.sarif")
	sarifBytes, err := os.ReadFile(sarifPath)
	if err != nil {
		t.Fatalf("failed reading generated SARIF file: %v", err)
	}
	if err := report.ValidateSARIF(sarifBytes); err != nil {
		t.Fatalf("generated SARIF report failed official 2.1.0 schema validation: %v", err)
	}

	// 2. Verify JSON report generation
	jsonPath := filepath.Join(reportsDir, "audit.json")
	jsonBytes, err := os.ReadFile(jsonPath)
	if err != nil {
		t.Fatalf("failed reading generated JSON file: %v", err)
	}
	var rep report.Report
	if err := json.Unmarshal(jsonBytes, &rep); err != nil {
		t.Fatalf("failed unmarshaling generated JSON report: %v", err)
	}

	// 3. Verify HTML report generation
	htmlPath := filepath.Join(reportsDir, "audit.html")
	if _, err := os.Stat(htmlPath); err != nil {
		t.Fatalf("HTML report not found at %s: %v", htmlPath, err)
	}

	// 4. Verify Step Summary & Output files
	sumBytes, err := os.ReadFile(summaryFile)
	if err != nil {
		t.Fatalf("failed reading step summary: %v", err)
	}
	if !strings.Contains(string(sumBytes), "STATUS: PASSED") {
		t.Errorf("step summary missing PASSED status marker")
	}

	outBytes, err := os.ReadFile(outputFile)
	if err != nil {
		t.Fatalf("failed reading step outputs: %v", err)
	}
	if !strings.Contains(string(outBytes), "exit_code=0") || !strings.Contains(string(outBytes), "policy_status=PASS") {
		t.Errorf("step outputs missing exit_code=0: %s", string(outBytes))
	}
}

func TestPhase85_CLI_PolicyViolation_Exit1(t *testing.T) {
	// Server serving AWS secret in external JavaScript asset
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/app.js" {
			w.Header().Set("Content-Type", "application/javascript")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`const AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE";`))
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`<!DOCTYPE html><html><head><script src="/app.js"></script></head><body>Portal</body></html>`))
	}))
	defer server.Close()

	tmpDir := t.TempDir()
	policyPath := filepath.Join(tmpDir, "strict_gate.yaml")
	_ = os.WriteFile(policyPath, []byte(`version: "1.0"
name: "Zero Critical Tolerance"
max_critical: 0
max_high: 0
fail_on_violation: true
`), 0644)

	reportsDir := filepath.Join(tmpDir, "reports")
	sarifPath := filepath.Join(reportsDir, "findings.sarif")
	jsonPath := filepath.Join(reportsDir, "findings.json")

	out, code := runFelix(t, "ci", "run",
		"--target", server.URL,
		"--policy", policyPath,
		"--output-dir", reportsDir,
		"--sarif", "findings.sarif",
		"--json", "findings.json",
		"--timeout", "5s",
	)

	// Contract: policy violations must return exit code 1
	if code != clierror.ExitSecurityFail {
		t.Fatalf("expected ExitSecurityFail (1) for policy violation, got %d. Output:\n%s", code, out)
	}

	// Invariant: Reports must still be generated, saved, and valid even when policy fails
	sarifBytes, err := os.ReadFile(sarifPath)
	if err != nil {
		t.Fatalf("SARIF report must be present after policy violation: %v", err)
	}
	if err := report.ValidateSARIF(sarifBytes); err != nil {
		t.Fatalf("SARIF report generated during policy failure must be schema-valid: %v", err)
	}

	jsonBytes, err := os.ReadFile(jsonPath)
	if err != nil {
		t.Fatalf("JSON report must be present after policy violation: %v", err)
	}
	var rep report.Report
	if err := json.Unmarshal(jsonBytes, &rep); err != nil {
		t.Fatalf("failed parsing JSON report: %v", err)
	}
	if len(rep.Findings) == 0 {
		t.Errorf("expected findings to be recorded in report")
	}
}

func TestPhase85_CLI_InvalidConfig_Exit2(t *testing.T) {
	// Missing target and assessment
	out, code := runFelix(t, "ci", "run")
	if code != clierror.ExitOperational {
		t.Errorf("expected ExitOperational (2) for missing target, got %d. Output: %s", code, out)
	}

	// Invalid URL scheme
	out, code = runFelix(t, "ci", "run", "--target", "gopher://unsupported.corp")
	if code != clierror.ExitOperational {
		t.Errorf("expected ExitOperational (2) for invalid URL scheme, got %d. Output: %s", code, out)
	}

	// Non-existent policy file
	out, code = runFelix(t, "ci", "run", "--target", "https://example.com", "--policy", "non_existent_gate.yaml")
	if code != clierror.ExitOperational {
		t.Errorf("expected ExitOperational (2) for missing policy file, got %d. Output: %s", code, out)
	}
}

func TestPhase85_CLI_UntrustedInputInjection_Exit2(t *testing.T) {
	payloads := []string{
		"https://example.com; rm -rf /",
		"https://example.com | cat /etc/shadow",
		"https://example.com && echo PWNED",
		"https://example.com/`whoami`",
		"https://example.com/$PATH",
		"https://example.com\r\nInjected-Header: 1",
	}

	for _, payload := range payloads {
		out, code := runFelix(t, "ci", "run", "--target", payload)
		if code != clierror.ExitOperational {
			t.Errorf("expected ExitOperational (2) for untrusted input %q, got exit code %d. Output:\n%s", payload, code, out)
		}
		if !strings.Contains(out, "prohibited control or shell character") {
			t.Errorf("expected rejection diagnostic for %q, got: %s", payload, out)
		}
	}
}

func TestPhase85_CLI_BinaryVerification_ExitCodes(t *testing.T) {
	binPath := getFelixBinPath(t)

	// Positive verification: valid executable passes with exit code 0
	out, code := runFelix(t, "ci", "--verify-bin", binPath)
	if code != clierror.ExitSuccess {
		t.Errorf("expected exit code 0 on valid binary verification, got %d. Output:\n%s", code, out)
	}

	// Negative verification: mismatched SHA256 checksum fails closed with exit code 2
	badSHA := "0000000000000000000000000000000000000000000000000000000000000000"
	out, code = runFelix(t, "ci", "--verify-bin", binPath, "--expected-sha256", badSHA)
	if code != clierror.ExitOperational {
		t.Errorf("expected ExitOperational (2) on checksum mismatch, got %d. Output:\n%s", code, out)
	}
	if !strings.Contains(out, "SHA256 integrity verification failed") {
		t.Errorf("expected SHA256 mismatch diagnostic in output, got: %s", out)
	}

	// Negative verification: mismatched version fails closed with exit code 2
	out, code = runFelix(t, "ci", "--verify-bin", binPath, "--expected-version", "99.99.99")
	if code != clierror.ExitOperational {
		t.Errorf("expected ExitOperational (2) on version mismatch, got %d. Output:\n%s", code, out)
	}

	// Negative verification: require-sha256 without expected-sha256 fails closed with exit code 2
	out, code = runFelix(t, "ci", "--verify-bin", binPath, "--require-sha256")
	if code != clierror.ExitOperational {
		t.Errorf("expected ExitOperational (2) when SHA256 is required but missing, got %d. Output:\n%s", code, out)
	}
	if !strings.Contains(out, "cryptographic integrity verification required") {
		t.Errorf("expected cryptographic integrity failure message, got: %s", out)
	}

	// Negative verification: malformed expected-sha256 fails closed with exit code 2
	out, code = runFelix(t, "ci", "--verify-bin", binPath, "--expected-sha256", "shortbadhash")
	if code != clierror.ExitOperational {
		t.Errorf("expected ExitOperational (2) on malformed SHA256 format, got %d. Output:\n%s", code, out)
	}
	if !strings.Contains(out, "must be exactly 64 hexadecimal characters") {
		t.Errorf("expected 64-char error message, got: %s", out)
	}
}

func TestPhase85_CLI_SubprocessCanaryExecutionProof(t *testing.T) {
	tmpDir := t.TempDir()

	canarySrc := `package main

import (
	"fmt"
	"os"
)

func main() {
	outFile := os.Getenv("FELIX_CLI_CANARY_OUT")
	if outFile != "" {
		_ = os.WriteFile(outFile, []byte("EXECUTED_VIA_CLI"), 0644)
	}
	fmt.Println("FELIX Security Platform v1.0.0-cli-canary")
}
`
	srcPath := filepath.Join(tmpDir, "main.go")
	if err := os.WriteFile(srcPath, []byte(canarySrc), 0644); err != nil {
		t.Fatalf("failed writing canary source: %v", err)
	}

	canaryBin := filepath.Join(tmpDir, "canary.exe")
	if runtime.GOOS != "windows" {
		canaryBin = filepath.Join(tmpDir, "canary")
	}

	buildCmd := exec.Command("go", "build", "-o", canaryBin, srcPath)
	if out, err := buildCmd.CombinedOutput(); err != nil {
		t.Fatalf("failed compiling canary binary: %v, out: %s", err, string(out))
	}

	canaryOut := filepath.Join(tmpDir, "cli_canary_touch.txt")
	t.Setenv("FELIX_CLI_CANARY_OUT", canaryOut)

	// Subtest 1: CLI invocation with mismatched digest fails closed with code 2 and NEVER executes canary
	_ = os.Remove(canaryOut)
	badDigest := strings.Repeat("a", 64)
	out, code := runFelix(t, "ci", "--verify-bin", canaryBin, "--expected-sha256", badDigest)
	if code != clierror.ExitOperational {
		t.Fatalf("expected ExitOperational (2) on digest mismatch, got %d. Output: %s", code, out)
	}
	if _, err := os.Stat(canaryOut); !os.IsNotExist(err) {
		t.Fatalf("CRITICAL SECURITY DEFECT: CLI invocation executed unverified binary on digest mismatch!")
	}

	// Subtest 2: CLI invocation with missing required digest fails closed with code 2 and NEVER executes canary
	_ = os.Remove(canaryOut)
	out, code = runFelix(t, "ci", "--verify-bin", canaryBin, "--require-sha256")
	if code != clierror.ExitOperational {
		t.Fatalf("expected ExitOperational (2) when digest required but missing, got %d. Output: %s", code, out)
	}
	if _, err := os.Stat(canaryOut); !os.IsNotExist(err) {
		t.Fatalf("CRITICAL SECURITY DEFECT: CLI invocation executed unverified binary when digest was omitted!")
	}

	// Subtest 3: CLI invocation with matching digest succeeds with code 0 and executes canary
	_ = os.Remove(canaryOut)
	hasher := sha256.New()
	binBytes, err := os.ReadFile(canaryBin)
	if err != nil {
		t.Fatalf("failed reading canary binary: %v", err)
	}
	hasher.Write(binBytes)
	actualHash := hex.EncodeToString(hasher.Sum(nil))

	out, code = runFelix(t, "ci", "--verify-bin", canaryBin, "--expected-sha256", actualHash, "--expected-version", "1.0.0-cli-canary")
	if code != clierror.ExitSuccess {
		t.Fatalf("expected ExitSuccess (0) on matching digest and version, got %d. Output: %s", code, out)
	}
	if _, err := os.Stat(canaryOut); os.IsNotExist(err) {
		t.Fatalf("expected canary binary to be executed when digest matched, but touch file was not found")
	}
}

// -----------------------------------------------------------------------------
// 2. Policy & Baseline Integration in CI
// -----------------------------------------------------------------------------

func TestPhase85_CLI_BaselineRelativeCIExecution(t *testing.T) {
	store, client, asm, tgt, dbPath := setupBaselineTestDB(t)
	authAdmin := assessment.NewAdminAuthContext()

	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Content-Security-Policy", "default-src 'self'")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("<!DOCTYPE html><html><head><title>Portal</title></head><body><h1>API</h1></body></html>"))
	}))
	defer mockServer.Close()
	_ = store.RemoveTarget(tgt.ID)
	tgt.TargetURL = mockServer.URL
	_ = store.AddTarget(tgt)

	// Create baseline run with an existing low finding
	now := time.Now().UTC()
	validFrom := now.Add(-1 * time.Hour)
	validUntil := now.Add(24 * time.Hour)
	_ = store.SetAuthorization(&assessment.AuthorizationRecord{
		ID:                  "auth-ci-base",
		AssessmentID:        asm.ID,
		AuthorizingParty:    "Security Operations",
		AuthorizationMethod: "PIPELINE_AUTHORIZATION",
		Status:              assessment.AuthApproved,
		DateReceived:        now,
		ValidFrom:           &validFrom,
		ValidUntil:          &validUntil,
	})

	tBase := now.Add(-2 * time.Hour)
	baseExec := &assessment.AssessmentExecution{
		ID:           "exec-ci-baseline",
		AssessmentID: asm.ID,
		ClientID:     client.ID,
		TenantID:     client.ID,
		Status:       assessment.StatusCompleted,
		StartedAt:    tBase,
		CompletedAt:  &tBase,
	}
	_ = store.CreateExecution(baseExec)

	fBase := report.Finding{
		ID:       "fnd-base-01",
		RuleID:   "SEC-LOW-01",
		Title:    "Information Disclosure",
		Severity: report.SeverityLow,
		Target:   tgt.TargetURL,
		Endpoint: "/info",
	}
	baseAF := assessment.ToAssessmentFinding(asm.ID, baseExec.ID, tgt.ID, fBase)
	baseAFs := []assessment.AssessmentFinding{baseAF}
	baseSnap := assessment.BuildAssessmentSnapshot(asm, baseExec, []string{tgt.TargetURL}, baseAFs, true)
	_ = store.CreateSnapshot(baseSnap, baseAFs, nil)
	baseExec.SnapshotID = baseSnap.ID
	_ = store.UpdateExecution(baseExec)
	_ = store.SaveFindings(baseAFs)

	// Policy that fails ONLY on NEW findings (allows persistent findings from baseline)
	tmpDir := t.TempDir()
	policyPath := filepath.Join(tmpDir, "new_only_gate.yaml")
	_ = os.WriteFile(policyPath, []byte(`version: "1.0"
name: "Fail on New Only Gate"
max_low: 0
evaluation_scope: "new"
fail_on_violation: true
`), 0644)

	reportsDir := filepath.Join(tmpDir, "reports")

	// Run CI assessment using the database project with --baseline and --baseline-scope new
	cfg := &ci.Config{
		Provider:        ci.ProviderGeneric,
		AssessmentRef:   asm.Ref,
		BaselineRef:     baseExec.ID,
		BaselineScope:   "new",
		PolicyPath:      policyPath,
		OutputDir:       reportsDir,
		DatabasePath:    dbPath,
		Quiet:           true,
		FailOnViolation: true,
		AllowLoopback:   true,
	}

	// Target server is clean; the old finding from baseline is PERSISTENT or RESOLVED (0 NEW findings)
	res, err := ci.Run(context.Background(), cfg, store)
	if err != nil {
		t.Fatalf("ci.Run baseline-relative assessment returned error: %v", err)
	}

	// Invariant: Because evaluation_scope is "new" and there are 0 new findings, policy PASSES (Exit 0)
	if res.ExitCode != clierror.ExitSuccess {
		t.Errorf("expected ExitSuccess (0) when 0 new findings exist under baseline-relative policy, got %d", res.ExitCode)
	}
	if res.PolicyStatus != "PASS" {
		t.Errorf("expected PolicyStatus PASS, got %s", res.PolicyStatus)
	}

	// Test non-existent baseline fails safely with exit code 2
	cfgBadBase := &ci.Config{
		Provider:      ci.ProviderGeneric,
		AssessmentRef: asm.Ref,
		BaselineRef:   "non-existent-baseline-id",
		PolicyPath:    policyPath,
		OutputDir:     reportsDir,
		DatabasePath:  dbPath,
		Quiet:         true,
	}
	resBad, errBad := ci.Run(context.Background(), cfgBadBase, store)
	if errBad == nil || resBad.ExitCode != clierror.ExitOperational {
		t.Errorf("expected non-existent baseline to fail with ExitOperational (2), got code %d, err %v", resBad.ExitCode, errBad)
	}

	_ = authAdmin
}

// -----------------------------------------------------------------------------
// 3. Artifact Handling & Zero-Leakage Tests
// -----------------------------------------------------------------------------

func TestPhase85_CLI_ZeroSecretLeakage(t *testing.T) {
	secretAWSKey := "AKIA" + "IOSFODNN7CANARY01"
	secretToken := "ghp_canaryPersonalAccessTokenSecret999"

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/bundle.js" {
			w.Header().Set("Content-Type", "application/javascript")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(fmt.Sprintf(`const aws = "%s"; const token = "%s";`, secretAWSKey, secretToken)))
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`<!DOCTYPE html><html><head><script src="/bundle.js"></script></head><body>SecTest</body></html>`))
	}))
	defer server.Close()

	tmpDir := t.TempDir()
	summaryFile := filepath.Join(tmpDir, "summary.md")

	out, _ := runFelix(t, "ci", "run",
		"--target", server.URL,
		"--output-dir", filepath.Join(tmpDir, "reports"),
		"--summary-path", summaryFile,
		"--timeout", "5s",
	)

	// Invariant: Secret values must NOT be printed unredacted to CLI stdout/stderr
	if strings.Contains(out, secretAWSKey) {
		t.Errorf("SECURITY LEAK: unredacted AWS key %s found in CLI output:\n%s", secretAWSKey, out)
	}
	if strings.Contains(out, secretToken) {
		t.Errorf("SECURITY LEAK: unredacted token %s found in CLI output:\n%s", secretToken, out)
	}

	// Invariant: Secret values must NOT be present unredacted in step summary file
	sumData, err := os.ReadFile(summaryFile)
	if err == nil {
		sumStr := string(sumData)
		if strings.Contains(sumStr, secretAWSKey) {
			t.Errorf("SECURITY LEAK: unredacted AWS key found in GITHUB_STEP_SUMMARY file")
		}
		if strings.Contains(sumStr, secretToken) {
			t.Errorf("SECURITY LEAK: unredacted token found in GITHUB_STEP_SUMMARY file")
		}
	}
}

// -----------------------------------------------------------------------------
// 4. GitHub Actions Workflow and Action YAML Validation Tests
// -----------------------------------------------------------------------------

func TestPhase85_WorkflowAndActionYAMLValidation(t *testing.T) {
	root := findRepoRoot()

	actionFiles := []string{
		filepath.Join(root, "action.yml"),
		filepath.Join(root, ".github", "actions", "felix-action", "action.yml"),
	}

	// Invariant: Root action.yml and namespaced action.yml must remain identical
	rootActionData, err := os.ReadFile(actionFiles[0])
	if err != nil {
		t.Fatalf("failed reading root action.yml: %v", err)
	}
	namespacedActionData, err := os.ReadFile(actionFiles[1])
	if err != nil {
		t.Fatalf("failed reading namespaced action.yml: %v", err)
	}
	if string(rootActionData) != string(namespacedActionData) {
		t.Errorf("action.yml and .github/actions/felix-action/action.yml must be identical")
	}

	for _, af := range actionFiles {
		data, err := os.ReadFile(af)
		if err != nil {
			t.Fatalf("failed reading action file %s: %v", af, err)
		}
		content := string(data)

		// Verify required composite action metadata
		if !strings.Contains(content, "using: 'composite'") {
			t.Errorf("%s missing composite action declaration", af)
		}
		if !strings.Contains(content, "inputs:") || !strings.Contains(content, "outputs:") {
			t.Errorf("%s missing inputs or outputs declaration", af)
		}
		if !strings.Contains(content, "upload-sarif") || !strings.Contains(content, "upload-artifacts") {
			t.Errorf("%s missing upload-sarif or upload-artifacts flags", af)
		}
		if !strings.Contains(content, "\"ci\"") && !strings.Contains(content, "ci") {
			t.Errorf("%s does not invoke felix ci", af)
		}
		if !strings.Contains(content, "Cryptographic SHA-256 integrity verification BEFORE execution") {
			t.Errorf("%s missing pre-execution SHA256 integrity verification check", af)
		}
	}

	workflowFiles := []string{
		filepath.Join(root, ".github", "workflows", "felix-audit.yml"),
		filepath.Join(root, ".github", "workflows", "felix-reusable.yml"),
	}

	for _, wf := range workflowFiles {
		data, err := os.ReadFile(wf)
		if err != nil {
			t.Fatalf("failed reading workflow file %s: %v", wf, err)
		}
		content := string(data)

		// Security requirement: Workflows must enforce least-privilege permissions
		if !strings.Contains(content, "permissions:") {
			t.Errorf("%s missing permissions declaration", wf)
		}
		if !strings.Contains(content, "contents: read") {
			t.Errorf("%s missing contents: read permission", wf)
		}
		if !strings.Contains(content, "security-events: write") {
			t.Errorf("%s missing security-events: write permission", wf)
		}

		// Security requirement: Must NEVER use privileged pull_request_target
		if strings.Contains(content, "pull_request_target") {
			t.Errorf("SECURITY RISK: %s contains dangerous pull_request_target trigger", wf)
		}
	}
}

// -----------------------------------------------------------------------------
// 5. Phase 8.6: CLI Pull-Request Feedback End-to-End Tests
// -----------------------------------------------------------------------------

func TestPhase86_CLI_PullRequestFeedback_EndToEnd(t *testing.T) {
	// 1. Mock Target Server
	targetServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("<!DOCTYPE html><html><head><title>App</title></head><body><h1>OK</h1></body></html>"))
	}))
	defer targetServer.Close()

	// 2. Mock GitHub API Server
	var getCommentsCount, postCommentsCount int
	var capturedCommentBody string

	ghServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == "GET" && r.URL.Path == "/repos/acme/repo/issues/42/comments":
			getCommentsCount++
			// Empty comment list initially
			_, _ = w.Write([]byte("[]"))
		case r.Method == "POST" && r.URL.Path == "/repos/acme/repo/issues/42/comments":
			postCommentsCount++
			var req map[string]string
			_ = json.NewDecoder(r.Body).Decode(&req)
			capturedCommentBody = req["body"]
			_, _ = w.Write([]byte(`{"id": 12345, "body": "ok"}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer ghServer.Close()

	tmpDir := t.TempDir()
	reportsDir := filepath.Join(tmpDir, "reports")
	outputFile := filepath.Join(tmpDir, "step_output.env")

	// Subtest 1: Successful PR comment creation with exit code 0
	out, code := runFelix(t, "ci", "run",
		"--target", targetServer.URL,
		"--output-dir", reportsDir,
		"--output-path", outputFile,
		"--allow-loopback",
		"--pr-comment",
		"--pr-number", "42",
		"--github-token", "ghp_MockToken1234567890abcdef",
		"--repo", "acme/repo",
		"--github-api-url", ghServer.URL,
		"--quiet",
	)

	if code != clierror.ExitSuccess {
		t.Fatalf("expected ExitSuccess (0), got %d. Output:\n%s", code, out)
	}

	if getCommentsCount == 0 || postCommentsCount == 0 {
		t.Errorf("expected GitHub API to be called (get: %d, post: %d)", getCommentsCount, postCommentsCount)
	}

	if !strings.Contains(capturedCommentBody, "<!-- felix-security-pr-comment -->") {
		t.Errorf("expected posted comment to contain marker tag, got:\n%s", capturedCommentBody)
	}
	if !strings.Contains(capturedCommentBody, "STATUS: PASSED") {
		t.Errorf("expected posted comment to show passed status")
	}

	outBytes, err := os.ReadFile(outputFile)
	if err != nil {
		t.Fatalf("failed reading output file: %v", err)
	}
	if !strings.Contains(string(outBytes), "feedback_published=true") {
		t.Errorf("expected output file to contain feedback_published=true, got:\n%s", string(outBytes))
	}

	// Subtest 2: Failed feedback publication with --feedback-failure-policy fail elevates Exit 0 to Exit 2
	failingGHServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "internal github api error", http.StatusInternalServerError)
	}))
	defer failingGHServer.Close()

	outputFailFile := filepath.Join(tmpDir, "step_output_fail.env")
	outFail, codeFail := runFelix(t, "ci", "run",
		"--target", targetServer.URL,
		"--output-dir", filepath.Join(tmpDir, "reports_fail"),
		"--output-path", outputFailFile,
		"--allow-loopback",
		"--pr-comment",
		"--pr-number", "42",
		"--github-token", "ghp_MockToken1234567890abcdef",
		"--repo", "acme/repo",
		"--github-api-url", failingGHServer.URL,
		"--feedback-failure-policy", "fail",
		"--quiet",
	)

	if codeFail != clierror.ExitOperational {
		t.Fatalf("expected ExitOperational (2) when feedback fails under fail policy, got %d. Output:\n%s", codeFail, outFail)
	}

	outFailBytes, _ := os.ReadFile(outputFailFile)
	if !strings.Contains(string(outFailBytes), "feedback_published=false") {
		t.Errorf("expected output file to contain feedback_published=false on failure, got:\n%s", string(outFailBytes))
	}
}
