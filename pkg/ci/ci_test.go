package ci

import (
	"context"
	"fmt"
	"net"
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
	"felix/pkg/clierror"
	"felix/pkg/crawler"
	"felix/pkg/policy"
	"felix/pkg/report"
)

// -----------------------------------------------------------------------------
// 1. Configuration Validation & Untrusted Input Sanitization Tests
// -----------------------------------------------------------------------------

func TestValidateConfig_MissingTargetAndAssessment(t *testing.T) {
	cfg := &Config{}
	err := ValidateConfig(cfg)
	if err == nil {
		t.Fatalf("expected error when neither target nor assessment is configured, got nil")
	}
	if !strings.Contains(err.Error(), "either target URL") {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestValidateConfig_BothTargetAndAssessment(t *testing.T) {
	cfg := &Config{
		TargetURL:     "https://example.com",
		AssessmentRef: "ASM-123",
	}
	err := ValidateConfig(cfg)
	if err == nil {
		t.Fatalf("expected error when both target and assessment are configured, got nil")
	}
	if !strings.Contains(err.Error(), "cannot configure both") {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestValidateConfig_InvalidTargetURL(t *testing.T) {
	tests := []struct {
		name    string
		url     string
		wantErr string
	}{
		{"missing scheme", "example.com", "scheme must be http or https"},
		{"ftp scheme", "ftp://example.com/file", "scheme must be http or https"},
		{"empty host", "http://", "must include a valid host name"},
		{"shell semicolon injection", "https://example.com;rm -rf /", "contains prohibited control or shell character"},
		{"shell pipe injection", "https://example.com|cat /etc/passwd", "contains prohibited control or shell character"},
		{"shell command subst injection", "https://example.com/`id`", "contains prohibited control or shell character"},
		{"shell env var injection", "https://example.com/$SECRET", "contains prohibited control or shell character"},
		{"crlf header injection", "https://example.com\r\nEvil: True", "contains prohibited control or shell character"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &Config{TargetURL: tc.url}
			err := ValidateConfig(cfg)
			if err == nil {
				t.Fatalf("expected error for URL %q, got nil", tc.url)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("expected error containing %q, got: %v", tc.wantErr, err)
			}
		})
	}
}

func TestValidateConfig_AssessmentRefTraversal(t *testing.T) {
	cfg := &Config{AssessmentRef: "../../etc/shadow"}
	err := ValidateConfig(cfg)
	if err == nil {
		t.Fatalf("expected error on path traversal in assessment ref, got nil")
	}
	if !strings.Contains(err.Error(), "path traversal") {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestValidateConfig_PolicyFileValidation(t *testing.T) {
	tmpDir := t.TempDir()

	// Non-existent policy file
	cfgNonExistent := &Config{
		TargetURL:  "https://example.com",
		PolicyPath: filepath.Join(tmpDir, "non_existent_policy.yaml"),
	}
	if err := ValidateConfig(cfgNonExistent); err == nil {
		t.Fatalf("expected error for non-existent policy file, got nil")
	}

	// Malformed policy file
	malformedPath := filepath.Join(tmpDir, "malformed.yaml")
	_ = os.WriteFile(malformedPath, []byte("this is not: a valid: [yaml"), 0644)
	cfgMalformed := &Config{
		TargetURL:  "https://example.com",
		PolicyPath: malformedPath,
	}
	if err := ValidateConfig(cfgMalformed); err == nil {
		t.Fatalf("expected error for malformed policy file, got nil")
	}

	// Valid policy file
	validPath := filepath.Join(tmpDir, "policy.yaml")
	validPolicy := `version: "1.0"
name: "CI Gate"
max_critical: 0
max_high: 0
fail_on_violation: true
`
	_ = os.WriteFile(validPath, []byte(validPolicy), 0644)
	cfgValid := &Config{
		TargetURL:  "https://example.com",
		PolicyPath: validPath,
		OutputDir:  filepath.Join(tmpDir, "reports"),
	}
	if err := ValidateConfig(cfgValid); err != nil {
		t.Fatalf("expected valid config to succeed, got: %v", err)
	}
}

func TestValidateConfig_BaselineScopeValidation(t *testing.T) {
	cfg := &Config{
		AssessmentRef: "ASM-VALID",
		BaselineRef:   "BASE-01",
		BaselineScope: "invalid-scope",
	}
	if err := ValidateConfig(cfg); err == nil {
		t.Fatalf("expected error on invalid baseline-scope, got nil")
	}

	for _, scope := range []string{"all", "new", "new_and_regressed"} {
		cfgValid := &Config{
			AssessmentRef: "ASM-VALID",
			BaselineRef:   "BASE-01",
			BaselineScope: scope,
		}
		if err := ValidateConfig(cfgValid); err != nil {
			t.Fatalf("expected scope %q to be valid, got: %v", scope, err)
		}
		if cfgValid.BaselineScope != scope {
			t.Errorf("expected scope %s, got %s", scope, cfgValid.BaselineScope)
		}
	}
}

// -----------------------------------------------------------------------------
// 2. Binary Verification Tests
// -----------------------------------------------------------------------------

func TestVerifyBinary_MissingOrInvalid(t *testing.T) {
	// Missing file
	if err := VerifyBinary("non_existent_binary_file", "", ""); err == nil {
		t.Errorf("expected error for missing binary, got nil")
	}

	// Directory instead of executable
	tmpDir := t.TempDir()
	if err := VerifyBinary(tmpDir, "", ""); err == nil {
		t.Errorf("expected error when path is a directory, got nil")
	}

	// File too small (< 1MB)
	smallFile := filepath.Join(tmpDir, "tiny.exe")
	_ = os.WriteFile(smallFile, []byte("echo hello"), 0755)
	if err := VerifyBinary(smallFile, "", ""); err == nil {
		t.Errorf("expected error when file is below 1MB, got nil")
	}
}

func TestVerifyBinary_ActualFelixBinary(t *testing.T) {
	binPath := filepath.Join("..", "..", "bin", "felix.exe")
	if _, err := os.Stat(binPath); os.IsNotExist(err) {
		binPath = filepath.Join("..", "..", "bin", "felix")
		if _, err := os.Stat(binPath); os.IsNotExist(err) {
			t.Skip("felix binary not yet compiled at bin/felix; skipping live binary test")
		}
	}

	// Verify existing compiled binary
	if err := VerifyBinary(binPath, "", ""); err != nil {
		t.Fatalf("VerifyBinary failed on actual felix binary: %v", err)
	}

	// Compute actual sha256 to test positive checksum matching
	h, err := computeSHA256(binPath)
	if err != nil {
		t.Fatalf("computeSHA256 failed: %v", err)
	}
	if err := VerifyBinary(binPath, "", h); err != nil {
		t.Fatalf("VerifyBinary failed with valid SHA256: %v", err)
	}

	// Test SHA256 mismatch failure
	badHash := "0000000000000000000000000000000000000000000000000000000000000000"
	if err := VerifyBinary(binPath, "", badHash); err == nil {
		t.Fatalf("expected error on SHA256 mismatch, got nil")
	}
}

// -----------------------------------------------------------------------------
// 3. Summary Formatting, Step Output & Secret Redaction Tests
// -----------------------------------------------------------------------------

func TestSummaryFormatting_SecretRedaction(t *testing.T) {
	sensitiveToken := "ghp_superSecretPersonalAccessToken12345"
	sensitivePass := "password123SuperSecret"
	canaryCookie := "session_token=secretSessionCookieValue999"

	res := &Result{
		ExitCode:      1,
		PolicyStatus:  "FAIL",
		TotalFindings: 1,
		SeverityCounts: map[string]int{
			report.SeverityCritical: 1,
		},
		SARIFPath: "reports/felix.sarif",
		Error:     nil,
		PolicyDecision: &policy.EvaluationDecision{
			PolicyDigest: "digest-12345",
			Violations: []policy.ThresholdViolation{
				{
					Severity: report.SeverityCritical,
					Message:  "Observed token: " + sensitiveToken + " with pass " + sensitivePass + " and " + canaryCookie,
				},
			},
		},
	}

	cfg := &Config{
		TargetURL:  "https://auth.internal.corp",
		PolicyPath: "ci-policy.yaml",
	}

	summary := FormatSummary(res, cfg)

	// Invariant: Zero sensitive credentials or tokens in summary
	if strings.Contains(summary, sensitiveToken) {
		t.Errorf("CRITICAL SECURITY LEAK: unredacted auth token in CI summary: %s", summary)
	}
	if strings.Contains(summary, sensitivePass) {
		t.Errorf("CRITICAL SECURITY LEAK: unredacted password in CI summary: %s", summary)
	}
	if strings.Contains(summary, "secretSessionCookieValue999") {
		t.Errorf("CRITICAL SECURITY LEAK: unredacted cookie token in CI summary: %s", summary)
	}

	// Redaction marker must be present
	if !strings.Contains(summary, "[REDACTED") {
		t.Errorf("expected [REDACTED placeholder in sanitized summary")
	}
}

func TestWriteStepOutputsAndSummary(t *testing.T) {
	tmpDir := t.TempDir()
	summaryFile := filepath.Join(tmpDir, "step_summary.md")
	outputFile := filepath.Join(tmpDir, "step_output.env")

	summaryText := "# FELIX Security Assessment Passed\nNo violations detected."
	if err := WriteStepSummary(summaryFile, summaryText); err != nil {
		t.Fatalf("WriteStepSummary failed: %v", err)
	}

	summaryBytes, err := os.ReadFile(summaryFile)
	if err != nil {
		t.Fatalf("failed reading summary file: %v", err)
	}
	if !strings.Contains(string(summaryBytes), "FELIX Security Assessment Passed") {
		t.Errorf("summary file content missing expected header")
	}

	outputs := map[string]string{
		"exit_code":      "0",
		"policy_status":  "PASS",
		"findings_count": "0",
	}
	if err := WriteStepOutputs(outputFile, outputs); err != nil {
		t.Fatalf("WriteStepOutputs failed: %v", err)
	}

	outputBytes, err := os.ReadFile(outputFile)
	if err != nil {
		t.Fatalf("failed reading output file: %v", err)
	}
	outStr := string(outputBytes)
	if !strings.Contains(outStr, "exit_code=0") || !strings.Contains(outStr, "policy_status=PASS") {
		t.Errorf("output file missing expected key-value pairs: %s", outStr)
	}
}

// -----------------------------------------------------------------------------
// 4. End-to-End Runner Tests with Isolated Mock HTTP Targets
// -----------------------------------------------------------------------------

func TestCIRunner_CleanAssessmentReturns0(t *testing.T) {
	// Setup clean target server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("<!DOCTYPE html><html><head><title>Clean App</title></head><body><h1>Welcome</h1></body></html>"))
	}))
	defer server.Close()

	tmpDir := t.TempDir()
	policyFile := filepath.Join(tmpDir, "gate.yaml")
	_ = os.WriteFile(policyFile, []byte(`version: "1.0"
name: "Clean Gate"
max_critical: 0
max_high: 0
max_medium: 0
fail_on_violation: true
`), 0644)

	cfg := &Config{
		Provider:        ProviderGeneric,
		TargetURL:       server.URL,
		PolicyPath:      policyFile,
		OutputDir:       filepath.Join(tmpDir, "reports"),
		SummaryPath:     filepath.Join(tmpDir, "summary.md"),
		OutputPath:      filepath.Join(tmpDir, "outputs.env"),
		Timeout:         "5s",
		Quiet:           true,
		FailOnViolation: true,
		AllowLoopback:   true,
	}

	res, err := Run(context.Background(), cfg, nil)
	if err != nil {
		t.Fatalf("Run returned unexpected error: %v", err)
	}

	if res.ExitCode != clierror.ExitSuccess {
		t.Errorf("expected ExitSuccess (0) for clean scan, got %d", res.ExitCode)
	}
	if res.PolicyStatus != "PASS" {
		t.Errorf("expected PolicyStatus PASS, got %s", res.PolicyStatus)
	}

	// Verify SARIF file was generated and is valid
	if _, err := os.Stat(res.SARIFPath); err != nil {
		t.Errorf("SARIF report was not generated at %s: %v", res.SARIFPath, err)
	}
	// Verify JSON file was generated
	if _, err := os.Stat(res.JSONPath); err != nil {
		t.Errorf("JSON report was not generated at %s: %v", res.JSONPath, err)
	}
	// Verify HTML file was generated
	if _, err := os.Stat(res.HTMLPath); err != nil {
		t.Errorf("HTML report was not generated at %s: %v", res.HTMLPath, err)
	}
}

func TestCIRunner_PolicyViolationReturns1(t *testing.T) {
	// Setup target server exposing a test finding (e.g. AWS access key pattern)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/config.js" {
			w.Header().Set("Content-Type", "application/javascript")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`const AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE";`))
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`<!DOCTYPE html><html><head><script src="/config.js"></script></head><body>Hello</body></html>`))
	}))
	defer server.Close()

	tmpDir := t.TempDir()
	policyFile := filepath.Join(tmpDir, "strict_gate.yaml")
	_ = os.WriteFile(policyFile, []byte(`version: "1.0"
name: "Strict Zero-Secret Gate"
max_critical: 0
max_high: 0
fail_on_violation: true
`), 0644)

	cfg := &Config{
		Provider:        ProviderGeneric,
		TargetURL:       server.URL,
		PolicyPath:      policyFile,
		OutputDir:       filepath.Join(tmpDir, "reports"),
		Timeout:         "5s",
		Quiet:           true,
		FailOnViolation: true,
		AllowLoopback:   true,
	}

	res, _ := Run(context.Background(), cfg, nil)
	if res.ExitCode != clierror.ExitSecurityFail {
		t.Errorf("expected ExitSecurityFail (1) for policy violation, got exit code %d (status: %s)", res.ExitCode, res.PolicyStatus)
	}
	if res.PolicyStatus != "FAIL" {
		t.Errorf("expected PolicyStatus FAIL, got %s", res.PolicyStatus)
	}

	// Invariant: Reports MUST be written and preserved even on policy violations
	if _, err := os.Stat(res.SARIFPath); err != nil {
		t.Errorf("SARIF report must be written and preserved on policy failure: %v", err)
	}
}

func TestCIRunner_InvalidConfigReturns2(t *testing.T) {
	cfg := &Config{
		TargetURL: "ftp://unsupported.corp",
	}

	res, err := Run(context.Background(), cfg, nil)
	if err == nil {
		t.Fatalf("expected error on invalid config, got nil")
	}
	if res.ExitCode != clierror.ExitOperational {
		t.Errorf("expected ExitOperational (2) on invalid config, got %d", res.ExitCode)
	}
	if res.PolicyStatus != "ERROR" {
		t.Errorf("expected PolicyStatus ERROR, got %s", res.PolicyStatus)
	}
}

func TestVerifyBinaryWithIntegrity_StrictSHA256(t *testing.T) {
	binPath := filepath.Join("..", "..", "bin", "felix.exe")
	if _, err := os.Stat(binPath); os.IsNotExist(err) {
		binPath = filepath.Join("..", "..", "bin", "felix")
		if _, err := os.Stat(binPath); os.IsNotExist(err) {
			t.Skip("felix binary not yet compiled; skipping binary test")
		}
	}

	// 1. Missing checksum when required fails closed
	if err := VerifyBinaryWithIntegrity(binPath, "", "", true); err == nil {
		t.Fatalf("expected error when SHA256 is required but omitted, got nil")
	} else if !strings.Contains(err.Error(), "cryptographic integrity verification required") {
		t.Errorf("unexpected error message: %v", err)
	}

	// 2. Malformed checksum length fails closed
	if err := VerifyBinaryWithIntegrity(binPath, "", "abc123short", false); err == nil {
		t.Fatalf("expected error for malformed checksum length, got nil")
	} else if !strings.Contains(err.Error(), "must be exactly 64 hexadecimal characters") {
		t.Errorf("unexpected error message: %v", err)
	}

	// 3. Non-hex characters fail closed
	badHex := strings.Repeat("z", 64)
	if err := VerifyBinaryWithIntegrity(binPath, "", badHex, false); err == nil {
		t.Fatalf("expected error for non-hex checksum, got nil")
	} else if !strings.Contains(err.Error(), "contains non-hexadecimal characters") {
		t.Errorf("unexpected error message: %v", err)
	}

	// 4. Correct 64-hex SHA256 succeeds
	actualHash, err := computeSHA256(binPath)
	if err != nil {
		t.Fatalf("computeSHA256 failed: %v", err)
	}
	if err := VerifyBinaryWithIntegrity(binPath, "", actualHash, true); err != nil {
		t.Fatalf("expected matching 64-char SHA256 to pass: %v", err)
	}
}

func TestCIRunner_NetworkSafety_ProhibitsUnauthorizedDestinations(t *testing.T) {
	tmpDir := t.TempDir()

	// Server on loopback
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("<!DOCTYPE html><html><body><h1>Internal</h1></body></html>"))
	}))
	defer server.Close()

	// Unset FELIX_ALLOW_LOOPBACK for this test
	t.Setenv("FELIX_ALLOW_LOOPBACK", "false")
	t.Setenv("FELIX_ALLOW_PRIVATE_IPS", "false")

	// 1. Unauthorized loopback scan without explicit AllowLoopback must be BLOCKED
	cfgBlocked := &Config{
		Provider:      ProviderGeneric,
		TargetURL:     server.URL,
		OutputDir:     filepath.Join(tmpDir, "reports-blocked"),
		Timeout:       "2s",
		Quiet:         true,
		AllowLoopback: false, // Default unprivileged safety state
	}

	resBlocked, err := Run(context.Background(), cfgBlocked, nil)
	if err == nil || resBlocked.ExitCode != clierror.ExitOperational {
		t.Errorf("expected unauthorized loopback scan to be blocked with ExitOperational (2), got exit code %d, err %v", resBlocked.ExitCode, err)
	}

	// 2. Cloud metadata IP (169.254.169.254) is ALWAYS blocked even if loopback is enabled
	cfgMetadata := &Config{
		Provider:      ProviderGeneric,
		TargetURL:     "http://169.254.169.254/latest/meta-data/",
		OutputDir:     filepath.Join(tmpDir, "reports-meta"),
		Timeout:       "2s",
		Quiet:         true,
		AllowLoopback: true, // Even with loopback enabled, link-local must remain prohibited
	}

	resMeta, errMeta := Run(context.Background(), cfgMetadata, nil)
	if errMeta == nil || resMeta.ExitCode != clierror.ExitOperational {
		t.Errorf("expected cloud metadata IP to be blocked with ExitOperational (2), got exit code %d, err %v", resMeta.ExitCode, errMeta)
	}

	// 3. Explicitly authorized loopback scan succeeds
	cfgAllowed := &Config{
		Provider:      ProviderGeneric,
		TargetURL:     server.URL,
		OutputDir:     filepath.Join(tmpDir, "reports-allowed"),
		Timeout:       "2s",
		Quiet:         true,
		AllowLoopback: true, // Explicitly granted permission
	}

	resAllowed, errAllowed := Run(context.Background(), cfgAllowed, nil)
	if errAllowed != nil || resAllowed.ExitCode != clierror.ExitSuccess {
		t.Errorf("expected explicitly authorized loopback scan to succeed with ExitSuccess (0), got exit code %d, err %v", resAllowed.ExitCode, errAllowed)
	}
}

// 4. Test that HTTP redirects targeting prohibited destinations (cloud metadata, private IPs)
// are blocked and cannot bypass network safety.
func TestCIRunner_NetworkSafety_RedirectToProhibitedDestinationBlocked(t *testing.T) {
	// Setup redirect server that redirects to link-local cloud metadata
	redirectServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/redirect-to-metadata" {
			http.Redirect(w, r, "http://169.254.169.254/latest/meta-data/", http.StatusFound)
			return
		}
		if r.URL.Path == "/redirect-to-private" {
			http.Redirect(w, r, "http://10.254.1.1/secret", http.StatusFound)
			return
		}
		// Base page containing links to the redirect endpoints
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`<!DOCTYPE html><html><body>
			<a href="/redirect-to-metadata">Metadata</a>
			<a href="/redirect-to-private">Private</a>
		</body></html>`))
	}))
	defer redirectServer.Close()

	tmpDir := t.TempDir()

	// Direct redirect to cloud metadata must fail closed
	cfgMetadataRedirect := &Config{
		Provider:      ProviderGeneric,
		TargetURL:     redirectServer.URL + "/redirect-to-metadata",
		OutputDir:     filepath.Join(tmpDir, "reports-redir-meta"),
		Timeout:       "2s",
		Quiet:         true,
		AllowLoopback: true, // Loopback allowed for the initial server, but redirect destination is prohibited
	}

	resMeta, errMeta := Run(context.Background(), cfgMetadataRedirect, nil)
	if errMeta == nil || resMeta.ExitCode != clierror.ExitOperational {
		t.Errorf("expected redirect to 169.254.169.254 to be blocked with ExitOperational (2), got exit code %d, err %v", resMeta.ExitCode, errMeta)
	}

	// Redirect to private IP without AllowPrivateIPs must fail closed
	cfgPrivateRedirect := &Config{
		Provider:        ProviderGeneric,
		TargetURL:       redirectServer.URL + "/redirect-to-private",
		OutputDir:       filepath.Join(tmpDir, "reports-redir-priv"),
		Timeout:         "2s",
		Quiet:           true,
		AllowLoopback:   true,
		AllowPrivateIPs: false, // Prohibited private destination
	}

	resPriv, errPriv := Run(context.Background(), cfgPrivateRedirect, nil)
	if errPriv == nil || resPriv.ExitCode != clierror.ExitOperational {
		t.Errorf("expected redirect to 10.254.1.1 to be blocked with ExitOperational (2), got exit code %d, err %v", resPriv.ExitCode, errPriv)
	}
}

// MockResolver implements crawler.Resolver for deterministic DNS resolution testing.
type mockDNSResolver struct {
	mapping map[string][]net.IPAddr
}

func (m *mockDNSResolver) LookupIPAddr(ctx context.Context, host string) ([]net.IPAddr, error) {
	if addrs, ok := m.mapping[host]; ok {
		return addrs, nil
	}
	return nil, fmt.Errorf("host not found in mock DNS: %s", host)
}

// 5. Test DNS resolution and rebinding prevention.
// Verifies that dual-homed DNS answers (safe + prohibited IP) and prohibited single IPs
// are immediately rejected by the SafeDialer at socket level before any connection is made.
func TestCIRunner_NetworkSafety_DNSResolutionRebindingProhibited(t *testing.T) {
	mockRes := &mockDNSResolver{
		mapping: map[string][]net.IPAddr{
			// Dual-homed rebinding trick: public IP + loopback
			"rebind.example.com": {
				{IP: net.ParseIP("93.184.216.34")},
				{IP: net.ParseIP("127.0.0.1")},
			},
			// Dual-homed rebinding trick: public IP + cloud metadata
			"meta-rebind.example.com": {
				{IP: net.ParseIP("93.184.216.34")},
				{IP: net.ParseIP("169.254.169.254")},
			},
			// Single prohibited loopback IP
			"loopback.example.com": {
				{IP: net.ParseIP("127.0.0.1")},
			},
			// Single prohibited private IP
			"internal.example.com": {
				{IP: net.ParseIP("10.0.0.1")},
			},
			// Pure public safe IP
			"safe.example.com": {
				{IP: net.ParseIP("93.184.216.34")},
			},
		},
	}

	dialCount := 0
	mockDial := func(ctx context.Context, network, addr string) (net.Conn, error) {
		dialCount++
		return nil, fmt.Errorf("dial intercepted")
	}

	// Case A: Dual-homed DNS containing loopback must be rejected
	dialerLoopback := crawler.NewSafeDialContext(crawler.SafeDialerOptions{
		AllowLoopback:   false,
		AllowPrivateIPs: false,
		Resolver:        mockRes,
		DialFunc:        mockDial,
	})

	_, err := dialerLoopback(context.Background(), "tcp", "rebind.example.com:80")
	if err == nil {
		t.Fatalf("expected dual-homed rebind to loopback to fail, got nil")
	}
	if !strings.Contains(err.Error(), "SSRF security refusal") || !strings.Contains(err.Error(), "loopback") {
		t.Errorf("expected SSRF refusal for loopback rebind, got: %v", err)
	}

	// Case B: Dual-homed DNS containing cloud metadata must be rejected even if loopback is permitted
	dialerMeta := crawler.NewSafeDialContext(crawler.SafeDialerOptions{
		AllowLoopback:   true,
		AllowPrivateIPs: true,
		Resolver:        mockRes,
		DialFunc:        mockDial,
	})

	_, err = dialerMeta(context.Background(), "tcp", "meta-rebind.example.com:80")
	if err == nil {
		t.Fatalf("expected dual-homed rebind to metadata to fail, got nil")
	}
	if !strings.Contains(err.Error(), "SSRF security refusal") || !strings.Contains(err.Error(), "cloud metadata") {
		t.Errorf("expected SSRF refusal for metadata rebind, got: %v", err)
	}

	// Case C: Private IP rejected when AllowPrivateIPs is false
	_, err = dialerLoopback(context.Background(), "tcp", "internal.example.com:80")
	if err == nil {
		t.Fatalf("expected internal private IP to fail, got nil")
	}
	if !strings.Contains(err.Error(), "SSRF security refusal") || !strings.Contains(err.Error(), "RFC 1918") {
		t.Errorf("expected SSRF refusal for private IP, got: %v", err)
	}

	// Invariant: Zero dials were attempted for prohibited destinations
	if dialCount != 0 {
		t.Errorf("expected 0 socket dial attempts for prohibited destinations, got %d", dialCount)
	}
}

// 6. Test that untrusted query strings, URL parameters, or headers cannot activate loopback opt-in
func TestCIRunner_NetworkSafety_UntrustedInputCannotActivateOptInFlags(t *testing.T) {
	tmpDir := t.TempDir()

	t.Setenv("FELIX_ALLOW_LOOPBACK", "false")
	t.Setenv("FELIX_ALLOW_PRIVATE_IPS", "false")

	// Target URL attempts parameter injection to spoof opt-in flags
	craftyURL := "http://127.0.0.1:8080/test?allow-loopback=true&FELIX_ALLOW_LOOPBACK=true#allow_private"
	cfg := &Config{
		Provider:      ProviderGeneric,
		TargetURL:     craftyURL,
		OutputDir:     filepath.Join(tmpDir, "reports-spoof"),
		Timeout:       "1s",
		Quiet:         true,
		AllowLoopback: false, // Default caller configuration
	}

	res, err := Run(context.Background(), cfg, nil)
	if err == nil || res.ExitCode != clierror.ExitOperational {
		t.Errorf("expected spoofed opt-in parameters in URL to fail closed with ExitOperational (2), got exit code %d, err %v", res.ExitCode, err)
	}
}

// 7. Test that internal assessments succeed ONLY with valid explicit authorization records
func TestCIRunner_NetworkSafety_AuthorizedInternalAssessmentMechanism(t *testing.T) {
	// Mock internal target server on loopback
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("<!DOCTYPE html><html><body>Authorized Internal Service</body></html>"))
	}))
	defer server.Close()

	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "auth_test.db")
	store, err := assessment.NewSQLiteStore(dbPath)
	if err != nil {
		t.Fatalf("failed creating store: %v", err)
	}
	defer store.Close()

	client := &assessment.Client{
		ID:   "client-internal",
		Name: "Internal Infrastructure Team",
	}
	_ = store.CreateClient(client)

	asm := &assessment.Assessment{
		ID:             "asm-internal-01",
		Ref:            "INT-01",
		ClientID:       client.ID,
		Name:           "Internal Authorized Assessment",
		AssessmentType: "web",
		Status:         assessment.StatusReady,
		ScopeMode:      "same-origin",
	}
	_ = store.CreateAssessment(asm)

	tgt := &assessment.AssessmentTarget{
		ID:           "tgt-internal-01",
		AssessmentID: asm.ID,
		TargetURL:    server.URL,
		ScopeStatus:  "APPROVED",
	}
	_ = store.AddTarget(tgt)

	// Subtest A: Missing / Expired Authorization fails closed
	now := time.Now().UTC()
	expiredFrom := now.Add(-48 * time.Hour)
	expiredUntil := now.Add(-24 * time.Hour)
	_ = store.SetAuthorization(&assessment.AuthorizationRecord{
		ID:                  "auth-expired",
		AssessmentID:        asm.ID,
		AuthorizingParty:    "Security Ops",
		AuthorizationMethod: "WRITTEN_CONTRACT",
		Status:              assessment.AuthApproved,
		DateReceived:        expiredFrom,
		ValidFrom:           &expiredFrom,
		ValidUntil:          &expiredUntil,
	})

	cfgExpired := &Config{
		Provider:      ProviderGeneric,
		AssessmentRef: asm.Ref,
		OutputDir:     filepath.Join(tmpDir, "reports-expired"),
		DatabasePath:  dbPath,
		Timeout:       "2s",
		Quiet:         true,
		AllowLoopback: true,
	}

	resExp, errExp := Run(context.Background(), cfgExpired, store)
	if errExp == nil || resExp.ExitCode == clierror.ExitSuccess {
		t.Errorf("expected assessment with expired authorization to fail with non-zero security refusal, got code %d, err %v", resExp.ExitCode, errExp)
	}
	if !strings.Contains(errExp.Error(), "security refusal: invalid authorization") {
		t.Errorf("expected security refusal error message, got: %v", errExp)
	}

	// Subtest B: Valid approved authorization record with AllowLoopback succeeds
	validFrom := now.Add(-1 * time.Hour)
	validUntil := now.Add(24 * time.Hour)
	_ = store.SetAuthorization(&assessment.AuthorizationRecord{
		ID:                  "auth-valid",
		AssessmentID:        asm.ID,
		AuthorizingParty:    "Security Ops",
		AuthorizationMethod: "WRITTEN_CONTRACT",
		Status:              assessment.AuthApproved,
		DateReceived:        now,
		ValidFrom:           &validFrom,
		ValidUntil:          &validUntil,
	})

	cfgValid := &Config{
		Provider:      ProviderGeneric,
		AssessmentRef: asm.Ref,
		OutputDir:     filepath.Join(tmpDir, "reports-valid"),
		DatabasePath:  dbPath,
		Timeout:       "2s",
		Quiet:         true,
		AllowLoopback: true,
	}

	resVal, errVal := Run(context.Background(), cfgValid, store)
	if errVal != nil || resVal.ExitCode != clierror.ExitSuccess {
		t.Errorf("expected authorized internal assessment to succeed with ExitSuccess (0), got code %d, err %v", resVal.ExitCode, errVal)
	}
}

// 8. Test real execution order and failure behavior using an instrumented canary test binary.
// Proves conclusively that:
// - Missing required digest blocks execution without invoking the binary.
// - Malformed digest blocks execution without invoking the binary.
// - Mismatched digest blocks execution without invoking the binary.
// - Correct digest allows execution to proceed.
func TestVerifyBinaryWithIntegrity_ExecutionOrderCanaryProof(t *testing.T) {
	tmpDir := t.TempDir()

	// 1. Create source for an instrumented canary binary that records execution
	canarySrc := `package main

import (
	"fmt"
	"os"
)

func main() {
	outFile := os.Getenv("FELIX_CANARY_TOUCH_FILE")
	if outFile != "" {
		_ = os.WriteFile(outFile, []byte("EXECUTED"), 0644)
	}
	fmt.Println("FELIX Security Platform v1.0.0-canary")
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

	// Compile the canary binary
	buildCmd := exec.Command("go", "build", "-o", canaryBin, srcPath)
	if out, err := buildCmd.CombinedOutput(); err != nil {
		t.Fatalf("failed compiling canary binary: %v, out: %s", err, string(out))
	}

	canaryTouch := filepath.Join(tmpDir, "canary_touch.txt")
	t.Setenv("FELIX_CANARY_TOUCH_FILE", canaryTouch)

	// Subtest 1: Missing required SHA-256 blocks execution
	_ = os.Remove(canaryTouch)
	errMissing := VerifyBinaryWithIntegrity(canaryBin, "", "", true)
	if errMissing == nil {
		t.Fatalf("expected error when SHA256 is required but missing, got nil")
	}
	if _, err := os.Stat(canaryTouch); !os.IsNotExist(err) {
		t.Fatalf("CRITICAL SECURITY DEFECT: unverified binary was executed despite missing digest!")
	}

	// Subtest 2: Malformed SHA-256 format blocks execution
	_ = os.Remove(canaryTouch)
	errMalformed := VerifyBinaryWithIntegrity(canaryBin, "", "bad-non-hex-hash", false)
	if errMalformed == nil {
		t.Fatalf("expected error for malformed SHA256 format, got nil")
	}
	if _, err := os.Stat(canaryTouch); !os.IsNotExist(err) {
		t.Fatalf("CRITICAL SECURITY DEFECT: unverified binary was executed despite malformed digest format!")
	}

	// Subtest 3: Mismatched SHA-256 blocks execution
	_ = os.Remove(canaryTouch)
	badDigest := strings.Repeat("0", 64)
	errMismatch := VerifyBinaryWithIntegrity(canaryBin, "", badDigest, false)
	if errMismatch == nil {
		t.Fatalf("expected error for mismatched SHA256, got nil")
	}
	if _, err := os.Stat(canaryTouch); !os.IsNotExist(err) {
		t.Fatalf("CRITICAL SECURITY DEFECT: unverified binary was executed despite mismatched digest!")
	}

	// Subtest 4: Matching SHA-256 digest allows execution to proceed
	_ = os.Remove(canaryTouch)
	actualHash, err := computeSHA256(canaryBin)
	if err != nil {
		t.Fatalf("failed computing canary hash: %v", err)
	}

	errMatch := VerifyBinaryWithIntegrity(canaryBin, "1.0.0-canary", actualHash, true)
	if errMatch != nil {
		t.Fatalf("expected matching SHA256 and version to succeed, got: %v", errMatch)
	}
	if _, err := os.Stat(canaryTouch); os.IsNotExist(err) {
		t.Fatalf("expected canary binary to be executed after verification passed, but touch file was not found")
	}
}
