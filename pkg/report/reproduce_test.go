package report

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func findGitBash() string {
	candidates := []string{
		`C:\Program Files\Git\bin\bash.exe`,
		`C:\Program Files\Git\usr\bin\bash.exe`,
		`bash`,
	}
	for _, c := range candidates {
		if _, err := exec.LookPath(c); err == nil {
			return c
		}
		if _, err := os.Stat(c); err == nil {
			return c
		}
	}
	return ""
}

// TestSanitizeScriptFilename verifies deterministic, collision-safe, path-traversal-free filenames.
func TestSanitizeScriptFilename(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"CHAIN-001", "reproduce_chain_CHAIN-001.sh"},
		{"chain_auth_bypass_42", "reproduce_chain_chain_auth_bypass_42.sh"},
		{"../../etc/passwd; rm -rf /", "reproduce_chain_etc_passwd_rm_rf.sh"},
		{"<script>alert('pwn')</script>", "reproduce_chain_script_alert_pwn_script.sh"},
		{"`id` && $(whoami)", "reproduce_chain_id_whoami.sh"},
		{"", "reproduce_chain_unnamed_chain.sh"},
		{"   ---___   ", "reproduce_chain_unnamed_chain.sh"},
	}

	for _, tt := range tests {
		got := SanitizeScriptFilename(tt.input)
		if got != tt.expected {
			t.Errorf("SanitizeScriptFilename(%q) = %q, expected %q", tt.input, got, tt.expected)
		}
		if !strings.HasPrefix(got, "reproduce_chain_") || !strings.HasSuffix(got, ".sh") {
			t.Errorf("SanitizeScriptFilename(%q) invalid prefix/suffix: %q", tt.input, got)
		}
	}
}

// TestShellEscape verifies that strings with single quotes, double quotes, backticks, and subshells
// are securely quoted for POSIX Bash.
func TestShellEscape(t *testing.T) {
	tests := []struct {
		input string
	}{
		{`normal text`},
		{`it's a quote`},
		{`"quoted" string`},
		{`$(rm -rf /)`},
		{"`whoami`"},
		{`hello; echo evil`},
		{"multi\nline\ntext"},
	}

	bashBin := findGitBash()
	for _, tt := range tests {
		escaped := ShellEscape(tt.input)
		if !strings.HasPrefix(escaped, "'") || !strings.HasSuffix(escaped, "'") {
			t.Errorf("ShellEscape(%q) missing single quotes: %s", tt.input, escaped)
		}

		// Verify with real bash if available
		if bashBin != "" {
			cmd := exec.Command(bashBin, "-c", fmt.Sprintf("printf '%%s' %s", escaped))
			out, err := cmd.CombinedOutput()
			if err != nil {
				t.Errorf("bash evaluation failed for %q: %v (output: %s)", tt.input, err, out)
			}
			if string(out) != tt.input {
				t.Errorf("bash round-trip mismatch: got %q, expected %q", string(out), tt.input)
			}
		}
	}
}

// TestPlanReproductionScript_SafeChain verifies that a multi-hop confirmed chain
// produces properly planned safe steps with expected predicates.
func TestPlanReproductionScript_SafeChain(t *testing.T) {
	findings := []Finding{
		{
			ID:       "FND-01",
			Title:    "JS Secret Exposure",
			Severity: "HIGH",
			Category: "Information Disclosure",
			Endpoint: "/static/js/main.js",
			Method:   "GET",
			Evidence: "const ADMIN_INTERNAL_KEY = 'tok_123';",
			EvidenceDetails: EvidenceDetails{
				HTTPStatus: 200,
			},
		},
		{
			ID:       "FND-02",
			Title:    "Admin Route Reachable",
			Severity: "CRITICAL",
			Category: "Broken Access Control",
			Endpoint: "/api/v2/admin/routes",
			Method:   "GET",
			EvidenceDetails: EvidenceDetails{
				HTTPStatus: 200,
			},
		},
	}

	path := AttackPathSummary{
		ID:          "CHAIN-SAFE-01",
		Title:       "Secret to Admin Route",
		Status:      "CONFIRMED",
		TargetAsset: "Admin Cluster",
		GraphNodes: []AttackPathNode{
			{ID: "FND-01", Title: "JS Secret Exposure", Severity: "HIGH", Endpoint: "/static/js/main.js"},
			{ID: "FND-02", Title: "Admin Route Reachable", Severity: "CRITICAL", Endpoint: "/api/v2/admin/routes"},
		},
		GraphEdges: []AttackPathEdge{
			{
				ID:               "E-01",
				SourceID:         "FND-01",
				TargetID:         "FND-02",
				RuleCode:         "COR-AUTH-LEAK",
				RuleName:         "Token Leakage",
				ValidationStatus: "CONFIRMED",
				Explanation:      "Token unlocks route",
			},
		},
	}

	plan, err := PlanReproductionScript(path, findings, ReproductionOptions{AssessmentRef: "ASM-TEST"})
	if err != nil {
		t.Fatalf("PlanReproductionScript failed: %v", err)
	}

	if plan.SafeStepCount != 2 {
		t.Errorf("expected 2 safe steps, got %d", plan.SafeStepCount)
	}
	if plan.ManualStepCount != 0 {
		t.Errorf("expected 0 manual steps, got %d", plan.ManualStepCount)
	}
	if len(plan.Steps) != 2 {
		t.Fatalf("expected 2 steps in plan, got %d", len(plan.Steps))
	}

	if plan.Steps[0].Endpoint != "/static/js/main.js" {
		t.Errorf("expected endpoint /static/js/main.js, got %s", plan.Steps[0].Endpoint)
	}
	if plan.Steps[0].ExpectedPattern != "ADMIN_INTERNAL_KEY" {
		t.Errorf("expected pattern ADMIN_INTERNAL_KEY, got %s", plan.Steps[0].ExpectedPattern)
	}
}

// TestPlanReproductionScript_SafetyPolicyExclusions verifies that destructive methods,
// RCE payloads, and destructive SQL are strictly marked MANUAL_VERIFICATION_REQUIRED.
func TestPlanReproductionScript_SafetyPolicyExclusions(t *testing.T) {
	findings := []Finding{
		{
			ID:       "FND-DELETE",
			Title:    "Unauthorized Tenant Deletion",
			Category: "Broken Access Control",
			Endpoint: "/api/v1/tenant/delete",
			Method:   "DELETE",
			Evidence: "DELETE /api/v1/tenant/delete",
		},
		{
			ID:       "FND-RCE",
			Title:    "Remote Code Execution",
			Category: "Remote Code Execution",
			Endpoint: "/api/v1/eval",
			Method:   "POST",
			Evidence: "cmd=cat /etc/passwd; id",
		},
		{
			ID:       "FND-DROP",
			Title:    "Destructive SQL Injection",
			Category: "Injection & Execution",
			Endpoint: "/api/v1/export?q=DROP+TABLE+users",
			Method:   "GET",
			Evidence: "DROP TABLE users;",
		},
	}

	path := AttackPathSummary{
		ID:    "CHAIN-UNSAFE",
		Title: "Unsafe Exploit Chain",
		GraphNodes: []AttackPathNode{
			{ID: "FND-DELETE", Title: "Unauthorized Tenant Deletion", Category: "Broken Access Control", Endpoint: "/api/v1/tenant/delete"},
			{ID: "FND-RCE", Title: "Remote Code Execution", Category: "Remote Code Execution", Endpoint: "/api/v1/eval"},
			{ID: "FND-DROP", Title: "Destructive SQL Injection", Category: "Injection & Execution", Endpoint: "/api/v1/export?q=DROP+TABLE+users"},
		},
	}

	plan, err := PlanReproductionScript(path, findings, ReproductionOptions{})
	if err != nil {
		t.Fatalf("PlanReproductionScript failed: %v", err)
	}

	if plan.SafeStepCount != 0 {
		t.Errorf("expected 0 safe steps for destructive actions, got %d", plan.SafeStepCount)
	}
	if plan.ManualStepCount != 3 {
		t.Errorf("expected 3 manual steps, got %d", plan.ManualStepCount)
	}

	for _, step := range plan.Steps {
		if step.IsSafelyRunnable {
			t.Errorf("step %s should NOT be safely runnable", step.SourceFindingID)
		}
		if step.UnsafeReason == "" {
			t.Errorf("step %s missing UnsafeReason", step.SourceFindingID)
		}
		if len(step.ManualChecklist) == 0 {
			t.Errorf("step %s missing ManualChecklist", step.SourceFindingID)
		}
	}
}

// TestGenerateReproductionScript_BashSyntax verifies that generated scripts pass bash -n syntax checking.
func TestGenerateReproductionScript_BashSyntax(t *testing.T) {
	bashBin := findGitBash()
	if bashBin == "" {
		t.Skip("bash not found, skipping syntax verification")
	}

	findings := []Finding{
		{
			ID:       "FND-TEST-01",
			Title:    "Test Finding with \"Quotes\" & `Backticks` and $Vars",
			Category: "Information Disclosure",
			Endpoint: "/api/test?query=value&sort=id",
			Method:   "GET",
			Evidence: "{\"status\": \"ok\", \"tenant_id\": \"42\"}",
			EvidenceDetails: EvidenceDetails{
				HTTPStatus: 200,
			},
		},
	}

	path := AttackPathSummary{
		ID:    "CHAIN-SYNTAX-TEST",
		Title: "Syntax Check Chain",
		GraphNodes: []AttackPathNode{
			{ID: "FND-TEST-01", Title: "Test Finding with \"Quotes\"", Endpoint: "/api/test?query=value&sort=id"},
		},
	}

	plan, err := GenerateReproductionScript(path, findings, ReproductionOptions{TargetOrigin: "https://example.com"})
	if err != nil {
		t.Fatalf("GenerateReproductionScript failed: %v", err)
	}

	tmpFile := filepath.Join(t.TempDir(), "test_syntax.sh")
	if err := os.WriteFile(tmpFile, []byte(plan.ShellScriptContent), 0755); err != nil {
		t.Fatalf("failed to write temp script: %v", err)
	}

	cmd := exec.Command(bashBin, "-n", tmpFile)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("bash -n syntax validation failed: %v\nOutput:\n%s\nScript:\n%s", err, string(out), plan.ShellScriptContent)
	}
}

// TestReproductionScript_ExecutionAgainstLocalMock tests end-to-end execution of a generated script
// against a local mock HTTP test server.
func TestReproductionScript_ExecutionAgainstLocalMock(t *testing.T) {
	bashBin := findGitBash()
	if bashBin == "" {
		t.Skip("bash not found, skipping local execution test")
	}

	// Local Mock Server
	var requestCount int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount++
		switch r.URL.Path {
		case "/api/leak":
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"admin_key": "ADMIN_INTERNAL_KEY"}`))
		case "/api/shadow":
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"route": "active", "database": "PostgreSQL"}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	findings := []Finding{
		{
			ID:       "FND-01",
			Title:    "Secret Leak",
			Endpoint: "/api/leak",
			Method:   "GET",
			Evidence: "ADMIN_INTERNAL_KEY",
			EvidenceDetails: EvidenceDetails{
				HTTPStatus: 200,
			},
		},
		{
			ID:       "FND-02",
			Title:    "Shadow Route",
			Endpoint: "/api/shadow",
			Method:   "GET",
			Evidence: "PostgreSQL",
			EvidenceDetails: EvidenceDetails{
				HTTPStatus: 200,
			},
		},
	}

	path := AttackPathSummary{
		ID:    "CHAIN-MOCK-TEST",
		Title: "Mock Test Chain",
		GraphNodes: []AttackPathNode{
			{ID: "FND-01", Title: "Secret Leak", Endpoint: "/api/leak"},
			{ID: "FND-02", Title: "Shadow Route", Endpoint: "/api/shadow"},
		},
	}

	// 1. Scenario A: Successful Verification (Exit Code 0)
	plan, err := GenerateReproductionScript(path, findings, ReproductionOptions{TargetOrigin: server.URL})
	if err != nil {
		t.Fatalf("GenerateReproductionScript failed: %v", err)
	}

	scriptPath := filepath.Join(t.TempDir(), "run_mock.sh")
	if err := os.WriteFile(scriptPath, []byte(plan.ShellScriptContent), 0755); err != nil {
		t.Fatalf("failed to write script: %v", err)
	}

	cmdA := exec.Command(bashBin, scriptPath)
	cmdA.Env = append(os.Environ(), "NON_INTERACTIVE=1", "TARGET_ORIGIN="+server.URL)
	outA, errA := cmdA.CombinedOutput()
	if errA != nil {
		t.Fatalf("expected exit code 0 on verified mock, got error: %v\nOutput:\n%s", errA, string(outA))
	}
	if !strings.Contains(string(outA), "[VERIFIED]") {
		t.Errorf("output missing [VERIFIED] marker:\n%s", string(outA))
	}

	// 2. Scenario B: Target Origin Validation Failure (Exit Code 1)
	cmdB := exec.Command(bashBin, scriptPath)
	cmdB.Env = append(os.Environ(), "NON_INTERACTIVE=1", "TARGET_ORIGIN=ftp://invalid-scheme.com")
	outB, errB := cmdB.CombinedOutput()
	if errB == nil {
		t.Fatalf("expected non-zero exit code for invalid target origin, got success\nOutput:\n%s", string(outB))
	}
	if !strings.Contains(string(outB), "Security Policy Violation") {
		t.Errorf("output missing Security Policy Violation warning:\n%s", string(outB))
	}

	// 3. Scenario C: Failed Verification when mock returns 404 (Exit Code 2)
	badFindings := []Finding{
		{
			ID:       "FND-BAD",
			Title:    "Missing Route",
			Endpoint: "/api/nonexistent",
			Method:   "GET",
			EvidenceDetails: EvidenceDetails{
				HTTPStatus: 200,
			},
		},
	}
	badPath := AttackPathSummary{
		ID:    "CHAIN-BAD",
		Title: "Bad Chain",
		GraphNodes: []AttackPathNode{
			{ID: "FND-BAD", Title: "Missing Route", Endpoint: "/api/nonexistent"},
		},
	}
	planBad, err := GenerateReproductionScript(badPath, badFindings, ReproductionOptions{TargetOrigin: server.URL})
	if err != nil {
		t.Fatalf("GenerateReproductionScript bad failed: %v", err)
	}
	scriptBad := filepath.Join(t.TempDir(), "run_bad.sh")
	_ = os.WriteFile(scriptBad, []byte(planBad.ShellScriptContent), 0755)

	cmdC := exec.Command(bashBin, scriptBad)
	cmdC.Env = append(os.Environ(), "NON_INTERACTIVE=1", "TARGET_ORIGIN="+server.URL)
	outC, errC := cmdC.CombinedOutput()
	if errC == nil {
		t.Fatalf("expected exit code 2 when check fails, got success\nOutput:\n%s", string(outC))
	}
	if !strings.Contains(string(outC), "[NOT_VERIFIED]") {
		t.Errorf("output missing [NOT_VERIFIED] marker:\n%s", string(outC))
	}
}

// TestWriteReproductionScript_OverwritePolicy verifies that existing files are protected
// unless opts.Overwrite is true.
func TestWriteReproductionScript_OverwritePolicy(t *testing.T) {
	tmpDir := t.TempDir()
	targetFile := filepath.Join(tmpDir, "reproduce_chain_OVERWRITE.sh")

	path := AttackPathSummary{
		ID:    "CHAIN-OVERWRITE",
		Title: "Overwrite Test",
		GraphNodes: []AttackPathNode{
			{ID: "F-1", Title: "Node 1", Endpoint: "/api/test"},
		},
	}

	// First write should succeed
	written, err := WriteReproductionScript(path, nil, ReproductionOptions{OutputFile: targetFile, Overwrite: false})
	if err != nil {
		t.Fatalf("first write failed: %v", err)
	}
	if written != targetFile {
		t.Errorf("expected written path %s, got %s", targetFile, written)
	}

	// Second write with Overwrite: false must return error
	_, err = WriteReproductionScript(path, nil, ReproductionOptions{OutputFile: targetFile, Overwrite: false})
	if err == nil {
		t.Fatalf("expected error when overwriting existing file with Overwrite=false")
	}

	// Third write with Overwrite: true must succeed
	_, err = WriteReproductionScript(path, nil, ReproductionOptions{OutputFile: targetFile, Overwrite: true})
	if err != nil {
		t.Fatalf("third write with Overwrite=true failed: %v", err)
	}
}

// TestReproductionScript_RedirectOriginEnforcement tests that requests never escape the authorized origin
// when an approved server attempts to redirect to a different host, port, scheme, or loopback/private address.
func TestReproductionScript_RedirectOriginEnforcement(t *testing.T) {
	bashBin := findGitBash()
	if bashBin == "" {
		t.Skip("bash not found, skipping redirect origin enforcement test")
	}

	testCases := []struct {
		name        string
		endpoint    string
		redirectLoc string
	}{
		{
			name:        "Redirect to different hostname",
			endpoint:    "/redirect/host",
			redirectLoc: "https://evil-external-domain.com/steal",
		},
		{
			name:        "Redirect to different port",
			endpoint:    "/redirect/port",
			redirectLoc: "http://127.0.0.1:9999/admin",
		},
		{
			name:        "Redirect to different scheme",
			endpoint:    "/redirect/scheme",
			redirectLoc: "ftp://127.0.0.1/file",
		},
		{
			name:        "Redirect to cloud metadata IP",
			endpoint:    "/redirect/metadata",
			redirectLoc: "http://169.254.169.254/latest/meta-data/",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				http.Redirect(w, r, tc.redirectLoc, http.StatusFound)
			}))
			defer server.Close()

			findings := []Finding{
				{
					ID:       "FND-REDIR",
					Title:    "Redirect Finding",
					Endpoint: tc.endpoint,
					Method:   "GET",
					EvidenceDetails: EvidenceDetails{
						HTTPStatus: 200,
					},
				},
			}
			path := AttackPathSummary{
				ID:    "CHAIN-REDIR-" + tc.name,
				Title: "Redirect Enforcement Chain",
				GraphNodes: []AttackPathNode{
					{ID: "FND-REDIR", Title: "Redirect Finding", Endpoint: tc.endpoint},
				},
			}

			plan, err := GenerateReproductionScript(path, findings, ReproductionOptions{TargetOrigin: server.URL})
			if err != nil {
				t.Fatalf("GenerateReproductionScript failed: %v", err)
			}

			scriptPath := filepath.Join(t.TempDir(), "run_redir.sh")
			if err := os.WriteFile(scriptPath, []byte(plan.ShellScriptContent), 0755); err != nil {
				t.Fatalf("failed to write script: %v", err)
			}

			cmd := exec.Command(bashBin, scriptPath)
			cmd.Env = append(os.Environ(), "NON_INTERACTIVE=1", "TARGET_ORIGIN="+server.URL)
			out, err := cmd.CombinedOutput()

			// Must exit with non-zero exit code (exit code 2: NOT_VERIFIED)
			if err == nil {
				t.Errorf("expected script to fail with exit code 2 when redirect escapes origin, got success\nOutput:\n%s", string(out))
			}
			outStr := string(out)
			if !strings.Contains(outStr, "Cross-origin redirect blocked") && !strings.Contains(outStr, "escapes authorized TARGET_ORIGIN") {
				t.Errorf("expected security policy cross-origin redirect warning in output:\n%s", outStr)
			}
			if !strings.Contains(outStr, "[NOT_VERIFIED]") {
				t.Errorf("expected [NOT_VERIFIED] marker in output:\n%s", outStr)
			}
		})
	}
}

// TestReproductionScript_HostileMetadataInjection tests that adversarial finding attributes
// cannot inject shell commands, curl flags, or escape escaping boundaries.
func TestReproductionScript_HostileMetadataInjection(t *testing.T) {
	bashBin := findGitBash()
	if bashBin == "" {
		t.Skip("bash not found, skipping hostile metadata test")
	}

	hostileFindings := []Finding{
		{
			ID:       "FND-HOSTILE-01",
			Title:    "Injection Title \"; id; touch /tmp/pwn; #",
			Endpoint: "/api/test?arg=\"$(whoami)\"&backtick=`id`&flag=--evil-flag",
			Method:   "GET",
			EvidenceDetails: EvidenceDetails{
				HTTPStatus: 200,
			},
		},
		{
			ID:       "FND-HOSTILE-02",
			Title:    "Protocol Relative URL",
			Endpoint: "//attacker.com/steal?data=123",
			Method:   "GET",
			EvidenceDetails: EvidenceDetails{
				HTTPStatus: 200,
			},
		},
		{
			ID:       "FND-HOSTILE-03",
			Title:    "Illegal Method with Shell Command",
			Endpoint: "/api/items",
			Method:   "GET; rm -rf /",
			EvidenceDetails: EvidenceDetails{
				HTTPStatus: 200,
			},
		},
	}

	path := AttackPathSummary{
		ID:    "CHAIN-HOSTILE",
		Title: "Hostile Input Chain",
		GraphNodes: []AttackPathNode{
			{ID: "FND-HOSTILE-01", Title: hostileFindings[0].Title, Endpoint: hostileFindings[0].Endpoint},
			{ID: "FND-HOSTILE-02", Title: hostileFindings[1].Title, Endpoint: hostileFindings[1].Endpoint},
			{ID: "FND-HOSTILE-03", Title: hostileFindings[2].Title, Endpoint: hostileFindings[2].Endpoint},
		},
	}

	plan, err := GenerateReproductionScript(path, hostileFindings, ReproductionOptions{TargetOrigin: "https://safe.target.local"})
	if err != nil {
		t.Fatalf("GenerateReproductionScript failed: %v", err)
	}

	// 1. Verify that FND-HOSTILE-03 with invalid method was marked manual/unsafe
	if plan.Steps[2].IsSafelyRunnable {
		t.Errorf("expected step 3 with method %q to be marked unsafe", hostileFindings[2].Method)
	}

	// 2. Verify protocol relative endpoint was collapsed to safe path
	if strings.HasPrefix(plan.Steps[1].Endpoint, "//") {
		t.Errorf("expected leading double slashes to be stripped, got %s", plan.Steps[1].Endpoint)
	}

	// 3. Verify bash -n syntax checking passes cleanly without shell syntax errors
	tmpFile := filepath.Join(t.TempDir(), "test_hostile.sh")
	if err := os.WriteFile(tmpFile, []byte(plan.ShellScriptContent), 0755); err != nil {
		t.Fatalf("failed to write temp script: %v", err)
	}

	cmd := exec.Command(bashBin, "-n", tmpFile)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("bash -n syntax validation failed on hostile input:\n%s\nScript:\n%s", string(out), plan.ShellScriptContent)
	}
}

// TestReproductionScript_SecretRedaction verifies that credentials, tokens, cookies,
// and passwords do not leak into generated reproduction scripts.
func TestReproductionScript_SecretRedaction(t *testing.T) {
	secretToken := "sk-live-999888777666555444333"
	secretPass := "SuperSecretPassword123!"
	secretCookie := "session_id=SEC_COOKIE_XYZ_98765"

	findings := []Finding{
		{
			ID:       "FND-SECRET-01",
			Title:    "Secret Leak Finding",
			Endpoint: "https://admin:" + secretPass + "@target.local/api/v1/auth?token=" + secretToken,
			Method:   "GET",
			Evidence: "Authorization: Bearer " + secretToken + "\nCookie: " + secretCookie,
			EvidenceDetails: EvidenceDetails{
				Observation: "Found sensitive token: " + secretToken + " and pass " + secretPass,
				HTTPStatus:  200,
			},
		},
	}

	path := AttackPathSummary{
		ID:    "CHAIN-SECRET-REDACT",
		Title: "Secret Redaction Chain",
		GraphNodes: []AttackPathNode{
			{ID: "FND-SECRET-01", Title: "Secret Leak Finding", Endpoint: findings[0].Endpoint},
		},
	}

	plan, err := GenerateReproductionScript(path, findings, ReproductionOptions{TargetOrigin: "https://target.local"})
	if err != nil {
		t.Fatalf("GenerateReproductionScript failed: %v", err)
	}

	scriptContent := plan.ShellScriptContent

	// Assert zero secret leaks in generated reproduction script
	if strings.Contains(scriptContent, secretToken) {
		t.Errorf("SECURITY LEAK: secret token %q found in generated reproduction script", secretToken)
	}
	if strings.Contains(scriptContent, secretPass) {
		t.Errorf("SECURITY LEAK: secret password %q found in generated reproduction script", secretPass)
	}
	if strings.Contains(scriptContent, secretCookie) {
		t.Errorf("SECURITY LEAK: session cookie %q found in generated reproduction script", secretCookie)
	}
}

// TestReproductionScript_EvidenceAndSemantics verifies:
// 1. HTTP 200 alone never proves a vulnerability without a specific evidence-backed predicate (exits code 3).
// 2. Candidate or inconclusive paths are not presented as verified (exits code 3).
// 3. Dependent steps halt when prerequisite steps fail.
func TestReproductionScript_EvidenceAndSemantics(t *testing.T) {
	bashBin := findGitBash()
	if bashBin == "" {
		t.Skip("bash not found, skipping semantics test")
	}

	// 1. HTTP 200 without evidence predicate
	serverA := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"generic": "response"}`))
	}))
	defer serverA.Close()

	findingNoPredicate := []Finding{
		{
			ID:       "FND-GENERIC-200",
			Title:    "Generic Endpoint Reachable",
			Endpoint: "/api/generic",
			Method:   "GET",
			EvidenceDetails: EvidenceDetails{
				HTTPStatus: 200,
			},
		},
	}
	pathConfirmed := AttackPathSummary{
		ID:     "CHAIN-200-ONLY",
		Title:  "200 Only Chain",
		Status: "CONFIRMED",
		GraphNodes: []AttackPathNode{
			{ID: "FND-GENERIC-200", Title: "Generic Endpoint", Endpoint: "/api/generic"},
		},
	}

	planA, err := GenerateReproductionScript(pathConfirmed, findingNoPredicate, ReproductionOptions{TargetOrigin: serverA.URL})
	if err != nil {
		t.Fatalf("GenerateReproductionScript failed: %v", err)
	}
	scriptA := filepath.Join(t.TempDir(), "run_no_predicate.sh")
	_ = os.WriteFile(scriptA, []byte(planA.ShellScriptContent), 0755)

	cmdA := exec.Command(bashBin, scriptA)
	cmdA.Env = append(os.Environ(), "NON_INTERACTIVE=1", "TARGET_ORIGIN="+serverA.URL)
	outA, errA := cmdA.CombinedOutput()

	// Must exit with code 3 (INCONCLUSIVE), NOT code 0 (VERIFIED)
	if errA == nil {
		t.Fatalf("expected exit code 3 (INCONCLUSIVE) for HTTP 200 without evidence predicate, got exit code 0\nOutput:\n%s", string(outA))
	}
	if !strings.Contains(string(outA), "[INCONCLUSIVE]") {
		t.Errorf("expected [INCONCLUSIVE] in output:\n%s", string(outA))
	}

	// 2. Candidate path is never presented as VERIFIED (must exit code 3)
	serverB := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`ADMIN_INTERNAL_KEY`))
	}))
	defer serverB.Close()

	findingCandidate := []Finding{
		{
			ID:       "FND-CAND-01",
			Title:    "Candidate Token Leak",
			Endpoint: "/api/cand",
			Method:   "GET",
			Evidence: "ADMIN_INTERNAL_KEY",
			EvidenceDetails: EvidenceDetails{
				HTTPStatus: 200,
			},
		},
	}
	pathCandidate := AttackPathSummary{
		ID:     "CHAIN-CANDIDATE-PATH",
		Title:  "Candidate Path",
		Status: "CANDIDATE",
		GraphNodes: []AttackPathNode{
			{ID: "FND-CAND-01", Title: "Candidate Token Leak", Endpoint: "/api/cand"},
		},
	}
	planB, err := GenerateReproductionScript(pathCandidate, findingCandidate, ReproductionOptions{TargetOrigin: serverB.URL})
	if err != nil {
		t.Fatalf("GenerateReproductionScript failed: %v", err)
	}
	scriptB := filepath.Join(t.TempDir(), "run_candidate.sh")
	_ = os.WriteFile(scriptB, []byte(planB.ShellScriptContent), 0755)

	cmdB := exec.Command(bashBin, scriptB)
	cmdB.Env = append(os.Environ(), "NON_INTERACTIVE=1", "TARGET_ORIGIN="+serverB.URL)
	outB, errB := cmdB.CombinedOutput()

	// Candidate path must exit with code 3 (INCONCLUSIVE / CANDIDATE), never code 0
	if errB == nil {
		t.Fatalf("expected candidate path to exit with code 3, got code 0\nOutput:\n%s", string(outB))
	}
	if !strings.Contains(string(outB), "INCONCLUSIVE / CANDIDATE") {
		t.Errorf("expected INCONCLUSIVE / CANDIDATE marker in output:\n%s", string(outB))
	}

	// 3. Dependent steps halt when prerequisite fails
	serverC := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/step1" {
			http.NotFound(w, r)
		} else {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`PostgreSQL`))
		}
	}))
	defer serverC.Close()

	findingsMultiHop := []Finding{
		{
			ID:       "STEP-1",
			Title:    "Step 1 Token Leak",
			Endpoint: "/step1",
			Method:   "GET",
			Evidence: "ADMIN_INTERNAL_KEY",
			EvidenceDetails: EvidenceDetails{
				HTTPStatus: 200,
			},
		},
		{
			ID:       "STEP-2",
			Title:    "Step 2 Route",
			Endpoint: "/step2",
			Method:   "GET",
			Evidence: "PostgreSQL",
			EvidenceDetails: EvidenceDetails{
				HTTPStatus: 200,
			},
		},
	}
	pathMultiHop := AttackPathSummary{
		ID:     "CHAIN-DEPENDENT-PREREQ",
		Title:  "Dependent Prereq Chain",
		Status: "CONFIRMED",
		GraphNodes: []AttackPathNode{
			{ID: "STEP-1", Title: "Step 1 Token Leak", Endpoint: "/step1"},
			{ID: "STEP-2", Title: "Step 2 Route", Endpoint: "/step2"},
		},
	}
	planC, err := GenerateReproductionScript(pathMultiHop, findingsMultiHop, ReproductionOptions{TargetOrigin: serverC.URL})
	if err != nil {
		t.Fatalf("GenerateReproductionScript failed: %v", err)
	}
	scriptC := filepath.Join(t.TempDir(), "run_multihop.sh")
	_ = os.WriteFile(scriptC, []byte(planC.ShellScriptContent), 0755)

	cmdC := exec.Command(bashBin, scriptC)
	cmdC.Env = append(os.Environ(), "NON_INTERACTIVE=1", "TARGET_ORIGIN="+serverC.URL)
	outC, errC := cmdC.CombinedOutput()

	if errC == nil {
		t.Fatalf("expected failed prerequisite to exit with code 2, got code 0\nOutput:\n%s", string(outC))
	}
	outCStr := string(outC)
	if !strings.Contains(outCStr, "[SKIPPED]") {
		t.Errorf("expected dependent step to be [SKIPPED] after failed prerequisite:\n%s", outCStr)
	}
	if !strings.Contains(outCStr, "NOT VERIFIED") {
		t.Errorf("expected NOT VERIFIED final outcome:\n%s", outCStr)
	}
}

// TestReproductionScript_AdversarialCanaryAudit performs negative leak assertions across
// standalone reproduction scripts, standard HTML reports, and commercial HTML reports
// for canaries in observations, URL credentials, sensitive query parameters,
// authorization headers, and values without obvious secret keywords.
func TestReproductionScript_AdversarialCanaryAudit(t *testing.T) {
	canaries := []string{
		"CANARY_TOKEN_VAL_01",
		"CANARY_PASS_VAL_02",
		"CANARY_SECRET_VAL_03",
		"CANARY_KEY_VAL_04",
		"CANARY_AUTH_VAL_05",
	}

	opaqueVal := "OPAQUE_SECRET_VAL_777"
	findingWithCanaries := Finding{
		ID:          "FND-CANARY-AUDIT",
		Title:       "Finding with token=" + canaries[0],
		Description: "Description with password=" + canaries[1],
		Target:      "https://admin:" + canaries[1] + "@target.corp:8443",
		Endpoint:    "https://admin:" + canaries[1] + "@target.corp:8443/v1/api?token=" + canaries[0] + "&secret=" + canaries[2],
		Evidence:    "Authorization: Bearer " + canaries[3] + "\nRaw data: api_key=" + canaries[3],
		EvidenceDetails: EvidenceDetails{
			Observation: "Observation with auth=" + canaries[4] + " and secret=" + canaries[2] + " and " + opaqueVal,
			Location:    "https://admin:" + canaries[1] + "@target.corp:8443/path",
			HTTPStatus:  200,
		},
	}

	path := AttackPathSummary{
		ID:            "PATH-CANARY-01",
		Title:         "Path with api_key=" + canaries[3],
		RiskRationale: "Rationale with auth=" + canaries[4],
		Status:        "VERIFIED",
		GraphNodes: []AttackPathNode{
			{
				ID:       "FND-CANARY-AUDIT",
				Title:    "Finding with token=" + canaries[0],
				Endpoint: findingWithCanaries.Endpoint,
			},
		},
	}

	// 1. Audit Standalone Reproduction Script
	plan, err := GenerateReproductionScript(path, []Finding{findingWithCanaries}, ReproductionOptions{TargetOrigin: "https://target.corp:8443"})
	if err != nil {
		t.Fatalf("GenerateReproductionScript failed: %v", err)
	}

	scriptContent := plan.ShellScriptContent
	for _, c := range canaries {
		if strings.Contains(scriptContent, c) {
			t.Errorf("LEAK in standalone reproduction script: canary %q found:\n%s", c, scriptContent)
		}
	}
	if strings.Contains(scriptContent, opaqueVal) {
		t.Errorf("LEAK in standalone reproduction script: opaque non-keyword observation %q found in script:\n%s", opaqueVal, scriptContent)
	}

	// Verify valid bash syntax of sanitized script if bash is available
	bashBin := findGitBash()
	if bashBin != "" {
		tmpScript := filepath.Join(t.TempDir(), "canary_audit.sh")
		_ = os.WriteFile(tmpScript, []byte(scriptContent), 0755)
		syntaxCheck := exec.Command(bashBin, "-n", tmpScript)
		out, err := syntaxCheck.CombinedOutput()
		if err != nil {
			t.Errorf("Bash syntax error in sanitized script:\n%s\nContent:\n%s", string(out), scriptContent)
		}
	}

	// 2. Audit Standard HTML Report Embedding
	rep := Report{
		Target:      findingWithCanaries.Target,
		Findings:    []Finding{findingWithCanaries},
		AttackPaths: []AttackPathSummary{path},
	}
	htmlStr, err := GenerateHTML(rep)
	if err != nil {
		t.Fatalf("GenerateHTML failed: %v", err)
	}
	for _, c := range canaries {
		if strings.Contains(htmlStr, c) {
			t.Errorf("LEAK in Standard HTML report: canary %q found", c)
		}
	}

	// 3. Audit Commercial HTML Report Embedding
	commRep := BuildCommercialReport(rep)
	commHTML, err := GenerateCommercialHTML(commRep)
	if err != nil {
		t.Fatalf("GenerateCommercialHTML failed: %v", err)
	}
	for _, c := range canaries {
		if strings.Contains(commHTML, c) {
			t.Errorf("LEAK in Commercial HTML report: canary %q found", c)
		}
	}
}
