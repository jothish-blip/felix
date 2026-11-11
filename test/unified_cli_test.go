package test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// CapabilityTestModel matches the JSON output structure of "felix capabilities --json".
type CapabilityTestModel struct {
	Command     string   `json:"command"`
	Engine      string   `json:"engine"`
	Maturity    string   `json:"maturity"`
	LicenseTier string   `json:"license_tier"`
	Description string   `json:"description"`
	Categories  []string `json:"categories"`
}

func TestUnifiedCLI_HelpAndBanner(t *testing.T) {
	for _, flag := range []string{"--help", "-h", "help"} {
		out, code := runFelix(t, flag)
		if code != 0 {
			t.Errorf("flag %q: expected exit code 0, got %d", flag, code)
		}
		expectedCategories := []string{
			"Unified Assessment:",
			"assess",
			"Security Audit Modules:",
			"recon",
			"web",
			"api",
			"auth",
			"bola",
			"bfla",
			"bopla",
			"secrets",
			"cloud",
			"mobile",
			"oast",
			"Assessment Projects & Operations:",
			"assessment",
			"Governance & Reporting:",
			"report",
			"license",
			"Core & System Utilities:",
			"capabilities",
			"doctor",
			"version",
			"Quick Start:",
		}
		for _, cat := range expectedCategories {
			if !strings.Contains(out, cat) {
				t.Errorf("flag %q: expected help text to contain %q", flag, cat)
			}
		}
	}
}

func TestUnifiedCLI_Capabilities(t *testing.T) {
	// 1. Text table output
	out, code := runFelix(t, "capabilities")
	if code != 0 {
		t.Fatalf("expected exit code 0 for capabilities, got %d, out: %s", code, out)
	}
	if !strings.Contains(out, "FELIX 1.0 CAPABILITIES & ENGINE REGISTRY") {
		t.Errorf("expected capabilities header, got: %s", out)
	}
	if !strings.Contains(out, "felix assess") || !strings.Contains(out, "PRODUCTION-GRADE") {
		t.Errorf("expected capability entries in table, got: %s", out)
	}

	// 2. JSON structured output
	jsonOut, code := runFelix(t, "capabilities", "--json")
	if code != 0 {
		t.Fatalf("expected exit code 0 for capabilities --json, got %d", code)
	}
	var caps []CapabilityTestModel
	if err := json.Unmarshal([]byte(jsonOut), &caps); err != nil {
		t.Fatalf("failed to parse capabilities JSON: %v, out: %s", err, jsonOut)
	}
	if len(caps) < 15 {
		t.Errorf("expected at least 15 capabilities, got %d", len(caps))
	}

	commandsFound := make(map[string]bool)
	maturityByCommand := make(map[string]string)
	for _, c := range caps {
		commandsFound[c.Command] = true
		maturityByCommand[c.Command] = c.Maturity
	}
	requiredCommands := []string{
		"assess", "recon", "scan", "web", "api", "auth",
		"authz", "bola", "bfla", "bopla", "graphql", "secrets", "cloud", "mobile", "cve", "oast",
	}
	for _, rc := range requiredCommands {
		if !commandsFound[rc] {
			t.Errorf("expected capability command %q in registry, was missing", rc)
		}
	}
	if maturityByCommand["bopla"] != "LAB-TESTED" {
		t.Errorf("expected bopla maturity LAB-TESTED, got %s", maturityByCommand["bopla"])
	}
	if maturityByCommand["cloud"] != "MOCK-VALIDATED" {
		t.Errorf("expected cloud maturity MOCK-VALIDATED, got %s", maturityByCommand["cloud"])
	}
	if maturityByCommand["graphql"] != "LAB-TESTED" {
		t.Errorf("expected graphql maturity LAB-TESTED, got %s", maturityByCommand["graphql"])
	}

	// 3. Tier filter
	commOut, code := runFelix(t, "capabilities", "--tier", "COMMUNITY", "--json")
	if code != 0 {
		t.Fatalf("expected exit code 0 for capabilities --tier COMMUNITY, got %d", code)
	}
	var commCaps []CapabilityTestModel
	if err := json.Unmarshal([]byte(commOut), &commCaps); err != nil {
		t.Fatalf("failed to parse filtered JSON: %v", err)
	}
	for _, c := range commCaps {
		if c.LicenseTier != "COMMUNITY" {
			t.Errorf("expected only COMMUNITY tier, found %s for %s", c.LicenseTier, c.Command)
		}
	}
}

func TestUnifiedCLI_Assess_Validation(t *testing.T) {
	// 1. Missing target
	out, code := runFelix(t, "assess")
	if code != 2 {
		t.Errorf("expected exit code 2 when target is missing, got %d, out: %s", code, out)
	}
	if !strings.Contains(out, "--target is required") {
		t.Errorf("expected missing target error message, got: %s", out)
	}

	// 2. Missing profile
	out, code = runFelix(t, "assess", "--target", "https://example.com")
	if code != 2 {
		t.Errorf("expected exit code 2 when profile is missing, got %d, out: %s", code, out)
	}
	if !strings.Contains(out, "--profile is required") {
		t.Errorf("expected missing profile error message, got: %s", out)
	}

	// 3. Missing output
	out, code = runFelix(t, "assess", "--target", "https://example.com", "--profile", "standard")
	if code != 2 {
		t.Errorf("expected exit code 2 when output dir is missing, got %d, out: %s", code, out)
	}
	if !strings.Contains(out, "--output directory is required") {
		t.Errorf("expected missing output error message, got: %s", out)
	}

	// 4. Invalid profile
	out, code = runFelix(t, "assess", "--target", "https://example.com", "--profile", "invalid_profile", "--output", "./test_out")
	if code != 2 {
		t.Errorf("expected exit code 2 for invalid profile, got %d, out: %s", code, out)
	}
	if !strings.Contains(out, "invalid --profile") {
		t.Errorf("expected invalid profile error message, got: %s", out)
	}

	// 5. Custom profile without modules
	out, code = runFelix(t, "assess", "--target", "https://example.com", "--profile", "custom", "--output", "./test_out")
	if code != 2 {
		t.Errorf("expected exit code 2 when custom profile has no modules, got %d, out: %s", code, out)
	}
	if !strings.Contains(out, "--modules is required") {
		t.Errorf("expected missing modules error message, got: %s", out)
	}
}

func TestUnifiedCLI_Assess_DryRun_Profiles(t *testing.T) {
	profiles := []struct {
		name            string
		expectedModules []string
	}{
		{
			name:            "quick",
			expectedModules: []string{"recon", "headers", "secrets", "cookies"},
		},
		{
			name:            "standard",
			expectedModules: []string{"recon", "web", "api", "auth", "headers", "secrets", "cookies", "cors"},
		},
		{
			name:            "api",
			expectedModules: []string{"recon", "api", "auth", "authz", "bola", "bfla", "headers", "cors"},
		},
		{
			name:            "full",
			expectedModules: []string{"recon", "web", "api", "auth", "authz", "bola", "bfla", "secrets", "headers", "cookies", "cors"},
		},
	}

	for _, p := range profiles {
		t.Run("Profile_"+p.name, func(t *testing.T) {
			out, code := runFelix(t, "assess",
				"--target", "https://example.com",
				"--profile", p.name,
				"--output", "./audit_dryrun",
				"--dry-run",
			)
			if code != 0 {
				t.Fatalf("expected exit code 0 for dry-run, got %d, out: %s", code, out)
			}
			if !strings.Contains(out, "FELIX 1.0 UNIFIED ASSESSMENT PLAN (DRY-RUN)") {
				t.Errorf("expected dry-run banner, got: %s", out)
			}
			for _, m := range p.expectedModules {
				if !strings.Contains(out, "["+m+"]") {
					t.Errorf("profile %s: expected module [%s] in planned execution, got: %s", p.name, m, out)
				}
			}
		})
	}

	// Custom profile with explicit modules
	t.Run("Profile_custom", func(t *testing.T) {
		out, code := runFelix(t, "assess",
			"--target", "https://example.com",
			"--profile", "custom",
			"--modules", "recon,secrets,headers",
			"--output", "./audit_dryrun",
			"--dry-run",
		)
		if code != 0 {
			t.Fatalf("expected exit code 0 for custom dry-run, got %d, out: %s", code, out)
		}
		if !strings.Contains(out, "[recon]") || !strings.Contains(out, "[secrets]") || !strings.Contains(out, "[headers]") {
			t.Errorf("expected custom modules in dry-run plan, got: %s", out)
		}
	})
}

func TestUnifiedCLI_Assess_ScopeProtection(t *testing.T) {
	// Without allow-loopback, loopback destination must fail closed with exit code 2
	envWithoutLoopback := []string{
		"PATH=" + os.Getenv("PATH"),
		"SYSTEMROOT=" + os.Getenv("SYSTEMROOT"),
	}
	out, code := runFelixWithOverrideEnv(t, envWithoutLoopback, "assess",
		"--target", "http://127.0.0.1:8080",
		"--profile", "quick",
		"--output", "./audit_out",
		"--dry-run",
	)
	if code != 2 {
		t.Errorf("expected exit code 2 (blocked by loopback protection), got %d, out: %s", code, out)
	}
	if !strings.Contains(out, "loopback address") {
		t.Errorf("expected loopback error message, got: %s", out)
	}

	// With explicit --allow-loopback, execution must proceed
	out, code = runFelixWithOverrideEnv(t, envWithoutLoopback, "assess",
		"--target", "http://127.0.0.1:8080",
		"--profile", "quick",
		"--output", "./audit_out",
		"--allow-loopback",
		"--dry-run",
	)
	if code != 0 {
		t.Errorf("expected exit code 0 when --allow-loopback is passed, got %d, out: %s", code, out)
	}
}

func TestUnifiedCLI_Assess_LiveExecution(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Set-Cookie", "session=abc123xyz; Path=/")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`<!DOCTYPE html><html><head><title>Test App</title></head><body><h1>Welcome</h1><a href="/about">About</a></body></html>`))
	}))
	defer ts.Close()

	tmpOut := t.TempDir()

	out, code := runFelix(t, "assess",
		"--target", ts.URL,
		"--profile", "quick",
		"--output", tmpOut,
		"--auth-confirm",
		"--allow-loopback",
	)
	if code != 0 && code != 1 {
		t.Fatalf("expected assessment exit code 0 or 1, got %d, out: %s", code, out)
	}

	// Verify terminal summary
	if !strings.Contains(out, "ASSESSMENT EXECUTION SUMMARY") {
		t.Errorf("expected terminal summary header, got: %s", out)
	}

	// Verify deliverables generated
	htmlFile := filepath.Join(tmpOut, "assessment_report.html")
	jsonFile := filepath.Join(tmpOut, "assessment_report.json")
	sarifFile := filepath.Join(tmpOut, "assessment_report.sarif")

	for _, f := range []string{htmlFile, jsonFile, sarifFile} {
		if fi, err := os.Stat(f); err != nil || fi.Size() == 0 {
			t.Errorf("expected deliverable %s to exist and be non-empty, err: %v", f, err)
		}
	}
}

func TestUnifiedCLI_Assess_SecurityRefusal_MissingAuthConfirm(t *testing.T) {
	out, code := runFelix(t, "assess",
		"--target", "https://example.com",
		"--profile", "quick",
		"--output", "./audit_out",
	)
	if code != 2 {
		t.Errorf("expected exit code 2 when --auth-confirm is missing, got %d, out: %s", code, out)
	}
	if !strings.Contains(out, "Security refusal") || !strings.Contains(out, "--auth-confirm") {
		t.Errorf("expected authorization refusal message, got: %s", out)
	}
}

func TestUnifiedCLI_DirectTarget_SecurityRefusal_MissingAuthConfirm(t *testing.T) {
	out, code := runFelix(t, "web", "https://example.com")
	if code != 2 {
		t.Errorf("expected exit code 2 when direct target lacks auth confirmation, got %d, out: %s", code, out)
	}
	if !strings.Contains(out, "Security refusal") || !strings.Contains(out, "--auth-confirm") {
		t.Errorf("expected authorization refusal message on direct command, got: %s", out)
	}
}

func TestUnifiedCLI_Secrets(t *testing.T) {
	// 1. Help
	out, code := runFelix(t, "secrets", "--help")
	if code != 0 || !strings.Contains(out, "felix secrets") {
		t.Errorf("expected help output for secrets, got code: %d, out: %s", code, out)
	}

	// 2. Missing target
	_, code = runFelix(t, "secrets")
	if code != 2 {
		t.Errorf("expected exit code 2 when secrets target is missing, got %d", code)
	}

	// 3. String with real token
	rawPayload := "aws_secret = AKIAIOSFODNN7EXAMPLE"
	out, code = runFelix(t, "secrets", "--string", rawPayload)
	if code != 1 {
		t.Errorf("expected exit code 1 when secrets are detected, got %d, out: %s", code, out)
	}
	if !strings.Contains(out, "AWS Access Key ID") {
		t.Errorf("expected AWS Access Key finding, got: %s", out)
	}
	if !strings.Contains(out, "AKIA********************MPLE") {
		t.Errorf("expected redacted secret value in output, got: %s", out)
	}

	// 4. String without secrets
	cleanPayload := "function hello() { return 'hello world'; }"
	out, code = runFelix(t, "secrets", "--string", cleanPayload)
	if code != 0 {
		t.Errorf("expected exit code 0 when no secrets are detected, got %d, out: %s", code, out)
	}
	if !strings.Contains(out, "No secrets, API keys, or private tokens detected") {
		t.Errorf("expected clean message, got: %s", out)
	}
}

func TestUnifiedCLI_Recon(t *testing.T) {
	// 1. Help
	out, code := runFelix(t, "recon", "--help")
	if code != 0 || !strings.Contains(out, "felix recon") {
		t.Errorf("expected help output for recon, got code: %d, out: %s", code, out)
	}

	// 2. Missing target
	_, code = runFelix(t, "recon")
	if code != 2 {
		t.Errorf("expected exit code 2 when recon target is missing, got %d", code)
	}

	// 3. Target execution against test server
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "nginx/1.24.0")
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`<html><body><form action="/login" method="POST"><input name="username"/><input name="password"/></form></body></html>`))
	}))
	defer ts.Close()

	out, code = runFelix(t, "recon", "--target", ts.URL, "--allow-loopback", "--verbose")
	if code != 0 {
		t.Fatalf("expected exit code 0 for recon, got %d, out: %s", code, out)
	}
	if !strings.Contains(out, "ATTACK-SURFACE RECONNAISSANCE") {
		t.Errorf("expected recon header, got: %s", out)
	}
}

func TestUnifiedCLI_OAST(t *testing.T) {
	// 1. Help
	out, code := runFelix(t, "oast", "--help")
	if code != 0 || !strings.Contains(out, "felix oast") {
		t.Errorf("expected help output for oast, got code: %d, out: %s", code, out)
	}

	// 2. Token generation
	out, code = runFelix(t, "oast", "token")
	if code != 0 {
		t.Fatalf("expected exit code 0 for oast token, got %d, out: %s", code, out)
	}
	if !strings.Contains(out, "OAST INTERACTION TOKEN") || !strings.Contains(out, ".oast.felix.internal") {
		t.Errorf("expected generated token output, got: %s", out)
	}

	// 3. Token generation JSON
	jsonOut, code := runFelix(t, "oast", "token", "--json")
	if code != 0 {
		t.Fatalf("expected exit code 0 for oast token --json, got %d", code)
	}
	var res map[string]string
	if err := json.Unmarshal([]byte(jsonOut), &res); err != nil {
		t.Fatalf("failed to parse oast token JSON: %v", err)
	}
	if len(res["token"]) != 32 {
		t.Errorf("expected 32-character hex token, got %q", res["token"])
	}

	// 4. Verify subcommand
	out, code = runFelix(t, "oast", "verify", "--token", res["token"])
	if code != 0 {
		t.Fatalf("expected exit code 0 for oast verify, got %d, out: %s", code, out)
	}
	if !strings.Contains(out, "AWAITING_CALLBACK") {
		t.Errorf("expected status in verify output, got: %s", out)
	}
}

func TestUnifiedCLI_DirectCapabilityHelpRouting(t *testing.T) {
	directCommands := []string{
		"web", "api", "auth", "authz", "bola", "bfla", "bopla", "cloud", "mobile",
	}

	for _, cmd := range directCommands {
		t.Run("Help_"+cmd, func(t *testing.T) {
			out, code := runFelix(t, cmd, "--help")
			if code != 0 {
				t.Errorf("felix %s --help: expected exit code 0, got %d, out: %s", cmd, code, out)
			}
			if len(out) == 0 {
				t.Errorf("felix %s --help: expected non-empty output", cmd)
			}
		})
	}
}

func TestUnifiedCLI_BackwardsCompatibility(t *testing.T) {
	commands := []struct {
		cmd          string
		expectedFrag string
	}{
		{"scan", "scan"},
		{"apk", "apk"},
		{"assessment", "assessment"},
		{"client", "client"},
		{"doctor", "environment"},
		{"version", "FELIX"},
	}

	for _, c := range commands {
		t.Run("Compat_"+c.cmd, func(t *testing.T) {
			var out string
			var code int
			if c.cmd == "version" || c.cmd == "doctor" {
				out, code = runFelix(t, c.cmd)
			} else {
				out, code = runFelix(t, c.cmd, "--help")
			}
			if code != 0 {
				t.Errorf("felix %s: expected exit code 0, got %d, out: %s", c.cmd, code, out)
			}
			if !strings.Contains(strings.ToLower(out), strings.ToLower(c.expectedFrag)) {
				t.Errorf("felix %s: expected output to contain %q, got: %s", c.cmd, c.expectedFrag, out)
			}
		})
	}
}

func TestUnifiedCLI_Assess_LiveInvestigationAndAttackChains(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		body := `<!DOCTYPE html><html><body><h1>API Console</h1>
		<script>const apiKey = "AKIAIOSFODNN7EXAMPLE";</script>
		</body></html>`
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(body))
	}))
	defer ts.Close()

	tmpOut := t.TempDir()

	out, code := runFelix(t, "assess",
		"--target", ts.URL,
		"--profile", "quick",
		"--output", tmpOut,
		"--auth-confirm",
		"--allow-loopback",
	)
	if code != 0 && code != 1 {
		t.Fatalf("expected assessment exit code 0 or 1, got %d, out: %s", code, out)
	}

	// Verify live investigation card was rendered
	if !strings.Contains(out, "LIVE FINDING INVESTIGATED:") {
		t.Errorf("expected live finding investigated banner in output, got: %s", out)
	}

	// Verify prioritized remediation roadmap
	if !strings.Contains(out, "CONTINUOUS REMEDIATION ROADMAP") {
		t.Errorf("expected continuous remediation roadmap in output, got: %s", out)
	}

	// Verify investigated findings deliverable exists
	invFile := filepath.Join(tmpOut, "investigated_findings.json")
	if fi, err := os.Stat(invFile); err != nil || fi.Size() == 0 {
		t.Errorf("expected %s to exist and be non-empty, err: %v", invFile, err)
	}
}

func TestUnifiedCLI_Assess_RetestWorkflow(t *testing.T) {
	repJSON := `{
  "target": "http://127.0.0.1:18999",
  "version": "1.0.0",
  "findings": [
    {
      "id": "FIND-TEST-SQLI-01",
      "title": "SQL Injection in User Search",
      "severity": "CRITICAL",
      "category": "SQL Injection",
      "method": "GET",
      "endpoint": "/search?q=test",
      "target": "http://127.0.0.1:18999/search?q=test",
      "verification": {
        "status": "CONFIRMED",
        "result": "Database error provoked",
        "attempted": true
      },
      "provenance": {
        "content_digest": "sha256:origsqlhash1234567890"
      }
    }
  ]
}`
	tmpDir := t.TempDir()
	baselineReportPath := filepath.Join(tmpDir, "baseline_report.json")
	if err := os.WriteFile(baselineReportPath, []byte(repJSON), 0644); err != nil {
		t.Fatalf("failed to write baseline report: %v", err)
	}

	// Start mock server where the vulnerability is now fixed (returns clean 200 OK without SQL error)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("Search completed safely. 0 results found."))
	}))
	defer ts.Close()

	retestOut := filepath.Join(tmpDir, "retest_out")

	// Run felix assess --retest pointing to ts.URL
	out, code := runFelix(t, "assess",
		"--retest", baselineReportPath,
		"--target", ts.URL,
		"--output", retestOut,
		"--auth-confirm",
		"--allow-loopback",
	)

	// Since vulnerability is fixed, exit code should be 0
	if code != 0 {
		t.Fatalf("expected exit code 0 for fixed retest, got %d, out: %s", code, out)
	}

	if !strings.Contains(out, "FIX DETECTED") {
		t.Errorf("expected [FIX DETECTED] in output, got: %s", out)
	}

	if !strings.Contains(out, "RETEST EXECUTION SUMMARY") {
		t.Errorf("expected RETEST EXECUTION SUMMARY in output, got: %s", out)
	}

	// Check retest_report.json
	retestFile := filepath.Join(retestOut, "retest_report.json")
	if fi, err := os.Stat(retestFile); err != nil || fi.Size() == 0 {
		t.Errorf("expected %s to exist and be non-empty, err: %v", retestFile, err)
	}
}

