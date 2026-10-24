package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"felix/pkg/clierror"
	"felix/pkg/report"
)

func captureScanOutput(f func() int) (int, string, string) {
	oldStdout := os.Stdout
	oldStderr := os.Stderr

	rOut, wOut, errOut := os.Pipe()
	rErr, wErr, errErr := os.Pipe()
	if errOut != nil || errErr != nil {
		return f(), "", ""
	}

	os.Stdout = wOut
	os.Stderr = wErr

	outChan := make(chan string)
	errChan := make(chan string)

	go func() {
		var buf bytes.Buffer
		_, _ = io.Copy(&buf, rOut)
		outChan <- buf.String()
	}()
	go func() {
		var buf bytes.Buffer
		_, _ = io.Copy(&buf, rErr)
		errChan <- buf.String()
	}()

	code := f()

	_ = wOut.Close()
	_ = wErr.Close()
	os.Stdout = oldStdout
	os.Stderr = oldStderr

	stdoutStr := <-outChan
	stderrStr := <-errChan

	_ = rOut.Close()
	_ = rErr.Close()

	return code, stdoutStr, stderrStr
}

// TestCLI_Representative_EndToEndScan verifies the integrated CLI execution across
// Cloud, Database, and API assessment capabilities within a single automated assessment run.
func TestCLI_Representative_EndToEndScan(t *testing.T) {
	tmpDir := t.TempDir()
	reportHTML := filepath.Join(tmpDir, "representative_audit.html")
	reportJSON := filepath.Join(tmpDir, "representative_audit.json")
	reportSARIF := filepath.Join(tmpDir, "representative_audit.sarif")

	const canarySecret = "AKIAIOSFODNN7CANARYSECRET"

	// Mock Target Server serving HTML, JS bundle referencing cloud/db, and API endpoints
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			w.Header().Set("Content-Type", "text/html")
			w.WriteHeader(http.StatusOK)
			fmt.Fprintln(w, `<!DOCTYPE html>
<html>
<head><title>Enterprise Web Portal</title></head>
<body>
    <script src="/static/bundle.js"></script>
    <a href="/api/v1/users">Users API</a>
</body>
</html>`)

		case "/static/bundle.js":
			w.Header().Set("Content-Type", "application/javascript")
			w.WriteHeader(http.StatusOK)
			// Contains references to S3 bucket, PostgreSQL connection indicator, documented API, and shadow API
			fmt.Fprintf(w, `
				const S3_BUCKET = "https://assets-corporate-vault.s3.amazonaws.com";
				const PG_CONN = "postgres://dbadmin:%s@db.internal:5432/orders";
				function getUsers() { return fetch("/api/v1/users"); }
				function getSecretKeys() { return fetch("/api/v1/shadow/internal_keys"); }
			`, canarySecret)

		case "/api/v1/users":
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			fmt.Fprintln(w, `{"users": [{"id": 1, "name": "Alice"}]}`)

		case "/api/v1/shadow/internal_keys":
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			fmt.Fprintln(w, `{"error": "Forbidden"}`)

		case "/api/v1/tenant/resource":
			w.Header().Set("Content-Type", "application/json")
			authHdr := r.Header.Get("Authorization")
			if strings.Contains(authHdr, "token-tenant-a") {
				w.WriteHeader(http.StatusOK)
				fmt.Fprintln(w, `{"id": "res-tenant-b-1", "owner": "tenant-b", "data": "CONFIDENTIAL_TENANT_B_RECORD"}`)
				return
			}
			w.WriteHeader(http.StatusForbidden)
			fmt.Fprintln(w, `{"error": "Access denied"}`)

		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer ts.Close()

	// 1. Create OpenAPI specification file
	specPath := filepath.Join(tmpDir, "openapi.json")
	openAPISpec := fmt.Sprintf(`{
		"openapi": "3.0.0",
		"info": {"title": "Representative Enterprise API", "version": "1.0.0"},
		"servers": [{"url": "%s"}],
		"paths": {
			"/api/v1/users": {
				"get": {
					"summary": "Retrieve user records",
					"responses": {"200": {"description": "OK"}}
				}
			}
		}
	}`, ts.URL)
	if err := os.WriteFile(specPath, []byte(openAPISpec), 0644); err != nil {
		t.Fatalf("failed writing openapi.json: %v", err)
	}

	// 2. Create Declarative Multi-Tenant Profile (felix.target.yml)
	profilePath := filepath.Join(tmpDir, "felix.target.yml")
	os.Setenv("FELIX_ALLOW_LOOPBACK", "true")
	os.Setenv("FELIX_TEST_TOKEN_A", "token-tenant-a-xyz")
	os.Setenv("FELIX_TEST_TOKEN_B", "token-tenant-b-xyz")
	defer func() {
		os.Unsetenv("FELIX_ALLOW_LOOPBACK")
		os.Unsetenv("FELIX_TEST_TOKEN_A")
		os.Unsetenv("FELIX_TEST_TOKEN_B")
	}()

	profileContent := fmt.Sprintf(`version: 1
target:
  name: "Representative Integration Target"
  base_urls:
    - "%s"
  allowed_hosts:
    - "127.0.0.1"
    - "localhost"
safety:
  mode: "non_destructive"
  require_explicit_authorization: true
  allow_cross_tenant_checks: true
tenants:
  - id: "tenant-a"
    identity: "tenant-a@example.com"
    credential_env: "FELIX_TEST_TOKEN_A"
    resource_ids:
      - "res-tenant-a-1"
  - id: "tenant-b"
    identity: "tenant-b@example.com"
    credential_env: "FELIX_TEST_TOKEN_B"
    resource_ids:
      - "res-tenant-b-1"
cross_tenant_tests:
  enabled: true
  comparisons:
    - requester_tenant: "tenant-a"
      resource_owner_tenant: "tenant-b"
      resource_id: "res-tenant-b-1"
      path: "/api/v1/tenant/resource?id=res-tenant-b-1"
      method: "GET"
      expected_marker: "CONFIDENTIAL_TENANT_B_RECORD"
`, ts.URL)
	if err := os.WriteFile(profilePath, []byte(profileContent), 0644); err != nil {
		t.Fatalf("failed writing profile: %v", err)
	}

	// 3. Execute End-to-End CLI Scan:
	// felix scan <target> --spec <spec> --probe --profile <profile> --cross-tenant --export <report.html> --json <report.json> --sarif <report.sarif>
	cliArgs := []string{
		ts.URL,
		"--spec", specPath,
		"--probe",
		"--profile", profilePath,
		"--cross-tenant",
		"--export", reportHTML,
		"--json", reportJSON,
		"--sarif", reportSARIF,
		"--timeout", "10s",
	}

	code, output := captureAPKOutput(func() int {
		return runScan(cliArgs)
	})

	// Exit code 1 indicates security findings discovered (ExitSecurityFail), which is standard
	if code != 1 {
		t.Fatalf("expected exit code 1 (findings discovered), got %d. Output:\n%s", code, output)
	}

	// Verify Cloud, Database, and API assessment sections in output
	if !strings.Contains(output, "CLOUD, DATABASE & STORAGE AUDITING") {
		t.Errorf("expected cloud/database audit section in output")
	}
	if !strings.Contains(output, "Multi-Tenant Isolation & Cross-Tenant Authorization Checks") {
		t.Errorf("expected multi-tenant / BOLA section in output")
	}
	if !strings.Contains(output, "BOLA OBSERVED") {
		t.Errorf("expected BOLA OBSERVED in output")
	}

	// Verify all 3 report formats were generated
	for _, p := range []string{reportHTML, reportJSON, reportSARIF} {
		info, err := os.Stat(p)
		if err != nil {
			t.Fatalf("expected report %s to exist: %v", p, err)
		}
		if info.Size() == 0 {
			t.Fatalf("report file %s is empty", p)
		}

		data, _ := os.ReadFile(p)
		content := string(data)

		// Verify secret redaction across all report formats
		if strings.Contains(content, canarySecret) {
			t.Errorf("canary secret %s leaked into report %s", canarySecret, p)
		}
	}
}

// TestCLI_Representative_BenignTargetCleanSuccess verifies that a benign web target
// completes cleanly with ExitSuccess (exit code 0) and risk level INFORMATIONAL.
func TestCLI_Representative_BenignTargetCleanSuccess(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
		w.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'")
		w.WriteHeader(http.StatusOK)
		fmt.Fprintln(w, `<!DOCTYPE html><html><head><title>Benign App</title></head><body><h1>Welcome</h1></body></html>`)
	}))
	defer ts.Close()

	os.Setenv("FELIX_ALLOW_LOOPBACK", "true")
	defer os.Unsetenv("FELIX_ALLOW_LOOPBACK")

	tmpDir := t.TempDir()
	jsonOut := filepath.Join(tmpDir, "benign_result.json")

	code, stdout, stderr := captureScanOutput(func() int {
		return runScan([]string{ts.URL, "--json", jsonOut, "--timeout", "5s"})
	})

	if code != clierror.ExitSuccess {
		t.Fatalf("expected ExitSuccess (0) for benign scan, got %d.\nStdout:\n%s\nStderr:\n%s", code, stdout, stderr)
	}

	data, err := os.ReadFile(jsonOut)
	if err != nil {
		t.Fatalf("failed reading json output: %v", err)
	}
	var rep report.Report
	if err := json.Unmarshal(data, &rep); err != nil {
		t.Fatalf("failed parsing report json: %v", err)
	}
	if rep.RiskScore != 0 || rep.RiskLevel != "INFORMATIONAL" {
		t.Errorf("expected clean risk score 0 and level INFORMATIONAL, got %d (%s)", rep.RiskScore, rep.RiskLevel)
	}
}

// TestCLI_Representative_OperationalErrorsAndSSRF verifies that missing arguments,
// invalid targets, and SSRF attempts fail closed with ExitOperational (exit code 2).
func TestCLI_Representative_OperationalErrorsAndSSRF(t *testing.T) {
	// 1. Missing target argument
	codeMissing, _, _ := captureScanOutput(func() int {
		return runScan([]string{})
	})
	if codeMissing != clierror.ExitOperational {
		t.Errorf("expected ExitOperational (2) for missing target, got %d", codeMissing)
	}

	// 2. SSRF refusal against cloud metadata IP
	codeSSRF, _, errSSRF := captureScanOutput(func() int {
		return runScan([]string{"http://169.254.169.254/latest/meta-data"})
	})
	if codeSSRF != clierror.ExitOperational {
		t.Errorf("expected ExitOperational (2) for SSRF to cloud metadata, got %d", codeSSRF)
	}
	if !strings.Contains(errSSRF, "SSRF") && !strings.Contains(errSSRF, "prohibited") && !strings.Contains(errSSRF, "blocked") {
		t.Errorf("expected SSRF refusal message in stderr, got:\n%s", errSSRF)
	}
}

// TestCLI_Representative_BlockedScanHonesty verifies that an unreachable target
// produces exit code 2 and does NOT claim a clean score or valid risk score.
func TestCLI_Representative_BlockedScanHonesty(t *testing.T) {
	os.Setenv("FELIX_ALLOW_LOOPBACK", "true")
	defer os.Unsetenv("FELIX_ALLOW_LOOPBACK")

	tmpDir := t.TempDir()
	jsonOut := filepath.Join(tmpDir, "blocked_result.json")

	// Target port 19999 is closed/unreachable
	code, _, _ := captureScanOutput(func() int {
		return runScan([]string{"http://127.0.0.1:19999", "--json", jsonOut, "--timeout", "1s"})
	})

	if code != clierror.ExitOperational {
		t.Fatalf("expected ExitOperational (2) for unreachable target, got %d", code)
	}

	// Verify report honesty if output was generated
	if data, err := os.ReadFile(jsonOut); err == nil {
		var rep report.Report
		if err := json.Unmarshal(data, &rep); err == nil {
			if rep.RiskScoreAvailable {
				t.Errorf("failed scan must not claim available risk score")
			}
			if rep.RiskLevel != "UNAVAILABLE" {
				t.Errorf("failed scan risk level must be UNAVAILABLE, got: %s", rep.RiskLevel)
			}
		}
	}
}
