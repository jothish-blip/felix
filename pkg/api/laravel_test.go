package api

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// --- LARAVEL IGNITION REGRESSION TESTS ---

// Test 1: Genuine Laravel Ignition debug page (APP_DEBUG=true confirmed)
func TestLaravel_IgnitionDebugPageConfirmed(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintf(w, `<!DOCTYPE html>
<html lang="en">
<head><title>Database connection refused - Ignition</title></head>
<body>
<div id="ignition">
  <div class="ignition">
    <div class="header">Laravel v10.15.0 (PHP v8.2.4)</div>
    <div class="stack-trace">
      <div class="frame">File "/var/www/laravel_app/app/Http/Controllers/OrderController.php" line 42</div>
      <div class="frame">File "/var/www/laravel_app/vendor/laravel/framework/src/Illuminate/Routing/Controller.php" line 54</div>
    </div>
  </div>
</div>
<script>
window.data = {"report":{"message":"Database connection refused","laravel_version":"10.15.0","php_version":"8.2.4"}};
</script>
</body></html>`)
	}))
	defer server.Close()

	client := NewClient(ClientOptions{HTTPClient: server.Client(), AllowLoopback: true})
	findings := AuditLaravelDiagnostics(context.Background(), client, server.URL, nil)

	if len(findings) == 0 {
		t.Fatalf("expected Laravel Ignition debug finding, got 0")
	}

	found := false
	for _, f := range findings {
		if f.Category == CategoryLaravelIgnitionDebug {
			found = true
			if f.Severity != SeverityHigh {
				t.Errorf("expected SeverityHigh, got %s", f.Severity)
			}
			if f.Confidence != ConfidenceHigh {
				t.Errorf("expected ConfidenceHigh, got %s", f.Confidence)
			}
			if f.Description != "Laravel Ignition developer diagnostic page exposed" {
				t.Errorf("expected description 'Laravel Ignition developer diagnostic page exposed', got %q", f.Description)
			}
			if f.Details["debug_mode"] != "diagnostic_page_confirmed" {
				t.Errorf("expected debug_mode diagnostic_page_confirmed, got %s", f.Details["debug_mode"])
			}
			if f.Details["app_debug_setting"] != "unconfirmed" {
				t.Errorf("expected app_debug_setting unconfirmed, got %s", f.Details["app_debug_setting"])
			}
			if f.Details["laravel_version"] != "10.15.0" {
				t.Errorf("expected Laravel version 10.15.0, got %s", f.Details["laravel_version"])
			}
			if f.Details["php_version"] != "8.2.4" {
				t.Errorf("expected PHP version 8.2.4, got %s", f.Details["php_version"])
			}
			if !strings.Contains(f.Evidence, "/var/www/laravel_app/app/Http/Controllers/OrderController.php") {
				t.Errorf("expected evidence to mention exposed path, got %s", f.Evidence)
			}
			break
		}
	}
	if !found {
		t.Errorf("expected CategoryLaravelIgnitionDebug finding")
	}
}

// Test 2: Ignition debug page exposing unmasked application secrets -> SeverityCritical with zero leak
func TestLaravel_IgnitionDebugPageWithUnmaskedSecret(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintf(w, `<!DOCTYPE html>
<html><head><title>Ignition</title></head>
<body>
<div id="ignition"></div>
<script>
window.data = {
  "report": {
    "message": "Key error",
    "context": {
      "env": {
        "APP_KEY": "%s",
        "DB_PASSWORD": "%s"
      }
    }
  }
};
</script></body></html>`, syntheticCanarySecret, syntheticCanarySecret)
	}))
	defer server.Close()

	client := NewClient(ClientOptions{HTTPClient: server.Client(), AllowLoopback: true})
	findings := AuditLaravelDiagnostics(context.Background(), client, server.URL, nil)

	if len(findings) == 0 {
		t.Fatalf("expected Ignition finding with unmasked secret")
	}

	f := findings[0]
	if f.Severity != SeverityCritical {
		t.Errorf("expected SeverityCritical for unmasked secrets in Ignition, got %s", f.Severity)
	}

	// Verify synthetic secret is NEVER present in plaintext anywhere in the finding
	if strings.Contains(f.Evidence, syntheticCanarySecret) {
		t.Errorf("SECURITY LEAK: raw synthetic canary secret appeared in evidence: %s", f.Evidence)
	}
	if strings.Contains(fmt.Sprintf("%v", f.Details), syntheticCanarySecret) {
		t.Errorf("SECURITY LEAK: raw synthetic canary secret appeared in details: %v", f.Details)
	}
}

// Test 3: Generic Whoops / Laravel traceback without official Ignition template -> Suspected debug mode
func TestLaravel_IgnitionSuspectedDebugMode(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head><title>Whoops! There was an error.</title></head>
<body>
<h1>Whoops! There was an error.</h1>
<div class="trace">
  <div class="frame">File "/var/www/html/app/Services/PaymentService.php" line 88</div>
  <div class="frame">File "/var/www/html/vendor/laravel/framework/src/Illuminate/Container/Container.php" line 120</div>
</div>
</body>
</html>`)
	}))
	defer server.Close()

	client := NewClient(ClientOptions{HTTPClient: server.Client(), AllowLoopback: true})
	findings := AuditLaravelDiagnostics(context.Background(), client, server.URL, nil)

	if len(findings) == 0 {
		t.Fatalf("expected suspected debug mode finding, got 0")
	}

	f := findings[0]
	if f.Confidence != ConfidenceMedium {
		t.Errorf("expected ConfidenceMedium for suspected debug mode, got %s", f.Confidence)
	}
	if f.Details["debug_mode"] != "suspected" {
		t.Errorf("expected debug_mode suspected, got %s", f.Details["debug_mode"])
	}
	if f.Severity != SeverityMedium {
		t.Errorf("expected SeverityMedium for suspected traceback with paths, got %s", f.Severity)
	}
	if !strings.Contains(f.NegativeEvidence, "unconfirmed") {
		t.Errorf("expected negative evidence explaining unconfirmed debug status, got %s", f.NegativeEvidence)
	}
}

// Test 4: Generic 500 error page without Laravel/Ignition markers must produce 0 findings
func TestLaravel_IgnitionGeneric500Suppressed(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintf(w, `<!DOCTYPE html><html><body><h1>Internal Server Error</h1><p>Something went wrong.</p></body></html>`)
	}))
	defer server.Close()

	client := NewClient(ClientOptions{HTTPClient: server.Client(), AllowLoopback: true})
	findings := AuditLaravelDiagnostics(context.Background(), client, server.URL, nil)

	if len(findings) > 0 {
		t.Errorf("expected 0 findings for generic 500 page, got %d", len(findings))
	}
}

// Test 5: Ignition health check endpoint (/ _ignition/health-check)
func TestLaravel_IgnitionHealthCheck(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/_ignition/health-check" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			fmt.Fprintf(w, `{"can_execute_commands": false}`)
			return
		}
		http.NotFound(w, r)
	}))
	defer server.Close()

	client := NewClient(ClientOptions{HTTPClient: server.Client(), AllowLoopback: true})
	findings := AuditLaravelDiagnostics(context.Background(), client, server.URL, nil)

	if len(findings) == 0 {
		t.Fatalf("expected Ignition health check finding, got 0")
	}

	found := false
	for _, f := range findings {
		if strings.Contains(f.Endpoint, "/_ignition/health-check") {
			found = true
			if f.Severity != SeverityInfo {
				t.Errorf("expected SeverityInfo for health-check without execution, got %s", f.Severity)
			}
			if f.Details["can_execute_commands"] != "false" {
				t.Errorf("expected can_execute_commands false, got %s", f.Details["can_execute_commands"])
			}
			break
		}
	}
	if !found {
		t.Errorf("expected health check finding")
	}
}

// Test 6: Ignition health check endpoint with command execution enabled -> SeverityMedium (unconfirmed exploitability)
func TestLaravel_IgnitionHealthCheckCommandExecution(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/_ignition/health-check" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			fmt.Fprintf(w, `{"can_execute_commands": true}`)
			return
		}
		http.NotFound(w, r)
	}))
	defer server.Close()

	client := NewClient(ClientOptions{HTTPClient: server.Client(), AllowLoopback: true})
	findings := AuditLaravelDiagnostics(context.Background(), client, server.URL, nil)

	if len(findings) == 0 {
		t.Fatalf("expected Ignition health check finding, got 0")
	}

	found := false
	for _, f := range findings {
		if strings.Contains(f.Endpoint, "/_ignition/health-check") {
			found = true
			if f.Severity != SeverityMedium {
				t.Errorf("expected SeverityMedium when can_execute_commands is true, got %s", f.Severity)
			}
			if f.Details["exploitability"] != "unconfirmed" {
				t.Errorf("expected exploitability unconfirmed, got %s", f.Details["exploitability"])
			}
			if f.Details["command_execution_tested"] != "false" {
				t.Errorf("expected command_execution_tested false, got %s", f.Details["command_execution_tested"])
			}
			break
		}
	}
	if !found {
		t.Errorf("expected health check finding")
	}
}

// --- LARAVEL TELESCOPE REGRESSION TESTS ---

// Test 7: Telescope interface restricted by HTTP 403 Forbidden
func TestLaravel_TelescopeProtectedForbidden403(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/telescope") {
			w.WriteHeader(http.StatusForbidden)
			fmt.Fprintf(w, `Forbidden`)
			return
		}
		http.NotFound(w, r)
	}))
	defer server.Close()

	client := NewClient(ClientOptions{HTTPClient: server.Client(), AllowLoopback: true})
	findings := AuditLaravelDiagnostics(context.Background(), client, server.URL, nil)

	if len(findings) == 0 {
		t.Fatalf("expected Telescope restricted finding, got 0")
	}

	found := false
	for _, f := range findings {
		if f.Category == CategoryLaravelTelescopeProtected {
			found = true
			if f.Severity != SeverityInfo {
				t.Errorf("expected SeverityInfo for protected Telescope, got %s", f.Severity)
			}
			if f.Confidence != ConfidenceHigh {
				t.Errorf("expected ConfidenceHigh, got %s", f.Confidence)
			}
			if f.Details["scope_note"] == "" {
				t.Errorf("expected scope_note explaining route restriction scope")
			}
			if !strings.Contains(f.NegativeEvidence, "probed route") {
				t.Errorf("expected negative evidence explaining probed route restriction, got %s", f.NegativeEvidence)
			}
			break
		}
	}
	if !found {
		t.Errorf("expected CategoryLaravelTelescopeProtected finding")
	}
}

// Test 8: Telescope interface restricted by HTTP 401 Unauthorized
func TestLaravel_TelescopeProtectedUnauthorized401(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/telescope") {
			w.Header().Set("WWW-Authenticate", `Basic realm="Telescope"`)
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprintf(w, `Unauthorized`)
			return
		}
		http.NotFound(w, r)
	}))
	defer server.Close()

	client := NewClient(ClientOptions{HTTPClient: server.Client(), AllowLoopback: true})
	findings := AuditLaravelDiagnostics(context.Background(), client, server.URL, nil)

	if len(findings) == 0 {
		t.Fatalf("expected Telescope restricted finding, got 0")
	}

	f := findings[0]
	if f.Category != CategoryLaravelTelescopeProtected {
		t.Errorf("expected CategoryLaravelTelescopeProtected, got %s", f.Category)
	}
	if f.Severity != SeverityInfo {
		t.Errorf("expected SeverityInfo, got %s", f.Severity)
	}
}

// Test 9: Telescope interface redirects to login (HTTP 302)
func TestLaravel_TelescopeProtectedRedirectLogin(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/telescope") {
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}
		if r.URL.Path == "/login" {
			w.Header().Set("Content-Type", "text/html")
			w.WriteHeader(http.StatusOK)
			fmt.Fprintf(w, `<html><body><h1>Login Page</h1><form></form></body></html>`)
			return
		}
		http.NotFound(w, r)
	}))
	defer server.Close()

	client := NewClient(ClientOptions{HTTPClient: server.Client(), AllowLoopback: true})
	findings := AuditLaravelDiagnostics(context.Background(), client, server.URL, nil)

	if len(findings) == 0 {
		t.Fatalf("expected Telescope restricted finding for redirect, got 0")
	}

	f := findings[0]
	if f.Category != CategoryLaravelTelescopeProtected {
		t.Errorf("expected CategoryLaravelTelescopeProtected, got %s", f.Category)
	}
	if f.Severity != SeverityInfo {
		t.Errorf("expected SeverityInfo, got %s", f.Severity)
	}
	if f.Details["scope_note"] == "" {
		t.Errorf("expected scope_note explaining route restriction scope")
	}
	if !strings.Contains(f.Evidence, "redirect") {
		t.Errorf("expected evidence to mention redirect, got %s", f.Evidence)
	}
}

// Test 10: Telescope public dashboard shell without sensitive records -> SeverityInfo
func TestLaravel_TelescopePublicShellNoRecords(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/telescope" {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.WriteHeader(http.StatusOK)
			fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head><title>Telescope</title><link href="/vendor/telescope/app.css" rel="stylesheet"></head>
<body>
<div id="telescope"></div>
<script>window.Telescope = {"path":"telescope","timezone":"UTC","recording":true};</script>
<script src="/vendor/telescope/app.js"></script>
</body></html>`)
			return
		}
		if r.URL.Path == "/telescope/telescope-api/requests" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			fmt.Fprintf(w, `{"entries": [], "status": "enabled"}`)
			return
		}
		http.NotFound(w, r)
	}))
	defer server.Close()

	client := NewClient(ClientOptions{HTTPClient: server.Client(), AllowLoopback: true})
	findings := AuditLaravelDiagnostics(context.Background(), client, server.URL, nil)

	if len(findings) == 0 {
		t.Fatalf("expected Telescope finding for public dashboard shell, got 0")
	}

	for _, f := range findings {
		if f.Category == CategoryLaravelTelescopeData {
			t.Errorf("must NOT report CategoryLaravelTelescopeData when 0 records are disclosed")
		}
		if f.Severity != SeverityInfo {
			t.Errorf("INTERFACE SHELL ALONE IS NOT A VULNERABILITY: expected SeverityInfo, got %s", f.Severity)
		}
	}
}

// Test 11: Unauthenticated Telescope API disclosing active diagnostic records -> SeverityHigh
func TestLaravel_TelescopeSensitiveTelemetryDisclosure(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/telescope" {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.WriteHeader(http.StatusOK)
			fmt.Fprintf(w, `<!DOCTYPE html><html><head><title>Telescope</title></head><body><div id="telescope"></div></body></html>`)
			return
		}
		if r.URL.Path == "/telescope/telescope-api/requests" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			fmt.Fprintf(w, `{
  "entries": [
    {
      "id": "1",
      "type": "request",
      "content": {
        "uri": "/api/v1/checkout",
        "method": "POST",
        "response_status": 200,
        "headers": {"content-type": ["application/json"]}
      }
    },
    {
      "id": "2",
      "type": "query",
      "content": {
        "sql": "SELECT * FROM users WHERE id = 1"
      }
    }
  ],
  "status": "enabled"
}`)
			return
		}
		http.NotFound(w, r)
	}))
	defer server.Close()

	client := NewClient(ClientOptions{HTTPClient: server.Client(), AllowLoopback: true})
	findings := AuditLaravelDiagnostics(context.Background(), client, server.URL, nil)

	if len(findings) == 0 {
		t.Fatalf("expected Telescope telemetry disclosure finding, got 0")
	}

	found := false
	for _, f := range findings {
		if f.Category == CategoryLaravelTelescopeData {
			found = true
			if f.Severity != SeverityHigh {
				t.Errorf("expected SeverityHigh for unauthenticated telemetry disclosure, got %s", f.Severity)
			}
			if f.Confidence != ConfidenceHigh {
				t.Errorf("expected ConfidenceHigh, got %s", f.Confidence)
			}
			if f.Details["entries_count"] != "2" {
				t.Errorf("expected 2 entries, got %s", f.Details["entries_count"])
			}
			break
		}
	}
	if !found {
		t.Errorf("expected CategoryLaravelTelescopeData finding")
	}
}

// Test 12: Telescope telemetry disclosing unmasked credential -> SeverityCritical with zero leak
func TestLaravel_TelescopeTelemetryWithUnmaskedSecret(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/telescope/telescope-api/requests" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			fmt.Fprintf(w, `{
  "entries": [
    {
      "id": "1",
      "type": "request",
      "content": {
        "uri": "/api/v1/auth",
        "headers": {
          "authorization": ["Bearer %s"]
        },
        "payload": {
          "password": "%s"
        }
      }
    }
  ]
}`, syntheticCanarySecret, syntheticCanarySecret)
			return
		}
		http.NotFound(w, r)
	}))
	defer server.Close()

	client := NewClient(ClientOptions{HTTPClient: server.Client(), AllowLoopback: true})
	findings := AuditLaravelDiagnostics(context.Background(), client, server.URL, nil)

	if len(findings) == 0 {
		t.Fatalf("expected finding for Telescope entries with credential")
	}

	f := findings[0]
	if f.Severity != SeverityCritical {
		t.Errorf("expected SeverityCritical for unmasked credentials in telemetry, got %s", f.Severity)
	}

	if strings.Contains(f.Evidence, syntheticCanarySecret) {
		t.Fatalf("SECURITY LEAK: synthetic canary leaked into evidence: %s", f.Evidence)
	}
	if strings.Contains(fmt.Sprintf("%v", f.Details), syntheticCanarySecret) {
		t.Fatalf("SECURITY LEAK: synthetic canary leaked into details: %v", f.Details)
	}
}

// Test 13: Generic HTML SPA shell returning 200 on /telescope without Telescope markers -> 0 findings
func TestLaravel_UnrelatedHTMLSuppressed(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, `<!doctype html><html><head><title>My React App</title></head><body><div id="root"></div></body></html>`)
	}))
	defer server.Close()

	client := NewClient(ClientOptions{HTTPClient: server.Client(), AllowLoopback: true})
	findings := AuditLaravelDiagnostics(context.Background(), client, server.URL, nil)

	if len(findings) > 0 {
		t.Errorf("expected generic HTML to produce 0 findings, got %d", len(findings))
	}
}

// Test 14: Nested base path scope preservation
func TestLaravel_NestedBasePathPreservation(t *testing.T) {
	var requestedPaths []string
	var mu sync.Mutex

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		requestedPaths = append(requestedPaths, r.URL.Path)
		mu.Unlock()

		if r.URL.Path == "/app/v2/telescope" {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		http.NotFound(w, r)
	}))
	defer server.Close()

	client := NewClient(ClientOptions{HTTPClient: server.Client(), AllowLoopback: true})
	nestedURL := server.URL + "/app/v2"

	findings := AuditLaravelDiagnostics(context.Background(), client, nestedURL, nil)
	if len(findings) == 0 {
		t.Fatalf("expected finding on nested base path")
	}

	mu.Lock()
	defer mu.Unlock()
	for _, p := range requestedPaths {
		if !strings.HasPrefix(p, "/app/v2") {
			t.Errorf("SECURITY LEAK: probe escaped nested base path /app/v2: %s", p)
		}
	}
}

// Test 15: Timeout handling
func TestLaravel_TimeoutHandling(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(200 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client := NewClient(ClientOptions{
		HTTPClient:    server.Client(),
		Timeout:       50 * time.Millisecond,
		AllowLoopback: true,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	findings := AuditLaravelDiagnostics(ctx, client, server.URL, nil)
	if len(findings) > 0 {
		t.Errorf("expected 0 findings on timeout")
	}
}

// Test 16: Oversized response handling
func TestLaravel_OversizedResponseHandling(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintf(w, `<!DOCTYPE html><html><head><title>Ignition</title></head><body><div id="ignition">`)
		for i := 0; i < 20000; i++ {
			fmt.Fprintf(w, `<div class="frame">File "/var/www/huge_%d.php" line %d</div>`, i, i)
		}
		fmt.Fprintf(w, `</div><script>window.data = {};</script></body></html>`)
	}))
	defer server.Close()

	client := NewClient(ClientOptions{HTTPClient: server.Client(), AllowLoopback: true})
	findings := AuditLaravelDiagnostics(context.Background(), client, server.URL, nil)

	if len(findings) == 0 {
		t.Fatalf("expected finding for oversized response")
	}
	f := findings[0]
	if f.Details["limitations"] == "" {
		t.Errorf("expected limitations noted for truncated response")
	}
}

// Test 17: SSRF and redirect protection
func TestLaravel_SSRFAndRedirectProtection(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://169.254.169.254/latest/meta-data/", http.StatusFound)
	}))
	defer server.Close()

	client := NewClient(ClientOptions{HTTPClient: server.Client(), AllowLoopback: true})
	findings := AuditLaravelDiagnostics(context.Background(), client, server.URL, nil)

	if len(findings) > 0 {
		t.Errorf("expected SSRF redirect to be blocked, got %d findings", len(findings))
	}
}

// Test 18: Rate limiting
func TestLaravel_RateLimitingHalt(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer server.Close()

	client := NewClient(ClientOptions{HTTPClient: server.Client(), AllowLoopback: true})
	findings := AuditLaravelDiagnostics(context.Background(), client, server.URL, nil)

	if len(findings) > 0 {
		t.Errorf("expected 0 findings when rate limited with 429, got %d", len(findings))
	}
}

// Test 19: No duplicate findings
func TestLaravel_NoDuplicateFindings(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/telescope" {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		http.NotFound(w, r)
	}))
	defer server.Close()

	client := NewClient(ClientOptions{HTTPClient: server.Client(), AllowLoopback: true})
	detector := NewDetector(client)

	result := detector.Audit(context.Background(), server.URL, nil)

	seenFP := make(map[string]int)
	for _, f := range result.Findings {
		seenFP[f.Fingerprint]++
		if seenFP[f.Fingerprint] > 1 {
			t.Errorf("duplicate finding fingerprint detected: %s (category: %s)", f.Fingerprint, f.Category)
		}
	}
}

// Test 20: Zero secret leakage across all finding fields
func TestLaravel_ZeroSecretLeakageVerification(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/_felix_ignition_probe":
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprintf(w, `<div id="ignition"></div><script>window.data={"env":{"APP_KEY":"%s"}};</script>`, syntheticCanarySecret)
		case "/telescope/telescope-api/requests":
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			fmt.Fprintf(w, `{"entries":[{"id":"1","content":{"token":"%s"}}]}`, syntheticCanarySecret)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	client := NewClient(ClientOptions{HTTPClient: server.Client(), AllowLoopback: true})
	detector := NewDetector(client)

	result := detector.Audit(context.Background(), server.URL, nil)

	for _, f := range result.Findings {
		if strings.Contains(f.Evidence, syntheticCanarySecret) {
			t.Fatalf("CRITICAL SECURITY LEAK: canary secret present in Evidence: %s", f.Evidence)
		}
		if strings.Contains(f.Description, syntheticCanarySecret) {
			t.Fatalf("CRITICAL SECURITY LEAK: canary secret present in Description: %s", f.Description)
		}
		for k, v := range f.Details {
			if strings.Contains(v, syntheticCanarySecret) {
				t.Fatalf("CRITICAL SECURITY LEAK: canary secret present in Details[%s]: %s", k, v)
			}
		}
	}
}

// Test 21: Detector integration verifying LaravelCount
func TestLaravel_DetectorIntegration(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/telescope" {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		http.NotFound(w, r)
	}))
	defer server.Close()

	client := NewClient(ClientOptions{HTTPClient: server.Client(), AllowLoopback: true})
	detector := NewDetector(client)

	result := detector.Audit(context.Background(), server.URL, nil)

	if result.LaravelCount == 0 {
		t.Errorf("expected LaravelCount > 0 in AuditResult, got %d", result.LaravelCount)
	}
}

// Test 22: Telescope unauthenticated API disclosing operational entries without queries/headers/exceptions -> SeverityMedium
func TestLaravel_TelescopeOperationalEventEntries(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/telescope/telescope-api/requests" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			fmt.Fprintf(w, `{
  "entries": [
    {
      "id": "1",
      "type": "event",
      "content": {
        "name": "App\\Events\\UserRegistered",
        "listener": "App\\Listeners\\SendWelcomeEmail"
      }
    },
    {
      "id": "2",
      "type": "job",
      "content": {
        "name": "App\\Jobs\\ProcessReport",
        "queue": "default"
      }
    }
  ],
  "status": "enabled"
}`)
			return
		}
		http.NotFound(w, r)
	}))
	defer server.Close()

	client := NewClient(ClientOptions{HTTPClient: server.Client(), AllowLoopback: true})
	findings := AuditLaravelDiagnostics(context.Background(), client, server.URL, nil)

	if len(findings) == 0 {
		t.Fatalf("expected Telescope operational telemetry finding, got 0")
	}

	found := false
	for _, f := range findings {
		if f.Category == CategoryLaravelTelescopeData {
			found = true
			if f.Severity != SeverityMedium {
				t.Errorf("expected SeverityMedium for operational event entries without queries/headers, got %s", f.Severity)
			}
			if f.Details["auth_context"] != "unauthenticated" {
				t.Errorf("expected auth_context unauthenticated, got %s", f.Details["auth_context"])
			}
			if f.Details["verification_limitations"] == "" {
				t.Errorf("expected verification_limitations in details")
			}
			if !strings.Contains(f.Description, "operational event entries") {
				t.Errorf("expected operational description, got %s", f.Description)
			}
			break
		}
	}
	if !found {
		t.Errorf("expected CategoryLaravelTelescopeData finding for operational entries")
	}
}
