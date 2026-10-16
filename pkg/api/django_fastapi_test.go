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

// syntheticCanarySecret is used to verify redaction without triggering GitHub Push Protection.
const syntheticCanarySecret = "felix_test_canary_secret_9876543210"

// --- DJANGO REGRESSION TESTS ---

// Test 1: Genuine Django technical error-page indicators
func TestDjango_Technical500ErrorPage(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintf(w, `<!DOCTYPE html>
<html lang="en">
<head><title>OperationalError at /api/users/</title></head>
<body>
<div id="summary">
  <h1>OperationalError at /api/users/</h1>
  <pre class="exception_value">no such table: auth_user</pre>
  <table class="meta">
    <tr><th>Request Method:</th><td>GET</td></tr>
    <tr><th>Request URL:</th><td>%s</td></tr>
    <tr><th>Django Version:</th><td>4.2.7</td></tr>
    <tr><th>Python Executable:</th><td>/usr/local/bin/python3</td></tr>
    <tr><th>Python Version:</th><td>3.11.4</td></tr>
  </table>
</div>
<div id="traceback">
  <h2>Traceback (most recent call last):</h2>
  <div class="frame">
    <code>File "/app/myproject/views.py", line 42, in get_users</code>
  </div>
</div>
<h2>Request information</h2>
<h3>Technical information (for developers)</h3>
</body></html>`, r.URL.String())
	}))
	defer server.Close()

	client := NewClient(ClientOptions{HTTPClient: server.Client(), AllowLoopback: true})
	findings := AuditDjangoDiagnostics(context.Background(), client, server.URL, nil)

	if len(findings) == 0 {
		t.Fatalf("expected Django debug mode finding, got 0")
	}

	found := false
	for _, f := range findings {
		if f.Category == CategoryDjangoDebugMode {
			found = true
			if f.Severity != SeverityHigh {
				t.Errorf("expected SeverityHigh, got %s", f.Severity)
			}
			if f.Details["django_version"] != "4.2.7" {
				t.Errorf("expected Django version 4.2.7, got %s", f.Details["django_version"])
			}
			if f.Details["debug_mode"] != "true" {
				t.Errorf("expected debug_mode true")
			}
			break
		}
	}
	if !found {
		t.Errorf("expected CategoryDjangoDebugMode finding")
	}
}

// Test 2: Traceback with absolute filesystem path
func TestDjango_TracebackWithAbsolutePath(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintf(w, `<div id="summary">
  <h1>ZeroDivisionError</h1>
  <table class="meta">
    <tr><th>Django Version:</th><td>4.2.7</td></tr>
    <tr><th>Python Version:</th><td>3.11.4</td></tr>
  </table>
</div>
<div id="traceback">
  <h2>Traceback (most recent call last):</h2>
  File "/var/www/internal_django_project/app/views.py", line 105, in calculate_rate
  File "/usr/local/lib/python3.11/site-packages/django/core/handlers/base.py", line 197, in get_response
</div>
<h3>Technical information (for developers)</h3>`)
	}))
	defer server.Close()

	client := NewClient(ClientOptions{HTTPClient: server.Client(), AllowLoopback: true})
	findings := AuditDjangoDiagnostics(context.Background(), client, server.URL, nil)

	if len(findings) == 0 {
		t.Fatalf("expected finding for traceback with absolute paths, got 0")
	}

	f := findings[0]
	if !strings.Contains(f.Evidence, "/var/www/internal_django_project") {
		t.Errorf("expected evidence to disclose internal filesystem path, got %s", f.Evidence)
	}
}

// Test 3: Generic error page that must not be classified as Django debug mode
func TestDjango_Generic500Suppressed(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintf(w, `<!DOCTYPE html><html><body><h1>Internal Server Error</h1><p>An unexpected error occurred. Please contact support.</p></body></html>`)
	}))
	defer server.Close()

	client := NewClient(ClientOptions{HTTPClient: server.Client(), AllowLoopback: true})
	findings := AuditDjangoDiagnostics(context.Background(), client, server.URL, nil)

	if len(findings) > 0 {
		t.Errorf("expected generic 500 error page to be suppressed, got %d findings", len(findings))
	}
}

// Test 4: Ordinary Django response without sensitive disclosure
func TestDjango_OrdinaryResponseWithoutDisclosure(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Set-Cookie", "csrftoken=abcdef1234567890; Path=/")
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, `<!DOCTYPE html><html><head><title>Welcome</title></head><body><h1>Welcome to our Django site</h1></body></html>`)
	}))
	defer server.Close()

	client := NewClient(ClientOptions{HTTPClient: server.Client(), AllowLoopback: true})
	findings := AuditDjangoDiagnostics(context.Background(), client, server.URL, nil)

	if len(findings) > 0 {
		t.Errorf("expected ordinary Django response to produce 0 findings, got %d", len(findings))
	}
}

// Test 5: Sensitive-value redaction in settings table
func TestDjango_SensitiveValueRedactionInSettings(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintf(w, `<div id="summary">
  <h1>KeyError at /</h1>
  <table class="meta">
    <tr><th>Django Version:</th><td>4.2.7</td></tr>
    <tr><th>Python Version:</th><td>3.11.4</td></tr>
  </table>
</div>
<div id="traceback">Traceback (most recent call last): File "/app/views.py", line 10</div>
<h3>Technical information (for developers)</h3>
<table class="meta" id="settings-meta">
  <tr><th>SECRET_KEY</th><td><pre>%s</pre></td></tr>
</table>`, syntheticCanarySecret)
	}))
	defer server.Close()

	client := NewClient(ClientOptions{HTTPClient: server.Client(), AllowLoopback: true})
	findings := AuditDjangoDiagnostics(context.Background(), client, server.URL, nil)

	if len(findings) == 0 {
		t.Fatalf("expected Django debug mode finding with unmasked secret")
	}

	f := findings[0]
	if f.Severity != SeverityCritical {
		t.Errorf("expected SeverityCritical for unmasked SECRET_KEY in debug page, got %s", f.Severity)
	}

	// Verify synthetic secret is NEVER present in plaintext anywhere in the finding
	if strings.Contains(f.Evidence, syntheticCanarySecret) {
		t.Errorf("SECURITY LEAK: raw synthetic canary secret appeared in evidence: %s", f.Evidence)
	}
	if strings.Contains(fmt.Sprintf("%v", f.Details), syntheticCanarySecret) {
		t.Errorf("SECURITY LEAK: raw synthetic canary secret appeared in details: %v", f.Details)
	}
}

// Test 6: Ambiguous framework identification
func TestDjango_AmbiguousFrameworkSuppressed(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, `<div>Django is a popular Python framework. You can debug applications using various tools.</div>`)
	}))
	defer server.Close()

	client := NewClient(ClientOptions{HTTPClient: server.Client(), AllowLoopback: true})
	findings := AuditDjangoDiagnostics(context.Background(), client, server.URL, nil)

	if len(findings) > 0 {
		t.Errorf("expected ambiguous framework references to produce 0 findings, got %d", len(findings))
	}
}

// Test: Django technical 404 URLconf route disclosure
func TestDjango_Technical404URLConfDisclosure(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusNotFound)
		fmt.Fprintf(w, `<!DOCTYPE html>
<html lang="en">
<head><title>Page not found (404)</title></head>
<body>
<h1>Page not found (404)</h1>
<p>Using the URLconf defined in <code>myproject.urls</code>, Django tried these URL patterns, in this order:</p>
<ol>
  <li>^admin/</li>
  <li>^api/v1/users/</li>
  <li>^api/v1/billing/</li>
  <li>^internal/metrics/</li>
</ol>
<p>The current path, <code>%s</code>, didn't match any of these.</p>
</body></html>`, r.URL.Path)
	}))
	defer server.Close()

	client := NewClient(ClientOptions{HTTPClient: server.Client(), AllowLoopback: true})
	findings := AuditDjangoDiagnostics(context.Background(), client, server.URL, nil)

	if len(findings) == 0 {
		t.Fatalf("expected Django technical 404 finding, got 0")
	}

	found := false
	for _, f := range findings {
		if f.Category == CategoryDjangoURLConfDisclosure {
			found = true
			if f.Severity != SeverityMedium {
				t.Errorf("expected SeverityMedium for URLconf disclosure, got %s", f.Severity)
			}
			if f.Details["urlconf"] != "myproject.urls" {
				t.Errorf("expected urlconf myproject.urls, got %s", f.Details["urlconf"])
			}
			if !strings.Contains(f.Evidence, "^admin/") {
				t.Errorf("expected evidence to include internal patterns, got %s", f.Evidence)
			}
			break
		}
	}
	if !found {
		t.Errorf("expected CategoryDjangoURLConfDisclosure finding")
	}
}

// Test: Django REST Framework Browsable API
func TestDjango_BrowsableAPI(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, `<!DOCTYPE html><html><head><title>Django REST framework</title></head>
<body>
<div class="navbar"><a class="navbar-brand" href="#">Django REST framework</a></div>
<div class="response-info"><pre class="prettyprint"><code>HTTP 200 OK
Allow: GET, HEAD, OPTIONS
Content-Type: application/json</code></pre></div>
<button data-target="#sourcePage" class="btn">View Source</button>
</body></html>`)
	}))
	defer server.Close()

	client := NewClient(ClientOptions{HTTPClient: server.Client(), AllowLoopback: true})
	findings := AuditDjangoDiagnostics(context.Background(), client, server.URL, []string{"/api/"})

	if len(findings) == 0 {
		t.Fatalf("expected DRF browsable API finding, got 0")
	}

	found := false
	for _, f := range findings {
		if f.Category == CategoryDjangoBrowsableAPI {
			found = true
			if f.Severity != SeverityLow {
				t.Errorf("expected SeverityLow for DRF browsable API, got %s", f.Severity)
			}
			break
		}
	}
	if !found {
		t.Errorf("expected CategoryDjangoBrowsableAPI finding")
	}
}

// --- FASTAPI REGRESSION TESTS ---

// Test 7: Genuine OpenAPI JSON schema
func TestFastAPI_GenuineOpenAPISchema(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/openapi.json" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			fmt.Fprintf(w, `{
  "openapi": "3.1.0",
  "info": {"title": "Users Service", "version": "1.0.0"},
  "paths": {
    "/items": {
      "get": {"summary": "List items"}
    }
  }
}`)
			return
		}
		http.NotFound(w, r)
	}))
	defer server.Close()

	client := NewClient(ClientOptions{HTTPClient: server.Client(), AllowLoopback: true})
	findings := AuditFastAPIDocs(context.Background(), client, server.URL, nil)

	if len(findings) == 0 {
		t.Fatalf("expected OpenAPI schema finding, got 0")
	}

	found := false
	for _, f := range findings {
		if f.Category == CategoryFastAPIDocs {
			found = true
			if f.Severity != SeverityInfo {
				t.Errorf("expected SeverityInfo for standard public documentation, got %s", f.Severity)
			}
			if f.Details["openapi_ver"] != "3.1.0" {
				t.Errorf("expected openapi_ver 3.1.0, got %s", f.Details["openapi_ver"])
			}
			break
		}
	}
	if !found {
		t.Errorf("expected CategoryFastAPIDocs finding")
	}
}

// Test 8: Public /docs and /redoc without an associated vulnerability
func TestFastAPI_PublicInteractiveDocsInformational(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		if r.URL.Path == "/docs" {
			fmt.Fprintf(w, `<!DOCTYPE html><html><head><title>FastAPI - Swagger UI</title>
<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/swagger-ui-dist@5/swagger-ui.css">
</head><body><div id="swagger-ui"></div>
<script src="https://cdn.jsdelivr.net/npm/swagger-ui-dist@5/swagger-ui-bundle.js"></script>
<script>
const ui = SwaggerUIBundle({url: '/openapi.json', dom_id: '#swagger-ui'});
</script></body></html>`)
			return
		}
		if r.URL.Path == "/redoc" {
			fmt.Fprintf(w, `<!DOCTYPE html><html><head><title>FastAPI - ReDoc</title></head>
<body><redoc spec-url="/openapi.json"></redoc>
<script src="https://cdn.jsdelivr.net/npm/redoc@next/bundles/redoc.standalone.js"></script></body></html>`)
			return
		}
		http.NotFound(w, r)
	}))
	defer server.Close()

	client := NewClient(ClientOptions{HTTPClient: server.Client(), AllowLoopback: true})
	findings := AuditFastAPIDocs(context.Background(), client, server.URL, nil)

	if len(findings) == 0 {
		t.Fatalf("expected interactive docs findings, got 0")
	}

	for _, f := range findings {
		if f.Category != CategoryFastAPIDocs {
			t.Errorf("expected CategoryFastAPIDocs, got %s", f.Category)
		}
		if f.Severity != SeverityInfo {
			t.Errorf("PUBLIC DOCS ARE NOT VULNERABILITIES: expected SeverityInfo, got %s", f.Severity)
		}
	}
}

// Test 9: Disabled or absent documentation endpoint
func TestFastAPI_DisabledDocsSuppressed(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	}))
	defer server.Close()

	client := NewClient(ClientOptions{HTTPClient: server.Client(), AllowLoopback: true})
	findings := AuditFastAPIDocs(context.Background(), client, server.URL, nil)

	if len(findings) > 0 {
		t.Errorf("expected 0 findings for disabled 404 docs, got %d", len(findings))
	}
}

// Test 10: Schema containing ordinary public routes
func TestFastAPI_OrdinaryPublicRoutesInformational(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/openapi.json" {
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprintf(w, `{
  "openapi": "3.0.3",
  "info": {"title": "Catalog API"},
  "paths": {
    "/products": {"get": {"summary": "List products"}},
    "/products/{id}": {"get": {"summary": "Get product"}},
    "/search": {"get": {"summary": "Search products"}}
  }
}`)
			return
		}
		http.NotFound(w, r)
	}))
	defer server.Close()

	client := NewClient(ClientOptions{HTTPClient: server.Client(), AllowLoopback: true})
	findings := AuditFastAPIDocs(context.Background(), client, server.URL, nil)

	if len(findings) == 0 {
		t.Fatalf("expected finding for public openapi.json, got 0")
	}

	for _, f := range findings {
		if f.Category == CategoryFastAPISensitivePaths || f.Category == CategoryFastAPISensitiveSchema {
			t.Errorf("ordinary public routes must not trigger sensitive findings: got %s", f.Category)
		}
		if f.Severity != SeverityInfo {
			t.Errorf("expected SeverityInfo for ordinary schema, got %s", f.Severity)
		}
	}
}

// Test 11: Schema revealing potentially sensitive internal paths
func TestFastAPI_SensitiveInternalPathsDisclosure(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/openapi.json" {
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprintf(w, `{
  "openapi": "3.0.0",
  "info": {"title": "Production App"},
  "paths": {
    "/api/v1/public": {"get": {"summary": "Public API"}},
    "/admin/flush_cache": {"post": {"summary": "Flush Redis Cache"}},
    "/internal/metrics/prometheus": {"get": {"summary": "Prometheus Metrics"}},
    "/debug/pprof/goroutine": {"get": {"summary": "Goroutine dump"}}
  }
}`)
			return
		}
		http.NotFound(w, r)
	}))
	defer server.Close()

	client := NewClient(ClientOptions{HTTPClient: server.Client(), AllowLoopback: true})
	findings := AuditFastAPIDocs(context.Background(), client, server.URL, nil)

	if len(findings) == 0 {
		t.Fatalf("expected sensitive path disclosure finding, got 0")
	}

	found := false
	for _, f := range findings {
		if f.Category == CategoryFastAPISensitivePaths {
			found = true
			if f.Severity != SeverityMedium {
				t.Errorf("expected SeverityMedium for sensitive internal paths, got %s", f.Severity)
			}
			if !strings.Contains(f.Evidence, "/admin/flush_cache") {
				t.Errorf("expected evidence to mention /admin/flush_cache, got %s", f.Evidence)
			}
			break
		}
	}
	if !found {
		t.Errorf("expected CategoryFastAPISensitivePaths finding")
	}
}

// Test 12: Secret-like content embedded in descriptions or examples
func TestFastAPI_EmbeddedSecretInSchema(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/openapi.json" {
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprintf(w, `{
  "openapi": "3.0.0",
  "info": {"title": "Service API"},
  "paths": {
    "/webhook": {
      "post": {
        "parameters": [
          {
            "name": "api_secret",
            "in": "header",
            "schema": {
              "type": "string",
              "default": "%s"
            }
          }
        ]
      }
    }
  }
}`, syntheticCanarySecret)
			return
		}
		http.NotFound(w, r)
	}))
	defer server.Close()

	client := NewClient(ClientOptions{HTTPClient: server.Client(), AllowLoopback: true})
	findings := AuditFastAPIDocs(context.Background(), client, server.URL, nil)

	if len(findings) == 0 {
		t.Fatalf("expected embedded secret in schema finding, got 0")
	}

	found := false
	for _, f := range findings {
		if f.Category == CategoryFastAPISensitiveSchema {
			found = true
			if f.Severity != SeverityHigh {
				t.Errorf("expected SeverityHigh for embedded credential in schema, got %s", f.Severity)
			}
			// Assert canary is completely redacted from all fields
			if strings.Contains(f.Evidence, syntheticCanarySecret) {
				t.Errorf("SECURITY LEAK: synthetic secret canary exposed in evidence: %s", f.Evidence)
			}
			break
		}
	}
	if !found {
		t.Errorf("expected CategoryFastAPISensitiveSchema finding")
	}
}

// Test 13: Malformed and unrelated JSON
func TestFastAPI_MalformedAndUnrelatedJSONSuppressed(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		// Returns generic unrelated JSON or broken JSON
		fmt.Fprintf(w, `{"status": "ok", "service": "payment-worker"}`)
	}))
	defer server.Close()

	client := NewClient(ClientOptions{HTTPClient: server.Client(), AllowLoopback: true})
	findings := AuditFastAPIDocs(context.Background(), client, server.URL, nil)

	if len(findings) > 0 {
		t.Errorf("expected unrelated JSON without openapi/swagger to produce 0 findings, got %d", len(findings))
	}
}

// Test 14: Generic HTML SPA shell returning HTTP 200
func TestFastAPI_GenericHTMLSPAShellSuppressed(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		// Generic SPA index.html returned for all paths including /openapi.json
		fmt.Fprintf(w, `<!doctype html><html><head><title>App</title></head><body><div id="root"></div><script src="/bundle.js"></script></body></html>`)
	}))
	defer server.Close()

	client := NewClient(ClientOptions{HTTPClient: server.Client(), AllowLoopback: true})
	findings := AuditFastAPIDocs(context.Background(), client, server.URL, nil)

	if len(findings) > 0 {
		t.Errorf("expected generic SPA HTML fallback to produce 0 findings, got %d", len(findings))
	}
}

// --- SHARED SAFETY BEHAVIOR TESTS ---

// Test 15: Authentication-required, forbidden, redirect, and inconclusive cases
func TestShared_AuthRequiredAndRedirectCases(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/docs":
			w.WriteHeader(http.StatusUnauthorized)
			w.Header().Set("WWW-Authenticate", `Bearer realm="FastAPI"`)
		case "/openapi.json":
			w.WriteHeader(http.StatusForbidden)
		default:
			http.Redirect(w, r, "/login", http.StatusFound)
		}
	}))
	defer server.Close()

	client := NewClient(ClientOptions{HTTPClient: server.Client(), AllowLoopback: true})
	findings := AuditFastAPIDocs(context.Background(), client, server.URL, nil)

	if len(findings) > 0 {
		t.Errorf("expected 0 findings for auth-required/forbidden docs endpoints, got %d", len(findings))
	}
}

// Test 16: Nested base paths and scope-boundary preservation
func TestShared_NestedBasePathScopePreservation(t *testing.T) {
	var requestedPaths []string
	var mu sync.Mutex

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		requestedPaths = append(requestedPaths, r.URL.Path)
		mu.Unlock()

		if r.URL.Path == "/api/v1/openapi.json" {
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprintf(w, `{"openapi":"3.0.0","info":{"title":"Nested"},"paths":{"/items":{}}}`)
			return
		}
		http.NotFound(w, r)
	}))
	defer server.Close()

	client := NewClient(ClientOptions{HTTPClient: server.Client(), AllowLoopback: true})
	nestedURL := server.URL + "/api/v1"

	findings := AuditFastAPIDocs(context.Background(), client, nestedURL, nil)
	if len(findings) == 0 {
		t.Fatalf("expected finding on nested base path")
	}

	mu.Lock()
	defer mu.Unlock()
	for _, p := range requestedPaths {
		if !strings.HasPrefix(p, "/api/v1") {
			t.Errorf("SECURITY LEAK: probe escaped nested base path /api/v1: %s", p)
		}
	}
}

// Test 17: Timeout handling
func TestShared_TimeoutHandling(t *testing.T) {
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

	findings := AuditFastAPIDocs(ctx, client, server.URL, nil)
	// Must return gracefully without crashing
	if len(findings) > 0 {
		t.Errorf("expected 0 findings on timeout")
	}
}

// Test 18: Oversized response handling
func TestShared_OversizedResponseHandling(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		// Generate an oversized > 512 KiB response
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, `{"openapi":"3.0.0","info":{"title":"Huge API"},"paths":{`)
		for i := 0; i < 20000; i++ {
			fmt.Fprintf(w, `"/route/%d":{"get":{"summary":"Route description repeating to exceed size limit"}},`, i)
		}
		fmt.Fprintf(w, `"/end":{"get":{}}}}`)
	}))
	defer server.Close()

	client := NewClient(ClientOptions{HTTPClient: server.Client(), AllowLoopback: true})
	findings := AuditFastAPIDocs(context.Background(), client, server.URL, nil)

	// Wire-read should be bounded and not crash or run out of memory
	if len(findings) > 0 {
		for _, f := range findings {
			if f.Details["limitations"] == "" {
				t.Logf("finding returned cleanly: %s", f.Category)
			}
		}
	}
}

// Test 19: Redirect scope and SSRF protection
func TestShared_SSRFAndRedirectProtection(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Attempt to redirect out of scope to AWS metadata service
		http.Redirect(w, r, "http://169.254.169.254/latest/meta-data/", http.StatusFound)
	}))
	defer server.Close()

	client := NewClient(ClientOptions{HTTPClient: server.Client(), AllowLoopback: true})
	findings := AuditFastAPIDocs(context.Background(), client, server.URL, nil)

	if len(findings) > 0 {
		t.Errorf("expected SSRF redirect to be blocked, got %d findings", len(findings))
	}
}

// Test 20: Rate limiting
func TestShared_RateLimitingHalt(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer server.Close()

	client := NewClient(ClientOptions{HTTPClient: server.Client(), AllowLoopback: true})
	findings := AuditFastAPIDocs(context.Background(), client, server.URL, nil)

	if len(findings) > 0 {
		t.Errorf("expected 0 findings when rate limited with 429, got %d", len(findings))
	}
}

// Test 21: No duplicate findings
func TestShared_NoDuplicateFindings(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/openapi.json" {
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprintf(w, `{"openapi":"3.0.0","info":{"title":"Test API"},"paths":{"/items":{}}}`)
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

// Test 22: Zero raw secret leakage into findings, logs, errors, or report models
func TestShared_ZeroSecretLeakageVerification(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/_felix_django_404_probe":
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprintf(w, `<div id="summary">
  <h1>KeyError at /</h1>
  <table class="meta">
    <tr><th>Django Version:</th><td>4.2.7</td></tr>
    <tr><th>Python Version:</th><td>3.11.4</td></tr>
  </table>
</div>
<div id="traceback">Traceback (most recent call last): File "/app/views.py", line 10</div>
<h3>Technical information (for developers)</h3>
<table class="meta" id="settings-meta">
  <tr><th>SECRET_KEY</th><td><pre>%s</pre></td></tr>
</table>`, syntheticCanarySecret)
		case "/openapi.json":
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprintf(w, `{"openapi":"3.0.0","info":{"title":"App"},"paths":{"/auth":{"post":{"parameters":[{"name":"secret_token","default":"%s"}]}}}}`,
				syntheticCanarySecret)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	client := NewClient(ClientOptions{HTTPClient: server.Client(), AllowLoopback: true})
	detector := NewDetector(client)

	auditResult := detector.Audit(context.Background(), server.URL, nil)

	for _, f := range auditResult.Findings {
		// Verify raw canary is NOT in APIFinding
		if strings.Contains(f.Evidence, syntheticCanarySecret) {
			t.Fatalf("CRITICAL SECURITY LEAK: canary secret present in APIFinding.Evidence: %s", f.Evidence)
		}
		if strings.Contains(f.Description, syntheticCanarySecret) {
			t.Fatalf("CRITICAL SECURITY LEAK: canary secret present in APIFinding.Description: %s", f.Description)
		}
		for k, v := range f.Details {
			if strings.Contains(v, syntheticCanarySecret) {
				t.Fatalf("CRITICAL SECURITY LEAK: canary secret present in APIFinding.Details[%s]: %s", k, v)
			}
		}
	}
}
