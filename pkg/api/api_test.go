package api

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"felix/pkg/crawler"
)

// Test 1: GraphQL endpoint discovery
func TestGraphQLEndpointDiscovery(t *testing.T) {
	d := NewDetector(nil)
	assets := []crawler.Asset{
		{
			URL:     "https://example.com/bundle.js",
			Content: []byte(`const endpoint = "/api/graphql"; const v1 = "/graphql";`),
		},
	}

	discovered := d.DiscoverCandidateEndpoints("https://example.com", assets)
	var foundAPI, foundV1 bool
	for _, ep := range discovered {
		if ep == "/api/graphql" {
			foundAPI = true
		}
		if ep == "/graphql" {
			foundV1 = true
		}
	}
	if !foundAPI || !foundV1 {
		t.Errorf("expected /api/graphql and /graphql in discovered endpoints, got: %+v", discovered)
	}
}

// Test 2: GraphQL introspection enabled
func TestGraphQLIntrospectionEnabled(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `{"data":{"__schema":{"types":[{"name":"User"},{"name":"Post"},{"name":"Query"}]}}}`)
	}))
	defer server.Close()

	client := NewClient(ClientOptions{HTTPClient: server.Client()})
	findings := AuditGraphQL(context.Background(), client, server.URL, []string{"/graphql"})

	if len(findings) == 0 {
		t.Fatalf("expected GraphQL introspection finding, got 0")
	}
	f := findings[0]
	if f.Category != CategoryGraphQLIntrospection {
		t.Errorf("expected CategoryGraphQLIntrospection, got %s", f.Category)
	}
	if f.Severity != SeverityLow {
		t.Errorf("expected SeverityLow, got %s", f.Severity)
	}
	if !strings.Contains(f.Evidence, "3 types observed") {
		t.Errorf("evidence should note observed type count: %s", f.Evidence)
	}
}

// Test 3: GraphQL protected endpoint (401/403)
func TestGraphQLProtectedEndpoint(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprint(w, `{"errors":[{"message":"Authentication required"}]}`)
	}))
	defer server.Close()

	client := NewClient(ClientOptions{HTTPClient: server.Client()})
	findings := AuditGraphQL(context.Background(), client, server.URL, []string{"/graphql"})

	if len(findings) != 0 {
		t.Errorf("protected GraphQL endpoint (401) must not generate exposure findings, got: %+v", findings)
	}
}

// Test 4: GraphQL 404
func TestGraphQL404(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	}))
	defer server.Close()

	client := NewClient(ClientOptions{HTTPClient: server.Client()})
	findings := AuditGraphQL(context.Background(), client, server.URL, []string{"/graphql"})

	if len(findings) != 0 {
		t.Errorf("404 endpoint must not generate findings, got: %+v", findings)
	}
}

// Test 5: CORS arbitrary-origin reflection
func TestCORSArbitraryOriginReflection(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if origin != "" {
			w.Header().Set("Access-Control-Allow-Origin", origin)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client := NewClient(ClientOptions{HTTPClient: server.Client()})
	findings := AuditCORS(context.Background(), client, server.URL)

	if len(findings) == 0 {
		t.Fatalf("expected CORS reflection finding")
	}
	f := findings[0]
	if f.Category != CategoryCORSOriginReflection {
		t.Errorf("expected CategoryCORSOriginReflection, got %s", f.Category)
	}
	if f.Severity != SeverityLow {
		t.Errorf("expected SeverityLow without credentials, got %s", f.Severity)
	}
}

// Test 6: CORS wildcard
func TestCORSWildcard(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client := NewClient(ClientOptions{HTTPClient: server.Client()})
	findings := AuditCORS(context.Background(), client, server.URL)

	if len(findings) == 0 {
		t.Fatalf("expected CORS wildcard finding")
	}
	f := findings[0]
	if f.Category != CategoryCORSWildcard {
		t.Errorf("expected CategoryCORSWildcard, got %s", f.Category)
	}
	if f.Severity != SeverityInfo {
		t.Errorf("expected SeverityInfo for wildcard, got %s", f.Severity)
	}
}

// Test 7: CORS credential behavior (origin reflection + credentials = High severity)
func TestCORSCredentialBehavior(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if origin != "" {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Access-Control-Allow-Credentials", "true")
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client := NewClient(ClientOptions{HTTPClient: server.Client()})
	findings := AuditCORS(context.Background(), client, server.URL)

	if len(findings) == 0 {
		t.Fatalf("expected CORS reflection with credentials finding")
	}
	f := findings[0]
	if f.Category != CategoryCORSOriginReflection {
		t.Errorf("expected CategoryCORSOriginReflection, got %s", f.Category)
	}
	if f.Severity != SeverityHigh {
		t.Errorf("expected SeverityHigh with credentials allowed, got %s", f.Severity)
	}
}

// Test 8: .env exposed
func TestEnvExposed(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.env" {
			w.Header().Set("Content-Type", "text/plain")
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, "APP_ENV=production\nDB_PASS=TEST_SECRET_VALUE\nAWS_KEY=AKIA123\n")
			return
		}
		http.NotFound(w, r)
	}))
	defer server.Close()

	client := NewClient(ClientOptions{HTTPClient: server.Client()})
	findings := AuditSensitiveEndpoints(context.Background(), client, server.URL, []string{"/.env"})

	var foundEnv bool
	for _, f := range findings {
		if f.Category == CategoryEnvExposure && f.Severity == SeverityCritical {
			foundEnv = true
			if strings.Contains(f.Evidence, "TEST_SECRET_VALUE") {
				t.Errorf("sensitive env values must NOT appear in evidence: %s", f.Evidence)
			}
			break
		}
	}
	if !foundEnv {
		t.Errorf("expected CRITICAL env-exposure finding for exposed .env")
	}
}

// Test 9: .env protected (404/403)
func TestEnvProtected(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		fmt.Fprint(w, "Access Denied")
	}))
	defer server.Close()

	client := NewClient(ClientOptions{HTTPClient: server.Client()})
	findings := AuditSensitiveEndpoints(context.Background(), client, server.URL, []string{"/.env"})

	for _, f := range findings {
		if f.Category == CategoryEnvExposure {
			t.Errorf("protected .env (403) must not produce exposure finding: %+v", f)
		}
	}
}

// Test 10: .git/HEAD exposed
func TestGitHeadExposed(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.git/HEAD" {
			w.Header().Set("Content-Type", "text/plain")
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, "ref: refs/heads/main\n")
			return
		}
		http.NotFound(w, r)
	}))
	defer server.Close()

	client := NewClient(ClientOptions{HTTPClient: server.Client()})
	findings := AuditSensitiveEndpoints(context.Background(), client, server.URL, []string{"/.git/HEAD"})

	var foundGit bool
	for _, f := range findings {
		if f.Category == CategoryGitExposure && f.Severity == SeverityHigh {
			foundGit = true
			break
		}
	}
	if !foundGit {
		t.Errorf("expected git-metadata-exposure finding for exposed .git/HEAD")
	}
}

// Test 11: Swagger/OpenAPI exposure
func TestSwaggerOpenAPIExposure(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/openapi.json" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, `{"openapi":"3.0.0","info":{"title":"Felix Test API"}}`)
			return
		}
		http.NotFound(w, r)
	}))
	defer server.Close()

	client := NewClient(ClientOptions{HTTPClient: server.Client()})
	findings := AuditSensitiveEndpoints(context.Background(), client, server.URL, []string{"/openapi.json"})

	var foundDocs bool
	for _, f := range findings {
		if f.Category == CategoryAPIDocsExposure {
			foundDocs = true
			break
		}
	}
	if !foundDocs {
		t.Errorf("expected api-docs-exposure finding for public openapi.json")
	}
}

// Test 12: Actuator health endpoint
func TestActuatorHealthEndpoint(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/actuator/health" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, `{"status":"UP"}`)
			return
		}
		http.NotFound(w, r)
	}))
	defer server.Close()

	client := NewClient(ClientOptions{HTTPClient: server.Client()})
	findings := AuditSensitiveEndpoints(context.Background(), client, server.URL, []string{"/actuator/health"})

	var foundHealth bool
	for _, f := range findings {
		if f.Category == CategoryHealthExposure && f.Severity == SeverityInfo {
			foundHealth = true
			break
		}
	}
	if !foundHealth {
		t.Errorf("expected health-endpoint finding for /actuator/health")
	}
}

// Test 13: Metrics endpoint
func TestMetricsEndpoint(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/metrics" {
			w.Header().Set("Content-Type", "text/plain")
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, "# HELP http_requests_total Total requests\n# TYPE http_requests_total counter\nhttp_requests_total 100\n")
			return
		}
		http.NotFound(w, r)
	}))
	defer server.Close()

	client := NewClient(ClientOptions{HTTPClient: server.Client()})
	findings := AuditSensitiveEndpoints(context.Background(), client, server.URL, []string{"/metrics"})

	var foundMetrics bool
	for _, f := range findings {
		if f.Category == CategoryMetricsExposure {
			foundMetrics = true
			break
		}
	}
	if !foundMetrics {
		t.Errorf("expected metrics-exposure finding for /metrics")
	}
}

// Test 14: Security header detection
func TestSecurityHeaderDetection(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Provide only basic headers without CSP, X-Frame-Options, or Permissions-Policy
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "<html><body>Hello</body></html>")
	}))
	defer server.Close()

	client := NewClient(ClientOptions{HTTPClient: server.Client()})
	findings := AuditSecurityHeaders(context.Background(), client, server.URL)

	var foundCSP, foundFrame bool
	for _, f := range findings {
		if f.Category == CategoryMissingCSP {
			foundCSP = true
		}
		if f.Category == CategoryMissingXFrameOptions {
			foundFrame = true
		}
	}
	if !foundCSP || !foundFrame {
		t.Errorf("expected missing-csp and missing-x-frame-options findings, got: %+v", findings)
	}
}

// Test 15: HTTPS/HSTS handling
func TestHTTPSHSTSHandling(t *testing.T) {
	// 1. On HTTP target, HSTS must NOT be flagged as missing
	serverHTTP := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer serverHTTP.Close()

	client := NewClient(ClientOptions{HTTPClient: serverHTTP.Client()})
	findingsHTTP := AuditSecurityHeaders(context.Background(), client, serverHTTP.URL)

	for _, f := range findingsHTTP {
		if f.Category == CategoryMissingHSTS {
			t.Errorf("HSTS must NOT be reported as missing on HTTP URL")
		}
	}

	// 2. On HTTPS target, missing HSTS IS reported
	serverHTTPS := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer serverHTTPS.Close()

	clientHTTPS := NewClient(ClientOptions{HTTPClient: serverHTTPS.Client()})
	findingsHTTPS := AuditSecurityHeaders(context.Background(), clientHTTPS, serverHTTPS.URL)

	var foundHSTS bool
	for _, f := range findingsHTTPS {
		if f.Category == CategoryMissingHSTS {
			foundHSTS = true
			break
		}
	}
	if !foundHSTS {
		t.Errorf("expected missing-hsts on HTTPS URL")
	}
}

// Test 16: Endpoint deduplication
func TestEndpointDeduplication(t *testing.T) {
	d := NewDetector(nil)
	assets := []crawler.Asset{
		{
			URL:     "https://example.com/a.js",
			Content: []byte(`fetch("/api/users"); fetch("/api/users");`),
		},
		{
			URL:     "https://example.com/b.js",
			Content: []byte(`fetch("/api/users");`),
		},
	}

	discovered := d.DiscoverCandidateEndpoints("https://example.com", assets)
	count := 0
	for _, ep := range discovered {
		if ep == "/api/users" {
			count++
		}
	}
	if count != 1 {
		t.Errorf("expected exactly 1 instance of /api/users, got %d", count)
	}
}

// Test 17: Finding deduplication
func TestFindingDeduplication(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client := NewClient(ClientOptions{HTTPClient: server.Client()})
	f1 := AuditCORS(context.Background(), client, server.URL)
	f2 := AuditCORS(context.Background(), client, server.URL)

	if len(f1) == 0 || len(f2) == 0 {
		t.Fatalf("expected findings")
	}
	if f1[0].Fingerprint != f2[0].Fingerprint {
		t.Errorf("expected identical fingerprints for deduplication: %s vs %s", f1[0].Fingerprint, f2[0].Fingerprint)
	}
}

// Test 18: Response-size limit
func TestResponseSizeLimit(t *testing.T) {
	oversizedData := strings.Repeat("B", 1024*1024) // 1 MB
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(oversizedData))
	}))
	defer server.Close()

	client := NewClient(ClientOptions{
		HTTPClient:      server.Client(),
		MaxResponseSize: 32 * 1024, // 32 KB limit
	})

	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, server.URL, nil)
	resp, err := client.Do(context.Background(), req)

	if err != nil && err != ErrResponseTooLarge {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp != nil && int64(len(resp.Body)) > 32*1024 {
		t.Errorf("response body exceeded size limit: %d", len(resp.Body))
	}
}

// Test 19: HTTP 429 handling stops probing
func TestRateLimitHandling(t *testing.T) {
	var requestCount int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&requestCount, 1)
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer server.Close()

	client := NewClient(ClientOptions{HTTPClient: server.Client()})
	// Audit with multiple paths
	AuditSensitiveEndpoints(context.Background(), client, server.URL, []string{"/p1", "/p2", "/p3", "/p4"})

	// Scanner must halt on 429 rather than bombarding all paths
	count := atomic.LoadInt32(&requestCount)
	if count > 1 {
		t.Errorf("scanner must halt on 429; sent %d requests", count)
	}
}

// Test 20: Cross-origin scope enforcement (redirects stopped cross-origin)
func TestCrossOriginScopeEnforcement(t *testing.T) {
	targetServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Attempt redirect to different external host
		http.Redirect(w, r, "http://external-unauthorized.invalid/evil", http.StatusFound)
	}))
	defer targetServer.Close()

	client := NewClient(ClientOptions{})
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, targetServer.URL, nil)
	resp, err := client.Do(context.Background(), req)

	if err != nil {
		t.Fatalf("client.Do failed: %v", err)
	}
	// Verify it did not follow to the external host; stopped on the redirect response
	if resp.StatusCode != http.StatusFound {
		t.Errorf("expected client to stop at redirect status 302, got %d", resp.StatusCode)
	}
}

// Test 21: Redaction of evidence
func TestRedaction(t *testing.T) {
	rawEvidence := "password=mysecretpassword123; token: super-secret-token; eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.sig"
	redacted := RedactEvidence(rawEvidence)

	if strings.Contains(redacted, "mysecretpassword123") {
		t.Errorf("raw password leaked in evidence: %s", redacted)
	}
	if strings.Contains(redacted, "super-secret-token") {
		t.Errorf("raw token leaked in evidence: %s", redacted)
	}
	if strings.Contains(redacted, "eyJhbGciOiJIUzI1NiJ9") {
		t.Errorf("raw JWT leaked in evidence: %s", redacted)
	}
}

// Test 22: Concurrent detector safety
func TestConcurrentDetectorSafety(t *testing.T) {
	d := NewDetector(nil)
	var wg sync.WaitGroup

	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			assets := []crawler.Asset{
				{
					URL:     fmt.Sprintf("https://example.com/asset%d.js", id),
					Content: []byte(fmt.Sprintf(`const ep = "/api/v1/resource%d";`, id)),
				},
			}
			eps := d.DiscoverCandidateEndpoints("https://example.com", assets)
			if len(eps) == 0 {
				t.Errorf("expected candidate endpoint in worker %d", id)
			}
		}(i)
	}
	wg.Wait()
}
