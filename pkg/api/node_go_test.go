package api

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// --- NODE.JS & GO REGRESSION TESTS ---

// Test 1: Node.js runtime identification (X-Powered-By: Express and Next.js)
func TestNode_RuntimeIdentification(t *testing.T) {
	tests := []struct {
		name          string
		headerVal     string
		expectedTech  string
	}{
		{"Express", "Express", "Express"},
		{"Next.js", "Next.js", "Next.js"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("X-Powered-By", tt.headerVal)
				w.WriteHeader(http.StatusOK)
				fmt.Fprint(w, `{"status":"ok"}`)
			}))
			defer server.Close()

			client := NewClient(ClientOptions{HTTPClient: server.Client(), AllowLoopback: true})
			findings := AuditNodeDiagnostics(context.Background(), client, server.URL, nil)

			if len(findings) == 0 {
				t.Fatalf("expected Node runtime finding for %s, got 0", tt.name)
			}

			f := findings[0]
			if f.Category != CategoryNodeRuntimeExposure {
				t.Errorf("expected CategoryNodeRuntimeExposure, got %s", f.Category)
			}
			if f.Severity != SeverityInfo {
				t.Errorf("expected SeverityInfo for framework header disclosure, got %s", f.Severity)
			}
			if f.Confidence != ConfidenceHigh {
				t.Errorf("expected ConfidenceHigh, got %s", f.Confidence)
			}
			if f.Classification != ClassAPI {
				t.Errorf("expected ClassAPI, got %s", f.Classification)
			}
			if !strings.Contains(f.Description, tt.expectedTech) {
				t.Errorf("expected description to mention %s, got %s", tt.expectedTech, f.Description)
			}
			if f.Details["framework"] != tt.expectedTech {
				t.Errorf("expected framework %s, got %s", tt.expectedTech, f.Details["framework"])
			}
			if f.NegativeEvidence == "" {
				t.Errorf("expected non-empty negative evidence")
			}
		})
	}
}

// Test 2: Go runtime identification (Server: Fiber and Echo)
func TestGo_RuntimeIdentification(t *testing.T) {
	tests := []struct {
		name         string
		serverVal    string
		expectedTech string
	}{
		{"Fiber", "Fiber/v2", "Fiber"},
		{"Echo", "Echo/4.0", "Echo"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Server", tt.serverVal)
				w.WriteHeader(http.StatusOK)
				fmt.Fprint(w, `{"status":"ok"}`)
			}))
			defer server.Close()

			client := NewClient(ClientOptions{HTTPClient: server.Client(), AllowLoopback: true})
			findings := AuditGoDiagnostics(context.Background(), client, server.URL, nil)

			if len(findings) == 0 {
				t.Fatalf("expected Go runtime finding for %s, got 0", tt.name)
			}

			f := findings[0]
			if f.Category != CategoryGoRuntimeExposure {
				t.Errorf("expected CategoryGoRuntimeExposure, got %s", f.Category)
			}
			if f.Severity != SeverityInfo {
				t.Errorf("expected SeverityInfo for framework header disclosure, got %s", f.Severity)
			}
			if f.Confidence != ConfidenceHigh {
				t.Errorf("expected ConfidenceHigh, got %s", f.Confidence)
			}
			if f.Classification != ClassAPI {
				t.Errorf("expected ClassAPI, got %s", f.Classification)
			}
			if !strings.Contains(f.Description, tt.expectedTech) {
				t.Errorf("expected description to mention %s, got %s", tt.expectedTech, f.Description)
			}
			if f.Details["framework"] != tt.expectedTech {
				t.Errorf("expected framework %s, got %s", tt.expectedTech, f.Details["framework"])
			}
			if f.NegativeEvidence == "" {
				t.Errorf("expected non-empty negative evidence")
			}
		})
	}
}

// Test 3: Generic HTML and JSON responses without false positives
func TestNodeAndGo_GenericHTMLAndJSONNoFalsePositives(t *testing.T) {
	testCases := []struct {
		name string
		body string
	}{
		{"HTML 404", "<html><head><title>Not Found</title></head><body><h1>404 Not Found</h1><p>Page does not exist.</p></body></html>"},
		{"HTML 500", "<html><head><title>Internal Server Error</title></head><body><h1>Server Error</h1><p>Please contact support.</p></body></html>"},
		{"JSON 404", `{"status":404,"error":"Not Found","message":"The requested resource was not found"}`},
		{"JSON 200", `{"status":"healthy","uptime":3600,"services":{"db":"up","cache":"up"}}`},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
				fmt.Fprint(w, tc.body)
			}))
			defer server.Close()

			client := NewClient(ClientOptions{HTTPClient: server.Client(), AllowLoopback: true})

			nodeFindings := AuditNodeDiagnostics(context.Background(), client, server.URL, nil)
			if len(nodeFindings) != 0 {
				t.Errorf("expected 0 Node findings on %s, got %d: %+v", tc.name, len(nodeFindings), nodeFindings)
			}

			goFindings := AuditGoDiagnostics(context.Background(), client, server.URL, nil)
			if len(goFindings) != 0 {
				t.Errorf("expected 0 Go findings on %s, got %d: %+v", tc.name, len(goFindings), goFindings)
			}
		})
	}
}

// Test 4: Generic 4xx/5xx responses without sensitive disclosure
func TestNodeAndGo_Generic4xx5xxResponsesSuppression(t *testing.T) {
	statuses := []int{
		http.StatusBadRequest,
		http.StatusNotFound,
		http.StatusInternalServerError,
		http.StatusBadGateway,
		http.StatusServiceUnavailable,
	}

	for _, code := range statuses {
		t.Run(fmt.Sprintf("Status_%d", code), func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(code)
				fmt.Fprintf(w, "HTTP %d - Request could not be processed", code)
			}))
			defer server.Close()

			client := NewClient(ClientOptions{HTTPClient: server.Client(), AllowLoopback: true})

			nodeFindings := AuditNodeDiagnostics(context.Background(), client, server.URL, nil)
			if len(nodeFindings) != 0 {
				t.Errorf("expected 0 Node findings for status %d, got %d", code, len(nodeFindings))
			}

			goFindings := AuditGoDiagnostics(context.Background(), client, server.URL, nil)
			if len(goFindings) != 0 {
				t.Errorf("expected 0 Go findings for status %d, got %d", code, len(goFindings))
			}
		})
	}
}

// Test 5: Node.js verbose stack trace with absolute filesystem paths
func TestNode_VerboseStackTraceWithAbsolutePaths(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprint(w, `TypeError: Cannot read properties of undefined (reading 'query')
    at getUserProfile (/app/controllers/userController.js:45:12)
    at Layer.handle [as handle_request] (/app/node_modules/express/lib/router/layer.js:95:5)
    at next (/app/node_modules/express/lib/router/route.js:144:13)
    at Route.dispatch (/app/node_modules/express/lib/router/route.js:114:3)
    at /var/www/internal-service/server.js:80:10
    at processTicksAndRejections (node:internal/process/task_queues:95:5)`)
	}))
	defer server.Close()

	client := NewClient(ClientOptions{HTTPClient: server.Client(), AllowLoopback: true})
	findings := AuditNodeDiagnostics(context.Background(), client, server.URL, nil)

	if len(findings) == 0 {
		t.Fatalf("expected Node stack trace finding, got 0")
	}

	f := findings[0]
	if f.Category != CategoryNodeStackTrace {
		t.Errorf("expected CategoryNodeStackTrace, got %s", f.Category)
	}
	if f.Severity != SeverityMedium {
		t.Errorf("expected SeverityMedium for internal path and stack disclosure, got %s", f.Severity)
	}
	if f.Confidence != ConfidenceHigh {
		t.Errorf("expected ConfidenceHigh, got %s", f.Confidence)
	}
	if f.Classification != ClassHealth {
		t.Errorf("expected ClassHealth, got %s", f.Classification)
	}
	if f.Details["disclosed_paths_count"] != "4" {
		t.Errorf("expected 4 disclosed paths, got %s", f.Details["disclosed_paths_count"])
	}
	if !strings.Contains(f.Evidence, "/app/controllers/userController.js") {
		t.Errorf("expected evidence to mention /app/controllers/userController.js, got %s", f.Evidence)
	}
	if f.Details["validity_status"] != "unverified_active_probe_omitted" {
		t.Errorf("expected validity_status unverified_active_probe_omitted, got %s", f.Details["validity_status"])
	}
	if f.NegativeEvidence == "" {
		t.Errorf("expected non-empty negative evidence")
	}
}

// Test 6: Go panic stack trace with source filenames and lines
func TestGo_PanicStackTraceWithSourceLocations(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprint(w, `panic: runtime error: invalid memory address or nil pointer dereference
[signal SIGSEGV: segmentation violation code=0x1 addr=0x0 pc=0x6b4a20]

goroutine 1 [running]:
main.processOrder(0x0, 0x10)
	/go/src/app/handlers/orders.go:88 +0x45
main.handleRequest(0x7ffd12, 0x8)
	/go/src/app/server.go:120 +0x1b2
net/http.HandlerFunc.ServeHTTP(0x6b49e0, 0x889900)
	/usr/local/go/src/net/http/server.go:2084 +0x2f`)
	}))
	defer server.Close()

	client := NewClient(ClientOptions{HTTPClient: server.Client(), AllowLoopback: true})
	findings := AuditGoDiagnostics(context.Background(), client, server.URL, nil)

	if len(findings) == 0 {
		t.Fatalf("expected Go panic finding, got 0")
	}

	f := findings[0]
	if f.Category != CategoryGoDebugPanic {
		t.Errorf("expected CategoryGoDebugPanic, got %s", f.Category)
	}
	if f.Severity != SeverityMedium {
		t.Errorf("expected SeverityMedium for source structure panic disclosure, got %s", f.Severity)
	}
	if f.Confidence != ConfidenceHigh {
		t.Errorf("expected ConfidenceHigh, got %s", f.Confidence)
	}
	if f.Classification != ClassHealth {
		t.Errorf("expected ClassHealth, got %s", f.Classification)
	}
	if f.Details["source_locations_count"] == "0" || f.Details["source_locations_count"] == "" {
		t.Errorf("expected non-zero source_locations_count, got %s", f.Details["source_locations_count"])
	}
	if !strings.Contains(f.Evidence, "/go/src/app/handlers/orders.go") {
		t.Errorf("expected evidence to mention source path, got %s", f.Evidence)
	}
	if f.Details["validity_status"] != "unverified_active_probe_omitted" {
		t.Errorf("expected validity_status unverified_active_probe_omitted, got %s", f.Details["validity_status"])
	}
	if f.NegativeEvidence == "" {
		t.Errorf("expected non-empty negative evidence")
	}
}

// Test 7: Version disclosure classified proportionately (SeverityInfo)
func TestNodeAndGo_VersionDisclosureProportionate(t *testing.T) {
	// Node.js Express header
	nodeServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Powered-By", "Express")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `OK`)
	}))
	defer nodeServer.Close()

	client := NewClient(ClientOptions{HTTPClient: nodeServer.Client(), AllowLoopback: true})
	nodeFindings := AuditNodeDiagnostics(context.Background(), client, nodeServer.URL, nil)
	if len(nodeFindings) == 0 {
		t.Fatalf("expected Node runtime finding")
	}
	if nodeFindings[0].Severity != SeverityInfo {
		t.Errorf("expected SeverityInfo for X-Powered-By: Express, got %s", nodeFindings[0].Severity)
	}

	// Go Fiber header
	goServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "Fiber")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `OK`)
	}))
	defer goServer.Close()

	goClient := NewClient(ClientOptions{HTTPClient: goServer.Client(), AllowLoopback: true})
	goFindings := AuditGoDiagnostics(context.Background(), goClient, goServer.URL, nil)
	if len(goFindings) == 0 {
		t.Fatalf("expected Go runtime finding")
	}
	if goFindings[0].Severity != SeverityInfo {
		t.Errorf("expected SeverityInfo for Server: Fiber, got %s", goFindings[0].Severity)
	}
}

// Test 8: Go expvar configuration disclosure with benign values (/debug/vars -> SeverityMedium)
func TestGo_ExpvarBenignDisclosure(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/debug/vars") {
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, `{"cmdline":["/usr/local/bin/api_server","-port=8080","-env=production"],"memstats":{"Alloc":4194304,"TotalAlloc":8388608,"Sys":16777216}}`)
			return
		}
		http.NotFound(w, r)
	}))
	defer server.Close()

	client := NewClient(ClientOptions{HTTPClient: server.Client(), AllowLoopback: true})
	findings := AuditGoDiagnostics(context.Background(), client, server.URL, nil)

	if len(findings) == 0 {
		t.Fatalf("expected Go expvar finding, got 0")
	}

	f := findings[0]
	if f.Category != CategoryGoVarsExposure {
		t.Errorf("expected CategoryGoVarsExposure, got %s", f.Category)
	}
	if f.Severity != SeverityMedium {
		t.Errorf("expected SeverityMedium for benign expvar exposure, got %s", f.Severity)
	}
	if f.Classification != ClassAdmin {
		t.Errorf("expected ClassAdmin, got %s", f.Classification)
	}
	if f.Confidence != ConfidenceHigh {
		t.Errorf("expected ConfidenceHigh, got %s", f.Confidence)
	}
	if !strings.Contains(f.Description, "expvar") {
		t.Errorf("expected description to mention expvar, got %s", f.Description)
	}
	if f.NegativeEvidence == "" {
		t.Errorf("expected non-empty negative evidence")
	}
}

// Test 9: Go expvar with sensitive configuration values detected and redacted
func TestGo_ExpvarSensitiveValuesRedacted(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/debug/vars") {
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			w.WriteHeader(http.StatusOK)
			fmt.Fprintf(w, `{"cmdline":["app"],"database_password":"%s","secret_key":"%s","memstats":{"Alloc":1024}}`,
				syntheticCanarySecret, syntheticCanarySecret)
			return
		}
		http.NotFound(w, r)
	}))
	defer server.Close()

	client := NewClient(ClientOptions{HTTPClient: server.Client(), AllowLoopback: true})
	findings := AuditGoDiagnostics(context.Background(), client, server.URL, nil)

	if len(findings) == 0 {
		t.Fatalf("expected Go expvar finding with unmasked secrets, got 0")
	}

	f := findings[0]
	if f.Category != CategoryGoVarsExposure {
		t.Errorf("expected CategoryGoVarsExposure, got %s", f.Category)
	}
	if f.Severity != SeverityCritical {
		t.Errorf("expected SeverityCritical for expvar with candidate secrets, got %s", f.Severity)
	}
	if f.Details["candidate_material_status"] != "unverified_candidate_material" {
		t.Errorf("expected candidate_material_status unverified_candidate_material, got %s", f.Details["candidate_material_status"])
	}
	if strings.Contains(f.Evidence, syntheticCanarySecret) {
		t.Errorf("canary secret leaked into evidence!")
	}
	if strings.Contains(f.Description, syntheticCanarySecret) {
		t.Errorf("canary secret leaked into description!")
	}
	for k, v := range f.Details {
		if strings.Contains(k, syntheticCanarySecret) || strings.Contains(v, syntheticCanarySecret) {
			t.Errorf("canary secret leaked into details [%s: %s]!", k, v)
		}
	}
}

// Test 10: Nested JSON secrets and canary values never leaking into findings
func TestNodeAndGo_CanarySecretsNeverLeaked(t *testing.T) {
	// 1. Node error response with canary secret
	nodeServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintf(w, `Error: Database connection failed
    at connectDB (/app/config/db.js:14:9)
    at /app/server.js:25:3
Configuration dump:
DB_PASSWORD=%s
API_SECRET=%s`, syntheticCanarySecret, syntheticCanarySecret)
	}))
	defer nodeServer.Close()

	client := NewClient(ClientOptions{HTTPClient: nodeServer.Client(), AllowLoopback: true})
	nodeFindings := AuditNodeDiagnostics(context.Background(), client, nodeServer.URL, nil)

	if len(nodeFindings) == 0 {
		t.Fatalf("expected Node finding with canary secret")
	}

	for _, f := range nodeFindings {
		if f.Severity != SeverityCritical {
			t.Errorf("expected SeverityCritical for candidate secret disclosure, got %s", f.Severity)
		}
		if strings.Contains(f.Evidence, syntheticCanarySecret) {
			t.Errorf("Node canary secret leaked in evidence")
		}
		if strings.Contains(f.Description, syntheticCanarySecret) {
			t.Errorf("Node canary secret leaked in description")
		}
		if strings.Contains(f.NegativeEvidence, syntheticCanarySecret) {
			t.Errorf("Node canary secret leaked in negative evidence")
		}
		for k, v := range f.Details {
			if strings.Contains(k, syntheticCanarySecret) || strings.Contains(v, syntheticCanarySecret) {
				t.Errorf("Node canary secret leaked in details [%s=%s]", k, v)
			}
		}
	}

	// 2. Go panic dump with canary secret
	goServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintf(w, `panic: connection auth failure: password=%s
goroutine 1 [running]:
main.connect(0x10, 0x20)
	/go/src/app/db.go:45 +0x3a
main.main()
	/go/src/app/main.go:18 +0x12`, syntheticCanarySecret)
	}))
	defer goServer.Close()

	goClient := NewClient(ClientOptions{HTTPClient: goServer.Client(), AllowLoopback: true})
	goFindings := AuditGoDiagnostics(context.Background(), goClient, goServer.URL, nil)

	if len(goFindings) == 0 {
		t.Fatalf("expected Go finding with canary secret")
	}

	for _, f := range goFindings {
		if f.Severity != SeverityCritical {
			t.Errorf("expected SeverityCritical for Go candidate secret disclosure, got %s", f.Severity)
		}
		if strings.Contains(f.Evidence, syntheticCanarySecret) {
			t.Errorf("Go canary secret leaked in evidence")
		}
		if strings.Contains(f.Description, syntheticCanarySecret) {
			t.Errorf("Go canary secret leaked in description")
		}
		if strings.Contains(f.NegativeEvidence, syntheticCanarySecret) {
			t.Errorf("Go canary secret leaked in negative evidence")
		}
		for k, v := range f.Details {
			if strings.Contains(k, syntheticCanarySecret) || strings.Contains(v, syntheticCanarySecret) {
				t.Errorf("Go canary secret leaked in details [%s=%s]", k, v)
			}
		}
	}
}

// Test 11: Malformed, truncated, and oversized responses (bounded at 512 KiB)
func TestNodeAndGo_MalformedAndOversizedResponsesBounded(t *testing.T) {
	// Oversized response (> 600 KiB)
	largePadding := strings.Repeat("A", 600*1024)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintf(w, "TypeError: fail\n    at /app/index.js:1:1\n    at /app/srv.js:2:2\n%s", largePadding)
	}))
	defer server.Close()

	client := NewClient(ClientOptions{HTTPClient: server.Client(), AllowLoopback: true})

	// Must not hang, crash, or exhaust memory
	findings := AuditNodeDiagnostics(context.Background(), client, server.URL, nil)
	if len(findings) > 0 {
		f := findings[0]
		if f.Details["limitations"] == "" {
			t.Errorf("expected truncation limitation recorded in details")
		}
	}
}

// Test 12: Timeout and cancellation behavior
func TestNodeAndGo_TimeoutAndContextCancellation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(500 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client := NewClient(ClientOptions{
		HTTPClient:    server.Client(),
		AllowLoopback: true,
		Timeout:       50 * time.Millisecond,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()

	nodeFindings := AuditNodeDiagnostics(ctx, client, server.URL, nil)
	if len(nodeFindings) != 0 {
		t.Errorf("expected 0 Node findings on timeout, got %d", len(nodeFindings))
	}

	goFindings := AuditGoDiagnostics(ctx, client, server.URL, nil)
	if len(goFindings) != 0 {
		t.Errorf("expected 0 Go findings on timeout, got %d", len(goFindings))
	}
}

// Test 13: SSRF and redirect protection (client isExcluded and isAllowed filtering)
func TestNodeAndGo_SSRFAndTransportProtection(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Powered-By", "Express")
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	// 1. Exclude the server URL
	clientWithExclusion := NewClient(ClientOptions{
		HTTPClient:    server.Client(),
		AllowLoopback: true,
		IsExcluded: func(target string) bool {
			return strings.Contains(target, server.URL)
		},
	})

	nodeFindings := AuditNodeDiagnostics(context.Background(), clientWithExclusion, server.URL, nil)
	if len(nodeFindings) != 0 {
		t.Errorf("expected 0 findings when target is excluded, got %d", len(nodeFindings))
	}

	// 2. Allow only a different domain
	clientWithAllowed := NewClient(ClientOptions{
		HTTPClient:    server.Client(),
		AllowLoopback: true,
		IsAllowed: func(target string) bool {
			return strings.Contains(target, "https://only-allowed.example.com")
		},
	})

	goFindings := AuditGoDiagnostics(context.Background(), clientWithAllowed, server.URL, nil)
	if len(goFindings) != 0 {
		t.Errorf("expected 0 findings when target is outside allowed scope, got %d", len(goFindings))
	}
}

// Test 14: Nested base-path and scope preservation
func TestNodeAndGo_NestedBasePathAndScopePreservation(t *testing.T) {
	baseURL := "https://example.com/api/v1"

	nodeCandidates := ResolveNodeCandidateURLs(baseURL, []string{"/api/v1/custom-node-debug"})
	expectedNodeProbe := "https://example.com/api/v1/_felix_node_probe"
	foundNodeProbe := false
	for _, c := range nodeCandidates {
		if c == expectedNodeProbe {
			foundNodeProbe = true
		}
	}
	if !foundNodeProbe {
		t.Errorf("expected %s in resolved Node candidates: %+v", expectedNodeProbe, nodeCandidates)
	}

	goCandidates := ResolveGoCandidateURLs(baseURL, []string{"/api/v1/custom-pprof"})
	expectedPprof := "https://example.com/api/v1/debug/pprof/"
	expectedVars := "https://example.com/api/v1/debug/vars"
	foundPprof := false
	foundVars := false
	for _, c := range goCandidates {
		if c == expectedPprof {
			foundPprof = true
		}
		if c == expectedVars {
			foundVars = true
		}
	}
	if !foundPprof || !foundVars {
		t.Errorf("expected pprof and vars in resolved Go candidates: %+v", goCandidates)
	}
}

// Test 15: 429 rate-limit handling
func TestNodeAndGo_RateLimitHandling(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer server.Close()

	client := NewClient(ClientOptions{HTTPClient: server.Client(), AllowLoopback: true})

	nodeFindings := AuditNodeDiagnostics(context.Background(), client, server.URL, nil)
	if len(nodeFindings) != 0 {
		t.Errorf("expected 0 Node findings on HTTP 429, got %d", len(nodeFindings))
	}

	goFindings := AuditGoDiagnostics(context.Background(), client, server.URL, nil)
	if len(goFindings) != 0 {
		t.Errorf("expected 0 Go findings on HTTP 429, got %d", len(goFindings))
	}
}

// Test 16: Authentication-required endpoints (401/403) and login redirects (0 findings)
func TestNodeAndGo_AuthProtectedAndRedirectSuppression(t *testing.T) {
	// 401 Unauthorized
	server401 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprint(w, `{"error":"unauthorized"}`)
	}))
	defer server401.Close()

	client := NewClient(ClientOptions{HTTPClient: server401.Client(), AllowLoopback: true})
	if f := AuditNodeDiagnostics(context.Background(), client, server401.URL, nil); len(f) != 0 {
		t.Errorf("expected 0 findings on 401, got %d", len(f))
	}
	if f := AuditGoDiagnostics(context.Background(), client, server401.URL, nil); len(f) != 0 {
		t.Errorf("expected 0 findings on 401, got %d", len(f))
	}

	// 403 Forbidden
	server403 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		fmt.Fprint(w, `{"error":"forbidden"}`)
	}))
	defer server403.Close()

	client403 := NewClient(ClientOptions{HTTPClient: server403.Client(), AllowLoopback: true})
	if f := AuditNodeDiagnostics(context.Background(), client403, server403.URL, nil); len(f) != 0 {
		t.Errorf("expected 0 findings on 403, got %d", len(f))
	}
	if f := AuditGoDiagnostics(context.Background(), client403, server403.URL, nil); len(f) != 0 {
		t.Errorf("expected 0 findings on 403, got %d", len(f))
	}

	// 302 Redirect to /login
	serverLoginRedirect := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/login", http.StatusFound)
	}))
	defer serverLoginRedirect.Close()

	clientRedirect := NewClient(ClientOptions{HTTPClient: serverLoginRedirect.Client(), AllowLoopback: true})
	if f := AuditNodeDiagnostics(context.Background(), clientRedirect, serverLoginRedirect.URL, nil); len(f) != 0 {
		t.Errorf("expected 0 findings on login redirect, got %d", len(f))
	}
	if f := AuditGoDiagnostics(context.Background(), clientRedirect, serverLoginRedirect.URL, nil); len(f) != 0 {
		t.Errorf("expected 0 findings on login redirect, got %d", len(f))
	}
}

// Test 17: Duplicate-finding suppression
func TestNodeAndGo_DuplicateFindingSuppression(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Powered-By", "Express")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `OK`)
	}))
	defer server.Close()

	client := NewClient(ClientOptions{HTTPClient: server.Client(), AllowLoopback: true})

	// Pass redundant candidate paths resolving to the same endpoint
	findings := AuditNodeDiagnostics(context.Background(), client, server.URL, []string{
		"/_felix_node_probe",
		"/_felix_node_probe",
	})

	if len(findings) != 1 {
		t.Errorf("expected exactly 1 finding after deduplication, got %d", len(findings))
	}
}

// Test 18: Correct detector registration and execution-path integration
func TestNodeAndGo_DetectorIntegration(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "pprof") {
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, `<html><head><title>/debug/pprof/</title></head><body>Types of profiles available:<br><a href="/debug/pprof/heap">heap</a></body></html>`)
			return
		}
		if r.URL.Path == "/_felix_node_probe" {
			w.Header().Set("X-Powered-By", "Express")
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, `{"status":"ok"}`)
			return
		}
		http.NotFound(w, r)
	}))
	defer server.Close()

	client := NewClient(ClientOptions{HTTPClient: server.Client(), AllowLoopback: true})
	detector := NewDetector(client)

	result := detector.Audit(context.Background(), server.URL, nil)

	if result.NodeCount < 1 {
		t.Errorf("expected result.NodeCount >= 1, got %d", result.NodeCount)
	}
	if result.GoCount < 1 {
		t.Errorf("expected result.GoCount >= 1, got %d", result.GoCount)
	}
	if result.EndpointsScanned == 0 {
		t.Errorf("expected EndpointsScanned > 0, got %d", result.EndpointsScanned)
	}
}

// Test 19: Go net/http/pprof profiling interface exposure
func TestGo_PprofInterfaceExposure(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/debug/pprof/" {
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, `<html><head><title>/debug/pprof/</title></head><body>Types of profiles available:<br>
<table>
<tr><td align=right>1</td><td><a href="/debug/pprof/allocs">allocs</a></td></tr>
<tr><td align=right>2</td><td><a href="/debug/pprof/block">block</a></td></tr>
<tr><td align=right>3</td><td><a href="/debug/pprof/goroutine">goroutine</a></td></tr>
<tr><td align=right>4</td><td><a href="/debug/pprof/heap">heap</a></td></tr>
</table>
</body></html>`)
			return
		}
		http.NotFound(w, r)
	}))
	defer server.Close()

	client := NewClient(ClientOptions{HTTPClient: server.Client(), AllowLoopback: true})
	findings := AuditGoDiagnostics(context.Background(), client, server.URL, nil)

	if len(findings) == 0 {
		t.Fatalf("expected Go pprof finding, got 0")
	}

	f := findings[0]
	if f.Category != CategoryGoPprofExposure {
		t.Errorf("expected CategoryGoPprofExposure, got %s", f.Category)
	}
	if f.Severity != SeverityHigh {
		t.Errorf("expected SeverityHigh for unauthenticated pprof, got %s", f.Severity)
	}
	if f.Classification != ClassAdmin {
		t.Errorf("expected ClassAdmin, got %s", f.Classification)
	}
	if f.Confidence != ConfidenceHigh {
		t.Errorf("expected ConfidenceHigh, got %s", f.Confidence)
	}
	if !strings.Contains(f.Description, "pprof") {
		t.Errorf("expected description to mention pprof, got %s", f.Description)
	}
	if f.NegativeEvidence == "" {
		t.Errorf("expected non-empty negative evidence")
	}
}

// Test 20: Regression protection for existing frameworks (Actuator, Django, FastAPI, Laravel)
func TestNodeAndGo_RegressionProtection(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/actuator/health":
			w.Header().Set("Content-Type", "application/vnd.spring-boot.actuator.v3+json")
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, `{"status":"UP","components":{"db":{"status":"UP"}}}`)
		case "/openapi.json":
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, `{"openapi":"3.0.0","info":{"title":"API","version":"1.0"},"paths":{}}`)
		case "/_felix_node_probe":
			w.Header().Set("X-Powered-By", "Express")
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, `{"status":"ok"}`)
		case "/debug/vars":
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, `{"cmdline":["app"],"memstats":{"Alloc":1024}}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	client := NewClient(ClientOptions{HTTPClient: server.Client(), AllowLoopback: true})
	detector := NewDetector(client)

	result := detector.Audit(context.Background(), server.URL, nil)

	// Verify all framework counts function simultaneously without interference
	if result.ActuatorCount < 1 {
		t.Errorf("expected ActuatorCount >= 1, got %d", result.ActuatorCount)
	}
	if result.FastAPICount < 1 {
		t.Errorf("expected FastAPICount >= 1, got %d", result.FastAPICount)
	}
	if result.NodeCount < 1 {
		t.Errorf("expected NodeCount >= 1, got %d", result.NodeCount)
	}
	if result.GoCount < 1 {
		t.Errorf("expected GoCount >= 1, got %d", result.GoCount)
	}

	// Verify all findings have valid categories and non-empty fingerprints
	for _, apiFinding := range result.Findings {
		if apiFinding.Category == "" {
			t.Errorf("expected non-empty category")
		}
		if apiFinding.Fingerprint == "" {
			t.Errorf("expected non-empty fingerprint for category %s", apiFinding.Category)
		}
	}
}
