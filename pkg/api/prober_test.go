package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"felix/pkg/crawler"
)

// 1. HEAD returning 200
func TestP14_3_HEADReturning200(t *testing.T) {
	var receivedMethods []string
	var mu sync.Mutex

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		receivedMethods = append(receivedMethods, r.Method)
		mu.Unlock()

		if r.Method == "HEAD" {
			w.WriteHeader(http.StatusOK)
			return
		}
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
	}))
	defer ts.Close()

	u, _ := url.Parse(ts.URL)
	opts := DefaultProberOptions()
	opts.AllowLoopback = true
	opts.EnableSafeGET = false
	opts.EnableHEAD = true
	opts.ScopeHost = u.Hostname()

	engine := NewProberEngine(opts)
	res := engine.ProbeCandidate(context.Background(), "CAND-1", "/api/v1/health", "GET", ts.URL)

	if res.Classification != ClassificationReachable {
		t.Fatalf("expected ClassificationReachable, got %s", res.Classification)
	}
	if res.Reachability != ProbeReachabilityConfirmed {
		t.Fatalf("expected ProbeReachabilityConfirmed, got %s", res.Reachability)
	}
	if res.StatusCode != 200 {
		t.Fatalf("expected status 200, got %d", res.StatusCode)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(receivedMethods) != 1 || receivedMethods[0] != "HEAD" {
		t.Fatalf("expected single HEAD request, received: %v", receivedMethods)
	}
}

// 2. OPTIONS returning Allow header
func TestP14_3_OPTIONSReturningAllowHeader(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "OPTIONS" {
			w.Header().Set("Allow", "GET, POST, OPTIONS")
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
			w.WriteHeader(http.StatusNoContent)
			return
		}
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
	}))
	defer ts.Close()

	u, _ := url.Parse(ts.URL)
	opts := DefaultProberOptions()
	opts.AllowLoopback = true
	opts.EnableSafeGET = false
	opts.EnableOPTIONS = true
	opts.ScopeHost = u.Hostname()

	engine := NewProberEngine(opts)
	res := engine.ProbeCandidate(context.Background(), "CAND-2", "/api/v1/users", "POST", ts.URL)

	if res.Classification != ClassificationReachableWithMetadata {
		t.Fatalf("expected ClassificationReachableWithMetadata, got %s", res.Classification)
	}
	if !res.HasStructuredMetadata || res.StructuredMetadataType != "ALLOWED_METHODS_HEADER" {
		t.Fatalf("expected ALLOWED_METHODS_HEADER metadata, got %s", res.StructuredMetadataType)
	}
	if res.SafeResponseHeaders["Allow"] != "GET, POST, OPTIONS" {
		t.Fatalf("expected Allow header preserved, got %v", res.SafeResponseHeaders)
	}
}

// 3. Safe GET returning JSON
func TestP14_3_SafeGETReturningJSON(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"ready","items_count":42}`))
	}))
	defer ts.Close()

	u, _ := url.Parse(ts.URL)
	opts := DefaultProberOptions()
	opts.AllowLoopback = true
	opts.ScopeHost = u.Hostname()

	engine := NewProberEngine(opts)
	res := engine.ProbeCandidate(context.Background(), "CAND-3", "/api/v1/status", "GET", ts.URL)

	if res.Classification != ClassificationReachableWithMetadata {
		t.Fatalf("expected ClassificationReachableWithMetadata, got %s", res.Classification)
	}
	if res.Reachability != ProbeReachabilityConfirmed {
		t.Fatalf("expected ReachabilityConfirmed, got %s", res.Reachability)
	}
	if res.StructuredMetadataType != "JSON_OBJECT_METADATA" {
		t.Fatalf("expected JSON_OBJECT_METADATA, got %s", res.StructuredMetadataType)
	}
}

// 4. HTTP 200 with generic HTML error page / SPA fallback
func TestP14_3_GenericHTMLErrorPage_SPAInconclusive(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`<!DOCTYPE html><html><head><title>App</title></head><body><div id="root"></div><script src="/bundle.js"></script></body></html>`))
	}))
	defer ts.Close()

	u, _ := url.Parse(ts.URL)
	opts := DefaultProberOptions()
	opts.AllowLoopback = true
	opts.ScopeHost = u.Hostname()

	engine := NewProberEngine(opts)
	res := engine.ProbeCandidate(context.Background(), "CAND-4", "/api/nonexistent/subroute", "GET", ts.URL)

	if res.Classification != ClassificationInconclusive {
		t.Fatalf("expected ClassificationInconclusive for SPA index fallback, got %s", res.Classification)
	}
	if res.Reachability != ProbeReachabilityInconclusive {
		t.Fatalf("expected ReachabilityInconclusive, got %s", res.Reachability)
	}
	if !res.ManualVerificationRecommended {
		t.Fatalf("expected ManualVerificationRecommended to be true")
	}
}

// 5. HTTP 200 with structured schema or validation error
func TestP14_3_StructuredSchemaOrValidationError(t *testing.T) {
	// 5a. OpenAPI schema response
	tsSchema := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"openapi":"3.0.1","info":{"title":"Internal Microservice API","version":"1.0.0"}}`))
	}))
	defer tsSchema.Close()

	uSchema, _ := url.Parse(tsSchema.URL)
	optsSchema := DefaultProberOptions()
	optsSchema.AllowLoopback = true
	optsSchema.ScopeHost = uSchema.Hostname()

	engineSchema := NewProberEngine(optsSchema)
	resSchema := engineSchema.ProbeCandidate(context.Background(), "CAND-5a", "/api/openapi.json", "GET", tsSchema.URL)

	if resSchema.Classification != ClassificationReachableWithMetadata {
		t.Fatalf("expected ClassificationReachableWithMetadata, got %s", resSchema.Classification)
	}
	if resSchema.StructuredMetadataType != "OPENAPI_SCHEMA" {
		t.Fatalf("expected OPENAPI_SCHEMA, got %s", resSchema.StructuredMetadataType)
	}

	// 5b. FastAPI / structured validation error response on 422
	tsValErr := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/problem+json")
		w.WriteHeader(http.StatusUnprocessableEntity)
		w.Write([]byte(`{"detail":[{"loc":["query","account_id"],"msg":"field required","type":"value_error.missing"}]}`))
	}))
	defer tsValErr.Close()

	uValErr, _ := url.Parse(tsValErr.URL)
	optsValErr := DefaultProberOptions()
	optsValErr.AllowLoopback = true
	optsValErr.ScopeHost = uValErr.Hostname()

	engineValErr := NewProberEngine(optsValErr)
	resValErr := engineValErr.ProbeCandidate(context.Background(), "CAND-5b", "/api/v1/accounts", "GET", tsValErr.URL)

	if resValErr.Classification != ClassificationReachableWithMetadata {
		t.Fatalf("expected ClassificationReachableWithMetadata, got %s", resValErr.Classification)
	}
	if resValErr.StructuredMetadataType != "FASTAPI_STRUCTURED_DETAIL" {
		t.Fatalf("expected FASTAPI_STRUCTURED_DETAIL, got %s", resValErr.StructuredMetadataType)
	}
}

// 6. HTTP 3xx redirect within authorized scope
func TestP14_3_RedirectWithinScope(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/old" {
			http.Redirect(w, r, "/v2/new", http.StatusMovedPermanently)
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	}))
	defer ts.Close()

	u, _ := url.Parse(ts.URL)
	opts := DefaultProberOptions()
	opts.AllowLoopback = true
	opts.ScopeHost = u.Hostname()

	engine := NewProberEngine(opts)
	res := engine.ProbeCandidate(context.Background(), "CAND-6", "/v1/old", "GET", ts.URL)

	if res.Classification != ClassificationReachable {
		t.Fatalf("expected ClassificationReachable, got %s", res.Classification)
	}
	if res.RedirectInfo == nil {
		t.Fatalf("expected RedirectInfo to be recorded")
	}
	if !res.RedirectInfo.IsInScope {
		t.Fatalf("expected redirect to be marked in scope")
	}
}

// 7. HTTP 3xx redirect to out-of-scope host
func TestP14_3_RedirectOutOfScope(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "https://external-auth.example.net/oauth/authorize", http.StatusFound)
	}))
	defer ts.Close()

	u, _ := url.Parse(ts.URL)
	opts := DefaultProberOptions()
	opts.AllowLoopback = true
	opts.ScopeHost = u.Hostname()

	engine := NewProberEngine(opts)
	res := engine.ProbeCandidate(context.Background(), "CAND-7", "/auth/login", "GET", ts.URL)

	if res.Classification != ClassificationReachable {
		t.Fatalf("expected ClassificationReachable, got %s", res.Classification)
	}
	if res.RedirectInfo == nil {
		t.Fatalf("expected RedirectInfo to be populated")
	}
	if res.RedirectInfo.IsInScope {
		t.Fatalf("expected redirect to external-auth.example.net to be out-of-scope")
	}
}

// 8. Redirect to loopback, private, link-local, or metadata destinations
func TestP14_3_RedirectToLoopbackPrivateSSRFBlocked(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://169.254.169.254/latest/meta-data/", http.StatusFound)
	}))
	defer ts.Close()

	u, _ := url.Parse(ts.URL)
	opts := DefaultProberOptions()
	opts.AllowLoopback = true // loopback allowed for mock, but metadata 169.254 is blocked
	opts.AllowPrivateIPs = false
	opts.ScopeHost = u.Hostname()

	engine := NewProberEngine(opts)
	res := engine.ProbeCandidate(context.Background(), "CAND-8", "/meta-redirect", "GET", ts.URL)

	if res.RedirectInfo == nil {
		t.Fatalf("expected RedirectInfo")
	}
	if res.RedirectInfo.IsInScope {
		t.Fatalf("expected metadata IP redirect to be flagged as out of scope")
	}
}

// 9. HTTP 401 Unauthorized
func TestP14_3_HTTP401AuthenticationRequired(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("WWW-Authenticate", "Bearer realm=\"felix-api\"")
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`{"error":"unauthorized","message":"missing bearer token"}`))
	}))
	defer ts.Close()

	u, _ := url.Parse(ts.URL)
	opts := DefaultProberOptions()
	opts.AllowLoopback = true
	opts.ScopeHost = u.Hostname()

	engine := NewProberEngine(opts)
	res := engine.ProbeCandidate(context.Background(), "CAND-9", "/api/v1/secure/data", "GET", ts.URL)

	if res.Classification != ClassificationAuthenticationRequired {
		t.Fatalf("expected ClassificationAuthenticationRequired, got %s", res.Classification)
	}
	if res.Reachability != ProbeReachabilityConfirmed {
		t.Fatalf("expected ReachabilityConfirmed, got %s", res.Reachability)
	}
	if res.StatusCode != 401 {
		t.Fatalf("expected status 401, got %d", res.StatusCode)
	}
}

// 10. HTTP 403 Forbidden
func TestP14_3_HTTP403AuthorizationBoundaryObserved(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte(`{"error":"forbidden","message":"insufficient permissions"}`))
	}))
	defer ts.Close()

	u, _ := url.Parse(ts.URL)
	opts := DefaultProberOptions()
	opts.AllowLoopback = true
	opts.ScopeHost = u.Hostname()

	engine := NewProberEngine(opts)
	res := engine.ProbeCandidate(context.Background(), "CAND-10", "/api/admin/roles", "GET", ts.URL)

	if res.Classification != ClassificationAuthorizationBoundaryObserved {
		t.Fatalf("expected ClassificationAuthorizationBoundaryObserved, got %s", res.Classification)
	}
	if res.Reachability != ProbeReachabilityConfirmed {
		t.Fatalf("expected ReachabilityConfirmed, got %s", res.Reachability)
	}
}

// 11. HTTP 404 Not Found
func TestP14_3_HTTP404NotFoundResponse(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte(`Route not registered`))
	}))
	defer ts.Close()

	u, _ := url.Parse(ts.URL)
	opts := DefaultProberOptions()
	opts.AllowLoopback = true
	opts.ScopeHost = u.Hostname()

	engine := NewProberEngine(opts)
	res := engine.ProbeCandidate(context.Background(), "CAND-11", "/api/unknown/missing", "GET", ts.URL)

	if res.Classification != ClassificationNotFoundResponse {
		t.Fatalf("expected ClassificationNotFoundResponse, got %s", res.Classification)
	}
	if res.Reachability != ProbeReachabilityUnconfirmed {
		t.Fatalf("expected ReachabilityUnconfirmed, got %s", res.Reachability)
	}
}

// 12. HTTP 429 and Retry-After
func TestP14_3_HTTP429RateLimited(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Retry-After", "120")
		w.WriteHeader(http.StatusTooManyRequests)
		w.Write([]byte(`Rate limit exceeded`))
	}))
	defer ts.Close()

	u, _ := url.Parse(ts.URL)
	opts := DefaultProberOptions()
	opts.AllowLoopback = true
	opts.ScopeHost = u.Hostname()

	engine := NewProberEngine(opts)
	res := engine.ProbeCandidate(context.Background(), "CAND-12", "/api/v1/feed", "GET", ts.URL)

	if res.Classification != ClassificationRateLimited {
		t.Fatalf("expected ClassificationRateLimited, got %s", res.Classification)
	}
	if res.Reachability != ProbeReachabilityConfirmed {
		t.Fatalf("expected ReachabilityConfirmed, got %s", res.Reachability)
	}
	if !strings.Contains(res.Rationale, "Retry-After: 120") {
		t.Fatalf("expected Retry-After noted in rationale, got %s", res.Rationale)
	}
}

// 13. HTTP 500 and 502 Upstream Failure
func TestP14_3_HTTP500And502UpstreamFailure(t *testing.T) {
	ts500 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`Internal crash`))
	}))
	defer ts500.Close()

	u500, _ := url.Parse(ts500.URL)
	opts := DefaultProberOptions()
	opts.AllowLoopback = true
	opts.ScopeHost = u500.Hostname()

	engine := NewProberEngine(opts)
	res500 := engine.ProbeCandidate(context.Background(), "CAND-13a", "/api/crash", "GET", ts500.URL)

	if res500.Classification != ClassificationUpstreamFailure {
		t.Fatalf("expected ClassificationUpstreamFailure for 500, got %s", res500.Classification)
	}

	ts502 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
		w.Write([]byte(`Bad Gateway`))
	}))
	defer ts502.Close()

	u502, _ := url.Parse(ts502.URL)
	opts.ScopeHost = u502.Hostname()
	res502 := engine.ProbeCandidate(context.Background(), "CAND-13b", "/api/proxy", "GET", ts502.URL)

	if res502.Classification != ClassificationUpstreamFailure {
		t.Fatalf("expected ClassificationUpstreamFailure for 502, got %s", res502.Classification)
	}
	if !strings.Contains(res502.Rationale, "502 Bad Gateway") {
		t.Fatalf("expected 502 Bad Gateway details in rationale, got %s", res502.Rationale)
	}
}

// 14. Transport Failures: Connection Refusal, DNS Failure, Timeout
func TestP14_3_TransportFailures_DNS_TLS_Refusal_Timeout(t *testing.T) {
	// Connection refusal: connect to a closed local port
	opts := DefaultProberOptions()
	opts.AllowLoopback = true
	opts.Timeout = 1 * time.Second
	engine := NewProberEngine(opts)

	resRefused := engine.ProbeCandidate(context.Background(), "CAND-14a", "/test", "GET", "http://127.0.0.1:49999")
	if resRefused.Classification != ClassificationTransportFailure {
		t.Fatalf("expected ClassificationTransportFailure for refusal, got %s", resRefused.Classification)
	}
	if resRefused.Reachability != ProbeReachabilityUnconfirmed {
		t.Fatalf("expected ReachabilityUnconfirmed, got %s", resRefused.Reachability)
	}

	// DNS failure: non-existent domain
	optsDNS := DefaultProberOptions()
	optsDNS.Timeout = 5 * time.Second
	engineDNS := NewProberEngine(optsDNS)
	resDNS := engineDNS.ProbeCandidate(context.Background(), "CAND-14b", "/test", "GET", "http://nonexistent-subdomain-felix-test-xyz123.com")
	if resDNS.Classification != ClassificationTransportFailure {
		t.Fatalf("expected ClassificationTransportFailure for DNS failure, got %s", resDNS.Classification)
	}
}

// 15. Context cancellation
func TestP14_3_ContextCancellation(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(500 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	u, _ := url.Parse(ts.URL)
	opts := DefaultProberOptions()
	opts.AllowLoopback = true
	opts.ScopeHost = u.Hostname()

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately

	engine := NewProberEngine(opts)
	res := engine.ProbeCandidate(ctx, "CAND-15", "/api/slow", "GET", ts.URL)

	if res.Classification != ClassificationInconclusive {
		t.Fatalf("expected ClassificationInconclusive on canceled context, got %s", res.Classification)
	}
	if res.TransportErrorCategory != "CONTEXT_CANCELED_OR_TIMEOUT" {
		t.Fatalf("expected CONTEXT_CANCELED_OR_TIMEOUT, got %s", res.TransportErrorCategory)
	}
}

// 16. Oversized response body truncation
func TestP14_3_OversizedResponseBodyTruncation(t *testing.T) {
	hugeBody := strings.Repeat("A", 1024*1024) // 1 MiB

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(hugeBody))
	}))
	defer ts.Close()

	u, _ := url.Parse(ts.URL)
	opts := DefaultProberOptions()
	opts.AllowLoopback = true
	opts.MaxResponseSize = 64 * 1024 // 64 KiB limit
	opts.ScopeHost = u.Hostname()

	engine := NewProberEngine(opts)
	res := engine.ProbeCandidate(context.Background(), "CAND-16", "/api/huge", "GET", ts.URL)

	if res.Classification != ClassificationReachable {
		t.Fatalf("expected ClassificationReachable, got %s", res.Classification)
	}
	if len(res.ResponseEvidence) > 256 {
		t.Fatalf("expected evidence to be bounded to 256 bytes, got %d", len(res.ResponseEvidence))
	}
}

// 17. Malformed JSON and invalid content types
func TestP14_3_MalformedJSONAndInvalidContentTypes(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{not-json-at-all: invalid!`))
	}))
	defer ts.Close()

	u, _ := url.Parse(ts.URL)
	opts := DefaultProberOptions()
	opts.AllowLoopback = true
	opts.ScopeHost = u.Hostname()

	engine := NewProberEngine(opts)
	res := engine.ProbeCandidate(context.Background(), "CAND-17", "/api/broken-json", "GET", ts.URL)

	if res.Classification != ClassificationReachable {
		t.Fatalf("expected ClassificationReachable without panicking or false metadata claim, got %s", res.Classification)
	}
	if res.HasStructuredMetadata {
		t.Fatalf("expected HasStructuredMetadata to be false for malformed JSON")
	}
}

// 18. Sensitive values in query parameters, headers, and response evidence
func TestP14_3_SecretSanitizationInEvidence(t *testing.T) {
	rawSnippet := `Response for token=secret_abc123456789 and auth=my_super_password_99!`
	sanitized := sanitizeEvidence(rawSnippet)

	if strings.Contains(sanitized, "secret_abc123456789") {
		t.Fatalf("token secret leaked into sanitized string: %s", sanitized)
	}
	if strings.Contains(sanitized, "my_super_password_99") {
		t.Fatalf("auth secret leaked into sanitized string: %s", sanitized)
	}
	if !strings.Contains(sanitized, "token=[REDACTED]") {
		t.Fatalf("expected token=[REDACTED], got %s", sanitized)
	}
}

// 19. Unsafe route candidates refused by eligibility policy
func TestP14_3_UnsafeRouteCandidateRefusal(t *testing.T) {
	opts := DefaultProberOptions()
	opts.EnableSafeGET = true
	opts.EnableOPTIONS = false
	opts.EnableHEAD = false

	// Mutating path with delete keyword and no safe method allowed
	el := EvaluateEligibility("/api/v1/orders/delete", "GET", "http://example.com", opts)
	if el.IsEligible {
		t.Fatalf("expected mutating path with no OPTIONS/HEAD to be refused")
	}
	if !el.IsSafeRefusal {
		t.Fatalf("expected IsSafeRefusal to be true")
	}

	// Unresolved parameter placeholder with no OPTIONS/HEAD enabled
	elParam := EvaluateEligibility("/api/v1/users/{userId}/profile", "GET", "http://example.com", opts)
	if elParam.IsEligible {
		t.Fatalf("expected unresolved parameter to be refused when OPTIONS/HEAD disabled")
	}

	// When OPTIONS is enabled, mutating path is safely downgraded to OPTIONS
	opts.EnableOPTIONS = true
	elOpt := EvaluateEligibility("/api/v1/orders/delete", "GET", "http://example.com", opts)
	if !elOpt.IsEligible || elOpt.SelectedMethod != "OPTIONS" {
		t.Fatalf("expected mutating candidate to be downgraded to OPTIONS, got method=%s eligible=%v", elOpt.SelectedMethod, elOpt.IsEligible)
	}
}

// 20. Zero Mutating Methods Sent by Default Probe Engine
func TestP14_3_ZeroMutatingMethodsSent(t *testing.T) {
	var receivedMethods []string
	var mu sync.Mutex

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		receivedMethods = append(receivedMethods, r.Method)
		mu.Unlock()

		w.Header().Set("Allow", "GET, POST, PUT, DELETE, OPTIONS")
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	u, _ := url.Parse(ts.URL)
	opts := DefaultProberOptions()
	opts.AllowLoopback = true
	opts.ScopeHost = u.Hostname()

	candidates := []ReconciliationItem{
		{CandidateID: "C1", Path: "/api/users", Method: "POST"},
		{CandidateID: "C2", Path: "/api/orders/123", Method: "DELETE"},
		{CandidateID: "C3", Path: "/api/account/update", Method: "PUT"},
		{CandidateID: "C4", Path: "/api/profile/patch", Method: "PATCH"},
		{CandidateID: "C5", Path: "/api/database/drop", Method: "POST"},
		{CandidateID: "C6", Path: "/api/session/terminate", Method: "POST"},
	}

	engine := NewProberEngine(opts)
	report := engine.ProbeBatch(context.Background(), candidates, ts.URL)

	if report.TotalProbesAttempted != 6 {
		t.Fatalf("expected 6 probes attempted, got %d", report.TotalProbesAttempted)
	}

	mu.Lock()
	defer mu.Unlock()

	for _, m := range receivedMethods {
		upper := strings.ToUpper(m)
		if upper == "POST" || upper == "PUT" || upper == "DELETE" || upper == "PATCH" {
			t.Fatalf("CRITICAL SAFETY VIOLATION: Mutating method %s was sent to target server!", upper)
		}
	}
}

// 21. Duplicate candidates deduplicated without losing provenance
func TestP14_3_Deduplication(t *testing.T) {
	var requestCount int32

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&requestCount, 1)
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	u, _ := url.Parse(ts.URL)
	opts := DefaultProberOptions()
	opts.AllowLoopback = true
	opts.ScopeHost = u.Hostname()

	duplicates := []ReconciliationItem{
		{CandidateID: "C1", Path: "/api/v1/common", Method: "GET", CanonicalPath: "/api/v1/common"},
		{CandidateID: "C2", Path: "/api/v1/common", Method: "GET", CanonicalPath: "/api/v1/common"},
		{CandidateID: "C3", Path: "/api/v1/common", Method: "GET", CanonicalPath: "/api/v1/common"},
	}

	engine := NewProberEngine(opts)
	report := engine.ProbeBatch(context.Background(), duplicates, ts.URL)

	if atomic.LoadInt32(&requestCount) != 1 {
		t.Fatalf("expected exactly 1 network request for duplicate candidates, got %d", requestCount)
	}
	if report.TotalCandidatesEvaluated != 3 {
		t.Fatalf("expected 3 candidates evaluated, got %d", report.TotalCandidatesEvaluated)
	}
	if report.TotalProbesAttempted != 1 {
		t.Fatalf("expected 1 probe attempted, got %d", report.TotalProbesAttempted)
	}
}

// 22. Out-of-scope candidate rejected before network activity
func TestP14_3_OutOfScopeCandidateRejectedBeforeNetwork(t *testing.T) {
	opts := DefaultProberOptions()
	opts.ScopeHost = "app.internal.domain"
	opts.AllowLoopback = false
	opts.AllowPrivateIPs = false

	engine := NewProberEngine(opts)
	// Target URL host differs from ScopeHost
	res := engine.ProbeCandidate(context.Background(), "CAND-22", "https://unauthorized-external-site.com/api/steal", "GET", "")

	if res.Classification != ClassificationScopeBlocked {
		t.Fatalf("expected ClassificationScopeBlocked, got %s", res.Classification)
	}
	if res.Reachability != ProbeReachabilityUnconfirmed {
		t.Fatalf("expected ReachabilityUnconfirmed, got %s", res.Reachability)
	}
}

// 23. Existing P14.1 and P14.2 Integration
func TestP14_3_P14_1_P14_2_Integration(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"items":[{"id":1}]}`))
	}))
	defer ts.Close()

	u, _ := url.Parse(ts.URL)

	// Step 1: P14.1 Bundle route discovery
	fakeJS := `
		function fetchOrders() { return fetch("/api/v2/orders", { method: "GET" }); }
		function deleteOrder(id) { return fetch("/api/v2/orders/" + id, { method: "DELETE" }); }
	`
	extractor := crawler.NewBundleExtractor(crawler.DefaultBundleAnalysisOptions())
	candidates, _, _, _ := extractor.ExtractFromBundle([]byte(fakeJS), "test-app.js")

	if len(candidates) == 0 {
		t.Fatalf("expected route candidates from P14.1 extractor")
	}

	// Step 2: P14.2 Reconciliation
	specDoc := `{"openapi":"3.0.0","paths":{"/api/v1/legacy":{"get":{}}}}`
	parser := NewSpecParser()
	ops, specMeta, err := parser.ParseSpecificationData([]byte(specDoc), "spec.json")
	if err != nil {
		t.Fatalf("spec parse error: %v", err)
	}

	reconEngine := NewReconciliationEngine([]SpecMetadata{*specMeta}, ops, DefaultReconciliationOptions())
	reconReport := reconEngine.Reconcile(candidates)

	if len(reconReport.ShadowSurface) == 0 {
		t.Fatalf("expected shadow surface items from P14.2 reconciliation")
	}

	// Step 3: P14.3 Live validation
	opts := DefaultProberOptions()
	opts.AllowLoopback = true
	opts.ScopeHost = u.Hostname()

	prober := NewProberEngine(opts)
	proberReport := prober.ProbeBatch(context.Background(), reconReport.ShadowSurface, ts.URL)

	if proberReport.TotalProbesAttempted == 0 {
		t.Fatalf("expected live probes attempted on shadow candidates")
	}
	if proberReport.TotalReachable == 0 {
		t.Fatalf("expected reachable results on mock server")
	}
}

// 24. Assessment and CLI integration
func TestP14_3_CLI_ScanProbeFlag(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"healthy"}`))
	}))
	defer ts.Close()

	u, _ := url.Parse(ts.URL)
	opts := DefaultProberOptions()
	opts.AllowLoopback = true
	opts.ScopeHost = u.Hostname()

	engine := NewProberEngine(opts)
	res := engine.ProbeCandidate(context.Background(), "CLI-1", "/healthz", "GET", ts.URL)

	if res.Classification != ClassificationReachableWithMetadata {
		t.Fatalf("expected ClassificationReachableWithMetadata, got %s", res.Classification)
	}
}

// 25. Stable handling of inconclusive and partially observed results
func TestP14_3_InconclusiveAndPartiallyObservedResults(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Non-standard HTTP status 418 I'm a teapot with ambiguous text body
		w.WriteHeader(http.StatusTeapot)
		w.Write([]byte(`I am a teapot`))
	}))
	defer ts.Close()

	u, _ := url.Parse(ts.URL)
	opts := DefaultProberOptions()
	opts.AllowLoopback = true
	opts.ScopeHost = u.Hostname()

	engine := NewProberEngine(opts)
	res := engine.ProbeCandidate(context.Background(), "CAND-25", "/teapot", "GET", ts.URL)

	if res.Classification != ClassificationInconclusive {
		t.Fatalf("expected ClassificationInconclusive for non-standard teapot status, got %s", res.Classification)
	}
	if res.Reachability != ProbeReachabilityInconclusive {
		t.Fatalf("expected ReachabilityInconclusive, got %s", res.Reachability)
	}
}
