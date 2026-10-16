package cloud

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"

	"felix/pkg/crawler"
)

// countingTransport intercepts and counts every HTTP request dispatched.
type countingTransport struct {
	requestCount atomic.Int32
	handler      http.HandlerFunc
}

func (c *countingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	c.requestCount.Add(1)
	if c.handler != nil {
		rec := &responseRecorder{header: make(http.Header)}
		c.handler(rec, req)
		return rec.toResponse(req), nil
	}
	return &http.Response{
		StatusCode: http.StatusOK,
		Header:     make(http.Header),
		Body:       io.NopCloser(strings.NewReader(`{}`)),
	}, nil
}

type responseRecorder struct {
	header     http.Header
	statusCode int
	body       []byte
}

func (r *responseRecorder) Header() http.Header {
	return r.header
}

func (r *responseRecorder) Write(b []byte) (int, error) {
	r.body = append(r.body, b...)
	return len(b), nil
}

func (r *responseRecorder) WriteHeader(code int) {
	r.statusCode = code
}

func (r *responseRecorder) toResponse(req *http.Request) *http.Response {
	code := r.statusCode
	if code == 0 {
		code = http.StatusOK
	}
	return &http.Response{
		StatusCode:    code,
		Header:        r.header,
		Body:          io.NopCloser(strings.NewReader(string(r.body))),
		ContentLength: int64(len(r.body)),
		Request:       req,
	}
}

// 1. Passive indicator detection performs zero DNS lookups and zero network connections.
func TestAuthorizationBoundary_PassiveIndicators_ZeroNetworkProbes(t *testing.T) {
	transport := &countingTransport{}
	var dialCount atomic.Int32
	client := NewClient(ClientOptions{
		HTTPClient: &http.Client{Transport: transport},
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			dialCount.Add(1)
			return nil, errors.New("network dial forbidden during passive analysis")
		},
	})

	detector := NewDetector(client, func(u string) bool { return true })

	// Assets containing various connection indicators with credentials
	assets := []crawler.Asset{
		{
			URL: "https://target.local/config.js",
			Content: []byte(`
				const pg = "postgres://admin:secret123@db.internal:5432/app";
				const rd = "redis://:token456@cache.internal:6379";
				const my = "mysql://user:pass789@mysql.internal:3306/db";
				const s3 = "s3://my-secret-bucket/backup.tar.gz";
				const mn = "http://minio.internal:9000";
			`),
			InScope: true,
		},
	}

	inds := detector.DetectConnectionIndicators(assets)
	if len(inds) == 0 {
		t.Fatalf("expected connection indicators to be detected, got 0")
	}

	// Verify ZERO network calls were made
	if reqs := transport.requestCount.Load(); reqs != 0 {
		t.Fatalf("SECURITY VIOLATION: %d HTTP requests occurred during passive indicator detection", reqs)
	}
	if dials := dialCount.Load(); dials != 0 {
		t.Fatalf("SECURITY VIOLATION: %d network dials occurred during passive indicator detection", dials)
	}

	// Verify all indicators have static classification
	for _, ind := range inds {
		f := ind.ToCloudFinding(true)
		if f.HTTPStatus != 0 {
			t.Errorf("expected HTTPStatus=0 for static indicator finding, got %d", f.HTTPStatus)
		}
		if f.Category == "" {
			t.Errorf("expected non-empty category for indicator")
		}
	}
}

// 2. Service Discovery probes are strictly blocked for out-of-scope targets before network transmission.
func TestAuthorizationBoundary_ServiceDiscovery_ScopeGated(t *testing.T) {
	transport := &countingTransport{
		handler: func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Server", "AmazonS3")
			w.WriteHeader(http.StatusOK)
		},
	}
	client := NewClient(ClientOptions{
		HTTPClient: &http.Client{Transport: transport},
	})

	// Authorization checker: only target.com is in scope; foreign-bucket is OUT OF SCOPE
	isAllowed := func(u string) bool {
		return strings.Contains(u, "target.com")
	}

	engine := NewServiceDiscoveryEngine(client, isAllowed)

	outOfScopeCandidate := DiscoveredService{
		Technology: TechAWSS3,
		Endpoint:   "https://foreign-unauthorized-bucket.s3.amazonaws.com",
		Host:       "foreign-unauthorized-bucket.s3.amazonaws.com",
	}

	verified := engine.VerifyCandidate(context.Background(), outOfScopeCandidate)

	// InScope must be false, limitations note set, and exactly zero probes sent
	if verified.InScope {
		t.Errorf("expected InScope=false for out-of-scope candidate")
	}
	if !strings.Contains(verified.Limitations, "outside authorized assessment scope") {
		t.Errorf("expected limitations note about scope exclusion, got %q", verified.Limitations)
	}
	if reqs := transport.requestCount.Load(); reqs != 0 {
		t.Fatalf("SECURITY VIOLATION: %d probes sent to out-of-scope target!", reqs)
	}

	// Now verify in-scope candidate is probed
	inScopeCandidate := DiscoveredService{
		Technology: TechAWSS3,
		Endpoint:   "https://target.com/bucket",
		Host:       "target.com",
	}
	verifiedInScope := engine.VerifyCandidate(context.Background(), inScopeCandidate)
	if !verifiedInScope.InScope {
		t.Errorf("expected InScope=true for in-scope candidate")
	}
	if reqs := transport.requestCount.Load(); reqs != 1 {
		t.Fatalf("expected exactly 1 probe for in-scope candidate, got %d", reqs)
	}
}

// 3. Active Access Verification cannot run when active verification is disabled.
func TestAuthorizationBoundary_ActiveAccessVerification_GatedByFlag(t *testing.T) {
	var probeAttempts atomic.Int32
	transport := &countingTransport{
		handler: func(w http.ResponseWriter, r *http.Request) {
			probeAttempts.Add(1)
			w.Header().Set("Server", "AmazonS3")
			w.WriteHeader(http.StatusOK)
		},
	}
	client := NewClient(ClientOptions{
		HTTPClient:    &http.Client{Transport: transport},
		AllowLoopback: true,
	})

	detector := NewDetector(client, func(u string) bool { return true })

	// Explicitly disable active verification
	detector.SetAllowActiveVerification(false)
	if detector.AllowActiveVerification() {
		t.Fatalf("expected AllowActiveVerification=false")
	}

	assets := []crawler.Asset{
		{
			URL:     "https://target.com/config.js",
			Content: []byte(`const s3 = "https://target-data.s3.amazonaws.com";`),
			InScope: true,
		},
	}

	res := detector.Audit(context.Background(), assets, nil)

	// Service was discovered (Phase 2.1 probe occurred for identification)
	if len(res.DiscoveredServices) == 0 {
		t.Fatalf("expected service to be discovered")
	}

	// Access verification records must be SKIPPED
	if len(res.AccessRecords) == 0 {
		t.Fatalf("expected skipped access records, got 0")
	}
	for _, rec := range res.AccessRecords {
		if rec.Status != StatusVerificationSkipped {
			t.Errorf("expected StatusVerificationSkipped when active verification disabled, got %s", rec.Status)
		}
		if !strings.Contains(rec.Limitations, "active access verification disabled") {
			t.Errorf("expected limitations note about active verification disabled, got: %s", rec.Limitations)
		}
	}
}

// 4. Write-capable canary operations require separate explicit authorization and are never triggered by --active alone.
func TestAuthorizationBoundary_CanaryWrite_SeparateAuthorizationRequired(t *testing.T) {
	checker := &CanaryGuardrailChecker{
		AllowWriteVerification: false, // Default: write verification disabled
		ScopeValidator:         func(u string) bool { return true },
	}

	// Case A: Even with --active enabled in general scan, canaries must be explicitly enabled
	canaryDefault := CanaryConfig{
		Enabled:              false,
		ExplicitlyAuthorized: false,
		TargetResource:       "felix-canary/test.txt",
	}

	eval := checker.EvaluateConditions("https://target.com", TechAWSS3, canaryDefault, true)
	if eval.Allowed {
		t.Fatalf("SECURITY VIOLATION: canary write allowed without explicit opt-in!")
	}
	if !strings.Contains(eval.Reason, "requires explicit opt-in") {
		t.Errorf("expected reason about explicit opt-in, got %q", eval.Reason)
	}

	// Case B: Opt-in enabled globally, but run configuration missing explicit authorization
	checker.AllowWriteVerification = true
	canaryNoRunAuth := CanaryConfig{
		Enabled:              true,
		ExplicitlyAuthorized: false,
		TargetResource:       "felix-canary/test.txt",
	}
	evalRunAuth := checker.EvaluateConditions("https://target.com", TechAWSS3, canaryNoRunAuth, true)
	if evalRunAuth.Allowed {
		t.Fatalf("SECURITY VIOLATION: canary write allowed without explicit run authorization!")
	}
	if !strings.Contains(evalRunAuth.Reason, "explicit write authorization") {
		t.Errorf("expected reason about explicit write authorization, got %q", evalRunAuth.Reason)
	}
}

// 5. Canary writes are strictly restricted to supported technologies (Redis, S3, MinIO) and blocked for databases.
func TestAuthorizationBoundary_CanaryWrite_ProviderRestriction(t *testing.T) {
	checker := &CanaryGuardrailChecker{
		AllowWriteVerification: true,
		ScopeValidator:         func(u string) bool { return true },
	}

	authorizedCanary := CanaryConfig{
		Enabled:                        true,
		ExplicitlyAuthorized:           true,
		PreventOverwriteCheck:          true,
		AllowCleanup:                   true,
		IdentityLeastPrivilegeVerified: true,
		TargetResource:                 "felix-canary/test.txt",
	}

	// Prohibited database technologies
	prohibitedTechs := []ServiceTechnology{
		TechPostgreSQL,
		TechMySQL,
		TechMongoDB,
		TechFirebaseRTDB,
		TechFirestore,
		TechSupabase,
		TechHasura,
		TechPrisma,
		TechMongoExpress,
		TechElasticsearch,
	}

	for _, tech := range prohibitedTechs {
		eval := checker.EvaluateConditions("target.local", tech, authorizedCanary, true)
		if eval.Allowed {
			t.Fatalf("SECURITY VIOLATION: canary write permitted for unsafe database technology %s!", tech)
		}
		if !strings.Contains(eval.Reason, "does not support isolated, non-destructive canary writes") {
			t.Errorf("expected unsupported reason for %s, got %q", tech, eval.Reason)
		}
	}

	// Supported technologies
	supportedTechs := []ServiceTechnology{
		TechRedis,
		TechAWSS3,
		TechMinIO,
	}

	for _, tech := range supportedTechs {
		eval := checker.EvaluateConditions("target.local", tech, authorizedCanary, true)
		if !eval.Allowed {
			t.Errorf("expected canary write to be allowed for supported tech %s, got error: %s", tech, eval.Reason)
		}
	}
}
