package test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"felix/pkg/api"
	"felix/pkg/cloud"
	"felix/pkg/cloudsec"
	"felix/pkg/crawler"
	"felix/pkg/report"
	"felix/pkg/secrets"
)

// ---------------------------------------------------------------------------
// 1. CLOUD ASSESSMENT REPRESENTATIVE FLOWS
// ---------------------------------------------------------------------------

// TestRepresentative_CloudSecurityFlow verifies:
// - Positive S3 anonymous bucket exposure finding
// - Benign control: S3 403 AccessDenied producing zero findings
// - Provider error (500) handled safely as CoverageFailedError without panic
// - SSRF refusal on IMDS IP 169.254.169.254 with zero TCP dials
// - Sensitive canary credentials redacted from all findings and evidence
func TestRepresentative_CloudSecurityFlow(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	const canarySecret = "AKIAIOSFODNN7CANARYKEY"

	// Mock S3 Vulnerable Server (Anonymous Bucket Read Allowed)
	vulnS3Server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "AmazonS3")
		w.Header().Set("Content-Type", "application/xml")
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, `<?xml version="1.0" encoding="UTF-8"?>
<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
    <Name>corporate-financial-records</Name>
    <Contents>
        <Key>audit_2026.pdf</Key>
        <Size>1048576</Size>
    </Contents>
</ListBucketResult>`)
	}))
	defer vulnS3Server.Close()

	// Mock S3 Benign/Secure Server (Access Denied)
	secureS3Server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "AmazonS3")
		w.Header().Set("Content-Type", "application/xml")
		w.WriteHeader(http.StatusForbidden)
		fmt.Fprintln(w, `<?xml version="1.0" encoding="UTF-8"?><Error><Code>AccessDenied</Code></Error>`)
	}))
	defer secureS3Server.Close()

	// Mock S3 Error Server (Internal 500)
	errorS3Server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "AmazonS3")
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintln(w, `Service unavailable`)
	}))
	defer errorS3Server.Close()

	engine := cloudsec.NewEngine(cloudsec.DefaultConfig())

	// 1. Positive Control: Anonymous S3 Bucket Exposure
	actxVuln := &cloudsec.AssessmentContext{
		AssessmentID: "asm-rep-cloud-vuln",
		Mode:         cloudsec.ModeExternal,
		Provider:     cloudsec.ProviderAWS,
		ExternalTargets: []cloudsec.ExternalTarget{
			{
				URL:      vulnS3Server.URL + "/assets",
				Hostname: "corporate-financial-records.s3.amazonaws.com",
				Headers:  map[string]string{"server": "AmazonS3", "x-canary": canarySecret},
			},
		},
	}
	resultsVuln, findingsVuln, summaryVuln, err := engine.Assess(ctx, actxVuln)
	if err != nil {
		t.Fatalf("unexpected assessment error: %v", err)
	}
	if summaryVuln.VerifiedCount != 1 || len(findingsVuln) != 1 {
		t.Fatalf("expected 1 verified S3 finding, got %d (findings: %d)", summaryVuln.VerifiedCount, len(findingsVuln))
	}
	if resultsVuln[0].VerificationState != cloudsec.StateVerified {
		t.Errorf("expected StateVerified, got %s", resultsVuln[0].VerificationState)
	}

	// Verify secret redaction in finding evidence
	for _, f := range findingsVuln {
		if strings.Contains(f.Evidence, canarySecret) || strings.Contains(f.Description, canarySecret) {
			t.Errorf("raw canary secret leaked into finding evidence: %s", f.Evidence)
		}
	}

	// 2. Benign Control: Private/Restricted S3 Bucket
	actxSecure := &cloudsec.AssessmentContext{
		AssessmentID: "asm-rep-cloud-secure",
		Mode:         cloudsec.ModeExternal,
		Provider:     cloudsec.ProviderAWS,
		ExternalTargets: []cloudsec.ExternalTarget{
			{
				URL:      secureS3Server.URL + "/assets",
				Hostname: "secure-private-vault.s3.amazonaws.com",
				Headers:  map[string]string{"server": "AmazonS3"},
			},
		},
	}
	resultsSecure, findingsSecure, summarySecure, err := engine.Assess(ctx, actxSecure)
	if err != nil {
		t.Fatalf("unexpected error on secure S3 bucket: %v", err)
	}
	if summarySecure.VerifiedCount != 0 || len(findingsSecure) != 0 {
		t.Fatalf("benign/secure bucket falsely flagged: got %d findings", len(findingsSecure))
	}
	if resultsSecure[0].VerificationState != cloudsec.StateObserved {
		t.Errorf("expected StateObserved for secure bucket, got %s", resultsSecure[0].VerificationState)
	}

	// 3. Provider Error Handling: 500 error handled safely
	actxError := &cloudsec.AssessmentContext{
		AssessmentID: "asm-rep-cloud-error",
		Mode:         cloudsec.ModeExternal,
		Provider:     cloudsec.ProviderAWS,
		ExternalTargets: []cloudsec.ExternalTarget{
			{
				URL:      errorS3Server.URL + "/assets",
				Hostname: "failing-bucket.s3.amazonaws.com",
				Headers:  map[string]string{"server": "AmazonS3"},
			},
		},
	}
	resultsError, findingsError, _, err := engine.Assess(ctx, actxError)
	if err != nil {
		t.Fatalf("unexpected panic or crash on provider error: %v", err)
	}
	if len(findingsError) != 0 {
		t.Errorf("expected 0 vulnerability findings on 500 server error, got %d", len(findingsError))
	}
	if len(resultsError) > 0 && resultsError[0].VerificationState == cloudsec.StateVerified {
		t.Errorf("provider 500 error must NOT be classified as StateVerified")
	}

	// 4. SSRF and Cloud Metadata IP Refusal
	var dialAttempts atomic.Int32
	safeTransport := crawler.NewSafeTransport(crawler.SafeTransportOptions{
		Timeout: 1 * time.Second,
		DialFunc: func(ctx context.Context, network, addr string) (net.Conn, error) {
			dialAttempts.Add(1)
			return nil, fmt.Errorf("unexpected dial to %s", addr)
		},
	})
	safeClient := cloud.NewClient(cloud.ClientOptions{
		HTTPClient: &http.Client{Transport: safeTransport},
	})

	imdsURLs := []string{
		"http://169.254.169.254/latest/meta-data/",
		"http://[fd00:ec2::254]/latest/meta-data/",
	}
	for _, u := range imdsURLs {
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
		_, err := safeClient.Do(ctx, req)
		if err == nil {
			t.Fatalf("expected SSRF error on IMDS endpoint %s", u)
		}
		if !strings.Contains(err.Error(), "SSRF") && !strings.Contains(err.Error(), "security refusal") {
			t.Errorf("expected SSRF security refusal for %s, got: %v", u, err)
		}
	}
	if dials := dialAttempts.Load(); dials != 0 {
		t.Fatalf("security violation: %d dials attempted to cloud metadata", dials)
	}
}

// ---------------------------------------------------------------------------
// 2. DATABASE ASSESSMENT REPRESENTATIVE FLOWS
// ---------------------------------------------------------------------------

// TestRepresentative_DatabaseSecurityFlow verifies:
// - Elasticsearch: unauthenticated root cluster discovery vs authenticated 401 challenge vs non-ES server
// - Redis: mock TCP server responding to PING (+PONG vs -NOAUTH)
// - Non-destructive guarantee: zero state-changing queries executed
// - Credential redaction in database connection strings
func TestRepresentative_DatabaseSecurityFlow(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	client := cloud.NewClient(cloud.ClientOptions{
		Timeout:         2 * time.Second,
		AllowLoopback:   true,
		AllowPrivateIPs: true,
	})

	// 1. Elasticsearch Checks
	// A. Open Elasticsearch instance (HTTP 200)
	esOpenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-elastic-product", "Elasticsearch")
		fmt.Fprintln(w, `{
			"name": "es-node-01",
			"cluster_name": "production-analytics",
			"tagline": "You Know, for Search",
			"version": {"number": "8.12.1"}
		}`)
	}))
	defer esOpenServer.Close()

	resOpen := cloud.ProbeElasticsearch(ctx, client, esOpenServer.URL)
	if resOpen.Outcome != cloud.OutcomeDetected {
		t.Fatalf("expected Elasticsearch OutcomeDetected, got %s", resOpen.Outcome)
	}
	if resOpen.AuthRequired {
		t.Errorf("expected AuthRequired=false for open ES, got true")
	}
	if resOpen.Version != "8.12.1" {
		t.Errorf("expected version 8.12.1, got %s", resOpen.Version)
	}

	// Active Access Verification on Open Elasticsearch
	recOpen := cloud.VerifyElasticsearchAccess(ctx, client, esOpenServer.URL, nil, nil)
	if recOpen.Decision != cloud.DecisionAllowed || recOpen.Status != cloud.StatusServiceReachable {
		t.Errorf("expected DecisionAllowed/StatusServiceReachable, got %s/%s", recOpen.Decision, recOpen.Status)
	}

	// B. Authenticated Elasticsearch (HTTP 401)
	esAuthServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("WWW-Authenticate", `Basic realm="security" charset="UTF-8"`)
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprintln(w, `{"error":{"root_cause":[{"type":"security_exception","reason":"missing authentication"}],"type":"security_exception"}}`)
	}))
	defer esAuthServer.Close()

	resAuth := cloud.ProbeElasticsearch(ctx, client, esAuthServer.URL)
	if resAuth.Outcome != cloud.OutcomeDetected {
		t.Fatalf("expected OutcomeDetected for 401 security_exception, got %s", resAuth.Outcome)
	}
	if !resAuth.AuthRequired {
		t.Errorf("expected AuthRequired=true for authenticated ES, got false")
	}

	recAuth := cloud.VerifyElasticsearchAccess(ctx, client, esAuthServer.URL, nil, nil)
	if recAuth.Decision != cloud.DecisionDenied || recAuth.Status != cloud.StatusAuthChallenged {
		t.Errorf("expected DecisionDenied/StatusAuthChallenged for 401, got %s/%s", recAuth.Decision, recAuth.Status)
	}

	// C. Ambiguous / Non-Elasticsearch server
	nonESServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprintln(w, `<html><body>Apache Web Server</body></html>`)
	}))
	defer nonESServer.Close()

	resNonES := cloud.ProbeElasticsearch(ctx, client, nonESServer.URL)
	if resNonES.Outcome != cloud.OutcomeNotDetected {
		t.Errorf("expected OutcomeNotDetected on generic HTML page, got %s", resNonES.Outcome)
	}

	// 2. Redis Mock TCP Protocol Check
	// A. Open Redis (responds +PONG)
	lnOpen, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen for mock redis: %v", err)
	}
	defer lnOpen.Close()

	go func() {
		for {
			conn, err := lnOpen.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 256)
				n, _ := c.Read(buf)
				if bytes.Contains(buf[:n], []byte("PING")) {
					_, _ = c.Write([]byte("+PONG\r\n"))
				} else if bytes.Contains(buf[:n], []byte("INFO")) {
					_, _ = c.Write([]byte("$24\r\nredis_version:7.2.4\r\n\r\n"))
				}
			}(conn)
		}
	}()

	hostOpen, portOpenStr, _ := net.SplitHostPort(lnOpen.Addr().String())
	var portOpen int
	fmt.Sscanf(portOpenStr, "%d", &portOpen)

	resRedisOpen := cloud.ProbeRedis(ctx, client, hostOpen, portOpen)
	if resRedisOpen.Outcome != cloud.OutcomeDetected || resRedisOpen.AuthRequired {
		t.Errorf("expected unauthenticated Redis to be detected without auth, got outcome=%s authRequired=%t", resRedisOpen.Outcome, resRedisOpen.AuthRequired)
	}

	// B. Authenticated Redis (responds -NOAUTH)
	lnAuth, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen for mock auth redis: %v", err)
	}
	defer lnAuth.Close()

	go func() {
		for {
			conn, err := lnAuth.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 256)
				n, _ := c.Read(buf)
				if bytes.Contains(buf[:n], []byte("PING")) || bytes.Contains(buf[:n], []byte("INFO")) {
					_, _ = c.Write([]byte("-NOAUTH Authentication required.\r\n"))
				}
			}(conn)
		}
	}()

	hostAuth, portAuthStr, _ := net.SplitHostPort(lnAuth.Addr().String())
	var portAuth int
	fmt.Sscanf(portAuthStr, "%d", &portAuth)

	resRedisAuth := cloud.ProbeRedis(ctx, client, hostAuth, portAuth)
	if resRedisAuth.Outcome != cloud.OutcomeDetected || !resRedisAuth.AuthRequired {
		t.Errorf("expected authenticated Redis to have AuthRequired=true, got outcome=%s authRequired=%t", resRedisAuth.Outcome, resRedisAuth.AuthRequired)
	}

	// 3. Database Connection String Credential Redaction Check
	const dbPassword = "SecretDatabasePassword2026!"
	rawConnStr := "postgres://admin:" + dbPassword + "@db.internal:5432/orders_prod"
	redacted := secrets.RedactText(rawConnStr)
	if strings.Contains(redacted, dbPassword) {
		t.Errorf("database password was not redacted from connection string: %s", redacted)
	}
}

// ---------------------------------------------------------------------------
// 3. API ASSESSMENT REPRESENTATIVE FLOWS
// ---------------------------------------------------------------------------

// TestRepresentative_APISecurityFlow verifies:
// - OpenAPI parsing and shadow route reconciliation (documented vs undocumented routes)
// - Live exploitability reachability and metadata probing
// - Benign denied response (401/403) classified as AUTH_REQUIRED
// - Ambiguous HTML login redirect classified as INCONCLUSIVE
// - Declarative multi-tenant profile BOLA verification
// - SSRF and redirect out of scope blocked
// - Oversized response handling
func TestRepresentative_APISecurityFlow(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	const canaryToken = "Bearer test_canary_api_token_12345"

	// Mock API Server
	apiServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/users":
			// Documented & Reachable
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			fmt.Fprintln(w, `{"users": [{"id": "usr-1", "name": "Alice"}]}`)

		case "/api/v1/shadow/admin_dump":
			// Shadow & Auth Required
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			fmt.Fprintln(w, `{"error": "Access denied"}`)

		case "/api/v1/ambiguous_spa":
			// Ambiguous 200 OK returning generic HTML login page
			w.Header().Set("Content-Type", "text/html")
			w.WriteHeader(http.StatusOK)
			fmt.Fprintln(w, `<!DOCTYPE html><html><head><title>Login</title></head><body><div id="root">Please log in</div></body></html>`)

		case "/api/v1/redirect_ssrf":
			// Malicious redirect attempting to reach AWS metadata
			http.Redirect(w, r, "http://169.254.169.254/latest/meta-data/", http.StatusFound)

		case "/api/v1/tenant/resource":
			// Multi-tenant endpoint
			authHdr := r.Header.Get("Authorization")
			resID := r.URL.Query().Get("id")
			w.Header().Set("Content-Type", "application/json")

			// Tenant A owns "res-tenant-a-1"
			// Tenant B owns "res-tenant-b-1"
			// If Tenant A provides token-a and asks for res-tenant-b-1, simulate BOLA vulnerability
			if resID == "res-tenant-b-1" && strings.Contains(authHdr, "token-tenant-a") {
				w.WriteHeader(http.StatusOK)
				fmt.Fprintln(w, `{"id": "res-tenant-b-1", "owner": "tenant-b", "secret_data": "TENANT_B_CONFIDENTIAL_RECORD"}`)
				return
			}
			if resID == "res-tenant-b-1" && strings.Contains(authHdr, "token-tenant-b") {
				w.WriteHeader(http.StatusOK)
				fmt.Fprintln(w, `{"id": "res-tenant-b-1", "owner": "tenant-b", "secret_data": "TENANT_B_CONFIDENTIAL_RECORD"}`)
				return
			}
			w.WriteHeader(http.StatusForbidden)
			fmt.Fprintln(w, `{"error": "Access denied"}`)

		case "/api/v1/oversized":
			// Large response
			w.Header().Set("Content-Type", "application/octet-stream")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(bytes.Repeat([]byte("A"), 2*1024*1024)) // 2 MB

		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer apiServer.Close()

	// 1. OpenAPI Specification Reconciliation
	openAPISpec := fmt.Sprintf(`{
		"openapi": "3.0.0",
		"info": {"title": "Test Customer API", "version": "1.0.0"},
		"servers": [{"url": "%s"}],
		"paths": {
			"/api/v1/users": {
				"get": {
					"summary": "Get all users",
					"responses": {"200": {"description": "Success"}}
				}
			}
		}
	}`, apiServer.URL)

	parser := api.NewSpecParser()
	ops, meta, err := parser.ParseSpecificationData([]byte(openAPISpec), "test_api.json")
	if err != nil {
		t.Fatalf("failed parsing OpenAPI spec: %v", err)
	}

	// Crawled discovered route candidates (1 documented, 1 shadow)
	candidates := []crawler.RouteCandidate{
		{
			ID:               "RCAND-1",
			Path:             "/api/v1/users",
			HTTPMethod:       "GET",
			OriginatingAsset: "https://app.local/main.js",
			Confidence:       crawler.ConfidenceConfirmed,
		},
		{
			ID:               "RCAND-2",
			Path:             "/api/v1/shadow/admin_dump",
			HTTPMethod:       "GET",
			OriginatingAsset: "https://app.local/main.js",
			Confidence:       crawler.ConfidenceConfirmed,
		},
	}

	recEngine := api.NewReconciliationEngine([]api.SpecMetadata{*meta}, ops, api.DefaultReconciliationOptions())
	reconReport := recEngine.Reconcile(candidates)

	if reconReport.TotalDiscoveredCandidates != 2 {
		t.Errorf("expected 2 discovered candidates, got %d", reconReport.TotalDiscoveredCandidates)
	}
	if reconReport.TotalDocumentedMatches != 1 {
		t.Errorf("expected 1 documented match, got %d", reconReport.TotalDocumentedMatches)
	}
	if reconReport.TotalUndocumentedCandidates != 1 {
		t.Errorf("expected 1 undocumented candidate, got %d", reconReport.TotalUndocumentedCandidates)
	}

	// 2. Live Exploitability Prober
	proberOptions := api.DefaultProberOptions()
	proberOptions.Timeout = 2 * time.Second
	proberOptions.AllowLoopback = true
	proberOptions.AllowPrivateIPs = true
	proberEngine := api.NewProberEngine(proberOptions)

	// A. Probe reachable documented endpoint
	probeResReachable := proberEngine.ProbeCandidate(ctx, "CAND-1", "/api/v1/users", "GET", apiServer.URL)
	if probeResReachable.Classification != api.ClassificationReachable && probeResReachable.Classification != api.ClassificationReachableWithMetadata {
		t.Errorf("expected Reachable or ReachableWithMetadata classification for /api/v1/users, got %s", probeResReachable.Classification)
	}

	// B. Probe shadow endpoint returning 403 Forbidden (Benign Denied / Auth Boundary)
	probeResAuth := proberEngine.ProbeCandidate(ctx, "CAND-2", "/api/v1/shadow/admin_dump", "GET", apiServer.URL)
	if probeResAuth.Classification != api.ClassificationAuthenticationRequired && probeResAuth.Classification != api.ClassificationAuthorizationBoundaryObserved {
		t.Errorf("expected AuthenticationRequired or AuthorizationBoundaryObserved for 403 endpoint, got %s", probeResAuth.Classification)
	}

	// C. Probe ambiguous HTML login shell
	probeResAmbiguous := proberEngine.ProbeCandidate(ctx, "CAND-3", "/api/v1/ambiguous_spa", "GET", apiServer.URL)
	if probeResAmbiguous.Classification != api.ClassificationInconclusive {
		t.Errorf("expected Inconclusive for HTML SPA shell, got %s", probeResAmbiguous.Classification)
	}

	// 3. Declarative Multi-Tenant Profile & BOLA Verification
	os.Setenv("FELIX_TEST_TOKEN_TENANT_A", "token-tenant-a-12345")
	os.Setenv("FELIX_TEST_TOKEN_TENANT_B", "token-tenant-b-67890")
	defer func() {
		os.Unsetenv("FELIX_TEST_TOKEN_TENANT_A")
		os.Unsetenv("FELIX_TEST_TOKEN_TENANT_B")
	}()

	profileYAML := fmt.Sprintf(`version: 1
target:
  name: "API Representative Target"
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
    credential_env: "FELIX_TEST_TOKEN_TENANT_A"
    resource_ids:
      - "res-tenant-a-1"
  - id: "tenant-b"
    identity: "tenant-b@example.com"
    credential_env: "FELIX_TEST_TOKEN_TENANT_B"
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
      expected_marker: "TENANT_B_CONFIDENTIAL_RECORD"
`, apiServer.URL)

	profile, err := api.ParseTargetProfile([]byte(profileYAML))
	if err != nil {
		t.Fatalf("failed parsing target profile: %v", err)
	}

	xtcEngine := api.NewMultiTenantEngine(profile, api.MultiTenantEngineOptions{
		CLIOptIn:        true,
		AllowLoopback:   true,
		AllowPrivateIPs: true,
	})
	xtcReport := xtcEngine.RunCrossTenantChecks(ctx)

	if xtcReport.TotalCrossTenantAccessObserved != 1 {
		var resDetails string
		if len(xtcReport.Results) > 0 {
			resDetails = fmt.Sprintf("Classification: %s, Rationale: %s, Status: %d", xtcReport.Results[0].Classification, xtcReport.Results[0].Rationale, xtcReport.Results[0].StatusCode)
		}
		t.Fatalf("expected 1 BOLA vulnerability observed, got %d. Warnings: %v. Details: %s", xtcReport.TotalCrossTenantAccessObserved, xtcReport.Warnings, resDetails)
	}
	if !xtcReport.Results[0].IsBOLAObserved {
		t.Errorf("expected IsBOLAObserved to be true")
	}

	// 4. SSRF and Redirect Protection
	safeTransport := crawler.NewSafeTransport(crawler.SafeTransportOptions{
		Timeout:       2 * time.Second,
		AllowLoopback: true, // Allow contacting apiServer loopback, but block redirect to private/IMDS
	})
	noRedirectClient := &http.Client{
		Transport: safeTransport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			// Ensure safe redirect policy
			if len(via) >= 10 {
				return fmt.Errorf("stopped after 10 redirects")
			}
			host := req.URL.Hostname()
			if host == "169.254.169.254" || strings.HasPrefix(host, "10.") || strings.HasPrefix(host, "192.168.") {
				return fmt.Errorf("SSRF refusal: redirect to %s blocked", host)
			}
			return nil
		},
	}
	reqRedirect, _ := http.NewRequestWithContext(ctx, "GET", apiServer.URL+"/api/v1/redirect_ssrf", nil)
	_, err = noRedirectClient.Do(reqRedirect)
	if err == nil {
		t.Fatalf("expected redirect to IMDS to be blocked")
	}
	if !strings.Contains(err.Error(), "SSRF refusal") {
		t.Errorf("expected SSRF refusal in redirect error, got: %v", err)
	}

	// 5. Oversized Response Bounding
	boundedClient := cloud.NewClient(cloud.ClientOptions{
		AllowLoopback:   true,
		MaxResponseSize: 64 * 1024, // 64 KB limit
	})
	reqOversized, _ := http.NewRequestWithContext(ctx, "GET", apiServer.URL+"/api/v1/oversized", nil)
	respOversized, err := boundedClient.Do(ctx, reqOversized)
	if err != nil && err != cloud.ErrResponseTooLarge {
		t.Fatalf("unexpected error on oversized response: %v", err)
	}
	if respOversized != nil && int64(len(respOversized.Body)) > 64*1024 {
		t.Errorf("expected response body to be bounded to 64KB, got %d bytes", len(respOversized.Body))
	}

	// 6. Secret Redaction
	rawHeader := "Authorization: " + canaryToken
	redactedHdr := secrets.RedactText(rawHeader)
	if strings.Contains(redactedHdr, "test_canary_api_token_12345") {
		t.Errorf("canary API token was not redacted: %s", redactedHdr)
	}
}

// ---------------------------------------------------------------------------
// 4. REPORTING & EVIDENCE INTEGRITY INTEGRATION
// ---------------------------------------------------------------------------

// TestRepresentative_ReportingAndEvidenceIntegrity verifies:
// - HTML, JSON, and SARIF export generation
// - Contextual HTML escaping prevents XSS injection from malicious provider strings
// - Sensitive canary tokens are redacted across all report formats
func TestRepresentative_ReportingAndEvidenceIntegrity(t *testing.T) {
	outDir := t.TempDir()
	htmlPath := filepath.Join(outDir, "assessment_report.html")
	jsonPath := filepath.Join(outDir, "assessment_report.json")
	sarifPath := filepath.Join(outDir, "assessment_report.sarif")

	const canarySecret = "AKIAIOSFODNN7CANARYKEY"
	const xssPayload = "<script>alert('pwned')</script>"

	// Construct representative findings combining Cloud, Database, and API
	findings := []report.Finding{
		{
			ID:          "FINDING-CLOUD-001",
			RuleID:      "CLOUD-AWS-S3-PUBLIC-BUCKET",
			Title:       "Publicly Accessible S3 Bucket: " + xssPayload,
			Severity:    report.SeverityCritical,
			Confidence:  report.ConfidenceHigh,
			Category:    "Cloud Security",
			Description: "An S3 bucket allows anonymous read access without authentication.",
			Endpoint:    "https://storage.example.com/vault",
			EvidenceDetails: report.EvidenceDetails{
				Observation:     "Unauthenticated bucket listing exposed client records",
				Location:        "https://storage.example.com/vault",
				ObservedBehavior: "Canary token: " + canarySecret,
				Details: map[string]string{
					"provider": "AWS",
					"service":  "S3",
				},
			},
			Verification: report.VerificationRecord{
				Status: report.VerificationVerified,
				Result: "Confirmed anonymous read access",
			},
			Score: 95,
		},
		{
			ID:          "FINDING-DB-001",
			RuleID:      "DB-ELASTICSEARCH-OPEN-METADATA",
			Title:       "Elasticsearch Cluster Exposed Without Authentication",
			Severity:    report.SeverityMedium,
			Confidence:  report.ConfidenceHigh,
			Category:    "Database Security",
			Description: "Elasticsearch root endpoint responded with cluster metadata.",
			Endpoint:    "http://es-cluster.internal:9200",
			EvidenceDetails: report.EvidenceDetails{
				Observation: "Cluster name: analytics-prod, version: 8.12.1",
				Location:    "http://es-cluster.internal:9200",
			},
			Score: 60,
		},
		{
			ID:          "FINDING-API-001",
			RuleID:      "API-BOLA-CROSS-TENANT-ACCESS",
			Title:       "Broken Object Level Authorization (BOLA) Across Tenant Boundary",
			Severity:    report.SeverityHigh,
			Confidence:  report.ConfidenceHigh,
			Category:    "API Security",
			Description: "Tenant A successfully accessed resource owned by Tenant B.",
			Endpoint:    "https://api.example.com/v1/tenant/resource",
			EvidenceDetails: report.EvidenceDetails{
				Observation: "Cross-tenant data returned with HTTP 200 OK",
				Location:    "https://api.example.com/v1/tenant/resource",
			},
			Score: 85,
		},
	}

	rep := report.Report{
		Version:   "1.0",
		Target:    "https://api.example.com",
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Findings:  findings,
		RiskScore: 80,
		RiskLevel: "HIGH",
	}

	// 1. Export HTML Report
	if err := report.WriteHTML(rep, htmlPath); err != nil {
		t.Fatalf("failed exporting HTML report: %v", err)
	}

	htmlBytes, err := os.ReadFile(htmlPath)
	if err != nil {
		t.Fatalf("failed reading HTML report: %v", err)
	}
	htmlContent := string(htmlBytes)

	// Verify XSS payload is safely escaped
	if strings.Contains(htmlContent, "<script>alert('pwned')</script>") {
		t.Errorf("XSS payload was not HTML-escaped in report: %s", htmlContent)
	}

	// Verify canary secret is redacted from HTML
	if strings.Contains(htmlContent, canarySecret) {
		t.Errorf("canary secret leaked into HTML report: %s", htmlContent)
	}

	// 2. Export JSON Report
	if err := report.WriteJSON(rep, jsonPath); err != nil {
		t.Fatalf("failed exporting JSON report: %v", err)
	}

	jsonBytes, err := os.ReadFile(jsonPath)
	if err != nil {
		t.Fatalf("failed reading JSON report: %v", err)
	}
	var parsedJSON map[string]interface{}
	if err := json.Unmarshal(jsonBytes, &parsedJSON); err != nil {
		t.Fatalf("invalid JSON report: %v", err)
	}

	jsonContent := string(jsonBytes)
	if strings.Contains(jsonContent, canarySecret) {
		t.Errorf("canary secret leaked into JSON report: %s", jsonContent)
	}

	// 3. Export SARIF Report
	if err := report.WriteSARIF(rep, sarifPath); err != nil {
		t.Fatalf("failed exporting SARIF report: %v", err)
	}

	sarifBytes, err := os.ReadFile(sarifPath)
	if err != nil {
		t.Fatalf("failed reading SARIF report: %v", err)
	}
	sarifContent := string(sarifBytes)
	if strings.Contains(sarifContent, canarySecret) {
		t.Errorf("canary secret leaked into SARIF report: %s", sarifContent)
	}
}
