package apisec

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"felix/pkg/auth"
	"felix/pkg/authz"
	"felix/pkg/report"
)

func TestOWASPCategoryMetadataCoverage(t *testing.T) {
	expectedCategories := []OWASPCategory{
		CategoryAPI1_BOLA,
		CategoryAPI2_BrokenAuth,
		CategoryAPI3_BOPLA,
		CategoryAPI4_ResourceConsumption,
		CategoryAPI5_BFLA,
		CategoryAPI6_BusinessFlows,
		CategoryAPI7_SSRF,
		CategoryAPI8_Misconfiguration,
		CategoryAPI9_ImproperInventory,
		CategoryAPI10_UnsafeConsumption,
	}

	if len(expectedCategories) != 10 {
		t.Fatalf("expected 10 OWASP categories, got %d", len(expectedCategories))
	}

	for _, cat := range expectedCategories {
		meta, ok := OWASPCategoryMetadata[cat]
		if !ok {
			t.Errorf("missing metadata for category %s", cat)
			continue
		}
		if meta.Code == "" || meta.Name == "" || meta.Description == "" {
			t.Errorf("incomplete metadata for category %s: %+v", cat, meta)
		}
		if !strings.HasPrefix(meta.Code, "API") || !strings.HasSuffix(meta.Code, ":2023") {
			t.Errorf("invalid OWASP code format %q for category %s", meta.Code, cat)
		}
	}
}

func TestSanitizeAndRedaction(t *testing.T) {
	headers := http.Header{
		"Authorization":   []string{"Bearer secret_token_12345"},
		"Cookie":          []string{"session_id=abcdef1234567890"},
		"X-Custom-Header": []string{"PublicValue"},
	}

	sanitizedHeaders := SanitizeHeaders(headers)
	if strings.Contains(sanitizedHeaders["Authorization"], "secret_token") {
		t.Errorf("expected Authorization header to be redacted, got %s", sanitizedHeaders["Authorization"])
	}
	if strings.Contains(sanitizedHeaders["Cookie"], "abcdef") {
		t.Errorf("expected Cookie header to be redacted, got %s", sanitizedHeaders["Cookie"])
	}
	if sanitizedHeaders["X-Custom-Header"] != "PublicValue" {
		t.Errorf("expected non-sensitive header preserved, got %s", sanitizedHeaders["X-Custom-Header"])
	}

	rawURL := "https://api.example.com/v1/user?token=supersecret123&key=xyz"
	sanitizedURL := SanitizeURL(rawURL)
	if strings.Contains(sanitizedURL, "supersecret123") {
		t.Errorf("expected query token redacted in URL, got %s", sanitizedURL)
	}

	body := []byte(`{"username":"alice","password":"mypassword123","token":"jwt.token.val","email":"alice@example.com"}`)
	redactedBody := RedactBody(body, 0)
	var bodyMap map[string]any
	if err := json.Unmarshal([]byte(redactedBody), &bodyMap); err != nil {
		t.Fatalf("failed to unmarshal redacted body: %v", err)
	}
	if bodyMap["password"] != "[REDACTED]" {
		t.Errorf("expected password redacted, got %v", bodyMap["password"])
	}
	if bodyMap["token"] != "[REDACTED]" {
		t.Errorf("expected token redacted, got %v", bodyMap["token"])
	}
	if bodyMap["username"] != "alice" {
		t.Errorf("expected username preserved, got %v", bodyMap["username"])
	}
}

func TestSSRFInternalAddressGuards(t *testing.T) {
	internalTargets := []string{
		"http://localhost/admin",
		"http://127.0.0.1:8080/metrics",
		"http://169.254.169.254/latest/meta-data/",
		"http://10.0.0.1/internal",
		"http://192.168.1.1/router",
		"http://172.16.0.5/api",
		"http://myhost.local/service",
	}

	for _, target := range internalTargets {
		if !isInternalAddress(target) {
			t.Errorf("expected target %s to be flagged as internal/dangerous", target)
		}
	}

	safeTargets := []string{
		"https://canary.validtest.org/callback",
		"https://api.webhookservice.com/notify",
	}

	for _, target := range safeTargets {
		if isInternalAddress(target) {
			t.Errorf("expected target %s to be identified as safe/external", target)
		}
	}
}

func TestAnalyzeEndpointHeuristics(t *testing.T) {
	// Test 1: BOLA Object reference
	ep1 := AnalyzeEndpoint("GET", "/api/v1/users/42", "discovered")
	if !ep1.IsObjectRef {
		t.Errorf("expected IsObjectRef to be true for /api/v1/users/42")
	}
	if ep1.Version != "v1" {
		t.Errorf("expected version v1, got %s", ep1.Version)
	}

	// Test 2: Privileged admin route (BFLA)
	ep2 := AnalyzeEndpoint("DELETE", "/api/v2/admin/users/all", "discovered")
	if !ep2.IsPrivileged {
		t.Errorf("expected IsPrivileged to be true for /api/v2/admin/users/all")
	}
	if ep2.Version != "v2" {
		t.Errorf("expected version v2, got %s", ep2.Version)
	}

	// Test 3: Sensitive business flow (API6)
	ep3 := AnalyzeEndpoint("POST", "/auth/register", "discovered")
	if !ep3.IsBusinessFlow || ep3.BusinessFlow != "USER_REGISTRATION" {
		t.Errorf("expected IsBusinessFlow USER_REGISTRATION, got %s (%t)", ep3.BusinessFlow, ep3.IsBusinessFlow)
	}

	// Test 4: SSRF URL parameter
	ep4 := AnalyzeEndpoint("GET", "/api/preview?url=https://example.com", "discovered")
	if !ep4.HasURLParam || ep4.URLParamName != "url" {
		t.Errorf("expected HasURLParam for preview?url, got %t (%s)", ep4.HasURLParam, ep4.URLParamName)
	}

	// Test 5: Resource consumption pagination
	ep5 := AnalyzeEndpoint("GET", "/api/items?limit=100", "discovered")
	if !ep5.HasPagination || ep5.PaginationParam != "limit" {
		t.Errorf("expected HasPagination for items?limit, got %t (%s)", ep5.HasPagination, ep5.PaginationParam)
	}
}

func TestLoadDeclaredSpec(t *testing.T) {
	tmpDir := t.TempDir()

	// 1. OpenAPI JSON Spec
	openAPIContent := `{
		"openapi": "3.0.0",
		"paths": {
			"/users": {
				"get": {},
				"post": {}
			},
			"/users/{id}": {
				"get": {}
			}
		}
	}`
	openAPIFile := filepath.Join(tmpDir, "openapi.json")
	if err := os.WriteFile(openAPIFile, []byte(openAPIContent), 0644); err != nil {
		t.Fatalf("failed to write openapi file: %v", err)
	}

	spec1, err := LoadDeclaredSpec(openAPIFile)
	if err != nil {
		t.Fatalf("LoadDeclaredSpec openapi failed: %v", err)
	}
	if len(spec1.Endpoints) != 3 {
		t.Errorf("expected 3 declared endpoints, got %d", len(spec1.Endpoints))
	}
	if _, ok := spec1.Endpoints["GET:/users"]; !ok {
		t.Errorf("expected GET:/users in spec")
	}
	if _, ok := spec1.Endpoints["POST:/users"]; !ok {
		t.Errorf("expected POST:/users in spec")
	}

	// 2. Line-delimited spec
	linesContent := "GET /api/v1/health\nPOST /api/v1/login\n# comment\nGET /api/v1/profile\n"
	linesFile := filepath.Join(tmpDir, "routes.txt")
	if err := os.WriteFile(linesFile, []byte(linesContent), 0644); err != nil {
		t.Fatalf("failed to write lines file: %v", err)
	}

	spec2, err := LoadDeclaredSpec(linesFile)
	if err != nil {
		t.Fatalf("LoadDeclaredSpec lines failed: %v", err)
	}
	if len(spec2.Endpoints) != 3 {
		t.Errorf("expected 3 declared endpoints, got %d", len(spec2.Endpoints))
	}
	if _, ok := spec2.Endpoints["GET:/api/v1/health"]; !ok {
		t.Errorf("expected GET:/api/v1/health in spec")
	}
}

func TestEngineAssessAllTenCategories(t *testing.T) {
	// Set up deterministic mock test server
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Provide RateLimit header to test API4
		w.Header().Set("RateLimit-Limit", "100")
		w.Header().Set("RateLimit-Remaining", "99")

		// Missing X-Content-Type-Options: nosniff to test API8
		// Insecure Access-Control-Allow-Origin: * to test API8 CORS
		w.Header().Set("Access-Control-Allow-Origin", "*")

		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"ok","items":["item1","item2"]}`))
	}))
	defer ts.Close()

	engine := NewEngine(ts.Client(), DefaultConfig())

	// Build assessment context covering all 10 OWASP categories
	actx := &AssessmentContext{
		AssessmentID: "test-assessment-uuid",
		ExecutionID:  "test-exec-uuid",
		BaseURL:      ts.URL,
		Endpoints: []APIEndpoint{
			AnalyzeEndpoint("GET", "/api/v1/users/123", "discovered"),                // API1 object ref, v1
			AnalyzeEndpoint("GET", "/api/v2/products", "discovered"),                 // v2 (API9 version coexistence)
			AnalyzeEndpoint("POST", "/api/v1/admin/delete", "discovered"),            // API5 privileged
			AnalyzeEndpoint("POST", "/auth/register", "discovered"),                  // API6 business flow
			AnalyzeEndpoint("GET", "/preview?url=https://other.com", "discovered"),   // API7 SSRF
			AnalyzeEndpoint("GET", "/api/v1/items?limit=50", "discovered"),           // API4 pagination
			AnalyzeEndpoint("GET", "/api/v1/undocumented-route", "discovered"),       // API9 shadow route
			AnalyzeEndpoint("GET", "/api/integrations/stripe.com/charge", "discovered"), // API10 third-party
		},
		AuthInv: &auth.AuthInventory{
			Surfaces: []auth.AuthSurface{
				{Category: auth.CategoryLogin, Identifier: ts.URL + "/auth/login"},
			},
			Cookies: []auth.CookieMetadata{
				{
					Name:             "session_token",
					SourceURL:        ts.URL + "/auth/login",
					IsSession:        true,
					HasSecurityIssue: true,
					SecurityDefects:  []string{"Missing HttpOnly flag", "Missing Secure attribute"},
				},
			},
			Tokens: []auth.TokenArtifact{
				{
					Name:            "access_token",
					TokenType:       "JWT",
					Algorithm:       "none",
					SourceAsset:     ts.URL + "/token",
					EvidenceSummary: "JWT declares insecure alg=none algorithm",
				},
			},
		},
		AuthzResults: []authz.AuthzTestResult{
			{
				Category:          authz.CategoryBOLA,
				Endpoint:          "/api/v1/users/123",
				Method:            "GET",
				VerificationState: authz.StateVerified,
				ObservedStatus:    200,
				EvidenceSummary:   "Tenant B accessed Tenant A record /api/v1/users/123 with status 200 OK",
			},
			{
				Category:          authz.CategoryBOPLAExposure,
				Endpoint:          "/api/v1/users/123",
				Method:            "GET",
				VerificationState: authz.StateVerified,
				ObservedStatus:    200,
				EvidenceSummary:   "Sensitive property 'is_admin' exposed in response body",
			},
			{
				Category:          authz.CategoryBFLA,
				Endpoint:          "/api/v1/admin/delete",
				Method:            "POST",
				VerificationState: authz.StateVerified,
				ObservedStatus:    200,
				EvidenceSummary:   "Unprivileged user invoked admin function /api/v1/admin/delete with status 200 OK",
			},
		},
		DeclaredSpec: &DeclaredSpec{
			Endpoints: map[string]struct{}{
				"GET:/api/v1/users/123": {},
				"GET:/api/v2/products":  {},
			},
		},
	}

	results, findings, summary, err := engine.Assess(context.Background(), actx)
	if err != nil {
		t.Fatalf("engine.Assess failed: %v", err)
	}

	if summary.TotalTests == 0 {
		t.Fatalf("expected tests to run, got 0")
	}
	if summary.CategoriesCovered != 10 {
		t.Errorf("expected 10 categories covered, got %d", summary.CategoriesCovered)
	}

	// Verify Category 1 (BOLA)
	cov1 := summary.CoverageMap[string(CategoryAPI1_BOLA)]
	if cov1.Status != CoverageVerifiedIssueFound || cov1.Verified == 0 {
		t.Errorf("expected API1 BOLA verified vulnerability, got status=%s, verified=%d", cov1.Status, cov1.Verified)
	}

	// Verify Category 2 (Broken Auth)
	cov2 := summary.CoverageMap[string(CategoryAPI2_BrokenAuth)]
	if cov2.Status != CoverageVerifiedIssueFound || cov2.Verified == 0 {
		t.Errorf("expected API2 Broken Auth verified issue, got status=%s, verified=%d", cov2.Status, cov2.Verified)
	}

	// Verify Category 3 (BOPLA)
	cov3 := summary.CoverageMap[string(CategoryAPI3_BOPLA)]
	if cov3.Status != CoverageVerifiedIssueFound || cov3.Verified == 0 {
		t.Errorf("expected API3 BOPLA verified issue, got status=%s, verified=%d", cov3.Status, cov3.Verified)
	}

	// Verify Category 4 (Resource Consumption)
	cov4 := summary.CoverageMap[string(CategoryAPI4_ResourceConsumption)]
	if cov4.Status != CoverageActivelyTested {
		t.Errorf("expected API4 actively tested, got %s", cov4.Status)
	}

	// Verify Category 5 (BFLA)
	cov5 := summary.CoverageMap[string(CategoryAPI5_BFLA)]
	if cov5.Status != CoverageVerifiedIssueFound || cov5.Verified == 0 {
		t.Errorf("expected API5 BFLA verified issue, got status=%s, verified=%d", cov5.Status, cov5.Verified)
	}

	// Verify Category 6 (Business Flows)
	cov6 := summary.CoverageMap[string(CategoryAPI6_BusinessFlows)]
	if cov6.Observations == 0 {
		t.Errorf("expected API6 business flow observations, got 0")
	}

	// Verify Category 7 (SSRF)
	cov7 := summary.CoverageMap[string(CategoryAPI7_SSRF)]
	if cov7.Observations == 0 {
		t.Errorf("expected API7 SSRF observations, got 0")
	}

	// Verify Category 8 (Security Misconfiguration)
	cov8 := summary.CoverageMap[string(CategoryAPI8_Misconfiguration)]
	if cov8.Observations == 0 {
		t.Errorf("expected API8 misconfiguration observations, got 0")
	}
	if cov8.Verified > 0 {
		t.Errorf("missing nosniff alone should not produce verified issues, got verified=%d", cov8.Verified)
	}

	// Verify Category 9 (Improper Inventory)
	cov9 := summary.CoverageMap[string(CategoryAPI9_ImproperInventory)]
	if cov9.Candidates == 0 {
		t.Errorf("expected API9 shadow API candidate drift, got 0")
	}
	if cov9.Verified > 0 {
		t.Errorf("shadow API drift should not be verified vulnerability, got verified=%d", cov9.Verified)
	}

	// Verify Category 10 (Unsafe Consumption)
	cov10 := summary.CoverageMap[string(CategoryAPI10_UnsafeConsumption)]
	if cov10.Observations == 0 {
		t.Errorf("expected API10 observation for stripe.com integration, got 0")
	}

	if summary.ObservedCount == 0 {
		t.Errorf("expected observed count in summary, got 0")
	}

	// Verify Findings Generation
	if len(findings) == 0 {
		t.Fatalf("expected findings generated, got 0")
	}
	for _, f := range findings {
		if f.Fingerprint == "" {
			t.Errorf("finding %s missing fingerprint", f.ID)
		}
		if f.Severity == "" {
			t.Errorf("finding %s missing severity", f.ID)
		}
		if f.Score < 0 {
			t.Errorf("finding %s invalid score: %d", f.ID, f.Score)
		}
	}

	// Check Results
	if len(results) == 0 {
		t.Fatalf("expected results recorded, got 0")
	}
}

func TestPassiveModeAndPrerequisiteHandling(t *testing.T) {
	engine := NewEngine(nil, DefaultConfig())

	actx := &AssessmentContext{
		AssessmentID: "test-assessment-passive",
		ExecutionID:  "test-exec-passive",
		BaseURL:      "http://example.com",
		Endpoints: []APIEndpoint{
			AnalyzeEndpoint("GET", "/api/v1/orders/123", "discovered"),
			AnalyzeEndpoint("GET", "/admin/settings", "discovered"),
		},
	}

	results, _, summary, err := engine.Assess(context.Background(), actx)
	if err != nil {
		t.Fatalf("engine.Assess failed: %v", err)
	}

	cov1 := summary.CoverageMap[string(CategoryAPI1_BOLA)]
	if cov1.Status != CoveragePrereqMissing {
		t.Errorf("expected API1 status PREREQUISITE_MISSING, got %s", cov1.Status)
	}

	cov5 := summary.CoverageMap[string(CategoryAPI5_BFLA)]
	if cov5.Status != CoveragePrereqMissing {
		t.Errorf("expected API5 status PREREQUISITE_MISSING, got %s", cov5.Status)
	}

	foundObserved := false
	for _, r := range results {
		if r.VerificationState == StateObserved {
			foundObserved = true
			break
		}
	}
	if !foundObserved {
		t.Errorf("expected observed results when prerequisites are missing")
	}
}

func TestMisconfigurationVerboseErrors(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("Traceback (most recent call last):\n  File \"app.py\", line 42, in index\n    ZeroDivisionError: division by zero"))
	}))
	defer ts.Close()

	engine := NewEngine(ts.Client(), DefaultConfig())
	actx := &AssessmentContext{
		AssessmentID: "test-assessment-err",
		ExecutionID:  "test-exec-err",
		BaseURL:      ts.URL,
		Endpoints: []APIEndpoint{
			AnalyzeEndpoint("GET", "/error", "discovered"),
		},
	}

	_, findings, summary, err := engine.Assess(context.Background(), actx)
	if err != nil {
		t.Fatalf("engine.Assess failed: %v", err)
	}

	cov8 := summary.CoverageMap[string(CategoryAPI8_Misconfiguration)]
	if cov8.Status != CoverageVerifiedIssueFound || cov8.Verified == 0 {
		t.Errorf("expected API8 verified issue for verbose traceback, got status=%s, verified=%d", cov8.Status, cov8.Verified)
	}

	foundTracebackFinding := false
	for _, f := range findings {
		if strings.Contains(f.Title, "Verbose Error") {
			foundTracebackFinding = true
			break
		}
	}
	if !foundTracebackFinding {
		t.Errorf("expected Verbose Error finding in findings list")
	}
}

func TestRegression1_MissingXContentTypeOptions_NotVerified(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"ok"}`))
	}))
	defer ts.Close()

	engine := NewEngine(ts.Client(), DefaultConfig())
	actx := &AssessmentContext{
		AssessmentID: "test-reg-1",
		ExecutionID:  "exec-reg-1",
		BaseURL:      ts.URL,
		Endpoints: []APIEndpoint{
			AnalyzeEndpoint("GET", "/api/v1/health", "discovered"),
		},
	}

	results, findings, summary, err := engine.Assess(context.Background(), actx)
	if err != nil {
		t.Fatalf("Assess failed: %v", err)
	}

	cov8 := summary.CoverageMap[string(CategoryAPI8_Misconfiguration)]
	if cov8.Verified > 0 {
		t.Errorf("regression: missing X-Content-Type-Options must NOT produce verified findings, got %d", cov8.Verified)
	}
	if cov8.Status == CoverageVerifiedIssueFound {
		t.Errorf("regression: status should not be CoverageVerifiedIssueFound, got %s", cov8.Status)
	}

	for _, f := range findings {
		if strings.Contains(f.Title, "X-Content-Type-Options") && f.Verification.Status == report.VerificationVerified {
			t.Errorf("found unexpected verified finding for nosniff: %s", f.Title)
		}
	}

	foundNosniffResult := false
	for _, r := range results {
		if r.Category == CategoryAPI8_Misconfiguration && strings.Contains(r.TestName, "X-Content-Type-Options") {
			foundNosniffResult = true
			if r.VerificationState == StateVerified {
				t.Errorf("nosniff result verification state must not be StateVerified, got %s", r.VerificationState)
			}
			if r.Severity != report.SeverityInfo {
				t.Errorf("expected severity INFO for missing nosniff, got %s", r.Severity)
			}
		}
	}
	if !foundNosniffResult {
		t.Errorf("expected to find nosniff evaluation result")
	}
}

func TestRegression2_MissingCookieFlagsHTTPS_NotSessionCompromise(t *testing.T) {
	engine := NewEngine(nil, DefaultConfig())
	actx := &AssessmentContext{
		AssessmentID: "test-reg-2",
		ExecutionID:  "exec-reg-2",
		BaseURL:      "https://secure.example.com",
		AuthInv: &auth.AuthInventory{
			Cookies: []auth.CookieMetadata{
				{
					Name:             "auth_session",
					SourceURL:        "https://secure.example.com/login",
					IsSession:        true,
					IsSecure:         true,
					HasSecurityIssue: true,
					SecurityDefects:  []string{"Missing HttpOnly flag", "Missing SameSite attribute"},
				},
			},
		},
	}

	results, _, summary, err := engine.Assess(context.Background(), actx)
	if err != nil {
		t.Fatalf("Assess failed: %v", err)
	}

	cov2 := summary.CoverageMap[string(CategoryAPI2_BrokenAuth)]
	if cov2.Verified > 0 {
		t.Errorf("regression: HTTPS session cookie missing defense-in-depth flags must NOT be verified compromise, got verified=%d", cov2.Verified)
	}
	if cov2.Candidates == 0 {
		t.Errorf("expected candidate hardening issue for HTTPS session cookie missing HttpOnly")
	}

	for _, r := range results {
		if r.Category == CategoryAPI2_BrokenAuth && strings.Contains(r.EvidenceSummary, "auth_session") {
			if r.VerificationState != StateCandidate {
				t.Errorf("expected StateCandidate for HTTPS cookie hardening, got %s", r.VerificationState)
			}
			if r.Severity != report.SeverityLow {
				t.Errorf("expected SeverityLow, got %s", r.Severity)
			}
		}
	}
}

func TestRegression3_WildcardCORS_CredentialsEvaluation(t *testing.T) {
	t.Run("WildcardWithoutCredentials_Observed", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Access-Control-Allow-Origin", "*")
			w.WriteHeader(http.StatusOK)
		}))
		defer ts.Close()

		engine := NewEngine(ts.Client(), DefaultConfig())
		actx := &AssessmentContext{
			AssessmentID: "test-reg-3a",
			BaseURL:      ts.URL,
			Endpoints:    []APIEndpoint{AnalyzeEndpoint("GET", "/api/public", "discovered")},
		}

		results, _, summary, err := engine.Assess(context.Background(), actx)
		if err != nil {
			t.Fatalf("Assess failed: %v", err)
		}

		cov8 := summary.CoverageMap[string(CategoryAPI8_Misconfiguration)]
		if cov8.Verified > 0 {
			t.Errorf("uncredentialed CORS wildcard should not produce verified finding, got %d", cov8.Verified)
		}

		foundObservedCORS := false
		for _, r := range results {
			if strings.Contains(r.TestName, "CORS") {
				foundObservedCORS = true
				if r.VerificationState != StateObserved {
					t.Errorf("expected StateObserved for uncredentialed CORS wildcard, got %s", r.VerificationState)
				}
			}
		}
		if !foundObservedCORS {
			t.Errorf("expected CORS evaluation result")
		}
	})

	t.Run("WildcardWithCredentials_Verified", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Access-Control-Allow-Origin", "*")
			w.Header().Set("Access-Control-Allow-Credentials", "true")
			w.WriteHeader(http.StatusOK)
		}))
		defer ts.Close()

		engine := NewEngine(ts.Client(), DefaultConfig())
		actx := &AssessmentContext{
			AssessmentID: "test-reg-3b",
			BaseURL:      ts.URL,
			Endpoints:    []APIEndpoint{AnalyzeEndpoint("GET", "/api/private", "discovered")},
		}

		results, findings, summary, err := engine.Assess(context.Background(), actx)
		if err != nil {
			t.Fatalf("Assess failed: %v", err)
		}

		cov8 := summary.CoverageMap[string(CategoryAPI8_Misconfiguration)]
		if cov8.Verified != 1 || cov8.Status != CoverageVerifiedIssueFound {
			t.Errorf("expected verified issue for credentialed CORS wildcard, got status=%s, verified=%d", cov8.Status, cov8.Verified)
		}

		foundVerifiedCORS := false
		for _, r := range results {
			if strings.Contains(r.TestName, "Credentialed CORS") {
				foundVerifiedCORS = true
				if r.VerificationState != StateVerified {
					t.Errorf("expected StateVerified, got %s", r.VerificationState)
				}
			}
		}
		if !foundVerifiedCORS {
			t.Errorf("expected Credentialed CORS result")
		}

		if len(findings) == 0 {
			t.Errorf("expected finding generated for credentialed CORS wildcard")
		}
	})
}

func TestRegression4_UndocumentedEndpoint_CandidateNotVerified(t *testing.T) {
	engine := NewEngine(nil, DefaultConfig())
	actx := &AssessmentContext{
		AssessmentID: "test-reg-4",
		BaseURL:      "http://example.com",
		Endpoints: []APIEndpoint{
			AnalyzeEndpoint("GET", "/api/v1/documented", "discovered"),
			AnalyzeEndpoint("POST", "/api/v1/undocumented", "discovered"),
		},
		DeclaredSpec: &DeclaredSpec{
			Endpoints: map[string]struct{}{
				"GET:/api/v1/documented": {},
			},
		},
	}

	results, _, summary, err := engine.Assess(context.Background(), actx)
	if err != nil {
		t.Fatalf("Assess failed: %v", err)
	}

	cov9 := summary.CoverageMap[string(CategoryAPI9_ImproperInventory)]
	if cov9.Verified > 0 {
		t.Errorf("undocumented endpoint drift must NOT be verified vulnerability, got %d", cov9.Verified)
	}
	if cov9.Status == CoverageVerifiedIssueFound {
		t.Errorf("status must not be CoverageVerifiedIssueFound, got %s", cov9.Status)
	}
	if cov9.Candidates != 1 {
		t.Errorf("expected 1 candidate drift, got %d", cov9.Candidates)
	}

	for _, r := range results {
		if r.Category == CategoryAPI9_ImproperInventory && strings.Contains(r.Endpoint, "undocumented") {
			if r.VerificationState != StateCandidate {
				t.Errorf("expected StateCandidate for spec drift, got %s", r.VerificationState)
			}
			if r.Severity != report.SeverityInfo {
				t.Errorf("expected SeverityInfo, got %s", r.Severity)
			}
		}
	}
}

func TestRegression5_MultipleAPIVersions_ObservedNotVerified(t *testing.T) {
	engine := NewEngine(nil, DefaultConfig())
	actx := &AssessmentContext{
		AssessmentID: "test-reg-5",
		BaseURL:      "http://example.com",
		Endpoints: []APIEndpoint{
			AnalyzeEndpoint("GET", "/api/v1/users", "discovered"),
			AnalyzeEndpoint("GET", "/api/v2/users", "discovered"),
		},
	}

	results, _, summary, err := engine.Assess(context.Background(), actx)
	if err != nil {
		t.Fatalf("Assess failed: %v", err)
	}

	cov9 := summary.CoverageMap[string(CategoryAPI9_ImproperInventory)]
	if cov9.Verified > 0 {
		t.Errorf("version coexistence must NOT be verified vulnerability, got %d", cov9.Verified)
	}
	if cov9.Observations == 0 {
		t.Errorf("expected version coexistence observation, got 0")
	}

	foundVersionObs := false
	for _, r := range results {
		if r.Category == CategoryAPI9_ImproperInventory && strings.Contains(r.TestName, "Versions") {
			foundVersionObs = true
			if r.VerificationState != StateObserved {
				t.Errorf("expected StateObserved for version coexistence, got %s", r.VerificationState)
			}
		}
	}
	if !foundVersionObs {
		t.Errorf("expected version coexistence result")
	}
}

func TestRegression6_MissingRateLimitHeaders_ObservedAndHTTP429NotVulnerable(t *testing.T) {
	t.Run("MissingHeaders_ObservedNotVerified", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))
		defer ts.Close()

		engine := NewEngine(ts.Client(), DefaultConfig())
		actx := &AssessmentContext{
			AssessmentID: "test-reg-6a",
			BaseURL:      ts.URL,
			Endpoints:    []APIEndpoint{AnalyzeEndpoint("GET", "/api/items", "discovered")},
		}

		results, _, summary, err := engine.Assess(context.Background(), actx)
		if err != nil {
			t.Fatalf("Assess failed: %v", err)
		}

		cov4 := summary.CoverageMap[string(CategoryAPI4_ResourceConsumption)]
		if cov4.Verified > 0 {
			t.Errorf("missing ratelimit headers must NOT be verified, got %d", cov4.Verified)
		}

		foundObs := false
		for _, r := range results {
			if r.Category == CategoryAPI4_ResourceConsumption && strings.Contains(r.TestName, "Telemetry") {
				foundObs = true
				if r.VerificationState != StateObserved {
					t.Errorf("expected StateObserved, got %s", r.VerificationState)
				}
			}
		}
		if !foundObs {
			t.Errorf("expected rate limit observation result")
		}
	})

	t.Run("HTTP429_NotVulnerable", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusTooManyRequests)
		}))
		defer ts.Close()

		engine := NewEngine(ts.Client(), DefaultConfig())
		actx := &AssessmentContext{
			AssessmentID: "test-reg-6b",
			BaseURL:      ts.URL,
			Endpoints:    []APIEndpoint{AnalyzeEndpoint("GET", "/api/items", "discovered")},
		}

		results, _, summary, err := engine.Assess(context.Background(), actx)
		if err != nil {
			t.Fatalf("Assess failed: %v", err)
		}

		cov4 := summary.CoverageMap[string(CategoryAPI4_ResourceConsumption)]
		if cov4.Verified > 0 {
			t.Errorf("HTTP 429 must not be verified finding, got %d", cov4.Verified)
		}

		foundNotVuln := false
		for _, r := range results {
			if r.Category == CategoryAPI4_ResourceConsumption && r.VerificationState == StateNotVulnerable {
				foundNotVuln = true
			}
		}
		if !foundNotVuln {
			t.Errorf("expected StateNotVulnerable result for HTTP 429 response")
		}
	})
}

func TestRegression7_StaticJWTAlgNone_CandidateIndicator(t *testing.T) {
	engine := NewEngine(nil, DefaultConfig())
	actx := &AssessmentContext{
		AssessmentID: "test-reg-7",
		BaseURL:      "http://example.com",
		AuthInv: &auth.AuthInventory{
			Tokens: []auth.TokenArtifact{
				{
					Name:        "auth_jwt",
					TokenType:   "JWT",
					Algorithm:   "none",
					SourceAsset: "http://example.com/bundle.js",
				},
			},
		},
	}

	results, _, summary, err := engine.Assess(context.Background(), actx)
	if err != nil {
		t.Fatalf("Assess failed: %v", err)
	}

	cov2 := summary.CoverageMap[string(CategoryAPI2_BrokenAuth)]
	if cov2.Verified > 0 {
		t.Errorf("static alg=none must NOT produce verified vulnerability, got %d", cov2.Verified)
	}
	if cov2.Candidates != 1 {
		t.Errorf("expected 1 candidate indicator, got %d", cov2.Candidates)
	}

	for _, r := range results {
		if r.Category == CategoryAPI2_BrokenAuth && strings.Contains(r.TestName, "JWT") {
			if r.VerificationState != StateCandidate {
				t.Errorf("expected StateCandidate, got %s", r.VerificationState)
			}
			if r.Severity != report.SeverityLow {
				t.Errorf("expected SeverityLow, got %s", r.Severity)
			}
		}
	}
}

func TestRegression8_BusinessFlowDiscovery_ObservedNotVulnerability(t *testing.T) {
	engine := NewEngine(nil, DefaultConfig())
	actx := &AssessmentContext{
		AssessmentID: "test-reg-8",
		BaseURL:      "http://example.com",
		Endpoints: []APIEndpoint{
			AnalyzeEndpoint("POST", "/api/v1/auth/register", "discovered"),
			AnalyzeEndpoint("POST", "/api/v1/orders/checkout", "discovered"),
			AnalyzeEndpoint("POST", "/api/v1/auth/password-reset", "discovered"),
		},
	}

	results, _, summary, err := engine.Assess(context.Background(), actx)
	if err != nil {
		t.Fatalf("Assess failed: %v", err)
	}

	cov6 := summary.CoverageMap[string(CategoryAPI6_BusinessFlows)]
	if cov6.Verified > 0 {
		t.Errorf("business flow discovery must NOT be verified vulnerability, got %d", cov6.Verified)
	}
	if cov6.Candidates > 0 {
		t.Errorf("business flow discovery must NOT be candidate vulnerability, got %d", cov6.Candidates)
	}
	if cov6.Observations != 3 {
		t.Errorf("expected 3 observations, got %d", cov6.Observations)
	}

	for _, r := range results {
		if r.Category == CategoryAPI6_BusinessFlows {
			if r.VerificationState != StateObserved {
				t.Errorf("expected StateObserved for business flow, got %s", r.VerificationState)
			}
			if r.Severity != report.SeverityInfo {
				t.Errorf("expected SeverityInfo, got %s", r.Severity)
			}
		}
	}
}

func TestRegression9_URLParamSSRF_CandidateOrObservedNotVerified(t *testing.T) {
	t.Run("WithoutCanary_Observed", func(t *testing.T) {
		engine := NewEngine(nil, DefaultConfig())
		actx := &AssessmentContext{
			AssessmentID: "test-reg-9a",
			BaseURL:      "http://example.com",
			Endpoints: []APIEndpoint{
				AnalyzeEndpoint("GET", "/fetch?url=https://other.com", "discovered"),
			},
		}

		results, _, summary, err := engine.Assess(context.Background(), actx)
		if err != nil {
			t.Fatalf("Assess failed: %v", err)
		}

		cov7 := summary.CoverageMap[string(CategoryAPI7_SSRF)]
		if cov7.Verified > 0 {
			t.Errorf("SSRF parameter discovery must NOT be verified, got %d", cov7.Verified)
		}
		if cov7.Candidates > 0 {
			t.Errorf("without canary, should be observed, not candidate, got %d candidates", cov7.Candidates)
		}
		if cov7.Observations != 1 {
			t.Errorf("expected 1 observation, got %d", cov7.Observations)
		}

		for _, r := range results {
			if r.Category == CategoryAPI7_SSRF {
				if r.VerificationState != StateObserved {
					t.Errorf("expected StateObserved, got %s", r.VerificationState)
				}
			}
		}
	})

	t.Run("WithCanary_CandidateNotVerified", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))
		defer ts.Close()

		cfg := DefaultConfig()
		cfg.CanaryCallbackURL = "https://safe-canary.external.domain/notify"
		engine := NewEngine(ts.Client(), cfg)

		actx := &AssessmentContext{
			AssessmentID: "test-reg-9b",
			BaseURL:      ts.URL,
			Endpoints: []APIEndpoint{
				AnalyzeEndpoint("GET", "/fetch?url=https://other.com", "discovered"),
			},
		}

		results, _, summary, err := engine.Assess(context.Background(), actx)
		if err != nil {
			t.Fatalf("Assess failed: %v", err)
		}

		cov7 := summary.CoverageMap[string(CategoryAPI7_SSRF)]
		if cov7.Verified > 0 {
			t.Errorf("canary probe without verified callback must NOT be verified, got %d", cov7.Verified)
		}
		if cov7.Candidates != 1 {
			t.Errorf("expected 1 candidate, got %d", cov7.Candidates)
		}

		for _, r := range results {
			if r.Category == CategoryAPI7_SSRF {
				if r.VerificationState != StateCandidate {
					t.Errorf("expected StateCandidate, got %s", r.VerificationState)
				}
			}
		}
	})
}

func TestRegression10_ThirdPartyIntegrations_ObservedArchitecture(t *testing.T) {
	engine := NewEngine(nil, DefaultConfig())
	actx := &AssessmentContext{
		AssessmentID: "test-reg-10",
		BaseURL:      "http://example.com",
		Endpoints: []APIEndpoint{
			AnalyzeEndpoint("POST", "/api/stripe.com/charge", "discovered"),
			AnalyzeEndpoint("POST", "/api/twilio.com/send", "discovered"),
		},
	}

	results, _, summary, err := engine.Assess(context.Background(), actx)
	if err != nil {
		t.Fatalf("Assess failed: %v", err)
	}

	cov10 := summary.CoverageMap[string(CategoryAPI10_UnsafeConsumption)]
	if cov10.Verified > 0 {
		t.Errorf("third party integrations must NOT be verified vulnerability, got %d", cov10.Verified)
	}
	if cov10.Candidates > 0 {
		t.Errorf("third party integrations must NOT be candidate vulnerability, got %d", cov10.Candidates)
	}
	if cov10.Observations != 2 {
		t.Errorf("expected 2 observations, got %d", cov10.Observations)
	}

	for _, r := range results {
		if r.Category == CategoryAPI10_UnsafeConsumption {
			if r.VerificationState != StateObserved {
				t.Errorf("expected StateObserved, got %s", r.VerificationState)
			}
			if r.Severity != report.SeverityInfo {
				t.Errorf("expected SeverityInfo, got %s", r.Severity)
			}
		}
	}
}

func TestRegression11_Stage4CandidatesPreserved(t *testing.T) {
	engine := NewEngine(nil, DefaultConfig())
	actx := &AssessmentContext{
		AssessmentID: "test-reg-11",
		BaseURL:      "http://example.com",
		AuthzResults: []authz.AuthzTestResult{
			{
				Category:          authz.CategoryBOLA,
				Endpoint:          "/api/v1/orders/123",
				Method:            "GET",
				VerificationState: authz.StateCandidate,
				EvidenceSummary:   "Possible tenant isolation issue under review",
			},
			{
				Category:          authz.CategoryBOPLAExposure,
				Endpoint:          "/api/v1/orders/123",
				Method:            "GET",
				VerificationState: authz.StateCandidate,
				EvidenceSummary:   "Suspected property leakage",
			},
			{
				Category:          authz.CategoryBFLA,
				Endpoint:          "/api/v1/admin/export",
				Method:            "GET",
				VerificationState: authz.StateCandidate,
				EvidenceSummary:   "Suspected function escalation",
			},
		},
	}

	results, findings, summary, err := engine.Assess(context.Background(), actx)
	if err != nil {
		t.Fatalf("Assess failed: %v", err)
	}

	cov1 := summary.CoverageMap[string(CategoryAPI1_BOLA)]
	if cov1.Verified != 0 || cov1.Candidates != 1 {
		t.Errorf("expected API1 0 verified, 1 candidate, got verified=%d, candidates=%d", cov1.Verified, cov1.Candidates)
	}

	cov3 := summary.CoverageMap[string(CategoryAPI3_BOPLA)]
	if cov3.Verified != 0 || cov3.Candidates != 1 {
		t.Errorf("expected API3 0 verified, 1 candidate, got verified=%d, candidates=%d", cov3.Verified, cov3.Candidates)
	}

	cov5 := summary.CoverageMap[string(CategoryAPI5_BFLA)]
	if cov5.Verified != 0 || cov5.Candidates != 1 {
		t.Errorf("expected API5 0 verified, 1 candidate, got verified=%d, candidates=%d", cov5.Verified, cov5.Candidates)
	}

	if summary.VerifiedCount != 0 {
		t.Errorf("expected 0 total verified findings, got %d", summary.VerifiedCount)
	}
	if len(findings) != 0 {
		t.Errorf("candidates should not generate verified findings, got %d findings", len(findings))
	}

	for _, r := range results {
		if r.VerificationState == StateVerified {
			t.Errorf("candidate result for %s was incorrectly upgraded to StateVerified", r.Category)
		}
	}
}

func TestRegression12_GenuinePositiveControls_ProduceVerified(t *testing.T) {
	// A: Stage 4 Real BOLA
	t.Run("Stage4RealBOLA_Verified", func(t *testing.T) {
		engine := NewEngine(nil, DefaultConfig())
		actx := &AssessmentContext{
			AssessmentID: "pos-bola",
			BaseURL:      "http://example.com",
			AuthzResults: []authz.AuthzTestResult{
				{
					Category:          authz.CategoryBOLA,
					Endpoint:          "/api/v1/tenants/456",
					Method:            "GET",
					VerificationState: authz.StateVerified,
					ObservedStatus:    200,
					EvidenceSummary:   "Tenant A successfully accessed Tenant B record with 200 OK",
				},
			},
		}

		_, findings, summary, err := engine.Assess(context.Background(), actx)
		if err != nil {
			t.Fatalf("Assess failed: %v", err)
		}

		cov1 := summary.CoverageMap[string(CategoryAPI1_BOLA)]
		if cov1.Verified != 1 || cov1.Status != CoverageVerifiedIssueFound {
			t.Errorf("expected API1 verified issue found, got verified=%d, status=%s", cov1.Verified, cov1.Status)
		}
		if len(findings) != 1 || findings[0].Severity != report.SeverityHigh {
			t.Errorf("expected 1 High severity finding for real BOLA, got %d findings", len(findings))
		}
	})

	// B: Unencrypted HTTP Session Cookie Transport
	t.Run("UnencryptedHTTPSessionCookie_Verified", func(t *testing.T) {
		engine := NewEngine(nil, DefaultConfig())
		actx := &AssessmentContext{
			AssessmentID: "pos-cookie",
			BaseURL:      "http://insecure.example.com",
			AuthInv: &auth.AuthInventory{
				Cookies: []auth.CookieMetadata{
					{
						Name:             "session_id",
						SourceURL:        "http://insecure.example.com/app",
						IsSession:        true,
						IsSecure:         false,
						HasSecurityIssue: true,
						SecurityDefects:  []string{"Missing Secure attribute over plain HTTP"},
					},
				},
			},
		}

		_, findings, summary, err := engine.Assess(context.Background(), actx)
		if err != nil {
			t.Fatalf("Assess failed: %v", err)
		}

		cov2 := summary.CoverageMap[string(CategoryAPI2_BrokenAuth)]
		if cov2.Verified != 1 || cov2.Status != CoverageVerifiedIssueFound {
			t.Errorf("expected API2 verified issue for unencrypted session cookie, got verified=%d, status=%s", cov2.Verified, cov2.Status)
		}
		if len(findings) != 1 || findings[0].Severity != report.SeverityMedium {
			t.Errorf("expected 1 Medium severity finding, got %d findings", len(findings))
		}
	})

	// C: Credentialed CORS Wildcard
	t.Run("CredentialedCORSWildcard_Verified", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Access-Control-Allow-Origin", "*")
			w.Header().Set("Access-Control-Allow-Credentials", "true")
			w.WriteHeader(http.StatusOK)
		}))
		defer ts.Close()

		engine := NewEngine(ts.Client(), DefaultConfig())
		actx := &AssessmentContext{
			AssessmentID: "pos-cors",
			BaseURL:      ts.URL,
			Endpoints:    []APIEndpoint{AnalyzeEndpoint("GET", "/api/profile", "discovered")},
		}

		_, findings, summary, err := engine.Assess(context.Background(), actx)
		if err != nil {
			t.Fatalf("Assess failed: %v", err)
		}

		cov8 := summary.CoverageMap[string(CategoryAPI8_Misconfiguration)]
		if cov8.Verified != 1 || cov8.Status != CoverageVerifiedIssueFound {
			t.Errorf("expected API8 verified issue for credentialed CORS wildcard, got verified=%d, status=%s", cov8.Verified, cov8.Status)
		}
		if len(findings) != 1 {
			t.Errorf("expected 1 finding for credentialed CORS wildcard, got %d", len(findings))
		}
	})

	// D: Verbose Multiline Stack Trace Disclosure
	t.Run("VerboseStackTraceDisclosure_Verified", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("X-Content-Type-Options", "nosniff")
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte("Traceback (most recent call last):\n  File \"views.py\", line 10, in dispatch\n    raise DatabaseError('connection lost')"))
		}))
		defer ts.Close()

		engine := NewEngine(ts.Client(), DefaultConfig())
		actx := &AssessmentContext{
			AssessmentID: "pos-stack",
			BaseURL:      ts.URL,
			Endpoints:    []APIEndpoint{AnalyzeEndpoint("GET", "/api/crash", "discovered")},
		}

		_, findings, summary, err := engine.Assess(context.Background(), actx)
		if err != nil {
			t.Fatalf("Assess failed: %v", err)
		}

		cov8 := summary.CoverageMap[string(CategoryAPI8_Misconfiguration)]
		if cov8.Verified != 1 || cov8.Status != CoverageVerifiedIssueFound {
			t.Errorf("expected API8 verified issue for stack trace disclosure, got verified=%d, status=%s", cov8.Verified, cov8.Status)
		}
		if len(findings) != 1 || findings[0].Severity != report.SeverityLow {
			t.Errorf("expected 1 Low severity finding for stack trace, got %d findings", len(findings))
		}
	})
}

func TestDeduplicateEndpoints(t *testing.T) {
	endpoints := []APIEndpoint{
		{Method: "GET", Path: "/api/v1/users"},
		{Method: "GET", Path: "/api/v1/users/"},
		{Method: "GET", Path: "/api/v1/users"},
		{Method: "POST", Path: "/api/v1/users"},
		{Method: "GET", Path: "/api/v1/orders"},
	}

	deduped := DeduplicateEndpoints(endpoints)
	expectedKeys := map[string]bool{
		"GET:/api/v1/users":  true,
		"POST:/api/v1/users": true,
		"GET:/api/v1/orders": true,
	}
	if len(deduped) != len(expectedKeys) {
		t.Fatalf("expected %d unique endpoints, got %d", len(expectedKeys), len(deduped))
	}
}

func TestHardenedSSRFCanaryValidation(t *testing.T) {
	dangerousTargets := []struct {
		url    string
		reason string
	}{
		// IPv4 Loopback & This-Host
		{"http://127.0.0.1/test", "IPv4 loopback"},
		{"http://127.1.2.3:8080/test", "IPv4 loopback range"},
		{"http://0.0.0.0/test", "this-host 0.0.0.0"},

		// RFC 1918 Private ranges
		{"http://10.0.0.1/", "RFC1918 10.0.0.0/8"},
		{"http://10.255.255.254/", "RFC1918 10.0.0.0/8 max"},
		{"http://172.16.0.1/", "RFC1918 172.16.0.0/12 min"},
		{"http://172.31.255.254/", "RFC1918 172.16.0.0/12 max"},
		{"http://192.168.0.1/", "RFC1918 192.168.0.0/16"},
		{"http://192.168.254.254/", "RFC1918 192.168.0.0/16"},

		// Link-Local and CGNAT
		{"http://169.254.169.254/latest/meta-data/", "AWS/GCP metadata link-local"},
		{"http://100.64.0.1/", "CGNAT RFC 6598"},
		{"http://100.127.255.254/", "CGNAT RFC 6598 max"},

		// Multicast & Broadcast
		{"http://224.0.0.1/", "multicast"},
		{"http://255.255.255.255/", "broadcast"},

		// Dword / Integer / Hex / Octal representations
		{"http://2130706433/test", "dword 127.0.0.1"},
		{"http://0x7f000001/test", "hex 127.0.0.1"},
		{"http://0177.0.0.1/test", "octal 127.0.0.1"},

		// IPv6 Loopback, ULA, Link-Local, and IPv4-mapped
		{"http://[::1]/", "IPv6 loopback"},
		{"http://[fe80::1]/", "IPv6 link-local"},
		{"http://[fc00::1]/", "IPv6 ULA"},
		{"http://[fd00::1]/", "IPv6 ULA"},
		{"http://[::ffff:127.0.0.1]/", "IPv4-mapped IPv6 loopback"},
		{"http://[::ffff:10.0.0.1]/", "IPv4-mapped IPv6 private"},

		// Hostname safety blacklist
		{"http://localhost:8080/", "localhost"},
		{"http://sub.localhost/", "*.localhost"},
		{"http://printer.local/", "*.local"},
		{"http://vault.internal/", "*.internal"},
		{"http://service.lan/", "*.lan"},
		{"http://dc.corp/", "*.corp"},
		{"http://router.home/", "*.home"},
		{"http://metadata.google.internal/computeMetadata/v1/", "GCP internal metadata"},
		{"http://instance-data/latest/meta-data/", "AWS instance-data"},
		{"http://metadata/", "short metadata hostname"},

		// Non-HTTP schemes
		{"file:///etc/passwd", "file scheme"},
		{"gopher://127.0.0.1:70/", "gopher scheme"},
		{"ftp://127.0.0.1/", "ftp scheme"},
	}

	for _, tc := range dangerousTargets {
		if !IsInternalOrUnsafeAddress(tc.url) {
			t.Errorf("expected %s (%s) to be rejected as internal/unsafe", tc.url, tc.reason)
		}
	}

	// DNS lookup hook test: hostname resolving to private IP must be rejected
	origHook := dnsLookupIPHook
	defer func() { dnsLookupIPHook = origHook }()

	dnsLookupIPHook = func(host string) ([]net.IP, error) {
		if host == "rebind.attacker.com" {
			return []net.IP{net.ParseIP("192.168.1.100")}, nil
		}
		if host == "safe.canaryservice.com" {
			return []net.IP{net.ParseIP("93.184.216.34")}, nil
		}
		return nil, fmt.Errorf("no such host")
	}

	if !IsInternalOrUnsafeAddress("https://rebind.attacker.com/webhook") {
		t.Errorf("expected hostname resolving to private IP to be rejected")
	}
	if IsInternalOrUnsafeAddress("https://safe.canaryservice.com/webhook") {
		t.Errorf("expected hostname resolving to public IP to be allowed")
	}
}

func TestAPISec_NonJSONRedaction(t *testing.T) {
	rawText := "access_token=secret123&password=myPass&Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoiYWRtaW4ifQ.abc123xyz\nconnect.sid=s%3AsessionSecret"
	redacted := RedactText(rawText)

	if strings.Contains(redacted, "secret123") {
		t.Errorf("access_token leaked: %s", redacted)
	}
	if strings.Contains(redacted, "myPass") {
		t.Errorf("password leaked: %s", redacted)
	}
	if strings.Contains(redacted, "sessionSecret") {
		t.Errorf("connect.sid leaked: %s", redacted)
	}
	if strings.Contains(redacted, "abc123xyz") {
		t.Errorf("JWT signature leaked: %s", redacted)
	}
}

func TestAPISec_ScopedRedirectEnforcement(t *testing.T) {
	thirdParty := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"leak": "data"}`))
	}))
	defer thirdParty.Close()

	primary := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/out-of-scope-redirect":
			http.Redirect(w, r, thirdParty.URL+"/leak", http.StatusFound)
		case "/excluded-redirect":
			http.Redirect(w, r, "/excluded-path", http.StatusFound)
		case "/excluded-path":
			w.WriteHeader(http.StatusOK)
		default:
			w.WriteHeader(http.StatusOK)
		}
	}))
	defer primary.Close()

	engine := NewEngine(nil, DefaultConfig())
	actx := &AssessmentContext{
		IsAllowed:  func(u string) bool { return strings.HasPrefix(u, primary.URL) },
		IsExcluded: func(u string) bool { return strings.Contains(u, "/excluded-path") },
	}
	client := engine.scopedClient(actx)

	// 1. Redirect to third-party server is blocked
	_, err := client.Get(primary.URL + "/out-of-scope-redirect")
	if err == nil {
		t.Errorf("expected redirect to third-party to be blocked")
	}

	// 2. Redirect into excluded path is blocked
	_, err = client.Get(primary.URL + "/excluded-redirect")
	if err == nil {
		t.Errorf("expected redirect into excluded path to be blocked")
	}
}


