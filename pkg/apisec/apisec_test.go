package apisec

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"felix/pkg/auth"
	"felix/pkg/authz"
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
	if cov6.Candidates == 0 {
		t.Errorf("expected API6 business flow candidates, got 0")
	}

	// Verify Category 7 (SSRF)
	cov7 := summary.CoverageMap[string(CategoryAPI7_SSRF)]
	if cov7.Candidates == 0 {
		t.Errorf("expected API7 SSRF candidate, got 0")
	}

	// Verify Category 8 (Security Misconfiguration)
	cov8 := summary.CoverageMap[string(CategoryAPI8_Misconfiguration)]
	if cov8.Status != CoverageVerifiedIssueFound || cov8.Verified == 0 {
		t.Errorf("expected API8 misconfiguration verified issue (missing nosniff), got status=%s, verified=%d", cov8.Status, cov8.Verified)
	}

	// Verify Category 9 (Improper Inventory)
	cov9 := summary.CoverageMap[string(CategoryAPI9_ImproperInventory)]
	if cov9.Status != CoverageVerifiedIssueFound || cov9.Verified == 0 {
		t.Errorf("expected API9 shadow API verified issue, got status=%s, verified=%d", cov9.Status, cov9.Verified)
	}

	// Verify Category 10 (Unsafe Consumption)
	cov10 := summary.CoverageMap[string(CategoryAPI10_UnsafeConsumption)]
	if cov10.Candidates == 0 {
		t.Errorf("expected API10 candidate finding for stripe.com integration, got 0")
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

