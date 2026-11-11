package crawler

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// -----------------------------------------------------------------------------
// Category A: Recursive Crawling Tests
// -----------------------------------------------------------------------------

func TestRecursiveCrawl_MultiPageNavigation(t *testing.T) {
	var pageHits int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&pageHits, 1)
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		switch r.URL.Path {
		case "/":
			fmt.Fprint(w, `<html><body><a href="/page1">Page 1</a><a href="/page2">Page 2</a></body></html>`)
		case "/page1":
			fmt.Fprint(w, `<html><body><h1>Page 1</h1><a href="/page3">Page 3</a></body></html>`)
		case "/page2":
			fmt.Fprint(w, `<html><body><h1>Page 2</h1></body></html>`)
		case "/page3":
			fmt.Fprint(w, `<html><body><h1>Page 3</h1></body></html>`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	opts := DefaultActiveCrawlOptions(server.URL)
	opts.AllowLoopback = true
	opts.MaxDepth = 3

	crawler, err := NewActiveCrawler(opts)
	if err != nil {
		t.Fatalf("NewActiveCrawler failed: %v", err)
	}

	res, err := crawler.CrawlApplication(context.Background(), server.Client(), "ANONYMOUS")
	if err != nil {
		t.Fatalf("CrawlApplication failed: %v", err)
	}

	if res.Summary.TotalPagesDiscovered < 4 {
		t.Errorf("expected at least 4 pages discovered, got %d", res.Summary.TotalPagesDiscovered)
	}

	// Verify all paths reached
	pathsFound := make(map[string]bool)
	for _, r := range res.Resources {
		if r.Classification == ClassificationConfirmedEndpoint {
			pathsFound[r.Path] = true
		}
	}

	for _, expectedPath := range []string{"/", "/page1", "/page2", "/page3"} {
		if !pathsFound[expectedPath] {
			t.Errorf("expected path %q to be discovered, but was not found", expectedPath)
		}
	}
}

func TestRecursiveCrawl_NestedRoutes(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		switch r.URL.Path {
		case "/":
			fmt.Fprint(w, `<html><a href="/app/dashboard">Dashboard</a></html>`)
		case "/app/dashboard":
			fmt.Fprint(w, `<html><a href="/app/dashboard/settings">Settings</a></html>`)
		case "/app/dashboard/settings":
			fmt.Fprint(w, `<html><a href="/app/dashboard/settings/profile">Profile</a></html>`)
		case "/app/dashboard/settings/profile":
			fmt.Fprint(w, `<html><h1>Final Depth</h1></html>`)
		}
	}))
	defer server.Close()

	opts := DefaultActiveCrawlOptions(server.URL)
	opts.AllowLoopback = true
	opts.MaxDepth = 4

	crawler, err := NewActiveCrawler(opts)
	if err != nil {
		t.Fatalf("NewActiveCrawler failed: %v", err)
	}

	res, err := crawler.CrawlApplication(context.Background(), server.Client(), "ANONYMOUS")
	if err != nil {
		t.Fatalf("CrawlApplication failed: %v", err)
	}

	pathsFound := make(map[string]bool)
	for _, r := range res.Resources {
		pathsFound[r.Path] = true
	}

	expected := []string{"/", "/app/dashboard", "/app/dashboard/settings", "/app/dashboard/settings/profile"}
	for _, p := range expected {
		if !pathsFound[p] {
			t.Errorf("nested route %s not discovered", p)
		}
	}
}

func TestRecursiveCrawl_DuplicateURLHandling(t *testing.T) {
	var requestCount int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&requestCount, 1)
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		// Multiple links pointing to the exact same page
		fmt.Fprint(w, `<html><body>
			<a href="/target">Link 1</a>
			<a href="/target">Link 2</a>
			<a href="/target#fragment">Link 3 with fragment</a>
			<a href="./target">Link 4 relative</a>
		</body></html>`)
	}))
	defer server.Close()

	opts := DefaultActiveCrawlOptions(server.URL)
	opts.AllowLoopback = true

	crawler, err := NewActiveCrawler(opts)
	if err != nil {
		t.Fatalf("NewActiveCrawler failed: %v", err)
	}

	res, err := crawler.CrawlApplication(context.Background(), server.Client(), "ANONYMOUS")
	if err != nil {
		t.Fatalf("CrawlApplication failed: %v", err)
	}

	// Should only make 2 requests: root ("/") and "/target" once
	if requestCount != 2 {
		t.Errorf("expected exactly 2 HTTP requests due to deduplication, got %d", requestCount)
	}

	targetCount := 0
	for _, r := range res.Resources {
		if r.Path == "/target" && r.Classification == ClassificationConfirmedEndpoint {
			targetCount++
		}
	}
	if targetCount != 1 {
		t.Errorf("expected /target to be recorded exactly once, got %d", targetCount)
	}
}

func TestRecursiveCrawl_QueryParameterExtraction(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprint(w, `<html><a href="/search?query=security&filter=recent&page=2">Search</a></html>`)
	}))
	defer server.Close()

	opts := DefaultActiveCrawlOptions(server.URL)
	opts.AllowLoopback = true

	crawler, err := NewActiveCrawler(opts)
	if err != nil {
		t.Fatalf("NewActiveCrawler failed: %v", err)
	}

	res, err := crawler.CrawlApplication(context.Background(), server.Client(), "ANONYMOUS")
	if err != nil {
		t.Fatalf("CrawlApplication failed: %v", err)
	}

	var foundResource *DiscoveredResource
	for _, r := range res.Resources {
		if r.Path == "/search" {
			foundResource = &r
			break
		}
	}

	if foundResource == nil {
		t.Fatal("expected /search endpoint to be discovered")
	}

	expectedParams := map[string]bool{"query": false, "filter": false, "page": false}
	for _, p := range foundResource.QueryParams {
		if _, ok := expectedParams[p]; ok {
			expectedParams[p] = true
		}
	}

	for k, found := range expectedParams {
		if !found {
			t.Errorf("expected query parameter %q to be extracted", k)
		}
	}
}

func TestRecursiveCrawl_CrawlDepthEnforcement(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		switch r.URL.Path {
		case "/":
			fmt.Fprint(w, `<html><a href="/d1">Depth 1</a></html>`)
		case "/d1":
			fmt.Fprint(w, `<html><a href="/d2">Depth 2</a></html>`)
		case "/d2":
			fmt.Fprint(w, `<html><a href="/d3">Depth 3</a></html>`)
		case "/d3":
			fmt.Fprint(w, `<html><a href="/d4">Depth 4</a></html>`)
		case "/d4":
			fmt.Fprint(w, `<html><h1>Should Not Reach</h1></html>`)
		}
	}))
	defer server.Close()

	opts := DefaultActiveCrawlOptions(server.URL)
	opts.AllowLoopback = true
	opts.MaxDepth = 2 // Strict depth limit: / (0) -> /d1 (1) -> /d2 (2)

	crawler, err := NewActiveCrawler(opts)
	if err != nil {
		t.Fatalf("NewActiveCrawler failed: %v", err)
	}

	res, err := crawler.CrawlApplication(context.Background(), server.Client(), "ANONYMOUS")
	if err != nil {
		t.Fatalf("CrawlApplication failed: %v", err)
	}

	pathsFound := make(map[string]bool)
	for _, r := range res.Resources {
		if r.Classification == ClassificationConfirmedEndpoint {
			pathsFound[r.Path] = true
		}
	}

	if !pathsFound["/"] || !pathsFound["/d1"] || !pathsFound["/d2"] {
		t.Errorf("expected /, /d1, /d2 to be reached within depth 2")
	}

	if pathsFound["/d4"] {
		t.Errorf("expected /d4 to NOT be reached (exceeds max depth 2)")
	}

	// Verify coverage gap recorded for depth limit
	hasLimitGap := false
	for _, gap := range res.CoverageGaps {
		if gap.Type == "LIMIT_REACHED" && strings.Contains(gap.Reason, "depth") {
			hasLimitGap = true
			break
		}
	}
	if !hasLimitGap {
		t.Errorf("expected LIMIT_REACHED coverage gap to be recorded for max depth")
	}
}

func TestRecursiveCrawl_RequestCountEnforcement(t *testing.T) {
	var totalRequests int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&totalRequests, 1)
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		// Generate 50 links
		var b strings.Builder
		b.WriteString("<html><body>")
		for i := 1; i <= 50; i++ {
			fmt.Fprintf(&b, `<a href="/item-%d">Item %d</a>`, i, i)
		}
		b.WriteString("</body></html>")
		fmt.Fprint(w, b.String())
	}))
	defer server.Close()

	opts := DefaultActiveCrawlOptions(server.URL)
	opts.AllowLoopback = true
	opts.MaxRequests = 5 // Cap at 5 requests max

	crawler, err := NewActiveCrawler(opts)
	if err != nil {
		t.Fatalf("NewActiveCrawler failed: %v", err)
	}

	res, err := crawler.CrawlApplication(context.Background(), server.Client(), "ANONYMOUS")
	if err != nil {
		t.Fatalf("CrawlApplication failed: %v", err)
	}

	if totalRequests > 5 {
		t.Errorf("expected total server requests <= 5, got %d", totalRequests)
	}

	if res.Summary.TotalRequestsMade > 5 {
		t.Errorf("expected crawler summary TotalRequestsMade <= 5, got %d", res.Summary.TotalRequestsMade)
	}
}

// -----------------------------------------------------------------------------
// Category B: HTML Extraction Tests
// -----------------------------------------------------------------------------

func TestHTMLExtraction_LinksAndForms(t *testing.T) {
	htmlSample := `<!DOCTYPE html>
<html>
<head>
    <title>HTML Extraction Test</title>
    <script src="/static/app.js"></script>
    <link rel="stylesheet" href="/static/style.css">
</head>
<body>
    <nav>
        <a href="/home">Home</a>
        <a href="/products?cat=1&sort=asc">Products</a>
        <a href="javascript:void(0)">Ignored JS</a>
        <a href="mailto:test@example.com">Ignored Mailto</a>
        <a href="#section">Ignored Fragment</a>
    </nav>
    <main>
        <form action="/api/v1/login" method="POST">
            <input type="text" name="username" required>
            <input type="password" name="password" required>
            <input type="hidden" name="csrf_token" value="abc123xyz">
            <button type="submit">Log in</button>
        </form>
        <form action="/search" method="GET">
            <input type="text" name="q">
            <select name="type">
                <option value="all">All</option>
            </select>
            <textarea name="comments"></textarea>
        </form>
    </main>
</body>
</html>`

	baseURL, _ := url.Parse("https://app.example.com/start")
	links, forms, staticAssets, err := ExtractHTMLLinksAndForms(strings.NewReader(htmlSample), baseURL)
	if err != nil {
		t.Fatalf("ExtractHTMLLinksAndForms failed: %v", err)
	}

	// 1. Check Links
	expectedLinks := []string{
		"https://app.example.com/home",
		"https://app.example.com/products?cat=1&sort=asc",
	}
	if len(links) != len(expectedLinks) {
		t.Fatalf("expected %d links, got %d: %+v", len(expectedLinks), len(links), links)
	}

	// 2. Check Forms
	if len(forms) != 2 {
		t.Fatalf("expected 2 forms, got %d", len(forms))
	}

	// Form 1: POST /api/v1/login
	f1 := forms[0]
	if f1.Method != "POST" || f1.Action != "/api/v1/login" {
		t.Errorf("form 1 method or action mismatch: %+v", f1)
	}
	if len(f1.Fields) != 3 {
		t.Errorf("expected 3 fields in form 1, got %d", len(f1.Fields))
	}

	// Form 2: GET /search
	f2 := forms[1]
	if f2.Method != "GET" || f2.Action != "/search" {
		t.Errorf("form 2 method or action mismatch: %+v", f2)
	}
	if len(f2.Fields) != 3 { // q, type, comments
		t.Errorf("expected 3 fields in form 2, got %d: %+v", len(f2.Fields), f2.Fields)
	}

	// 3. Check Static Assets
	if len(staticAssets) != 2 { // app.js and style.css
		t.Errorf("expected 2 static assets, got %d: %+v", len(staticAssets), staticAssets)
	}
}

func TestHTMLExtraction_DestructiveActionExclusion(t *testing.T) {
	destructiveURLs := []string{
		"http://127.0.0.1:8080/logout",
		"http://127.0.0.1:8080/api/auth/signout",
		"http://127.0.0.1:8080/account/delete",
		"http://127.0.0.1:8080/user/deactivate",
		"http://127.0.0.1:8080/billing/cancel",
		"http://127.0.0.1:8080/order/checkout",
		"http://127.0.0.1:8080/action?cmd=destroy",
		"http://127.0.0.1:8080/token/revoke",
	}

	for _, u := range destructiveURLs {
		isDest, reason := IsDestructiveURL(u, nil)
		if !isDest {
			t.Errorf("expected URL %q to be identified as destructive, but was not (reason: %s)", u, reason)
		}
	}

	safeURLs := []string{
		"http://127.0.0.1:8080/",
		"http://127.0.0.1:8080/dashboard",
		"http://127.0.0.1:8080/api/users",
		"http://127.0.0.1:8080/catalog/products",
		"http://127.0.0.1:8080/about-us",
	}

	for _, u := range safeURLs {
		isDest, reason := IsDestructiveURL(u, nil)
		if isDest {
			t.Errorf("expected safe URL %q to NOT be flagged as destructive, but got: %s", u, reason)
		}
	}
}

func TestDestructiveLinkNotCrawled(t *testing.T) {
	var logoutCalled int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/logout" {
			atomic.AddInt32(&logoutCalled, 1)
			http.Error(w, "session destroyed", http.StatusOK)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprint(w, `<html><body><a href="/logout">Logout</a><a href="/profile">Profile</a></body></html>`)
	}))
	defer server.Close()

	opts := DefaultActiveCrawlOptions(server.URL)
	opts.AllowLoopback = true

	crawler, err := NewActiveCrawler(opts)
	if err != nil {
		t.Fatalf("NewActiveCrawler failed: %v", err)
	}

	res, err := crawler.CrawlApplication(context.Background(), server.Client(), "ANONYMOUS")
	if err != nil {
		t.Fatalf("CrawlApplication failed: %v", err)
	}

	if logoutCalled > 0 {
		t.Fatalf("CRITICAL SAFETY VIOLATION: destructive endpoint /logout was requested %d times!", logoutCalled)
	}

	// Verify that /logout was classified as EXCLUDED_DESTRUCTIVE_ACTION
	foundExcluded := false
	for _, r := range res.Resources {
		if r.Path == "/logout" && r.Classification == ClassificationExcludedDestructive {
			foundExcluded = true
			break
		}
	}
	if !foundExcluded {
		t.Errorf("expected /logout to be recorded as ClassificationExcludedDestructive")
	}
}

// -----------------------------------------------------------------------------
// Category C: JavaScript Extraction Tests
// -----------------------------------------------------------------------------

func TestJSExtraction_StaticAPIRouteStrings(t *testing.T) {
	bundleContent := `
	(function() {
		var apiPrefix = "/api/v1";
		function fetchUsers() {
			return fetch("/api/v1/users");
		}
		function getOrder(id) {
			return fetch("/api/v1/orders/" + id);
		}
		function updateSettings() {
			return axios.post("/api/v2/settings", { theme: "dark" });
		}
	})();
	`

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/app.js" {
			w.Header().Set("Content-Type", "application/javascript")
			fmt.Fprint(w, bundleContent)
			return
		}
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<html><script src="/app.js"></script></html>`)
	}))
	defer server.Close()

	opts := DefaultActiveCrawlOptions(server.URL)
	opts.AllowLoopback = true

	crawler, err := NewActiveCrawler(opts)
	if err != nil {
		t.Fatalf("NewActiveCrawler failed: %v", err)
	}

	res, err := crawler.CrawlApplication(context.Background(), server.Client(), "ANONYMOUS")
	if err != nil {
		t.Fatalf("CrawlApplication failed: %v", err)
	}

	candidates := make(map[string]bool)
	for _, r := range res.Resources {
		if r.Classification == ClassificationEndpointCandidate {
			candidates[r.Path] = true
		}
	}

	if !candidates["/api/v1/users"] {
		t.Errorf("expected candidate /api/v1/users to be extracted from JS bundle")
	}
	if !candidates["/api/v2/settings"] {
		t.Errorf("expected candidate /api/v2/settings to be extracted from JS bundle")
	}
}

func TestJSExtraction_MultipleBundles(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/bundle-a.js":
			w.Header().Set("Content-Type", "application/javascript")
			fmt.Fprint(w, `fetch("/api/auth/token");`)
		case "/bundle-b.js":
			w.Header().Set("Content-Type", "application/javascript")
			fmt.Fprint(w, `fetch("/api/metrics/realtime");`)
		default:
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprint(w, `<html><script src="/bundle-a.js"></script><script src="/bundle-b.js"></script></html>`)
		}
	}))
	defer server.Close()

	opts := DefaultActiveCrawlOptions(server.URL)
	opts.AllowLoopback = true

	crawler, err := NewActiveCrawler(opts)
	if err != nil {
		t.Fatalf("NewActiveCrawler failed: %v", err)
	}

	res, err := crawler.CrawlApplication(context.Background(), server.Client(), "ANONYMOUS")
	if err != nil {
		t.Fatalf("CrawlApplication failed: %v", err)
	}

	if res.Summary.TotalJavaScriptBundles != 2 {
		t.Errorf("expected 2 JS bundles, got %d", res.Summary.TotalJavaScriptBundles)
	}

	candidates := make(map[string]bool)
	for _, r := range res.Resources {
		if r.Classification == ClassificationEndpointCandidate {
			candidates[r.Path] = true
		}
	}

	if !candidates["/api/auth/token"] || !candidates["/api/metrics/realtime"] {
		t.Errorf("expected both bundles' candidates to be extracted: %+v", candidates)
	}
}

// -----------------------------------------------------------------------------
// Category D: Identity-Aware Crawling Tests
// -----------------------------------------------------------------------------

func TestIdentityAwareCrawl_MultiIdentityVisibility(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")

		switch r.URL.Path {
		case "/api/public":
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, `{"status":"public_ok"}`)
		case "/api/user/profile":
			if authHeader == "" {
				w.WriteHeader(http.StatusUnauthorized)
				fmt.Fprint(w, `{"error":"unauthorized"}`)
				return
			}
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, `{"user":"profile_ok"}`)
		case "/api/admin/system":
			if authHeader == "Bearer admin_token_secret" {
				w.WriteHeader(http.StatusOK)
				fmt.Fprint(w, `{"admin":"system_ok"}`)
				return
			} else if authHeader != "" {
				w.WriteHeader(http.StatusForbidden)
				fmt.Fprint(w, `{"error":"forbidden"}`)
				return
			}
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprint(w, `{"error":"unauthorized"}`)
		default:
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprint(w, `<html><a href="/api/public">Public</a><a href="/api/user/profile">User</a><a href="/api/admin/system">Admin</a></html>`)
		}
	}))
	defer server.Close()

	// Create custom client map with bearer tokens
	idClientMap := make(map[string]*http.Client)

	// 1. Anonymous client
	idClientMap["ANONYMOUS"] = server.Client()

	// 2. User A client
	userAClient := &http.Client{
		Transport: &testHeaderTransport{
			base:   server.Client().Transport,
			header: "Authorization",
			value:  "Bearer user_a_token",
		},
	}
	idClientMap["USER_A"] = userAClient

	// 3. Admin client
	adminClient := &http.Client{
		Transport: &testHeaderTransport{
			base:   server.Client().Transport,
			header: "Authorization",
			value:  "Bearer admin_token_secret",
		},
	}
	idClientMap["ADMIN"] = adminClient

	opts := DefaultActiveCrawlOptions(server.URL)
	opts.AllowLoopback = true

	multiRes, err := CrawlMultiIdentity(context.Background(), opts, idClientMap)
	if err != nil {
		t.Fatalf("CrawlMultiIdentity failed: %v", err)
	}

	matrix := multiRes.VisibilityMatrix
	if matrix == nil {
		t.Fatal("expected VisibilityMatrix to be non-nil")
	}

	// Check observations for each endpoint
	// 1. /api/public -> Reachable (200) for all identities
	pubObsAnon := matrix.Endpoints["GET /api/public"]["ANONYMOUS"]
	pubObsUserA := matrix.Endpoints["GET /api/public"]["USER_A"]
	pubObsAdmin := matrix.Endpoints["GET /api/public"]["ADMIN"]

	if pubObsAnon.StatusCode != 200 || pubObsUserA.StatusCode != 200 || pubObsAdmin.StatusCode != 200 {
		t.Errorf("/api/public should return 200 for all identities: anon=%d, userA=%d, admin=%d",
			pubObsAnon.StatusCode, pubObsUserA.StatusCode, pubObsAdmin.StatusCode)
	}

	// 2. /api/user/profile -> 401 for anon, 200 for User A, 200 for Admin
	userObsAnon := matrix.Endpoints["GET /api/user/profile"]["ANONYMOUS"]
	userObsUserA := matrix.Endpoints["GET /api/user/profile"]["USER_A"]
	if userObsAnon.StatusCode != 401 {
		t.Errorf("expected /api/user/profile to return 401 for ANONYMOUS, got %d", userObsAnon.StatusCode)
	}
	if userObsUserA.StatusCode != 200 {
		t.Errorf("expected /api/user/profile to return 200 for USER_A, got %d", userObsUserA.StatusCode)
	}

	// 3. /api/admin/system -> 401 for anon, 403 for User A, 200 for Admin
	adminObsAnon := matrix.Endpoints["GET /api/admin/system"]["ANONYMOUS"]
	adminObsUserA := matrix.Endpoints["GET /api/admin/system"]["USER_A"]
	adminObsAdmin := matrix.Endpoints["GET /api/admin/system"]["ADMIN"]

	if adminObsAnon.StatusCode != 401 {
		t.Errorf("expected /api/admin/system to return 401 for ANONYMOUS, got %d", adminObsAnon.StatusCode)
	}
	if adminObsUserA.StatusCode != 403 {
		t.Errorf("expected /api/admin/system to return 403 for USER_A, got %d", adminObsUserA.StatusCode)
	}
	if adminObsAdmin.StatusCode != 200 {
		t.Errorf("expected /api/admin/system to return 200 for ADMIN, got %d", adminObsAdmin.StatusCode)
	}
}

// testHeaderTransport injects an HTTP header into every outgoing request.
type testHeaderTransport struct {
	base   http.RoundTripper
	header string
	value  string
}

func (t *testHeaderTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	cloned := req.Clone(req.Context())
	if cloned.Header.Get(t.header) == "" {
		cloned.Header.Set(t.header, t.value)
	}
	rt := t.base
	if rt == nil {
		rt = http.DefaultTransport
	}
	return rt.RoundTrip(cloned)
}

// -----------------------------------------------------------------------------
// Category E: Security Boundary Tests
// -----------------------------------------------------------------------------

func TestSecurityBoundaries_ExternalLinksOutOfScope(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<html><body>
			<a href="/in-scope">Internal</a>
			<a href="https://external-target.attacker.com/leak">External</a>
			<a href="http://169.254.169.254/latest/meta-data/">Cloud Metadata</a>
		</body></html>`)
	}))
	defer server.Close()

	opts := DefaultActiveCrawlOptions(server.URL)
	opts.AllowLoopback = true

	crawler, err := NewActiveCrawler(opts)
	if err != nil {
		t.Fatalf("NewActiveCrawler failed: %v", err)
	}

	res, err := crawler.CrawlApplication(context.Background(), server.Client(), "ANONYMOUS")
	if err != nil {
		t.Fatalf("CrawlApplication failed: %v", err)
	}

	for _, r := range res.Resources {
		if strings.Contains(r.URL, "external-target.attacker.com") || strings.Contains(r.URL, "169.254.169.254") {
			if r.Classification != ClassificationOutOfScope {
				t.Errorf("external asset %s was NOT classified as OUT_OF_SCOPE: %s", r.URL, r.Classification)
			}
			if r.InScope {
				t.Errorf("external asset %s had InScope=true", r.URL)
			}
		}
	}
}

func TestSecurityBoundaries_ResponseSizeLimits(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		// Output 5 MB of data
		padding := strings.Repeat("A", 1024*1024*5)
		fmt.Fprint(w, padding)
	}))
	defer server.Close()

	opts := DefaultActiveCrawlOptions(server.URL)
	opts.AllowLoopback = true
	opts.MaxAssetSize = 1024 * 1024 // 1 MB max size limit

	crawler, err := NewActiveCrawler(opts)
	if err != nil {
		t.Fatalf("NewActiveCrawler failed: %v", err)
	}

	res, err := crawler.CrawlApplication(context.Background(), server.Client(), "ANONYMOUS")
	if err != nil {
		t.Fatalf("CrawlApplication failed: %v", err)
	}

	hasLimitGap := false
	for _, gap := range res.CoverageGaps {
		if gap.Type == "LIMIT_REACHED" && strings.Contains(gap.Reason, "size") {
			hasLimitGap = true
			break
		}
	}

	if !hasLimitGap {
		t.Errorf("expected LIMIT_REACHED coverage gap for oversized response body")
	}
}

func TestSecurityBoundaries_RequestTimeoutsAndCancellation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(500 * time.Millisecond)
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<html>OK</html>`)
	}))
	defer server.Close()

	opts := DefaultActiveCrawlOptions(server.URL)
	opts.AllowLoopback = true

	crawler, err := NewActiveCrawler(opts)
	if err != nil {
		t.Fatalf("NewActiveCrawler failed: %v", err)
	}

	// Cancel context after 50ms (before server responds)
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	res, _ := crawler.CrawlApplication(ctx, server.Client(), "ANONYMOUS")
	if res == nil {
		t.Fatal("expected non-nil result even on timeout")
	}

	hasTimeout := false
	for _, gap := range res.CoverageGaps {
		if gap.Type == "LIMIT_REACHED" || gap.Type == "NETWORK_ERROR" {
			hasTimeout = true
			break
		}
	}

	if !hasTimeout {
		t.Errorf("expected coverage gap for cancellation or network timeout")
	}
}

// ---------------------------------------------------------------------------
// Category C Extensions: JavaScript Extraction Verification
// ---------------------------------------------------------------------------

func TestJSExtraction_MinifiedJS(t *testing.T) {
	minifiedCode := `!function(e,t){"use strict";var n=function(){fetch("/api/v1/auth/login")},r=function(e){return axios.get("/api/v2/products/"+e)};window.api={login:n,prod:r}}();`
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprint(w, `<html><head><script src="/bundle.min.js"></script></head><body><h1>Minified Test</h1></body></html>`)
		case "/bundle.min.js":
			w.Header().Set("Content-Type", "application/javascript")
			fmt.Fprint(w, minifiedCode)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	opts := DefaultActiveCrawlOptions(server.URL)
	opts.MaxDepth = 2
	opts.AllowLoopback = true

	crawler, err := NewActiveCrawler(opts)
	if err != nil {
		t.Fatalf("NewActiveCrawler failed: %v", err)
	}

	res, err := crawler.CrawlApplication(context.Background(), server.Client(), "ANONYMOUS")
	if err != nil {
		t.Fatalf("CrawlApplication failed: %v", err)
	}

	foundLogin := false
	foundProducts := false
	for _, r := range res.Resources {
		if strings.Contains(r.Path, "/api/v1/auth/login") {
			foundLogin = true
			if r.Classification != ClassificationEndpointCandidate {
				t.Errorf("expected endpoint candidate classification for minified route, got %s", r.Classification)
			}
		}
		if strings.Contains(r.Path, "/api/v2/products") {
			foundProducts = true
		}
	}

	if !foundLogin {
		t.Errorf("expected to extract /api/v1/auth/login from minified JS bundle")
	}
	if !foundProducts {
		t.Errorf("expected to extract /api/v2/products from minified JS bundle")
	}
}

func TestJSExtraction_ParameterizedRouteTemplates(t *testing.T) {
	scriptCode := `
		const userRoute = "/api/v1/users/{userId}";
		const tenantRoute = "/api/v2/tenants/:tenantId/settings";
		const itemRoute = "/api/v3/items/[itemId]";
	`
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprint(w, `<html><head><script src="/routes.js"></script></head><body><h1>Templates</h1></body></html>`)
		case "/routes.js":
			w.Header().Set("Content-Type", "application/javascript")
			fmt.Fprint(w, scriptCode)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	opts := DefaultActiveCrawlOptions(server.URL)
	opts.MaxDepth = 2
	opts.AllowLoopback = true

	crawler, err := NewActiveCrawler(opts)
	if err != nil {
		t.Fatalf("NewActiveCrawler failed: %v", err)
	}

	res, err := crawler.CrawlApplication(context.Background(), server.Client(), "ANONYMOUS")
	if err != nil {
		t.Fatalf("CrawlApplication failed: %v", err)
	}

	var foundUser, foundTenant, foundItem bool
	for _, r := range res.Resources {
		if strings.Contains(r.Path, "/api/v1/users") {
			foundUser = true
		}
		if strings.Contains(r.Path, "/api/v2/tenants") {
			foundTenant = true
		}
		if strings.Contains(r.Path, "/api/v3/items") {
			foundItem = true
		}
	}

	if !foundUser {
		t.Errorf("expected parameterized route /api/v1/users/{userId} extracted")
	}
	if !foundTenant {
		t.Errorf("expected colon-parameter route /api/v2/tenants/:tenantId/settings extracted")
	}
	if !foundItem {
		t.Errorf("expected bracket-parameter route /api/v3/items/[itemId] extracted")
	}
}

func TestJSExtraction_SourceBundleProvenance(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprint(w, `<html><head>
				<script src="/bundles/auth.js"></script>
				<script src="/bundles/billing.js"></script>
			</head><body><h1>Provenance Test</h1></body></html>`)
		case "/bundles/auth.js":
			w.Header().Set("Content-Type", "application/javascript")
			fmt.Fprint(w, `function getAuth() { return fetch("/api/auth/token"); }`)
		case "/bundles/billing.js":
			w.Header().Set("Content-Type", "application/javascript")
			fmt.Fprint(w, `function getInvoices() { return fetch("/api/billing/invoices"); }`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	opts := DefaultActiveCrawlOptions(server.URL)
	opts.MaxDepth = 2
	opts.AllowLoopback = true

	crawler, err := NewActiveCrawler(opts)
	if err != nil {
		t.Fatalf("NewActiveCrawler failed: %v", err)
	}

	res, err := crawler.CrawlApplication(context.Background(), server.Client(), "ANONYMOUS")
	if err != nil {
		t.Fatalf("CrawlApplication failed: %v", err)
	}

	var authProvenanceOK, billingProvenanceOK bool
	for _, r := range res.Resources {
		if strings.Contains(r.Path, "/api/auth/token") {
			if strings.HasSuffix(r.SourcePage, "/bundles/auth.js") {
				authProvenanceOK = true
			}
		}
		if strings.Contains(r.Path, "/api/billing/invoices") {
			if strings.HasSuffix(r.SourcePage, "/bundles/billing.js") {
				billingProvenanceOK = true
			}
		}
	}

	if !authProvenanceOK {
		t.Errorf("expected /api/auth/token to have SourcePage ending in /bundles/auth.js")
	}
	if !billingProvenanceOK {
		t.Errorf("expected /api/billing/invoices to have SourcePage ending in /bundles/billing.js")
	}
}

func TestJSExtraction_FrameworkSignatures(t *testing.T) {
	nextManifest := `self.__BUILD_MANIFEST = {"/api/next/pages": ["static/chunks/pages.js"], sortedPages: ["/api/next/pages"]};`
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprint(w, `<html><head><script src="/_buildManifest.js"></script></head><body><h1>Next Manifest</h1></body></html>`)
		case "/_buildManifest.js":
			w.Header().Set("Content-Type", "application/javascript")
			fmt.Fprint(w, nextManifest)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	opts := DefaultActiveCrawlOptions(server.URL)
	opts.MaxDepth = 2
	opts.AllowLoopback = true

	crawler, err := NewActiveCrawler(opts)
	if err != nil {
		t.Fatalf("NewActiveCrawler failed: %v", err)
	}

	res, err := crawler.CrawlApplication(context.Background(), server.Client(), "ANONYMOUS")
	if err != nil {
		t.Fatalf("CrawlApplication failed: %v", err)
	}

	foundNextRoute := false
	for _, r := range res.Resources {
		if strings.Contains(r.Path, "/api/next/pages") {
			foundNextRoute = true
			break
		}
	}

	if !foundNextRoute {
		t.Errorf("expected Next.js build manifest route /api/next/pages to be extracted")
	}
}

func TestJSExtraction_FalsePositiveFiltering(t *testing.T) {
	jsWithNoise := `
		const contentType = "application/json";
		const htmlType = "text/html";
		const cssClass = "btn-primary";
		const styleMargin = "margin-left: 10px";
		const realEndpoint = "/api/v1/telemetry";
	`
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprint(w, `<html><head><script src="/noise.js"></script></head><body><h1>Noise</h1></body></html>`)
		case "/noise.js":
			w.Header().Set("Content-Type", "application/javascript")
			fmt.Fprint(w, jsWithNoise)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	opts := DefaultActiveCrawlOptions(server.URL)
	opts.MaxDepth = 2
	opts.AllowLoopback = true

	crawler, err := NewActiveCrawler(opts)
	if err != nil {
		t.Fatalf("NewActiveCrawler failed: %v", err)
	}

	res, err := crawler.CrawlApplication(context.Background(), server.Client(), "ANONYMOUS")
	if err != nil {
		t.Fatalf("CrawlApplication failed: %v", err)
	}

	foundTelemetry := false
	for _, r := range res.Resources {
		if strings.Contains(r.Path, "application/json") || strings.Contains(r.Path, "text/html") || strings.Contains(r.Path, "btn-primary") {
			t.Errorf("non-API noise was improperly extracted as resource: %s", r.Path)
		}
		if strings.Contains(r.Path, "/api/v1/telemetry") {
			foundTelemetry = true
		}
	}

	if !foundTelemetry {
		t.Errorf("expected real API route /api/v1/telemetry to be extracted")
	}
}

// ---------------------------------------------------------------------------
// Candidate Route Safety Verification
// ---------------------------------------------------------------------------

func TestDownstreamCandidateSafety_NoUnsafeDispatch(t *testing.T) {
	// Local server tracking dispatch counts across candidate routes
	var mu sync.Mutex
	requestCounts := make(map[string]int)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		requestCounts[fmt.Sprintf("%s %s", r.Method, r.URL.Path)]++
		mu.Unlock()

		switch r.URL.Path {
		case "/":
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprint(w, `<html><head><script src="/bundle.js"></script></head><body><h1>App</h1></body></html>`)
		case "/bundle.js":
			w.Header().Set("Content-Type", "application/javascript")
			// JavaScript contains references to safe routes and destructive/unsafe routes
			fmt.Fprint(w, `
				fetch("/api/users", { method: "GET" });
				fetch("/api/orders/123", { method: "GET" });
				fetch("/api/admin/restart", { method: "POST" });
				fetch("/account/delete", { method: "POST" });
				fetch("/payment/checkout", { method: "POST" });
			`)
		case "/api/users":
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, `[{"id": 1, "name": "Alice"}]`)
		case "/api/orders/123":
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, `{"orderId": 123}`)
		case "/api/admin/restart":
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, `{"status": "restarted"}`)
		case "/account/delete":
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, `{"status": "deleted"}`)
		case "/payment/checkout":
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, `{"status": "paid"}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	opts := DefaultActiveCrawlOptions(server.URL)
	opts.MaxDepth = 2
	opts.AllowLoopback = true

	crawler, err := NewActiveCrawler(opts)
	if err != nil {
		t.Fatalf("NewActiveCrawler failed: %v", err)
	}

	res, err := crawler.CrawlApplication(context.Background(), server.Client(), "ANONYMOUS")
	if err != nil {
		t.Fatalf("CrawlApplication failed: %v", err)
	}

	// Verify discovery results: destructive routes must be tagged ClassificationExcludedDestructive
	for _, r := range res.Resources {
		if strings.Contains(r.Path, "restart") || strings.Contains(r.Path, "delete") || strings.Contains(r.Path, "checkout") {
			if r.Classification != ClassificationExcludedDestructive {
				t.Errorf("destructive candidate %s was classified as %s, expected %s",
					r.Path, r.Classification, ClassificationExcludedDestructive)
			}
		}
	}

	// Simulate downstream candidate safety contract
	var dispatchedEndpoints []string
	for _, dr := range res.Resources {
		// Rule 1: Exclude destructive actions unconditionally
		if dr.Classification == ClassificationExcludedDestructive {
			continue
		}
		if isDest, _ := IsDestructiveURL(dr.Path, nil); isDest {
			continue
		}
		// Rule 2: Unsafe methods in candidate routes MUST NOT be dispatched
		if dr.Classification == ClassificationEndpointCandidate {
			if dr.HTTPMethod != "GET" && dr.HTTPMethod != "HEAD" && dr.HTTPMethod != "OPTIONS" {
				continue
			}
		}

		// Dispatch safe candidate verification probe
		if dr.Classification == ClassificationEndpointCandidate {
			req, err := http.NewRequestWithContext(context.Background(), dr.HTTPMethod, dr.URL, nil)
			if err == nil {
				resp, err := server.Client().Do(req)
				if err == nil {
					resp.Body.Close()
					dispatchedEndpoints = append(dispatchedEndpoints, fmt.Sprintf("%s %s", dr.HTTPMethod, dr.Path))
				}
			}
		}
	}

	mu.Lock()
	defer mu.Unlock()

	// Assert: Destructive / unsafe candidate routes had ZERO dispatched requests
	if count := requestCounts["POST /api/admin/restart"]; count != 0 {
		t.Errorf("SAFETY VIOLATION: POST /api/admin/restart was dispatched %d times (expected 0)", count)
	}
	if count := requestCounts["POST /account/delete"]; count != 0 {
		t.Errorf("SAFETY VIOLATION: POST /account/delete was dispatched %d times (expected 0)", count)
	}
	if count := requestCounts["POST /payment/checkout"]; count != 0 {
		t.Errorf("SAFETY VIOLATION: POST /payment/checkout was dispatched %d times (expected 0)", count)
	}

	t.Logf("Candidate safety verified: Dispatched safe endpoints: %v", dispatchedEndpoints)
}

func TestFourIdentityVisibility_WithUnconfiguredIdentities(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHdr := r.Header.Get("Authorization")
		switch r.URL.Path {
		case "/":
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprint(w, `<html><body>
				<a href="/public/about">About</a>
				<a href="/api/user_a/vault">Vault A</a>
				<a href="/api/user_b/vault">Vault B</a>
				<a href="/api/admin/metrics">Metrics</a>
			</body></html>`)
		case "/public/about":
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, `{"status": "public"}`)
		case "/api/user_a/vault":
			if authHdr == "Bearer token-user-a" {
				w.WriteHeader(http.StatusOK)
				fmt.Fprint(w, `{"vault": "A"}`)
			} else {
				w.WriteHeader(http.StatusUnauthorized)
			}
		case "/api/user_b/vault":
			if authHdr == "Bearer token-user-b" {
				w.WriteHeader(http.StatusOK)
				fmt.Fprint(w, `{"vault": "B"}`)
			} else {
				w.WriteHeader(http.StatusUnauthorized)
			}
		case "/api/admin/metrics":
			if authHdr == "Bearer token-admin" {
				w.WriteHeader(http.StatusOK)
				fmt.Fprint(w, `{"metrics": "all"}`)
			} else {
				w.WriteHeader(http.StatusUnauthorized)
			}
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	opts := DefaultActiveCrawlOptions(server.URL)
	opts.MaxDepth = 2
	opts.AllowLoopback = true

	// Client map with only ANONYMOUS and USER_A (USER_B and ADMIN unconfigured)
	anonClient := server.Client()

	userATransport := &customHeaderTransport{
		base:   server.Client().Transport,
		header: "Authorization",
		value:  "Bearer token-user-a",
	}
	userAClient := &http.Client{Transport: userATransport}

	idMap := map[string]*http.Client{
		"ANONYMOUS": anonClient,
		"USER_A":    userAClient,
		// USER_B omitted
		// ADMIN omitted
	}

	multiRes, err := CrawlMultiIdentity(context.Background(), opts, idMap)
	if err != nil {
		t.Fatalf("CrawlMultiIdentity failed: %v", err)
	}

	if multiRes.VisibilityMatrix == nil {
		t.Fatal("expected non-nil VisibilityMatrix")
	}

	matrix := multiRes.VisibilityMatrix
	// Check unconfigured status
	for routeKey, idObs := range matrix.Endpoints {
		userBObs, hasB := idObs["USER_B"]
		if !hasB || userBObs.StatusText != "NOT_CONFIGURED" {
			t.Errorf("route %s under unconfigured USER_B expected status NOT_CONFIGURED, got %+v", routeKey, userBObs)
		}

		adminObs, hasAdmin := idObs["ADMIN"]
		if !hasAdmin || adminObs.StatusText != "NOT_CONFIGURED" {
			t.Errorf("route %s under unconfigured ADMIN expected status NOT_CONFIGURED, got %+v", routeKey, adminObs)
		}
	}
}

type customHeaderTransport struct {
	base   http.RoundTripper
	header string
	value  string
}

func (c *customHeaderTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	reqCopy := req.Clone(req.Context())
	reqCopy.Header.Set(c.header, c.value)
	rt := c.base
	if rt == nil {
		rt = http.DefaultTransport
	}
	return rt.RoundTrip(reqCopy)
}
