package discovery

import (
	"context"
	"net/http"
	"net/url"
	"testing"
	"time"

	"felix/pkg/crawler"
)

func TestExtractRootDomain(t *testing.T) {
	cases := []struct {
		input    string
		expected string
	}{
		{"example.com", "example.com"},
		{"app.example.com", "example.com"},
		{"api.staging.example.com", "example.com"},
		{"portal.service.co.uk", "service.co.uk"},
		{"sub.domain.com.au", "domain.com.au"},
		{"localhost", "localhost"},
	}

	for _, c := range cases {
		actual := ExtractRootDomain(c.input)
		if actual != c.expected {
			t.Errorf("ExtractRootDomain(%q) = %q; expected %q", c.input, actual, c.expected)
		}
	}
}

func TestExtractHostnamesFromContent(t *testing.T) {
	content := `
		Check out https://api.example.com/v1 and https://cdn.assets.net/script.js.
		Also internal host staging.internal.corp is mentioned here.
		Contact us at admin@corporate.org or visit //assets.global.net/app.
		Ignore images like test.png or fake.map.
		Ignore media files: intro-cinematic.mp4 and soundtrack.mp3.
		Ignore CSS utilities: gap-1.5 py-2.5 translate-x-0.5 1.5rem 0.18em.
		Ignore SVG coordinates: m13.832 9.2-11.5 85.5 0.08.
		Ignore JavaScript DOM accesses: document.documentElement.classList.toggle('dark'),
		localStorage.getItem('token'), window.matchMedia('(prefers-color-scheme)'),
		React.Fragment, next.metadata.
	`
	hosts := ExtractHostnamesFromContent(content)
	found := make(map[string]bool)
	for _, h := range hosts {
		found[h] = true
	}

	// Legitimate targets must be discovered
	if !found["api.example.com"] {
		t.Errorf("expected api.example.com to be discovered, got: %v", hosts)
	}
	if !found["cdn.assets.net"] {
		t.Errorf("expected cdn.assets.net to be discovered, got: %v", hosts)
	}
	if !found["staging.internal.corp"] {
		t.Errorf("expected staging.internal.corp to be discovered, got: %v", hosts)
	}
	if !found["corporate.org"] {
		t.Errorf("expected corporate.org from email to be discovered, got: %v", hosts)
	}
	if !found["assets.global.net"] {
		t.Errorf("expected assets.global.net from protocol-relative URL to be discovered, got: %v", hosts)
	}

	// False positives from real-world sites must be strictly rejected
	falsePositives := []string{
		"test.png", "fake.map", "intro-cinematic.mp4", "soundtrack.mp3",
		"0.08", "85.5", "1.5rem", "0.18em", "gap-1.5", "py-2.5", "translate-x-0.5",
		"document.documentelement.classlist.toggle", "localstorage.getitem",
		"window.matchmedia", "react.fragment", "next.metadata",
	}
	for _, fp := range falsePositives {
		if found[fp] {
			t.Errorf("false positive hostname %q should NOT be discovered; all found: %v", fp, hosts)
		}
	}
}

func TestFormExtractor(t *testing.T) {
	html := `
	<!DOCTYPE html>
	<html>
	<body>
		<!-- Login form -->
		<form action="/auth/login" method="POST" enctype="application/x-www-form-urlencoded">
			<input type="text" name="username" required />
			<input type="password" name="password" required />
			<input type="hidden" name="csrf_token" value="abc123token" />
			<button type="submit">Sign In</button>
		</form>

		<!-- Search form -->
		<form action="/search" method="GET">
			<input type="text" name="q" />
		</form>

		<!-- Upload form -->
		<form action="/api/upload" method="POST" enctype="multipart/form-data">
			<input type="file" name="attachment" />
			<textarea name="description"></textarea>
		</form>
	</body>
	</html>
	`
	baseURL, _ := url.Parse("https://app.example.com/index.html")
	fe := NewFormExtractor()
	forms := fe.ExtractForms(html, baseURL)

	if len(forms) != 3 {
		t.Fatalf("expected 3 forms, got %d", len(forms))
	}

	// Login form verification
	loginForm := forms[0]
	if loginForm.Purpose != "LOGIN" {
		t.Errorf("expected loginForm.Purpose = LOGIN, got %s", loginForm.Purpose)
	}
	if loginForm.Method != "POST" {
		t.Errorf("expected POST method, got %s", loginForm.Method)
	}
	if !loginForm.HasPassword {
		t.Errorf("expected HasPassword = true")
	}
	if len(loginForm.Fields) != 3 {
		t.Errorf("expected 3 fields in login form, got %d", len(loginForm.Fields))
	}

	// Search form verification
	searchForm := forms[1]
	if searchForm.Purpose != "SEARCH" {
		t.Errorf("expected searchForm.Purpose = SEARCH, got %s", searchForm.Purpose)
	}

	// Upload form verification
	uploadForm := forms[2]
	if uploadForm.Purpose != "FILE_UPLOAD" {
		t.Errorf("expected uploadForm.Purpose = FILE_UPLOAD, got %s", uploadForm.Purpose)
	}
	if !uploadForm.HasFileUpload {
		t.Errorf("expected HasFileUpload = true")
	}
}

func TestParameterExtractor(t *testing.T) {
	pe := NewParameterExtractor()

	// 1. URL Query and Path Template Normalization
	rawURL := "https://api.example.com/v1/users/{userId}?status=active&sort=desc"
	endpoint, params := NormalizeEndpointWithParams(rawURL)

	if endpoint != "https://api.example.com/v1/users/{userId}" {
		t.Errorf("unexpected endpoint: %s", endpoint)
	}

	foundParams := make(map[string]DiscoveredParameter)
	for _, p := range params {
		foundParams[p.Name] = p
	}

	if p, ok := foundParams["userId"]; !ok || p.Location != ParamLocPath {
		t.Errorf("expected path parameter userId, got: %v", p)
	}
	if p, ok := foundParams["status"]; !ok || p.Location != ParamLocQuery {
		t.Errorf("expected query parameter status, got: %v", p)
	}
	if p, ok := foundParams["sort"]; !ok || p.Location != ParamLocQuery {
		t.Errorf("expected query parameter sort, got: %v", p)
	}

	// 2. JS Request Parameters
	jsCode := `
		fetch("/api/login", {
			method: "POST",
			body: JSON.stringify({
				username: user,
				password: pwd,
				remember_me: true
			})
		});
		const gql = "query GetAccount($accountId: ID!, $includeDetails: Boolean!) { account { id } }";
	`
	jsParams := pe.ExtractJSRequestParameters("/api/login", jsCode, "bundle.js")
	foundJS := make(map[string]bool)
	for _, p := range jsParams {
		foundJS[p.Name] = true
	}

	if !foundJS["username"] || !foundJS["password"] {
		t.Errorf("expected username and password parameters from JS, got: %v", jsParams)
	}
	if !foundJS["accountId"] {
		t.Errorf("expected accountId GraphQL variable from JS, got: %v", jsParams)
	}
}

func TestTechnologyExtractor(t *testing.T) {
	te := NewTechnologyExtractor()

	headers := http.Header{}
	headers.Set("Server", "nginx/1.22.1")
	headers.Set("X-Powered-By", "Express")
	headers.Add("Set-Cookie", "connect.sid=s%3A123; Path=/; HttpOnly")

	html := `
	<!DOCTYPE html>
	<html>
	<head>
		<meta name="next-head-count" content="5" />
		<link rel="stylesheet" href="/assets/tailwind.min.css" />
	</head>
	<body>
		<div id="__next">
			<script id="__NEXT_DATA__" type="application/json">{"props":{}}</script>
		</div>
	</body>
	</html>
	`

	techs := te.ExtractTechnologies(headers, html)
	foundTech := make(map[string]DiscoveredTechnology)
	for _, tc := range techs {
		foundTech[tc.Name] = tc
	}

	if nginx, ok := foundTech["Nginx"]; !ok || nginx.Version != "1.22.1" {
		t.Errorf("expected Nginx 1.22.1, got: %v", nginx)
	}
	if express, ok := foundTech["Express.js"]; !ok || express.Category != TechCategoryBackendRuntime {
		t.Errorf("expected Express.js runtime, got: %v", express)
	}
	if nextjs, ok := foundTech["Next.js"]; !ok || nextjs.Category != TechCategoryFramework {
		t.Errorf("expected Next.js framework, got: %v", nextjs)
	}
	if tailwind, ok := foundTech["Tailwind CSS"]; !ok {
		t.Errorf("expected Tailwind CSS, got: %v", tailwind)
	}
}

func TestAuthSurfaceExtractor(t *testing.T) {
	routes := []string{
		"/login",
		"/register",
		"/reset-password",
		"/oauth/authorize",
		"/mfa/verify",
		"/session/logout",
		"/about-us",
	}

	for _, r := range routes {
		authType, isAuth := ClassifyAuthRoute(r)
		if r == "/about-us" {
			if isAuth {
				t.Errorf("/about-us should NOT be classified as auth surface, got %s", authType)
			}
		} else {
			if !isAuth {
				t.Errorf("expected %s to be classified as auth surface", r)
			}
		}
	}
}

func TestUnifiedEngine_EndToEnd(t *testing.T) {
	cfg := Config{
		Concurrency: 2,
		Timeout:     3 * time.Second,
	}
	eng := NewEngine(cfg)

	targetURL := "https://app.clientcorp.example:443"
	html := `
	<!DOCTYPE html>
	<html>
	<head>
		<title>Customer Portal</title>
		<script id="__NEXT_DATA__">{}</script>
	</head>
	<body>
		<a href="/portal/dashboard">Dashboard</a>
		<a href="/admin/settings">Admin Area</a>
		<form action="/auth/login" method="POST">
			<input type="text" name="email" required />
			<input type="password" name="password" required />
		</form>
	</body>
	</html>
	`
	headers := http.Header{}
	headers.Set("Server", "cloudflare")
	headers.Set("X-Powered-By", "PHP/8.1.0")

	jsContent := []byte(`
		const API_BASE = "https://app.clientcorp.example/api/v1";
		fetch("/api/v1/users", { method: "GET" });
		fetch("/api/v1/auth/token", { method: "POST", body: JSON.stringify({ grant_type: "password" }) });
		const sb = "https://myproject.supabase.co";
	`)

	crawledAssets := []crawler.Asset{
		{
			URL:      "https://app.clientcorp.example/assets/main.js",
			Type:     crawler.AssetJavaScript,
			Content:  jsContent,
			Size:     int64(len(jsContent)),
			InScope:  true,
		},
	}

	inv := eng.AnalyzeTarget(
		context.Background(),
		"ASM-TEST",
		"EXEC-001",
		"TGT-001",
		targetURL,
		html,
		headers,
		nil,
		crawledAssets,
		func(h string) bool { return h == "app.clientcorp.example" },
	)

	summary := inv.Summary()

	// Assertions on attack surface inventory
	if summary.DomainsCount == 0 {
		t.Errorf("expected at least 1 domain, got %d", summary.DomainsCount)
	}
	if summary.SubdomainsCount == 0 {
		t.Errorf("expected at least 1 subdomain, got %d", summary.SubdomainsCount)
	}
	if summary.WebServicesCount == 0 {
		t.Errorf("expected at least 1 web service, got %d", summary.WebServicesCount)
	}
	if summary.ApplicationsCount < 2 {
		t.Errorf("expected at least 2 applications (root and admin), got %d", summary.ApplicationsCount)
	}
	if summary.FormsCount == 0 {
		t.Errorf("expected at least 1 form, got %d", summary.FormsCount)
	}
	if summary.ParametersCount == 0 {
		t.Errorf("expected parameters discovered, got %d", summary.ParametersCount)
	}
	if summary.AuthSurfacesCount == 0 {
		t.Errorf("expected auth surfaces discovered, got %d", summary.AuthSurfacesCount)
	}
	if summary.TechnologiesCount < 2 {
		t.Errorf("expected at least 2 technologies (Next.js, Cloudflare, PHP), got %d", summary.TechnologiesCount)
	}
	if summary.CloudServicesCount == 0 {
		t.Errorf("expected at least 1 cloud service (Supabase), got %d", summary.CloudServicesCount)
	}
	if summary.TotalRelations == 0 {
		t.Errorf("expected relations created, got %d", summary.TotalRelations)
	}

	// Verify deduplication
	initialCount := len(inv.Assets)
	// Re-add an existing asset
	inv.AddAsset(inv.Assets[0])
	if len(inv.Assets) != initialCount {
		t.Errorf("expected deduplication to prevent asset count increase: %d vs %d", len(inv.Assets), initialCount)
	}
}
