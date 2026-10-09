package discovery

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"felix/pkg/crawler"
)

// TestSyntheticCorpus_PrecisionRecallGroundTruth tests the discovery engine against a known ground-truth application.
func TestSyntheticCorpus_PrecisionRecallGroundTruth(t *testing.T) {
	var formSubmissionCount int64

	// Ground-truth server simulating an enterprise web property
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Detect if any form was accidentally submitted
		if r.Method == http.MethodPost && (r.URL.Path == "/auth/login" || r.URL.Path == "/auth/register") {
			atomic.AddInt64(&formSubmissionCount, 1)
		}

		w.Header().Set("Server", "nginx/1.24.0")
		w.Header().Set("X-Powered-By", "Express")

		switch r.URL.Path {
		case "/", "/index.html":
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write([]byte(`
				<!DOCTYPE html>
				<html>
				<head>
					<title>Corporate Portal</title>
					<meta name="next-head-count" content="12" />
					<link rel="stylesheet" href="/static/tailwind.min.css" />
				</head>
				<body>
					<div id="__next">
						<script id="__NEXT_DATA__" type="application/json">{"buildId":"test-build"}</script>
					</div>

					<!-- Navigation Links -->
					<nav>
						<a href="/portal/dashboard">Dashboard</a>
						<a href="/admin/console">Admin Console</a>
						<a href="https://external-partner.example.org/docs">External Partner Docs</a>
					</nav>

					<!-- Login Form -->
					<form action="/auth/login" method="POST" enctype="application/x-www-form-urlencoded">
						<input type="text" name="username" required />
						<input type="password" name="password" required />
						<input type="hidden" name="csrf_token" value="static_csrf_token_123" />
						<button type="submit">Sign In</button>
					</form>

					<!-- Registration Form -->
					<form action="/auth/register" method="POST">
						<input type="text" name="email" required />
						<input type="password" name="new_password" required />
						<input type="password" name="confirm_password" required />
					</form>

					<!-- Password Reset Link -->
					<a href="/auth/reset-password">Forgot Password?</a>

					<!-- Script Bundles -->
					<script src="/static/app.js"></script>
				</body>
				</html>
			`))

		case "/static/app.js":
			w.Header().Set("Content-Type", "application/javascript")
			_, _ = w.Write([]byte(`
				const API_ROOT = "/api/v1";
				fetch("/api/v1/users", { method: "GET" });
				fetch("/api/v1/orders/{orderId}", { method: "GET" });
				fetch("/api/v1/checkout", {
					method: "POST",
					body: JSON.stringify({
						cart_id: "cart_99",
						payment_method: "stripe"
					})
				});
				const wsClient = "wss://stream.clientcorp.example/v1/feed";
				const supabaseBackend = "https://corp-prod.supabase.co";
				const s3Bucket = "https://corp-assets.s3.amazonaws.com/uploads";
				const thirdPartyAPI = "https://api.thirdparty-analytics.com/v1/track";
			`))

		default:
			http.NotFound(w, r)
		}
	}))
	defer ts.Close()

	// 1. Crawl synthetic target with crawler
	crawlerCfg := crawler.Config{
		Concurrency: 2,
		Timeout:     5 * time.Second,
		Client:      ts.Client(),
	}
	cEng := crawler.New(crawlerCfg)
	crawlChan := cEng.CrawlConcurrently(context.Background(), []string{ts.URL})
	var crawlRes crawler.Result
	for r := range crawlChan {
		crawlRes = r
	}

	if crawlRes.Err != nil {
		t.Fatalf("crawler failed on synthetic target: %v", crawlRes.Err)
	}

	// 2. Execute Attack-Surface Engine
	eng := NewEngine(Config{
		Concurrency: 2,
		Timeout:     5 * time.Second,
	})

	scopeAllowFunc := func(host string) bool {
		// Only ts.URL host is in-scope; external-partner and thirdparty are out of scope
		return strings.EqualFold(host, ts.Listener.Addr().String())
	}

	inv := eng.AnalyzeTarget(
		context.Background(),
		"ASM-BENCHMARK",
		"EXEC-001",
		"TGT-001",
		ts.URL,
		string(crawlRes.HTML),
		crawlRes.Header,
		nil,
		crawlRes.Assets,
		scopeAllowFunc,
	)

	// 3. Ground-Truth Acceptance Verification: Form Submissions
	if atomic.LoadInt64(&formSubmissionCount) != 0 {
		t.Fatalf("CRITICAL SAFETY VIOLATION: %d form submissions detected during discovery phase!", formSubmissionCount)
	}

	// 4. Ground-Truth Acceptance Verification: Entity Counts & Specific Discoveries
	summary := inv.Summary()

	// Ground truth definitions:
	// - Technologies expected: Nginx, Express.js, Next.js, Tailwind CSS (4)
	// - Forms expected: Login Form (/auth/login), Registration Form (/auth/register) (2)
	// - Applications expected: Root App, Admin Portal (/admin) (2)
	// - Auth surfaces expected: Login, Registration, Password Reset (/auth/reset-password) (>=3)
	// - Cloud services expected: Supabase (corp-prod.supabase.co), AWS S3 (corp-assets.s3.amazonaws.com) (2)
	// - Third-party out-of-scope hostnames: external-partner.example.org, api.thirdparty-analytics.com (2)

	techs := inv.FilterByType(AssetTypeTechnology)
	forms := inv.FilterByType(AssetTypeForm)
	apps := inv.FilterByType(AssetTypeApplication)
	auths := inv.FilterByType(AssetTypeAuthSurface)
	clouds := inv.FilterByType(AssetTypeCloudService)
	subdomains := inv.FilterByType(AssetTypeSubdomain)

	// Evaluate True Positives (TP) and False Positives (FP)
	// Technologies
	expectedTechs := map[string]bool{"Nginx": false, "Express.js": false, "Next.js": false, "Tailwind CSS": false}
	for _, tc := range techs {
		if name, ok := tc.Metadata["name"].(string); ok {
			if _, exists := expectedTechs[name]; exists {
				expectedTechs[name] = true
			}
		}
	}
	techTP := 0
	for _, found := range expectedTechs {
		if found {
			techTP++
		}
	}
	techRecall := float64(techTP) / float64(len(expectedTechs))
	if techRecall < 1.0 {
		t.Errorf("technology recall = %.2f; expected 1.0 (found: %+v)", techRecall, expectedTechs)
	}

	// Forms
	if len(forms) < 2 {
		t.Errorf("forms recall: expected at least 2 forms, got %d", len(forms))
	}
	hasLoginForm := false
	hasRegForm := false
	for _, f := range forms {
		if strings.Contains(f.CanonicalID, "/auth/login") {
			hasLoginForm = true
		}
		if strings.Contains(f.CanonicalID, "/auth/register") {
			hasRegForm = true
		}
	}
	if !hasLoginForm || !hasRegForm {
		t.Errorf("missing expected login/registration forms: login=%v, reg=%v", hasLoginForm, hasRegForm)
	}

	// Applications
	if len(apps) < 2 {
		t.Errorf("applications recall: expected at least 2 distinct applications (root and /admin), got %d", len(apps))
	}

	// Auth Surfaces
	if len(auths) < 3 {
		t.Errorf("auth surfaces recall: expected at least 3 auth surfaces (login, register, reset), got %d", len(auths))
	}

	// Cloud Services
	if len(clouds) < 2 {
		t.Errorf("cloud services recall: expected at least 2 cloud references (Supabase, S3), got %d", len(clouds))
	}

	// Third-Party Hostnames & Out-of-Scope Classification
	outOfScopeHostFound := false
	for _, sd := range subdomains {
		if strings.Contains(sd.CanonicalID, "external-partner.example.org") || strings.Contains(sd.CanonicalID, "api.thirdparty-analytics.com") {
			outOfScopeHostFound = true
			if sd.InScope {
				t.Errorf("CRITICAL SCOPE ERROR: third-party hostname %s marked in-scope!", sd.CanonicalID)
			}
			if sd.DiscoveryStatus != StatusOutOfScope {
				t.Errorf("expected DiscoveryStatus OUT_OF_SCOPE for %s, got %s", sd.CanonicalID, sd.DiscoveryStatus)
			}
		}
	}
	if !outOfScopeHostFound {
		t.Errorf("expected passive discovery of out-of-scope hostnames from HTML/JS")
	}

	// Endpoints & Parameters
	endpoints := inv.FilterByType(AssetTypeEndpoint)
	params := inv.FilterByType(AssetTypeParameter)

	if len(endpoints) < 3 {
		t.Errorf("endpoints recall: expected at least 3 REST endpoints, got %d", len(endpoints))
	}
	if len(params) < 4 {
		t.Errorf("parameters recall: expected parameters from forms and JS body, got %d", len(params))
	}

	// Output ground truth evaluation
	t.Logf("Ground-Truth Acceptance Metrics:")
	t.Logf("  Total Assets:         %d", summary.TotalAssets)
	t.Logf("  In-Scope / Out-Scope: %d / %d", summary.InScopeAssets, summary.OutOfScopeAssets)
	t.Logf("  Total Relationships:  %d", summary.TotalRelations)
	t.Logf("  Technologies TP/Exp:  %d/%d (Recall: %.2f)", techTP, len(expectedTechs), techRecall)
	t.Logf("  Forms Verified:       %d", len(forms))
	t.Logf("  Auth Surfaces:        %d", len(auths))
	t.Logf("  Cloud Services:       %d", len(clouds))
	t.Logf("  Endpoints:            %d", len(endpoints))
	t.Logf("  Input Parameters:     %d", len(params))
}
