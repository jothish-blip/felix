package crawler_test

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"felix/pkg/crawler"
)

// 1. Minified JS with literal API paths
func TestP14_1_MinifiedJSLiteralPaths(t *testing.T) {
	minifiedJS := `!function(e){function t(r){fetch("/api/v1/projects",{method:"POST"})}axios.get("/api/v1/users");axios.delete("/api/v1/users/123")}()`

	opts := crawler.DefaultBundleAnalysisOptions()
	opts.TargetHost = "app.local"
	extractor := crawler.NewBundleExtractor(opts)

	candidates, _, _, warnings := extractor.ExtractFromBundle([]byte(minifiedJS), "https://app.local/static/bundle.min.js")
	if len(warnings) > 0 {
		t.Logf("Warnings: %v", warnings)
	}

	foundUsers := false
	foundProjects := false
	for _, c := range candidates {
		if c.Path == "/api/v1/users" && c.HTTPMethod == "GET" {
			foundUsers = true
			if c.Confidence != crawler.ConfidenceConfirmed {
				t.Errorf("Expected CONFIRMED confidence, got %s", c.Confidence)
			}
		}
		if c.Path == "/api/v1/projects" && c.HTTPMethod == "POST" {
			foundProjects = true
		}
	}

	if !foundUsers {
		t.Errorf("Expected to find /api/v1/users GET candidate, got: %+v", candidates)
	}
	if !foundProjects {
		t.Errorf("Expected to find /api/v1/projects POST candidate, got: %+v", candidates)
	}
}

// 2. Concatenated strings and template literals
func TestP14_1_ConcatenatedStringsAndTemplateLiterals(t *testing.T) {
	js := `
		var API_ROOT = "/api/v2";
		var ENDPOINT = API_ROOT + "/reports";
		fetch(ENDPOINT);

		function getItem(id) {
			return fetch("/api/v1/items/" + id);
		}

		function getDetails(itemId) {
			return fetch(` + "`" + `/api/v1/details/${itemId}` + "`" + `);
		}
	`

	opts := crawler.DefaultBundleAnalysisOptions()
	opts.TargetHost = "app.local"
	extractor := crawler.NewBundleExtractor(opts)

	candidates, _, _, _ := extractor.ExtractFromBundle([]byte(js), "https://app.local/app.js")

	foundReports := false
	foundDetails := false
	for _, c := range candidates {
		if c.Path == "/api/v2/reports" {
			foundReports = true
			if !c.IsStaticallyReconstructed {
				t.Errorf("Expected /api/v2/reports to be marked statically reconstructed")
			}
		}
		if c.Path == "/api/v1/details/{param}" {
			foundDetails = true
		}
	}

	if !foundReports {
		t.Errorf("Expected /api/v2/reports from constant concatenation, got: %+v", candidates)
	}
	if !foundDetails {
		t.Errorf("Expected /api/v1/details/{param} from template literal, got: %+v", candidates)
	}
}

// 3. Next.js App Router build metadata
func TestP14_1_NextBuildManifest(t *testing.T) {
	manifestJS := `self.__BUILD_MANIFEST={"/dashboard":["static/chunks/dashboard.js"],"/settings":["static/chunks/settings.js"],"/api/metrics":["static/chunks/metrics.js"]};self.__BUILD_MANIFEST_CB&&self.__BUILD_MANIFEST_CB();`

	opts := crawler.DefaultBundleAnalysisOptions()
	opts.TargetHost = "next.local"
	extractor := crawler.NewBundleExtractor(opts)

	candidates, _, _, _ := extractor.ExtractFromBundle([]byte(manifestJS), "https://next.local/_next/static/buildManifest.js")

	foundMetrics := false
	foundDashboard := false
	for _, c := range candidates {
		if c.Path == "/api/metrics" {
			foundMetrics = true
			if c.SourceType != crawler.SourceTypeNextManifest {
				t.Errorf("Expected NEXT_MANIFEST source type, got %s", c.SourceType)
			}
		}
		if c.Path == "/dashboard" {
			foundDashboard = true
		}
	}

	if !foundMetrics {
		t.Errorf("Expected /api/metrics from __BUILD_MANIFEST, got: %+v", candidates)
	}
	if !foundDashboard {
		t.Errorf("Expected /dashboard from __BUILD_MANIFEST, got: %+v", candidates)
	}
}

// 4. $ACTION_ID_ references (assert zero fabricated endpoints)
func TestP14_1_ServerActionReferences(t *testing.T) {
	js := `
		var actionA = $$ACTION_ID_409b626e2e4b313ef4b14d2325dd6774ecfa8828;
		var actionB = createServerReference("d8e20f92b45a6c31829e12039840294820194820", callServer, undefined, findSourceMapURL, "submitOrder");
	`

	opts := crawler.DefaultBundleAnalysisOptions()
	extractor := crawler.NewBundleExtractor(opts)

	candidates, actions, _, _ := extractor.ExtractFromBundle([]byte(js), "https://app.local/main.js")

	if len(actions) != 2 {
		t.Fatalf("Expected 2 server actions, got %d", len(actions))
	}

	for _, c := range candidates {
		if strings.Contains(c.Path, "409b62") || strings.Contains(c.Path, "d8e20f") {
			t.Fatalf("CRITICAL: Fabricated standalone HTTP endpoint for server action ID: %s", c.Path)
		}
	}

	actionMap := make(map[string]crawler.ServerActionReference)
	for _, a := range actions {
		actionMap[a.ActionID] = a
	}

	if _, ok := actionMap["409b626e2e4b313ef4b14d2325dd6774ecfa8828"]; !ok {
		t.Errorf("Missing ActionID 409b626e2e4b313ef4b14d2325dd6774ecfa8828")
	}
	actB, ok := actionMap["d8e20f92b45a6c31829e12039840294820194820"]
	if !ok {
		t.Errorf("Missing ActionID d8e20f92b45a6c31829e12039840294820194820")
	} else if actB.ExportName != "submitOrder" {
		t.Errorf("Expected export name 'submitOrder', got %q", actB.ExportName)
	}
}

// 5. Webpack runtime chunk mappings and asynchronous chunks
func TestP14_1_WebpackChunksAndAsyncTraversal(t *testing.T) {
	var ts *httptest.Server
	ts = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprintf(w, `<html><script src="/static/runtime.js"></script></html>`)
		case "/static/runtime.js":
			w.Header().Set("Content-Type", "application/javascript")
			fmt.Fprintf(w, `
				__webpack_require__.p = "/static/";
				var chunks = { 101: "abc1234", 102: "def5678" };
			`)
		case "/static/101.abc1234.js":
			w.Header().Set("Content-Type", "application/javascript")
			fmt.Fprintf(w, `fetch("/api/v1/async-users");`)
		case "/static/102.def5678.js":
			w.Header().Set("Content-Type", "application/javascript")
			fmt.Fprintf(w, `axios.post("/api/v1/async-checkout");`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer ts.Close()

	cfg := crawler.DefaultConfig()
	cfg.AllowLoopback = true
	cfg.BundleAnalysis.TraverseChunks = true
	c := crawler.New(cfg)

	res := c.Crawl(context.Background(), ts.URL)
	if res.Err != nil {
		t.Fatalf("Crawl error: %v", res.Err)
	}

	if res.BundleAnalysis == nil {
		t.Fatalf("Expected non-nil BundleAnalysis report")
	}

	foundAsyncUsers := false
	foundAsyncCheckout := false
	for _, cand := range res.RouteCandidates {
		if cand.Path == "/api/v1/async-users" {
			foundAsyncUsers = true
		}
		if cand.Path == "/api/v1/async-checkout" {
			foundAsyncCheckout = true
		}
	}

	if !foundAsyncUsers {
		t.Errorf("Expected to discover /api/v1/async-users from chunk 101, candidates: %+v", res.RouteCandidates)
	}
	if !foundAsyncCheckout {
		t.Errorf("Expected to discover /api/v1/async-checkout from chunk 102, candidates: %+v", res.RouteCandidates)
	}
}

// 6. Missing and malformed chunks
func TestP14_1_MissingAndMalformedChunks(t *testing.T) {
	var ts *httptest.Server
	ts = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprintf(w, `<html><script src="/runtime.js"></script></html>`)
		case "/runtime.js":
			w.Header().Set("Content-Type", "application/javascript")
			fmt.Fprintf(w, `
				var chunks = { 404: "missing", 500: "corrupt" };
			`)
		case "/404.missing.js":
			http.NotFound(w, r)
		case "/500.corrupt.js":
			w.Header().Set("Content-Type", "application/javascript")
			// Severely malformed/truncated JS
			w.Write([]byte(`function broken( { "unclosed`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer ts.Close()

	cfg := crawler.DefaultConfig()
	cfg.AllowLoopback = true
	cfg.BundleAnalysis.TraverseChunks = true
	c := crawler.New(cfg)

	res := c.Crawl(context.Background(), ts.URL)
	if res.Err != nil {
		t.Fatalf("Crawl failed unexpectedly: %v", res.Err)
	}

	if res.BundleAnalysis == nil {
		t.Fatalf("Expected non-nil BundleAnalysis report")
	}

	found404 := false
	for _, chunk := range res.BundleAnalysis.Chunks {
		if strings.Contains(chunk.URL, "404.missing") && (chunk.Status == "NOT_FOUND" || chunk.Status == "EMPTY") {
			found404 = true
		}
	}
	if !found404 {
		t.Logf("Chunk results: %+v", res.BundleAnalysis.Chunks)
	}
}

// 7. React Native Metro-style bundles
func TestP14_1_ReactNativeMetroBundles(t *testing.T) {
	metroBundle := `
		__d(function(g,r,i,a,m,e,d){
			var api = {
				login: function() {
					return fetch("/api/mobile/v1/auth/login", { method: "POST" });
				},
				profile: function() {
					return axios.get("/api/mobile/v1/user/profile");
				}
			};
		}, 42, [1, 2]);
	`

	opts := crawler.DefaultBundleAnalysisOptions()
	opts.TargetHost = "app.local"

	candidates, actions, report, err := crawler.AnalyzeReactNativeBundle([]byte(metroBundle), "index.android.bundle", opts)
	if err != nil {
		t.Fatalf("AnalyzeReactNativeBundle failed: %v", err)
	}

	if report.TotalCandidatesDiscovered < 2 {
		t.Errorf("Expected at least 2 candidates, got %d", report.TotalCandidatesDiscovered)
	}
	if len(actions) != 0 {
		t.Errorf("Expected 0 server actions in React Native bundle, got %d", len(actions))
	}

	foundLogin := false
	foundProfile := false
	for _, c := range candidates {
		if c.Path == "/api/mobile/v1/auth/login" {
			foundLogin = true
			if c.BundleType != "REACT_NATIVE" {
				t.Errorf("Expected REACT_NATIVE bundle type, got %s", c.BundleType)
			}
			if c.SourceType != crawler.SourceTypeReactNativeBundle {
				t.Errorf("Expected REACT_NATIVE_BUNDLE source type, got %s", c.SourceType)
			}
		}
		if c.Path == "/api/mobile/v1/user/profile" {
			foundProfile = true
		}
	}

	if !foundLogin {
		t.Errorf("Missing /api/mobile/v1/auth/login in Metro bundle, got: %+v", candidates)
	}
	if !foundProfile {
		t.Errorf("Missing /api/mobile/v1/user/profile in Metro bundle, got: %+v", candidates)
	}
}

// 8. Multiple bundles exposing the same endpoint with different provenance
func TestP14_1_ProvenanceDeduplication(t *testing.T) {
	bundle1 := `var x = "/api/v1/status";`
	bundle2 := `axios.get("/api/v1/status");`

	cfg := crawler.DefaultConfig()
	cfg.AllowLoopback = true

	var ts *httptest.Server
	ts = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			fmt.Fprintf(w, `<html><script src="/b1.js"></script><script src="/b2.js"></script></html>`)
		case "/b1.js":
			w.Header().Set("Content-Type", "application/javascript")
			fmt.Fprint(w, bundle1)
		case "/b2.js":
			w.Header().Set("Content-Type", "application/javascript")
			fmt.Fprint(w, bundle2)
		default:
			http.NotFound(w, r)
		}
	}))
	defer ts.Close()

	c := crawler.New(cfg)
	res := c.Crawl(context.Background(), ts.URL)

	countStatus := 0
	var finalCandidate crawler.RouteCandidate
	for _, cand := range res.RouteCandidates {
		if cand.Path == "/api/v1/status" {
			countStatus++
			finalCandidate = cand
		}
	}

	if countStatus != 1 {
		t.Errorf("Expected exactly 1 deduplicated entry for /api/v1/status, got %d", countStatus)
	}
	if finalCandidate.Confidence != crawler.ConfidenceConfirmed {
		t.Errorf("Expected merged confidence to be CONFIRMED, got %s", finalCandidate.Confidence)
	}
}

// 9. Encoded strings, irrelevant strings, and false-positive candidates
func TestP14_1_FalsePositiveFiltration(t *testing.T) {
	js := `
		var img = "/assets/logo.png";
		var css = "/styles/theme.css";
		var jsLink = "javascript:void(0)";
		var dataUri = "data:text/html;base64,PHNjcmlwdD4=";
		var valid = fetch("/api/v1/valid-endpoint");
	`

	opts := crawler.DefaultBundleAnalysisOptions()
	extractor := crawler.NewBundleExtractor(opts)

	candidates, _, _, _ := extractor.ExtractFromBundle([]byte(js), "https://app.local/app.js")

	for _, c := range candidates {
		if strings.HasSuffix(c.Path, ".png") || strings.HasSuffix(c.Path, ".css") {
			t.Errorf("Static asset leaked as route candidate: %s", c.Path)
		}
		if strings.HasPrefix(c.Path, "javascript:") || strings.HasPrefix(c.Path, "data:") {
			t.Errorf("Non-HTTP pseudo scheme leaked as route candidate: %s", c.Path)
		}
	}

	foundValid := false
	for _, c := range candidates {
		if c.Path == "/api/v1/valid-endpoint" {
			foundValid = true
		}
	}
	if !foundValid {
		t.Errorf("Expected to find /api/v1/valid-endpoint, got: %+v", candidates)
	}
}

// 10. Malicious-looking strings and parser edge cases
func TestP14_1_ParserEdgeCases(t *testing.T) {
	edgeCases := []string{
		`"unterminated string literal`,
		`function foo() { {{{ [[[]`,
		"`nested ${`template ${`literals`}`}`",
		`var x = "/api/v1/\u0061\u0075\u0074\u0068";`,
		`fetch("/api/v1/test//double//slash/");`,
	}

	opts := crawler.DefaultBundleAnalysisOptions()
	extractor := crawler.NewBundleExtractor(opts)

	for _, ec := range edgeCases {
		// Ensure it never panics
		cands, _, _, _ := extractor.ExtractFromBundle([]byte(ec), "https://app.local/edge.js")
		for _, c := range cands {
			if strings.Contains(c.Path, "//") {
				t.Errorf("Normalized path contains consecutive slashes: %s", c.Path)
			}
			if strings.HasSuffix(c.Path, "/") && len(c.Path) > 1 {
				t.Errorf("Normalized path has trailing slash: %s", c.Path)
			}
		}
	}
}

// 11. Very large inputs and deeply nested expressions
func TestP14_1_BoundedLimits(t *testing.T) {
	// Create a deeply nested expression: (((((...)))))
	nested := strings.Repeat("(", 200) + `"/api/v1/deep"` + strings.Repeat(")", 200)

	opts := crawler.DefaultBundleAnalysisOptions()
	opts.MaxTokens = 1000
	extractor := crawler.NewBundleExtractor(opts)

	done := make(chan bool)
	go func() {
		extractor.ExtractFromBundle([]byte(nested), "https://app.local/nested.js")
		done <- true
	}()

	select {
	case <-done:
		// Succeeded within bounded recursion
	case <-time.After(5 * time.Second):
		t.Fatalf("Parser hung or timed out on deeply nested expression")
	}
}

// 12. Out-of-scope absolute URLs
func TestP14_1_OutOfScopeAbsoluteURLs(t *testing.T) {
	js := `
		fetch("https://external-auth.com/oauth/v2/token");
		fetch("https://app.local/api/v1/in-scope");
	`

	opts := crawler.DefaultBundleAnalysisOptions()
	opts.TargetHost = "app.local"
	extractor := crawler.NewBundleExtractor(opts)

	candidates, _, _, _ := extractor.ExtractFromBundle([]byte(js), "https://app.local/app.js")

	for _, c := range candidates {
		if strings.Contains(c.Path, "external-auth.com") {
			t.Errorf("Out-of-scope host added as in-scope candidate: %s", c.Path)
		}
		if c.Path == "/oauth/v2/token" {
			t.Errorf("CRITICAL: Out-of-scope absolute URL converted into in-scope relative path: %s", c.Path)
		}
	}

	foundInScope := false
	for _, c := range candidates {
		if c.Path == "/api/v1/in-scope" {
			foundInScope = true
		}
	}
	if !foundInScope {
		t.Errorf("Expected in-scope candidate /api/v1/in-scope, got: %+v", candidates)
	}
}

// 13. Secret-bearing query parameters
func TestP14_1_SecretQueryRedaction(t *testing.T) {
	js := `
		fetch("/api/v1/data?token=supersecret123&api_key=XYZ987&filter=active");
	`

	opts := crawler.DefaultBundleAnalysisOptions()
	extractor := crawler.NewBundleExtractor(opts)

	candidates, _, _, _ := extractor.ExtractFromBundle([]byte(js), "https://app.local/app.js")

	found := false
	for _, c := range candidates {
		if strings.HasPrefix(c.Path, "/api/v1/data") {
			found = true
			if strings.Contains(c.Path, "supersecret123") {
				t.Errorf("Token secret was not redacted: %s", c.Path)
			}
			if strings.Contains(c.Path, "XYZ987") {
				t.Errorf("API key was not redacted: %s", c.Path)
			}
			if !strings.Contains(c.Path, "token=[REDACTED]") {
				t.Errorf("Expected token=[REDACTED], got: %s", c.Path)
			}
			if !strings.Contains(c.Path, "api_key=[REDACTED]") {
				t.Errorf("Expected api_key=[REDACTED], got: %s", c.Path)
			}
			if !strings.Contains(c.Path, "filter=active") {
				t.Errorf("Non-sensitive query parameter lost: %s", c.Path)
			}
		}
	}
	if !found {
		t.Errorf("Expected candidate /api/v1/data, got: %+v", candidates)
	}
}

// 14. Cyclic chunk relationships and duplicate chunk references
func TestP14_1_CyclicChunkTraversal(t *testing.T) {
	var ts *httptest.Server
	ts = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			fmt.Fprintf(w, `<html><script src="/chunkA.js"></script></html>`)
		case "/chunkA.js":
			w.Header().Set("Content-Type", "application/javascript")
			// Chunk A references Chunk B and Chunk A
			fmt.Fprintf(w, `
				var chunks = { 1: "chunkB", 2: "chunkA" };
				fetch("/api/v1/chunkA");
			`)
		case "/1.chunkB.js":
			w.Header().Set("Content-Type", "application/javascript")
			// Chunk B references Chunk A
			fmt.Fprintf(w, `
				var chunks = { 1: "chunkA" };
				fetch("/api/v1/chunkB");
			`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer ts.Close()

	cfg := crawler.DefaultConfig()
	cfg.AllowLoopback = true
	cfg.BundleAnalysis.TraverseChunks = true
	cfg.BundleAnalysis.MaxChunks = 10
	c := crawler.New(cfg)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	res := c.Crawl(ctx, ts.URL)
	if res.Err != nil {
		t.Fatalf("Crawl failed: %v", res.Err)
	}

	if res.BundleAnalysis.TotalChunksTraversed > 10 {
		t.Errorf("Traversed chunks exceeded max chunks limit: %d", res.BundleAnalysis.TotalChunksTraversed)
	}

	foundA, foundB := false, false
	for _, cand := range res.RouteCandidates {
		if cand.Path == "/api/v1/chunkA" {
			foundA = true
		}
		if cand.Path == "/api/v1/chunkB" {
			foundB = true
		}
	}

	if !foundA || !foundB {
		t.Errorf("Expected both chunk endpoints, got: %+v", res.RouteCandidates)
	}
}

// 15. Source maps (inline data URI and downloaded .map)
func TestP14_1_SourceMapExtraction(t *testing.T) {
	// Source map with API routes in sources and sourcesContent
	sourceMapJSON := `{
		"version": 3,
		"file": "bundle.js",
		"sources": [
			"webpack:///src/pages/api/v1/login.ts",
			"webpack:///src/pages/api/v1/users/[id].ts"
		],
		"sourcesContent": [
			"export default function handler(req, res) { fetch('/api/v1/internal-status'); }",
			"export default function userHandler(req, res) {}"
		]
	}`

	b64Map := base64.StdEncoding.EncodeToString([]byte(sourceMapJSON))
	jsWithInlineMap := fmt.Sprintf("//# sourceMappingURL=data:application/json;charset=utf-8;base64,%s\nvar x = 1;", b64Map)

	opts := crawler.DefaultBundleAnalysisOptions()
	opts.IncludeSourceMaps = true
	extractor := crawler.NewBundleExtractor(opts)

	candidates, _, _, _ := extractor.ExtractFromBundle([]byte(jsWithInlineMap), "https://app.local/bundle.js")

	foundLogin := false
	foundUsers := false
	foundInternal := false

	for _, c := range candidates {
		if c.Path == "/api/v1/login" {
			foundLogin = true
			if c.SourceType != crawler.SourceTypeSourceMap {
				t.Errorf("Expected SOURCE_MAP source type, got %s", c.SourceType)
			}
		}
		if c.Path == "/api/v1/users/{param}" {
			foundUsers = true
		}
		if c.Path == "/api/v1/internal-status" {
			foundInternal = true
		}
	}

	if !foundLogin {
		t.Errorf("Expected /api/v1/login from source map sources, got: %+v", candidates)
	}
	if !foundUsers {
		t.Errorf("Expected /api/v1/users/{param} from source map sources, got: %+v", candidates)
	}
	if !foundInternal {
		t.Errorf("Expected /api/v1/internal-status from source map sourcesContent, got: %+v", candidates)
	}
}
