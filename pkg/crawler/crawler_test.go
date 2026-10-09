package crawler

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestExtractScripts(t *testing.T) {
	mockHTML := `<!DOCTYPE html>
<html>
<head>
    <title>Felix Audit Target</title>
    <script src="/_next/static/chunks/main-app.js"></script>
    <script src="https://cdn.example.com/analytics.js"></script>
    <script src="//static.example.com/tracker.js"></script>
    <script src="relative/path/bundle.js"></script>
    <script>console.log("inline script - no src");</script>
    <!-- duplicate check -->
    <script src="/_next/static/chunks/main-app.js"></script>
</head>
<body>
    <h1>Application Content</h1>
    <script src="/_next/static/chunks/pages/index.js"></script>
</body>
</html>`

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprint(w, mockHTML)
	}))
	defer server.Close()

	c := New(DefaultConfig())
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	scripts, err := c.ExtractScripts(ctx, server.URL)
	if err != nil {
		t.Fatalf("ExtractScripts failed: %v", err)
	}

	expectedCount := 5 // main-app.js, analytics.js, tracker.js, bundle.js, index.js
	if len(scripts) != expectedCount {
		t.Fatalf("expected %d scripts, got %d: %+v", expectedCount, len(scripts), scripts)
	}

	// Verify resolution
	expectedPrefix := server.URL + "/_next/static/chunks/main-app.js"
	if scripts[0] != expectedPrefix {
		t.Errorf("expected script[0] == %s, got %s", expectedPrefix, scripts[0])
	}
}

func TestCrawlConcurrently(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprintf(w, `<html><script src="/asset-%s.js"></script></html>`, r.URL.Path[1:])
	}))
	defer server.Close()

	c := New(Config{
		Concurrency: 3,
		Timeout:     5 * time.Second,
	})

	targets := []string{
		server.URL + "/alpha",
		server.URL + "/beta",
		server.URL + "/gamma",
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	resultsChan := c.CrawlConcurrently(ctx, targets)

	collected := make(map[string][]string)
	for res := range resultsChan {
		if res.Err != nil {
			t.Errorf("target %s returned error: %v", res.Target, res.Err)
		}
		collected[res.Target] = res.Scripts
	}

	if len(collected) != 3 {
		t.Errorf("expected 3 results, got %d", len(collected))
	}
}

// Test 1: Relative JavaScript URL
func TestRelativeJavaScriptURL(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprint(w, `<html><script src="/assets/app.js"></script></html>`)
			return
		}
		if r.URL.Path == "/assets/app.js" {
			w.Header().Set("Content-Type", "application/javascript")
			fmt.Fprint(w, `console.log("relative");`)
			return
		}
		http.NotFound(w, r)
	}))
	defer server.Close()

	c := New(DefaultConfig())
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	res := c.Crawl(ctx, server.URL)
	if res.Err != nil {
		t.Fatalf("Crawl failed: %v", res.Err)
	}

	expectedURL := server.URL + "/assets/app.js"
	var found bool
	for _, a := range res.Assets {
		if a.URL == expectedURL && a.Type == AssetJavaScript {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected relative URL %s in assets, got: %+v", expectedURL, res.Assets)
	}
}

// Test 2: Absolute JavaScript URL
func TestAbsoluteJavaScriptURL(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<html><script src="https://example.com/assets/vendor.js"></script></html>`)
	}))
	defer server.Close()

	c := New(DefaultConfig())
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	res := c.Crawl(ctx, server.URL)
	if res.Err != nil {
		t.Fatalf("Crawl failed: %v", res.Err)
	}

	expectedURL := "https://example.com/assets/vendor.js"
	var found bool
	for _, a := range res.Assets {
		if a.URL == expectedURL && a.Type == AssetJavaScript {
			found = true
			if a.InScope {
				t.Errorf("expected cross-origin absolute URL to be marked out-of-scope")
			}
			break
		}
	}
	if !found {
		t.Errorf("expected absolute URL %s in assets, got: %+v", expectedURL, res.Assets)
	}
}

// Test 3: Protocol-relative URL
func TestProtocolRelativeURL(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<html><script src="//example.com/assets/tracker.js"></script></html>`)
	}))
	defer server.Close()

	c := New(DefaultConfig())
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	res := c.Crawl(ctx, server.URL)
	if res.Err != nil {
		t.Fatalf("Crawl failed: %v", res.Err)
	}

	// Server URL is http://..., so protocol-relative should resolve to http://example.com/...
	expectedURL := "http://example.com/assets/tracker.js"
	var found bool
	for _, a := range res.Assets {
		if a.URL == expectedURL {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected protocol-relative URL resolved to %s, got: %+v", expectedURL, res.Assets)
	}
}

// Test 4: Duplicate scripts
func TestDuplicateScripts(t *testing.T) {
	requestCount := int32(0)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprint(w, `<html>
				<script src="/dup.js"></script>
				<script src="/dup.js"></script>
				<script src="/dup.js"></script>
			</html>`)
			return
		}
		if r.URL.Path == "/dup.js" {
			atomic.AddInt32(&requestCount, 1)
			w.Header().Set("Content-Type", "application/javascript")
			fmt.Fprint(w, `console.log("dup");`)
			return
		}
		http.NotFound(w, r)
	}))
	defer server.Close()

	c := New(DefaultConfig())
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	res := c.Crawl(ctx, server.URL)
	if res.Err != nil {
		t.Fatalf("Crawl failed: %v", res.Err)
	}

	if len(res.Assets) != 1 {
		t.Errorf("expected exactly 1 deduplicated asset, got %d", len(res.Assets))
	}
	if count := atomic.LoadInt32(&requestCount); count != 1 {
		t.Errorf("expected exactly 1 HTTP request for deduplicated script, got %d", count)
	}
}

// Test 5: Inline script without src
func TestInlineScriptWithoutSrc(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<html>
			<head>
				<script>console.log("inline1");</script>
				<script type="application/javascript">var inline2 = true;</script>
			</head>
			<body>
				<script>alert("inline3");</script>
			</body>
		</html>`)
	}))
	defer server.Close()

	c := New(DefaultConfig())
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	res := c.Crawl(ctx, server.URL)
	if res.Err != nil {
		t.Fatalf("Crawl failed: %v", res.Err)
	}

	if len(res.Assets) != 0 {
		t.Errorf("expected 0 assets from inline scripts, got %d: %+v", len(res.Assets), res.Assets)
	}
}

// Test 6: JavaScript downloading
func TestJavaScriptDownloading(t *testing.T) {
	expectedBody := `console.log("Felix auditing bundle");`
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprint(w, `<html><script src="/bundle.js"></script></html>`)
			return
		}
		if r.URL.Path == "/bundle.js" {
			w.Header().Set("Content-Type", "application/javascript")
			fmt.Fprint(w, expectedBody)
			return
		}
		http.NotFound(w, r)
	}))
	defer server.Close()

	c := New(DefaultConfig())
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	res := c.Crawl(ctx, server.URL)
	if res.Err != nil {
		t.Fatalf("Crawl failed: %v", res.Err)
	}

	if len(res.Assets) != 1 {
		t.Fatalf("expected 1 asset, got %d", len(res.Assets))
	}

	asset := res.Assets[0]
	if string(asset.Content) != expectedBody {
		t.Errorf("expected content %q, got %q", expectedBody, string(asset.Content))
	}
	if asset.StatusCode != http.StatusOK {
		t.Errorf("expected status 200, got %d", asset.StatusCode)
	}
	if !asset.InScope {
		t.Errorf("expected asset to be in scope")
	}
	if asset.Error != nil {
		t.Errorf("expected nil error, got %v", asset.Error)
	}
}

// Test 7: JavaScript asset metadata
func TestJavaScriptAssetMetadata(t *testing.T) {
	jsPayload := `function computeHash(){ return 42; }`
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprint(w, `<html><script src="/static/app.js"></script></html>`)
			return
		}
		if r.URL.Path == "/static/app.js" {
			w.Header().Set("Content-Type", "application/javascript; charset=utf-8")
			fmt.Fprint(w, jsPayload)
			return
		}
		http.NotFound(w, r)
	}))
	defer server.Close()

	c := New(DefaultConfig())
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	res := c.Crawl(ctx, server.URL)
	if res.Err != nil {
		t.Fatalf("Crawl failed: %v", res.Err)
	}

	if len(res.Assets) != 1 {
		t.Fatalf("expected 1 asset, got %d", len(res.Assets))
	}

	asset := res.Assets[0]
	if asset.Type != AssetJavaScript {
		t.Errorf("expected AssetJavaScript, got %s", asset.Type)
	}
	if asset.Size != int64(len(jsPayload)) {
		t.Errorf("expected size %d, got %d", len(jsPayload), asset.Size)
	}
	if !strings.Contains(asset.ContentType, "application/javascript") {
		t.Errorf("expected ContentType application/javascript, got %s", asset.ContentType)
	}
	if asset.StatusCode != 200 {
		t.Errorf("expected status 200, got %d", asset.StatusCode)
	}
}

// Test 8: Source-map discovery
func TestSourceMapDiscovery(t *testing.T) {
	jsContent := "var a = 10;\n//# sourceMappingURL=app.js.map\n"
	mapContent := `{"version":3,"file":"app.js","sources":["app.ts"],"mappings":"AAAA"}`

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprint(w, `<html><script src="/assets/app.js"></script></html>`)
		case "/assets/app.js":
			w.Header().Set("Content-Type", "application/javascript")
			fmt.Fprint(w, jsContent)
		case "/assets/app.js.map":
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, mapContent)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	c := New(DefaultConfig())
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	res := c.Crawl(ctx, server.URL)
	if res.Err != nil {
		t.Fatalf("Crawl failed: %v", res.Err)
	}

	var foundMap *Asset
	for _, a := range res.Assets {
		if a.Type == AssetSourceMap || a.IsSourceMap {
			foundMap = &a
			break
		}
	}

	if foundMap == nil {
		t.Fatalf("expected source map asset in results, got: %+v", res.Assets)
	}

	expectedMapURL := server.URL + "/assets/app.js.map"
	if foundMap.URL != expectedMapURL {
		t.Errorf("expected map URL %s, got %s", expectedMapURL, foundMap.URL)
	}
	if string(foundMap.Content) != mapContent {
		t.Errorf("expected map content %q, got %q", mapContent, string(foundMap.Content))
	}
	if !foundMap.IsSourceMap {
		t.Errorf("expected IsSourceMap to be true")
	}
}

// Test 9: Cross-origin asset scope enforcement
func TestCrossOriginScopeEnforcement(t *testing.T) {
	crossOriginRequests := int32(0)

	// Cross-origin server (CDN)
	cdnServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&crossOriginRequests, 1)
		w.Header().Set("Content-Type", "application/javascript")
		fmt.Fprint(w, `console.log("unauthorized cdn fetch");`)
	}))
	defer cdnServer.Close()

	// Target server
	targetServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprintf(w, `<html>
				<script src="/local.js"></script>
				<script src="%s/external.js"></script>
			</html>`, cdnServer.URL)
			return
		}
		if r.URL.Path == "/local.js" {
			w.Header().Set("Content-Type", "application/javascript")
			fmt.Fprint(w, `console.log("local script");`)
			return
		}
		http.NotFound(w, r)
	}))
	defer targetServer.Close()

	c := New(DefaultConfig()) // Default is ScopeSameOrigin
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	res := c.Crawl(ctx, targetServer.URL)
	if res.Err != nil {
		t.Fatalf("Crawl failed: %v", res.Err)
	}

	// Verify no HTTP requests hit the cross-origin CDN server
	if count := atomic.LoadInt32(&crossOriginRequests); count != 0 {
		t.Errorf("expected 0 requests to cross-origin server, got %d", count)
	}

	// Verify assets inventory records the external script as discovered but out-of-scope
	var foundExternal bool
	for _, a := range res.Assets {
		if strings.Contains(a.URL, "external.js") {
			foundExternal = true
			if a.InScope {
				t.Errorf("expected external asset InScope to be false")
			}
			if len(a.Content) != 0 {
				t.Errorf("expected external asset Content to be empty")
			}
		}
	}
	if !foundExternal {
		t.Errorf("expected external script to be recorded in discovered assets")
	}
}

// Test 10: Oversized asset rejection
func TestOversizedAssetRejection(t *testing.T) {
	oversizedData := strings.Repeat("A", 1024) // 1024 bytes

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprint(w, `<html><script src="/huge.js"></script></html>`)
			return
		}
		if r.URL.Path == "/huge.js" {
			w.Header().Set("Content-Type", "application/javascript")
			fmt.Fprint(w, oversizedData)
			return
		}
		http.NotFound(w, r)
	}))
	defer server.Close()

	cfg := DefaultConfig()
	cfg.MaxAssetSize = 256 // Limit to 256 bytes

	c := New(cfg)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	res := c.Crawl(ctx, server.URL)
	if res.Err != nil {
		t.Fatalf("Crawl target should succeed even if individual asset exceeds size: %v", res.Err)
	}

	if len(res.Assets) != 1 {
		t.Fatalf("expected 1 asset, got %d", len(res.Assets))
	}

	asset := res.Assets[0]
	if !errors.Is(asset.Error, ErrAssetTooLarge) {
		t.Errorf("expected ErrAssetTooLarge, got %v", asset.Error)
	}
	if len(asset.Content) != 0 {
		t.Errorf("expected empty content for oversized asset, got %d bytes", len(asset.Content))
	}
}

// Test 11: HTTP error handling
func TestHTTPErrorHandling(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprint(w, `<html>
				<script src="/ok.js"></script>
				<script src="/missing.js"></script>
				<script src="/error.js"></script>
			</html>`)
		case "/ok.js":
			w.Header().Set("Content-Type", "application/javascript")
			fmt.Fprint(w, `console.log("ok");`)
		case "/missing.js":
			http.NotFound(w, r)
		case "/error.js":
			http.Error(w, "internal server error", http.StatusInternalServerError)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	c := New(DefaultConfig())
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	res := c.Crawl(ctx, server.URL)
	// One failed asset must not fail the entire scan
	if res.Err != nil {
		t.Fatalf("Crawl returned unexpected error: %v", res.Err)
	}

	if len(res.Assets) != 3 {
		t.Fatalf("expected 3 assets, got %d", len(res.Assets))
	}

	for _, a := range res.Assets {
		switch {
		case strings.HasSuffix(a.URL, "/ok.js"):
			if a.StatusCode != 200 || a.Error != nil {
				t.Errorf("expected ok.js status 200, got %d (err: %v)", a.StatusCode, a.Error)
			}
		case strings.HasSuffix(a.URL, "/missing.js"):
			if a.StatusCode != 404 || a.Error == nil {
				t.Errorf("expected missing.js status 404 with error, got %d (err: %v)", a.StatusCode, a.Error)
			}
		case strings.HasSuffix(a.URL, "/error.js"):
			if a.StatusCode != 500 || a.Error == nil {
				t.Errorf("expected error.js status 500 with error, got %d (err: %v)", a.StatusCode, a.Error)
			}
		}
	}
}

// Test 12: Concurrent downloading
func TestConcurrentDownloading(t *testing.T) {
	var inFlight atomic.Int32
	var maxInFlight atomic.Int32

	assetCount := 10
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			w.Header().Set("Content-Type", "text/html")
			var b strings.Builder
			b.WriteString("<html><head>")
			for i := 0; i < assetCount; i++ {
				fmt.Fprintf(&b, `<script src="/chunk-%d.js"></script>`, i)
			}
			b.WriteString("</head></html>")
			w.Write([]byte(b.String()))
			return
		}

		// Track concurrent worker execution
		cur := inFlight.Add(1)
		defer inFlight.Add(-1)

		for {
			m := maxInFlight.Load()
			if cur <= m || maxInFlight.CompareAndSwap(m, cur) {
				break
			}
		}

		time.Sleep(30 * time.Millisecond)

		w.Header().Set("Content-Type", "application/javascript")
		w.Write([]byte(`console.log("chunk");`))
	}))
	defer server.Close()

	concurrencyLimit := 3
	c := New(Config{
		Concurrency: concurrencyLimit,
		Timeout:     5 * time.Second,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	res := c.Crawl(ctx, server.URL)
	if res.Err != nil {
		t.Fatalf("Crawl failed: %v", res.Err)
	}

	if len(res.Assets) != assetCount {
		t.Fatalf("expected %d assets, got %d", assetCount, len(res.Assets))
	}

	peak := maxInFlight.Load()
	if peak > int32(concurrencyLimit) {
		t.Errorf("concurrency exceeded limit: max observed %d > limit %d", peak, concurrencyLimit)
	}
	if peak < 2 {
		t.Errorf("expected concurrent execution (peak >= 2), observed peak was %d", peak)
	}
}

// Test Classification & Stylesheets / Manifests
func TestAssetClassificationAndStylesheets(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprint(w, `<html>
				<link rel="stylesheet" href="/style.css">
				<link rel="manifest" href="/manifest.json">
				<script src="/app.mjs"></script>
			</html>`)
		case "/style.css":
			w.Header().Set("Content-Type", "text/css")
			fmt.Fprint(w, "body { color: red; }")
		case "/manifest.json":
			w.Header().Set("Content-Type", "application/manifest+json")
			fmt.Fprint(w, `{"name": "FelixApp"}`)
		case "/app.mjs":
			w.Header().Set("Content-Type", "application/javascript")
			fmt.Fprint(w, "export const x = 1;")
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	c := New(DefaultConfig())
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	res := c.Crawl(ctx, server.URL)
	if res.Err != nil {
		t.Fatalf("Crawl failed: %v", res.Err)
	}

	typesFound := make(map[AssetType]bool)
	for _, a := range res.Assets {
		typesFound[a.Type] = true
	}

	if !typesFound[AssetStylesheet] {
		t.Errorf("expected AssetStylesheet in discovered assets")
	}
	if !typesFound[AssetManifest] {
		t.Errorf("expected AssetManifest in discovered assets")
	}
	if !typesFound[AssetJavaScript] {
		t.Errorf("expected AssetJavaScript in discovered assets")
	}
}

// Test Source Map extraction variations
func TestSourceMapExtractionVariations(t *testing.T) {
	cases := []struct {
		content  string
		expected string
	}{
		{"var a = 1;\n//# sourceMappingURL=app.js.map", "app.js.map"},
		{"var a = 1;\n//@ sourceMappingURL=app.js.map", "app.js.map"},
		{"var a = 1;\n/*# sourceMappingURL=app.js.map */", "app.js.map"},
		{"var a = 1;\n/*@ sourceMappingURL=app.js.map */", "app.js.map"},
		{"var a = 1;\n//# sourceMappingURL=http://cdn.com/app.js.map\r\n", "http://cdn.com/app.js.map"},
		{"var a = 1;\n//# sourceMappingURL=data:application/json;base64,eyJ2...", ""},
		{"var a = 1;", ""},
	}

	for _, tc := range cases {
		extracted := ExtractSourceMapURL([]byte(tc.content))
		if extracted != tc.expected {
			t.Errorf("ExtractSourceMapURL(%q) = %q, expected %q", tc.content, extracted, tc.expected)
		}
	}
}

// Test Scope Rules (same-origin, subdomains, explicit, ports, schemes)
func TestScopeRules(t *testing.T) {
	// Same-origin mode
	sOrigin, err := NewScope("https://example.com/app", ScopeSameOrigin)
	if err != nil {
		t.Fatalf("NewScope failed: %v", err)
	}
	if !sOrigin.IsAllowed("https://example.com/assets/app.js") {
		t.Errorf("same-origin: expected https://example.com/assets/app.js to be allowed")
	}
	if !sOrigin.IsAllowed("/assets/app.js") {
		t.Errorf("same-origin: expected relative path /assets/app.js to be allowed")
	}
	if sOrigin.IsAllowed("https://cdn.example.com/app.js") {
		t.Errorf("same-origin: cdn.example.com should NOT be allowed")
	}
	if sOrigin.IsAllowed("http://example.com/app.js") {
		t.Errorf("same-origin: http scheme on https target should NOT be allowed")
	}
	if sOrigin.IsAllowed("https://example.com:8443/app.js") {
		t.Errorf("same-origin: different port should NOT be allowed")
	}

	// Subdomains mode
	sSub, err := NewScope("https://example.com", ScopeSubdomains)
	if err != nil {
		t.Fatalf("NewScope failed: %v", err)
	}
	if !sSub.IsAllowed("https://example.com/app.js") {
		t.Errorf("subdomains: example.com should be allowed")
	}
	if !sSub.IsAllowed("https://cdn.example.com/app.js") {
		t.Errorf("subdomains: cdn.example.com should be allowed")
	}
	if !sSub.IsAllowed("https://sub.cdn.example.com/app.js") {
		t.Errorf("subdomains: sub.cdn.example.com should be allowed")
	}
	if sSub.IsAllowed("https://fakeexample.com/app.js") {
		t.Errorf("subdomains: fakeexample.com should NOT be allowed")
	}
	if sSub.IsAllowed("https://evil.com/app.js") {
		t.Errorf("subdomains: evil.com should NOT be allowed")
	}

	// Explicit mode
	sExp, err := NewScope("https://example.com", ScopeExplicit, "cdn.internal.org", "static.partner.com")
	if err != nil {
		t.Fatalf("NewScope failed: %v", err)
	}
	if !sExp.IsAllowed("https://example.com/app.js") {
		t.Errorf("explicit: example.com should be allowed")
	}
	if !sExp.IsAllowed("https://cdn.internal.org/lib.js") {
		t.Errorf("explicit: cdn.internal.org should be allowed")
	}
	if !sExp.IsAllowed("https://static.partner.com/style.css") {
		t.Errorf("explicit: static.partner.com should be allowed")
	}
	if sExp.IsAllowed("https://untrusted.com/evil.js") {
		t.Errorf("explicit: untrusted.com should NOT be allowed")
	}
}

func TestCrawler_ScopedRedirectEnforcement(t *testing.T) {
	thirdParty := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "third-party content")
	}))
	defer thirdParty.Close()

	primary := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/out-of-scope":
			http.Redirect(w, r, thirdParty.URL+"/secret", http.StatusFound)
		case "/excluded":
			http.Redirect(w, r, "/blocked-path", http.StatusFound)
		case "/blocked-path":
			w.WriteHeader(http.StatusOK)
		case "/allowed-redirect":
			http.Redirect(w, r, "/in-scope-dest", http.StatusFound)
		case "/in-scope-dest":
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprint(w, `<html><script src="/main.js"></script></html>`)
		default:
			w.WriteHeader(http.StatusOK)
		}
	}))
	defer primary.Close()

	cfg := DefaultConfig()
	cfg.ScopeMode = ScopeSameOrigin
	cfg.IsExcluded = func(u string) bool {
		return strings.Contains(u, "/blocked-path")
	}
	c := New(cfg)
	scope, err := NewScope(primary.URL, ScopeSameOrigin)
	if err != nil {
		t.Fatalf("failed to create scope: %v", err)
	}
	client := c.scopedClientForTarget(scope)

	// 1. In-scope redirect succeeds
	resp, err := client.Get(primary.URL + "/allowed-redirect")
	if err != nil {
		t.Fatalf("expected in-scope redirect to succeed, got: %v", err)
	}
	resp.Body.Close()

	// 2. Redirect to third-party server is blocked
	_, err = client.Get(primary.URL + "/out-of-scope")
	if err == nil {
		t.Errorf("expected out-of-scope redirect to third-party to be blocked")
	}

	// 3. Redirect to excluded path is blocked
	_, err = client.Get(primary.URL + "/excluded")
	if err == nil {
		t.Errorf("expected redirect to excluded path to be blocked")
	}
}

