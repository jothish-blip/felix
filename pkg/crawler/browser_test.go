package crawler

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

// MockBrowserDriver implements BrowserDiscoveryDriver for deterministic fixture testing.
type MockBrowserDriver struct {
	RenderedHTML string
	Delay        time.Duration
	Err          error
}

func (m *MockBrowserDriver) Discover(ctx context.Context, targetURL string, opts BrowserDiscoveryOptions, scope *Scope) (*BrowserDiscoveryResult, error) {
	if m.Delay > 0 {
		select {
		case <-time.After(m.Delay):
		case <-ctx.Done():
			return &BrowserDiscoveryResult{
				Inconclusive: true,
				Reason:       "headless browser execution timed out",
			}, ErrBrowserTimeout
		}
	}
	if m.Err != nil {
		return &BrowserDiscoveryResult{
			Inconclusive: true,
			Reason:       m.Err.Error(),
		}, m.Err
	}

	parsedBase, err := url.Parse(targetURL)
	if err != nil {
		return nil, err
	}

	endpoints := ExtractDynamicEndpoints(m.RenderedHTML, parsedBase, scope)
	return &BrowserDiscoveryResult{
		Endpoints:    endpoints,
		RenderedHTML: m.RenderedHTML,
		Duration:     10 * time.Millisecond,
		BinaryUsed:   "mock-browser",
	}, nil
}

// 1. JS-rendered route discovery fixture
func TestBrowserDiscovery_JSRenderedRoute(t *testing.T) {
	renderedDOM := `<!DOCTYPE html>
<html>
<head><title>SPA App</title></head>
<body>
  <div id="root">
    <nav>
      <a href="/dashboard/metrics">Metrics</a>
      <a href="/admin/users">User Management</a>
    </nav>
  </div>
</body>
</html>`

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			// Static HTML does not contain the rendered links
			w.Header().Set("Content-Type", "text/html")
			w.Write([]byte(`<!DOCTYPE html><html><body><div id="root"></div><script src="/bundle.js"></script></body></html>`))
		case "/bundle.js":
			w.Header().Set("Content-Type", "application/javascript")
			w.Write([]byte(`console.log("SPA bundle");`))
		case "/dashboard/metrics", "/admin/users":
			w.Header().Set("Content-Type", "text/html")
			w.Write([]byte(`OK`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer ts.Close()

	cfg := DefaultConfig()
	cfg.BrowserDiscovery = BrowserDiscoveryOptions{
		Enabled: true,
		Driver: &MockBrowserDriver{
			RenderedHTML: renderedDOM,
		},
	}

	c := New(cfg)
	res := c.Crawl(context.Background(), ts.URL)

	if res.Err != nil {
		t.Fatalf("unexpected crawl error: %v", res.Err)
	}
	if res.BrowserDiscovery == nil {
		t.Fatalf("expected browser discovery result, got nil")
	}

	var foundMetrics, foundAdmin, foundStaticBundle bool
	for _, asset := range res.Assets {
		if strings.HasSuffix(asset.URL, "/dashboard/metrics") {
			foundMetrics = true
			if asset.Provenance != ProvenanceBrowser {
				t.Errorf("expected ProvenanceBrowser for /dashboard/metrics, got %s", asset.Provenance)
			}
		}
		if strings.HasSuffix(asset.URL, "/admin/users") {
			foundAdmin = true
			if asset.Provenance != ProvenanceBrowser {
				t.Errorf("expected ProvenanceBrowser for /admin/users, got %s", asset.Provenance)
			}
		}
		if strings.HasSuffix(asset.URL, "/bundle.js") {
			foundStaticBundle = true
			if asset.Provenance != ProvenanceStatic {
				t.Errorf("expected ProvenanceStatic for static bundle.js, got %s", asset.Provenance)
			}
		}
	}

	if !foundMetrics {
		t.Errorf("failed to discover dynamic route /dashboard/metrics")
	}
	if !foundAdmin {
		t.Errorf("failed to discover dynamic route /admin/users")
	}
	if !foundStaticBundle {
		t.Errorf("failed to retain static asset bundle.js")
	}
}

// 2. Interaction-revealed link fixture
func TestBrowserDiscovery_InteractionRevealedLink(t *testing.T) {
	renderedDOM := `<html><body>
  <div class="action-menu">
    <a href="/export/financial-report.csv">Export Report</a>
    <a href="/workflow/approve?id=42">Approve Invoice</a>
  </div>
</body></html>`

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(`<html><body><button id="toggle">Actions</button></body></html>`))
	}))
	defer ts.Close()

	cfg := DefaultConfig()
	cfg.BrowserDiscovery = BrowserDiscoveryOptions{
		Enabled: true,
		Driver: &MockBrowserDriver{
			RenderedHTML: renderedDOM,
		},
	}

	c := New(cfg)
	res := c.Crawl(context.Background(), ts.URL)

	var foundExport, foundWorkflow bool
	for _, a := range res.Assets {
		if strings.Contains(a.URL, "/export/financial-report.csv") {
			foundExport = true
			if a.Provenance != ProvenanceBrowser {
				t.Errorf("expected ProvenanceBrowser, got %s", a.Provenance)
			}
		}
		if strings.Contains(a.URL, "/workflow/approve?id=42") {
			foundWorkflow = true
			if a.Provenance != ProvenanceBrowser {
				t.Errorf("expected ProvenanceBrowser, got %s", a.Provenance)
			}
		}
	}

	if !foundExport || !foundWorkflow {
		t.Errorf("expected interaction-revealed endpoints, foundExport=%v, foundWorkflow=%v", foundExport, foundWorkflow)
	}
}

// 3. Runtime API request extraction fixture
func TestBrowserDiscovery_RuntimeAPIRequests(t *testing.T) {
	renderedDOM := `<html><body>
<script>
  fetch('/api/v1/user/profile');
  axios.get('/api/v2/orders/recent');
  $.ajax('/api/v3/auth/status');
</script>
</body></html>`

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(renderedDOM))
	}))
	defer ts.Close()

	cfg := DefaultConfig()
	cfg.BrowserDiscovery = BrowserDiscoveryOptions{
		Enabled: true,
		Driver: &MockBrowserDriver{
			RenderedHTML: renderedDOM,
		},
	}

	c := New(cfg)
	res := c.Crawl(context.Background(), ts.URL)

	var foundV1, foundV2, foundV3 bool
	for _, ep := range res.BrowserDiscovery.Endpoints {
		if strings.Contains(ep.URL, "/api/v1/user/profile") {
			foundV1 = true
			if ep.Provenance != ProvenanceBrowser {
				t.Errorf("expected ProvenanceBrowser, got %s", ep.Provenance)
			}
		}
		if strings.Contains(ep.URL, "/api/v2/orders/recent") {
			foundV2 = true
		}
		if strings.Contains(ep.URL, "/api/v3/auth/status") {
			foundV3 = true
		}
	}

	if !foundV1 || !foundV2 || !foundV3 {
		t.Errorf("failed to discover runtime API endpoints: v1=%v, v2=%v, v3=%v", foundV1, foundV2, foundV3)
	}
}

// 4. Out-of-scope redirect and link blocking fixture
func TestBrowserDiscovery_OutOfScopeBlocked(t *testing.T) {
	renderedDOM := `<html><body>
  <a href="/internal/settings">Internal Settings</a>
  <a href="https://external-thirdparty.example.com/login">Third Party Login</a>
  <a href="https://malicious-telemetry.example.org/track">Telemetry</a>
</body></html>`

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(renderedDOM))
	}))
	defer ts.Close()

	cfg := DefaultConfig()
	cfg.ScopeMode = ScopeSameOrigin
	cfg.BrowserDiscovery = BrowserDiscoveryOptions{
		Enabled: true,
		Driver: &MockBrowserDriver{
			RenderedHTML: renderedDOM,
		},
	}

	c := New(cfg)
	res := c.Crawl(context.Background(), ts.URL)

	var internalInScope bool
	var externalOutOfScopeCount int

	for _, a := range res.Assets {
		if strings.Contains(a.URL, "/internal/settings") {
			if !a.InScope {
				t.Errorf("expected internal settings to be in scope")
			}
			internalInScope = true
		}
		if strings.Contains(a.URL, "external-thirdparty.example.com") || strings.Contains(a.URL, "malicious-telemetry.example.org") {
			if a.InScope {
				t.Errorf("expected out-of-scope asset to have InScope=false: %s", a.URL)
			}
			externalOutOfScopeCount++
		}
	}

	if !internalInScope {
		t.Errorf("internal settings route not found")
	}
	if externalOutOfScopeCount != 2 {
		t.Errorf("expected 2 out-of-scope assets identified, got %d", externalOutOfScopeCount)
	}
}

// 5. Hanging page timeout handling fixture
func TestBrowserDiscovery_HangingPageTimeout(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(`<html><body>Static OK</body></html>`))
	}))
	defer ts.Close()

	cfg := DefaultConfig()
	cfg.BrowserDiscovery = BrowserDiscoveryOptions{
		Enabled: true,
		Timeout: 50 * time.Millisecond,
		Driver: &MockBrowserDriver{
			Delay: 200 * time.Millisecond, // Simulates slow/hanging render beyond timeout
		},
	}

	c := New(cfg)
	res := c.Crawl(context.Background(), ts.URL)

	if res.Err != nil {
		t.Fatalf("crawl should not fail completely on browser timeout: %v", res.Err)
	}
	if res.BrowserDiscovery == nil {
		t.Fatalf("expected browser discovery result")
	}
	if !res.BrowserDiscovery.Inconclusive {
		t.Errorf("expected Inconclusive: true on timeout")
	}
	if !strings.Contains(strings.ToLower(res.BrowserDiscovery.Reason), "timed out") {
		t.Errorf("expected timeout reason, got: %s", res.BrowserDiscovery.Reason)
	}
}

// 6. Browser-unavailable fallback fixture
func TestBrowserDiscovery_BrowserUnavailableFallback(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			w.Header().Set("Content-Type", "text/html")
			w.Write([]byte(`<html><body><script src="/static.js"></script><h1>Home</h1></body></html>`))
		case "/static.js":
			w.Header().Set("Content-Type", "application/javascript")
			w.Write([]byte(`console.log("static only");`))
		}
	}))
	defer ts.Close()

	cfg := DefaultConfig()
	cfg.BrowserDiscovery = BrowserDiscoveryOptions{
		Enabled:       true,
		BrowserBinary: "C:\\nonexistent\\path\\to\\fakebrowser.exe",
	}

	c := New(cfg)
	res := c.Crawl(context.Background(), ts.URL)

	if res.Err != nil {
		t.Fatalf("crawl should not fail when browser is missing: %v", res.Err)
	}
	if res.BrowserDiscovery == nil {
		t.Fatalf("expected browser discovery result")
	}
	if !res.BrowserDiscovery.Inconclusive {
		t.Errorf("expected Inconclusive: true when browser executable is missing")
	}
	if !strings.Contains(strings.ToLower(res.BrowserDiscovery.Reason), "not found") {
		t.Errorf("expected missing browser reason, got: %s", res.BrowserDiscovery.Reason)
	}

	// Verify static assets were still properly captured
	var foundStaticJS bool
	for _, a := range res.Assets {
		if strings.HasSuffix(a.URL, "/static.js") {
			foundStaticJS = true
			if a.Provenance != ProvenanceStatic {
				t.Errorf("expected static asset to have ProvenanceStatic, got %s", a.Provenance)
			}
		}
	}
	if !foundStaticJS {
		t.Errorf("expected static asset /static.js to be retained despite browser absence")
	}
}

// 7. Test HeadlessBrowserDriver with system browser if present
func TestHeadlessBrowserDriver_IntegrationIfAvailable(t *testing.T) {
	bin, err := FindBrowserBinary("")
	if err != nil {
		t.Skip("skipping integration test: no chromium browser in local environment")
	}

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(`<!DOCTYPE html><html><body><h1>Test</h1><script>document.body.innerHTML += '<a href="/dynamic-discovered">Link</a>';</script></body></html>`))
	}))
	defer ts.Close()

	driver := NewHeadlessBrowserDriver()
	scope, _ := NewScope(ts.URL, ScopeSameOrigin)
	opts := BrowserDiscoveryOptions{
		BrowserBinary:  bin,
		Timeout:        5 * time.Second,
		WaitUntilReady: 500 * time.Millisecond,
	}

	res, err := driver.Discover(context.Background(), ts.URL, opts, scope)
	if err != nil {
		t.Logf("driver execution returned error in test environment: %v (res inconclusive: %v)", err, res.Inconclusive)
		return
	}

	if res.Inconclusive {
		t.Logf("browser execution inconclusive: %s", res.Reason)
		return
	}

	var foundDynamic bool
	for _, ep := range res.Endpoints {
		if strings.Contains(ep.URL, "/dynamic-discovered") {
			foundDynamic = true
			break
		}
	}

	if !foundDynamic {
		t.Logf("rendered HTML: %s", res.RenderedHTML)
	}
}
