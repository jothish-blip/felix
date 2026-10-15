package crawler

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// TestSafety_CrawlerMaxAssetsLimit verifies that MaxAssets strictly caps the number of discovered
// and downloaded assets during a crawl.
func TestSafety_CrawlerMaxAssetsLimit(t *testing.T) {
	// Generate HTML pointing to 25 scripts
	var scriptTags strings.Builder
	for i := 0; i < 25; i++ {
		scriptTags.WriteString(fmt.Sprintf(`<script src="/asset-%d.js"></script>`+"\n", i))
	}
	mockHTML := fmt.Sprintf(`<!DOCTYPE html><html><head>%s</head><body><h1>MaxAssets Test</h1></body></html>`, scriptTags.String())

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			w.Header().Set("Content-Type", "text/html")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(mockHTML))
			return
		}
		w.Header().Set("Content-Type", "application/javascript")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`console.log("asset");`))
	}))
	defer ts.Close()

	maxCap := 5
	cfg := DefaultConfig()
	cfg.AllowLoopback = true
	cfg.MaxAssets = maxCap

	c := New(cfg)
	ctx := context.Background()
	res := c.Crawl(ctx, ts.URL)

	if res.Err != nil {
		t.Fatalf("Crawl failed unexpectedly: %v", res.Err)
	}

	if len(res.Assets) > maxCap {
		t.Errorf("expected at most %d assets, got %d", maxCap, len(res.Assets))
	}
	if len(res.Scripts) > maxCap {
		t.Errorf("expected at most %d scripts, got %d", maxCap, len(res.Scripts))
	}
}

// TestSafety_CrawlerMaxAssetSizeLimit verifies that responses exceeding MaxAssetSize
// are truncated and flagged with ErrAssetTooLarge.
func TestSafety_CrawlerMaxAssetSizeLimit(t *testing.T) {
	oversizedBytes := make([]byte, 100*1024) // 100 KB
	for i := range oversizedBytes {
		oversizedBytes[i] = 'A'
	}

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			w.Header().Set("Content-Type", "text/html")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`<html><head><script src="/large.js"></script></head><body>Oversized Test</body></html>`))
			return
		}
		if r.URL.Path == "/large.js" {
			w.Header().Set("Content-Type", "application/javascript")
			w.WriteHeader(http.StatusOK)
			w.Write(oversizedBytes)
			return
		}
		http.NotFound(w, r)
	}))
	defer ts.Close()

	limitBytes := int64(10 * 1024) // 10 KB limit
	cfg := DefaultConfig()
	cfg.AllowLoopback = true
	cfg.MaxAssetSize = limitBytes

	c := New(cfg)
	ctx := context.Background()
	res := c.Crawl(ctx, ts.URL)

	if res.Err != nil {
		t.Fatalf("Crawl failed unexpectedly: %v", res.Err)
	}

	foundLarge := false
	for _, a := range res.Assets {
		if strings.Contains(a.URL, "large.js") {
			foundLarge = true
			if a.Error != ErrAssetTooLarge {
				t.Errorf("expected large.js asset to have ErrAssetTooLarge, got: %v", a.Error)
			}
		}
	}
	if !foundLarge {
		t.Errorf("expected large.js to be discovered and evaluated")
	}
}

// TestSafety_CrawlerConcurrencyLimit verifies that concurrent downloads respect the Concurrency setting.
func TestSafety_CrawlerConcurrencyLimit(t *testing.T) {
	var scriptTags strings.Builder
	for i := 0; i < 15; i++ {
		scriptTags.WriteString(fmt.Sprintf(`<script src="/chunk-%d.js"></script>`+"\n", i))
	}
	mockHTML := fmt.Sprintf(`<!DOCTYPE html><html><head>%s</head><body>Concurrency Test</body></html>`, scriptTags.String())

	var (
		currentInFlight int32
		maxObserved     int32
	)

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			w.Header().Set("Content-Type", "text/html")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(mockHTML))
			return
		}

		inFlight := atomic.AddInt32(&currentInFlight, 1)
		defer atomic.AddInt32(&currentInFlight, -1)

		for {
			oldMax := atomic.LoadInt32(&maxObserved)
			if inFlight <= oldMax {
				break
			}
			if atomic.CompareAndSwapInt32(&maxObserved, oldMax, inFlight) {
				break
			}
		}

		time.Sleep(25 * time.Millisecond)
		w.Header().Set("Content-Type", "application/javascript")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`console.log("chunk");`))
	}))
	defer ts.Close()

	concurrencyCap := 2
	cfg := DefaultConfig()
	cfg.AllowLoopback = true
	cfg.Concurrency = concurrencyCap

	c := New(cfg)
	ctx := context.Background()
	res := c.Crawl(ctx, ts.URL)

	if res.Err != nil {
		t.Fatalf("Crawl failed: %v", res.Err)
	}

	peak := atomic.LoadInt32(&maxObserved)
	if peak > int32(concurrencyCap) {
		t.Errorf("concurrency violation: observed peak %d in-flight requests, expected <= %d", peak, concurrencyCap)
	}
}

// TestSafety_CrawlerMaxRedirects verifies that recursive or infinite redirect loops
// halt at MaxRedirects.
func TestSafety_CrawlerMaxRedirects(t *testing.T) {
	redirectHops := 0
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		redirectHops++
		http.Redirect(w, r, fmt.Sprintf("/hop-%d", redirectHops), http.StatusFound)
	}))
	defer ts.Close()

	cfg := DefaultConfig()
	cfg.AllowLoopback = true
	cfg.MaxRedirects = 4

	c := New(cfg)
	ctx := context.Background()
	res := c.Crawl(ctx, ts.URL)

	if res.Err == nil {
		t.Fatalf("expected redirect loop error, got nil")
	}
	if !strings.Contains(res.Err.Error(), "stopped after 4 redirects") {
		t.Errorf("expected error mentioning stopped after 4 redirects, got: %v", res.Err)
	}
}

// TestSafety_CrawlerContextCancellation verifies that canceling context terminates
// CrawlConcurrently promptly without hangs.
func TestSafety_CrawlerContextCancellation(t *testing.T) {
	serverBlock := make(chan struct{})
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-serverBlock:
			w.WriteHeader(http.StatusOK)
		case <-r.Context().Done():
		}
	}))
	defer func() {
		close(serverBlock)
		ts.Close()
	}()

	cfg := DefaultConfig()
	cfg.AllowLoopback = true
	cfg.Concurrency = 2

	c := New(cfg)
	ctx, cancel := context.WithCancel(context.Background())

	targets := []string{
		ts.URL + "/t1",
		ts.URL + "/t2",
		ts.URL + "/t3",
		ts.URL + "/t4",
	}

	start := time.Now()
	resultsChan := c.CrawlConcurrently(ctx, targets)

	// Cancel context after 50ms
	time.Sleep(50 * time.Millisecond)
	cancel()

	resultCount := 0
	for res := range resultsChan {
		resultCount++
		if res.Err != nil && !strings.Contains(res.Err.Error(), "canceled") && !strings.Contains(res.Err.Error(), "context canceled") {
			// Some errors might be connection closed
		}
	}
	duration := time.Since(start)

	if duration > 2*time.Second {
		t.Errorf("cancellation took too long (%v), expected prompt termination", duration)
	}
	if resultCount != len(targets) {
		t.Errorf("expected all targets to receive a result on channel, got %d of %d", resultCount, len(targets))
	}
}

// TestSafety_CrawlerConfigLimitsValidation documents and verifies operational limits validation.
// Phase 1.7 identified that recursive multi-hop depth and automatic retries are bounded in configuration
// but the current crawler is a single-page asset discovery engine.
func TestSafety_CrawlerConfigLimitsValidation(t *testing.T) {
	cfg := DefaultConfig()

	// Verify defaults
	if cfg.Concurrency != DefaultConcurrency {
		t.Errorf("Default Concurrency = %d, want %d", cfg.Concurrency, DefaultConcurrency)
	}
	if cfg.Timeout != DefaultTimeout {
		t.Errorf("Default Timeout = %v, want %v", cfg.Timeout, DefaultTimeout)
	}
	if cfg.MaxAssetSize != DefaultMaxAssetSize {
		t.Errorf("Default MaxAssetSize = %d, want %d", cfg.MaxAssetSize, DefaultMaxAssetSize)
	}
	if cfg.ScopeMode != ScopeSameOrigin {
		t.Errorf("Default ScopeMode = %q, want %q", cfg.ScopeMode, ScopeSameOrigin)
	}
	if cfg.AllowLoopback {
		t.Errorf("Default AllowLoopback must be false")
	}
	if cfg.AllowPrivateIPs {
		t.Errorf("Default AllowPrivateIPs must be false")
	}

	// Verify that Crawler constructor applies safe defaults when zeros are passed
	c := New(Config{})
	if c.config.Concurrency != DefaultConcurrency {
		t.Errorf("New(Config{}) Concurrency = %d, want %d", c.config.Concurrency, DefaultConcurrency)
	}
	if c.config.Timeout != DefaultTimeout {
		t.Errorf("New(Config{}) Timeout = %v, want %v", c.config.Timeout, DefaultTimeout)
	}
	if c.config.MaxAssetSize != DefaultMaxAssetSize {
		t.Errorf("New(Config{}) MaxAssetSize = %d, want %d", c.config.MaxAssetSize, DefaultMaxAssetSize)
	}
	if c.config.ScopeMode != ScopeSameOrigin {
		t.Errorf("New(Config{}) ScopeMode = %q, want %q", c.config.ScopeMode, ScopeSameOrigin)
	}
}
