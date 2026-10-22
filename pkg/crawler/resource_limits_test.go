package crawler

import (
	"bytes"
	"compress/gzip"
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// TestResourceLimits_DecompressionBombProtection verifies that a highly compressed
// gzip stream (decompression bomb) expanding far beyond MaxAssetSize is bounded
// by io.LimitReader without consuming unbounded memory, and yields ErrAssetTooLarge.
func TestResourceLimits_DecompressionBombProtection(t *testing.T) {
	// Create a 5MB payload of repeating characters
	decompressedSize := 5 * 1024 * 1024
	decompressed := bytes.Repeat([]byte("A"), decompressedSize)

	var compressedBuf bytes.Buffer
	gw := gzip.NewWriter(&compressedBuf)
	if _, err := gw.Write(decompressed); err != nil {
		t.Fatalf("failed to gzip: %v", err)
	}
	if err := gw.Close(); err != nil {
		t.Fatalf("failed to close gzip writer: %v", err)
	}
	compressedBytes := compressedBuf.Bytes()

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			w.Header().Set("Content-Type", "text/html")
			w.Write([]byte(`<html><head><script src="/bomb.js"></script></head><body>Bomb Test</body></html>`))
			return
		}
		if r.URL.Path == "/bomb.js" {
			// Serve the pre-compressed gzip payload with Content-Encoding: gzip
			w.Header().Set("Content-Type", "application/javascript")
			w.Header().Set("Content-Encoding", "gzip")
			w.WriteHeader(http.StatusOK)
			w.Write(compressedBytes)
			return
		}
		http.NotFound(w, r)
	}))
	defer ts.Close()

	// Bound asset size to 64 KB
	limitBytes := int64(64 * 1024)
	cfg := DefaultConfig()
	cfg.AllowLoopback = true
	cfg.MaxAssetSize = limitBytes

	c := New(cfg)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	res := c.Crawl(ctx, ts.URL)
	if res.Err != nil {
		t.Fatalf("Crawl failed unexpectedly: %v", res.Err)
	}

	foundBomb := false
	for _, a := range res.Assets {
		if strings.Contains(a.URL, "bomb.js") {
			foundBomb = true
			if a.Error != ErrAssetTooLarge {
				t.Fatalf("expected ErrAssetTooLarge for decompression bomb, got %v", a.Error)
			}
			if int64(len(a.Content)) > limitBytes {
				t.Fatalf("asset content length %d exceeds MaxAssetSize %d", len(a.Content), limitBytes)
			}
		}
	}

	if !foundBomb {
		t.Fatal("expected bomb.js asset to be discovered and bounded")
	}
}

// TestResourceLimits_AssetLoopCancellationResponsiveness verifies that cancelling
// context during the asset download loop terminates immediately via labeled break.
func TestResourceLimits_AssetLoopCancellationResponsiveness(t *testing.T) {
	// Create page with 50 assets
	var links strings.Builder
	for i := 0; i < 50; i++ {
		links.WriteString(fmt.Sprintf(`<script src="/asset-%d.js"></script>`+"\n", i))
	}
	mockHTML := fmt.Sprintf(`<!DOCTYPE html><html><head>%s</head><body>Test</body></html>`, links.String())

	var requestsServed int32
	serverBlock := make(chan struct{})

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			w.Header().Set("Content-Type", "text/html")
			w.Write([]byte(mockHTML))
			return
		}
		atomic.AddInt32(&requestsServed, 1)
		// Wait on serverBlock or request context
		select {
		case <-serverBlock:
			w.Header().Set("Content-Type", "application/javascript")
			w.Write([]byte(`console.log(1);`))
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

	doneCh := make(chan Result, 1)
	go func() {
		doneCh <- c.Crawl(ctx, ts.URL)
	}()

	// Wait briefly until at least 1 request reaches the server, then cancel
	for i := 0; i < 50; i++ {
		if atomic.LoadInt32(&requestsServed) >= 1 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	cancel()

	select {
	case res := <-doneCh:
		// Crawl should finish promptly without waiting for all 50 assets
		served := atomic.LoadInt32(&requestsServed)
		if served >= 50 {
			t.Errorf("expected cancellation to stop asset queue before all 50 served, but served %d", served)
		}
		_ = res
	case <-time.After(3 * time.Second):
		t.Fatal("crawl did not terminate promptly after context cancellation")
	}
}

// TestResourceLimits_GoroutineLeakFreedom verifies that cancelled or failing crawls
// release all worker goroutines without leaking them.
func TestResourceLimits_GoroutineLeakFreedom(t *testing.T) {
	// Let existing background runtime goroutines stabilize
	runtime.GC()
	initialGoroutines := runtime.NumGoroutine()

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(20 * time.Millisecond)
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(`<html><head><script src="/a.js"></script><script src="/b.js"></script></head><body>OK</body></html>`))
	}))
	defer ts.Close()

	cfg := DefaultConfig()
	cfg.AllowLoopback = true
	cfg.Concurrency = 4
	c := New(cfg)

	// Run multiple cycles with rapid cancellation
	for i := 0; i < 5; i++ {
		ctx, cancel := context.WithTimeout(context.Background(), 25*time.Millisecond)
		_ = c.Crawl(ctx, ts.URL)
		cancel()
	}

	// Give runtime a moment to tear down finished goroutines
	time.Sleep(100 * time.Millisecond)
	runtime.GC()

	finalGoroutines := runtime.NumGoroutine()
	delta := finalGoroutines - initialGoroutines
	// Allow minor variance for runtime / test runner workers, but prevent significant leak (> 5)
	if delta > 5 {
		t.Fatalf("possible goroutine leak: initial %d, final %d, delta %d", initialGoroutines, finalGoroutines, delta)
	}
}
