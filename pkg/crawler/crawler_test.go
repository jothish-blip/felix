package crawler

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
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
