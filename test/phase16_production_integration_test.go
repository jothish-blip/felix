package test

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"felix/pkg/crawler"
	"felix/pkg/crawler/browser"
)

// TestProductionCrawler_SPANavigationIntegration verifies that the production crawler entry point
// (crawler.New(cfg).Crawl(ctx, target)) invokes the CDP SPA State Navigator when enabled.
func TestProductionCrawler_SPANavigationIntegration(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		htmlPath := filepath.Join("..", "test", "lab", "spa_navigator.html")
		content, err := os.ReadFile(htmlPath)
		if err != nil {
			http.Error(w, "fixture not found: "+err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write(content)
	})

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed binding loopback listener: %v", err)
	}
	defer listener.Close()

	server := &http.Server{Handler: mux}
	go func() {
		_ = server.Serve(listener)
	}()
	defer server.Close()

	targetURL := fmt.Sprintf("http://%s/", listener.Addr().String())

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// 1. Production Crawler Configuration with SPA State Navigation enabled
	cfg := crawler.DefaultConfig()
	cfg.AllowLoopback = true
	cfg.Timeout = 25 * time.Second
	cfg.BrowserDiscovery = crawler.BrowserDiscoveryOptions{
		Enabled:             true,
		EnableSPANavigation: true,
		Timeout:             15 * time.Second,
	}

	// 2. Production Crawler Entry Point
	c := crawler.New(cfg)
	res := c.Crawl(ctx, targetURL)

	// 3. Assertions proving SPA navigator was executed by the production workflow
	if res.Err != nil {
		t.Fatalf("Production crawl failed: %v", res.Err)
	}
	if res.BrowserDiscovery == nil {
		t.Fatalf("Expected res.BrowserDiscovery to be populated by production crawler")
	}
	if res.BrowserDiscovery.Inconclusive {
		t.Fatalf("Browser discovery reported inconclusive: %s", res.BrowserDiscovery.Reason)
	}
	if res.BrowserDiscovery.SPANavigation == nil {
		t.Fatalf("Production crawler did not invoke SPA navigator: res.BrowserDiscovery.SPANavigation is nil")
	}

	report, ok := res.BrowserDiscovery.SPANavigation.(*browser.SPANavigationReport)
	if !ok {
		t.Fatalf("Expected res.BrowserDiscovery.SPANavigation to be *browser.SPANavigationReport, got %T", res.BrowserDiscovery.SPANavigation)
	}

	if report.TotalStates < 3 {
		t.Errorf("Expected at least 3 SPA states discovered by crawler entry point, got %d", report.TotalStates)
	}
	if report.TotalTransitions < 5 {
		t.Errorf("Expected at least 5 transitions executed by crawler entry point, got %d", report.TotalTransitions)
	}
	if report.BlockedActions < 1 {
		t.Errorf("Expected at least 1 action blocked by safety policy during production crawl, got %d", report.BlockedActions)
	}

	// Verify endpoints discovered by the SPA navigator were ingested into crawler findings
	var foundBrowserEndpoints int
	for _, ep := range res.BrowserDiscovery.Endpoints {
		if ep.Provenance == crawler.ProvenanceBrowser {
			foundBrowserEndpoints++
		}
	}
	if foundBrowserEndpoints == 0 {
		t.Errorf("Expected crawler to ingest browser-discovered dynamic endpoints, found 0")
	}

	t.Logf("Production Crawler SPA Integration PASS: Discovered %d states, executed %d transitions, blocked %d unsafe actions, ingested %d browser endpoints",
		report.TotalStates, report.TotalTransitions, report.BlockedActions, foundBrowserEndpoints)
}
