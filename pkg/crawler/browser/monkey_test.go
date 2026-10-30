package browser

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/chromedp/chromedp"
)

func TestDOMMonkeyInteractionAndDialogBypass(t *testing.T) {
	// 1. Locate test/lab/spa_events.html
	fixturePath := filepath.Join("..", "..", "..", "test", "lab", "spa_events.html")
	htmlBytes, err := os.ReadFile(fixturePath)
	if err != nil {
		t.Fatalf("Failed to read fixture %s: %v", fixturePath, err)
	}

	var hiddenRouteHits int32
	var layer3Hits int32
	var formSubmitHits int32
	var layer3CompleteHits int32
	var destructiveDeleteHits int32

	// 2. Spin up local HTTP server serving the SPA fixture and tracking API calls
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to bind listener: %v", err)
	}
	defer listener.Close()

	serverAddr := listener.Addr().String()

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write(htmlBytes)
	})

	mux.HandleFunc("/api/hidden-route", func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hiddenRouteHits, 1)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"hidden_discovered"}`))
	})

	mux.HandleFunc("/api/form-submit", func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&formSubmitHits, 1)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"form_accepted"}`))
	})

	mux.HandleFunc("/api/layer3", func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&layer3Hits, 1)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"layer3_reached"}`))
	})

	mux.HandleFunc("/api/layer3-completed", func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&layer3CompleteHits, 1)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"layer3_done"}`))
	})

	// Destructive route - must NEVER be called by safe-mode crawler
	mux.HandleFunc("/api/destructive-delete-all", func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&destructiveDeleteHits, 1)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"status":"error","error":"destructive purge triggered!"}`))
	})

	server := &http.Server{Handler: mux}
	go server.Serve(listener)
	defer server.Close()

	targetURL := fmt.Sprintf("http://%s/", serverAddr)

	// 3. Launch headless browser
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()

	cfg := DefaultConfig()
	inst, err := Launch(ctx, cfg)
	if err != nil {
		t.Fatalf("Failed to launch browser: %v", err)
	}
	defer inst.Close()

	// 4. Attach 1.2 Network Sniffer with SafeDialer
	gw, err := AttachNetworkGateway(ctx, inst, GatewayOptions{
		AllowLoopback:   false,
		AllowPrivateIPs: false,
		AllowedHosts:    []string{serverAddr},
	})
	if err != nil {
		t.Fatalf("Failed to attach network gateway: %v", err)
	}
	defer gw.Stop()

	// 5. Navigate to fixture
	if err := chromedp.Do(inst.Ctx, chromedp.Navigate(targetURL), chromedp.WaitVisible("#layer1")); err != nil {
		t.Fatalf("Navigation to test page failed: %v", err)
	}

	// 6. Initialize DOM Monkey Engine with MaxDepth = 3 and Safe Mode Defaults
	monkeyCfg := DefaultMonkeyConfig()
	monkeyCfg.MaxDepth = 3
	monkeyCfg.ActionDelay = 60 * time.Millisecond
	monkeyCfg.AllowDestructiveConfirmations = false // Explicit safe audit mode verification

	monkey, err := NewDOMMonkey(inst, monkeyCfg)
	if err != nil {
		t.Fatalf("Failed to initialize DOM Monkey: %v", err)
	}
	defer monkey.Stop()

	// 7. Execute Multi-Layer DOM Event Simulation
	report, err := monkey.Execute(ctx)
	if err != nil {
		t.Fatalf("DOM Monkey execution returned unexpected error: %v", err)
	}

	// Allow pending async fetch responses to finalize
	time.Sleep(300 * time.Millisecond)

	// 8. Assertions for Iron Gate Verification
	t.Logf("=== MONKEY REPORT ===")
	t.Logf("Max Depth Reached    : %d (Threshold >= 3)", report.MaxDepthReached)
	t.Logf("Total Actions Executed: %d", report.TotalActions)
	t.Logf("Forms Auto-Filled    : %d", report.FormsFilled)
	t.Logf("Dialogs Auto-Handled : %d (Messages: %v)", report.DialogsHandled, report.DialogMessages)
	t.Logf("Execution Duration   : %.2f ms", report.ExecutionDurationMS)

	// Requirement A: Dialog Trapping & Zero Deadlock
	if report.DialogsHandled < 2 {
		t.Errorf("Expected at least 2 dialogs (alert + confirm) to be trapped and handled, got %d", report.DialogsHandled)
	}

	// Verify Stall Alert was dismissed without hanging
	alertFound := false
	confirmFound := false
	for _, msg := range report.DialogMessages {
		if strings.Contains(msg, "Stall!") {
			alertFound = true
		}
		if strings.Contains(msg, "permanently delete") {
			confirmFound = true
		}
	}
	if !alertFound {
		t.Errorf("Expected dialog message 'Stall!' in trapped messages, got: %v", report.DialogMessages)
	}
	if !confirmFound {
		t.Errorf("Expected confirm dialog in trapped messages, got: %v", report.DialogMessages)
	}

	// Requirement B: Safe Mode Policy Integrity (Confirm dismissed -> 0 destructive hits)
	if atomic.LoadInt32(&destructiveDeleteHits) > 0 {
		t.Fatalf("SECURITY VIOLATION: Safe-mode crawler auto-accepted destructive confirm() and triggered %d purge requests!",
			destructiveDeleteHits)
	}
	t.Logf("VERIFIED: Destructive confirmation safely rejected by default policy (0 purge hits)")

	// Requirement C: Interaction Depth Threshold >= 3 layers
	if report.MaxDepthReached < 3 {
		t.Errorf("Expected MaxDepthReached >= 3 layers, got %d", report.MaxDepthReached)
	}

	// Requirement D: Network Sniffer captured /api/hidden-route (revealed via panel)
	if atomic.LoadInt32(&hiddenRouteHits) == 0 {
		t.Errorf("Expected /api/hidden-route to be called on server, got 0 hits")
	}
	if gw.FindRequestByURL("/api/hidden-route") == nil {
		t.Errorf("Expected Network Sniffer to capture /api/hidden-route")
	}

	// Requirement E: Network Sniffer captured /api/layer3 (genuine state transition)
	if atomic.LoadInt32(&layer3Hits) == 0 {
		t.Errorf("Expected /api/layer3 to be called on server, got 0 hits")
	}
	if gw.FindRequestByURL("/api/layer3") == nil {
		t.Errorf("Expected Network Sniffer to capture /api/layer3")
	}

	// Requirement F: Form filling triggered /api/form-submit
	if atomic.LoadInt32(&formSubmitHits) == 0 {
		t.Errorf("Expected /api/form-submit to be called on server, got 0 hits")
	}

	t.Logf("VERIFIED: DOM Monkey successfully bypassed blocking dialogs, rejected destructive actions, explored %d layers deep, and triggered hidden endpoints!",
		report.MaxDepthReached)
}
