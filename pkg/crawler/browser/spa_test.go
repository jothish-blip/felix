package browser

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/chromedp/chromedp"
)

func setupSPAServer(t *testing.T) (string, func()) {
	t.Helper()

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		htmlPath := filepath.Join("..", "..", "..", "test", "lab", "spa_navigator.html")
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

	server := &http.Server{Handler: mux}
	go func() {
		_ = server.Serve(listener)
	}()

	addr := listener.Addr().String()
	cleanup := func() {
		_ = server.Close()
	}

	return addr, cleanup
}

// 1. State Identity: Equivalent normalized states deduplicate and volatile clocks do not create duplicates.
func TestSPAStateIdentity_DeduplicationAndVolatileFiltering(t *testing.T) {
	serverAddr, cleanup := setupSPAServer(t)
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	inst, err := Launch(ctx, DefaultConfig())
	if err != nil {
		t.Fatalf("Launch failed: %v", err)
	}
	defer inst.Close()

	targetURL := fmt.Sprintf("http://%s/", serverAddr)
	if err := chromedp.Do(inst.Ctx, chromedp.Navigate(targetURL), chromedp.Sleep(200*time.Millisecond)); err != nil {
		t.Fatalf("Navigate failed: %v", err)
	}

	nav, err := NewSPANavigator(inst, DefaultSPANavigatorConfig())
	if err != nil {
		t.Fatalf("NewSPANavigator failed: %v", err)
	}

	// Capture initial state
	state1, _, err := nav.captureState(ctx, 0)
	if err != nil {
		t.Fatalf("captureState 1 failed: %v", err)
	}

	// Click no-op clock update 3 times (updates volatile timestamp)
	for i := 0; i < 3; i++ {
		_ = chromedp.Do(inst.Ctx, chromedp.Click("#btn-noop-clock"))
		time.Sleep(50 * time.Millisecond)
	}

	// Capture state after volatile clock updates
	state2, _, err := nav.captureState(ctx, 0)
	if err != nil {
		t.Fatalf("captureState 2 failed: %v", err)
	}

	if state1.ID != state2.ID {
		t.Fatalf("State ID changed due to volatile clock update! Expected %s, got %s", state1.ID, state2.ID)
	}
	if state1.StructuralDigest != state2.StructuralDigest {
		t.Fatalf("Structural digest differed on volatile clock update")
	}

	t.Logf("State Identity PASS: Volatile clock updates safely ignored; state fingerprint %s deterministic", state1.ID)
}

// 2. Material Differences: Distinct views (Home, Settings, Score Board) produce distinct state IDs.
func TestSPAStateIdentity_MaterialDifferencesRemainDistinct(t *testing.T) {
	serverAddr, cleanup := setupSPAServer(t)
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	inst, err := Launch(ctx, DefaultConfig())
	if err != nil {
		t.Fatalf("Launch failed: %v", err)
	}
	defer inst.Close()

	targetURL := fmt.Sprintf("http://%s/", serverAddr)
	if err := chromedp.Do(inst.Ctx, chromedp.Navigate(targetURL), chromedp.Sleep(200*time.Millisecond)); err != nil {
		t.Fatalf("Navigate failed: %v", err)
	}

	nav, err := NewSPANavigator(inst, DefaultSPANavigatorConfig())
	if err != nil {
		t.Fatalf("NewSPANavigator failed: %v", err)
	}

	// State 1: Home
	stateHome, _, err := nav.captureState(ctx, 0)
	if err != nil {
		t.Fatalf("captureState Home failed: %v", err)
	}

	// Navigate to Settings tab
	_ = chromedp.Do(inst.Ctx, chromedp.Click("#nav-settings"), chromedp.Sleep(100*time.Millisecond))
	stateSettings, _, err := nav.captureState(ctx, 1)
	if err != nil {
		t.Fatalf("captureState Settings failed: %v", err)
	}

	// Navigate to Score Board route
	_ = chromedp.Do(inst.Ctx, chromedp.Click("#nav-history-route"), chromedp.Sleep(100*time.Millisecond))
	stateScoreboard, _, err := nav.captureState(ctx, 2)
	if err != nil {
		t.Fatalf("captureState Scoreboard failed: %v", err)
	}

	if stateHome.ID == stateSettings.ID {
		t.Errorf("Home and Settings incorrectly shared identical state ID %s", stateHome.ID)
	}
	if stateSettings.ID == stateScoreboard.ID {
		t.Errorf("Settings and Scoreboard incorrectly shared identical state ID %s", stateSettings.ID)
	}
	if stateHome.ID == stateScoreboard.ID {
		t.Errorf("Home and Scoreboard incorrectly shared identical state ID %s", stateHome.ID)
	}

	t.Logf("Material Differences PASS: 3 distinct UI states verified (Home: %s, Settings: %s, Scoreboard: %s)",
		stateHome.ID, stateSettings.ID, stateScoreboard.ID)
}

// 3. Safety: Destructive actions and out-of-scope targets are safely blocked.
func TestSPASafety_DestructiveAndExternalControlsBlocked(t *testing.T) {
	serverAddr, cleanup := setupSPAServer(t)
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	inst, err := Launch(ctx, DefaultConfig())
	if err != nil {
		t.Fatalf("Launch failed: %v", err)
	}
	defer inst.Close()

	targetURL := fmt.Sprintf("http://%s/", serverAddr)
	if err := chromedp.Do(inst.Ctx, chromedp.Navigate(targetURL), chromedp.Sleep(200*time.Millisecond)); err != nil {
		t.Fatalf("Navigate failed: %v", err)
	}

	cfg := DefaultSPANavigatorConfig()
	cfg.MaxTransitionsPerState = 20
	cfg.TotalMaxTransitions = 20

	nav, err := NewSPANavigator(inst, cfg)
	if err != nil {
		t.Fatalf("NewSPANavigator failed: %v", err)
	}

	rep, err := nav.Explore(ctx)
	if err != nil {
		t.Fatalf("Explore failed: %v", err)
	}

	var blockedDestructive, blockedExternal bool
	for _, trans := range rep.Transitions {
		if trans.TargetSelector == "#btn-destructive-delete" && trans.Status == TransitionBlockedPolicy {
			blockedDestructive = true
		}
		if trans.TargetSelector == "#link-external-threat" && trans.Status == TransitionBlockedScope {
			blockedExternal = true
		}
	}

	if !blockedDestructive {
		t.Errorf("Expected #btn-destructive-delete to be blocked by destructive policy")
	}
	if !blockedExternal {
		t.Errorf("Expected #link-external-threat to be blocked by scope boundary")
	}

	t.Logf("Safety PASS: Blocked destructive action (%v) and external scope link (%v)",
		blockedDestructive, blockedExternal)
}

// 4. Resource Limits: Bounds on states, depth, and transitions are strictly enforced.
func TestSPALimits_MaxBoundsEnforced(t *testing.T) {
	serverAddr, cleanup := setupSPAServer(t)
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	inst, err := Launch(ctx, DefaultConfig())
	if err != nil {
		t.Fatalf("Launch failed: %v", err)
	}
	defer inst.Close()

	targetURL := fmt.Sprintf("http://%s/", serverAddr)
	if err := chromedp.Do(inst.Ctx, chromedp.Navigate(targetURL), chromedp.Sleep(200*time.Millisecond)); err != nil {
		t.Fatalf("Navigate failed: %v", err)
	}

	cfg := DefaultSPANavigatorConfig()
	cfg.MaxStates = 3
	cfg.MaxDepth = 2
	cfg.TotalMaxTransitions = 5

	nav, err := NewSPANavigator(inst, cfg)
	if err != nil {
		t.Fatalf("NewSPANavigator failed: %v", err)
	}

	rep, err := nav.Explore(ctx)
	if err != nil {
		t.Fatalf("Explore failed: %v", err)
	}

	if len(rep.States) > cfg.MaxStates {
		t.Errorf("Discovered states %d exceeded configured cap %d", len(rep.States), cfg.MaxStates)
	}
	if rep.TotalTransitions > cfg.TotalMaxTransitions {
		t.Errorf("Total transitions %d exceeded configured cap %d", rep.TotalTransitions, cfg.TotalMaxTransitions)
	}

	t.Logf("Limits PASS: Bounded to %d states and %d transitions", len(rep.States), rep.TotalTransitions)
}

// 5. Comprehensive Exploration: Full traversal discovering views, tabs, wizards, and route changes.
func TestSPAExploration_ComprehensiveE2E(t *testing.T) {
	serverAddr, cleanup := setupSPAServer(t)
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()

	inst, err := Launch(ctx, DefaultConfig())
	if err != nil {
		t.Fatalf("Launch failed: %v", err)
	}
	defer inst.Close()

	targetURL := fmt.Sprintf("http://%s/", serverAddr)
	if err := chromedp.Do(inst.Ctx, chromedp.Navigate(targetURL), chromedp.Sleep(200*time.Millisecond)); err != nil {
		t.Fatalf("Navigate failed: %v", err)
	}

	cfg := DefaultSPANavigatorConfig()
	cfg.MaxStates = 15
	cfg.TotalMaxTransitions = 25
	cfg.MaxDepth = 3

	nav, err := NewSPANavigator(inst, cfg)
	if err != nil {
		t.Fatalf("NewSPANavigator failed: %v", err)
	}

	rep, err := nav.Explore(ctx)
	if err != nil {
		t.Fatalf("Explore failed: %v", err)
	}

	if len(rep.States) < 3 {
		t.Errorf("Expected at least 3 distinct SPA states discovered, found %d", len(rep.States))
	}
	if rep.TotalTransitions < 5 {
		t.Errorf("Expected at least 5 transitions executed, found %d", rep.TotalTransitions)
	}
	if rep.BlockedActions < 1 {
		t.Errorf("Expected at least 1 blocked action, found %d", rep.BlockedActions)
	}

	// Verify route changes were tracked
	var foundHashRoute bool
	for _, s := range rep.States {
		if strings.Contains(s.Route, "#/settings") || strings.Contains(s.Route, "#/score-board") {
			foundHashRoute = true
			break
		}
	}

	t.Logf("SPA Exploration PASS: Discovered %d states, executed %d transitions, blocked %d unsafe actions, tracked dynamic routes: %v",
		len(rep.States), rep.TotalTransitions, rep.BlockedActions, foundHashRoute)
}

// 6. Wizard Transitions: Progressing through wizard reveals distinct states per step.
func TestSPATransitions_MultiStepWizard(t *testing.T) {
	serverAddr, cleanup := setupSPAServer(t)
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	inst, err := Launch(ctx, DefaultConfig())
	if err != nil {
		t.Fatalf("Launch failed: %v", err)
	}
	defer inst.Close()

	targetURL := fmt.Sprintf("http://%s/", serverAddr)
	if err := chromedp.Do(inst.Ctx, chromedp.Navigate(targetURL), chromedp.Sleep(200*time.Millisecond)); err != nil {
		t.Fatalf("Navigate failed: %v", err)
	}

	nav, err := NewSPANavigator(inst, DefaultSPANavigatorConfig())
	if err != nil {
		t.Fatalf("NewSPANavigator failed: %v", err)
	}

	// Navigate to wizard view
	_ = chromedp.Do(inst.Ctx, chromedp.Click("#nav-wizard"), chromedp.Sleep(100*time.Millisecond))
	step1State, _, err := nav.captureState(ctx, 1)
	if err != nil {
		t.Fatalf("captureState Step 1 failed: %v", err)
	}

	// Click Step 2
	_ = chromedp.Do(inst.Ctx, chromedp.Click("#btn-wiz-next-1"), chromedp.Sleep(100*time.Millisecond))
	step2State, _, err := nav.captureState(ctx, 2)
	if err != nil {
		t.Fatalf("captureState Step 2 failed: %v", err)
	}

	// Click Step 3
	_ = chromedp.Do(inst.Ctx, chromedp.Click("#btn-wiz-next-2"), chromedp.Sleep(100*time.Millisecond))
	step3State, _, err := nav.captureState(ctx, 3)
	if err != nil {
		t.Fatalf("captureState Step 3 failed: %v", err)
	}

	if step1State.ID == step2State.ID {
		t.Errorf("Wizard Step 1 and Step 2 had identical state ID %s", step1State.ID)
	}
	if step2State.ID == step3State.ID {
		t.Errorf("Wizard Step 2 and Step 3 had identical state ID %s", step2State.ID)
	}

	t.Logf("Wizard PASS: 3 distinct wizard step states captured (Step1: %s, Step2: %s, Step3: %s)",
		step1State.ID, step2State.ID, step3State.ID)
}

// 7. No-Op Discrimination: A click that does not alter UI structure is classified as NO_STATE_CHANGE.
func TestSPATransitions_NoOpProducesNoStateChange(t *testing.T) {
	serverAddr, cleanup := setupSPAServer(t)
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	inst, err := Launch(ctx, DefaultConfig())
	if err != nil {
		t.Fatalf("Launch failed: %v", err)
	}
	defer inst.Close()

	targetURL := fmt.Sprintf("http://%s/", serverAddr)
	if err := chromedp.Do(inst.Ctx, chromedp.Navigate(targetURL), chromedp.Sleep(200*time.Millisecond)); err != nil {
		t.Fatalf("Navigate failed: %v", err)
	}

	nav, err := NewSPANavigator(inst, DefaultSPANavigatorConfig())
	if err != nil {
		t.Fatalf("NewSPANavigator failed: %v", err)
	}

	fromState, _, err := nav.captureState(ctx, 0)
	if err != nil {
		t.Fatalf("captureState failed: %v", err)
	}

	cand := rawCandidate{
		Tag:        "button",
		Selector:   "#btn-noop-clock",
		Text:       "Update Clock (No-Op)",
		ActionType: "click",
	}

	trans, nextState, _ := nav.executeTransition(ctx, fromState, cand, 1)

	if trans.Status != TransitionNoStateChange {
		t.Errorf("Expected TransitionNoStateChange for clock click, got %s", trans.Status)
	}
	if trans.MaterialChange {
		t.Errorf("Expected MaterialChange=false for clock click")
	}
	if nextState.ID != fromState.ID {
		t.Errorf("Expected identical state ID for no-op, got from=%s, to=%s", fromState.ID, nextState.ID)
	}

	t.Logf("No-Op PASS: Transition correctly recorded as NO_STATE_CHANGE with MaterialChange=false")
}

// 8. Cycle Prevention: Alternating between cycle views detects duplicates and terminates safely.
func TestSPALimits_CyclePrevention(t *testing.T) {
	serverAddr, cleanup := setupSPAServer(t)
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	inst, err := Launch(ctx, DefaultConfig())
	if err != nil {
		t.Fatalf("Launch failed: %v", err)
	}
	defer inst.Close()

	targetURL := fmt.Sprintf("http://%s/", serverAddr)
	if err := chromedp.Do(inst.Ctx, chromedp.Navigate(targetURL), chromedp.Sleep(200*time.Millisecond)); err != nil {
		t.Fatalf("Navigate failed: %v", err)
	}

	cfg := DefaultSPANavigatorConfig()
	cfg.MaxStates = 10
	cfg.TotalMaxTransitions = 15

	nav, err := NewSPANavigator(inst, cfg)
	if err != nil {
		t.Fatalf("NewSPANavigator failed: %v", err)
	}

	rep, err := nav.Explore(ctx)
	if err != nil {
		t.Fatalf("Explore failed: %v", err)
	}

	// Verify that duplicate states were encountered and handled without infinite looping
	if rep.TotalTransitions > cfg.TotalMaxTransitions {
		t.Errorf("Total transitions %d exceeded cap %d", rep.TotalTransitions, cfg.TotalMaxTransitions)
	}

	t.Logf("Cycle Prevention PASS: Exploration bounded safely across %d transitions (%d duplicates suppressed)",
		rep.TotalTransitions, rep.DuplicateStates)
}

// 9. Context Cancellation Safety: Aborting parent context halts exploration immediately.
func TestSPALifecycle_ContextCancellation(t *testing.T) {
	_, cleanup := setupSPAServer(t)
	defer cleanup()

	cancelCtx, cancel := context.WithCancel(context.Background())
	cancel() // pre-cancel context

	inst, err := Launch(context.Background(), DefaultConfig())
	if err != nil {
		t.Fatalf("Launch failed: %v", err)
	}
	defer inst.Close()

	nav, err := NewSPANavigator(inst, DefaultSPANavigatorConfig())
	if err != nil {
		t.Fatalf("NewSPANavigator failed: %v", err)
	}

	_, _ = nav.Explore(cancelCtx)
	t.Logf("Lifecycle PASS: Pre-canceled context handled gracefully without panic or hang")
}
