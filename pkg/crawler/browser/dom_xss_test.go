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

func setupDOMXSSServer(t *testing.T) (string, func()) {
	t.Helper()
	fixturePath := filepath.Join("..", "..", "..", "test", "lab", "dom_xss.html")
	htmlBytes, err := os.ReadFile(fixturePath)
	if err != nil {
		t.Fatalf("Failed to read fixture %s: %v", fixturePath, err)
	}

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to bind local listener: %v", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write(htmlBytes)
	})

	server := &http.Server{Handler: mux}
	go server.Serve(listener)

	cleanup := func() {
		_ = server.Close()
		_ = listener.Close()
	}

	return listener.Addr().String(), cleanup
}

func TestDOMXSSCaseA_VulnerableHTMLSink(t *testing.T) {
	serverAddr, cleanupServer := setupDOMXSSServer(t)
	defer cleanupServer()

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	inst, err := Launch(ctx, DefaultConfig())
	if err != nil {
		t.Fatalf("Launch failed: %v", err)
	}
	defer inst.Close()

	dx, err := AttachDOMXSSInstrumenter(ctx, inst, DefaultDOMXSSOptions())
	if err != nil {
		t.Fatalf("AttachDOMXSSInstrumenter failed: %v", err)
	}
	defer dx.Stop()

	// 1. Generate and register unique canary
	canary := GenerateCanaryToken("felix_vuln_canary")
	dx.RegisterCanary(canary)

	// 2. Navigate with canary in hash payload targeting vulnerable innerHTML
	payload := fmt.Sprintf("<b id='injected'>%s</b>", canary)
	targetURL := fmt.Sprintf("http://%s/?mode=vuln_html#%s", serverAddr, payload)

	if err := chromedp.Do(inst.Ctx, chromedp.Navigate(targetURL), chromedp.Sleep(400*time.Millisecond)); err != nil {
		t.Fatalf("Navigation failed: %v", err)
	}

	// 3. Assertions
	unsafeFindings := dx.GetUnsafeFindings()
	if len(unsafeFindings) == 0 {
		t.Fatalf("Expected at least 1 unsafe DOM sink finding, got 0. All findings: %v", dx.GetFindings())
	}

	var found *SinkFinding
	for _, f := range unsafeFindings {
		if f.CanaryToken == canary {
			found = f
			break
		}
	}

	if found == nil {
		t.Fatalf("Expected finding correlating canary %q, got: %v", canary, unsafeFindings)
	}

	if found.SinkType != SinkInnerHTML {
		t.Errorf("Expected SinkType %s, got %s", SinkInnerHTML, found.SinkType)
	}
	if found.Classification != ClassificationPotentiallyUnsafe {
		t.Errorf("Expected classification %s, got %s", ClassificationPotentiallyUnsafe, found.Classification)
	}
	if !found.IsExecutable {
		t.Errorf("Expected IsExecutable to be true")
	}
	if found.CallStack == "" {
		t.Errorf("Expected call stack trace to be captured, got empty string")
	}

	t.Logf("Case A PASS: Unsafe innerHTML flow detected: Canary=%s Sink=%s StackLines=%d",
		canary, found.SinkType, len(strings.Split(found.CallStack, "\n")))
}

func TestDOMXSSCaseB_DefendedTextSink(t *testing.T) {
	serverAddr, cleanupServer := setupDOMXSSServer(t)
	defer cleanupServer()

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	inst, err := Launch(ctx, DefaultConfig())
	if err != nil {
		t.Fatalf("Launch failed: %v", err)
	}
	defer inst.Close()

	dx, err := AttachDOMXSSInstrumenter(ctx, inst, DefaultDOMXSSOptions())
	if err != nil {
		t.Fatalf("AttachDOMXSSInstrumenter failed: %v", err)
	}
	defer dx.Stop()

	// 1. Generate canary and register it
	canary := GenerateCanaryToken("felix_safe_canary")
	dx.RegisterCanary(canary)

	// 2. Target defended textContent sink
	targetURL := fmt.Sprintf("http://%s/?mode=defended_text#%s", serverAddr, canary)
	if err := chromedp.Do(inst.Ctx, chromedp.Navigate(targetURL), chromedp.Sleep(400*time.Millisecond)); err != nil {
		t.Fatalf("Navigation failed: %v", err)
	}

	// 3. Verify ZERO unsafe findings for textContent
	unsafeFindings := dx.GetUnsafeFindings()
	for _, f := range unsafeFindings {
		if f.CanaryToken == canary {
			t.Fatalf("False positive: textContent incorrectly classified as unsafe flow: %v", f)
		}
	}

	t.Logf("Case B PASS: textContent safe rendering produced 0 false alarms")
}

func TestDOMXSSCaseB2_DefendedEscapedHTML(t *testing.T) {
	serverAddr, cleanupServer := setupDOMXSSServer(t)
	defer cleanupServer()

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	inst, err := Launch(ctx, DefaultConfig())
	if err != nil {
		t.Fatalf("Launch failed: %v", err)
	}
	defer inst.Close()

	dx, err := AttachDOMXSSInstrumenter(ctx, inst, DefaultDOMXSSOptions())
	if err != nil {
		t.Fatalf("AttachDOMXSSInstrumenter failed: %v", err)
	}
	defer dx.Stop()

	canary := GenerateCanaryToken("felix_escaped_canary")
	dx.RegisterCanary(canary)

	// Inject markup that the target page safely escapes with &lt; and &gt;
	payload := fmt.Sprintf("<script>%s</script>", canary)
	targetURL := fmt.Sprintf("http://%s/?mode=escaped_html#%s", serverAddr, payload)

	if err := chromedp.Do(inst.Ctx, chromedp.Navigate(targetURL), chromedp.Sleep(400*time.Millisecond)); err != nil {
		t.Fatalf("Navigation failed: %v", err)
	}

	// Canary reaches innerHTML, but it is HTML-entity escaped (&lt;script&gt;)
	unsafeFindings := dx.GetUnsafeFindings()
	for _, f := range unsafeFindings {
		if f.CanaryToken == canary {
			t.Fatalf("False positive: Entity-escaped HTML classified as unsafe flow: %v", f)
		}
	}

	// Verify it was correctly classified as SAFE_OR_ENCODED
	allFindings := dx.GetFindings()
	var escapedFinding *SinkFinding
	for _, f := range allFindings {
		if f.CanaryToken == canary {
			escapedFinding = f
			break
		}
	}

	if escapedFinding == nil {
		t.Fatalf("Expected canary %q in findings, got %d findings", canary, len(allFindings))
	}
	if escapedFinding.Classification != ClassificationSafeOrEncoded {
		t.Errorf("Expected classification %s for escaped input, got %s",
			ClassificationSafeOrEncoded, escapedFinding.Classification)
	}

	t.Logf("Case B2 PASS: HTML-entity escaped innerHTML correctly categorized as SAFE_OR_ENCODED")
}

func TestDOMXSSCaseC_HarmlessReflection(t *testing.T) {
	serverAddr, cleanupServer := setupDOMXSSServer(t)
	defer cleanupServer()

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	inst, err := Launch(ctx, DefaultConfig())
	if err != nil {
		t.Fatalf("Launch failed: %v", err)
	}
	defer inst.Close()

	dx, err := AttachDOMXSSInstrumenter(ctx, inst, DefaultDOMXSSOptions())
	if err != nil {
		t.Fatalf("AttachDOMXSSInstrumenter failed: %v", err)
	}
	defer dx.Stop()

	canary := GenerateCanaryToken("felix_reflected_canary")
	dx.RegisterCanary(canary)

	// Normal static page navigation without triggering any sinks
	targetURL := fmt.Sprintf("http://%s/#%s", serverAddr, canary)
	if err := chromedp.Do(inst.Ctx, chromedp.Navigate(targetURL), chromedp.Sleep(300*time.Millisecond)); err != nil {
		t.Fatalf("Navigation failed: %v", err)
	}

	unsafeFindings := dx.GetUnsafeFindings()
	if len(unsafeFindings) > 0 {
		t.Fatalf("False positive on harmless reflection: got %d unsafe findings", len(unsafeFindings))
	}

	t.Logf("Case C PASS: Harmless reflection produced 0 false alarms")
}

func TestDOMXSSCaseD_AdditionalSinks(t *testing.T) {
	serverAddr, cleanupServer := setupDOMXSSServer(t)
	defer cleanupServer()

	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()

	inst, err := Launch(ctx, DefaultConfig())
	if err != nil {
		t.Fatalf("Launch failed: %v", err)
	}
	defer inst.Close()

	dx, err := AttachDOMXSSInstrumenter(ctx, inst, DefaultDOMXSSOptions())
	if err != nil {
		t.Fatalf("AttachDOMXSSInstrumenter failed: %v", err)
	}
	defer dx.Stop()

	// 1. Test eval sink
	evalCanary := GenerateCanaryToken("felix_eval_canary")
	dx.RegisterCanary(evalCanary)
	evalURL := fmt.Sprintf("http://%s/?mode=eval_sink#%s", serverAddr, evalCanary)
	if err := chromedp.Do(inst.Ctx, chromedp.Navigate(evalURL), chromedp.Sleep(300*time.Millisecond)); err != nil {
		t.Fatalf("Navigation failed: %v", err)
	}

	// 2. Test setTimeout sink
	timeoutCanary := GenerateCanaryToken("felix_timeout_canary")
	dx.RegisterCanary(timeoutCanary)
	timeoutURL := fmt.Sprintf("http://%s/?mode=timeout_sink#%s", serverAddr, timeoutCanary)
	if err := chromedp.Do(inst.Ctx, chromedp.Navigate(timeoutURL), chromedp.Sleep(300*time.Millisecond)); err != nil {
		t.Fatalf("Navigation failed: %v", err)
	}

	// 3. Test Function constructor sink
	fnCanary := GenerateCanaryToken("felix_fn_canary")
	dx.RegisterCanary(fnCanary)
	fnURL := fmt.Sprintf("http://%s/?mode=func_sink#%s", serverAddr, fnCanary)
	if err := chromedp.Do(inst.Ctx, chromedp.Navigate(fnURL), chromedp.Sleep(300*time.Millisecond)); err != nil {
		t.Fatalf("Navigation failed: %v", err)
	}

	// 4. Test CONFIRMED_EXECUTION controlled sentinel signal
	execCanary := GenerateCanaryToken("felix_exec_canary")
	dx.RegisterCanary(execCanary)
	execURL := fmt.Sprintf("http://%s/?mode=confirm_exec#%s", serverAddr, execCanary)
	if err := chromedp.Do(inst.Ctx, chromedp.Navigate(execURL), chromedp.Sleep(300*time.Millisecond)); err != nil {
		t.Fatalf("Navigation failed: %v", err)
	}

	// Assertions
	unsafe := dx.GetUnsafeFindings()
	var foundEval, foundTimeout, foundFn, foundConfirmedExec bool
	for _, f := range unsafe {
		if f.CanaryToken == evalCanary && f.SinkType == SinkEval {
			foundEval = true
		}
		if f.CanaryToken == timeoutCanary && f.SinkType == SinkSetTimeout {
			foundTimeout = true
		}
		if f.CanaryToken == fnCanary && f.SinkType == SinkFunction {
			foundFn = true
		}
		if f.CanaryToken == execCanary && f.Classification == ClassificationConfirmedExec {
			foundConfirmedExec = true
		}
	}

	if !foundEval {
		t.Errorf("Expected eval sink to be identified and classified unsafe")
	}
	if !foundTimeout {
		t.Errorf("Expected setTimeout sink to be identified and classified unsafe")
	}
	if !foundFn {
		t.Errorf("Expected Function constructor sink to be identified and classified unsafe")
	}
	if !foundConfirmedExec {
		t.Errorf("Expected CONFIRMED_EXECUTION classification for controlled sentinel signal")
	}

	t.Logf("Case D PASS: Successfully validated eval, setTimeout, Function, and CONFIRMED_EXECUTION signals")
}

func TestDOMXSSCaseE_FailureAndLifecycle(t *testing.T) {
	serverAddr, cleanupServer := setupDOMXSSServer(t)
	defer cleanupServer()

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	// 1. Verify bounded event recording
	boundedOpts := DefaultDOMXSSOptions()
	boundedOpts.MaxEvents = 5

	inst, err := Launch(ctx, DefaultConfig())
	if err != nil {
		t.Fatalf("Launch failed: %v", err)
	}
	defer inst.Close()

	dx, err := AttachDOMXSSInstrumenter(ctx, inst, boundedOpts)
	if err != nil {
		t.Fatalf("AttachDOMXSSInstrumenter failed: %v", err)
	}
	defer dx.Stop()

	// Trigger 15 rapid innerHTML writes
	floodScript := `(function() {
		for (let i = 0; i < 15; i++) {
			document.getElementById('sink-vuln-html').innerHTML = 'flood_' + i;
		}
	})()`

	targetURL := fmt.Sprintf("http://%s/", serverAddr)
	if err := chromedp.Do(inst.Ctx, chromedp.Navigate(targetURL), chromedp.Evaluate[chromedp.Void](floodScript), chromedp.Sleep(200*time.Millisecond)); err != nil {
		t.Fatalf("Evaluation failed: %v", err)
	}

	findings := dx.GetFindings()
	if len(findings) > 5 {
		t.Errorf("MaxEvents limit exceeded: expected <= 5, got %d", len(findings))
	}
	t.Logf("Event volume bounded successfully: %d events recorded (cap: 5)", len(findings))

	// 2. Verify clean Stop without panic
	dx.Stop()
	dx.Stop() // idempotent

	t.Logf("Case E PASS: Lifecycle boundaries, event capping, and idempotent cleanup verified")
}

func TestDOMXSSMonkeyIntegration(t *testing.T) {
	serverAddr, cleanupServer := setupDOMXSSServer(t)
	defer cleanupServer()

	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()

	inst, err := Launch(ctx, DefaultConfig())
	if err != nil {
		t.Fatalf("Launch failed: %v", err)
	}
	defer inst.Close()

	// 1. Attach DOM XSS Instrumenter (Phase 1.4)
	dx, err := AttachDOMXSSInstrumenter(ctx, inst, DefaultDOMXSSOptions())
	if err != nil {
		t.Fatalf("AttachDOMXSSInstrumenter failed: %v", err)
	}
	defer dx.Stop()

	canary := GenerateCanaryToken("felix_monkey_canary")
	dx.RegisterCanary(canary)

	// 2. Attach DOM Monkey Simulator (Phase 1.3)
	monkeyCfg := DefaultMonkeyConfig()
	monkeyCfg.MaxDepth = 2
	monkeyCfg.ActionDelay = 100 * time.Millisecond
	monkeyCfg.SyntheticInputs["text"] = canary // Injected into form input by monkey
	monkey, err := NewDOMMonkey(inst, monkeyCfg)
	if err != nil {
		t.Fatalf("NewDOMMonkey failed: %v", err)
	}
	defer monkey.Stop()

	// 3. Navigate to controlled interactive fixture (mode=monkey_interactive)
	// In this mode, no sinks execute on initial page load; action requires user/monkey interaction
	targetURL := fmt.Sprintf("http://%s/?mode=monkey_interactive#%s", serverAddr, canary)
	if err := chromedp.Do(inst.Ctx, chromedp.Navigate(targetURL), chromedp.Sleep(200*time.Millisecond)); err != nil {
		t.Fatalf("Navigation failed: %v", err)
	}

	// Verify precondition: zero canary findings prior to monkey interaction
	initialFindings := dx.GetFindings()
	for _, f := range initialFindings {
		if f.CanaryToken == canary {
			t.Fatalf("Precondition failed: canary observed before monkey executed any action")
		}
	}

	// 4. Run DOM Monkey execution
	report, err := monkey.Execute(ctx)
	if err != nil {
		t.Fatalf("Monkey execution error: %v", err)
	}

	// 5. Verification 1: Verify monkey executed at least one real action
	if report.TotalActions <= 0 {
		t.Fatalf("FAILED: DOM Monkey executed 0 actions (expected >= 1)")
	}

	// 6. Verification 2: Verify action caused intended state transition in the fixture
	stateText, err := chromedp.Run(inst.Ctx, chromedp.Evaluate[string]("document.getElementById('monkey-state-status').textContent"))
	if err != nil {
		t.Fatalf("Failed to read fixture state indicator: %v", err)
	}
	if stateText != "transition_completed" {
		t.Fatalf("FAILED: Fixture state transition did not occur (expected 'transition_completed', got %q)", stateText)
	}

	// 7. Verification 3: Verify XSS instrumentation captured resulting sink event during session
	findings := dx.GetFindings()
	var matchedFinding *SinkFinding
	for _, f := range findings {
		if f.CanaryToken == canary && f.SinkType == SinkInnerHTML {
			matchedFinding = f
			break
		}
	}

	if matchedFinding == nil {
		t.Fatalf("FAILED: DOM XSS engine failed to capture sink event correlating to canary %q (total findings: %d)", canary, len(findings))
	}

	if matchedFinding.Classification != ClassificationPotentiallyUnsafe {
		t.Errorf("Expected sink classification %s, got %s", ClassificationPotentiallyUnsafe, matchedFinding.Classification)
	}

	t.Logf("Monkey Integration PASS: DOM Monkey executed %d actions across %d layers; state transitioned to %q; XSS engine captured sink %s with canary %s",
		report.TotalActions, report.MaxDepthReached, stateText, matchedFinding.SinkType, matchedFinding.CanaryToken)
}
