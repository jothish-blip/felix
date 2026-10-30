package browser

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"iter"
	"strings"
	"sync"
	"time"

	"github.com/chromedp/cdproto/cdp"
	"github.com/chromedp/cdproto/page"
	"github.com/chromedp/cdproto/runtime"
	"github.com/chromedp/chromedp"
)

// SinkType categorizes browser DOM sinks capable of executing arbitrary script or HTML injection.
type SinkType string

const (
	SinkInnerHTML       SinkType = "Element.innerHTML"
	SinkOuterHTML       SinkType = "Element.outerHTML"
	SinkInsertAdjacent  SinkType = "Element.insertAdjacentHTML"
	SinkDocumentWrite   SinkType = "document.write"
	SinkDocumentWriteln SinkType = "document.writeln"
	SinkEval            SinkType = "eval"
	SinkFunction        SinkType = "Function"
	SinkSetTimeout      SinkType = "setTimeout"
	SinkSetInterval     SinkType = "setInterval"
	SinkLocationHref    SinkType = "location.href"
	SinkLocationAssign  SinkType = "location.assign"
	SinkLocationReplace SinkType = "location.replace"
	SinkExecutionMarker SinkType = "execution_marker"
)

// FlowClassification distinguishes evidence confidence levels for observed sink interactions.
type FlowClassification string

const (
	// ClassificationSinkObserved indicates a sink API was called without any monitored test canary.
	ClassificationSinkObserved FlowClassification = "SINK_OBSERVED"

	// ClassificationCanaryReachedSink indicates a controlled canary reached an active sink.
	ClassificationCanaryReachedSink FlowClassification = "CANARY_REACHED_SINK"

	// ClassificationPotentiallyUnsafe indicates a canary reached an executable sink without adequate sanitization.
	ClassificationPotentiallyUnsafe FlowClassification = "POTENTIALLY_UNSAFE_FLOW"

	// ClassificationConfirmedExec indicates a harmless test payload produced an explicit execution marker.
	ClassificationConfirmedExec FlowClassification = "CONFIRMED_EXECUTION"

	// ClassificationSafeOrEncoded indicates a canary was safely entity-encoded or rendered as inert text.
	ClassificationSafeOrEncoded FlowClassification = "SAFE_OR_ENCODED"
)

// RawSinkPayload models the JSON payload dispatched by the in-browser hook.
type RawSinkPayload struct {
	Sink      string `json:"sink"`
	Value     string `json:"value"`
	Stack     string `json:"stack"`
	URL       string `json:"url"`
	Timestamp string `json:"timestamp"`
}

// SinkFinding encapsulates an audited DOM sink observation with canary correlation.
type SinkFinding struct {
	SinkType       SinkType           `json:"sink_type"`
	Classification FlowClassification `json:"classification"`
	CanaryToken    string             `json:"canary_token,omitempty"`
	RawValue       string             `json:"raw_value"`
	CallStack      string             `json:"call_stack,omitempty"`
	SourceURL      string             `json:"source_url"`
	Timestamp      time.Time          `json:"timestamp"`
	IsExecutable   bool               `json:"is_executable"`
	Notes          string             `json:"notes,omitempty"`
}

// DOMXSSOptions configures sink instrumentation and event bounding.
type DOMXSSOptions struct {
	// MaxEvents caps the maximum number of sink invocations recorded per session (prevents memory exhaustion).
	MaxEvents int

	// TruncateValueAt sets the maximum string length stored per sink value.
	TruncateValueAt int

	// BindingName defines the unique window binding identifier for CDP communication.
	BindingName string
}

// DefaultDOMXSSOptions returns standard hardened defaults.
func DefaultDOMXSSOptions() DOMXSSOptions {
	return DOMXSSOptions{
		MaxEvents:       250,
		TruncateValueAt: 1024,
		BindingName:     "__felix_dom_xss_sink__",
	}
}

// DOMXSSInstrumenter hooks into Chromium CDP to intercept, correlate, and analyze DOM XSS sinks.
type DOMXSSInstrumenter struct {
	inst      *Instance
	opts      DOMXSSOptions
	ctx       context.Context
	cancel    context.CancelFunc
	mu        sync.RWMutex
	canaries  map[string]struct{}
	findings  []*SinkFinding
	scriptID  page.ScriptIdentifier
	closed    bool
}

// GenerateCanaryToken creates an inert, cryptographically random tracking token for taint tracing.
func GenerateCanaryToken(prefix string) string {
	if prefix == "" {
		prefix = "felix_dom_canary"
	}
	b := make([]byte, 6)
	_, _ = rand.Read(b)
	return fmt.Sprintf("%s_%x", prefix, b)
}

// AttachDOMXSSInstrumenter injects sink interception hooks before target scripts execute.
func AttachDOMXSSInstrumenter(parentCtx context.Context, inst *Instance, opts DOMXSSOptions) (*DOMXSSInstrumenter, error) {
	if inst == nil || inst.Ctx == nil {
		return nil, fmt.Errorf("invalid browser instance: context is nil")
	}

	if opts.MaxEvents <= 0 {
		opts.MaxEvents = 250
	}
	if opts.TruncateValueAt <= 0 {
		opts.TruncateValueAt = 1024
	}
	if opts.BindingName == "" {
		opts.BindingName = "__felix_dom_xss_sink__"
	}

	instCtx, instCancel := context.WithCancel(inst.Ctx)

	dx := &DOMXSSInstrumenter{
		inst:     inst,
		opts:     opts,
		ctx:      instCtx,
		cancel:   instCancel,
		canaries: make(map[string]struct{}),
		findings: make([]*SinkFinding, 0),
	}

	// 1. Enable Runtime and Page domains
	if _, err := chromedp.Call(inst.Ctx, runtime.Enable, cdp.Empty{}); err != nil {
		instCancel()
		return nil, fmt.Errorf("failed enabling CDP Runtime domain: %w", err)
	}
	if _, err := chromedp.Call(inst.Ctx, page.Enable, page.EnableParams{}); err != nil {
		instCancel()
		return nil, fmt.Errorf("failed enabling CDP Page domain: %w", err)
	}

	// 2. Establish bidirectional CDP binding for asynchronous sink telemetry
	if _, err := chromedp.Call(inst.Ctx, runtime.AddBinding, runtime.AddBindingParams{
		Name: opts.BindingName,
	}); err != nil {
		instCancel()
		return nil, fmt.Errorf("failed adding CDP runtime binding %q: %w", opts.BindingName, err)
	}

	// 3. Construct and inject the pre-document JavaScript instrumentation hook
	hookSource := buildHookScript(opts.BindingName, opts.TruncateValueAt)
	res, err := chromedp.Call(inst.Ctx, page.AddScriptToEvaluateOnNewDocument, page.AddScriptToEvaluateOnNewDocumentParams{
		Source: hookSource,
	})
	if err != nil {
		instCancel()
		return nil, fmt.Errorf("failed evaluating sink hook script on new document: %w", err)
	}
	dx.scriptID = res.Identifier

	// 4. Start background listener for Runtime.bindingCalled events
	bindingEvents := chromedp.Events(instCtx, runtime.BindingCalled)
	go dx.runBindingEventListener(bindingEvents)

	return dx, nil
}

// RegisterCanary registers a token to be actively tracked across all observed sink invocations.
func (dx *DOMXSSInstrumenter) RegisterCanary(token string) {
	if token == "" {
		return
	}
	dx.mu.Lock()
	defer dx.mu.Unlock()
	dx.canaries[token] = struct{}{}
}

func (dx *DOMXSSInstrumenter) runBindingEventListener(events iter.Seq2[runtime.EventBindingCalled, error]) {
	for ev, err := range events {
		if err != nil || dx.ctx.Err() != nil {
			return
		}

		if ev.Name != dx.opts.BindingName {
			continue
		}

		var payload RawSinkPayload
		if err := json.Unmarshal([]byte(ev.Payload), &payload); err != nil {
			continue
		}

		finding := dx.analyzeSinkPayload(payload)

		dx.mu.Lock()
		if len(dx.findings) < dx.opts.MaxEvents {
			dx.findings = append(dx.findings, finding)
		}
		dx.mu.Unlock()
	}
}

func (dx *DOMXSSInstrumenter) analyzeSinkPayload(payload RawSinkPayload) *SinkFinding {
	dx.mu.RLock()
	defer dx.mu.RUnlock()

	s := SinkType(payload.Sink)

	// Check if any registered canary matches the sink input
	var matchedCanary string
	for canary := range dx.canaries {
		if strings.Contains(payload.Value, canary) {
			matchedCanary = canary
			break
		}
	}

	finding := &SinkFinding{
		SinkType:    s,
		RawValue:    payload.Value,
		CallStack:   payload.Stack,
		SourceURL:   payload.URL,
		Timestamp:   time.Now(),
		CanaryToken: matchedCanary,
	}

	// Negative Control: Sink observed without monitored canary
	if matchedCanary == "" {
		finding.Classification = ClassificationSinkObserved
		finding.Notes = "Sink invoked during page operation without monitored canary"
		return finding
	}

	finding.Classification = ClassificationCanaryReachedSink

	// Evaluate context-aware executability
	switch s {
	case SinkExecutionMarker:
		finding.IsExecutable = true
		finding.Classification = ClassificationConfirmedExec
		finding.Notes = "Direct execution confirmed via controlled sentinel execution marker"

	case SinkEval, SinkFunction, SinkSetTimeout, SinkSetInterval:
		finding.IsExecutable = true
		finding.Classification = ClassificationPotentiallyUnsafe
		finding.Notes = fmt.Sprintf("Canary passed directly into code execution sink: %s", s)

	case SinkInnerHTML, SinkOuterHTML, SinkInsertAdjacent, SinkDocumentWrite, SinkDocumentWriteln:
		if isUnescapedHTML(payload.Value, matchedCanary) {
			finding.IsExecutable = true
			finding.Classification = ClassificationPotentiallyUnsafe
			finding.Notes = "Canary observed in unescaped HTML markup reaching DOM sink"
		} else if strings.Contains(payload.Value, "&lt;") && strings.Contains(payload.Value, "&gt;") {
			finding.IsExecutable = false
			finding.Classification = ClassificationSafeOrEncoded
			finding.Notes = "Canary observed in HTML sink with verified entity-escaping"
		} else {
			finding.IsExecutable = false
			finding.Classification = ClassificationCanaryReachedSink
			finding.Notes = "Canary observed in HTML sink without executable markup tags"
		}

	case SinkLocationHref, SinkLocationAssign, SinkLocationReplace:
		trimmed := strings.ToLower(strings.TrimSpace(payload.Value))
		if strings.HasPrefix(trimmed, "javascript:") {
			finding.IsExecutable = true
			finding.Classification = ClassificationPotentiallyUnsafe
			finding.Notes = "Canary supplied to javascript: pseudo-protocol navigation sink"
		} else {
			finding.IsExecutable = false
			finding.Classification = ClassificationSafeOrEncoded
			finding.Notes = "Standard web navigation target"
		}
	}

	return finding
}

func isUnescapedHTML(value, canary string) bool {
	// If the value contains raw unescaped HTML tag delimiters (< and >),
	// it parses executable HTML tags regardless of whether some entities also exist.
	hasRawTags := strings.Contains(value, "<") && strings.Contains(value, ">")
	return hasRawTags
}

// GetFindings returns a snapshot of all recorded DOM sink findings.
func (dx *DOMXSSInstrumenter) GetFindings() []*SinkFinding {
	dx.mu.RLock()
	defer dx.mu.RUnlock()
	copied := make([]*SinkFinding, len(dx.findings))
	copy(copied, dx.findings)
	return copied
}

// GetUnsafeFindings filters findings for instances where canaries reached executable sinks unescaped.
func (dx *DOMXSSInstrumenter) GetUnsafeFindings() []*SinkFinding {
	dx.mu.RLock()
	defer dx.mu.RUnlock()
	var unsafe []*SinkFinding
	for _, f := range dx.findings {
		if f.Classification == ClassificationPotentiallyUnsafe || f.Classification == ClassificationConfirmedExec {
			unsafe = append(unsafe, f)
		}
	}
	return unsafe
}

// ClearFindings clears the recorded sink history.
func (dx *DOMXSSInstrumenter) ClearFindings() {
	dx.mu.Lock()
	defer dx.mu.Unlock()
	dx.findings = make([]*SinkFinding, 0)
}

// Stop detaches the instrumenter and cleans up background workers.
func (dx *DOMXSSInstrumenter) Stop() {
	dx.mu.Lock()
	defer dx.mu.Unlock()
	if dx.closed {
		return
	}
	dx.closed = true
	if dx.cancel != nil {
		dx.cancel()
	}
}

func buildHookScript(bindingName string, truncateAt int) string {
	return fmt.Sprintf(`(function() {
		if (window.__felix_dom_xss_installed__) return;
		window.__felix_dom_xss_installed__ = true;

		function dispatch(sinkType, value) {
			try {
				if (typeof window['%s'] !== 'function') return;
				const str = typeof value === 'string' ? value : String(value || '');
				const safe = str.length > %d ? str.substring(0, %d) + '...[truncated]' : str;
				const stack = new Error().stack || '';
				window['%s'](JSON.stringify({
					sink: sinkType,
					value: safe,
					stack: stack,
					url: window.location.href,
					timestamp: new Date().toISOString()
				}));
			} catch(e) {}
		}

		// 1. Element.prototype.innerHTML
		try {
			const d = Object.getOwnPropertyDescriptor(Element.prototype, 'innerHTML');
			if (d && d.set) {
				Object.defineProperty(Element.prototype, 'innerHTML', {
					set: function(v) {
						dispatch('Element.innerHTML', v);
						return d.set.call(this, v);
					},
					get: function() { return d.get.call(this); },
					configurable: true,
					enumerable: true
				});
			}
		} catch(e) {}

		// 2. Element.prototype.outerHTML
		try {
			const d = Object.getOwnPropertyDescriptor(Element.prototype, 'outerHTML');
			if (d && d.set) {
				Object.defineProperty(Element.prototype, 'outerHTML', {
					set: function(v) {
						dispatch('Element.outerHTML', v);
						return d.set.call(this, v);
					},
					get: function() { return d.get.call(this); },
					configurable: true,
					enumerable: true
				});
			}
		} catch(e) {}

		// 3. Element.prototype.insertAdjacentHTML
		try {
			const orig = Element.prototype.insertAdjacentHTML;
			Element.prototype.insertAdjacentHTML = function(pos, text) {
				dispatch('Element.insertAdjacentHTML', text);
				return orig.apply(this, arguments);
			};
		} catch(e) {}

		// 4. document.write & document.writeln
		try {
			const origW = document.write;
			document.write = function() {
				dispatch('document.write', Array.prototype.slice.call(arguments).join(''));
				return origW.apply(this, arguments);
			};
			const origWln = document.writeln;
			document.writeln = function() {
				dispatch('document.writeln', Array.prototype.slice.call(arguments).join(''));
				return origWln.apply(this, arguments);
			};
		} catch(e) {}

		// 5. window.eval
		try {
			const origEval = window.eval;
			window.eval = function(code) {
				dispatch('eval', code);
				return origEval.apply(this, arguments);
			};
		} catch(e) {}

		// 6. window.setTimeout & setInterval (string handlers)
		try {
			const origST = window.setTimeout;
			window.setTimeout = function(h, t) {
				if (typeof h === 'string') dispatch('setTimeout', h);
				return origST.apply(this, arguments);
			};
			const origSI = window.setInterval;
			window.setInterval = function(h, t) {
				if (typeof h === 'string') dispatch('setInterval', h);
				return origSI.apply(this, arguments);
			};
		} catch(e) {}

		// 7. Function constructor
		try {
			const origF = window.Function;
			const pF = function() {
				const args = Array.prototype.slice.call(arguments);
				if (args.length > 0) dispatch('Function', args.join(';'));
				return origF.apply(this, arguments);
			};
			pF.prototype = origF.prototype;
			window.Function = pF;
		} catch(e) {}

		// 8. Controlled Execution Confirmation Sentinel
		try {
			window.__felix_confirm_exec__ = function(token) {
				dispatch('execution_marker', token);
			};
		} catch(e) {}

		// 9. Location navigation sinks (Location.prototype)
		try {
			const locProto = window.Location ? window.Location.prototype : null;
			if (locProto) {
				const dHref = Object.getOwnPropertyDescriptor(locProto, 'href');
				if (dHref && dHref.set) {
					Object.defineProperty(locProto, 'href', {
						set: function(v) {
							dispatch('location.href', v);
							return dHref.set.call(this, v);
						},
						get: function() { return dHref.get.call(this); },
						configurable: true,
						enumerable: true
					});
				}
				if (typeof locProto.assign === 'function') {
					const origAssign = locProto.assign;
					locProto.assign = function(u) {
						dispatch('location.assign', u);
						return origAssign.apply(this, arguments);
					};
				}
				if (typeof locProto.replace === 'function') {
					const origReplace = locProto.replace;
					locProto.replace = function(u) {
						dispatch('location.replace', u);
						return origReplace.apply(this, arguments);
					};
				}
			}
		} catch(e) {}
	})();`, bindingName, truncateAt, truncateAt, bindingName)
}
