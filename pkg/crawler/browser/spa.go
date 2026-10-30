package browser

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/chromedp/cdproto/runtime"
	"github.com/chromedp/chromedp"
)

// SPAStateType defines classifications for discovered SPA application states.
type SPAStateType string

const (
	StateNew          SPAStateType = "NEW_STATE"
	StateEquivalent   SPAStateType = "EQUIVALENT_STATE"
	StateInconclusive SPAStateType = "INCONCLUSIVE_STATE"
)

// TransitionStatus classifies the outcome of an attempted state transition.
type TransitionStatus string

const (
	TransitionCompleted     TransitionStatus = "COMPLETED"
	TransitionNoStateChange TransitionStatus = "NO_STATE_CHANGE"
	TransitionBlockedScope  TransitionStatus = "BLOCKED_SCOPE"
	TransitionBlockedPolicy TransitionStatus = "BLOCKED_DESTRUCTIVE"
	TransitionTimedOut      TransitionStatus = "TIMED_OUT"
	TransitionFailed        TransitionStatus = "FAILED"
	TransitionInconclusive  TransitionStatus = "INCONCLUSIVE"
)

// SPAState models an observed client-side application state.
type SPAState struct {
	ID                string       `json:"id"`                  // Deterministic SHA-256 fingerprint
	Route             string       `json:"route"`               // Normalized path or hash route (e.g. "/#/score-board")
	URL               string       `json:"url"`                 // Full browser URL
	Title             string       `json:"title"`               // Document title
	StructuralDigest  string       `json:"structural_digest"`   // Normalized DOM skeleton hash
	ActiveNavElement  string       `json:"active_nav,omitempty"`// Active tab, link, or navigation marker
	FormsCount        int          `json:"forms_count"`
	InteractiveCount  int          `json:"interactive_count"`
	Depth             int          `json:"depth"`
	DiscoveredAt      string       `json:"discovered_at"`
	IsSettled         bool         `json:"is_settled"`
	Framework         string       `json:"framework,omitempty"`
	Classification    SPAStateType `json:"classification"`
	Rationale         string       `json:"rationale"`
}

// SPATransition models an action leading from one state to another.
type SPATransition struct {
	FromStateID    string           `json:"from_state_id"`
	ToStateID      string           `json:"to_state_id,omitempty"`
	ActionType     string           `json:"action_type"`     // "click", "tab_select", "wizard_step", "history_navigate"
	TargetSelector string           `json:"target_selector"`
	TargetTag      string           `json:"target_tag"`
	TargetText     string           `json:"target_text"`
	ResultRoute    string           `json:"result_route"`
	MaterialChange bool             `json:"material_change"`
	Status         TransitionStatus `json:"status"`
	DurationMS     float64          `json:"duration_ms"`
	ErrorMessage   string           `json:"error_message,omitempty"`
	Rationale      string           `json:"rationale"`
	Timestamp      string           `json:"timestamp"`
}

// SPANavigatorConfig bounds SPA exploration to prevent hangs or endless loops.
type SPANavigatorConfig struct {
	MaxDepth                int
	MaxStates               int
	MaxTransitionsPerState  int
	TotalMaxTransitions     int
	SettleTimeout           time.Duration
	TransitionTimeout       time.Duration
	ExplorationTimeout      time.Duration
	AllowDestructiveActions bool
	AllowExternalNavigation bool
	SyntheticInputs         map[string]string
	InteractiveSelectors    []string
	DestructiveKeywords     []string
}

// DefaultSPANavigatorConfig returns hardened, bounded defaults for SPA exploration.
func DefaultSPANavigatorConfig() SPANavigatorConfig {
	return SPANavigatorConfig{
		MaxDepth:                4,
		MaxStates:               25,
		MaxTransitionsPerState:  8,
		TotalMaxTransitions:     40,
		SettleTimeout:           250 * time.Millisecond,
		TransitionTimeout:       3 * time.Second,
		ExplorationTimeout:      20 * time.Second,
		AllowDestructiveActions: false, // SAFE AUDIT: block destructive actions by default
		AllowExternalNavigation: false, // Scope guard: stay within target origin
		SyntheticInputs:         DefaultSyntheticInputs(),
		InteractiveSelectors: []string{
			"[role='tab']",
			"[role='link']",
			"[role='button']",
			"button",
			"a[href]",
			"[data-toggle]",
			"[data-action]",
			"[data-step]",
			".nav-link",
			".tab-btn",
			"summary",
		},
		DestructiveKeywords: []string{
			"delete", "remove", "destroy", "purge", "drop",
			"logout", "signout", "sign-out", "exit",
			"pay", "purchase", "checkout", "buy", "order",
		},
	}
}

// SPANavigationReport compiles the full exploration graph and metrics.
type SPANavigationReport struct {
	Origin               string           `json:"origin"`
	InitialRoute         string           `json:"initial_route"`
	TotalStates          int              `json:"total_states"`
	TotalTransitions     int              `json:"total_transitions"`
	CandidatesDiscovered int              `json:"candidates_discovered"`
	ActionsAttempted     int              `json:"actions_attempted"`
	CompletedTransitions int              `json:"completed_transitions"`
	NoOpTransitions      int              `json:"no_op_transitions"`
	BlockedActions       int              `json:"blocked_actions"`
	DuplicateStates      int              `json:"duplicate_states"`
	FailedTransitions    int              `json:"failed_transitions"`
	TimedOutTransitions  int              `json:"timed_out_transitions"`
	MaxDepthReached      int              `json:"max_depth_reached"`
	ExecutionDurationMS  float64          `json:"execution_duration_ms"`
	States               []*SPAState      `json:"states"`
	Transitions          []*SPATransition `json:"transitions"`
	Limitations          []string         `json:"limitations"`
}

// SPANavigator orchestrates bounded client-side exploration across single-page applications.
type SPANavigator struct {
	inst     *Instance
	cfg      SPANavigatorConfig
	origin   string
	mu       sync.Mutex
	history  []string
}

// NewSPANavigator creates a new SPA State Navigator bound to an active browser instance.
func NewSPANavigator(inst *Instance, cfg SPANavigatorConfig) (*SPANavigator, error) {
	if inst == nil || inst.Ctx == nil {
		return nil, fmt.Errorf("invalid browser instance: context is nil")
	}

	if cfg.MaxDepth <= 0 {
		cfg.MaxDepth = 4
	}
	if cfg.MaxStates <= 0 {
		cfg.MaxStates = 25
	}
	if cfg.MaxTransitionsPerState <= 0 {
		cfg.MaxTransitionsPerState = 8
	}
	if cfg.TotalMaxTransitions <= 0 {
		cfg.TotalMaxTransitions = 40
	}
	if cfg.SettleTimeout <= 0 {
		cfg.SettleTimeout = 250 * time.Millisecond
	}
	if cfg.TransitionTimeout <= 0 {
		cfg.TransitionTimeout = 3 * time.Second
	}
	if cfg.ExplorationTimeout <= 0 {
		cfg.ExplorationTimeout = 20 * time.Second
	}
	if len(cfg.SyntheticInputs) == 0 {
		cfg.SyntheticInputs = DefaultSyntheticInputs()
	}
	if len(cfg.InteractiveSelectors) == 0 {
		cfg.InteractiveSelectors = DefaultSPANavigatorConfig().InteractiveSelectors
	}
	if len(cfg.DestructiveKeywords) == 0 {
		cfg.DestructiveKeywords = DefaultSPANavigatorConfig().DestructiveKeywords
	}

	return &SPANavigator{
		inst: inst,
		cfg:  cfg,
	}, nil
}

type rawDOMSnapshot struct {
	URL              string   `json:"url"`
	Route            string   `json:"route"`
	Title            string   `json:"title"`
	DOMSkeleton      string   `json:"dom_skeleton"`
	ActiveNav        string   `json:"active_nav"`
	FormsCount       int      `json:"forms_count"`
	InteractiveCount int      `json:"interactive_count"`
	IsSettled        bool     `json:"is_settled"`
	Framework        string   `json:"framework"`
	CandidateCount   int      `json:"candidate_count"`
	Candidates       []rawCandidate `json:"candidates"`
}

type rawCandidate struct {
	Tag         string `json:"tag"`
	Selector    string `json:"selector"`
	Text        string `json:"text"`
	Role        string `json:"role"`
	ActionType  string `json:"action_type"`
	IsExternal  bool   `json:"is_external"`
	IsDestruct  bool   `json:"is_destructive"`
}

// captureSnapshotScript executes in browser context to inspect structure, routes, and active controls.
const captureSnapshotScript = `(function(selectors, destructiveKeywords) {
	function normalizeRoute() {
		const u = new URL(window.location.href);
		let r = u.pathname;
		if (u.hash) {
			r += u.hash;
		}
		// Strip volatile query params (e.g. timestamps, nonces, session markers)
		const cleanParams = new URLSearchParams();
		u.searchParams.forEach((v, k) => {
			const lk = k.toLowerCase();
			if (!lk.startsWith('ts') && !lk.startsWith('_t') && !lk.startsWith('nonce') && !lk.startsWith('cache')) {
				cleanParams.append(k, v);
			}
		});
		const qs = cleanParams.toString();
		return qs ? r + '?' + qs : r;
	}

	function isVisible(el) {
		if (!el) return false;
		const style = window.getComputedStyle(el);
		if (style.display === 'none' || style.visibility === 'hidden' || style.opacity === '0') return false;
		if (el.offsetParent === null && style.position !== 'fixed') return false;
		return true;
	}

	// 1. DOM structural skeleton (semantic landmarks, containers, panels, wizard steps, form controls)
	const landmarks = [
		'main', 'section', 'article', 'nav', 'header', 'dialog', 'form',
		'[role="tabpanel"]', '.view-container', '#view-content', '.panel',
		'.wizard-step', '.step', '[data-step-container]', 'fieldset',
		'input:not([type="hidden"])', 'select', 'textarea'
	];
	const structuralTags = [];
	document.querySelectorAll(landmarks.join(', ')).forEach(el => {
		if (isVisible(el)) {
			const tag = el.tagName.toLowerCase();
			const idPart = el.id ? '#' + el.id : '';
			const rolePart = el.getAttribute('role') ? '[' + el.getAttribute('role') + ']' : '';
			const classPart = el.className && typeof el.className === 'string' ? '.' + el.className.trim().split(/\s+/).slice(0, 2).join('.') : '';
			structuralTags.push(tag + idPart + rolePart + classPart);
		}
	});

	// 2. Active navigation / selected tab indicator
	let activeNav = '';
	const activeEl = document.querySelector('[aria-selected="true"], [aria-expanded="true"], .nav-link.active, .tab.active, .btn-active');
	if (activeEl && isVisible(activeEl)) {
		activeNav = (activeEl.id ? '#' + activeEl.id : '') + '[' + (activeEl.innerText || activeEl.getAttribute('aria-label') || '').trim().substring(0, 30) + ']';
	}

	// 3. Hydration & Settled state detection
	let isSettled = true;
	const loader = document.querySelector('#loading-indicator, .spinner, .loader, [data-state="loading"]');
	if (loader && isVisible(loader)) {
		isSettled = false;
	}

	let framework = 'vanilla';
	if (window.getAllAngularTestabilities || window.angular || document.querySelector('[ng-version], [ng-app], app-root')) {
		framework = 'angular';
	} else if (document.querySelector('#root, [data-reactroot]') || window.__REACT_DEVTOOLS_GLOBAL_HOOK__) {
		framework = 'react';
	} else if (window.__VUE__ || document.querySelector('#app[data-v-]')) {
		framework = 'vue';
	}

	// 4. Candidate interactive controls extraction
	const candidates = [];
	const selectorStr = selectors.join(', ');
	document.querySelectorAll(selectorStr).forEach((el, idx) => {
		if (!isVisible(el)) return;
		const tag = el.tagName.toLowerCase();
		const text = (el.innerText || el.value || el.getAttribute('title') || el.getAttribute('aria-label') || '').trim().substring(0, 60);

		// Build stable selector
		let sel = '';
		if (el.id) {
			sel = '#' + el.id;
		} else if (el.getAttribute('data-action')) {
			sel = '[data-action="' + el.getAttribute('data-action') + '"]';
		} else if (el.getAttribute('data-step')) {
			sel = '[data-step="' + el.getAttribute('data-step') + '"]';
		} else if (el.getAttribute('role')) {
			sel = tag + '[role="' + el.getAttribute('role') + '"]:nth-of-type(' + (idx + 1) + ')';
		} else {
			sel = tag + ':nth-of-type(' + (idx + 1) + ')';
		}

		// Check external navigation
		let isExternal = false;
		if (tag === 'a' && el.hostname && el.hostname !== window.location.hostname) {
			isExternal = true;
		}

		// Check destructive keyword
		const lowerText = text.toLowerCase();
		const lowerSel = sel.toLowerCase();
		let isDestruct = false;
		for (const kw of destructiveKeywords) {
			if (lowerText.includes(kw) || lowerSel.includes(kw)) {
				isDestruct = true;
				break;
			}
		}

		let actionType = 'click';
		if (el.getAttribute('role') === 'tab' || el.classList.contains('tab-btn')) {
			actionType = 'tab_select';
		} else if (el.getAttribute('data-step')) {
			actionType = 'wizard_step';
		} else if (tag === 'a') {
			actionType = 'navigate_link';
		}

		candidates.push({
			tag: tag,
			selector: sel,
			text: text,
			role: el.getAttribute('role') || '',
			action_type: actionType,
			is_external: isExternal,
			is_destructive: isDestruct
		});
	});

	return JSON.stringify({
		url: window.location.href,
		route: normalizeRoute(),
		title: document.title || '',
		dom_skeleton: structuralTags.join(' > '),
		active_nav: activeNav,
		forms_count: document.querySelectorAll('form').length,
		interactive_count: candidates.length,
		is_settled: isSettled,
		framework: framework,
		candidate_count: candidates.length,
		candidates: candidates
	});
})`

// captureState captures a normalized snapshot of the active page and computes its deterministic ID.
func (sn *SPANavigator) captureState(ctx context.Context, depth int) (*SPAState, []rawCandidate, error) {
	selJSON, _ := json.Marshal(sn.cfg.InteractiveSelectors)
	kwJSON, _ := json.Marshal(sn.cfg.DestructiveKeywords)

	script := fmt.Sprintf("%s(%s, %s)", captureSnapshotScript, string(selJSON), string(kwJSON))

	tTrue := true
	evalRes, err := chromedp.Call(sn.inst.Ctx, runtime.Evaluate, runtime.EvaluateParams{
		Expression:    script,
		AwaitPromise:  &tTrue,
		ReturnByValue: &tTrue,
	})
	if err != nil {
		return nil, nil, fmt.Errorf("failed evaluating SPA snapshot: %w", err)
	}

	var rawJSON string
	if evalRes.Result != nil && len(evalRes.Result.Value) > 0 {
		_ = json.Unmarshal(evalRes.Result.Value, &rawJSON)
	}

	var snapshot rawDOMSnapshot
	if err := json.Unmarshal([]byte(rawJSON), &snapshot); err != nil {
		return nil, nil, fmt.Errorf("failed unmarshaling SPA snapshot payload: %w", err)
	}

	// Deterministic fingerprint: SHA-256 of Route + DOMSkeleton + ActiveNav
	h := sha256.New()
	h.Write([]byte(snapshot.Route))
	h.Write([]byte("|"))
	h.Write([]byte(snapshot.DOMSkeleton))
	h.Write([]byte("|"))
	h.Write([]byte(snapshot.ActiveNav))
	stateID := hex.EncodeToString(h.Sum(nil))[:16]

	state := &SPAState{
		ID:               stateID,
		Route:            snapshot.Route,
		URL:              snapshot.URL,
		Title:            snapshot.Title,
		StructuralDigest: snapshot.DOMSkeleton,
		ActiveNavElement: snapshot.ActiveNav,
		FormsCount:       snapshot.FormsCount,
		InteractiveCount: snapshot.InteractiveCount,
		Depth:            depth,
		DiscoveredAt:     time.Now().UTC().Format(time.RFC3339),
		IsSettled:        snapshot.IsSettled,
		Framework:        snapshot.Framework,
		Classification:   StateNew,
		Rationale:        fmt.Sprintf("Discovered at depth %d (Route: %s, Landmarks: %s)", depth, snapshot.Route, snapshot.DOMSkeleton),
	}

	return state, snapshot.Candidates, nil
}

// Explore navigates the single-page application using BFS work queue with safety and bounded limits.
func (sn *SPANavigator) Explore(parentCtx context.Context) (*SPANavigationReport, error) {
	startTime := time.Now()

	exploreCtx, cancel := context.WithTimeout(parentCtx, sn.cfg.ExplorationTimeout)
	defer cancel()

	// Resolve origin
	currentOrigin, _ := chromedp.Run(sn.inst.Ctx, chromedp.Evaluate[string]("window.location.origin"))
	sn.origin = currentOrigin

	// Capture initial state
	initState, initCandidates, err := sn.captureState(exploreCtx, 0)
	if err != nil {
		return nil, fmt.Errorf("failed capturing initial SPA state: %w", err)
	}

	report := &SPANavigationReport{
		Origin:              sn.origin,
		InitialRoute:        initState.Route,
		States:              make([]*SPAState, 0),
		Transitions:         make([]*SPATransition, 0),
		Limitations: []string{
			"Shadow DOM closed roots are not pierced during querySelector traversal",
			"WebGL and canvas-drawn UI controls lack DOM elements and require coordinate simulation",
			"Destructive actions (delete, purge, logout, pay) are safely blocked by default policy",
		},
	}

	visitedStates := make(map[string]*SPAState)
	visitedStates[initState.ID] = initState
	report.States = append(report.States, initState)

	type stateWorkItem struct {
		state      *SPAState
		candidates []rawCandidate
		depth      int
	}

	queue := []*stateWorkItem{
		{state: initState, candidates: initCandidates, depth: 0},
	}

	seenStateActions := make(map[string]struct{})
	totalTransitions := 0
	highestDepth := 0
	duplicateCount := 0
	blockedCount := 0
	candidatesDiscovered := len(initCandidates)
	actionsAttempted := 0
	completedTransitions := 0
	noOpTransitions := 0
	failedTransitions := 0
	timedOutTransitions := 0

	for len(queue) > 0 && len(visitedStates) < sn.cfg.MaxStates && totalTransitions < sn.cfg.TotalMaxTransitions {
		if exploreCtx.Err() != nil {
			break
		}

		current := queue[0]
		queue = queue[1:]

		if current.depth > highestDepth {
			highestDepth = current.depth
		}

		// Step count for this state
		actionsFromState := 0

		for _, cand := range current.candidates {
			if exploreCtx.Err() != nil || totalTransitions >= sn.cfg.TotalMaxTransitions || actionsFromState >= sn.cfg.MaxTransitionsPerState || len(visitedStates) >= sn.cfg.MaxStates {
				break
			}

			actionKey := current.state.ID + "::" + cand.Selector
			if _, exists := seenStateActions[actionKey]; exists {
				continue
			}
			seenStateActions[actionKey] = struct{}{}

			t0 := time.Now()

			// Safety Check 1: Out of Scope navigation
			if cand.IsExternal {
				blockedCount++
				totalTransitions++
				report.Transitions = append(report.Transitions, &SPATransition{
					FromStateID:    current.state.ID,
					ActionType:     cand.ActionType,
					TargetSelector: cand.Selector,
					TargetTag:      cand.Tag,
					TargetText:     cand.Text,
					Status:         TransitionBlockedScope,
					MaterialChange: false,
					DurationMS:     float64(time.Since(t0).Milliseconds()),
					Rationale:      fmt.Sprintf("Blocked external target navigation to preserve authorized scope: %s", cand.Selector),
					Timestamp:      time.Now().UTC().Format(time.RFC3339),
				})
				continue
			}

			// Safety Check 2: Destructive action policy
			if cand.IsDestruct && !sn.cfg.AllowDestructiveActions {
				blockedCount++
				totalTransitions++
				report.Transitions = append(report.Transitions, &SPATransition{
					FromStateID:    current.state.ID,
					ActionType:     cand.ActionType,
					TargetSelector: cand.Selector,
					TargetTag:      cand.Tag,
					TargetText:     cand.Text,
					Status:         TransitionBlockedPolicy,
					MaterialChange: false,
					DurationMS:     float64(time.Since(t0).Milliseconds()),
					Rationale:      fmt.Sprintf("Blocked potentially destructive action (%q) under safe audit policy", cand.Text),
					Timestamp:      time.Now().UTC().Format(time.RFC3339),
				})
				continue
			}

			// Execute Transition
			transOutcome, nextState, nextCandidates := sn.executeTransition(exploreCtx, current.state, cand, current.depth+1)
			actionsAttempted++
			totalTransitions++
			actionsFromState++

			switch transOutcome.Status {
			case TransitionCompleted:
				completedTransitions++
			case TransitionNoStateChange:
				noOpTransitions++
			case TransitionBlockedScope, TransitionBlockedPolicy:
				blockedCount++
			case TransitionTimedOut:
				timedOutTransitions++
			case TransitionFailed, TransitionInconclusive:
				failedTransitions++
			}

			report.Transitions = append(report.Transitions, transOutcome)

			if transOutcome.Status == TransitionCompleted && nextState != nil {
				if _, exists := visitedStates[nextState.ID]; !exists {
					if len(visitedStates) < sn.cfg.MaxStates {
						// Discovered a brand-new distinct state within bounds
						visitedStates[nextState.ID] = nextState
						report.States = append(report.States, nextState)
						candidatesDiscovered += len(nextCandidates)

						if current.depth+1 < sn.cfg.MaxDepth {
							queue = append(queue, &stateWorkItem{
								state:      nextState,
								candidates: nextCandidates,
								depth:      current.depth + 1,
							})
						}
					}
				} else {
					duplicateCount++
				}
			}
		}
	}

	report.TotalStates = len(visitedStates)
	report.TotalTransitions = len(report.Transitions)
	report.CandidatesDiscovered = candidatesDiscovered
	report.ActionsAttempted = actionsAttempted
	report.CompletedTransitions = completedTransitions
	report.NoOpTransitions = noOpTransitions
	report.BlockedActions = blockedCount
	report.DuplicateStates = duplicateCount
	report.FailedTransitions = failedTransitions
	report.TimedOutTransitions = timedOutTransitions
	report.MaxDepthReached = highestDepth
	report.ExecutionDurationMS = float64(time.Since(startTime).Milliseconds())

	return report, nil
}

// executeTransition executes a trusted click/interaction and measures resulting state changes.
func (sn *SPANavigator) executeTransition(ctx context.Context, fromState *SPAState, cand rawCandidate, newDepth int) (*SPATransition, *SPAState, []rawCandidate) {
	t0 := time.Now()

	// 1. Dispatch interaction script
	clickScript := fmt.Sprintf(`(function(sel) {
		const el = document.querySelector(sel);
		if (!el) return 'element_not_found';
		try {
			el.focus();
			el.dispatchEvent(new MouseEvent('mouseover', { bubbles: true, cancelable: true }));
			el.dispatchEvent(new MouseEvent('mousedown', { bubbles: true, cancelable: true }));
			el.dispatchEvent(new MouseEvent('mouseup', { bubbles: true, cancelable: true }));
			el.click();
			return 'ok';
		} catch(err) {
			return String(err);
		}
	})('%s')`, cand.Selector)

	transCtx, cancel := context.WithTimeout(ctx, sn.cfg.TransitionTimeout)
	defer cancel()

	res, err := chromedp.Run(sn.inst.Ctx, chromedp.Evaluate[string](clickScript))
	if err != nil {
		return &SPATransition{
			FromStateID:    fromState.ID,
			ActionType:     cand.ActionType,
			TargetSelector: cand.Selector,
			TargetTag:      cand.Tag,
			TargetText:     cand.Text,
			Status:         TransitionFailed,
			MaterialChange: false,
			DurationMS:     float64(time.Since(t0).Milliseconds()),
			ErrorMessage:   err.Error(),
			Rationale:      fmt.Sprintf("Failed dispatching interaction: %v", err),
			Timestamp:      time.Now().UTC().Format(time.RFC3339),
		}, nil, nil
	}

	if res != "ok" {
		return &SPATransition{
			FromStateID:    fromState.ID,
			ActionType:     cand.ActionType,
			TargetSelector: cand.Selector,
			TargetTag:      cand.Tag,
			TargetText:     cand.Text,
			Status:         TransitionFailed,
			MaterialChange: false,
			DurationMS:     float64(time.Since(t0).Milliseconds()),
			ErrorMessage:   res,
			Rationale:      fmt.Sprintf("Interaction script returned error: %s", res),
			Timestamp:      time.Now().UTC().Format(time.RFC3339),
		}, nil, nil
	}

	// 2. Wait for settle condition (settle timeout or framework completion)
	select {
	case <-transCtx.Done():
		return &SPATransition{
			FromStateID:    fromState.ID,
			ActionType:     cand.ActionType,
			TargetSelector: cand.Selector,
			TargetTag:      cand.Tag,
			TargetText:     cand.Text,
			Status:         TransitionTimedOut,
			MaterialChange: false,
			DurationMS:     float64(time.Since(t0).Milliseconds()),
			Rationale:      "Transition exceeded configured transition timeout",
			Timestamp:      time.Now().UTC().Format(time.RFC3339),
		}, nil, nil
	case <-time.After(sn.cfg.SettleTimeout):
	}

	// 3. Capture new state
	newState, candidates, err := sn.captureState(ctx, newDepth)
	if err != nil {
		return &SPATransition{
			FromStateID:    fromState.ID,
			ActionType:     cand.ActionType,
			TargetSelector: cand.Selector,
			TargetTag:      cand.Tag,
			TargetText:     cand.Text,
			Status:         TransitionInconclusive,
			MaterialChange: false,
			DurationMS:     float64(time.Since(t0).Milliseconds()),
			ErrorMessage:   err.Error(),
			Rationale:      fmt.Sprintf("Failed capturing resulting state: %v", err),
			Timestamp:      time.Now().UTC().Format(time.RFC3339),
		}, nil, nil
	}

	// 4. Scope validation on resulting navigation
	durMS := float64(time.Since(t0).Milliseconds())
	if !sn.cfg.AllowExternalNavigation && sn.origin != "" && newState.URL != "" {
		newURL, pErr := url.Parse(newState.URL)
		origURL, oErr := url.Parse(sn.origin)
		if pErr == nil && oErr == nil && newURL.Host != "" && origURL.Host != "" {
			if !strings.EqualFold(newURL.Host, origURL.Host) {
				return &SPATransition{
					FromStateID:    fromState.ID,
					ActionType:     cand.ActionType,
					TargetSelector: cand.Selector,
					TargetTag:      cand.Tag,
					TargetText:     cand.Text,
					ResultRoute:    newState.Route,
					Status:         TransitionBlockedScope,
					MaterialChange: false,
					DurationMS:     durMS,
					Rationale:      fmt.Sprintf("Client interaction redirected out of scope to external host %s", newURL.Host),
					Timestamp:      time.Now().UTC().Format(time.RFC3339),
				}, nil, nil
			}
		}
	}

	// 5. Compare with fromState
	if newState.ID == fromState.ID {
		// Completed interaction with no material state change
		return &SPATransition{
			FromStateID:    fromState.ID,
			ToStateID:      fromState.ID,
			ActionType:     cand.ActionType,
			TargetSelector: cand.Selector,
			TargetTag:      cand.Tag,
			TargetText:     cand.Text,
			ResultRoute:    newState.Route,
			MaterialChange: false,
			Status:         TransitionNoStateChange,
			DurationMS:     durMS,
			Rationale:      "Interaction produced no structural DOM, route, or active panel change (idempotent/no-op)",
			Timestamp:      time.Now().UTC().Format(time.RFC3339),
		}, newState, candidates
	}

	// Material state change detected
	return &SPATransition{
		FromStateID:    fromState.ID,
		ToStateID:      newState.ID,
		ActionType:     cand.ActionType,
		TargetSelector: cand.Selector,
		TargetTag:      cand.Tag,
		TargetText:     cand.Text,
		ResultRoute:    newState.Route,
		MaterialChange: true,
		Status:         TransitionCompleted,
		DurationMS:     durMS,
		Rationale:      fmt.Sprintf("Material state transition observed (Route: %s -> %s)", fromState.Route, newState.Route),
		Timestamp:      time.Now().UTC().Format(time.RFC3339),
	}, newState, candidates
}
