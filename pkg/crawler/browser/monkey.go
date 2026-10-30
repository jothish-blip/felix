package browser

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/chromedp/cdproto/page"
	"github.com/chromedp/chromedp"
)

// InteractionRecord logs a single DOM interaction executed by the monkey simulator.
type InteractionRecord struct {
	Layer       int    `json:"layer"`
	ActionIndex int    `json:"action_index"`
	ActionType  string `json:"action_type"`
	TagName     string `json:"tag_name"`
	ElementID   string `json:"element_id"`
	Selector    string `json:"selector"`
	TextContent string `json:"text_content"`
	Timestamp   string `json:"timestamp"`
	Success     bool   `json:"success"`
	ErrorMsg    string `json:"error_msg,omitempty"`
}

// MonkeyReport records metrics and execution traces from a DOM Monkey session.
type MonkeyReport struct {
	MaxDepthReached     int                  `json:"max_depth_reached"`
	TotalActions        int                  `json:"total_actions"`
	FormsFilled         int                  `json:"forms_filled"`
	DialogsHandled      int                  `json:"dialogs_handled"`
	DialogMessages      []string             `json:"dialog_messages"`
	Interactions        []*InteractionRecord `json:"interactions"`
	ExecutionDurationMS float64              `json:"execution_duration_ms"`
}

// MonkeyConfig configures event simulation, interaction depth, and timeouts.
type MonkeyConfig struct {
	// MaxDepth specifies how many hierarchical DOM discovery cycles to execute (minimum 3).
	MaxDepth int

	// MaxActionsPerLayer bounds the actions executed per discovered DOM depth level.
	MaxActionsPerLayer int

	// TotalMaxActions caps overall interactions across the session.
	TotalMaxActions int

	// ActionDelay is the settling duration after each interaction to allow DOM rendering / network dispatch.
	ActionDelay time.Duration

	// AllowDestructiveConfirmations determines whether window.confirm() modals are accepted.
	// Default is false (safe audit mode: reject all destructive confirmation gates).
	AllowDestructiveConfirmations bool

	// AllowFormSubmissions authorizes automated dispatch of synthetic form payloads.
	AllowFormSubmissions bool

	// SessionTimeout defines the maximum duration permitted for DOM monkey interaction (default: 30s).
	SessionTimeout time.Duration

	// SyntheticInputs maps input types to realistic security audit canary payloads.
	SyntheticInputs map[string]string

	// InteractiveSelectors defines CSS query rules for finding interactive elements.
	InteractiveSelectors []string
}

// DefaultSyntheticInputs returns standard payloads for form discovery.
func DefaultSyntheticInputs() map[string]string {
	return map[string]string{
		"email":    "auditor@felix-sec.org",
		"password": "FelixP@ssw0rd!123",
		"text":     "felix_input_probe",
		"search":   "felix_canary_probe",
		"number":   "42",
		"tel":      "555-0199",
		"url":      "https://felix-sec.org",
		"date":     "2026-10-28",
	}
}

// DefaultInteractiveSelectors returns comprehensive query selectors for interactive DOM targets.
func DefaultInteractiveSelectors() []string {
	return []string{
		"button",
		"input[type='button']",
		"input[type='submit']",
		"input[type='reset']",
		"a[href]",
		"[role='button']",
		"[role='tab']",
		"[role='link']",
		"[role='menuitem']",
		"[onclick]",
		"[ng-click]",
		"[data-action]",
		"[data-toggle]",
		"[data-target]",
		"summary",
	}
}

// DefaultMonkeyConfig returns hardened production settings for the DOM Monkey.
func DefaultMonkeyConfig() MonkeyConfig {
	return MonkeyConfig{
		MaxDepth:                      3,
		MaxActionsPerLayer:            50,
		TotalMaxActions:               150,
		ActionDelay:                   100 * time.Millisecond,
		AllowDestructiveConfirmations: false, // SAFE AUDIT DEFAULT: block destructive confirm dialogs
		AllowFormSubmissions:          true,
		SessionTimeout:                30 * time.Second,
		SyntheticInputs:               DefaultSyntheticInputs(),
		InteractiveSelectors:          DefaultInteractiveSelectors(),
	}
}

// DOMMonkey orchestrates blind, automated DOM event simulation to uncover dynamic SPA attack surfaces.
type DOMMonkey struct {
	inst           *Instance
	cfg            MonkeyConfig
	ctx            context.Context
	cancel         context.CancelFunc
	mu             sync.Mutex
	dialogsHandled int32
	dialogHistory  []string
	interactions   []*InteractionRecord
	formsFilled    int32
	currentDepth   int
	closed         bool
}

// NewDOMMonkey creates and initializes a DOM Monkey simulator bound to a browser instance.
func NewDOMMonkey(inst *Instance, cfg MonkeyConfig) (*DOMMonkey, error) {
	if inst == nil || inst.Ctx == nil {
		return nil, fmt.Errorf("invalid browser instance: context is nil")
	}

	if cfg.MaxDepth <= 0 {
		cfg.MaxDepth = 3
	}
	if cfg.MaxActionsPerLayer <= 0 {
		cfg.MaxActionsPerLayer = 50
	}
	if cfg.TotalMaxActions <= 0 {
		cfg.TotalMaxActions = 150
	}
	if cfg.ActionDelay <= 0 {
		cfg.ActionDelay = 100 * time.Millisecond
	}
	if len(cfg.SyntheticInputs) == 0 {
		cfg.SyntheticInputs = DefaultSyntheticInputs()
	}
	if len(cfg.InteractiveSelectors) == 0 {
		cfg.InteractiveSelectors = DefaultInteractiveSelectors()
	}

	monkeyCtx, monkeyCancel := context.WithCancel(inst.Ctx)

	m := &DOMMonkey{
		inst:   inst,
		cfg:    cfg,
		ctx:    monkeyCtx,
		cancel: monkeyCancel,
	}

	// 1. Enable Page domain and trap all JavaScript modal dialogs
	if err := m.startDialogTrap(); err != nil {
		monkeyCancel()
		return nil, fmt.Errorf("failed to enable CDP dialog auto-trap: %w", err)
	}

	return m, nil
}

// startDialogTrap listens for page.JavascriptDialogOpening and auto-accepts/dismisses dialogs.
func (m *DOMMonkey) startDialogTrap() error {
	if _, err := chromedp.Call(m.inst.Ctx, page.Enable, page.EnableParams{}); err != nil {
		return err
	}

	dialogEvents := chromedp.Events(m.ctx, page.JavascriptDialogOpening)
	go func() {
		for ev, err := range dialogEvents {
			if err != nil || m.ctx.Err() != nil {
				return
			}
			m.mu.Lock()
			atomic.AddInt32(&m.dialogsHandled, 1)
			m.dialogHistory = append(m.dialogHistory, fmt.Sprintf("[%s] %s", ev.Type, ev.Message))

			// Safe Audit Dialog Policy:
			// - Alert: Accept (clear dialog)
			// - Confirm: Reject by default (prevent destructive actions) unless explicitly authorized
			// - Prompt: Reject by default
			shouldAccept := true
			if ev.Type == page.DialogTypeConfirm {
				shouldAccept = m.cfg.AllowDestructiveConfirmations
			} else if ev.Type == page.DialogTypePrompt {
				shouldAccept = false
			}
			m.mu.Unlock()

			_, _ = chromedp.Call(m.inst.Ctx, page.HandleJavaScriptDialog, page.HandleJavaScriptDialogParams{
				Accept:     shouldAccept,
				PromptText: "felix_auto",
			})
		}
	}()

	return nil
}

// Execute performs iterative, multi-layer DOM event simulation up to cfg.MaxDepth using BFS staging.
func (m *DOMMonkey) Execute(ctx context.Context) (*MonkeyReport, error) {
	startTime := time.Now()
	totalActions := 0
	highestLayer := 0

	for layer := 1; layer <= m.cfg.MaxDepth; layer++ {
		if ctx.Err() != nil || m.ctx.Err() != nil {
			break
		}

		// Step 1: Fill any newly visible synthetic inputs
		filled, _ := m.fillFormInputs()
		if filled > 0 {
			atomic.AddInt32(&m.formsFilled, int32(filled))
		}

		// Step 2: Snapshot interactive candidates specifically for this layer
		stagedCount, err := m.stageLayerCandidates(layer)
		if err != nil {
			break
		}

		// If no elements exist for this layer and no forms were filled, hierarchy is exhausted
		if stagedCount == 0 && filled == 0 {
			break
		}

		highestLayer = layer
		m.currentDepth = layer
		layerActions := 0

		// Step 3: Interactively click through elements staged specifically for this layer
		for layerActions < m.cfg.MaxActionsPerLayer && totalActions < m.cfg.TotalMaxActions {
			if ctx.Err() != nil || m.ctx.Err() != nil {
				break
			}

			rec, err := m.interactNextStagedCandidate(layer, totalActions+1)
			if err != nil {
				// Element reference stale or JS error; continue to next staged element
				continue
			}
			if rec == nil {
				// All staged elements in this layer have been interacted with
				break
			}

			m.mu.Lock()
			m.interactions = append(m.interactions, rec)
			m.mu.Unlock()

			layerActions++
			totalActions++

			// Settle delay allowing async network calls and DOM mutations to reveal next layer
			select {
			case <-ctx.Done():
				goto FINISH
			case <-m.ctx.Done():
				goto FINISH
			case <-time.After(m.cfg.ActionDelay):
			}
		}
	}

FINISH:
	m.mu.Lock()
	defer m.mu.Unlock()

	return &MonkeyReport{
		MaxDepthReached:     highestLayer,
		TotalActions:        totalActions,
		FormsFilled:         int(atomic.LoadInt32(&m.formsFilled)),
		DialogsHandled:      int(atomic.LoadInt32(&m.dialogsHandled)),
		DialogMessages:      append([]string{}, m.dialogHistory...),
		Interactions:        append([]*InteractionRecord{}, m.interactions...),
		ExecutionDurationMS: float64(time.Since(startTime).Milliseconds()),
	}, nil
}

// stageLayerCandidates snapshots all currently visible, unvisited elements and binds them to the specified layer.
func (m *DOMMonkey) stageLayerCandidates(layer int) (int, error) {
	selectorsJSON, err := json.Marshal(m.cfg.InteractiveSelectors)
	if err != nil {
		return 0, err
	}

	script := fmt.Sprintf(`(function(selectors, layer) {
		const selectorStr = selectors.join(', ');
		const all = Array.from(document.querySelectorAll(selectorStr));
		let staged = 0;

		all.forEach(el => {
			if (el.getAttribute('data-felix-interacted') === 'true') return;
			if (el.getAttribute('data-felix-layer')) return;

			// Visibility check
			const style = window.getComputedStyle(el);
			if (style.display === 'none' || style.visibility === 'hidden' || style.opacity === '0') return;
			if (el.offsetParent === null && style.position !== 'fixed') return;

			el.setAttribute('data-felix-layer', String(layer));
			staged++;
		});

		return staged;
	})(%s, %d)`, string(selectorsJSON), layer)

	return chromedp.Run(m.inst.Ctx, chromedp.Evaluate[int](script))
}

// fillFormInputs finds and populates unfilled input/textarea/select controls with synthetic payloads.
func (m *DOMMonkey) fillFormInputs() (int, error) {
	inputsJSON, err := json.Marshal(m.cfg.SyntheticInputs)
	if err != nil {
		return 0, err
	}

	script := fmt.Sprintf(`(function(config) {
		const inputs = document.querySelectorAll('input:not([data-felix-filled]), textarea:not([data-felix-filled]), select:not([data-felix-filled])');
		let count = 0;
		inputs.forEach(el => {
			try {
				const tag = el.tagName.toLowerCase();
				const type = (el.getAttribute('type') || 'text').toLowerCase();
				if (type === 'hidden' || type === 'submit' || type === 'button' || type === 'reset') return;

				let val = config[type] || config['text'] || 'felix_probe';
				if (type === 'checkbox' || type === 'radio') {
					el.checked = true;
				} else if (tag === 'select') {
					if (el.options && el.options.length > 1) {
						el.selectedIndex = 1;
					}
				} else {
					el.value = val;
				}
				el.dispatchEvent(new Event('input', { bubbles: true }));
				el.dispatchEvent(new Event('change', { bubbles: true }));
				el.setAttribute('data-felix-filled', 'true');
				count++;
			} catch(e) {}
		});
		return count;
	})(%s)`, string(inputsJSON))

	return chromedp.Run(m.inst.Ctx, chromedp.Evaluate[int](script))
}

// interactNextStagedCandidate finds the next staged element for the given layer and executes a trusted click.
func (m *DOMMonkey) interactNextStagedCandidate(layer, actionIndex int) (*InteractionRecord, error) {
	selectorsJSON, err := json.Marshal(m.cfg.InteractiveSelectors)
	if err != nil {
		return nil, err
	}

	script := fmt.Sprintf(`(function(selectors, layer, actionIndex) {
		const selectorStr = selectors.join(', ');
		const all = Array.from(document.querySelectorAll(selectorStr));

		// Find next un-interacted element specifically staged for this layer
		const target = all.find(el => {
			return el.getAttribute('data-felix-layer') === String(layer) &&
			       el.getAttribute('data-felix-interacted') !== 'true';
		});

		if (!target) return null;

		target.setAttribute('data-felix-interacted', 'true');

		// Prevent external domain navigation
		if (target.tagName === 'A') {
			const href = target.getAttribute('href');
			if (href && (href.startsWith('mailto:') || href.startsWith('tel:') || href.startsWith('javascript:void(0)'))) {
				// safe
			} else if (target.hostname && target.hostname !== window.location.hostname) {
				return {
					layer: layer,
					action_index: actionIndex,
					action_type: 'skip_external',
					tag_name: 'a',
					element_id: target.id || '',
					selector: 'a[external]',
					text_content: target.innerText || '',
					timestamp: new Date().toISOString(),
					success: true
				};
			}
		}

		const info = {
			layer: layer,
			action_index: actionIndex,
			action_type: 'click',
			tag_name: target.tagName.toLowerCase(),
			element_id: target.id || '',
			selector: target.id ? '#' + target.id : (target.className && typeof target.className === 'string' ? '.' + target.className.trim().split(/\s+/).join('.') : target.tagName.toLowerCase()),
			text_content: (target.innerText || target.value || target.getAttribute('title') || '').substring(0, 60).trim(),
			timestamp: new Date().toISOString(),
			success: true
		};

		try {
			target.focus();
			target.dispatchEvent(new MouseEvent('mouseover', { bubbles: true, cancelable: true, view: window }));
			target.dispatchEvent(new MouseEvent('mousedown', { bubbles: true, cancelable: true, view: window }));
			target.dispatchEvent(new MouseEvent('mouseup', { bubbles: true, cancelable: true, view: window }));
			target.click();
		} catch (err) {
			info.success = false;
			info.error_msg = String(err);
		}

		return info;
	})(%s, %d, %d)`, string(selectorsJSON), layer, actionIndex)

	return chromedp.Run(m.inst.Ctx, chromedp.Evaluate[*InteractionRecord](script))
}

// Stop cleanly terminates the DOM Monkey background workers.
func (m *DOMMonkey) Stop() {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return
	}
	m.closed = true
	if m.cancel != nil {
		m.cancel()
	}
}
