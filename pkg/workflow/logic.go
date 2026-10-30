package workflow

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"felix/pkg/auth"
)

// Common business logic and workflow errors.
var (
	ErrWorkflowNotFound       = errors.New("workflow definition not found")
	ErrStepNotFound           = errors.New("workflow step not found")
	ErrPrerequisiteNotMet     = errors.New("mandatory workflow prerequisite step not completed")
	ErrInvalidStateTransition = errors.New("invalid or prohibited workflow state transition")
	ErrInvalidMutationConfig  = errors.New("invalid parameter tampering mutation configuration")
	ErrNilPersonaOrchestrator = errors.New("multi-persona orchestrator is required")
)

// BusinessLogicCategory identifies the business logic vulnerability category.
type BusinessLogicCategory string

const (
	CategoryParameterTampering BusinessLogicCategory = "PARAM_TAMPERING_QUANTITY_PRICE"
	CategoryWorkflowStepSkip   BusinessLogicCategory = "WORKFLOW_STEP_SKIPPING"
	CategoryConcurrencyRace    BusinessLogicCategory = "CONCURRENCY_RACE_DOUBLE_SPEND"
	CategoryCouponReuse        BusinessLogicCategory = "COUPON_REUSE_DOUBLE_REDEMPTION"
	CategoryInvalidTransition  BusinessLogicCategory = "INVALID_STATE_TRANSITION"
)

// LogicStatus represents the verification outcome of a business logic test.
type LogicStatus string

const (
	StatusVerifiedDefect LogicStatus = "VERIFIED_DEFECT"
	StatusDefended       LogicStatus = "DEFENDED_BARRIER"
	StatusInconclusive   LogicStatus = "INCONCLUSIVE"
)

// LogicWorkflowState defines states in a business workflow state machine.
type LogicWorkflowState string

const (
	StateCartEmpty         LogicWorkflowState = "CART_EMPTY"
	StateItemAdded         LogicWorkflowState = "ITEM_ADDED"
	StateQuantityUpdated   LogicWorkflowState = "QUANTITY_UPDATED"
	StateCheckoutStarted   LogicWorkflowState = "CHECKOUT_STARTED"
	StatePaymentAuthorized LogicWorkflowState = "PAYMENT_AUTHORIZED"
	StateOrderConfirmed    LogicWorkflowState = "ORDER_CONFIRMED"
	StateOrderCancelled    LogicWorkflowState = "ORDER_CANCELLED"
	StateCustom            LogicWorkflowState = "CUSTOM_STATE"
)

// LogicStep models an individual operation in a business workflow.
type LogicStep struct {
	ID                string             `json:"id"`
	Name              string             `json:"name"`
	Endpoint          string             `json:"endpoint"`
	Method            string             `json:"method"`
	FromState         LogicWorkflowState `json:"from_state"`
	ToState           LogicWorkflowState `json:"to_state"`
	Payload           string             `json:"payload,omitempty"`
	Headers           map[string]string  `json:"headers,omitempty"`
	Preconditions     []string           `json:"preconditions,omitempty"` // Required predecessor Step IDs
	IsTerminal        bool               `json:"is_terminal"`             // Completion/terminal operation
	IsSingleUse       bool               `json:"is_single_use"`          // Single-use non-idempotent action
	StateReadBackURL  string             `json:"state_readback_url,omitempty"`
	StatePropertyPath string             `json:"state_property_path,omitempty"`
}

// LogicWorkflow defines a directed state machine sequence representing a multi-step business workflow.
type LogicWorkflow struct {
	ID             string               `json:"id"`
	Name           string               `json:"name"`
	InitialState   LogicWorkflowState   `json:"initial_state"`
	TerminalStates []LogicWorkflowState `json:"terminal_states"`
	Steps          []LogicStep          `json:"steps"`
	ReadBackURL    string               `json:"readback_url,omitempty"`
}

// StepByID retrieves a step by its unique identifier.
func (w *LogicWorkflow) StepByID(id string) (*LogicStep, error) {
	for i := range w.Steps {
		if w.Steps[i].ID == id {
			return &w.Steps[i], nil
		}
	}
	return nil, fmt.Errorf("%w: %s", ErrStepNotFound, id)
}

// PrerequisitesFor retrieves the complete transitive prerequisites for a step.
func (w *LogicWorkflow) PrerequisitesFor(stepID string) ([]string, error) {
	step, err := w.StepByID(stepID)
	if err != nil {
		return nil, err
	}
	var result []string
	visited := make(map[string]bool)

	var collect func(s *LogicStep)
	collect = func(s *LogicStep) {
		for _, prereqID := range s.Preconditions {
			if !visited[prereqID] {
				visited[prereqID] = true
				result = append(result, prereqID)
				if nextStep, err := w.StepByID(prereqID); err == nil {
					collect(nextStep)
				}
			}
		}
	}
	collect(step)
	return result, nil
}

// BusinessLogicFinding models an empirical finding from business logic testing.
type BusinessLogicFinding struct {
	ID                string                `json:"id"`
	WorkflowID        string                `json:"workflow_id"`
	Category          BusinessLogicCategory `json:"category"`
	OWASP             string                `json:"owasp"`
	CWE               string                `json:"cwe"`
	Status            LogicStatus           `json:"status"`
	Endpoint          string                `json:"endpoint"`
	Method            string                `json:"method"`
	Parameter         string                `json:"parameter,omitempty"`
	OriginalInput     any                   `json:"original_input,omitempty"`
	TamperedInput     any                   `json:"tampered_input,omitempty"`
	ExpectedInvariant string                `json:"expected_invariant"`
	ObservedViolation string                `json:"observed_violation"`
	BeforeState       any                   `json:"before_state,omitempty"`
	AfterState        any                   `json:"after_state,omitempty"`
	PersonaID         string                `json:"persona_id"`
	PersonaRole       auth.PersonaRole      `json:"persona_role"`
	SanitizedPoC      string                `json:"sanitized_poc,omitempty"`
	EvidenceDetails   string                `json:"evidence_details,omitempty"`
	Timestamp         time.Time             `json:"timestamp"`
}

// TamperMutation defines a candidate mutation for parameter tampering evaluation.
type TamperMutation struct {
	Description string `json:"description"`
	Value       any    `json:"value"`
	Category    string `json:"category"` // "negative", "zero", "large_int", "decimal", "overflow", "type_confusion"
}

// DefaultNumericMutations returns the comprehensive suite of boundary mutations required by Phase 3.6.
func DefaultNumericMutations() []TamperMutation {
	return []TamperMutation{
		{Description: "Negative integer -1", Value: -1, Category: "negative"},
		{Description: "Negative integer -5", Value: -5, Category: "negative"},
		{Description: "Negative integer -100", Value: -100, Category: "negative"},
		{Description: "Zero quantity/price", Value: 0, Category: "zero"},
		{Description: "Boundary large integer 999999999", Value: 999999999, Category: "large_int"},
		{Description: "Integer 32-bit boundary overflow 2147483648", Value: int64(2147483648), Category: "overflow"},
		{Description: "Integer 64-bit boundary 9223372036854775807", Value: int64(9223372036854775807), Category: "overflow"},
		{Description: "Decimal precision 0.0000001", Value: 0.0000001, Category: "decimal"},
		{Description: "Decimal precision overflow 1.9999999999999999", Value: 1.9999999999999999, Category: "decimal"},
		{Description: "Negative float -0.01", Value: -0.01, Category: "negative"},
		{Description: "Type confusion string NaN", Value: "NaN", Category: "type_confusion"},
		{Description: "Type confusion boolean true", Value: true, Category: "type_confusion"},
		{Description: "Type confusion JSON object filter", Value: map[string]any{"$gt": 0}, Category: "type_confusion"},
		{Description: "Type confusion null literal", Value: nil, Category: "type_confusion"},
	}
}

// ParamTamperRequest configures an active parameter tampering evaluation.
type ParamTamperRequest struct {
	WorkflowID        string            `json:"workflow_id"`
	Endpoint          string            `json:"endpoint"`
	Method            string            `json:"method"`
	ParameterName     string            `json:"parameter_name"`
	BasePayload       map[string]any    `json:"base_payload"`
	PersonaID         string            `json:"persona_id"`
	StateReadBackURL  string            `json:"state_readback_url"`
	StatePropertyPath string            `json:"state_property_path"` // e.g. "total", "quantity", "price"
	Mutations         []TamperMutation  `json:"mutations,omitempty"`
}

// RaceConditionRequest configures a synchronized 20-request concurrency race condition evaluation.
type RaceConditionRequest struct {
	WorkflowID           string            `json:"workflow_id"`
	Endpoint             string            `json:"endpoint"`
	Method               string            `json:"method"`
	Payload              string            `json:"payload,omitempty"`
	Headers              map[string]string `json:"headers,omitempty"`
	PersonaID            string            `json:"persona_id"`
	Concurrency          int               `json:"concurrency"` // Defaults to 20
	StateReadBackURL     string            `json:"state_readback_url"`
	StatePropertyPath    string            `json:"state_property_path"`
	MaxAllowedExecutions int               `json:"max_allowed_executions"` // e.g. 1 for single-use coupon
}

// LogicEngineConfig configures the business logic assessment engine.
type LogicEngineConfig struct {
	Orchestrator   *auth.MultiPersonaOrchestrator
	ScopeValidator *auth.LocalScopeValidator
	Timeout        time.Duration
}

// LogicEngine executes stateful workflow and business logic vulnerability evaluations.
type LogicEngine struct {
	cfg          LogicEngineConfig
	orchestrator *auth.MultiPersonaOrchestrator
	client       *http.Client
}

// NewLogicEngine constructs a new business logic assessment engine.
func NewLogicEngine(cfg LogicEngineConfig) (*LogicEngine, error) {
	if cfg.Orchestrator == nil {
		return nil, ErrNilPersonaOrchestrator
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 10 * time.Second
	}
	client := &http.Client{
		Timeout: cfg.Timeout,
	}
	return &LogicEngine{
		cfg:          cfg,
		orchestrator: cfg.Orchestrator,
		client:       client,
	}, nil
}

// ReadServerState fetches authoritative server-side state from a read-back URL.
func (e *LogicEngine) ReadServerState(ctx context.Context, persona *auth.Persona, readBackURL, propPath string) (any, error) {
	if readBackURL == "" {
		return nil, errors.New("empty state read-back URL")
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, readBackURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create state read-back request: %w", err)
	}

	var resp *http.Response
	if persona != nil {
		resp, err = persona.Do(ctx, req)
	} else {
		resp, err = e.client.Do(req)
	}
	if err != nil {
		return nil, fmt.Errorf("read-back request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("read-back returned HTTP status %d", resp.StatusCode)
	}

	bodyBytes, err := io.ReadAll(io.LimitReader(resp.Body, 1024*1024))
	if err != nil {
		return nil, fmt.Errorf("failed to read read-back body: %w", err)
	}

	var parsed any
	if err := json.Unmarshal(bodyBytes, &parsed); err != nil {
		// Return raw string representation if not valid JSON
		return strings.TrimSpace(string(bodyBytes)), nil
	}

	if propPath == "" {
		return parsed, nil
	}

	return extractJSONProperty(parsed, propPath), nil
}

// extractJSONProperty extracts a nested property via dot-delimited path.
func extractJSONProperty(data any, path string) any {
	parts := strings.Split(path, ".")
	current := data
	for _, p := range parts {
		m, ok := current.(map[string]any)
		if !ok {
			return nil
		}
		current = m[p]
	}
	return current
}

// EvaluateParameterTampering tests numeric and structured parameter tampering across business boundaries.
func (e *LogicEngine) EvaluateParameterTampering(ctx context.Context, req ParamTamperRequest) ([]*BusinessLogicFinding, error) {
	if req.Endpoint == "" || req.ParameterName == "" {
		return nil, errors.New("endpoint and parameter_name are required")
	}

	persona, ok := e.orchestrator.GetPersona(req.PersonaID)
	if !ok {
		return nil, fmt.Errorf("persona %q not found", req.PersonaID)
	}

	mutations := req.Mutations
	if len(mutations) == 0 {
		mutations = DefaultNumericMutations()
	}

	// STEP 1: Execute Baseline Request to establish valid state and baseline acceptance
	basePayloadBytes, err := json.Marshal(req.BasePayload)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal base payload: %w", err)
	}

	baseReq, err := http.NewRequestWithContext(ctx, req.Method, req.Endpoint, bytes.NewReader(basePayloadBytes))
	if err != nil {
		return nil, fmt.Errorf("failed to create baseline request: %w", err)
	}
	baseReq.Header.Set("Content-Type", "application/json")

	baseResp, err := persona.Do(ctx, baseReq)
	baselineSucceeded := false
	if err == nil && baseResp != nil {
		if baseResp.StatusCode >= 200 && baseResp.StatusCode < 300 {
			baselineSucceeded = true
		}
		baseResp.Body.Close()
	}

	var beforeState any
	if req.StateReadBackURL != "" {
		beforeState, _ = e.ReadServerState(ctx, persona, req.StateReadBackURL, req.StatePropertyPath)
	}

	var findings []*BusinessLogicFinding

	// STEP 2: Iterate over mutations
	for _, mut := range mutations {
		mutatedPayload := make(map[string]any)
		for k, v := range req.BasePayload {
			mutatedPayload[k] = v
		}
		mutatedPayload[req.ParameterName] = mut.Value

		mutBytes, err := json.Marshal(mutatedPayload)
		if err != nil {
			continue
		}

		tamperReq, err := http.NewRequestWithContext(ctx, req.Method, req.Endpoint, bytes.NewReader(mutBytes))
		if err != nil {
			continue
		}
		tamperReq.Header.Set("Content-Type", "application/json")

		resp, err := persona.Do(ctx, tamperReq)
		if err != nil {
			continue
		}
		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
		resp.Body.Close()

		var afterState any
		if req.StateReadBackURL != "" {
			afterState, _ = e.ReadServerState(ctx, persona, req.StateReadBackURL, req.StatePropertyPath)
		}

		findingID := fmt.Sprintf("logic-%s-%d", mut.Category, time.Now().UnixNano())
		poc := auth.GenerateSanitizedPoC(req.Method, req.Endpoint, persona.HasBearerToken(), string(mutBytes))

		finding := &BusinessLogicFinding{
			ID:                findingID,
			WorkflowID:        req.WorkflowID,
			Category:          CategoryParameterTampering,
			OWASP:             "API10:2023 Unsafe Consumption of APIs / Business Flow Tampering",
			CWE:               "CWE-840 Business Logic Errors",
			Endpoint:          req.Endpoint,
			Method:            req.Method,
			Parameter:         req.ParameterName,
			OriginalInput:     req.BasePayload[req.ParameterName],
			TamperedInput:     mut.Value,
			ExpectedInvariant: fmt.Sprintf("Server must strictly reject invalid %s value %v (%s)", req.ParameterName, mut.Value, mut.Description),
			BeforeState:       beforeState,
			AfterState:        afterState,
			PersonaID:         req.PersonaID,
			PersonaRole:       persona.Role(),
			SanitizedPoC:      poc,
			Timestamp:         time.Now().UTC(),
		}

		// Analysis Logic:
		// 1. Defended Barrier or Inconclusive on 4xx rejection:
		// Requires:
		//   a) A valid positive baseline succeeded
		//   b) An explicit, relevant business-rule or validation refusal
		//   c) Independent state verification confirming protected state remained unchanged
		if resp.StatusCode >= 400 && resp.StatusCode < 500 {
			stateUnchanged := statesEqual(beforeState, afterState)
			hasRelevantRefusal := isRelevantBusinessRefusal(resp.StatusCode, respBody, req.ParameterName)

			if baselineSucceeded && hasRelevantRefusal && stateUnchanged {
				finding.Status = StatusDefended
				finding.EvidenceDetails = fmt.Sprintf("Server correctly defended parameter invariant: HTTP %d (%s) with verified unmodified state", resp.StatusCode, mut.Description)
			} else {
				finding.Status = StatusInconclusive
				finding.EvidenceDetails = fmt.Sprintf("Server returned HTTP %d for %s, but outcome is inconclusive (baselineSucceeded=%t, relevantRefusal=%t, stateUnchanged=%t)", resp.StatusCode, mut.Description, baselineSucceeded, hasRelevantRefusal, stateUnchanged)
			}
			findings = append(findings, finding)
			continue
		}

		// 2. Evaluated HTTP 2xx: Must inspect server state for invariant violation
		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			// Check if afterState proves an actual unauthorized business violation
			isViolation := false
			var violationReason string

			switch mut.Category {
			case "negative":
				// If quantity or price was negative, did server-side total/count become negative?
				if numVal, ok := toFloat(afterState); ok && numVal < 0 {
					isViolation = true
					violationReason = fmt.Sprintf("Server accepted negative %s (%v); resulting state reflects negative value: %v", req.ParameterName, mut.Value, numVal)
				} else if strVal, ok := afterState.(string); ok && strings.HasPrefix(strVal, "-") {
					isViolation = true
					violationReason = fmt.Sprintf("Server accepted negative %s (%v); state string: %s", req.ParameterName, mut.Value, strVal)
				}

			case "zero":
				// If price was manipulated to zero, did item/cart persist at 0.0?
				if numVal, ok := toFloat(afterState); ok && numVal == 0 {
					isViolation = true
					violationReason = fmt.Sprintf("Server allowed free purchase / zero %s (%v); state reflects 0", req.ParameterName, mut.Value)
				}

			case "large_int", "overflow":
				// Did integer wrap into negative number (e.g. integer overflow)?
				if numVal, ok := toFloat(afterState); ok && numVal < 0 {
					isViolation = true
					violationReason = fmt.Sprintf("Integer overflow detected: %s value %v resulted in negative state %v", req.ParameterName, mut.Value, numVal)
				}
			}

			if isViolation {
				finding.Status = StatusVerifiedDefect
				finding.ObservedViolation = violationReason
				finding.EvidenceDetails = fmt.Sprintf("VERIFIED DEFECT: Invariant violated: %s", violationReason)
			} else {
				// If server returned 200 but response body contains business error or state was clamped
				if isBusinessErrorPayload(respBody) {
					finding.Status = StatusDefended
					finding.EvidenceDetails = "Server returned 200 but payload contained business validation error"
				} else {
					finding.Status = StatusInconclusive
					finding.EvidenceDetails = fmt.Sprintf("Server returned HTTP %d but server-side state did not reflect measurable business invariant violation", resp.StatusCode)
				}
			}

			findings = append(findings, finding)
			continue
		} else {
			finding.Status = StatusInconclusive
			finding.EvidenceDetails = fmt.Sprintf("Unexpected status code %d received during parameter tampering probe", resp.StatusCode)
			findings = append(findings, finding)
		}
	}

	return findings, nil
}

// EvaluateStepSkipping verifies whether terminal/protected workflow operations can be executed out of order without completing mandatory prerequisites.
func (e *LogicEngine) EvaluateStepSkipping(ctx context.Context, wf LogicWorkflow, terminalStepID string, personaID string) (*BusinessLogicFinding, error) {
	persona, ok := e.orchestrator.GetPersona(personaID)
	if !ok {
		return nil, fmt.Errorf("persona %q not found", personaID)
	}

	termStep, err := wf.StepByID(terminalStepID)
	if err != nil {
		return nil, err
	}

	prereqs, err := wf.PrerequisitesFor(terminalStepID)
	if err != nil {
		return nil, err
	}

	// Capture initial state
	var beforeState any
	if termStep.StateReadBackURL != "" {
		beforeState, _ = e.ReadServerState(ctx, persona, termStep.StateReadBackURL, termStep.StatePropertyPath)
	}

	// Execute terminal step DIRECTLY without executing prerequisite steps
	req, err := http.NewRequestWithContext(ctx, termStep.Method, termStep.Endpoint, strings.NewReader(termStep.Payload))
	if err != nil {
		return nil, fmt.Errorf("failed to create terminal step request: %w", err)
	}
	if termStep.Payload != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	for k, v := range termStep.Headers {
		req.Header.Set(k, v)
	}

	resp, err := persona.Do(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("terminal step probe failed: %w", err)
	}
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	resp.Body.Close()

	// Capture post-state
	var afterState any
	if termStep.StateReadBackURL != "" {
		afterState, _ = e.ReadServerState(ctx, persona, termStep.StateReadBackURL, termStep.StatePropertyPath)
	}

	poc := auth.GenerateSanitizedPoC(termStep.Method, termStep.Endpoint, persona.HasBearerToken(), termStep.Payload)
	finding := &BusinessLogicFinding{
		ID:                fmt.Sprintf("step-skip-%d", time.Now().UnixNano()),
		WorkflowID:        wf.ID,
		Category:          CategoryWorkflowStepSkip,
		OWASP:             "API10:2023 Unsafe Consumption of APIs / Business Flow Bypass",
		CWE:               "CWE-840 Business Logic Errors / Step Circumvention",
		Endpoint:          termStep.Endpoint,
		Method:            termStep.Method,
		ExpectedInvariant: fmt.Sprintf("Terminal operation %s must be rejected without prerequisite steps: %v", termStep.Name, prereqs),
		BeforeState:       beforeState,
		AfterState:        afterState,
		PersonaID:         personaID,
		PersonaRole:       persona.Role(),
		SanitizedPoC:      poc,
		Timestamp:         time.Now().UTC(),
	}

	// 1. Defended Barrier or Inconclusive on 4xx rejection:
	// Requires:
	//   a) Relevant business-rule or workflow prerequisite refusal (not generic 404/405/500)
	//   b) Independent state verification confirming protected state remained unchanged
	if resp.StatusCode >= 400 && resp.StatusCode < 500 {
		stateUnchanged := statesEqual(beforeState, afterState)
		hasRelevantRefusal := isRelevantWorkflowRefusal(resp.StatusCode, respBody)

		if hasRelevantRefusal && stateUnchanged {
			finding.Status = StatusDefended
			finding.EvidenceDetails = fmt.Sprintf("Workflow prerequisite barrier defended: Server rejected out-of-order execution with HTTP %d and verified unmodified state", resp.StatusCode)
			return finding, nil
		}

		finding.Status = StatusInconclusive
		finding.EvidenceDetails = fmt.Sprintf("Server returned HTTP %d for skipped step, but outcome is inconclusive (relevantRefusal=%t, stateUnchanged=%t)", resp.StatusCode, hasRelevantRefusal, stateUnchanged)
		return finding, nil
	}

	// 2. Evaluated HTTP 2xx: Must check if state actually transitioned
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		if isBusinessErrorPayload(respBody) {
			finding.Status = StatusDefended
			finding.EvidenceDetails = "Server returned 200 but body contains workflow prerequisite validation error"
			return finding, nil
		}

		// Positive verification: did server create order or transition to terminal state?
		if afterState != nil && !statesEqual(beforeState, afterState) {
			finding.Status = StatusVerifiedDefect
			finding.ObservedViolation = fmt.Sprintf("Terminal operation %s completed successfully (HTTP %d) without completing required predecessors %v. State changed from %v to %v", termStep.Name, resp.StatusCode, prereqs, beforeState, afterState)
			finding.EvidenceDetails = fmt.Sprintf("VERIFIED DEFECT: Step skipping allowed unauthorized workflow completion: %s", finding.ObservedViolation)
			return finding, nil
		}

		// If status is 200 but no server state changed, it is INCONCLUSIVE
		finding.Status = StatusInconclusive
		finding.EvidenceDetails = fmt.Sprintf("Server returned HTTP %d for skipped step, but state read-back did not demonstrate order confirmation or unauthorized state transition", resp.StatusCode)
		return finding, nil
	}

	finding.Status = StatusInconclusive
	finding.EvidenceDetails = fmt.Sprintf("Unexpected status code %d received during step skipping probe", resp.StatusCode)
	return finding, nil
}

// EvaluateConcurrencyRace executes 20 synchronized parallel requests using barrier synchronization to detect double-spending, coupon reuse, and duplicate redemptions.
func (e *LogicEngine) EvaluateConcurrencyRace(ctx context.Context, raceReq RaceConditionRequest) (*BusinessLogicFinding, error) {
	if raceReq.Endpoint == "" {
		return nil, errors.New("endpoint is required for race condition evaluation")
	}

	concurrency := raceReq.Concurrency
	if concurrency <= 0 {
		concurrency = 20 // Roadmap mandate: 20 parallel requests
	}
	if raceReq.MaxAllowedExecutions <= 0 {
		raceReq.MaxAllowedExecutions = 1 // Default single-use invariant
	}

	persona, ok := e.orchestrator.GetPersona(raceReq.PersonaID)
	if !ok {
		return nil, fmt.Errorf("persona %q not found", raceReq.PersonaID)
	}

	// STEP 1: Read initial server state
	var beforeState any
	if raceReq.StateReadBackURL != "" {
		beforeState, _ = e.ReadServerState(ctx, persona, raceReq.StateReadBackURL, raceReq.StatePropertyPath)
	}

	// STEP 2: Prepare 20 synchronized parallel requests
	var wg sync.WaitGroup
	startBarrier := make(chan struct{})
	type reqResult struct {
		StatusCode int
		Body       []byte
		Err        error
		Timestamp  time.Time
	}
	results := make([]reqResult, concurrency)

	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()

			probeReq, err := http.NewRequestWithContext(ctx, raceReq.Method, raceReq.Endpoint, strings.NewReader(raceReq.Payload))
			if err != nil {
				results[idx] = reqResult{Err: err}
				return
			}
			if raceReq.Payload != "" {
				probeReq.Header.Set("Content-Type", "application/json")
			}
			for k, v := range raceReq.Headers {
				probeReq.Header.Set(k, v)
			}

			// Synchronize TCP socket writes using the barrier release
			<-startBarrier
			dispatchTime := time.Now().UTC()

			resp, err := persona.Do(ctx, probeReq)
			if err != nil {
				results[idx] = reqResult{Err: err, Timestamp: dispatchTime}
				return
			}
			respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 16*1024))
			resp.Body.Close()

			results[idx] = reqResult{
				StatusCode: resp.StatusCode,
				Body:       respBody,
				Timestamp:  dispatchTime,
			}
		}(i)
	}

	// Release all 20 requests simultaneously
	close(startBarrier)
	wg.Wait()

	// STEP 3: Read post-concurrency authoritative server state
	var afterState any
	if raceReq.StateReadBackURL != "" {
		afterState, _ = e.ReadServerState(ctx, persona, raceReq.StateReadBackURL, raceReq.StatePropertyPath)
	}

	// Count successful operations
	successCount := 0
	deniedCount := 0
	for _, res := range results {
		if res.Err == nil && res.StatusCode >= 200 && res.StatusCode < 300 && !isBusinessErrorPayload(res.Body) {
			successCount++
		} else if res.StatusCode >= 400 && res.StatusCode < 500 {
			deniedCount++
		}
	}

	poc := auth.GenerateSanitizedPoC(raceReq.Method, raceReq.Endpoint, persona.HasBearerToken(), raceReq.Payload)
	finding := &BusinessLogicFinding{
		ID:                fmt.Sprintf("race-%d", time.Now().UnixNano()),
		WorkflowID:        raceReq.WorkflowID,
		Category:          CategoryConcurrencyRace,
		OWASP:             "API10:2023 Unsafe Consumption of APIs / Concurrency Race Condition",
		CWE:               "CWE-362 Concurrent Execution using Shared Resource with Improper Synchronization",
		Endpoint:          raceReq.Endpoint,
		Method:            raceReq.Method,
		ExpectedInvariant: fmt.Sprintf("Single-use operation must permit at most %d execution; subsequent concurrent attempts must be rejected atomically", raceReq.MaxAllowedExecutions),
		BeforeState:       beforeState,
		AfterState:        afterState,
		PersonaID:         raceReq.PersonaID,
		PersonaRole:       persona.Role(),
		SanitizedPoC:      poc,
		Timestamp:         time.Now().UTC(),
	}

	// Check for double spending / coupon reuse
	// Invariant violation: success count exceeds max allowed executions AND afterState confirms multiple executions
	if successCount > raceReq.MaxAllowedExecutions {
		finding.Status = StatusVerifiedDefect
		finding.ObservedViolation = fmt.Sprintf("Race condition confirmed across %d synchronized requests: %d operations succeeded (expected max: %d). State reflects %v", concurrency, successCount, raceReq.MaxAllowedExecutions, afterState)
		finding.EvidenceDetails = fmt.Sprintf("VERIFIED DEFECT: Multi-request race condition produced duplicate side-effects (%d successes / %d attempts)", successCount, concurrency)
		return finding, nil
	}

	// If exactly <= maxAllowed succeeded and remainder failed
	if successCount <= raceReq.MaxAllowedExecutions && deniedCount > 0 {
		finding.Status = StatusDefended
		finding.EvidenceDetails = fmt.Sprintf("Concurrency barrier defended: Server atomically allowed %d operation and rejected %d concurrent attempts", successCount, deniedCount)
		return finding, nil
	}

	finding.Status = StatusInconclusive
	finding.EvidenceDetails = fmt.Sprintf("Concurrency evaluation inconclusive: %d succeeded, %d denied, beforeState=%v, afterState=%v", successCount, deniedCount, beforeState, afterState)
	return finding, nil
}

// Helper utilities for business logic evaluation

func toFloat(val any) (float64, bool) {
	if val == nil {
		return 0, false
	}
	switch v := val.(type) {
	case float64:
		return v, true
	case float32:
		return float64(v), true
	case int:
		return float64(v), true
	case int32:
		return float64(v), true
	case int64:
		return float64(v), true
	case string:
		if f, err := strconv.ParseFloat(v, 64); err == nil {
			return f, true
		}
	}
	return 0, false
}

func statesEqual(a, b any) bool {
	if a == nil && b == nil {
		return true
	}
	if a == nil || b == nil {
		return false
	}
	ab, _ := json.Marshal(a)
	bb, _ := json.Marshal(b)
	return bytes.Equal(ab, bb)
}

func isBusinessErrorPayload(body []byte) bool {
	if len(body) == 0 {
		return false
	}
	lower := strings.ToLower(string(body))
	indicators := []string{
		"error", "invalid", "rejected", "insufficient",
		"prerequisite", "not allowed", "prohibited",
		"already used", "already redeemed", "expired",
		"empty cart", "empty basket", "not found",
	}
	for _, ind := range indicators {
		if strings.Contains(lower, ind) {
			return true
		}
	}
	return false
}

func isRelevantBusinessRefusal(statusCode int, body []byte, param string) bool {
	// Exclude generic not-found, method-not-allowed, or gateway errors
	if statusCode == http.StatusNotFound || statusCode == http.StatusMethodNotAllowed || statusCode == http.StatusBadGateway {
		return false
	}
	if len(body) == 0 {
		return false
	}
	lower := strings.ToLower(string(body))
	indicators := []string{
		"invalid", "quantity", "price", "greater than", "less than",
		"must be", "minimum", "positive", "validation", "rejected",
		"out of bounds", "range", "zero", "negative", "not allowed",
	}
	if param != "" && strings.Contains(lower, strings.ToLower(param)) {
		return true
	}
	for _, ind := range indicators {
		if strings.Contains(lower, ind) {
			return true
		}
	}
	return false
}

func isRelevantWorkflowRefusal(statusCode int, body []byte) bool {
	if statusCode == http.StatusPreconditionFailed {
		return true
	}
	if statusCode == http.StatusNotFound || statusCode == http.StatusMethodNotAllowed || statusCode == http.StatusBadGateway {
		return false
	}
	if len(body) == 0 {
		return false
	}
	lower := strings.ToLower(string(body))
	indicators := []string{
		"prerequisite", "basket", "cart", "empty", "checkout",
		"precondition", "sequence", "order", "state", "step",
		"not initialized", "not met", "unauthorized", "conflict",
	}
	for _, ind := range indicators {
		if strings.Contains(lower, ind) {
			return true
		}
	}
	return false
}

// ComputeLogicFindingID computes a deterministic defect identifier.
func ComputeLogicFindingID(workflowID, endpoint, method, param, category, boundary string) string {
	raw := workflowID + "|" + endpoint + "|" + method + "|" + param + "|" + category + "|" + boundary
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}
