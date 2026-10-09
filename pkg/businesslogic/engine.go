package businesslogic

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"felix/pkg/report"
	"github.com/google/uuid"
)

// Engine evaluates business logic workflows, state transitions, and business invariants.
type Engine struct {
	client *http.Client
	config Config
}

// NewEngine creates a new Business Logic Security Engine.
func NewEngine(client *http.Client, config Config) *Engine {
	if client == nil {
		client = &http.Client{
			Timeout: config.Timeout,
		}
	}
	return &Engine{
		client: client,
		config: config,
	}
}

// scopedClient creates an HTTP client that validates every redirect destination
// against the assessment's approved scope and exclusions before the redirected request is sent.
func (e *Engine) scopedClient(actx *AssessmentContext) *http.Client {
	return &http.Client{
		Timeout: e.config.Timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 10 {
				return fmt.Errorf("stopped after 10 redirects")
			}
			destURL := req.URL.String()
			if actx.IsExcluded != nil && actx.IsExcluded(destURL) {
				return fmt.Errorf("redirect blocked: %s is excluded from assessment scope", destURL)
			}
			if actx.IsAllowed != nil && !actx.IsAllowed(destURL) {
				return fmt.Errorf("redirect blocked: %s is out of authorized scope", destURL)
			}
			return nil
		},
	}
}

// ModelWorkflows discovers and models candidate workflows from discovered endpoints or operator definitions.
func (e *Engine) ModelWorkflows(ctx context.Context, actx *AssessmentContext) []Workflow {
	if len(actx.Workflows) > 0 {
		return actx.Workflows
	}

	var workflows []Workflow

	// 1. Order Fulfillment / E-Commerce Flow
	var cartEP, checkoutEP, payEP, downloadEP *DiscoveredEndpoint
	for i := range actx.Endpoints {
		ep := &actx.Endpoints[i]
		lower := strings.ToLower(ep.Path + " " + ep.Type)
		if strings.Contains(lower, "cart") || strings.Contains(lower, "item") {
			cartEP = ep
		}
		if strings.Contains(lower, "checkout") || strings.Contains(lower, "order") || strings.Contains(lower, "step") {
			checkoutEP = ep
		}
		if strings.Contains(lower, "pay") || strings.Contains(lower, "billing") {
			payEP = ep
		}
		if strings.Contains(lower, "download") || strings.Contains(lower, "fulfill") || strings.Contains(lower, "receipt") || strings.Contains(lower, "terminal") {
			downloadEP = ep
		}
	}

	if cartEP != nil || checkoutEP != nil || payEP != nil || downloadEP != nil {
		wf := Workflow{
			ID:             "WF-ECOMMERCE-ORDER",
			Name:           "Order Creation & Fulfillment Workflow",
			Description:    "E-commerce transition flow from item addition to payment and asset fulfillment",
			EvidenceSource: SourceObservedFact,
			Confidence:     "HIGH",
			States:         []string{"CREATED", "CHECKOUT_PENDING", "PAID", "FULFILLED", "CANCELLED"},
			Preconditions: map[string]string{
				"FULFILLED": "PAID",
				"PAID":      "CHECKOUT_PENDING",
			},
			AllowedTransitions: []Transition{
				{FromState: "CREATED", ToState: "CHECKOUT_PENDING", Action: "checkout"},
				{FromState: "CHECKOUT_PENDING", ToState: "PAID", Action: "pay"},
				{FromState: "PAID", ToState: "FULFILLED", Action: "fulfill"},
				{FromState: "CHECKOUT_PENDING", ToState: "CANCELLED", Action: "cancel"},
			},
		}

		idx := 1
		if cartEP != nil {
			wf.Steps = append(wf.Steps, WorkflowStep{
				Index:           idx,
				Name:            "Add to Cart",
				Endpoint:        cartEP.Path,
				Method:          cartEP.Method,
				IsStateChanging: true,
			})
			idx++
		}
		if checkoutEP != nil {
			wf.Steps = append(wf.Steps, WorkflowStep{
				Index:           idx,
				Name:            "Initiate Checkout",
				Endpoint:        checkoutEP.Path,
				Method:          checkoutEP.Method,
				Prerequisites:   []string{"Cart Created"},
				IsStateChanging: true,
			})
			idx++
		}
		if payEP != nil {
			wf.Steps = append(wf.Steps, WorkflowStep{
				Index:           idx,
				Name:            "Submit Payment",
				Endpoint:        payEP.Path,
				Method:          payEP.Method,
				Prerequisites:   []string{"Checkout Initiated"},
				IsStateChanging: true,
			})
			idx++
		}
		if downloadEP != nil {
			wf.Steps = append(wf.Steps, WorkflowStep{
				Index:                idx,
				Name:                 "Download / Fulfill Digital Asset",
				Endpoint:             downloadEP.Path,
				Method:               downloadEP.Method,
				Prerequisites:        []string{"Payment Confirmed"},
				IsStateChanging:      false,
				VerificationEligible: true,
			})
		}
		if len(wf.Steps) >= 2 {
			workflows = append(workflows, wf)
		}
	}

	// 2. Resource Approval / Publication Flow
	var draftEP, submitEP, approveEP, publishEP *DiscoveredEndpoint
	for i := range actx.Endpoints {
		ep := &actx.Endpoints[i]
		lower := strings.ToLower(ep.Path + " " + ep.Type)
		if strings.Contains(lower, "draft") || strings.Contains(lower, "create") {
			draftEP = ep
		}
		if strings.Contains(lower, "submit") || strings.Contains(lower, "review") {
			submitEP = ep
		}
		if strings.Contains(lower, "approve") || strings.Contains(lower, "reject") {
			approveEP = ep
		}
		if strings.Contains(lower, "publish") || strings.Contains(lower, "deploy") {
			publishEP = ep
		}
	}

	if draftEP != nil || submitEP != nil || approveEP != nil || publishEP != nil {
		wf := Workflow{
			ID:             "WF-RESOURCE-APPROVAL",
			Name:           "Resource Creation & Approval Flow",
			Description:    "Multi-step document or asset submission and approval workflow",
			EvidenceSource: SourceObservedFact,
			Confidence:     "MEDIUM",
			States:         []string{"DRAFT", "PENDING_APPROVAL", "APPROVED", "PUBLISHED", "REJECTED"},
			Preconditions: map[string]string{
				"PUBLISHED": "APPROVED",
				"APPROVED":  "PENDING_APPROVAL",
			},
			AllowedTransitions: []Transition{
				{FromState: "DRAFT", ToState: "PENDING_APPROVAL", Action: "submit"},
				{FromState: "PENDING_APPROVAL", ToState: "APPROVED", Action: "approve"},
				{FromState: "PENDING_APPROVAL", ToState: "REJECTED", Action: "reject"},
				{FromState: "APPROVED", ToState: "PUBLISHED", Action: "publish"},
			},
		}

		idx := 1
		if draftEP != nil {
			wf.Steps = append(wf.Steps, WorkflowStep{Index: idx, Name: "Create Draft", Endpoint: draftEP.Path, Method: draftEP.Method, IsStateChanging: true})
			idx++
		}
		if submitEP != nil {
			wf.Steps = append(wf.Steps, WorkflowStep{Index: idx, Name: "Submit for Approval", Endpoint: submitEP.Path, Method: submitEP.Method, IsStateChanging: true})
			idx++
		}
		if approveEP != nil {
			wf.Steps = append(wf.Steps, WorkflowStep{Index: idx, Name: "Approve Resource", Endpoint: approveEP.Path, Method: approveEP.Method, RequiredRole: "approver", IsStateChanging: true})
			idx++
		}
		if publishEP != nil {
			wf.Steps = append(wf.Steps, WorkflowStep{Index: idx, Name: "Publish Live", Endpoint: publishEP.Path, Method: publishEP.Method, Prerequisites: []string{"Resource Approved"}, IsStateChanging: true, VerificationEligible: true})
		}
		if len(wf.Steps) >= 2 {
			workflows = append(workflows, wf)
		}
	}

	// 3. Fallback from any observed sequential endpoints if >= 1 endpoints exist
	if len(workflows) == 0 && len(actx.Endpoints) > 0 {
		wf := Workflow{
			ID:             "WF-DISCOVERED-FLOW",
			Name:           "Discovered Multi-Step Application Flow",
			Description:    "Inferred multi-step workflow from discovered endpoints",
			EvidenceSource: SourceInferredHypothesis,
			Confidence:     "MEDIUM",
			IsPartial:      len(actx.Endpoints) < 2,
			States:         []string{"INITIATED", "IN_PROGRESS", "TERMINAL"},
		}
		for i, ep := range actx.Endpoints {
			isTerm := (i == len(actx.Endpoints)-1)
			wf.Steps = append(wf.Steps, WorkflowStep{
				Index:                i + 1,
				Name:                 fmt.Sprintf("Step %d (%s)", i+1, ep.Path),
				Endpoint:             ep.Path,
				Method:               ep.Method,
				IsStateChanging:      ep.Method == "POST" || ep.Method == "PUT" || ep.Method == "DELETE",
				VerificationEligible: isTerm,
			})
		}
		workflows = append(workflows, wf)
	}

	// 4. Baseline Workflows if no endpoints observed
	if len(workflows) == 0 {
		workflows = append(workflows, Workflow{
			ID:             "WF-DEFAULT-CHECKOUT",
			Name:           "Default Multi-Step Checkout Flow",
			Description:    "Standard multi-step checkout workflow for business logic evaluation",
			EvidenceSource: SourceInferredHypothesis,
			Confidence:     "MEDIUM",
			States:         []string{"CART", "CHECKOUT", "PAID", "FULFILLED", "CANCELLED"},
			Steps: []WorkflowStep{
				{Index: 1, Name: "Add Item", Endpoint: "/cart/add", Method: "POST", IsStateChanging: true},
				{Index: 2, Name: "Initiate Checkout", Endpoint: "/checkout", Method: "POST", IsStateChanging: true},
				{Index: 3, Name: "Process Payment", Endpoint: "/pay", Method: "POST", IsStateChanging: true},
				{Index: 4, Name: "Download Asset", Endpoint: "/order/receipt", Method: "GET", Prerequisites: []string{"Process Payment"}, VerificationEligible: true},
			},
			Preconditions: map[string]string{
				"FULFILLED": "PAID",
			},
		})
		workflows = append(workflows, Workflow{
			ID:             "WF-DEFAULT-APPROVAL",
			Name:           "Default Document / Action Approval Flow",
			Description:    "Standard multi-party approval workflow for role transition testing",
			EvidenceSource: SourceInferredHypothesis,
			Confidence:     "MEDIUM",
			States:         []string{"DRAFT", "PENDING_APPROVAL", "APPROVED", "PUBLISHED"},
			Steps: []WorkflowStep{
				{Index: 1, Name: "Submit Draft", Endpoint: "/items/submit", Method: "POST", IsStateChanging: true},
				{Index: 2, Name: "Approve Item", Endpoint: "/items/approve", Method: "POST", RequiredRole: "approver", IsStateChanging: true},
				{Index: 3, Name: "Publish Item", Endpoint: "/items/publish", Method: "POST", Prerequisites: []string{"Item Approved"}, VerificationEligible: true},
			},
		})
	}

	return workflows
}

// Plan produces a pre-assessment test plan evaluating workflow prerequisites without executing state changes.
func (e *Engine) Plan(ctx context.Context, actx *AssessmentContext) (*TestPlan, error) {
	workflows := e.ModelWorkflows(ctx, actx)

	plan := &TestPlan{
		AssessmentID:   actx.AssessmentID,
		TargetURL:      actx.BaseURL,
		GeneratedAt:    time.Now().UTC(),
		TotalWorkflows: len(workflows),
		PlannedChecks:  make([]PlannedCheck, 0, len(workflows)*8),
	}

	categories := []BLCategory{
		CategoryWorkflowCircumvention,
		CategoryUnexpectedStateTransition,
		CategoryStateManipulation,
		CategoryUnauthorizedWorkflowAccess,
		CategorySensitiveFlowAbuse,
		CategoryReplayIdempotency,
		CategoryPrivilegeStateMismatch,
		CategoryDataValidationInvariants,
	}

	for _, wf := range workflows {
		for _, cat := range categories {
			info := CategoryMetadata[cat]
			pc := PlannedCheck{
				ID:                fmt.Sprintf("PLAN-%s-%s", cat, wf.ID),
				Category:          cat,
				Name:              fmt.Sprintf("%s on %s", info.Name, wf.Name),
				WorkflowID:        wf.ID,
				SecurityObjective: info.Description,
				Preconditions:     info.Preconditions,
				ExpectedBehavior:  info.VerificationBoundary,
				Status:            PlanReady,
			}

			if cat == CategoryUnexpectedStateTransition || cat == CategoryReplayIdempotency {
				pc.IsStateChanging = true
			}

			// Evaluate preconditions
			if cat == CategoryUnauthorizedWorkflowAccess && len(actx.Identities) < 2 && !actx.SyntheticFixture {
				pc.Status = PlanBlocked
				pc.BlockedReason = "Requires at least 2 distinct authorized test identities"
			}
			if len(wf.Steps) < 2 && !actx.SyntheticFixture {
				pc.Status = PlanBlocked
				pc.BlockedReason = "Workflow has fewer than 2 modeled steps"
			}

			if pc.Status == PlanReady {
				plan.ReadyChecks++
			} else {
				plan.BlockedChecks++
			}
			plan.PlannedChecks = append(plan.PlannedChecks, pc)
		}
	}

	plan.TotalPlannedChecks = len(plan.PlannedChecks)
	return plan, nil
}

// Assess runs the business logic security evaluation across all 8 required categories.
func (e *Engine) Assess(ctx context.Context, actx *AssessmentContext) ([]Result, []report.Finding, *Summary, error) {
	client := e.scopedClient(actx)
	workflows := e.ModelWorkflows(ctx, actx)

	var allResults []Result
	var allFindings []report.Finding
	coverageMap := make(map[string]CategoryCoverage)

	categories := []BLCategory{
		CategoryWorkflowCircumvention,
		CategoryUnexpectedStateTransition,
		CategoryStateManipulation,
		CategoryUnauthorizedWorkflowAccess,
		CategorySensitiveFlowAbuse,
		CategoryReplayIdempotency,
		CategoryPrivilegeStateMismatch,
		CategoryDataValidationInvariants,
	}

	for _, cat := range categories {
		info := CategoryMetadata[cat]
		coverageMap[string(cat)] = CategoryCoverage{
			Category: cat,
			Code:     info.Code,
			Name:     info.Name,
			Status:   CoverageActivelyTested,
		}
	}

	if len(workflows) == 0 {
		for _, cat := range categories {
			cov := coverageMap[string(cat)]
			cov.Status = CoverageBlockedMissingPrereq
			cov.Explanation = "No business logic workflows could be established from available targets or inputs"
			coverageMap[string(cat)] = cov
		}
		summary := e.compileSummary(actx.BaseURL, len(workflows), allResults, coverageMap, actx.SyntheticFixture)
		return allResults, allFindings, summary, nil
	}

	for _, wf := range workflows {
		// BL-01: Workflow Circumvention (Skipped Steps)
		e.evalWorkflowCircumvention(ctx, actx, client, wf, &allResults, &allFindings, coverageMap)

		// BL-02: Unexpected State Transitions
		e.evalUnexpectedStateTransitions(ctx, actx, client, wf, &allResults, &allFindings, coverageMap)

		// BL-03: State Manipulation & Parameter Integrity
		e.evalStateManipulation(ctx, actx, client, wf, &allResults, &allFindings, coverageMap)

		// BL-04: Unauthorized Workflow Access
		e.evalUnauthorizedWorkflowAccess(ctx, actx, client, wf, &allResults, &allFindings, coverageMap)

		// BL-05: Sensitive Business-Flow Abuse
		e.evalSensitiveFlowAbuse(ctx, actx, client, wf, &allResults, &allFindings, coverageMap)

		// BL-06: Replay & Idempotency Flaws
		e.evalReplayIdempotency(ctx, actx, client, wf, &allResults, &allFindings, coverageMap)

		// BL-07: Privilege & State Inconsistency
		e.evalPrivilegeStateMismatch(ctx, actx, client, wf, &allResults, &allFindings, coverageMap)

		// BL-08: Business Data Validation & Invariants
		e.evalDataValidationInvariants(ctx, actx, client, wf, &allResults, &allFindings, coverageMap)
	}

	summary := e.compileSummary(actx.BaseURL, len(workflows), allResults, coverageMap, actx.SyntheticFixture)
	return allResults, allFindings, summary, nil
}

// -------------------------------------------------------------------------
// Category Evaluators
// -------------------------------------------------------------------------

// BL-01: Workflow Circumvention (Skipped Steps)
func (e *Engine) evalWorkflowCircumvention(ctx context.Context, actx *AssessmentContext, client *http.Client, wf Workflow, results *[]Result, findings *[]report.Finding, coverage map[string]CategoryCoverage) {
	catKey := string(CategoryWorkflowCircumvention)
	cov := coverage[catKey]
	cov.ChecksRun++

	r := Result{
		ID:           uuid.New().String(),
		AssessmentID: actx.AssessmentID,
		ExecutionID:  actx.ExecutionID,
		Category:     CategoryWorkflowCircumvention,
		CheckID:      fmt.Sprintf("BL-01-%s-SKIP-STEP", wf.ID),
		CheckName:    fmt.Sprintf("Workflow Circumvention on %s", wf.Name),
		WorkflowID:   wf.ID,
		WorkflowName: wf.Name,
		CreatedAt:    time.Now().UTC(),
	}

	terminalStep := wf.terminalStep()
	if terminalStep == nil {
		r.VerificationState = StateInconclusive
		r.Severity = report.SeverityInfo
		r.Confidence = report.ConfidenceLow
		r.EvidenceSummary = fmt.Sprintf("Workflow %s has no identifiable terminal or fulfillment step to evaluate for circumvention", wf.Name)
		cov.Inconclusive++
		coverage[catKey] = cov
		*results = append(*results, r)
		return
	}

	r.Endpoint = terminalStep.Endpoint
	r.Method = terminalStep.Method
	if r.Method == "" {
		r.Method = "GET"
	}

	probeURL := buildTargetURL(actx.BaseURL, terminalStep.Endpoint)
	if actx.IsExcluded != nil && actx.IsExcluded(probeURL) {
		r.VerificationState = StateInconclusive
		r.Severity = report.SeverityInfo
		r.EvidenceSummary = fmt.Sprintf("Target URL %s is excluded by assessment scope", probeURL)
		cov.Inconclusive++
		coverage[catKey] = cov
		*results = append(*results, r)
		return
	}
	if actx.IsAllowed != nil && !actx.IsAllowed(probeURL) {
		r.VerificationState = StateInconclusive
		r.Severity = report.SeverityInfo
		r.EvidenceSummary = fmt.Sprintf("Target URL %s is out of authorized assessment scope", probeURL)
		cov.Inconclusive++
		coverage[catKey] = cov
		*results = append(*results, r)
		return
	}

	req, err := http.NewRequestWithContext(ctx, r.Method, probeURL, nil)
	if err != nil {
		r.VerificationState = StateInconclusive
		r.Severity = report.SeverityInfo
		r.EvidenceSummary = fmt.Sprintf("Failed to construct probe request: %v", err)
		cov.Inconclusive++
		coverage[catKey] = cov
		*results = append(*results, r)
		return
	}
	req.Header.Set("User-Agent", e.config.UserAgent)

	resp, err := client.Do(req)
	if err != nil {
		r.VerificationState = StateInconclusive
		r.Severity = report.SeverityInfo
		r.EvidenceSummary = fmt.Sprintf("Network error executing out-of-order probe: %v", err)
		cov.Inconclusive++
		coverage[catKey] = cov
		*results = append(*results, r)
		return
	}
	defer resp.Body.Close()
	r.ObservedStatus = resp.StatusCode

	bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 65536))
	bodyStr := string(bodyBytes)
	bodyLower := strings.ToLower(bodyStr)

	// 400, 401, 403, 404, 409, 412, 422 indicates prerequisite enforced
	if resp.StatusCode == 400 || resp.StatusCode == 401 || resp.StatusCode == 403 ||
		resp.StatusCode == 404 || resp.StatusCode == 409 || resp.StatusCode == 412 || resp.StatusCode == 422 {
		r.VerificationState = StateNotVulnerable
		r.Severity = report.SeverityInfo
		r.Confidence = report.ConfidenceHigh
		r.EvidenceSummary = fmt.Sprintf("Terminal action %s %s correctly rejected out-of-order invocation with HTTP %d. Prerequisites enforced.",
			terminalStep.Method, terminalStep.Endpoint, resp.StatusCode)
		cov.NotVulnerable++
	} else if resp.StatusCode == 200 || resp.StatusCode == 201 {
		hasProof := strings.Contains(bodyLower, "fulfilled") || strings.Contains(bodyLower, "paid") ||
			strings.Contains(bodyLower, "order_id") || strings.Contains(bodyLower, "receipt") ||
			strings.Contains(bodyLower, "download") || strings.Contains(bodyLower, "success")

		if hasProof {
			if wf.EvidenceSource == SourceInferredHypothesis {
				r.VerificationState = StateCandidate
				r.Severity = report.SeverityMedium
				r.Confidence = report.ConfidenceMedium
				r.EvidenceSummary = fmt.Sprintf("Terminal action %s %s returned fulfillment proof, but workflow '%s' is an unconfirmed inferred hypothesis.",
					terminalStep.Method, terminalStep.Endpoint, wf.Name)
				r.EvidenceDetails = map[string]string{
					"workflow":        wf.Name,
					"terminal_step":   terminalStep.Name,
					"observed_status": fmt.Sprintf("%d", resp.StatusCode),
					"hypothesis":      "INFERRED_WORKFLOW_REQUIRES_OPERATOR_CORROBORATION",
				}
				fnd := createBusinessLogicFinding(actx, r, CategoryWorkflowCircumvention,
					"Potential Workflow Circumvention on Inferred Workflow (Candidate)",
					r.EvidenceSummary, report.SeverityMedium, 60,
					"Verify whether skipped steps are mandatory business requirements before enforcing state gate.")
				r.Finding = fnd
				*findings = append(*findings, *fnd)
				cov.Candidates++
			} else {
				r.VerificationState = StateVerified
				r.Severity = report.SeverityHigh
				r.Confidence = report.ConfidenceHigh
				r.StateBefore = "UNPAID"
				r.StateAfter = "FULFILLED"
				r.EvidenceSummary = fmt.Sprintf("Invoking terminal step '%s' (%s %s) succeeded without fulfilling prerequisite '%s'. Protected outcome granted without prerequisite confirmation.",
					terminalStep.Name, terminalStep.Method, terminalStep.Endpoint, strings.Join(terminalStep.Prerequisites, ", "))
				r.EvidenceDetails = map[string]string{
					"workflow":        wf.Name,
					"terminal_step":   terminalStep.Name,
					"prerequisites":   strings.Join(terminalStep.Prerequisites, ", "),
					"observed_status": fmt.Sprintf("%d", resp.StatusCode),
					"violation":       "WORKFLOW_CIRCUMVENTION_CONFIRMED",
				}
				fnd := createBusinessLogicFinding(actx, r, CategoryWorkflowCircumvention,
					"Workflow Circumvention: Protected Action Accessible Without Required Prerequisite",
					r.EvidenceSummary, report.SeverityHigh, 85,
					"Enforce mandatory server-side precondition checks at every terminal workflow action; reject requests when required preceding states are missing.")
				r.Finding = fnd
				*findings = append(*findings, *fnd)
				cov.Verified++
			}
		} else {
			r.VerificationState = StateCandidate
			r.Severity = report.SeverityMedium
			r.Confidence = report.ConfidenceMedium
			r.EvidenceSummary = fmt.Sprintf("Terminal action %s %s returned HTTP %d on out-of-order invocation, but fulfillment outcome is not confirmed in response. Candidate finding.",
				terminalStep.Method, terminalStep.Endpoint, resp.StatusCode)
			r.EvidenceDetails = map[string]string{
				"status": fmt.Sprintf("%d", resp.StatusCode),
				"reason": "HTTP_SUCCESS_WITHOUT_FULFILLMENT_PROOF",
			}
			fnd := createBusinessLogicFinding(actx, r, CategoryWorkflowCircumvention,
				"Potential Workflow Circumvention: Terminal Endpoint Accepted Out-of-Order Invocation (Candidate)",
				r.EvidenceSummary, report.SeverityMedium, 60,
				"Validate workflow state on the server before granting access or returning successful fulfillment response.")
			r.Finding = fnd
			*findings = append(*findings, *fnd)
			cov.Candidates++
		}
	} else {
		r.VerificationState = StateObserved
		r.Severity = report.SeverityInfo
		r.Confidence = report.ConfidenceLow
		r.EvidenceSummary = fmt.Sprintf("Terminal action %s %s returned HTTP %d on out-of-order probe.",
			terminalStep.Method, terminalStep.Endpoint, resp.StatusCode)
		cov.Observations++
	}

	coverage[catKey] = cov
	*results = append(*results, r)
}

// BL-02: Unexpected State Transitions
func (e *Engine) evalUnexpectedStateTransitions(ctx context.Context, actx *AssessmentContext, client *http.Client, wf Workflow, results *[]Result, findings *[]report.Finding, coverage map[string]CategoryCoverage) {
	catKey := string(CategoryUnexpectedStateTransition)
	cov := coverage[catKey]
	cov.ChecksRun++

	r := Result{
		ID:           uuid.New().String(),
		AssessmentID: actx.AssessmentID,
		ExecutionID:  actx.ExecutionID,
		Category:     CategoryUnexpectedStateTransition,
		CheckID:      fmt.Sprintf("BL-02-%s-STATE-JUMP", wf.ID),
		CheckName:    fmt.Sprintf("Unexpected State Transition on %s", wf.Name),
		WorkflowID:   wf.ID,
		WorkflowName: wf.Name,
		CreatedAt:    time.Now().UTC(),
	}

	// Safety gating: Mutating state-changing checks blocked by default
	if !e.config.AllowStateChanging {
		r.VerificationState = StateBlockedBySafety
		r.Severity = report.SeverityInfo
		r.EvidenceSummary = fmt.Sprintf("State-changing transition testing on %s skipped by safety policy (read-only mode active)", wf.Name)
		cov.Blocked++
		coverage[catKey] = cov
		*results = append(*results, r)
		return
	}

	step := wf.transitionStep()
	if step == nil {
		r.VerificationState = StateInconclusive
		r.Severity = report.SeverityInfo
		r.EvidenceSummary = fmt.Sprintf("Workflow %s has no state transition step to evaluate", wf.Name)
		cov.Inconclusive++
		coverage[catKey] = cov
		*results = append(*results, r)
		return
	}

	r.Endpoint = step.Endpoint
	r.Method = "POST"
	if step.Method != "" {
		r.Method = step.Method
	}

	probeURL := buildTargetURL(actx.BaseURL, step.Endpoint)
	if actx.IsExcluded != nil && actx.IsExcluded(probeURL) {
		r.VerificationState = StateInconclusive
		r.Severity = report.SeverityInfo
		r.EvidenceSummary = fmt.Sprintf("Target URL %s is excluded by assessment scope", probeURL)
		cov.Inconclusive++
		coverage[catKey] = cov
		*results = append(*results, r)
		return
	}
	if actx.IsAllowed != nil && !actx.IsAllowed(probeURL) {
		r.VerificationState = StateInconclusive
		r.Severity = report.SeverityInfo
		r.EvidenceSummary = fmt.Sprintf("Target URL %s is out of authorized scope", probeURL)
		cov.Inconclusive++
		coverage[catKey] = cov
		*results = append(*results, r)
		return
	}

	payload := []byte(`{"status":"COMPLETED","from":"CANCELLED","action":"complete"}`)
	req, err := http.NewRequestWithContext(ctx, r.Method, probeURL, bytes.NewReader(payload))
	if err != nil {
		r.VerificationState = StateInconclusive
		r.Severity = report.SeverityInfo
		r.EvidenceSummary = fmt.Sprintf("Failed to construct probe request: %v", err)
		cov.Inconclusive++
		coverage[catKey] = cov
		*results = append(*results, r)
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", e.config.UserAgent)

	resp, err := client.Do(req)
	if err != nil {
		r.VerificationState = StateInconclusive
		r.Severity = report.SeverityInfo
		r.EvidenceSummary = fmt.Sprintf("Network error executing state jump probe: %v", err)
		cov.Inconclusive++
		coverage[catKey] = cov
		*results = append(*results, r)
		return
	}
	defer resp.Body.Close()
	r.ObservedStatus = resp.StatusCode

	bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 65536))
	bodyStr := string(bodyBytes)
	bodyLower := strings.ToLower(bodyStr)

	if resp.StatusCode == 400 || resp.StatusCode == 401 || resp.StatusCode == 403 ||
		resp.StatusCode == 404 || resp.StatusCode == 409 || resp.StatusCode == 412 || resp.StatusCode == 422 {
		r.VerificationState = StateNotVulnerable
		r.Severity = report.SeverityInfo
		r.Confidence = report.ConfidenceHigh
		r.EvidenceSummary = fmt.Sprintf("Server correctly rejected prohibited state jump on %s with HTTP %d.", step.Endpoint, resp.StatusCode)
		cov.NotVulnerable++
	} else if resp.StatusCode == 200 || resp.StatusCode == 201 {
		hasJumpProof := strings.Contains(bodyLower, `"completed"`) || strings.Contains(bodyLower, "state_changed") ||
			strings.Contains(bodyLower, "transition_success")

		if hasJumpProof {
			if wf.EvidenceSource == SourceInferredHypothesis {
				r.VerificationState = StateCandidate
				r.Severity = report.SeverityMedium
				r.Confidence = report.ConfidenceMedium
				r.EvidenceSummary = fmt.Sprintf("State transition on inferred workflow %s returned COMPLETED, but transition rule is hypothesized.", wf.Name)
				cov.Candidates++
				fnd := createBusinessLogicFinding(actx, r, CategoryUnexpectedStateTransition,
					"Potential Unexpected State Transition (Candidate)",
					r.EvidenceSummary, report.SeverityMedium, 60,
					"Validate finite state machine rules before allowing direct transitions.")
				r.Finding = fnd
				*findings = append(*findings, *fnd)
			} else {
				r.VerificationState = StateVerified
				r.Severity = report.SeverityHigh
				r.Confidence = report.ConfidenceHigh
				r.StateBefore = "CANCELLED"
				r.StateAfter = "COMPLETED"
				r.EvidenceSummary = fmt.Sprintf("Prohibited state machine transition from 'CANCELLED' to 'COMPLETED' was accepted and committed on workflow %s.", wf.Name)
				r.EvidenceDetails = map[string]string{
					"workflow":     wf.Name,
					"state_before": "CANCELLED",
					"state_after":  "COMPLETED",
					"defect":       "PROHIBITED_STATE_TRANSITION_PERMITTED",
				}
				fnd := createBusinessLogicFinding(actx, r, CategoryUnexpectedStateTransition,
					"Unexpected State Transition: Prohibited State Machine Jump Permitted",
					r.EvidenceSummary, report.SeverityHigh, 80,
					"Implement a strict finite state machine (FSM) on the server; disallow direct transitions between terminal, cancelled, or inactive states to completed.")
				r.Finding = fnd
				*findings = append(*findings, *fnd)
				cov.Verified++
			}
		} else {
			r.VerificationState = StateCandidate
			r.Severity = report.SeverityMedium
			r.Confidence = report.ConfidenceMedium
			r.EvidenceSummary = fmt.Sprintf("State jump probe on %s returned HTTP %d, but resulting state was not authoritatively observable.", step.Endpoint, resp.StatusCode)
			cov.Candidates++
			fnd := createBusinessLogicFinding(actx, r, CategoryUnexpectedStateTransition,
				"Unconfirmed State Transition: Success Status Without Observable State (Candidate)",
				r.EvidenceSummary, report.SeverityMedium, 60,
				"Verify state transitions explicitly on the server before acknowledging completion.")
			r.Finding = fnd
			*findings = append(*findings, *fnd)
		}
	} else {
		r.VerificationState = StateObserved
		r.Severity = report.SeverityInfo
		r.EvidenceSummary = fmt.Sprintf("State transition probe on %s returned HTTP %d.", step.Endpoint, resp.StatusCode)
		cov.Observations++
	}

	coverage[catKey] = cov
	*results = append(*results, r)
}

// BL-03: State Manipulation & Parameter Integrity
func (e *Engine) evalStateManipulation(ctx context.Context, actx *AssessmentContext, client *http.Client, wf Workflow, results *[]Result, findings *[]report.Finding, coverage map[string]CategoryCoverage) {
	catKey := string(CategoryStateManipulation)
	cov := coverage[catKey]
	cov.ChecksRun++

	r := Result{
		ID:           uuid.New().String(),
		AssessmentID: actx.AssessmentID,
		ExecutionID:  actx.ExecutionID,
		Category:     CategoryStateManipulation,
		CheckID:      fmt.Sprintf("BL-03-%s-PARAM-INTEGRITY", wf.ID),
		CheckName:    fmt.Sprintf("State Manipulation & Integrity on %s", wf.Name),
		WorkflowID:   wf.ID,
		WorkflowName: wf.Name,
		CreatedAt:    time.Now().UTC(),
	}

	step := wf.calculationStep()
	if step == nil {
		r.VerificationState = StateInconclusive
		r.Severity = report.SeverityInfo
		r.EvidenceSummary = fmt.Sprintf("Workflow %s has no calculation/pricing step to evaluate", wf.Name)
		cov.Inconclusive++
		coverage[catKey] = cov
		*results = append(*results, r)
		return
	}

	r.Endpoint = step.Endpoint
	r.Method = "POST"
	if step.Method != "" {
		r.Method = step.Method
	}

	probeURL := buildTargetURL(actx.BaseURL, step.Endpoint)
	if actx.IsExcluded != nil && actx.IsExcluded(probeURL) {
		r.VerificationState = StateInconclusive
		r.Severity = report.SeverityInfo
		r.EvidenceSummary = fmt.Sprintf("Target URL %s is excluded by assessment scope", probeURL)
		cov.Inconclusive++
		coverage[catKey] = cov
		*results = append(*results, r)
		return
	}
	if actx.IsAllowed != nil && !actx.IsAllowed(probeURL) {
		r.VerificationState = StateInconclusive
		r.Severity = report.SeverityInfo
		r.EvidenceSummary = fmt.Sprintf("Target URL %s is out of authorized scope", probeURL)
		cov.Inconclusive++
		coverage[catKey] = cov
		*results = append(*results, r)
		return
	}

	payload := []byte(`{"status":"PAID","total_amount":0.01,"price":0.01,"role":"admin"}`)
	req, err := http.NewRequestWithContext(ctx, r.Method, probeURL, bytes.NewReader(payload))
	if err != nil {
		r.VerificationState = StateInconclusive
		r.Severity = report.SeverityInfo
		cov.Inconclusive++
		coverage[catKey] = cov
		*results = append(*results, r)
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", e.config.UserAgent)

	resp, err := client.Do(req)
	if err != nil {
		r.VerificationState = StateInconclusive
		r.Severity = report.SeverityInfo
		r.EvidenceSummary = fmt.Sprintf("Network error executing state manipulation probe: %v", err)
		cov.Inconclusive++
		coverage[catKey] = cov
		*results = append(*results, r)
		return
	}
	defer resp.Body.Close()
	r.ObservedStatus = resp.StatusCode

	bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 65536))
	bodyStr := string(bodyBytes)
	bodyLower := strings.ToLower(bodyStr)

	if resp.StatusCode == 400 || resp.StatusCode == 401 || resp.StatusCode == 403 || resp.StatusCode == 422 {
		r.VerificationState = StateNotVulnerable
		r.Severity = report.SeverityInfo
		r.Confidence = report.ConfidenceHigh
		r.EvidenceSummary = fmt.Sprintf("Server correctly rejected client-supplied state fields on %s with HTTP %d.", step.Endpoint, resp.StatusCode)
		cov.NotVulnerable++
	} else if resp.StatusCode == 200 || resp.StatusCode == 201 {
		hasOverride := strings.Contains(bodyLower, "0.01") || (strings.Contains(bodyLower, `"paid"`) && !strings.Contains(bodyLower, `"unpaid"`))
		hasIgnored := strings.Contains(bodyLower, "ignored") || strings.Contains(bodyLower, "recalculated")

		if hasOverride && !hasIgnored {
			if wf.EvidenceSource == SourceInferredHypothesis {
				r.VerificationState = StateCandidate
				r.Severity = report.SeverityMedium
				r.Confidence = report.ConfidenceMedium
				r.EvidenceSummary = fmt.Sprintf("Client parameters altered response on inferred workflow %s, but workflow rules are unconfirmed.", wf.Name)
				cov.Candidates++
				fnd := createBusinessLogicFinding(actx, r, CategoryStateManipulation,
					"Potential State Manipulation (Candidate)",
					r.EvidenceSummary, report.SeverityMedium, 60,
					"Ensure server-side validation ignores client-supplied state parameters.")
				r.Finding = fnd
				*findings = append(*findings, *fnd)
			} else {
				r.VerificationState = StateVerified
				r.Severity = report.SeverityHigh
				r.Confidence = report.ConfidenceHigh
				r.EvidenceSummary = fmt.Sprintf("Client-supplied parameter 'status=PAID' and 'total_amount=0.01' in request to %s overrode server-authoritative state on workflow %s.", step.Endpoint, wf.Name)
				r.EvidenceDetails = map[string]string{
					"workflow":        wf.Name,
					"endpoint":        step.Endpoint,
					"injected_fields": "status=PAID, total_amount=0.01",
					"defect":          "CLIENT_OVERRIDE_SERVER_STATE",
				}
				fnd := createBusinessLogicFinding(actx, r, CategoryStateManipulation,
					"State Manipulation: Client Parameters Override Authoritative Server State",
					r.EvidenceSummary, report.SeverityHigh, 85,
					"Ignore client-supplied status, price, and role flags during state updates; calculate billing totals and verify workflow state exclusively on the server.")
				r.Finding = fnd
				*findings = append(*findings, *fnd)
				cov.Verified++
			}
		} else if hasIgnored || strings.Contains(bodyLower, "total") {
			r.VerificationState = StateNotVulnerable
			r.Severity = report.SeverityInfo
			r.Confidence = report.ConfidenceHigh
			r.EvidenceSummary = fmt.Sprintf("Server accepted request at %s but ignored client-supplied state override fields, maintaining server-calculated values.", step.Endpoint)
			cov.NotVulnerable++
		} else {
			r.VerificationState = StateCandidate
			r.Severity = report.SeverityMedium
			r.Confidence = report.ConfidenceMedium
			r.EvidenceSummary = fmt.Sprintf("Server returned HTTP %d at %s, but state manipulation effect was unobservable in response.", resp.StatusCode, step.Endpoint)
			cov.Candidates++
		}
	} else {
		r.VerificationState = StateObserved
		r.Severity = report.SeverityInfo
		cov.Observations++
	}

	coverage[catKey] = cov
	*results = append(*results, r)
}

// BL-04: Unauthorized Workflow Access
func (e *Engine) evalUnauthorizedWorkflowAccess(ctx context.Context, actx *AssessmentContext, client *http.Client, wf Workflow, results *[]Result, findings *[]report.Finding, coverage map[string]CategoryCoverage) {
	catKey := string(CategoryUnauthorizedWorkflowAccess)
	cov := coverage[catKey]
	cov.ChecksRun++

	r := Result{
		ID:           uuid.New().String(),
		AssessmentID: actx.AssessmentID,
		ExecutionID:  actx.ExecutionID,
		Category:     CategoryUnauthorizedWorkflowAccess,
		CheckID:      fmt.Sprintf("BL-04-%s-UNAUTH-ACCESS", wf.ID),
		CheckName:    fmt.Sprintf("Unauthorized Workflow Access on %s", wf.Name),
		WorkflowID:   wf.ID,
		WorkflowName: wf.Name,
		CreatedAt:    time.Now().UTC(),
	}

	if len(actx.Identities) < 2 && !actx.SyntheticFixture {
		r.VerificationState = StateInconclusive
		r.Severity = report.SeverityInfo
		r.EvidenceSummary = "Evaluating unauthorized workflow access requires at least two distinct authorized role or identity contexts; reported inconclusive due to missing test identities."
		cov.Inconclusive++
		coverage[catKey] = cov
		*results = append(*results, r)
		return
	}

	step := wf.restrictedStep()
	if step == nil {
		r.VerificationState = StateInconclusive
		r.Severity = report.SeverityInfo
		r.EvidenceSummary = fmt.Sprintf("Workflow %s has no identifiable role-restricted workflow action to evaluate", wf.Name)
		cov.Inconclusive++
		coverage[catKey] = cov
		*results = append(*results, r)
		return
	}

	r.Endpoint = step.Endpoint
	r.Method = "POST"
	if step.Method != "" {
		r.Method = step.Method
	}

	probeURL := buildTargetURL(actx.BaseURL, step.Endpoint)
	if actx.IsExcluded != nil && actx.IsExcluded(probeURL) {
		r.VerificationState = StateInconclusive
		r.Severity = report.SeverityInfo
		r.EvidenceSummary = fmt.Sprintf("Target URL %s is excluded by assessment scope", probeURL)
		cov.Inconclusive++
		coverage[catKey] = cov
		*results = append(*results, r)
		return
	}
	if actx.IsAllowed != nil && !actx.IsAllowed(probeURL) {
		r.VerificationState = StateInconclusive
		r.Severity = report.SeverityInfo
		r.EvidenceSummary = fmt.Sprintf("Target URL %s is out of authorized scope", probeURL)
		cov.Inconclusive++
		coverage[catKey] = cov
		*results = append(*results, r)
		return
	}

	payload := []byte(`{"action":"approve","comment":"unauthorized role approval"}`)
	req, err := http.NewRequestWithContext(ctx, r.Method, probeURL, bytes.NewReader(payload))
	if err != nil {
		r.VerificationState = StateInconclusive
		r.Severity = report.SeverityInfo
		cov.Inconclusive++
		coverage[catKey] = cov
		*results = append(*results, r)
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", e.config.UserAgent)
	req.Header.Set("X-User-Role", "viewer")

	resp, err := client.Do(req)
	if err != nil {
		r.VerificationState = StateInconclusive
		r.Severity = report.SeverityInfo
		r.EvidenceSummary = fmt.Sprintf("Network error executing unauthorized workflow probe: %v", err)
		cov.Inconclusive++
		coverage[catKey] = cov
		*results = append(*results, r)
		return
	}
	defer resp.Body.Close()
	r.ObservedStatus = resp.StatusCode

	bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 65536))
	bodyStr := string(bodyBytes)
	bodyLower := strings.ToLower(bodyStr)

	if resp.StatusCode == 401 || resp.StatusCode == 403 || resp.StatusCode == 404 {
		r.VerificationState = StateNotVulnerable
		r.Severity = report.SeverityInfo
		r.Confidence = report.ConfidenceHigh
		r.EvidenceSummary = fmt.Sprintf("Server correctly denied unprivileged role access to %s with HTTP %d.", step.Endpoint, resp.StatusCode)
		cov.NotVulnerable++
	} else if resp.StatusCode == 200 || resp.StatusCode == 201 {
		hasExecution := strings.Contains(bodyLower, "approved") || strings.Contains(bodyLower, "published") ||
			strings.Contains(bodyLower, "granted") || strings.Contains(bodyLower, "success")

		if hasExecution {
			if wf.EvidenceSource == SourceInferredHypothesis {
				r.VerificationState = StateCandidate
				r.Severity = report.SeverityMedium
				r.Confidence = report.ConfidenceMedium
				r.EvidenceSummary = fmt.Sprintf("Unprivileged request to %s succeeded on inferred workflow %s, but role boundaries are hypothesized.", step.Endpoint, wf.Name)
				cov.Candidates++
				fnd := createBusinessLogicFinding(actx, r, CategoryUnauthorizedWorkflowAccess,
					"Potential Unauthorized Workflow Access (Candidate)",
					r.EvidenceSummary, report.SeverityMedium, 60,
					"Verify role-based access control at restricted workflow transitions.")
				r.Finding = fnd
				*findings = append(*findings, *fnd)
			} else {
				r.VerificationState = StateVerified
				r.Severity = report.SeverityHigh
				r.Confidence = report.ConfidenceHigh
				r.EvidenceSummary = fmt.Sprintf("Unprivileged actor (Role: 'viewer') successfully executed restricted transition '%s' on workflow %s without required role permissions.", step.Endpoint, wf.Name)
				r.EvidenceDetails = map[string]string{
					"workflow":        wf.Name,
					"actor_role":      "viewer",
					"restricted_step": step.Endpoint,
					"defect":          "ROLE_RESTRICTION_BYPASSED",
				}
				fnd := createBusinessLogicFinding(actx, r, CategoryUnauthorizedWorkflowAccess,
					"Unauthorized Workflow Access: Restricted Transition Executed by Unprivileged Role",
					r.EvidenceSummary, report.SeverityHigh, 85,
					"Enforce fine-grained role-based access control (RBAC) at every state transition handler; verify user identity has required permissions for the requested workflow action.")
				r.Finding = fnd
				*findings = append(*findings, *fnd)
				cov.Verified++
			}
		} else {
			r.VerificationState = StateCandidate
			r.Severity = report.SeverityMedium
			r.Confidence = report.ConfidenceMedium
			r.EvidenceSummary = fmt.Sprintf("Endpoint %s returned HTTP %d to unprivileged role, but execution outcome was not confirmed.", step.Endpoint, resp.StatusCode)
			cov.Candidates++
		}
	} else {
		r.VerificationState = StateObserved
		r.Severity = report.SeverityInfo
		cov.Observations++
	}

	coverage[catKey] = cov
	*results = append(*results, r)
}

// BL-05: Sensitive Business-Flow Abuse
func (e *Engine) evalSensitiveFlowAbuse(ctx context.Context, actx *AssessmentContext, client *http.Client, wf Workflow, results *[]Result, findings *[]report.Finding, coverage map[string]CategoryCoverage) {
	catKey := string(CategorySensitiveFlowAbuse)
	cov := coverage[catKey]
	cov.ChecksRun++

	r := Result{
		ID:           uuid.New().String(),
		AssessmentID: actx.AssessmentID,
		ExecutionID:  actx.ExecutionID,
		Category:     CategorySensitiveFlowAbuse,
		CheckID:      fmt.Sprintf("BL-05-%s-FLOW-ABUSE", wf.ID),
		CheckName:    fmt.Sprintf("Sensitive Business-Flow Abuse on %s", wf.Name),
		WorkflowID:   wf.ID,
		WorkflowName: wf.Name,
		CreatedAt:    time.Now().UTC(),
	}

	step := wf.sensitiveStep()
	if step == nil {
		r.VerificationState = StateInconclusive
		r.Severity = report.SeverityInfo
		r.EvidenceSummary = fmt.Sprintf("Workflow %s has no sensitive allocation or promotion action to evaluate", wf.Name)
		cov.Inconclusive++
		coverage[catKey] = cov
		*results = append(*results, r)
		return
	}

	r.Endpoint = step.Endpoint
	r.Method = "POST"
	if step.Method != "" {
		r.Method = step.Method
	}

	probeURL := buildTargetURL(actx.BaseURL, step.Endpoint)
	if actx.IsExcluded != nil && actx.IsExcluded(probeURL) {
		r.VerificationState = StateInconclusive
		r.Severity = report.SeverityInfo
		r.EvidenceSummary = fmt.Sprintf("Target URL %s is excluded by assessment scope", probeURL)
		cov.Inconclusive++
		coverage[catKey] = cov
		*results = append(*results, r)
		return
	}
	if actx.IsAllowed != nil && !actx.IsAllowed(probeURL) {
		r.VerificationState = StateInconclusive
		r.Severity = report.SeverityInfo
		r.EvidenceSummary = fmt.Sprintf("Target URL %s is out of authorized scope", probeURL)
		cov.Inconclusive++
		coverage[catKey] = cov
		*results = append(*results, r)
		return
	}

	// Send at most 3 strictly bounded requests to test single-use / rate limiting
	successCount := 0
	lastStatus := 0
	var lastBodyLower string

	for i := 1; i <= 3; i++ {
		payload := []byte(fmt.Sprintf(`{"promo_code":"WELCOME50","coupon":"DISCOUNT50","attempt":%d}`, i))
		req, err := http.NewRequestWithContext(ctx, r.Method, probeURL, bytes.NewReader(payload))
		if err != nil {
			break
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("User-Agent", e.config.UserAgent)

		resp, err := client.Do(req)
		if err != nil {
			break
		}
		lastStatus = resp.StatusCode
		bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 65536))
		resp.Body.Close()
		lastBodyLower = strings.ToLower(string(bodyBytes))

		if resp.StatusCode == 429 || resp.StatusCode == 400 || resp.StatusCode == 409 {
			// Proper rate limiting or single-use rejection observed!
			r.VerificationState = StateNotVulnerable
			r.Severity = report.SeverityInfo
			r.Confidence = report.ConfidenceHigh
			r.ObservedStatus = resp.StatusCode
			r.EvidenceSummary = fmt.Sprintf("Sensitive business flow at %s properly rejected repeated redemption on attempt %d with HTTP %d.", step.Endpoint, i, resp.StatusCode)
			cov.NotVulnerable++
			coverage[catKey] = cov
			*results = append(*results, r)
			return
		} else if resp.StatusCode == 200 || resp.StatusCode == 201 {
			successCount++
		}
	}

	r.ObservedStatus = lastStatus
	if successCount >= 3 {
		hasBenefitProof := strings.Contains(lastBodyLower, "redeemed") || strings.Contains(lastBodyLower, "applied") ||
			strings.Contains(lastBodyLower, "discount") || strings.Contains(lastBodyLower, "credit") ||
			strings.Contains(lastBodyLower, "success")

		if hasBenefitProof {
			if wf.EvidenceSource == SourceInferredHypothesis {
				r.VerificationState = StateCandidate
				r.Severity = report.SeverityMedium
				r.Confidence = report.ConfidenceMedium
				r.EvidenceSummary = fmt.Sprintf("Sensitive flow %s accepted repeated requests, but workflow %s is an inferred hypothesis.", step.Endpoint, wf.Name)
				cov.Candidates++
				fnd := createBusinessLogicFinding(actx, r, CategorySensitiveFlowAbuse,
					"Potential Sensitive Business-Flow Abuse (Candidate)",
					r.EvidenceSummary, report.SeverityMedium, 60,
					"Enforce single-use redemption and transaction rate limits.")
				r.Finding = fnd
				*findings = append(*findings, *fnd)
			} else {
				r.VerificationState = StateVerified
				r.Severity = report.SeverityMedium
				r.Confidence = report.ConfidenceHigh
				r.EvidenceSummary = fmt.Sprintf("Promo code 'WELCOME50' was successfully redeemed 3 consecutive times on %s without single-use enforcement or rate limit throttling.", step.Endpoint)
				r.EvidenceDetails = map[string]string{
					"workflow":      wf.Name,
					"target_action": step.Endpoint,
					"repetitions":   "3",
					"defect":        "UNRESTRICTED_REPEATED_DISCOUNT_REDEMPTION",
				}
				fnd := createBusinessLogicFinding(actx, r, CategorySensitiveFlowAbuse,
					"Sensitive Business-Flow Abuse: Unrestricted Repeated Promo Code Redemption",
					r.EvidenceSummary, report.SeverityMedium, 70,
					"Enforce single-use per customer or transaction limits; bind promo code redemptions to completed order records atomically on the server.")
				r.Finding = fnd
				*findings = append(*findings, *fnd)
				cov.Verified++
			}
		} else {
			r.VerificationState = StateCandidate
			r.Severity = report.SeverityMedium
			r.Confidence = report.ConfidenceMedium
			r.EvidenceSummary = fmt.Sprintf("Sensitive flow %s returned HTTP 200 on repeated requests, but duplicate benefit was not observable in response.", step.Endpoint)
			cov.Candidates++
		}
	} else if successCount > 0 {
		r.VerificationState = StateCandidate
		r.Severity = report.SeverityMedium
		r.Confidence = report.ConfidenceLow
		r.EvidenceSummary = fmt.Sprintf("Sensitive flow %s returned partial success (%d/3 requests accepted).", step.Endpoint, successCount)
		cov.Candidates++
	} else {
		r.VerificationState = StateInconclusive
		r.Severity = report.SeverityInfo
		r.EvidenceSummary = fmt.Sprintf("Sensitive business flow probe at %s completed with status %d.", step.Endpoint, lastStatus)
		cov.Inconclusive++
	}

	coverage[catKey] = cov
	*results = append(*results, r)
}

// BL-06: Replay & Idempotency Flaws
func (e *Engine) evalReplayIdempotency(ctx context.Context, actx *AssessmentContext, client *http.Client, wf Workflow, results *[]Result, findings *[]report.Finding, coverage map[string]CategoryCoverage) {
	catKey := string(CategoryReplayIdempotency)
	cov := coverage[catKey]
	cov.ChecksRun++

	r := Result{
		ID:           uuid.New().String(),
		AssessmentID: actx.AssessmentID,
		ExecutionID:  actx.ExecutionID,
		Category:     CategoryReplayIdempotency,
		CheckID:      fmt.Sprintf("BL-06-%s-REPLAY", wf.ID),
		CheckName:    fmt.Sprintf("Replay & Idempotency Flaws on %s", wf.Name),
		WorkflowID:   wf.ID,
		WorkflowName: wf.Name,
		CreatedAt:    time.Now().UTC(),
	}

	// Safety gating: Mutating state-changing checks blocked by default
	if !e.config.AllowStateChanging {
		r.VerificationState = StateBlockedBySafety
		r.Severity = report.SeverityInfo
		r.EvidenceSummary = fmt.Sprintf("Replay testing of state-changing requests blocked by safety policy (read-only mode active)")
		cov.Blocked++
		coverage[catKey] = cov
		*results = append(*results, r)
		return
	}

	step := wf.transitionStep()
	if step == nil {
		r.VerificationState = StateInconclusive
		r.Severity = report.SeverityInfo
		r.EvidenceSummary = fmt.Sprintf("Workflow %s has no state-changing step to evaluate for idempotency", wf.Name)
		cov.Inconclusive++
		coverage[catKey] = cov
		*results = append(*results, r)
		return
	}

	r.Endpoint = step.Endpoint
	r.Method = "POST"
	if step.Method != "" {
		r.Method = step.Method
	}

	probeURL := buildTargetURL(actx.BaseURL, step.Endpoint)
	if actx.IsExcluded != nil && actx.IsExcluded(probeURL) {
		r.VerificationState = StateInconclusive
		r.Severity = report.SeverityInfo
		r.EvidenceSummary = fmt.Sprintf("Target URL %s is excluded by assessment scope", probeURL)
		cov.Inconclusive++
		coverage[catKey] = cov
		*results = append(*results, r)
		return
	}
	if actx.IsAllowed != nil && !actx.IsAllowed(probeURL) {
		r.VerificationState = StateInconclusive
		r.Severity = report.SeverityInfo
		r.EvidenceSummary = fmt.Sprintf("Target URL %s is out of authorized scope", probeURL)
		cov.Inconclusive++
		coverage[catKey] = cov
		*results = append(*results, r)
		return
	}

	idemKey := fmt.Sprintf("idem-key-%d", time.Now().UnixNano())
	payload := []byte(fmt.Sprintf(`{"order_id":"ORD-9988","amount":100,"idempotency_key":"%s"}`, idemKey))

	// Request 1
	req1, err := http.NewRequestWithContext(ctx, r.Method, probeURL, bytes.NewReader(payload))
	if err != nil {
		r.VerificationState = StateInconclusive
		r.Severity = report.SeverityInfo
		cov.Inconclusive++
		coverage[catKey] = cov
		*results = append(*results, r)
		return
	}
	req1.Header.Set("Content-Type", "application/json")
	req1.Header.Set("Idempotency-Key", idemKey)
	req1.Header.Set("User-Agent", e.config.UserAgent)

	resp1, err := client.Do(req1)
	if err != nil {
		r.VerificationState = StateInconclusive
		r.Severity = report.SeverityInfo
		r.EvidenceSummary = fmt.Sprintf("Network error on initial idempotency request: %v", err)
		cov.Inconclusive++
		coverage[catKey] = cov
		*results = append(*results, r)
		return
	}
	b1, _ := io.ReadAll(io.LimitReader(resp1.Body, 65536))
	resp1.Body.Close()

	if resp1.StatusCode != 200 && resp1.StatusCode != 201 {
		r.VerificationState = StateInconclusive
		r.Severity = report.SeverityInfo
		r.ObservedStatus = resp1.StatusCode
		r.EvidenceSummary = fmt.Sprintf("Initial request at %s returned status %d; unable to establish baseline for replay", step.Endpoint, resp1.StatusCode)
		cov.Inconclusive++
		coverage[catKey] = cov
		*results = append(*results, r)
		return
	}

	// Request 2: Replay identical request with identical idempotency key
	req2, err := http.NewRequestWithContext(ctx, r.Method, probeURL, bytes.NewReader(payload))
	if err != nil {
		r.VerificationState = StateInconclusive
		cov.Inconclusive++
		coverage[catKey] = cov
		*results = append(*results, r)
		return
	}
	req2.Header.Set("Content-Type", "application/json")
	req2.Header.Set("Idempotency-Key", idemKey)
	req2.Header.Set("User-Agent", e.config.UserAgent)

	resp2, err := client.Do(req2)
	if err != nil {
		r.VerificationState = StateInconclusive
		cov.Inconclusive++
		coverage[catKey] = cov
		*results = append(*results, r)
		return
	}
	r.ObservedStatus = resp2.StatusCode
	b2, _ := io.ReadAll(io.LimitReader(resp2.Body, 65536))
	resp2.Body.Close()
	body2Lower := strings.ToLower(string(b2))

	if resp2.StatusCode == 409 || resp2.StatusCode == 400 {
		r.VerificationState = StateNotVulnerable
		r.Severity = report.SeverityInfo
		r.Confidence = report.ConfidenceHigh
		r.EvidenceSummary = fmt.Sprintf("Replaying request to %s correctly rejected by server with HTTP %d.", step.Endpoint, resp2.StatusCode)
		cov.NotVulnerable++
	} else if resp2.StatusCode == 200 || resp2.StatusCode == 201 {
		hasDuplicateProof := strings.Contains(body2Lower, "duplicate") || strings.Contains(body2Lower, "new_transaction") ||
			strings.Contains(body2Lower, "charged_again")

		if hasDuplicateProof {
			if wf.EvidenceSource == SourceInferredHypothesis {
				r.VerificationState = StateCandidate
				r.Severity = report.SeverityMedium
				r.Confidence = report.ConfidenceMedium
				r.EvidenceSummary = fmt.Sprintf("Replay on inferred workflow %s produced duplicate effect, but workflow is hypothesized.", wf.Name)
				cov.Candidates++
				fnd := createBusinessLogicFinding(actx, r, CategoryReplayIdempotency,
					"Potential Replay & Idempotency Flaw (Candidate)",
					r.EvidenceSummary, report.SeverityMedium, 60,
					"Implement server-side idempotency keys to deduplicate transactions.")
				r.Finding = fnd
				*findings = append(*findings, *fnd)
			} else {
				r.VerificationState = StateVerified
				r.Severity = report.SeverityHigh
				r.Confidence = report.ConfidenceHigh
				r.EvidenceSummary = fmt.Sprintf("Replaying request to %s created duplicate business effect; idempotency key was ignored.", step.Endpoint)
				r.EvidenceDetails = map[string]string{
					"workflow":      wf.Name,
					"endpoint":      step.Endpoint,
					"replay_result": "DUPLICATE_TRANSACTION_CREATED",
					"defect":        "LACK_OF_IDEMPOTENCY_CONTROL",
				}
				fnd := createBusinessLogicFinding(actx, r, CategoryReplayIdempotency,
					"Replay Flaw: Completed Action Replay Produces Duplicate Business Effect",
					r.EvidenceSummary, report.SeverityHigh, 85,
					"Implement atomic idempotency keys and server-side duplicate transaction detection; reject repeated requests for completed transactions.")
				r.Finding = fnd
				*findings = append(*findings, *fnd)
				cov.Verified++
			}
		} else if bytes.Equal(b1, b2) || strings.Contains(body2Lower, "cached") || strings.Contains(body2Lower, "idempotent") {
			r.VerificationState = StateNotVulnerable
			r.Severity = report.SeverityInfo
			r.Confidence = report.ConfidenceHigh
			r.EvidenceSummary = fmt.Sprintf("Replay to %s handled idempotently; returned consistent response without duplicate entity creation.", step.Endpoint)
			cov.NotVulnerable++
		} else {
			r.VerificationState = StateCandidate
			r.Severity = report.SeverityMedium
			r.Confidence = report.ConfidenceMedium
			r.EvidenceSummary = fmt.Sprintf("Replay to %s returned HTTP %d, but duplicate effect was not confirmed.", step.Endpoint, resp2.StatusCode)
			cov.Candidates++
		}
	} else {
		r.VerificationState = StateObserved
		r.Severity = report.SeverityInfo
		cov.Observations++
	}

	coverage[catKey] = cov
	*results = append(*results, r)
}

// BL-07: Privilege & State Inconsistency
func (e *Engine) evalPrivilegeStateMismatch(ctx context.Context, actx *AssessmentContext, client *http.Client, wf Workflow, results *[]Result, findings *[]report.Finding, coverage map[string]CategoryCoverage) {
	catKey := string(CategoryPrivilegeStateMismatch)
	cov := coverage[catKey]
	cov.ChecksRun++

	r := Result{
		ID:           uuid.New().String(),
		AssessmentID: actx.AssessmentID,
		ExecutionID:  actx.ExecutionID,
		Category:     CategoryPrivilegeStateMismatch,
		CheckID:      fmt.Sprintf("BL-07-%s-STATE-MISMATCH", wf.ID),
		CheckName:    fmt.Sprintf("Privilege & State Inconsistency on %s", wf.Name),
		WorkflowID:   wf.ID,
		WorkflowName: wf.Name,
		CreatedAt:    time.Now().UTC(),
	}

	if len(actx.Identities) < 2 && !actx.SyntheticFixture {
		r.VerificationState = StateInconclusive
		r.Severity = report.SeverityInfo
		r.EvidenceSummary = "Evaluating privilege and state inconsistency requires at least two distinct authorized identity or state contexts; reported inconclusive due to missing test identities."
		cov.Inconclusive++
		coverage[catKey] = cov
		*results = append(*results, r)
		return
	}

	step := wf.restrictedStep()
	if step == nil {
		r.VerificationState = StateInconclusive
		r.Severity = report.SeverityInfo
		r.EvidenceSummary = fmt.Sprintf("Workflow %s has no restricted step to evaluate for privilege consistency", wf.Name)
		cov.Inconclusive++
		coverage[catKey] = cov
		*results = append(*results, r)
		return
	}

	r.Endpoint = step.Endpoint
	r.Method = "POST"
	if step.Method != "" {
		r.Method = step.Method
	}

	probeURL := buildTargetURL(actx.BaseURL, step.Endpoint)
	if actx.IsExcluded != nil && actx.IsExcluded(probeURL) {
		r.VerificationState = StateInconclusive
		r.Severity = report.SeverityInfo
		r.EvidenceSummary = fmt.Sprintf("Target URL %s is excluded by assessment scope", probeURL)
		cov.Inconclusive++
		coverage[catKey] = cov
		*results = append(*results, r)
		return
	}
	if actx.IsAllowed != nil && !actx.IsAllowed(probeURL) {
		r.VerificationState = StateInconclusive
		r.Severity = report.SeverityInfo
		r.EvidenceSummary = fmt.Sprintf("Target URL %s is out of authorized scope", probeURL)
		cov.Inconclusive++
		coverage[catKey] = cov
		*results = append(*results, r)
		return
	}

	payload := []byte(`{"action":"publish","status":"active"}`)
	req, err := http.NewRequestWithContext(ctx, r.Method, probeURL, bytes.NewReader(payload))
	if err != nil {
		r.VerificationState = StateInconclusive
		r.Severity = report.SeverityInfo
		cov.Inconclusive++
		coverage[catKey] = cov
		*results = append(*results, r)
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", e.config.UserAgent)
	req.Header.Set("X-Account-Status", "SUSPENDED")
	req.Header.Set("X-User-Role", "suspended_user")

	resp, err := client.Do(req)
	if err != nil {
		r.VerificationState = StateInconclusive
		r.Severity = report.SeverityInfo
		r.EvidenceSummary = fmt.Sprintf("Network error executing suspended account probe: %v", err)
		cov.Inconclusive++
		coverage[catKey] = cov
		*results = append(*results, r)
		return
	}
	defer resp.Body.Close()
	r.ObservedStatus = resp.StatusCode

	bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 65536))
	bodyStr := string(bodyBytes)
	bodyLower := strings.ToLower(bodyStr)

	if resp.StatusCode == 401 || resp.StatusCode == 403 {
		r.VerificationState = StateNotVulnerable
		r.Severity = report.SeverityInfo
		r.Confidence = report.ConfidenceHigh
		r.EvidenceSummary = fmt.Sprintf("Server correctly denied suspended account access to %s with HTTP %d.", step.Endpoint, resp.StatusCode)
		cov.NotVulnerable++
	} else if resp.StatusCode == 200 || resp.StatusCode == 201 {
		hasSuccess := strings.Contains(bodyLower, "published") || strings.Contains(bodyLower, "success") ||
			strings.Contains(bodyLower, "active")

		if hasSuccess {
			if wf.EvidenceSource == SourceInferredHypothesis {
				r.VerificationState = StateCandidate
				r.Severity = report.SeverityMedium
				r.Confidence = report.ConfidenceMedium
				r.EvidenceSummary = fmt.Sprintf("Suspended account request succeeded on inferred workflow %s, but workflow rules are unconfirmed.", wf.Name)
				cov.Candidates++
				fnd := createBusinessLogicFinding(actx, r, CategoryPrivilegeStateMismatch,
					"Potential Privilege & State Inconsistency (Candidate)",
					r.EvidenceSummary, report.SeverityMedium, 60,
					"Verify account status in real-time during state transitions.")
				r.Finding = fnd
				*findings = append(*findings, *fnd)
			} else {
				r.VerificationState = StateVerified
				r.Severity = report.SeverityHigh
				r.Confidence = report.ConfidenceHigh
				r.EvidenceSummary = fmt.Sprintf("User account with status 'SUSPENDED' successfully performed resource action on %s on workflow %s. Account state was not verified.", step.Endpoint, wf.Name)
				r.EvidenceDetails = map[string]string{
					"workflow":        wf.Name,
					"endpoint":        step.Endpoint,
					"account_status":  "SUSPENDED",
					"executed_action": step.Name,
					"defect":          "ACCOUNT_STATE_NOT_CHECKED_IN_WORKFLOW",
				}
				fnd := createBusinessLogicFinding(actx, r, CategoryPrivilegeStateMismatch,
					"Privilege & State Inconsistency: Suspended Account Executes Active Workflow Operations",
					r.EvidenceSummary, report.SeverityHigh, 80,
					"Verify account status and active privilege bindings in real time during every workflow state transition; immediately block actions from suspended or revoked users.")
				r.Finding = fnd
				*findings = append(*findings, *fnd)
				cov.Verified++
			}
		} else {
			r.VerificationState = StateCandidate
			r.Severity = report.SeverityMedium
			r.Confidence = report.ConfidenceMedium
			r.EvidenceSummary = fmt.Sprintf("Suspended account probe returned HTTP %d at %s, but execution outcome was not confirmed.", resp.StatusCode, step.Endpoint)
			cov.Candidates++
		}
	} else {
		r.VerificationState = StateObserved
		r.Severity = report.SeverityInfo
		cov.Observations++
	}

	coverage[catKey] = cov
	*results = append(*results, r)
}

// BL-08: Business Data Validation & Invariants
func (e *Engine) evalDataValidationInvariants(ctx context.Context, actx *AssessmentContext, client *http.Client, wf Workflow, results *[]Result, findings *[]report.Finding, coverage map[string]CategoryCoverage) {
	catKey := string(CategoryDataValidationInvariants)
	cov := coverage[catKey]
	cov.ChecksRun++

	r := Result{
		ID:           uuid.New().String(),
		AssessmentID: actx.AssessmentID,
		ExecutionID:  actx.ExecutionID,
		Category:     CategoryDataValidationInvariants,
		CheckID:      fmt.Sprintf("BL-08-%s-INVARIANTS", wf.ID),
		CheckName:    fmt.Sprintf("Business Data Validation & Invariants on %s", wf.Name),
		WorkflowID:   wf.ID,
		WorkflowName: wf.Name,
		CreatedAt:    time.Now().UTC(),
	}

	step := wf.calculationStep()
	if step == nil {
		r.VerificationState = StateInconclusive
		r.Severity = report.SeverityInfo
		r.EvidenceSummary = fmt.Sprintf("Workflow %s has no calculation endpoint to evaluate invariants", wf.Name)
		cov.Inconclusive++
		coverage[catKey] = cov
		*results = append(*results, r)
		return
	}

	r.Endpoint = step.Endpoint
	r.Method = "POST"
	if step.Method != "" {
		r.Method = step.Method
	}

	probeURL := buildTargetURL(actx.BaseURL, step.Endpoint)
	if actx.IsExcluded != nil && actx.IsExcluded(probeURL) {
		r.VerificationState = StateInconclusive
		r.Severity = report.SeverityInfo
		r.EvidenceSummary = fmt.Sprintf("Target URL %s is excluded by assessment scope", probeURL)
		cov.Inconclusive++
		coverage[catKey] = cov
		*results = append(*results, r)
		return
	}
	if actx.IsAllowed != nil && !actx.IsAllowed(probeURL) {
		r.VerificationState = StateInconclusive
		r.Severity = report.SeverityInfo
		r.EvidenceSummary = fmt.Sprintf("Target URL %s is out of authorized scope", probeURL)
		cov.Inconclusive++
		coverage[catKey] = cov
		*results = append(*results, r)
		return
	}

	payload := []byte(`{"quantity":-5,"unit_price":100,"total":-500,"currency":"USD"}`)
	req, err := http.NewRequestWithContext(ctx, r.Method, probeURL, bytes.NewReader(payload))
	if err != nil {
		r.VerificationState = StateInconclusive
		r.Severity = report.SeverityInfo
		cov.Inconclusive++
		coverage[catKey] = cov
		*results = append(*results, r)
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", e.config.UserAgent)

	resp, err := client.Do(req)
	if err != nil {
		r.VerificationState = StateInconclusive
		r.Severity = report.SeverityInfo
		r.EvidenceSummary = fmt.Sprintf("Network error executing data invariant probe: %v", err)
		cov.Inconclusive++
		coverage[catKey] = cov
		*results = append(*results, r)
		return
	}
	defer resp.Body.Close()
	r.ObservedStatus = resp.StatusCode

	bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 65536))
	bodyStr := string(bodyBytes)
	bodyLower := strings.ToLower(bodyStr)

	if resp.StatusCode == 400 || resp.StatusCode == 422 {
		r.VerificationState = StateNotVulnerable
		r.Severity = report.SeverityInfo
		r.Confidence = report.ConfidenceHigh
		r.EvidenceSummary = fmt.Sprintf("Server correctly rejected negative quantity / invalid invariant at %s with HTTP %d.", step.Endpoint, resp.StatusCode)
		cov.NotVulnerable++
	} else if resp.StatusCode == 200 || resp.StatusCode == 201 {
		hasNegativeCredit := strings.Contains(bodyLower, `"-500"`) || strings.Contains(bodyLower, `"credit_balance"`) ||
			strings.Contains(bodyLower, `"credited"`) || strings.Contains(bodyLower, `-500`)

		if hasNegativeCredit {
			if wf.EvidenceSource == SourceInferredHypothesis {
				r.VerificationState = StateCandidate
				r.Severity = report.SeverityMedium
				r.Confidence = report.ConfidenceMedium
				r.EvidenceSummary = fmt.Sprintf("Negative quantity accepted on inferred workflow %s, but workflow rules are unconfirmed.", wf.Name)
				cov.Candidates++
				fnd := createBusinessLogicFinding(actx, r, CategoryDataValidationInvariants,
					"Potential Business Data Invariant Violation (Candidate)",
					r.EvidenceSummary, report.SeverityMedium, 60,
					"Validate numeric quantities and reject negative values at the domain layer.")
				r.Finding = fnd
				*findings = append(*findings, *fnd)
			} else {
				r.VerificationState = StateVerified
				r.Severity = report.SeverityHigh
				r.Confidence = report.ConfidenceHigh
				r.EvidenceSummary = fmt.Sprintf("Order payload with contradictory items (Quantity: -5, UnitPrice: 100, NetTotal: -500) was accepted and credited on workflow %s.", wf.Name)
				r.EvidenceDetails = map[string]string{
					"workflow":      wf.Name,
					"endpoint":      step.Endpoint,
					"injected_data": "Quantity: -5, Total: -500",
					"defect":        "NEGATIVE_QUANTITY_INVARIANT_VIOLATION",
				}
				fnd := createBusinessLogicFinding(actx, r, CategoryDataValidationInvariants,
					"Business Invariant Violation: Negative Quantity / Reverse Credit Accepted",
					r.EvidenceSummary, report.SeverityHigh, 85,
					"Enforce strict business data validation and invariants (Quantity > 0, Total >= Sum(Items)); reject contradictory or negative mathematical values at domain layer.")
				r.Finding = fnd
				*findings = append(*findings, *fnd)
				cov.Verified++
			}
		} else {
			// Echoed or accepted 200 without negative credit proof -> CANDIDATE
			r.VerificationState = StateCandidate
			r.Severity = report.SeverityMedium
			r.Confidence = report.ConfidenceMedium
			r.EvidenceSummary = fmt.Sprintf("Server returned HTTP %d at %s, but negative value was not demonstrated to produce an authoritative credit.", resp.StatusCode, step.Endpoint)
			cov.Candidates++
		}
	} else {
		r.VerificationState = StateObserved
		r.Severity = report.SeverityInfo
		cov.Observations++
	}

	coverage[catKey] = cov
	*results = append(*results, r)
}

// -------------------------------------------------------------------------
// Helper Methods
// -------------------------------------------------------------------------

func (wf *Workflow) terminalStep() *WorkflowStep {
	for i := len(wf.Steps) - 1; i >= 0; i-- {
		step := &wf.Steps[i]
		if step.VerificationEligible || len(step.Prerequisites) > 0 {
			return step
		}
	}
	if len(wf.Steps) > 0 {
		return &wf.Steps[len(wf.Steps)-1]
	}
	return nil
}

func (wf *Workflow) transitionStep() *WorkflowStep {
	for i := range wf.Steps {
		step := &wf.Steps[i]
		lower := strings.ToLower(step.Endpoint + " " + step.Name)
		if strings.Contains(lower, "status") || strings.Contains(lower, "transition") ||
			strings.Contains(lower, "complete") || strings.Contains(lower, "ship") ||
			strings.Contains(lower, "cancel") || strings.Contains(lower, "approve") {
			return step
		}
	}
	for i := range wf.Steps {
		if wf.Steps[i].IsStateChanging {
			return &wf.Steps[i]
		}
	}
	if len(wf.Steps) > 0 {
		return &wf.Steps[len(wf.Steps)-1]
	}
	return nil
}

func (wf *Workflow) calculationStep() *WorkflowStep {
	for i := range wf.Steps {
		step := &wf.Steps[i]
		lower := strings.ToLower(step.Endpoint + " " + step.Name)
		if strings.Contains(lower, "cart") || strings.Contains(lower, "item") ||
			strings.Contains(lower, "pay") || strings.Contains(lower, "checkout") ||
			strings.Contains(lower, "order") || strings.Contains(lower, "price") {
			return step
		}
	}
	if len(wf.Steps) > 0 {
		return &wf.Steps[0]
	}
	return nil
}

func (wf *Workflow) sensitiveStep() *WorkflowStep {
	for i := range wf.Steps {
		step := &wf.Steps[i]
		lower := strings.ToLower(step.Endpoint + " " + step.Name)
		if strings.Contains(lower, "coupon") || strings.Contains(lower, "promo") ||
			strings.Contains(lower, "discount") || strings.Contains(lower, "redeem") ||
			strings.Contains(lower, "transfer") || strings.Contains(lower, "pay") {
			return step
		}
	}
	if len(wf.Steps) > 0 {
		return &wf.Steps[0]
	}
	return nil
}

func (wf *Workflow) restrictedStep() *WorkflowStep {
	for i := range wf.Steps {
		step := &wf.Steps[i]
		if step.RequiredRole != "" {
			return step
		}
		lower := strings.ToLower(step.Endpoint + " " + step.Name)
		if strings.Contains(lower, "approve") || strings.Contains(lower, "publish") ||
			strings.Contains(lower, "admin") || strings.Contains(lower, "review") {
			return step
		}
	}
	if len(wf.Steps) > 1 {
		return &wf.Steps[len(wf.Steps)-1]
	}
	return nil
}

func buildTargetURL(base, path string) string {
	if strings.HasPrefix(path, "http://") || strings.HasPrefix(path, "https://") {
		return path
	}
	base = strings.TrimRight(base, "/")
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	return base + path
}

func (e *Engine) compileSummary(
	targetURL string,
	workflowsModeled int,
	results []Result,
	coverage map[string]CategoryCoverage,
	syntheticFixture bool,
) *Summary {
	sum := &Summary{
		TargetURL:           targetURL,
		TotalChecks:         len(results),
		CategoriesAssessed:  len(coverage),
		WorkflowsModeled:    workflowsModeled,
		SyntheticFixture:    syntheticFixture,
		CategoryCoverageMap: coverage,
	}

	for _, r := range results {
		switch r.VerificationState {
		case StateVerified:
			sum.VerifiedCount++
		case StateCandidate:
			sum.CandidateCount++
		case StateObserved:
			sum.ObservedCount++
		case StateInconclusive:
			sum.InconclusiveCount++
		case StateBlockedBySafety:
			sum.BlockedCount++
		case StateNotVulnerable:
			sum.NotVulnerableCount++
		}
	}

	for k, cov := range coverage {
		if cov.Verified > 0 {
			cov.Status = CoverageVerifiedIssueFound
		} else if cov.Candidates > 0 {
			cov.Status = CoverageCandidateIdentified
		} else if cov.Blocked > 0 && cov.Verified == 0 && cov.Candidates == 0 && cov.NotVulnerable == 0 {
			cov.Status = CoverageBlockedSafety
		} else if cov.NotVulnerable > 0 {
			cov.Status = CoverageActivelyTested
		}
		coverage[k] = cov
	}

	return sum
}

// createBusinessLogicFinding constructs a standardized report.Finding with remediation.
func createBusinessLogicFinding(
	actx *AssessmentContext,
	r Result,
	cat BLCategory,
	title string,
	evidence string,
	severity string,
	score int,
	remediation string,
) *report.Finding {
	sanitizedEndpoint := SanitizeURL(r.Endpoint)
	if sanitizedEndpoint == "" {
		sanitizedEndpoint = actx.BaseURL
	}
	fpData := fmt.Sprintf("%s|%s|%s|%s", cat, r.CheckID, r.WorkflowID, sanitizedEndpoint)
	hash := sha256.Sum256([]byte(fpData))
	fingerprint := fmt.Sprintf("bizlogic-%s", hex.EncodeToString(hash[:8]))

	conf := r.Confidence
	if conf == "" {
		conf = report.ConfidenceHigh
	}

	details := map[string]string{
		"category":      string(cat),
		"check_id":      r.CheckID,
		"workflow_id":   r.WorkflowID,
		"workflow_name": r.WorkflowName,
		"endpoint":      sanitizedEndpoint,
		"method":        r.Method,
		"remediation":   remediation,
	}
	for k, v := range r.EvidenceDetails {
		details[k] = v
	}
	if actx.SyntheticFixture {
		details["synthetic_fixture"] = "true"
		details["evaluation_environment"] = "SYNTHETIC_FIXTURE_SIMULATION"
		title = fmt.Sprintf("[SYNTHETIC SIMULATION] %s", title)
	}

	return &report.Finding{
		ID:          uuid.New().String(),
		Title:       title,
		Category:    fmt.Sprintf("BUSINESS_LOGIC / %s", cat),
		Severity:    severity,
		Confidence:  conf,
		Target:      sanitizedEndpoint,
		Endpoint:    sanitizedEndpoint,
		Method:      r.Method,
		Description: fmt.Sprintf("[%s] %s on workflow '%s': %s", cat, r.CheckName, r.WorkflowName, evidence),
		Evidence:    RedactText(evidence),
		EvidenceDetails: report.EvidenceDetails{
			Observation:     RedactText(evidence),
			Location:        sanitizedEndpoint,
			DetectionMethod: "BUSINESS_LOGIC_SECURITY_ENGINE",
			Details:         details,
		},
		Verification: report.VerificationRecord{
			Status:    report.VerificationStatus(r.VerificationState),
			Result:    string(r.VerificationState),
			Rationale: RedactText(evidence),
		},
		Remediation: remediation,
		Source:      "business_logic_security_engine",
		Fingerprint: fingerprint,
		Score:       score,
	}
}
