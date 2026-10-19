package workflow

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"

	"felix/pkg/crawler"
	"felix/pkg/report"
)

type credentialGuardedTransport struct {
	base        http.RoundTripper
	maxRequests int
	reqCount    *int32
}

func (c *credentialGuardedTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if c.maxRequests > 0 && c.reqCount != nil {
		for {
			curr := atomic.LoadInt32(c.reqCount)
			if int(curr) >= c.maxRequests {
				return nil, fmt.Errorf("assessment request budget exceeded (%d/%d)", curr, c.maxRequests)
			}
			if atomic.CompareAndSwapInt32(c.reqCount, curr, curr+1) {
				break
			}
		}
	} else if c.reqCount != nil {
		atomic.AddInt32(c.reqCount, 1)
	}

	// Withhold sensitive credentials when transmitting over remote unencrypted HTTP
	if strings.EqualFold(req.URL.Scheme, "http") && !IsLoopbackHost(req.URL.Hostname()) {
		reqClone := req.Clone(req.Context())
		StripSensitiveCredentials(reqClone)
		return c.base.RoundTrip(reqClone)
	}
	return c.base.RoundTrip(req)
}

// Engine executes workflow integrity and multi-step business logic invariant verification.
type Engine struct {
	client *http.Client
	cfg    Config
}

// NewEngine creates an Engine instance with safe defaults.
func NewEngine(client *http.Client, cfg Config) *Engine {
	if cfg.Timeout == 0 {
		cfg.Timeout = 15 * time.Second
	}
	if cfg.MaxResponseBytes == 0 {
		cfg.MaxResponseBytes = 2 * 1024 * 1024
	}
	if cfg.Concurrency <= 0 {
		cfg.Concurrency = 3
	}
	if client == nil {
		safeTransport := crawler.NewSafeTransport(crawler.SafeTransportOptions{
			Timeout:       cfg.Timeout,
			AllowLoopback: true,
		})
		client = &http.Client{
			Transport: crawler.NewRateLimitedTransport(safeTransport, crawler.RateLimitOptions{}),
			Timeout:   cfg.Timeout,
		}
	}
	return &Engine{
		client: client,
		cfg:    cfg,
	}
}

// scopedClient creates an isolated http.Client scoped to an assessment execution.
func (e *Engine) scopedClient(actx *AssessmentContext) *http.Client {
	baseTransport := e.client.Transport
	if baseTransport == nil {
		uTarget, _ := url.Parse(actx.BaseURL)
		isLoopback := uTarget != nil && IsLoopbackHost(uTarget.Hostname())
		safeTransport := crawler.NewSafeTransport(crawler.SafeTransportOptions{
			Timeout:       e.cfg.Timeout,
			AllowLoopback: isLoopback,
		})
		baseTransport = crawler.NewRateLimitedTransport(safeTransport, crawler.RateLimitOptions{})
	}

	guard := &credentialGuardedTransport{
		base:        baseTransport,
		maxRequests: actx.MaxRequests,
		reqCount:    actx.DispatchedRequests,
	}

	return &http.Client{
		Transport: guard,
		Timeout:   e.cfg.Timeout,
		Jar:       nil, // Prevent cookie bleed across distinct principals
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 10 {
				return fmt.Errorf("stopped after 10 redirects")
			}
			if len(via) > 0 {
				prevURL := via[len(via)-1].URL
				if !IsSameOrigin(req.URL, prevURL) {
					StripSensitiveCredentials(req)
				}
			}
			return nil
		},
	}
}

// Plan produces a pre-assessment test plan without dispatching network requests (dry-run).
func (e *Engine) Plan(ctx context.Context, actx *AssessmentContext) (*TestPlan, error) {
	if actx == nil {
		return nil, fmt.Errorf("assessment context is nil")
	}
	if actx.BaseURL == "" {
		return nil, fmt.Errorf("base target URL is required")
	}

	workflows := actx.Workflows
	if len(workflows) == 0 {
		workflows = DefaultWorkflows()
	}

	plan := &TestPlan{
		AssessmentID:   actx.AssessmentID,
		TargetURL:      actx.BaseURL,
		GeneratedAt:    time.Now().UTC(),
		TotalWorkflows: len(workflows),
		PlannedChecks:  make([]PlannedCheck, 0),
	}

	for _, wf := range workflows {
		// Graph validation
		if err := ValidateWorkflow(wf); err != nil {
			pc := PlannedCheck{
				ID:            fmt.Sprintf("plan-%s-validation", wf.ID),
				WorkflowID:    wf.ID,
				Name:          fmt.Sprintf("Workflow Validation for %s", wf.Name),
				Status:        PlanBlocked,
				BlockedReason: fmt.Sprintf("Workflow validation failed: %v", err),
			}
			plan.BlockedChecks++
			plan.PlannedChecks = append(plan.PlannedChecks, pc)
			continue
		}

		cats := wf.CategoriesToAssess
		if len(cats) == 0 {
			cats = AllCategories()
		}

		for _, cat := range cats {
			meta := CategoryMetadata[cat]
			pc := PlannedCheck{
				ID:                fmt.Sprintf("plan-%s-%s", wf.ID, cat),
				Category:          cat,
				Name:              fmt.Sprintf("%s on %s", meta.Name, wf.Name),
				WorkflowID:        wf.ID,
				OWASPRef:          meta.OWASP,
				CWERef:            meta.CWE,
				SecurityObjective: meta.Description,
				Preconditions:     meta.Preconditions,
				Status:            PlanReady,
			}

			// Identify if check involves state mutation
			isMutation := cat == CategoryReplayIdempotency ||
				cat == CategoryConcurrentTransition ||
				cat == CategoryInvalidOrdering ||
				wf.HasStateChangingStep()

			pc.IsStateChanging = isMutation
			if isMutation {
				plan.StateChangingChecks++
			}

			// Target endpoint resolution for primary step
			primaryStep := wf.Steps[len(wf.Steps)-1]
			pc.Endpoint = primaryStep.Endpoint
			pc.Method = primaryStep.Method
			pc.StepID = primaryStep.ID

			fullURL, err := ResolveURL(actx.BaseURL, primaryStep.Endpoint)
			if err != nil {
				pc.Status = PlanBlocked
				pc.BlockedReason = fmt.Sprintf("Endpoint resolution error: %v", err)
				plan.BlockedChecks++
				plan.PlannedChecks = append(plan.PlannedChecks, pc)
				continue
			}

			// Evaluate safety gating
			if actx.IsExcluded != nil && actx.IsExcluded(fullURL) {
				pc.Status = PlanSkipped
				pc.BlockedReason = "Target endpoint is excluded by assessment scope rules"
				plan.BlockedChecks++
			} else if isMutation && !actx.AllowStateChangingTests {
				pc.Status = PlanSkipped
				pc.BlockedReason = "State-changing workflow tests require explicit --allow-state-changing opt-in"
				plan.BlockedChecks++
			} else if isMutation && !actx.SyntheticFixture {
				pc.Status = PlanBlocked
				pc.BlockedReason = "State-changing workflow tests are restricted to designated synthetic fixtures or isolated test environments"
				plan.BlockedChecks++
			} else if isMutation && !IsIsolatedFixtureTarget(fullURL, actx.AuthorizedFixtureHosts, actx.IsFixtureTarget) {
				pc.Status = PlanBlocked
				pc.BlockedReason = "State-changing workflow tests blocked: target is not an authorized synthetic fixture or isolated test environment"
				plan.BlockedChecks++
			} else if cat == CategoryIdentityContinuity && len(actx.Identities) < 2 {
				pc.Status = PlanBlocked
				pc.BlockedReason = "Ownership continuity testing requires at least two distinct identity contexts"
				plan.BlockedChecks++
			} else {
				pc.Status = PlanReady
				plan.ReadyChecks++
			}

			plan.PlannedChecks = append(plan.PlannedChecks, pc)
		}
	}

	plan.TotalPlannedChecks = len(plan.PlannedChecks)
	return plan, nil
}

// Assess executes active workflow integrity assessment against target endpoints.
func (e *Engine) Assess(ctx context.Context, actx *AssessmentContext) ([]Result, *Summary, error) {
	if actx == nil {
		return nil, nil, fmt.Errorf("assessment context is nil")
	}
	if actx.BaseURL == "" {
		return nil, nil, fmt.Errorf("base target URL is required")
	}

	// Mandatory Authorization Precondition
	if actx.Authorization == nil {
		return nil, nil, fmt.Errorf("refused: assessment lacks authorization record")
	}
	valid, reason := actx.Authorization.IsCurrentlyValid(time.Now().UTC())
	if !valid {
		return nil, nil, fmt.Errorf("refused: authorization invalid (%s)", reason)
	}

	// Dry run returns zero network requests
	if actx.DryRun {
		return []Result{}, &Summary{CategoryCoverageMap: make(map[string]CategoryCoverage)}, nil
	}

	workflows := actx.Workflows
	if len(workflows) == 0 {
		workflows = DefaultWorkflows()
	}

	identities := actx.Identities
	if len(identities) == 0 {
		identities = DefaultIdentities()
	}

	// Initialize budget and scoped client
	if actx.DispatchedRequests == nil {
		var initialReqs int32
		actx.DispatchedRequests = &initialReqs
	}
	client := e.scopedClient(actx)

	results := make([]Result, 0)

	for _, wf := range workflows {
		if ctx.Err() != nil {
			return nil, nil, ctx.Err()
		}

		// Validate workflow graph
		if err := ValidateWorkflow(wf); err != nil {
			res := makeErrorResult(actx, wf, "", "Validation", fmt.Sprintf("Workflow graph validation failed: %v", err))
			results = append(results, res)
			continue
		}

		cats := wf.CategoriesToAssess
		if len(cats) == 0 {
			cats = AllCategories()
		}

		for _, cat := range cats {
			if ctx.Err() != nil {
				return nil, nil, ctx.Err()
			}

			switch cat {
			case CategoryPrerequisiteSkipping:
				res := e.assessPrerequisiteSkipping(ctx, client, actx, wf, identities)
				results = append(results, res...)

			case CategoryInvalidOrdering:
				res := e.assessInvalidOrdering(ctx, client, actx, wf, identities)
				results = append(results, res...)

			case CategoryReplayIdempotency:
				res := e.assessReplayIdempotency(ctx, client, actx, wf, identities)
				results = append(results, res...)

			case CategoryTokenContinuity:
				res := e.assessTokenContinuity(ctx, client, actx, wf, identities)
				results = append(results, res...)

			case CategoryIdentityContinuity:
				res := e.assessIdentityContinuity(ctx, client, actx, wf, identities)
				results = append(results, res...)

			case CategoryConcurrentTransition:
				res := e.assessConcurrentTransition(ctx, client, actx, wf, identities)
				results = append(results, res...)
			}
		}
	}

	summary := compileSummary(results, workflows)
	return results, summary, nil
}

// -------------------------------------------------------------------------
// Category A: Missing Prerequisite & Step Circumvention
// -------------------------------------------------------------------------

func (e *Engine) assessPrerequisiteSkipping(ctx context.Context, client *http.Client, actx *AssessmentContext, wf Workflow, identities []TestIdentity) []Result {
	var results []Result

	// Find steps that have preconditions
	for _, step := range wf.Steps {
		if len(step.Preconditions) == 0 {
			continue
		}

		fullURL, err := ResolveURL(actx.BaseURL, step.Endpoint)
		if err != nil {
			results = append(results, makeErrorResult(actx, wf, step.ID, "URLResolution", fmt.Sprintf("Invalid URL: %v", err)))
			continue
		}

		// Scope checks
		if actx.IsAllowed != nil && !actx.IsAllowed(fullURL) {
			results = append(results, makeSkippedResult(actx, wf, step.ID, CategoryPrerequisiteSkipping, "Endpoint out of scope"))
			continue
		}
		if actx.IsExcluded != nil && actx.IsExcluded(fullURL) {
			results = append(results, makeSkippedResult(actx, wf, step.ID, CategoryPrerequisiteSkipping, "Endpoint excluded by scope rules"))
			continue
		}

		// State-changing safety guard
		if step.IsStateChanging {
			if !actx.AllowStateChangingTests {
				results = append(results, makeSkippedResult(actx, wf, step.ID, CategoryPrerequisiteSkipping, "State-changing test blocked: requires explicit --allow-state-changing opt-in"))
				continue
			}
			if !actx.SyntheticFixture {
				results = append(results, makeSkippedResult(actx, wf, step.ID, CategoryPrerequisiteSkipping, "State-changing test blocked: write mutations are restricted to designated synthetic fixtures"))
				continue
			}
			if !IsIsolatedFixtureTarget(fullURL, actx.AuthorizedFixtureHosts, actx.IsFixtureTarget) {
				results = append(results, makeSkippedResult(actx, wf, step.ID, CategoryPrerequisiteSkipping, fmt.Sprintf("State-changing test blocked: target %q is not an authorized synthetic fixture", fullURL)))
				continue
			}
		}

		ident := selectIdentity(step.RequiredRole, identities)

		// Positive control baseline: execute prerequisite flow first
		var baselineResp ResponseData
		for _, prereqID := range step.Preconditions {
			prereqStep := findStep(wf, prereqID)
			if prereqStep != nil {
				prereqURL, err := ResolveURL(actx.BaseURL, prereqStep.Endpoint)
				if err == nil {
					baseData, err := e.executeRequest(ctx, client, prereqStep.Method, prereqURL, prereqStep.Payload, ident)
					if err == nil {
						baselineResp = baseData
					}
				}
			}
		}

		// Circumvention probe: invoke later step directly WITHOUT satisfying prerequisites
		skipResp, err := e.executeRequest(ctx, client, step.Method, fullURL, step.Payload, ident)
		if err != nil {
			results = append(results, Result{
				ID:                uuid.New().String(),
				AssessmentID:      actx.AssessmentID,
				ExecutionID:       actx.ExecutionID,
				Category:          CategoryPrerequisiteSkipping,
				VulnCode:          string(CategoryPrerequisiteSkipping),
				WorkflowID:        wf.ID,
				WorkflowName:      wf.Name,
				StepID:            step.ID,
				CheckID:           fmt.Sprintf("wf-%s-prereq-skip", step.ID),
				CheckName:         fmt.Sprintf("Prerequisite Skipping on %s", step.Name),
				OWASPRef:          CategoryMetadata[CategoryPrerequisiteSkipping].OWASP,
				CWERef:            CategoryMetadata[CategoryPrerequisiteSkipping].CWE,
				Endpoint:          step.Endpoint,
				Method:            step.Method,
				VerificationState: StateInconclusive,
				Severity:          "INFO",
				Confidence:        "LOW",
				EvidenceSummary:   fmt.Sprintf("Circumvention probe request failed: %v", err),
				CreatedAt:         time.Now().UTC(),
			})
			continue
		}

		// Independent read-back verification
		var readBackResp ResponseData
		if skipResp.StatusCode >= 200 && skipResp.StatusCode < 300 && step.VerificationEndpoint != "" {
			rbURL, err := ResolveURL(actx.BaseURL, step.VerificationEndpoint)
			if err == nil {
				rbMethod := step.VerificationMethod
				if rbMethod == "" {
					rbMethod = "GET"
				}
				rbData, err := e.executeRequest(ctx, client, rbMethod, rbURL, "", ident)
				if err == nil {
					readBackResp = rbData
				}
			}
		}

		comp := ComparePrerequisiteSkipping(baselineResp, skipResp, readBackResp, wf, step, "admin", ident.Role)
		res := Result{
			ID:                uuid.New().String(),
			AssessmentID:      actx.AssessmentID,
			ExecutionID:       actx.ExecutionID,
			Category:          CategoryPrerequisiteSkipping,
			VulnCode:          string(CategoryPrerequisiteSkipping),
			WorkflowID:        wf.ID,
			WorkflowName:      wf.Name,
			StepID:            step.ID,
			CheckID:           fmt.Sprintf("wf-%s-prereq-skip", step.ID),
			CheckName:         fmt.Sprintf("Prerequisite Skipping on %s", step.Name),
			OWASPRef:          CategoryMetadata[CategoryPrerequisiteSkipping].OWASP,
			CWERef:            CategoryMetadata[CategoryPrerequisiteSkipping].CWE,
			Endpoint:          step.Endpoint,
			Method:            step.Method,
			VerificationState: comp.State,
			Severity:          comp.Severity,
			Confidence:        comp.Confidence,
			ObservedStatus:    skipResp.StatusCode,
			EvidenceSummary:   comp.EvidenceSummary,
			EvidenceDetails:   comp.EvidenceDetails,
			CreatedAt:         time.Now().UTC(),
		}
		if comp.State == StateVerified || comp.State == StateCandidate {
			res.Finding = buildFinding(res, wf, step, comp, fullURL)
		}
		results = append(results, res)
	}

	return results
}

// -------------------------------------------------------------------------
// Category B: Invalid Ordering & State Transitions
// -------------------------------------------------------------------------

func (e *Engine) assessInvalidOrdering(ctx context.Context, client *http.Client, actx *AssessmentContext, wf Workflow, identities []TestIdentity) []Result {
	var results []Result

	for _, pt := range wf.ProhibitedTransitions {
		step := findStep(wf, pt.StepID)
		if step == nil {
			continue
		}

		fullURL, err := ResolveURL(actx.BaseURL, step.Endpoint)
		if err != nil {
			results = append(results, makeErrorResult(actx, wf, step.ID, "URLResolution", fmt.Sprintf("Invalid URL: %v", err)))
			continue
		}

		if actx.IsAllowed != nil && !actx.IsAllowed(fullURL) {
			results = append(results, makeSkippedResult(actx, wf, step.ID, CategoryInvalidOrdering, "Endpoint out of scope"))
			continue
		}
		if actx.IsExcluded != nil && actx.IsExcluded(fullURL) {
			results = append(results, makeSkippedResult(actx, wf, step.ID, CategoryInvalidOrdering, "Endpoint excluded by scope rules"))
			continue
		}

		if step.IsStateChanging {
			if !actx.AllowStateChangingTests {
				results = append(results, makeSkippedResult(actx, wf, step.ID, CategoryInvalidOrdering, "State-changing test blocked: requires explicit --allow-state-changing opt-in"))
				continue
			}
			if !actx.SyntheticFixture {
				results = append(results, makeSkippedResult(actx, wf, step.ID, CategoryInvalidOrdering, "State-changing test blocked: write mutations are restricted to designated synthetic fixtures"))
				continue
			}
			if !IsIsolatedFixtureTarget(fullURL, actx.AuthorizedFixtureHosts, actx.IsFixtureTarget) {
				results = append(results, makeSkippedResult(actx, wf, step.ID, CategoryInvalidOrdering, fmt.Sprintf("State-changing test blocked: target %q is not an authorized synthetic fixture", fullURL)))
				continue
			}
		}

		ident := selectIdentity(step.RequiredRole, identities)

		// Execute prohibited transition attempt
		orderResp, err := e.executeRequest(ctx, client, step.Method, fullURL, step.Payload, ident)
		if err != nil {
			results = append(results, Result{
				ID:                uuid.New().String(),
				AssessmentID:      actx.AssessmentID,
				ExecutionID:       actx.ExecutionID,
				Category:          CategoryInvalidOrdering,
				VulnCode:          string(CategoryInvalidOrdering),
				WorkflowID:        wf.ID,
				WorkflowName:      wf.Name,
				StepID:            step.ID,
				CheckID:           fmt.Sprintf("wf-%s-order", step.ID),
				CheckName:         fmt.Sprintf("Prohibited Transition (%s -> %s)", pt.FromState, pt.ToState),
				OWASPRef:          CategoryMetadata[CategoryInvalidOrdering].OWASP,
				CWERef:            CategoryMetadata[CategoryInvalidOrdering].CWE,
				Endpoint:          step.Endpoint,
				Method:            step.Method,
				VerificationState: StateInconclusive,
				Severity:          "INFO",
				Confidence:        "LOW",
				EvidenceSummary:   fmt.Sprintf("Order test request failed: %v", err),
				CreatedAt:         time.Now().UTC(),
			})
			continue
		}

		var readBackResp ResponseData
		if orderResp.StatusCode >= 200 && orderResp.StatusCode < 300 && step.VerificationEndpoint != "" {
			rbURL, err := ResolveURL(actx.BaseURL, step.VerificationEndpoint)
			if err == nil {
				rbMethod := step.VerificationMethod
				if rbMethod == "" {
					rbMethod = "GET"
				}
				rbData, err := e.executeRequest(ctx, client, rbMethod, rbURL, "", ident)
				if err == nil {
					readBackResp = rbData
				}
			}
		}

		comp := CompareInvalidOrdering(ResponseData{}, orderResp, readBackResp, wf, *step, pt)
		res := Result{
			ID:                uuid.New().String(),
			AssessmentID:      actx.AssessmentID,
			ExecutionID:       actx.ExecutionID,
			Category:          CategoryInvalidOrdering,
			VulnCode:          string(CategoryInvalidOrdering),
			WorkflowID:        wf.ID,
			WorkflowName:      wf.Name,
			StepID:            step.ID,
			CheckID:           fmt.Sprintf("wf-%s-order", step.ID),
			CheckName:         fmt.Sprintf("Prohibited Transition (%s -> %s)", pt.FromState, pt.ToState),
			OWASPRef:          CategoryMetadata[CategoryInvalidOrdering].OWASP,
			CWERef:            CategoryMetadata[CategoryInvalidOrdering].CWE,
			Endpoint:          step.Endpoint,
			Method:            step.Method,
			VerificationState: comp.State,
			Severity:          comp.Severity,
			Confidence:        comp.Confidence,
			ObservedStatus:    orderResp.StatusCode,
			StateBefore:       pt.FromState,
			StateAfter:        pt.ToState,
			EvidenceSummary:   comp.EvidenceSummary,
			EvidenceDetails:   comp.EvidenceDetails,
			CreatedAt:         time.Now().UTC(),
		}
		if comp.State == StateVerified || comp.State == StateCandidate {
			res.Finding = buildFinding(res, wf, *step, comp, fullURL)
		}
		results = append(results, res)
	}

	return results
}

// -------------------------------------------------------------------------
// Category C: Replay, Duplicate Execution & Idempotency
// -------------------------------------------------------------------------

func (e *Engine) assessReplayIdempotency(ctx context.Context, client *http.Client, actx *AssessmentContext, wf Workflow, identities []TestIdentity) []Result {
	var results []Result

	for _, step := range wf.Steps {
		if !step.IsSingleUse && !step.IsStateChanging {
			continue
		}

		fullURL, err := ResolveURL(actx.BaseURL, step.Endpoint)
		if err != nil {
			results = append(results, makeErrorResult(actx, wf, step.ID, "URLResolution", fmt.Sprintf("Invalid URL: %v", err)))
			continue
		}

		if actx.IsAllowed != nil && !actx.IsAllowed(fullURL) {
			results = append(results, makeSkippedResult(actx, wf, step.ID, CategoryReplayIdempotency, "Endpoint out of scope"))
			continue
		}
		if actx.IsExcluded != nil && actx.IsExcluded(fullURL) {
			results = append(results, makeSkippedResult(actx, wf, step.ID, CategoryReplayIdempotency, "Endpoint excluded by scope rules"))
			continue
		}

		// Replay mutation safety guard
		if !actx.AllowStateChangingTests {
			results = append(results, makeSkippedResult(actx, wf, step.ID, CategoryReplayIdempotency, "Replay test blocked: requires explicit --allow-state-changing opt-in"))
			continue
		}
		if !actx.SyntheticFixture {
			results = append(results, makeSkippedResult(actx, wf, step.ID, CategoryReplayIdempotency, "Replay test blocked: write mutations are restricted to designated synthetic fixtures"))
			continue
		}
		if !IsIsolatedFixtureTarget(fullURL, actx.AuthorizedFixtureHosts, actx.IsFixtureTarget) {
			results = append(results, makeSkippedResult(actx, wf, step.ID, CategoryReplayIdempotency, fmt.Sprintf("Replay test blocked: target %q is not an authorized synthetic fixture", fullURL)))
			continue
		}

		ident := selectIdentity(step.RequiredRole, identities)

		// Initial counter reading
		initialCounter := 0
		if step.VerificationEndpoint != "" {
			rbURL, err := ResolveURL(actx.BaseURL, step.VerificationEndpoint)
			if err == nil {
				rbMethod := step.VerificationMethod
				if rbMethod == "" {
					rbMethod = "GET"
				}
				rbData, err := e.executeRequest(ctx, client, rbMethod, rbURL, "", ident)
				if err == nil {
					var m map[string]any
					if json.Unmarshal(rbData.Body, &m) == nil {
						if cVal, ok := ExtractProperty(m, step.VerificationProperty); ok {
							if f, err := toInt(cVal); err == nil {
								initialCounter = f
							}
						}
					}
				}
			}
		}

		// Request 1: Valid primary execution
		firstResp, err := e.executeRequest(ctx, client, step.Method, fullURL, step.Payload, ident)
		if err != nil {
			results = append(results, makeErrorResult(actx, wf, step.ID, "ReplayPrimary", fmt.Sprintf("Primary request failed: %v", err)))
			continue
		}
		if firstResp.StatusCode >= 400 {
			results = append(results, makeInconclusiveResult(actx, wf, step.ID, CategoryReplayIdempotency, fmt.Sprintf("Primary execution returned HTTP %d; aborted replay to prevent duplicate or unsafe retries", firstResp.StatusCode)))
			continue
		}

		// Request 2: Duplicate replay execution
		secondResp, err := e.executeRequest(ctx, client, step.Method, fullURL, step.Payload, ident)
		if err != nil {
			results = append(results, makeErrorResult(actx, wf, step.ID, "ReplaySecond", fmt.Sprintf("Replay request failed: %v", err)))
			continue
		}

		// Final counter reading
		finalCounter := initialCounter
		var counterReadBack ResponseData
		if step.VerificationEndpoint != "" {
			rbURL, err := ResolveURL(actx.BaseURL, step.VerificationEndpoint)
			if err == nil {
				rbMethod := step.VerificationMethod
				if rbMethod == "" {
					rbMethod = "GET"
				}
				rbData, err := e.executeRequest(ctx, client, rbMethod, rbURL, "", ident)
				if err == nil {
					counterReadBack = rbData
					var m map[string]any
					if json.Unmarshal(rbData.Body, &m) == nil {
						if cVal, ok := ExtractProperty(m, step.VerificationProperty); ok {
							if f, err := toInt(cVal); err == nil {
								finalCounter = f
							}
						}
					}
				}
			}
		}

		comp := CompareReplay(firstResp, secondResp, counterReadBack, wf, step, initialCounter, finalCounter)
		res := Result{
			ID:                uuid.New().String(),
			AssessmentID:      actx.AssessmentID,
			ExecutionID:       actx.ExecutionID,
			Category:          CategoryReplayIdempotency,
			VulnCode:          string(CategoryReplayIdempotency),
			WorkflowID:        wf.ID,
			WorkflowName:      wf.Name,
			StepID:            step.ID,
			CheckID:           fmt.Sprintf("wf-%s-replay", step.ID),
			CheckName:         fmt.Sprintf("Single-Use Replay on %s", step.Name),
			OWASPRef:          CategoryMetadata[CategoryReplayIdempotency].OWASP,
			CWERef:            CategoryMetadata[CategoryReplayIdempotency].CWE,
			Endpoint:          step.Endpoint,
			Method:            step.Method,
			VerificationState: comp.State,
			Severity:          comp.Severity,
			Confidence:        comp.Confidence,
			ObservedStatus:    secondResp.StatusCode,
			EvidenceSummary:   comp.EvidenceSummary,
			EvidenceDetails:   comp.EvidenceDetails,
			CreatedAt:         time.Now().UTC(),
		}
		if comp.State == StateVerified || comp.State == StateCandidate {
			res.Finding = buildFinding(res, wf, step, comp, fullURL)
		}
		results = append(results, res)
	}

	return results
}

// -------------------------------------------------------------------------
// Category D: Token & Workflow-State Continuity
// -------------------------------------------------------------------------

func (e *Engine) assessTokenContinuity(ctx context.Context, client *http.Client, actx *AssessmentContext, wf Workflow, identities []TestIdentity) []Result {
	var results []Result

	for _, step := range wf.Steps {
		if step.ExtractTokenField == "" && step.InjectTokenHeader == "" && step.InjectTokenField == "" {
			continue
		}

		fullURL, err := ResolveURL(actx.BaseURL, step.Endpoint)
		if err != nil {
			results = append(results, makeErrorResult(actx, wf, step.ID, "URLResolution", fmt.Sprintf("Invalid URL: %v", err)))
			continue
		}

		if actx.IsAllowed != nil && !actx.IsAllowed(fullURL) {
			results = append(results, makeSkippedResult(actx, wf, step.ID, CategoryTokenContinuity, "Endpoint out of scope"))
			continue
		}
		if actx.IsExcluded != nil && actx.IsExcluded(fullURL) {
			results = append(results, makeSkippedResult(actx, wf, step.ID, CategoryTokenContinuity, "Endpoint excluded by scope rules"))
			continue
		}

		ident := selectIdentity(step.RequiredRole, identities)

		// 1. Obtain valid workflow token
		validResp, err := e.executeRequest(ctx, client, step.Method, fullURL, step.Payload, ident)
		if err != nil {
			results = append(results, makeErrorResult(actx, wf, step.ID, "TokenInit", fmt.Sprintf("Token initialization request failed: %v", err)))
			continue
		}

		extractedToken := "flx_synthetic_token_12345"
		if step.ExtractTokenField != "" {
			var bodyMap map[string]any
			if json.Unmarshal(validResp.Body, &bodyMap) == nil {
				if tVal, ok := ExtractProperty(bodyMap, step.ExtractTokenField); ok {
					extractedToken = fmt.Sprintf("%v", tVal)
				}
			}
		}

		// Prepare identity and payload with extracted token
		tokenIdent := *ident
		if ident != nil {
			tokenIdent.Headers = make(map[string]string)
			for k, v := range ident.Headers {
				tokenIdent.Headers[k] = v
			}
			tokenIdent.Cookies = make(map[string]string)
			for k, v := range ident.Cookies {
				tokenIdent.Cookies[k] = v
			}
		}
		if step.InjectTokenHeader != "" {
			tokenIdent.Headers[step.InjectTokenHeader] = extractedToken
		} else {
			tokenIdent.Headers["X-Workflow-Token"] = extractedToken
		}

		tokenPayload := step.Payload
		if step.InjectTokenField != "" && step.Payload != "" {
			var pMap map[string]any
			if json.Unmarshal([]byte(step.Payload), &pMap) == nil {
				pMap[step.InjectTokenField] = extractedToken
				if pb, err := json.Marshal(pMap); err == nil {
					tokenPayload = string(pb)
				}
			}
		}

		// 2. Consume the token (step completion)
		consumeResp, _ := e.executeRequest(ctx, client, step.Method, fullURL, tokenPayload, &tokenIdent)

		// 3. Replay with already-consumed / invalidated token
		reusedResp, err := e.executeRequest(ctx, client, step.Method, fullURL, tokenPayload, &tokenIdent)
		if err != nil {
			results = append(results, makeErrorResult(actx, wf, step.ID, "TokenReused", fmt.Sprintf("Reused token request failed: %v", err)))
			continue
		}

		var verifyResp ResponseData
		if step.VerificationEndpoint != "" {
			rbURL, err := ResolveURL(actx.BaseURL, step.VerificationEndpoint)
			if err == nil {
				rbMethod := step.VerificationMethod
				if rbMethod == "" {
					rbMethod = "GET"
				}
				rbData, err := e.executeRequest(ctx, client, rbMethod, rbURL, "", ident)
				if err == nil {
					verifyResp = rbData
				}
			}
		}

		_ = consumeResp
		comp := CompareTokenContinuity(validResp, reusedResp, verifyResp, wf, step, step.ExtractTokenField)
		res := Result{
			ID:                uuid.New().String(),
			AssessmentID:      actx.AssessmentID,
			ExecutionID:       actx.ExecutionID,
			Category:          CategoryTokenContinuity,
			VulnCode:          string(CategoryTokenContinuity),
			WorkflowID:        wf.ID,
			WorkflowName:      wf.Name,
			StepID:            step.ID,
			CheckID:           fmt.Sprintf("wf-%s-token-reuse", step.ID),
			CheckName:         fmt.Sprintf("Workflow Token Continuity on %s", step.Name),
			OWASPRef:          CategoryMetadata[CategoryTokenContinuity].OWASP,
			CWERef:            CategoryMetadata[CategoryTokenContinuity].CWE,
			Endpoint:          step.Endpoint,
			Method:            step.Method,
			VerificationState: comp.State,
			Severity:          comp.Severity,
			Confidence:        comp.Confidence,
			ObservedStatus:    reusedResp.StatusCode,
			EvidenceSummary:   comp.EvidenceSummary,
			EvidenceDetails:   comp.EvidenceDetails,
			CreatedAt:         time.Now().UTC(),
		}
		if comp.State == StateVerified || comp.State == StateCandidate {
			res.Finding = buildFinding(res, wf, step, comp, fullURL)
		}
		results = append(results, res)
	}

	return results
}

// -------------------------------------------------------------------------
// Category E: Identity & Ownership Continuity
// -------------------------------------------------------------------------

func (e *Engine) assessIdentityContinuity(ctx context.Context, client *http.Client, actx *AssessmentContext, wf Workflow, identities []TestIdentity) []Result {
	var results []Result

	if len(identities) < 2 {
		return results
	}

	ownerIdent := &identities[0]
	intruderIdent := &identities[1]

	for _, step := range wf.Steps {
		fullURL, err := ResolveURL(actx.BaseURL, step.Endpoint)
		if err != nil {
			continue
		}

		if actx.IsAllowed != nil && !actx.IsAllowed(fullURL) {
			continue
		}
		if actx.IsExcluded != nil && actx.IsExcluded(fullURL) {
			continue
		}

		if step.IsStateChanging {
			if !actx.AllowStateChangingTests || !actx.SyntheticFixture || !IsIsolatedFixtureTarget(fullURL, actx.AuthorizedFixtureHosts, actx.IsFixtureTarget) {
				continue
			}
		}

		// Owner performs step
		ownerResp, err := e.executeRequest(ctx, client, step.Method, fullURL, step.Payload, ownerIdent)
		if err != nil {
			continue
		}

		// Non-owner attempts to execute or finalize step
		intruderResp, err := e.executeRequest(ctx, client, step.Method, fullURL, step.Payload, intruderIdent)
		if err != nil {
			continue
		}

		var verifyResp ResponseData
		if step.VerificationEndpoint != "" {
			rbURL, err := ResolveURL(actx.BaseURL, step.VerificationEndpoint)
			if err == nil {
				rbMethod := step.VerificationMethod
				if rbMethod == "" {
					rbMethod = "GET"
				}
				rbData, err := e.executeRequest(ctx, client, rbMethod, rbURL, "", intruderIdent)
				if err == nil {
					verifyResp = rbData
				}
			}
		}

		comp := CompareIdentityContinuity(ownerResp, intruderResp, verifyResp, wf, step, ownerIdent.Role, intruderIdent.Role)
		res := Result{
			ID:                uuid.New().String(),
			AssessmentID:      actx.AssessmentID,
			ExecutionID:       actx.ExecutionID,
			Category:          CategoryIdentityContinuity,
			VulnCode:          string(CategoryIdentityContinuity),
			WorkflowID:        wf.ID,
			WorkflowName:      wf.Name,
			StepID:            step.ID,
			CheckID:           fmt.Sprintf("wf-%s-identity", step.ID),
			CheckName:         fmt.Sprintf("Ownership Continuity on %s", step.Name),
			OWASPRef:          CategoryMetadata[CategoryIdentityContinuity].OWASP,
			CWERef:            CategoryMetadata[CategoryIdentityContinuity].CWE,
			Endpoint:          step.Endpoint,
			Method:            step.Method,
			VerificationState: comp.State,
			Severity:          comp.Severity,
			Confidence:        comp.Confidence,
			ObservedStatus:    intruderResp.StatusCode,
			EvidenceSummary:   comp.EvidenceSummary,
			EvidenceDetails:   comp.EvidenceDetails,
			CreatedAt:         time.Now().UTC(),
		}
		if comp.State == StateVerified || comp.State == StateCandidate {
			res.Finding = buildFinding(res, wf, step, comp, fullURL)
		}
		results = append(results, res)
	}

	return results
}

// -------------------------------------------------------------------------
// Category F: Concurrent Transition & Race Condition Integrity
// -------------------------------------------------------------------------

func (e *Engine) assessConcurrentTransition(ctx context.Context, client *http.Client, actx *AssessmentContext, wf Workflow, identities []TestIdentity) []Result {
	var results []Result

	for _, step := range wf.Steps {
		if !step.IsSingleUse && !step.IsStateChanging {
			continue
		}

		fullURL, err := ResolveURL(actx.BaseURL, step.Endpoint)
		if err != nil {
			continue
		}

		if actx.IsAllowed != nil && !actx.IsAllowed(fullURL) {
			continue
		}
		if actx.IsExcluded != nil && actx.IsExcluded(fullURL) {
			continue
		}

		// Concurrency mutation guards: strictly synthetic fixture only!
		if !actx.AllowStateChangingTests {
			results = append(results, makeSkippedResult(actx, wf, step.ID, CategoryConcurrentTransition, "Concurrent test blocked: requires explicit --allow-state-changing opt-in"))
			continue
		}
		if !actx.SyntheticFixture {
			results = append(results, makeSkippedResult(actx, wf, step.ID, CategoryConcurrentTransition, "Concurrent test blocked: write mutations are restricted to designated synthetic fixtures"))
			continue
		}
		if !IsIsolatedFixtureTarget(fullURL, actx.AuthorizedFixtureHosts, actx.IsFixtureTarget) {
			results = append(results, makeSkippedResult(actx, wf, step.ID, CategoryConcurrentTransition, fmt.Sprintf("Concurrent test blocked: target %q is not an authorized synthetic fixture", fullURL)))
			continue
		}

		ident := selectIdentity(step.RequiredRole, identities)

		// Initial counter reading
		initialCounter := 0
		if step.VerificationEndpoint != "" {
			rbURL, err := ResolveURL(actx.BaseURL, step.VerificationEndpoint)
			if err == nil {
				rbMethod := step.VerificationMethod
				if rbMethod == "" {
					rbMethod = "GET"
				}
				rbData, err := e.executeRequest(ctx, client, rbMethod, rbURL, "", ident)
				if err == nil {
					var m map[string]any
					if json.Unmarshal(rbData.Body, &m) == nil {
						if cVal, ok := ExtractProperty(m, step.VerificationProperty); ok {
							if f, err := toInt(cVal); err == nil {
								initialCounter = f
							}
						}
					}
				}
			}
		}

		// Dispatch bounded concurrent requests (max 5)
		numRequests := actx.Concurrency
		if numRequests <= 1 {
			numRequests = 3
		}
		if numRequests > 5 {
			numRequests = 5 // Hard upper safety limit for concurrency testing
		}

		responses := make([]ResponseData, numRequests)
		var wg sync.WaitGroup
		wg.Add(numRequests)

		for i := 0; i < numRequests; i++ {
			go func(idx int) {
				defer wg.Done()
				resp, err := e.executeRequest(ctx, client, step.Method, fullURL, step.Payload, ident)
				if err == nil {
					responses[idx] = resp
				}
			}(i)
		}
		wg.Wait()

		// Final counter reading
		finalCounter := initialCounter
		var counterReadBack ResponseData
		if step.VerificationEndpoint != "" {
			rbURL, err := ResolveURL(actx.BaseURL, step.VerificationEndpoint)
			if err == nil {
				rbMethod := step.VerificationMethod
				if rbMethod == "" {
					rbMethod = "GET"
				}
				rbData, err := e.executeRequest(ctx, client, rbMethod, rbURL, "", ident)
				if err == nil {
					counterReadBack = rbData
					var m map[string]any
					if json.Unmarshal(rbData.Body, &m) == nil {
						if cVal, ok := ExtractProperty(m, step.VerificationProperty); ok {
							if f, err := toInt(cVal); err == nil {
								finalCounter = f
							}
						}
					}
				}
			}
		}

		comp := CompareConcurrentTransition(responses, counterReadBack, wf, step, initialCounter, finalCounter, numRequests)
		res := Result{
			ID:                uuid.New().String(),
			AssessmentID:      actx.AssessmentID,
			ExecutionID:       actx.ExecutionID,
			Category:          CategoryConcurrentTransition,
			VulnCode:          string(CategoryConcurrentTransition),
			WorkflowID:        wf.ID,
			WorkflowName:      wf.Name,
			StepID:            step.ID,
			CheckID:           fmt.Sprintf("wf-%s-concurrency", step.ID),
			CheckName:         fmt.Sprintf("Concurrent Transition on %s", step.Name),
			OWASPRef:          CategoryMetadata[CategoryConcurrentTransition].OWASP,
			CWERef:            CategoryMetadata[CategoryConcurrentTransition].CWE,
			Endpoint:          step.Endpoint,
			Method:            step.Method,
			VerificationState: comp.State,
			Severity:          comp.Severity,
			Confidence:        comp.Confidence,
			ObservedStatus:    responses[0].StatusCode,
			EvidenceSummary:   comp.EvidenceSummary,
			EvidenceDetails:   comp.EvidenceDetails,
			CreatedAt:         time.Now().UTC(),
		}
		if comp.State == StateVerified || comp.State == StateCandidate {
			res.Finding = buildFinding(res, wf, step, comp, fullURL)
		}
		results = append(results, res)
	}

	return results
}

// -------------------------------------------------------------------------
// Helper Execution & Model Functions
// -------------------------------------------------------------------------

func (e *Engine) executeRequest(ctx context.Context, client *http.Client, method, urlStr, payload string, identity *TestIdentity) (ResponseData, error) {
	var respData ResponseData
	if ctx.Err() != nil {
		return respData, ctx.Err()
	}

	var bodyReader io.Reader
	if payload != "" {
		bodyReader = strings.NewReader(payload)
	}

	req, err := http.NewRequestWithContext(ctx, method, urlStr, bodyReader)
	if err != nil {
		return respData, err
	}

	if payload != "" {
		req.Header.Set("Content-Type", "application/json")
	}

	if identity != nil {
		for k, v := range identity.Headers {
			req.Header.Set(k, v)
		}
		for k, v := range identity.Cookies {
			req.AddCookie(&http.Cookie{
				Name:  k,
				Value: v,
			})
		}
	}

	start := time.Now()
	resp, err := client.Do(req)
	duration := time.Since(start)

	if err != nil {
		return respData, err
	}
	defer resp.Body.Close()

	respData.StatusCode = resp.StatusCode
	respData.Header = resp.Header
	respData.ExecutionTime = duration
	respData.ContentLength = resp.ContentLength

	maxBytes := e.cfg.MaxResponseBytes
	if maxBytes <= 0 {
		maxBytes = 2 * 1024 * 1024
	}
	lr := io.LimitReader(resp.Body, maxBytes)
	body, err := io.ReadAll(lr)
	if err != nil && err != io.EOF {
		return respData, err
	}
	respData.Body = body

	return respData, nil
}

func selectIdentity(role string, identities []TestIdentity) *TestIdentity {
	if len(identities) == 0 {
		return nil
	}
	if role == "" {
		return &identities[0]
	}
	for i := range identities {
		if strings.EqualFold(identities[i].Role, role) || strings.EqualFold(identities[i].Alias, role) {
			return &identities[i]
		}
	}
	return &identities[0]
}

func findStep(wf Workflow, stepID string) *Step {
	for i := range wf.Steps {
		if wf.Steps[i].ID == stepID {
			return &wf.Steps[i]
		}
	}
	return nil
}

func toInt(val any) (int, error) {
	switch v := val.(type) {
	case int:
		return v, nil
	case int64:
		return int(v), nil
	case float64:
		return int(v), nil
	case string:
		return strconv.Atoi(strings.TrimSpace(v))
	default:
		return 0, fmt.Errorf("not an int")
	}
}

func buildFinding(res Result, wf Workflow, step Step, comp ComparisonResult, targetURL string) *report.Finding {
	meta := CategoryMetadata[res.Category]
	sanitizedTarget := SanitizeURL(targetURL)
	sanitizedEndpoint := SanitizeURL(step.Endpoint)
	if sanitizedEndpoint == "" {
		sanitizedEndpoint = sanitizedTarget
	}

	evidence := RedactText(comp.EvidenceSummary)
	return &report.Finding{
		ID:          BuildFindingID(res.AssessmentID, wf.ID, res.CheckID),
		Title:       fmt.Sprintf("[%s] %s on %s [%s]", res.VulnCode, meta.Name, res.Endpoint, step.Name),
		Category:    fmt.Sprintf("%s / %s", meta.OWASP, meta.Name),
		Severity:    res.Severity,
		Confidence:  res.Confidence,
		Target:      sanitizedTarget,
		Endpoint:    sanitizedEndpoint,
		Method:      res.Method,
		Description: fmt.Sprintf("[%s / %s] %s (Workflow: %s)", res.VulnCode, meta.OWASP, meta.Description, wf.Name),
		Evidence:    evidence,
		EvidenceDetails: report.EvidenceDetails{
			Observation:     evidence,
			Location:        sanitizedEndpoint,
			HTTPMethod:      res.Method,
			HTTPStatus:      res.ObservedStatus,
			DetectionMethod: "WORKFLOW_INTEGRITY_ENGINE",
			Details: map[string]string{
				"category":    string(res.Category),
				"vuln_code":   res.VulnCode,
				"workflow_id": wf.ID,
				"step_id":     res.StepID,
			},
		},
		Remediation: fmt.Sprintf("Enforce server-authoritative state transitions and prerequisite validation for workflow %q. Ensure step %q cannot be invoked out of order, replayed, or completed without prerequisite proof.", wf.Name, step.Name),
	}
}

func makeSkippedResult(actx *AssessmentContext, wf Workflow, stepID string, cat Category, reason string) Result {
	meta := CategoryMetadata[cat]
	return Result{
		ID:                uuid.New().String(),
		AssessmentID:      actx.AssessmentID,
		ExecutionID:       actx.ExecutionID,
		Category:          cat,
		VulnCode:          string(cat),
		WorkflowID:        wf.ID,
		WorkflowName:      wf.Name,
		StepID:            stepID,
		CheckID:           fmt.Sprintf("wf-%s-%s", wf.ID, cat),
		CheckName:         fmt.Sprintf("%s on %s", meta.Name, wf.Name),
		OWASPRef:          meta.OWASP,
		CWERef:            meta.CWE,
		VerificationState: StateSkipped,
		Severity:          "INFO",
		Confidence:        "CONFIRMED",
		EvidenceSummary:   reason,
		CreatedAt:         time.Now().UTC(),
	}
}

func makeInconclusiveResult(actx *AssessmentContext, wf Workflow, stepID string, cat Category, reason string) Result {
	meta := CategoryMetadata[cat]
	return Result{
		ID:                uuid.New().String(),
		AssessmentID:      actx.AssessmentID,
		ExecutionID:       actx.ExecutionID,
		Category:          cat,
		VulnCode:          string(cat),
		WorkflowID:        wf.ID,
		WorkflowName:      wf.Name,
		StepID:            stepID,
		CheckID:           fmt.Sprintf("wf-%s-%s", wf.ID, cat),
		CheckName:         fmt.Sprintf("%s on %s", meta.Name, wf.Name),
		OWASPRef:          meta.OWASP,
		CWERef:            meta.CWE,
		VerificationState: StateInconclusive,
		Severity:          "INFO",
		Confidence:        "LOW",
		EvidenceSummary:   reason,
		CreatedAt:         time.Now().UTC(),
	}
}

func makeErrorResult(actx *AssessmentContext, wf Workflow, stepID, checkSuffix, reason string) Result {
	return Result{
		ID:                uuid.New().String(),
		AssessmentID:      actx.AssessmentID,
		ExecutionID:       actx.ExecutionID,
		Category:          CategoryPrerequisiteSkipping,
		VulnCode:          string(CategoryPrerequisiteSkipping),
		WorkflowID:        wf.ID,
		WorkflowName:      wf.Name,
		StepID:            stepID,
		CheckID:           fmt.Sprintf("wf-%s-%s", wf.ID, checkSuffix),
		CheckName:         fmt.Sprintf("Error on %s", wf.Name),
		VerificationState: StateInconclusive,
		Severity:          "INFO",
		Confidence:        "LOW",
		EvidenceSummary:   fmt.Sprintf("Execution error: %s", reason),
		CreatedAt:         time.Now().UTC(),
	}
}

func compileSummary(results []Result, workflows []Workflow) *Summary {
	summary := &Summary{
		TotalWorkflows:      len(workflows),
		TotalChecks:         len(results),
		CategoryCoverageMap: make(map[string]CategoryCoverage),
	}

	for _, cat := range AllCategories() {
		meta := CategoryMetadata[cat]
		summary.CategoryCoverageMap[string(cat)] = CategoryCoverage{
			Category: cat,
			Code:     meta.Code,
			Name:     meta.Name,
			OWASPRef: meta.OWASP,
			Status:   CoverageUntested,
		}
	}

	for _, r := range results {
		cov := summary.CategoryCoverageMap[string(r.Category)]
		cov.ChecksRun++

		switch r.VerificationState {
		case StateVerified:
			summary.VerifiedCount++
			cov.Verified++
			cov.Status = CoverageVerifiedIssueFound
		case StateCandidate:
			summary.CandidateCount++
			cov.Candidates++
			if cov.Status != CoverageVerifiedIssueFound {
				cov.Status = CoverageCandidateIdentified
			}
		case StateNotVulnerable:
			summary.NotVulnerableCount++
			cov.NotVulnerable++
			if cov.Status == CoverageUntested {
				cov.Status = CoverageActivelyTested
			}
		case StateInconclusive:
			summary.InconclusiveCount++
			cov.Inconclusive++
			if cov.Status == CoverageUntested {
				cov.Status = CoverageBlockedMissingPrereq
			}
		case StateSkipped:
			summary.BlockedCount++
			cov.Blocked++
			if cov.Status == CoverageUntested {
				cov.Status = CoverageBlockedMissingPrereq
			}
		}

		summary.CategoryCoverageMap[string(r.Category)] = cov
	}

	covered := 0
	for _, cov := range summary.CategoryCoverageMap {
		if cov.ChecksRun > 0 {
			covered++
		}
	}
	summary.CategoriesAssessed = covered

	return summary
}

// DefaultWorkflows provides standard default workflow templates for multi-step verification.
func DefaultWorkflows() []Workflow {
	return []Workflow{
		{
			ID:          "WF-ORDER-CHECKOUT",
			Name:        "Multi-Step Order & Payment Workflow",
			Description: "Standard e-commerce flow from cart addition, checkout, payment to digital fulfillment",
			States:      []string{"CART", "CHECKOUT_PENDING", "PAID", "FULFILLED", "CANCELLED"},
			Steps: []Step{
				{
					ID:              "step-cart",
					Name:            "Add to Cart",
					Endpoint:        "/api/cart/add",
					Method:          "POST",
					IsStateChanging: true,
					ToState:         "CART",
				},
				{
					ID:              "step-checkout",
					Name:            "Initiate Checkout",
					Endpoint:        "/api/order/checkout",
					Method:          "POST",
					Preconditions:   []string{"step-cart"},
					IsStateChanging: true,
					FromState:       "CART",
					ToState:         "CHECKOUT_PENDING",
				},
				{
					ID:                   "step-payment",
					Name:                 "Process Payment",
					Endpoint:             "/api/order/pay",
					Method:               "POST",
					Preconditions:        []string{"step-checkout"},
					IsStateChanging:      true,
					IsSingleUse:          true,
					FromState:            "CHECKOUT_PENDING",
					ToState:              "PAID",
					VerificationEndpoint: "/api/order/status",
					VerificationProperty: "payment_status",
					ExpectedVerifiedValue: "PAID",
				},
				{
					ID:                   "step-fulfill",
					Name:                 "Fulfill & Download Asset",
					Endpoint:             "/api/order/download",
					Method:               "GET",
					Preconditions:        []string{"step-payment"},
					IsStateChanging:      false,
					VerificationEndpoint: "/api/order/status",
					VerificationProperty: "order_status",
					ExpectedVerifiedValue: "FULFILLED",
				},
			},
			ProhibitedTransitions: []Transition{
				{FromState: "CANCELLED", ToState: "PAID", StepID: "step-payment", IsProhibited: true},
				{FromState: "CART", ToState: "FULFILLED", StepID: "step-fulfill", IsProhibited: true},
			},
		},
		{
			ID:          "WF-RESOURCE-APPROVAL",
			Name:        "Resource Submission & Approval Flow",
			Description: "Multi-party workflow requiring approval before publication",
			States:      []string{"DRAFT", "PENDING_APPROVAL", "APPROVED", "PUBLISHED"},
			Steps: []Step{
				{
					ID:              "step-submit",
					Name:            "Submit Draft",
					Endpoint:        "/api/documents/submit",
					Method:          "POST",
					IsStateChanging: true,
					ToState:         "PENDING_APPROVAL",
				},
				{
					ID:                   "step-approve",
					Name:                 "Approve Document",
					Endpoint:             "/api/documents/approve",
					Method:               "POST",
					RequiredRole:         "approver",
					Preconditions:        []string{"step-submit"},
					IsStateChanging:      true,
					IsSingleUse:          true,
					FromState:            "PENDING_APPROVAL",
					ToState:              "APPROVED",
					VerificationEndpoint: "/api/documents/status",
					VerificationProperty: "approval_state",
					ExpectedVerifiedValue: "APPROVED",
				},
				{
					ID:                   "step-publish",
					Name:                 "Publish Document",
					Endpoint:             "/api/documents/publish",
					Method:               "POST",
					Preconditions:        []string{"step-approve"},
					IsStateChanging:      true,
					FromState:            "APPROVED",
					ToState:              "PUBLISHED",
					VerificationEndpoint: "/api/documents/status",
					VerificationProperty: "publication_status",
					ExpectedVerifiedValue: "PUBLISHED",
				},
			},
			ProhibitedTransitions: []Transition{
				{FromState: "DRAFT", ToState: "PUBLISHED", StepID: "step-publish", IsProhibited: true},
			},
		},
	}
}

// DefaultIdentities provides standard testing identities.
func DefaultIdentities() []TestIdentity {
	return []TestIdentity{
		{
			ID:             "admin_user",
			Alias:          "admin",
			Role:           "admin",
			PrivilegeLevel: 5,
			Headers:        map[string]string{"Authorization": "Bearer token_admin_synthetic"},
		},
		{
			ID:             "standard_user",
			Alias:          "user",
			Role:           "user",
			PrivilegeLevel: 1,
			Headers:        map[string]string{"Authorization": "Bearer token_user_synthetic"},
		},
	}
}
