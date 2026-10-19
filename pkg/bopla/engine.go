package bopla

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
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

// Engine executes BOPLA property-level authorization testing.
type Engine struct {
	client *http.Client
	cfg    Config
}

// NewEngine creates an Engine instance with safe defaults.
func NewEngine(client *http.Client, cfg Config) *Engine {
	if cfg.Timeout == 0 {
		cfg.Timeout = 10 * time.Second
	}
	if cfg.MaxResponseBytes == 0 {
		cfg.MaxResponseBytes = 2 * 1024 * 1024
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

// scopedClient creates an isolated http.Client scoped to an assessment execution,
// enforcing redirect credential protection and budget constraints.
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
		Jar:       nil, // Prevent cookie bleed across identities
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

// Plan outputs the planned BOPLA tests without sending any network requests.
func (e *Engine) Plan(ctx context.Context, actx *AssessmentContext) (*TestPlan, error) {
	if actx == nil {
		return nil, fmt.Errorf("assessment context is nil")
	}
	if actx.BaseURL == "" {
		return nil, fmt.Errorf("base target URL is required")
	}

	plan := &TestPlan{
		AssessmentID: actx.AssessmentID,
		TargetURL:    actx.BaseURL,
		GeneratedAt:  time.Now().UTC(),
		Tests:        make([]PlannedTest, 0),
	}

	policies := actx.Policies
	if len(policies) == 0 {
		policies = DefaultPolicies()
	}

	identities := actx.Identities
	if len(identities) == 0 {
		identities = DefaultIdentities()
	}

	plan.TotalTests = len(policies)

	for _, pol := range policies {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}

		fullURL, err := ResolveURL(actx.BaseURL, pol.Endpoint)
		if err != nil {
			fullURL = actx.BaseURL + pol.Endpoint
		}

		allowedIdent, testedIdent := selectIdentities(pol, identities)

		pt := PlannedTest{
			ID:                fmt.Sprintf("bopla-%s", pol.PropertyID),
			Category:          pol.Category,
			Name:              pol.Name,
			OWASPRef:          CategoryMetadata[pol.Category].OWASP,
			CWERef:            CategoryMetadata[pol.Category].CWE,
			Endpoint:          pol.Endpoint,
			Method:            pol.Method,
			PropertyPath:      pol.PropertyPath,
			ExpectedAccess:    string(pol.ExpectedAccess),
			AllowedRole:       "admin",
			TestedRole:        "user",
			TestedAlias:       "unassigned",
			IsStateChanging:   pol.IsStateChanging,
			SecurityObjective: CategoryMetadata[pol.Category].Description,
			Preconditions:     CategoryMetadata[pol.Category].Preconditions,
		}

		if allowedIdent != nil {
			pt.AllowedRole = allowedIdent.Role
		}
		if testedIdent != nil {
			pt.TestedRole = testedIdent.Role
			pt.TestedAlias = testedIdent.Alias
		}

		// Check scope exclusions and safety guards
		if actx.IsExcluded != nil && actx.IsExcluded(fullURL) {
			pt.Status = PlanSkipped
			pt.BlockedReason = "Target endpoint is excluded by assessment scope rules"
			plan.BlockedTests++
		} else if (pol.IsStateChanging || pol.Category == CategoryBOPLAPropertyWrite || pol.Category == CategoryBOPLAMassAssignment) && !actx.AllowStateChangingTests {
			pt.Status = PlanSkipped
			pt.BlockedReason = "State-changing property tests require explicit --allow-state-changing opt-in"
			plan.StateChangingTests++
		} else if (pol.IsStateChanging || pol.Category == CategoryBOPLAPropertyWrite || pol.Category == CategoryBOPLAMassAssignment) && !actx.SyntheticFixture {
			pt.Status = PlanBlocked
			pt.BlockedReason = "State-changing property tests are restricted to designated synthetic fixtures or isolated test environments"
			plan.BlockedTests++
		} else if (pol.IsStateChanging || pol.Category == CategoryBOPLAPropertyWrite || pol.Category == CategoryBOPLAMassAssignment) && !IsIsolatedFixtureTarget(fullURL, actx.AuthorizedFixtureHosts, actx.IsFixtureTarget) {
			pt.Status = PlanBlocked
			pt.BlockedReason = "State-changing property tests blocked: target is not an authorized synthetic fixture or isolated test environment"
			plan.BlockedTests++
		} else if (pol.IsStateChanging || pol.Category == CategoryBOPLAPropertyWrite || pol.Category == CategoryBOPLAMassAssignment) && strings.TrimSpace(pol.PropertyPath) == "" {
			pt.Status = PlanBlocked
			pt.BlockedReason = "State-changing property test blocked: missing required property path"
			plan.BlockedTests++
		} else if (pol.IsStateChanging || pol.Category == CategoryBOPLAPropertyWrite || pol.Category == CategoryBOPLAMassAssignment) && pol.MutationValue == nil && strings.TrimSpace(pol.MutationPayload) == "" {
			pt.Status = PlanBlocked
			pt.BlockedReason = "State-changing property test blocked: missing required mutation value or payload"
			plan.BlockedTests++
		} else if testedIdent == nil {
			pt.Status = PlanBlocked
			pt.BlockedReason = "No distinct lower-privilege identity available to test property restriction"
			plan.BlockedTests++
		} else {
			pt.Status = PlanReady
			plan.ReadyTests++
		}

		plan.Tests = append(plan.Tests, pt)
	}

	return plan, nil
}

// Assess executes active BOPLA differential authorization verification.
func (e *Engine) Assess(ctx context.Context, actx *AssessmentContext) ([]Result, *Summary, error) {
	if actx == nil {
		return nil, nil, fmt.Errorf("assessment context is nil")
	}
	if actx.BaseURL == "" {
		return nil, nil, fmt.Errorf("base target URL is required")
	}

	// Validate authorization record
	if actx.Authorization == nil {
		return nil, nil, fmt.Errorf("refused: assessment lacks authorization record")
	}
	valid, reason := actx.Authorization.IsCurrentlyValid(time.Now().UTC())
	if !valid {
		return nil, nil, fmt.Errorf("refused: authorization invalid (%s)", reason)
	}

	policies := actx.Policies
	if len(policies) == 0 {
		policies = DefaultPolicies()
	}

	identities := actx.Identities
	if len(identities) == 0 {
		identities = DefaultIdentities()
	}

	results := make([]Result, 0, len(policies))

	// Initialize counters and setup scoped client
	if actx.DispatchedRequests == nil {
		var initialReqs int32
		actx.DispatchedRequests = &initialReqs
	}
	client := e.scopedClient(actx)

	for _, pol := range policies {
		if ctx.Err() != nil {
			return nil, nil, ctx.Err()
		}

		fullURL, err := ResolveURL(actx.BaseURL, pol.Endpoint)
		if err != nil {
			res := makeErrorResult(actx, pol, fmt.Sprintf("Invalid URL resolution: %v", err))
			results = append(results, res)
			continue
		}

		// Scope checks
		if actx.IsAllowed != nil && !actx.IsAllowed(fullURL) {
			res := makeSkippedResult(actx, pol, "Endpoint out of scope")
			results = append(results, res)
			continue
		}
		if actx.IsExcluded != nil && actx.IsExcluded(fullURL) {
			res := makeSkippedResult(actx, pol, "Endpoint excluded by scope rules")
			results = append(results, res)
			continue
		}

		// Property path validation
		if strings.TrimSpace(pol.PropertyPath) == "" {
			res := makeSkippedResult(actx, pol, "Property test blocked: missing required property path")
			results = append(results, res)
			continue
		}

		// State-changing safety check
		if pol.IsStateChanging || pol.Category == CategoryBOPLAPropertyWrite || pol.Category == CategoryBOPLAMassAssignment {
			if !actx.AllowStateChangingTests {
				res := makeSkippedResult(actx, pol, "State-changing property test blocked: requires explicit --allow-state-changing opt-in")
				results = append(results, res)
				continue
			}
			if !actx.SyntheticFixture {
				res := makeSkippedResult(actx, pol, "State-changing property test blocked: write mutations are restricted to designated synthetic fixtures or isolated test environments")
				results = append(results, res)
				continue
			}
			if !IsIsolatedFixtureTarget(fullURL, actx.AuthorizedFixtureHosts, actx.IsFixtureTarget) {
				res := makeSkippedResult(actx, pol, fmt.Sprintf("State-changing property test blocked: target %q is not an authorized synthetic fixture or isolated test environment", fullURL))
				results = append(results, res)
				continue
			}
			if pol.MutationValue == nil && strings.TrimSpace(pol.MutationPayload) == "" {
				res := makeSkippedResult(actx, pol, "State-changing property test blocked: missing required mutation value or payload")
				results = append(results, res)
				continue
			}
		}

		// Identity resolution
		allowedIdent, testedIdent := selectIdentities(pol, identities)
		if allowedIdent == nil || testedIdent == nil {
			res := makeInconclusiveResult(actx, pol, "Missing required identity contexts for differential property testing")
			results = append(results, res)
			continue
		}
		if !AreIdentitiesDistinct(*allowedIdent, *testedIdent) {
			res := makeInconclusiveResult(actx, pol, "Identical identities configured; differential property testing requires distinct principal contexts")
			results = append(results, res)
			continue
		}

		// Step A: Positive Control Baseline Request (Authorized Role)
		baseResp, err := e.executeRequest(ctx, client, "GET", fullURL, "", allowedIdent)
		if err != nil {
			res := Result{
				ID:                uuid.New().String(),
				AssessmentID:      actx.AssessmentID,
				ExecutionID:       actx.ExecutionID,
				Category:          pol.Category,
				VulnCode:          string(pol.Category),
				TestID:            fmt.Sprintf("bopla-%s", pol.PropertyID),
				TestName:          pol.Name,
				OWASPRef:          CategoryMetadata[pol.Category].OWASP,
				CWERef:            CategoryMetadata[pol.Category].CWE,
				Endpoint:          pol.Endpoint,
				Method:            pol.Method,
				PropertyPath:      pol.PropertyPath,
				ExpectedAccess:    string(pol.ExpectedAccess),
				RequiredRole:      allowedIdent.Role,
				AccessorRole:      testedIdent.Role,
				AccessorAlias:     testedIdent.Alias,
				VerificationState: StateInconclusive,
				Severity:          "INFO",
				Confidence:        "LOW",
				EvidenceSummary:   fmt.Sprintf("Authorized baseline request for role %s failed: %v", allowedIdent.Role, err),
				CreatedAt:         time.Now().UTC(),
			}
			results = append(results, res)
			continue
		}

		// Step B: Execution based on Read vs Write Mutation
		if pol.IsStateChanging || pol.Category == CategoryBOPLAPropertyWrite || pol.Category == CategoryBOPLAMassAssignment {
			// Write Mutation / Mass Assignment workflow
			payload := pol.MutationPayload
			if payload == "" {
				payload = buildMutationPayload(pol.PropertyPath, pol.MutationValue)
			}

			// Execute exactly 1 mutation write request with test identity
			mutationResp, err := e.executeRequest(ctx, client, pol.Method, fullURL, payload, testedIdent)
			if err != nil {
				res := Result{
					ID:                uuid.New().String(),
					AssessmentID:      actx.AssessmentID,
					ExecutionID:       actx.ExecutionID,
					Category:          pol.Category,
					VulnCode:          string(pol.Category),
					TestID:            fmt.Sprintf("bopla-%s", pol.PropertyID),
					TestName:          pol.Name,
					OWASPRef:          CategoryMetadata[pol.Category].OWASP,
					CWERef:            CategoryMetadata[pol.Category].CWE,
					Endpoint:          pol.Endpoint,
					Method:            pol.Method,
					PropertyPath:      pol.PropertyPath,
					ExpectedAccess:    string(pol.ExpectedAccess),
					RequiredRole:      allowedIdent.Role,
					AccessorRole:      testedIdent.Role,
					AccessorAlias:     testedIdent.Alias,
					VerificationState: StateInconclusive,
					Severity:          "INFO",
					Confidence:        "LOW",
					EvidenceSummary:   fmt.Sprintf("Property mutation request failed: %v", err),
					CreatedAt:         time.Now().UTC(),
				}
				results = append(results, res)
				continue
			}

			var readBackResp ResponseData
			// If mutation returned 2xx, execute independent read-back verification ONLY if ReadBackEndpoint is configured
			if mutationResp.StatusCode >= 200 && mutationResp.StatusCode < 300 && pol.ReadBackEndpoint != "" {
				readBackURL := fullURL
				rbURL, err := ResolveURL(actx.BaseURL, pol.ReadBackEndpoint)
				if err == nil {
					readBackURL = rbURL
				}
				rbMethod := pol.ReadBackMethod
				if rbMethod == "" {
					rbMethod = "GET"
				}

				// Perform read-back using authorized identity (or test identity if readable)
				readBackData, err := e.executeRequest(ctx, client, rbMethod, readBackURL, "", allowedIdent)
				if err == nil {
					readBackResp = readBackData
				}
			}

			comp := ComparePropertyMutation(baseResp, mutationResp, readBackResp, pol, allowedIdent.Role, testedIdent.Role, testedIdent.Alias)
			res := Result{
				ID:                uuid.New().String(),
				AssessmentID:      actx.AssessmentID,
				ExecutionID:       actx.ExecutionID,
				Category:          pol.Category,
				VulnCode:          string(pol.Category),
				TestID:            fmt.Sprintf("bopla-%s", pol.PropertyID),
				TestName:          pol.Name,
				OWASPRef:          CategoryMetadata[pol.Category].OWASP,
				CWERef:            CategoryMetadata[pol.Category].CWE,
				Endpoint:          pol.Endpoint,
				Method:            pol.Method,
				PropertyPath:      pol.PropertyPath,
				ExpectedAccess:    string(pol.ExpectedAccess),
				RequiredRole:      allowedIdent.Role,
				AccessorRole:      testedIdent.Role,
				AccessorAlias:     testedIdent.Alias,
				VerificationState: comp.State,
				Severity:          comp.Severity,
				Confidence:        comp.Confidence,
				ObservedStatus:    mutationResp.StatusCode,
				EvidenceSummary:   comp.EvidenceSummary,
				EvidenceDetails:   comp.EvidenceDetails,
				CreatedAt:         time.Now().UTC(),
			}
			if comp.State == StateVerified || comp.State == StateCandidate {
				res.Finding = buildFinding(res, pol, comp, fullURL)
			}
			results = append(results, res)

		} else {
			// Read / Excessive Exposure / Representation Bypass workflow
			testResp, err := e.executeRequest(ctx, client, pol.Method, fullURL, "", testedIdent)
			if err != nil {
				res := Result{
					ID:                uuid.New().String(),
					AssessmentID:      actx.AssessmentID,
					ExecutionID:       actx.ExecutionID,
					Category:          pol.Category,
					VulnCode:          string(pol.Category),
					TestID:            fmt.Sprintf("bopla-%s", pol.PropertyID),
					TestName:          pol.Name,
					OWASPRef:          CategoryMetadata[pol.Category].OWASP,
					CWERef:            CategoryMetadata[pol.Category].CWE,
					Endpoint:          pol.Endpoint,
					Method:            pol.Method,
					PropertyPath:      pol.PropertyPath,
					ExpectedAccess:    string(pol.ExpectedAccess),
					RequiredRole:      allowedIdent.Role,
					AccessorRole:      testedIdent.Role,
					AccessorAlias:     testedIdent.Alias,
					VerificationState: StateInconclusive,
					Severity:          "INFO",
					Confidence:        "LOW",
					EvidenceSummary:   fmt.Sprintf("Test request for role %s failed: %v", testedIdent.Role, err),
					CreatedAt:         time.Now().UTC(),
				}
				results = append(results, res)
				continue
			}

			comp := ComparePropertyRead(baseResp, testResp, pol, allowedIdent.Role, testedIdent.Role, testedIdent.Alias)
			res := Result{
				ID:                uuid.New().String(),
				AssessmentID:      actx.AssessmentID,
				ExecutionID:       actx.ExecutionID,
				Category:          pol.Category,
				VulnCode:          string(pol.Category),
				TestID:            fmt.Sprintf("bopla-%s", pol.PropertyID),
				TestName:          pol.Name,
				OWASPRef:          CategoryMetadata[pol.Category].OWASP,
				CWERef:            CategoryMetadata[pol.Category].CWE,
				Endpoint:          pol.Endpoint,
				Method:            pol.Method,
				PropertyPath:      pol.PropertyPath,
				ExpectedAccess:    string(pol.ExpectedAccess),
				RequiredRole:      allowedIdent.Role,
				AccessorRole:      testedIdent.Role,
				AccessorAlias:     testedIdent.Alias,
				VerificationState: comp.State,
				Severity:          comp.Severity,
				Confidence:        comp.Confidence,
				ObservedStatus:    testResp.StatusCode,
				EvidenceSummary:   comp.EvidenceSummary,
				EvidenceDetails:   comp.EvidenceDetails,
				CreatedAt:         time.Now().UTC(),
			}
			if comp.State == StateVerified || comp.State == StateCandidate {
				res.Finding = buildFinding(res, pol, comp, fullURL)
			}
			results = append(results, res)
		}
	}

	summary := compileSummary(results)
	return results, summary, nil
}

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

func selectIdentities(pol PropertyPolicy, identities []TestIdentity) (*TestIdentity, *TestIdentity) {
	var allowed *TestIdentity
	var tested *TestIdentity

	// 1. Look for matching allowed identity
	for i := range identities {
		id := &identities[i]
		for _, ar := range pol.AllowedRoles {
			if strings.EqualFold(id.Role, ar) || strings.EqualFold(id.Alias, ar) {
				allowed = id
				break
			}
		}
		if allowed != nil {
			break
		}
	}

	// 2. Look for matching restricted identity
	for i := range identities {
		id := &identities[i]
		for _, rr := range pol.RestrictedRoles {
			if strings.EqualFold(id.Role, rr) || strings.EqualFold(id.Alias, rr) {
				tested = id
				break
			}
		}
		if tested != nil {
			break
		}
	}

	// Fallback to highest and lowest privilege
	if allowed == nil && len(identities) > 0 {
		allowed = &identities[0]
	}
	if tested == nil && len(identities) > 1 {
		tested = &identities[1]
	}

	return allowed, tested
}

func buildMutationPayload(path string, val any) string {
	parts := strings.Split(path, ".")
	if len(parts) == 1 {
		m := map[string]any{parts[0]: val}
		b, _ := json.Marshal(m)
		return string(b)
	}

	// Build nested object
	root := make(map[string]any)
	curr := root
	for i := 0; i < len(parts)-1; i++ {
		next := make(map[string]any)
		curr[parts[i]] = next
		curr = next
	}
	curr[parts[len(parts)-1]] = val

	b, _ := json.Marshal(root)
	return string(b)
}

func buildFinding(res Result, pol PropertyPolicy, comp ComparisonResult, targetURL string) *report.Finding {
	meta := CategoryMetadata[pol.Category]
	sanitizedTarget := SanitizeURL(targetURL)
	sanitizedEndpoint := SanitizeURL(pol.Endpoint)
	if sanitizedEndpoint == "" {
		sanitizedEndpoint = sanitizedTarget
	}

	evidence := RedactText(comp.EvidenceSummary)
	return &report.Finding{
		ID:          uuid.New().String(),
		Title:       fmt.Sprintf("[%s] %s on %s [%s]", res.VulnCode, meta.Name, res.Endpoint, pol.PropertyPath),
		Category:    fmt.Sprintf("%s / %s", meta.OWASP, meta.Name),
		Severity:    res.Severity,
		Confidence:  res.Confidence,
		Target:      sanitizedTarget,
		Endpoint:    sanitizedEndpoint,
		Method:      res.Method,
		Description: fmt.Sprintf("[%s / %s] %s", res.VulnCode, meta.OWASP, meta.Description),
		Evidence:    evidence,
		EvidenceDetails: report.EvidenceDetails{
			Observation:     evidence,
			Location:        sanitizedEndpoint,
			HTTPMethod:      res.Method,
			HTTPStatus:      res.ObservedStatus,
			DetectionMethod: "BOPLA_VERIFICATION_ENGINE",
			Details: map[string]string{
				"category":        string(res.Category),
				"vuln_code":       res.VulnCode,
				"property_path":   pol.PropertyPath,
				"expected_access": string(pol.ExpectedAccess),
				"required_role":   res.RequiredRole,
				"accessor_role":   res.AccessorRole,
				"accessor_alias":  res.AccessorAlias,
			},
		},
		Remediation: fmt.Sprintf("Enforce property-level authorization checks at the data serialization and model binding layers. Ensure restricted property %q is omitted or masked from unauthorized responses, and forbid mass assignment on mutating endpoints.", pol.PropertyPath),
	}
}

func compileSummary(results []Result) *Summary {
	summary := &Summary{
		TotalTests:  len(results),
		CoverageMap: make(map[string]CategoryCoverage),
	}

	// Initialize all categories in coverage map
	for cat, meta := range CategoryMetadata {
		summary.CoverageMap[string(cat)] = CategoryCoverage{
			Category: cat,
			Code:     meta.Code,
			Name:     meta.Name,
			OWASPRef: meta.OWASP,
			Status:   CoverageUntested,
		}
	}

	for _, r := range results {
		cov := summary.CoverageMap[string(r.Category)]
		cov.TestsRun++

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

		summary.CoverageMap[string(r.Category)] = cov
	}

	covered := 0
	for _, cov := range summary.CoverageMap {
		if cov.TestsRun > 0 {
			covered++
		}
	}
	summary.CategoriesCovered = covered

	return summary
}

func makeSkippedResult(actx *AssessmentContext, pol PropertyPolicy, reason string) Result {
	return Result{
		ID:                uuid.New().String(),
		AssessmentID:      actx.AssessmentID,
		ExecutionID:       actx.ExecutionID,
		Category:          pol.Category,
		VulnCode:          string(pol.Category),
		TestID:            fmt.Sprintf("bopla-%s", pol.PropertyID),
		TestName:          pol.Name,
		OWASPRef:          CategoryMetadata[pol.Category].OWASP,
		CWERef:            CategoryMetadata[pol.Category].CWE,
		Endpoint:          pol.Endpoint,
		Method:            pol.Method,
		PropertyPath:      pol.PropertyPath,
		ExpectedAccess:    string(pol.ExpectedAccess),
		VerificationState: StateSkipped,
		Severity:          "INFO",
		Confidence:        "CONFIRMED",
		EvidenceSummary:   reason,
		CreatedAt:         time.Now().UTC(),
	}
}

func makeInconclusiveResult(actx *AssessmentContext, pol PropertyPolicy, reason string) Result {
	return Result{
		ID:                uuid.New().String(),
		AssessmentID:      actx.AssessmentID,
		ExecutionID:       actx.ExecutionID,
		Category:          pol.Category,
		VulnCode:          string(pol.Category),
		TestID:            fmt.Sprintf("bopla-%s", pol.PropertyID),
		TestName:          pol.Name,
		OWASPRef:          CategoryMetadata[pol.Category].OWASP,
		CWERef:            CategoryMetadata[pol.Category].CWE,
		Endpoint:          pol.Endpoint,
		Method:            pol.Method,
		PropertyPath:      pol.PropertyPath,
		ExpectedAccess:    string(pol.ExpectedAccess),
		VerificationState: StateInconclusive,
		Severity:          "INFO",
		Confidence:        "LOW",
		EvidenceSummary:   reason,
		CreatedAt:         time.Now().UTC(),
	}
}

func makeErrorResult(actx *AssessmentContext, pol PropertyPolicy, reason string) Result {
	return Result{
		ID:                uuid.New().String(),
		AssessmentID:      actx.AssessmentID,
		ExecutionID:       actx.ExecutionID,
		Category:          pol.Category,
		VulnCode:          string(pol.Category),
		TestID:            fmt.Sprintf("bopla-%s", pol.PropertyID),
		TestName:          pol.Name,
		OWASPRef:          CategoryMetadata[pol.Category].OWASP,
		CWERef:            CategoryMetadata[pol.Category].CWE,
		Endpoint:          pol.Endpoint,
		Method:            pol.Method,
		PropertyPath:      pol.PropertyPath,
		ExpectedAccess:    string(pol.ExpectedAccess),
		VerificationState: StateInconclusive,
		Severity:          "INFO",
		Confidence:        "LOW",
		EvidenceSummary:   fmt.Sprintf("Execution error: %s", reason),
		CreatedAt:         time.Now().UTC(),
	}
}

// DefaultIdentities provides standard test identities for BOPLA verification.
func DefaultIdentities() []TestIdentity {
	return []TestIdentity{
		{
			Alias:          "admin_user",
			Role:           "admin",
			PrivilegeLevel: 5,
			Headers: map[string]string{
				"Authorization": "Bearer token_admin_synthetic",
			},
		},
		{
			Alias:          "standard_user",
			Role:           "user",
			PrivilegeLevel: 1,
			Headers: map[string]string{
				"Authorization": "Bearer token_user_synthetic",
			},
		},
	}
}
