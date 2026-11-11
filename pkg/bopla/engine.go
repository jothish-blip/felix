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
	base          http.RoundTripper
	maxRequests   int
	reqCount      *int32
	perIdentLimit int
	perIdentCount *int32
}

func (c *credentialGuardedTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if c.perIdentLimit > 0 && c.perIdentCount != nil {
		for {
			curr := atomic.LoadInt32(c.perIdentCount)
			if int(curr) >= c.perIdentLimit {
				return nil, fmt.Errorf("per-identity request budget exceeded (%d/%d)", curr, c.perIdentLimit)
			}
			if atomic.CompareAndSwapInt32(c.perIdentCount, curr, curr+1) {
				break
			}
		}
	} else if c.perIdentCount != nil {
		atomic.AddInt32(c.perIdentCount, 1)
	}

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

// IsDestructivePropertyAction returns true if endpoint/property semantics involve irreversible account/credential/billing writes.
func IsDestructivePropertyAction(endpoint, propertyPath string) bool {
	ep := strings.ToLower(strings.TrimSpace(endpoint))
	pp := strings.ToLower(strings.TrimSpace(propertyPath))
	destructiveEndpointTokens := []string{"/delete", "/remove", "/suspend", "/payment", "/billing", "/checkout", "/wipe", "/reset"}
	for _, tok := range destructiveEndpointTokens {
		if strings.Contains(ep, tok) {
			return true
		}
	}
	destructivePropTokens := []string{"password", "passcode", "pin", "delete", "payment", "card_number", "cvv", "wipe"}
	for _, tok := range destructivePropTokens {
		if pp == tok || strings.HasSuffix(pp, "."+tok) {
			return true
		}
	}
	return false
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
	return e.buildGuardedClient(e.client, actx, 0, nil)
}

func (e *Engine) buildGuardedClient(baseClient *http.Client, actx *AssessmentContext, perIdentLimit int, perIdentCount *int32) *http.Client {
	var baseTransport http.RoundTripper
	var jar http.CookieJar
	if baseClient != nil {
		baseTransport = baseClient.Transport
		jar = baseClient.Jar
	}
	if baseTransport == nil && e.client != nil {
		baseTransport = e.client.Transport
	}
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
		base:          baseTransport,
		maxRequests:   actx.MaxRequests,
		reqCount:      actx.DispatchedRequests,
		perIdentLimit: perIdentLimit,
		perIdentCount: perIdentCount,
	}

	return &http.Client{
		Transport: guard,
		Timeout:   e.cfg.Timeout,
		Jar:       jar,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 10 {
				return fmt.Errorf("stopped after 10 redirects")
			}
			if actx.IsExcluded != nil && actx.IsExcluded(req.URL.String()) {
				return fmt.Errorf("redirect target %s excluded by scope", SanitizeURL(req.URL.String()))
			}
			if actx.IsAllowed != nil && !actx.IsAllowed(req.URL.String()) {
				return fmt.Errorf("redirect target %s outside authorized scope", SanitizeURL(req.URL.String()))
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

func (e *Engine) scopedClientFor(actx *AssessmentContext, id *TestIdentity, cache map[string]*http.Client, perIdentCounts map[string]*int32) *http.Client {
	if id == nil {
		return e.scopedClient(actx)
	}
	key := strings.ToUpper(strings.TrimSpace(id.Alias))
	if key == "" {
		key = strings.ToUpper(strings.TrimSpace(id.Role))
	}
	if cached, ok := cache[key]; ok {
		return cached
	}
	var baseClient *http.Client
	if len(actx.IdentityClients) > 0 {
		for k, c := range actx.IdentityClients {
			if strings.EqualFold(k, id.Alias) || strings.EqualFold(k, id.Role) {
				baseClient = c
				break
			}
		}
	}
	if baseClient == nil {
		baseClient = e.client
	}
	var perCount *int32
	if actx.MaxRequestsPerIdentity > 0 {
		perCount = perIdentCounts[key]
		if perCount == nil {
			var zero int32
			perCount = &zero
			perIdentCounts[key] = perCount
		}
	}
	wrapped := e.buildGuardedClient(baseClient, actx, actx.MaxRequestsPerIdentity, perCount)
	cache[key] = wrapped
	return wrapped
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
		} else if (pol.SafetyClass == "DESTRUCTIVE" || (pol.DiscoverySource != "" && (pol.IsStateChanging || pol.Category == CategoryBOPLAPropertyWrite || pol.Category == CategoryBOPLAMassAssignment) && IsDestructivePropertyAction(pol.Endpoint, pol.PropertyPath))) && !pol.IsReversibleTest {
			pt.Status = PlanSkipped
			pt.BlockedReason = "Destructive property mutation excluded by default safety policy"
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

	// Initialize counters and setup scoped client caches
	if actx.DispatchedRequests == nil {
		var initialReqs int32
		actx.DispatchedRequests = &initialReqs
	}
	clientCache := make(map[string]*http.Client)
	perIdentCounts := make(map[string]*int32)
	readBaselineCache := make(map[string]ResponseData)
	var exposureTests, modTests int

	seenPolicies := make(map[string]bool)
	evaluatedProps := 0
	mutationHaltedReason := ""

	for _, pol := range policies {
		if ctx.Err() != nil {
			return nil, nil, ctx.Err()
		}

		dedupKey := strings.ToUpper(strings.TrimSpace(pol.Method)) + " " + strings.TrimSpace(pol.Endpoint) + "::" + strings.TrimSpace(pol.PropertyPath)
		if dedupKey != " ::" && seenPolicies[dedupKey] {
			continue
		}
		seenPolicies[dedupKey] = true

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

		isWriteTest := pol.IsStateChanging || pol.Category == CategoryBOPLAPropertyWrite || pol.Category == CategoryBOPLAMassAssignment
		if (pol.SafetyClass == "DESTRUCTIVE" || (pol.DiscoverySource != "" && isWriteTest && IsDestructivePropertyAction(pol.Endpoint, pol.PropertyPath))) && !pol.IsReversibleTest {
			res := makeSkippedResult(actx, pol, "Destructive property mutation excluded by default safety policy")
			results = append(results, res)
			continue
		}

		// State-changing safety check
		if isWriteTest {
			if mutationHaltedReason != "" {
				res := makeSkippedResult(actx, pol, mutationHaltedReason)
				results = append(results, res)
				continue
			}
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

		if actx.MaxProperties > 0 && evaluatedProps >= actx.MaxProperties {
			res := makeSkippedResult(actx, pol, fmt.Sprintf("Skipped due to max property evaluation cap (%d)", actx.MaxProperties))
			results = append(results, res)
			continue
		}
		evaluatedProps++

		// Identity resolution
		allowedIdent, singleTestedIdent := selectIdentities(pol, identities)
		var testedIdents []*TestIdentity
		if actx.TestAllIdentities || len(actx.IdentityClients) > 0 {
			testedIdents = selectRestrictedIdentities(pol, identities, allowedIdent)
		} else if singleTestedIdent != nil {
			testedIdents = []*TestIdentity{singleTestedIdent}
		}

		if allowedIdent == nil || len(testedIdents) == 0 {
			res := makeInconclusiveResult(actx, pol, "Missing required identity contexts for differential property testing")
			results = append(results, res)
			continue
		}
		distinctPairs := make([]*TestIdentity, 0, len(testedIdents))
		for _, cand := range testedIdents {
			if AreIdentitiesDistinct(*allowedIdent, *cand) {
				distinctPairs = append(distinctPairs, cand)
			}
		}
		if len(distinctPairs) == 0 {
			res := makeInconclusiveResult(actx, pol, "Identical identities configured; differential property testing requires distinct principal contexts")
			results = append(results, res)
			continue
		}

		allowedClient := e.scopedClientFor(actx, allowedIdent, clientCache, perIdentCounts)

		// Step A: Positive Control Baseline Request (Authorized Role) executed once per policy
		baselineURL := fullURL
		if pol.DiscoverySource != "" && isWriteTest && pol.ReadBackEndpoint != "" {
			if rbURL, err := ResolveURL(actx.BaseURL, pol.ReadBackEndpoint); err == nil {
				baselineURL = rbURL
			}
		}
		cacheKey := strings.ToUpper(allowedIdent.Alias) + "::" + baselineURL
		var baseResp ResponseData
		if pol.DiscoverySource != "" && !isWriteTest {
			if cached, ok := readBaselineCache[cacheKey]; ok {
				baseResp = cached
			}
		}
		if baseResp.StatusCode == 0 {
			fetched, err := e.executeRequest(ctx, allowedClient, "GET", baselineURL, "", allowedIdent)
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
					AccessorRole:      distinctPairs[0].Role,
					AccessorAlias:     distinctPairs[0].Alias,
					VerificationState: StateInconclusive,
					Severity:          "INFO",
					Confidence:        "LOW",
					EvidenceSummary:   fmt.Sprintf("Authorized baseline request for role %s failed: %v", allowedIdent.Role, err),
					CreatedAt:         time.Now().UTC(),
				}
				results = append(results, res)
				continue
			}
			baseResp = fetched
			if pol.DiscoverySource != "" && !isWriteTest {
				readBaselineCache[cacheKey] = baseResp
			}
		}

		// Step B: Execute against each distinct restricted identity with isolated transport
		for _, testedIdent := range distinctPairs {
			if ctx.Err() != nil {
				return nil, nil, ctx.Err()
			}
			testedClient := e.scopedClientFor(actx, testedIdent, clientCache, perIdentCounts)

			if isWriteTest {
				if mutationHaltedReason != "" {
					res := makeSkippedResult(actx, pol, mutationHaltedReason)
					res.AccessorRole = testedIdent.Role
					res.AccessorAlias = testedIdent.Alias
					results = append(results, res)
					continue
				}
				modTests++
				payload := pol.MutationPayload
				if payload == "" {
					payload = buildMutationPayload(pol.PropertyPath, pol.MutationValue)
				}

				// Execute bounded mutation write request with isolated test identity
				mutationResp, err := e.executeRequest(ctx, testedClient, pol.Method, fullURL, payload, testedIdent)
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
				var readBackURL, rbMethod string
				if mutationResp.StatusCode >= 200 && mutationResp.StatusCode < 300 && pol.ReadBackEndpoint != "" {
					readBackURL = fullURL
					if rbURL, rbErr := ResolveURL(actx.BaseURL, pol.ReadBackEndpoint); rbErr == nil {
						readBackURL = rbURL
					}
					rbMethod = pol.ReadBackMethod
					if rbMethod == "" {
						rbMethod = "GET"
					}

					// Read-back using tested identity or authorized baseline identity
					readIdent := testedIdent
					readClient := testedClient
					if strings.EqualFold(testedIdent.Role, "anonymous") || strings.EqualFold(testedIdent.Alias, "ANONYMOUS") {
						readIdent = allowedIdent
						readClient = allowedClient
					}
					readBackData, rbErr := e.executeRequest(ctx, readClient, rbMethod, readBackURL, "", readIdent)
					if rbErr == nil {
						readBackResp = readBackData
					}
				}

				comp := downgradeIfPolicyUnestablished(
					ComparePropertyMutation(baseResp, mutationResp, readBackResp, pol, allowedIdent.Role, testedIdent.Role, testedIdent.Alias),
					pol,
				)

				// Attempt and verify cleanup when reversible fixture mutation may have persisted
				var cleanupStatus, cleanupWarning string
				if mutationResp.StatusCode >= 200 && mutationResp.StatusCode < 300 && comp.State != StateNotVulnerable {
					if pol.IsReversibleTest && pol.RestorePayload != "" {
						cleanupStatus, cleanupWarning = e.executeAndVerifyCleanup(ctx, allowedClient, allowedIdent, fullURL, readBackURL, rbMethod, pol)
					} else if comp.State == StateVerified {
						cleanupStatus = "CLEANUP_UNAVAILABLE"
						cleanupWarning = fmt.Sprintf("BOPLA mass assignment persisted on %s [%s] without a baseline restore payload; verify fixture state manually", pol.Endpoint, pol.PropertyPath)
					}
					if comp.EvidenceDetails == nil {
						comp.EvidenceDetails = make(map[string]string)
					}
					if cleanupStatus != "" {
						comp.EvidenceDetails["cleanup_status"] = cleanupStatus
					}
					if cleanupWarning != "" {
						comp.EvidenceDetails["cleanup_warning"] = cleanupWarning
					}
				}

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
					CleanupStatus:     cleanupStatus,
					CleanupWarning:    cleanupWarning,
					EvidenceSummary:   comp.EvidenceSummary,
					EvidenceDetails:   comp.EvidenceDetails,
					CreatedAt:         time.Now().UTC(),
				}
				if comp.State == StateVerified || comp.State == StateCandidate {
					res.Finding = buildFinding(res, pol, comp, fullURL)
				}
				results = append(results, res)
				if cleanupStatus == "CLEANUP_FAILED" || cleanupStatus == "CLEANUP_UNVERIFIED" {
					mutationHaltedReason = fmt.Sprintf("State-changing property probe stopped due to prior restoration failure (%s: %s)", cleanupStatus, RedactText(cleanupWarning))
				}

			} else {
				exposureTests++
				testResp, err := e.executeRequest(ctx, testedClient, pol.Method, fullURL, "", testedIdent)
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

				comp := downgradeIfPolicyUnestablished(
					ComparePropertyRead(baseResp, testResp, pol, allowedIdent.Role, testedIdent.Role, testedIdent.Alias),
					pol,
				)
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
	}

	summary := compileSummaryWithContext(results, policies, exposureTests, modTests)
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

func selectRestrictedIdentities(pol PropertyPolicy, identities []TestIdentity, allowed *TestIdentity) []*TestIdentity {
	var out []*TestIdentity
	for i := range identities {
		id := &identities[i]
		if allowed != nil && !AreIdentitiesDistinct(*id, *allowed) {
			continue
		}
		restrictedMatch := false
		for _, rr := range pol.RestrictedRoles {
			if strings.EqualFold(id.Role, rr) || strings.EqualFold(id.Alias, rr) {
				restrictedMatch = true
				break
			}
		}
		if !restrictedMatch && len(pol.RestrictedRoles) == 0 {
			allowedMatch := false
			for _, ar := range pol.AllowedRoles {
				if strings.EqualFold(id.Role, ar) || strings.EqualFold(id.Alias, ar) {
					allowedMatch = true
					break
				}
			}
			restrictedMatch = !allowedMatch
		}
		if restrictedMatch || (allowed != nil && strings.EqualFold(id.Role, allowed.Role) == false) {
			out = append(out, id)
		}
	}
	return out
}

func downgradeIfPolicyUnestablished(comp ComparisonResult, pol PropertyPolicy) ComparisonResult {
	if !pol.PolicyUnestablished || comp.State != StateVerified {
		return comp
	}
	if comp.EvidenceDetails == nil {
		comp.EvidenceDetails = make(map[string]string)
	}
	comp.EvidenceDetails["policy_unestablished"] = "true"
	comp.State = StateCandidate
	comp.Severity = "MEDIUM"
	comp.Confidence = "POSSIBLE"
	comp.EvidenceSummary = strings.TrimSpace(comp.EvidenceSummary) + " (Note: property sensitivity/expectation was inferred without authoritative schema or cross-role differential; downgraded from VERIFIED to CANDIDATE.)"
	return comp
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
	findingStatus := report.FindingStatusSuspected
	verStatus := report.VerificationDetected
	detectionStatus := "CANDIDATE"
	confidenceScore := 55
	if res.VerificationState == StateVerified {
		findingStatus = report.FindingStatusConfirmed
		verStatus = report.VerificationVerified
		detectionStatus = "CONFIRMED"
		confidenceScore = 95
	}

	details := map[string]string{
		"category":              string(res.Category),
		"vuln_code":             res.VulnCode,
		"property_path":         pol.PropertyPath,
		"expected_access":       string(pol.ExpectedAccess),
		"required_role":         res.RequiredRole,
		"accessor_role":         res.AccessorRole,
		"accessor_alias":        res.AccessorAlias,
		"verification_state":    string(res.VerificationState),
		"authz_engine_verified": "true",
	}
	if pol.PropertyClassification != "" {
		details["property_classification"] = pol.PropertyClassification
	}
	if pol.DiscoverySource != "" {
		details["discovery_source"] = pol.DiscoverySource
	}
	if pol.DiscoveryConfidence != "" {
		details["discovery_confidence"] = pol.DiscoveryConfidence
	}
	if pol.PolicyEvidence != "" {
		details["policy_evidence"] = RedactText(pol.PolicyEvidence)
	}
	if pol.PolicyUnestablished {
		details["policy_unestablished"] = "true"
	}
	if res.CleanupStatus != "" {
		details["cleanup_status"] = res.CleanupStatus
	}
	if res.CleanupWarning != "" {
		details["cleanup_warning"] = RedactText(res.CleanupWarning)
		evidence = fmt.Sprintf("%s [CLEANUP WARNING: %s]", evidence, RedactText(res.CleanupWarning))
	}
	remediation := fmt.Sprintf("Enforce property-level authorization checks at the data serialization and model binding layers. Ensure restricted property %q is omitted or masked from unauthorized responses, and forbid mass assignment on mutating endpoints.", pol.PropertyPath)
	if res.CleanupStatus == "CLEANUP_FAILED" || res.CleanupStatus == "CLEANUP_UNVERIFIED" {
		remediation = fmt.Sprintf("%s Additionally, automated restoration of %q reported %s (%s); verify and reset target fixture state manually.", remediation, pol.PropertyPath, res.CleanupStatus, RedactText(res.CleanupWarning))
	}

	return &report.Finding{
		ID:          uuid.New().String(),
		RuleID:      "VULN-BOPLA-001",
		Status:      findingStatus,
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
			Observation:      evidence,
			Location:         sanitizedEndpoint,
			HTTPMethod:       res.Method,
			HTTPStatus:       res.ObservedStatus,
			DetectionMethod:  "BOPLA_VERIFICATION_ENGINE",
			DetectionStatus:  detectionStatus,
			ExpectedBehavior: fmt.Sprintf("Property %q should enforce %s for role %s", pol.PropertyPath, pol.ExpectedAccess, res.AccessorRole),
			ObservedBehavior: evidence,
			Details:          details,
		},
		Verification: report.VerificationRecord{
			Status:             verStatus,
			DetectionStatus:    detectionStatus,
			Result:             evidence,
			Rationale:          RedactText(pol.PolicyEvidence),
			PolicyID:           pol.PropertyID,
			VerificationMethod: "DIFFERENTIAL_PROPERTY_AUTHORIZATION",
			AnalysisMethod:     "ACTIVE_VERIFICATION",
			ConfidenceScore:    confidenceScore,
			Attempted:          true,
		},
		Remediation: remediation,
	}
}

// executeAndVerifyCleanup restores a mutated reversible property and verifies persistence reverted cleanly.
func (e *Engine) executeAndVerifyCleanup(
	ctx context.Context,
	allowedClient *http.Client,
	allowedIdent *TestIdentity,
	fullURL, readBackURL, rbMethod string,
	pol PropertyPolicy,
) (string, string) {
	restoreResp, restoreErr := e.executeRequest(ctx, allowedClient, pol.Method, fullURL, pol.RestorePayload, allowedIdent)
	if restoreErr != nil {
		return "CLEANUP_FAILED", fmt.Sprintf("BOPLA cleanup failed for %s [%s]: restore request error: %v", pol.Endpoint, pol.PropertyPath, restoreErr)
	}
	if restoreResp.StatusCode < 200 || restoreResp.StatusCode >= 300 {
		return "CLEANUP_FAILED", fmt.Sprintf("BOPLA cleanup failed for %s [%s]: restore returned non-2xx HTTP %d", pol.Endpoint, pol.PropertyPath, restoreResp.StatusCode)
	}

	if readBackURL != "" && pol.PropertyPath != "" {
		if rbMethod == "" {
			rbMethod = "GET"
		}
		postResp, rbErr := e.executeRequest(ctx, allowedClient, rbMethod, readBackURL, "", allowedIdent)
		if rbErr != nil {
			return "CLEANUP_UNVERIFIED", fmt.Sprintf("BOPLA restore returned HTTP %d for %s [%s], but post-restore verification read-back failed: %v", restoreResp.StatusCode, pol.Endpoint, pol.PropertyPath, rbErr)
		}
		if postResp.StatusCode < 200 || postResp.StatusCode >= 300 {
			return "CLEANUP_UNVERIFIED", fmt.Sprintf("BOPLA restore returned HTTP %d for %s [%s], but post-restore verification read-back returned HTTP %d", restoreResp.StatusCode, pol.Endpoint, pol.PropertyPath, postResp.StatusCode)
		}
		var postData any
		if err := json.Unmarshal(postResp.Body, &postData); err != nil {
			return "CLEANUP_UNVERIFIED", fmt.Sprintf("BOPLA restore returned HTTP %d for %s [%s], but post-restore verification read-back returned non-JSON body", restoreResp.StatusCode, pol.Endpoint, pol.PropertyPath)
		}
		if postVal, found := ExtractProperty(postData, pol.PropertyPath); found && IsPropertyEqual(postVal, pol.MutationValue) {
			return "CLEANUP_FAILED", fmt.Sprintf("BOPLA cleanup failed for %s [%s]: restore returned HTTP %d, but post-restore read-back still observed injected value %q", pol.Endpoint, pol.PropertyPath, restoreResp.StatusCode, RedactValue(pol.MutationValue))
		}
	}

	return "RESTORED", ""
}

func compileSummary(results []Result) *Summary {
	return compileSummaryWithContext(results, nil, 0, 0)
}

func compileSummaryWithContext(results []Result, policies []PropertyPolicy, exposureTests, modTests int) *Summary {
	summary := &Summary{
		TotalTests:           len(results),
		PropertiesDiscovered: len(policies),
		ExposureTests:        exposureTests,
		ModificationTests:    modTests,
		CoverageMap:          make(map[string]CategoryCoverage),
	}

	for _, pol := range policies {
		if !pol.PolicyUnestablished && pol.ExpectedAccess != "" {
			summary.PropertiesWithPolicy++
		}
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
			summary.SkippedCount++
			cov.Blocked++
			if cov.Status == CoverageUntested {
				cov.Status = CoverageBlockedMissingPrereq
			}
		}

		switch r.CleanupStatus {
		case "RESTORED":
			summary.CleanupAttempted++
			summary.CleanupRestored++
		case "CLEANUP_FAILED":
			summary.CleanupAttempted++
			summary.CleanupFailed++
			if r.CleanupWarning != "" {
				summary.CleanupWarnings = append(summary.CleanupWarnings, r.CleanupWarning)
			}
		case "CLEANUP_UNVERIFIED":
			summary.CleanupAttempted++
			summary.CleanupUnverified++
			if r.CleanupWarning != "" {
				summary.CleanupWarnings = append(summary.CleanupWarnings, r.CleanupWarning)
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
