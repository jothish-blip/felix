package bfla

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"
	"time"

	"felix/pkg/crawler"
	"felix/pkg/report"
	"github.com/google/uuid"
)

// EffectivePort returns the explicit port or default scheme port for standard HTTP/HTTPS URLs.
func EffectivePort(u *url.URL) string {
	if u == nil {
		return ""
	}
	if p := u.Port(); p != "" {
		return p
	}
	switch strings.ToLower(u.Scheme) {
	case "https":
		return "443"
	case "http":
		return "80"
	default:
		return ""
	}
}

// IsSameOrigin checks whether two URLs share the exact scheme, host, and effective port.
func IsSameOrigin(u1, u2 *url.URL) bool {
	if u1 == nil || u2 == nil {
		return false
	}
	if !strings.EqualFold(u1.Scheme, u2.Scheme) {
		return false
	}
	if !strings.EqualFold(u1.Hostname(), u2.Hostname()) {
		return false
	}
	return EffectivePort(u1) == EffectivePort(u2)
}

// IsLoopbackHost checks whether a hostname or IP represents the local loopback machine.
func IsLoopbackHost(host string) bool {
	h := strings.ToLower(strings.TrimSpace(host))
	if h == "localhost" || h == "127.0.0.1" || h == "::1" || h == "ip6-localhost" || h == "ip6-loopback" {
		return true
	}
	if ip := net.ParseIP(h); ip != nil {
		return ip.IsLoopback()
	}
	return false
}

// SensitiveCredentialHeaders enumerates HTTP headers containing authentication credentials or session tokens.
var SensitiveCredentialHeaders = []string{
	"Authorization",
	"Cookie",
	"Cookie2",
	"X-Auth-Token",
	"X-API-Key",
	"X-Session-ID",
	"X-Session-Token",
	"X-CSRF-Token",
	"X-XSRF-Token",
	"Proxy-Authorization",
}

// StripSensitiveCredentials strips all sensitive authentication, token, and session headers from an HTTP request.
func StripSensitiveCredentials(req *http.Request) {
	if req == nil || req.Header == nil {
		return
	}
	for _, h := range SensitiveCredentialHeaders {
		req.Header.Del(h)
	}
}

// credentialGuardedTransport wraps an http.RoundTripper to withhold sensitive credentials
// from remote unencrypted HTTP requests and enforce request budget.
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
				return nil, fmt.Errorf("per-identity request budget exceeded (limit: %d)", c.perIdentLimit)
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
				return nil, fmt.Errorf("request budget exceeded (limit: %d)", c.maxRequests)
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

// IsDestructiveFunction identifies paths or HTTP methods that mutate sensitive account/system state.
func IsDestructiveFunction(method, rawPath string) bool {
	m := strings.ToUpper(strings.TrimSpace(method))
	if m == http.MethodDelete {
		return true
	}
	lower := strings.ToLower(strings.TrimSpace(rawPath))
	destructiveTokens := []string{
		"/delete", "/remove", "/suspend", "/disable", "/deactivate",
		"/password", "/reset", "/createdb", "/initdb", "/resetdb",
		"/payment", "/billing", "/checkout", "/purchase",
		"/restart", "/shutdown", "/reboot", "/wipe", "/purge", "/truncate", "/drop",
		"/logout", "/signout",
	}
	for _, tok := range destructiveTokens {
		if strings.Contains(lower, tok) {
			return true
		}
	}
	return false
}

// Engine evaluates Broken Function Level Authorization (BFLA) across privilege boundaries.
type Engine struct {
	client *http.Client
	config Config
}

// NewEngine creates a new BFLA Verification Engine.
func NewEngine(client *http.Client, config Config) *Engine {
	if client == nil {
		safeTransport := crawler.NewSafeTransport(crawler.SafeTransportOptions{
			Timeout:       config.Timeout,
			KeepAlive:     30 * time.Second,
			AllowLoopback: true,
		})
		client = &http.Client{
			Transport: crawler.NewRateLimitedTransport(safeTransport, crawler.RateLimitOptions{}),
			Timeout:   config.Timeout,
		}
	}
	return &Engine{
		client: client,
		config: config,
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
		baseTransport = http.DefaultTransport
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
		Jar:       jar,
		Timeout:   e.config.Timeout,
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

// Plan produces a pre-assessment execution plan without dispatching network requests (dry-run).
func (e *Engine) Plan(ctx context.Context, actx *AssessmentContext) (*TestPlan, error) {
	plan := &TestPlan{
		AssessmentID: actx.AssessmentID,
		TargetURL:    actx.BaseURL,
		GeneratedAt:  time.Now().UTC(),
	}

	policies := actx.Policies
	if len(policies) == 0 {
		policies = DefaultPolicies()
	}

	identities := actx.Identities
	if len(identities) == 0 {
		identities = DefaultIdentities()
	}

	for _, pol := range policies {
		fullURL := joinURL(actx.BaseURL, pol.Path)
		pt := PlannedTest{
			ID:                fmt.Sprintf("test-%s", pol.FunctionID),
			Category:          pol.Category,
			Name:              pol.Name,
			OWASPRef:          CategoryMetadata[pol.Category].OWASP,
			CWERef:            CategoryMetadata[pol.Category].CWE,
			Endpoint:          pol.Path,
			Method:            pol.Method,
			AllowedRole:       strings.Join(pol.AllowedRoles, ","),
			IsStateChanging:   pol.IsStateChanging,
			SecurityObjective: fmt.Sprintf("Verify that restricted function %s %s cannot be invoked by unauthorized roles", pol.Method, pol.Path),
			Preconditions:     CategoryMetadata[pol.Category].Preconditions,
		}

		// Find lower privilege candidate identity
		var testedIdent *TestIdentity
		for i := range identities {
			id := &identities[i]
			if isRestrictedRole(id.Role, pol) || (pol.RequiredPrivilegeLevel > 0 && id.PrivilegeLevel < pol.RequiredPrivilegeLevel) {
				testedIdent = id
				break
			}
		}

		if testedIdent != nil {
			pt.TestedRole = testedIdent.Role
			pt.TestedAlias = testedIdent.Alias
		} else {
			pt.TestedRole = "unassigned"
			pt.TestedAlias = "none"
		}

		// Evaluate plan status
		if actx.IsExcluded != nil && actx.IsExcluded(fullURL) {
			pt.Status = PlanBlocked
			pt.BlockedReason = "Target endpoint is excluded by assessment scope policy"
			plan.BlockedTests++
		} else if (pol.SafetyClass == "DESTRUCTIVE" || (pol.DiscoverySource != "" && IsDestructiveFunction(pol.Method, pol.Path))) && !pol.AllowReversibleTest {
			pt.Status = PlanSkipped
			pt.BlockedReason = "Destructive function excluded by safety policy"
			plan.BlockedTests++
		} else if (pol.IsStateChanging || pol.Category == CategoryBFLAWriteMutation) && !actx.AllowStateChangingTests {
			pt.Status = PlanSkipped
			pt.BlockedReason = "State-changing function tests require explicit --allow-state-changing opt-in"
			plan.StateChangingTests++
		} else if (pol.IsStateChanging || pol.Category == CategoryBFLAWriteMutation) && !actx.SyntheticFixture {
			pt.Status = PlanBlocked
			pt.BlockedReason = "State-changing function tests are restricted to designated synthetic fixtures or isolated test environments"
			plan.BlockedTests++
		} else if (pol.IsStateChanging || pol.Category == CategoryBFLAWriteMutation) && !IsIsolatedFixtureTarget(fullURL, actx.AuthorizedFixtureHosts, actx.IsFixtureTarget) {
			pt.Status = PlanBlocked
			pt.BlockedReason = "State-changing function tests blocked: target is not a verified isolated synthetic fixture"
			plan.BlockedTests++
		} else if testedIdent == nil {
			pt.Status = PlanBlocked
			pt.BlockedReason = "No distinct lower-privilege identity available to test function restriction"
			plan.BlockedTests++
		} else {
			pt.Status = PlanReady
			plan.ReadyTests++
			plan.ActiveTests++
		}

		plan.Tests = append(plan.Tests, pt)
		plan.TotalTests++
	}

	return plan, nil
}

// Assess executes the active BFLA verification assessment against target endpoints.
func (e *Engine) Assess(ctx context.Context, actx *AssessmentContext) ([]Result, *Summary, error) {
	// 1. Mandatory Authorization Precondition
	if actx.Authorization == nil {
		return nil, nil, fmt.Errorf("authorization required: assessment has no authorization record")
	}
	if valid, reason := actx.Authorization.IsCurrentlyValid(time.Now().UTC()); !valid {
		return nil, nil, fmt.Errorf("authorization required: %s", reason)
	}

	// 2. Scope & Exclusion Check on Target Base
	if actx.IsExcluded != nil && actx.IsExcluded(actx.BaseURL) {
		return nil, nil, fmt.Errorf("assessment target %s is excluded from scope", actx.BaseURL)
	}
	if actx.IsAllowed != nil && !actx.IsAllowed(actx.BaseURL) {
		return nil, nil, fmt.Errorf("assessment target %s is out of authorized scope", actx.BaseURL)
	}

	// 3. Dry-Run Check: return 0 network requests
	if actx.DryRun {
		return []Result{}, &Summary{CoverageMap: make(map[string]CategoryCoverage)}, nil
	}

	// 4. Base URL validation
	if actx.BaseURL == "" {
		return nil, nil, fmt.Errorf("target base URL is empty")
	}
	parsedBase, err := url.Parse(actx.BaseURL)
	if err != nil || (parsedBase.Scheme != "http" && parsedBase.Scheme != "https") {
		return nil, nil, fmt.Errorf("invalid target base URL: %s", actx.BaseURL)
	}

	// 3. Prepare Policies and Identities
	policies := actx.Policies
	if len(policies) == 0 {
		policies = DefaultPolicies()
	}

	identities := actx.Identities
	if len(identities) == 0 {
		identities = DefaultIdentities()
	}

	// 4. Initialize counters and results
	if actx.DispatchedRequests == nil {
		var initialReqs int32
		actx.DispatchedRequests = &initialReqs
	}

	clientCache := make(map[string]*http.Client)
	perIdentCounts := make(map[string]*int32)
	var results []Result
	var privilegeComparisons int

	// Check if we have at least two distinct identities
	hasDistinctIdentities := false
	if len(identities) >= 2 {
		for i := 0; i < len(identities); i++ {
			for j := i + 1; j < len(identities); j++ {
				if AreIdentitiesDistinct(identities[i], identities[j]) {
					hasDistinctIdentities = true
					break
				}
			}
			if hasDistinctIdentities {
				break
			}
		}
	}

	// 5. Execute assessment for each policy (with deduplication & bounded function budget)
	seenFuncs := make(map[string]bool)
	evaluatedFuncs := 0
	for _, pol := range policies {
		if ctx.Err() != nil {
			return nil, nil, ctx.Err()
		}

		funcKey := strings.ToUpper(strings.TrimSpace(pol.Method)) + " " + strings.TrimSpace(pol.Path)
		if funcKey != " " && seenFuncs[funcKey] {
			continue
		}
		seenFuncs[funcKey] = true

		fullURL := joinURL(actx.BaseURL, pol.Path)

		// Scope Exclusions
		if actx.IsExcluded != nil && actx.IsExcluded(fullURL) {
			res := makeSkippedResult(actx, pol, "Endpoint excluded by assessment scope rules")
			results = append(results, res)
			continue
		}

		// Destructive operation safety gate
		if (pol.SafetyClass == "DESTRUCTIVE" || (pol.DiscoverySource != "" && IsDestructiveFunction(pol.Method, pol.Path))) && !pol.AllowReversibleTest {
			res := makeSkippedResult(actx, pol, "Destructive function excluded by default safety policy")
			results = append(results, res)
			continue
		}

		// State changing & write mutation check
		if pol.IsStateChanging || pol.Category == CategoryBFLAWriteMutation {
			if !actx.AllowStateChangingTests {
				res := makeSkippedResult(actx, pol, "State-changing test blocked: requires explicit --allow-state-changing opt-in")
				results = append(results, res)
				continue
			}
			if !actx.SyntheticFixture {
				res := makeSkippedResult(actx, pol, "State-changing test blocked: write mutations are restricted to designated synthetic fixtures or isolated test environments (SyntheticFixture required)")
				results = append(results, res)
				continue
			}
			if !IsIsolatedFixtureTarget(fullURL, actx.AuthorizedFixtureHosts, actx.IsFixtureTarget) {
				res := makeSkippedResult(actx, pol, fmt.Sprintf("State-changing test blocked: target %q is not a verified isolated synthetic fixture", SanitizeURL(fullURL)))
				results = append(results, res)
				continue
			}
		}

		if actx.MaxFunctions > 0 && evaluatedFuncs >= actx.MaxFunctions {
			res := makeSkippedResult(actx, pol, fmt.Sprintf("Skipped due to max function evaluation cap (%d)", actx.MaxFunctions))
			results = append(results, res)
			continue
		}
		evaluatedFuncs++

		// Check for distinct identities
		if !hasDistinctIdentities {
			res := Result{
				ID:                uuid.New().String(),
				AssessmentID:      actx.AssessmentID,
				ExecutionID:       actx.ExecutionID,
				Category:          pol.Category,
				VulnCode:          string(pol.Category),
				TestID:            fmt.Sprintf("bfla-%s", pol.FunctionID),
				TestName:          pol.Name,
				OWASPRef:          CategoryMetadata[pol.Category].OWASP,
				CWERef:            CategoryMetadata[pol.Category].CWE,
				Endpoint:          pol.Path,
				Method:            pol.Method,
				VerificationState: StateInconclusive,
				Severity:          "INFO",
				Confidence:        "LOW",
				EvidenceSummary:   "Identities provided are missing, incomplete, or identical; cannot establish role boundaries",
				CreatedAt:         time.Now().UTC(),
			}
			results = append(results, res)
			continue
		}

		// Resolve allowed identity (positive control) and restricted identities (test targets)
		allowedIdent := findAllowedIdentity(identities, pol)
		var testedIdents []*TestIdentity
		if actx.TestAllIdentities || len(actx.IdentityClients) > 0 {
			testedIdents = findRestrictedIdentities(identities, pol, allowedIdent)
		} else if single := findRestrictedIdentity(identities, pol, allowedIdent); single != nil {
			testedIdents = []*TestIdentity{single}
		}

		if allowedIdent == nil || len(testedIdents) == 0 {
			res := Result{
				ID:                uuid.New().String(),
				AssessmentID:      actx.AssessmentID,
				ExecutionID:       actx.ExecutionID,
				Category:          pol.Category,
				VulnCode:          string(pol.Category),
				TestID:            fmt.Sprintf("bfla-%s", pol.FunctionID),
				TestName:          pol.Name,
				OWASPRef:          CategoryMetadata[pol.Category].OWASP,
				CWERef:            CategoryMetadata[pol.Category].CWE,
				Endpoint:          pol.Path,
				Method:            pol.Method,
				VerificationState: StateInconclusive,
				Severity:          "INFO",
				Confidence:        "LOW",
				EvidenceSummary:   fmt.Sprintf("Missing required identity pairing for policy %s; requires allowed and restricted roles", pol.FunctionID),
				CreatedAt:         time.Now().UTC(),
			}
			results = append(results, res)
			continue
		}

		// Step A: Positive Control Baseline (Allowed Role) executed once per policy with its isolated client
		var baselineResp ResponseData
		allowedClient := e.scopedClientFor(actx, allowedIdent, clientCache, perIdentCounts)
		if pol.PositiveControlRequired {
			baseData, err := e.executeRequest(ctx, allowedClient, pol.Method, fullURL, pol.Payload, allowedIdent)
			if err != nil {
				res := Result{
					ID:                uuid.New().String(),
					AssessmentID:      actx.AssessmentID,
					ExecutionID:       actx.ExecutionID,
					Category:          pol.Category,
					VulnCode:          string(pol.Category),
					TestID:            fmt.Sprintf("bfla-%s", pol.FunctionID),
					TestName:          pol.Name,
					OWASPRef:          CategoryMetadata[pol.Category].OWASP,
					CWERef:            CategoryMetadata[pol.Category].CWE,
					Endpoint:          pol.Path,
					Method:            pol.Method,
					RequiredRole:      allowedIdent.Role,
					AccessorRole:      testedIdents[0].Role,
					AccessorAlias:     testedIdents[0].Alias,
					VerificationState: StateInconclusive,
					Severity:          "INFO",
					Confidence:        "LOW",
					EvidenceSummary:   fmt.Sprintf("Positive control request failed: %v", err),
					CreatedAt:         time.Now().UTC(),
				}
				results = append(results, res)
				continue
			}
			baselineResp = baseData
		}

		for _, testedIdent := range testedIdents {
			if ctx.Err() != nil {
				return nil, nil, ctx.Err()
			}
			testedClient := e.scopedClientFor(actx, testedIdent, clientCache, perIdentCounts)

			// Special Handling for CategoryBFLAMethodBypass
			if pol.Category == CategoryBFLAMethodBypass {
				// Step B1: Test Primary Method (Restricted Role)
				primaryResp, err := e.executeRequest(ctx, testedClient, pol.Method, fullURL, pol.Payload, testedIdent)
				if err != nil {
					res := Result{
						ID:                uuid.New().String(),
						AssessmentID:      actx.AssessmentID,
						ExecutionID:       actx.ExecutionID,
						Category:          pol.Category,
						VulnCode:          string(pol.Category),
						TestID:            fmt.Sprintf("bfla-%s", pol.FunctionID),
						TestName:          pol.Name,
						OWASPRef:          CategoryMetadata[pol.Category].OWASP,
						CWERef:            CategoryMetadata[pol.Category].CWE,
						Endpoint:          pol.Path,
						Method:            pol.Method,
						RequiredRole:      allowedIdent.Role,
						AccessorRole:      testedIdent.Role,
						AccessorAlias:     testedIdent.Alias,
						VerificationState: StateInconclusive,
						Severity:          "INFO",
						Confidence:        "LOW",
						EvidenceSummary:   fmt.Sprintf("Primary method %s test request for role %s failed: %v", pol.Method, testedIdent.Role, err),
						CreatedAt:         time.Now().UTC(),
					}
					results = append(results, res)
					continue
				}

				// Check if primary method was denied
				isPrimaryDenied := primaryResp.StatusCode == http.StatusUnauthorized ||
					primaryResp.StatusCode == http.StatusForbidden ||
					primaryResp.StatusCode == http.StatusNotFound ||
					primaryResp.StatusCode == http.StatusMethodNotAllowed ||
					IsHTMLOrLoginPage(primaryResp) ||
					IsGenericErrorJSON(primaryResp.Body)

				if isPrimaryDenied {
					altMethods := pol.AlternateMethods
					if len(altMethods) == 0 {
						altMethods = defaultAlternateMethods(pol.Method)
					}

					var bestComp *ComparisonResult
					var bestAltMethod string
					var bestAltStatus int
					writeAttempted := false

					for _, altM := range altMethods {
						if ctx.Err() != nil {
							return nil, nil, ctx.Err()
						}
						// If alternate method is a write method:
						if isWriteMethod(altM) {
							if writeAttempted {
								continue
							}
							if IsDestructiveFunction(altM, pol.Path) && !pol.AllowReversibleTest && pol.DiscoverySource != "" {
								continue
							}
							if !actx.AllowStateChangingTests || !actx.SyntheticFixture || !IsIsolatedFixtureTarget(fullURL, actx.AuthorizedFixtureHosts, actx.IsFixtureTarget) {
								continue
							}
							writeAttempted = true
						}

						altResp, err := e.executeRequest(ctx, testedClient, altM, fullURL, pol.Payload, testedIdent)
						if err != nil {
							continue
						}

						privilegeComparisons++
						comp := downgradeIfRoleUnestablished(
							CompareMethodBypass(primaryResp, altResp, pol, allowedIdent.Role, testedIdent.Role, testedIdent.Alias, altM),
							pol,
						)
						if comp.State == StateVerified {
							bestComp = &comp
							bestAltMethod = altM
							bestAltStatus = altResp.StatusCode
							break
						}
						if comp.State == StateCandidate && (bestComp == nil || bestComp.State != StateCandidate) {
							bestComp = &comp
							bestAltMethod = altM
							bestAltStatus = altResp.StatusCode
						} else if bestComp == nil {
							bestComp = &comp
							bestAltMethod = altM
							bestAltStatus = altResp.StatusCode
						}
					}

					if bestComp != nil {
						res := Result{
							ID:                uuid.New().String(),
							AssessmentID:      actx.AssessmentID,
							ExecutionID:       actx.ExecutionID,
							Category:          pol.Category,
							VulnCode:          string(pol.Category),
							TestID:            fmt.Sprintf("bfla-%s", pol.FunctionID),
							TestName:          pol.Name,
							OWASPRef:          CategoryMetadata[pol.Category].OWASP,
							CWERef:            CategoryMetadata[pol.Category].CWE,
							Endpoint:          pol.Path,
							Method:            bestAltMethod,
							RequiredRole:      allowedIdent.Role,
							AccessorRole:      testedIdent.Role,
							AccessorAlias:     testedIdent.Alias,
							VerificationState: bestComp.State,
							Severity:          bestComp.Severity,
							Confidence:        bestComp.Confidence,
							ObservedStatus:    bestAltStatus,
							EvidenceSummary:   bestComp.EvidenceSummary,
							EvidenceDetails:   bestComp.EvidenceDetails,
							CreatedAt:         time.Now().UTC(),
						}
						if bestComp.State == StateVerified || bestComp.State == StateCandidate {
							res.Finding = buildFinding(res, pol, *bestComp, fullURL)
						}
						results = append(results, res)
						continue
					}
				}
			}

			// Step B: Lower-Privilege Test Request (Restricted Role)
			testResp, err := e.executeRequest(ctx, testedClient, pol.Method, fullURL, pol.Payload, testedIdent)
			if err != nil {
				res := Result{
					ID:                uuid.New().String(),
					AssessmentID:      actx.AssessmentID,
					ExecutionID:       actx.ExecutionID,
					Category:          pol.Category,
					VulnCode:          string(pol.Category),
					TestID:            fmt.Sprintf("bfla-%s", pol.FunctionID),
					TestName:          pol.Name,
					OWASPRef:          CategoryMetadata[pol.Category].OWASP,
					CWERef:            CategoryMetadata[pol.Category].CWE,
					Endpoint:          pol.Path,
					Method:            pol.Method,
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

			// Step C: Differential Authorization Comparison
			privilegeComparisons++
			comp := downgradeIfRoleUnestablished(
				CompareFunctionAccess(baselineResp, testResp, pol, allowedIdent.Role, testedIdent.Role, testedIdent.Alias),
				pol,
			)

			res := Result{
				ID:                uuid.New().String(),
				AssessmentID:      actx.AssessmentID,
				ExecutionID:       actx.ExecutionID,
				Category:          pol.Category,
				VulnCode:          string(pol.Category),
				TestID:            fmt.Sprintf("bfla-%s", pol.FunctionID),
				TestName:          pol.Name,
				OWASPRef:          CategoryMetadata[pol.Category].OWASP,
				CWERef:            CategoryMetadata[pol.Category].CWE,
				Endpoint:          pol.Path,
				Method:            pol.Method,
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

			// Attach Finding if VERIFIED or CANDIDATE
			if comp.State == StateVerified || comp.State == StateCandidate {
				res.Finding = buildFinding(res, pol, comp, fullURL)
			}

			results = append(results, res)
		}
	}

	summary := compileSummaryWithContext(results, policies, privilegeComparisons)
	return results, summary, nil
}

func (e *Engine) executeRequest(ctx context.Context, client *http.Client, method, targetURL, payload string, id *TestIdentity) (ResponseData, error) {
	var bodyReader io.Reader
	if payload != "" {
		bodyReader = strings.NewReader(payload)
	}

	req, err := http.NewRequestWithContext(ctx, method, targetURL, bodyReader)
	if err != nil {
		return ResponseData{}, err
	}

	req.Header.Set("User-Agent", e.config.UserAgent)
	if payload != "" {
		req.Header.Set("Content-Type", "application/json")
	}

	// Apply identity headers
	if id != nil && id.Headers != nil {
		for k, v := range id.Headers {
			req.Header.Set(k, v)
		}
	}

	// Apply identity cookies
	if id != nil && id.Cookies != nil {
		for k, v := range id.Cookies {
			req.AddCookie(&http.Cookie{Name: k, Value: v})
		}
	}

	resp, err := client.Do(req)
	if err != nil {
		return ResponseData{}, err
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(io.LimitReader(resp.Body, e.config.MaxBodyReadBytes))
	if err != nil {
		return ResponseData{}, err
	}

	return ResponseData{
		StatusCode: resp.StatusCode,
		Header:     resp.Header.Clone(),
		Body:       bodyBytes,
		URL:        resp.Request.URL.String(),
	}, nil
}

func isRestrictedRole(role string, pol FunctionPolicy) bool {
	for _, r := range pol.RestrictedRoles {
		if strings.EqualFold(r, role) {
			return true
		}
	}
	// If restricted roles not explicitly specified, any role not in allowed roles is restricted
	for _, a := range pol.AllowedRoles {
		if strings.EqualFold(a, role) {
			return false
		}
	}
	return true
}

func findAllowedIdentity(identities []TestIdentity, pol FunctionPolicy) *TestIdentity {
	for i := range identities {
		id := &identities[i]
		for _, allowed := range pol.AllowedRoles {
			if strings.EqualFold(id.Role, allowed) {
				return id
			}
		}
		if pol.RequiredPrivilegeLevel > 0 && id.PrivilegeLevel >= pol.RequiredPrivilegeLevel {
			return id
		}
	}
	return nil
}

func findRestrictedIdentity(identities []TestIdentity, pol FunctionPolicy, allowed *TestIdentity) *TestIdentity {
	for i := range identities {
		id := &identities[i]
		if allowed != nil && !AreIdentitiesDistinct(*id, *allowed) {
			continue
		}
		if isRestrictedRole(id.Role, pol) {
			return id
		}
		if pol.RequiredPrivilegeLevel > 0 && id.PrivilegeLevel < pol.RequiredPrivilegeLevel {
			return id
		}
	}
	return nil
}

func findRestrictedIdentities(identities []TestIdentity, pol FunctionPolicy, allowed *TestIdentity) []*TestIdentity {
	var out []*TestIdentity
	for i := range identities {
		id := &identities[i]
		if allowed != nil && !AreIdentitiesDistinct(*id, *allowed) {
			continue
		}
		if isRestrictedRole(id.Role, pol) || (pol.RequiredPrivilegeLevel > 0 && id.PrivilegeLevel < pol.RequiredPrivilegeLevel) {
			out = append(out, id)
		}
	}
	return out
}

func downgradeIfRoleUnestablished(comp ComparisonResult, pol FunctionPolicy) ComparisonResult {
	if !pol.RoleUnestablished || comp.State != StateVerified {
		return comp
	}
	if comp.EvidenceDetails == nil {
		comp.EvidenceDetails = make(map[string]string)
	}
	comp.EvidenceDetails["role_unestablished"] = "true"
	comp.State = StateCandidate
	comp.Severity = "MEDIUM"
	comp.Confidence = "POSSIBLE"
	comp.EvidenceSummary = strings.TrimSpace(comp.EvidenceSummary) + " (Note: required role was inferred without authoritative policy or visibility differential; downgraded from VERIFIED to CANDIDATE.)"
	return comp
}

func makeSkippedResult(actx *AssessmentContext, pol FunctionPolicy, reason string) Result {
	return Result{
		ID:                uuid.New().String(),
		AssessmentID:      actx.AssessmentID,
		ExecutionID:       actx.ExecutionID,
		Category:          pol.Category,
		VulnCode:          string(pol.Category),
		TestID:            fmt.Sprintf("bfla-%s", pol.FunctionID),
		TestName:          pol.Name,
		OWASPRef:          CategoryMetadata[pol.Category].OWASP,
		CWERef:            CategoryMetadata[pol.Category].CWE,
		Endpoint:          pol.Path,
		Method:            pol.Method,
		VerificationState: StateSkipped,
		Severity:          "INFO",
		Confidence:        "NONE",
		EvidenceSummary:   reason,
		CreatedAt:         time.Now().UTC(),
	}
}

func buildFinding(res Result, pol FunctionPolicy, comp ComparisonResult, targetURL string) *report.Finding {
	meta := CategoryMetadata[pol.Category]
	sanitizedTarget := SanitizeURL(targetURL)
	sanitizedEndpoint := SanitizeURL(pol.Path)
	if sanitizedEndpoint == "" {
		sanitizedEndpoint = sanitizedTarget
	}

	evidence := RedactText(comp.EvidenceSummary)
	proofDetails := RedactText(formatEvidenceDetails(comp.EvidenceDetails))

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
		"required_role":         res.RequiredRole,
		"accessor_role":         res.AccessorRole,
		"accessor_alias":        res.AccessorAlias,
		"verification_state":    string(res.VerificationState),
		"authz_engine_verified": "true",
	}
	if pol.DiscoverySource != "" {
		details["discovery_source"] = pol.DiscoverySource
	}
	if pol.DiscoveryConfidence != "" {
		details["discovery_confidence"] = pol.DiscoveryConfidence
	}
	if pol.RoleEvidence != "" {
		details["role_evidence"] = RedactText(pol.RoleEvidence)
	}
	if pol.RoleUnestablished {
		details["role_unestablished"] = "true"
	}

	rationale := RedactText(pol.RoleEvidence)
	if proofDetails != "" {
		if rationale != "" {
			rationale += "; "
		}
		rationale += proofDetails
	}

	return &report.Finding{
		ID:          uuid.New().String(),
		RuleID:      "VULN-BFLA-001",
		Status:      findingStatus,
		Title:       fmt.Sprintf("[%s] %s on %s %s", res.VulnCode, meta.Name, res.Method, res.Endpoint),
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
			DetectionMethod:  "BFLA_VERIFICATION_ENGINE",
			DetectionStatus:  detectionStatus,
			ExpectedBehavior: fmt.Sprintf("Only authorized role(s) (%s) should execute %s %s", res.RequiredRole, res.Method, sanitizedEndpoint),
			ObservedBehavior: fmt.Sprintf("Restricted identity %s (role: %s) received HTTP %d", res.AccessorAlias, res.AccessorRole, res.ObservedStatus),
			Details:          details,
		},
		Verification: report.VerificationRecord{
			Status:             verStatus,
			DetectionStatus:    detectionStatus,
			Result:             evidence,
			Rationale:          rationale,
			PolicyID:           pol.FunctionID,
			VerificationMethod: "DIFFERENTIAL_FUNCTION_AUTHORIZATION",
			AnalysisMethod:     "ACTIVE_VERIFICATION",
			ConfidenceScore:    confidenceScore,
			Attempted:          true,
		},
		Remediation: "Implement robust server-side role and function-level authorization checks. Verify that the principal has the required role/privilege level before invoking privileged handlers. Do not rely on UI-level hiding or client-side enforcement.",
	}
}

func formatEvidenceDetails(details map[string]string) string {
	if len(details) == 0 {
		return ""
	}
	var sb strings.Builder
	for k, v := range details {
		sb.WriteString(fmt.Sprintf("- %s: %s\n", k, v))
	}
	return sb.String()
}

func compileSummary(results []Result) *Summary {
	return compileSummaryWithContext(results, nil, 0)
}

func compileSummaryWithContext(results []Result, policies []FunctionPolicy, privilegeComparisons int) *Summary {
	summary := &Summary{
		TotalTests:           len(results),
		FunctionsDiscovered:  len(policies),
		PrivilegeComparisons: privilegeComparisons,
		CoverageMap:          make(map[string]CategoryCoverage),
	}

	for _, pol := range policies {
		if !pol.RoleUnestablished && len(pol.AllowedRoles) > 0 {
			summary.FunctionsWithEstablishedRole++
		}
	}

	allCats := []Category{
		CategoryBFLAAdminEndpoint,
		CategoryBFLAPrivilegeEscalation,
		CategoryBFLAMethodBypass,
		CategoryBFLAWriteMutation,
	}

	for _, cat := range allCats {
		meta := CategoryMetadata[cat]
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
			cov.Explanation = "One or more verified function-level authorization bypasses detected"
		case StateCandidate:
			summary.CandidateCount++
			cov.Candidates++
			if cov.Status != CoverageVerifiedIssueFound {
				cov.Status = CoverageCandidateIdentified
				cov.Explanation = "Candidate authorization anomaly identified requiring human review"
			}
		case StateNotVulnerable:
			summary.NotVulnerableCount++
			if cov.Status == CoverageUntested {
				cov.Status = CoverageActivelyTested
				cov.Explanation = "Authorization controls actively tested and verified enforced"
			}
		case StateInconclusive:
			summary.InconclusiveCount++
			cov.Inconclusive++
			if cov.Status == CoverageUntested {
				cov.Status = CoverageBlockedMissingPrereq
				cov.Explanation = "Testing inconclusive due to missing prerequisites or positive control failure"
			}
		case StateSkipped:
			summary.BlockedCount++
			summary.SkippedCount++
			cov.Blocked++
		}

		summary.CoverageMap[string(r.Category)] = cov
	}

	for _, cov := range summary.CoverageMap {
		if cov.TestsRun > 0 {
			summary.CategoriesCovered++
		}
	}

	return summary
}

func joinURL(base, path string) string {
	trimmedPath := strings.TrimSpace(path)
	if strings.HasPrefix(trimmedPath, "http://") || strings.HasPrefix(trimmedPath, "https://") {
		return trimmedPath
	}
	if baseU, err := url.Parse(strings.TrimSpace(base)); err == nil && baseU.Scheme != "" && baseU.Host != "" {
		if !strings.HasPrefix(trimmedPath, "/") {
			trimmedPath = "/" + trimmedPath
		}
		if relU, relErr := url.Parse(trimmedPath); relErr == nil {
			origin := url.URL{Scheme: baseU.Scheme, Host: baseU.Host}
			return origin.ResolveReference(relU).String()
		}
	}
	base = strings.TrimRight(base, "/")
	if !strings.HasPrefix(trimmedPath, "/") {
		trimmedPath = "/" + trimmedPath
	}
	return base + trimmedPath
}

// DefaultPolicies returns standard representative function policies for BFLA assessment.
func DefaultPolicies() []FunctionPolicy {
	return []FunctionPolicy{
		{
			FunctionID:              "admin-metrics",
			Name:                    "Administrative Metrics & System Stats",
			Path:                    "/api/admin/metrics",
			Method:                  "GET",
			Category:                CategoryBFLAAdminEndpoint,
			AllowedRoles:            []string{"admin", "superadmin"},
			RestrictedRoles:         []string{"user", "viewer", "guest"},
			RequiredPrivilegeLevel:  5,
			ProtectedResponseMarker: "metrics",
			PositiveControlRequired: true,
		},
		{
			FunctionID:              "admin-users",
			Name:                    "User Directory Administration",
			Path:                    "/api/admin/users",
			Method:                  "GET",
			Category:                CategoryBFLAAdminEndpoint,
			AllowedRoles:            []string{"admin", "superadmin"},
			RestrictedRoles:         []string{"user", "viewer", "guest"},
			RequiredPrivilegeLevel:  5,
			ProtectedResponseMarker: "users",
			PositiveControlRequired: true,
		},
		{
			FunctionID:              "system-config",
			Name:                    "Privileged Configuration Access",
			Path:                    "/api/admin/config",
			Method:                  "GET",
			Category:                CategoryBFLAPrivilegeEscalation,
			AllowedRoles:            []string{"admin"},
			RestrictedRoles:         []string{"operator", "user"},
			RequiredPrivilegeLevel:  5,
			ProtectedResponseMarker: "config",
			PositiveControlRequired: true,
		},
		{
			FunctionID:              "method-parity",
			Name:                    "Method-Level Authorization Parity",
			Path:                    "/api/admin/settings",
			Method:                  "POST",
			Category:                CategoryBFLAMethodBypass,
			AllowedRoles:            []string{"admin"},
			RestrictedRoles:         []string{"user"},
			RequiredPrivilegeLevel:  5,
			ProtectedResponseMarker: "settings",
			PositiveControlRequired: true,
		},
		{
			FunctionID:              "state-purge",
			Name:                    "Privileged System State Mutation",
			Path:                    "/api/admin/purge",
			Method:                  "POST",
			Category:                CategoryBFLAWriteMutation,
			AllowedRoles:            []string{"admin"},
			RestrictedRoles:         []string{"user"},
			RequiredPrivilegeLevel:  5,
			ProtectedResponseMarker: "purged",
			PositiveControlRequired: true,
			IsStateChanging:         true,
		},
	}
}

// DefaultIdentities returns representative distinct test identities for BFLA assessment.
func DefaultIdentities() []TestIdentity {
	return []TestIdentity{
		{
			Alias:          "admin_user",
			Role:           "admin",
			PrivilegeLevel: 5,
			Headers:        map[string]string{"Authorization": "Bearer token_admin_synthetic"},
		},
		{
			Alias:          "standard_user",
			Role:           "user",
			PrivilegeLevel: 1,
			Headers:        map[string]string{"Authorization": "Bearer token_user_synthetic"},
		},
	}
}

func defaultAlternateMethods(method string) []string {
	m := strings.ToUpper(strings.TrimSpace(method))
	switch m {
	case "POST":
		return []string{"GET", "PUT"}
	case "GET":
		return []string{"POST", "PUT"}
	case "PUT":
		return []string{"POST", "GET"}
	case "DELETE":
		return []string{"POST", "GET"}
	default:
		return []string{"GET", "POST"}
	}
}

func isWriteMethod(method string) bool {
	m := strings.ToUpper(strings.TrimSpace(method))
	return m == "POST" || m == "PUT" || m == "PATCH" || m == "DELETE"
}
