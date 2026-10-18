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
	base        http.RoundTripper
	maxRequests int
	reqCount    *int32
}

func (c *credentialGuardedTransport) RoundTrip(req *http.Request) (*http.Response, error) {
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
	baseTransport := e.client.Transport
	if baseTransport == nil {
		baseTransport = http.DefaultTransport
	}

	guard := &credentialGuardedTransport{
		base:        baseTransport,
		maxRequests: actx.MaxRequests,
		reqCount:    actx.DispatchedRequests,
	}

	return &http.Client{
		Transport: guard,
		Timeout:   e.config.Timeout,
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
		} else if pol.IsStateChanging && !actx.AllowStateChangingTests {
			pt.Status = PlanSkipped
			pt.BlockedReason = "State-changing function tests require explicit --allow-state-changing opt-in"
			plan.StateChangingTests++
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

	client := e.scopedClient(actx)
	var results []Result

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

	// 5. Execute assessment for each policy
	for _, pol := range policies {
		if ctx.Err() != nil {
			return nil, nil, ctx.Err()
		}

		fullURL := joinURL(actx.BaseURL, pol.Path)

		// Scope Exclusions
		if actx.IsExcluded != nil && actx.IsExcluded(fullURL) {
			res := makeSkippedResult(actx, pol, "Endpoint excluded by assessment scope rules")
			results = append(results, res)
			continue
		}

		// State changing opt-in check
		if pol.IsStateChanging && !actx.AllowStateChangingTests {
			res := makeSkippedResult(actx, pol, "State-changing test skipped: requires explicit --allow-state-changing")
			results = append(results, res)
			continue
		}

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

		// Resolve allowed identity (positive control) and restricted identity (test target)
		allowedIdent := findAllowedIdentity(identities, pol)
		testedIdent := findRestrictedIdentity(identities, pol, allowedIdent)

		if allowedIdent == nil || testedIdent == nil {
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

		// Step A: Positive Control Baseline (Allowed Role)
		var baselineResp ResponseData
		if pol.PositiveControlRequired {
			baseData, err := e.executeRequest(ctx, client, pol.Method, fullURL, pol.Payload, allowedIdent)
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
					EvidenceSummary:   fmt.Sprintf("Positive control request failed: %v", err),
					CreatedAt:         time.Now().UTC(),
				}
				results = append(results, res)
				continue
			}
			baselineResp = baseData
		}

		// Step B: Lower-Privilege Test Request (Restricted Role)
		testResp, err := e.executeRequest(ctx, client, pol.Method, fullURL, pol.Payload, testedIdent)
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
		comp := CompareFunctionAccess(baselineResp, testResp, pol, allowedIdent.Role, testedIdent.Role, testedIdent.Alias)

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

	summary := compileSummary(results)
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
	return &report.Finding{
		ID:          uuid.New().String(),
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
			Observation:     evidence,
			Location:        sanitizedEndpoint,
			HTTPMethod:      res.Method,
			HTTPStatus:      res.ObservedStatus,
			DetectionMethod: "BFLA_VERIFICATION_ENGINE",
			Details: map[string]string{
				"category":       string(res.Category),
				"vuln_code":      res.VulnCode,
				"required_role":  res.RequiredRole,
				"accessor_role":  res.AccessorRole,
				"accessor_alias": res.AccessorAlias,
			},
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
	summary := &Summary{
		TotalTests:  len(results),
		CoverageMap: make(map[string]CategoryCoverage),
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
	base = strings.TrimRight(base, "/")
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	return base + path
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
