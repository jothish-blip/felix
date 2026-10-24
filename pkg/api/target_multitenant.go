package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"felix/pkg/crawler"
)

// MultiTenantEngineOptions configures runtime safety and scope controls for cross-tenant authorization testing.
type MultiTenantEngineOptions struct {
	CLIOptIn        bool
	AllowLoopback   bool
	AllowPrivateIPs bool
	ScopeValidator  func(string) bool
	UserAgent       string
}

// MultiTenantEngine coordinates declarative cross-tenant BOLA/IDOR authorization assessments.
type MultiTenantEngine struct {
	profile *TargetProfile
	options MultiTenantEngineOptions
	client  *Client
}

// NewMultiTenantEngine initializes an engine bound to an authorized profile and safety options.
func NewMultiTenantEngine(profile *TargetProfile, opts MultiTenantEngineOptions) *MultiTenantEngine {
	timeout := 10 * time.Second
	if profile != nil && profile.Safety.TimeoutSeconds > 0 {
		timeout = time.Duration(profile.Safety.TimeoutSeconds) * time.Second
	}

	rateLimit := 5.0
	if profile != nil && profile.Safety.RequestsPerSecond > 0 {
		rateLimit = profile.Safety.RequestsPerSecond
	}

	ua := "Felix/0.1 (Multi-Tenant Authorization Verifier; Defensive)"
	if opts.UserAgent != "" {
		ua = opts.UserAgent
	}

	clientOpts := ClientOptions{
		Timeout:         timeout,
		MaxResponseSize: 512 * 1024,
		UserAgent:       ua,
		AllowLoopback:   opts.AllowLoopback,
		AllowPrivateIPs: opts.AllowPrivateIPs,
		RateLimit:       rateLimit,
		MaxConcurrency:  1, // sequential execution for deterministic cross-tenant testing
		IsAllowed:       opts.ScopeValidator,
	}

	engineClient := NewClient(clientOpts)

	// Enforce non-destructive redirect policy
	if profile != nil && !profile.Safety.FollowRedirects {
		// Stop immediately on redirects; never follow or forward credentials
		engineClient.httpClient.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		}
	} else if profile != nil && profile.Safety.FollowRedirects {
		// Even if profile allows redirects, strip authorization if host changes
		origCheckRedirect := engineClient.httpClient.CheckRedirect
		engineClient.httpClient.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			if len(via) > 0 && !strings.EqualFold(req.URL.Host, via[0].URL.Host) {
				req.Header.Del("Authorization")
			}
			if origCheckRedirect != nil {
				return origCheckRedirect(req, via)
			}
			return nil
		}
	}

	return &MultiTenantEngine{
		profile: profile,
		options: opts,
		client:  engineClient,
	}
}

// RunCrossTenantChecks executes all configured cross-tenant comparisons subject to dual opt-in.
func (me *MultiTenantEngine) RunCrossTenantChecks(ctx context.Context) *CrossTenantReport {
	report := &CrossTenantReport{
		SafetyPolicySummary: "non_destructive; read_only; dual_opt_in_required",
	}

	if me.profile == nil {
		report.Warnings = append(report.Warnings, "No target profile provided; multi-tenant testing aborted")
		return report
	}

	report.TotalComparisonsConfigured = len(me.profile.CrossTenantTests.Comparisons)

	// Gate 1: CLI explicit opt-in requirement
	if !me.options.CLIOptIn {
		report.TotalSkipped = len(me.profile.CrossTenantTests.Comparisons)
		report.Warnings = append(report.Warnings, "Cross-tenant authorization testing skipped: requires explicit CLI opt-in (--cross-tenant)")
		return report
	}

	// Gate 2: Profile policy enablement requirement
	if !me.profile.Safety.AllowCrossTenantChecks && !me.profile.CrossTenantTests.Enabled {
		report.TotalSkipped = len(me.profile.CrossTenantTests.Comparisons)
		report.Warnings = append(report.Warnings, "Cross-tenant authorization testing skipped: disabled in profile (safety.allow_cross_tenant_checks: false)")
		return report
	}

	// Build tenant lookup table
	tenantMap := make(map[string]TenantConfig)
	for _, t := range me.profile.Tenants {
		tenantMap[t.ID] = t
	}

	maxRequests := me.profile.Safety.MaxRequests
	if maxRequests <= 0 {
		maxRequests = 100
	}

	baseURL := ""
	if len(me.profile.Target.BaseURLs) > 0 {
		baseURL = me.profile.Target.BaseURLs[0]
	}

	for _, comp := range me.profile.CrossTenantTests.Comparisons {
		if ctx.Err() != nil {
			report.Warnings = append(report.Warnings, "Assessment canceled by context")
			break
		}

		if report.TotalExecuted >= maxRequests {
			report.Warnings = append(report.Warnings, fmt.Sprintf("Request budget exhausted (%d max requests)", maxRequests))
			report.TotalSkipped++
			continue
		}

		res := me.executeComparison(ctx, comp, tenantMap, baseURL)
		report.Results = append(report.Results, res)

		switch res.Classification {
		case CrossTenantAccessObserved:
			report.TotalExecuted++
			report.TotalCrossTenantAccessObserved++
		case CrossTenantAccessDeniedObserved:
			report.TotalExecuted++
			report.TotalAccessDeniedObserved++
		case CrossTenantNotFoundObserved:
			report.TotalExecuted++
			report.TotalNotFoundObserved++
		case CrossTenantInconclusive:
			report.TotalExecuted++
			report.TotalInconclusive++
		case CrossTenantMissingCredential, CrossTenantUnsafeRouteSkipped, CrossTenantScopeBlocked:
			report.TotalSkipped++
		case CrossTenantTransportFailure:
			report.TotalExecuted++
			report.TotalFailed++
		default:
			report.TotalExecuted++
		}
	}

	return report
}

// executeComparison evaluates a single comparison definition.
func (me *MultiTenantEngine) executeComparison(ctx context.Context, comp TenantComparison, tenantMap map[string]TenantConfig, baseURL string) CrossTenantResult {
	now := time.Now().UTC()
	compID := GenerateComparisonID(comp.RequesterTenant, comp.ResourceOwnerTenant, comp.ResourceID, comp.Path)

	result := CrossTenantResult{
		ComparisonID:        compID,
		RequesterTenant:     comp.RequesterTenant,
		ResourceOwnerTenant: comp.ResourceOwnerTenant,
		ResourceID:          comp.ResourceID,
		Method:              "GET",
		ExecutionTimestamp:  now,
		Classification:      CrossTenantInconclusive,
	}

	if comp.Method != "" {
		result.Method = strings.ToUpper(comp.Method)
	}

	// 1. Resolve requester & owner tenant configs
	requester, hasReq := tenantMap[comp.RequesterTenant]
	owner, hasOwner := tenantMap[comp.ResourceOwnerTenant]
	if !hasReq || !hasOwner {
		result.Classification = CrossTenantInconclusive
		result.Rationale = "Unknown tenant context in comparison definition"
		return result
	}

	// 2. Pre-flight Route & Scope Safety Checks (P14.4 safety policy)
	if prohibitedMutatingMethods[result.Method] {
		result.Classification = CrossTenantUnsafeRouteSkipped
		result.Rationale = fmt.Sprintf("Method %s is mutating; non-destructive policy forbids execution", result.Method)
		return result
	}

	// Resolve path and target URL
	resolvedPath := comp.Path
	if resolvedPath == "" {
		resolvedPath = "/api/v1/resources/" + comp.ResourceID
	} else {
		// Replace parameter placeholders safely with explicitly authorized test resource ID
		resolvedPath = strings.ReplaceAll(resolvedPath, "{id}", comp.ResourceID)
		resolvedPath = strings.ReplaceAll(resolvedPath, "{resource_id}", comp.ResourceID)
		resolvedPath = strings.ReplaceAll(resolvedPath, "{param}", comp.ResourceID)
	}
	result.Path = resolvedPath

	var targetURL string
	if strings.HasPrefix(resolvedPath, "http://") || strings.HasPrefix(resolvedPath, "https://") {
		targetURL = resolvedPath
	} else {
		if !strings.HasPrefix(resolvedPath, "/") {
			resolvedPath = "/" + resolvedPath
		}
		targetURL = strings.TrimRight(baseURL, "/") + resolvedPath
	}
	result.TargetURL = targetURL

	parsedURL, err := url.Parse(targetURL)
	if err != nil {
		result.Classification = CrossTenantScopeBlocked
		result.Rationale = fmt.Sprintf("Invalid target URL %q: %v", targetURL, err)
		return result
	}

	// Reject unsupported or unsafe schemes and empty hostnames
	if (parsedURL.Scheme != "http" && parsedURL.Scheme != "https") || parsedURL.Hostname() == "" {
		result.Classification = CrossTenantScopeBlocked
		result.Rationale = fmt.Sprintf("Unsupported or unsafe scheme/host %q; only http and https with valid hosts are permitted", targetURL)
		return result
	}

	// Reject embedded credentials in URL
	if parsedURL.User != nil {
		result.Classification = CrossTenantScopeBlocked
		result.Rationale = "Target URL contains embedded credentials; strictly prohibited"
		return result
	}

	// Validate port
	if port := parsedURL.Port(); port != "" {
		if pNum, err := strconv.Atoi(port); err != nil || pNum <= 0 || pNum > 65535 {
			result.Classification = CrossTenantScopeBlocked
			result.Rationale = fmt.Sprintf("Invalid target port %q", port)
			return result
		}
	}

	destHost := strings.ToLower(parsedURL.Hostname())
	isHostAllowed := false
	for _, h := range me.profile.Target.AllowedHosts {
		if destHost == strings.ToLower(h) || strings.HasSuffix(destHost, "."+strings.ToLower(h)) {
			isHostAllowed = true
			break
		}
	}
	if !isHostAllowed {
		result.Classification = CrossTenantScopeBlocked
		result.Rationale = fmt.Sprintf("Target host %q is not in profile allowed_hosts", destHost)
		return result
	}

	if me.options.ScopeValidator != nil && !me.options.ScopeValidator(targetURL) {
		result.Classification = CrossTenantScopeBlocked
		result.Rationale = fmt.Sprintf("Target URL %q rejected by assessment scope validator", targetURL)
		return result
	}

	// Mutating keyword inspection in path
	for _, seg := range strings.Split(strings.ToLower(resolvedPath), "/") {
		cleanSeg := strings.Trim(seg, ".-_?=&")
		if mutatingKeywords[cleanSeg] {
			result.Classification = CrossTenantUnsafeRouteSkipped
			result.Rationale = fmt.Sprintf("Path contains mutating keyword %q; skipped by safe-probe policy", cleanSeg)
			return result
		}
	}

	// Mutating keyword inspection in query parameters
	if parsedURL.RawQuery != "" {
		for _, qseg := range strings.FieldsFunc(strings.ToLower(parsedURL.RawQuery), func(r rune) bool {
			return r == '&' || r == '=' || r == ';'
		}) {
			cleanQ := strings.Trim(qseg, ".-_")
			if mutatingKeywords[cleanQ] {
				result.Classification = CrossTenantUnsafeRouteSkipped
				result.Rationale = fmt.Sprintf("Query contains mutating keyword %q; skipped by safe-probe policy", cleanQ)
				return result
			}
		}
	}

	// 3. Resolve credentials from environment securely (NEVER commit/persist raw secret)
	if requester.CredentialEnv == "" {
		result.Classification = CrossTenantMissingCredential
		result.Rationale = fmt.Sprintf("Missing credential: requester tenant %q has no credential_env declared; cross-tenant tests require explicit authentication", requester.ID)
		return result
	}
	token := os.Getenv(requester.CredentialEnv)
	if token == "" {
		result.Classification = CrossTenantMissingCredential
		result.Rationale = fmt.Sprintf("Missing credential: environment variable %s is not set for requester %q", requester.CredentialEnv, requester.ID)
		return result
	}

	// 5. Construct safe HTTP probe
	req, err := http.NewRequestWithContext(ctx, result.Method, targetURL, nil)
	if err != nil {
		result.Classification = CrossTenantTransportFailure
		result.Rationale = fmt.Sprintf("Failed to construct probe request: %v", err)
		return result
	}

	// Apply requester authentication headers (custom headers CANNOT override Authorization)
	req.Header.Set("Authorization", "Bearer "+token)
	for k, v := range requester.Headers {
		if strings.EqualFold(k, "authorization") {
			continue // custom headers cannot override or mix tenant authentication
		}
		req.Header.Set(k, v)
	}
	req.Header.Set("Accept", "application/json,application/problem+json,text/plain,*/*;q=0.8")
	req.Header.Set("X-Felix-Probe", "MultiTenantValidator/P14.4")

	// 6. Dispatch Bounded Request
	resp, probeErr := me.client.DoBounded(ctx, req, 512*1024)
	if probeErr != nil {
		me.handleTransportError(probeErr, &result)
		return result
	}

	result.StatusCode = resp.StatusCode

	// 7. Bounded & Sanitized Evidence
	if len(resp.Body) > 0 {
		evidenceLimit := 256
		if len(resp.Body) < evidenceLimit {
			evidenceLimit = len(resp.Body)
		}
		rawStr := string(resp.Body[:evidenceLimit])
		if token != "" {
			rawStr = strings.ReplaceAll(rawStr, token, "[REDACTED_CANARY_TOKEN]")
		}
		snippet := RedactEvidence(rawStr)
		result.EvidenceSnippet = snippet
	}

	// 8. Classify Response & Evidence Interpretation
	me.classifyCrossTenantResponse(resp, comp, requester, owner, &result)

	return result
}

// classifyCrossTenantResponse applies conservative evidence evaluation to determine BOLA status.
func (me *MultiTenantEngine) classifyCrossTenantResponse(resp *ProbeResponse, comp TenantComparison, requester, owner TenantConfig, result *CrossTenantResult) {
	status := resp.StatusCode

	// 0. Handle truncated responses
	if resp.Truncated {
		result.Classification = CrossTenantInconclusive
		result.IsBOLAObserved = false
		result.Rationale = "Response exceeded maximum size limit and was truncated; resource access inconclusive"
		result.Limitations = "Response truncated at size limit"
		return
	}

	// 1. Authentication failure
	if status == http.StatusUnauthorized {
		result.Classification = CrossTenantAuthenticationRequired
		result.Rationale = fmt.Sprintf("Server returned HTTP 401 Unauthorized for requester %q; token expired or rejected", requester.ID)
		return
	}

	// 2. Access Denied (Boundary enforcement observed)
	if status == http.StatusForbidden {
		result.Classification = CrossTenantAccessDeniedObserved
		result.IsBOLAObserved = false
		result.Confidence = "MEDIUM"
		result.Rationale = fmt.Sprintf("Server returned HTTP 403 Forbidden to requester %q; access denied (does not prove holistic multi-tenant isolation)", requester.ID)
		return
	}

	// 3. Not Found (Protected resource hidden or unmapped)
	if status == http.StatusNotFound {
		result.Classification = CrossTenantNotFoundObserved
		result.IsBOLAObserved = false
		result.Confidence = "LOW"
		result.Rationale = fmt.Sprintf("Server returned HTTP 404 Not Found; owner %q resource %q is inaccessible or route is unmapped (does not establish authorization enforcement)", owner.ID, comp.ResourceID)
		return
	}

	// 4. Rate Limited
	if status == http.StatusTooManyRequests {
		result.Classification = CrossTenantRateLimited
		result.Rationale = "Target rate limit exceeded (HTTP 429)"
		return
	}

	// 5. Redirect Responses (301, 302, 303, 307, 308)
	if status >= 300 && status < 400 {
		result.Classification = CrossTenantInconclusive
		result.IsBOLAObserved = false
		result.Rationale = fmt.Sprintf("Server returned HTTP %d redirect to %q; cross-tenant redirects are not automatically followed", status, resp.Header.Get("Location"))
		return
	}

	// 6. Upstream server error
	if status >= 500 && status < 600 {
		result.Classification = CrossTenantTransportFailure
		result.Rationale = fmt.Sprintf("Server returned HTTP %d server error to cross-tenant probe", status)
		return
	}

	// 7. HTTP 200–299: Must strictly corroborate resource-specific data before claiming BOLA
	if status >= 200 && status < 300 {
		// A. Detect SPA Catch-All fallback shells (False-Positive defense)
		if isSPAFallback(resp) {
			result.Classification = CrossTenantInconclusive
			result.IsBOLAObserved = false
			result.Rationale = "Server returned HTTP 200 with generic SPA HTML shell; inconclusive (not resource data)"
			result.Limitations = "Target web frontend routes unauthenticated or unauthorized paths to index.html"
			return
		}

		// B. Detect HTML login/challenge page
		bodyStr := string(resp.Body)
		lowerBody := strings.ToLower(bodyStr)
		if strings.Contains(resp.Header.Get("Content-Type"), "text/html") {
			if strings.Contains(lowerBody, "login") || strings.Contains(lowerBody, "sign in") || strings.Contains(lowerBody, "password") {
				result.Classification = CrossTenantInconclusive
				result.IsBOLAObserved = false
				result.Rationale = "Server returned HTTP 200 with HTML authentication page; access not observed"
				return
			}
		}

		// C. Safe Resource-Specific Evidence Predicate
		me.evaluateResourceEvidence(resp, comp, requester, owner, result)
		return
	}

	result.Classification = CrossTenantInconclusive
	result.Rationale = fmt.Sprintf("Server returned unexpected HTTP status %d", status)
}

// evaluateResourceEvidence applies safe, resource-specific evidence checks to determine BOLA status.
func (me *MultiTenantEngine) evaluateResourceEvidence(resp *ProbeResponse, comp TenantComparison, requester, owner TenantConfig, result *CrossTenantResult) {
	bodyStr := string(resp.Body)
	lowerBody := strings.ToLower(bodyStr)

	var js map[string]any
	isJSON := json.Unmarshal(resp.Body, &js) == nil

	// Check for application-level error / rejection payload disguised under 200 OK
	if isJSON && isErrorOrRejectionPayload(js) {
		result.Classification = CrossTenantInconclusive
		result.IsBOLAObserved = false
		result.Rationale = "Server returned HTTP 200 with application-level error/rejection payload; resource access not established"
		return
	}

	if !isJSON && strings.Contains(resp.Header.Get("Content-Type"), "text/html") {
		if strings.Contains(lowerBody, "access denied") || strings.Contains(lowerBody, "unauthorized") ||
			strings.Contains(lowerBody, "forbidden") || strings.Contains(lowerBody, "not found") {
			result.Classification = CrossTenantInconclusive
			result.IsBOLAObserved = false
			result.Rationale = "Server returned HTTP 200 with HTML error/denial page; access not observed"
			return
		}
	}

	// 1. Expected Marker Check
	if comp.ExpectedMarker != "" {
		if strings.Contains(bodyStr, comp.ExpectedMarker) {
			// Ensure marker is not merely reflected in an echo/error context
			if isJSON && isReflectedMarker(js, comp.ExpectedMarker) {
				result.Classification = CrossTenantInconclusive
				result.IsBOLAObserved = false
				result.Rationale = fmt.Sprintf("Expected marker %q was present only in reflection/echo field; inconclusive", comp.ExpectedMarker)
				return
			}
			result.Classification = CrossTenantAccessObserved
			result.IsBOLAObserved = true
			result.Confidence = "HIGH"
			result.Rationale = fmt.Sprintf("BOLA OBSERVED: Requester %q successfully accessed owner %q resource %q containing expected marker %q",
				requester.ID, owner.ID, comp.ResourceID, comp.ExpectedMarker)
			return
		}
		result.Classification = CrossTenantInconclusive
		result.IsBOLAObserved = false
		result.Rationale = fmt.Sprintf("Server returned HTTP %d but missing expected resource marker %q; inconclusive", resp.StatusCode, comp.ExpectedMarker)
		return
	}

	// 2. Structured JSON Object Inspection (when no marker is declared)
	if isJSON {
		// Detect reflected resource ID (ID only present in echo / query / path fields)
		if isEchoedResourceID(js, comp.ResourceID) {
			result.Classification = CrossTenantInconclusive
			result.IsBOLAObserved = false
			result.Rationale = fmt.Sprintf("Resource ID %q appeared only in query/echo/path reflection; access not established", comp.ResourceID)
			return
		}

		// Locate canonical resource identity
		hasCanonicalID, conf, matchDetails := findCanonicalResourceMatch(js, comp.ResourceID, owner)
		if hasCanonicalID {
			result.Classification = CrossTenantAccessObserved
			result.IsBOLAObserved = true
			result.Confidence = conf
			result.Rationale = fmt.Sprintf("BOLA OBSERVED: Requester %q successfully accessed owner %q resource %q (%s)",
				requester.ID, owner.ID, comp.ResourceID, matchDetails)
			return
		}

		result.Classification = CrossTenantInconclusive
		result.IsBOLAObserved = false
		result.Rationale = fmt.Sprintf("Server returned HTTP %d JSON object without verified canonical resource %q identity; inconclusive", resp.StatusCode, comp.ResourceID)
		return
	}

	result.Classification = CrossTenantInconclusive
	result.IsBOLAObserved = false
	result.Rationale = fmt.Sprintf("Server returned HTTP %d with non-structured content; inconclusive without expected_marker", resp.StatusCode)
}

func isErrorOrRejectionPayload(js map[string]any) bool {
	if errVal, exists := js["error"]; exists && errVal != nil && errVal != false && errVal != "" {
		return true
	}
	if errVal, exists := js["errors"]; exists && errVal != nil {
		return true
	}
	if errVal, exists := js["rejection"]; exists && errVal != nil {
		return true
	}
	if succ, exists := js["success"]; exists && succ == false {
		return true
	}
	if st, exists := js["status"]; exists {
		stStr := strings.ToLower(fmt.Sprintf("%v", st))
		if stStr == "error" || stStr == "fail" || stStr == "denied" || stStr == "forbidden" || stStr == "unauthorized" {
			return true
		}
	}
	if codeVal, exists := js["code"]; exists {
		if cFloat, ok := codeVal.(float64); ok && cFloat >= 400 {
			return true
		}
	}
	return false
}

func isReflectedMarker(js map[string]any, marker string) bool {
	echoKeys := []string{"echo", "query", "param", "params", "path", "url", "error", "message", "reason"}
	for _, k := range echoKeys {
		if v, exists := js[k]; exists {
			vStr := fmt.Sprintf("%v", v)
			if strings.Contains(vStr, marker) {
				return true
			}
		}
	}
	return false
}

func isEchoedResourceID(js map[string]any, resourceID string) bool {
	echoKeys := map[string]bool{
		"echo": true, "query": true, "param": true, "params": true,
		"path": true, "url": true, "requested_id": true, "requested_resource": true,
		"target": true, "input": true, "request": true,
	}

	foundInEcho := false
	foundOutsideEcho := false

	for k, v := range js {
		vStr := fmt.Sprintf("%v", v)
		if strings.Contains(vStr, resourceID) {
			if echoKeys[strings.ToLower(k)] {
				foundInEcho = true
			} else {
				foundOutsideEcho = true
			}
		}
	}

	return foundInEcho && !foundOutsideEcho
}

func findCanonicalResourceMatch(js map[string]any, resourceID string, owner TenantConfig) (bool, string, string) {
	canonicalKeys := map[string]bool{
		"id": true, "_id": true, "resource_id": true, "resourceid": true,
		"doc_id": true, "document_id": true, "uuid": true, "key": true,
	}

	targetObj := js
	// Unwrap data/item/resource envelope if present
	for _, envKey := range []string{"data", "item", "resource", "document", "result"} {
		if sub, ok := js[envKey].(map[string]any); ok {
			targetObj = sub
			break
		}
	}

	// Must have substantive payload attributes (at least 2 non-ID attributes)
	if len(targetObj) < 2 {
		return false, "", ""
	}

	matchFound := false
	for k, v := range targetObj {
		if canonicalKeys[strings.ToLower(k)] {
			valStr := strings.TrimSpace(fmt.Sprintf("%v", v))
			if valStr == resourceID {
				matchFound = true
				break
			}
		}
	}

	if !matchFound {
		return false, "", ""
	}

	// Check if owner identity is explicitly corroborated in payload
	for _, ownKey := range []string{"owner", "owner_id", "tenant", "tenant_id", "organization", "org_id"} {
		if v, exists := targetObj[ownKey]; exists {
			valStr := strings.ToLower(fmt.Sprintf("%v", v))
			if strings.Contains(valStr, strings.ToLower(owner.ID)) || (owner.Identity != "" && strings.Contains(valStr, strings.ToLower(owner.Identity))) {
				return true, "HIGH", "canonical resource ID and owner identity confirmed in payload"
			}
		}
	}

	return true, "MEDIUM", "canonical resource ID and substantive attributes confirmed in payload"
}

func (me *MultiTenantEngine) handleTransportError(err error, result *CrossTenantResult) {
	if errors.Is(err, ErrRateLimited) {
		result.StatusCode = http.StatusTooManyRequests
		result.Classification = CrossTenantRateLimited
		result.Rationale = "Target rate limit exceeded (HTTP 429)"
		return
	}

	var ssrfErr *crawler.SSRFError
	if errors.As(err, &ssrfErr) || strings.Contains(err.Error(), "blocked") {
		result.Classification = CrossTenantScopeBlocked
		result.Rationale = fmt.Sprintf("Request blocked by SSRF/Scope defense: %v", err)
		return
	}

	result.Classification = CrossTenantTransportFailure
	result.Rationale = fmt.Sprintf("Transport error: %v", err)
}
