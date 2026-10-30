package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"felix/pkg/crawler"
)

// ProberEngine coordinates live non-destructive validation of shadow API candidates.
type ProberEngine struct {
	client  *Client
	options ProberOptions
}

// NewProberEngine initializes a live exploitability prober with safety and rate-limit controls.
func NewProberEngine(opts ProberOptions) *ProberEngine {
	clientOpts := ClientOptions{
		Timeout:         opts.Timeout,
		MaxResponseSize: opts.MaxResponseSize,
		UserAgent:       opts.UserAgent,
		AllowLoopback:   opts.AllowLoopback,
		AllowPrivateIPs: opts.AllowPrivateIPs,
		RateLimit:       opts.RateLimit,
		MaxConcurrency:  opts.MaxConcurrency,
		IsAllowed:       opts.IsAllowed,
		IsExcluded:      opts.IsExcluded,
	}

	return &ProberEngine{
		client:  NewClient(clientOpts),
		options: opts,
	}
}

// ProbeCandidate evaluates a single candidate using scope-checked non-destructive probing.
func (pe *ProberEngine) ProbeCandidate(ctx context.Context, candidateID, candidatePath, candidateMethod, targetBaseURL string) ProbeResult {
	now := time.Now().UTC()

	result := ProbeResult{
		CandidateID:     candidateID,
		NormalizedRoute: candidatePath,
		CanonicalPath:   CanonicalizeRoutePath(candidatePath),
		OriginalMethod:  candidateMethod,
		ProbeTimestamp:  now,
		Reachability:    ProbeReachabilityInconclusive,
	}

	// 1. Evaluate Eligibility & Select Safe Method (P14.3-A, P14.3-B, P14.3-E)
	eligibility := EvaluateEligibility(candidatePath, candidateMethod, targetBaseURL, pe.options)
	result.IsEligible = eligibility.IsEligible
	result.TargetURL = eligibility.ResolvedURL
	result.ProbeMethod = eligibility.SelectedMethod

	if !eligibility.IsEligible {
		result.IneligibilityReason = eligibility.Reason
		if eligibility.IsScopeBlocked {
			result.Classification = ClassificationScopeBlocked
			result.Reachability = ReachabilityUnconfirmed
			result.Rationale = eligibility.Reason
		} else {
			result.Classification = ClassificationSafeProbeSkipped
			result.Reachability = ProbeReachabilityInconclusive
			result.Rationale = eligibility.Reason
			result.ManualVerificationRecommended = true
		}
		return result
	}

	// 2. Build Safe Request
	req, err := http.NewRequestWithContext(ctx, eligibility.SelectedMethod, eligibility.ResolvedURL, nil)
	if err != nil {
		result.Classification = ClassificationTransportFailure
		result.Reachability = ReachabilityUnconfirmed
		result.TransportErrorCategory = "REQUEST_CREATION_ERROR"
		result.TransportErrorDetails = err.Error()
		result.Rationale = fmt.Sprintf("Failed to construct probe request: %v", err)
		return result
	}

	if pe.options.CustomProbeHeader != "" {
		req.Header.Set("X-Felix-Probe", pe.options.CustomProbeHeader)
	}
	req.Header.Set("Accept", "application/json,application/problem+json,text/plain,*/*;q=0.8")

	// 3. Dispatch Bounded Request
	resp, probeErr := pe.client.DoBounded(ctx, req, pe.options.MaxResponseSize)
	if probeErr != nil {
		pe.classifyTransportError(ctx, probeErr, &result)
		return result
	}

	// 4. Capture Response Status and Headers
	result.StatusCode = resp.StatusCode
	result.SafeResponseHeaders = extractSafeHeaders(resp.Header)

	// Capture Redirect Information
	if resp.Redirected || (resp.StatusCode >= 300 && resp.StatusCode < 400) {
		redirURL := resp.RedirectURL
		if redirURL == "" {
			redirURL = resp.Header.Get("Location")
		}
		if redirURL != "" {
			parsedRedir, _ := url.Parse(redirURL)
			redirHost := ""
			inScope := false
			if parsedRedir != nil {
				redirHost = strings.ToLower(parsedRedir.Hostname())
				if pe.options.ScopeHost != "" {
					inScope = (redirHost == pe.options.ScopeHost || strings.HasSuffix(redirHost, "."+pe.options.ScopeHost))
				}
			}
			result.RedirectInfo = &ProbeRedirectInfo{
				InitialStatusCode: resp.InitialStatusCode,
				RedirectURL:       sanitizeEvidence(redirURL),
				RedirectHost:      redirHost,
				IsInScope:         inScope,
			}
		}
	}

	// Capture Bounded & Sanitized Response Evidence
	if len(resp.Body) > 0 {
		evidenceLimit := 256
		if len(resp.Body) < evidenceLimit {
			evidenceLimit = len(resp.Body)
		}
		rawSnippet := string(resp.Body[:evidenceLimit])
		result.ResponseEvidence = sanitizeEvidence(rawSnippet)
	}

	// 5. Evaluate Response Classification (P14.3-C, P14.3-D)
	pe.classifyResponse(resp, &result)

	return result
}

// ProbeBatch evaluates a list of reconciliation items or route candidates concurrently with bounded concurrency.
func (pe *ProberEngine) ProbeBatch(ctx context.Context, items []ReconciliationItem, targetBaseURL string) *ProberReport {
	report := &ProberReport{
		TotalCandidatesEvaluated: len(items),
	}

	if len(items) == 0 {
		return report
	}

	concurrency := pe.options.MaxConcurrency
	if concurrency <= 0 {
		concurrency = 5
	}

	sem := make(chan struct{}, concurrency)
	var wg sync.WaitGroup
	var mu sync.Mutex

	seenURL := make(map[string]bool)

	for _, item := range items {
		if ctx.Err() != nil {
			break
		}

		// Prevent duplicate probes to identical endpoints
		canonPath := item.CanonicalPath
		if canonPath == "" {
			canonPath = CanonicalizeRoutePath(item.Path)
		}
		dedupKey := fmt.Sprintf("%s|%s", strings.ToUpper(item.Method), canonPath)
		mu.Lock()
		if seenURL[dedupKey] {
			mu.Unlock()
			continue
		}
		seenURL[dedupKey] = true
		mu.Unlock()

		sem <- struct{}{}
		wg.Add(1)

		go func(it ReconciliationItem) {
			defer wg.Done()
			defer func() { <-sem }()

			res := pe.ProbeCandidate(ctx, it.CandidateID, it.Path, it.Method, targetBaseURL)

			mu.Lock()
			defer mu.Unlock()

			report.Results = append(report.Results, res)
			report.TotalProbesAttempted++

			switch res.Classification {
			case ClassificationReachable:
				report.TotalReachable++
			case ClassificationReachableWithMetadata:
				report.TotalReachableWithMetadata++
				report.TotalReachable++
			case ClassificationAuthenticationRequired:
				report.TotalAuthenticationRequired++
			case ClassificationAuthorizationBoundaryObserved:
				report.TotalAuthorizationDenied++
			case ClassificationNotFoundResponse:
				report.TotalNotFound++
			case ClassificationUpstreamFailure:
				report.TotalUpstreamFailures++
			case ClassificationRateLimited:
				report.TotalRateLimited++
			case ClassificationTransportFailure:
				report.TotalTransportFailures++
			case ClassificationScopeBlocked:
				report.TotalScopeBlocked++
			case ClassificationSafeProbeSkipped:
				report.TotalSafeProbeSkipped++
			case ClassificationInconclusive:
				report.TotalInconclusive++
			}

			if res.ManualVerificationRecommended {
				report.ManualVerificationCandidates++
			}
		}(item)
	}

	wg.Wait()
	return report
}

// classifyResponse evaluates observed HTTP status code, headers, and body metadata.
func (pe *ProberEngine) classifyResponse(resp *ProbeResponse, result *ProbeResult) {
	status := resp.StatusCode
	bodyStr := string(resp.Body)
	lowerBody := strings.ToLower(bodyStr)

	// Check for Allow / CORS header metadata
	allowHdr := resp.Header.Get("Allow")
	if allowHdr == "" {
		allowHdr = resp.Header.Get("Access-Control-Allow-Methods")
	}

	// 1. HTTP 200–299
	if status >= 200 && status < 300 {
		// Detect SPA Catch-All / HTML Index Fallback
		if isSPAFallback(resp) {
			result.Classification = ClassificationInconclusive
			result.Reachability = ProbeReachabilityInconclusive
			result.Rationale = "Observed HTTP 200 response with generic Single-Page Application (SPA) HTML index shell; live endpoint existence is inconclusive"
			result.ManualVerificationRecommended = true
			return
		}

		// Inspect for structured API metadata (JSON, Schema, Error)
		if metaType := detectStructuredMetadata(resp); metaType != "" {
			result.Classification = ClassificationReachableWithMetadata
			result.Reachability = ReachabilityConfirmed
			result.HasStructuredMetadata = true
			result.StructuredMetadataType = metaType
			result.Rationale = fmt.Sprintf("Observed reachable HTTP %d response with structured API metadata (%s)", status, metaType)
			return
		}

		if allowHdr != "" {
			result.Classification = ClassificationReachableWithMetadata
			result.Reachability = ReachabilityConfirmed
			result.HasStructuredMetadata = true
			result.StructuredMetadataType = "ALLOWED_METHODS_HEADER"
			result.Rationale = fmt.Sprintf("Observed reachable HTTP %d response advertising methods: %s", status, allowHdr)
			return
		}

		result.Classification = ClassificationReachable
		result.Reachability = ReachabilityConfirmed
		result.Rationale = fmt.Sprintf("Observed reachable HTTP %d response to safe non-destructive probe", status)
		return
	}

	// 2. HTTP 3xx Redirects
	if status >= 300 && status < 400 {
		result.Classification = ClassificationReachable
		result.Reachability = ReachabilityConfirmed
		redirDest := resp.Header.Get("Location")
		result.Rationale = fmt.Sprintf("Observed HTTP %d redirect to %q (redirect not automatically followed to prevent scope escape)", status, sanitizeEvidence(redirDest))
		return
	}

	// 3. HTTP 401 Unauthorized
	if status == http.StatusUnauthorized {
		result.Classification = ClassificationAuthenticationRequired
		result.Reachability = ReachabilityConfirmed
		result.Rationale = "Server returned HTTP 401 Unauthorized; endpoint is reachable and enforces an authentication requirement"
		return
	}

	// 4. HTTP 403 Forbidden
	if status == http.StatusForbidden {
		result.Classification = ClassificationAuthorizationBoundaryObserved
		result.Reachability = ReachabilityConfirmed
		result.Rationale = "Server returned HTTP 403 Forbidden; endpoint is reachable and enforces an access-control or authorization boundary"
		return
	}

	// 5. HTTP 404 Not Found
	if status == http.StatusNotFound {
		result.Classification = ClassificationNotFoundResponse
		result.Reachability = ReachabilityUnconfirmed
		result.Rationale = "Server returned HTTP 404 Not Found for probed route; endpoint may be unmapped, disabled, or requiring dynamic parameters"
		return
	}

	// 6. HTTP 429 Too Many Requests
	if status == http.StatusTooManyRequests {
		result.Classification = ClassificationRateLimited
		result.Reachability = ReachabilityConfirmed
		retryAfter := resp.Header.Get("Retry-After")
		result.Rationale = fmt.Sprintf("Server returned HTTP 429 Too Many Requests (Retry-After: %s)", retryAfter)
		return
	}

	// 7. HTTP 5xx Upstream / Server Error
	if status >= 500 && status < 600 {
		result.Classification = ClassificationUpstreamFailure
		result.Reachability = ReachabilityConfirmed
		if status == 502 {
			result.Rationale = "Server returned HTTP 502 Bad Gateway; upstream backend service could not be reached"
		} else {
			result.Rationale = fmt.Sprintf("Server returned HTTP %d server error to safe probe", status)
		}
		result.ManualVerificationRecommended = true
		return
	}

	// Other client errors (400, 405, 422)
	if status == http.StatusMethodNotAllowed || status == http.StatusBadRequest || status == http.StatusUnprocessableEntity {
		if allowHdr != "" {
			result.Classification = ClassificationReachableWithMetadata
			result.Reachability = ProbeReachabilityConfirmed
			result.HasStructuredMetadata = true
			result.StructuredMetadataType = "ALLOWED_METHODS_HEADER"
			result.Rationale = fmt.Sprintf("Server returned HTTP %d advertising supported methods (%s)", status, allowHdr)
			return
		}
		if metaType := detectStructuredMetadata(resp); metaType != "" {
			result.Classification = ClassificationReachableWithMetadata
			result.Reachability = ProbeReachabilityConfirmed
			result.HasStructuredMetadata = true
			result.StructuredMetadataType = metaType
			result.Rationale = fmt.Sprintf("Server returned HTTP %d with structured API error metadata (%s)", status, metaType)
			return
		}
		if strings.Contains(lowerBody, "json") || strings.Contains(resp.Header.Get("Content-Type"), "json") {
			result.Classification = ClassificationReachableWithMetadata
			result.Reachability = ProbeReachabilityConfirmed
			result.HasStructuredMetadata = true
			result.StructuredMetadataType = "JSON_ERROR_RESPONSE"
			result.Rationale = fmt.Sprintf("Server returned HTTP %d with structured API error response", status)
			return
		}
		result.Classification = ClassificationReachable
		result.Reachability = ProbeReachabilityConfirmed
		result.Rationale = fmt.Sprintf("Server responded with HTTP %d to safe probe", status)
		return
	}

	result.Classification = ClassificationInconclusive
	result.Reachability = ProbeReachabilityInconclusive
	result.Rationale = fmt.Sprintf("Server returned HTTP %d; behavior could not be definitively classified", status)
}

// classifyTransportError categorizes network and transport failures.
func (pe *ProberEngine) classifyTransportError(ctx context.Context, err error, result *ProbeResult) {
	result.Reachability = ReachabilityUnconfirmed

	if ctx.Err() != nil {
		result.Classification = ClassificationInconclusive
		result.TransportErrorCategory = "CONTEXT_CANCELED_OR_TIMEOUT"
		result.TransportErrorDetails = err.Error()
		result.Rationale = "Probe operation timed out or was canceled"
		return
	}

	if errors.Is(err, ErrRateLimited) {
		result.StatusCode = http.StatusTooManyRequests
		result.Classification = ClassificationRateLimited
		result.Reachability = ProbeReachabilityConfirmed
		result.TransportErrorCategory = "RATE_LIMITED"
		host := ""
		if parsed, _ := url.Parse(result.TargetURL); parsed != nil {
			host = parsed.Hostname()
		}
		retryAfter := pe.client.GetLastRetryAfter(host)
		if retryAfter != "" {
			result.Rationale = fmt.Sprintf("Server returned HTTP 429 Too Many Requests (Retry-After: %s)", retryAfter)
			if result.SafeResponseHeaders == nil {
				result.SafeResponseHeaders = make(map[string]string)
			}
			result.SafeResponseHeaders["Retry-After"] = retryAfter
		} else {
			result.Rationale = "Server returned HTTP 429 Too Many Requests"
		}
		return
	}

	var urlErr *url.Error
	if errors.As(err, &urlErr) && urlErr.URL != "" {
		if result.RedirectInfo == nil {
			parsedRedir, _ := url.Parse(urlErr.URL)
			redirHost := ""
			if parsedRedir != nil {
				redirHost = strings.ToLower(parsedRedir.Hostname())
			}
			result.RedirectInfo = &ProbeRedirectInfo{
				RedirectURL:  sanitizeEvidence(urlErr.URL),
				RedirectHost: redirHost,
				IsInScope:    false,
			}
		}
	}

	var ssrfErr *crawler.SSRFError
	if errors.As(err, &ssrfErr) || strings.Contains(err.Error(), "blocked") {
		result.Classification = ClassificationScopeBlocked
		result.TransportErrorCategory = "SCOPE_OR_SSRF_BLOCKED"
		result.TransportErrorDetails = err.Error()
		result.Rationale = fmt.Sprintf("Request blocked by SSRF or scope boundary: %v", err)
		return
	}

	var netErr net.Error
	if errors.Is(err, context.DeadlineExceeded) || (errors.As(err, &netErr) && netErr.Timeout()) {
		result.Classification = ClassificationTransportFailure
		result.TransportErrorCategory = "TIMEOUT"
		result.TransportErrorDetails = err.Error()
		result.Rationale = fmt.Sprintf("Network connection timed out: %v", err)
		result.ManualVerificationRecommended = true
		return
	}

	errStr := err.Error()
	switch {
	case strings.Contains(errStr, "certificate") || strings.Contains(errStr, "tls") || strings.Contains(errStr, "handshake"):
		result.Classification = ClassificationTransportFailure
		result.TransportErrorCategory = "TLS_FAILURE"
		result.Rationale = fmt.Sprintf("TLS handshake failed: %v", err)
	case strings.Contains(errStr, "connection refused"):
		result.Classification = ClassificationTransportFailure
		result.TransportErrorCategory = "CONNECTION_REFUSED"
		result.Rationale = fmt.Sprintf("Connection refused: %v", err)
	case strings.Contains(errStr, "no such host"):
		result.Classification = ClassificationTransportFailure
		result.TransportErrorCategory = "DNS_FAILURE"
		result.Rationale = fmt.Sprintf("DNS resolution failed: %v", err)
	default:
		result.Classification = ClassificationTransportFailure
		result.TransportErrorCategory = "NETWORK_FAILURE"
		result.Rationale = fmt.Sprintf("Transport failure: %v", err)
	}

	result.TransportErrorDetails = err.Error()
	result.ManualVerificationRecommended = true
}

func isSPAFallback(resp *ProbeResponse) bool {
	ct := strings.ToLower(resp.Header.Get("Content-Type"))
	if !strings.Contains(ct, "text/html") {
		return false
	}

	lower := strings.ToLower(string(resp.Body))
	if strings.Contains(lower, "<!doctype html") || strings.Contains(lower, "<html") {
		if strings.Contains(lower, `<div id="root"`) ||
			strings.Contains(lower, `<div id="app"`) ||
			strings.Contains(lower, `<div id="__next"`) ||
			strings.Contains(lower, `window.__next_data__`) {
			return true
		}
	}
	return false
}

func detectStructuredMetadata(resp *ProbeResponse) string {
	ct := strings.ToLower(resp.Header.Get("Content-Type"))
	body := strings.TrimSpace(string(resp.Body))

	if strings.Contains(ct, "application/json") || strings.Contains(ct, "application/problem+json") {
		var js map[string]any
		if err := json.Unmarshal([]byte(body), &js); err == nil {
			if _, hasOpenAPI := js["openapi"]; hasOpenAPI {
				return "OPENAPI_SCHEMA"
			}
			if _, hasSwagger := js["swagger"]; hasSwagger {
				return "SWAGGER_SCHEMA"
			}
			if _, hasSchema := js["$schema"]; hasSchema {
				return "JSON_SCHEMA"
			}
			if _, hasErr := js["error"]; hasErr {
				return "STRUCTURED_JSON_ERROR"
			}
			if _, hasMsg := js["message"]; hasMsg {
				return "STRUCTURED_JSON_MESSAGE"
			}
			if _, hasDetail := js["detail"]; hasDetail {
				return "FASTAPI_STRUCTURED_DETAIL"
			}
			return "JSON_OBJECT_METADATA"
		}
	}
	return ""
}

func extractSafeHeaders(h http.Header) map[string]string {
	safe := make(map[string]string)
	safeKeys := []string{
		"Allow",
		"Access-Control-Allow-Methods",
		"Access-Control-Allow-Origin",
		"Content-Type",
		"Server",
		"Retry-After",
		"X-Powered-By",
	}

	for _, k := range safeKeys {
		if val := h.Get(k); val != "" {
			safe[k] = val
		}
	}
	return safe
}

func sanitizeEvidence(s string) string {
	// Redact sensitive query parameters and auth tokens
	return rxSecretValues.ReplaceAllString(s, "$1=[REDACTED]")
}
