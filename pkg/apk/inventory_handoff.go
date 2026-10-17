package apk

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"felix/pkg/api"
	"felix/pkg/assessment"
	"felix/pkg/crawler"
	"felix/pkg/secrets"
)

// EndpointDisposition represents the final assessment outcome for an inventory endpoint.
type EndpointDisposition string

const (
	DispositionTested       EndpointDisposition = "tested"
	DispositionSkipped      EndpointDisposition = "skipped"
	DispositionFailed       EndpointDisposition = "failed"
	DispositionInconclusive EndpointDisposition = "inconclusive"
)

// HandoffState represents the lifecycle and gate state of an endpoint during authorized handoff.
type HandoffState string

const (
	StateDiscovered        HandoffState = "discovered"
	StateEligible          HandoffState = "eligible"
	StateAuthorizedInScope HandoffState = "authorized_in_scope"
	StateTested            HandoffState = "tested"
	StateSkipped           HandoffState = "skipped"
	StateFailed            HandoffState = "failed"
	StateInconclusive      HandoffState = "inconclusive"
)

// HandoffConfig configures the authorized backend handoff and assessment boundaries.
type HandoffConfig struct {
	AuthorizedTargets    []string
	ScopeMode            string // "same-origin", "subdomains", "explicit"
	ScopeRules           []assessment.ScopeRule
	Exclusions           []assessment.Exclusion
	Authorization        *assessment.AuthorizationRecord
	AllowInferredRoutes  bool
	AllowThirdParties    bool
	ExplicitAllowedHosts []string
	AllowLoopback        bool
	AllowPrivateIPs      bool
	MaxRequestsTotal     int
	MaxRequestsPerHost   int
	RateLimit            float64
	MaxConcurrency       int
	PerRequestTimeout    time.Duration
	OverallDeadline      time.Duration
	MaxResponseSize      int64
	MaxRedirects         int
	DryRun               bool
	UserAgent            string
	ProgressFunc         func(msg string)
}

// DefaultHandoffConfig provides conservative, safe default parameters for backend handoff.
func DefaultHandoffConfig() HandoffConfig {
	return HandoffConfig{
		ScopeMode:           "same-origin",
		AllowInferredRoutes: false,
		AllowThirdParties:   false,
		AllowLoopback:       false,
		AllowPrivateIPs:     false,
		MaxRequestsTotal:    50,
		MaxRequestsPerHost:  20,
		RateLimit:           10.0,
		MaxConcurrency:      2,
		PerRequestTimeout:   5 * time.Second,
		OverallDeadline:     30 * time.Second,
		MaxResponseSize:     512 * 1024, // 512 KiB
		MaxRedirects:        5,
		DryRun:              false,
		UserAgent:           api.DefaultUserAgent,
		ProgressFunc:        func(string) {},
	}
}

// HandoffEndpointResult records the deterministic evaluation and assessment outcome for an individual endpoint.
type HandoffEndpointResult struct {
	EndpointID        string                  `json:"endpoint_id"`
	NormalizedURL     string                  `json:"normalized_url"`
	HostGroup         string                  `json:"host_group"`
	Classification    ReferenceClassification `json:"classification"`
	IsInferred        bool                    `json:"is_inferred"`
	Category          EndpointCategory        `json:"category"`
	Confidence        string                  `json:"confidence"`
	Disposition       EndpointDisposition     `json:"disposition"` // tested, skipped, failed, inconclusive
	State             HandoffState            `json:"state"`
	ReasonCode        string                  `json:"reason_code"`
	ReasonMessage     string                  `json:"reason_message"`
	RequestDispatched bool                    `json:"request_dispatched"`
	RequestCount      int                     `json:"request_count"`
	DurationMs        int64                   `json:"duration_ms,omitempty"`
	HTTPStatus        int                     `json:"http_status,omitempty"`
	APIFindings       []api.APIFinding        `json:"api_findings,omitempty"`
	Provenance        []ProvenanceRecord      `json:"provenance,omitempty"`
	APKSHA256         string                  `json:"apk_sha256,omitempty"`
	StartedAt         *time.Time              `json:"started_at,omitempty"`
	CompletedAt       *time.Time              `json:"completed_at,omitempty"`
}

// HandoffReport captures the aggregate outcome, individual endpoint results, and audit metrics of the handoff run.
type HandoffReport struct {
	APKSHA256         string                  `json:"apk_sha256,omitempty"`
	APKFileName       string                  `json:"apk_filename,omitempty"`
	TotalDiscovered   int                     `json:"total_discovered"`
	TotalEligible     int                     `json:"total_eligible"`
	TotalAuthorized   int                     `json:"total_authorized"`
	TotalTested       int                     `json:"total_tested"`
	TotalSkipped      int                     `json:"total_skipped"`
	TotalFailed       int                     `json:"total_failed"`
	TotalInconclusive int                     `json:"total_inconclusive"`
	TotalRequestsSent int                     `json:"total_requests_sent"`
	BudgetExhausted   bool                    `json:"budget_exhausted"`
	DryRun            bool                    `json:"dry_run"`
	StartedAt         time.Time               `json:"started_at"`
	CompletedAt       time.Time               `json:"completed_at"`
	DurationMs        int64                   `json:"duration_ms"`
	ScopeMode         string                  `json:"scope_mode"`
	AuthorizedTargets []string                `json:"authorized_targets"`
	Results           []HandoffEndpointResult `json:"results"`
	Findings          []api.APIFinding        `json:"findings,omitempty"`
	Limitations       []string                `json:"limitations,omitempty"`
}

// RequestBudgetTracker manages per-host and global request budgets with thread-safe atomic accounting.
type RequestBudgetTracker struct {
	mu          sync.Mutex
	maxTotal    int
	maxPerHost  int
	totalUsed   int
	usedPerHost map[string]int
	exhausted   bool
}

// NewRequestBudgetTracker creates a new request budget tracker.
func NewRequestBudgetTracker(maxTotal, maxPerHost int) *RequestBudgetTracker {
	if maxTotal <= 0 {
		maxTotal = 50
	}
	if maxPerHost <= 0 {
		maxPerHost = 20
	}
	return &RequestBudgetTracker{
		maxTotal:    maxTotal,
		maxPerHost:  maxPerHost,
		usedPerHost: make(map[string]int),
	}
}

// Acquire requests budget for a single network request to host.
func (b *RequestBudgetTracker) Acquire(host string) (bool, string) {
	b.mu.Lock()
	defer b.mu.Unlock()

	cleanHost := strings.ToLower(host)
	if h, _, err := net.SplitHostPort(cleanHost); err == nil {
		cleanHost = h
	}

	if b.totalUsed >= b.maxTotal {
		b.exhausted = true
		return false, fmt.Sprintf("total request budget exhausted (%d/%d requests)", b.totalUsed, b.maxTotal)
	}

	if b.usedPerHost[cleanHost] >= b.maxPerHost {
		return false, fmt.Sprintf("per-host request budget exhausted for %s (%d/%d requests)", cleanHost, b.usedPerHost[cleanHost], b.maxPerHost)
	}

	b.totalUsed++
	b.usedPerHost[cleanHost]++
	return true, ""
}

// TotalUsed returns the cumulative count of acquired requests.
func (b *RequestBudgetTracker) TotalUsed() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.totalUsed
}

// IsExhausted returns whether the total request budget was exhausted.
func (b *RequestBudgetTracker) IsExhausted() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.exhausted
}

// EvaluateEndpointEligibility deterministically determines whether an inventory endpoint is eligible and authorized.
func EvaluateEndpointEligibility(
	ep EndpointEntry,
	cfg HandoffConfig,
	scopeVal *assessment.ScopeValidator,
) (eligible bool, code string, msg string) {
	raw := ep.NormalizedURL
	if strings.TrimSpace(raw) == "" || ep.HostIdentity == "(unresolved)" {
		return false, "UNRESOLVED_ROUTE", "endpoint has unresolved or ambiguous base URL; no active request permitted"
	}

	parsed, err := url.Parse(raw)
	if err != nil {
		return false, "INVALID_SYNTAX", fmt.Sprintf("malformed URL syntax: %v", err)
	}

	scheme := strings.ToLower(parsed.Scheme)
	if scheme != "http" && scheme != "https" {
		return false, "UNSUPPORTED_SCHEME", fmt.Sprintf("scheme %q is not supported for active HTTP assessment", parsed.Scheme)
	}

	host := strings.ToLower(parsed.Hostname())
	if host == "" {
		return false, "MISSING_HOST", "endpoint lacks an absolute hostname"
	}

	if parsed.User != nil {
		return false, "EMBEDDED_CREDENTIALS", "endpoint contains embedded user credentials"
	}

	// Prohibited destination IP literal check
	if ip := net.ParseIP(host); ip != nil {
		if prohibited, reason := crawler.ProhibitedIPReason(ip, cfg.AllowLoopback, cfg.AllowPrivateIPs); prohibited {
			return false, "PROHIBITED_IP", fmt.Sprintf("destination IP %s is prohibited: %s", ip, reason)
		}
	}

	// Inferred route policy
	if ep.Classification == ClassificationInferredRoute && !cfg.AllowInferredRoutes {
		return false, "INFERRED_ROUTE_DISABLED", "inferred routes are excluded from active testing by default policy"
	}

	// Exclusion check
	if scopeVal != nil {
		if excluded, reason := scopeVal.IsExcluded(raw); excluded {
			return false, "EXCLUDED", reason
		}
	}

	// Scope allowance check
	if scopeVal == nil || !scopeVal.IsAllowed(raw) {
		return false, "OUT_OF_SCOPE", "endpoint host/origin is outside explicitly authorized assessment scope"
	}

	// Unauthorized Third-Party check
	isThirdParty := ep.Category == CategoryFirebase ||
		ep.Category == CategoryStorage ||
		ep.Category == CategoryCloudService ||
		isTelemetryHost(host)

	if isThirdParty && !cfg.AllowThirdParties {
		// Verify if this specific host is explicitly listed in AuthorizedTargets or ExplicitAllowedHosts
		var explicitlyApproved bool
		for _, t := range cfg.AuthorizedTargets {
			if tp, err := url.Parse(t); err == nil && strings.ToLower(tp.Hostname()) == host {
				explicitlyApproved = true
				break
			}
		}
		for _, eh := range cfg.ExplicitAllowedHosts {
			if strings.EqualFold(strings.TrimSpace(eh), host) {
				explicitlyApproved = true
				break
			}
		}
		if !explicitlyApproved {
			return false, "UNAUTHORIZED_THIRD_PARTY", fmt.Sprintf("third-party cloud/telemetry host %q is excluded without explicit authorization", host)
		}
	}

	return true, "ELIGIBLE", "endpoint is authorized and in scope for active assessment"
}

// PlanHandoff performs static evaluation and dry-run planning of inventory endpoints without sending network traffic.
func PlanHandoff(inventory *BackendInventory, cfg HandoffConfig) (*HandoffReport, error) {
	cfg.DryRun = true
	return ExecuteHandoff(context.Background(), inventory, cfg)
}

// ExecuteHandoff coordinates the authorized handoff of discovered backend inventory to the API assessment engine.
func ExecuteHandoff(ctx context.Context, inventory *BackendInventory, cfg HandoffConfig) (*HandoffReport, error) {
	startTime := time.Now().UTC()
	if inventory == nil {
		return nil, errors.New("inventory is nil")
	}

	if cfg.ProgressFunc == nil {
		cfg.ProgressFunc = func(string) {}
	}

	// 1. Mandatory Authorization Validation
	if cfg.Authorization == nil {
		return nil, errors.New("security refusal: authorization record is required for active backend assessment")
	}
	if valid, reason := cfg.Authorization.IsCurrentlyValid(startTime); !valid {
		return nil, fmt.Errorf("security refusal: invalid authorization: %s", reason)
	}
	if len(cfg.AuthorizedTargets) == 0 {
		return nil, errors.New("security refusal: at least one authorized target URL must be configured")
	}

	// 2. Validate Approved Targets Syntax
	var validApprovedTargets []string
	for _, t := range cfg.AuthorizedTargets {
		norm, err := assessment.NormalizeTargetURL(t)
		if err != nil {
			return nil, fmt.Errorf("invalid approved target %q: %w", t, err)
		}
		validApprovedTargets = append(validApprovedTargets, norm)
	}

	// 3. Build Scope Validator
	scopeMode := cfg.ScopeMode
	if scopeMode == "" {
		scopeMode = "same-origin"
	}
	scopeVal := assessment.NewScopeValidator(scopeMode, validApprovedTargets, cfg.ScopeRules, cfg.Exclusions)

	// 4. Initialize Request Budget Tracker & Rate Limiter
	budget := NewRequestBudgetTracker(cfg.MaxRequestsTotal, cfg.MaxRequestsPerHost)

	// 5. Setup Overall Deadline Context
	overallCtx := ctx
	var overallCancel context.CancelFunc
	if cfg.OverallDeadline > 0 {
		overallCtx, overallCancel = context.WithTimeout(ctx, cfg.OverallDeadline)
		defer overallCancel()
	}

	// 6. Pre-evaluate eligibility for all endpoints
	totalDiscovered := len(inventory.Endpoints)
	results := make([]HandoffEndpointResult, totalDiscovered)
	var (
		eligibleCount   int
		eligibleIndices []int
	)

	for i, ep := range inventory.Endpoints {
		epID := fmt.Sprintf("ep-%d", i+1)
		isInferred := ep.Classification == ClassificationInferredRoute
		hostGroup := ep.HostIdentity
		if hostGroup == "" {
			hostGroup = "(unknown)"
		}

		res := HandoffEndpointResult{
			EndpointID:        epID,
			NormalizedURL:     secrets.RedactText(ep.NormalizedURL),
			HostGroup:         hostGroup,
			Classification:    ep.Classification,
			IsInferred:        isInferred,
			Category:          ep.Category,
			Confidence:        ep.Confidence,
			Provenance:        ep.Provenance,
			APKSHA256:         inventory.APKSHA256,
			RequestDispatched: false,
			RequestCount:      0,
		}

		eligible, code, msg := EvaluateEndpointEligibility(ep, cfg, scopeVal)
		res.ReasonCode = code
		res.ReasonMessage = msg

		if !eligible {
			res.Disposition = DispositionSkipped
			res.State = StateSkipped
			results[i] = res
			continue
		}

		// Marked eligible and authorized
		eligibleCount++
		res.State = StateAuthorizedInScope
		if cfg.DryRun {
			res.Disposition = DispositionSkipped
			res.ReasonCode = "DRY_RUN_PLAN"
			res.ReasonMessage = "Authorized and in scope; skipped during dry-run planning mode"
			results[i] = res
			continue
		}

		results[i] = res
		eligibleIndices = append(eligibleIndices, i)
	}

	var (
		allFindings []api.APIFinding
		findingsMu  sync.Mutex
	)

	// 7. Active Assessment Execution (if not dry run)
	if !cfg.DryRun && len(eligibleIndices) > 0 {
		// Construct Hardened HTTP Client with Central Scope Gate & Safe Transport
		perReqTimeout := cfg.PerRequestTimeout
		if perReqTimeout <= 0 {
			perReqTimeout = 5 * time.Second
		}
		maxRespSize := cfg.MaxResponseSize
		if maxRespSize <= 0 {
			maxRespSize = 512 * 1024
		}
		maxRedirects := cfg.MaxRedirects
		if maxRedirects <= 0 {
			maxRedirects = 5
		}

		safeTransport := crawler.NewSafeTransport(crawler.SafeTransportOptions{
			Timeout:         perReqTimeout,
			KeepAlive:       30 * time.Second,
			AllowLoopback:   cfg.AllowLoopback,
			AllowPrivateIPs: cfg.AllowPrivateIPs,
			TLSConfig: &tls.Config{
				MinVersion: tls.VersionTLS12,
			},
		})

		rateTransport := crawler.NewRateLimitedTransport(safeTransport, crawler.RateLimitOptions{
			Rate:           cfg.RateLimit,
			MaxConcurrency: cfg.MaxConcurrency,
		})

		httpClient := &http.Client{
			Transport: rateTransport,
			Timeout:   perReqTimeout,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if len(via) >= maxRedirects {
					return fmt.Errorf("stopped after %d redirects", maxRedirects)
				}
				scheme := strings.ToLower(req.URL.Scheme)
				if scheme != "http" && scheme != "https" {
					return fmt.Errorf("redirect to unsupported scheme %q blocked", req.URL.Scheme)
				}
				if req.URL.User != nil {
					return fmt.Errorf("redirect with embedded credentials blocked")
				}
				destHost := req.URL.Hostname()
				if ip := net.ParseIP(destHost); ip != nil {
					if prohibited, reason := crawler.ProhibitedIPReason(ip, cfg.AllowLoopback, cfg.AllowPrivateIPs); prohibited {
						return &crawler.SSRFError{Host: destHost, IP: ip, Reason: reason}
					}
				}

				redirectURL := req.URL.String()
				if excluded, reason := scopeVal.IsExcluded(redirectURL); excluded {
					return fmt.Errorf("redirect to %s blocked: matches exclusion (%s)", redirectURL, reason)
				}
				if !scopeVal.IsAllowed(redirectURL) {
					return fmt.Errorf("redirect to %s blocked: target is outside approved assessment scope", redirectURL)
				}

				lastURL := ""
				if len(via) > 0 {
					lastURL = via[len(via)-1].URL.String()
				}
				if err := scopeVal.ValidateRedirect(lastURL, redirectURL); err != nil {
					return fmt.Errorf("redirect blocked by origin boundary: %w", err)
				}

				// Consume redirect request from budget
				if allowed, rReason := budget.Acquire(destHost); !allowed {
					return fmt.Errorf("redirect blocked: %s", rReason)
				}

				return nil
			},
		}

		apiClient := api.NewClient(api.ClientOptions{
			Timeout:         perReqTimeout,
			MaxResponseSize: maxRespSize,
			UserAgent:       cfg.UserAgent,
			HTTPClient:      httpClient,
			AllowLoopback:   cfg.AllowLoopback,
			AllowPrivateIPs: cfg.AllowPrivateIPs,
			IsAllowed:       scopeVal.IsAllowed,
			IsExcluded:      func(u string) bool { excluded, _ := scopeVal.IsExcluded(u); return excluded },
		})

		concurrency := cfg.MaxConcurrency
		if concurrency <= 0 {
			concurrency = 2
		}
		sem := make(chan struct{}, concurrency)
		var wg sync.WaitGroup

		for _, idx := range eligibleIndices {
			// Check overall context cancellation or budget exhaustion before dispatch
			if overallCtx.Err() != nil {
				results[idx].Disposition = DispositionInconclusive
				results[idx].State = StateInconclusive
				results[idx].ReasonCode = "DEADLINE_EXCEEDED"
				results[idx].ReasonMessage = fmt.Sprintf("overall assessment deadline or cancellation reached: %v", overallCtx.Err())
				continue
			}

			ep := inventory.Endpoints[idx]
			destHost := ep.Host
			if destHost == "" {
				if parsed, err := url.Parse(ep.NormalizedURL); err == nil {
					destHost = parsed.Hostname()
				}
			}

			// Acquire budget for the primary request
			allowed, bReason := budget.Acquire(destHost)
			if !allowed {
				results[idx].Disposition = DispositionSkipped
				results[idx].State = StateSkipped
				results[idx].ReasonCode = "BUDGET_EXHAUSTED"
				results[idx].ReasonMessage = bReason
				continue
			}

			wg.Add(1)
			sem <- struct{}{}

			go func(i int, targetEP EndpointEntry) {
				defer func() {
					<-sem
					wg.Done()
				}()

				reqStart := time.Now().UTC()
				results[i].StartedAt = &reqStart
				results[i].RequestDispatched = true
				results[i].RequestCount = 1

				targetURL := targetEP.NormalizedURL

				// Create safe per-request context
				reqCtx, reqCancel := context.WithTimeout(overallCtx, perReqTimeout)
				defer reqCancel()

				req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, targetURL, nil)
				if err != nil {
					reqEnd := time.Now().UTC()
					results[i].CompletedAt = &reqEnd
					results[i].DurationMs = reqEnd.Sub(reqStart).Milliseconds()
					results[i].Disposition = DispositionFailed
					results[i].State = StateFailed
					results[i].ReasonCode = "REQUEST_CREATION_FAILED"
					results[i].ReasonMessage = fmt.Sprintf("failed to build HTTP request: %v", err)
					return
				}
				req.Header.Set("Accept", "*/*")

				resp, err := apiClient.Do(reqCtx, req)
				reqEnd := time.Now().UTC()
				results[i].CompletedAt = &reqEnd
				results[i].DurationMs = reqEnd.Sub(reqStart).Milliseconds()

				if err != nil {
					// Handle specific technical error conditions
					if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
						results[i].Disposition = DispositionInconclusive
						results[i].State = StateInconclusive
						results[i].ReasonCode = "INCONCLUSIVE_TIMEOUT"
						results[i].ReasonMessage = fmt.Sprintf("request timed out or was cancelled: %v", err)
						return
					}
					if err == api.ErrRateLimited {
						results[i].Disposition = DispositionInconclusive
						results[i].State = StateInconclusive
						results[i].ReasonCode = "INCONCLUSIVE_RATE_LIMITED"
						results[i].ReasonMessage = "target responded with HTTP 429 Too Many Requests"
						return
					}

					results[i].Disposition = DispositionFailed
					results[i].State = StateFailed
					results[i].ReasonCode = "NETWORK_ERROR"
					results[i].ReasonMessage = secrets.RedactText(err.Error())
					return
				}

				// Successful network dispatch
				results[i].Disposition = DispositionTested
				results[i].State = StateTested
				results[i].HTTPStatus = resp.StatusCode
				results[i].ReasonCode = "TESTED"
				results[i].ReasonMessage = fmt.Sprintf("dispatched authorized probe (HTTP %d, %d bytes)", resp.StatusCode, len(resp.Body))

				// Reasoning and findings evaluation
				var epFindings []api.APIFinding

				// Auth state reasoning
				authObs := api.ReasonAuthState(resp.StatusCode, resp.Header, resp.Body)
				if authObs.State != api.AuthStateNotFound && (!authObs.IsHTMLShell || targetEP.Category == CategoryAuthentication) {
					invFinding := api.APIFinding{
						Category:       api.CategoryEndpointDiscovered,
						Endpoint:       secrets.RedactText(targetURL),
						Method:         "GET",
						Description:    fmt.Sprintf("Audited %s endpoint: %s (%s)", targetEP.Classification, secrets.RedactText(targetURL), authObs.State),
						Evidence:       authObs.Reason,
						Severity:       api.SeverityInfo,
						Confidence:     api.ConfidenceHigh,
						Fingerprint:    api.GenerateFingerprint(api.CategoryEndpointDiscovered, targetURL, "GET"),
						Classification: api.ClassifyEndpoint(targetEP.Path),
						AuthState:      authObs.State,
					}
					epFindings = append(epFindings, invFinding)
				}

				// GraphQL Auditing if endpoint category is GraphQL or path contains "graphql"
				isGraphQL := targetEP.Category == CategoryGraphQL || strings.Contains(strings.ToLower(targetEP.Path), "graphql")
				if isGraphQL {
					baseURL := fmt.Sprintf("%s://%s", targetEP.Scheme, targetEP.Host)
					if targetEP.Port > 0 && targetEP.Port != DefaultPortForScheme(targetEP.Scheme) {
						baseURL = fmt.Sprintf("%s://%s:%d", targetEP.Scheme, targetEP.Host, targetEP.Port)
					}
					if allowed, _ := budget.Acquire(targetEP.Host); allowed {
						results[i].RequestCount++
						gqlFindings := api.AuditGraphQL(reqCtx, apiClient, baseURL, []string{targetEP.Path})
						for _, gf := range gqlFindings {
							gf.Endpoint = secrets.RedactText(gf.Endpoint)
							epFindings = append(epFindings, gf)
						}
					}
				}

				// Security Headers Auditing from existing response headers
				headerFindings := api.AuditResponseHeaders(targetURL, resp.StatusCode, resp.Header)
				for _, hf := range headerFindings {
					hf.Endpoint = secrets.RedactText(hf.Endpoint)
					epFindings = append(epFindings, hf)
				}

				if len(epFindings) > 0 {
					results[i].APIFindings = epFindings
					findingsMu.Lock()
					allFindings = append(allFindings, epFindings...)
					findingsMu.Unlock()
				}
			}(idx, ep)
		}

		wg.Wait()
	}

	endTime := time.Now().UTC()

	// 8. Tally metrics ensuring accounting invariant
	var (
		testedCount       int
		skippedCount      int
		failedCount       int
		inconclusiveCount int
		authorizedCount   int
	)

	for _, res := range results {
		if res.State == StateAuthorizedInScope || res.State == StateTested {
			authorizedCount++
		}
		switch res.Disposition {
		case DispositionTested:
			testedCount++
		case DispositionSkipped:
			skippedCount++
		case DispositionFailed:
			failedCount++
		case DispositionInconclusive:
			inconclusiveCount++
		}
	}

	limitations := []string{
		"Authorization was verified for designated targets; no unapproved endpoints were contacted.",
		"SSRF prevention was enforced at socket level; loopback, private, and link-local ranges were blocked.",
		"Redirects were bounded and re-checked against scope before dispatch.",
		"Static discovery alone did not grant testing permission.",
	}
	if budget.IsExhausted() {
		limitations = append(limitations, "Global request budget limit was reached; subsequent requests were stopped safely.")
	}

	report := &HandoffReport{
		APKSHA256:         inventory.APKSHA256,
		APKFileName:       inventory.APKFileName,
		TotalDiscovered:   totalDiscovered,
		TotalEligible:     eligibleCount,
		TotalAuthorized:   authorizedCount,
		TotalTested:       testedCount,
		TotalSkipped:      skippedCount,
		TotalFailed:       failedCount,
		TotalInconclusive: inconclusiveCount,
		TotalRequestsSent: budget.TotalUsed(),
		BudgetExhausted:   budget.IsExhausted(),
		DryRun:            cfg.DryRun,
		StartedAt:         startTime,
		CompletedAt:       endTime,
		DurationMs:        endTime.Sub(startTime).Milliseconds(),
		ScopeMode:         scopeMode,
		AuthorizedTargets: validApprovedTargets,
		Results:           results,
		Findings:          allFindings,
		Limitations:       limitations,
	}

	return report, nil
}
