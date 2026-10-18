package bola

import (
	"bytes"
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

// Engine evaluates Broken Object Level Authorization (BOLA/IDOR) across multi-user boundaries.
type Engine struct {
	client *http.Client
	config Config
}

// NewEngine creates a new BOLA Verification Engine.
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

// scopedClient creates an HTTP client that validates every redirect destination
// against the assessment's approved scope and exclusions before the redirected request is sent,
// and enforces cross-origin and cleartext credential withholding.
func (e *Engine) scopedClient(actx *AssessmentContext) *http.Client {
	transport := e.client.Transport
	if transport == nil {
		transport = crawler.NewSafeTransport(crawler.SafeTransportOptions{
			Timeout:       e.config.Timeout,
			KeepAlive:     30 * time.Second,
			AllowLoopback: true,
		})
	}
	if _, ok := transport.(*crawler.RateLimitedTransport); !ok {
		transport = crawler.NewRateLimitedTransport(transport, crawler.RateLimitOptions{})
	}

	reqCounter := actx.DispatchedRequests
	if reqCounter == nil {
		var localCounter int32
		reqCounter = &localCounter
	}
	guardedTransport := &credentialGuardedTransport{
		base:        transport,
		maxRequests: actx.MaxRequests,
		reqCount:    reqCounter,
	}

	return &http.Client{
		Transport: guardedTransport,
		Timeout:   e.config.Timeout,
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

			// Origin boundary and chained redirect defense:
			if len(via) > 0 {
				initialURL := via[0].URL
				prevURL := via[len(via)-1].URL

				crossPrev := !IsSameOrigin(prevURL, req.URL)
				crossInitial := !IsSameOrigin(initialURL, req.URL)
				chainedUntrusted := false
				for _, v := range via {
					if !IsSameOrigin(v.URL, initialURL) {
						chainedUntrusted = true
						break
					}
				}
				isRemoteCleartext := strings.EqualFold(req.URL.Scheme, "http") && !IsLoopbackHost(req.URL.Hostname())

				if crossPrev || crossInitial || chainedUntrusted || isRemoteCleartext {
					StripSensitiveCredentials(req)
				}
			}
			return nil
		},
	}
}

// Plan produces a pre-assessment test plan evaluating prerequisites without dispatching network requests.
func (e *Engine) Plan(ctx context.Context, actx *AssessmentContext) (*TestPlan, error) {
	plan := &TestPlan{
		AssessmentID: actx.AssessmentID,
		TargetURL:    actx.BaseURL,
		GeneratedAt:  time.Now().UTC(),
		Tests:        make([]PlannedTest, 0),
	}

	distinctIdentities := len(actx.Identities) >= 2 && AreIdentitiesDistinct(actx.Identities[0], actx.Identities[1])
	var identA TestIdentity
	if len(actx.Identities) >= 1 {
		identA = actx.Identities[0]
	}

	testIdx := 1
	for _, ep := range actx.Endpoints {
		isMutation := ep.IsStateChanging || isStateChangingMethod(ep.Method)
		for _, obj := range actx.Objects {
			cat := CategoryBOLAUserRead
			if obj.TenantID != "" {
				cat = CategoryBOLATenantRead
			}
			if ep.IsCollection {
				cat = CategoryBOLACollection
			}
			if isMutation {
				cat = CategoryBOLAWriteMutation
			}

			meta := CategoryMetadata[cat]
			t := PlannedTest{
				ID:                fmt.Sprintf("BOLA-TEST-%03d", testIdx),
				Category:          cat,
				Name:              fmt.Sprintf("%s on %s", meta.Name, ep.PathPattern),
				OWASPRef:          meta.OWASP,
				CWERef:            meta.CWE,
				Endpoint:          ep.PathPattern,
				Method:            ep.Method,
				ObjectID:          obj.ID,
				OwnerAlias:        obj.OwnerIdentity,
				AccessorAlias:     identA.Alias,
				IsStateChanging:   isMutation,
				SecurityObjective: meta.Description,
				Preconditions:     meta.Preconditions,
				Status:            PlanReady,
			}

			// Validate plan prerequisites
			if len(actx.Identities) < 2 {
				t.Status = PlanBlocked
				t.BlockedReason = "requires at least two distinct test identities"
			} else if !distinctIdentities {
				t.Status = PlanBlocked
				t.BlockedReason = "configured test identities are identical; dual-identity test blocked"
			} else if obj.OwnerIdentity == "" {
				t.Status = PlanBlocked
				t.BlockedReason = "missing object owner identity mapping"
			} else if isMutation && !actx.AllowStateChangingTests {
				t.Status = PlanBlocked
				t.BlockedReason = "state-changing mutations require --allow-state-changing opt-in"
			}

			if t.Status == PlanReady {
				plan.ReadyTests++
			} else {
				plan.BlockedTests++
			}
			if isMutation {
				plan.StateChangingTests++
			} else {
				plan.ActiveTests++
			}

			plan.Tests = append(plan.Tests, t)
			testIdx++
		}
	}

	plan.TotalTests = len(plan.Tests)
	return plan, nil
}

// Assess executes authorization-aware BOLA verification against approved targets.
func (e *Engine) Assess(ctx context.Context, actx *AssessmentContext) ([]Result, *Summary, error) {
	// 1. Authorization Gate: Fail closed if missing, expired, or not approved
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

	// 4. Identity Prerequisite Gate
	var results []Result
	now := time.Now().UTC()

	if len(actx.Identities) < 2 {
		r := Result{
			ID:                uuid.New().String(),
			AssessmentID:      actx.AssessmentID,
			ExecutionID:       actx.ExecutionID,
			Category:          CategoryBOLAUserRead,
			VulnCode:          "BOLA-MISSING-IDENTITY",
			TestID:            "BOLA-PREREQ-01",
			TestName:          "Dual-Identity Prerequisite Validation",
			OWASPRef:          "API1:2023",
			CWERef:            "CWE-639",
			VerificationState: StateInconclusive,
			Severity:          "INFO",
			Confidence:        "LOW",
			EvidenceSummary:   "BOLA verification requires at least two distinct test identities; prerequisites not met",
			CreatedAt:         now,
		}
		results = append(results, r)
		return results, e.compileSummary(results), nil
	}

	if !AreIdentitiesDistinct(actx.Identities[0], actx.Identities[1]) {
		r := Result{
			ID:                uuid.New().String(),
			AssessmentID:      actx.AssessmentID,
			ExecutionID:       actx.ExecutionID,
			Category:          CategoryBOLAUserRead,
			VulnCode:          "BOLA-IDENTICAL-IDENTITIES",
			TestID:            "BOLA-PREREQ-02",
			TestName:          "Distinct Identity Separation Validation",
			OWASPRef:          "API1:2023",
			CWERef:            "CWE-639",
			VerificationState: StateInconclusive,
			Severity:          "INFO",
			Confidence:        "LOW",
			EvidenceSummary:   "Configured test identities are identical; cross-principal testing cannot be performed without distinct sessions",
			CreatedAt:         now,
		}
		results = append(results, r)
		return results, e.compileSummary(results), nil
	}

	// 5. Object Reference Prerequisite Gate
	if len(actx.Objects) == 0 {
		r := Result{
			ID:                uuid.New().String(),
			AssessmentID:      actx.AssessmentID,
			ExecutionID:       actx.ExecutionID,
			Category:          CategoryBOLAUserRead,
			VulnCode:          "BOLA-MISSING-OBJECTS",
			TestID:            "BOLA-PREREQ-03",
			TestName:          "Object Reference Inventory Validation",
			OWASPRef:          "API1:2023",
			CWERef:            "CWE-639",
			VerificationState: StateInconclusive,
			Severity:          "INFO",
			Confidence:        "LOW",
			EvidenceSummary:   "No object identifiers or ownership mappings configured; cannot test BOLA without object references",
			CreatedAt:         now,
		}
		results = append(results, r)
		return results, e.compileSummary(results), nil
	}

	client := e.scopedClient(actx)

	// Map identities by alias
	identMap := make(map[string]TestIdentity)
	for _, id := range actx.Identities {
		identMap[id.Alias] = id
	}

	testIdx := 1
	for _, ep := range actx.Endpoints {
		isMutation := ep.IsStateChanging || isStateChangingMethod(ep.Method)

		for _, obj := range actx.Objects {
			// Check context cancellation
			select {
			case <-ctx.Done():
				return results, e.compileSummary(results), ctx.Err()
			default:
			}

			// Check request budget
			if actx.MaxRequests > 0 && actx.DispatchedRequests != nil {
				if int(atomic.LoadInt32(actx.DispatchedRequests)) >= actx.MaxRequests {
					break
				}
			}

			cat := CategoryBOLAUserRead
			if obj.TenantID != "" {
				cat = CategoryBOLATenantRead
			}
			if ep.IsCollection {
				cat = CategoryBOLACollection
			}
			if isMutation {
				cat = CategoryBOLAWriteMutation
			}
			meta := CategoryMetadata[cat]

			// Ownership mapping check
			if obj.OwnerIdentity == "" {
				r := Result{
					ID:                uuid.New().String(),
					AssessmentID:      actx.AssessmentID,
					ExecutionID:       actx.ExecutionID,
					Category:          cat,
					VulnCode:          "BOLA-MISSING-OWNERSHIP",
					TestID:            fmt.Sprintf("BOLA-TEST-%03d", testIdx),
					TestName:          fmt.Sprintf("Ownership Mapping Validation for %s", obj.ID),
					OWASPRef:          meta.OWASP,
					CWERef:            meta.CWE,
					Endpoint:          ep.PathPattern,
					Method:            ep.Method,
					ObjectID:          obj.ID,
					VerificationState: StateInconclusive,
					Severity:          "INFO",
					Confidence:        "LOW",
					EvidenceSummary:   fmt.Sprintf("Missing ownership mapping for object %s; inconclusive", obj.ID),
					CreatedAt:         time.Now().UTC(),
				}
				results = append(results, r)
				testIdx++
				continue
			}

			owner, hasOwner := identMap[obj.OwnerIdentity]
			if !hasOwner {
				r := Result{
					ID:                uuid.New().String(),
					AssessmentID:      actx.AssessmentID,
					ExecutionID:       actx.ExecutionID,
					Category:          cat,
					VulnCode:          "BOLA-UNRESOLVED-OWNER",
					TestID:            fmt.Sprintf("BOLA-TEST-%03d", testIdx),
					TestName:          fmt.Sprintf("Owner Identity Resolution for %s", obj.ID),
					OWASPRef:          meta.OWASP,
					CWERef:            meta.CWE,
					Endpoint:          ep.PathPattern,
					Method:            ep.Method,
					ObjectID:          obj.ID,
					OwnerAlias:        obj.OwnerIdentity,
					VerificationState: StateInconclusive,
					Severity:          "INFO",
					Confidence:        "LOW",
					EvidenceSummary:   fmt.Sprintf("Configured owner %q not found in assessment identities; ownership cannot be established for object %s", obj.OwnerIdentity, obj.ID),
					CreatedAt:         time.Now().UTC(),
				}
				results = append(results, r)
				testIdx++
				continue
			}

			// Find distinct non-owner identity
			var nonOwner TestIdentity
			var hasNonOwner bool
			for _, id := range actx.Identities {
				if !strings.EqualFold(id.Alias, owner.Alias) {
					nonOwner = id
					hasNonOwner = true
					break
				}
			}
			if !hasNonOwner || !AreIdentitiesDistinct(owner, nonOwner) {
				r := Result{
					ID:                uuid.New().String(),
					AssessmentID:      actx.AssessmentID,
					ExecutionID:       actx.ExecutionID,
					Category:          cat,
					VulnCode:          "BOLA-NO-NON-OWNER",
					TestID:            fmt.Sprintf("BOLA-TEST-%03d", testIdx),
					TestName:          fmt.Sprintf("Non-Owner Identity Resolution for %s", obj.ID),
					OWASPRef:          meta.OWASP,
					CWERef:            meta.CWE,
					Endpoint:          ep.PathPattern,
					Method:            ep.Method,
					ObjectID:          obj.ID,
					OwnerAlias:        owner.Alias,
					VerificationState: StateInconclusive,
					Severity:          "INFO",
					Confidence:        "LOW",
					EvidenceSummary:   fmt.Sprintf("No distinct non-owner identity available to test cross-principal access for object %s", obj.ID),
					CreatedAt:         time.Now().UTC(),
				}
				results = append(results, r)
				testIdx++
				continue
			}

			targetURL := buildTargetURL(actx.BaseURL, ep, obj)

			// Validate URL scope before dispatch
			if actx.IsExcluded != nil && actx.IsExcluded(targetURL) {
				continue
			}
			if actx.IsAllowed != nil && !actx.IsAllowed(targetURL) {
				continue
			}

			if isMutation {
				if !actx.AllowStateChangingTests {
					// Read-only default guard
					r := Result{
						ID:                uuid.New().String(),
						AssessmentID:      actx.AssessmentID,
						ExecutionID:       actx.ExecutionID,
						Category:          cat,
						VulnCode:          meta.Code,
						TestID:            fmt.Sprintf("BOLA-TEST-%03d", testIdx),
						TestName:          fmt.Sprintf("%s: %s", meta.Name, ep.PathPattern),
						OWASPRef:          meta.OWASP,
						CWERef:            meta.CWE,
						Endpoint:          ep.PathPattern,
						Method:            ep.Method,
						ObjectID:          obj.ID,
						OwnerAlias:        owner.Alias,
						AccessorAlias:     nonOwner.Alias,
						VerificationState: StateSkipped,
						Severity:          "INFO",
						Confidence:        "LOW",
						EvidenceSummary:   "State-changing mutation test skipped: requires explicit --allow-state-changing opt-in",
						CreatedAt:         time.Now().UTC(),
					}
					results = append(results, r)
					testIdx++
					continue
				}

				// Execute authorized mutation test
				crossResp, err := e.sendRequest(ctx, client, ep.Method, targetURL, nonOwner, []byte(`{"canary":"felix_bola_probe"}`))
				if err != nil {
					if ctx.Err() != nil {
						return results, e.compileSummary(results), ctx.Err()
					}
					continue
				}
				cmp := CompareWrite(crossResp, obj, owner.Alias, nonOwner.Alias, true)
				res := Result{
					ID:                uuid.New().String(),
					AssessmentID:      actx.AssessmentID,
					ExecutionID:       actx.ExecutionID,
					Category:          cat,
					VulnCode:          meta.Code,
					TestID:            fmt.Sprintf("BOLA-TEST-%03d", testIdx),
					TestName:          fmt.Sprintf("%s: %s", meta.Name, ep.PathPattern),
					OWASPRef:          meta.OWASP,
					CWERef:            meta.CWE,
					Endpoint:          ep.PathPattern,
					Method:            ep.Method,
					ObjectID:          obj.ID,
					OwnerAlias:        owner.Alias,
					AccessorAlias:     nonOwner.Alias,
					VerificationState: cmp.State,
					Severity:          cmp.Severity,
					Confidence:        cmp.Confidence,
					ObservedStatus:    crossResp.StatusCode,
					EvidenceSummary:   cmp.EvidenceSummary,
					EvidenceDetails:   cmp.EvidenceDetails,
					CreatedAt:         time.Now().UTC(),
				}
				if cmp.State == StateVerified || cmp.State == StateCandidate {
					res.Finding = e.buildFinding(res, meta, targetURL)
				}
				results = append(results, res)
				testIdx++
				continue
			}

			// Read-Only Verification (GET)
			// 1. Owner Baseline Request
			baseResp, err := e.sendRequest(ctx, client, "GET", targetURL, owner, nil)
			if err != nil {
				if ctx.Err() != nil {
					return results, e.compileSummary(results), ctx.Err()
				}
				continue
			}

			// 2. Non-Owner Cross-Principal Request
			crossResp, err := e.sendRequest(ctx, client, "GET", targetURL, nonOwner, nil)
			if err != nil {
				if ctx.Err() != nil {
					return results, e.compileSummary(results), ctx.Err()
				}
				continue
			}

			// 3. Response Analysis & Differential Comparison
			cmp := CompareRead(baseResp, crossResp, obj, owner.Alias, nonOwner.Alias)
			res := Result{
				ID:                uuid.New().String(),
				AssessmentID:      actx.AssessmentID,
				ExecutionID:       actx.ExecutionID,
				Category:          cat,
				VulnCode:          meta.Code,
				TestID:            fmt.Sprintf("BOLA-TEST-%03d", testIdx),
				TestName:          fmt.Sprintf("%s: %s", meta.Name, ep.PathPattern),
				OWASPRef:          meta.OWASP,
				CWERef:            meta.CWE,
				Endpoint:          ep.PathPattern,
				Method:            "GET",
				ObjectID:          obj.ID,
				OwnerAlias:        owner.Alias,
				AccessorAlias:     nonOwner.Alias,
				VerificationState: cmp.State,
				Severity:          cmp.Severity,
				Confidence:        cmp.Confidence,
				ObservedStatus:    crossResp.StatusCode,
				EvidenceSummary:   cmp.EvidenceSummary,
				EvidenceDetails:   cmp.EvidenceDetails,
				CreatedAt:         time.Now().UTC(),
			}
			if cmp.State == StateVerified || cmp.State == StateCandidate {
				res.Finding = e.buildFinding(res, meta, targetURL)
			}
			results = append(results, res)
			testIdx++
		}
	}

	return results, e.compileSummary(results), nil
}

func (e *Engine) sendRequest(ctx context.Context, client *http.Client, method, rawURL string, ident TestIdentity, body []byte) (ResponseData, error) {
	var bodyReader io.Reader
	if len(body) > 0 {
		bodyReader = bytes.NewReader(body)
	}

	req, err := http.NewRequestWithContext(ctx, method, rawURL, bodyReader)
	if err != nil {
		return ResponseData{}, err
	}

	req.Header.Set("User-Agent", e.config.UserAgent)
	if len(body) > 0 {
		req.Header.Set("Content-Type", "application/json")
	}

	// Apply identity auth headers
	for k, v := range ident.Headers {
		req.Header.Set(k, v)
	}
	// Apply identity cookies
	for k, v := range ident.Cookies {
		req.AddCookie(&http.Cookie{Name: k, Value: v})
	}

	resp, err := client.Do(req)
	if err != nil {
		return ResponseData{}, err
	}
	defer resp.Body.Close()

	// Bounded response read
	maxBytes := e.config.MaxBodyReadBytes
	if maxBytes <= 0 {
		maxBytes = 1 * 1024 * 1024 // 1MB default
	}
	limited := io.LimitReader(resp.Body, maxBytes)
	bodyBytes, _ := io.ReadAll(limited)

	return ResponseData{
		StatusCode: resp.StatusCode,
		Header:     resp.Header,
		Body:       bodyBytes,
		URL:        rawURL,
	}, nil
}

func (e *Engine) buildFinding(r Result, meta CategoryInfo, targetURL string) *report.Finding {
	sanitizedTarget := SanitizeURL(targetURL)
	sanitizedEndpoint := SanitizeURL(r.Endpoint)
	if sanitizedEndpoint == "" {
		sanitizedEndpoint = sanitizedTarget
	}

	evidence := RedactText(r.EvidenceSummary)
	return &report.Finding{
		ID:          uuid.New().String(),
		Title:       fmt.Sprintf("[%s] %s on %s", r.VulnCode, meta.Name, r.ObjectID),
		Category:    fmt.Sprintf("%s / %s", meta.OWASP, meta.Name),
		Severity:    r.Severity,
		Confidence:  r.Confidence,
		Target:      sanitizedTarget,
		Endpoint:    sanitizedEndpoint,
		Method:      r.Method,
		Description: fmt.Sprintf("[%s / %s] %s", r.VulnCode, meta.OWASP, meta.Description),
		Evidence:    evidence,
		EvidenceDetails: report.EvidenceDetails{
			Observation:     evidence,
			Location:        sanitizedEndpoint,
			HTTPMethod:      r.Method,
			HTTPStatus:      r.ObservedStatus,
			DetectionMethod: "BOLA_VERIFICATION_ENGINE",
			Details: map[string]string{
				"category":       string(r.Category),
				"vuln_code":      r.VulnCode,
				"object_id":      RedactText(r.ObjectID),
				"owner_alias":    r.OwnerAlias,
				"accessor_alias": r.AccessorAlias,
			},
		},
		Remediation: "Enforce strict object-level authorization on the server side by validating that the authenticated principal possesses legitimate ownership or tenant access rights to the requested resource identifier before fulfilling the request.",
	}
}

func (e *Engine) compileSummary(results []Result) *Summary {
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
		switch r.VerificationState {
		case StateVerified:
			summary.VerifiedCount++
		case StateCandidate:
			summary.CandidateCount++
		case StateNotVulnerable:
			summary.NotVulnerableCount++
		case StateInconclusive:
			summary.InconclusiveCount++
		case StateSkipped:
			summary.BlockedCount++
		}

		cov := summary.CoverageMap[string(r.Category)]
		cov.TestsRun++
		switch r.VerificationState {
		case StateVerified:
			cov.Verified++
			cov.Status = CoverageVerifiedIssueFound
		case StateCandidate:
			cov.Candidates++
			if cov.Status != CoverageVerifiedIssueFound {
				cov.Status = CoverageCandidateIdentified
			}
		case StateNotVulnerable:
			if cov.Status == CoverageUntested {
				cov.Status = CoverageActivelyTested
			}
		case StateInconclusive, StateSkipped:
			cov.Inconclusive++
			if cov.Status == CoverageUntested {
				cov.Status = CoverageBlockedMissingPrereq
			}
		}
		cov.Explanation = r.EvidenceSummary
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

func isStateChangingMethod(m string) bool {
	upper := strings.ToUpper(m)
	return upper == "POST" || upper == "PUT" || upper == "PATCH" || upper == "DELETE"
}

func buildTargetURL(baseURL string, ep EndpointTemplate, obj ObjectIdentifier) string {
	base := strings.TrimRight(baseURL, "/")
	pattern := ep.PathPattern
	if !strings.HasPrefix(pattern, "/") {
		pattern = "/" + pattern
	}

	// Replace {id}, {objectId}, {userId}, {recordId}
	targetPath := pattern
	targetPath = strings.ReplaceAll(targetPath, "{id}", url.PathEscape(obj.ID))
	targetPath = strings.ReplaceAll(targetPath, "{objectId}", url.PathEscape(obj.ID))
	targetPath = strings.ReplaceAll(targetPath, "{userId}", url.PathEscape(obj.ID))
	targetPath = strings.ReplaceAll(targetPath, "{recordId}", url.PathEscape(obj.ID))
	if obj.TenantID != "" {
		targetPath = strings.ReplaceAll(targetPath, "{tenantId}", url.PathEscape(obj.TenantID))
	}

	fullURL := base + targetPath
	if obj.Location == "query" && obj.ParamName != "" {
		sep := "?"
		if strings.Contains(fullURL, "?") {
			sep = "&"
		}
		fullURL = fmt.Sprintf("%s%s%s=%s", fullURL, sep, url.QueryEscape(obj.ParamName), url.QueryEscape(obj.ID))
	}
	return fullURL
}
