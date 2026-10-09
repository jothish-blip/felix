package apisec

import (
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"

	"felix/pkg/auth"
	"felix/pkg/authz"
	"felix/pkg/report"
)

// Engine orchestrates the OWASP API Security Top 10 (2023) assessment pipeline.
type Engine struct {
	client *http.Client
	cfg    Config
}

// NewEngine creates an API security assessment engine.
func NewEngine(client *http.Client, cfg Config) *Engine {
	if client == nil {
		client = &http.Client{Timeout: cfg.Timeout}
	}
	return &Engine{
		client: client,
		cfg:    cfg,
	}
}

func (e *Engine) scopedClient(actx *AssessmentContext) *http.Client {
	base := e.client
	if base == nil {
		base = &http.Client{Timeout: e.cfg.Timeout}
	}
	origCheck := base.CheckRedirect

	return &http.Client{
		Transport: base.Transport,
		Timeout:   base.Timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 10 {
				return fmt.Errorf("stopped after 10 redirects")
			}
			if origCheck != nil {
				if err := origCheck(req, via); err != nil {
					return err
				}
			}
			nextURL := req.URL.String()
			if actx != nil {
				if actx.IsExcluded != nil && actx.IsExcluded(nextURL) {
					return fmt.Errorf("redirect to %s blocked: matches exclusion rule", nextURL)
				}
				if actx.IsAllowed != nil && !actx.IsAllowed(nextURL) {
					return fmt.Errorf("redirect to %s blocked: out of approved scope", nextURL)
				}
			}
			if len(via) > 0 {
				lastHost := strings.ToLower(via[len(via)-1].URL.Hostname())
				nextHost := strings.ToLower(req.URL.Hostname())
				if lastHost != "" && nextHost != "" && lastHost != nextHost {
					if actx != nil && actx.IsAllowed != nil && !actx.IsAllowed(nextURL) {
						return fmt.Errorf("cross-host redirect from %s to %s blocked", lastHost, nextHost)
					}
				}
			}
			return nil
		},
	}
}

// AssessmentContext contains all available asset inventory, discovery data, and policies.
type AssessmentContext struct {
	AssessmentID string
	ExecutionID  string
	BaseURL      string
	Endpoints    []APIEndpoint
	AuthInv      *auth.AuthInventory
	AuthzPolicy  *authz.AuthzPolicy
	AuthzResults []authz.AuthzTestResult
	DeclaredSpec *DeclaredSpec
	IsAllowed    func(string) bool
	IsExcluded   func(string) bool
}

// Assess executes the evidence-first pipeline across all 10 OWASP API categories.
func (e *Engine) Assess(ctx context.Context, actx *AssessmentContext) ([]Result, []report.Finding, *Summary, error) {
	if actx == nil {
		return nil, nil, nil, fmt.Errorf("assessment context is nil")
	}

	// Deduplicate endpoints across crawler links and discovery assets
	actx.Endpoints = DeduplicateEndpoints(actx.Endpoints)

	client := e.scopedClient(actx)

	var allResults []Result
	var allFindings []report.Finding
	coverageMap := make(map[string]CategoryCoverage)

	// Initialize coverage map for all 10 OWASP categories
	for cat, meta := range OWASPCategoryMetadata {
		coverageMap[string(cat)] = CategoryCoverage{
			Category: cat,
			Code:     meta.Code,
			Name:     meta.Name,
			Status:   CoverageUntested,
		}
	}

	// 1. API1: Broken Object Level Authorization (BOLA / IDOR)
	res1, fnd1, cov1 := e.assessAPI1(actx)
	allResults = append(allResults, res1...)
	allFindings = append(allFindings, fnd1...)
	coverageMap[string(CategoryAPI1_BOLA)] = cov1

	// 2. API2: Broken Authentication
	res2, fnd2, cov2 := e.assessAPI2(actx)
	allResults = append(allResults, res2...)
	allFindings = append(allFindings, fnd2...)
	coverageMap[string(CategoryAPI2_BrokenAuth)] = cov2

	// 3. API3: Broken Object Property Level Authorization (BOPLA)
	res3, fnd3, cov3 := e.assessAPI3(actx)
	allResults = append(allResults, res3...)
	allFindings = append(allFindings, fnd3...)
	coverageMap[string(CategoryAPI3_BOPLA)] = cov3

	// 4. API4: Unrestricted Resource Consumption
	res4, fnd4, cov4 := e.assessAPI4(ctx, actx, client)
	allResults = append(allResults, res4...)
	allFindings = append(allFindings, fnd4...)
	coverageMap[string(CategoryAPI4_ResourceConsumption)] = cov4

	// 5. API5: Broken Function Level Authorization (BFLA)
	res5, fnd5, cov5 := e.assessAPI5(actx)
	allResults = append(allResults, res5...)
	allFindings = append(allFindings, fnd5...)
	coverageMap[string(CategoryAPI5_BFLA)] = cov5

	// 6. API6: Unrestricted Access to Sensitive Business Flows
	res6, fnd6, cov6 := e.assessAPI6(actx)
	allResults = append(allResults, res6...)
	allFindings = append(allFindings, fnd6...)
	coverageMap[string(CategoryAPI6_BusinessFlows)] = cov6

	// 7. API7: Server-Side Request Forgery (SSRF)
	res7, fnd7, cov7 := e.assessAPI7(ctx, actx, client)
	allResults = append(allResults, res7...)
	allFindings = append(allFindings, fnd7...)
	coverageMap[string(CategoryAPI7_SSRF)] = cov7

	// 8. API8: Security Misconfiguration
	res8, fnd8, cov8 := e.assessAPI8(ctx, actx, client)
	allResults = append(allResults, res8...)
	allFindings = append(allFindings, fnd8...)
	coverageMap[string(CategoryAPI8_Misconfiguration)] = cov8

	// 9. API9: Improper Inventory Management
	res9, fnd9, cov9 := e.assessAPI9(actx)
	allResults = append(allResults, res9...)
	allFindings = append(allFindings, fnd9...)
	coverageMap[string(CategoryAPI9_ImproperInventory)] = cov9

	// 10. API10: Unsafe Consumption of APIs
	res10, fnd10, cov10 := e.assessAPI10(ctx, actx)
	allResults = append(allResults, res10...)
	allFindings = append(allFindings, fnd10...)
	coverageMap[string(CategoryAPI10_UnsafeConsumption)] = cov10

	summary := e.compileSummary(allResults, coverageMap)
	return allResults, allFindings, summary, nil
}

// --- Category 1: API1 (BOLA) ---
func (e *Engine) assessAPI1(actx *AssessmentContext) ([]Result, []report.Finding, CategoryCoverage) {
	cov := CategoryCoverage{
		Category: CategoryAPI1_BOLA,
		Code:     OWASPCategoryMetadata[CategoryAPI1_BOLA].Code,
		Name:     OWASPCategoryMetadata[CategoryAPI1_BOLA].Name,
		Status:   CoveragePassivelyAssessed,
	}

	var results []Result
	var findings []report.Finding

	// Check if Stage 4 authorization results exist
	for _, ar := range actx.AuthzResults {
		if ar.Category == authz.CategoryBOLA {
			r := Result{
				ID:                uuid.New().String(),
				AssessmentID:      actx.AssessmentID,
				ExecutionID:       actx.ExecutionID,
				Category:          CategoryAPI1_BOLA,
				OWASPCode:         "API1:2023",
				TestName:          "BOLA / Object-Level Access Control",
				Endpoint:          ar.Endpoint,
				Method:            ar.Method,
				VerificationState: VerificationState(ar.VerificationState),
				ObservedStatus:    ar.ObservedStatus,
				EvidenceSummary:   ar.EvidenceSummary,
				CreatedAt:         time.Now().UTC(),
			}

			if ar.VerificationState == authz.StateVerified {
				cov.Status = CoverageVerifiedIssueFound
				cov.Verified++
				r.Severity = report.SeverityHigh
				r.Confidence = report.ConfidenceHigh

				fnd := e.createFinding(actx, r, "API1:2023 Broken Object Level Authorization (BOLA)",
					ar.EvidenceSummary, report.SeverityHigh, 80)
				r.Finding = fnd
				findings = append(findings, *fnd)
			} else if ar.VerificationState == authz.StateNotVulnerable {
				cov.Status = CoverageActivelyTested
				r.Severity = report.SeverityInfo
				r.Confidence = report.ConfidenceHigh
			} else {
				cov.Candidates++
				r.Severity = report.SeverityInfo
				r.Confidence = report.ConfidenceMedium
			}

			results = append(results, r)
		}
	}

	cov.TestsRun = len(results)
	if cov.TestsRun > 0 {
		cov.Explanation = fmt.Sprintf("Evaluated %d object-level access tests via Stage 4 authorization engine (%d verified vulnerabilities)", cov.TestsRun, cov.Verified)
		return results, findings, cov
	}

	// Passive inventory check if no Stage 4 tests were run
	var objectEndpoints []string
	for _, ep := range actx.Endpoints {
		if ep.IsObjectRef {
			objectEndpoints = append(objectEndpoints, ep.Path)
		}
	}

	if len(objectEndpoints) > 0 {
		cov.Status = CoveragePrereqMissing
		cov.Observations = len(objectEndpoints)
		cov.Explanation = fmt.Sprintf("Discovered %d object-referencing API endpoints; active BOLA verification requires test identities via --policy", len(objectEndpoints))
		results = append(results, Result{
			ID:                uuid.New().String(),
			AssessmentID:      actx.AssessmentID,
			ExecutionID:       actx.ExecutionID,
			Category:          CategoryAPI1_BOLA,
			OWASPCode:         "API1:2023",
			TestName:          "Object-Reference Discovery",
			Endpoint:          objectEndpoints[0],
			Method:            "GET",
			VerificationState: StateObserved,
			Severity:          report.SeverityInfo,
			Confidence:        report.ConfidenceHigh,
			EvidenceSummary:   fmt.Sprintf("Discovered %d endpoints containing resource identifiers; active multi-user authorization policy required for BOLA test", len(objectEndpoints)),
			CreatedAt:         time.Now().UTC(),
		})
	} else {
		cov.Explanation = "No object-referencing endpoints discovered in API attack surface"
	}

	return results, findings, cov
}

// --- Category 2: API2 (Broken Authentication) ---
func (e *Engine) assessAPI2(actx *AssessmentContext) ([]Result, []report.Finding, CategoryCoverage) {
	cov := CategoryCoverage{
		Category: CategoryAPI2_BrokenAuth,
		Code:     OWASPCategoryMetadata[CategoryAPI2_BrokenAuth].Code,
		Name:     OWASPCategoryMetadata[CategoryAPI2_BrokenAuth].Name,
		Status:   CoveragePassivelyAssessed,
	}

	var results []Result
	var findings []report.Finding

	if actx.AuthInv != nil {
		// 1. Inspect Cookies for Session Security Issues
		for _, ck := range actx.AuthInv.Cookies {
			if ck.IsSession && ck.HasSecurityIssue {
				// Evaluate transport security context
				isPlainHTTP := strings.HasPrefix(strings.ToLower(ck.SourceURL), "http://")
				if isPlainHTTP && !ck.IsSecure {
					// Confirmed transport exposure: sensitive session cookie sent over unencrypted HTTP
					r := Result{
						ID:                uuid.New().String(),
						AssessmentID:      actx.AssessmentID,
						ExecutionID:       actx.ExecutionID,
						Category:          CategoryAPI2_BrokenAuth,
						OWASPCode:         "API2:2023",
						TestName:          "Unencrypted Session Cookie Transport",
						Endpoint:          ck.SourceURL,
						Method:            "GET",
						VerificationState: StateVerified,
						Severity:          report.SeverityMedium,
						Confidence:        report.ConfidenceHigh,
						EvidenceSummary:   fmt.Sprintf("Session cookie %q lacks Secure flag and was transmitted over unencrypted HTTP: %s", ck.Name, strings.Join(ck.SecurityDefects, "; ")),
						CreatedAt:         time.Now().UTC(),
					}
					cov.Verified++
					cov.Status = CoverageVerifiedIssueFound

					fnd := e.createFinding(actx, r, fmt.Sprintf("API2:2023 Unencrypted Session Cookie Transport (%s)", ck.Name),
						r.EvidenceSummary, report.SeverityMedium, 40)
					r.Finding = fnd
					findings = append(findings, *fnd)
					results = append(results, r)
				} else {
					// HTTPS session cookie missing defense-in-depth attributes: candidate issue, not proven compromise
					r := Result{
						ID:                uuid.New().String(),
						AssessmentID:      actx.AssessmentID,
						ExecutionID:       actx.ExecutionID,
						Category:          CategoryAPI2_BrokenAuth,
						OWASPCode:         "API2:2023",
						TestName:          "Session Cookie Attribute Hardening",
						Endpoint:          ck.SourceURL,
						Method:            "GET",
						VerificationState: StateCandidate,
						Severity:          report.SeverityLow,
						Confidence:        report.ConfidenceMedium,
						EvidenceSummary:   fmt.Sprintf("Session cookie %q missing recommended defensive attribute(s) (%s); candidate hardening issue (no session compromise demonstrated)", ck.Name, strings.Join(ck.SecurityDefects, "; ")),
						CreatedAt:         time.Now().UTC(),
					}
					cov.Candidates++
					results = append(results, r)
				}
			} else if ck.HasSecurityIssue {
				// Non-session cookie missing flags: observational only
				r := Result{
					ID:                uuid.New().String(),
					AssessmentID:      actx.AssessmentID,
					ExecutionID:       actx.ExecutionID,
					Category:          CategoryAPI2_BrokenAuth,
					OWASPCode:         "API2:2023",
					TestName:          "Non-Session Cookie Attribute Observation",
					Endpoint:          ck.SourceURL,
					Method:            "GET",
					VerificationState: StateObserved,
					Severity:          report.SeverityInfo,
					Confidence:        report.ConfidenceLow,
					EvidenceSummary:   fmt.Sprintf("Non-session cookie %q missing attributes: %s (informational observation)", ck.Name, strings.Join(ck.SecurityDefects, "; ")),
					CreatedAt:         time.Now().UTC(),
				}
				cov.Observations++
				results = append(results, r)
			}
		}

		// 2. Inspect Token Artifacts (e.g. alg=none JWT)
		for _, tok := range actx.AuthInv.Tokens {
			if strings.EqualFold(tok.Algorithm, "none") {
				r := Result{
					ID:                uuid.New().String(),
					AssessmentID:      actx.AssessmentID,
					ExecutionID:       actx.ExecutionID,
					Category:          CategoryAPI2_BrokenAuth,
					OWASPCode:         "API2:2023",
					TestName:          "Unsecured JWT Algorithm Header Indicator",
					Endpoint:          tok.SourceAsset,
					Method:            "STATIC",
					VerificationState: StateCandidate,
					Severity:          report.SeverityLow,
					Confidence:        report.ConfidenceMedium,
					EvidenceSummary:   "Token structure declares alg=none in header; candidate static indicator (server acceptance not verified without active signature validation test)",
					CreatedAt:         time.Now().UTC(),
				}
				cov.Candidates++
				results = append(results, r)
			}
		}

		cov.TestsRun = len(results)
		cov.Explanation = fmt.Sprintf("Analyzed %d authentication surfaces, %d session cookies, and %d token architectures (%d verified, %d candidates, %d observations)",
			len(actx.AuthInv.Surfaces), len(actx.AuthInv.Cookies), len(actx.AuthInv.Tokens), cov.Verified, cov.Candidates, cov.Observations)
	} else {
		cov.Explanation = "No authentication intelligence records available"
	}

	return results, findings, cov
}

// --- Category 3: API3 (BOPLA) ---
func (e *Engine) assessAPI3(actx *AssessmentContext) ([]Result, []report.Finding, CategoryCoverage) {
	cov := CategoryCoverage{
		Category: CategoryAPI3_BOPLA,
		Code:     OWASPCategoryMetadata[CategoryAPI3_BOPLA].Code,
		Name:     OWASPCategoryMetadata[CategoryAPI3_BOPLA].Name,
		Status:   CoveragePassivelyAssessed,
	}

	var results []Result
	var findings []report.Finding

	for _, ar := range actx.AuthzResults {
		if ar.Category == authz.CategoryBOPLAExposure || ar.Category == authz.CategoryBOPLAModification {
			r := Result{
				ID:                uuid.New().String(),
				AssessmentID:      actx.AssessmentID,
				ExecutionID:       actx.ExecutionID,
				Category:          CategoryAPI3_BOPLA,
				OWASPCode:         "API3:2023",
				TestName:          string(ar.Category),
				Endpoint:          ar.Endpoint,
				Method:            ar.Method,
				VerificationState: VerificationState(ar.VerificationState),
				ObservedStatus:    ar.ObservedStatus,
				EvidenceSummary:   ar.EvidenceSummary,
				CreatedAt:         time.Now().UTC(),
			}

			if ar.VerificationState == authz.StateVerified {
				cov.Status = CoverageVerifiedIssueFound
				cov.Verified++
				sev := report.SeverityMedium
				score := 50
				if ar.Category == authz.CategoryBOPLAModification {
					sev = report.SeverityHigh
					score = 75
				}
				r.Severity = sev
				r.Confidence = report.ConfidenceHigh

				fnd := e.createFinding(actx, r, fmt.Sprintf("API3:2023 Broken Object Property Level Authorization (%s)", ar.Category),
					ar.EvidenceSummary, sev, score)
				r.Finding = fnd
				findings = append(findings, *fnd)
			} else if ar.VerificationState == authz.StateNotVulnerable {
				cov.Status = CoverageActivelyTested
				r.Severity = report.SeverityInfo
				r.Confidence = report.ConfidenceHigh
			} else {
				cov.Candidates++
				r.Severity = report.SeverityInfo
				r.Confidence = report.ConfidenceMedium
			}

			results = append(results, r)
		}
	}

	cov.TestsRun = len(results)
	if cov.TestsRun > 0 {
		cov.Explanation = fmt.Sprintf("Evaluated %d property-level exposure/modification tests via Stage 4 engine", cov.TestsRun)
	} else {
		cov.Status = CoveragePrereqMissing
		cov.Explanation = "No property-level authorization tests executed; multi-user authorization policy required via --policy"
	}

	return results, findings, cov
}

// --- Category 4: API4 (Resource Consumption) ---
func (e *Engine) assessAPI4(ctx context.Context, actx *AssessmentContext, client *http.Client) ([]Result, []report.Finding, CategoryCoverage) {
	cov := CategoryCoverage{
		Category: CategoryAPI4_ResourceConsumption,
		Code:     OWASPCategoryMetadata[CategoryAPI4_ResourceConsumption].Code,
		Name:     OWASPCategoryMetadata[CategoryAPI4_ResourceConsumption].Name,
		Status:   CoverageActivelyTested,
	}

	var results []Result
	var findings []report.Finding

	// Identify candidate endpoints with pagination or list capabilities
	var testEndpoints []APIEndpoint
	for _, ep := range actx.Endpoints {
		if ep.HasPagination || strings.Contains(ep.Path, "/list") || strings.Contains(ep.Path, "/search") {
			testEndpoints = append(testEndpoints, ep)
		}
	}

	if len(testEndpoints) == 0 && len(actx.Endpoints) > 0 {
		testEndpoints = append(testEndpoints, actx.Endpoints[0])
	}

	if len(testEndpoints) == 0 {
		cov.Status = CoveragePassivelyAssessed
		cov.Explanation = "No endpoints available for resource consumption auditing"
		return results, findings, cov
	}

	target := testEndpoints[0]
	fullURL := actx.BaseURL + target.Path

	if actx.IsExcluded != nil && actx.IsExcluded(fullURL) {
		cov.Status = CoveragePassivelyAssessed
		cov.Explanation = fmt.Sprintf("Target URL %s matches assessment exclusion rule; active tests skipped", fullURL)
		return results, findings, cov
	}
	if actx.IsAllowed != nil && !actx.IsAllowed(fullURL) {
		cov.Status = CoveragePassivelyAssessed
		cov.Explanation = fmt.Sprintf("Target URL %s is outside approved scope; active tests skipped", fullURL)
		return results, findings, cov
	}

	// Bounded Rate Limiting Audit (Safe 3-request probe)
	hasRateLimitHeader := false
	got429 := false
	reqCount := 3
	for i := 0; i < reqCount; i++ {
		req, err := http.NewRequestWithContext(ctx, "GET", fullURL, nil)
		if err != nil {
			break
		}
		resp, err := client.Do(req)
		if err != nil {
			break
		}
		if resp.StatusCode == http.StatusTooManyRequests {
			got429 = true
		}
		for h := range resp.Header {
			lowerH := strings.ToLower(h)
			if strings.Contains(lowerH, "ratelimit") || strings.Contains(lowerH, "retry-after") {
				hasRateLimitHeader = true
			}
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}

	cov.TestsRun++
	if got429 || hasRateLimitHeader {
		res := Result{
			ID:                uuid.New().String(),
			AssessmentID:      actx.AssessmentID,
			ExecutionID:       actx.ExecutionID,
			Category:          CategoryAPI4_ResourceConsumption,
			OWASPCode:         "API4:2023",
			TestName:          "Rate Limiting Defensive Control Verification",
			Endpoint:          fullURL,
			Method:            "GET",
			VerificationState: StateNotVulnerable,
			Severity:          report.SeverityInfo,
			Confidence:        report.ConfidenceHigh,
			EvidenceSummary:   fmt.Sprintf("Endpoint enforced rate limiting or provided telemetry (HTTP 429 observed: %t, telemetry headers: %t)", got429, hasRateLimitHeader),
			CreatedAt:         time.Now().UTC(),
		}
		results = append(results, res)
	} else {
		// Missing telemetry headers alone does not demonstrate vulnerability (reverse proxies/WAFs frequently suppress telemetry)
		cov.Observations++
		res := Result{
			ID:                uuid.New().String(),
			AssessmentID:      actx.AssessmentID,
			ExecutionID:       actx.ExecutionID,
			Category:          CategoryAPI4_ResourceConsumption,
			OWASPCode:         "API4:2023",
			TestName:          "Rate Limiting Telemetry Header Observation",
			Endpoint:          fullURL,
			Method:            "GET",
			VerificationState: StateObserved,
			Severity:          report.SeverityInfo,
			Confidence:        report.ConfidenceMedium,
			EvidenceSummary:   "API endpoint did not expose standard rate-limiting telemetry headers (RateLimit-Limit, Retry-After); reverse-proxy or volumetric thresholds may exist unadvertised",
			CreatedAt:         time.Now().UTC(),
		}
		results = append(results, res)
	}

	// Record pagination boundary control observations
	for _, ep := range actx.Endpoints {
		if ep.HasPagination {
			cov.Observations++
			results = append(results, Result{
				ID:                uuid.New().String(),
				AssessmentID:      actx.AssessmentID,
				ExecutionID:       actx.ExecutionID,
				Category:          CategoryAPI4_ResourceConsumption,
				OWASPCode:         "API4:2023",
				TestName:          "Pagination Boundary Control Observation",
				Endpoint:          actx.BaseURL + ep.Path,
				Method:            ep.Method,
				VerificationState: StateObserved,
				Severity:          report.SeverityInfo,
				Confidence:        report.ConfidenceHigh,
				EvidenceSummary:   fmt.Sprintf("Endpoint %s %s accepts pagination parameters; verify server enforces maximum page size limits", ep.Method, ep.Path),
				CreatedAt:         time.Now().UTC(),
			})
		}
	}

	cov.Explanation = fmt.Sprintf("Tested rate limiting headers and pagination controls on %s (Rate limit enforced/advertised: %t)", target.Path, got429 || hasRateLimitHeader)
	return results, findings, cov
}

// --- Category 5: API5 (BFLA) ---
func (e *Engine) assessAPI5(actx *AssessmentContext) ([]Result, []report.Finding, CategoryCoverage) {
	cov := CategoryCoverage{
		Category: CategoryAPI5_BFLA,
		Code:     OWASPCategoryMetadata[CategoryAPI5_BFLA].Code,
		Name:     OWASPCategoryMetadata[CategoryAPI5_BFLA].Name,
		Status:   CoveragePassivelyAssessed,
	}

	var results []Result
	var findings []report.Finding

	for _, ar := range actx.AuthzResults {
		if ar.Category == authz.CategoryBFLA {
			r := Result{
				ID:                uuid.New().String(),
				AssessmentID:      actx.AssessmentID,
				ExecutionID:       actx.ExecutionID,
				Category:          CategoryAPI5_BFLA,
				OWASPCode:         "API5:2023",
				TestName:          "BFLA / Privileged Function Access",
				Endpoint:          ar.Endpoint,
				Method:            ar.Method,
				VerificationState: VerificationState(ar.VerificationState),
				ObservedStatus:    ar.ObservedStatus,
				EvidenceSummary:   ar.EvidenceSummary,
				CreatedAt:         time.Now().UTC(),
			}

			if ar.VerificationState == authz.StateVerified {
				cov.Status = CoverageVerifiedIssueFound
				cov.Verified++
				r.Severity = report.SeverityHigh
				r.Confidence = report.ConfidenceHigh

				fnd := e.createFinding(actx, r, "API5:2023 Broken Function Level Authorization (BFLA)",
					ar.EvidenceSummary, report.SeverityHigh, 85)
				r.Finding = fnd
				findings = append(findings, *fnd)
			} else if ar.VerificationState == authz.StateNotVulnerable {
				cov.Status = CoverageActivelyTested
				r.Severity = report.SeverityInfo
				r.Confidence = report.ConfidenceHigh
			} else {
				cov.Candidates++
				r.Severity = report.SeverityInfo
				r.Confidence = report.ConfidenceMedium
			}

			results = append(results, r)
		}
	}

	cov.TestsRun = len(results)
	if cov.TestsRun > 0 {
		cov.Explanation = fmt.Sprintf("Evaluated %d function-level role tests via Stage 4 engine (%d verified vulnerabilities)", cov.TestsRun, cov.Verified)
		return results, findings, cov
	}

	// Passive administrative route discovery check
	var adminEndpoints []string
	for _, ep := range actx.Endpoints {
		if ep.IsPrivileged {
			adminEndpoints = append(adminEndpoints, ep.Path)
		}
	}

	if len(adminEndpoints) > 0 {
		cov.Status = CoveragePrereqMissing
		cov.Observations = len(adminEndpoints)
		cov.Explanation = fmt.Sprintf("Discovered %d administrative/privileged API endpoints; active BFLA verification requires role policy via --policy", len(adminEndpoints))
		results = append(results, Result{
			ID:                uuid.New().String(),
			AssessmentID:      actx.AssessmentID,
			ExecutionID:       actx.ExecutionID,
			Category:          CategoryAPI5_BFLA,
			OWASPCode:         "API5:2023",
			TestName:          "Privileged Route Discovery",
			Endpoint:          adminEndpoints[0],
			Method:            "GET",
			VerificationState: StateObserved,
			Severity:          report.SeverityInfo,
			Confidence:        report.ConfidenceHigh,
			EvidenceSummary:   fmt.Sprintf("Discovered %d administrative API routes; multi-role authorization policy required for BFLA verification", len(adminEndpoints)),
			CreatedAt:         time.Now().UTC(),
		})
	} else {
		cov.Explanation = "No administrative API routes discovered"
	}

	return results, findings, cov
}

// --- Category 6: API6 (Sensitive Business Flows) ---
func (e *Engine) assessAPI6(actx *AssessmentContext) ([]Result, []report.Finding, CategoryCoverage) {
	cov := CategoryCoverage{
		Category: CategoryAPI6_BusinessFlows,
		Code:     OWASPCategoryMetadata[CategoryAPI6_BusinessFlows].Code,
		Name:     OWASPCategoryMetadata[CategoryAPI6_BusinessFlows].Name,
		Status:   CoveragePassivelyAssessed,
	}

	var results []Result
	var findings []report.Finding

	var flowEndpoints []APIEndpoint
	for _, ep := range actx.Endpoints {
		if ep.IsBusinessFlow {
			flowEndpoints = append(flowEndpoints, ep)
		}
	}

	cov.TestsRun = len(flowEndpoints)
	if len(flowEndpoints) > 0 {
		cov.Observations = len(flowEndpoints)
		cov.Explanation = fmt.Sprintf("Identified %d sensitive business workflow endpoints (registration, checkout, password reset)", len(flowEndpoints))

		for _, ep := range flowEndpoints {
			r := Result{
				ID:                uuid.New().String(),
				AssessmentID:      actx.AssessmentID,
				ExecutionID:       actx.ExecutionID,
				Category:          CategoryAPI6_BusinessFlows,
				OWASPCode:         "API6:2023",
				TestName:          "Sensitive Business Flow Observation",
				Endpoint:          ep.Path,
				Method:            ep.Method,
				VerificationState: StateObserved,
				Severity:          report.SeverityInfo,
				Confidence:        report.ConfidenceHigh,
				EvidenceSummary:   fmt.Sprintf("Endpoint %s %s participates in sensitive business flow: %s; informational observation (recommend auditing rate limits and anti-automation controls)", ep.Method, ep.Path, ep.BusinessFlow),
				CreatedAt:         time.Now().UTC(),
			}
			results = append(results, r)
		}
	} else {
		cov.Explanation = "No sensitive business workflow endpoints discovered"
	}

	return results, findings, cov
}

// --- Category 7: API7 (SSRF) ---
func (e *Engine) assessAPI7(ctx context.Context, actx *AssessmentContext, client *http.Client) ([]Result, []report.Finding, CategoryCoverage) {
	cov := CategoryCoverage{
		Category: CategoryAPI7_SSRF,
		Code:     OWASPCategoryMetadata[CategoryAPI7_SSRF].Code,
		Name:     OWASPCategoryMetadata[CategoryAPI7_SSRF].Name,
		Status:   CoveragePassivelyAssessed,
	}

	var results []Result
	var findings []report.Finding

	var ssrfCandidates []APIEndpoint
	for _, ep := range actx.Endpoints {
		if ep.HasURLParam {
			ssrfCandidates = append(ssrfCandidates, ep)
		}
	}

	cov.TestsRun = len(ssrfCandidates)
	if len(ssrfCandidates) > 0 {
		for _, ep := range ssrfCandidates {
			// If canary callback URL is provided, test safely
			testedCanary := false
			if e.cfg.CanaryCallbackURL != "" {
				// Safety guard: Canary must NOT be internal, loopback, private, or unsafe address
				if !IsInternalOrUnsafeAddress(e.cfg.CanaryCallbackURL) {
					testURL := actx.BaseURL + ep.Path
					if strings.Contains(testURL, "?") {
						testURL += fmt.Sprintf("&%s=%s", ep.URLParamName, url.QueryEscape(e.cfg.CanaryCallbackURL))
					} else {
						testURL += fmt.Sprintf("?%s=%s", ep.URLParamName, url.QueryEscape(e.cfg.CanaryCallbackURL))
					}

					// Verify testURL itself respects scope and exclusion rules before sending probe
					inScope := true
					if actx.IsExcluded != nil && actx.IsExcluded(testURL) {
						inScope = false
					}
					if actx.IsAllowed != nil && !actx.IsAllowed(testURL) {
						inScope = false
					}

					if inScope {
						testedCanary = true
						cov.Status = CoverageActivelyTested
						req, err := http.NewRequestWithContext(ctx, "GET", testURL, nil)
						if err == nil {
							resp, err := client.Do(req)
							if err == nil {
								io.Copy(io.Discard, resp.Body)
								resp.Body.Close()
							}
						}
					}
				}
			}

			if testedCanary {
				// With canary tested but without confirmed out-of-band callback proof, it's a Candidate
				r := Result{
					ID:                uuid.New().String(),
					AssessmentID:      actx.AssessmentID,
					ExecutionID:       actx.ExecutionID,
					Category:          CategoryAPI7_SSRF,
					OWASPCode:         "API7:2023",
					TestName:          "Remote URL Fetching Parameter Analysis",
					Endpoint:          ep.Path,
					Method:            ep.Method,
					VerificationState: StateCandidate,
					Severity:          report.SeverityLow,
					Confidence:        report.ConfidenceMedium,
					EvidenceSummary:   fmt.Sprintf("Endpoint %s %s accepts URL parameter %q; probed with canary token (requires out-of-band callback verification to confirm SSRF)", ep.Method, ep.Path, ep.URLParamName),
					CreatedAt:         time.Now().UTC(),
				}
				cov.Candidates++
				results = append(results, r)
			} else {
				// Passive parameter observation without active canary testing
				r := Result{
					ID:                uuid.New().String(),
					AssessmentID:      actx.AssessmentID,
					ExecutionID:       actx.ExecutionID,
					Category:          CategoryAPI7_SSRF,
					OWASPCode:         "API7:2023",
					TestName:          "Remote URL Fetching Parameter Discovery",
					Endpoint:          ep.Path,
					Method:            ep.Method,
					VerificationState: StateObserved,
					Severity:          report.SeverityInfo,
					Confidence:        report.ConfidenceHigh,
					EvidenceSummary:   fmt.Sprintf("Endpoint %s %s accepts user-supplied URL parameter %q; potential SSRF fetch surface (requires callback verification)", ep.Method, ep.Path, ep.URLParamName),
					CreatedAt:         time.Now().UTC(),
				}
				cov.Observations++
				results = append(results, r)
			}
		}
		cov.Explanation = fmt.Sprintf("Discovered %d potential SSRF fetch parameters; internal probing prohibited by safety policy", len(ssrfCandidates))
	} else {
		cov.Explanation = "No URL-fetching parameters discovered in API endpoints"
	}

	return results, findings, cov
}

// --- Category 8: API8 (Security Misconfiguration) ---
func (e *Engine) assessAPI8(ctx context.Context, actx *AssessmentContext, client *http.Client) ([]Result, []report.Finding, CategoryCoverage) {
	cov := CategoryCoverage{
		Category: CategoryAPI8_Misconfiguration,
		Code:     OWASPCategoryMetadata[CategoryAPI8_Misconfiguration].Code,
		Name:     OWASPCategoryMetadata[CategoryAPI8_Misconfiguration].Name,
		Status:   CoverageActivelyTested,
	}

	var results []Result
	var findings []report.Finding

	testURL := actx.BaseURL
	if len(actx.Endpoints) > 0 {
		testURL = actx.BaseURL + actx.Endpoints[0].Path
	}

	if actx.IsExcluded != nil && actx.IsExcluded(testURL) {
		cov.Explanation = fmt.Sprintf("Target URL %s matches assessment exclusion rule; active tests skipped", testURL)
		return results, findings, cov
	}
	if actx.IsAllowed != nil && !actx.IsAllowed(testURL) {
		cov.Explanation = fmt.Sprintf("Target URL %s is outside approved scope; active tests skipped", testURL)
		return results, findings, cov
	}

	req, err := http.NewRequestWithContext(ctx, "GET", testURL, nil)
	if err != nil {
		cov.Explanation = "Failed to construct baseline request"
		return results, findings, cov
	}

	resp, err := client.Do(req)
	if err != nil {
		cov.Explanation = fmt.Sprintf("Baseline request failed: %v", err)
		return results, findings, cov
	}
	defer resp.Body.Close()

	bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	cov.TestsRun++

	// 1. Check Missing X-Content-Type-Options: nosniff
	// Defense-in-depth header; missing header alone is an informational observation, never a verified vulnerability
	if resp.Header.Get("X-Content-Type-Options") != "nosniff" {
		contentType := resp.Header.Get("Content-Type")
		isSniffableMIME := strings.Contains(contentType, "text/html") || strings.Contains(contentType, "image/svg+xml")
		state := StateObserved
		if isSniffableMIME {
			state = StateCandidate
		}

		r := Result{
			ID:                uuid.New().String(),
			AssessmentID:      actx.AssessmentID,
			ExecutionID:       actx.ExecutionID,
			Category:          CategoryAPI8_Misconfiguration,
			OWASPCode:         "API8:2023",
			TestName:          "Missing X-Content-Type-Options Header",
			Endpoint:          testURL,
			Method:            "GET",
			VerificationState: state,
			Severity:          report.SeverityInfo,
			Confidence:        report.ConfidenceHigh,
			EvidenceSummary:   "API response missing X-Content-Type-Options: nosniff defense-in-depth header (informational hardening observation)",
			CreatedAt:         time.Now().UTC(),
		}
		if state == StateCandidate {
			cov.Candidates++
		} else {
			cov.Observations++
		}
		results = append(results, r)
	}

	// 2. Check Permissive CORS Configuration
	corsOrigin := resp.Header.Get("Access-Control-Allow-Origin")
	corsCredentials := strings.EqualFold(resp.Header.Get("Access-Control-Allow-Credentials"), "true")

	if corsOrigin == "*" {
		if corsCredentials {
			// Credentialed wildcard CORS is a genuine security misconfiguration
			r := Result{
				ID:                uuid.New().String(),
				AssessmentID:      actx.AssessmentID,
				ExecutionID:       actx.ExecutionID,
				Category:          CategoryAPI8_Misconfiguration,
				OWASPCode:         "API8:2023",
				TestName:          "Credentialed CORS Wildcard Configuration",
				Endpoint:          testURL,
				Method:            "GET",
				VerificationState: StateVerified,
				Severity:          report.SeverityMedium,
				Confidence:        report.ConfidenceHigh,
				EvidenceSummary:   "API endpoint permits wildcard (*) CORS origin with Access-Control-Allow-Credentials: true",
				CreatedAt:         time.Now().UTC(),
			}
			cov.Verified++
			cov.Status = CoverageVerifiedIssueFound
			fnd := e.createFinding(actx, r, "API8:2023 Insecure Credentialed CORS Wildcard", r.EvidenceSummary, report.SeverityMedium, 55)
			r.Finding = fnd
			findings = append(findings, *fnd)
			results = append(results, r)
		} else {
			// Standard public API wildcard CORS: informational observation only
			r := Result{
				ID:                uuid.New().String(),
				AssessmentID:      actx.AssessmentID,
				ExecutionID:       actx.ExecutionID,
				Category:          CategoryAPI8_Misconfiguration,
				OWASPCode:         "API8:2023",
				TestName:          "Permissive CORS Wildcard Origin",
				Endpoint:          testURL,
				Method:            "GET",
				VerificationState: StateObserved,
				Severity:          report.SeverityInfo,
				Confidence:        report.ConfidenceHigh,
				EvidenceSummary:   "API endpoint permits uncredentialed wildcard (*) CORS origin (standard for public APIs)",
				CreatedAt:         time.Now().UTC(),
			}
			cov.Observations++
			results = append(results, r)
		}
	}

	// 3. Verbose Error Disclosure Check
	bodyStr := string(bodyBytes)
	hasStackTrace := strings.Contains(bodyStr, "Traceback (most recent call last)") ||
		strings.Contains(bodyStr, "Fatal error:")
	hasSQLErrorHint := strings.Contains(bodyStr, "SQL syntax error") ||
		strings.Contains(bodyStr, "syntax error at or near")

	if hasStackTrace {
		r := Result{
			ID:                uuid.New().String(),
			AssessmentID:      actx.AssessmentID,
			ExecutionID:       actx.ExecutionID,
			Category:          CategoryAPI8_Misconfiguration,
			OWASPCode:         "API8:2023",
			TestName:          "Verbose Server Error / Stack Trace Disclosure",
			Endpoint:          testURL,
			Method:            "GET",
			VerificationState: StateVerified,
			Severity:          report.SeverityLow,
			Confidence:        report.ConfidenceHigh,
			EvidenceSummary:   "Server response disclosed internal stack trace or fatal execution error details",
			CreatedAt:         time.Now().UTC(),
		}
		cov.Verified++
		cov.Status = CoverageVerifiedIssueFound
		fnd := e.createFinding(actx, r, "API8:2023 Verbose Error Disclosure in API Response", r.EvidenceSummary, report.SeverityLow, 25)
		r.Finding = fnd
		findings = append(findings, *fnd)
		results = append(results, r)
	} else if hasSQLErrorHint {
		r := Result{
			ID:                uuid.New().String(),
			AssessmentID:      actx.AssessmentID,
			ExecutionID:       actx.ExecutionID,
			Category:          CategoryAPI8_Misconfiguration,
			OWASPCode:         "API8:2023",
			TestName:          "Database Error Syntax Indicator",
			Endpoint:          testURL,
			Method:            "GET",
			VerificationState: StateCandidate,
			Severity:          report.SeverityLow,
			Confidence:        report.ConfidenceMedium,
			EvidenceSummary:   "Server response revealed raw database error syntax details; candidate disclosure (SQL injection exploitability unverified)",
			CreatedAt:         time.Now().UTC(),
		}
		cov.Candidates++
		results = append(results, r)
	}

	cov.Explanation = fmt.Sprintf("Audited security headers, CORS policies, and error disclosure on %s", testURL)
	return results, findings, cov
}

// --- Category 9: API9 (Improper Inventory Management) ---
func (e *Engine) assessAPI9(actx *AssessmentContext) ([]Result, []report.Finding, CategoryCoverage) {
	cov := CategoryCoverage{
		Category: CategoryAPI9_ImproperInventory,
		Code:     OWASPCategoryMetadata[CategoryAPI9_ImproperInventory].Code,
		Name:     OWASPCategoryMetadata[CategoryAPI9_ImproperInventory].Name,
		Status:   CoveragePassivelyAssessed,
	}

	var results []Result
	var findings []report.Finding

	// Check 1: Shadow Endpoints (discovered vs declared spec)
	if actx.DeclaredSpec != nil && len(actx.DeclaredSpec.Endpoints) > 0 {
		cov.Status = CoverageActivelyTested
		var shadowEndpoints []APIEndpoint
		for _, ep := range actx.Endpoints {
			key := fmt.Sprintf("%s:%s", ep.Method, strings.ToLower(ep.Path))
			if _, declared := actx.DeclaredSpec.Endpoints[key]; !declared {
				shadowEndpoints = append(shadowEndpoints, ep)
			}
		}

		if len(shadowEndpoints) > 0 {
			cov.Candidates += len(shadowEndpoints)
			for _, sep := range shadowEndpoints {
				r := Result{
					ID:                uuid.New().String(),
					AssessmentID:      actx.AssessmentID,
					ExecutionID:       actx.ExecutionID,
					Category:          CategoryAPI9_ImproperInventory,
					OWASPCode:         "API9:2023",
					TestName:          "Undocumented API Endpoint Drift",
					Endpoint:          sep.Path,
					Method:            sep.Method,
					VerificationState: StateCandidate,
					Severity:          report.SeverityInfo,
					Confidence:        report.ConfidenceHigh,
					EvidenceSummary:   fmt.Sprintf("Discovered API endpoint %s %s was absent from declared API specification (spec drift / undocumented route)", sep.Method, sep.Path),
					CreatedAt:         time.Now().UTC(),
				}
				results = append(results, r)
			}
		}
	}

	// Check 2: Outdated / Deprecated API Version Coexistence
	versionsSeen := make(map[string]int)
	for _, ep := range actx.Endpoints {
		if ep.Version != "" {
			versionsSeen[ep.Version]++
		}
	}

	if len(versionsSeen) > 1 {
		var vList []string
		for v := range versionsSeen {
			vList = append(vList, v)
		}
		cov.Observations++
		r := Result{
			ID:                uuid.New().String(),
			AssessmentID:      actx.AssessmentID,
			ExecutionID:       actx.ExecutionID,
			Category:          CategoryAPI9_ImproperInventory,
			OWASPCode:         "API9:2023",
			TestName:          "Multiple API Versions Concurrently Exposed",
			Endpoint:          actx.BaseURL,
			Method:            "GET",
			VerificationState: StateObserved,
			Severity:          report.SeverityInfo,
			Confidence:        report.ConfidenceHigh,
			EvidenceSummary:   fmt.Sprintf("Observed multiple concurrent API versions (%s); audit older versions for missing security controls", strings.Join(vList, ", ")),
			CreatedAt:         time.Now().UTC(),
		}
		results = append(results, r)
	}

	cov.TestsRun = len(actx.Endpoints)
	cov.Explanation = fmt.Sprintf("Analyzed %d discovered endpoints for inventory discrepancies and version coexistence (%d candidate drift, %d observations)", len(actx.Endpoints), cov.Candidates, cov.Observations)
	return results, findings, cov
}

// --- Category 10: API10 (Unsafe Consumption of APIs) ---
func (e *Engine) assessAPI10(ctx context.Context, actx *AssessmentContext) ([]Result, []report.Finding, CategoryCoverage) {
	cov := CategoryCoverage{
		Category: CategoryAPI10_UnsafeConsumption,
		Code:     OWASPCategoryMetadata[CategoryAPI10_UnsafeConsumption].Code,
		Name:     OWASPCategoryMetadata[CategoryAPI10_UnsafeConsumption].Name,
		Status:   CoveragePassivelyAssessed,
	}

	var results []Result
	var findings []report.Finding

	// Identify third-party API integration references in JavaScript or endpoint declarations
	var externalIntegrations []string
	knownThirdParties := []string{"stripe.com", "api.github.com", "googleapis.com", "twilio.com", "sendgrid.com", "paypal.com"}

	for _, ep := range actx.Endpoints {
		lowerPath := strings.ToLower(ep.Path)
		for _, tp := range knownThirdParties {
			if strings.Contains(lowerPath, tp) {
				externalIntegrations = append(externalIntegrations, ep.Path)
			}
		}
	}

	cov.TestsRun = len(externalIntegrations)
	if len(externalIntegrations) > 0 {
		cov.Observations = len(externalIntegrations)
		r := Result{
			ID:                uuid.New().String(),
			AssessmentID:      actx.AssessmentID,
			ExecutionID:       actx.ExecutionID,
			Category:          CategoryAPI10_UnsafeConsumption,
			OWASPCode:         "API10:2023",
			TestName:          "Third-Party API Integration Observation",
			Endpoint:          externalIntegrations[0],
			Method:            "GET",
			VerificationState: StateObserved,
			Severity:          report.SeverityInfo,
			Confidence:        report.ConfidenceHigh,
			EvidenceSummary:   fmt.Sprintf("Identified %d third-party partner integration endpoints (%s); informational architectural observation", len(externalIntegrations), strings.Join(externalIntegrations, ", ")),
			CreatedAt:         time.Now().UTC(),
		}
		results = append(results, r)
		cov.Explanation = fmt.Sprintf("Observed %d third-party API integrations (external probing withheld for safety)", len(externalIntegrations))
	} else {
		cov.Explanation = "No external third-party API integration points identified"
	}

	return results, findings, cov
}

func (e *Engine) createFinding(
	actx *AssessmentContext,
	r Result,
	title string,
	description string,
	severity string,
	score int,
) *report.Finding {
	sanitizedEndpoint := SanitizeURL(r.Endpoint)
	sanitizedTarget := SanitizeURL(actx.BaseURL)

	fpData := fmt.Sprintf("%s|%s|%s|%s", r.Category, r.Method, sanitizedEndpoint, r.TestName)
	hash := sha256.Sum256([]byte(fpData))
	fingerprint := fmt.Sprintf("apisec-%x", hash[:8])

	conf := r.Confidence
	if conf == "" {
		conf = report.ConfidenceHigh
	}

	return &report.Finding{
		ID:          uuid.New().String(),
		Title:       title,
		Category:    fmt.Sprintf("OWASP %s / %s", r.OWASPCode, OWASPCategoryMetadata[r.Category].Name),
		Severity:    severity,
		Confidence:  conf,
		Target:      sanitizedTarget,
		Endpoint:    sanitizedEndpoint,
		Method:      r.Method,
		Description: description,
		Evidence:    r.EvidenceSummary,
		EvidenceDetails: report.EvidenceDetails{
			Observation:     r.EvidenceSummary,
			Location:        sanitizedEndpoint,
			HTTPMethod:      r.Method,
			HTTPStatus:      r.ObservedStatus,
			DetectionMethod: "OWASP_API_SECURITY_PIPELINE",
			Details: map[string]string{
				"owasp_category": string(r.Category),
				"owasp_code":     r.OWASPCode,
				"test_name":      r.TestName,
			},
		},
		Verification: report.VerificationRecord{
			Status:    report.VerificationStatus(r.VerificationState),
			Result:    string(r.VerificationState),
			Rationale: r.EvidenceSummary,
		},
		Source:      "api_security_engine",
		Fingerprint: fingerprint,
		Score:       score,
	}
}

func (e *Engine) compileSummary(results []Result, coverage map[string]CategoryCoverage) *Summary {
	sum := &Summary{
		TotalTests:        len(results),
		CategoriesCovered: len(coverage),
		CoverageMap:       coverage,
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
		case StateNotVulnerable:
			sum.NotVulnerableCount++
		}
	}

	// Ensure CoverageVerifiedIssueFound is ONLY set when verified findings actually exist
	for catKey, cov := range coverage {
		if cov.Status == CoverageVerifiedIssueFound && cov.Verified == 0 {
			if cov.TestsRun > 0 {
				cov.Status = CoverageActivelyTested
			} else {
				cov.Status = CoveragePassivelyAssessed
			}
			coverage[catKey] = cov
		}
	}

	return sum
}

var dnsLookupIPHook = func(host string) ([]net.IP, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	return net.DefaultResolver.LookupIP(ctx, "ip", host)
}

var nonGlobalCIDRs []*net.IPNet

func init() {
	cidrs := []string{
		// IPv4
		"0.0.0.0/8",          // Current network ("this" network)
		"10.0.0.0/8",         // Private-use (RFC 1918)
		"100.64.0.0/10",      // Shared address space (CGNAT, RFC 6598)
		"127.0.0.0/8",        // Loopback (RFC 1122)
		"169.254.0.0/16",     // Link-local (RFC 3927)
		"172.16.0.0/12",      // Private-use (RFC 1918)
		"192.0.0.0/24",       // IETF Protocol Assignments (RFC 6890)
		"192.0.2.0/24",       // Documentation TEST-NET-1 (RFC 5737)
		"192.88.99.0/24",     // 6to4 Relay Anycast (RFC 7526)
		"192.168.0.0/16",     // Private-use (RFC 1918)
		"198.18.0.0/15",      // Benchmarking (RFC 2544)
		"198.51.100.0/24",    // Documentation TEST-NET-2 (RFC 5737)
		"203.0.113.0/24",     // Documentation TEST-NET-3 (RFC 5737)
		"224.0.0.0/4",        // Multicast (RFC 5771)
		"240.0.0.0/4",        // Reserved (RFC 1112)
		"255.255.255.255/32", // Limited Broadcast (RFC 8190)

		// IPv6
		"::/128",        // Unspecified
		"::1/128",       // Loopback
		"64:ff9b::/96",  // IPv4-IPv6 translation
		"100::/64",      // Discard-only
		"2001::/23",     // IETF protocol assignments
		"2001:db8::/32", // Documentation
		"fc00::/7",      // Unique Local Address (ULA, RFC 4193)
		"fe80::/10",     // Link-Local Unicast (RFC 4291)
		"ff00::/8",      // Multicast (RFC 4291)
	}
	for _, c := range cidrs {
		_, block, err := net.ParseCIDR(c)
		if err == nil {
			nonGlobalCIDRs = append(nonGlobalCIDRs, block)
		}
	}
}

func isPrivateOrNonGlobalIP(ip net.IP) bool {
	if ip == nil {
		return true
	}
	if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
		ip.IsInterfaceLocalMulticast() || ip.IsMulticast() || ip.IsUnspecified() || ip.IsPrivate() {
		return true
	}
	if ip4 := ip.To4(); ip4 != nil {
		for _, block := range nonGlobalCIDRs {
			if block.IP.To4() != nil && block.Contains(ip4) {
				return true
			}
		}
		return false
	}
	// Native IPv6
	for _, block := range nonGlobalCIDRs {
		if block.IP.To4() == nil && block.Contains(ip) {
			return true
		}
	}
	return false
}

func isInternalAddress(rawURL string) bool {
	return IsInternalOrUnsafeAddress(rawURL)
}

// IsInternalOrUnsafeAddress evaluates whether rawURL targets a private, loopback, link-local,
// reserved, or unsafe internal destination. It returns true if the address is internal or unsafe.
func IsInternalOrUnsafeAddress(rawURL string) bool {
	if rawURL == "" {
		return true
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return true
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme != "http" && scheme != "https" {
		return true
	}
	host := strings.ToLower(u.Hostname())
	if host == "" {
		return true
	}
	host = strings.TrimPrefix(strings.TrimSuffix(host, "]"), "[")

	// Hostname safety blacklist
	if host == "localhost" ||
		strings.HasSuffix(host, ".localhost") ||
		strings.HasSuffix(host, ".local") ||
		strings.HasSuffix(host, ".internal") ||
		strings.HasSuffix(host, ".lan") ||
		strings.HasSuffix(host, ".corp") ||
		strings.HasSuffix(host, ".home") ||
		strings.HasSuffix(host, ".intranet") ||
		host == "metadata.google.internal" ||
		host == "instance-data" ||
		host == "metadata" {
		return true
	}

	// Dword/integer IPv4 parsing (e.g. 2130706433 or 0x7f000001 or 017700000001)
	if val, err := strconv.ParseUint(host, 0, 64); err == nil && val <= 0xFFFFFFFF {
		ip := net.IPv4(byte(val>>24), byte(val>>16), byte(val>>8), byte(val))
		if isPrivateOrNonGlobalIP(ip) {
			return true
		}
	}

	// Dotted numeric parsing (e.g. 0177.0.0.1)
	parts := strings.Split(host, ".")
	if len(parts) == 4 {
		var octets [4]byte
		parsedAll := true
		for i, part := range parts {
			val, err := strconv.ParseUint(part, 0, 8)
			if err != nil {
				parsedAll = false
				break
			}
			octets[i] = byte(val)
		}
		if parsedAll {
			ip := net.IPv4(octets[0], octets[1], octets[2], octets[3])
			if isPrivateOrNonGlobalIP(ip) {
				return true
			}
		}
	}

	// Direct IP address check
	if ip := net.ParseIP(host); ip != nil {
		return isPrivateOrNonGlobalIP(ip)
	}

	// Hostname DNS resolution
	if dnsLookupIPHook != nil {
		if ips, err := dnsLookupIPHook(host); err == nil && len(ips) > 0 {
			for _, ip := range ips {
				if isPrivateOrNonGlobalIP(ip) {
					return true
				}
			}
		}
	}

	return false
}
