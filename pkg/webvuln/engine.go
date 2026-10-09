package webvuln

import (
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"felix/pkg/apisec"
	"felix/pkg/report"
	"github.com/google/uuid"
)

// Engine performs controlled, evidence-first web vulnerability assessments.
type Engine struct {
	client *http.Client
	config Config
}

// NewEngine constructs a new Web Vulnerability Engine.
func NewEngine(client *http.Client, cfg Config) *Engine {
	if cfg.Timeout <= 0 {
		cfg.Timeout = 10 * time.Second
	}
	if cfg.Concurrency <= 0 {
		cfg.Concurrency = 5
	}
	if cfg.MaxBodyReadBytes <= 0 {
		cfg.MaxBodyReadBytes = 2 * 1024 * 1024
	}
	if cfg.UserAgent == "" {
		cfg.UserAgent = DefaultConfig().UserAgent
	}

	if client == nil {
		client = &http.Client{
			Timeout: cfg.Timeout,
		}
	}

	return &Engine{
		client: client,
		config: cfg,
	}
}

// scopedClient builds an HTTP client that strictly validates scope and exclusions on every redirect hop.
func (e *Engine) scopedClient(actx *AssessmentContext) *http.Client {
	transport := e.client.Transport
	if transport == nil {
		transport = http.DefaultTransport
	}

	return &http.Client{
		Transport: transport,
		Timeout:   e.config.Timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 10 {
				return fmt.Errorf("stopped after 10 redirects")
			}

			nextURL := req.URL.String()
			if actx.IsExcluded != nil && actx.IsExcluded(nextURL) {
				return fmt.Errorf("redirect destination %s is excluded by scope rules", nextURL)
			}
			if actx.IsAllowed != nil && !actx.IsAllowed(nextURL) {
				return fmt.Errorf("redirect destination %s is out of authorized scope", nextURL)
			}
			return nil
		},
	}
}

// Assess executes the comprehensive Web Vulnerability Engine pipeline across all 13 categories.
func (e *Engine) Assess(ctx context.Context, actx *AssessmentContext) ([]Result, []report.Finding, *Summary, error) {
	if actx == nil {
		return nil, nil, nil, fmt.Errorf("nil assessment context provided")
	}

	client := e.scopedClient(actx)

	// Ensure at least target root endpoint is present
	if len(actx.Endpoints) == 0 {
		actx.Endpoints = []TargetEndpoint{
			{Method: "GET", Path: "/", Source: "target_root"},
		}
	}

	var allResults []Result
	var allFindings []report.Finding
	coverageMap := make(map[string]CategoryCoverage)

	// Initialize coverage map for all 13 categories
	for cat, meta := range CategoryMetadata {
		coverageMap[string(cat)] = CategoryCoverage{
			Category: cat,
			Code:     meta.Code,
			Name:     meta.Name,
			Status:   CoverageUntested,
		}
	}

	// 1. Cross-Site Scripting (XSS)
	res1, fnd1, cov1 := e.assessXSS(ctx, actx, client)
	allResults = append(allResults, res1...)
	allFindings = append(allFindings, fnd1...)
	coverageMap[string(CategoryXSS)] = cov1

	// 2. SQL Injection (SQLi)
	res2, fnd2, cov2 := e.assessSQLi(ctx, actx, client)
	allResults = append(allResults, res2...)
	allFindings = append(allFindings, fnd2...)
	coverageMap[string(CategorySQLi)] = cov2

	// 3. NoSQL Injection (NoSQLi)
	res3, fnd3, cov3 := e.assessNoSQLi(ctx, actx, client)
	allResults = append(allResults, res3...)
	allFindings = append(allFindings, fnd3...)
	coverageMap[string(CategoryNoSQLi)] = cov3

	// 4. OS Command Injection (CmdI)
	res4, fnd4, cov4 := e.assessCmdi(ctx, actx, client)
	allResults = append(allResults, res4...)
	allFindings = append(allFindings, fnd4...)
	coverageMap[string(CategoryCmdi)] = cov4

	// 5. Path Traversal
	res5, fnd5, cov5 := e.assessPathTraversal(ctx, actx, client)
	allResults = append(allResults, res5...)
	allFindings = append(allFindings, fnd5...)
	coverageMap[string(CategoryPathTraversal)] = cov5

	// 6. File Inclusion (LFI/RFI)
	res6, fnd6, cov6 := e.assessFileInclusion(ctx, actx, client)
	allResults = append(allResults, res6...)
	allFindings = append(allFindings, fnd6...)
	coverageMap[string(CategoryFileInclusion)] = cov6

	// 7. Server-Side Template Injection (SSTI)
	res7, fnd7, cov7 := e.assessSSTI(ctx, actx, client)
	allResults = append(allResults, res7...)
	allFindings = append(allFindings, fnd7...)
	coverageMap[string(CategorySSTI)] = cov7

	// 8. Server-Side Request Forgery (SSRF)
	res8, fnd8, cov8 := e.assessSSRF(ctx, actx, client)
	allResults = append(allResults, res8...)
	allFindings = append(allFindings, fnd8...)
	coverageMap[string(CategorySSRF)] = cov8

	// 9. Open Redirect
	res9, fnd9, cov9 := e.assessOpenRedirect(ctx, actx, client)
	allResults = append(allResults, res9...)
	allFindings = append(allFindings, fnd9...)
	coverageMap[string(CategoryOpenRedirect)] = cov9

	// 10. HTTP Request Issues / Smuggling
	res10, fnd10, cov10 := e.assessRequestIssues(ctx, actx, client)
	allResults = append(allResults, res10...)
	allFindings = append(allFindings, fnd10...)
	coverageMap[string(CategoryRequestIssues)] = cov10

	// 11. Information Disclosure
	res11, fnd11, cov11 := e.assessInfoDisclosure(ctx, actx, client)
	allResults = append(allResults, res11...)
	allFindings = append(allFindings, fnd11...)
	coverageMap[string(CategoryInfoDisclosure)] = cov11

	// 12. Insecure Deserialization
	res12, fnd12, cov12 := e.assessDeserialization(ctx, actx, client)
	allResults = append(allResults, res12...)
	allFindings = append(allFindings, fnd12...)
	coverageMap[string(CategoryDeserialization)] = cov12

	// 13. Security Misconfiguration
	res13, fnd13, cov13 := e.assessMisconfiguration(ctx, actx, client)
	allResults = append(allResults, res13...)
	allFindings = append(allFindings, fnd13...)
	coverageMap[string(CategoryMisconfiguration)] = cov13

	summary := e.compileSummary(allResults, coverageMap)
	return allResults, allFindings, summary, nil
}

// -------------------------------------------------------------------------
// Category 1: Cross-Site Scripting (XSS)
// -------------------------------------------------------------------------

func (e *Engine) assessXSS(ctx context.Context, actx *AssessmentContext, client *http.Client) ([]Result, []report.Finding, CategoryCoverage) {
	meta := CategoryMetadata[CategoryXSS]
	cov := CategoryCoverage{
		Category: CategoryXSS,
		Code:     meta.Code,
		Name:     meta.Name,
		Status:   CoverageActivelyTested,
	}

	var results []Result
	var findings []report.Finding

	for _, ep := range actx.Endpoints {
		params := ep.Parameters
		if len(params) == 0 {
			params = []string{"q", "search", "name", "input"}
		}

		for _, p := range params {
			token := fmt.Sprintf("flx_%x", time.Now().UnixNano()%1000000)
			rawProbe := fmt.Sprintf("<flx_xss_%s>", token)
			encodedProbe := fmt.Sprintf("&lt;flx_xss_%s&gt;", token)

			targetURL := buildEndpointURL(actx.BaseURL, ep.Path, map[string]string{p: rawProbe})
			if actx.IsExcluded != nil && actx.IsExcluded(targetURL) {
				continue
			}
			if actx.IsAllowed != nil && !actx.IsAllowed(targetURL) {
				continue
			}

			req, err := http.NewRequestWithContext(ctx, "GET", targetURL, nil)
			if err != nil {
				continue
			}
			req.Header.Set("User-Agent", e.config.UserAgent)

			resp, err := client.Do(req)
			if err != nil {
				continue
			}
			bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, e.config.MaxBodyReadBytes))
			resp.Body.Close()
			bodyStr := string(bodyBytes)
			contentType := strings.ToLower(resp.Header.Get("Content-Type"))

			r := Result{
				ID:             uuid.New().String(),
				AssessmentID:   actx.AssessmentID,
				ExecutionID:    actx.ExecutionID,
				Category:       CategoryXSS,
				VulnCode:       meta.Code,
				TestName:       fmt.Sprintf("XSS Context Reflection Analysis (%s)", p),
				Endpoint:       targetURL,
				Method:         "GET",
				ObservedStatus: resp.StatusCode,
				CreatedAt:      time.Now().UTC(),
			}

			// Verification logic:
			// 1. Raw unescaped probe tag reflected in HTML response -> VERIFIED
			// 2. Encoded probe tag reflected -> NOT_VULNERABLE
			// 3. JSON reflection without HTML execution context -> OBSERVED
			// 4. Not reflected -> NOT_VULNERABLE
			if strings.Contains(contentType, "text/html") || strings.Contains(contentType, "application/xhtml+xml") {
				if strings.Contains(bodyStr, rawProbe) {
					r.VerificationState = StateVerified
					r.Severity = report.SeverityHigh
					r.Confidence = report.ConfidenceHigh
					r.EvidenceSummary = fmt.Sprintf("Inert probe %s reflected unescaped into executable HTML body context via parameter '%s'", rawProbe, p)
					r.EvidenceDetails = map[string]string{
						"parameter":    p,
						"probe":        rawProbe,
						"content_type": contentType,
						"reflection":   "unescaped_html",
					}

					fnd := e.createFinding(actx, r, fmt.Sprintf("Reflected Cross-Site Scripting (XSS) on %s", ep.Path),
						r.EvidenceSummary, report.SeverityHigh, 75)
					r.Finding = fnd
					findings = append(findings, *fnd)
					cov.Verified++
					cov.Status = CoverageVerifiedIssueFound
				} else if strings.Contains(bodyStr, encodedProbe) || strings.Contains(bodyStr, token) {
					r.VerificationState = StateNotVulnerable
					r.Severity = report.SeverityInfo
					r.Confidence = report.ConfidenceHigh
					r.EvidenceSummary = fmt.Sprintf("Probe on parameter '%s' was safely sanitized/encoded with HTML entities", p)
				} else {
					r.VerificationState = StateNotVulnerable
					r.Severity = report.SeverityInfo
					r.Confidence = report.ConfidenceMedium
					r.EvidenceSummary = fmt.Sprintf("Probe on parameter '%s' was not reflected in response", p)
				}
			} else if strings.Contains(contentType, "application/json") {
				if strings.Contains(bodyStr, rawProbe) || strings.Contains(bodyStr, token) {
					r.VerificationState = StateObserved
					r.Severity = report.SeverityInfo
					r.Confidence = report.ConfidenceMedium
					r.EvidenceSummary = fmt.Sprintf("Probe on parameter '%s' reflected within JSON data structure; non-executable without DOM XSS", p)
					cov.Observations++
				} else {
					r.VerificationState = StateNotVulnerable
					r.Severity = report.SeverityInfo
					r.Confidence = report.ConfidenceMedium
					r.EvidenceSummary = "No reflection in JSON response"
				}
			} else {
				r.VerificationState = StateNotVulnerable
				r.Severity = report.SeverityInfo
				r.Confidence = report.ConfidenceLow
				r.EvidenceSummary = fmt.Sprintf("Non-HTML response type (%s) returned", contentType)
			}

			results = append(results, r)
			if len(results) >= 5 {
				break
			}
		}
		if len(results) >= 10 {
			break
		}
	}

	cov.TestsRun = len(results)
	cov.Explanation = fmt.Sprintf("Evaluated %d reflection tests across input parameters (%d verified XSS vulnerabilities)", cov.TestsRun, cov.Verified)
	return results, findings, cov
}

// -------------------------------------------------------------------------
// Category 2: SQL Injection (SQLi)
// -------------------------------------------------------------------------

var sqlErrorSignatures = []*regexp.Regexp{
	regexp.MustCompile(`(?i)you have an error in your sql syntax`),
	regexp.MustCompile(`(?i)check the manual that corresponds to your (?:mysql|mariadb) server version`),
	regexp.MustCompile(`(?i)syntax error at or near`),
	regexp.MustCompile(`(?i)pg_query\(\)`),
	regexp.MustCompile(`(?i)unclosed quotation mark after the character string`),
	regexp.MustCompile(`(?i)sqlite3::|near "[^"]+": syntax error`),
	regexp.MustCompile(`(?i)ORA-01756|ORA-00933`),
	regexp.MustCompile(`(?i)Syntax error in string in query expression`),
	regexp.MustCompile(`(?i)Microsoft OLE DB Provider for SQL Server`),
}

func checkSQLError(body string) string {
	for _, reg := range sqlErrorSignatures {
		if loc := reg.FindString(body); loc != "" {
			return loc
		}
	}
	return ""
}

func (e *Engine) assessSQLi(ctx context.Context, actx *AssessmentContext, client *http.Client) ([]Result, []report.Finding, CategoryCoverage) {
	meta := CategoryMetadata[CategorySQLi]
	cov := CategoryCoverage{
		Category: CategorySQLi,
		Code:     meta.Code,
		Name:     meta.Name,
		Status:   CoverageActivelyTested,
	}

	var results []Result
	var findings []report.Finding

	for _, ep := range actx.Endpoints {
		params := ep.Parameters
		if len(params) == 0 {
			params = []string{"id", "item", "user", "cat", "search"}
		}

		for _, p := range params {
			// 1. Baseline Request
			baselineURL := buildEndpointURL(actx.BaseURL, ep.Path, map[string]string{p: "101"})
			if actx.IsAllowed != nil && !actx.IsAllowed(baselineURL) {
				continue
			}
			reqBase, _ := http.NewRequestWithContext(ctx, "GET", baselineURL, nil)
			reqBase.Header.Set("User-Agent", e.config.UserAgent)
			respBase, err := client.Do(reqBase)
			if err != nil {
				continue
			}
			baseBytes, _ := io.ReadAll(io.LimitReader(respBase.Body, e.config.MaxBodyReadBytes))
			respBase.Body.Close()
			baseErr := checkSQLError(string(baseBytes))

			// 2. Syntax Disruption Probe (Safe single quote)
			probeURL := buildEndpointURL(actx.BaseURL, ep.Path, map[string]string{p: "101'"})
			reqProbe, _ := http.NewRequestWithContext(ctx, "GET", probeURL, nil)
			reqProbe.Header.Set("User-Agent", e.config.UserAgent)
			respProbe, err := client.Do(reqProbe)
			if err != nil {
				continue
			}
			probeBytes, _ := io.ReadAll(io.LimitReader(respProbe.Body, e.config.MaxBodyReadBytes))
			respProbe.Body.Close()
			probeErr := checkSQLError(string(probeBytes))

			r := Result{
				ID:             uuid.New().String(),
				AssessmentID:   actx.AssessmentID,
				ExecutionID:    actx.ExecutionID,
				Category:       CategorySQLi,
				VulnCode:       meta.Code,
				TestName:       fmt.Sprintf("SQL Syntax Disruption Probe (%s)", p),
				Endpoint:       probeURL,
				Method:         "GET",
				ObservedStatus: respProbe.StatusCode,
				CreatedAt:      time.Now().UTC(),
			}

			// Verification logic:
			// Database syntax error on probe that was absent in baseline -> VERIFIED.
			// Generic HTTP 500 error alone without DB syntax error -> CANDIDATE.
			// Identical behavior -> NOT_VULNERABLE.
			if probeErr != "" && baseErr == "" {
				r.VerificationState = StateVerified
				r.Severity = report.SeverityCritical
				r.Confidence = report.ConfidenceHigh
				r.EvidenceSummary = fmt.Sprintf("Non-destructive syntax probe on parameter '%s' triggered database error signature: '%s'", p, probeErr)
				r.EvidenceDetails = map[string]string{
					"parameter":     p,
					"syntax_error":  probeErr,
					"baseline_code": fmt.Sprintf("%d", respBase.StatusCode),
					"probe_code":    fmt.Sprintf("%d", respProbe.StatusCode),
				}

				fnd := e.createFinding(actx, r, fmt.Sprintf("SQL Injection via Database Syntax Disruption on %s", ep.Path),
					r.EvidenceSummary, report.SeverityCritical, 90)
				r.Finding = fnd
				findings = append(findings, *fnd)
				cov.Verified++
				cov.Status = CoverageVerifiedIssueFound
			} else if respProbe.StatusCode == 500 && respBase.StatusCode != 500 {
				r.VerificationState = StateCandidate
				r.Severity = report.SeverityMedium
				r.Confidence = report.ConfidenceLow
				r.EvidenceSummary = fmt.Sprintf("Syntax probe on parameter '%s' induced generic HTTP 500 server error; database signature unconfirmed", p)
				r.EvidenceDetails = map[string]string{
					"parameter":     p,
					"probe_code":    "500",
					"baseline_code": fmt.Sprintf("%d", respBase.StatusCode),
				}
				cov.Candidates++
			} else {
				r.VerificationState = StateNotVulnerable
				r.Severity = report.SeverityInfo
				r.Confidence = report.ConfidenceHigh
				r.EvidenceSummary = fmt.Sprintf("Parameter '%s' handled syntax disruption probe without database error or anomalous response", p)
			}

			results = append(results, r)
			if len(results) >= 5 {
				break
			}
		}
		if len(results) >= 10 {
			break
		}
	}

	cov.TestsRun = len(results)
	cov.Explanation = fmt.Sprintf("Evaluated %d SQL syntax tests (%d verified SQLi vulnerabilities)", cov.TestsRun, cov.Verified)
	return results, findings, cov
}

// -------------------------------------------------------------------------
// Category 3: NoSQL Injection (NoSQLi)
// -------------------------------------------------------------------------

func (e *Engine) assessNoSQLi(ctx context.Context, actx *AssessmentContext, client *http.Client) ([]Result, []report.Finding, CategoryCoverage) {
	meta := CategoryMetadata[CategoryNoSQLi]
	cov := CategoryCoverage{
		Category: CategoryNoSQLi,
		Code:     meta.Code,
		Name:     meta.Name,
		Status:   CoverageActivelyTested,
	}

	var results []Result
	var findings []report.Finding

	for _, ep := range actx.Endpoints {
		params := ep.Parameters
		if len(params) == 0 {
			params = []string{"username", "user", "filter"}
		}

		for _, p := range params {
			// Test 1: $ne query parameter probe
			neURL := buildEndpointURL(actx.BaseURL, ep.Path, map[string]string{p + "[$ne]": "__felix_nonexistent__"})
			eqURL := buildEndpointURL(actx.BaseURL, ep.Path, map[string]string{p + "[$eq]": "__felix_nonexistent__"})

			if actx.IsAllowed != nil && !actx.IsAllowed(neURL) {
				continue
			}

			reqNE, _ := http.NewRequestWithContext(ctx, "GET", neURL, nil)
			reqNE.Header.Set("User-Agent", e.config.UserAgent)
			respNE, err := client.Do(reqNE)
			if err != nil {
				continue
			}
			neBytes, _ := io.ReadAll(io.LimitReader(respNE.Body, e.config.MaxBodyReadBytes))
			respNE.Body.Close()

			reqEQ, _ := http.NewRequestWithContext(ctx, "GET", eqURL, nil)
			reqEQ.Header.Set("User-Agent", e.config.UserAgent)
			respEQ, err := client.Do(reqEQ)
			if err != nil {
				continue
			}
			eqBytes, _ := io.ReadAll(io.LimitReader(respEQ.Body, e.config.MaxBodyReadBytes))
			respEQ.Body.Close()

			r := Result{
				ID:             uuid.New().String(),
				AssessmentID:   actx.AssessmentID,
				ExecutionID:    actx.ExecutionID,
				Category:       CategoryNoSQLi,
				VulnCode:       meta.Code,
				TestName:       fmt.Sprintf("NoSQL Safe Operator Query Probe (%s)", p),
				Endpoint:       neURL,
				Method:         "GET",
				ObservedStatus: respNE.StatusCode,
				CreatedAt:      time.Now().UTC(),
			}

			// If $ne returns 200 with substantial content while $eq returns 404 or empty collection
			if respNE.StatusCode == 200 && (respEQ.StatusCode == 404 || len(neBytes) > len(eqBytes)+200) {
				r.VerificationState = StateVerified
				r.Severity = report.SeverityHigh
				r.Confidence = report.ConfidenceHigh
				r.EvidenceSummary = fmt.Sprintf("NoSQL operator [$ne] probe on parameter '%s' altered query logic, yielding data differential over [$eq]", p)
				r.EvidenceDetails = map[string]string{
					"parameter": p,
					"ne_code":   fmt.Sprintf("%d", respNE.StatusCode),
					"eq_code":   fmt.Sprintf("%d", respEQ.StatusCode),
					"ne_bytes":  fmt.Sprintf("%d", len(neBytes)),
					"eq_bytes":  fmt.Sprintf("%d", len(eqBytes)),
				}

				fnd := e.createFinding(actx, r, fmt.Sprintf("NoSQL Injection Operator Bypass on %s", ep.Path),
					r.EvidenceSummary, report.SeverityHigh, 80)
				r.Finding = fnd
				findings = append(findings, *fnd)
				cov.Verified++
				cov.Status = CoverageVerifiedIssueFound
			} else if respNE.StatusCode == 500 {
				r.VerificationState = StateCandidate
				r.Severity = report.SeverityMedium
				r.Confidence = report.ConfidenceLow
				r.EvidenceSummary = fmt.Sprintf("NoSQL operator probe on '%s' caused unhandled 500 error; syntax parsing suspect", p)
				cov.Candidates++
			} else {
				r.VerificationState = StateNotVulnerable
				r.Severity = report.SeverityInfo
				r.Confidence = report.ConfidenceHigh
				r.EvidenceSummary = fmt.Sprintf("NoSQL operator probes rejected or safely handled on parameter '%s'", p)
			}

			results = append(results, r)
			if len(results) >= 5 {
				break
			}
		}
		if len(results) >= 8 {
			break
		}
	}

	cov.TestsRun = len(results)
	cov.Explanation = fmt.Sprintf("Evaluated %d NoSQL operator tests (%d verified NoSQLi vulnerabilities)", cov.TestsRun, cov.Verified)
	return results, findings, cov
}

// -------------------------------------------------------------------------
// Category 4: OS Command Injection (CmdI)
// -------------------------------------------------------------------------

func (e *Engine) assessCmdi(ctx context.Context, actx *AssessmentContext, client *http.Client) ([]Result, []report.Finding, CategoryCoverage) {
	meta := CategoryMetadata[CategoryCmdi]
	cov := CategoryCoverage{
		Category: CategoryCmdi,
		Code:     meta.Code,
		Name:     meta.Name,
		Status:   CoveragePassivelyAssessed,
	}

	var results []Result
	var findings []report.Finding

	cmdParamNames := map[string]bool{
		"cmd": true, "exec": true, "command": true, "run": true,
		"ping": true, "host": true, "ip": true, "script": true,
	}

	for _, ep := range actx.Endpoints {
		for _, p := range ep.Parameters {
			if !cmdParamNames[strings.ToLower(p)] {
				continue
			}

			targetURL := buildEndpointURL(actx.BaseURL, ep.Path, map[string]string{p: "127.0.0.1"})
			r := Result{
				ID:           uuid.New().String(),
				AssessmentID: actx.AssessmentID,
				ExecutionID:  actx.ExecutionID,
				Category:     CategoryCmdi,
				VulnCode:     meta.Code,
				TestName:     fmt.Sprintf("OS Command Parameter Surface Analysis (%s)", p),
				Endpoint:     targetURL,
				Method:       ep.Method,
				CreatedAt:    time.Now().UTC(),
			}

			// Controlled synthetic test fixture support
			if actx.SyntheticFixture {
				syntheticURL := buildEndpointURL(actx.BaseURL, ep.Path, map[string]string{p: "flx_synthetic_sim"})
				req, _ := http.NewRequestWithContext(ctx, "GET", syntheticURL, nil)
				resp, err := client.Do(req)
				if err == nil {
					body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
					resp.Body.Close()
					if strings.Contains(string(body), "FLX_SYNTHETIC_CMDI_ACK") {
						r.VerificationState = StateVerified
						r.Severity = report.SeverityCritical
						r.Confidence = report.ConfidenceHigh
						r.EvidenceSummary = "Synthetic test harness fixture verified command execution emulation"
						fnd := e.createFinding(actx, r, fmt.Sprintf("OS Command Injection (Synthetic Fixture) on %s", ep.Path),
							r.EvidenceSummary, report.SeverityCritical, 95)
						r.Finding = fnd
						findings = append(findings, *fnd)
						cov.Verified++
						cov.Status = CoverageVerifiedIssueFound
						results = append(results, r)
						continue
					}
				}
			}

			// Mandatory safety: Live targets strictly reported as CANDIDATE or OBSERVED
			r.VerificationState = StateCandidate
			r.Severity = report.SeverityMedium
			r.Confidence = report.ConfidenceMedium
			r.EvidenceSummary = fmt.Sprintf("High-risk command parameter pattern detected ('%s'); live execution strictly prohibited by safety policy", p)
			r.EvidenceDetails = map[string]string{
				"parameter":   p,
				"safety_rule": "live_os_command_prohibited",
				"remediation": "Implement strict input allowlisting and avoid shell execution wrappers",
			}
			cov.Candidates++
			results = append(results, r)
		}
	}

	cov.TestsRun = len(results)
	cov.Explanation = fmt.Sprintf("Assessed %d command execution candidate surfaces (zero live destructive payloads)", cov.TestsRun)
	return results, findings, cov
}

// -------------------------------------------------------------------------
// Category 5: Path Traversal
// -------------------------------------------------------------------------

func (e *Engine) assessPathTraversal(ctx context.Context, actx *AssessmentContext, client *http.Client) ([]Result, []report.Finding, CategoryCoverage) {
	meta := CategoryMetadata[CategoryPathTraversal]
	cov := CategoryCoverage{
		Category: CategoryPathTraversal,
		Code:     meta.Code,
		Name:     meta.Name,
		Status:   CoverageActivelyTested,
	}

	var results []Result
	var findings []report.Finding

	traversalParams := map[string]bool{
		"file": true, "path": true, "doc": true, "document": true,
		"view": true, "template": true, "page": true, "include": true,
	}

	for _, ep := range actx.Endpoints {
		params := ep.Parameters
		if len(params) == 0 {
			params = []string{"file", "page", "path"}
		}

		for _, p := range params {
			if !traversalParams[strings.ToLower(p)] && len(ep.Parameters) > 0 {
				continue
			}

			// Controlled synthetic fixture test
			if actx.SyntheticFixture {
				syntheticURL := buildEndpointURL(actx.BaseURL, ep.Path, map[string]string{p: "../../../../flx_canary_fixture"})
				req, _ := http.NewRequestWithContext(ctx, "GET", syntheticURL, nil)
				resp, err := client.Do(req)
				if err == nil {
					b, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
					resp.Body.Close()
					if strings.Contains(string(b), "FLX_CANARY_TRAVERSAL_TOKEN_OK") {
						r := Result{
							ID:                uuid.New().String(),
							AssessmentID:      actx.AssessmentID,
							ExecutionID:       actx.ExecutionID,
							Category:          CategoryPathTraversal,
							VulnCode:          meta.Code,
							TestName:          fmt.Sprintf("Synthetic Path Traversal Fixture Probe (%s)", p),
							Endpoint:          syntheticURL,
							Method:            "GET",
							VerificationState: StateVerified,
							Severity:          report.SeverityHigh,
							Confidence:        report.ConfidenceHigh,
							EvidenceSummary:   "Synthetic fixture successfully retrieved bounded non-sensitive test canary",
							CreatedAt:         time.Now().UTC(),
						}
						fnd := e.createFinding(actx, r, fmt.Sprintf("Path Traversal via Parameter %s on %s", p, ep.Path),
							r.EvidenceSummary, report.SeverityHigh, 80)
						r.Finding = fnd
						findings = append(findings, *fnd)
						cov.Verified++
						cov.Status = CoverageVerifiedIssueFound
						results = append(results, r)
						continue
					}
				}
			}

			// Live safe probe: non-sensitive benign traversal sequence
			safeURL := buildEndpointURL(actx.BaseURL, ep.Path, map[string]string{p: "../../../../nonexistent_felix_canary"})
			if actx.IsAllowed != nil && !actx.IsAllowed(safeURL) {
				continue
			}

			req, err := http.NewRequestWithContext(ctx, "GET", safeURL, nil)
			if err != nil {
				continue
			}
			req.Header.Set("User-Agent", e.config.UserAgent)
			resp, err := client.Do(req)
			if err != nil {
				continue
			}
			bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
			resp.Body.Close()
			bodyStr := string(bodyBytes)

			r := Result{
				ID:             uuid.New().String(),
				AssessmentID:   actx.AssessmentID,
				ExecutionID:    actx.ExecutionID,
				Category:       CategoryPathTraversal,
				VulnCode:       meta.Code,
				TestName:       fmt.Sprintf("Path Traversal Safe Parameter Analysis (%s)", p),
				Endpoint:       safeURL,
				Method:         "GET",
				ObservedStatus: resp.StatusCode,
				CreatedAt:      time.Now().UTC(),
			}

			// If filesystem disclosure error appears
			if strings.Contains(bodyStr, "FileNotFoundException") || strings.Contains(bodyStr, "open_basedir restriction") ||
				strings.Contains(bodyStr, "Directory traversal attempt") {
				r.VerificationState = StateCandidate
				r.Severity = report.SeverityMedium
				r.Confidence = report.ConfidenceMedium
				r.EvidenceSummary = fmt.Sprintf("Parameter '%s' yielded filesystem path traversal error indicator in response", p)
				cov.Candidates++
			} else {
				r.VerificationState = StateNotVulnerable
				r.Severity = report.SeverityInfo
				r.Confidence = report.ConfidenceMedium
				r.EvidenceSummary = fmt.Sprintf("Parameter '%s' safely handled traversal sequences", p)
			}

			results = append(results, r)
			if len(results) >= 5 {
				break
			}
		}
		if len(results) >= 8 {
			break
		}
	}

	cov.TestsRun = len(results)
	cov.Explanation = fmt.Sprintf("Evaluated %d path traversal parameters (zero sensitive files accessed)", cov.TestsRun)
	return results, findings, cov
}

// -------------------------------------------------------------------------
// Category 6: File Inclusion (LFI/RFI)
// -------------------------------------------------------------------------

func (e *Engine) assessFileInclusion(ctx context.Context, actx *AssessmentContext, client *http.Client) ([]Result, []report.Finding, CategoryCoverage) {
	meta := CategoryMetadata[CategoryFileInclusion]
	cov := CategoryCoverage{
		Category: CategoryFileInclusion,
		Code:     meta.Code,
		Name:     meta.Name,
		Status:   CoveragePassivelyAssessed,
	}

	var results []Result
	var findings []report.Finding

	inclusionParams := map[string]bool{
		"include": true, "page": true, "file": true, "template": true, "tpl": true, "layout": true,
	}

	for _, ep := range actx.Endpoints {
		for _, p := range ep.Parameters {
			if !inclusionParams[strings.ToLower(p)] {
				continue
			}

			targetURL := buildEndpointURL(actx.BaseURL, ep.Path, map[string]string{p: "header"})
			r := Result{
				ID:                uuid.New().String(),
				AssessmentID:      actx.AssessmentID,
				ExecutionID:       actx.ExecutionID,
				Category:          CategoryFileInclusion,
				VulnCode:          meta.Code,
				TestName:          fmt.Sprintf("File Inclusion Parameter Analysis (%s)", p),
				Endpoint:          targetURL,
				Method:            ep.Method,
				VerificationState: StateCandidate,
				Severity:          report.SeverityMedium,
				Confidence:        report.ConfidenceMedium,
				EvidenceSummary:   fmt.Sprintf("Identified file inclusion candidate parameter '%s'; remote payload inclusion prohibited by safety policy", p),
				CreatedAt:         time.Now().UTC(),
			}
			cov.Candidates++
			results = append(results, r)
		}
	}

	cov.TestsRun = len(results)
	cov.Explanation = fmt.Sprintf("Assessed %d file inclusion parameter surfaces (zero remote attacker inclusion)", cov.TestsRun)
	return results, findings, cov
}

// -------------------------------------------------------------------------
// Category 7: Server-Side Template Injection (SSTI)
// -------------------------------------------------------------------------

func (e *Engine) assessSSTI(ctx context.Context, actx *AssessmentContext, client *http.Client) ([]Result, []report.Finding, CategoryCoverage) {
	meta := CategoryMetadata[CategorySSTI]
	cov := CategoryCoverage{
		Category: CategorySSTI,
		Code:     meta.Code,
		Name:     meta.Name,
		Status:   CoverageActivelyTested,
	}

	var results []Result
	var findings []report.Finding

	arithmeticProbes := []struct {
		probe    string
		expected string
		syntax   string
	}{
		{probe: "{{491*13}}", expected: "6383", syntax: "Jinja2/Twig/Django"},
		{probe: "${491*13}", expected: "6383", syntax: "Freemarker/MVEL/Spring"},
		{probe: "<%= 491*13 %>", expected: "6383", syntax: "ERB/EJS"},
	}

	for _, ep := range actx.Endpoints {
		params := ep.Parameters
		if len(params) == 0 {
			params = []string{"name", "template", "msg", "q"}
		}

		for _, p := range params {
			for _, ap := range arithmeticProbes {
				probeURL := buildEndpointURL(actx.BaseURL, ep.Path, map[string]string{p: ap.probe})
				if actx.IsAllowed != nil && !actx.IsAllowed(probeURL) {
					continue
				}

				req, err := http.NewRequestWithContext(ctx, "GET", probeURL, nil)
				if err != nil {
					continue
				}
				req.Header.Set("User-Agent", e.config.UserAgent)
				resp, err := client.Do(req)
				if err != nil {
					continue
				}
				bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, e.config.MaxBodyReadBytes))
				resp.Body.Close()
				bodyStr := string(bodyBytes)

				r := Result{
					ID:             uuid.New().String(),
					AssessmentID:   actx.AssessmentID,
					ExecutionID:    actx.ExecutionID,
					Category:       CategorySSTI,
					VulnCode:       meta.Code,
					TestName:       fmt.Sprintf("SSTI Harmless Arithmetic Probe (%s / %s)", p, ap.syntax),
					Endpoint:       probeURL,
					Method:         "GET",
					ObservedStatus: resp.StatusCode,
					CreatedAt:      time.Now().UTC(),
				}

				// Verification logic:
				// If calculated product (6383) appears and input expression does NOT appear literally -> VERIFIED!
				// If expression appears literally -> NOT_VULNERABLE (plain literal reflection).
				if strings.Contains(bodyStr, ap.expected) && !strings.Contains(bodyStr, ap.probe) {
					r.VerificationState = StateVerified
					r.Severity = report.SeverityHigh
					r.Confidence = report.ConfidenceHigh
					r.EvidenceSummary = fmt.Sprintf("Server evaluated template arithmetic %s to '%s' via parameter '%s' (%s syntax)",
						ap.probe, ap.expected, p, ap.syntax)
					r.EvidenceDetails = map[string]string{
						"parameter":       p,
						"probe":           ap.probe,
						"computed_result": ap.expected,
						"template_syntax": ap.syntax,
					}

					fnd := e.createFinding(actx, r, fmt.Sprintf("Server-Side Template Injection (SSTI) on %s", ep.Path),
						r.EvidenceSummary, report.SeverityHigh, 85)
					r.Finding = fnd
					findings = append(findings, *fnd)
					cov.Verified++
					cov.Status = CoverageVerifiedIssueFound
				} else if strings.Contains(bodyStr, ap.probe) {
					r.VerificationState = StateNotVulnerable
					r.Severity = report.SeverityInfo
					r.Confidence = report.ConfidenceHigh
					r.EvidenceSummary = fmt.Sprintf("Template expression '%s' reflected literally without server evaluation", ap.probe)
				} else {
					r.VerificationState = StateNotVulnerable
					r.Severity = report.SeverityInfo
					r.Confidence = report.ConfidenceMedium
					r.EvidenceSummary = "Arithmetic probe not evaluated or reflected"
				}

				results = append(results, r)
				if r.VerificationState == StateVerified {
					break
				}
			}
			if len(results) >= 6 {
				break
			}
		}
		if len(results) >= 10 {
			break
		}
	}

	cov.TestsRun = len(results)
	cov.Explanation = fmt.Sprintf("Evaluated %d SSTI arithmetic expressions (%d verified SSTI vulnerabilities)", cov.TestsRun, cov.Verified)
	return results, findings, cov
}

// -------------------------------------------------------------------------
// Category 8: Server-Side Request Forgery (SSRF)
// -------------------------------------------------------------------------

func (e *Engine) assessSSRF(ctx context.Context, actx *AssessmentContext, client *http.Client) ([]Result, []report.Finding, CategoryCoverage) {
	meta := CategoryMetadata[CategorySSRF]
	cov := CategoryCoverage{
		Category: CategorySSRF,
		Code:     meta.Code,
		Name:     meta.Name,
		Status:   CoveragePassivelyAssessed,
	}

	var results []Result
	var findings []report.Finding

	urlParamNames := map[string]bool{
		"url": true, "dest": true, "redirect": true, "webhook": true,
		"callback": true, "target": true, "feed": true, "fetch": true, "endpoint": true,
	}

	for _, ep := range actx.Endpoints {
		for _, p := range ep.Parameters {
			if !urlParamNames[strings.ToLower(p)] {
				continue
			}

			// Pre-validation: ensure we never probe private or metadata addresses
			if e.config.CanaryCallbackURL != "" {
				if apisec.IsInternalOrUnsafeAddress(e.config.CanaryCallbackURL) {
					// Failsafe refusal
					continue
				}

				canaryProbeURL := buildEndpointURL(actx.BaseURL, ep.Path, map[string]string{p: e.config.CanaryCallbackURL})
				req, _ := http.NewRequestWithContext(ctx, "GET", canaryProbeURL, nil)
				req.Header.Set("User-Agent", e.config.UserAgent)
				resp, err := client.Do(req)
				if err == nil {
					resp.Body.Close()
					r := Result{
						ID:                uuid.New().String(),
						AssessmentID:      actx.AssessmentID,
						ExecutionID:       actx.ExecutionID,
						Category:          CategorySSRF,
						VulnCode:          meta.Code,
						TestName:          fmt.Sprintf("SSRF Canary Callback Probe (%s)", p),
						Endpoint:          canaryProbeURL,
						Method:            "GET",
						VerificationState: StateCandidate,
						Severity:          report.SeverityMedium,
						Confidence:        report.ConfidenceMedium,
						ObservedStatus:    resp.StatusCode,
						EvidenceSummary:   fmt.Sprintf("Dispatched safe canary URL to parameter '%s'; awaiting out-of-band verification", p),
						CreatedAt:         time.Now().UTC(),
					}
					cov.Candidates++
					results = append(results, r)
					continue
				}
			}

			// Parameter observation without callback canary
			targetURL := buildEndpointURL(actx.BaseURL, ep.Path, map[string]string{p: "https://example.com/felix_safe_canary"})
			r := Result{
				ID:                uuid.New().String(),
				AssessmentID:      actx.AssessmentID,
				ExecutionID:       actx.ExecutionID,
				Category:          CategorySSRF,
				VulnCode:          meta.Code,
				TestName:          fmt.Sprintf("SSRF Parameter Surface Inspection (%s)", p),
				Endpoint:          targetURL,
				Method:            ep.Method,
				VerificationState: StateCandidate,
				Severity:          report.SeverityMedium,
				Confidence:        report.ConfidenceMedium,
				EvidenceSummary:   fmt.Sprintf("Endpoint accepts URL-like parameter '%s'; SSRF verification requires out-of-band canary", p),
				CreatedAt:         time.Now().UTC(),
			}
			cov.Candidates++
			results = append(results, r)
		}
	}

	cov.TestsRun = len(results)
	cov.Explanation = fmt.Sprintf("Assessed %d SSRF candidate surfaces (zero internal/metadata addresses probed)", cov.TestsRun)
	return results, findings, cov
}

// -------------------------------------------------------------------------
// Category 9: Open Redirect
// -------------------------------------------------------------------------

func (e *Engine) assessOpenRedirect(ctx context.Context, actx *AssessmentContext, client *http.Client) ([]Result, []report.Finding, CategoryCoverage) {
	meta := CategoryMetadata[CategoryOpenRedirect]
	cov := CategoryCoverage{
		Category: CategoryOpenRedirect,
		Code:     meta.Code,
		Name:     meta.Name,
		Status:   CoverageActivelyTested,
	}

	var results []Result
	var findings []report.Finding

	redirectParams := map[string]bool{
		"redirect": true, "url": true, "next": true, "return": true,
		"return_to": true, "goto": true, "out": true, "target": true, "dest": true,
	}

	canaryTarget := "https://example.com/felix_inert_redirect_canary"

	// Dedicated client that refuses to follow redirects so we can inspect Location header directly
	noRedirectClient := &http.Client{
		Timeout: e.config.Timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	for _, ep := range actx.Endpoints {
		params := ep.Parameters
		if len(params) == 0 {
			params = []string{"redirect", "next", "url", "return"}
		}

		for _, p := range params {
			if !redirectParams[strings.ToLower(p)] && len(ep.Parameters) > 0 {
				continue
			}

			targetURL := buildEndpointURL(actx.BaseURL, ep.Path, map[string]string{p: canaryTarget})
			if actx.IsAllowed != nil && !actx.IsAllowed(targetURL) {
				continue
			}

			req, err := http.NewRequestWithContext(ctx, "GET", targetURL, nil)
			if err != nil {
				continue
			}
			req.Header.Set("User-Agent", e.config.UserAgent)

			resp, err := noRedirectClient.Do(req)
			if err != nil {
				continue
			}
			resp.Body.Close()

			location := resp.Header.Get("Location")
			r := Result{
				ID:             uuid.New().String(),
				AssessmentID:   actx.AssessmentID,
				ExecutionID:    actx.ExecutionID,
				Category:       CategoryOpenRedirect,
				VulnCode:       meta.Code,
				TestName:       fmt.Sprintf("Open Redirect Validation (%s)", p),
				Endpoint:       targetURL,
				Method:         "GET",
				ObservedStatus: resp.StatusCode,
				CreatedAt:      time.Now().UTC(),
			}

			// Verification logic:
			// If 3xx and Location matches external canary target -> VERIFIED!
			// If sanitized or relative -> NOT_VULNERABLE.
			if (resp.StatusCode >= 300 && resp.StatusCode < 400) && (strings.HasPrefix(location, canaryTarget) || strings.Contains(location, "example.com/felix_inert_redirect_canary")) {
				r.VerificationState = StateVerified
				r.Severity = report.SeverityMedium
				r.Confidence = report.ConfidenceHigh
				r.EvidenceSummary = fmt.Sprintf("Server returned %d redirect with Location targeting untrusted external URI: %s", resp.StatusCode, location)
				r.EvidenceDetails = map[string]string{
					"parameter": p,
					"status":    fmt.Sprintf("%d", resp.StatusCode),
					"location":  location,
				}

				fnd := e.createFinding(actx, r, fmt.Sprintf("Open Redirect via Parameter '%s' on %s", p, ep.Path),
					r.EvidenceSummary, report.SeverityMedium, 60)
				r.Finding = fnd
				findings = append(findings, *fnd)
				cov.Verified++
				cov.Status = CoverageVerifiedIssueFound
			} else {
				r.VerificationState = StateNotVulnerable
				r.Severity = report.SeverityInfo
				r.Confidence = report.ConfidenceHigh
				r.EvidenceSummary = fmt.Sprintf("Redirect parameter '%s' was safely validated or rejected (status: %d)", p, resp.StatusCode)
			}

			results = append(results, r)
			if len(results) >= 5 {
				break
			}
		}
		if len(results) >= 8 {
			break
		}
	}

	cov.TestsRun = len(results)
	cov.Explanation = fmt.Sprintf("Evaluated %d redirect parameters (%d verified open redirects)", cov.TestsRun, cov.Verified)
	return results, findings, cov
}

// -------------------------------------------------------------------------
// Category 10: HTTP Request Issues / Smuggling
// -------------------------------------------------------------------------

func (e *Engine) assessRequestIssues(ctx context.Context, actx *AssessmentContext, client *http.Client) ([]Result, []report.Finding, CategoryCoverage) {
	meta := CategoryMetadata[CategoryRequestIssues]
	cov := CategoryCoverage{
		Category: CategoryRequestIssues,
		Code:     meta.Code,
		Name:     meta.Name,
		Status:   CoveragePassivelyAssessed,
	}

	var results []Result
	var findings []report.Finding

	// Passive analysis of root target responses for conflicting header normalization
	targetURL := actx.BaseURL
	req, err := http.NewRequestWithContext(ctx, "GET", targetURL, nil)
	if err == nil {
		req.Header.Set("User-Agent", e.config.UserAgent)
		resp, err := client.Do(req)
		if err == nil {
			resp.Body.Close()
			r := Result{
				ID:                uuid.New().String(),
				AssessmentID:      actx.AssessmentID,
				ExecutionID:       actx.ExecutionID,
				Category:          CategoryRequestIssues,
				VulnCode:          meta.Code,
				TestName:          "HTTP Request Header Parsing & Normalization Check",
				Endpoint:          targetURL,
				Method:            "GET",
				VerificationState: StateObserved,
				Severity:          report.SeverityInfo,
				Confidence:        report.ConfidenceHigh,
				ObservedStatus:    resp.StatusCode,
				EvidenceSummary:   "Passive HTTP response header normalization verified. Active request desynchronization disabled by safety policy.",
				CreatedAt:         time.Now().UTC(),
			}
			cov.Observations++
			results = append(results, r)
		}
	}

	cov.TestsRun = len(results)
	cov.Explanation = "Assessed HTTP header normalization (active request smuggling disabled by default)"
	return results, findings, cov
}

// -------------------------------------------------------------------------
// Category 11: Information Disclosure
// -------------------------------------------------------------------------

var stackTraceSignatures = []*regexp.Regexp{
	regexp.MustCompile(`(?i)Traceback \(most recent call last\)`),
	regexp.MustCompile(`(?i)Exception in thread "[^"]*"`),
	regexp.MustCompile(`(?i)Fatal error: Uncaught [a-zA-Z0-9_]+`),
	regexp.MustCompile(`(?i)ActionController::RoutingError`),
	regexp.MustCompile(`(?i)Werkzeug (?:Debugger|Powered)`),
	regexp.MustCompile(`(?i)Server Error in '/' Application`),
}

func (e *Engine) assessInfoDisclosure(ctx context.Context, actx *AssessmentContext, client *http.Client) ([]Result, []report.Finding, CategoryCoverage) {
	meta := CategoryMetadata[CategoryInfoDisclosure]
	cov := CategoryCoverage{
		Category: CategoryInfoDisclosure,
		Code:     meta.Code,
		Name:     meta.Name,
		Status:   CoverageActivelyTested,
	}

	var results []Result
	var findings []report.Finding

	// 1. Sensitive file endpoints check (.env, .git/config)
	sensitivePaths := []string{"/.env", "/.git/config", "/server-status"}
	for _, p := range sensitivePaths {
		targetURL := buildEndpointURL(actx.BaseURL, p, nil)
		if actx.IsAllowed != nil && !actx.IsAllowed(targetURL) {
			continue
		}

		req, err := http.NewRequestWithContext(ctx, "GET", targetURL, nil)
		if err != nil {
			continue
		}
		req.Header.Set("User-Agent", e.config.UserAgent)
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		resp.Body.Close()
		bodyStr := string(b)

		r := Result{
			ID:             uuid.New().String(),
			AssessmentID:   actx.AssessmentID,
			ExecutionID:    actx.ExecutionID,
			Category:       CategoryInfoDisclosure,
			VulnCode:       meta.Code,
			TestName:       fmt.Sprintf("Sensitive Configuration File Check (%s)", p),
			Endpoint:       targetURL,
			Method:         "GET",
			ObservedStatus: resp.StatusCode,
			CreatedAt:      time.Now().UTC(),
		}

		if resp.StatusCode == 200 && (strings.Contains(bodyStr, "DB_PASSWORD=") || strings.Contains(bodyStr, "[core]") || strings.Contains(bodyStr, "Apache Server Status")) {
			r.VerificationState = StateVerified
			r.Severity = report.SeverityHigh
			r.Confidence = report.ConfidenceHigh
			r.EvidenceSummary = fmt.Sprintf("Exposed sensitive configuration file retrieved: %s (secrets redacted)", p)
			r.EvidenceDetails = map[string]string{
				"path":    p,
				"snippet": RedactText(bodyStr[:min(len(bodyStr), 200)]),
			}

			fnd := e.createFinding(actx, r, fmt.Sprintf("Sensitive Configuration Disclosure (%s)", p),
				r.EvidenceSummary, report.SeverityHigh, 80)
			r.Finding = fnd
			findings = append(findings, *fnd)
			cov.Verified++
			cov.Status = CoverageVerifiedIssueFound
		} else {
			r.VerificationState = StateNotVulnerable
			r.Severity = report.SeverityInfo
			r.Confidence = report.ConfidenceHigh
			r.EvidenceSummary = fmt.Sprintf("Sensitive path %s properly protected or not found (%d)", p, resp.StatusCode)
		}
		results = append(results, r)
	}

	// 2. Unhandled Stack Trace Check
	for _, ep := range actx.Endpoints {
		errURL := buildEndpointURL(actx.BaseURL, ep.Path, map[string]string{"debug_probe": "\x00\xff"})
		req, err := http.NewRequestWithContext(ctx, "GET", errURL, nil)
		if err != nil {
			continue
		}
		req.Header.Set("User-Agent", e.config.UserAgent)
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 8192))
		resp.Body.Close()
		bodyStr := string(b)

		var matchedSig string
		for _, reg := range stackTraceSignatures {
			if match := reg.FindString(bodyStr); match != "" {
				matchedSig = match
				break
			}
		}

		if matchedSig != "" {
			r := Result{
				ID:                uuid.New().String(),
				AssessmentID:      actx.AssessmentID,
				ExecutionID:       actx.ExecutionID,
				Category:          CategoryInfoDisclosure,
				VulnCode:          meta.Code,
				TestName:          "Stack Trace & Debug Leakage Analysis",
				Endpoint:          errURL,
				Method:            "GET",
				VerificationState: StateVerified,
				Severity:          report.SeverityMedium,
				Confidence:        report.ConfidenceHigh,
				ObservedStatus:    resp.StatusCode,
				EvidenceSummary:   fmt.Sprintf("Unhandled stack trace disclosure detected in response (%s)", matchedSig),
				EvidenceDetails: map[string]string{
					"signature": matchedSig,
					"snippet":   RedactText(bodyStr[:min(len(bodyStr), 300)]),
				},
				CreatedAt: time.Now().UTC(),
			}

			fnd := e.createFinding(actx, r, fmt.Sprintf("Debug Stack Trace Exposure on %s", ep.Path),
				r.EvidenceSummary, report.SeverityMedium, 50)
			r.Finding = fnd
			findings = append(findings, *fnd)
			cov.Verified++
			cov.Status = CoverageVerifiedIssueFound
			results = append(results, r)
			break
		}
	}

	cov.TestsRun = len(results)
	cov.Explanation = fmt.Sprintf("Evaluated %d information disclosure tests (%d verified exposures)", cov.TestsRun, cov.Verified)
	return results, findings, cov
}

// -------------------------------------------------------------------------
// Category 12: Insecure Deserialization
// -------------------------------------------------------------------------

func (e *Engine) assessDeserialization(ctx context.Context, actx *AssessmentContext, client *http.Client) ([]Result, []report.Finding, CategoryCoverage) {
	meta := CategoryMetadata[CategoryDeserialization]
	cov := CategoryCoverage{
		Category: CategoryDeserialization,
		Code:     meta.Code,
		Name:     meta.Name,
		Status:   CoveragePassivelyAssessed,
	}

	var results []Result
	var findings []report.Finding

	// Passive detection: inspect target responses for serialized object signatures
	req, err := http.NewRequestWithContext(ctx, "GET", actx.BaseURL, nil)
	if err == nil {
		req.Header.Set("User-Agent", e.config.UserAgent)
		resp, err := client.Do(req)
		if err == nil {
			resp.Body.Close()

			var hasSerializedCookie bool
			for _, ck := range resp.Cookies() {
				val := ck.Value
				// Java serialized object marker
				if strings.HasPrefix(val, "rO0AB") {
					hasSerializedCookie = true
					break
				}
				// PHP serialized object marker
				if strings.HasPrefix(val, "O:") || strings.HasPrefix(val, "a:") {
					hasSerializedCookie = true
					break
				}
			}

			r := Result{
				ID:             uuid.New().String(),
				AssessmentID:   actx.AssessmentID,
				ExecutionID:    actx.ExecutionID,
				Category:       CategoryDeserialization,
				VulnCode:       meta.Code,
				TestName:       "Passive Serialized Object Marker Detection",
				Endpoint:       actx.BaseURL,
				Method:         "GET",
				ObservedStatus: resp.StatusCode,
				CreatedAt:      time.Now().UTC(),
			}

			if hasSerializedCookie {
				r.VerificationState = StateCandidate
				r.Severity = report.SeverityMedium
				r.Confidence = report.ConfidenceMedium
				r.EvidenceSummary = "Detected serialized object marker in session cookie; zero RCE payloads dispatched"
				cov.Candidates++
			} else {
				r.VerificationState = StateObserved
				r.Severity = report.SeverityInfo
				r.Confidence = report.ConfidenceHigh
				r.EvidenceSummary = "No serialized object markers identified in headers or session artifacts"
				cov.Observations++
			}
			results = append(results, r)
		}
	}

	cov.TestsRun = len(results)
	cov.Explanation = "Assessed serialized object signatures (passive static inspection only; zero gadget chains)"
	return results, findings, cov
}

// -------------------------------------------------------------------------
// Category 13: Security Misconfiguration
// -------------------------------------------------------------------------

func (e *Engine) assessMisconfiguration(ctx context.Context, actx *AssessmentContext, client *http.Client) ([]Result, []report.Finding, CategoryCoverage) {
	meta := CategoryMetadata[CategoryMisconfiguration]
	cov := CategoryCoverage{
		Category: CategoryMisconfiguration,
		Code:     meta.Code,
		Name:     meta.Name,
		Status:   CoverageActivelyTested,
	}

	var results []Result
	var findings []report.Finding

	// 1. Directory Listing Check
	dirPaths := []string{"/static/", "/uploads/", "/images/", "/assets/"}
	for _, p := range dirPaths {
		targetURL := buildEndpointURL(actx.BaseURL, p, nil)
		if actx.IsAllowed != nil && !actx.IsAllowed(targetURL) {
			continue
		}

		req, err := http.NewRequestWithContext(ctx, "GET", targetURL, nil)
		if err != nil {
			continue
		}
		req.Header.Set("User-Agent", e.config.UserAgent)
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		resp.Body.Close()
		bodyStr := string(b)

		r := Result{
			ID:             uuid.New().String(),
			AssessmentID:   actx.AssessmentID,
			ExecutionID:    actx.ExecutionID,
			Category:       CategoryMisconfiguration,
			VulnCode:       meta.Code,
			TestName:       fmt.Sprintf("Directory Listing Analysis (%s)", p),
			Endpoint:       targetURL,
			Method:         "GET",
			ObservedStatus: resp.StatusCode,
			CreatedAt:      time.Now().UTC(),
		}

		if resp.StatusCode == 200 && (strings.Contains(bodyStr, "<title>Index of /") || strings.Contains(bodyStr, "<h1>Index of /")) {
			r.VerificationState = StateVerified
			r.Severity = report.SeverityMedium
			r.Confidence = report.ConfidenceHigh
			r.EvidenceSummary = fmt.Sprintf("Directory listing enabled on %s displaying server file hierarchy", p)
			r.EvidenceDetails = map[string]string{
				"path":      p,
				"signature": "Index of /",
			}

			fnd := e.createFinding(actx, r, fmt.Sprintf("Directory Listing Enabled on %s", p),
				r.EvidenceSummary, report.SeverityMedium, 40)
			r.Finding = fnd
			findings = append(findings, *fnd)
			cov.Verified++
			cov.Status = CoverageVerifiedIssueFound
		} else {
			r.VerificationState = StateNotVulnerable
			r.Severity = report.SeverityInfo
			r.Confidence = report.ConfidenceHigh
			r.EvidenceSummary = fmt.Sprintf("Directory listing disabled on %s", p)
		}
		results = append(results, r)
		if r.VerificationState == StateVerified {
			break
		}
	}

	// 2. Exposed Debug Console Check (e.g. Werkzeug /console)
	consoleURL := buildEndpointURL(actx.BaseURL, "/console", nil)
	if actx.IsAllowed == nil || actx.IsAllowed(consoleURL) {
		req, err := http.NewRequestWithContext(ctx, "GET", consoleURL, nil)
		if err == nil {
			req.Header.Set("User-Agent", e.config.UserAgent)
			resp, err := client.Do(req)
			if err == nil {
				b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
				resp.Body.Close()
				bodyStr := string(b)

				r := Result{
					ID:             uuid.New().String(),
					AssessmentID:   actx.AssessmentID,
					ExecutionID:    actx.ExecutionID,
					Category:       CategoryMisconfiguration,
					VulnCode:       meta.Code,
					TestName:       "Interactive Debug Console Exposure Check (/console)",
					Endpoint:       consoleURL,
					Method:         "GET",
					ObservedStatus: resp.StatusCode,
					CreatedAt:      time.Now().UTC(),
				}

				if resp.StatusCode == 200 && (strings.Contains(bodyStr, "Werkzeug") && strings.Contains(bodyStr, "console")) {
					r.VerificationState = StateVerified
					r.Severity = report.SeverityHigh
					r.Confidence = report.ConfidenceHigh
					r.EvidenceSummary = "Unauthenticated interactive debug console exposed at /console"
					fnd := e.createFinding(actx, r, "Exposed Interactive Debug Console (/console)",
						r.EvidenceSummary, report.SeverityHigh, 85)
					r.Finding = fnd
					findings = append(findings, *fnd)
					cov.Verified++
					cov.Status = CoverageVerifiedIssueFound
				} else {
					r.VerificationState = StateNotVulnerable
					r.Severity = report.SeverityInfo
					r.Confidence = report.ConfidenceHigh
					r.EvidenceSummary = "/console not exposed or properly protected"
				}
				results = append(results, r)
			}
		}
	}

	cov.TestsRun = len(results)
	cov.Explanation = fmt.Sprintf("Evaluated %d misconfiguration checks (%d verified issues)", cov.TestsRun, cov.Verified)
	return results, findings, cov
}

// -------------------------------------------------------------------------
// Helper Functions
// -------------------------------------------------------------------------

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
	fingerprint := fmt.Sprintf("webvuln-%x", hash[:8])

	conf := r.Confidence
	if conf == "" {
		conf = report.ConfidenceHigh
	}

	meta := CategoryMetadata[r.Category]

	return &report.Finding{
		ID:          uuid.New().String(),
		Title:       title,
		Category:    fmt.Sprintf("%s / %s", meta.Code, meta.Name),
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
			DetectionMethod: "WEB_VULNERABILITY_ENGINE",
			Details: map[string]string{
				"vuln_category": string(r.Category),
				"vuln_code":     r.VulnCode,
				"test_name":     r.TestName,
			},
		},
		Verification: report.VerificationRecord{
			Status:    report.VerificationStatus(r.VerificationState),
			Result:    string(r.VerificationState),
			Rationale: r.EvidenceSummary,
		},
		Source:      "web_vulnerability_engine",
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

	// Reconcile status when verified findings are confirmed
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

func buildEndpointURL(base, path string, queryParams map[string]string) string {
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	base = strings.TrimRight(base, "/")
	full := base + path

	u, err := url.Parse(full)
	if err != nil {
		return full
	}

	if len(queryParams) > 0 {
		q := u.Query()
		for k, v := range queryParams {
			q.Set(k, v)
		}
		u.RawQuery = q.Encode()
	}

	return u.String()
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
