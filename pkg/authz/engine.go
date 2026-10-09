package authz

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"

	"felix/pkg/report"
)

// Engine orchestrates authorization test execution, safety verification, and finding generation.
type Engine struct {
	client     *http.Client
	comparator *Comparator
}

// NewEngine creates an authorization intelligence engine.
func NewEngine(client *http.Client) *Engine {
	if client == nil {
		client = &http.Client{Timeout: 15 * time.Second}
	}
	return &Engine{
		client:     client,
		comparator: NewComparator(),
	}
}

// Execute runs planned authorization tests against the target baseURL under the specified policy.
func (e *Engine) Execute(
	ctx context.Context,
	baseURL string,
	policy *AuthzPolicy,
	assessmentID string,
	executionID string,
	isAllowed func(string) bool,
	isExcluded func(string) bool,
) ([]AuthzTestResult, []report.Finding, *AuthzSummary, error) {
	if policy == nil {
		return nil, nil, nil, fmt.Errorf("authorization policy is nil")
	}

	planner := NewPlanner(policy)
	testCases := planner.PlanTestCases(baseURL)

	var results []AuthzTestResult
	var findings []report.Finding

	// Cache of baseline responses keyed by "identity:method:endpoint"
	baselineCache := make(map[string]*ResponseData)

	// Step 1: Run baseline (ALLOW) cases first to establish baseline ground truth
	for _, tc := range testCases {
		if tc.ExpectedResult != ExpectedAllow {
			continue
		}

		key := fmt.Sprintf("%s:%s:%s", tc.PrimaryIdentity, tc.Method, tc.Endpoint)
		if _, exists := baselineCache[key]; exists {
			continue
		}

		resp, err := e.executeRequest(ctx, &tc, policy, isAllowed, isExcluded)
		if err != nil {
			continue
		}
		baselineCache[key] = resp

		// Evaluate baseline
		res := e.getResource(policy, tc.TargetResource)
		resEval := e.comparator.Compare(&tc, resp, nil, res)
		resEval.ID = uuid.New().String()
		resEval.AssessmentID = assessmentID
		resEval.ExecutionID = executionID
		resEval.CreatedAt = time.Now().UTC()
		results = append(results, *resEval)
	}

	// Step 2: Run test (DENY) cases and evaluate against baseline
	for _, tc := range testCases {
		if tc.ExpectedResult == ExpectedAllow {
			continue // Already processed
		}

		// Enforce write test safety guard
		if (tc.Method == "POST" || tc.Method == "PUT" || tc.Method == "PATCH" || tc.Method == "DELETE") && !policy.AllowWriteTests {
			// Write test blocked because explicit approval is missing
			refusedResult := AuthzTestResult{
				ID:                uuid.New().String(),
				TestCaseID:        tc.ID,
				AssessmentID:      assessmentID,
				ExecutionID:       executionID,
				Category:          tc.Category,
				VerificationState: StateCandidate,
				Endpoint:          tc.Endpoint,
				Method:            tc.Method,
				PrimaryIdentity:   tc.PrimaryIdentity,
				TargetResource:    tc.TargetResource,
				EvidenceSummary:   fmt.Sprintf("Mutating authorization test skipped for safety: write-test approval required (policy.allow_write_tests is false)"),
				CreatedAt:         time.Now().UTC(),
			}
			results = append(results, refusedResult)
			continue
		}

		resp, err := e.executeRequest(ctx, &tc, policy, isAllowed, isExcluded)
		if err != nil {
			errResult := AuthzTestResult{
				ID:                uuid.New().String(),
				TestCaseID:        tc.ID,
				AssessmentID:      assessmentID,
				ExecutionID:       executionID,
				Category:          tc.Category,
				VerificationState: StateInconclusive,
				Endpoint:          tc.Endpoint,
				Method:            tc.Method,
				PrimaryIdentity:   tc.PrimaryIdentity,
				TargetResource:    tc.TargetResource,
				EvidenceSummary:   fmt.Sprintf("Request execution failed: %v", err),
				CreatedAt:         time.Now().UTC(),
			}
			results = append(results, errResult)
			continue
		}

		// Retrieve matching baseline if available
		var baselineResp *ResponseData
		if tc.BaselineIdentity != "" {
			baseKey := fmt.Sprintf("%s:%s:%s", tc.BaselineIdentity, tc.Method, tc.Endpoint)
			baselineResp = baselineCache[baseKey]
		}

		res := e.getResource(policy, tc.TargetResource)
		resEval := e.comparator.Compare(&tc, resp, baselineResp, res)
		resEval.ID = uuid.New().String()
		resEval.AssessmentID = assessmentID
		resEval.ExecutionID = executionID
		resEval.CreatedAt = time.Now().UTC()

		// Redacted structural evidence
		resEval.RedactedResponse = RedactBody(resp.Body, 512)

		// If verified vulnerability found, generate finding
		if resEval.VerificationState == StateVerified {
			finding := e.generateFinding(&tc, resEval, baseURL, policy)
			resEval.Finding = finding
			findings = append(findings, *finding)
		}

		results = append(results, *resEval)
	}

	summary := e.compileSummary(results)
	return results, findings, summary, nil
}

func (e *Engine) executeRequest(
	ctx context.Context,
	tc *AuthzTestCase,
	policy *AuthzPolicy,
	isAllowed func(string) bool,
	isExcluded func(string) bool,
) (*ResponseData, error) {
	// Scope check
	if isAllowed != nil && !isAllowed(tc.Endpoint) {
		return nil, fmt.Errorf("endpoint %s is out of scope", tc.Endpoint)
	}
	if isExcluded != nil && isExcluded(tc.Endpoint) {
		return nil, fmt.Errorf("endpoint %s matches exclusion rule", tc.Endpoint)
	}

	var bodyReader io.Reader
	if tc.Payload != "" {
		bodyReader = bytes.NewBufferString(tc.Payload)
	}

	req, err := http.NewRequestWithContext(ctx, tc.Method, tc.Endpoint, bodyReader)
	if err != nil {
		return nil, err
	}

	if tc.Payload != "" {
		req.Header.Set("Content-Type", "application/json")
	}

	// Apply identity authentication credentials
	if id, exists := policy.Identities[tc.PrimaryIdentity]; exists {
		for k, v := range id.Headers {
			req.Header.Set(k, v)
		}
		for k, v := range id.Cookies {
			req.AddCookie(&http.Cookie{Name: k, Value: v})
		}
	}

	resp, err := e.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	// Read response with safety limit (512KB)
	lr := io.LimitReader(resp.Body, 512*1024)
	bodyBytes, err := io.ReadAll(lr)
	if err != nil {
		return nil, err
	}

	headers := make(map[string]string)
	for k, vv := range resp.Header {
		headers[k] = strings.Join(vv, ", ")
	}

	return &ResponseData{
		StatusCode: resp.StatusCode,
		Body:       bodyBytes,
		Headers:    headers,
	}, nil
}

func (e *Engine) generateFinding(
	tc *AuthzTestCase,
	res *AuthzTestResult,
	baseURL string,
	policy *AuthzPolicy,
) *report.Finding {
	categoryTitle := FindingCategoryTitles[tc.Category]
	if categoryTitle == "" {
		categoryTitle = "API Security / Authorization Bypass"
	}

	sev := report.SeverityHigh
	score := 75
	switch tc.Category {
	case CategoryBOLA:
		sev = report.SeverityHigh
		score = 80
	case CategoryBFLA:
		sev = report.SeverityHigh
		score = 85
	case CategoryBOPLAModification:
		sev = report.SeverityHigh
		score = 75
	case CategoryBOPLAExposure:
		sev = report.SeverityMedium
		score = 50
	case CategoryHorizontalEsc:
		sev = report.SeverityHigh
		score = 80
	case CategoryVerticalEsc:
		sev = report.SeverityHigh
		score = 90
	}

	sanitizedEndpoint := SanitizeURL(tc.Endpoint)
	sanitizedTarget := SanitizeURL(baseURL)

	title := fmt.Sprintf("%s at %s (%s)", categoryTitle, tc.Method, sanitizedEndpoint)
	if tc.Category == CategoryBOLA {
		title = fmt.Sprintf("Broken Object Level Authorization (BOLA/IDOR) on %s %s", tc.Method, sanitizedEndpoint)
	} else if tc.Category == CategoryBFLA {
		title = fmt.Sprintf("Broken Function Level Authorization (BFLA) on %s %s", tc.Method, sanitizedEndpoint)
	} else if tc.Category == CategoryBOPLAExposure {
		title = fmt.Sprintf("Broken Object Property Exposure (%s) on %s", tc.PropertyKey, sanitizedEndpoint)
	} else if tc.Category == CategoryBOPLAModification {
		title = fmt.Sprintf("Broken Object Property Modification (%s) on %s", tc.PropertyKey, sanitizedEndpoint)
	}

	// Fingerprint for deterministic deduplication
	fpData := fmt.Sprintf("%s|%s|%s|%s|%s", tc.Category, tc.Method, sanitizedEndpoint, tc.PrimaryIdentity, tc.TargetResource)
	hash := sha256.Sum256([]byte(fpData))
	fingerprint := fmt.Sprintf("authz-%x", hash[:8])

	return &report.Finding{
		ID:          uuid.New().String(),
		Title:       title,
		Category:    categoryTitle,
		Severity:    sev,
		Confidence:  report.ConfidenceHigh,
		Target:      sanitizedTarget,
		Endpoint:    sanitizedEndpoint,
		Method:      tc.Method,
		Description: fmt.Sprintf("Authorization policy failure: %s", res.EvidenceSummary),
		Evidence:    res.EvidenceSummary,
		EvidenceDetails: report.EvidenceDetails{
			Observation:     res.EvidenceSummary,
			Location:        sanitizedEndpoint,
			HTTPMethod:      tc.Method,
			HTTPStatus:      res.ObservedStatus,
			DetectionMethod: "AUTHORIZATION_POLICY_VERIFICATION",
			Details: map[string]string{
				"category":         string(tc.Category),
				"primary_identity": tc.PrimaryIdentity,
				"target_resource":  tc.TargetResource,
				"expected":         string(tc.ExpectedResult),
				"status":           fmt.Sprintf("%d", res.ObservedStatus),
			},
		},
		Verification: report.VerificationRecord{
			Status:    report.VerificationVerified,
			Result:    "CONFIRMED_VULNERABILITY",
			Rationale: res.EvidenceSummary,
		},
		Source:      "api_authz",
		Fingerprint: fingerprint,
		Score:       score,
	}
}

func (e *Engine) getResource(policy *AuthzPolicy, resID string) *TestResource {
	if policy == nil || resID == "" {
		return nil
	}
	if r, exists := policy.Resources[resID]; exists {
		return &r
	}
	return nil
}

func (e *Engine) compileSummary(results []AuthzTestResult) *AuthzSummary {
	summary := &AuthzSummary{
		TotalTests:        len(results),
		CategoryBreakdown: make(map[string]int),
		VerifiedBreakdown: make(map[string]int),
	}

	for _, r := range results {
		summary.CategoryBreakdown[string(r.Category)]++

		switch r.VerificationState {
		case StateVerified:
			summary.VerifiedCount++
			summary.VerifiedBreakdown[string(r.Category)]++
		case StateCandidate:
			summary.CandidateCount++
		case StateInconclusive:
			summary.InconclusiveCount++
		case StateNotVulnerable:
			summary.NotVulnerableCount++
		}
	}

	return summary
}
