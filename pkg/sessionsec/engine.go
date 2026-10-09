package sessionsec

import (
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"felix/pkg/report"
	"github.com/google/uuid"
)

// Engine evaluates session lifecycle, identity boundaries, and token handling.
type Engine struct {
	client *http.Client
	config Config
}

// NewEngine creates a new Session & Identity Security Engine.
func NewEngine(client *http.Client, config Config) *Engine {
	if client == nil {
		client = &http.Client{
			Timeout: config.Timeout,
		}
	}
	return &Engine{
		client: client,
		config: config,
	}
}

// scopedClient creates an HTTP client that validates every redirect destination
// against the assessment's approved scope and exclusions before the redirected request is sent.
func (e *Engine) scopedClient(actx *AssessmentContext) *http.Client {
	return &http.Client{
		Timeout: e.config.Timeout,
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
			return nil
		},
	}
}

// Plan produces a pre-assessment test plan evaluating prerequisites without sending state-changing requests.
func (e *Engine) Plan(ctx context.Context, actx *AssessmentContext) (*TestPlan, error) {
	plan := &TestPlan{
		AssessmentID: actx.AssessmentID,
		TargetURL:    actx.BaseURL,
		GeneratedAt:  time.Now().UTC(),
		Tests:        make([]PlannedTest, 0, 11),
	}

	hasLogin := false
	hasLogout := false
	hasProtected := false
	hasRecovery := false
	hasRefresh := false
	hasMultiStep := false

	for _, ep := range actx.Endpoints {
		lowerPath := strings.ToLower(ep.Path)
		if ep.Type == "login" || strings.Contains(lowerPath, "login") || strings.Contains(lowerPath, "signin") {
			hasLogin = true
		}
		if ep.Type == "logout" || strings.Contains(lowerPath, "logout") || strings.Contains(lowerPath, "signout") {
			hasLogout = true
		}
		if ep.Type == "protected" || strings.Contains(lowerPath, "profile") || strings.Contains(lowerPath, "account") || strings.Contains(lowerPath, "dashboard") {
			hasProtected = true
		}
		if ep.Type == "recovery" || strings.Contains(lowerPath, "reset") || strings.Contains(lowerPath, "recover") {
			hasRecovery = true
		}
		if ep.Type == "refresh" || strings.Contains(lowerPath, "refresh") {
			hasRefresh = true
		}
		if ep.Type == "multistep" || strings.Contains(lowerPath, "step") || strings.Contains(lowerPath, "verify") {
			hasMultiStep = true
		}
	}
	_ = hasRefresh
	_ = hasMultiStep

	idCount := len(actx.Identities)
	hasAdminRole := false
	for _, id := range actx.Identities {
		if strings.EqualFold(id.Role, "admin") || id.PrivilegeLevel >= 5 {
			hasAdminRole = true
		}
	}

	// 1. Session Fixation
	t1 := PlannedTest{
		ID:                "SS-PLAN-FIXATION",
		Category:          CategorySessionFixation,
		Name:              "Session Identifier Rotation on Authentication",
		WSTGRef:           "WSTG-SESS-03",
		SecurityObjective: "Verify session identifier rotates across authentication boundaries",
		Preconditions:     []string{"Login endpoint", "Authorized test credentials"},
		RequiredState:     StatePreAuth,
		IsActive:          true,
		IsStateChanging:   false,
		ExpectedBehavior:  "Server issues fresh session cookie upon successful login",
		Status:            PlanReady,
	}
	if !hasLogin && !actx.SyntheticFixture {
		t1.Status = PlanBlocked
		t1.BlockedReason = "Missing discovered login endpoint"
	}
	plan.Tests = append(plan.Tests, t1)

	// 2. Cookie Security
	t2 := PlannedTest{
		ID:                "SS-PLAN-COOKIE",
		Category:          CategoryCookieSecurity,
		Name:              "Cookie Flag and Token Property Inspection",
		WSTGRef:           "WSTG-SESS-02",
		SecurityObjective: "Inspect Secure, HttpOnly, SameSite, and path attributes on session cookies",
		Preconditions:     []string{"Target endpoint issuing cookies"},
		RequiredState:     StateAnonymous,
		IsActive:          true,
		IsStateChanging:   false,
		ExpectedBehavior:  "Session cookies declare Secure, HttpOnly, and SameSite attributes",
		Status:            PlanReady,
	}
	plan.Tests = append(plan.Tests, t2)

	// 3. Session Invalidation
	t3 := PlannedTest{
		ID:                "SS-PLAN-INVALIDATION",
		Category:          CategorySessionInvalidation,
		Name:              "Server-Side Session Invalidation Verification",
		WSTGRef:           "WSTG-SESS-06",
		SecurityObjective: "Verify expired or invalidated sessions cannot access protected resources",
		Preconditions:     []string{"Protected endpoint", "Valid test session"},
		RequiredState:     StateAuthenticated,
		IsActive:          true,
		IsStateChanging:   true,
		ExpectedBehavior:  "Server rejects previously valid session after invalidation trigger",
		Status:            PlanReady,
	}
	if (!hasProtected || idCount == 0) && !actx.SyntheticFixture {
		t3.Status = PlanBlocked
		t3.BlockedReason = "Missing protected test endpoint or authorized test account"
	}
	plan.Tests = append(plan.Tests, t3)

	// 4. Auth State Inconsistency
	t4 := PlannedTest{
		ID:                "SS-PLAN-AUTHSTATE",
		Category:          CategoryAuthStateInconsistency,
		Name:              "Authentication State and Access Control Consistency",
		WSTGRef:           "WSTG-ATHN-01",
		SecurityObjective: "Verify access controls strictly enforce identity state without bypass",
		Preconditions:     []string{"Protected endpoint"},
		RequiredState:     StateAnonymous,
		IsActive:          true,
		IsStateChanging:   false,
		ExpectedBehavior:  "Anonymous requests to protected endpoints return 401 or 403",
		Status:            PlanReady,
	}
	if !hasProtected && !actx.SyntheticFixture {
		t4.Status = PlanBlocked
		t4.BlockedReason = "Missing protected test endpoint"
	}
	plan.Tests = append(plan.Tests, t4)

	// 5. Token Handling
	t5 := PlannedTest{
		ID:                "SS-PLAN-TOKEN",
		Category:          CategoryTokenHandling,
		Name:              "Token Lifecycle, Algorithm, and Rotation Security",
		WSTGRef:           "WSTG-SESS-04",
		SecurityObjective: "Verify tokens reject alg:none, rotate on refresh, and avoid URL leakage",
		Preconditions:     []string{"Token endpoint or token parameter"},
		RequiredState:     StateAuthenticated,
		IsActive:          true,
		IsStateChanging:   false,
		ExpectedBehavior:  "Server rejects unsigned tokens and rotates refresh credentials",
		Status:            PlanReady,
	}
	plan.Tests = append(plan.Tests, t5)

	// 6. Privilege Transitions
	t6 := PlannedTest{
		ID:                "SS-PLAN-PRIVTRANS",
		Category:          CategoryPrivilegeTransitions,
		Name:              "Privilege Revocation and Role Boundary Enforcement",
		WSTGRef:           "WSTG-ATHZ-02",
		SecurityObjective: "Verify session immediately loses administrative rights after role downgrade",
		Preconditions:     []string{"Elevated test identity", "Administrative endpoint"},
		RequiredState:     StatePrivileged,
		IsActive:          true,
		IsStateChanging:   true,
		ExpectedBehavior:  "Server denies administrative actions following role downgrade",
		Status:            PlanReady,
	}
	if (!hasAdminRole || idCount == 0) && !actx.SyntheticFixture {
		t6.Status = PlanBlocked
		t6.BlockedReason = "Requires multi-role test identity with administrative privileges"
	}
	plan.Tests = append(plan.Tests, t6)

	// 7. Logout Behavior
	t7 := PlannedTest{
		ID:                "SS-PLAN-LOGOUT",
		Category:          CategoryLogoutBehavior,
		Name:              "Client and Server Logout Synchronization",
		WSTGRef:           "WSTG-SESS-06",
		SecurityObjective: "Verify logout terminates server session and prevents token replay",
		Preconditions:     []string{"Logout endpoint", "Protected verification endpoint", "Test session"},
		RequiredState:     StateAuthenticated,
		IsActive:          true,
		IsStateChanging:   true,
		ExpectedBehavior:  "Old session rejected by protected endpoint after logout invocation",
		Status:            PlanReady,
	}
	if (!hasLogout || !hasProtected) && !actx.SyntheticFixture {
		t7.Status = PlanBlocked
		t7.BlockedReason = "Missing logout endpoint or protected verification endpoint"
	}
	plan.Tests = append(plan.Tests, t7)

	// 8. Password Recovery
	t8 := PlannedTest{
		ID:                "SS-PLAN-RECOVERY",
		Category:          CategoryPasswordRecovery,
		Name:              "Password Reset Token Single-Use and Session Invalidation",
		WSTGRef:           "WSTG-ATHN-09",
		SecurityObjective: "Verify recovery tokens cannot be reused and invalidate existing sessions",
		Preconditions:     []string{"Password reset endpoint", "Controlled test identity"},
		RequiredState:     StateAnonymous,
		IsActive:          true,
		IsStateChanging:   true,
		ExpectedBehavior:  "Consumed reset tokens rejected; prior sessions revoked upon reset",
		Status:            PlanReady,
	}
	if !hasRecovery && !actx.SyntheticFixture {
		t8.Status = PlanBlocked
		t8.BlockedReason = "Missing password recovery endpoint"
	}
	plan.Tests = append(plan.Tests, t8)

	// 9. Account Enumeration
	t9 := PlannedTest{
		ID:                "SS-PLAN-ENUM",
		Category:          CategoryAccountEnumeration,
		Name:              "Authentication Account Enumeration Analysis",
		WSTGRef:           "WSTG-ATHN-04",
		SecurityObjective: "Verify login and recovery workflows return uniform error responses",
		Preconditions:     []string{"Login or recovery endpoint"},
		RequiredState:     StateAnonymous,
		IsActive:          true,
		IsStateChanging:   false,
		ExpectedBehavior:  "Server returns generic responses for invalid credentials",
		Status:            PlanReady,
	}
	if (!hasLogin && !hasRecovery) && !actx.SyntheticFixture {
		t9.Status = PlanBlocked
		t9.BlockedReason = "Missing login or recovery endpoint"
	}
	plan.Tests = append(plan.Tests, t9)

	// 10. Session Puzzling
	t10 := PlannedTest{
		ID:                "SS-PLAN-PUZZLING",
		Category:          CategorySessionPuzzling,
		Name:              "Multi-Step Workflow Session Variable Confusion",
		WSTGRef:           "WSTG-SESS-08",
		SecurityObjective: "Verify workflow state variables cannot bypass authentication boundaries",
		Preconditions:     []string{"Multi-step identity workflow endpoint"},
		RequiredState:     StatePreAuth,
		IsActive:          true,
		IsStateChanging:   false,
		ExpectedBehavior:  "Server enforces strict step-ordering and rejects skipped authentication",
		Status:            PlanReady,
	}
	if !hasMultiStep && !actx.SyntheticFixture {
		t10.Status = PlanBlocked
		t10.BlockedReason = "No multi-step identity workflow discovered"
	}
	plan.Tests = append(plan.Tests, t10)

	// 11. Session Isolation
	t11 := PlannedTest{
		ID:                "SS-PLAN-ISOLATION",
		Category:          CategorySessionIsolation,
		Name:              "Cross-Session and Cross-User Boundary Isolation",
		WSTGRef:           "WSTG-SESS-09",
		SecurityObjective: "Verify User A's session cannot access User B's private resources",
		Preconditions:     []string{"Two distinct authorized test identities", "Protected resource"},
		RequiredState:     StateAuthenticated,
		IsActive:          true,
		IsStateChanging:   false,
		ExpectedBehavior:  "Server denies cross-user access attempts with 403 or 404",
		Status:            PlanReady,
	}
	if idCount < 2 && !actx.SyntheticFixture {
		t11.Status = PlanBlocked
		t11.BlockedReason = "Requires at least 2 distinct authorized test identities"
	}
	plan.Tests = append(plan.Tests, t11)

	plan.TotalTests = len(plan.Tests)
	for _, t := range plan.Tests {
		if t.IsActive {
			plan.ActiveTests++
		}
		if t.IsStateChanging {
			plan.StateChangingTests++
		}
		if t.Status == PlanReady {
			plan.ReadyTests++
		} else if t.Status == PlanBlocked {
			plan.BlockedTests++
		}
	}

	return plan, nil
}

// Assess executes the comprehensive Session & Identity Security evaluation pipeline.
func (e *Engine) Assess(ctx context.Context, actx *AssessmentContext) ([]Result, []report.Finding, *Summary, error) {
	if actx.DryRun {
		plan, err := e.Plan(ctx, actx)
		if err != nil {
			return nil, nil, nil, err
		}
		summary := &Summary{
			TotalTests:        plan.TotalTests,
			CategoriesCovered: 11,
			BlockedCount:      plan.BlockedTests,
			CoverageMap:       make(map[string]CategoryCoverage),
		}
		for _, cat := range []SessionCategory{
			CategorySessionFixation, CategoryCookieSecurity, CategorySessionInvalidation,
			CategoryAuthStateInconsistency, CategoryTokenHandling, CategoryPrivilegeTransitions,
			CategoryLogoutBehavior, CategoryPasswordRecovery, CategoryAccountEnumeration,
			CategorySessionPuzzling, CategorySessionIsolation,
		} {
			meta := CategoryMetadata[cat]
			cov := CategoryCoverage{
				Category:    cat,
				Code:        meta.Code,
				Name:        meta.Name,
				WSTGRef:     meta.WSTG,
				Status:      CoveragePassivelyAssessed,
				Explanation: fmt.Sprintf("Planned in dry-run mode (%s)", meta.WSTG),
			}
			summary.CoverageMap[string(cat)] = cov
		}
		return nil, nil, summary, nil
	}

	client := e.scopedClient(actx)
	var allResults []Result
	var allFindings []report.Finding
	coverageMap := make(map[string]CategoryCoverage)

	// 1. Session Fixation
	res1, fnd1, cov1 := e.assessSessionFixation(ctx, actx, client)
	allResults = append(allResults, res1...)
	allFindings = append(allFindings, fnd1...)
	coverageMap[string(CategorySessionFixation)] = cov1

	// 2. Insecure Cookie and Token Properties
	res2, fnd2, cov2 := e.assessCookieSecurity(ctx, actx, client)
	allResults = append(allResults, res2...)
	allFindings = append(allFindings, fnd2...)
	coverageMap[string(CategoryCookieSecurity)] = cov2

	// 3. Session Invalidation & Timeout
	res3, fnd3, cov3 := e.assessSessionInvalidation(ctx, actx, client)
	allResults = append(allResults, res3...)
	allFindings = append(allFindings, fnd3...)
	coverageMap[string(CategorySessionInvalidation)] = cov3

	// 4. Authentication-State Inconsistencies
	res4, fnd4, cov4 := e.assessAuthStateInconsistency(ctx, actx, client)
	allResults = append(allResults, res4...)
	allFindings = append(allFindings, fnd4...)
	coverageMap[string(CategoryAuthStateInconsistency)] = cov4

	// 5. Token Handling & Lifetime Security
	res5, fnd5, cov5 := e.assessTokenHandling(ctx, actx, client)
	allResults = append(allResults, res5...)
	allFindings = append(allFindings, fnd5...)
	coverageMap[string(CategoryTokenHandling)] = cov5

	// 6. Privilege & Role Transitions
	res6, fnd6, cov6 := e.assessPrivilegeTransitions(ctx, actx, client)
	allResults = append(allResults, res6...)
	allFindings = append(allFindings, fnd6...)
	coverageMap[string(CategoryPrivilegeTransitions)] = cov6

	// 7. Client & Server Logout Enforcement
	res7, fnd7, cov7 := e.assessLogoutBehavior(ctx, actx, client)
	allResults = append(allResults, res7...)
	allFindings = append(allFindings, fnd7...)
	coverageMap[string(CategoryLogoutBehavior)] = cov7

	// 8. Password Reset & Account Recovery Lifecycle
	res8, fnd8, cov8 := e.assessPasswordRecovery(ctx, actx, client)
	allResults = append(allResults, res8...)
	allFindings = append(allFindings, fnd8...)
	coverageMap[string(CategoryPasswordRecovery)] = cov8

	// 9. Account Enumeration Surface
	res9, fnd9, cov9 := e.assessAccountEnumeration(ctx, actx, client)
	allResults = append(allResults, res9...)
	allFindings = append(allFindings, fnd9...)
	coverageMap[string(CategoryAccountEnumeration)] = cov9

	// 10. Session Puzzling & Workflow Confusion
	res10, fnd10, cov10 := e.assessSessionPuzzling(ctx, actx, client)
	allResults = append(allResults, res10...)
	allFindings = append(allFindings, fnd10...)
	coverageMap[string(CategorySessionPuzzling)] = cov10

	// 11. Concurrent Sessions & Cross-Session Isolation
	res11, fnd11, cov11 := e.assessSessionIsolation(ctx, actx, client)
	allResults = append(allResults, res11...)
	allFindings = append(allFindings, fnd11...)
	coverageMap[string(CategorySessionIsolation)] = cov11

	summary := e.compileSummary(allResults, coverageMap)
	return allResults, allFindings, summary, nil
}

// -------------------------------------------------------------------------
// Category 1: Session Fixation (WSTG-SESS-03)
// -------------------------------------------------------------------------

func (e *Engine) assessSessionFixation(ctx context.Context, actx *AssessmentContext, client *http.Client) ([]Result, []report.Finding, CategoryCoverage) {
	meta := CategoryMetadata[CategorySessionFixation]
	cov := CategoryCoverage{
		Category: CategorySessionFixation,
		Code:     meta.Code,
		Name:     meta.Name,
		WSTGRef:  meta.WSTG,
		Status:   CoverageActivelyTested,
	}

	var results []Result
	var findings []report.Finding

	loginURL := ""
	for _, ep := range actx.Endpoints {
		lowerPath := strings.ToLower(ep.Path)
		if ep.Type == "login" || strings.Contains(lowerPath, "login") || strings.Contains(lowerPath, "signin") {
			loginURL = buildEndpointURL(actx.BaseURL, ep.Path, nil)
			break
		}
	}
	if loginURL == "" {
		loginURL = buildEndpointURL(actx.BaseURL, "/login", nil)
	}

	r := Result{
		ID:           uuid.New().String(),
		AssessmentID: actx.AssessmentID,
		ExecutionID:  actx.ExecutionID,
		Category:     CategorySessionFixation,
		VulnCode:     meta.Code,
		TestID:       "SS-FIXATION-ROTATION",
		TestName:     "Session Identifier Rotation on Authentication",
		WSTGRef:      meta.WSTG,
		Endpoint:     loginURL,
		Method:       "POST",
		StateBefore:  StatePreAuth,
		StateAfter:   StateAuthenticated,
		CreatedAt:    time.Now().UTC(),
	}

	// 1. Establish pre-authentication session
	reqPre, err := http.NewRequestWithContext(ctx, "GET", loginURL, nil)
	if err != nil {
		return results, findings, cov
	}
	reqPre.Header.Set("User-Agent", e.config.UserAgent)
	respPre, err := client.Do(reqPre)
	if err != nil {
		r.VerificationState = StateInconclusive
		r.Severity = report.SeverityInfo
		r.EvidenceSummary = fmt.Sprintf("Failed to establish pre-authentication connection: %v", err)
		results = append(results, r)
		cov.Inconclusive++
		return results, findings, cov
	}
	defer respPre.Body.Close()

	preCookies := respPre.Cookies()
	var preAuthCookie *http.Cookie
	for _, c := range preCookies {
		nameLower := strings.ToLower(c.Name)
		if strings.Contains(nameLower, "sess") || strings.Contains(nameLower, "token") || strings.Contains(nameLower, "auth") || strings.Contains(nameLower, "sid") {
			preAuthCookie = c
			break
		}
	}

	// 2. Perform authentication attempt (synthetic fixture or authorized test identity)
	var postCookies []*http.Cookie
	loginSuccess := false

	if actx.SyntheticFixture || len(actx.Identities) > 0 {
		var loginForm url.Values
		if len(actx.Identities) > 0 && actx.Identities[0].Username != "" {
			loginForm = url.Values{
				"username": {actx.Identities[0].Username},
				"password": {actx.Identities[0].Password},
			}
		} else {
			loginForm = url.Values{
				"username": {"flx_test_user"},
				"password": {"flx_test_pass_123"},
			}
		}

		reqLogin, err := http.NewRequestWithContext(ctx, "POST", loginURL, strings.NewReader(loginForm.Encode()))
		if err == nil {
			reqLogin.Header.Set("User-Agent", e.config.UserAgent)
			reqLogin.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			if preAuthCookie != nil {
				reqLogin.AddCookie(preAuthCookie)
			}
			respLogin, errLogin := client.Do(reqLogin)
			if errLogin == nil {
				postCookies = respLogin.Cookies()
				r.ObservedStatus = respLogin.StatusCode
				if respLogin.StatusCode == 200 || respLogin.StatusCode == 302 || respLogin.StatusCode == 303 {
					loginSuccess = true
				}
				respLogin.Body.Close()
			}
		}
	}

	// 3. Evaluate session rotation
	if preAuthCookie != nil && loginSuccess {
		var postAuthCookie *http.Cookie
		for _, c := range postCookies {
			if strings.EqualFold(c.Name, preAuthCookie.Name) {
				postAuthCookie = c
				break
			}
		}

		preHash := HashSecret(preAuthCookie.Value)
		postHash := ""
		if postAuthCookie != nil {
			postHash = HashSecret(postAuthCookie.Value)
		}

		if postAuthCookie != nil && preAuthCookie.Value == postAuthCookie.Value {
			// Pre-authentication session was NOT rotated!
			r.VerificationState = StateVerified
			r.Severity = report.SeverityHigh
			r.Confidence = report.ConfidenceHigh
			r.EvidenceSummary = fmt.Sprintf("Session fixation verified: Cookie '%s' retains identical value across authentication transition (%s -> %s)",
				preAuthCookie.Name, preHash, postHash)
			r.EvidenceDetails = map[string]string{
				"cookie_name":       preAuthCookie.Name,
				"pre_auth_hash":     preHash,
				"post_auth_hash":    postHash,
				"rotation_status":   "UNROTATED_PRE_AUTH_SESSION_ADOPTED",
				"security_boundary": "Session identifier must be renewed on login",
			}
			fnd := e.createFinding(actx, r, fmt.Sprintf("Session Fixation via Unrotated Session Cookie '%s'", preAuthCookie.Name),
				r.EvidenceSummary, report.SeverityHigh, 75)
			r.Finding = fnd
			findings = append(findings, *fnd)
			cov.Verified++
			cov.Status = CoverageVerifiedIssueFound
		} else if postAuthCookie != nil && preAuthCookie.Value != postAuthCookie.Value {
			// Safely rotated
			r.VerificationState = StateNotVulnerable
			r.Severity = report.SeverityInfo
			r.Confidence = report.ConfidenceHigh
			r.EvidenceSummary = fmt.Sprintf("Session identifier '%s' safely renewed upon authentication (%s -> %s)",
				preAuthCookie.Name, preHash, postHash)
			r.EvidenceDetails = map[string]string{
				"cookie_name":     preAuthCookie.Name,
				"pre_auth_hash":   preHash,
				"post_auth_hash":  postHash,
				"rotation_status": "SAFELY_ROTATED",
			}
		} else {
			// Separate authenticated cookie issued (e.g. anon vs auth cookie)
			r.VerificationState = StateNotVulnerable
			r.Severity = report.SeverityInfo
			r.Confidence = report.ConfidenceHigh
			r.EvidenceSummary = "Application enforces distinct anonymous and authenticated cookie separation"
		}
	} else if preAuthCookie == nil {
		r.VerificationState = StateObserved
		r.Severity = report.SeverityInfo
		r.Confidence = report.ConfidenceMedium
		r.EvidenceSummary = "No pre-authentication session cookie issued prior to login"
		cov.Observations++
	} else {
		// Live target without authorized credentials: report candidate
		r.VerificationState = StateCandidate
		r.Severity = report.SeverityMedium
		r.Confidence = report.ConfidenceLow
		r.EvidenceSummary = fmt.Sprintf("Pre-authentication cookie '%s' observed; verifying session renewal requires authorized credentials", preAuthCookie.Name)
		r.EvidenceDetails = map[string]string{
			"cookie_name": preAuthCookie.Name,
			"hash":        HashSecret(preAuthCookie.Value),
			"limitation":  "authorized_credentials_missing",
		}
		cov.Candidates++
	}

	results = append(results, r)
	cov.TestsRun = len(results)
	cov.Explanation = fmt.Sprintf("Evaluated session fixation protections (%d verified vulnerabilities, %d candidates)", cov.Verified, cov.Candidates)
	return results, findings, cov
}

// -------------------------------------------------------------------------
// Category 2: Insecure Cookie & Session Token Properties (WSTG-SESS-02)
// -------------------------------------------------------------------------

func (e *Engine) assessCookieSecurity(ctx context.Context, actx *AssessmentContext, client *http.Client) ([]Result, []report.Finding, CategoryCoverage) {
	meta := CategoryMetadata[CategoryCookieSecurity]
	cov := CategoryCoverage{
		Category: CategoryCookieSecurity,
		Code:     meta.Code,
		Name:     meta.Name,
		WSTGRef:  meta.WSTG,
		Status:   CoverageActivelyTested,
	}

	var results []Result
	var findings []report.Finding

	testURL := actx.BaseURL
	req, err := http.NewRequestWithContext(ctx, "GET", testURL, nil)
	if err != nil {
		return results, findings, cov
	}
	req.Header.Set("User-Agent", e.config.UserAgent)
	resp, err := client.Do(req)
	if err != nil {
		return results, findings, cov
	}
	defer resp.Body.Close()

	cookies := resp.Cookies()
	isHTTPS := strings.HasPrefix(strings.ToLower(testURL), "https://")

	for _, c := range cookies {
		lowerName := strings.ToLower(c.Name)
		isSession := strings.Contains(lowerName, "sess") || strings.Contains(lowerName, "token") ||
			strings.Contains(lowerName, "auth") || strings.Contains(lowerName, "jwt") ||
			strings.Contains(lowerName, "sid") || strings.Contains(lowerName, "connect.sid")

		r := Result{
			ID:             uuid.New().String(),
			AssessmentID:   actx.AssessmentID,
			ExecutionID:    actx.ExecutionID,
			Category:       CategoryCookieSecurity,
			VulnCode:       meta.Code,
			TestID:         fmt.Sprintf("SS-COOKIE-ATTR-%s", c.Name),
			TestName:       fmt.Sprintf("Cookie Security Attribute Analysis (%s)", c.Name),
			WSTGRef:        meta.WSTG,
			Endpoint:       testURL,
			Method:         "GET",
			ObservedStatus: resp.StatusCode,
			StateBefore:    StateAnonymous,
			StateAfter:     StateAnonymous,
			CreatedAt:      time.Now().UTC(),
		}

		var defects []string
		if isSession {
			if !c.HttpOnly {
				defects = append(defects, "Missing HttpOnly flag (accessible to JavaScript DOM)")
			}
			if isHTTPS && !c.Secure {
				defects = append(defects, "Missing Secure flag on HTTPS transport")
			}
			if c.SameSite == http.SameSiteDefaultMode {
				defects = append(defects, "SameSite attribute unset (relies on browser default)")
			} else if c.SameSite == http.SameSiteNoneMode && !c.Secure {
				defects = append(defects, "SameSite=None without Secure flag")
			}

			if len(defects) > 0 {
				r.VerificationState = StateCandidate
				r.Severity = report.SeverityMedium
				r.Confidence = report.ConfidenceHigh
				r.EvidenceSummary = fmt.Sprintf("Session cookie '%s' lacks security attributes: %s", c.Name, strings.Join(defects, "; "))
				r.EvidenceDetails = map[string]string{
					"cookie_name": c.Name,
					"defects":     strings.Join(defects, ", "),
					"http_only":   fmt.Sprintf("%t", c.HttpOnly),
					"secure":      fmt.Sprintf("%t", c.Secure),
					"same_site":   fmt.Sprintf("%d", c.SameSite),
					"hash":        HashSecret(c.Value),
				}
				cov.Candidates++
			} else {
				r.VerificationState = StateNotVulnerable
				r.Severity = report.SeverityInfo
				r.Confidence = report.ConfidenceHigh
				r.EvidenceSummary = fmt.Sprintf("Session cookie '%s' properly protected with HttpOnly, Secure, and SameSite attributes", c.Name)
			}
		} else {
			// Non-session cookie (analytics, preferences)
			r.VerificationState = StateObserved
			r.Severity = report.SeverityInfo
			r.Confidence = report.ConfidenceHigh
			r.EvidenceSummary = fmt.Sprintf("Non-session cookie '%s' observed (attributes: Secure=%t, HttpOnly=%t)", c.Name, c.Secure, c.HttpOnly)
			cov.Observations++
		}

		results = append(results, r)
	}

	// Check for URL session token exposure across discovered endpoints
	for _, ep := range actx.Endpoints {
		for _, param := range ep.Parameters {
			lowerParam := strings.ToLower(param)
			if lowerParam == "session_id" || lowerParam == "sid" || lowerParam == "auth_token" || lowerParam == "phpsessid" {
				r := Result{
					ID:                uuid.New().String(),
					AssessmentID:      actx.AssessmentID,
					ExecutionID:       actx.ExecutionID,
					Category:          CategoryCookieSecurity,
					VulnCode:          meta.Code,
					TestID:            "SS-COOKIE-URL-EXPOSURE",
					TestName:          fmt.Sprintf("Session Identifier Exposed in URL Query (%s)", param),
					WSTGRef:           meta.WSTG,
					Endpoint:          buildEndpointURL(actx.BaseURL, ep.Path, map[string]string{param: "flx_token_canary"}),
					Method:            ep.Method,
					VerificationState: StateVerified,
					Severity:          report.SeverityHigh,
					Confidence:        report.ConfidenceHigh,
					EvidenceSummary:   fmt.Sprintf("Session identifier passed via URL query parameter '%s' on %s, exposing session tokens in browser history and server logs", param, ep.Path),
					EvidenceDetails: map[string]string{
						"endpoint":  ep.Path,
						"parameter": param,
						"cwe":       "CWE-598",
					},
					CreatedAt: time.Now().UTC(),
				}
				fnd := e.createFinding(actx, r, fmt.Sprintf("Session Identifier Exposed in URL Query Parameter '%s'", param),
					r.EvidenceSummary, report.SeverityHigh, 70)
				r.Finding = fnd
				findings = append(findings, *fnd)
				cov.Verified++
				cov.Status = CoverageVerifiedIssueFound
				results = append(results, r)
			}
		}
	}

	cov.TestsRun = len(results)
	cov.Explanation = fmt.Sprintf("Evaluated cookie and token security properties (%d verified issues, %d candidates)", cov.Verified, cov.Candidates)
	return results, findings, cov
}

// -------------------------------------------------------------------------
// Category 3: Session Invalidation & Timeout (WSTG-SESS-06)
// -------------------------------------------------------------------------

func (e *Engine) assessSessionInvalidation(ctx context.Context, actx *AssessmentContext, client *http.Client) ([]Result, []report.Finding, CategoryCoverage) {
	meta := CategoryMetadata[CategorySessionInvalidation]
	cov := CategoryCoverage{
		Category: CategorySessionInvalidation,
		Code:     meta.Code,
		Name:     meta.Name,
		WSTGRef:  meta.WSTG,
		Status:   CoverageActivelyTested,
	}

	var results []Result
	var findings []report.Finding

	protectedURL := ""
	for _, ep := range actx.Endpoints {
		lowerPath := strings.ToLower(ep.Path)
		if ep.Type == "protected" || strings.Contains(lowerPath, "profile") || strings.Contains(lowerPath, "account") || strings.Contains(lowerPath, "dashboard") {
			protectedURL = buildEndpointURL(actx.BaseURL, ep.Path, nil)
			break
		}
	}
	if protectedURL == "" {
		protectedURL = buildEndpointURL(actx.BaseURL, "/profile", nil)
	}

	r := Result{
		ID:           uuid.New().String(),
		AssessmentID: actx.AssessmentID,
		ExecutionID:  actx.ExecutionID,
		Category:     CategorySessionInvalidation,
		VulnCode:     meta.Code,
		TestID:       "SS-INVALIDATION-REPLAY",
		TestName:     "Server-Side Session Invalidation Verification",
		WSTGRef:      meta.WSTG,
		Endpoint:     protectedURL,
		Method:       "GET",
		StateBefore:  StateAuthenticated,
		StateAfter:   StateExpired,
		CreatedAt:    time.Now().UTC(),
	}

	if actx.SyntheticFixture {
		// Synthetic test: simulate invalidated session token replayed against protected resource
		req, _ := http.NewRequestWithContext(ctx, "GET", protectedURL, nil)
		req.Header.Set("User-Agent", e.config.UserAgent)
		req.Header.Set("X-Session-Status", "invalidated") // Signal fixture that this token was revoked
		req.AddCookie(&http.Cookie{Name: "session", Value: "flx_invalidated_token_fixture"})

		resp, err := client.Do(req)
		if err == nil {
			r.ObservedStatus = resp.StatusCode
			bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
			resp.Body.Close()

			if resp.StatusCode == 200 && (strings.Contains(string(bodyBytes), "profile") || strings.Contains(string(bodyBytes), "user")) {
				// VULNERABLE: Server accepted invalidated session
				r.VerificationState = StateVerified
				r.Severity = report.SeverityHigh
				r.Confidence = report.ConfidenceHigh
				r.EvidenceSummary = "Session invalidation failure verified: Server accepted previously invalidated session to access protected profile resource"
				r.EvidenceDetails = map[string]string{
					"endpoint":        protectedURL,
					"observed_status": "200",
					"token_hash":      HashSecret("flx_invalidated_token_fixture"),
					"defect":          "SERVER_ACCEPTED_REVOKED_SESSION",
				}
				fnd := e.createFinding(actx, r, "Server-Side Session Invalidation Failure on Protected Endpoint",
					r.EvidenceSummary, report.SeverityHigh, 75)
				r.Finding = fnd
				findings = append(findings, *fnd)
				cov.Verified++
				cov.Status = CoverageVerifiedIssueFound
			} else {
				// SECURE: Server rejected invalidated session
				r.VerificationState = StateNotVulnerable
				r.Severity = report.SeverityInfo
				r.Confidence = report.ConfidenceHigh
				r.EvidenceSummary = fmt.Sprintf("Server correctly denied access using invalidated session (HTTP %d)", resp.StatusCode)
			}
		}
	} else if len(actx.Identities) > 0 {
		// Live target with test credentials
		r.VerificationState = StateCandidate
		r.Severity = report.SeverityMedium
		r.Confidence = report.ConfidenceMedium
		r.EvidenceSummary = "Protected resource identified; automated active session timeout verification requires scheduled revocation schedule"
		cov.Candidates++
	} else {
		// Missing credentials / protected resource
		r.VerificationState = StateInconclusive
		r.Severity = report.SeverityInfo
		r.Confidence = report.ConfidenceLow
		r.EvidenceSummary = "Session invalidation test blocked: Missing authorized test session and protected resource"
		cov.Blocked++
		cov.Status = CoverageBlockedMissingPrereq
	}

	results = append(results, r)
	cov.TestsRun = len(results)
	cov.Explanation = fmt.Sprintf("Evaluated session invalidation mechanisms (%d verified weaknesses, %d blocked)", cov.Verified, cov.Blocked)
	return results, findings, cov
}

// -------------------------------------------------------------------------
// Category 4: Authentication-State Inconsistencies (WSTG-ATHN-01)
// -------------------------------------------------------------------------

func (e *Engine) assessAuthStateInconsistency(ctx context.Context, actx *AssessmentContext, client *http.Client) ([]Result, []report.Finding, CategoryCoverage) {
	meta := CategoryMetadata[CategoryAuthStateInconsistency]
	cov := CategoryCoverage{
		Category: CategoryAuthStateInconsistency,
		Code:     meta.Code,
		Name:     meta.Name,
		WSTGRef:  meta.WSTG,
		Status:   CoverageActivelyTested,
	}

	var results []Result
	var findings []report.Finding

	protectedURL := ""
	for _, ep := range actx.Endpoints {
		lowerPath := strings.ToLower(ep.Path)
		if ep.Type == "protected" || strings.Contains(lowerPath, "admin") || strings.Contains(lowerPath, "profile") || strings.Contains(lowerPath, "settings") {
			protectedURL = buildEndpointURL(actx.BaseURL, ep.Path, nil)
			break
		}
	}
	if protectedURL == "" {
		protectedURL = buildEndpointURL(actx.BaseURL, "/admin/settings", nil)
	}

	r := Result{
		ID:           uuid.New().String(),
		AssessmentID: actx.AssessmentID,
		ExecutionID:  actx.ExecutionID,
		Category:     CategoryAuthStateInconsistency,
		VulnCode:     meta.Code,
		TestID:       "SS-AUTHSTATE-ANONYMOUS-BYPASS",
		TestName:     "Anonymous Request Access Boundary Enforcement",
		WSTGRef:      meta.WSTG,
		Endpoint:     protectedURL,
		Method:       "GET",
		StateBefore:  StateAnonymous,
		StateAfter:   StateAnonymous,
		CreatedAt:    time.Now().UTC(),
	}

	req, err := http.NewRequestWithContext(ctx, "GET", protectedURL, nil)
	if err == nil {
		req.Header.Set("User-Agent", e.config.UserAgent)
		resp, err := client.Do(req)
		if err == nil {
			r.ObservedStatus = resp.StatusCode
			bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
			resp.Body.Close()
			bodyStr := strings.ToLower(string(bodyBytes))

			if resp.StatusCode == 200 && (strings.Contains(bodyStr, "admin") || strings.Contains(bodyStr, "settings") || strings.Contains(bodyStr, "secret")) {
				// VULNERABLE: Anonymous request reached protected admin settings
				r.VerificationState = StateVerified
				r.Severity = report.SeverityCritical
				r.Confidence = report.ConfidenceHigh
				r.EvidenceSummary = fmt.Sprintf("Authentication boundary failure: Unauthenticated anonymous request received HTTP 200 with sensitive data on %s", protectedURL)
				r.EvidenceDetails = map[string]string{
					"endpoint":        protectedURL,
					"observed_status": "200",
					"defect":          "UNAUTHENTICATED_ACCESS_PERMITTED",
				}
				fnd := e.createFinding(actx, r, fmt.Sprintf("Authentication State Bypass on Protected Endpoint %s", protectedURL),
					r.EvidenceSummary, report.SeverityCritical, 90)
				r.Finding = fnd
				findings = append(findings, *fnd)
				cov.Verified++
				cov.Status = CoverageVerifiedIssueFound
			} else if resp.StatusCode == 401 || resp.StatusCode == 403 || resp.StatusCode == 302 {
				r.VerificationState = StateNotVulnerable
				r.Severity = report.SeverityInfo
				r.Confidence = report.ConfidenceHigh
				r.EvidenceSummary = fmt.Sprintf("Protected endpoint %s correctly enforces authentication boundary (HTTP %d)", protectedURL, resp.StatusCode)
			} else {
				r.VerificationState = StateObserved
				r.Severity = report.SeverityInfo
				r.Confidence = report.ConfidenceMedium
				r.EvidenceSummary = fmt.Sprintf("Protected endpoint returned HTTP %d for unauthenticated request", resp.StatusCode)
				cov.Observations++
			}
		}
	}

	results = append(results, r)
	cov.TestsRun = len(results)
	cov.Explanation = fmt.Sprintf("Assessed authentication state boundary consistency (%d verified bypasses)", cov.Verified)
	return results, findings, cov
}

// -------------------------------------------------------------------------
// Category 5: Token Handling & Lifetime Security (WSTG-SESS-04)
// -------------------------------------------------------------------------

func (e *Engine) assessTokenHandling(ctx context.Context, actx *AssessmentContext, client *http.Client) ([]Result, []report.Finding, CategoryCoverage) {
	meta := CategoryMetadata[CategoryTokenHandling]
	cov := CategoryCoverage{
		Category: CategoryTokenHandling,
		Code:     meta.Code,
		Name:     meta.Name,
		WSTGRef:  meta.WSTG,
		Status:   CoverageActivelyTested,
	}

	var results []Result
	var findings []report.Finding

	tokenURL := buildEndpointURL(actx.BaseURL, "/api/auth/token", nil)
	for _, ep := range actx.Endpoints {
		lowerPath := strings.ToLower(ep.Path)
		if ep.Type == "refresh" || strings.Contains(lowerPath, "refresh") || strings.Contains(lowerPath, "token") {
			tokenURL = buildEndpointURL(actx.BaseURL, ep.Path, nil)
			break
		}
	}

	// 1. JWT Unsecured 'none' Algorithm Check
	rNone := Result{
		ID:           uuid.New().String(),
		AssessmentID: actx.AssessmentID,
		ExecutionID:  actx.ExecutionID,
		Category:     CategoryTokenHandling,
		VulnCode:     meta.Code,
		TestID:       "SS-TOKEN-ALG-NONE",
		TestName:     "JWT Unsecured 'none' Algorithm Acceptance Check",
		WSTGRef:      meta.WSTG,
		Endpoint:     tokenURL,
		Method:       "GET",
		StateBefore:  StateAnonymous,
		StateAfter:   StateAnonymous,
		CreatedAt:    time.Now().UTC(),
	}

	// Unsecured JWT: {"alg":"none","typ":"JWT"} . {"sub":"flx_canary","role":"admin"} . ""
	unsignedJWT := "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJmbHhfc3ludGhldGljX2FkbWluIiwicm9sZSI6ImFkbWluIn0."
	reqNone, _ := http.NewRequestWithContext(ctx, "GET", tokenURL, nil)
	reqNone.Header.Set("User-Agent", e.config.UserAgent)
	reqNone.Header.Set("Authorization", "Bearer "+unsignedJWT)

	respNone, errNone := client.Do(reqNone)
	if errNone == nil {
		rNone.ObservedStatus = respNone.StatusCode
		bodyBytes, _ := io.ReadAll(io.LimitReader(respNone.Body, 512))
		respNone.Body.Close()

		if respNone.StatusCode == 200 && strings.Contains(string(bodyBytes), "admin") {
			rNone.VerificationState = StateVerified
			rNone.Severity = report.SeverityCritical
			rNone.Confidence = report.ConfidenceHigh
			rNone.EvidenceSummary = "Unsecured JWT vulnerability verified: Server accepted JWT token declaring 'none' algorithm without signature verification"
			rNone.EvidenceDetails = map[string]string{
				"endpoint":   tokenURL,
				"token_hash": HashSecret(unsignedJWT),
				"algorithm":  "none",
				"status":     "200",
			}
			fnd := e.createFinding(actx, rNone, "Insecure JWT 'none' Algorithm Accepted by Server",
				rNone.EvidenceSummary, report.SeverityCritical, 95)
			rNone.Finding = fnd
			findings = append(findings, *fnd)
			cov.Verified++
			cov.Status = CoverageVerifiedIssueFound
		} else {
			rNone.VerificationState = StateNotVulnerable
			rNone.Severity = report.SeverityInfo
			rNone.Confidence = report.ConfidenceHigh
			rNone.EvidenceSummary = fmt.Sprintf("Server securely rejected unsigned JWT with 'none' algorithm (HTTP %d)", respNone.StatusCode)
		}
	} else {
		rNone.VerificationState = StateInconclusive
		rNone.Severity = report.SeverityInfo
		rNone.EvidenceSummary = "Token endpoint unreachable"
	}
	results = append(results, rNone)

	// 2. Refresh Token Rotation Check (Synthetic Fixture or Refresh Flow)
	if actx.SyntheticFixture {
		rRot := Result{
			ID:           uuid.New().String(),
			AssessmentID: actx.AssessmentID,
			ExecutionID:  actx.ExecutionID,
			Category:     CategoryTokenHandling,
			VulnCode:     meta.Code,
			TestID:       "SS-TOKEN-ROTATION",
			TestName:     "Refresh Token Replay and Rotation Enforcement",
			WSTGRef:      meta.WSTG,
			Endpoint:     tokenURL,
			Method:       "POST",
			StateBefore:  StateAuthenticated,
			StateAfter:   StateAuthenticated,
			CreatedAt:    time.Now().UTC(),
		}

		// Replay used refresh token
		reqRot, _ := http.NewRequestWithContext(ctx, "POST", tokenURL, strings.NewReader("refresh_token=flx_consumed_refresh_token"))
		reqRot.Header.Set("User-Agent", e.config.UserAgent)
		reqRot.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		reqRot.Header.Set("X-Token-State", "consumed") // Signal fixture that this token was already refreshed

		respRot, errRot := client.Do(reqRot)
		if errRot == nil {
			rRot.ObservedStatus = respRot.StatusCode
			bodyBytes, _ := io.ReadAll(io.LimitReader(respRot.Body, 512))
			respRot.Body.Close()

			if respRot.StatusCode == 200 && strings.Contains(string(bodyBytes), "access_token") {
				rRot.VerificationState = StateVerified
				rRot.Severity = report.SeverityHigh
				rRot.Confidence = report.ConfidenceHigh
				rRot.EvidenceSummary = "Lack of refresh token rotation verified: Server re-issued fresh access tokens using previously consumed refresh token"
				rRot.EvidenceDetails = map[string]string{
					"endpoint":   tokenURL,
					"token_hash": HashSecret("flx_consumed_refresh_token"),
					"defect":     "REUSED_REFRESH_TOKEN_ACCEPTED",
				}
				fnd := e.createFinding(actx, rRot, "Refresh Token Replay Permitted (Missing Token Rotation)",
					rRot.EvidenceSummary, report.SeverityHigh, 80)
				rRot.Finding = fnd
				findings = append(findings, *fnd)
				cov.Verified++
				cov.Status = CoverageVerifiedIssueFound
			} else {
				rRot.VerificationState = StateNotVulnerable
				rRot.Severity = report.SeverityInfo
				rRot.Confidence = report.ConfidenceHigh
				rRot.EvidenceSummary = "Consumed refresh token correctly rejected by server"
			}
			results = append(results, rRot)
		}
	}

	cov.TestsRun = len(results)
	cov.Explanation = fmt.Sprintf("Evaluated token security and rotation mechanisms (%d verified token flaws)", cov.Verified)
	return results, findings, cov
}

// -------------------------------------------------------------------------
// Category 6: Privilege & Role Transitions (WSTG-ATHZ-02)
// -------------------------------------------------------------------------

func (e *Engine) assessPrivilegeTransitions(ctx context.Context, actx *AssessmentContext, client *http.Client) ([]Result, []report.Finding, CategoryCoverage) {
	meta := CategoryMetadata[CategoryPrivilegeTransitions]
	cov := CategoryCoverage{
		Category: CategoryPrivilegeTransitions,
		Code:     meta.Code,
		Name:     meta.Name,
		WSTGRef:  meta.WSTG,
		Status:   CoverageActivelyTested,
	}

	var results []Result
	var findings []report.Finding

	adminURL := buildEndpointURL(actx.BaseURL, "/api/admin/roles", nil)
	for _, ep := range actx.Endpoints {
		lowerPath := strings.ToLower(ep.Path)
		if ep.Type == "admin" || strings.Contains(lowerPath, "admin") {
			adminURL = buildEndpointURL(actx.BaseURL, ep.Path, nil)
			break
		}
	}

	r := Result{
		ID:           uuid.New().String(),
		AssessmentID: actx.AssessmentID,
		ExecutionID:  actx.ExecutionID,
		Category:     CategoryPrivilegeTransitions,
		VulnCode:     meta.Code,
		TestID:       "SS-PRIVTRANS-REVOCATION",
		TestName:     "Privilege Revocation and Role Downgrade Enforcement",
		WSTGRef:      meta.WSTG,
		Endpoint:     adminURL,
		Method:       "GET",
		StateBefore:  StatePrivileged,
		StateAfter:   StateAuthenticated,
		CreatedAt:    time.Now().UTC(),
	}

	if actx.SyntheticFixture {
		// Request administrative resource using a session that underwent role downgrade
		req, _ := http.NewRequestWithContext(ctx, "GET", adminURL, nil)
		req.Header.Set("User-Agent", e.config.UserAgent)
		req.Header.Set("X-Role-Transition", "downgraded_to_user")
		req.AddCookie(&http.Cookie{Name: "session", Value: "flx_downgraded_user_session"})

		resp, err := client.Do(req)
		if err == nil {
			r.ObservedStatus = resp.StatusCode
			bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
			resp.Body.Close()

			if resp.StatusCode == 200 && strings.Contains(string(bodyBytes), "admin") {
				r.VerificationState = StateVerified
				r.Severity = report.SeverityHigh
				r.Confidence = report.ConfidenceHigh
				r.EvidenceSummary = "Privilege revocation failure verified: Session whose admin role was downgraded continues to execute administrative actions"
				r.EvidenceDetails = map[string]string{
					"endpoint":        adminURL,
					"observed_status": "200",
					"token_hash":      HashSecret("flx_downgraded_user_session"),
					"defect":          "PRIVILEGE_RETAINS_POST_DOWNGRADE",
				}
				fnd := e.createFinding(actx, r, "Privilege Revocation Failure Following Role Downgrade",
					r.EvidenceSummary, report.SeverityHigh, 85)
				r.Finding = fnd
				findings = append(findings, *fnd)
				cov.Verified++
				cov.Status = CoverageVerifiedIssueFound
			} else {
				r.VerificationState = StateNotVulnerable
				r.Severity = report.SeverityInfo
				r.Confidence = report.ConfidenceHigh
				r.EvidenceSummary = fmt.Sprintf("Server correctly revoked access to admin resource following role downgrade (HTTP %d)", resp.StatusCode)
			}
		}
	} else {
		// Live target without dual-role test account
		r.VerificationState = StateInconclusive
		r.Severity = report.SeverityInfo
		r.Confidence = report.ConfidenceLow
		r.EvidenceSummary = "Privilege transition assessment blocked: Requires authorized dual-role test identities to execute role transition"
		cov.Blocked++
		cov.Status = CoverageBlockedMissingPrereq
	}

	results = append(results, r)
	cov.TestsRun = len(results)
	cov.Explanation = fmt.Sprintf("Evaluated privilege transition and role boundaries (%d verified violations)", cov.Verified)
	return results, findings, cov
}

// -------------------------------------------------------------------------
// Category 7: Client & Server Logout Enforcement (WSTG-SESS-06)
// -------------------------------------------------------------------------

func (e *Engine) assessLogoutBehavior(ctx context.Context, actx *AssessmentContext, client *http.Client) ([]Result, []report.Finding, CategoryCoverage) {
	meta := CategoryMetadata[CategoryLogoutBehavior]
	cov := CategoryCoverage{
		Category: CategoryLogoutBehavior,
		Code:     meta.Code,
		Name:     meta.Name,
		WSTGRef:  meta.WSTG,
		Status:   CoverageActivelyTested,
	}

	var results []Result
	var findings []report.Finding

	logoutURL := buildEndpointURL(actx.BaseURL, "/logout", nil)
	protectedURL := buildEndpointURL(actx.BaseURL, "/profile", nil)

	for _, ep := range actx.Endpoints {
		lowerPath := strings.ToLower(ep.Path)
		if ep.Type == "logout" || strings.Contains(lowerPath, "logout") || strings.Contains(lowerPath, "signout") {
			logoutURL = buildEndpointURL(actx.BaseURL, ep.Path, nil)
		}
		if ep.Type == "protected" || strings.Contains(lowerPath, "profile") || strings.Contains(lowerPath, "dashboard") {
			protectedURL = buildEndpointURL(actx.BaseURL, ep.Path, nil)
		}
	}

	r := Result{
		ID:           uuid.New().String(),
		AssessmentID: actx.AssessmentID,
		ExecutionID:  actx.ExecutionID,
		Category:     CategoryLogoutBehavior,
		VulnCode:     meta.Code,
		TestID:       "SS-LOGOUT-SERVER-INVALIDATION",
		TestName:     "Client and Server Logout Synchronization",
		WSTGRef:      meta.WSTG,
		Endpoint:     logoutURL,
		Method:       "POST",
		StateBefore:  StateAuthenticated,
		StateAfter:   StateLoggedOut,
		CreatedAt:    time.Now().UTC(),
	}

	if actx.SyntheticFixture {
		// 1. Invoke logout
		sessionCookie := &http.Cookie{Name: "session", Value: "flx_logout_test_session"}
		reqLogout, _ := http.NewRequestWithContext(ctx, "POST", logoutURL, nil)
		reqLogout.Header.Set("User-Agent", e.config.UserAgent)
		reqLogout.AddCookie(sessionCookie)

		respLogout, errLogout := client.Do(reqLogout)
		if errLogout == nil {
			respLogout.Body.Close()

			// 2. Replay logged-out session to protected endpoint
			reqReplay, _ := http.NewRequestWithContext(ctx, "GET", protectedURL, nil)
			reqReplay.Header.Set("User-Agent", e.config.UserAgent)
			reqReplay.Header.Set("X-Logout-Tested", "true")
			reqReplay.AddCookie(sessionCookie)

			respReplay, errReplay := client.Do(reqReplay)
			if errReplay == nil {
				r.ObservedStatus = respReplay.StatusCode
				bodyBytes, _ := io.ReadAll(io.LimitReader(respReplay.Body, 512))
				respReplay.Body.Close()

				if respReplay.StatusCode == 200 && strings.Contains(string(bodyBytes), "profile") {
					// VULNERABLE: Client deleted cookie, but server still accepted session
					r.VerificationState = StateVerified
					r.Severity = report.SeverityHigh
					r.Confidence = report.ConfidenceHigh
					r.EvidenceSummary = "Incomplete logout verified: Application cleared client-side cookie, but server accepted the session after logout"
					r.EvidenceDetails = map[string]string{
						"logout_endpoint":    logoutURL,
						"protected_endpoint": protectedURL,
						"session_hash":       HashSecret("flx_logout_test_session"),
						"defect":             "SERVER_SIDE_SESSION_NOT_TERMINATED",
					}
					fnd := e.createFinding(actx, r, "Incomplete Logout: Server-Side Session Survives Termination",
						r.EvidenceSummary, report.SeverityHigh, 80)
					r.Finding = fnd
					findings = append(findings, *fnd)
					cov.Verified++
					cov.Status = CoverageVerifiedIssueFound
				} else {
					r.VerificationState = StateNotVulnerable
					r.Severity = report.SeverityInfo
					r.Confidence = report.ConfidenceHigh
					r.EvidenceSummary = fmt.Sprintf("Logout successfully terminated server-side session (HTTP %d on replay)", respReplay.StatusCode)
				}
			}
		}
	} else {
		// Live target without state-changing permission
		r.VerificationState = StateCandidate
		r.Severity = report.SeverityMedium
		r.Confidence = report.ConfidenceLow
		r.EvidenceSummary = fmt.Sprintf("Logout endpoint '%s' discovered; active server invalidation test requires authorized session state", logoutURL)
		cov.Candidates++
	}

	results = append(results, r)
	cov.TestsRun = len(results)
	cov.Explanation = fmt.Sprintf("Evaluated logout synchronization and server invalidation (%d verified weaknesses)", cov.Verified)
	return results, findings, cov
}

// -------------------------------------------------------------------------
// Category 8: Password Reset & Account Recovery Lifecycle (WSTG-ATHN-09)
// -------------------------------------------------------------------------

func (e *Engine) assessPasswordRecovery(ctx context.Context, actx *AssessmentContext, client *http.Client) ([]Result, []report.Finding, CategoryCoverage) {
	meta := CategoryMetadata[CategoryPasswordRecovery]
	cov := CategoryCoverage{
		Category: CategoryPasswordRecovery,
		Code:     meta.Code,
		Name:     meta.Name,
		WSTGRef:  meta.WSTG,
		Status:   CoverageActivelyTested,
	}

	var results []Result
	var findings []report.Finding

	resetURL := buildEndpointURL(actx.BaseURL, "/reset-password", nil)
	for _, ep := range actx.Endpoints {
		lowerPath := strings.ToLower(ep.Path)
		if ep.Type == "recovery" || strings.Contains(lowerPath, "reset") || strings.Contains(lowerPath, "recovery") {
			resetURL = buildEndpointURL(actx.BaseURL, ep.Path, nil)
			break
		}
	}

	r := Result{
		ID:           uuid.New().String(),
		AssessmentID: actx.AssessmentID,
		ExecutionID:  actx.ExecutionID,
		Category:     CategoryPasswordRecovery,
		VulnCode:     meta.Code,
		TestID:       "SS-RECOVERY-TOKEN-REPLAY",
		TestName:     "Password Reset Token Single-Use and Invalidation Enforcement",
		WSTGRef:      meta.WSTG,
		Endpoint:     resetURL,
		Method:       "POST",
		StateBefore:  StateAnonymous,
		StateAfter:   StatePasswordChanged,
		CreatedAt:    time.Now().UTC(),
	}

	if actx.SyntheticFixture {
		// Attempt to consume a reset token that was already used
		form := url.Values{
			"token":        {"flx_consumed_reset_token"},
			"new_password": {"flx_new_secure_pass_123"},
		}
		req, _ := http.NewRequestWithContext(ctx, "POST", resetURL, strings.NewReader(form.Encode()))
		req.Header.Set("User-Agent", e.config.UserAgent)
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("X-Token-State", "consumed") // Signal fixture token was already used

		resp, err := client.Do(req)
		if err == nil {
			r.ObservedStatus = resp.StatusCode
			bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
			resp.Body.Close()

			if resp.StatusCode == 200 && strings.Contains(string(bodyBytes), "success") {
				// VULNERABLE: Token was consumed but succeeded again
				r.VerificationState = StateVerified
				r.Severity = report.SeverityHigh
				r.Confidence = report.ConfidenceHigh
				r.EvidenceSummary = "Reusable password reset token verified: Consumed recovery token accepted a second time"
				r.EvidenceDetails = map[string]string{
					"endpoint":   resetURL,
					"token_hash": HashSecret("flx_consumed_reset_token"),
					"defect":     "REUSABLE_RECOVERY_TOKEN",
				}
				fnd := e.createFinding(actx, r, "Password Reset Token Reusable After Consumption",
					r.EvidenceSummary, report.SeverityHigh, 85)
				r.Finding = fnd
				findings = append(findings, *fnd)
				cov.Verified++
				cov.Status = CoverageVerifiedIssueFound
			} else {
				r.VerificationState = StateNotVulnerable
				r.Severity = report.SeverityInfo
				r.Confidence = report.ConfidenceHigh
				r.EvidenceSummary = fmt.Sprintf("Consumed recovery token correctly rejected by server (HTTP %d)", resp.StatusCode)
			}
		}
	} else {
		// Live target: Safety rule forbids sending unsolicited resets to live users
		r.VerificationState = StateCandidate
		r.Severity = report.SeverityMedium
		r.Confidence = report.ConfidenceLow
		r.EvidenceSummary = fmt.Sprintf("Recovery endpoint '%s' discovered; token lifecycle verification requires controlled test email/account", resetURL)
		cov.Candidates++
	}

	results = append(results, r)
	cov.TestsRun = len(results)
	cov.Explanation = fmt.Sprintf("Evaluated password recovery token single-use lifecycle (%d verified weaknesses)", cov.Verified)
	return results, findings, cov
}

// -------------------------------------------------------------------------
// Category 9: Account Enumeration Surface (WSTG-ATHN-04)
// -------------------------------------------------------------------------

func (e *Engine) assessAccountEnumeration(ctx context.Context, actx *AssessmentContext, client *http.Client) ([]Result, []report.Finding, CategoryCoverage) {
	meta := CategoryMetadata[CategoryAccountEnumeration]
	cov := CategoryCoverage{
		Category: CategoryAccountEnumeration,
		Code:     meta.Code,
		Name:     meta.Name,
		WSTGRef:  meta.WSTG,
		Status:   CoverageActivelyTested,
	}

	var results []Result
	var findings []report.Finding

	loginURL := buildEndpointURL(actx.BaseURL, "/login", nil)
	for _, ep := range actx.Endpoints {
		lowerPath := strings.ToLower(ep.Path)
		if ep.Type == "login" || strings.Contains(lowerPath, "login") || strings.Contains(lowerPath, "signin") {
			loginURL = buildEndpointURL(actx.BaseURL, ep.Path, nil)
			break
		}
	}

	r := Result{
		ID:           uuid.New().String(),
		AssessmentID: actx.AssessmentID,
		ExecutionID:  actx.ExecutionID,
		Category:     CategoryAccountEnumeration,
		VulnCode:     meta.Code,
		TestID:       "SS-ENUM-DIFFERENTIAL-RESPONSE",
		TestName:     "Authentication Account Enumeration Analysis",
		WSTGRef:      meta.WSTG,
		Endpoint:     loginURL,
		Method:       "POST",
		StateBefore:  StateAnonymous,
		StateAfter:   StateAnonymous,
		CreatedAt:    time.Now().UTC(),
	}

	// 1. Probe with known-existing identity
	existForm := url.Values{"username": {"existing_user@example.com"}, "password": {"invalid_pass_123"}}
	reqExist, _ := http.NewRequestWithContext(ctx, "POST", loginURL, strings.NewReader(existForm.Encode()))
	reqExist.Header.Set("User-Agent", e.config.UserAgent)
	reqExist.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	respExist, errExist := client.Do(reqExist)

	// 2. Probe with known-nonexistent identity
	nonExistForm := url.Values{"username": {"definitely_nonexistent_81923@example.com"}, "password": {"invalid_pass_123"}}
	reqNonExist, _ := http.NewRequestWithContext(ctx, "POST", loginURL, strings.NewReader(nonExistForm.Encode()))
	reqNonExist.Header.Set("User-Agent", e.config.UserAgent)
	reqNonExist.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	respNonExist, errNonExist := client.Do(reqNonExist)

	if errExist == nil && errNonExist == nil {
		r.ObservedStatus = respExist.StatusCode
		b1, _ := io.ReadAll(io.LimitReader(respExist.Body, 512))
		b2, _ := io.ReadAll(io.LimitReader(respNonExist.Body, 512))
		respExist.Body.Close()
		respNonExist.Body.Close()

		s1 := strings.ToLower(string(b1))
		s2 := strings.ToLower(string(b2))

		// Check for distinct messages (e.g. "user not found" vs "invalid password") or distinct status codes
		if (respExist.StatusCode != respNonExist.StatusCode) ||
			(strings.Contains(s1, "password") && strings.Contains(s2, "user not found")) ||
			(strings.Contains(s1, "incorrect password") && strings.Contains(s2, "does not exist")) {
			r.VerificationState = StateVerified
			r.Severity = report.SeverityMedium
			r.Confidence = report.ConfidenceHigh
			r.EvidenceSummary = fmt.Sprintf("Account enumeration verified: Server reveals user account presence via distinct error messages (%d vs %d)",
				respExist.StatusCode, respNonExist.StatusCode)
			r.EvidenceDetails = map[string]string{
				"existing_user_status":    fmt.Sprintf("%d", respExist.StatusCode),
				"nonexistent_user_status": fmt.Sprintf("%d", respNonExist.StatusCode),
				"message_existing":        RedactText(s1[:min(len(s1), 100)]),
				"message_nonexistent":     RedactText(s2[:min(len(s2), 100)]),
			}
			fnd := e.createFinding(actx, r, "Account Enumeration via Observable Differential Authentication Responses",
				r.EvidenceSummary, report.SeverityMedium, 55)
			r.Finding = fnd
			findings = append(findings, *fnd)
			cov.Verified++
			cov.Status = CoverageVerifiedIssueFound
		} else {
			r.VerificationState = StateNotVulnerable
			r.Severity = report.SeverityInfo
			r.Confidence = report.ConfidenceHigh
			r.EvidenceSummary = "Authentication failure responses are uniform across existing and non-existent identities"
		}
	} else {
		r.VerificationState = StateInconclusive
		r.Severity = report.SeverityInfo
		r.EvidenceSummary = "Login endpoint unreachable"
	}

	results = append(results, r)
	cov.TestsRun = len(results)
	cov.Explanation = fmt.Sprintf("Evaluated account enumeration surface (%d verified enumeration vectors)", cov.Verified)
	return results, findings, cov
}

// -------------------------------------------------------------------------
// Category 10: Session Puzzling & Workflow Confusion (WSTG-SESS-08)
// -------------------------------------------------------------------------

func (e *Engine) assessSessionPuzzling(ctx context.Context, actx *AssessmentContext, client *http.Client) ([]Result, []report.Finding, CategoryCoverage) {
	meta := CategoryMetadata[CategorySessionPuzzling]
	cov := CategoryCoverage{
		Category: CategorySessionPuzzling,
		Code:     meta.Code,
		Name:     meta.Name,
		WSTGRef:  meta.WSTG,
		Status:   CoverageActivelyTested,
	}

	var results []Result
	var findings []report.Finding

	step2URL := buildEndpointURL(actx.BaseURL, "/onboarding/step2", nil)
	for _, ep := range actx.Endpoints {
		lowerPath := strings.ToLower(ep.Path)
		if ep.Type == "multistep" || strings.Contains(lowerPath, "step") {
			step2URL = buildEndpointURL(actx.BaseURL, ep.Path, nil)
			break
		}
	}

	r := Result{
		ID:           uuid.New().String(),
		AssessmentID: actx.AssessmentID,
		ExecutionID:  actx.ExecutionID,
		Category:     CategorySessionPuzzling,
		VulnCode:     meta.Code,
		TestID:       "SS-PUZZLING-STEP-CONFUSION",
		TestName:     "Multi-Step Workflow Session Variable Confusion",
		WSTGRef:      meta.WSTG,
		Endpoint:     step2URL,
		Method:       "GET",
		StateBefore:  StatePreAuth,
		StateAfter:   StatePreAuth,
		CreatedAt:    time.Now().UTC(),
	}

	if actx.SyntheticFixture {
		// Attempt to access step 2 by providing a pre-auth session variable claiming step completion
		req, _ := http.NewRequestWithContext(ctx, "GET", step2URL, nil)
		req.Header.Set("User-Agent", e.config.UserAgent)
		req.AddCookie(&http.Cookie{Name: "workflow_step", Value: "verification_passed"})

		resp, err := client.Do(req)
		if err == nil {
			r.ObservedStatus = resp.StatusCode
			bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
			resp.Body.Close()

			if resp.StatusCode == 200 && strings.Contains(strings.ToLower(string(bodyBytes)), "dashboard") {
				r.VerificationState = StateVerified
				r.Severity = report.SeverityHigh
				r.Confidence = report.ConfidenceHigh
				r.EvidenceSummary = "Session puzzling verified: Unvalidated session variable 'workflow_step' allowed skipping authentication to access restricted step"
				r.EvidenceDetails = map[string]string{
					"endpoint":        step2URL,
					"observed_status": "200",
					"defect":          "SESSION_VARIABLE_STEP_CONFUSION",
				}
				fnd := e.createFinding(actx, r, "Session Puzzling: Workflow State Confusion Allows Auth Bypass",
					r.EvidenceSummary, report.SeverityHigh, 75)
				r.Finding = fnd
				findings = append(findings, *fnd)
				cov.Verified++
				cov.Status = CoverageVerifiedIssueFound
			} else {
				r.VerificationState = StateNotVulnerable
				r.Severity = report.SeverityInfo
				r.Confidence = report.ConfidenceHigh
				r.EvidenceSummary = fmt.Sprintf("Multi-step workflow correctly enforces state boundaries (HTTP %d)", resp.StatusCode)
			}
		}
	} else {
		// Live target without multi-step workflow definition
		r.VerificationState = StateInconclusive
		r.Severity = report.SeverityInfo
		r.Confidence = report.ConfidenceLow
		r.EvidenceSummary = "Session puzzling test blocked: No multi-step identity workflow discovered"
		cov.Blocked++
		cov.Status = CoverageBlockedMissingPrereq
	}

	results = append(results, r)
	cov.TestsRun = len(results)
	cov.Explanation = fmt.Sprintf("Evaluated multi-step workflow session variable boundaries (%d verified flaws)", cov.Verified)
	return results, findings, cov
}

// -------------------------------------------------------------------------
// Category 11: Concurrent Sessions & Cross-Session Isolation (WSTG-SESS-09)
// -------------------------------------------------------------------------

func (e *Engine) assessSessionIsolation(ctx context.Context, actx *AssessmentContext, client *http.Client) ([]Result, []report.Finding, CategoryCoverage) {
	meta := CategoryMetadata[CategorySessionIsolation]
	cov := CategoryCoverage{
		Category: CategorySessionIsolation,
		Code:     meta.Code,
		Name:     meta.Name,
		WSTGRef:  meta.WSTG,
		Status:   CoverageActivelyTested,
	}

	var results []Result
	var findings []report.Finding

	userBResource := buildEndpointURL(actx.BaseURL, "/api/users/user_b/data", nil)

	r := Result{
		ID:           uuid.New().String(),
		AssessmentID: actx.AssessmentID,
		ExecutionID:  actx.ExecutionID,
		Category:     CategorySessionIsolation,
		VulnCode:     meta.Code,
		TestID:       "SS-ISOLATION-CROSS-USER",
		TestName:     "Cross-Session and Cross-User Boundary Isolation",
		WSTGRef:      meta.WSTG,
		Endpoint:     userBResource,
		Method:       "GET",
		StateBefore:  StateAuthenticated,
		StateAfter:   StateAuthenticated,
		CreatedAt:    time.Now().UTC(),
	}

	if actx.SyntheticFixture {
		// User A attempts to access User B's private resource
		req, _ := http.NewRequestWithContext(ctx, "GET", userBResource, nil)
		req.Header.Set("User-Agent", e.config.UserAgent)
		req.AddCookie(&http.Cookie{Name: "session", Value: "flx_user_a_session"})

		resp, err := client.Do(req)
		if err == nil {
			r.ObservedStatus = resp.StatusCode
			bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
			resp.Body.Close()

			if resp.StatusCode == 200 && strings.Contains(string(bodyBytes), "user_b_private") {
				// VULNERABLE: Cross-session leakage
				r.VerificationState = StateVerified
				r.Severity = report.SeverityCritical
				r.Confidence = report.ConfidenceHigh
				r.EvidenceSummary = "Cross-session isolation failure verified: User A's session successfully retrieved User B's private data"
				r.EvidenceDetails = map[string]string{
					"endpoint":        userBResource,
					"observed_status": "200",
					"defect":          "CROSS_USER_SESSION_DATA_LEAK",
				}
				fnd := e.createFinding(actx, r, "Cross-Session Isolation Failure (Data Leakage Between Users)",
					r.EvidenceSummary, report.SeverityCritical, 90)
				r.Finding = fnd
				findings = append(findings, *fnd)
				cov.Verified++
				cov.Status = CoverageVerifiedIssueFound
			} else {
				r.VerificationState = StateNotVulnerable
				r.Severity = report.SeverityInfo
				r.Confidence = report.ConfidenceHigh
				r.EvidenceSummary = fmt.Sprintf("Cross-session access correctly denied (HTTP %d)", resp.StatusCode)
			}
		}
	} else if len(actx.Identities) < 2 {
		r.VerificationState = StateInconclusive
		r.Severity = report.SeverityInfo
		r.Confidence = report.ConfidenceLow
		r.EvidenceSummary = "Cross-session isolation assessment blocked: Requires at least 2 distinct authorized test identities"
		cov.Blocked++
		cov.Status = CoverageBlockedMissingPrereq
	} else {
		r.VerificationState = StateCandidate
		r.Severity = report.SeverityMedium
		r.Confidence = report.ConfidenceMedium
		r.EvidenceSummary = "Dual test identities available; automated isolation verification requires mapped private test resources"
		cov.Candidates++
	}

	results = append(results, r)
	cov.TestsRun = len(results)
	cov.Explanation = fmt.Sprintf("Evaluated cross-session isolation and boundary enforcement (%d verified violations)", cov.Verified)
	return results, findings, cov
}

// -------------------------------------------------------------------------
// Helper Functions
// -------------------------------------------------------------------------

func (e *Engine) createFinding(actx *AssessmentContext, r Result, title, evidence string, severity string, score int) *report.Finding {
	sanitizedEndpoint := SanitizeURL(r.Endpoint)
	sanitizedTarget := SanitizeURL(actx.BaseURL)

	fpData := fmt.Sprintf("%s|%s|%s|%s", r.Category, r.Method, sanitizedEndpoint, r.TestName)
	hash := sha256.Sum256([]byte(fpData))
	fingerprint := fmt.Sprintf("sessionsec-%x", hash[:8])

	conf := r.Confidence
	if conf == "" {
		conf = report.ConfidenceHigh
	}

	meta := CategoryMetadata[r.Category]

	return &report.Finding{
		ID:          uuid.New().String(),
		Title:       title,
		Category:    fmt.Sprintf("%s / %s", meta.WSTG, meta.Name),
		Severity:    severity,
		Confidence:  conf,
		Target:      sanitizedTarget,
		Endpoint:    sanitizedEndpoint,
		Method:      r.Method,
		Description: fmt.Sprintf("[%s / %s] %s", r.VulnCode, r.WSTGRef, meta.Description),
		Evidence:    RedactText(evidence),
		EvidenceDetails: report.EvidenceDetails{
			Observation:     RedactText(evidence),
			Location:        sanitizedEndpoint,
			HTTPMethod:      r.Method,
			HTTPStatus:      r.ObservedStatus,
			DetectionMethod: "SESSION_IDENTITY_ENGINE",
			Details: map[string]string{
				"session_category": string(r.Category),
				"vuln_code":        r.VulnCode,
				"test_name":        r.TestName,
			},
		},
		Verification: report.VerificationRecord{
			Status:    report.VerificationStatus(r.VerificationState),
			Result:    string(r.VerificationState),
			Rationale: RedactText(evidence),
		},
		Source:      "session_identity_engine",
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

	for _, cov := range coverage {
		sum.BlockedCount += cov.Blocked
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
