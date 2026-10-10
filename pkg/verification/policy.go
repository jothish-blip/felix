package verification

import (
	"context"
	"fmt"
	"strings"
	"time"

	"felix/pkg/report"
	"github.com/google/uuid"
)

// Policy defines the verification contract for a class of security findings.
type Policy interface {
	ID() string
	Version() string
	Name() string
	Description() string
	AppliesTo(f report.Finding) bool
	Verify(ctx context.Context, f report.Finding, checker *SafetyChecker) (VerificationResult, error)
}

// BasePolicy provides common evaluation and result generation helpers.
type BasePolicy struct {
	id          string
	version     string
	name        string
	description string
}

func (bp *BasePolicy) ID() string          { return bp.id }
func (bp *BasePolicy) Version() string     { return bp.version }
func (bp *BasePolicy) Name() string        { return bp.name }
func (bp *BasePolicy) Description() string { return bp.description }

// createResult constructs a populated VerificationResult.
func (bp *BasePolicy) createResult(
	f report.Finding,
	status report.VerificationStatus,
	method string,
	attempted bool,
	detConf string,
	verConf string,
	criteria []CriterionResult,
	expected string,
	observed string,
	preconditions []string,
	limitations []string,
	failureReason string,
	inconclusiveReason string,
	safety SafetyDecisionResult,
	synthetic bool,
	startTime time.Time,
) VerificationResult {
	// Check mandatory criteria
	mandatoryPassed := true
	for _, c := range criteria {
		if c.Status != CriterionPassed && !strings.Contains(c.CriterionID, "OPTIONAL") && !strings.Contains(c.CriterionID, "NEG") {
			mandatoryPassed = false
			break
		}
	}

	// Status invariants:
	// 1. VERIFIED strictly requires all mandatory criteria to pass
	if status == StatusVerified && !mandatoryPassed {
		status = StatusNotVerified
		if failureReason == "" {
			failureReason = "Mandatory proof criteria not satisfied"
		}
	}

	// 2. NOT_EXPOSED strictly requires applicable negative criteria to pass
	negativePassed := false
	for _, c := range criteria {
		if strings.Contains(c.CriterionID, "NEG") && c.Status == CriterionPassed {
			negativePassed = true
			break
		}
	}
	if status == StatusNotExposed && !negativePassed {
		status = StatusNotVerified
		if failureReason == "" {
			failureReason = "Claim-specific negative criteria not satisfied"
		}
	}

	// 3. Contradiction detection:
	// Evidence contradicts original positive claim, but does not establish conclusive negative proof
	hasContradiction := false
	if status != StatusNotExposed {
		if f.EvidenceDetails.HTTPStatus == 404 || (f.EvidenceDetails.HTTPStatus >= 400 && f.EvidenceDetails.HTTPStatus <= 403 && status != StatusVerified) {
			hasContradiction = true
		}
		for _, c := range criteria {
			if c.Status == CriterionFailed && strings.Contains(strings.ToLower(c.Rationale), "contradict") {
				hasContradiction = true
				break
			}
		}
	}

	confRes := ComputeConfidence(detConf, verConf, status, hasContradiction, synthetic, mandatoryPassed)

	repro := BuildReproductionContext(
		f,
		f.Target,
		bp.id,
		status,
		expected,
		observed,
		preconditions,
		limitations,
	)

	var evRefs []string
	if f.Endpoint != "" {
		evRefs = append(evRefs, f.Endpoint)
	}
	if f.Evidence != "" {
		evRefs = append(evRefs, f.Evidence)
	}

	return VerificationResult{
		ID:                     "VER-" + uuid.New().String(),
		FindingID:              f.ID,
		TargetURL:              f.Target,
		Endpoint:               f.Endpoint,
		Category:               f.Category,
		Status:                 status,
		VerificationMethod:     method,
		PolicyID:               bp.id,
		PolicyVersion:          bp.version,
		Attempted:              attempted,
		DetectionConfidence:    confRes.DetectionConfidence,
		VerificationConfidence: confRes.VerificationConfidence,
		OverallConfidence:      confRes.OverallConfidence,
		ConfidenceScore:        confRes.Score,
		ConfidenceRationale:    confRes.Rationale,
		EvidenceReferences:     evRefs,
		Reproduction:           repro,
		Preconditions:          preconditions,
		ExpectedBehavior:       expected,
		ObservedBehavior:       observed,
		CriteriaResults:        criteria,
		Limitations:            limitations,
		FailureReason:          failureReason,
		InconclusiveReason:     inconclusiveReason,
		SafetyDecision:         safety.Decision,
		BlockReason:            safety.BlockReason,
		SyntheticFixture:       synthetic,
		VerifierVersion:        "2.0.0",
		StartedAt:              startTime,
		CompletedAt:            time.Now().UTC(),
	}
}

// -----------------------------------------------------------------------------
// 1. Discovery & Exposure Policy (POL-DISC-01)
// -----------------------------------------------------------------------------

type DiscoveryExposurePolicy struct {
	BasePolicy
}

func NewDiscoveryExposurePolicy() *DiscoveryExposurePolicy {
	return &DiscoveryExposurePolicy{
		BasePolicy: BasePolicy{
			id:          "POL-DISC-01",
			version:     "2.0.0",
			name:        "Discovery and Exposure Verification Policy",
			description: "Distinguishes discovered assets, candidate exposures, affirmative protection, and proven public leaks.",
		},
	}
}

func (p *DiscoveryExposurePolicy) AppliesTo(f report.Finding) bool {
	cat := strings.ToUpper(f.Category)
	src := f.Source
	return src == report.SourceCrawler || src == report.SourceSecrets ||
		strings.Contains(cat, "DISCOVERY") || strings.Contains(cat, "RECON") ||
		strings.Contains(cat, "EXPOSURE") || strings.Contains(cat, "SECRET")
}

func (p *DiscoveryExposurePolicy) Verify(ctx context.Context, f report.Finding, checker *SafetyChecker) (VerificationResult, error) {
	start := time.Now().UTC()
	cat := strings.ToUpper(f.Category)
	synthetic := f.Verification.SyntheticFixture || strings.Contains(f.Evidence, "[SYNTHETIC FIXTURE]") || strings.Contains(f.Title, "[SYNTHETIC FIXTURE]")

	// Safety check
	safety := checker.Check(f.Target, f.Endpoint, f.Method, false)
	if !safety.Allowed {
		return p.createResult(
			f, StatusNotVerified, "safety_block", false,
			f.Confidence, ConfidenceNone, nil,
			"Scope and authorization validation", "Verification probe blocked by safety controls",
			nil, []string{"Safety control prevented active probe"},
			safety.BlockReason, "Check blocked by safety controls",
			safety, synthetic, start,
		), nil
	}

	var criteria []CriterionResult

	// Case 1: Secrets in client code (SourceSecrets)
	if f.Source == report.SourceSecrets || strings.Contains(cat, "SECRET") {
		// Mandatory rule: Live credential testing is avoided to prevent lockouts
		criteria = append(criteria, CriterionResult{
			CriterionID: "CRIT-STATIC-SIG",
			Name:        "Static Signature Match",
			Status:      CriterionPassed,
			Evidence:    f.Evidence,
			Rationale:   "Pattern matched credential structure in client bundle",
		})
		criteria = append(criteria, CriterionResult{
			CriterionID: "CRIT-LIVE-PROOF",
			Name:        "Live Credential Verification",
			Status:      CriterionSkipped,
			Rationale:   "Live credential probe intentionally avoided by safe audit policy",
		})

		return p.createResult(
			f, StatusNotVerified, "static_pattern_analysis", true,
			f.Confidence, ConfidenceLow, criteria,
			"Credential confirmed functional on live provider endpoint",
			"Pattern identified in client asset; live credential validation skipped for safety",
			[]string{"Client assets parsed"},
			[]string{"Live credential testing not executed"},
			"", "Live credential validity not tested",
			safety, synthetic, start,
		), nil
	}

	// Case 2: Claim-specific negative verification
	// NOT_EXPOSED is valid ONLY when:
	// a) The finding specifically claimed public unauthenticated access to an exact file/endpoint
	// b) The probe specifically tested that claim under anonymous/unauthenticated conditions
	// c) Documented negative evidence confirms access was denied (401/403)
	isPublicExposureClaim := strings.Contains(strings.ToLower(f.Title), "public") ||
		strings.Contains(strings.ToLower(f.Title), "exposed") ||
		strings.Contains(strings.ToLower(f.Category), "exposure")
	hasDocumentedNegativeEvidence := f.EvidenceDetails.NegativeEvidence != "" ||
		(f.EvidenceDetails.Details != nil && f.EvidenceDetails.Details["negative_proof"] == "true")
	hasAccessDeniedStatus := f.EvidenceDetails.HTTPStatus == 401 || f.EvidenceDetails.HTTPStatus == 403

	if isPublicExposureClaim && hasDocumentedNegativeEvidence && hasAccessDeniedStatus {
		criteria = append(criteria, CriterionResult{
			CriterionID: "CRIT-NEG-AUTH-DENIED",
			Name:        "Specific Resource Access Control Enforced",
			Status:      CriterionPassed,
			Evidence:    fmt.Sprintf("HTTP %d received for tested resource", f.EvidenceDetails.HTTPStatus),
			Rationale:   fmt.Sprintf("Specific unauthenticated access claim for %s was disproved: target returned HTTP %d", f.Endpoint, f.EvidenceDetails.HTTPStatus),
		})

		return p.createResult(
			f, StatusNotExposed, "active_probe_boundary_check", true,
			report.ConfidenceHigh, ConfidenceHigh, criteria,
			"Access denied by authentication or authorization boundary for tested resource",
			fmt.Sprintf("Access denied (HTTP %d) on tested endpoint; does not prove overall application is secure", f.EvidenceDetails.HTTPStatus),
			[]string{"Anonymous HTTP probe against specific endpoint"},
			[]string{"Verification strictly limited to tested resource and unauthenticated caller; other endpoints and roles not tested"},
			"", "",
			safety, synthetic, start,
		), nil
	}

	// Case 3: Contradictory evidence (e.g. 404 Not Found, connection reset)
	// Contradicts claim of exposure, but HTTP 404 does NOT prove vulnerability is absent or site is secure!
	if f.EvidenceDetails.HTTPStatus == 404 {
		criteria = append(criteria, CriterionResult{
			CriterionID: "CRIT-EXPOSURE-404-CONTRADICTION",
			Name:        "Endpoint Not Found",
			Status:      CriterionFailed,
			Evidence:    "HTTP 404 Not Found",
			Rationale:   "HTTP 404 contradicts positive exposure claim but does not conclusively disprove vulnerability under negative policy; recorded as NOT_VERIFIED",
		})
		return p.createResult(
			f, StatusNotVerified, "active_get_probe", true,
			f.Confidence, ConfidenceLow, criteria,
			"Resource reachable with HTTP 200",
			"HTTP 404 Not Found returned (contradicts exposure hypothesis without proving negative security)",
			nil, []string{"Target returned 404; route may be moved, protected, or virtual-host dependent"},
			"Endpoint returned 404; exposure unverified", "Contradictory response without conclusive negative proof",
			safety, synthetic, start,
		), nil
	}

	// Case 4: Generic 401/403 without specific claim-matching negative criteria
	// A generic status code alone must NEVER prove an application is secure!
	if hasAccessDeniedStatus {
		criteria = append(criteria, CriterionResult{
			CriterionID: "CRIT-GENERIC-STATUS-INCONCLUSIVE",
			Name:        "Generic Status Code Evaluation",
			Status:      CriterionInconclusive,
			Evidence:    fmt.Sprintf("HTTP %d received", f.EvidenceDetails.HTTPStatus),
			Rationale:   fmt.Sprintf("HTTP %d observed, but generic status code alone does not disprove exposure claim without documented negative verification criteria", f.EvidenceDetails.HTTPStatus),
		})
		return p.createResult(
			f, StatusNotVerified, "status_inspection", true,
			f.Confidence, ConfidenceLow, criteria,
			"Documented negative verification criteria satisfying claim disproof",
			fmt.Sprintf("Generic HTTP %d observed without documented claim-specific negative evidence", f.EvidenceDetails.HTTPStatus),
			nil, []string{"Generic status code cannot establish that resource or application is secure"},
			"Generic status code lacks claim-specific negative proof", "Inconclusive negative evidence",
			safety, synthetic, start,
		), nil
	}

	// Case 3: Confirmed public configuration exposure (.env, .git/HEAD) with content proof
	isDirectExposure := (strings.Contains(f.Endpoint, ".env") || strings.Contains(f.Endpoint, ".git")) &&
		f.EvidenceDetails.HTTPStatus == 200 &&
		len(f.Evidence) > 0 &&
		!strings.Contains(f.Evidence, "<html") && !strings.Contains(f.Evidence, "<!DOCTYPE")

	if isDirectExposure {
		criteria = append(criteria, CriterionResult{
			CriterionID: "CRIT-EXACT-RESOURCE",
			Name:        "Exact Sensitive Resource Retrieved",
			Status:      CriterionPassed,
			Evidence:    f.Endpoint,
			Rationale:   "Sensitive configuration file reached directly via public request",
		})
		criteria = append(criteria, CriterionResult{
			CriterionID: "CRIT-BODY-CONTENT",
			Name:        "Sensitive Content Verified",
			Status:      CriterionPassed,
			Evidence:    report.SanitizeEvidence(f.Evidence),
			Rationale:   "Response body verified containing sensitive keys or git object format",
		})

		return p.createResult(
			f, StatusVerified, "active_get_probe", true,
			report.ConfidenceHigh, ConfidenceHigh, criteria,
			"Access denied or 404 Not Found",
			"HTTP 200 OK with sensitive configuration content returned",
			[]string{"Direct HTTP reachability"}, nil,
			"", "",
			safety, synthetic, start,
		), nil
	}

	// Case 4: Discovered route or asset without proof of vulnerability -> OBSERVED
	criteria = append(criteria, CriterionResult{
		CriterionID: "CRIT-ASSET-OBSERVED",
		Name:        "Asset Reachability Observed",
		Status:      CriterionPassed,
		Evidence:    f.Endpoint,
		Rationale:   "Endpoint/asset was discovered and indexed during crawling",
	})
	criteria = append(criteria, CriterionResult{
		CriterionID: "CRIT-VULN-PROOF",
		Name:        "Vulnerability Proof",
		Status:      CriterionSkipped,
		Rationale:   "No vulnerability claim made; asset observation only",
	})

	return p.createResult(
		f, StatusObserved, "discovery_crawl", true,
		report.ConfidenceLow, ConfidenceNone, criteria,
		"Expected standard web route behavior",
		"Asset observed during discovery phase",
		nil, nil, "", "",
		safety, synthetic, start,
	), nil
}

// -----------------------------------------------------------------------------
// 2. Authentication Policy (POL-AUTH-01)
// -----------------------------------------------------------------------------

type AuthenticationPolicy struct {
	BasePolicy
}

func NewAuthenticationPolicy() *AuthenticationPolicy {
	return &AuthenticationPolicy{
		BasePolicy: BasePolicy{
			id:          "POL-AUTH-01",
			version:     "2.0.0",
			name:        "Authentication & Identity Verification Policy",
			description: "Verifies authentication boundary consistency, token acceptance, and session behavior.",
		},
	}
}

func (p *AuthenticationPolicy) AppliesTo(f report.Finding) bool {
	cat := strings.ToUpper(f.Category)
	return strings.Contains(cat, "AUTH") || strings.Contains(cat, "SESSION") ||
		strings.Contains(cat, "TOKEN") || strings.Contains(cat, "JWT") ||
		strings.Contains(cat, "LOGIN")
}

func (p *AuthenticationPolicy) Verify(ctx context.Context, f report.Finding, checker *SafetyChecker) (VerificationResult, error) {
	start := time.Now().UTC()
	synthetic := f.Verification.SyntheticFixture || strings.Contains(f.Evidence, "[SYNTHETIC FIXTURE]")

	safety := checker.Check(f.Target, f.Endpoint, f.Method, false)
	if !safety.Allowed {
		return p.createResult(
			f, StatusNotVerified, "safety_block", false,
			f.Confidence, ConfidenceNone, nil,
			"Authorized probe", "Verification probe blocked by safety controls",
			nil, []string{"Safety control prevented probe"},
			safety.BlockReason, "Safety blocked",
			safety, synthetic, start,
		), nil
	}

	var criteria []CriterionResult

	// Cookie attribute gap (e.g. HttpOnly / Secure missing on session cookie)
	// Evaluated FIRST so cookie flaws are never obscured by an authentication response code
	isCookieFlaw := strings.Contains(strings.ToLower(f.Title), "cookie") &&
		(strings.Contains(strings.ToLower(f.Title), "httponly") || strings.Contains(strings.ToLower(f.Title), "samesite") || strings.Contains(strings.ToLower(f.Title), "secure"))
	if isCookieFlaw && f.EvidenceDetails.Details != nil && f.EvidenceDetails.Details["cookie_name"] != "" {
		criteria = append(criteria, CriterionResult{
			CriterionID: "CRIT-COOKIE-HEADER",
			Name:        "Set-Cookie Header Inspected",
			Status:      CriterionPassed,
			Evidence:    f.Evidence,
			Rationale:   "Observed Set-Cookie header missing required security attribute on sensitive cookie",
		})
		return p.createResult(
			f, StatusVerified, "header_inspection", true,
			report.ConfidenceHigh, ConfidenceHigh, criteria,
			"Cookie should include HttpOnly, Secure, and SameSite attributes",
			"Cookie missing required security attributes",
			[]string{"Response header inspection"}, nil,
			"", "",
			safety, synthetic, start,
		), nil
	}

	// Claim-specific negative evidence:
	// A 401/403 proves NOT_EXPOSED ONLY IF:
	// 1) The finding specifically claimed unauthenticated access bypass on that route
	// 2) Documented unauthenticated identity context was tested
	// 3) Documented negative evidence confirms access was denied
	isUnauthBypassClaim := (strings.Contains(strings.ToLower(f.Title), "unauthenticated") ||
		strings.Contains(strings.ToLower(f.Title), "bypass") ||
		strings.Contains(strings.ToLower(f.Category), "unauthenticated")) &&
		!strings.Contains(strings.ToLower(f.Title), "cookie")
	hasNegativeEvidence := f.EvidenceDetails.NegativeEvidence != "" ||
		(f.EvidenceDetails.Details != nil && (f.EvidenceDetails.Details["unauth_bypass_tested"] == "true" || f.EvidenceDetails.Details["auth_enforced"] == "true"))
	hasAccessDenied := f.EvidenceDetails.HTTPStatus == 401 || f.EvidenceDetails.HTTPStatus == 403

	if isUnauthBypassClaim && hasNegativeEvidence && hasAccessDenied {
		criteria = append(criteria, CriterionResult{
			CriterionID: "CRIT-NEG-AUTHN-DISPROVED",
			Name:        "Authentication Barrier Enforced on Tested Route",
			Status:      CriterionPassed,
			Evidence:    fmt.Sprintf("HTTP %d returned on protected route", f.EvidenceDetails.HTTPStatus),
			Rationale:   fmt.Sprintf("Unauthenticated access bypass claim for %s disproved: target returned HTTP %d", f.Endpoint, f.EvidenceDetails.HTTPStatus),
		})
		return p.createResult(
			f, StatusNotExposed, "auth_barrier_check", true,
			report.ConfidenceHigh, ConfidenceHigh, criteria,
			"Authentication barrier enforced on tested endpoint",
			fmt.Sprintf("Authentication enforced with HTTP %d for unauthenticated caller; does not establish overall authentication system is defect-free", f.EvidenceDetails.HTTPStatus),
			[]string{"Anonymous/unauthenticated HTTP probe against protected endpoint"},
			[]string{"Negative verification strictly limited to tested endpoint; other endpoints, credential strength, and token handling not tested"},
			"", "",
			safety, synthetic, start,
		), nil
	}

	// Generic 401 or 403 without specific unauthenticated bypass claim & negative proof -> NOT_VERIFIED
	if hasAccessDenied {
		criteria = append(criteria, CriterionResult{
			CriterionID: "CRIT-GENERIC-AUTH-STATUS",
			Name:        "Generic Authentication Status Evaluation",
			Status:      CriterionInconclusive,
			Evidence:    fmt.Sprintf("HTTP %d returned", f.EvidenceDetails.HTTPStatus),
			Rationale:   "HTTP 401/403 observed, but status code alone does not prove authentication system is secure or disprove other auth weaknesses",
		})
		return p.createResult(
			f, StatusNotVerified, "auth_barrier_check", true,
			f.Confidence, ConfidenceLow, criteria,
			"Claim-specific negative proof establishing authentication security",
			fmt.Sprintf("Generic HTTP %d observed without documented unauthenticated bypass disproof", f.EvidenceDetails.HTTPStatus),
			nil, []string{"Generic status code cannot establish that overall authentication system is secure"},
			"Generic 401/403 status code does not disprove vulnerability", "Inconclusive authentication status",
			safety, synthetic, start,
		), nil
	}

	// Unauthenticated protected endpoint access: requires evidence that non-public sensitive data was returned
	isUnauthAccess := f.EvidenceDetails.HTTPStatus == 200 &&
		(strings.Contains(strings.ToLower(f.Title), "unauthenticated") || strings.Contains(strings.ToLower(f.Title), "bypass")) &&
		len(f.Evidence) > 0

	if isUnauthAccess {
		criteria = append(criteria, CriterionResult{
			CriterionID: "CRIT-UNAUTH-200",
			Name:        "Unauthenticated Request Succeeded",
			Status:      CriterionPassed,
			Evidence:    fmt.Sprintf("HTTP %d received without credentials", f.EvidenceDetails.HTTPStatus),
			Rationale:   "Protected route returned HTTP 200 without valid credentials",
		})
		return p.createResult(
			f, StatusVerified, "unauthenticated_probe", true,
			report.ConfidenceHigh, ConfidenceHigh, criteria,
			"HTTP 401 Unauthorized expected",
			"HTTP 200 OK returned with protected resources",
			[]string{"Unauthenticated request dispatched"}, nil,
			"", "",
			safety, synthetic, start,
		), nil
	}

	// Fallback for general auth findings without definitive proof: DETECTED -> NOT_VERIFIED
	criteria = append(criteria, CriterionResult{
		CriterionID: "CRIT-AUTH-INCONCLUSIVE",
		Name:        "Authentication Claim Validation",
		Status:      CriterionInconclusive,
		Rationale:   "Behavior observed but session reuse or credential bypass was not definitively proven",
	})
	return p.createResult(
		f, StatusNotVerified, "auth_evaluation", true,
		f.Confidence, ConfidenceLow, criteria,
		"Definitive proof of authentication failure",
		"Signal observed but insufficient proof for verified exploitability",
		nil, []string{"Session reuse not independently repeated"},
		"", "Insufficient evidence to verify authentication bypass claim",
		safety, synthetic, start,
	), nil
}

// -----------------------------------------------------------------------------
// 3. Authorization & BOLA/BFLA Policy (POL-AUTHZ-01)
// -----------------------------------------------------------------------------

type AuthorizationPolicy struct {
	BasePolicy
}

func NewAuthorizationPolicy() *AuthorizationPolicy {
	return &AuthorizationPolicy{
		BasePolicy: BasePolicy{
			id:          "POL-AUTHZ-01",
			version:     "2.0.0",
			name:        "Authorization & Access Control Verification Policy",
			description: "Requires controlled differential comparison (authorized vs unauthorized identity) to prove authorization bypass.",
		},
	}
}

func (p *AuthorizationPolicy) AppliesTo(f report.Finding) bool {
	cat := strings.ToUpper(f.Category)
	return strings.Contains(cat, "BOLA") || strings.Contains(cat, "IDOR") ||
		strings.Contains(cat, "BFLA") || strings.Contains(cat, "BOPLA") ||
		strings.Contains(cat, "AUTHORIZATION") || strings.Contains(cat, "PRIVILEGE")
}

func (p *AuthorizationPolicy) Verify(ctx context.Context, f report.Finding, checker *SafetyChecker) (VerificationResult, error) {
	start := time.Now().UTC()
	synthetic := f.Verification.SyntheticFixture || strings.Contains(f.Evidence, "[SYNTHETIC FIXTURE]")

	safety := checker.Check(f.Target, f.Endpoint, f.Method, false)
	if !safety.Allowed {
		return p.createResult(
			f, StatusNotVerified, "safety_block", false,
			f.Confidence, ConfidenceNone, nil,
			"Controlled differential access test", "Verification blocked by safety controls",
			nil, []string{"Safety control prevented probe"},
			safety.BlockReason, "Safety blocked",
			safety, synthetic, start,
		), nil
	}

	var criteria []CriterionResult

	// Check for required comparative differential authorization evidence:
	// Both negative verification (NOT_EXPOSED) and positive verification (VERIFIED) of BOLA/BFLA
	// require comparative access evidence establishing:
	// 1) Target resource identifier
	// 2) Resource owner identity
	// 3) Baseline access proof (resource exists and is accessible to owner)
	// 4) Distinct unauthorized identity context
	hasResource := f.EvidenceDetails.Details != nil && f.EvidenceDetails.Details["resource_id"] != ""
	hasOwner := f.EvidenceDetails.Details != nil && (f.EvidenceDetails.Details["owner_identity"] != "" || f.EvidenceDetails.Details["tenant_a"] != "")
	hasUnauthorizedCaller := f.EvidenceDetails.Details != nil && (f.EvidenceDetails.Details["unauthorized_identity"] != "" || f.EvidenceDetails.Details["tenant_b"] != "" || f.EvidenceDetails.Details["cross_tenant"] == "true")
	hasBaselineAccess := f.EvidenceDetails.Details != nil && (f.EvidenceDetails.Details["baseline_accessible"] == "true" || f.EvidenceDetails.Details["authorized_status"] == "200")

	hasComparativeEvidence := hasResource && hasOwner && hasUnauthorizedCaller && hasBaselineAccess

	// Case 1: Claim-specific negative verification
	// Requires FULL comparative differential evidence:
	// Owner had access, unauthorized caller was specifically denied (403/401), negative evidence documented
	hasAccessDenied := f.EvidenceDetails.HTTPStatus == 403 || f.EvidenceDetails.HTTPStatus == 401
	hasNegativeEvidence := f.EvidenceDetails.NegativeEvidence != "" || (f.EvidenceDetails.Details != nil && f.EvidenceDetails.Details["isolation_verified"] == "true")

	if hasComparativeEvidence && hasAccessDenied && hasNegativeEvidence {
		criteria = append(criteria, CriterionResult{
			CriterionID: "CRIT-NEG-AUTHZ-DIFFERENTIAL-DENIED",
			Name:        "Differential Authorization Barrier Enforced",
			Status:      CriterionPassed,
			Evidence:    fmt.Sprintf("Owner accessed resource; unauthorized caller received HTTP %d", f.EvidenceDetails.HTTPStatus),
			Rationale:   "Controlled differential test proved unauthorized identity was denied access to existing foreign resource while owner had access",
		})
		return p.createResult(
			f, StatusNotExposed, "differential_authz_probe", true,
			report.ConfidenceHigh, ConfidenceHigh, criteria,
			"Access denied (HTTP 403 Forbidden) for unauthorized tenant identity",
			fmt.Sprintf("Access denied (HTTP %d) for tested unauthorized identity against specific resource; does not prove overall application authorization is defect-free", f.EvidenceDetails.HTTPStatus),
			[]string{"Controlled differential identity test harness", "Verified resource ownership baseline"},
			[]string{"Verification strictly limited to tested resource and identity pair; other objects, tenants, or roles not tested"},
			"", "",
			safety, synthetic, start,
		), nil
	}

	// Case 2: Positive BOLA/BFLA verification
	// Requires comparative differential evidence + unauthorized caller accessed foreign object (HTTP 200 + leak)
	isUnauthorizedAccessSuccess := (f.EvidenceDetails.HTTPStatus == 200 || f.Verification.Status == report.VerificationVerified) &&
		len(f.Evidence) > 0 &&
		(f.EvidenceDetails.Details != nil && (f.EvidenceDetails.Details["cross_tenant_data_confirmed"] == "true" || f.EvidenceDetails.Details["cross_tenant"] == "true"))

	if hasComparativeEvidence && isUnauthorizedAccessSuccess {
		criteria = append(criteria, CriterionResult{
			CriterionID: "CRIT-DIFF-ACCESS",
			Name:        "Differential Access Demonstration",
			Status:      CriterionPassed,
			Evidence:    f.Evidence,
			Rationale:   "Controlled differential test proved unauthorized caller accessed restricted object",
		})
		criteria = append(criteria, CriterionResult{
			CriterionID: "CRIT-DATA-LEAK",
			Name:        "Cross-Tenant Record Disclosed",
			Status:      CriterionPassed,
			Evidence:    report.SanitizeEvidence(f.Evidence),
			Rationale:   "Object payload contained foreign tenant identifier without authorization barrier",
		})
		return p.createResult(
			f, StatusVerified, "differential_tenant_comparison", true,
			report.ConfidenceHigh, ConfidenceHigh, criteria,
			"HTTP 403 Forbidden for unauthorized tenant identity",
			"HTTP 200 OK with cross-tenant object disclosed",
			[]string{"Differential test identity configured", "Resource ownership baseline established"},
			nil, "", "",
			safety, synthetic, start,
		), nil
	}

	// Case 3: Missing comparative differential authorization evidence
	// Invariant: Missing comparative evidence MUST produce NOT_VERIFIED
	criteria = append(criteria, CriterionResult{
		CriterionID: "CRIT-DIFF-AUTHZ-INCONCLUSIVE",
		Name:        "Comparative Differential Evidence Audit",
		Status:      CriterionInconclusive,
		Evidence:    fmt.Sprintf("HTTP %d received; comparative proof available: %v", f.EvidenceDetails.HTTPStatus, hasComparativeEvidence),
		Rationale:   "Missing comparative differential authorization evidence (owner baseline, resource ownership, or distinct unauthorized identity); status code alone cannot establish authorization correctness or vulnerability",
	})
	return p.createResult(
		f, StatusNotVerified, "differential_authz_probe", true,
		f.Confidence, ConfidenceLow, criteria,
		"Controlled differential access test with distinct identities and baseline ownership",
		fmt.Sprintf("Single request response (HTTP %d) without complete comparative differential authorization evidence", f.EvidenceDetails.HTTPStatus),
		nil, []string{"Comparative test with multi-tenant identity credentials required"},
		"Missing comparative authorization evidence", "Inconclusive authorization proof",
		safety, synthetic, start,
	), nil
}

// -----------------------------------------------------------------------------
// 4. API Security Policy (POL-APISEC-01)
// -----------------------------------------------------------------------------

type APISecurityPolicy struct {
	BasePolicy
}

func NewAPISecurityPolicy() *APISecurityPolicy {
	return &APISecurityPolicy{
		BasePolicy: BasePolicy{
			id:          "POL-APISEC-01",
			version:     "2.0.0",
			name:        "API Security Verification Policy",
			description: "Verifies excessive data exposure, defensive headers, and API endpoint access controls.",
		},
	}
}

func (p *APISecurityPolicy) AppliesTo(f report.Finding) bool {
	cat := strings.ToUpper(f.Category)
	return f.Source == report.SourceAPI || strings.Contains(cat, "API") ||
		strings.Contains(cat, "EXCESSIVE") || strings.Contains(cat, "HEADERS")
}

func (p *APISecurityPolicy) Verify(ctx context.Context, f report.Finding, checker *SafetyChecker) (VerificationResult, error) {
	start := time.Now().UTC()
	synthetic := f.Verification.SyntheticFixture || strings.Contains(f.Evidence, "[SYNTHETIC FIXTURE]")

	safety := checker.Check(f.Target, f.Endpoint, f.Method, false)
	if !safety.Allowed {
		return p.createResult(
			f, StatusNotVerified, "safety_block", false,
			f.Confidence, ConfidenceNone, nil,
			"Authorized API probe", "Probe blocked by safety controls",
			nil, []string{"Safety control prevented probe"},
			safety.BlockReason, "Safety blocked",
			safety, synthetic, start,
		), nil
	}

	var criteria []CriterionResult

	// Missing security headers: verified if response headers confirmed missing required defensive header
	if strings.Contains(strings.ToLower(f.Category), "header") || strings.Contains(strings.ToLower(f.Title), "header") {
		criteria = append(criteria, CriterionResult{
			CriterionID: "CRIT-HEADER-INSPECTION",
			Name:        "HTTP Header Audit",
			Status:      CriterionPassed,
			Evidence:    f.Evidence,
			Rationale:   "Response header inspection verified absence of defensive security header",
		})
		return p.createResult(
			f, StatusVerified, "response_header_audit", true,
			report.ConfidenceHigh, ConfidenceHigh, criteria,
			"Defensive security header configured",
			"Header absent in response",
			[]string{"In-scope HTTP GET response"}, nil,
			"", "",
			safety, synthetic, start,
		), nil
	}

	// Excessive data exposure: verified if response contains sensitive data
	isDataExposure := strings.Contains(strings.ToLower(f.Category), "data_exposure") ||
		strings.Contains(strings.ToLower(f.Title), "pii") ||
		strings.Contains(strings.ToLower(f.Title), "excessive data")

	if isDataExposure && len(f.Evidence) > 0 {
		criteria = append(criteria, CriterionResult{
			CriterionID: "CRIT-SENSITIVE-DATA-RETURNED",
			Name:        "Sensitive Data in Payload",
			Status:      CriterionPassed,
			Evidence:    report.SanitizeEvidence(f.Evidence),
			Rationale:   "API response payload contains unneeded sensitive fields (PII/secrets)",
		})
		return p.createResult(
			f, StatusVerified, "payload_inspection", true,
			report.ConfidenceHigh, ConfidenceHigh, criteria,
			"Minimal response schema without sensitive data",
			"Sensitive fields present in JSON response body",
			[]string{"API endpoint query"}, nil,
			"", "",
			safety, synthetic, start,
		), nil
	}

	// Generic API finding without execution proof
	criteria = append(criteria, CriterionResult{
		CriterionID: "CRIT-API-VERIFICATION",
		Name:        "API Property Proof",
		Status:      CriterionInconclusive,
		Rationale:   "API endpoint responded but claimed vulnerability property was not empirically proven",
	})
	return p.createResult(
		f, StatusNotVerified, "api_heuristic", true,
		f.Confidence, ConfidenceLow, criteria,
		"Empirical proof of API vulnerability",
		"API behavior observed but insufficient proof for verified exploitability",
		nil, []string{"Extended API schema verification required"},
		"", "Inconclusive API security check",
		safety, synthetic, start,
	), nil
}

// -----------------------------------------------------------------------------
// 5. Web Vulnerability Policy (POL-WEBVULN-01)
// -----------------------------------------------------------------------------

type WebVulnerabilityPolicy struct {
	BasePolicy
}

func NewWebVulnerabilityPolicy() *WebVulnerabilityPolicy {
	return &WebVulnerabilityPolicy{
		BasePolicy: BasePolicy{
			id:          "POL-WEBVULN-01",
			version:     "2.0.0",
			name:        "Web Vulnerabilities Verification Policy",
			description: "Enforces safe, non-destructive proof for injection, XSS, SSRF, and directory traversal.",
		},
	}
}

func (p *WebVulnerabilityPolicy) AppliesTo(f report.Finding) bool {
	cat := strings.ToUpper(f.Category)
	return strings.Contains(cat, "XSS") || strings.Contains(cat, "SQLI") ||
		strings.Contains(cat, "INJECTION") || strings.Contains(cat, "SSRF") ||
		strings.Contains(cat, "TRAVERSAL") || strings.Contains(cat, "VULN")
}

func (p *WebVulnerabilityPolicy) Verify(ctx context.Context, f report.Finding, checker *SafetyChecker) (VerificationResult, error) {
	start := time.Now().UTC()
	synthetic := f.Verification.SyntheticFixture || strings.Contains(f.Evidence, "[SYNTHETIC FIXTURE]")

	safety := checker.Check(f.Target, f.Endpoint, f.Method, false)
	if !safety.Allowed {
		return p.createResult(
			f, StatusNotVerified, "safety_block", false,
			f.Confidence, ConfidenceNone, nil,
			"Non-destructive injection test", "Probe blocked by safety controls",
			nil, []string{"Safety control prevented probe"},
			safety.BlockReason, "Safety blocked",
			safety, synthetic, start,
		), nil
	}

	var criteria []CriterionResult

	// Invariant: Reflected string alone is NOT proof of XSS! Requires unescaped execution context
	isXSS := strings.Contains(strings.ToUpper(f.Category), "XSS") || strings.Contains(strings.ToUpper(f.Title), "XSS")
	if isXSS {
		// Check whether evidence demonstrates unescaped HTML/script execution context
		isUnescaped := strings.Contains(f.Evidence, "<script>") || strings.Contains(f.Evidence, "onerror=") ||
			(f.EvidenceDetails.Details != nil && f.EvidenceDetails.Details["unescaped_reflection"] == "true")

		if isUnescaped && f.EvidenceDetails.HTTPStatus == 200 {
			criteria = append(criteria, CriterionResult{
				CriterionID: "CRIT-UNESCAPED-REFLECTION",
				Name:        "Unescaped Execution Context",
				Status:      CriterionPassed,
				Evidence:    report.SanitizeEvidence(f.Evidence),
				Rationale:   "Payload reflected in executable HTML context without appropriate output encoding",
			})
			return p.createResult(
				f, StatusVerified, "reflection_context_analysis", true,
				report.ConfidenceHigh, ConfidenceHigh, criteria,
				"HTML entity encoding of user-controlled input",
				"Unescaped reflection executable in browser DOM",
				[]string{"Active input reflection probe"}, nil,
				"", "",
				safety, synthetic, start,
			), nil
		}

		// Reflected in text only or escaped -> NOT_VERIFIED
		criteria = append(criteria, CriterionResult{
			CriterionID: "CRIT-UNESCAPED-REFLECTION",
			Name:        "Unescaped Execution Context",
			Status:      CriterionFailed,
			Rationale:   "Input reflection detected, but executable context (unescaped script execution) was not proved",
		})
		return p.createResult(
			f, StatusNotVerified, "reflection_check", true,
			f.Confidence, ConfidenceLow, criteria,
			"Execution context proof required for verified XSS",
			"Reflection observed without proof of script execution capability",
			nil, []string{"Browser DOM execution not simulated"},
			"Reflection alone does not prove XSS exploitability",
			"Unconfirmed script execution context",
			safety, synthetic, start,
		), nil
	}

	// Invariant: Generic 500 error is NOT proof of SQLi!
	isSQLi := strings.Contains(strings.ToUpper(f.Category), "SQL") || strings.Contains(strings.ToUpper(f.Title), "SQL")
	if isSQLi {
		hasDBError := strings.Contains(strings.ToLower(f.Evidence), "syntax error") ||
			strings.Contains(strings.ToLower(f.Evidence), "sql") ||
			(f.EvidenceDetails.Details != nil && f.EvidenceDetails.Details["db_error"] != "")

		if hasDBError {
			criteria = append(criteria, CriterionResult{
				CriterionID: "CRIT-SQL-ERROR-PROOF",
				Name:        "Database Syntax Error Confirmed",
				Status:      CriterionPassed,
				Evidence:    report.SanitizeEvidence(f.Evidence),
				Rationale:   "Input divergence triggered database-specific syntax or error response",
			})
			return p.createResult(
				f, StatusVerified, "error_based_sqli_probe", true,
				report.ConfidenceHigh, ConfidenceHigh, criteria,
				"Parameterized query execution",
				"Database error signature returned",
				[]string{"Non-destructive single-quote probe"}, nil,
				"", "",
				safety, synthetic, start,
			), nil
		}

		// Generic 500 error alone -> NOT_VERIFIED
		criteria = append(criteria, CriterionResult{
			CriterionID: "CRIT-SQL-ERROR-PROOF",
			Name:        "Database Syntax Error Confirmed",
			Status:      CriterionFailed,
			Rationale:   "Server error occurred, but database syntax error or execution divergence was not established",
		})
		return p.createResult(
			f, StatusNotVerified, "sqli_error_probe", true,
			f.Confidence, ConfidenceLow, criteria,
			"Definitive database error signature or boolean divergence",
			"Generic application error without SQL syntax confirmation",
			nil, []string{"Destructive or time-based testing disallowed by safety policy"},
			"Generic error does not establish SQL injection vulnerability",
			"Unconfirmed execution divergence",
			safety, synthetic, start,
		), nil
	}

	// Traversal
	isTraversal := strings.Contains(strings.ToUpper(f.Category), "TRAVERSAL") || strings.Contains(strings.ToUpper(f.Title), "TRAVERSAL")
	if isTraversal {
		hasFileMarker := strings.Contains(f.Evidence, "root:x:") || strings.Contains(f.Evidence, "[extensions]") ||
			(f.EvidenceDetails.Details != nil && f.EvidenceDetails.Details["marker_found"] == "true")

		if hasFileMarker {
			criteria = append(criteria, CriterionResult{
				CriterionID: "CRIT-FILE-MARKER",
				Name:        "Target File Marker Retrieved",
				Status:      CriterionPassed,
				Evidence:    report.SanitizeEvidence(f.Evidence),
				Rationale:   "Known system file marker retrieved via path traversal",
			})
			return p.createResult(
				f, StatusVerified, "traversal_probe", true,
				report.ConfidenceHigh, ConfidenceHigh, criteria,
				"Strict path canonicalization rejecting dot-dot-slash",
				"System file contents retrieved via traversal",
				[]string{"Safe read-only traversal probe"}, nil,
				"", "",
				safety, synthetic, start,
			), nil
		}

		criteria = append(criteria, CriterionResult{
			CriterionID: "CRIT-FILE-MARKER",
			Name:        "Target File Marker Retrieved",
			Status:      CriterionFailed,
			Rationale:   "Path traversal sequence dispatched, but expected file markers were not retrieved",
		})
		return p.createResult(
			f, StatusNotVerified, "traversal_probe", true,
			f.Confidence, ConfidenceLow, criteria,
			"System file content retrieval",
			"No file marker observed in response",
			nil, nil,
			"Path traversal not demonstrated",
			"Unconfirmed file disclosure",
			safety, synthetic, start,
		), nil
	}

	// Invariant: HTTP 404 does NOT disprove a web vulnerability!
	if f.EvidenceDetails.HTTPStatus == 404 {
		criteria = append(criteria, CriterionResult{
			CriterionID: "CRIT-WEBVULN-404-INCONCLUSIVE",
			Name:        "HTTP 404 Status Evaluation",
			Status:      CriterionFailed,
			Evidence:    "HTTP 404 Not Found received",
			Rationale:   "HTTP 404 does not disprove vulnerability; endpoint may be route-dependent or gated; recorded as NOT_VERIFIED",
		})
		return p.createResult(
			f, StatusNotVerified, "webvuln_probe", true,
			f.Confidence, ConfidenceLow, criteria,
			"Empirical proof of vulnerability execution",
			"HTTP 404 Not Found received (does not establish absence of vulnerability)",
			nil, []string{"Endpoint returned 404; testing inconclusive"},
			"Endpoint returned 404; vulnerability not disproved", "404 does not disprove vulnerability",
			safety, synthetic, start,
		), nil
	}

	// General fallback for other web vulnerabilities
	return p.createResult(
		f, StatusNotVerified, "webvuln_generic_check", true,
		f.Confidence, ConfidenceLow, nil,
		"Empirical proof of vulnerability execution",
		"Anomaly observed but safe proof was incomplete",
		nil, []string{"Destructive exploitation disallowed"},
		"Incomplete verification evidence",
		"Vulnerability impact not safely demonstrable",
		safety, synthetic, start,
	), nil
}

// -----------------------------------------------------------------------------
// 6. Cloud Security Policy (POL-CLOUD-01)
// -----------------------------------------------------------------------------

type CloudSecurityPolicy struct {
	BasePolicy
}

func NewCloudSecurityPolicy() *CloudSecurityPolicy {
	return &CloudSecurityPolicy{
		BasePolicy: BasePolicy{
			id:          "POL-CLOUD-01",
			version:     "2.0.0",
			name:        "Cloud & BaaS Security Verification Policy",
			description: "Verifies cloud storage permissions and BaaS Row Level Security without data exfiltration.",
		},
	}
}

func (p *CloudSecurityPolicy) AppliesTo(f report.Finding) bool {
	cat := strings.ToUpper(f.Category)
	return f.Source == report.SourceCloud || strings.Contains(cat, "CLOUD") ||
		strings.Contains(cat, "S3") || strings.Contains(cat, "GCS") ||
		strings.Contains(cat, "AZURE") || strings.Contains(cat, "FIREBASE") ||
		strings.Contains(cat, "SUPABASE") || strings.Contains(cat, "STORAGE")
}

func (p *CloudSecurityPolicy) Verify(ctx context.Context, f report.Finding, checker *SafetyChecker) (VerificationResult, error) {
	start := time.Now().UTC()
	synthetic := f.Verification.SyntheticFixture || strings.Contains(f.Evidence, "[SYNTHETIC FIXTURE]")

	safety := checker.Check(f.Target, f.Endpoint, f.Method, false)
	if !safety.Allowed {
		return p.createResult(
			f, StatusNotVerified, "safety_block", false,
			f.Confidence, ConfidenceNone, nil,
			"Authorized cloud probe", "Probe blocked by safety controls",
			nil, []string{"Safety control prevented probe"},
			safety.BlockReason, "Safety blocked",
			safety, synthetic, start,
		), nil
	}

	var criteria []CriterionResult

	// Missing provider credentials or permissions -> Inconclusive (NOT_VERIFIED)
	if strings.Contains(strings.ToLower(f.Evidence), "missing permissions") ||
		strings.Contains(strings.ToLower(f.Description), "missing permissions") {
		criteria = append(criteria, CriterionResult{
			CriterionID: "CRIT-CLOUD-PERMISSIONS",
			Name:        "Cloud Audit Permissions",
			Status:      CriterionInconclusive,
			Rationale:   "Assessment lacked cloud provider credentials; resource state could not be verified",
		})
		return p.createResult(
			f, StatusNotVerified, "cloud_api_audit", false,
			f.Confidence, ConfidenceNone, criteria,
			"Valid cloud audit credentials",
			"Missing credentials or insufficient IAM permissions",
			nil, []string{"Cloud provider credentials not configured"},
			"Missing permissions", "Check inconclusive due to unavailable credentials",
			safety, synthetic, start,
		), nil
	}

	// Claim-specific negative evidence:
	// A 403 / AccessDenied response proves NOT_EXPOSED ONLY IF:
	// 1) The finding specifically claimed anonymous public bucket listing or anonymous object exposure on that specific resource
	// 2) The probe specifically tested anonymous access against that exact resource
	// 3) Documented negative evidence confirms access was denied (403 AccessDenied)
	// 4) Narrow scope & limitations explicitly recorded: does NOT prove whole bucket or account is secure!
	isAnonymousListingClaim := strings.Contains(strings.ToLower(f.Title), "bucket") ||
		strings.Contains(strings.ToLower(f.Title), "listing") ||
		strings.Contains(strings.ToLower(f.Title), "public") ||
		strings.Contains(strings.ToLower(f.Title), "anonymous")
	hasNegativeEvidence := f.EvidenceDetails.NegativeEvidence != "" ||
		(f.EvidenceDetails.Details != nil && f.EvidenceDetails.Details["access_denied_confirmed"] == "true")
	hasAccessDenied := f.EvidenceDetails.HTTPStatus == 403 ||
		strings.Contains(strings.ToLower(f.Evidence), "accessdenied") ||
		strings.Contains(strings.ToLower(f.Evidence), "access denied")

	if isAnonymousListingClaim && hasNegativeEvidence && hasAccessDenied {
		criteria = append(criteria, CriterionResult{
			CriterionID: "CRIT-NEG-CLOUD-DENIED",
			Name:        "Specific Cloud Resource Access Barrier Enforced",
			Status:      CriterionPassed,
			Evidence:    fmt.Sprintf("HTTP 403 AccessDenied received for %s", f.Endpoint),
			Rationale:   fmt.Sprintf("Anonymous access probe to %s denied by cloud storage policy; specific public listing claim disproved for tested request", f.Endpoint),
		})
		return p.createResult(
			f, StatusNotExposed, "cloud_storage_probe", true,
			report.ConfidenceHigh, ConfidenceHigh, criteria,
			"Cloud access denied to anonymous caller on tested resource",
			fmt.Sprintf("Access denied (HTTP 403 AccessDenied) for tested anonymous request to %s; does not establish that all objects, operations, or entire cloud account are secure", f.Endpoint),
			[]string{"Anonymous read-only cloud storage probe"},
			[]string{"Negative verification strictly limited to tested request and path; other bucket permissions, ACLs, objects, or authenticated roles may remain exposed"},
			"", "",
			safety, synthetic, start,
		), nil
	}

	// Generic 401/403 or access-denied without specific claim-matching negative criteria
	// A cloud storage access-denied response CANNOT establish that the entire resource is secure!
	if hasAccessDenied {
		criteria = append(criteria, CriterionResult{
			CriterionID: "CRIT-GENERIC-CLOUD-STATUS",
			Name:        "Generic Cloud Access Status Evaluation",
			Status:      CriterionInconclusive,
			Evidence:    fmt.Sprintf("Access denied / HTTP %d received", f.EvidenceDetails.HTTPStatus),
			Rationale:   "Access denied observed on probe, but response alone cannot establish that the entire cloud resource, bucket, or account is secure",
		})
		return p.createResult(
			f, StatusNotVerified, "cloud_storage_probe", true,
			f.Confidence, ConfidenceLow, criteria,
			"Claim-specific negative proof establishing cloud resource security",
			"Access denied observed on single probe; insufficient proof to establish overall cloud resource is secure",
			nil, []string{"A single access-denied response cannot establish that the entire cloud resource or account is secure"},
			"Access denied response alone cannot establish resource security", "Inconclusive cloud storage verification",
			safety, synthetic, start,
		), nil
	}

	// Missing provider credentials or permissions -> Inconclusive (NOT_VERIFIED)
	if strings.Contains(strings.ToLower(f.Evidence), "missing permissions") ||
		strings.Contains(strings.ToLower(f.Description), "missing permissions") {
		criteria = append(criteria, CriterionResult{
			CriterionID: "CRIT-CLOUD-PERMISSIONS",
			Name:        "Cloud Audit Permissions",
			Status:      CriterionInconclusive,
			Rationale:   "Assessment lacked cloud provider credentials; resource state could not be verified",
		})
		return p.createResult(
			f, StatusNotVerified, "cloud_api_audit", false,
			f.Confidence, ConfidenceNone, criteria,
			"Valid cloud audit credentials",
			"Missing credentials or insufficient IAM permissions",
			nil, []string{"Cloud provider credentials not configured"},
			"Missing permissions", "Check inconclusive due to unavailable credentials",
			safety, synthetic, start,
		), nil
	}

	// Confirmed public bucket listing or unauthenticated database read (HTTP 200)
	isOpenBucket := f.EvidenceDetails.HTTPStatus == 200 &&
		(strings.Contains(strings.ToLower(f.Title), "public") || strings.Contains(strings.ToLower(f.Title), "listing") || strings.Contains(strings.ToLower(f.Title), "unauthorized")) &&
		len(f.Evidence) > 0

	if isOpenBucket {
		criteria = append(criteria, CriterionResult{
			CriterionID: "CRIT-PUBLIC-STORAGE-200",
			Name:        "Public Storage Listing Confirmed",
			Status:      CriterionPassed,
			Evidence:    report.SanitizeEvidence(f.Evidence),
			Rationale:   "Anonymous GET request returned live storage listing or database objects",
		})
		return p.createResult(
			f, StatusVerified, "storage_read_probe", true,
			report.ConfidenceHigh, ConfidenceHigh, criteria,
			"Access denied or private bucket configuration",
			"Public bucket listing or unauthenticated database access confirmed",
			[]string{"Anonymous read-only GET probe"},
			[]string{"Objects were not downloaded (non-destructive policy)"},
			"", "",
			safety, synthetic, start,
		), nil
	}

	// Default fallback for cloud finding
	criteria = append(criteria, CriterionResult{
		CriterionID: "CRIT-CLOUD-OBSERVED",
		Name:        "Cloud Resource Observed",
		Status:      CriterionPassed,
		Evidence:    f.Endpoint,
		Rationale:   "Cloud resource endpoint identified in client configuration",
	})
	return p.createResult(
		f, StatusObserved, "cloud_discovery", true,
		report.ConfidenceLow, ConfidenceNone, criteria,
		"Expected standard cloud endpoint configuration",
		"Cloud endpoint observed",
		nil, nil, "", "",
		safety, synthetic, start,
	), nil
}

// -----------------------------------------------------------------------------
// 7. Business Logic Policy (POL-BIZLOGIC-01)
// -----------------------------------------------------------------------------

type BusinessLogicPolicy struct {
	BasePolicy
}

func NewBusinessLogicPolicy() *BusinessLogicPolicy {
	return &BusinessLogicPolicy{
		BasePolicy: BasePolicy{
			id:          "POL-BIZLOGIC-01",
			version:     "2.0.0",
			name:        "Business Logic Verification Policy",
			description: "Requires explicit state transitions and enforces strict safety controls against state-changing abuse.",
		},
	}
}

func (p *BusinessLogicPolicy) AppliesTo(f report.Finding) bool {
	cat := strings.ToUpper(f.Category)
	return strings.Contains(cat, "BUSINESS_LOGIC") || strings.Contains(cat, "WORKFLOW") ||
		strings.Contains(cat, "STEP_SKIP") || strings.Contains(cat, "STATE_MANIPULATION") ||
		strings.Contains(cat, "REPLAY")
}

func (p *BusinessLogicPolicy) Verify(ctx context.Context, f report.Finding, checker *SafetyChecker) (VerificationResult, error) {
	start := time.Now().UTC()
	synthetic := f.Verification.SyntheticFixture || strings.Contains(f.Evidence, "[SYNTHETIC FIXTURE]")

	// Business logic checks frequently involve state changes: check if allowed
	safety := checker.Check(f.Target, f.Endpoint, f.Method, true)
	if !safety.Allowed {
		return p.createResult(
			f, StatusNotVerified, "safety_block", false,
			f.Confidence, ConfidenceNone, nil,
			"Workflow state transition check", "Probe blocked by non-destructive safety policy",
			nil, []string{"State-changing verification prohibited by safety policy"},
			safety.BlockReason, "Check blocked by safety controls",
			safety, synthetic, start,
		), nil
	}

	var criteria []CriterionResult

	// Proof of workflow anomaly: requires state before and state after proving sequence bypass
	hasStateProof := false
	if f.EvidenceDetails.Details != nil {
		if f.EvidenceDetails.Details["state_before"] != "" && f.EvidenceDetails.Details["state_after"] != "" {
			hasStateProof = true
		}
	}
	if f.Verification.Status == report.VerificationVerified && len(f.Evidence) > 0 {
		hasStateProof = true
	}

	if hasStateProof {
		criteria = append(criteria, CriterionResult{
			CriterionID: "CRIT-STATE-TRANSITION-BYPASS",
			Name:        "Invalid State Transition Proof",
			Status:      CriterionPassed,
			Evidence:    f.Evidence,
			Rationale:   "Controlled test verified workflow completed without mandatory intermediate step",
		})
		return p.createResult(
			f, StatusVerified, "workflow_transition_audit", true,
			report.ConfidenceHigh, ConfidenceHigh, criteria,
			"Enforcement of strict workflow step prerequisites",
			"Workflow completed with skipped step",
			[]string{"Controlled test session"}, nil,
			"", "",
			safety, synthetic, start,
		), nil
	}

	// Inconclusive check without state before/after proof
	criteria = append(criteria, CriterionResult{
		CriterionID: "CRIT-STATE-TRANSITION-BYPASS",
		Name:        "Invalid State Transition Proof",
		Status:      CriterionFailed,
		Rationale:   "Business logic flaw hypothesized but state transitions before and after were not captured",
	})
	return p.createResult(
		f, StatusNotVerified, "workflow_heuristic", true,
		f.Confidence, ConfidenceLow, criteria,
		"Demonstrated state transition inconsistency",
		"Hypothesized logic anomaly without before/after state proof",
		nil, []string{"Controlled multi-step workflow execution required"},
		"Lacks state transition proof",
		"Inconclusive workflow check",
		safety, synthetic, start,
	), nil
}

// -----------------------------------------------------------------------------
// 8. Generic Fallback Policy (POL-GENERIC-01)
// -----------------------------------------------------------------------------

type GenericPolicy struct {
	BasePolicy
}

func NewGenericPolicy() *GenericPolicy {
	return &GenericPolicy{
		BasePolicy: BasePolicy{
			id:          "POL-GENERIC-01",
			version:     "2.0.0",
			name:        "Generic Fallback Verification Policy",
			description: "Default fallback for finding categories lacking specialized empirical verification routines.",
		},
	}
}

func (p *GenericPolicy) AppliesTo(f report.Finding) bool {
	return true // Fallback applies to everything
}

func (p *GenericPolicy) Verify(ctx context.Context, f report.Finding, checker *SafetyChecker) (VerificationResult, error) {
	start := time.Now().UTC()
	synthetic := f.Verification.SyntheticFixture || strings.Contains(f.Evidence, "[SYNTHETIC FIXTURE]")
	safety := checker.Check(f.Target, f.Endpoint, f.Method, false)

	// Generic fallback policy does NOT validate negative claims without a specialized domain policy.
	// NOT_EXPOSED may be returned only when the specific exposure claim has an applicable negative-verification policy.

	// If finding was already previously verified with direct evidence:
	if f.Verification.Status == report.VerificationVerified && len(f.Evidence) > 0 {
		crit := []CriterionResult{
			{
				CriterionID: "CRIT-EMPIRICAL-PROOF",
				Name:        "Empirical Evidence Provided",
				Status:      CriterionPassed,
				Evidence:    report.SanitizeEvidence(f.Evidence),
				Rationale:   "Direct observation confirmed finding claim",
			},
		}
		return p.createResult(
			f, StatusVerified, "direct_evidence_evaluation", true,
			report.ConfidenceHigh, ConfidenceHigh, crit,
			"Secure operation", "Empirical evidence recorded",
			nil, nil, "", "",
			safety, synthetic, start,
		), nil
	}

	// Otherwise, unsupported category falls back to NOT_VERIFIED
	crit := []CriterionResult{
		{
			CriterionID: "CRIT-UNSUPPORTED-POLICY",
			Name:        "Dedicated Policy Evaluation",
			Status:      CriterionInconclusive,
			Rationale:   "No specialized empirical verification policy registered for category; detection preserved",
		},
	}
	return p.createResult(
		f, StatusNotVerified, "unsupported_category_fallback", false,
		f.Confidence, ConfidenceNone, crit,
		"Empirical proof of finding claim",
		"Detection recorded without specialized verification procedure",
		nil, []string{"Specialized verification policy not available for this finding category"},
		"Unsupported category for active verification",
		"Finding category lacks dedicated empirical verification policy",
		safety, synthetic, start,
	), nil
}
