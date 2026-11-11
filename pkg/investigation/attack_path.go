package investigation

import (
	"fmt"
	"net/url"
	"strings"

	"felix/pkg/report"
	"felix/pkg/secrets"
)

// ReconstructAttackPath builds a structured, evidence-backed attack path for an investigated finding.
func ReconstructAttackPath(f report.Finding, status ValidationStatus, bundle *EvidenceBundle) *AttackPath {
	isConfirmed := (status == StatusConfirmed)

	entryPoint := f.Target
	if entryPoint == "" {
		entryPoint = f.Endpoint
	}

	// 1. Determine Required Auth State & Roles
	reqAuth := "UNAUTHENTICATED"
	userRole := "ANONYMOUS_GUEST"
	if f.AuthContext != "" && f.AuthContext != report.AuthContextNoChallenge {
		reqAuth = string(f.AuthContext)
		userRole = "AUTHENTICATED_USER"
	}
	cat := strings.ToUpper(f.Category)
	if strings.Contains(cat, "BOLA") || strings.Contains(cat, "IDOR") {
		reqAuth = "AUTHENTICATED_USER"
		userRole = "AUTHENTICATED_USER (User B)"
	}
	if strings.Contains(cat, "BFLA") || strings.Contains(cat, "ADMIN") {
		reqAuth = "AUTHENTICATED_LOW_PRIVILEGE"
		userRole = "STANDARD_USER"
	}

	// 2. Identify Parameters
	var params []string
	if strings.Contains(entryPoint, "?") {
		if parsed, err := url.Parse(entryPoint); err == nil {
			for k := range parsed.Query() {
				params = append(params, k)
			}
		}
	}

	// 3. Determine Failed Security Control & Impact
	failedControl := "Missing or insufficient server-side input validation"
	demonstratedImpact := "Unauthorized information disclosure or operational deviation"
	observedBehavior := f.Evidence

	switch {
	case strings.Contains(cat, "SQL"):
		failedControl = "Missing parameterization / prepared statement enforcement in SQL query construction"
		demonstratedImpact = "Arbitrary database query execution, bypassing application authentication and authorization constraints"
		observedBehavior = "Database error or boolean divergence provoked via unescaped input parameter"
	case strings.Contains(cat, "XSS"):
		failedControl = "Missing contextual HTML/JavaScript output encoding of user-controlled input"
		demonstratedImpact = "Execution of arbitrary client-side scripts within victim's browser session"
		observedBehavior = "Unescaped HTML/script tag reflected verbatim into browser DOM"
	case strings.Contains(cat, "SSRF"):
		failedControl = "Missing egress network validation and destination allowlisting for outbound HTTP requests"
		demonstratedImpact = "Forced server-side request routing to internal infrastructure or external callback targets"
		observedBehavior = "Target server initiated outbound HTTP connection to attacker-specified destination"
	case strings.Contains(cat, "BOLA") || strings.Contains(cat, "IDOR"):
		failedControl = "Missing object-level access control check validating caller ownership of requested resource ID"
		demonstratedImpact = "Unauthorized cross-user access and horizontal disclosure of another user's private records"
		observedBehavior = "Secondary test identity (User B) successfully accessed primary test identity's (User A) object without authorization"
	case strings.Contains(cat, "BFLA"):
		failedControl = "Missing function-level role-based authorization gate on administrative route"
		demonstratedImpact = "Privilege escalation allowing standard users to execute administrative operations"
		observedBehavior = "Administrative endpoint executed successfully without administrative role verification"
	case strings.Contains(cat, "TRAVERSAL"):
		failedControl = "Missing file path canonicalization and directory boundary confinement"
		demonstratedImpact = "Unauthorized read access to files outside designated web document root"
		observedBehavior = "Relative directory navigation returned file structure markers beyond intended directory"
	case strings.Contains(cat, "AUTH"):
		failedControl = "Missing authentication challenge enforcement on sensitive route"
		demonstratedImpact = "Unauthenticated access to protected application functionality"
		observedBehavior = "Endpoint returned HTTP 200 OK without requiring authentication challenge"
	case strings.Contains(cat, "SECRET"):
		failedControl = "Insecure credential management: private token or secret committed to client-facing assets"
		demonstratedImpact = "Credential compromise enabling direct authentication to third-party API or cloud services"
		observedBehavior = "High-entropy token detected in cleartext in public asset body"
	case strings.Contains(cat, "CORS"):
		failedControl = "Overly permissive Cross-Origin Resource Sharing policy allowing wildcard origin with credentials"
		demonstratedImpact = "Cross-origin data exfiltration from authenticated victim browser sessions"
		observedBehavior = "Preflight response granted wildcard access with Access-Control-Allow-Credentials"
	case strings.Contains(cat, "BUSINESS") || strings.Contains(cat, "LOGIC"):
		failedControl = "Missing server-side procedural state machine validation across multi-step workflow"
		demonstratedImpact = "Circumvention of business restrictions, payment verification, or operational prerequisites"
		observedBehavior = "Final workflow request processed successfully despite skipping intermediate validation steps"
	}

	endpointPath := f.Endpoint
	if endpointPath == "" {
		endpointPath = f.Target
	}

	// 4. Build Structured Discrete Attack Steps
	step1Class := "INFERRED"
	step1Demonstrated := isConfirmed
	if isConfirmed {
		step1Class = "DEMONSTRATED"
	} else if status == StatusNotValidated {
		step1Class = "NOT_VALIDATED"
	}

	var steps []AttackStep
	steps = append(steps, AttackStep{
		StepNumber:       1,
		Action:           "Initial Target Access",
		Description:      fmt.Sprintf("Attacker establishes connection to %s as %s (%s)", secrets.SanitizeURL(entryPoint), userRole, reqAuth),
		Endpoint:         endpointPath,
		RequiredRole:     userRole,
		ObservedBehavior: "Target application endpoint reachable",
		IsDemonstrated:   step1Demonstrated,
		Classification:   step1Class,
	})

	if len(params) > 0 {
		steps = append(steps, AttackStep{
			StepNumber:       2,
			Action:           "Parameter Manipulation",
			Description:      fmt.Sprintf("Attacker delivers targeted probe to parameter(s): %s", strings.Join(params, ", ")),
			Endpoint:         endpointPath,
			Parameter:        params[0],
			SecurityControl:  failedControl,
			ObservedBehavior: "Input processed by target application backend",
			IsDemonstrated:   step1Demonstrated,
			Classification:   step1Class,
		})
	}

	failClass := "INFERRED"
	if isConfirmed {
		failClass = "DEMONSTRATED"
	} else if status == StatusNotValidated {
		failClass = "NOT_VALIDATED"
	}
	steps = append(steps, AttackStep{
		StepNumber:       len(steps) + 1,
		Action:           "Security Control Failure",
		Description:      failedControl,
		Endpoint:         endpointPath,
		SecurityControl:  failedControl,
		ObservedBehavior: secrets.RedactText(observedBehavior),
		IsDemonstrated:   isConfirmed,
		Classification:   failClass,
	})

	impactClass := "INFERRED"
	if isConfirmed {
		impactClass = "DEMONSTRATED"
	} else if status == StatusNotValidated {
		impactClass = "NOT_VALIDATED"
	}
	steps = append(steps, AttackStep{
		StepNumber:       len(steps) + 1,
		Action:           "Impact Demonstration",
		Description:      demonstratedImpact,
		Endpoint:         endpointPath,
		ObservedBehavior: fmt.Sprintf("Vulnerability verification status: %s", status),
		IsDemonstrated:   isConfirmed,
		Classification:   impactClass,
	})

	// 5. Generate ASCII Graph Representation
	graphVisual := fmt.Sprintf("[%s] -> [Endpoint: %s] -> [Failed Control: %s] -> [Demonstrated Impact: %s]",
		userRole, endpointPath, failedControl, demonstratedImpact)

	reproSteps := []string{
		fmt.Sprintf("1. Access endpoint %s (%s)", f.Endpoint, f.Method),
		fmt.Sprintf("2. Provide required authentication state: %s", reqAuth),
		fmt.Sprintf("3. Observe security control failure: %s", failedControl),
	}
	if bundle != nil && len(bundle.ReproductionSteps) > 0 {
		reproSteps = bundle.ReproductionSteps
	}

	return &AttackPath{
		FindingID:          f.ID,
		Title:              f.Title,
		InitialEntryPoint:  secrets.SanitizeURL(entryPoint),
		RequiredAuthState:  reqAuth,
		UserRole:           userRole,
		AffectedEndpoint:   f.Endpoint,
		RelevantParameters: params,
		FailedControl:      failedControl,
		ObservedBehavior:   secrets.RedactText(observedBehavior),
		DemonstratedImpact: demonstratedImpact,
		Preconditions:      []string{fmt.Sprintf("Target service online at %s", entryPoint), fmt.Sprintf("Authentication: %s", reqAuth)},
		ReproductionSteps:  reproSteps,
		Steps:              steps,
		GraphVisual:        graphVisual,
		IsConfirmed:        isConfirmed,
	}
}

func isInvestigatedPlaceholderSecret(inf *InvestigatedFinding) bool {
	if inf == nil {
		return false
	}
	if d := inf.Finding.EvidenceDetails.Details; d != nil {
		if strings.EqualFold(d["is_placeholder"], "true") || strings.EqualFold(d["credential_status"], "INVALID") {
			return true
		}
	}
	if ok, _ := secrets.ContainsPlaceholderCredential(inf.Finding.Evidence + " " + inf.Finding.EvidenceDetails.Observation + " " + inf.Finding.EvidenceDetails.ObservedBehavior + " " + inf.Finding.Title); ok {
		return true
	}
	return false
}

func sameChainTargetOrigin(a, b *InvestigatedFinding) bool {
	if a == nil || b == nil {
		return false
	}
	rawA := strings.TrimSpace(a.Finding.Target)
	rawB := strings.TrimSpace(b.Finding.Target)
	if rawA == "" || rawB == "" {
		return true
	}
	uA, errA := url.Parse(rawA)
	uB, errB := url.Parse(rawB)
	if errA != nil || errB != nil || uA.Hostname() == "" || uB.Hostname() == "" {
		return true
	}
	return strings.EqualFold(uA.Hostname(), uB.Hostname()) && uA.Port() == uB.Port() && strings.EqualFold(uA.Scheme, uB.Scheme)
}

func hasVerifiedTransitionFlag(inf *InvestigatedFinding) bool {
	if inf == nil || inf.Finding.EvidenceDetails.Details == nil {
		return false
	}
	return strings.EqualFold(inf.Finding.EvidenceDetails.Details["transition_verified"], "true") ||
		strings.EqualFold(inf.Finding.EvidenceDetails.Details["credential_status"], "VERIFIED")
}

// AnalyzeAttackChains identifies candidate and validated multi-hop vulnerability sequences across findings.
// Strictly enforces: a cross-finding transition link is CONFIRMED only if non-placeholder credentials/origins
// match and the cross-step transition itself has been explicitly validated.
func AnalyzeAttackChains(findings []*InvestigatedFinding) []AttackChain {
	var chains []AttackChain

	// Index findings by category and confirmation status
	var secretFindings []*InvestigatedFinding
	var authFindings []*InvestigatedFinding
	var bflaFindings []*InvestigatedFinding
	var bolaFindings []*InvestigatedFinding
	var sqliFindings []*InvestigatedFinding
	var ssrfFindings []*InvestigatedFinding

	for _, inf := range findings {
		cat := strings.ToUpper(inf.Finding.Category)
		title := strings.ToUpper(inf.Finding.Title)

		if (strings.Contains(cat, "SECRET") || strings.Contains(title, "TOKEN") ||
			strings.Contains(title, "API KEY") || strings.Contains(title, "ACCESS KEY")) &&
			!strings.Contains(cat, "CORS") && !strings.Contains(title, "CORS") {
			if !isInvestigatedPlaceholderSecret(inf) {
				secretFindings = append(secretFindings, inf)
			}
		}
		if (strings.Contains(cat, "AUTH") || strings.Contains(title, "AUTHENTICATION")) &&
			!strings.Contains(cat, "CORS") {
			authFindings = append(authFindings, inf)
		}
		if strings.Contains(cat, "BFLA") || strings.Contains(title, "FUNCTION LEVEL") {
			bflaFindings = append(bflaFindings, inf)
		}
		if strings.Contains(cat, "BOLA") || strings.Contains(cat, "IDOR") {
			bolaFindings = append(bolaFindings, inf)
		}
		if strings.Contains(cat, "SQL") || strings.Contains(title, "SQL") {
			sqliFindings = append(sqliFindings, inf)
		}
		if strings.Contains(cat, "SSRF") || strings.Contains(title, "SSRF") {
			ssrfFindings = append(ssrfFindings, inf)
		}
	}

	// Pattern A: Validated Credential Pivot -> Object Access (BOLA)
	// Rejects documentation/placeholder credentials and cross-origin pairs.
	if len(secretFindings) > 0 && len(bolaFindings) > 0 {
		for _, sf := range secretFindings {
			var matchedBOLA *InvestigatedFinding
			for _, bf := range bolaFindings {
				if sameChainTargetOrigin(sf, bf) {
					matchedBOLA = bf
					break
				}
			}
			if matchedBOLA == nil {
				continue
			}

			transitionDemonstrated := hasVerifiedTransitionFlag(sf) &&
				sf.ValidationStatus == StatusConfirmed &&
				matchedBOLA.ValidationStatus == StatusConfirmed

			status := StatusPotential
			summary := "Candidate pivot: non-placeholder credential and object-level authorization flaw exist on the same origin, but cross-step credential usability for the BOLA request has not yet been independently validated."
			explanation := "Candidate credential-to-object link observed on shared origin; requires read-only identity verification before confirming causal reachability."
			if transitionDemonstrated {
				status = StatusConfirmed
				summary = "Validated attack path: verified credential identity enables cross-tenant access through broken object-level authorization."
				explanation = "Leaked credential identity was verified against target scope and reaches the foreign object endpoint via BOLA."
			}

			links := []AttackChainLink{
				{
					FromFindingID:    sf.Finding.ID,
					FromTitle:        sf.Finding.Title,
					ToFindingID:      matchedBOLA.Finding.ID,
					ToTitle:          matchedBOLA.Finding.Title,
					DependencyType:   "CREDENTIAL_PIVOT_TO_OBJECT_ACCESS",
					DemonstratedLink: transitionDemonstrated,
					Explanation:      explanation,
				},
			}

			chains = append(chains, AttackChain{
				ID:               "chain_cred_to_bola",
				Title:            "Exposed Credential Pivot to Multi-Tenant Object Access (BOLA)",
				Status:           status,
				Summary:          summary,
				FindingIDs:       []string{sf.Finding.ID, matchedBOLA.Finding.ID},
				Links:            links,
				DemonstratedPath: fmt.Sprintf("[%s] -> [Token Acquisition] -> [%s]", sf.Finding.Endpoint, matchedBOLA.Finding.Endpoint),
			})
			break
		}
	}

	// Pattern B: Authentication Weakness -> Administrative Route Access (BFLA)
	if len(authFindings) > 0 && len(bflaFindings) > 0 {
		for _, af := range authFindings {
			var matchedBFLA *InvestigatedFinding
			for _, bflaf := range bflaFindings {
				if sameChainTargetOrigin(af, bflaf) {
					matchedBFLA = bflaf
					break
				}
			}
			if matchedBFLA == nil {
				continue
			}

			transitionDemonstrated := hasVerifiedTransitionFlag(af) &&
				af.ValidationStatus == StatusConfirmed &&
				matchedBFLA.ValidationStatus == StatusConfirmed

			status := StatusPotential
			summary := "Candidate privilege escalation path: authentication weakness and BFLA flaw share the same origin, but session escalation across steps awaits independent transition validation."
			explanation := "Both findings share the same origin, but end-to-end reachability from the authentication weakness into the administrative operation is not yet empirically demonstrated."
			if transitionDemonstrated {
				status = StatusConfirmed
				summary = "Validated privilege escalation path: circumvented authentication boundary reaches administrative operation protected by broken function-level authorization."
				explanation = "Session derived from authentication weakness was verified to reach administrative function without role enforcement."
			}

			links := []AttackChainLink{
				{
					FromFindingID:    af.Finding.ID,
					FromTitle:        af.Finding.Title,
					ToFindingID:      matchedBFLA.Finding.ID,
					ToTitle:          matchedBFLA.Finding.Title,
					DependencyType:   "AUTH_BYPASS_TO_ADMIN_PRIVILEGE",
					DemonstratedLink: transitionDemonstrated,
					Explanation:      explanation,
				},
			}

			chains = append(chains, AttackChain{
				ID:               "chain_auth_to_bfla",
				Title:            "Authentication Weakness to Administrative Function Bypass (BFLA)",
				Status:           status,
				Summary:          summary,
				FindingIDs:       []string{af.Finding.ID, matchedBFLA.Finding.ID},
				Links:            links,
				DemonstratedPath: fmt.Sprintf("[%s] -> [Access Acquisition] -> [%s]", af.Finding.Endpoint, matchedBFLA.Finding.Endpoint),
			})
			break
		}
	}

	// Pattern C: SQL Injection -> Full Database Boundary Bypass
	if len(sqliFindings) > 0 {
		sqf := sqliFindings[0]
		if sqf.ValidationStatus == StatusConfirmed {
			chains = append(chains, AttackChain{
				ID:               "chain_sqli_takeover",
				Title:            "Direct Database Execution via Unchecked SQL Injection",
				Status:           StatusConfirmed,
				Summary:          "SQL injection point directly undermines application-tier authentication and multi-tenancy controls by manipulating backend database queries directly.",
				FindingIDs:       []string{sqf.Finding.ID},
				Links:            []AttackChainLink{
					{
						FromFindingID:    sqf.Finding.ID,
						FromTitle:        sqf.Finding.Title,
						ToFindingID:      "db_backend",
						ToTitle:          "Database Engine",
						DependencyType:   "QUERY_SUBVERSION",
						DemonstratedLink: true,
						Explanation:      "Input divergence demonstrated unhandled database query execution without query parameterization.",
					},
				},
				DemonstratedPath: fmt.Sprintf("[%s] -> [Parameter Syntax Error] -> [Database Subversion]", sqf.Finding.Endpoint),
			})
		}
	}

	// Pattern D: SSRF -> Network Perimeter Pivot
	if len(ssrfFindings) > 0 {
		ssrf := ssrfFindings[0]
		if ssrf.ValidationStatus == StatusConfirmed {
			chains = append(chains, AttackChain{
				ID:               "chain_ssrf_egress",
				Title:            "Server-Side Request Forgery Perimeter Pivot",
				Status:           StatusConfirmed,
				Summary:          "Server-side request forgery verified via out-of-band callback receipt, allowing attacker to force server requests across network perimeter boundaries.",
				FindingIDs:       []string{ssrf.Finding.ID},
				Links:            []AttackChainLink{
					{
						FromFindingID:    ssrf.Finding.ID,
						FromTitle:        ssrf.Finding.Title,
						ToFindingID:      "internal_network",
						ToTitle:          "Perimeter / Internal Network",
						DependencyType:   "PERIMETER_PIVOT",
						DemonstratedLink: true,
						Explanation:      "Outbound server callback confirmed server-side execution of caller-supplied URL.",
					},
				},
				DemonstratedPath: fmt.Sprintf("[%s] -> [Outbound Callback] -> [Perimeter Subversion]", ssrf.Finding.Endpoint),
			})
		}
	}

	return chains
}
