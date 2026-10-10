package correlation

import (
	"fmt"
	"strings"

	"felix/pkg/report"
)

// EvaluateRules iterates through candidate pairs of normalized findings and generates
// validated relationships according to the 10 core correlation rules.
func EvaluateRules(findings []NormalizedFinding, cfg Config) []Relationship {
	var rels []Relationship
	seenPairs := make(map[string]bool)

	rulesEnabled := make(map[RuleCode]bool)
	for _, r := range cfg.RulesEnabled {
		rulesEnabled[r] = true
	}

	for i := range findings {
		f1 := &findings[i]
		for j := range findings {
			if i == j {
				continue
			}
			f2 := &findings[j]

			pairKey := fmt.Sprintf("%s->%s", f1.ID, f2.ID)
			if seenPairs[pairKey] {
				continue
			}

			// Evaluate each enabled rule
			if rulesEnabled[RuleCOR01] {
				if r, ok := evaluateCOR01(f1, f2); ok {
					rels = append(rels, r)
					seenPairs[pairKey] = true
					continue
				}
			}
			if rulesEnabled[RuleCOR02] {
				if r, ok := evaluateCOR02(f1, f2); ok {
					rels = append(rels, r)
					seenPairs[pairKey] = true
					continue
				}
			}
			if rulesEnabled[RuleCOR03] {
				if r, ok := evaluateCOR03(f1, f2); ok {
					rels = append(rels, r)
					seenPairs[pairKey] = true
					continue
				}
			}
			if rulesEnabled[RuleCOR04] {
				if r, ok := evaluateCOR04(f1, f2); ok {
					rels = append(rels, r)
					seenPairs[pairKey] = true
					continue
				}
			}
			if rulesEnabled[RuleCOR05] {
				if r, ok := evaluateCOR05(f1, f2); ok {
					rels = append(rels, r)
					seenPairs[pairKey] = true
					continue
				}
			}
			if rulesEnabled[RuleCOR06] {
				if r, ok := evaluateCOR06(f1, f2); ok {
					rels = append(rels, r)
					seenPairs[pairKey] = true
					continue
				}
			}
			if rulesEnabled[RuleCOR07] {
				if r, ok := evaluateCOR07(f1, f2); ok {
					rels = append(rels, r)
					seenPairs[pairKey] = true
					continue
				}
			}
			if rulesEnabled[RuleCOR08] {
				if r, ok := evaluateCOR08(f1, f2); ok {
					rels = append(rels, r)
					seenPairs[pairKey] = true
					continue
				}
			}
			if rulesEnabled[RuleCOR09] {
				if r, ok := evaluateCOR09(f1, f2); ok {
					rels = append(rels, r)
					seenPairs[pairKey] = true
					continue
				}
			}
			if rulesEnabled[RuleCOR10] {
				if r, ok := evaluateCOR10(f1, f2); ok {
					rels = append(rels, r)
					seenPairs[pairKey] = true
					continue
				}
			}
		}
	}

	return rels
}

// COR-01: Entry Point to Vulnerable Resource
func evaluateCOR01(f1, f2 *NormalizedFinding) (Relationship, bool) {
	if !f1.IsEntrypoint {
		return Relationship{}, false
	}
	if f1.Host == "" || f2.Host == "" || f1.Host != f2.Host {
		return Relationship{}, false
	}
	if f2.VerificationStatus == report.VerificationNotExposed {
		return Relationship{}, false
	}

	// Must share exact path or f2 must be reachable subpath of f1
	samePath := f1.Path == f2.Path
	subPath := strings.HasPrefix(f2.Path, f1.Path) && f1.Path != "/"
	if !samePath && !subPath {
		return Relationship{}, false
	}

	// Do not correlate entrypoint with itself
	if f1.ID == f2.ID || (f1.Category == f2.Category && samePath) {
		return Relationship{}, false
	}

	status := ValidationPlausible
	conf := report.ConfidenceMedium
	if f2.IsVerified && samePath {
		status = ValidationConfirmed
		conf = report.ConfidenceHigh
	}

	return Relationship{
		ID:                 fmt.Sprintf("REL-COR01-%s-%s", shortID(f1.ID), shortID(f2.ID)),
		SourceFindingID:    f1.ID,
		TargetFindingID:    f2.ID,
		SourceTitle:        f1.Title,
		TargetTitle:        f2.Title,
		Type:               RelReaches,
		ValidationStatus:   status,
		Confidence:         conf,
		RuleCode:           RuleCOR01,
		EvidenceReferences: []string{f1.Endpoint, f2.Endpoint},
		Explanation: fmt.Sprintf("Public entry point '%s' (%s) provides external reachability directly to vulnerable component '%s' (%s).",
			f1.Title, f1.Endpoint, f2.Title, f2.Endpoint),
	}, true
}

// COR-02: Authentication to Authorization
func evaluateCOR02(f1, f2 *NormalizedFinding) (Relationship, bool) {
	isAuthFlaw := strings.Contains(f1.NormalizedCategory, "auth") ||
		strings.Contains(f1.NormalizedCategory, "session") ||
		strings.Contains(f1.NormalizedCategory, "jwt") ||
		strings.Contains(f1.NormalizedCategory, "token")
	isAuthzFlaw := strings.Contains(f2.NormalizedCategory, "bola") ||
		strings.Contains(f2.NormalizedCategory, "idor") ||
		strings.Contains(f2.NormalizedCategory, "bfla") ||
		strings.Contains(f2.NormalizedCategory, "bopla") ||
		strings.Contains(f2.NormalizedCategory, "authorization")

	if !isAuthFlaw || !isAuthzFlaw {
		return Relationship{}, false
	}
	if f1.Host == "" || f2.Host == "" || f1.Host != f2.Host {
		return Relationship{}, false
	}

	// Destination must require authentication/identity context
	if f2.EvidenceDetails["auth_state"] == "ANONYMOUS_PUBLIC" {
		return Relationship{}, false
	}

	status := ValidationPlausible
	conf := report.ConfidenceMedium
	if f1.IsVerified && f2.IsVerified {
		status = ValidationConfirmed
		conf = report.ConfidenceHigh
	}

	return Relationship{
		ID:                 fmt.Sprintf("REL-COR02-%s-%s", shortID(f1.ID), shortID(f2.ID)),
		SourceFindingID:    f1.ID,
		TargetFindingID:    f2.ID,
		SourceTitle:        f1.Title,
		TargetTitle:        f2.Title,
		Type:               RelEnables,
		ValidationStatus:   status,
		Confidence:         conf,
		RuleCode:           RuleCOR02,
		EvidenceReferences: []string{f1.Endpoint, f2.Endpoint},
		Explanation: fmt.Sprintf("Authentication/identity boundary weakness '%s' enables caller to establish session context required to invoke protected authorization flaw '%s'.",
			f1.Title, f2.Title),
	}, true
}

// COR-03: BOLA and Sensitive Data Exposure
func evaluateCOR03(f1, f2 *NormalizedFinding) (Relationship, bool) {
	isBola := strings.Contains(f1.NormalizedCategory, "bola") ||
		strings.Contains(f1.NormalizedCategory, "idor") ||
		strings.Contains(f1.NormalizedCategory, "bopla") ||
		strings.Contains(f1.NormalizedCategory, "object-level-authorization")

	if !isBola || !f2.IsSensitiveData {
		return Relationship{}, false
	}

	// Must share origin/host
	if f1.Host == "" || f2.Host == "" || f1.Host != f2.Host {
		return Relationship{}, false
	}

	// Context matching: same endpoint or shared resource identifier
	sameEndpoint := f1.Path == f2.Path
	sharedResource := f1.AffectedResource != "" && f2.AffectedResource != "" &&
		f1.AffectedResource == f2.AffectedResource

	if !sameEndpoint && !sharedResource {
		return Relationship{}, false
	}

	status := ValidationPlausible
	conf := report.ConfidenceMedium
	if f1.IsVerified && f2.IsVerified {
		status = ValidationConfirmed
		conf = report.ConfidenceHigh
	}

	return Relationship{
		ID:                 fmt.Sprintf("REL-COR03-%s-%s", shortID(f1.ID), shortID(f2.ID)),
		SourceFindingID:    f1.ID,
		TargetFindingID:    f2.ID,
		SourceTitle:        f1.Title,
		TargetTitle:        f2.Title,
		Type:               RelExposes,
		ValidationStatus:   status,
		Confidence:         conf,
		RuleCode:           RuleCOR03,
		EvidenceReferences: []string{f1.Endpoint, f2.Endpoint},
		Explanation: fmt.Sprintf("Object-level authorization weakness '%s' permits unauthorized cross-tenant object access, directly exposing sensitive data '%s'.",
			f1.Title, f2.Title),
	}, true
}

// COR-04: Public Exposure to Sensitive Resource
func evaluateCOR04(f1, f2 *NormalizedFinding) (Relationship, bool) {
	isPublicExposure := strings.Contains(f1.NormalizedCategory, "public") ||
		strings.Contains(f1.NormalizedCategory, "env-exposure") ||
		strings.Contains(f1.NormalizedCategory, "firebase") ||
		strings.Contains(f1.NormalizedCategory, "git-exposure") ||
		strings.Contains(f1.NormalizedCategory, "backup")

	if !isPublicExposure || !f2.IsSensitiveData {
		return Relationship{}, false
	}

	// Must concern matching target, asset, or bucket
	sameTarget := f1.Target == f2.Target || f1.Host == f2.Host
	matchingBucket := f1.AffectedResource != "" && f2.AffectedResource != "" &&
		f1.AffectedResource == f2.AffectedResource
	matchingFile := strings.Contains(f2.Endpoint, f1.Endpoint) || strings.Contains(f1.Endpoint, f2.Endpoint)

	if !sameTarget && !matchingBucket && !matchingFile {
		return Relationship{}, false
	}

	status := ValidationPlausible
	conf := report.ConfidenceMedium
	if f1.IsVerified && f2.IsVerified {
		status = ValidationConfirmed
		conf = report.ConfidenceHigh
	}

	return Relationship{
		ID:                 fmt.Sprintf("REL-COR04-%s-%s", shortID(f1.ID), shortID(f2.ID)),
		SourceFindingID:    f1.ID,
		TargetFindingID:    f2.ID,
		SourceTitle:        f1.Title,
		TargetTitle:        f2.Title,
		Type:               RelExposes,
		ValidationStatus:   status,
		Confidence:         conf,
		RuleCode:           RuleCOR04,
		EvidenceReferences: []string{f1.Endpoint, f2.Endpoint},
		Explanation: fmt.Sprintf("Public service/storage exposure '%s' provides unauthenticated reachability, disclosing sensitive resource '%s'.",
			f1.Title, f2.Title),
	}, true
}

// COR-05: Privilege Escalation
func evaluateCOR05(f1, f2 *NormalizedFinding) (Relationship, bool) {
	isAuthzEsc := f1.IsEntrypoint ||
		strings.Contains(f1.NormalizedCategory, "bfla") ||
		strings.Contains(f1.NormalizedCategory, "role") ||
		strings.Contains(f1.NormalizedCategory, "unauthorized-workflow-access") ||
		strings.Contains(f1.NormalizedCategory, "privilege") ||
		strings.Contains(strings.ToLower(f1.Title), "unprivileged") ||
		strings.Contains(strings.ToLower(f1.Title), "user")

	isPrivilegedAction := strings.Contains(f2.NormalizedCategory, "admin") ||
		strings.Contains(f2.NormalizedCategory, "privilege") ||
		strings.Contains(f2.NormalizedCategory, "bfla") ||
		f2.IsRoleRestricted ||
		strings.Contains(strings.ToLower(f2.Endpoint), "/admin") ||
		strings.Contains(strings.ToLower(f2.Title), "admin") ||
		strings.Contains(strings.ToLower(f2.Title), "privilege escalation")

	if !isAuthzEsc || !isPrivilegedAction {
		return Relationship{}, false
	}
	if f1.Host == "" || f2.Host == "" || f1.Host != f2.Host {
		return Relationship{}, false
	}

	status := ValidationPlausible
	conf := report.ConfidenceMedium
	if f1.IsVerified && f2.IsVerified {
		status = ValidationConfirmed
		conf = report.ConfidenceHigh
	}

	return Relationship{
		ID:                 fmt.Sprintf("REL-COR05-%s-%s", shortID(f1.ID), shortID(f2.ID)),
		SourceFindingID:    f1.ID,
		TargetFindingID:    f2.ID,
		SourceTitle:        f1.Title,
		TargetTitle:        f2.Title,
		Type:               RelEnables,
		ValidationStatus:   status,
		Confidence:         conf,
		RuleCode:           RuleCOR05,
		EvidenceReferences: []string{f1.Endpoint, f2.Endpoint},
		Explanation: fmt.Sprintf("Unprivileged workflow access or role weakness '%s' enables elevation into privileged administrative capability '%s'.",
			f1.Title, f2.Title),
	}, true
}

// COR-06: Business Logic Chains
func evaluateCOR06(f1, f2 *NormalizedFinding) (Relationship, bool) {
	if !f1.IsWorkflowStep {
		return Relationship{}, false
	}

	wf1 := f1.EvidenceDetails["workflow"]
	if wf1 == "" {
		wf1 = f1.EvidenceDetails["workflow_id"]
	}
	wf2 := f2.EvidenceDetails["workflow"]
	if wf2 == "" {
		wf2 = f2.EvidenceDetails["workflow_id"]
	}
	if wf1 == "" || wf2 == "" || wf1 != wf2 {
		// If explicit workflow not tagged, fallback to shared order/checkout endpoint sequence
		if !strings.Contains(f1.Path, "order") && !strings.Contains(f1.Path, "checkout") && !strings.Contains(f1.Path, "cart") {
			return Relationship{}, false
		}
		if !strings.Contains(f2.Path, "order") && !strings.Contains(f2.Path, "checkout") && !strings.Contains(f2.Path, "pay") {
			return Relationship{}, false
		}
	}

	if f1.ID == f2.ID {
		return Relationship{}, false
	}

	status := ValidationPlausible
	conf := report.ConfidenceMedium
	if f1.IsVerified && f2.IsVerified && !f1.InferredHypothesis && !f2.InferredHypothesis {
		status = ValidationConfirmed
		conf = report.ConfidenceHigh
	}

	return Relationship{
		ID:                 fmt.Sprintf("REL-COR06-%s-%s", shortID(f1.ID), shortID(f2.ID)),
		SourceFindingID:    f1.ID,
		TargetFindingID:    f2.ID,
		SourceTitle:        f1.Title,
		TargetTitle:        f2.Title,
		Type:               RelEnables,
		ValidationStatus:   status,
		Confidence:         conf,
		RuleCode:           RuleCOR06,
		EvidenceReferences: []string{f1.Endpoint, f2.Endpoint},
		Explanation: fmt.Sprintf("Workflow circumvention or state transition flaw '%s' directly enables downstream business logic impact '%s'.",
			f1.Title, f2.Title),
	}, true
}

// COR-07: Session and Identity Dependencies
func evaluateCOR07(f1, f2 *NormalizedFinding) (Relationship, bool) {
	isSessionFlaw := strings.Contains(f1.NormalizedCategory, "session") ||
		strings.Contains(f1.NormalizedCategory, "logout") ||
		strings.Contains(f1.NormalizedCategory, "cookie") ||
		strings.Contains(f1.NormalizedCategory, "fixation")

	if !isSessionFlaw {
		return Relationship{}, false
	}
	if f1.Host == "" || f2.Host == "" || f1.Host != f2.Host {
		return Relationship{}, false
	}
	if f1.ID == f2.ID {
		return Relationship{}, false
	}

	status := ValidationPlausible
	conf := report.ConfidenceMedium
	if f1.IsVerified && f2.IsVerified {
		status = ValidationConfirmed
		conf = report.ConfidenceHigh
	}

	return Relationship{
		ID:                 fmt.Sprintf("REL-COR07-%s-%s", shortID(f1.ID), shortID(f2.ID)),
		SourceFindingID:    f1.ID,
		TargetFindingID:    f2.ID,
		SourceTitle:        f1.Title,
		TargetTitle:        f2.Title,
		Type:               RelDependsOn,
		ValidationStatus:   status,
		Confidence:         conf,
		RuleCode:           RuleCOR07,
		EvidenceReferences: []string{f1.Endpoint, f2.Endpoint},
		Explanation: fmt.Sprintf("Resource action '%s' depends on persistent or improperly invalidated identity context '%s'.",
			f2.Title, f1.Title),
	}, true
}

// COR-08: Cloud and Application Dependencies
func evaluateCOR08(f1, f2 *NormalizedFinding) (Relationship, bool) {
	isAppPivot := strings.Contains(f1.NormalizedCategory, "ssrf") ||
		strings.Contains(f1.NormalizedCategory, "secret") ||
		strings.Contains(f1.NormalizedCategory, "service-key") ||
		strings.Contains(f1.NormalizedCategory, "credential")

	if !isAppPivot || !f2.IsCloudResource {
		return Relationship{}, false
	}

	// Must establish connected dependency (e.g. matching endpoint or provider)
	ep2Lower := strings.ToLower(f2.Endpoint)
	hasPivot := strings.Contains(ep2Lower, "169.254.169.254") ||
		strings.Contains(ep2Lower, "supabase.co") ||
		strings.Contains(ep2Lower, "amazonaws.com") ||
		strings.Contains(ep2Lower, "windows.net") ||
		strings.Contains(ep2Lower, "googleapis.com")

	if !hasPivot && f1.Host != f2.Host {
		return Relationship{}, false
	}

	status := ValidationPlausible
	conf := report.ConfidenceMedium
	if f1.IsVerified && f2.IsVerified {
		status = ValidationConfirmed
		conf = report.ConfidenceHigh
	}

	return Relationship{
		ID:                 fmt.Sprintf("REL-COR08-%s-%s", shortID(f1.ID), shortID(f2.ID)),
		SourceFindingID:    f1.ID,
		TargetFindingID:    f2.ID,
		SourceTitle:        f1.Title,
		TargetTitle:        f2.Title,
		Type:               RelEnables,
		ValidationStatus:   status,
		Confidence:         conf,
		RuleCode:           RuleCOR08,
		EvidenceReferences: []string{f1.Endpoint, f2.Endpoint},
		Explanation: fmt.Sprintf("Application exposure '%s' provides pivot capability or credentials directly accessing cloud infrastructure resource '%s'.",
			f1.Title, f2.Title),
	}, true
}

// COR-09: Common Root Cause
func evaluateCOR09(f1, f2 *NormalizedFinding) (Relationship, bool) {
	if f1.Host == "" || f2.Host == "" || f1.Host != f2.Host {
		return Relationship{}, false
	}
	if f1.ID == f2.ID {
		return Relationship{}, false
	}

	// Share exact endpoint and similar hardening / architectural category
	sameEndpoint := f1.Path == f2.Path && f1.Method == f2.Method
	sameDefect := (strings.HasPrefix(f1.NormalizedCategory, "missing-") && strings.HasPrefix(f2.NormalizedCategory, "missing-")) ||
		(strings.Contains(f1.NormalizedCategory, "cors") && strings.Contains(f2.NormalizedCategory, "cors")) ||
		(strings.Contains(f1.NormalizedCategory, "header") && strings.Contains(f2.NormalizedCategory, "header"))

	if !sameEndpoint && !sameDefect {
		return Relationship{}, false
	}

	return Relationship{
		ID:                 fmt.Sprintf("REL-COR09-%s-%s", shortID(f1.ID), shortID(f2.ID)),
		SourceFindingID:    f1.ID,
		TargetFindingID:    f2.ID,
		SourceTitle:        f1.Title,
		TargetTitle:        f2.Title,
		Type:               RelSharesRootCause,
		ValidationStatus:   ValidationConfirmed,
		Confidence:         report.ConfidenceHigh,
		RuleCode:           RuleCOR09,
		EvidenceReferences: []string{f1.Endpoint, f2.Endpoint},
		Explanation: fmt.Sprintf("Findings '%s' and '%s' share a common underlying implementation defect or missing middleware at %s.",
			f1.Title, f2.Title, f1.Endpoint),
	}, true
}

// COR-10: Impact Amplification
func evaluateCOR10(f1, f2 *NormalizedFinding) (Relationship, bool) {
	isAmplifier := strings.Contains(f1.NormalizedCategory, "cors") ||
		strings.Contains(f1.NormalizedCategory, "source-map") ||
		strings.Contains(f1.NormalizedCategory, "info-disclosure")

	if !isAmplifier {
		return Relationship{}, false
	}
	if f1.Host == "" || f2.Host == "" || f1.Host != f2.Host {
		return Relationship{}, false
	}
	if f1.ID == f2.ID {
		return Relationship{}, false
	}

	isVulnerableAPI := strings.Contains(f2.NormalizedCategory, "bola") ||
		strings.Contains(f2.NormalizedCategory, "idor") ||
		strings.Contains(f2.NormalizedCategory, "xss") ||
		f2.IsSensitiveData

	if !isVulnerableAPI {
		return Relationship{}, false
	}

	status := ValidationPlausible
	conf := report.ConfidenceMedium
	if f1.IsVerified && f2.IsVerified {
		status = ValidationConfirmed
		conf = report.ConfidenceHigh
	}

	return Relationship{
		ID:                 fmt.Sprintf("REL-COR10-%s-%s", shortID(f1.ID), shortID(f2.ID)),
		SourceFindingID:    f1.ID,
		TargetFindingID:    f2.ID,
		SourceTitle:        f1.Title,
		TargetTitle:        f2.Title,
		Type:               RelAmplifiesImpact,
		ValidationStatus:   status,
		Confidence:         conf,
		RuleCode:           RuleCOR10,
		EvidenceReferences: []string{f1.Endpoint, f2.Endpoint},
		Explanation: fmt.Sprintf("Client/cross-origin condition '%s' amplifies the real-world exploitability and threat impact of '%s'.",
			f1.Title, f2.Title),
	}, true
}

func shortID(id string) string {
	if len(id) > 8 {
		return id[:8]
	}
	return id
}
