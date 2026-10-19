package correlation

import (
	"fmt"
	"sort"
	"strings"

	"felix/pkg/report"
	"felix/pkg/secrets"
)

// EvaluateRules iterates through candidate pairs of normalized findings and generates
// validated relationships according to the core correlation rules and structural asset rules.
func EvaluateRules(findings []NormalizedFinding, cfg Config) []Relationship {
	var rels []Relationship
	seenDirectedPairs := make(map[string]bool)
	seenSymmetricPairs := make(map[string]bool)

	rulesEnabled := make(map[RuleCode]bool)
	for _, r := range cfg.RulesEnabled {
		rulesEnabled[r] = true
	}

	// 1. Evaluate directed causal rules (COR-01 to COR-08, COR-10) across ordered pairs (f1, f2)
	for i := range findings {
		f1 := &findings[i]
		for j := range findings {
			if i == j {
				continue
			}
			f2 := &findings[j]

			pairKey := fmt.Sprintf("%s->%s", f1.ID, f2.ID)
			if seenDirectedPairs[pairKey] {
				continue
			}

			if rulesEnabled[RuleCOR01] {
				if r, ok := evaluateCOR01(f1, f2); ok {
					rels = append(rels, r)
					seenDirectedPairs[pairKey] = true
					continue
				}
			}
			if rulesEnabled[RuleCOR02] {
				if r, ok := evaluateCOR02(f1, f2); ok {
					rels = append(rels, r)
					seenDirectedPairs[pairKey] = true
					continue
				}
			}
			if rulesEnabled[RuleCOR03] {
				if r, ok := evaluateCOR03(f1, f2); ok {
					rels = append(rels, r)
					seenDirectedPairs[pairKey] = true
					continue
				}
			}
			if rulesEnabled[RuleCOR04] {
				if r, ok := evaluateCOR04(f1, f2); ok {
					rels = append(rels, r)
					seenDirectedPairs[pairKey] = true
					continue
				}
			}
			if rulesEnabled[RuleCOR05] {
				if r, ok := evaluateCOR05(f1, f2); ok {
					rels = append(rels, r)
					seenDirectedPairs[pairKey] = true
					continue
				}
			}
			if rulesEnabled[RuleCOR06] {
				if r, ok := evaluateCOR06(f1, f2); ok {
					rels = append(rels, r)
					seenDirectedPairs[pairKey] = true
					continue
				}
			}
			if rulesEnabled[RuleCOR07] {
				if r, ok := evaluateCOR07(f1, f2); ok {
					rels = append(rels, r)
					seenDirectedPairs[pairKey] = true
					continue
				}
			}
			if rulesEnabled[RuleCOR08] {
				if r, ok := evaluateCOR08(f1, f2); ok {
					rels = append(rels, r)
					seenDirectedPairs[pairKey] = true
					continue
				}
			}
			if rulesEnabled[RuleCOR10] {
				if r, ok := evaluateCOR10(f1, f2); ok {
					rels = append(rels, r)
					seenDirectedPairs[pairKey] = true
					continue
				}
			}
		}
	}

	// 2. Evaluate symmetric & structural rules on canonical unordered pairs (i < j)
	for i := 0; i < len(findings); i++ {
		for j := i + 1; j < len(findings); j++ {
			fA := &findings[i]
			fB := &findings[j]
			first, second := fA, fB
			if first.ID > second.ID {
				first, second = fB, fA
			}

			symKey := fmt.Sprintf("%s<->%s", first.ID, second.ID)

			// COR-09: Common Root Cause
			if rulesEnabled[RuleCOR09] {
				cor09Key := "COR09:" + symKey
				if !seenSymmetricPairs[cor09Key] {
					if r, ok := evaluateCOR09(first, second); ok {
						rels = append(rels, r)
						seenSymmetricPairs[cor09Key] = true
					}
				}
			}

			hasExactRel := false

			// Structural Asset Rules:
			// 1. Same Endpoint: Exact canonical endpoint match
			hasEndpoint := false
			if rulesEnabled[RuleCORSameEndpoint] {
				epKey := "SAME_EP:" + symKey
				if !seenSymmetricPairs[epKey] {
					if r, ok := evaluateSameEndpoint(first, second); ok {
						rels = append(rels, r)
						seenSymmetricPairs[epKey] = true
						hasEndpoint = true
						hasExactRel = true
					}
				}
			}

			// 2. Same Asset: Same origin/bucket/database/package (skip if already SAME_ENDPOINT)
			if !hasEndpoint && rulesEnabled[RuleCORSameAsset] {
				assetKey := "SAME_ASSET:" + symKey
				if !seenSymmetricPairs[assetKey] {
					if r, ok := evaluateSameAsset(first, second); ok {
						rels = append(rels, r)
						seenSymmetricPairs[assetKey] = true
						hasExactRel = true
					}
				}
			}

			// 3. Shared Component: Shared backend service, database, or cloud resource
			if rulesEnabled[RuleCORSharedComp] {
				compKey := "SHARED_COMP:" + symKey
				if !seenSymmetricPairs[compKey] {
					if r, ok := evaluateSharedComponent(first, second); ok {
						rels = append(rels, r)
						seenSymmetricPairs[compKey] = true
						hasExactRel = true
					}
				}
			}

			// 4. Related Evidence: Shared parameters or technical indicators
			if rulesEnabled[RuleCORRelatedEv] {
				evKey := "RELATED_EV:" + symKey
				if !seenSymmetricPairs[evKey] {
					if r, ok := evaluateRelatedEvidence(first, second); ok {
						rels = append(rels, r)
						seenSymmetricPairs[evKey] = true
						hasExactRel = true
					}
				}
			}

			// 5. Possible Relationship: Heuristic infrastructure fallback (only if no exact relationship matched)
			if !hasExactRel && rulesEnabled[RuleCORPossible] {
				possKey := "POSSIBLE:" + symKey
				if !seenSymmetricPairs[possKey] {
					if r, ok := evaluatePossibleRelationship(first, second); ok {
						rels = append(rels, r)
						seenSymmetricPairs[possKey] = true
					}
				}
			}
		}
	}

	// 3. Sort rels deterministically by ID, then SourceFindingID, then TargetFindingID
	sort.Slice(rels, func(i, j int) bool {
		if rels[i].ID != rels[j].ID {
			return rels[i].ID < rels[j].ID
		}
		if rels[i].SourceFindingID != rels[j].SourceFindingID {
			return rels[i].SourceFindingID < rels[j].SourceFindingID
		}
		return rels[i].TargetFindingID < rels[j].TargetFindingID
	})

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

	if !sameEndpoint || !sameDefect {
		return Relationship{}, false
	}

	first, second := f1, f2
	if first.ID > second.ID {
		first, second = f2, f1
	}

	return Relationship{
		ID:                 fmt.Sprintf("REL-COR09-%s-%s", shortID(first.ID), shortID(second.ID)),
		SourceFindingID:    first.ID,
		TargetFindingID:    second.ID,
		SourceTitle:        first.Title,
		TargetTitle:        second.Title,
		Type:               RelSharesRootCause,
		ValidationStatus:   ValidationConfirmed,
		Confidence:         report.ConfidenceHigh,
		RuleCode:           RuleCOR09,
		MatchingRule:       string(RuleCOR09),
		EvidenceReferences: []string{secrets.SanitizeURL(first.Endpoint), secrets.SanitizeURL(second.Endpoint)},
		Explanation: fmt.Sprintf("Findings '%s' and '%s' share a common underlying implementation defect or missing middleware at %s.",
			first.Title, second.Title, secrets.SanitizeURL(first.Endpoint)),
	}, true
}

// COR-SAME-ENDPOINT: Connects findings that demonstrably affect the exact same canonical endpoint
func evaluateSameEndpoint(f1, f2 *NormalizedFinding) (Relationship, bool) {
	ep1 := f1.Endpoint
	if ep1 == "" {
		ep1 = f1.Target
	}
	ep2 := f2.Endpoint
	if ep2 == "" {
		ep2 = f2.Target
	}
	if ep1 == "" || ep2 == "" {
		return Relationship{}, false
	}

	canon1, err1 := CanonicalizeURL(ep1)
	canon2, err2 := CanonicalizeURL(ep2)
	if err1 != nil || err2 != nil {
		return Relationship{}, false
	}

	// Must match origin, clean path, and clean query
	if canon1.Origin != canon2.Origin || canon1.Path != canon2.Path || canon1.Query != canon2.Query {
		return Relationship{}, false
	}

	// Compare HTTP methods (default to GET if unspecified)
	m1 := f1.Method
	if m1 == "" {
		m1 = "GET"
	}
	m2 := f2.Method
	if m2 == "" {
		m2 = "GET"
	}
	if !strings.EqualFold(m1, m2) {
		return Relationship{}, false
	}

	first, second := f1, f2
	if first.ID > second.ID {
		first, second = f2, f1
	}

	assetID := first.PrimaryAssetID
	if assetID == "" {
		assetID = second.PrimaryAssetID
	}
	assetKey := first.CanonicalAssetKey
	if assetKey == "" {
		assetKey = second.CanonicalAssetKey
	}

	return Relationship{
		ID:                 fmt.Sprintf("REL-SAME-ENDPOINT-%s-%s", shortID(first.ID), shortID(second.ID)),
		SourceFindingID:    first.ID,
		TargetFindingID:    second.ID,
		SourceTitle:        first.Title,
		TargetTitle:        second.Title,
		Type:               RelSameEndpoint,
		ValidationStatus:   ValidationConfirmed,
		Confidence:         report.ConfidenceHigh,
		RuleCode:           RuleCORSameEndpoint,
		MatchingRule:       string(RuleCORSameEndpoint),
		AssetID:            assetID,
		AssetKey:           assetKey,
		IsExact:            true,
		EvidenceReferences: []string{secrets.SanitizeURL(first.Endpoint), secrets.SanitizeURL(second.Endpoint)},
		Explanation: fmt.Sprintf("Findings '%s' and '%s' demonstrably affect the exact same canonical endpoint (%s %s).",
			first.Title, second.Title, strings.ToUpper(m1), canon1.Endpoint),
	}, true
}

// COR-SAME-ASSET: Connects findings that demonstrably affect the same resolved asset identity
func evaluateSameAsset(f1, f2 *NormalizedFinding) (Relationship, bool) {
	first, second := f1, f2
	if first.ID > second.ID {
		first, second = f2, f1
	}

	// 1. Check matching explicit canonical asset key (if valid and not unresolved/malformed)
	if first.CanonicalAssetKey != "" && first.CanonicalAssetKey == second.CanonicalAssetKey &&
		!strings.HasPrefix(first.CanonicalAssetKey, "unresolved") &&
		!strings.HasPrefix(first.CanonicalAssetKey, "malformed") {
		return Relationship{
			ID:                 fmt.Sprintf("REL-SAME-ASSET-%s-%s", shortID(first.ID), shortID(second.ID)),
			SourceFindingID:    first.ID,
			TargetFindingID:    second.ID,
			SourceTitle:        first.Title,
			TargetTitle:        second.Title,
			Type:               RelSameAsset,
			ValidationStatus:   ValidationConfirmed,
			Confidence:         report.ConfidenceHigh,
			RuleCode:           RuleCORSameAsset,
			MatchingRule:       string(RuleCORSameAsset),
			AssetID:            first.PrimaryAssetID,
			AssetKey:           first.CanonicalAssetKey,
			IsExact:            true,
			EvidenceReferences: []string{secrets.SanitizeURL(first.Endpoint), secrets.SanitizeURL(second.Endpoint)},
			Explanation: fmt.Sprintf("Findings '%s' and '%s' demonstrably affect the same resolved asset (%s).",
				first.Title, second.Title, first.CanonicalAssetKey),
		}, true
	}

	// 2. Check matching PrimaryAssetID (if explicit and valid)
	if first.PrimaryAssetID != "" && first.PrimaryAssetID == second.PrimaryAssetID &&
		first.PrimaryAssetID != "unresolved" {
		return Relationship{
			ID:                 fmt.Sprintf("REL-SAME-ASSET-%s-%s", shortID(first.ID), shortID(second.ID)),
			SourceFindingID:    first.ID,
			TargetFindingID:    second.ID,
			SourceTitle:        first.Title,
			TargetTitle:        second.Title,
			Type:               RelSameAsset,
			ValidationStatus:   ValidationConfirmed,
			Confidence:         report.ConfidenceHigh,
			RuleCode:           RuleCORSameAsset,
			MatchingRule:       string(RuleCORSameAsset),
			AssetID:            first.PrimaryAssetID,
			AssetKey:           first.CanonicalAssetKey,
			IsExact:            true,
			EvidenceReferences: []string{secrets.SanitizeURL(first.Endpoint), secrets.SanitizeURL(second.Endpoint)},
			Explanation: fmt.Sprintf("Findings '%s' and '%s' demonstrably affect the same asset ID (%s).",
				first.Title, second.Title, first.PrimaryAssetID),
		}, true
	}

	// 3. Check matching application Origin (compatible scheme and host:port)
	if first.Origin != "" && second.Origin != "" && first.Origin == second.Origin {
		return Relationship{
			ID:                 fmt.Sprintf("REL-SAME-ASSET-%s-%s", shortID(first.ID), shortID(second.ID)),
			SourceFindingID:    first.ID,
			TargetFindingID:    second.ID,
			SourceTitle:        first.Title,
			TargetTitle:        second.Title,
			Type:               RelSameAsset,
			ValidationStatus:   ValidationConfirmed,
			Confidence:         report.ConfidenceHigh,
			RuleCode:           RuleCORSameAsset,
			MatchingRule:       string(RuleCORSameAsset),
			AssetID:            first.PrimaryAssetID,
			AssetKey:           first.Origin,
			IsExact:            true,
			EvidenceReferences: []string{secrets.SanitizeURL(first.Endpoint), secrets.SanitizeURL(second.Endpoint)},
			Explanation: fmt.Sprintf("Findings '%s' and '%s' affect different endpoints of the same application origin (%s).",
				first.Title, second.Title, first.Origin),
		}, true
	}

	return Relationship{}, false
}

// COR-SHARED-COMP: Connects findings sharing an underlying backend service, database, or cloud resource
func evaluateSharedComponent(f1, f2 *NormalizedFinding) (Relationship, bool) {
	first, second := f1, f2
	if first.ID > second.ID {
		first, second = f2, f1
	}

	// 1. Shared AffectedResource (if explicitly set and not empty)
	if first.AffectedResource != "" && first.AffectedResource == second.AffectedResource {
		return Relationship{
			ID:                 fmt.Sprintf("REL-SHARED-COMP-%s-%s", shortID(first.ID), shortID(second.ID)),
			SourceFindingID:    first.ID,
			TargetFindingID:    second.ID,
			SourceTitle:        first.Title,
			TargetTitle:        second.Title,
			Type:               RelSharedComponent,
			ValidationStatus:   ValidationConfirmed,
			Confidence:         report.ConfidenceHigh,
			RuleCode:           RuleCORSharedComp,
			MatchingRule:       string(RuleCORSharedComp),
			EvidenceReferences: []string{secrets.SanitizeURL(first.Endpoint), secrets.SanitizeURL(second.Endpoint)},
			Explanation: fmt.Sprintf("Findings '%s' and '%s' share backend resource '%s'.",
				first.Title, second.Title, first.AffectedResource),
		}, true
	}

	// 2. Shared component / backend / service in EvidenceDetails
	componentKeys := []string{"component", "database", "service", "backend", "framework", "bucket", "project_id"}
	for _, k := range componentKeys {
		v1 := strings.TrimSpace(first.EvidenceDetails[k])
		v2 := strings.TrimSpace(second.EvidenceDetails[k])
		if v1 != "" && strings.EqualFold(v1, v2) {
			return Relationship{
				ID:                 fmt.Sprintf("REL-SHARED-COMP-%s-%s", shortID(first.ID), shortID(second.ID)),
				SourceFindingID:    first.ID,
				TargetFindingID:    second.ID,
				SourceTitle:        first.Title,
				TargetTitle:        second.Title,
				Type:               RelSharedComponent,
				ValidationStatus:   ValidationConfirmed,
				Confidence:         report.ConfidenceHigh,
				RuleCode:           RuleCORSharedComp,
				MatchingRule:       string(RuleCORSharedComp),
				EvidenceReferences: []string{secrets.SanitizeURL(first.Endpoint), secrets.SanitizeURL(second.Endpoint)},
				Explanation: fmt.Sprintf("Findings '%s' and '%s' share underlying %s '%s'.",
					first.Title, second.Title, k, v1),
			}, true
		}
	}

	return Relationship{}, false
}

// COR-RELATED-EV: Connects findings sharing documented technical indicators or specific evidence parameters
func evaluateRelatedEvidence(f1, f2 *NormalizedFinding) (Relationship, bool) {
	first, second := f1, f2
	if first.ID > second.ID {
		first, second = f2, f1
	}

	// Must share at least host or origin to prevent arbitrary cross-domain coincidence
	if first.Host == "" || second.Host == "" || first.Host != second.Host {
		return Relationship{}, false
	}

	// Check shared parameters
	if len(first.Parameters) > 0 && len(second.Parameters) > 0 {
		for _, p1 := range first.Parameters {
			cleanP1 := strings.ToLower(strings.TrimSpace(p1))
			if cleanP1 == "" || cleanP1 == "id" {
				continue // skip overly generic single letters or "id"
			}
			for _, p2 := range second.Parameters {
				cleanP2 := strings.ToLower(strings.TrimSpace(p2))
				if cleanP1 == cleanP2 {
					return Relationship{
						ID:                 fmt.Sprintf("REL-RELATED-EV-%s-%s", shortID(first.ID), shortID(second.ID)),
						SourceFindingID:    first.ID,
						TargetFindingID:    second.ID,
						SourceTitle:        first.Title,
						TargetTitle:        second.Title,
						Type:               RelRelatedEvidence,
						ValidationStatus:   ValidationConfirmed,
						Confidence:         report.ConfidenceMedium,
						RuleCode:           RuleCORRelatedEv,
						MatchingRule:       string(RuleCORRelatedEv),
						EvidenceReferences: []string{secrets.SanitizeURL(first.Endpoint), secrets.SanitizeURL(second.Endpoint)},
						Explanation: fmt.Sprintf("Findings '%s' and '%s' share parameter evidence '%s'.",
							first.Title, second.Title, cleanP1),
					}, true
				}
			}
		}
	}

	// Check shared technical indicator in EvidenceDetails
	evKeys := []string{"cve", "indicator", "header", "vulnerability_id"}
	for _, k := range evKeys {
		v1 := strings.TrimSpace(first.EvidenceDetails[k])
		v2 := strings.TrimSpace(second.EvidenceDetails[k])
		if v1 != "" && strings.EqualFold(v1, v2) {
			return Relationship{
				ID:                 fmt.Sprintf("REL-RELATED-EV-%s-%s", shortID(first.ID), shortID(second.ID)),
				SourceFindingID:    first.ID,
				TargetFindingID:    second.ID,
				SourceTitle:        first.Title,
				TargetTitle:        second.Title,
				Type:               RelRelatedEvidence,
				ValidationStatus:   ValidationConfirmed,
				Confidence:         report.ConfidenceMedium,
				RuleCode:           RuleCORRelatedEv,
				MatchingRule:       string(RuleCORRelatedEv),
				EvidenceReferences: []string{secrets.SanitizeURL(first.Endpoint), secrets.SanitizeURL(second.Endpoint)},
				Explanation: fmt.Sprintf("Findings '%s' and '%s' share %s indicator '%s'.",
					first.Title, second.Title, k, v1),
			}, true
		}
	}

	return Relationship{}, false
}

// COR-POSSIBLE: Records heuristic associations where evidence suggests shared infrastructure
func evaluatePossibleRelationship(f1, f2 *NormalizedFinding) (Relationship, bool) {
	first, second := f1, f2
	if first.ID > second.ID {
		first, second = f2, f1
	}

	// 1. Shared IP address
	ip1 := strings.TrimSpace(first.EvidenceDetails["ip"])
	ip2 := strings.TrimSpace(second.EvidenceDetails["ip"])
	if ip1 != "" && ip1 == ip2 {
		return Relationship{
			ID:                 fmt.Sprintf("REL-POSSIBLE-%s-%s", shortID(first.ID), shortID(second.ID)),
			SourceFindingID:    first.ID,
			TargetFindingID:    second.ID,
			SourceTitle:        first.Title,
			TargetTitle:        second.Title,
			Type:               RelPossibleRelationship,
			ValidationStatus:   ValidationInconclusive,
			Confidence:         report.ConfidenceLow,
			IsExact:            false,
			RuleCode:           RuleCORPossible,
			MatchingRule:       string(RuleCORPossible),
			EvidenceReferences: []string{secrets.SanitizeURL(first.Endpoint), secrets.SanitizeURL(second.Endpoint)},
			Explanation: fmt.Sprintf("Findings '%s' and '%s' resolve to the same IP address (%s), but shared infrastructure does not imply common root cause or sequential relationship.",
				first.Title, second.Title, ip1),
			InconclusiveReason: "Shared IP address suggests common hosting infrastructure but does not establish application-level relationship or common defect.",
		}, true
	}

	// 2. Same Hostname with different schemes or ports (e.g. http:// vs https://, or :8080 vs :8443)
	if first.Host != "" && second.Host != "" && first.Host == second.Host && first.Origin != second.Origin {
		return Relationship{
			ID:                 fmt.Sprintf("REL-POSSIBLE-%s-%s", shortID(first.ID), shortID(second.ID)),
			SourceFindingID:    first.ID,
			TargetFindingID:    second.ID,
			SourceTitle:        first.Title,
			TargetTitle:        second.Title,
			Type:               RelPossibleRelationship,
			ValidationStatus:   ValidationInconclusive,
			Confidence:         report.ConfidenceLow,
			IsExact:            false,
			RuleCode:           RuleCORPossible,
			MatchingRule:       string(RuleCORPossible),
			EvidenceReferences: []string{secrets.SanitizeURL(first.Endpoint), secrets.SanitizeURL(second.Endpoint)},
			Explanation: fmt.Sprintf("Findings '%s' and '%s' share hostname '%s' across different origins (%s vs %s); shared infrastructure does not imply common root cause or sequential relationship.",
				first.Title, second.Title, first.Host, first.Origin, second.Origin),
			InconclusiveReason: "Different origins on the same host may represent distinct services or isolation boundaries.",
		}, true
	}

	return Relationship{}, false
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
