package correlation

import (
	"crypto/sha256"
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

			if len(seenDirectedPairs) > 0 {
				pairKey := f1.ID + "->" + f2.ID
				if seenDirectedPairs[pairKey] {
					continue
				}
			}

			if rulesEnabled[RuleCOR01] {
				if r, ok := evaluateCOR01(f1, f2); ok {
					rels = append(rels, r)
					seenDirectedPairs[f1.ID+"->"+f2.ID] = true
					continue
				}
			}
			if rulesEnabled[RuleCOR02] {
				if r, ok := evaluateCOR02(f1, f2); ok {
					rels = append(rels, r)
					seenDirectedPairs[f1.ID+"->"+f2.ID] = true
					continue
				}
			}
			if rulesEnabled[RuleCOR03] {
				if r, ok := evaluateCOR03(f1, f2); ok {
					rels = append(rels, r)
					seenDirectedPairs[f1.ID+"->"+f2.ID] = true
					continue
				}
			}
			if rulesEnabled[RuleCOR04] {
				if r, ok := evaluateCOR04(f1, f2); ok {
					rels = append(rels, r)
					seenDirectedPairs[f1.ID+"->"+f2.ID] = true
					continue
				}
			}
			if rulesEnabled[RuleCOR05] {
				if r, ok := evaluateCOR05(f1, f2); ok {
					rels = append(rels, r)
					seenDirectedPairs[f1.ID+"->"+f2.ID] = true
					continue
				}
			}
			if rulesEnabled[RuleCOR06] {
				if r, ok := evaluateCOR06(f1, f2); ok {
					rels = append(rels, r)
					seenDirectedPairs[f1.ID+"->"+f2.ID] = true
					continue
				}
			}
			if rulesEnabled[RuleCOR07] {
				if r, ok := evaluateCOR07(f1, f2); ok {
					rels = append(rels, r)
					seenDirectedPairs[f1.ID+"->"+f2.ID] = true
					continue
				}
			}
			if rulesEnabled[RuleCOR08] {
				if r, ok := evaluateCOR08(f1, f2); ok {
					rels = append(rels, r)
					seenDirectedPairs[f1.ID+"->"+f2.ID] = true
					continue
				}
			}
			if rulesEnabled[RuleCOR10] {
				if r, ok := evaluateCOR10(f1, f2); ok {
					rels = append(rels, r)
					seenDirectedPairs[f1.ID+"->"+f2.ID] = true
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

			// COR-09: Common Root Cause
			if rulesEnabled[RuleCOR09] {
				if r, ok := evaluateCOR09(first, second); ok {
					cor09Key := "COR09:" + first.ID + "<->" + second.ID
					if !seenSymmetricPairs[cor09Key] {
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
				if r, ok := evaluateSameEndpoint(first, second); ok {
					epKey := "SAME_EP:" + first.ID + "<->" + second.ID
					if !seenSymmetricPairs[epKey] {
						rels = append(rels, r)
						seenSymmetricPairs[epKey] = true
						hasEndpoint = true
						hasExactRel = true
					}
				}
			}

			// 2. Same Asset: Same origin/bucket/database/package (skip if already SAME_ENDPOINT)
			if !hasEndpoint && rulesEnabled[RuleCORSameAsset] {
				if r, ok := evaluateSameAsset(first, second); ok {
					assetKey := "SAME_ASSET:" + first.ID + "<->" + second.ID
					if !seenSymmetricPairs[assetKey] {
						rels = append(rels, r)
						seenSymmetricPairs[assetKey] = true
						hasExactRel = true
					}
				}
			}

			// 3. Shared Component: Shared backend service, database, or cloud resource
			if rulesEnabled[RuleCORSharedComp] {
				if r, ok := evaluateSharedComponent(first, second); ok {
					compKey := "SHARED_COMP:" + first.ID + "<->" + second.ID
					if !seenSymmetricPairs[compKey] {
						rels = append(rels, r)
						seenSymmetricPairs[compKey] = true
						hasExactRel = true
					}
				}
			}

			// 4. Related Evidence: Shared parameters or technical indicators
			if rulesEnabled[RuleCORRelatedEv] {
				if r, ok := evaluateRelatedEvidence(first, second); ok {
					evKey := "RELATED_EV:" + first.ID + "<->" + second.ID
					if !seenSymmetricPairs[evKey] {
						rels = append(rels, r)
						seenSymmetricPairs[evKey] = true
						hasExactRel = true
					}
				}
			}

			// 5. Possible Relationship: Heuristic infrastructure fallback (only if no exact relationship matched)
			if !hasExactRel && rulesEnabled[RuleCORPossible] {
				if r, ok := evaluatePossibleRelationship(first, second); ok {
					possKey := "POSSIBLE:" + first.ID + "<->" + second.ID
					if !seenSymmetricPairs[possKey] {
						rels = append(rels, r)
						seenSymmetricPairs[possKey] = true
					}
				}
			}
		}
	}

	// 3. Deterministically sort candidate relationships by RuleCode, SourceFindingID, TargetFindingID
	sort.Slice(rels, func(i, j int) bool {
		if rels[i].RuleCode != rels[j].RuleCode {
			return rels[i].RuleCode < rels[j].RuleCode
		}
		if rels[i].SourceFindingID != rels[j].SourceFindingID {
			return rels[i].SourceFindingID < rels[j].SourceFindingID
		}
		return rels[i].TargetFindingID < rels[j].TargetFindingID
	})

	// 4. Resolve any ID collisions deterministically to strictly guarantee uniqueness across all relationship IDs
	seenRelIDs := make(map[string]int)
	for i := range rels {
		baseID := rels[i].ID
		if count := seenRelIDs[baseID]; count > 0 {
			rels[i].ID = fmt.Sprintf("%s_c%d", baseID, count)
		}
		seenRelIDs[baseID]++
	}

	// 5. Final deterministic sort by ID, SourceFindingID, TargetFindingID
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

	// Boundary conflict prevents cross-boundary reachable exposure
	if conflict, _, _ := hasBoundaryConflict(f1.EvidenceDetails, f2.EvidenceDetails); conflict {
		return Relationship{}, false
	}

	// Target must not be a configuration omission, missing header, or informational fingerprint
	cat2 := strings.ToLower(f2.NormalizedCategory)
	if strings.HasPrefix(cat2, "missing-") ||
		strings.Contains(cat2, "header") ||
		strings.Contains(cat2, "csp") ||
		strings.Contains(cat2, "runtime") ||
		strings.Contains(cat2, "fingerprint") ||
		strings.Contains(cat2, "source-map") {
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
		ID:                 relationshipID(RuleCOR01, f1.ID, f2.ID),
		SourceFindingID:    f1.ID,
		TargetFindingID:    f2.ID,
		SourceTitle:        f1.Title,
		TargetTitle:        f2.Title,
		Type:               RelReaches,
		ValidationStatus:   status,
		Confidence:         conf,
		RuleCode:           RuleCOR01,
		EvidenceReferences: []string{findingRef(f1), findingRef(f2)},
		Explanation: fmt.Sprintf("Public entry point '%s' (%s) provides external reachability directly to vulnerable component '%s' (%s).",
			f1.Title, findingRef(f1), f2.Title, findingRef(f2)),
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
		ID:                 relationshipID(RuleCOR02, f1.ID, f2.ID),
		SourceFindingID:    f1.ID,
		TargetFindingID:    f2.ID,
		SourceTitle:        f1.Title,
		TargetTitle:        f2.Title,
		Type:               RelEnables,
		ValidationStatus:   status,
		Confidence:         conf,
		RuleCode:           RuleCOR02,
		EvidenceReferences: []string{findingRef(f1), findingRef(f2)},
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
		ID:                 relationshipID(RuleCOR03, f1.ID, f2.ID),
		SourceFindingID:    f1.ID,
		TargetFindingID:    f2.ID,
		SourceTitle:        f1.Title,
		TargetTitle:        f2.Title,
		Type:               RelExposes,
		ValidationStatus:   status,
		Confidence:         conf,
		RuleCode:           RuleCOR03,
		EvidenceReferences: []string{findingRef(f1), findingRef(f2)},
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
		ID:                 relationshipID(RuleCOR04, f1.ID, f2.ID),
		SourceFindingID:    f1.ID,
		TargetFindingID:    f2.ID,
		SourceTitle:        f1.Title,
		TargetTitle:        f2.Title,
		Type:               RelExposes,
		ValidationStatus:   status,
		Confidence:         conf,
		RuleCode:           RuleCOR04,
		EvidenceReferences: []string{findingRef(f1), findingRef(f2)},
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
		ID:                 relationshipID(RuleCOR05, f1.ID, f2.ID),
		SourceFindingID:    f1.ID,
		TargetFindingID:    f2.ID,
		SourceTitle:        f1.Title,
		TargetTitle:        f2.Title,
		Type:               RelEnables,
		ValidationStatus:   status,
		Confidence:         conf,
		RuleCode:           RuleCOR05,
		EvidenceReferences: []string{findingRef(f1), findingRef(f2)},
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
		ID:                 relationshipID(RuleCOR06, f1.ID, f2.ID),
		SourceFindingID:    f1.ID,
		TargetFindingID:    f2.ID,
		SourceTitle:        f1.Title,
		TargetTitle:        f2.Title,
		Type:               RelEnables,
		ValidationStatus:   status,
		Confidence:         conf,
		RuleCode:           RuleCOR06,
		EvidenceReferences: []string{findingRef(f1), findingRef(f2)},
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
		ID:                 relationshipID(RuleCOR07, f1.ID, f2.ID),
		SourceFindingID:    f1.ID,
		TargetFindingID:    f2.ID,
		SourceTitle:        f1.Title,
		TargetTitle:        f2.Title,
		Type:               RelDependsOn,
		ValidationStatus:   status,
		Confidence:         conf,
		RuleCode:           RuleCOR07,
		EvidenceReferences: []string{findingRef(f1), findingRef(f2)},
		Explanation: fmt.Sprintf("Resource action '%s' depends on persistent or improperly invalidated identity context '%s'.",
			f2.Title, f1.Title),
	}, true
}

// COR-08: Cloud and Application Dependencies
func evaluateCOR08(f1, f2 *NormalizedFinding) (Relationship, bool) {
	isAppPivot := strings.Contains(f1.NormalizedCategory, "ssrf") ||
		strings.Contains(f1.NormalizedCategory, "secret") ||
		strings.Contains(f1.NormalizedCategory, "service-key") ||
		strings.Contains(f1.NormalizedCategory, "credential") ||
		(f1.IsSensitiveData && (strings.Contains(strings.ToLower(f1.Title), "credential") ||
			strings.Contains(strings.ToLower(f1.Title), "key") ||
			strings.Contains(strings.ToLower(f1.Title), "token") ||
			strings.Contains(strings.ToLower(f1.Title), "secret") ||
			f1.EvidenceDetails["secret_type"] != "" ||
			f1.EvidenceDetails["credential"] != ""))

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
		ID:                 relationshipID(RuleCOR08, f1.ID, f2.ID),
		SourceFindingID:    f1.ID,
		TargetFindingID:    f2.ID,
		SourceTitle:        f1.Title,
		TargetTitle:        f2.Title,
		Type:               RelEnables,
		ValidationStatus:   status,
		Confidence:         conf,
		RuleCode:           RuleCOR08,
		EvidenceReferences: []string{findingRef(f1), findingRef(f2)},
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
		ID:                 relationshipID(RuleCOR09, first.ID, second.ID),
		SourceFindingID:    first.ID,
		TargetFindingID:    second.ID,
		SourceTitle:        first.Title,
		TargetTitle:        second.Title,
		Type:               RelSharesRootCause,
		ValidationStatus:   ValidationConfirmed,
		Confidence:         report.ConfidenceHigh,
		RuleCode:           RuleCOR09,
		MatchingRule:       string(RuleCOR09),
		EvidenceReferences: []string{findingRef(first), findingRef(second)},
		Explanation: fmt.Sprintf("Findings '%s' and '%s' share a common underlying implementation defect or missing middleware at %s.",
			first.Title, second.Title, findingRef(first)),
	}, true
}

// hasBoundaryConflict checks whether two findings have conflicting tenant, account, or organization isolation boundaries.
// Returns (hasConflict, boundaryDesc1, boundaryDesc2).
// Explicit missing identifiers on either side are NEVER treated as proof that boundaries match or conflict.
// Free-form prose is ignored; only explicit structured boundary metadata keys are evaluated.
func hasBoundaryConflict(d1, d2 map[string]string) (bool, string, string) {
	if d1 == nil || d2 == nil {
		return false, "", ""
	}

	// 1. Explicit Tenant boundary comparison
	t1 := strings.TrimSpace(d1["tenant_id"])
	t2 := strings.TrimSpace(d2["tenant_id"])
	if t1 != "" && t2 != "" && !strings.EqualFold(t1, t2) {
		return true, fmt.Sprintf("tenant:%s", t1), fmt.Sprintf("tenant:%s", t2)
	}

	// 2. Explicit Account boundary comparison
	a1 := strings.TrimSpace(d1["account_id"])
	a2 := strings.TrimSpace(d2["account_id"])
	if a1 != "" && a2 != "" && !strings.EqualFold(a1, a2) {
		return true, fmt.Sprintf("account:%s", a1), fmt.Sprintf("account:%s", a2)
	}

	// 3. Explicit Organization boundary comparison
	o1 := strings.TrimSpace(d1["org_id"])
	if o1 == "" {
		o1 = strings.TrimSpace(d1["organization_id"])
	}
	o2 := strings.TrimSpace(d2["org_id"])
	if o2 == "" {
		o2 = strings.TrimSpace(d2["organization_id"])
	}
	if o1 != "" && o2 != "" && !strings.EqualFold(o1, o2) {
		return true, fmt.Sprintf("org:%s", o1), fmt.Sprintf("org:%s", o2)
	}

	return false, "", ""
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

	// Boundary check: distinct tenant or account IDs must not be SAME_ENDPOINT
	if conflict, _, _ := hasBoundaryConflict(f1.EvidenceDetails, f2.EvidenceDetails); conflict {
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

	dispEP := canon1.DisplayEndpoint
	if dispEP == "" {
		dispEP = canon1.Endpoint
	}

	return Relationship{
		ID:                 relationshipID(RuleCORSameEndpoint, first.ID, second.ID),
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
		EvidenceReferences: []string{findingRef(first), findingRef(second)},
		Explanation: fmt.Sprintf("Findings '%s' and '%s' demonstrably affect the exact same canonical endpoint (%s %s).",
			first.Title, second.Title, strings.ToUpper(m1), dispEP),
	}, true
}

// COR-SAME-ASSET: Connects findings that demonstrably affect the same resolved asset identity
func evaluateSameAsset(f1, f2 *NormalizedFinding) (Relationship, bool) {
	// Boundary check: distinct tenant or account IDs must not be SAME_ASSET
	if conflict, _, _ := hasBoundaryConflict(f1.EvidenceDetails, f2.EvidenceDetails); conflict {
		return Relationship{}, false
	}

	first, second := f1, f2
	if first.ID > second.ID {
		first, second = f2, f1
	}

	// 1. Check matching explicit canonical asset key (if valid and not unresolved/malformed)
	if first.CanonicalAssetKey != "" && first.CanonicalAssetKey == second.CanonicalAssetKey &&
		!strings.HasPrefix(first.CanonicalAssetKey, "unresolved") &&
		!strings.HasPrefix(first.CanonicalAssetKey, "malformed") {
		return Relationship{
			ID:                 relationshipID(RuleCORSameAsset, first.ID, second.ID),
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
			EvidenceReferences: []string{findingRef(first), findingRef(second)},
			Explanation: fmt.Sprintf("Findings '%s' and '%s' demonstrably affect the same resolved asset (%s).",
				first.Title, second.Title, first.CanonicalAssetKey),
		}, true
	}

	// 2. Check matching PrimaryAssetID (if explicit and valid)
	if first.PrimaryAssetID != "" && first.PrimaryAssetID == second.PrimaryAssetID &&
		first.PrimaryAssetID != "unresolved" {
		return Relationship{
			ID:                 relationshipID(RuleCORSameAsset, first.ID, second.ID),
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
			EvidenceReferences: []string{findingRef(first), findingRef(second)},
			Explanation: fmt.Sprintf("Findings '%s' and '%s' demonstrably affect the same asset ID (%s).",
				first.Title, second.Title, first.PrimaryAssetID),
		}, true
	}

	// 3. Check matching application Origin (compatible scheme and host:port)
	if first.Origin != "" && second.Origin != "" && first.Origin == second.Origin {
		return Relationship{
			ID:                 relationshipID(RuleCORSameAsset, first.ID, second.ID),
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
			EvidenceReferences: []string{findingRef(first), findingRef(second)},
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
			ID:                 relationshipID(RuleCORSharedComp, first.ID, second.ID),
			SourceFindingID:    first.ID,
			TargetFindingID:    second.ID,
			SourceTitle:        first.Title,
			TargetTitle:        second.Title,
			Type:               RelSharedComponent,
			ValidationStatus:   ValidationConfirmed,
			Confidence:         report.ConfidenceHigh,
			RuleCode:           RuleCORSharedComp,
			MatchingRule:       string(RuleCORSharedComp),
			EvidenceReferences: []string{findingRef(first), findingRef(second)},
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
				ID:                 relationshipID(RuleCORSharedComp, first.ID, second.ID),
				SourceFindingID:    first.ID,
				TargetFindingID:    second.ID,
				SourceTitle:        first.Title,
				TargetTitle:        second.Title,
				Type:               RelSharedComponent,
				ValidationStatus:   ValidationConfirmed,
				Confidence:         report.ConfidenceHigh,
				RuleCode:           RuleCORSharedComp,
				MatchingRule:       string(RuleCORSharedComp),
				EvidenceReferences: []string{findingRef(first), findingRef(second)},
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
						ID:                 relationshipID(RuleCORRelatedEv, first.ID, second.ID),
						SourceFindingID:    first.ID,
						TargetFindingID:    second.ID,
						SourceTitle:        first.Title,
						TargetTitle:        second.Title,
						Type:               RelRelatedEvidence,
						ValidationStatus:   ValidationConfirmed,
						Confidence:         report.ConfidenceMedium,
						RuleCode:           RuleCORRelatedEv,
						MatchingRule:       string(RuleCORRelatedEv),
						EvidenceReferences: []string{findingRef(first), findingRef(second)},
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
				ID:                 relationshipID(RuleCORRelatedEv, first.ID, second.ID),
				SourceFindingID:    first.ID,
				TargetFindingID:    second.ID,
				SourceTitle:        first.Title,
				TargetTitle:        second.Title,
				Type:               RelRelatedEvidence,
				ValidationStatus:   ValidationConfirmed,
				Confidence:         report.ConfidenceMedium,
				RuleCode:           RuleCORRelatedEv,
				MatchingRule:       string(RuleCORRelatedEv),
				EvidenceReferences: []string{findingRef(first), findingRef(second)},
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

	// Check cross-boundary (tenant or account) isolation on shared host
	if conflict, b1, b2 := hasBoundaryConflict(first.EvidenceDetails, second.EvidenceDetails); conflict && first.Host != "" && first.Host == second.Host {
		boundaryType := "isolation"
		inconclusiveReason := "Distinct isolation boundaries on shared hosting infrastructure."
		if strings.HasPrefix(b1, "tenant:") && strings.HasPrefix(b2, "tenant:") {
			boundaryType = "tenant"
			inconclusiveReason = "Distinct tenant boundaries on shared hosting infrastructure."
		} else if strings.HasPrefix(b1, "account:") && strings.HasPrefix(b2, "account:") {
			boundaryType = "account"
			inconclusiveReason = "Distinct account boundaries on shared hosting infrastructure."
		}

		return Relationship{
			ID:                 relationshipID(RuleCORPossible, first.ID, second.ID),
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
			EvidenceReferences: []string{findingRef(first), findingRef(second)},
			Explanation: fmt.Sprintf("Findings '%s' and '%s' share host '%s' across distinct %s boundaries (%s vs %s); shared infrastructure does not imply common root cause or identity.",
				first.Title, second.Title, first.Host, boundaryType, b1, b2),
			InconclusiveReason: inconclusiveReason,
		}, true
	}

	// 1. Shared IP address
	ip1 := strings.TrimSpace(first.EvidenceDetails["ip"])
	ip2 := strings.TrimSpace(second.EvidenceDetails["ip"])
	if ip1 != "" && ip1 == ip2 {
		return Relationship{
			ID:                 relationshipID(RuleCORPossible, first.ID, second.ID),
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
			EvidenceReferences: []string{findingRef(first), findingRef(second)},
			Explanation: fmt.Sprintf("Findings '%s' and '%s' resolve to the same IP address (%s), but shared infrastructure does not imply common root cause or sequential relationship.",
				first.Title, second.Title, ip1),
			InconclusiveReason: "Shared IP address suggests common hosting infrastructure but does not establish application-level relationship or common defect.",
		}, true
	}

	// 2. Same Hostname with different schemes or ports (e.g. http:// vs https://, or :8080 vs :8443)
	if first.Host != "" && second.Host != "" && first.Host == second.Host && first.Origin != second.Origin {
		return Relationship{
			ID:                 relationshipID(RuleCORPossible, first.ID, second.ID),
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
			EvidenceReferences: []string{findingRef(first), findingRef(second)},
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

	cat2 := strings.ToLower(f2.NormalizedCategory)
	if strings.Contains(cat2, "runtime") || strings.Contains(cat2, "fingerprint") || strings.HasPrefix(cat2, "missing-") || strings.Contains(cat2, "header") {
		return Relationship{}, false
	}

	isVulnerableAPI := strings.Contains(cat2, "bola") ||
		strings.Contains(cat2, "idor") ||
		strings.Contains(cat2, "xss") ||
		strings.Contains(cat2, "auth") ||
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
		ID:                 relationshipID(RuleCOR10, f1.ID, f2.ID),
		SourceFindingID:    f1.ID,
		TargetFindingID:    f2.ID,
		SourceTitle:        f1.Title,
		TargetTitle:        f2.Title,
		Type:               RelAmplifiesImpact,
		ValidationStatus:   status,
		Confidence:         conf,
		RuleCode:           RuleCOR10,
		EvidenceReferences: []string{findingRef(f1), findingRef(f2)},
		Explanation: fmt.Sprintf("Client/cross-origin condition '%s' amplifies the real-world exploitability and threat impact of '%s'.",
			f1.Title, f2.Title),
	}, true
}

// computeFindingKey produces a clean, readable finding key for relationship identifiers.
// For identifiers longer than 48 characters, it preserves the leading prefix and appends
// a compact SHA-256 digest for brevity.
//
// NOTE: Truncated hashes provide compact readability, NOT a mathematical uniqueness guarantee.
// Strict uniqueness across all relationship identifiers is guaranteed post-generation via
// deterministic collision resolution in EvaluateRules.
func computeFindingKey(id string) string {
	clean := strings.TrimSpace(id)
	if clean == "" {
		return "anon"
	}
	clean = strings.Map(func(r rune) rune {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_' {
			return r
		}
		return '_'
	}, clean)

	if len(clean) <= 48 {
		return clean
	}
	h := sha256.Sum256([]byte(id))
	return fmt.Sprintf("%s_%x", clean[:36], h[:6])
}

func relationshipID(ruleCode RuleCode, srcID, tgtID string) string {
	return fmt.Sprintf("REL-%s-%s-%s", ruleCode, computeFindingKey(srcID), computeFindingKey(tgtID))
}

func findingRef(f *NormalizedFinding) string {
	if f == nil {
		return ""
	}
	if f.DisplayEndpoint != "" {
		return f.DisplayEndpoint
	}
	if f.Endpoint != "" {
		return secrets.SanitizeURL(f.Endpoint)
	}
	return secrets.SanitizeURL(f.Target)
}
