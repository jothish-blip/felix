package correlation

import (
	"fmt"
	"strings"

	"felix/pkg/secrets"
)

// isPassiveCookieHygieneFinding distinguishes passive missing-attribute header warnings
// (e.g. Missing HttpOnly/Secure/SameSite) from active session exploitation defects.
func isPassiveCookieHygieneFinding(f *NormalizedFinding) bool {
	if f == nil {
		return false
	}
	cat := strings.ToLower(f.NormalizedCategory + " " + f.Category)
	title := strings.ToLower(f.Title)

	// Explicit active session compromise / fixation / invalidation findings are NOT passive hygiene
	if strings.Contains(cat, "fixation") ||
		strings.Contains(cat, "invalidation") ||
		strings.Contains(cat, "hijack") ||
		strings.Contains(cat, "compromise") ||
		strings.Contains(title, "fixation") ||
		strings.Contains(title, "invalidation") ||
		strings.Contains(title, "session hijack") ||
		strings.Contains(title, "token leak") {
		return false
	}

	if strings.Contains(title, "samesite") ||
		strings.Contains(title, "httponly") ||
		strings.Contains(title, "secure flag") ||
		strings.Contains(title, "missing cookie") ||
		strings.Contains(cat, "cookie-attribute") ||
		strings.Contains(cat, "missing-headers") ||
		strings.Contains(cat, "security-headers") {
		return true
	}
	return false
}

// isCredentialFinding checks whether a normalized finding exposes an authentication secret or token.
func isCredentialFinding(f *NormalizedFinding) bool {
	if f == nil {
		return false
	}
	cat := strings.ToLower(f.NormalizedCategory + " " + f.Category + " " + f.Title)
	// Exclude CORS header misconfiguration titles like "CORS Origin Reflection With Credentials"
	if strings.Contains(cat, "cors") {
		return false
	}
	if f.EvidenceDetails["credential"] == "true" ||
		f.EvidenceDetails["token_type"] != "" ||
		f.EvidenceDetails["secret_type"] != "" {
		return true
	}
	return strings.Contains(cat, "secret") ||
		strings.Contains(cat, "credential") ||
		strings.Contains(cat, "api key") ||
		strings.Contains(cat, "api_key") ||
		strings.Contains(cat, "bearer token") ||
		strings.Contains(cat, "private key") ||
		strings.Contains(cat, "aws access key")
}

// hasPlaceholderCredential checks whether the finding carries placeholder/example secret text.
func hasPlaceholderCredential(f *NormalizedFinding) (bool, string) {
	if f == nil {
		return false, ""
	}
	if strings.EqualFold(f.EvidenceDetails["is_placeholder"], "true") ||
		strings.EqualFold(f.EvidenceDetails["credential_status"], string(CredInvalid)) {
		reason := f.EvidenceDetails["placeholder_reason"]
		if reason == "" {
			reason = "Annotated as placeholder or invalid synthetic credential"
		}
		return true, reason
	}
	for _, sample := range []string{
		f.EvidenceSummary,
		f.Title,
		f.EvidenceDetails["token_preview"],
		f.EvidenceDetails["matched_pattern"],
		f.EvidenceDetails["raw_token"],
		f.EvidenceDetails["secret_value"],
		f.EvidenceDetails["evidence"],
	} {
		if ok, reason := secrets.ContainsPlaceholderCredential(sample); ok {
			return true, reason
		}
	}
	return false, ""
}

// extractFindingIdentityContext determines the explicit identity & auth context associated with f.
func extractFindingIdentityContext(f *NormalizedFinding) (identityCtx string, authCtx string) {
	if f == nil {
		return "UNKNOWN", "UNKNOWN"
	}
	if id := strings.TrimSpace(f.EvidenceDetails["identity"]); id != "" {
		identityCtx = strings.ToUpper(id)
	} else if id := strings.TrimSpace(f.EvidenceDetails["identity_context"]); id != "" {
		identityCtx = strings.ToUpper(id)
	} else if id := strings.TrimSpace(f.EvidenceDetails["intended_identity"]); id != "" {
		identityCtx = strings.ToUpper(id)
	} else if id := strings.TrimSpace(f.EvidenceDetails["accessor_identity"]); id != "" {
		identityCtx = strings.ToUpper(id)
	} else if id := strings.TrimSpace(f.EvidenceDetails["role"]); id != "" {
		identityCtx = strings.ToUpper(id)
	}

	authCtx = strings.TrimSpace(f.EvidenceDetails["auth_context"])
	if authCtx == "" {
		authCtx = strings.TrimSpace(f.EvidenceDetails["auth_state"])
	}
	if authCtx == "" {
		if strings.EqualFold(f.EvidenceDetails["auth_required"], "true") {
			authCtx = "AUTHENTICATED"
		} else if f.IsEntrypoint {
			authCtx = "PUBLIC_OR_ENTRYPOINT"
		} else {
			authCtx = "UNSPECIFIED"
		}
	}
	if identityCtx == "" {
		if strings.Contains(strings.ToUpper(authCtx), "UNAUTH") || strings.Contains(strings.ToUpper(authCtx), "NO_AUTH") || strings.Contains(strings.ToUpper(authCtx), "ANONYMOUS") {
			identityCtx = "UNAUTHENTICATED"
		} else {
			identityCtx = "UNSPECIFIED"
		}
	}
	return identityCtx, strings.ToUpper(authCtx)
}

// hasIdentityMismatch checks whether two sequential findings belong to incompatible explicit identities
// when there is no proven cross-identity bypass or privilege escalation connecting them.
func hasIdentityMismatch(f1, f2 *NormalizedFinding, relType RelationshipType, rule RuleCode) (bool, string) {
	if f1 == nil || f2 == nil {
		return false, ""
	}
	id1 := strings.ToUpper(strings.TrimSpace(f1.EvidenceDetails["intended_identity"]))
	if id1 == "" {
		id1 = strings.ToUpper(strings.TrimSpace(f1.EvidenceDetails["identity_context"]))
	}
	if id1 == "" {
		id1 = strings.ToUpper(strings.TrimSpace(f1.EvidenceDetails["identity"]))
	}

	req2 := strings.ToUpper(strings.TrimSpace(f2.EvidenceDetails["required_identity"]))
	if req2 == "" {
		req2 = strings.ToUpper(strings.TrimSpace(f2.EvidenceDetails["owner_identity"]))
	}
	if req2 == "" && strings.Contains(strings.ToLower(f2.Path+" "+f2.Title), "/admin") {
		req2 = "ADMIN"
	}

	if id1 != "" && req2 != "" && id1 != "UNSPECIFIED" && req2 != "UNSPECIFIED" && id1 != req2 {
		// If f2 is explicitly marked as cross-tenant BOLA or verified BFLA bypass, an attacker identity may bypass the boundary,
		// EXCEPT if f1 is a credential relationship claimed specifically for a different identity (e.g. User A token used to claim Admin).
		isBolaOrPrivEsc := strings.Contains(strings.ToLower(f2.NormalizedCategory+" "+f2.Category), "bola") ||
			strings.Contains(strings.ToLower(f2.NormalizedCategory+" "+f2.Category), "bfla") ||
			relType == RelBACCrossTenant || relType == RelPrivEscRestricted || rule == RuleCOR05
		if isCredentialFinding(f1) && !isBolaOrPrivEsc {
			return true, fmt.Sprintf("Credential identity (%s) does not match destination required identity (%s)", id1, req2)
		}
		if strings.EqualFold(f1.EvidenceDetails["strict_identity_binding"], "true") {
			return true, fmt.Sprintf("Strict identity mismatch: source identity %s cannot directly assume %s", id1, req2)
		}
	}
	return false, ""
}

// postProcessAndHardenRelationship validates and enriches any candidate relationship with explicit
// Phase 5 attributes (evidence refs, identity context, preconditions, required privileges, reachability,
// explanation) and prevents spurious auto-confirmation or placeholder credential escalation.
func postProcessAndHardenRelationship(rel Relationship, f1, f2 *NormalizedFinding, cfg Config) (Relationship, bool) {
	if f1 == nil || f2 == nil {
		return rel, false
	}

	// 1. Reject placeholder or explicitly invalid credentials from creating verified exploit paths
	if isCredentialFinding(f1) || isCredentialFinding(f2) {
		if isPh, reason := hasPlaceholderCredential(f1); isPh {
			rel.ValidationStatus = ValidationInvalid
			rel.ReachabilityStatus = ReachabilityNotReachable
			rel.ValidationResult = "INVALID_PLACEHOLDER_CREDENTIAL"
			rel.InconclusiveReason = reason
			rel.Explanation = fmt.Sprintf("Rejected credential transition: %s contains placeholder/example artifact (%s)", f1.ID, reason)
			rel.CredentialValidation = &CredentialVerificationResult{
				ID:                relationshipID(rel.RuleCode, f1.ID, f2.ID) + "-CRED",
				Status:            CredInvalid,
				SourceFindingID:   f1.ID,
				SourceEvidenceRef: f1.Endpoint,
				IsPlaceholder:     true,
				PlaceholderReason: reason,
				EvidenceSummary:   reason,
			}
			// Keep sequence graph free of bogus placeholder pivots, but allow auditability via Relationships if non-sequence or drop from path building
			if rel.Type.IsSequenceType() {
				return rel, true
			}
		}
		if isPh, reason := hasPlaceholderCredential(f2); isPh && rel.Type.IsSequenceType() {
			rel.ValidationStatus = ValidationInvalid
			rel.ReachabilityStatus = ReachabilityNotReachable
			rel.ValidationResult = "INVALID_PLACEHOLDER_CREDENTIAL"
			rel.Explanation = fmt.Sprintf("Rejected destination %s: contains placeholder credential (%s)", f2.ID, reason)
			return rel, true
		}
	}

	// 2. Reject passive cookie attribute warnings from forging host-wide COR-07 session paths
	if rel.RuleCode == RuleCOR07 && (isPassiveCookieHygieneFinding(f1) || isPassiveCookieHygieneFinding(f2)) {
		return rel, false
	}

	// 3. Tighten COR-10 CORS impact amplification: require verified credentialed origin misconfiguration
	if rel.RuleCode == RuleCOR10 && rel.Type.IsSequenceType() {
		t1 := strings.ToLower(f1.NormalizedCategory + " " + f1.Category + " " + f1.Title)
		if strings.Contains(t1, "cors") {
			hasCredCORS := strings.Contains(t1, "credential") ||
				strings.Contains(t1, "arbitrary") ||
				strings.EqualFold(f1.EvidenceDetails["allow_credentials"], "true")
			if !hasCredCORS {
				return rel, false
			}
		}
	}

	// 4. Reject identity mismatches
	if mismatch, msg := hasIdentityMismatch(f1, f2, rel.Type, rel.RuleCode); mismatch {
		rel.ValidationStatus = ValidationInvalid
		rel.ReachabilityStatus = ReachabilityNotReachable
		rel.ValidationResult = "IDENTITY_MISMATCH"
		rel.InconclusiveReason = msg
		rel.Explanation = msg
		return rel, true
	}

	// 5. Populate & sanitize evidence references
	var evRefs []string
	seenRef := make(map[string]bool)
	addRef := func(s string) {
		clean := secrets.RedactText(strings.TrimSpace(s))
		if clean != "" && !seenRef[clean] {
			seenRef[clean] = true
			evRefs = append(evRefs, clean)
		}
	}
	for _, r := range rel.EvidenceReferences {
		addRef(r)
	}
	if f1.Endpoint != "" {
		addRef(fmt.Sprintf("%s@%s", f1.ID, secrets.SanitizeURL(f1.Endpoint)))
	}
	if f1.EvidenceSummary != "" {
		addRef(f1.ID + ": " + f1.EvidenceSummary)
	}
	if f2.Endpoint != "" {
		addRef(fmt.Sprintf("%s@%s", f2.ID, secrets.SanitizeURL(f2.Endpoint)))
	}
	if f2.EvidenceSummary != "" {
		addRef(f2.ID + ": " + f2.EvidenceSummary)
	}
	rel.EvidenceReferences = evRefs

	// 6. Enforce Identity Context, Auth Context, Preconditions, and Required Privileges
	id1, auth1 := extractFindingIdentityContext(f1)
	id2, auth2 := extractFindingIdentityContext(f2)
	if id1 != "" && id1 != "UNSPECIFIED" {
		rel.IdentityContext = id1
	} else if id2 != "" && id2 != "UNSPECIFIED" {
		rel.IdentityContext = id2
	} else {
		rel.IdentityContext = "UNSPECIFIED"
	}
	if auth2 != "" && auth2 != "UNSPECIFIED" {
		rel.AuthContext = auth2
	} else {
		rel.AuthContext = auth1
	}

	if rel.RequiredPrivileges == "" {
		if strings.Contains(strings.ToLower(f2.Path+" "+f2.Title), "admin") || id2 == "ADMIN" {
			rel.RequiredPrivileges = "ADMIN_OR_PRIVILEGED_ROLE"
		} else if auth2 == "AUTHENTICATED" || strings.EqualFold(f2.EvidenceDetails["auth_required"], "true") {
			rel.RequiredPrivileges = "AUTHENTICATED_IDENTITY"
		} else {
			rel.RequiredPrivileges = "NONE_OR_LOW_PRIVILEGE"
		}
	}

	if len(rel.Prerequisites) == 0 {
		rel.Prerequisites = buildDefaultPrerequisites(rel.RuleCode, f1, f2, rel.IdentityContext, rel.RequiredPrivileges)
	}

	// 7. Reject confirmation if supporting evidence is missing
	hasDirectEvidence := (f1.EvidenceSummary != "" || len(f1.EvidenceDetails) > 0) &&
		(f2.EvidenceSummary != "" || len(f2.EvidenceDetails) > 0) &&
		len(rel.EvidenceReferences) > 0
	if !hasDirectEvidence && rel.ValidationStatus == ValidationConfirmed {
		rel.ValidationStatus = ValidationCandidate
		rel.ValidationResult = "MISSING_SUPPORTING_EVIDENCE"
		rel.InconclusiveReason = "Insufficient direct evidence references to confirm transition"
	}

	// 8. In RequireValidatedTransitions mode (Phase 5 strict validation / felix assess),
	// static correlation must NOT promote cross-finding transitions to CONFIRMED before active validation.
	if cfg.RequireValidatedTransitions && rel.Type.IsSequenceType() {
		if rel.ValidationStatus == ValidationConfirmed || rel.ValidationStatus == ValidationPlausible {
			rel.ValidationStatus = ValidationCandidate
		}
		if rel.ReachabilityStatus == "" {
			rel.ReachabilityStatus = ReachabilityNotTested
		}
		if rel.ValidationResult == "" {
			rel.ValidationResult = "AWAITING_REACHABILITY_VALIDATION"
		}
	} else if rel.ReachabilityStatus == "" {
		if rel.ValidationStatus == ValidationConfirmed {
			rel.ReachabilityStatus = ReachabilityReachable
			rel.ValidationResult = "STATIC_SAME_BOUNDARY_CONFIRMED"
		} else {
			rel.ReachabilityStatus = ReachabilityNotTested
			rel.ValidationResult = string(NormalizeEdgeStatus(rel.ValidationStatus))
		}
	}

	if strings.TrimSpace(rel.Explanation) == "" {
		rel.Explanation = fmt.Sprintf("Transition %s -> %s under rule %s (%s)", f1.ID, f2.ID, rel.RuleCode, rel.Type)
	} else {
		rel.Explanation = secrets.RedactText(rel.Explanation)
	}

	// Upgrade credential-exposure edges (e.g. secret -> bola/authz) to explicit extensible type RelCredEnablesAccess
	if isCredentialFinding(f1) && rel.RuleCode == RuleCOR02 {
		rel.RuleCode = RuleCORCredPivot
		rel.Type = RelCredEnablesAccess
	}

	return rel, true
}

func buildDefaultPrerequisites(rule RuleCode, f1, f2 *NormalizedFinding, idCtx, reqPriv string) []string {
	var prereqs []string
	prereqs = append(prereqs, fmt.Sprintf("Source condition '%s' verified or observed on %s", f1.Title, secrets.SanitizeURL(f1.Endpoint)))
	if reqPriv != "" && reqPriv != "NONE_OR_LOW_PRIVILEGE" {
		prereqs = append(prereqs, fmt.Sprintf("Required identity/privilege: %s (%s)", idCtx, reqPriv))
	}
	if f2.Endpoint != "" {
		prereqs = append(prereqs, fmt.Sprintf("Target resource reachable: %s", secrets.SanitizeURL(f2.Endpoint)))
	}
	return prereqs
}

// evaluateCredentialPivot checks whether a secret/credential exposure enables authenticated
// access or downstream authorization testing on the same target boundary.
func evaluateCredentialPivot(f1, f2 *NormalizedFinding) (Relationship, bool) {
	if f1 == nil || f2 == nil || f1.ID == f2.ID {
		return Relationship{}, false
	}
	if !isCredentialFinding(f1) {
		return Relationship{}, false
	}
	// Do not pivot back onto an upstream vulnerability or auth-bypass weakness on the same/parent route
	cat2 := strings.ToLower(f2.NormalizedCategory + " " + f2.Category + " " + f2.Title)
	if strings.Contains(cat2, "jwt") || strings.Contains(cat2, "auth-bypass") || strings.Contains(cat2, "fixation") {
		return Relationship{}, false
	}
	if f1.Path != "" && f2.Path != "" && (strings.EqualFold(f1.Path, f2.Path) || strings.HasPrefix(strings.ToLower(f1.Path), strings.ToLower(f2.Path))) &&
		(strings.Contains(cat2, "bola") || strings.Contains(cat2, "idor") || strings.Contains(cat2, "sqli") || strings.Contains(cat2, "ssrf")) {
		return Relationship{}, false
	}
	// Do not pivot to another informational passive finding or header missing check
	if isPassiveCookieHygieneFinding(f2) || strings.EqualFold(f2.NormalizedCategory, "discovery") {
		return Relationship{}, false
	}
	if hasConflict, _, _ := hasBoundaryConflict(f1.EvidenceDetails, f2.EvidenceDetails); hasConflict {
		return Relationship{}, false
	}

	// Target must require authentication or be an authorization / privileged / sensitive endpoint on compatible host
	needsAuthOrAuthz := strings.EqualFold(f2.EvidenceDetails["auth_required"], "true") ||
		strings.Contains(cat2, "bola") ||
		strings.Contains(cat2, "bfla") ||
		strings.Contains(cat2, "bopla") ||
		strings.Contains(cat2, "idor") ||
		strings.Contains(cat2, "admin") ||
		strings.Contains(cat2, "sensitive") ||
		f2.IsAuthRequirement || f2.IsRoleRestricted
	if !needsAuthOrAuthz {
		return Relationship{}, false
	}

	sameHost := f1.Host != "" && f2.Host != "" && strings.EqualFold(f1.Host, f2.Host)
	sameOrigin := f1.Origin != "" && f2.Origin != "" && strings.EqualFold(f1.Origin, f2.Origin)
	explicitTargetMatch := f1.EvidenceDetails["target_host"] != "" && strings.EqualFold(f1.EvidenceDetails["target_host"], f2.Host)
	if !sameHost && !sameOrigin && !explicitTargetMatch {
		return Relationship{}, false
	}

	return Relationship{
		ID:              relationshipID(RuleCORCredPivot, f1.ID, f2.ID),
		SourceFindingID: f1.ID,
		TargetFindingID: f2.ID,
		SourceTitle:     f1.Title,
		TargetTitle:     f2.Title,
		Type:            RelCredEnablesAccess,
		ValidationStatus: ValidationCandidate,
		Confidence:      string(ValidationCandidate),
		RuleCode:        RuleCORCredPivot,
		AssetID:         f2.PrimaryAssetID,
		AssetKey:        f2.CanonicalAssetKey,
		IsExact:         sameOrigin,
		EvidenceReferences: []string{
			fmt.Sprintf("Credential source %s (%s)", f1.ID, secrets.SanitizeURL(f1.Endpoint)),
			fmt.Sprintf("Target access boundary %s (%s)", f2.ID, secrets.SanitizeURL(f2.Endpoint)),
		},
		Explanation: fmt.Sprintf("Exposed credential %s may authorize access to %s; requires credential usability and identity confirmation", f1.ID, f2.ID),
	}, true
}
