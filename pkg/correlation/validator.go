package correlation

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"felix/pkg/auth"
	"felix/pkg/crawler"
	"felix/pkg/report"
	"felix/pkg/secrets"
)

// ValidationOptions configures active credential relationship and multi-step transition verification.
type ValidationOptions struct {
	TargetURL              string
	BaseClient             *http.Client
	IdentityClients        map[auth.IdentityContext]*http.Client
	IdentityManager        *auth.IdentityManager
	ScopeAllowed           func(string) bool
	AllowLoopback          bool
	AllowPrivate           bool
	AllowStateChanging     bool
	SyntheticFixture       bool
	AuthorizedFixtureHosts []string
	SafeMode               bool
	MaxProbeRequests       int
	Timeout                time.Duration
	KnownIdentities        map[auth.IdentityContext]string
	// RawCredentialTokens maps FindingID -> transient cleartext token strictly for authorized
	// HTTP usability checks. Values are NEVER stored on output structs, logs, or reports.
	RawCredentialTokens map[string]string
}

// Phase5Validator executes evidence-backed credential verification and multi-step reachability validation.
type Phase5Validator struct {
	opts           ValidationOptions
	probesSent     int
	allowedBaseURL *url.URL
}

// NewPhase5Validator constructs a Phase 5 attack path validator.
func NewPhase5Validator(opts ValidationOptions) *Phase5Validator {
	if opts.Timeout <= 0 {
		opts.Timeout = 10 * time.Second
	}
	if opts.MaxProbeRequests <= 0 {
		opts.MaxProbeRequests = 60
	}
	var parsedBase *url.URL
	if strings.TrimSpace(opts.TargetURL) != "" {
		parsedBase, _ = url.Parse(opts.TargetURL)
	}
	return &Phase5Validator{
		opts:           opts,
		allowedBaseURL: parsedBase,
	}
}

// ValidateAttackPaths validates candidate relationships, credential usability/identity bindings,
// and step-by-step transition reachability over correlated paths.
func (v *Phase5Validator) ValidateAttackPaths(
	ctx context.Context,
	findings []report.Finding,
	paths []AttackPath,
	rels []Relationship,
	summary *Summary,
) ([]AttackPath, []Relationship, *Summary) {
	if summary == nil {
		summary = &Summary{}
	}

	normList := NormalizeFindings(findings)
	normByID := make(map[string]NormalizedFinding, len(normList))
	rawByID := make(map[string]report.Finding, len(findings))
	for _, nf := range normList {
		normByID[nf.ID] = nf
	}
	for _, rf := range findings {
		rawByID[rf.ID] = rf
	}
	// Preserve nodes carried directly on caller-constructed AttackPath structs when findings is empty or partial.
	for _, p := range paths {
		for _, node := range p.Nodes {
			if node.ID == "" {
				continue
			}
			if _, exists := normByID[node.ID]; !exists {
				normByID[node.ID] = node
				normList = append(normList, node)
			}
		}
	}

	// 1. Validate credential findings & relationships once per credential finding ID (avoid duplicate HTTP calls)
	credCache := make(map[string]CredentialVerificationResult)
	for i := range normList {
		nf := normList[i]
		if !isCredentialFinding(&nf) {
			continue
		}
		targetHint := nf.EvidenceDetails["auth_check_url"]
		if targetHint == "" {
			for _, rel := range rels {
				if rel.SourceFindingID == nf.ID && rel.Type.IsSequenceType() {
					if dst, ok := normByID[rel.TargetFindingID]; ok && (dst.RawURL != "" || dst.Endpoint != "") {
						targetHint = firstNonEmpty(dst.RawURL, dst.Endpoint)
						break
					}
				}
			}
		}
		res := v.verifyCredentialFinding(ctx, nf, targetHint)
		credCache[nf.ID] = res
	}

	// Update relationships with credential results
	updatedRels := make([]Relationship, 0, len(rels))
	for _, r := range rels {
		if cr, ok := credCache[r.SourceFindingID]; ok {
			crCopy := cr
			r.CredentialValidation = &crCopy
			if cr.Status == CredInvalid {
				r.ValidationStatus = ValidationInvalid
				r.ReachabilityStatus = ReachabilityNotReachable
				r.ValidationResult = "CREDENTIAL_INVALID"
				r.Explanation = secrets.RedactText(cr.EvidenceSummary)
			} else if cr.Status == CredInconclusive {
				r.ValidationStatus = ValidationInconclusive
				r.ReachabilityStatus = ReachabilityInconclusive
				r.ValidationResult = "CREDENTIAL_INCONCLUSIVE"
			}
		}
		updatedRels = append(updatedRels, r)
	}

	// 2. Validate each attack path step-by-step
	validatedPaths := make([]AttackPath, 0, len(paths))
	relByEdgeID := make(map[string]Relationship, len(updatedRels))
	for _, r := range updatedRels {
		relByEdgeID[r.SourceFindingID+"->"+r.TargetFindingID] = r
	}

	for _, p := range paths {
		// Enforce graph integrity on the path itself (reject self-loops, duplicates, missing edges, cycles)
		if !v.validatePathDAG(&p) {
			continue
		}

		// Check if any edge involves an invalid/placeholder credential
		hasInvalidEdge := false
		for idx := range p.Edges {
			key := p.Edges[idx].SourceFindingID + "->" + p.Edges[idx].TargetFindingID
			if ur, ok := relByEdgeID[key]; ok {
				if ur.CredentialValidation != nil {
					p.Edges[idx].CredentialValidation = ur.CredentialValidation
				}
				if ur.ValidationStatus == ValidationInvalid {
					p.Edges[idx].ValidationStatus = ValidationInvalid
					p.Edges[idx].ReachabilityStatus = ReachabilityNotReachable
					p.Edges[idx].ValidationResult = ur.ValidationResult
					p.Edges[idx].Explanation = ur.Explanation
					hasInvalidEdge = true
				}
			}
		}

		if hasInvalidEdge {
			// Placeholder or identity-mismatched credentials must NOT form a verified attack path;
			// drop invalid credential chains cleanly from attack paths while retaining failure in relationships.
			continue
		}

		vp := v.validateSinglePath(ctx, p, normByID, rawByID, credCache)
		validatedPaths = append(validatedPaths, vp)
	}

	// Sync updated edges back into relationships slice
	for _, vp := range validatedPaths {
		for _, edge := range vp.Edges {
			relByEdgeID[edge.SourceFindingID+"->"+edge.TargetFindingID] = edge
		}
	}
	for i := range updatedRels {
		k := updatedRels[i].SourceFindingID + "->" + updatedRels[i].TargetFindingID
		if ve, ok := relByEdgeID[k]; ok {
			updatedRels[i] = ve
		}
	}

	// 3. Recompute summary metrics cleanly
	var credList []CredentialVerificationResult
	for _, cr := range credCache {
		credList = append(credList, cr)
	}
	newSummary := v.recomputeSummary(findings, validatedPaths, updatedRels, credList, summary)
	return validatedPaths, updatedRels, newSummary
}

func (v *Phase5Validator) verifyCredentialFinding(ctx context.Context, nf NormalizedFinding, targetHint string) CredentialVerificationResult {
	res := CredentialVerificationResult{
		ID:                "CRED-" + nf.ID,
		SourceFindingID:   nf.ID,
		SourceEvidenceRef: firstNonEmpty(secrets.SanitizeURL(nf.Endpoint), nf.ID),
		TokenKind:         firstNonEmpty(nf.EvidenceDetails["token_type"], nf.EvidenceDetails["secret_type"], "credential"),
		IntendedIdentity:  strings.ToUpper(strings.TrimSpace(firstNonEmpty(nf.EvidenceDetails["intended_identity"], nf.EvidenceDetails["identity_context"], nf.EvidenceDetails["identity"]))),
		TargetScope:       firstNonEmpty(nf.Origin, nf.Host, v.opts.TargetURL),
	}

	// 1. Placeholder / Example / Documentation Token Gate
	if isPh, reason := hasPlaceholderCredential(&nf); isPh {
		res.Status = CredInvalid
		res.IsPlaceholder = true
		res.PlaceholderReason = reason
		res.EvidenceSummary = fmt.Sprintf("Placeholder/example credential rejected (%s)", reason)
		res.Limitation = "Credential-shaped placeholder strings are never treated as live compromised credentials"
		return res
	}

	// Locate transient cleartext token ONLY from in-memory map or explicit fixture field
	rawToken := strings.TrimSpace(v.opts.RawCredentialTokens[nf.ID])
	if rawToken == "" {
		rawToken = strings.TrimSpace(nf.EvidenceDetails["candidate_token"])
	}
	if rawToken != "" {
		res.TokenFingerprint = secrets.CredentialFingerprint(rawToken)
		if isPh, reason := secrets.IsKnownPlaceholderCredential(rawToken); isPh {
			res.Status = CredInvalid
			res.IsPlaceholder = true
			res.PlaceholderReason = reason
			res.EvidenceSummary = fmt.Sprintf("Placeholder/example token rejected (%s)", reason)
			return res
		}
	}

	// Determine check endpoint within target scope
	checkURL := v.resolveTargetURL(firstNonEmpty(nf.EvidenceDetails["auth_check_url"], targetHint))
	if checkURL == "" || !v.isURLAllowed(checkURL) {
		if rawToken == "" {
			res.Status = CredNotTested
			res.EvidenceSummary = "Credential usability verification not performed (no authorized introspection endpoint or live token provided)"
		} else {
			res.Status = CredCandidate
			res.EvidenceSummary = "Credential artifact present, target scope or check URL missing for usability verification"
		}
		res.Limitation = "Requires authorized same-origin identity check URL within scope"
		return res
	}
	res.ScopeValid = true

	if v.opts.SafeMode && rawToken == "" {
		res.Status = CredNotTested
		res.EvidenceSummary = "Safe mode enabled without active credential verification token"
		return res
	}

	if rawToken == "" {
		res.Status = CredCandidate
		res.EvidenceSummary = "Exposed credential finding lacks raw verification token in runtime session; cannot confirm active usability"
		res.Limitation = "Usability verification skipped to avoid unredacted secret persistence"
		return res
	}

	if v.probesSent >= v.opts.MaxProbeRequests {
		res.Status = CredNotTested
		res.EvidenceSummary = "Verification request budget reached before credential check"
		return res
	}

	// 2. Execute isolated, read-only GET check with strict cross-origin credential stripping
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, checkURL, nil)
	if err != nil {
		res.Status = CredInconclusive
		res.EvidenceSummary = fmt.Sprintf("Invalid credential verification URL: %v", err)
		return res
	}
	injectTokenHeader(req, rawToken, res.TokenKind)

	client := v.isolatedProbeClient()
	v.probesSent++
	resp, err := client.Do(req)
	if err != nil {
		res.Status = CredInconclusive
		res.UsabilityChecked = true
		res.EvidenceSummary = fmt.Sprintf("Credential check request error: %v", err)
		return res
	}
	defer resp.Body.Close()

	bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 256*1024))
	bodyStr := string(bodyBytes)
	res.HTTPStatus = resp.StatusCode
	res.UsabilityChecked = true

	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		res.Status = CredInvalid
		res.EvidenceSummary = fmt.Sprintf("Target rejected credential with HTTP %d on %s", resp.StatusCode, secrets.SanitizeURL(checkURL))
		return res
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		res.Status = CredInconclusive
		res.EvidenceSummary = fmt.Sprintf("Credential check returned non-2xx HTTP %d", resp.StatusCode)
		return res
	}

	// Reject Soft-200 login pages or generic error responses
	if isSoft200NonImpactResponse(bodyStr, resp.Header.Get("Content-Type")) {
		res.Status = CredInvalid
		res.EvidenceSummary = fmt.Sprintf("HTTP %d returned login form, empty wrapper, or error response rather than authenticated identity data", resp.StatusCode)
		return res
	}

	observedID := extractObservedIdentity(bodyStr)
	res.ObservedIdentity = observedID
	if observedID == "" {
		res.Status = CredInconclusive
		res.EvidenceSummary = fmt.Sprintf("HTTP %d lacked observable user/role identity claim to verify credential attribution", resp.StatusCode)
		res.Limitation = "HTTP 200 status without observable identity claim cannot verify credential relationship"
		return res
	}

	if res.IntendedIdentity != "" && res.IntendedIdentity != "UNSPECIFIED" {
		if !identitiesCompatible(res.IntendedIdentity, observedID) {
			res.Status = CredInvalid
			res.IdentityMatched = false
			res.EvidenceSummary = fmt.Sprintf("Identity mismatch: credential resolves to %s, not claimed identity %s", observedID, res.IntendedIdentity)
			return res
		}
	}

	res.Status = CredVerified
	res.IdentityMatched = true
	res.EvidenceSummary = fmt.Sprintf("Credential (%s) verified usable on %s with observed identity %s (HTTP %d)",
		firstNonEmpty(res.TokenFingerprint, "fingerprint_unavailable"), secrets.SanitizeURL(checkURL), observedID, resp.StatusCode)
	return res
}

func (v *Phase5Validator) validateSinglePath(
	ctx context.Context,
	p AttackPath,
	normByID map[string]NormalizedFinding,
	rawByID map[string]report.Finding,
	credCache map[string]CredentialVerificationResult,
) AttackPath {
	var steps []StepVerification
	var credResults []CredentialVerificationResult
	seenCredID := make(map[string]bool)
	var evidenceRefs []string
	seenRef := make(map[string]bool)
	addRef := func(r string) {
		clean := secrets.RedactText(strings.TrimSpace(r))
		if clean != "" && !seenRef[clean] {
			seenRef[clean] = true
			evidenceRefs = append(evidenceRefs, clean)
		}
	}

	var preconditions []string
	seenPre := make(map[string]bool)
	addPre := func(s string) {
		clean := secrets.RedactText(strings.TrimSpace(s))
		if clean != "" && !seenPre[clean] {
			seenPre[clean] = true
			preconditions = append(preconditions, clean)
		}
	}

	var limitations []string
	seenLim := make(map[string]bool)
	addLim := func(s string) {
		clean := secrets.RedactText(strings.TrimSpace(s))
		if clean != "" && !seenLim[clean] {
			seenLim[clean] = true
			limitations = append(limitations, clean)
		}
	}

	var demonstratedParts []string
	var unverifiedParts []string

	// Record Step 0 (Entry condition / initial finding)
	if len(p.Nodes) > 0 {
		n0 := p.Nodes[0]
		id0, _ := extractFindingIdentityContext(&n0)
		s0 := StepVerification{
			StepIndex:           0,
			FindingID:           n0.ID,
			EntryCondition:      fmt.Sprintf("Initial finding %s (%s) on %s", n0.ID, n0.Title, secrets.SanitizeURL(n0.Endpoint)),
			RequiredIdentity:    id0,
			RequiredPermissions: "INITIAL_SURFACE_ACCESS",
			TargetResource:      secrets.SanitizeURL(firstNonEmpty(n0.RawURL, n0.Endpoint)),
			Method:              firstNonEmpty(n0.Method, http.MethodGet),
			ExpectedResult:      fmt.Sprintf("Observable evidence of %s", n0.Title),
			EvidenceRefs:        []string{},
			NextStepReachable:   ReachabilityNotTested,
			ValidationStatus:    ValidationNotTested,
		}
		if n0.EvidenceSummary != "" {
			s0.EvidenceRefs = append(s0.EvidenceRefs, n0.ID+": "+secrets.RedactText(n0.EvidenceSummary))
			addRef(n0.ID + ": " + n0.EvidenceSummary)
		}
		if n0.IsVerified && (n0.EvidenceSummary != "" || len(n0.EvidenceDetails) > 0) {
			s0.ObservedResult = secrets.RedactText(firstNonEmpty(n0.EvidenceSummary, "Verified source finding evidence"))
			s0.ValidationStatus = ValidationConfirmed
			s0.NextStepReachable = ReachabilityReachable
			s0.ImpactVerified = true
			s0.DemonstratedImpact = fmt.Sprintf("Initial condition confirmed (%s)", n0.Title)
		} else if n0.IsCandidate {
			s0.ObservedResult = "Initial finding is an unconfirmed candidate"
			s0.ValidationStatus = ValidationCandidate
			s0.UnverifiedImpact = fmt.Sprintf("Unconfirmed initial finding %s", n0.Title)
		} else {
			s0.ObservedResult = "Insufficient direct evidence on initial node"
			s0.ValidationStatus = ValidationCandidate
		}
		if cr, ok := credCache[n0.ID]; ok {
			if !seenCredID[cr.ID] {
				seenCredID[cr.ID] = true
				credResults = append(credResults, cr)
			}
			s0.EvidenceRefs = append(s0.EvidenceRefs, cr.EvidenceSummary)
			if cr.Status == CredVerified {
				s0.ValidationStatus = ValidationConfirmed
				s0.ImpactVerified = true
				s0.ObservedResult = cr.EvidenceSummary
				s0.DemonstratedImpact = fmt.Sprintf("Usable credential for %s verified (%s)", firstNonEmpty(cr.ObservedIdentity, cr.IntendedIdentity), cr.TokenFingerprint)
			} else if cr.Status != CredVerified {
				s0.ValidationStatus = ValidationCandidate
				s0.ImpactVerified = false
				s0.UnverifiedImpact = cr.EvidenceSummary
				if cr.Limitation != "" {
					addLim(cr.Limitation)
				}
			}
		}
		steps = append(steps, s0)
	}

	chainBroken := false
	verifiedTransitions := 0
	unverifiedTransitions := 0

	// Validate each edge transition i -> i+1 sequentially
	for idx := range p.Edges {
		edge := &p.Edges[idx]
		src := normByID[edge.SourceFindingID]
		dst := normByID[edge.TargetFindingID]
		dstRaw := rawByID[edge.TargetFindingID]

		reqID := strings.ToUpper(strings.TrimSpace(firstNonEmpty(dst.EvidenceDetails["required_identity"], edge.IdentityContext, dst.EvidenceDetails["identity"], "UNSPECIFIED")))
		if cr, ok := credCache[src.ID]; ok {
			if !seenCredID[cr.ID] {
				seenCredID[cr.ID] = true
				credResults = append(credResults, cr)
			}
			edge.CredentialValidation = &cr
			if cr.ObservedIdentity != "" {
				reqID = cr.ObservedIdentity
			}
		}

		for _, pre := range edge.Prerequisites {
			addPre(pre)
		}
		for _, ref := range edge.EvidenceReferences {
			addRef(ref)
		}

		step := StepVerification{
			StepIndex:           idx + 1,
			FindingID:           dst.ID,
			EdgeID:              edge.ID,
			EntryCondition:      fmt.Sprintf("After %s (%s), attempt transition to %s (%s)", src.ID, src.Title, dst.ID, dst.Title),
			RequiredIdentity:    reqID,
			RequiredPermissions: firstNonEmpty(edge.RequiredPrivileges, "AUTHENTICATED_OR_PUBLIC_ACCESS"),
			TargetResource:      secrets.SanitizeURL(firstNonEmpty(dst.RawURL, dst.Endpoint)),
			Method:              firstNonEmpty(dst.Method, http.MethodGet),
			ExpectedResult:      firstNonEmpty(dst.EvidenceDetails["expected_behavior"], dstRaw.EvidenceDetails.ExpectedBehavior, fmt.Sprintf("Observable response proving %s impact", dst.Title)),
			EvidenceRefs:        append([]string{}, edge.EvidenceReferences...),
			NextStepReachable:   ReachabilityNotTested,
			ValidationStatus:    NormalizeEdgeStatus(edge.ValidationStatus),
		}

		if chainBroken {
			edge.ValidationStatus = ValidationNotReachable
			edge.ReachabilityStatus = ReachabilityNotReachable
			edge.ValidationResult = "BLOCKED_BY_PRIOR_STEP"
			step.ValidationStatus = ValidationNotReachable
			step.NextStepReachable = ReachabilityNotReachable
			step.ObservedResult = "Upstream transition was unreachable or failed verification; downstream step cannot be reached via this chain"
			step.UnverifiedImpact = dst.Title
			steps = append(steps, step)
			unverifiedTransitions++
			unverifiedParts = append(unverifiedParts, step.UnverifiedImpact)
			continue
		}

		// Evaluate credential precondition if source is credential
		var activeCred *CredentialVerificationResult
		if cr, ok := credCache[src.ID]; ok {
			activeCred = &cr
			if cr.Status == CredInvalid {
				edge.ValidationStatus = ValidationInvalid
				edge.ReachabilityStatus = ReachabilityNotReachable
				edge.ValidationResult = "CREDENTIAL_INVALID"
				step.ValidationStatus = ValidationInvalid
				step.NextStepReachable = ReachabilityNotReachable
				step.ObservedResult = cr.EvidenceSummary
				step.UnverifiedImpact = dst.Title
				chainBroken = true
				steps = append(steps, step)
				unverifiedTransitions++
				unverifiedParts = append(unverifiedParts, dst.Title)
				continue
			}
			if cr.Status == CredNotTested || cr.Status == CredInconclusive || cr.Status == CredCandidate {
				// Cannot confirm downstream step via unverified credential
				edge.ValidationStatus = ValidationCandidate
				if cr.Status == CredNotTested {
					edge.ValidationStatus = ValidationNotTested
				} else if cr.Status == CredInconclusive {
					edge.ValidationStatus = ValidationInconclusive
				}
				edge.ReachabilityStatus = ReachabilityNotTested
				edge.ValidationResult = "CREDENTIAL_UNVERIFIED"
				step.ValidationStatus = edge.ValidationStatus
				step.NextStepReachable = ReachabilityNotTested
				step.ObservedResult = cr.EvidenceSummary
				step.UnverifiedImpact = dst.Title
				addLim(cr.EvidenceSummary)
				steps = append(steps, step)
				unverifiedTransitions++
				unverifiedParts = append(unverifiedParts, dst.Title)
				continue
			}
		}

		// Execute bounded active transition probe against dst
		probeRes := v.probeTransitionStep(ctx, src, dst, dstRaw, edge, activeCred)
		step.ObservedResult = secrets.RedactText(probeRes.observedResult)
		step.HTTPStatus = probeRes.httpStatus
		step.ValidationStatus = probeRes.edgeStatus
		step.NextStepReachable = probeRes.reachability
		step.ImpactVerified = probeRes.impactVerified
		if probeRes.limitation != "" {
			step.Limitations = append(step.Limitations, probeRes.limitation)
			addLim(probeRes.limitation)
		}
		for _, er := range probeRes.evidenceRefs {
			step.EvidenceRefs = append(step.EvidenceRefs, secrets.RedactText(er))
			addRef(er)
		}

		edge.ValidationStatus = probeRes.edgeStatus
		edge.ReachabilityStatus = probeRes.reachability
		edge.ValidationResult = probeRes.validationResult
		edge.EvidenceReferences = step.EvidenceRefs
		if probeRes.explanation != "" {
			edge.Explanation = secrets.RedactText(probeRes.explanation)
		}

		if probeRes.edgeStatus == ValidationConfirmed {
			verifiedTransitions++
			step.DemonstratedImpact = firstNonEmpty(probeRes.demonstratedImpact, fmt.Sprintf("Step %d transition confirmed on %s", idx+1, step.TargetResource))
			demonstratedParts = append(demonstratedParts, step.DemonstratedImpact)
		} else {
			unverifiedTransitions++
			step.UnverifiedImpact = firstNonEmpty(probeRes.unverifiedImpact, fmt.Sprintf("%s (%s)", dst.Title, probeRes.edgeStatus))
			unverifiedParts = append(unverifiedParts, step.UnverifiedImpact)
			if probeRes.edgeStatus == ValidationNotReachable || probeRes.edgeStatus == ValidationInvalid {
				chainBroken = true
			}
		}
		steps = append(steps, step)
	}

	// Sync Step 0 transition reachability with first edge if applicable
	if len(steps) > 1 {
		if steps[1].ValidationStatus == ValidationNotReachable {
			steps[0].NextStepReachable = ReachabilityNotReachable
		} else if steps[1].ValidationStatus == ValidationConfirmed {
			steps[0].NextStepReachable = ReachabilityReachable
		}
	}

	// Deterministic Phase 5 classification (never statistical probabilities)
	status, confLabel, rationale := ClassifyPathConfidence(&p, steps, credResults)
	p.Status = status
	p.ValidationState = status
	p.Confidence = confLabel
	p.ConfidenceRationale = rationale
	p.VerifiedTransitions = verifiedTransitions
	p.UnverifiedTransitions = unverifiedTransitions
	p.StepVerifications = steps
	p.CredentialValidations = credResults
	p.Preconditions = preconditions
	p.EvidenceRefs = evidenceRefs
	p.Limitations = limitations

	if len(demonstratedParts) > 0 {
		p.DemonstratedImpact = strings.Join(demonstratedParts, "; ")
	} else {
		p.DemonstratedImpact = "No downstream exploit impact empirically demonstrated"
	}
	if len(unverifiedParts) > 0 {
		p.UnverifiedImpact = strings.Join(unverifiedParts, "; ")
	}

	// Aggregate overall path ReachabilityStatus
	if verifiedTransitions > 0 && unverifiedTransitions == 0 && IsConfirmedStatus(status) {
		p.ReachabilityStatus = ReachabilityReachable
	} else if status == PathNotReachable {
		p.ReachabilityStatus = ReachabilityNotReachable
	} else if status == PathNotTested {
		p.ReachabilityStatus = ReachabilityNotTested
	} else {
		p.ReachabilityStatus = ReachabilityInconclusive
	}

	// Collect unique identities referenced across edges
	var ids []string
	seenID := make(map[string]bool)
	for _, st := range steps {
		if st.RequiredIdentity != "" && st.RequiredIdentity != "UNSPECIFIED" && !seenID[st.RequiredIdentity] {
			seenID[st.RequiredIdentity] = true
			ids = append(ids, st.RequiredIdentity)
		}
	}
	if len(ids) > 0 {
		p.IdentityContext = strings.Join(ids, " -> ")
	}

	// Update compound risk score conservatively (unconfirmed paths cannot inflate primary risk)
	score, level, riskRat := AssessPathRisk(&p)
	p.CombinedRiskScore = score
	p.CombinedRiskLevel = level
	p.RiskRationale = rationale + " | " + riskRat
	p.SecurityStory = GenerateSecurityStory(&p)

	return p
}

type transitionProbeOutcome struct {
	edgeStatus         ValidationStatus
	reachability       ReachabilityStatus
	validationResult   string
	httpStatus         int
	observedResult     string
	evidenceRefs       []string
	impactVerified     bool
	demonstratedImpact string
	unverifiedImpact   string
	explanation        string
	limitation         string
}

func (v *Phase5Validator) probeTransitionStep(
	ctx context.Context,
	src, dst NormalizedFinding,
	dstRaw report.Finding,
	edge *Relationship,
	activeCred *CredentialVerificationResult,
) transitionProbeOutcome {
	targetURL := v.resolveTargetURL(firstNonEmpty(dst.RawURL, dst.Endpoint))
	method := strings.ToUpper(strings.TrimSpace(firstNonEmpty(dst.Method, dstRaw.Method, http.MethodGet)))
	if method == "" {
		method = http.MethodGet
	}

	// Check if step explicitly skips active testing / missing verification flag
	if strings.EqualFold(dst.EvidenceDetails["skip_reachability_test"], "true") ||
		strings.EqualFold(dst.EvidenceDetails["transition_tested"], "false") {
		return transitionProbeOutcome{
			edgeStatus:       ValidationNotTested,
			reachability:     ReachabilityNotTested,
			validationResult: "NOT_TESTED",
			observedResult:   "Transition validation skipped by explicit step boundary policy",
			unverifiedImpact: dst.Title,
			limitation:       "Downstream step transition not tested",
		}
	}

	if targetURL == "" || !v.isURLAllowed(targetURL) {
		return transitionProbeOutcome{
			edgeStatus:       ValidationNotTested,
			reachability:     ReachabilityNotTested,
			validationResult: "OUT_OF_SCOPE_OR_MISSING_URL",
			observedResult:   "Destination URL absent or outside permitted scope; transition not tested",
			unverifiedImpact: dst.Title,
			limitation:       "Requires valid in-scope target URL for step reachability check",
		}
	}

	// Enforce safety gate against destructive operations
	isMutating := method != http.MethodGet && method != http.MethodHead && method != http.MethodOptions
	if isDestr, reason := crawler.IsDestructiveURL(targetURL, nil); isDestr || isMutating {
		if !v.opts.AllowStateChanging || !v.opts.SyntheticFixture || !v.isAuthorizedFixtureTarget(targetURL) {
			return transitionProbeOutcome{
				edgeStatus:       ValidationNotTested,
				reachability:     ReachabilityNotTested,
				validationResult: "SKIPPED_NON_DESTRUCTIVE_POLICY",
				observedResult:   fmt.Sprintf("State-changing/destructive transition (%s %s) skipped under safety policy (%s)", method, secrets.SanitizeURL(targetURL), reason),
				unverifiedImpact: dst.Title,
				limitation:       "Mutating transition requires --allow-state-changing --synthetic-fixture on authorized local fixture",
			}
		}
	}

	if v.opts.SafeMode && v.probesSent == 0 && activeCred == nil && len(v.opts.IdentityClients) == 0 && v.opts.BaseClient == nil {
		return transitionProbeOutcome{
			edgeStatus:       ValidationNotTested,
			reachability:     ReachabilityNotTested,
			validationResult: "SAFE_MODE_PASSIVE_ONLY",
			observedResult:   "Safe mode active without configured identity transport; transition not probed",
			unverifiedImpact: dst.Title,
			limitation:       "Transition reachability requires active non-destructive verification",
		}
	}

	if v.probesSent >= v.opts.MaxProbeRequests {
		return transitionProbeOutcome{
			edgeStatus:       ValidationNotTested,
			reachability:     ReachabilityNotTested,
			validationResult: "REQUEST_BUDGET_EXHAUSTED",
			observedResult:   "Phase 5 probe request budget reached before checking step",
			unverifiedImpact: dst.Title,
			limitation:       "Reached max probe requests budget",
		}
	}

	// Select scoped HTTP client and identity cleanly without leakage
	client, activeIdentity := v.clientForTransition(src, dst, edge, activeCred)
	if client == nil {
		return transitionProbeOutcome{
			edgeStatus:       ValidationNotTested,
			reachability:     ReachabilityNotTested,
			validationResult: "NO_HTTP_CLIENT_AVAILABLE",
			observedResult:   "No scoped HTTP client configured for transition validation",
			unverifiedImpact: dst.Title,
			limitation:       "Requires configured HTTP client or IdentityManager",
		}
	}

	reqCtx := ctx
	if activeCred == nil && activeIdentity != "" {
		reqCtx = auth.WithIdentity(ctx, activeIdentity)
	}
	req, err := http.NewRequestWithContext(reqCtx, method, targetURL, nil)
	if err != nil {
		return transitionProbeOutcome{
			edgeStatus:       ValidationInconclusive,
			reachability:     ReachabilityInconclusive,
			validationResult: "INVALID_REQUEST",
			observedResult:   fmt.Sprintf("Failed to build transition request: %v", err),
			unverifiedImpact: dst.Title,
		}
	}

	// If validated discovered credential applies cleanly for this hop, bind via header on isolated client
	if activeCred != nil && activeCred.Status == CredVerified {
		if rawTok := strings.TrimSpace(v.opts.RawCredentialTokens[src.ID]); rawTok != "" {
			injectTokenHeader(req, rawTok, activeCred.TokenKind)
		}
	}

	v.probesSent++
	resp, err := client.Do(req)
	if err != nil {
		return transitionProbeOutcome{
			edgeStatus:       ValidationInconclusive,
			reachability:     ReachabilityInconclusive,
			validationResult: "PROBE_ERROR",
			observedResult:   fmt.Sprintf("Transition request failed: %v", err),
			unverifiedImpact: dst.Title,
			limitation:       fmt.Sprintf("Network/transport error during reachability probe: %v", err),
		}
	}
	defer resp.Body.Close()

	bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 256*1024))
	bodyStr := string(bodyBytes)
	ctype := resp.Header.Get("Content-Type")

	// Redirect to login or auth failure => NOT_REACHABLE
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden ||
		resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusMethodNotAllowed {
		return transitionProbeOutcome{
			edgeStatus:       ValidationNotReachable,
			reachability:     ReachabilityNotReachable,
			validationResult: fmt.Sprintf("HTTP_%d_BLOCKED", resp.StatusCode),
			httpStatus:       resp.StatusCode,
			observedResult:   fmt.Sprintf("Transition blocked with HTTP %d on %s", resp.StatusCode, secrets.SanitizeURL(targetURL)),
			evidenceRefs:     []string{fmt.Sprintf("Probe %s %s -> HTTP %d", method, secrets.SanitizeURL(targetURL), resp.StatusCode)},
			unverifiedImpact: fmt.Sprintf("%s unreachable (HTTP %d)", dst.Title, resp.StatusCode),
			explanation:      fmt.Sprintf("Next step %s returned HTTP %d under active identity %s", dst.ID, resp.StatusCode, firstNonEmpty(string(activeIdentity), "UNAUTHENTICATED")),
		}
	}

	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		loc := strings.ToLower(resp.Header.Get("Location"))
		if strings.Contains(loc, "login") || strings.Contains(loc, "signin") || strings.Contains(loc, "auth") {
			return transitionProbeOutcome{
				edgeStatus:       ValidationNotReachable,
				reachability:     ReachabilityNotReachable,
				validationResult: "REDIRECT_TO_LOGIN",
				httpStatus:       resp.StatusCode,
				observedResult:   fmt.Sprintf("Transition redirected to authentication boundary (%s)", secrets.SanitizeURL(loc)),
				evidenceRefs:     []string{fmt.Sprintf("Probe %s -> %d Redirect(%s)", secrets.SanitizeURL(targetURL), resp.StatusCode, loc)},
				unverifiedImpact: dst.Title,
			}
		}
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return transitionProbeOutcome{
			edgeStatus:       ValidationInconclusive,
			reachability:     ReachabilityInconclusive,
			validationResult: fmt.Sprintf("HTTP_%d_UNEXPECTED", resp.StatusCode),
			httpStatus:       resp.StatusCode,
			observedResult:   fmt.Sprintf("Transition probe returned HTTP %d", resp.StatusCode),
			unverifiedImpact: dst.Title,
		}
	}

	// False-Impact / Soft-200 Guard (Section 7G):
	// HTTP 200 alone NEVER confirms an attack path step if the body lacks real impact evidence!
	if isSoft200NonImpactResponse(bodyStr, ctype) {
		return transitionProbeOutcome{
			edgeStatus:       ValidationInconclusive,
			reachability:     ReachabilityInconclusive,
			validationResult: "SOFT_200_FALSE_IMPACT",
			httpStatus:       resp.StatusCode,
			observedResult:   fmt.Sprintf("HTTP %d received from %s, but response body shows login page, empty payload, or soft error — impact NOT demonstrated", resp.StatusCode, secrets.SanitizeURL(targetURL)),
			evidenceRefs:     []string{fmt.Sprintf("Probe %s -> HTTP %d (no impact marker / soft-200 rejected)", secrets.SanitizeURL(targetURL), resp.StatusCode)},
			unverifiedImpact: dst.Title,
			limitation:       "HTTP 200 response lacked observable impact proof (false impact rejected)",
		}
	}

	// Verify explicit impact markers if expected or required for BOLA/BFLA/Data/PrivEsc
	hasImpact, impactSummary, rejectReason := verifyObservableStepImpact(dst, bodyStr, edge.Type, activeIdentity)
	if !hasImpact {
		return transitionProbeOutcome{
			edgeStatus:       ValidationInconclusive,
			reachability:     ReachabilityInconclusive,
			validationResult: "MISSING_IMPACT_EVIDENCE",
			httpStatus:       resp.StatusCode,
			observedResult:   rejectReason,
			evidenceRefs:     []string{fmt.Sprintf("Probe %s -> HTTP %d (%s)", secrets.SanitizeURL(targetURL), resp.StatusCode, rejectReason)},
			unverifiedImpact: dst.Title,
			limitation:       rejectReason,
		}
	}

	// Check Missing Evidence Guard on relationship/finding itself (Section 7F)
	if len(edge.EvidenceReferences) == 0 && dst.EvidenceSummary == "" && src.EvidenceSummary == "" {
		return transitionProbeOutcome{
			edgeStatus:       ValidationCandidate,
			reachability:     ReachabilityNotTested,
			validationResult: "MISSING_FINDING_EVIDENCE",
			httpStatus:       resp.StatusCode,
			observedResult:   "Source/destination findings lack supporting evidence references",
			unverifiedImpact: dst.Title,
			limitation:       "Transition cannot be confirmed without supporting finding evidence",
		}
	}

	evRef := fmt.Sprintf("Transition probe %s %s -> HTTP %d (%s)", method, secrets.SanitizeURL(targetURL), resp.StatusCode, impactSummary)
	return transitionProbeOutcome{
		edgeStatus:         ValidationConfirmed,
		reachability:       ReachabilityReachable,
		validationResult:   "CONFIRMED",
		httpStatus:         resp.StatusCode,
		observedResult:     impactSummary,
		evidenceRefs:       append(append([]string{}, edge.EvidenceReferences...), evRef),
		impactVerified:     true,
		demonstratedImpact: impactSummary,
		explanation:        fmt.Sprintf("Empirically verified %s -> %s (%s)", src.ID, dst.ID, impactSummary),
	}
}

func (v *Phase5Validator) validatePathDAG(p *AttackPath) bool {
	if p == nil || len(p.Nodes) < 2 || len(p.Edges) == 0 {
		return false
	}
	seenNode := make(map[string]bool)
	for _, n := range p.Nodes {
		if n.ID == "" || seenNode[n.ID] {
			return false
		}
		seenNode[n.ID] = true
	}
	seenEdge := make(map[string]bool)
	for _, e := range p.Edges {
		if e.SourceFindingID == "" || e.TargetFindingID == "" || e.SourceFindingID == e.TargetFindingID {
			return false
		}
		if !seenNode[e.SourceFindingID] || !seenNode[e.TargetFindingID] {
			return false
		}
		k := fmt.Sprintf("%s->%s:%s", e.SourceFindingID, e.TargetFindingID, e.RuleCode)
		if seenEdge[k] {
			return false
		}
		seenEdge[k] = true
	}
	g := NewAttackGraph(p.Nodes, p.Edges)
	return !g.Validation.HasCycle && g.Validation.IsValid
}

func (v *Phase5Validator) resolveTargetURL(raw string) string {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return ""
	}
	if strings.HasPrefix(trimmed, "http://") || strings.HasPrefix(trimmed, "https://") {
		return trimmed
	}
	if v.allowedBaseURL != nil {
		ref, err := url.Parse(trimmed)
		if err == nil {
			return v.allowedBaseURL.ResolveReference(ref).String()
		}
	}
	return trimmed
}

func (v *Phase5Validator) isURLAllowed(rawURL string) bool {
	if v.opts.ScopeAllowed != nil {
		return v.opts.ScopeAllowed(rawURL)
	}
	u, err := url.Parse(rawURL)
	if err != nil || u.Host == "" {
		return false
	}
	if v.allowedBaseURL != nil {
		if auth.IsSameOrigin(u, v.allowedBaseURL) {
			return true
		}
		if v.opts.AllowLoopback && auth.IsLoopbackURL(u) && auth.IsLoopbackURL(v.allowedBaseURL) && auth.EffectivePort(u) == auth.EffectivePort(v.allowedBaseURL) {
			return true
		}
		return false
	}
	return true
}

func (v *Phase5Validator) isAuthorizedFixtureTarget(rawURL string) bool {
	u, err := url.Parse(rawURL)
	if err != nil {
		return false
	}
	for _, h := range v.opts.AuthorizedFixtureHosts {
		if strings.EqualFold(u.Host, strings.TrimSpace(h)) || strings.EqualFold(u.Hostname(), strings.TrimSpace(h)) {
			return true
		}
	}
	return auth.IsLoopbackURL(u)
}

func (v *Phase5Validator) isolatedProbeClient() *http.Client {
	var transport http.RoundTripper
	if v.opts.BaseClient != nil && v.opts.BaseClient.Transport != nil {
		if _, isAuthTx := v.opts.BaseClient.Transport.(*auth.AuthenticatedTransport); !isAuthTx {
			transport = v.opts.BaseClient.Transport
		}
	}
	if transport == nil {
		transport = &http.Transport{
			DialContext: crawler.NewSafeDialContext(crawler.SafeDialerOptions{
				Timeout:         v.opts.Timeout,
				AllowLoopback:   v.opts.AllowLoopback,
				AllowPrivateIPs: v.opts.AllowPrivate,
			}),
		}
	}
	allowed := v.allowedBaseURL
	return &http.Client{
		Timeout:   v.opts.Timeout,
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return http.ErrUseLastResponse
			}
			// Never leak credentials across origin boundaries during redirects
			if allowed != nil && !auth.IsSameOrigin(req.URL, allowed) {
				req.Header.Del("Authorization")
				req.Header.Del("Cookie")
				req.Header.Del("X-API-Key")
				return http.ErrUseLastResponse
			}
			return nil
		},
	}
}

func (v *Phase5Validator) clientForTransition(src, dst NormalizedFinding, edge *Relationship, activeCred *CredentialVerificationResult) (*http.Client, auth.IdentityContext) {
	if activeCred != nil && activeCred.Status == CredVerified {
		return v.isolatedProbeClient(), auth.IdentityContext(activeCred.ObservedIdentity)
	}

	reqID := strings.ToUpper(strings.TrimSpace(firstNonEmpty(
		edge.IdentityContext,
		dst.EvidenceDetails["accessor_identity"],
		src.EvidenceDetails["identity"],
		src.EvidenceDetails["identity_context"],
	)))
	idCtx := parseAuthIdentityContext(reqID)

	if idCtx != "" && v.opts.IdentityClients != nil {
		if c, ok := v.opts.IdentityClients[idCtx]; ok && c != nil {
			return c, idCtx
		}
	}
	if idCtx != "" && v.opts.IdentityManager != nil {
		if c := v.opts.IdentityManager.ClientFor(idCtx); c != nil {
			return c, idCtx
		}
	}
	if v.opts.BaseClient != nil {
		return v.opts.BaseClient, idCtx
	}
	if v.opts.IdentityManager != nil {
		return v.isolatedProbeClient(), auth.IdentityUnauthenticated
	}
	return nil, ""
}

func (v *Phase5Validator) recomputeSummary(
	findings []report.Finding,
	paths []AttackPath,
	rels []Relationship,
	creds []CredentialVerificationResult,
	prev *Summary,
) *Summary {
	sum := *prev
	sum.TotalFindings = len(findings)
	sum.IndividualFindingsCount = len(findings)
	sum.Relationships = rels
	sum.CandidateRelationships = len(rels)
	sum.CredentialValidations = creds
	sum.CorrelatedObservations = 0
	for _, r := range rels {
		if !r.Type.IsSequenceType() && r.ValidationStatus != ValidationInvalid {
			sum.CorrelatedObservations++
		}
	}

	sum.VerifiedPaths = 0
	sum.ConfirmedPaths = 0
	sum.HighConfidencePaths = 0
	sum.CandidatePaths = 0
	sum.InconclusivePaths = 0
	sum.NotReachablePaths = 0
	sum.NotTestedPaths = 0
	sum.ConfirmedRelationships = 0

	for _, r := range rels {
		if r.ValidationStatus == ValidationConfirmed {
			sum.ConfirmedRelationships++
		}
	}

	maxScore := 0
	highestLevel := report.SeverityInfo
	for _, p := range paths {
		switch p.Status {
		case PathConfirmed:
			sum.ConfirmedPaths++
			sum.VerifiedPaths++
			if p.CombinedRiskScore > maxScore {
				maxScore = p.CombinedRiskScore
				highestLevel = p.CombinedRiskLevel
			}
		case PathVerified:
			sum.VerifiedPaths++
			sum.ConfirmedPaths++
			if p.CombinedRiskScore > maxScore {
				maxScore = p.CombinedRiskScore
				highestLevel = p.CombinedRiskLevel
			}
		case PathHighConfidence:
			sum.HighConfidencePaths++
		case PathCandidate:
			sum.CandidatePaths++
		case PathInconclusive:
			sum.InconclusivePaths++
		case PathNotReachable:
			sum.NotReachablePaths++
		case PathNotTested:
			sum.NotTestedPaths++
		}
	}
	sum.HighestRiskScore = maxScore
	sum.HighestRiskLevel = highestLevel
	if len(paths) > 0 {
		sum.BottleneckAnalysis = AnalyzeRemediationBottlenecks(paths, nil, nil)
	}
	return &sum
}

func injectTokenHeader(req *http.Request, token, tokenKind string) {
	lowerKind := strings.ToLower(tokenKind)
	switch {
	case strings.Contains(lowerKind, "x-api-key") || strings.Contains(lowerKind, "api_key") || strings.Contains(lowerKind, "apikey"):
		req.Header.Set("X-API-Key", token)
	case strings.Contains(lowerKind, "cookie") || strings.Contains(lowerKind, "session"):
		req.Header.Set("Cookie", token)
	case strings.HasPrefix(strings.ToLower(token), "bearer "):
		req.Header.Set("Authorization", token)
	default:
		req.Header.Set("Authorization", "Bearer "+token)
	}
}

func parseAuthIdentityContext(s string) auth.IdentityContext {
	switch strings.ToUpper(strings.TrimSpace(s)) {
	case "USER_A", "USERA", "OWNER":
		return auth.IdentityUserA
	case "USER_B", "USERB", "ATTACKER":
		return auth.IdentityUserB
	case "ADMIN", "ADMINISTRATOR":
		return auth.IdentityAdmin
	case "UNAUTHENTICATED", "ANON", "ANONYMOUS":
		return auth.IdentityUnauthenticated
	default:
		return ""
	}
}

func isSoft200NonImpactResponse(body, contentType string) bool {
	trimmed := strings.TrimSpace(body)
	if trimmed == "" || trimmed == "{}" || trimmed == "[]" || trimmed == "null" {
		return true
	}
	lower := strings.ToLower(trimmed)
	// Reject HTML login / SSO prompts returned with HTTP 200
	if (strings.Contains(lower, "<html") || strings.Contains(lower, "<form") || strings.Contains(contentType, "text/html")) &&
		(strings.Contains(lower, "login") || strings.Contains(lower, "sign in") || strings.Contains(lower, `type="password"`) || strings.Contains(lower, "unauthorized") || strings.Contains(lower, "access denied")) {
		return true
	}
	// Reject explicit JSON error/denial wrappers wrapped in 200 OK
	var m map[string]any
	if json.Unmarshal([]byte(trimmed), &m) == nil && len(m) > 0 {
		if errVal, ok := m["error"]; ok && errVal != nil && fmt.Sprint(errVal) != "" {
			return true
		}
		if okVal, hasOk := m["ok"].(bool); hasOk && !okVal {
			return true
		}
		if msg, ok := m["message"].(string); ok {
			lm := strings.ToLower(msg)
			if strings.Contains(lm, "unauthorized") || strings.Contains(lm, "forbidden") || strings.Contains(lm, "access denied") || strings.Contains(lm, "not authenticated") || strings.Contains(lm, "login required") {
				return true
			}
		}
	}
	return false
}

func extractObservedIdentity(body string) string {
	trimmed := strings.TrimSpace(body)
	var m map[string]any
	if json.Unmarshal([]byte(trimmed), &m) == nil {
		for _, k := range []string{"identity", "username", "user", "sub", "role", "email", "account_id", "owner"} {
			if rawVal, ok := m[k]; ok && rawVal != nil {
				s := strings.TrimSpace(fmt.Sprint(rawVal))
				if s != "" && s != "<nil>" {
					return normalizeIdentityLabel(s)
				}
			}
		}
	}
	return ""
}

func normalizeIdentityLabel(raw string) string {
	lower := strings.ToLower(strings.TrimSpace(raw))
	switch {
	case strings.Contains(lower, "admin"):
		return "ADMIN"
	case strings.Contains(lower, "user_b") || strings.Contains(lower, "userb") || lower == "bob":
		return "USER_B"
	case strings.Contains(lower, "user_a") || strings.Contains(lower, "usera") || lower == "alice":
		return "USER_A"
	default:
		return strings.ToUpper(strings.TrimSpace(raw))
	}
}

func identitiesCompatible(intended, observed string) bool {
	n1 := normalizeIdentityLabel(intended)
	n2 := normalizeIdentityLabel(observed)
	if n1 == n2 {
		return true
	}
	return strings.EqualFold(intended, observed)
}

func verifyObservableStepImpact(dst NormalizedFinding, body string, edgeType RelationshipType, activeIdentity auth.IdentityContext) (bool, string, string) {
	trimmed := strings.TrimSpace(body)
	if expectedMarker := strings.TrimSpace(dst.EvidenceDetails["expected_marker"]); expectedMarker != "" {
		if !strings.Contains(body, expectedMarker) {
			return false, "", fmt.Sprintf("HTTP 200 did not contain expected impact marker %q (soft-200 false impact rejected)", expectedMarker)
		}
		return true, fmt.Sprintf("Observed verified impact marker %q in HTTP response", secrets.RedactText(expectedMarker)), ""
	}

	// If destination finding is marked false-impact trap / ambiguous generic status without real resource fields
	if strings.EqualFold(dst.EvidenceDetails["require_explicit_impact"], "true") {
		return false, "", "Explicit impact proof required, but HTTP 200 lacked impact indicator"
	}

	var parsed map[string]any
	isJSON := json.Unmarshal([]byte(trimmed), &parsed) == nil && len(parsed) > 0

	cat := strings.ToLower(dst.NormalizedCategory + " " + dst.Category + " " + dst.Title)
	if strings.Contains(cat, "bola") || strings.Contains(cat, "idor") || edgeType == RelBACCrossTenant {
		owner := normalizeIdentityLabel(firstNonEmpty(dst.EvidenceDetails["owner_identity"], dst.EvidenceDetails["victim_identity"], ""))
		caller := normalizeIdentityLabel(string(activeIdentity))
		if isJSON {
			// Verify sensitive tenant data fields or victim owner match exist (not generic {"status":"ok"})
			if _, okOnly := parsed["status"]; okOnly && len(parsed) == 1 {
				return false, "", "HTTP 200 returned generic status without tenant/object payload"
			}
			bodyOwner := normalizeIdentityLabel(fmt.Sprint(parsed["owner"], parsed["tenant_id"], parsed["user"], parsed["account_owner"]))
			if owner != "" && caller != "" && owner != caller && !strings.Contains(strings.ToUpper(trimmed), owner) && bodyOwner == "" {
				return false, "", fmt.Sprintf("HTTP 200 lacked cross-tenant victim record (%s) proof", owner)
			}
			return true, fmt.Sprintf("Cross-tenant resource access demonstrated (%d structured response fields returned under %s)", len(parsed), firstNonEmpty(caller, "ACTIVE_IDENTITY")), ""
		}
		return false, "", "BOLA transition expected structured object record, got non-object response"
	}

	if strings.Contains(cat, "bfla") || strings.Contains(cat, "admin") || edgeType == RelPrivEscRestricted {
		if isJSON {
			if _, okOnly := parsed["status"]; okOnly && len(parsed) == 1 {
				return false, "", "HTTP 200 returned generic status without privileged function output"
			}
			return true, fmt.Sprintf("Restricted function response verified (%d JSON fields under %s)", len(parsed), firstNonEmpty(string(activeIdentity), "CALLER")), ""
		}
		if len(trimmed) > 32 && !strings.Contains(strings.ToLower(trimmed), "hello") {
			return true, fmt.Sprintf("Restricted function content accessible (%d bytes)", len(trimmed)), ""
		}
		return false, "", "HTTP 200 lacked privileged function execution evidence"
	}

	// Default: require meaningful non-trivial payload beyond stub status
	if isJSON {
		if statusVal, hasStatus := parsed["status"]; hasStatus && len(parsed) == 1 && strings.EqualFold(fmt.Sprint(statusVal), "ok") {
			return false, "", "Generic {\"status\":\"ok\"} HTTP 200 without domain evidence rejected as false impact"
		}
		return true, fmt.Sprintf("Observable structured response verified (%d fields)", len(parsed)), ""
	}
	if len(trimmed) >= 24 {
		return true, fmt.Sprintf("Observable response verified (%d bytes)", len(trimmed)), ""
	}
	return false, "", "Response body too short or empty to substantiate security impact"
}

func firstNonEmpty(vals ...string) string {
	for _, s := range vals {
		if strings.TrimSpace(s) != "" {
			return s
		}
	}
	return ""
}
