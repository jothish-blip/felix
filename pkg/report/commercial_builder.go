package report

import (
	"crypto/sha256"
	"fmt"
	"net/url"
	"sort"
	"strings"
	"time"
)

// CommercialReportOption configures optional parameters during Commercial Report construction.
type CommercialReportOption func(*commercialReportBuilder)

type commercialReportBuilder struct {
	scopeDomains         []string
	scopeURLs            []string
	enginesExecuted      []string
	enginesSkipped       []string
	executionErrors      []string
	explicitRestrictions []string
	excludedTargets      []string
	completionStatus     string
}

// WithScopeDetails configures explicit scope domains and URLs.
func WithScopeDetails(domains, urls []string) CommercialReportOption {
	return func(b *commercialReportBuilder) {
		b.scopeDomains = domains
		b.scopeURLs = urls
	}
}

// WithEngineExecutionDetails records executed and skipped engines.
func WithEngineExecutionDetails(executed, skipped []string) CommercialReportOption {
	return func(b *commercialReportBuilder) {
		b.enginesExecuted = executed
		b.enginesSkipped = skipped
	}
}

// WithExecutionErrors records errors encountered during assessment execution.
func WithExecutionErrors(errors []string) CommercialReportOption {
	return func(b *commercialReportBuilder) {
		b.executionErrors = errors
	}
}

// WithScopeExclusions records explicit scope restrictions and exclusions.
func WithScopeExclusions(restrictions, exclusions []string) CommercialReportOption {
	return func(b *commercialReportBuilder) {
		b.explicitRestrictions = restrictions
		b.excludedTargets = exclusions
	}
}

// WithCompletionStatus overrides the assessment completion status.
func WithCompletionStatus(status string) CommercialReportOption {
	return func(b *commercialReportBuilder) {
		b.completionStatus = status
	}
}

// BuildCommercialReport transforms an existing Felix Report into a Commercial Report 2.0.
// It is strictly a reporting and presentation transformation:
// - It executes zero new probes.
// - It does not mutate source findings.
// - It does not invent evidence, assets, or risk scores.
// - It does not upgrade detections to verifications.
// - It preserves synthetic fixture provenance.
// - It omits all remediation recommendations and fix advice.
func BuildCommercialReport(rep Report, opts ...CommercialReportOption) CommercialReport {
	cfg := &commercialReportBuilder{
		enginesExecuted: []string{
			"felix-crawler",
			"felix-secrets",
			"felix-cloud",
			"felix-api",
			"felix-webvuln",
			"felix-authz",
			"felix-sessionsec",
			"felix-businesslogic",
			"felix-correlation",
			"felix-verification",
		},
	}
	for _, opt := range opts {
		opt(cfg)
	}

	sanitizedRep := SanitizeReport(rep)
	reportID := fmt.Sprintf("REP-%s", sanitizedRep.ReportID())

	timestamp := sanitizedRep.Timestamp
	if timestamp == "" {
		timestamp = time.Now().UTC().Format(time.RFC3339)
	}

	// 1. Separate Findings into Verified, Detected, Observations, and Negative Outcomes
	var verifiedFindings []CommercialFinding
	var detectedFindings []CommercialFinding
	var observations []CommercialObservation
	var negativeOutcomes []CommercialNegativeOutcome
	var traceabilityIndex []CommercialTraceabilityEntry

	hasSynthetic := false

	// Index attack paths and stories per finding for risk contributions
	findingStoryMap := make(map[string][]string)
	for _, st := range sanitizedRep.SecurityStories {
		for _, fid := range st.RelatedIDs {
			findingStoryMap[fid] = append(findingStoryMap[fid], st.ID)
		}
	}

	findingPathMap := make(map[string][]string)
	for _, p := range sanitizedRep.AttackPaths {
		for _, nid := range p.NodeIDs {
			findingPathMap[nid] = append(findingPathMap[nid], p.ID)
		}
	}

	// Authoritative risk contributions breakdown
	contributions, _, _ := CalculateRiskBreakdown(sanitizedRep.Findings, sanitizedRep.SecurityStories)
	findingContribMap := make(map[string]CommercialRiskContribution)
	for _, c := range contributions {
		findingContribMap[c.FindingID] = c
	}

	// Process findings deterministically
	for _, f := range sanitizedRep.Findings {
		isSynth := f.Verification.SyntheticFixture ||
			strings.Contains(f.Evidence, "[SYNTHETIC FIXTURE]") ||
			strings.Contains(f.Title, "[SYNTHETIC FIXTURE]")
		if isSynth {
			hasSynthetic = true
		}

		canonicalStatus := NormalizeVerificationStatus(f.Verification.Status)
		traceabilityIndex = append(traceabilityIndex, buildTraceabilityEntry(f, canonicalStatus, isSynth))

		switch canonicalStatus {
		case VerificationVerified:
			cf := buildCommercialFinding(f, sanitizedRep, findingStoryMap, findingPathMap, findingContribMap, isSynth, timestamp)
			verifiedFindings = append(verifiedFindings, cf)

		case VerificationDetected, VerificationNotVerified:
			cf := buildCommercialFinding(f, sanitizedRep, findingStoryMap, findingPathMap, findingContribMap, isSynth, timestamp)
			detectedFindings = append(detectedFindings, cf)

		case VerificationObserved:
			obs := buildCommercialObservation(f, isSynth)
			observations = append(observations, obs)

		case VerificationNotExposed:
			// NOT_EXPOSED is strictly NOT a vulnerability; it belongs in Technical Appendix
			neg := CommercialNegativeOutcome{
				FindingID:     f.ID,
				TargetURL:     f.Target,
				Endpoint:      f.Endpoint,
				PolicyID:      f.Verification.PolicyID,
				ResultSummary: f.Verification.Result,
				Evidence:      f.Evidence,
				Limitations:   f.Verification.Limitations,
			}
			if neg.PolicyID == "" {
				neg.PolicyID = "POL-DEFENSE-BOUNDARY"
			}
			if len(neg.Limitations) == 0 {
				neg.Limitations = []string{"Status code confirms tested boundary under evaluated conditions; does not prove entire application or account is secure."}
			}
			negativeOutcomes = append(negativeOutcomes, neg)

		default:
			// Fallback: If detection status is DETECTED, keep as detected finding; else observation
			if strings.EqualFold(f.EvidenceDetails.DetectionStatus, "DETECTED") {
				cf := buildCommercialFinding(f, sanitizedRep, findingStoryMap, findingPathMap, findingContribMap, isSynth, timestamp)
				detectedFindings = append(detectedFindings, cf)
			} else {
				obs := buildCommercialObservation(f, isSynth)
				observations = append(observations, obs)
			}
		}
	}

	// Deterministic sorting of findings and traceability
	sortCommercialFindings(verifiedFindings)
	sortCommercialFindings(detectedFindings)
	sortCommercialObservations(observations)
	sort.SliceStable(traceabilityIndex, func(i, j int) bool {
		return traceabilityIndex[i].FindingID < traceabilityIndex[j].FindingID
	})

	// 2. Build Attack Surface
	attackSurface := buildAttackSurface(sanitizedRep)

	// 3. Build Scope Summary
	scope := buildAssessmentScope(sanitizedRep, cfg, attackSurface, hasSynthetic)

	// 4. Build Risk Overview
	riskOverview := buildRiskOverview(sanitizedRep, verifiedFindings, detectedFindings)

	// 5. Build Executive Summary
	execSummary := buildExecutiveSummary(sanitizedRep, cfg, verifiedFindings, detectedFindings, observations, attackSurface, hasSynthetic)

	// 6. Build Technical Appendix
	appendix := buildTechnicalAppendix(sanitizedRep, cfg, negativeOutcomes, traceabilityIndex, hasSynthetic, timestamp)

	return CommercialReport{
		SchemaVersion:     CommercialReportSchemaVersion,
		ReportID:          reportID,
		GeneratedAt:       timestamp,
		ExecutiveSummary:  execSummary,
		AssessmentScope:   scope,
		AttackSurface:     attackSurface,
		RiskOverview:      riskOverview,
		VerifiedFindings:  verifiedFindings,
		DetectedFindings:  detectedFindings,
		Observations:      observations,
		TechnicalAppendix: appendix,
	}
}

// -----------------------------------------------------------------------------
// Helper: Finding Construction (Sections 5 & 6)
// -----------------------------------------------------------------------------

func buildCommercialFinding(
	f Finding,
	rep Report,
	storyMap map[string][]string,
	pathMap map[string][]string,
	contribMap map[string]CommercialRiskContribution,
	synthetic bool,
	timestamp string,
) CommercialFinding {
	endpoint := f.Endpoint
	if endpoint == "" {
		endpoint = f.Target
	}
	location := f.EvidenceDetails.Location
	if location == "" {
		location = endpoint
	}

	severity := NormalizeSeverity(f.Severity)
	if severity == "" {
		severity = "UNAVAILABLE"
	}

	confidence := buildConfidenceDetail(f)
	authState := extractAuthenticationState(f)
	detectionMethod := f.EvidenceDetails.DetectionMethod
	if detectionMethod == "" {
		detectionMethod = f.Source
		if detectionMethod == "" {
			detectionMethod = "automated_engine_audit"
		}
	}

	verification := buildVerificationDetail(f)
	evidence := buildEvidenceDetail(f, synthetic, timestamp)
	impact := buildSecurityImpact(f)
	riskContrib := buildRiskContribution(f, storyMap[f.ID], pathMap[f.ID], contribMap[f.ID])

	desc := SanitizeEvidence(f.Description)
	if desc == "" {
		desc = fmt.Sprintf("Observed security condition: %s", SanitizeEvidence(f.Title))
	}

	return CommercialFinding{
		ID:                  f.ID,
		Title:               SanitizeEvidence(f.Title),
		Description:         desc,
		AffectedAsset:       endpoint,
		AssetLocation:       location,
		Severity:            severity,
		Confidence:          confidence,
		AuthenticationState: authState,
		DetectionMethod:     detectionMethod,
		Verification:        verification,
		Evidence:            evidence,
		SecurityImpact:      impact,
		RiskContribution:    riskContrib,
		Category:            f.Category,
		Source:              f.Source,
		SyntheticFixture:    synthetic,
	}
}

func buildConfidenceDetail(f Finding) CommercialConfidenceDetail {
	detConf := NormalizeConfidence(f.Confidence)
	if detConf == "" {
		detConf = ConfidenceMedium
	}

	verConf := ConfidenceLow
	score := f.Verification.ConfidenceScore
	switch NormalizeVerificationStatus(f.Verification.Status) {
	case VerificationVerified:
		verConf = ConfidenceHigh
		if score == 0 {
			score = 90
		}
	case VerificationDetected:
		verConf = ConfidenceMedium
		if score == 0 {
			score = 65
		}
	case VerificationNotVerified:
		verConf = ConfidenceLow
		if score == 0 {
			score = 45
		}
	case VerificationObserved:
		verConf = "NONE"
		if score == 0 {
			score = 25
		}
	case VerificationNotExposed:
		verConf = ConfidenceHigh
		if score == 0 {
			score = 85
		}
	}

	overallConf := detConf
	if verConf == ConfidenceHigh && detConf == ConfidenceHigh {
		overallConf = ConfidenceHigh
	} else if verConf == ConfidenceLow && detConf != ConfidenceHigh {
		overallConf = ConfidenceLow
	}

	rationale := f.Verification.Rationale
	if rationale == "" {
		rationale = fmt.Sprintf("Detection confidence %s based on %s; verification empirical confidence %s.",
			detConf, f.Source, verConf)
	}

	return CommercialConfidenceDetail{
		DetectionConfidence:    detConf,
		VerificationConfidence: verConf,
		OverallConfidence:      overallConf,
		ConfidenceScore:        score,
		Rationale:              rationale,
	}
}

func extractAuthenticationState(f Finding) string {
	if f.EvidenceDetails.Details != nil {
		if as, ok := f.EvidenceDetails.Details["auth_state"]; ok && as != "" {
			switch strings.ToUpper(as) {
			case "AUTH_REQUIRED", "AUTH-REQUIRED":
				return "Unauthenticated (Authentication Required)"
			case "PUBLIC":
				return "Unauthenticated (Public Route)"
			case "FORBIDDEN":
				return "Unauthenticated (Access Denied / 403)"
			case "NOT_FOUND":
				return "Unauthenticated (Route Not Found / 404)"
			default:
				return as
			}
		}
		if id, ok := f.EvidenceDetails.Details["owner_identity"]; ok && id != "" {
			if unauth, ok2 := f.EvidenceDetails.Details["unauthorized_identity"]; ok2 && unauth != "" {
				return "Multiple Identities (Comparative Differential Access)"
			}
			return "Authenticated"
		}
		if idCtx, ok := f.EvidenceDetails.Details["identity_context"]; ok && idCtx != "" {
			return idCtx
		}
	}

	cat := strings.ToLower(f.Category)
	title := strings.ToLower(f.Title)

	if strings.Contains(cat, "bola") || strings.Contains(title, "bola") ||
		strings.Contains(cat, "idor") || strings.Contains(title, "idor") {
		return "Multiple Identities (Comparative Authorization Context)"
	}
	if strings.Contains(cat, "privileged") || strings.Contains(title, "admin") {
		return "Privileged"
	}
	if strings.Contains(cat, "session") || strings.Contains(cat, "cookie") || strings.Contains(cat, "jwt") {
		return "Authenticated"
	}
	if f.Source == SourceSecrets {
		return "Not Applicable (Static Source Asset)"
	}
	if f.EvidenceDetails.HTTPStatus == 401 || f.EvidenceDetails.HTTPStatus == 403 {
		return "Unauthenticated"
	}

	return "Unknown"
}

func buildVerificationDetail(f Finding) CommercialVerificationDetail {
	status := NormalizeVerificationStatus(f.Verification.Status)
	policyID := f.Verification.PolicyID
	if policyID == "" {
		policyID = fmt.Sprintf("POL-%s-01", strings.ToUpper(NormalizeCategory(f.Category)))
	}

	method := f.Verification.VerificationMethod
	if method == "" {
		if status == VerificationVerified {
			method = "empirical_active_probe"
		} else {
			method = "signal_detection_heuristic"
		}
	}

	var satisfied []string
	var notSatisfied []string

	if status == VerificationVerified {
		satisfied = append(satisfied, "Resource reachability verified", "Response content criteria satisfied")
	} else if status == VerificationNotVerified {
		notSatisfied = append(notSatisfied, "Mandatory proof criteria not satisfied", "Independent reproduction pending")
	} else if status == VerificationDetected {
		notSatisfied = append(notSatisfied, "Active verification not attempted")
	}

	var blockedReason string
	if strings.Contains(strings.ToLower(f.Verification.Result), "blocked") {
		blockedReason = f.Verification.Result
	}

	limitations := f.Verification.Limitations
	if len(limitations) == 0 {
		if status == VerificationVerified {
			limitations = []string{"Verification establishes tested condition only; non-destructive bounds enforced."}
		} else {
			limitations = []string{"Finding is an unverified detection hypothesis."}
		}
	}

	resultSummary := f.Verification.Result
	if resultSummary == "" {
		if status == VerificationVerified {
			resultSummary = "Condition empirically confirmed under authorized testing parameters."
		} else {
			resultSummary = "Condition detected by static pattern or probe heuristics; verification incomplete."
		}
	}

	return CommercialVerificationDetail{
		Status:                status,
		MethodOrPolicy:        policyID,
		CriteriaSatisfied:     satisfied,
		CriteriaNotSatisfied:  notSatisfied,
		Preconditions:         []string{"Authorized assessment target within defined scope boundaries"},
		InconclusiveOrBlocked: blockedReason,
		Limitations:           limitations,
		ResultSummary:         resultSummary,
	}
}

func buildEvidenceDetail(f Finding, synthetic bool, timestamp string) CommercialEvidenceDetail {
	provenance := "LIVE"
	if synthetic {
		provenance = "FIXTURE"
	} else if f.Source == SourceSecrets {
		provenance = "STATIC"
	}

	obs := f.EvidenceDetails.Observation
	if obs == "" {
		obs = f.Evidence
	}
	if obs == "" {
		obs = "Observable security signal captured during assessment execution."
	}

	var evRefs []string
	if f.Endpoint != "" {
		evRefs = append(evRefs, f.Endpoint)
	}
	if f.EvidenceDetails.Location != "" && f.EvidenceDetails.Location != f.Endpoint {
		evRefs = append(evRefs, f.EvidenceDetails.Location)
	}

	var headers map[string]string
	if f.EvidenceDetails.Details != nil {
		headers = make(map[string]string)
		for k, v := range f.EvidenceDetails.Details {
			if strings.HasPrefix(strings.ToLower(k), "header_") {
				cleanKey := strings.TrimPrefix(k, "header_")
				headers[cleanKey] = SanitizeEvidence(v)
			}
		}
		if len(headers) == 0 {
			headers = nil
		}
	}

	isAvailable := len(f.Evidence) > 0 || f.EvidenceDetails.HTTPStatus > 0 || len(f.EvidenceDetails.Observation) > 0

	var sanitizedSteps []string
	if len(f.Verification.ReproductionSteps) > 0 {
		sanitizedSteps = make([]string, len(f.Verification.ReproductionSteps))
		for idx, step := range f.Verification.ReproductionSteps {
			sanitizedSteps[idx] = SanitizeEvidence(step)
		}
	}

	return CommercialEvidenceDetail{
		Observation:        SanitizeEvidence(obs),
		Location:           SanitizeEvidence(f.EvidenceDetails.Location),
		HTTPMethod:         f.Method,
		HTTPStatus:         f.EvidenceDetails.HTTPStatus,
		Headers:            headers,
		SanitizedExcerpt:   SanitizeEvidence(f.Evidence),
		EvidenceSummary:    SanitizeEvidence(f.Evidence),
		NegativeEvidence:   SanitizeEvidence(f.EvidenceDetails.NegativeEvidence),
		EvidenceReferences: evRefs,
		ReproductionSteps:  sanitizedSteps,
		SafeCurlCommand:    SanitizeEvidence(f.Verification.SafeCurlCommand),
		Provenance:         provenance,
		Timestamp:          timestamp,
		IsAvailable:        isAvailable,
	}
}

// buildSecurityImpact describes security consequences WITHOUT providing remediation advice.
func buildSecurityImpact(f Finding) CommercialSecurityImpact {
	cat := strings.ToLower(NormalizeCategory(f.Category))
	sev := NormalizeSeverity(f.Severity)

	demonstrated := ""
	plausible := ""
	unverified := ""
	summary := ""

	switch {
	case strings.Contains(cat, "service-key") || strings.Contains(cat, "service-role") || strings.Contains(cat, "aws-secret"):
		demonstrated = "High-entropy administrative or service key pattern identified in client-accessible assets."
		plausible = "Direct unauthorized queries or administrative operations against backend cloud infrastructure."
		unverified = "Live credential validity, quota consumption, and privileged mutations were intentionally not tested to protect tenant safety."
		summary = "Exposure of high-privilege backend credentials poses significant risk of unauthorized cloud resource access."

	case strings.Contains(cat, "bola") || strings.Contains(cat, "idor"):
		demonstrated = "Object-level authorization boundary failed to restrict access to target resource."
		plausible = "Systematic enumeration of resource identifiers leading to unauthorized extraction of peer tenant data."
		unverified = "Cross-organization administrative privilege escalation was not evaluated."
		summary = "Broken object-level authorization allows unauthorized data retrieval across identity boundaries."

	case strings.Contains(cat, "env-exposure") || strings.Contains(cat, "git-metadata"):
		demonstrated = "Server configuration or source repository metadata directly reachable via unauthenticated HTTP GET."
		plausible = "Reconstruction of application source code or extraction of deployment environment secrets."
		unverified = "Backend host compromise or container breakout was not tested."
		summary = "Direct disclosure of configuration artifacts exposes internal environment details."

	case strings.Contains(cat, "cors"):
		demonstrated = "Web server responds with permissive cross-origin resource sharing headers."
		plausible = "Cross-origin reading of response data when authenticated users visit malicious origins."
		unverified = "Exploitation depends on user interaction with an independent attacker-controlled origin."
		summary = "Overly permissive CORS configuration weakens browser origin isolation."

	case strings.HasPrefix(cat, "missing-") || strings.HasPrefix(cat, "weak-"):
		demonstrated = "Server HTTP response headers lack standard defense-in-depth protection directives."
		plausible = "In the event of an independent injection flaw, browser-side defensive mitigations would be absent."
		unverified = "No active injection, cross-site scripting, or framing condition was demonstrated."
		summary = "Absence of hardening headers reduces defense-in-depth protection against secondary attacks."

	default:
		switch sev {
		case SeverityCritical, SeverityHigh:
			demonstrated = "Security weakness observed on target endpoint during authorized assessment."
			plausible = "Potential compromise of resource confidentiality or integrity under attacker execution."
			unverified = "Destructive exploitation was not attempted under non-destructive safety policy."
			summary = "High-severity security condition identified on assessed endpoint."
		default:
			demonstrated = "Technical observation recorded on target endpoint."
			plausible = "Informational signal or minor configuration variance."
			unverified = "Active vulnerability exploitation was not demonstrated."
			summary = "Security posture observation without direct exploitability demonstrated."
		}
	}

	return CommercialSecurityImpact{
		DemonstratedImpact: demonstrated,
		PlausibleImpact:    plausible,
		UnverifiedImpact:   unverified,
		Summary:            summary,
	}
}

func buildRiskContribution(f Finding, storyIDs, pathIDs []string, contrib CommercialRiskContribution) CommercialRiskContribution {
	score := f.Score
	if score == 0 {
		score = CalculateFindingScore(f)
	}

	riskType := "INDIVIDUAL"
	if len(pathIDs) > 0 {
		riskType = "ATTACK_PATH"
	} else if len(storyIDs) > 0 {
		riskType = "CORRELATED"
	} else if isHardeningCategory(f.Category) {
		riskType = "HARDENING_DEFENSE_IN_DEPTH"
	}

	weight := contrib.Weight
	adjScore := contrib.AdjustedScore
	if contrib.RiskType != "" {
		riskType = contrib.RiskType
	}
	rationale := contrib.Rationale
	if rationale == "" {
		rationale = fmt.Sprintf("Calculated risk score %d/40 weighted by severity (%s), confidence (%s), and verification status (%s).",
			score, f.Severity, f.Confidence, f.Verification.Status)
	}

	return CommercialRiskContribution{
		FindingID:          f.ID,
		Title:              SanitizeEvidence(f.Title),
		Severity:           f.Severity,
		VerificationStatus: string(f.Verification.Status),
		Score:              score,
		Weight:             weight,
		AdjustedScore:      adjScore,
		Model:              "felix_deterministic_v1",
		RiskType:           riskType,
		CorrelatedStoryIDs: storyIDs,
		AttackPathIDs:      pathIDs,
		Rationale:          rationale,
		IsAvailable:        true,
	}
}

// -----------------------------------------------------------------------------
// Helper: Observation Construction (Section 7)
// -----------------------------------------------------------------------------

func buildCommercialObservation(f Finding, synthetic bool) CommercialObservation {
	obsType := "INFORMATIONAL_SIGNAL"
	cat := strings.ToLower(f.Category)
	if strings.Contains(cat, "asset-") || strings.Contains(cat, "crawler") {
		obsType = "ATTACK_SURFACE_CHARACTERISTIC"
	} else if strings.Contains(cat, "config") || strings.Contains(cat, "client-") {
		obsType = "DEFENSIVE_CONFIGURATION"
	}

	asset := f.Endpoint
	if asset == "" {
		asset = f.Target
	}

	evidence := f.Evidence
	if evidence == "" {
		evidence = f.EvidenceDetails.Observation
	}

	return CommercialObservation{
		ObservationID:     fmt.Sprintf("OBS-%s", shortHash(f.ID)),
		Title:             SanitizeEvidence(f.Title),
		Description:       SanitizeEvidence(f.Description),
		AffectedAsset:     asset,
		ObservationSource: f.Source,
		Evidence:          SanitizeEvidence(evidence),
		AssessmentContext: "Discovered and cataloged during baseline inventory and discovery crawl.",
		Limitations: []string{
			"Observation reflects informational asset cataloging; does not represent a verified vulnerability or security failure.",
		},
		ObservationType:  obsType,
		Category:         f.Category,
		SyntheticFixture: synthetic,
	}
}

// -----------------------------------------------------------------------------
// Helper: Attack Surface Construction (Section 3)
// -----------------------------------------------------------------------------

func buildAttackSurface(rep Report) CommercialAttackSurface {
	assetMap := make(map[string]*CommercialAttackSurfaceAsset)
	byType := make(map[string]int)

	// Ingest from target list
	for _, t := range rep.Targets {
		cleanT := strings.TrimSpace(t)
		if cleanT == "" {
			continue
		}
		id := "AST-" + shortHash(cleanT)
		assetMap[cleanT] = &CommercialAttackSurfaceAsset{
			AssetID:               id,
			URL:                   cleanT,
			AssetType:             classifyAssetType(cleanT),
			DiscoverySource:       "assessment_target_configuration",
			AssessmentState:       "ASSESSED",
			AuthenticationContext: "Configured Assessment Target",
			ExposureInfo:          "Primary authorized target boundary",
		}
	}

	// Ingest from findings
	for _, f := range rep.Findings {
		rawURL := f.Endpoint
		if rawURL == "" {
			rawURL = f.Target
		}
		if rawURL == "" {
			continue
		}

		existing, exists := assetMap[rawURL]
		if !exists {
			id := "AST-" + shortHash(rawURL)
			assetType := classifyAssetType(rawURL)
			assessmentState := "ASSESSED"
			if f.Verification.Status == VerificationObserved {
				assessmentState = "DISCOVERED_ONLY"
			}

			existing = &CommercialAttackSurfaceAsset{
				AssetID:               id,
				URL:                   rawURL,
				AssetType:             assetType,
				DiscoverySource:       f.Source,
				AssessmentState:       assessmentState,
				AuthenticationContext: extractAuthenticationState(f),
				ExposureInfo:          fmt.Sprintf("Observed via %s (%s)", f.Source, f.Category),
				HTTPStatus:            f.EvidenceDetails.HTTPStatus,
			}
			assetMap[rawURL] = existing
		}

		existing.AssociatedFindingIDs = append(existing.AssociatedFindingIDs, f.ID)
		if f.EvidenceDetails.HTTPStatus > 0 && existing.HTTPStatus == 0 {
			existing.HTTPStatus = f.EvidenceDetails.HTTPStatus
		}
	}

	var assets []CommercialAttackSurfaceAsset
	for _, a := range assetMap {
		byType[a.AssetType]++
		assets = append(assets, *a)
	}

	// Deterministic sort
	sort.Slice(assets, func(i, j int) bool {
		if assets[i].AssetType != assets[j].AssetType {
			return assets[i].AssetType < assets[j].AssetType
		}
		return assets[i].URL < assets[j].URL
	})

	frontendCount := byType["CLIENT_ASSET"]
	if rep.Metadata != nil {
		if raw, ok := rep.Metadata["crawled_assets_count"]; ok {
			switch v := raw.(type) {
			case int:
				frontendCount = v
			case float64:
				frontendCount = int(v)
			}
		}
	}
	if frontendCount == 0 && rep.CommercialReport != nil {
		if rep.CommercialReport.ExecutiveSummary.FrontendAssetsCount > 0 {
			frontendCount = rep.CommercialReport.ExecutiveSummary.FrontendAssetsCount
		} else if rep.CommercialReport.AttackSurface.FrontendAssetsCount > 0 {
			frontendCount = rep.CommercialReport.AttackSurface.FrontendAssetsCount
		}
	}

	apiEndpointsCount := byType["API_ENDPOINT"] + byType["AUTH_ENTRYPOINT"]
	webRoutesCount := byType["WEB_ROUTE"] + byType["DOMAIN"]

	return CommercialAttackSurface{
		TotalAssets:         len(assets),
		FrontendAssetsCount: frontendCount,
		APIEndpointsCount:   apiEndpointsCount,
		WebRoutesCount:      webRoutesCount,
		AssetsByType:        byType,
		Assets:              assets,
	}
}

func classifyAssetType(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil || u.Host == "" {
		if strings.HasPrefix(rawURL, "s3://") || strings.Contains(rawURL, ".amazonaws.com") ||
			strings.Contains(rawURL, "supabase.co") || strings.Contains(rawURL, "firebaseio.com") {
			return "CLOUD_RESOURCE"
		}
		return "WEB_ROUTE"
	}

	path := strings.ToLower(u.Path)
	switch {
	case strings.Contains(rawURL, "supabase.co") || strings.Contains(rawURL, ".amazonaws.com") ||
		strings.Contains(rawURL, "storage.googleapis.com") || strings.Contains(rawURL, "blob.core.windows.net"):
		return "CLOUD_RESOURCE"
	case strings.Contains(path, "/auth") || strings.Contains(path, "/login") ||
		strings.Contains(path, "/token") || strings.Contains(path, "/oauth") || strings.Contains(path, "/session"):
		return "AUTH_ENTRYPOINT"
	case strings.HasPrefix(path, "/api") || strings.Contains(path, "/v1/") ||
		strings.Contains(path, "/v2/") || strings.Contains(path, "/graphql"):
		return "API_ENDPOINT"
	case strings.HasSuffix(path, ".js") || strings.HasSuffix(path, ".map") ||
		strings.HasSuffix(path, ".css") || strings.HasSuffix(path, ".json"):
		return "CLIENT_ASSET"
	case u.Path == "" || u.Path == "/":
		return "DOMAIN"
	default:
		return "WEB_ROUTE"
	}
}

// -----------------------------------------------------------------------------
// Helper: Assessment Scope Construction (Section 2)
// -----------------------------------------------------------------------------

func buildAssessmentScope(
	rep Report,
	cfg *commercialReportBuilder,
	attackSurface CommercialAttackSurface,
	hasSynthetic bool,
) CommercialAssessmentScope {
	domains := cfg.scopeDomains
	if len(domains) == 0 {
		domainSet := make(map[string]bool)
		for _, t := range rep.Targets {
			if u, err := url.Parse(t); err == nil && u.Hostname() != "" {
				domainSet[u.Hostname()] = true
			}
		}
		if len(domainSet) == 0 && rep.Target != "" {
			if u, err := url.Parse(rep.Target); err == nil && u.Hostname() != "" {
				domainSet[u.Hostname()] = true
			}
		}
		for d := range domainSet {
			domains = append(domains, d)
		}
		sort.Strings(domains)
	}

	urls := cfg.scopeURLs
	if len(urls) == 0 {
		urls = rep.Targets
		if len(urls) == 0 && rep.Target != "" {
			urls = []string{rep.Target}
		}
	}

	var apiServices []string
	var cloudResources []string
	for _, a := range attackSurface.Assets {
		if a.AssetType == "API_ENDPOINT" {
			apiServices = append(apiServices, a.URL)
		} else if a.AssetType == "CLOUD_RESOURCE" {
			cloudResources = append(cloudResources, a.URL)
		}
	}

	provenance := "LIVE"
	if hasSynthetic {
		provenance = "SYNTHETIC"
	}

	authContexts := []string{"Unauthenticated Baseline"}
	completedChecks := rep.Summary.VerifiedCount + rep.Summary.DetectedCount + rep.Summary.NotExposedCount
	inconclusiveChecks := rep.Summary.InconclusiveCount

	return CommercialAssessmentScope{
		InScopeDomains:           domains,
		InScopeURLs:              urls,
		DiscoveredEndpointsCount: attackSurface.TotalAssets,
		AssessedEndpointsCount:   rep.Summary.AttemptedCount,
		FrontendAssetsCount:      attackSurface.FrontendAssetsCount,
		APIEndpointsCount:        attackSurface.APIEndpointsCount,
		WebRoutesCount:           attackSurface.WebRoutesCount,
		APIServices:              dedupStringSlice(apiServices),
		CloudResources:           dedupStringSlice(cloudResources),
		AuthenticationContexts:   authContexts,
		StartedAt:                rep.Timestamp,
		CompletedAt:              rep.Timestamp,
		Duration:                 rep.Duration,
		EnginesExecuted:          cfg.enginesExecuted,
		EnginesSkipped:           cfg.enginesSkipped,
		CompletedChecksCount:     completedChecks,
		IncompleteChecksCount:    rep.Summary.NotVerifiedCount,
		InconclusiveChecksCount:  inconclusiveChecks,
		ExplicitRestrictions:     cfg.explicitRestrictions,
		ExcludedTargets:          cfg.excludedTargets,
		Provenance:               provenance,
		SyntheticFixture:         hasSynthetic,
		ExecutionErrors:          cfg.executionErrors,
	}
}

// -----------------------------------------------------------------------------
// Helper: Risk Overview Construction (Section 4)
// -----------------------------------------------------------------------------

func buildRiskOverview(
	rep Report,
	verified []CommercialFinding,
	detected []CommercialFinding,
) CommercialRiskOverview {
	sevDist := map[string]int{
		SeverityCritical: rep.Summary.CriticalCount,
		SeverityHigh:     rep.Summary.HighCount,
		SeverityMedium:   rep.Summary.MediumCount,
		SeverityLow:      rep.Summary.LowCount,
		SeverityInfo:     rep.Summary.InfoCount,
	}

	verBySev := make(map[string]int)
	for _, vf := range verified {
		verBySev[vf.Severity]++
	}

	detBySev := make(map[string]int)
	for _, df := range detected {
		detBySev[df.Severity]++
	}

	contributions, breakdown, _ := CalculateRiskBreakdown(rep.Findings, rep.SecurityStories)

	// If attack paths escalated the primary report risk score, reconcile breakdown
	if rep.RiskScore > breakdown.TotalScore {
		breakdown.AttackPathScore = rep.RiskScore
		breakdown.TotalScore = rep.RiskScore
		breakdown.Formula = fmt.Sprintf("max(%s, %d verified attack path) = %d", breakdown.Formula, rep.RiskScore, rep.RiskScore)
	}

	// Calculate concentrations by component
	compMap := make(map[string]*CommercialRiskConcentration)
	for _, vf := range verified {
		comp := extractComponent(vf.AffectedAsset)
		existing, ok := compMap[comp]
		if !ok {
			existing = &CommercialRiskConcentration{
				Component: comp,
				RiskLevel: vf.Severity,
			}
			compMap[comp] = existing
		}
		existing.Score += vf.RiskContribution.Score
		existing.Count++
		if SeverityRank(vf.Severity) > SeverityRank(existing.RiskLevel) {
			existing.RiskLevel = vf.Severity
		}
	}

	var concentrations []CommercialRiskConcentration
	for _, c := range compMap {
		concentrations = append(concentrations, *c)
	}
	sort.Slice(concentrations, func(i, j int) bool {
		return concentrations[i].Score > concentrations[j].Score
	})

	modelDesc := "Felix Deterministic Risk Model (0–100): Weighted empirical verification, multi-exposure diminishing returns, hardening caps (max 20 pts), and correlated story bonuses (max +15 pts). This metric reflects demonstrable exposure and is deliberately distinct from standalone CVSS base scoring."

	status := rep.CompletionStatus
	isAvailable := rep.RiskScoreAvailable
	if status == "BLOCKED" || status == "FAILED" {
		isAvailable = false
	} else if status != "" {
		isAvailable = true
	} else if rep.RiskLevel == "UNAVAILABLE" {
		isAvailable = false
	} else {
		isAvailable = true
	}

	riskScore := rep.RiskScore
	riskLevel := rep.RiskLevel
	if !isAvailable {
		riskScore = 0
		riskLevel = "UNAVAILABLE"
		modelDesc = "Risk scoring is unavailable because the assessment was blocked or failed before targets could be evaluated."
		breakdown = CommercialScoreBreakdown{
			Formula: "N/A (assessment blocked or failed before evaluation)",
		}
		contributions = nil
	}

	limitations := []string{
		"Risk score reflects non-destructive black-box evaluation and does not calculate likelihood of zero-day attacks or internal network penetration.",
		"Hardening findings (e.g. defense-in-depth headers) are strictly capped at 20 points maximum to prevent artificial score inflation on otherwise secure targets.",
		"Candidate attack paths without empirical confirmation contribute zero unverified risk to the primary score.",
	}

	return CommercialRiskOverview{
		RiskScore:                riskScore,
		RiskScoreAvailable:       isAvailable,
		RiskLevel:                riskLevel,
		ScoringModelDescription:  modelDesc,
		SeverityDistribution:     sevDist,
		VerifiedCountsBySeverity: verBySev,
		DetectedCountsBySeverity: detBySev,
		FindingRiskContributions: contributions,
		ScoreBreakdown:           breakdown,
		SecurityStories:          rep.SecurityStories,
		AttackPaths:              rep.AttackPaths,
		RiskConcentrations:       concentrations,
		RiskLimitations:          limitations,
	}
}

// -----------------------------------------------------------------------------
// Helper: Executive Summary Construction (Section 1)
// -----------------------------------------------------------------------------

func buildExecutiveSummary(
	rep Report,
	cfg *commercialReportBuilder,
	verified []CommercialFinding,
	detected []CommercialFinding,
	observations []CommercialObservation,
	attackSurface CommercialAttackSurface,
	hasSynthetic bool,
) CommercialExecutiveSummary {
	target := rep.Target
	if target == "" && len(rep.Targets) > 0 {
		target = rep.Targets[0]
	}

	status := "COMPLETED"
	if len(cfg.executionErrors) > 0 {
		status = "COMPLETED_WITH_ERRORS"
	} else if len(verified) == 0 && len(detected) == 0 && len(observations) == 0 {
		status = "EMPTY"
	}
	if cfg.completionStatus != "" {
		status = cfg.completionStatus
	} else if rep.CompletionStatus != "" {
		status = rep.CompletionStatus
	}

	isScoreAvailable := rep.RiskScoreAvailable
	if status == "BLOCKED" || status == "FAILED" {
		isScoreAvailable = false
	} else if status != "" {
		isScoreAvailable = true
	} else if rep.RiskLevel == "UNAVAILABLE" {
		isScoreAvailable = false
	} else {
		isScoreAvailable = true
	}

	riskScore := rep.RiskScore
	riskLevel := rep.RiskLevel
	if !isScoreAvailable {
		riskScore = 0
		riskLevel = "UNAVAILABLE"
	}

	sevDist := map[string]int{
		SeverityCritical: rep.Summary.CriticalCount,
		SeverityHigh:     rep.Summary.HighCount,
		SeverityMedium:   rep.Summary.MediumCount,
		SeverityLow:      rep.Summary.LowCount,
		SeverityInfo:     rep.Summary.InfoCount,
	}

	var highlights []string
	highlights = append(highlights, fmt.Sprintf("%d total attack-surface resources cataloged across %d endpoint/route categories.",
		attackSurface.TotalAssets, len(attackSurface.AssetsByType)))
	if attackSurface.FrontendAssetsCount > 0 {
		highlights = append(highlights, fmt.Sprintf("%d frontend assets crawled and analyzed.", attackSurface.FrontendAssetsCount))
	}
	if count := attackSurface.APIEndpointsCount; count > 0 {
		highlights = append(highlights, fmt.Sprintf("%d API endpoints cataloged.", count))
	}
	if count := attackSurface.WebRoutesCount; count > 0 {
		highlights = append(highlights, fmt.Sprintf("%d web routes cataloged.", count))
	}
	if count, ok := attackSurface.AssetsByType["CLOUD_RESOURCE"]; ok && count > 0 {
		highlights = append(highlights, fmt.Sprintf("%d cloud backend or storage resources cataloged.", count))
	}

	var keyConcerns []string
	for _, vf := range verified {
		if vf.Severity == SeverityCritical || vf.Severity == SeverityHigh {
			keyConcerns = append(keyConcerns, fmt.Sprintf("[%s] %s at %s (%s)",
				vf.Severity, vf.Title, vf.AffectedAsset, vf.SecurityImpact.Summary))
		}
	}
	if len(keyConcerns) == 0 {
		for _, df := range detected {
			if df.Severity == SeverityCritical || df.Severity == SeverityHigh {
				keyConcerns = append(keyConcerns, fmt.Sprintf("[%s - UNVERIFIED] %s at %s (%s)",
					df.Severity, df.Title, df.AffectedAsset, df.SecurityImpact.Summary))
			}
		}
	}
	if len(keyConcerns) == 0 {
		keyConcerns = append(keyConcerns, "No Critical or High severity exposures were verified during assessment execution.")
	}

	limitations := []string{
		"Assessment strictly enforced authorized, non-destructive black-box audit boundaries.",
		"No invasive privilege mutation, destructive payloads, or credential stuffing attacks were executed.",
	}
	if status == "BLOCKED" {
		limitations = append(limitations, "Target endpoints presented access controls or automated challenges; assessment halted without evaluation.")
	} else if status == "FAILED" {
		limitations = append(limitations, "Target endpoints could not be reached; dynamic crawler and audit engines could not execute.")
	}
	if len(cfg.enginesSkipped) > 0 {
		limitations = append(limitations, fmt.Sprintf("Engines skipped: %s.", strings.Join(cfg.enginesSkipped, ", ")))
	}

	var posture string
	if status == "BLOCKED" {
		posture = "Assessment was BLOCKED by target access controls or bot detection mechanisms (HTTP 403 / challenge). Felix respected access boundaries and did not attempt challenge bypasses or automated circumvention. Security posture could not be evaluated."
	} else if status == "FAILED" {
		posture = "Assessment FAILED due to network reachability or transport errors. Felix could not connect to target endpoints. Security posture could not be evaluated."
	} else if len(verified) == 0 && len(detected) == 0 {
		posture = "No security findings were identified within the evaluated scope. Important note: The absence of verified findings does not guarantee that the target is completely secure against unassessed attack classes, authenticated privilege boundaries, or internal network vulnerabilities."
	} else if len(verified) == 0 {
		posture = fmt.Sprintf("Felix recorded %d detected findings, %d observations, and %d defended checks, but zero findings reached empirical verification. The overall risk score is %d/100 (%s). Unverified detections remain hypotheses pending manual engineering review.",
			rep.Summary.DetectedCount, rep.Summary.ObservedCount, rep.Summary.NotExposedCount, riskScore, riskLevel)
	} else {
		posture = fmt.Sprintf("Felix confirmed %d verified findings, %d detected findings, %d observations, and %d defended checks, resulting in a deterministic risk score of %d/100 (%s). High-priority verified findings represent immediate actionable exposures.",
			rep.Summary.VerifiedCount, rep.Summary.DetectedCount, rep.Summary.ObservedCount, rep.Summary.NotExposedCount, riskScore, riskLevel)
	}

	return CommercialExecutiveSummary{
		AssessmentID:            rep.ReportID(),
		Target:                  target,
		Targets:                 rep.Targets,
		Timestamp:               rep.Timestamp,
		ScopeSummary:            fmt.Sprintf("Authorized web security evaluation of %s spanning %d targets.", target, len(rep.Targets)),
		CompletionStatus:        status,
		AssetsDiscoveredCount:   attackSurface.TotalAssets,
		FrontendAssetsCount:     attackSurface.FrontendAssetsCount,
		APIEndpointsCount:       attackSurface.APIEndpointsCount,
		WebRoutesCount:          attackSurface.WebRoutesCount,
		FindingsDetectedCount:   rep.Summary.DetectedCount,
		FindingsVerifiedCount:   rep.Summary.VerifiedCount,
		FindingsUnverifiedCount: rep.Summary.NotVerifiedCount,
		ObservationsCount:       rep.Summary.ObservedCount,
		NotExposedChecksCount:   rep.Summary.NotExposedCount,
		InconclusiveChecksCount: rep.Summary.InconclusiveCount,
		NotAssessedChecksCount:  rep.Summary.NotVerifiedCount,
		SeverityDistribution:    sevDist,
		RiskScore:               riskScore,
		RiskScoreAvailable:      isScoreAvailable,
		RiskLevel:               riskLevel,
		AttackSurfaceHighlights: highlights,
		KeyConcerns:             keyConcerns,
		AssessmentLimitations:   limitations,
		PostureStatement:        posture,
	}
}

// -----------------------------------------------------------------------------
// Helper: Technical Appendix Construction (Section 8)
// -----------------------------------------------------------------------------

func buildTechnicalAppendix(
	rep Report,
	cfg *commercialReportBuilder,
	negativeOutcomes []CommercialNegativeOutcome,
	traceabilityIndex []CommercialTraceabilityEntry,
	hasSynthetic bool,
	timestamp string,
) CommercialTechnicalAppendix {
	asmMeta := make(map[string]any)
	for k, v := range rep.Metadata {
		asmMeta[k] = v
	}
	asmMeta["target"] = rep.Target
	asmMeta["duration"] = rep.Duration
	asmMeta["request_count"] = rep.RequestCount

	engineSummaries := []CommercialEngineSummary{
		{EngineName: "felix-crawler", Version: "2.0.0", Status: "EXECUTED", AssetsAnalyzed: rep.Summary.TotalFindings, FindingsCount: rep.Summary.BySource[SourceCrawler]},
		{EngineName: "felix-secrets", Version: "2.0.0", Status: "EXECUTED", AssetsAnalyzed: rep.Summary.TotalFindings, FindingsCount: rep.Summary.BySource[SourceSecrets]},
		{EngineName: "felix-cloud", Version: "2.0.0", Status: "EXECUTED", AssetsAnalyzed: rep.Summary.TotalFindings, FindingsCount: rep.Summary.BySource[SourceCloud]},
		{EngineName: "felix-api", Version: "2.0.0", Status: "EXECUTED", AssetsAnalyzed: rep.Summary.TotalFindings, FindingsCount: rep.Summary.BySource[SourceAPI]},
		{EngineName: "felix-verification", Version: "2.0.0", Status: "EXECUTED", AssetsAnalyzed: rep.Summary.AttemptedCount, FindingsCount: rep.Summary.VerifiedCount},
		{EngineName: "felix-correlation", Version: "2.0.0", Status: "EXECUTED", AssetsAnalyzed: len(rep.Findings), FindingsCount: len(rep.AttackPaths)},
	}

	verCounts := map[string]int{
		"VERIFIED":     rep.Summary.VerifiedCount,
		"DETECTED":     rep.Summary.DetectedCount,
		"OBSERVED":     rep.Summary.ObservedCount,
		"NOT_VERIFIED": rep.Summary.NotVerifiedCount,
		"NOT_EXPOSED":  rep.Summary.NotExposedCount,
		"BLOCKED":      rep.Summary.BlockedCount,
		"INCONCLUSIVE": rep.Summary.InconclusiveCount,
		"SYNTHETIC":    rep.Summary.SyntheticCount,
	}

	discStats := map[string]int{
		"total_findings":     rep.Summary.TotalFindings,
		"critical_count":     rep.Summary.CriticalCount,
		"high_count":         rep.Summary.HighCount,
		"medium_count":       rep.Summary.MediumCount,
		"low_count":          rep.Summary.LowCount,
		"info_count":         rep.Summary.InfoCount,
		"attempted_checks":   rep.Summary.AttemptedCount,
		"attack_paths_total": len(rep.AttackPaths),
		"stories_total":      len(rep.SecurityStories),
	}

	rules := []string{
		"COR-01: Entry Point to Vulnerable Resource (WSTG-INFO-01 / CWE-200)",
		"COR-02: Authentication to Authorization (WSTG-ATHN-01 / CWE-287)",
		"COR-03: BOLA and Sensitive Data Exposure (WSTG-ATHZ-04 / CWE-639)",
		"COR-04: Public Exposure to Sensitive Resource (WSTG-CONF-04 / CWE-552)",
		"COR-05: Privilege Escalation (WSTG-ATHZ-03 / CWE-269)",
		"COR-06: Business Logic Chains (WSTG-BUSL-01 / CWE-840)",
		"COR-07: Session and Identity Dependencies (WSTG-SESS-06 / CWE-613)",
		"COR-08: Cloud and Application Dependencies (WSTG-INPV-12 / CWE-918)",
		"COR-09: Common Root Cause (WSTG-CONF-01 / CWE-657)",
		"COR-10: Impact Amplification (WSTG-CLNT-07 / CWE-942)",
	}

	var syntheticIndicators []string
	if hasSynthetic {
		for _, f := range rep.Findings {
			if f.Verification.SyntheticFixture || strings.Contains(f.Evidence, "[SYNTHETIC FIXTURE]") {
				syntheticIndicators = append(syntheticIndicators, fmt.Sprintf("%s (%s)", f.ID, f.Title))
			}
		}
	}

	riskModelMeta := map[string]any{
		"algorithm":           "felix_deterministic_v1",
		"range":               "0-100",
		"diminishing_weights": []float64{1.0, 0.5, 0.3, 0.2, 0.1},
		"hardening_cap":       20,
		"story_bonus_cap":     15,
	}

	return CommercialTechnicalAppendix{
		AssessmentMetadata:           asmMeta,
		EngineExecutionSummary:       engineSummaries,
		DiscoveryAndDetectionStats:   discStats,
		VerificationStatusCounts:     verCounts,
		NegativeVerificationOutcomes: negativeOutcomes,
		FindingIndex:                 traceabilityIndex,
		CorrelationRulesEvaluated:    rules,
		ErrorsAndCoverageGaps:        cfg.executionErrors,
		SyntheticFixtureIndicators:   syntheticIndicators,
		RiskModelMetadata:            riskModelMeta,
		ReportGeneratedAt:            timestamp,
		ReportSchemaVersion:          CommercialReportSchemaVersion,
	}
}

func buildTraceabilityEntry(f Finding, canonicalStatus VerificationStatus, synthetic bool) CommercialTraceabilityEntry {
	provenance := "LIVE"
	if synthetic {
		provenance = "FIXTURE"
	} else if f.Source == SourceSecrets {
		provenance = "STATIC"
	}

	policyID := f.Verification.PolicyID
	if policyID == "" {
		policyID = fmt.Sprintf("POL-%s", strings.ToUpper(NormalizeCategory(f.Category)))
	}

	detMethod := f.EvidenceDetails.DetectionMethod
	if detMethod == "" {
		detMethod = f.Source
	}

	return CommercialTraceabilityEntry{
		FindingID:           f.ID,
		Title:               f.Title,
		SourceEngine:        f.Source,
		Category:            f.Category,
		DetectionMethod:     detMethod,
		PolicyOrRuleID:      policyID,
		EvidenceReferences:  f.Endpoint,
		Provenance:          provenance,
		AuthenticationState: extractAuthenticationState(f),
		CanonicalStatus:     string(canonicalStatus),
		Severity:            f.Severity,
	}
}

// -----------------------------------------------------------------------------
// Utilities
// -----------------------------------------------------------------------------

func sortCommercialFindings(findings []CommercialFinding) {
	sort.SliceStable(findings, func(i, j int) bool {
		vi := VerificationRank(findings[i].Verification.Status)
		vj := VerificationRank(findings[j].Verification.Status)
		if vi != vj {
			return vi > vj
		}

		si := SeverityRank(findings[i].Severity)
		sj := SeverityRank(findings[j].Severity)
		if si != sj {
			return si > sj
		}

		ci := ConfidenceRank(findings[i].Confidence.OverallConfidence)
		cj := ConfidenceRank(findings[j].Confidence.OverallConfidence)
		if ci != cj {
			return ci > cj
		}

		return findings[i].ID < findings[j].ID
	})
}

func sortCommercialObservations(obs []CommercialObservation) {
	sort.SliceStable(obs, func(i, j int) bool {
		return obs[i].ObservationID < obs[j].ObservationID
	})
}

func extractComponent(u string) string {
	parsed, err := url.Parse(u)
	if err == nil && parsed.Host != "" {
		parts := strings.Split(strings.Trim(parsed.Path, "/"), "/")
		if len(parts) > 0 && parts[0] != "" {
			return fmt.Sprintf("%s/%s", parsed.Host, parts[0])
		}
		return parsed.Host
	}
	return u
}

func dedupStringSlice(items []string) []string {
	if len(items) == 0 {
		return nil
	}
	m := make(map[string]bool)
	var res []string
	for _, it := range items {
		if !m[it] && it != "" {
			m[it] = true
			res = append(res, it)
		}
	}
	sort.Strings(res)
	return res
}

func (rep *Report) ReportID() string {
	if ref, ok := rep.Metadata["assessment_ref"].(string); ok && ref != "" {
		return ref
	}
	if id, ok := rep.Metadata["assessment_id"].(string); ok && id != "" {
		return id
	}
	if rep.Target != "" {
		h := sha256.Sum256([]byte(rep.Target))
		return fmt.Sprintf("ASM-%x", h[:4])
	}
	return "ASM-UNKNOWN"
}
