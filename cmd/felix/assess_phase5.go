package main

import (
	"context"
	"fmt"
	"net/http"
	"regexp"
	"strings"

	"felix/pkg/assessment"
	"felix/pkg/auth"
	"felix/pkg/correlation"
	"felix/pkg/investigation"
	"felix/pkg/report"
	"felix/pkg/secrets"
)

var (
	phase5BearerRe = regexp.MustCompile(`(?i)\bbearer\s+([A-Za-z0-9\-._~+/]+=*)`)
	phase5JWTRe    = regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}(?:\.[A-Za-z0-9_-]*)?\b`)
	phase5AWSRe    = regexp.MustCompile(`\b(?:AKIA|ASIA|AROA)[A-Z0-9]{12,}[A-Z0-9]*\b`)
	phase5GHRe     = regexp.MustCompile(`\bgh[pousr]_[A-Za-z0-9_]{12,}\b`)
	phase5GoogleRe = regexp.MustCompile(`\bAIza[A-Za-z0-9_\-]{20,}\b`)
	phase5JSONTok  = regexp.MustCompile(`(?i)"(?:access_token|api_key|apikey|token|secret|auth_token|bearer)"\s*:\s*"([^"\r\n]{8,})"`)
)

// phase5PipelineOutput holds sanitized Phase 5 correlation and validation outputs.
type phase5PipelineOutput struct {
	ValidatedPaths         []correlation.AttackPath
	ValidatedRelationships []correlation.Relationship
	CorrelationSummary     *correlation.Summary
	ValidatedChains        []investigation.AttackChain
	CredentialValidations  []correlation.CredentialVerificationResult
}

// extractTransientCredentialTokens recovers credential artifacts from raw in-memory findings
// solely for authorized same-origin HTTP usability probes. Returned map is never serialized
// and is wiped immediately after ValidateAttackPaths completes.
func extractTransientCredentialTokens(findings []report.Finding) map[string]string {
	tokens := make(map[string]string)
	for _, f := range findings {
		if f.EvidenceDetails.Details != nil {
			if tok := strings.TrimSpace(f.EvidenceDetails.Details["candidate_token"]); tok != "" {
				tokens[f.ID] = tok
				continue
			}
		}
		blob := strings.Join([]string{
			f.Evidence,
			f.EvidenceDetails.Observation,
			f.EvidenceDetails.ObservedBehavior,
		}, "\n")
		if tok := extractTokenFromBlob(blob); tok != "" {
			tokens[f.ID] = tok
		}
	}
	return tokens
}

func extractTokenFromBlob(blob string) string {
	if strings.TrimSpace(blob) == "" {
		return ""
	}
	if m := phase5JWTRe.FindString(blob); m != "" {
		return strings.TrimSpace(m)
	}
	if m := phase5BearerRe.FindStringSubmatch(blob); len(m) > 1 && !strings.Contains(m[1], "REDACTED") {
		return strings.TrimSpace(m[1])
	}
	if m := phase5AWSRe.FindString(blob); m != "" {
		return strings.TrimSpace(m)
	}
	if m := phase5GHRe.FindString(blob); m != "" {
		return strings.TrimSpace(m)
	}
	if m := phase5GoogleRe.FindString(blob); m != "" {
		return strings.TrimSpace(m)
	}
	if m := phase5JSONTok.FindStringSubmatch(blob); len(m) > 1 && !strings.Contains(m[1], "REDACTED") {
		return strings.TrimSpace(m[1])
	}
	return ""
}

// sanitizeFindingsSlice sanitizes every finding in-place copy for downstream correlation & reporting.
func sanitizeFindingsSlice(findings []report.Finding) []report.Finding {
	out := make([]report.Finding, len(findings))
	for i, f := range findings {
		cf := report.SanitizeFinding(f)
		if cf.EvidenceDetails.Details != nil {
			if _, ok := cf.EvidenceDetails.Details["candidate_token"]; ok {
				cf.EvidenceDetails.Details["candidate_token"] = "[REDACTED]"
			}
		}
		out[i] = cf
	}
	return out
}

// sanitizeInvestigatedSlice ensures investigated_findings.json never persists raw secrets or tokens.
func sanitizeInvestigatedSlice(in []*investigation.InvestigatedFinding) []*investigation.InvestigatedFinding {
	out := make([]*investigation.InvestigatedFinding, 0, len(in))
	for _, inf := range in {
		if inf == nil {
			continue
		}
		copyInf := *inf
		copyInf.Finding = report.SanitizeFinding(inf.Finding)
		if copyInf.Finding.EvidenceDetails.Details != nil {
			if _, ok := copyInf.Finding.EvidenceDetails.Details["candidate_token"]; ok {
				copyInf.Finding.EvidenceDetails.Details["candidate_token"] = "[REDACTED]"
			}
		}
		if inf.EvidenceBundle != nil {
			eb := *inf.EvidenceBundle
			eb.SanitizedRequest = secrets.RedactText(eb.SanitizedRequest)
			eb.SanitizedResponse = secrets.RedactText(eb.SanitizedResponse)
			eb.SafeCurlCommand = secrets.RedactText(eb.SafeCurlCommand)
			eb.ProofSummary = secrets.RedactText(eb.ProofSummary)
			if len(eb.ReproductionSteps) > 0 {
				steps := make([]string, len(eb.ReproductionSteps))
				for i, st := range eb.ReproductionSteps {
					steps[i] = secrets.RedactText(st)
				}
				eb.ReproductionSteps = steps
			}
			copyInf.EvidenceBundle = &eb
		}
		if inf.AttackPath != nil {
			ap := *inf.AttackPath
			ap.InitialEntryPoint = secrets.SanitizeURL(ap.InitialEntryPoint)
			ap.AffectedEndpoint = secrets.SanitizeURL(ap.AffectedEndpoint)
			ap.ObservedBehavior = secrets.RedactText(ap.ObservedBehavior)
			ap.DemonstratedImpact = secrets.RedactText(ap.DemonstratedImpact)
			copyInf.AttackPath = &ap
		}
		out = append(out, &copyInf)
	}
	return out
}

// buildValidatedAttackChains projects Phase 5 validated paths into investigation.AttackChain records
// so standalone attack_chains.json and console summaries stay consistent with rep.AttackPaths.
func buildValidatedAttackChains(paths []correlation.AttackPath) []investigation.AttackChain {
	chains := make([]investigation.AttackChain, 0, len(paths))
	for _, p := range paths {
		var links []investigation.AttackChainLink
		var parts []string
		for _, n := range p.Nodes {
			parts = append(parts, fmt.Sprintf("[%s]", secrets.SanitizeURL(firstNonEmptyString(n.Endpoint, n.Target, n.ID))))
		}
		for _, e := range p.Edges {
			links = append(links, investigation.AttackChainLink{
				FromFindingID:    e.SourceFindingID,
				FromTitle:        secrets.RedactText(e.SourceTitle),
				ToFindingID:      e.TargetFindingID,
				ToTitle:          secrets.RedactText(e.TargetTitle),
				DependencyType:   string(e.Type),
				DemonstratedLink: e.ValidationStatus == correlation.ValidationConfirmed || e.ReachabilityStatus == correlation.ReachabilityReachable,
				Explanation:      secrets.RedactText(e.Explanation),
			})
		}

		st := investigation.StatusPotential
		switch p.Status {
		case correlation.PathConfirmed, correlation.PathVerified:
			st = investigation.StatusConfirmed
		case correlation.PathHighConfidence:
			st = investigation.StatusHighConfidence
		case correlation.PathNotTested:
			st = investigation.StatusNotTested
		case correlation.PathNotReachable, correlation.PathInconclusive:
			st = investigation.StatusNotValidated
		}

		chains = append(chains, investigation.AttackChain{
			ID:               p.ID,
			Title:            secrets.RedactText(p.Title),
			Status:           st,
			Summary:          secrets.RedactText(firstNonEmptyString(p.RiskRationale, p.DemonstratedImpact, p.TerminalImpact)),
			FindingIDs:       append([]string{}, p.NodeIDs...),
			Links:            links,
			DemonstratedPath: strings.Join(parts, " -> "),
		})
	}
	return chains
}

func firstNonEmptyString(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

// runPhase5AttackPathPipeline executes strict evidence-backed correlation, credential validation,
// and step-by-step transition reachability validation against sanitized findings and updates rep.
func runPhase5AttackPathPipeline(
	ctx context.Context,
	rt *AssessmentRuntimeContext,
	rawFindings []report.Finding,
	rep *report.Report,
) *phase5PipelineOutput {
	out := &phase5PipelineOutput{}
	if rep == nil {
		return out
	}

	// Capture transient credential artifacts solely in-memory prior to full sanitization.
	rawCredTokens := extractTransientCredentialTokens(rawFindings)
	defer func() {
		for k := range rawCredTokens {
			rawCredTokens[k] = ""
		}
		rawCredTokens = nil
	}()

	// Always sanitize findings before correlation and final report construction.
	sourceFindings := rawFindings
	if len(rep.Findings) > 0 {
		sourceFindings = rep.Findings
	}
	sanitizedFindings := sanitizeFindingsSlice(sourceFindings)
	rep.Findings = sanitizedFindings

	var idClients map[auth.IdentityContext]*http.Client
	var knownIdentities map[auth.IdentityContext]string
	var idMgr *auth.IdentityManager
	var baseClient *http.Client
	var targetURL string
	var scopeAllowed func(string) bool
	var allowLoopback, allowPrivate, allowStateChanging, syntheticFixture, safeMode bool
	var fixtureHosts []string

	if rt != nil {
		idMgr = rt.IdentityMgr
		baseClient = rt.Client
		targetURL = rt.TargetURL
		scopeAllowed = rt.ScopeAllowed
		allowLoopback = rt.Opts.AllowLoopback
		allowPrivate = rt.Opts.AllowPrivate
		allowStateChanging = rt.Opts.AllowStateChanging
		syntheticFixture = rt.Opts.SyntheticFixture
		fixtureHosts = rt.Opts.FixtureHosts
		safeMode = rt.Opts.SafeMode

		if rt.IdentityMgr != nil {
			configured := rt.IdentityMgr.ConfiguredIdentities()
			if len(configured) > 0 {
				idClients = make(map[auth.IdentityContext]*http.Client, len(configured))
				knownIdentities = make(map[auth.IdentityContext]string, len(configured))
				for _, ic := range configured {
					idClients[ic] = rt.IdentityMgr.ClientFor(ic)
					uname := strings.TrimSpace(rt.IdentityMgr.IdentityUsername(ic))
					if uname != "" {
						knownIdentities[ic] = uname
					} else {
						knownIdentities[ic] = string(rt.IdentityMgr.IdentityRole(ic))
					}
				}
			}
		}
	}

	corrCfg := correlation.DefaultConfig()
	corrCfg.RequireValidatedTransitions = true
	corrCfg.AllowSynthetic = syntheticFixture
	corrEngine := correlation.NewEngine(corrCfg)

	corrSummary, corrPaths, corrRels, err := corrEngine.Correlate(ctx, sanitizedFindings)
	if err != nil {
		return out
	}

	validator := correlation.NewPhase5Validator(correlation.ValidationOptions{
		TargetURL:              targetURL,
		BaseClient:             baseClient,
		IdentityClients:        idClients,
		IdentityManager:        idMgr,
		ScopeAllowed:           scopeAllowed,
		AllowLoopback:          allowLoopback,
		AllowPrivate:           allowPrivate,
		AllowStateChanging:     allowStateChanging,
		SyntheticFixture:       syntheticFixture,
		AuthorizedFixtureHosts: fixtureHosts,
		SafeMode:               safeMode,
		KnownIdentities:        knownIdentities,
		RawCredentialTokens:    rawCredTokens,
	})

	valPaths, valRels, valSummary := validator.ValidateAttackPaths(ctx, sanitizedFindings, corrPaths, corrRels, corrSummary)

	// Recompute bottlenecks strictly from validated Phase 5 paths.
	bottleneckRes := correlation.AnalyzeRemediationBottlenecks(valPaths, correlation.NormalizeFindings(sanitizedFindings), nil)
	if valSummary != nil {
		valSummary.BottleneckAnalysis = bottleneckRes
	}

	var repPaths []report.AttackPathSummary
	var repStories []report.SecurityStory
	seenStoryIDs := make(map[string]bool)
	for _, p := range valPaths {
		repPaths = append(repPaths, assessment.ConvertAttackPathToSummary(p))
		if p.SecurityStory.ID != "" && !seenStoryIDs[p.SecurityStory.ID] {
			seenStoryIDs[p.SecurityStory.ID] = true
			repStories = append(repStories, p.SecurityStory)
		}
	}

	rep.RemediationBottlenecks = assessment.ConvertBottleneckAnalysisToReport(bottleneckRes)
	if len(repStories) > 0 {
		report.AttachSecurityStories(rep, repStories)
	}
	report.AttachAttackPaths(rep, repPaths)

	out.ValidatedPaths = valPaths
	out.ValidatedRelationships = valRels
	out.CorrelationSummary = valSummary
	if valSummary != nil {
		out.CredentialValidations = valSummary.CredentialValidations
	}
	out.ValidatedChains = buildValidatedAttackChains(valPaths)
	return out
}
