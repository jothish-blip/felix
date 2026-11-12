package validation

import (
	"fmt"
	"math"
	"net/url"
	"sort"
	"strings"
	"time"

	"felix/pkg/investigation"
	"felix/pkg/report"
)

const zScore95 = 1.959963984540054

// CanonicalVulnClass maps heterogeneous finding categories/titles and ground-truth labels
// into a uniform taxonomy for accurate per-class evaluation.
func CanonicalVulnClass(category, title, id string) string {
	joined := strings.ToUpper(strings.TrimSpace(category + " " + title + " " + id))
	switch {
	case strings.Contains(joined, "ATTACK SURFACE DISCOVERY") || strings.HasPrefix(strings.ToUpper(strings.TrimSpace(id)), "RECON-INFO"):
		return "DISCOVERY_OBSERVATION"
	case strings.Contains(joined, "BOLA") || strings.Contains(joined, "IDOR") || strings.Contains(joined, "API1:2023"):
		return "BOLA"
	case strings.Contains(joined, "BFLA") || strings.Contains(joined, "API5:2023"):
		return "BFLA"
	case strings.Contains(joined, "BOPLA") || strings.Contains(joined, "API3:2023") || strings.Contains(joined, "MASS ASSIGNMENT") || strings.Contains(joined, "EXCESSIVE DATA EXPOSURE"):
		return "BOPLA"
	case strings.Contains(joined, "CMDI") || strings.Contains(joined, "COMMAND INJECTION"):
		return "CMDI"
	case strings.Contains(joined, "NOSQL"):
		return "NOSQLI"
	case strings.Contains(joined, "SQLI") || strings.Contains(joined, "SQL INJECTION"):
		return "SQLI"
	case strings.Contains(joined, "SSTI") || strings.Contains(joined, "TEMPLATE INJECTION"):
		return "SSTI"
	case strings.Contains(joined, "SSRF") || strings.Contains(joined, "SERVER-SIDE REQUEST FORGERY"):
		return "SSRF"
	case strings.Contains(joined, "XSS") || strings.Contains(joined, "CROSS-SITE SCRIPTING"):
		return "XSS"
	case strings.Contains(joined, "TRAVERSAL") || strings.Contains(joined, "LFI") || strings.Contains(joined, "FILE INCLUSION"):
		return "PATH_TRAVERSAL"
	case strings.Contains(joined, "OPEN REDIRECT"):
		return "OPEN_REDIRECT"
	case strings.Contains(joined, "CORS"):
		return "CORS"
	case strings.Contains(joined, "MISSING SECURITY HEADER") || strings.Contains(joined, "CLICKJACKING") ||
		strings.Contains(joined, "SECURITY_HEADERS") || strings.HasPrefix(strings.ToUpper(strings.TrimSpace(id)), "HDR-"):
		return "SECURITY_HEADERS"
	case strings.Contains(joined, "INFO_DISCLOSURE") || strings.Contains(joined, "INFORMATION DISCLOSURE") ||
		strings.Contains(joined, "SENSITIVE CONFIGURATION") || strings.Contains(joined, "WV-INFODISC") || strings.Contains(joined, "SECRET"):
		return "INFO_DISCLOSURE"
	case strings.Contains(joined, "AUTH") || strings.Contains(joined, "JWT") || strings.Contains(joined, "COOKIE") || strings.Contains(joined, "SESSION"):
		return "AUTH_SESSION"
	case strings.Contains(joined, "MISCONF") || strings.Contains(joined, "MISCONFIG"):
		return "MISCONFIG"
	default:
		clean := strings.ToUpper(strings.TrimSpace(category))
		if clean == "" {
			return "OTHER"
		}
		return clean
	}
}

// ComputeWilson95 calculates the exact 95% Wilson score confidence interval for k successes in n trials.
func ComputeWilson95(successes, trials int) WilsonInterval {
	if trials <= 0 || successes < 0 || successes > trials {
		return WilsonInterval{Valid: false}
	}
	n := float64(trials)
	p := float64(successes) / n
	z2 := zScore95 * zScore95
	denom := 1.0 + z2/n
	center := (p + z2/(2.0*n)) / denom
	half := (zScore95 * math.Sqrt((p*(1.0-p)+z2/(4.0*n))/n)) / denom
	lo := math.Max(0.0, center-half)
	hi := math.Min(1.0, center+half)
	return WilsonInterval{
		Valid:   true,
		Lower95: round4(lo),
		Upper95: round4(hi),
	}
}

// ComputeRate builds a denominator-safe MetricRate with a 95% Wilson CI.
func ComputeRate(numerator, denominator int, zeroReason string) MetricRate {
	if denominator <= 0 {
		return MetricRate{
			Numerator:     numerator,
			Denominator:   denominator,
			Valid:         false,
			InvalidReason: zeroReason,
		}
	}
	val := float64(numerator) / float64(denominator)
	return MetricRate{
		Value:       round4(val),
		Numerator:   numerator,
		Denominator: denominator,
		Valid:       true,
		CI95:        ComputeWilson95(numerator, denominator),
	}
}

// ComputeF1 derives the harmonic mean of Precision and Recall when both denominators are valid.
func ComputeF1(tp, fp, fn int) MetricRate {
	denom := 2*tp + fp + fn
	if denom <= 0 || (tp+fp) <= 0 || (tp+fn) <= 0 {
		return MetricRate{
			Numerator:     2 * tp,
			Denominator:   denom,
			Valid:         false,
			InvalidReason: "undefined when TP+FP == 0 or TP+FN == 0",
		}
	}
	return MetricRate{
		Value:       round4(float64(2*tp) / float64(denom)),
		Numerator:   2 * tp,
		Denominator: denom,
		Valid:       true,
	}
}

func round4(v float64) float64 {
	return math.Round(v*10000.0) / 10000.0
}

func isConfigMissing(requires string, manifest *CampaignManifest, authz *report.AuthorizationReportSummary) bool {
	req := strings.ToUpper(strings.TrimSpace(requires))
	if req == "" {
		return false
	}
	if manifest == nil {
		return false
	}
	switch req {
	case "MULTI_ROLE":
		if len(manifest.RolesConfigured) >= 2 {
			return false
		}
		if authz != nil && authz.QuantitativeCoverage.IdentitiesConfigured >= 2 {
			return false
		}
		return true
	case "STATE_CHANGING":
		return !manifest.AllowStateChanging
	case "SAFE_ONLY":
		return false
	default:
		return false
	}
}

func extractEndpointPath(raw string) string {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return "/"
	}
	if strings.HasPrefix(trimmed, "http://") || strings.HasPrefix(trimmed, "https://") {
		if u, err := url.Parse(trimmed); err == nil {
			if u.Path != "" {
				return u.Path
			}
			return "/"
		}
	}
	return trimmed
}

func matchEntryToFinding(entry GroundTruthEntry, f report.Finding) bool {
	fClass := CanonicalVulnClass(f.Category, f.Title, f.ID)
	if fClass == "DISCOVERY_OBSERVATION" {
		return false
	}

	gtClass := CanonicalVulnClass(entry.VulnClass, entry.Description, entry.ID)
	classMatched := gtClass == fClass
	for _, alt := range entry.Matcher.VulnClasses {
		if CanonicalVulnClass(alt, "", "") == fClass {
			classMatched = true
			break
		}
	}
	if !classMatched {
		return false
	}

	if len(entry.Matcher.Methods) > 0 {
		mMatch := false
		for _, m := range entry.Matcher.Methods {
			if strings.EqualFold(strings.TrimSpace(m), strings.TrimSpace(f.Method)) {
				mMatch = true
				break
			}
		}
		if !mMatch {
			return false
		}
	} else if entry.Method != "" && !strings.EqualFold(entry.Method, "ANY") && f.Method != "" {
		if !strings.EqualFold(entry.Method, f.Method) {
			return false
		}
	}

	if len(entry.Matcher.TitleContains) > 0 {
		tMatch := false
		tUpper := strings.ToUpper(f.Title + " " + f.Description)
		for _, kw := range entry.Matcher.TitleContains {
			if strings.Contains(tUpper, strings.ToUpper(kw)) {
				tMatch = true
				break
			}
		}
		if !tMatch {
			return false
		}
	}

	ep := strings.ToLower(extractEndpointPath(f.Endpoint))
	targetPath := strings.ToLower(extractEndpointPath(f.Target))
	if len(entry.Matcher.PathContains) > 0 {
		for _, sub := range entry.Matcher.PathContains {
			sLow := strings.ToLower(sub)
			if strings.Contains(ep, sLow) || strings.Contains(targetPath, sLow) {
				return true
			}
		}
		return false
	}

	gtPath := strings.ToLower(strings.TrimSpace(entry.EndpointPattern))
	if gtPath == "" || gtPath == "/" {
		return ep == "/" || ep == "" || gtClass == "SECURITY_HEADERS"
	}
	// Match template prefix before placeholder brace e.g. /books/v1/{book_title}
	prefix := gtPath
	if idx := strings.Index(prefix, "{"); idx > 0 {
		prefix = prefix[:idx]
	}
	return ep == gtPath || strings.HasPrefix(ep, strings.TrimRight(prefix, "/"))
}

func checkNegativeControlCoverage(entry GroundTruthEntry, authz *report.AuthorizationReportSummary, rep *report.Report, manifest *CampaignManifest) (tested bool, inconclusive bool, reason string) {
	gtPath := strings.ToLower(strings.TrimSpace(entry.EndpointPattern))
	prefix := gtPath
	if idx := strings.Index(prefix, "{"); idx > 0 {
		prefix = strings.TrimRight(prefix[:idx], "/")
	}
	gtClass := CanonicalVulnClass(entry.VulnClass, entry.Description, entry.ID)

	// Security headers are evaluated deterministically only if header checks ran (explicit SECURITY_HEADERS finding/observation or non-custom profile root crawl).
	if gtClass == "SECURITY_HEADERS" && rep != nil {
		nonCustomProfile := manifest != nil && !strings.EqualFold(strings.TrimSpace(manifest.Profile), "custom")
		for _, f := range rep.Findings {
			cls := CanonicalVulnClass(f.Category, f.Title, f.ID)
			if cls == "SECURITY_HEADERS" || (cls == "DISCOVERY_OBSERVATION" && nonCustomProfile) {
				return true, false, "target root headers inspected without triggering finding on present control header"
			}
		}
	}

	if authz == nil {
		return false, false, "no coverage artifact confirming deterministic negative control execution"
	}

	foundDeterminative := false
	foundInconclusive := false
	for _, item := range authz.CoverageItems {
		itemClass := CanonicalVulnClass(item.Engine, item.Item, item.Engine)
		if itemClass != gtClass && gtClass != "OTHER" {
			continue
		}
		epLow := strings.ToLower(extractEndpointPath(item.Item))
		if gtPath != "" && gtPath != "/" && !strings.Contains(epLow, prefix) && epLow != gtPath {
			continue
		}
		st := strings.ToUpper(strings.TrimSpace(item.Outcome))
		switch st {
		case "NOT_VULNERABLE", "VERIFIED", "DETECTED":
			foundDeterminative = true
		case "INCONCLUSIVE":
			foundInconclusive = true
		}
	}
	if foundDeterminative {
		return true, false, "coverage artifact confirms determinative check with zero findings"
	}
	if foundInconclusive {
		return false, true, "coverage artifact returned INCONCLUSIVE; never counted as True Negative"
	}
	return false, false, "negative control endpoint was not deterministically tested"
}

// EvaluateAccuracy compares an independent GroundTruthRegistry against FELIX outputs while strictly
// enforcing verified-vs-candidate separation, inconclusive-vs-TN separation, and valid denominators.
func EvaluateAccuracy(
	reg *GroundTruthRegistry,
	rep *report.Report,
	authz *report.AuthorizationReportSummary,
	retestVerdicts []*investigation.RetestVerdict,
	retestExpected []RetestExpectedItem,
	manifest *CampaignManifest,
	now time.Time,
) (*AccuracyEvaluationReport, error) {
	if reg == nil {
		return nil, fmt.Errorf("ground-truth registry is required")
	}
	if rep == nil {
		return nil, fmt.Errorf("assessment report is required")
	}
	seenGTIDs := make(map[string]bool, len(reg.Entries))
	for idx, entry := range reg.Entries {
		id := strings.TrimSpace(entry.ID)
		if id == "" {
			return nil, fmt.Errorf("ground-truth entry at index %d has empty ID", idx)
		}
		if seenGTIDs[id] {
			return nil, fmt.Errorf("duplicate ground-truth entry ID %q", id)
		}
		seenGTIDs[id] = true
		switch entry.ExpectedStatus {
		case GTVulnerable, GTNegativeControl, GTExcludedScope, GTOutOfScope:
		default:
			return nil, fmt.Errorf("ground-truth entry %q has invalid ExpectedStatus %q", id, entry.ExpectedStatus)
		}
	}
	seenRetestIDs := make(map[string]bool, len(retestExpected))
	for idx, item := range retestExpected {
		fid := strings.TrimSpace(item.FindingID)
		if fid == "" {
			return nil, fmt.Errorf("retest expected item at index %d has empty FindingID", idx)
		}
		if seenRetestIDs[fid] {
			return nil, fmt.Errorf("duplicate retest expected FindingID %q", fid)
		}
		seenRetestIDs[fid] = true
		switch strings.ToUpper(strings.TrimSpace(item.ExpectedAction)) {
		case "FIXED", "STILL_PRESENT":
		default:
			return nil, fmt.Errorf("retest expected item %q has invalid ExpectedAction %q", fid, item.ExpectedAction)
		}
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}

	gtHash, err := CanonicalGroundTruthSHA256(reg)
	if err != nil {
		return nil, err
	}
	notes, manifestOK, blindOK := VerifyCampaignBlindness(reg, manifest)

	targetName := reg.Application
	campaignID := ""
	if manifest != nil {
		if manifest.TargetName != "" {
			targetName = manifest.TargetName
		}
		campaignID = manifest.ManifestID
	}

	eval := &AccuracyEvaluationReport{
		SchemaVersion:            "phase8-accuracy-v1",
		TargetName:               targetName,
		RegistryID:               reg.RegistryID,
		CampaignID:               campaignID,
		EvaluatedAt:              now.UTC(),
		GroundTruthSHA256:        gtHash,
		ManifestIntegrityOK:      manifestOK,
		BlindExecutionVerified:   blindOK,
		BlindnessNotes:           notes,
		ClassBreakdown:           make(map[string]*ClassMetrics),
		RedactionAudit:           AuditReportRedaction(rep),
		FindingsCountReported:    len(rep.Findings),
		SummaryTotalReported:     rep.Summary.TotalFindings,
		ReportSummaryConsistent:  rep.Summary.TotalFindings == len(rep.Findings),
		UniversalAccuracyClaimed: false,
		Disclaimer:               "Metrics measure empirical performance strictly on the registered target, scope, and evaluated population. Zero universal accuracy claim is made.",
	}

	getClass := func(cls string) *ClassMetrics {
		cm, ok := eval.ClassBreakdown[cls]
		if !ok {
			cm = &ClassMetrics{VulnClass: cls}
			eval.ClassBreakdown[cls] = cm
		}
		return cm
	}

	usedFindings := make(map[int]bool)
	satisfiedTPIDs := make(map[string]bool)

	// 1. Evaluate every registered ground-truth entry independently.
	for _, entry := range reg.Entries {
		cls := CanonicalVulnClass(entry.VulnClass, entry.Description, entry.ID)
		cm := getClass(cls)

		if !entry.InScope || entry.ExpectedStatus == GTOutOfScope || entry.ExpectedStatus == GTExcludedScope {
			eval.Counts.OutOfScope++
			cm.Counts.OutOfScope++
			eval.EvidenceComparison = append(eval.EvidenceComparison, FindingComparisonItem{
				GroundTruthID: entry.ID,
				Endpoint:      entry.EndpointPattern,
				VulnClass:     cls,
				Outcome:       OutcomeOutOfScope,
				Rationale:     "marked excluded or out of scope in independent ground truth",
			})
			continue
		}

		if entry.SafetyExcluded || (manifest != nil && manifest.SafeMode && entry.ExpectedStatus == GTVulnerable && cls != "SECURITY_HEADERS" && cls != "INFO_DISCLOSURE") {
			eval.Counts.SafetyExcluded++
			cm.Counts.SafetyExcluded++
			eval.EvidenceComparison = append(eval.EvidenceComparison, FindingComparisonItem{
				GroundTruthID: entry.ID,
				Endpoint:      entry.EndpointPattern,
				VulnClass:     cls,
				Outcome:       OutcomeSafetyExcluded,
				Rationale:     "excluded by active safety gate or --safe assessment mode",
			})
			continue
		}

		if isConfigMissing(entry.RequiresConfig, manifest, authz) {
			eval.Counts.NotConfigured++
			cm.Counts.NotConfigured++
			eval.EvidenceComparison = append(eval.EvidenceComparison, FindingComparisonItem{
				GroundTruthID: entry.ID,
				Endpoint:      entry.EndpointPattern,
				VulnClass:     cls,
				Outcome:       OutcomeNotConfigured,
				Rationale:     fmt.Sprintf("required capability/config %q not active in campaign", entry.RequiresConfig),
			})
			continue
		}

		// Search report findings matching this ground-truth entry.
		matchedIdx := -1
		matchedVerifiedIdx := -1
		for idx, f := range rep.Findings {
			if matchEntryToFinding(entry, f) {
				if matchedIdx == -1 {
					matchedIdx = idx
				}
				if report.NormalizeVerificationStatus(f.Verification.Status) == report.VerificationVerified {
					matchedVerifiedIdx = idx
					break
				}
			}
		}

		switch entry.ExpectedStatus {
		case GTVulnerable:
			eval.EvaluatedPopulation++
			eval.ExecutablePositivePop++
			cm.EvaluatedPop++

			if matchedVerifiedIdx >= 0 {
				usedFindings[matchedVerifiedIdx] = true
				satisfiedTPIDs[entry.ID] = true
				f := rep.Findings[matchedVerifiedIdx]
				eval.Counts.TP++
				cm.Counts.TP++
				eval.EvidenceComparison = append(eval.EvidenceComparison, FindingComparisonItem{
					GroundTruthID:    entry.ID,
					FindingID:        f.ID,
					FindingTitle:     f.Title,
					Endpoint:         f.Endpoint,
					VulnClass:        cls,
					Outcome:          OutcomeTP,
					VerificationTier: string(report.VerificationVerified),
					EvidencePresent:  strings.TrimSpace(f.Evidence) != "" || strings.TrimSpace(f.Verification.Rationale) != "",
					Rationale:        "verified finding matches executable in-scope positive ground-truth entry",
				})
			} else if matchedIdx >= 0 {
				// Unverified candidate/detected finding MUST NOT count as verified TP!
				usedFindings[matchedIdx] = true
				f := rep.Findings[matchedIdx]
				eval.Counts.CandidateOnlyMatches++
				cm.Counts.CandidateOnlyMatches++
				eval.Counts.FN++
				cm.Counts.FN++
				eval.EvidenceComparison = append(eval.EvidenceComparison, FindingComparisonItem{
					GroundTruthID:    entry.ID,
					FindingID:        f.ID,
					FindingTitle:     f.Title,
					Endpoint:         f.Endpoint,
					VulnClass:        cls,
					Outcome:          OutcomeFN,
					VerificationTier: string(report.NormalizeVerificationStatus(f.Verification.Status)),
					EvidencePresent:  strings.TrimSpace(f.Evidence) != "",
					Rationale:        "unverified candidate finding matched pattern, but candidate tier cannot be promoted to verified TP",
				})
			} else {
				eval.Counts.FN++
				cm.Counts.FN++
				eval.EvidenceComparison = append(eval.EvidenceComparison, FindingComparisonItem{
					GroundTruthID: entry.ID,
					Endpoint:      entry.EndpointPattern,
					VulnClass:     cls,
					Outcome:       OutcomeFN,
					Rationale:     "executable in-scope vulnerability missed by FELIX",
				})
			}

		case GTNegativeControl:
			if matchedIdx >= 0 {
				usedFindings[matchedIdx] = true
				f := rep.Findings[matchedIdx]
				eval.EvaluatedPopulation++
				eval.EvaluatedNegativePop++
				cm.EvaluatedPop++
				eval.Counts.FP++
				cm.Counts.FP++
				verTier := report.NormalizeVerificationStatus(f.Verification.Status)
				if verTier == report.VerificationVerified {
					eval.Counts.VerifiedFPs++
					cm.Counts.VerifiedFPs++
				} else {
					eval.Counts.CandidateFPs++
					cm.Counts.CandidateFPs++
				}
				eval.EvidenceComparison = append(eval.EvidenceComparison, FindingComparisonItem{
					GroundTruthID:    entry.ID,
					FindingID:        f.ID,
					FindingTitle:     f.Title,
					Endpoint:         f.Endpoint,
					VulnClass:        cls,
					Outcome:          OutcomeFP,
					VerificationTier: string(verTier),
					EvidencePresent:  strings.TrimSpace(f.Evidence) != "",
					Rationale:        "false positive reported against secure negative control",
				})
			} else {
				tested, inconclusive, reason := checkNegativeControlCoverage(entry, authz, rep, manifest)
				if inconclusive {
					eval.EvaluatedPopulation++
					cm.EvaluatedPop++
					eval.Counts.Inconclusive++
					cm.Counts.Inconclusive++
					eval.EvidenceComparison = append(eval.EvidenceComparison, FindingComparisonItem{
						GroundTruthID: entry.ID,
						Endpoint:      entry.EndpointPattern,
						VulnClass:     cls,
						Outcome:       OutcomeInconclusive,
						Rationale:     reason,
					})
				} else if tested {
					eval.EvaluatedPopulation++
					eval.EvaluatedNegativePop++
					cm.EvaluatedPop++
					eval.Counts.TN++
					cm.Counts.TN++
					eval.EvidenceComparison = append(eval.EvidenceComparison, FindingComparisonItem{
						GroundTruthID: entry.ID,
						Endpoint:      entry.EndpointPattern,
						VulnClass:     cls,
						Outcome:       OutcomeTN,
						Rationale:     reason,
					})
				} else {
					eval.Counts.NotTested++
					cm.Counts.NotTested++
					eval.EvidenceComparison = append(eval.EvidenceComparison, FindingComparisonItem{
						GroundTruthID: entry.ID,
						Endpoint:      entry.EndpointPattern,
						VulnClass:     cls,
						Outcome:       OutcomeNotTested,
						Rationale:     reason,
					})
				}
			}
		}
	}

	// 2. Account for any unmatched FELIX findings (either discovery observation, corroborating GT match, or unexpected FP).
	for idx, f := range rep.Findings {
		if usedFindings[idx] {
			continue
		}
		cls := CanonicalVulnClass(f.Category, f.Title, f.ID)
		if cls == "DISCOVERY_OBSERVATION" {
			eval.Counts.DiscoveryObservationsIgnored++
			continue
		}
		// Check if a VERIFIED finding corroborates an already-matched verified positive ground-truth template.
		corroboratedID := ""
		if report.NormalizeVerificationStatus(f.Verification.Status) == report.VerificationVerified {
			for _, entry := range reg.Entries {
				if entry.ExpectedStatus == GTVulnerable && entry.InScope && !entry.SafetyExcluded && satisfiedTPIDs[entry.ID] && matchEntryToFinding(entry, f) {
					corroboratedID = entry.ID
					break
				}
			}
		}
		if corroboratedID != "" {
			eval.EvidenceComparison = append(eval.EvidenceComparison, FindingComparisonItem{
				GroundTruthID:    corroboratedID,
				FindingID:        f.ID,
				FindingTitle:     f.Title,
				Endpoint:         f.Endpoint,
				VulnClass:        cls,
				Outcome:          OutcomeTP,
				VerificationTier: string(report.NormalizeVerificationStatus(f.Verification.Status)),
				EvidencePresent:  strings.TrimSpace(f.Evidence) != "",
				Rationale:        "additional verified/corroborating finding for already-satisfied ground-truth entry",
			})
			continue
		}
		cm := getClass(cls)
		eval.EvaluatedPopulation++
		cm.EvaluatedPop++
		eval.Counts.FP++
		cm.Counts.FP++
		verTier := report.NormalizeVerificationStatus(f.Verification.Status)
		if verTier == report.VerificationVerified {
			eval.Counts.VerifiedFPs++
			cm.Counts.VerifiedFPs++
		} else {
			eval.Counts.CandidateFPs++
			cm.Counts.CandidateFPs++
		}
		eval.EvidenceComparison = append(eval.EvidenceComparison, FindingComparisonItem{
			FindingID:        f.ID,
			FindingTitle:     f.Title,
			Endpoint:         f.Endpoint,
			VulnClass:        cls,
			Outcome:          OutcomeFP,
			VerificationTier: string(verTier),
			EvidencePresent:  strings.TrimSpace(f.Evidence) != "",
			Rationale:        "reported finding did not match any registered positive ground-truth entry",
		})
	}

	// 3. Calculate aggregate & per-class metrics with strict denominator validation.
	eval.Precision = ComputeRate(eval.Counts.TP, eval.Counts.TP+eval.Counts.FP, "no positive findings evaluated (TP+FP == 0)")
	eval.Recall = ComputeRate(eval.Counts.TP, eval.Counts.TP+eval.Counts.FN, "no executable in-scope positive ground-truth cases (TP+FN == 0)")
	eval.Specificity = ComputeRate(eval.Counts.TN, eval.Counts.TN+eval.Counts.FP, "no evaluated negative controls or FPs (TN+FP == 0)")
	eval.F1Score = ComputeF1(eval.Counts.TP, eval.Counts.FP, eval.Counts.FN)

	// Execution coverage counts evaluated in-scope executable items vs total in-scope executable GT entries (including inconclusive attempts).
	totalInScopeExecutable := eval.Counts.TP + eval.Counts.FN + eval.Counts.TN + eval.Counts.Inconclusive + eval.Counts.NotTested
	evaluatedInScope := eval.Counts.TP + eval.Counts.FN + eval.Counts.TN + eval.Counts.Inconclusive
	eval.ExecutionCoverage = ComputeRate(evaluatedInScope, totalInScopeExecutable, "no executable in-scope ground-truth cases")

	classKeys := make([]string, 0, len(eval.ClassBreakdown))
	for k := range eval.ClassBreakdown {
		classKeys = append(classKeys, k)
	}
	sort.Strings(classKeys)
	for _, k := range classKeys {
		cm := eval.ClassBreakdown[k]
		cm.Precision = ComputeRate(cm.Counts.TP, cm.Counts.TP+cm.Counts.FP, "TP+FP == 0")
		cm.Recall = ComputeRate(cm.Counts.TP, cm.Counts.TP+cm.Counts.FN, "TP+FN == 0")
		cm.Specificity = ComputeRate(cm.Counts.TN, cm.Counts.TN+cm.Counts.FP, "TN+FP == 0")
		cTotal := cm.Counts.TP + cm.Counts.FN + cm.Counts.TN + cm.Counts.Inconclusive + cm.Counts.NotTested
		cExec := cm.Counts.TP + cm.Counts.FN + cm.Counts.TN + cm.Counts.Inconclusive
		cm.ExecutionCoverage = ComputeRate(cExec, cTotal, "no executable in-scope cases")
	}

	// 4. Optional remediation retest verification evaluation.
	if len(retestExpected) > 0 {
		rm := &RetestAccuracyMetrics{ExpectedTotal: len(retestExpected)}
		verdictByID := make(map[string]*investigation.RetestVerdict, len(retestVerdicts))
		for _, v := range retestVerdicts {
			if v != nil {
				verdictByID[v.FindingID] = v
			}
		}
		for _, exp := range retestExpected {
			v, ok := verdictByID[exp.FindingID]
			if !ok {
				rm.MissingVerdict++
				continue
			}
			switch v.RetestStatus {
			case investigation.RetestInconclusive:
				rm.InconclusiveCount++
			case investigation.RetestFixDetected:
				if strings.EqualFold(exp.ExpectedAction, "FIXED") {
					rm.CorrectFixed++
				} else {
					rm.IncorrectVerdict++
				}
			case investigation.RetestVulnerabilityPresent, investigation.RetestRegressionDetected:
				if strings.EqualFold(exp.ExpectedAction, "STILL_PRESENT") {
					rm.CorrectStillPresent++
				} else {
					rm.IncorrectVerdict++
				}
			default:
				rm.InconclusiveCount++
			}
		}
		conclusive := rm.CorrectFixed + rm.CorrectStillPresent + rm.IncorrectVerdict
		rm.RetestAccuracy = ComputeRate(rm.CorrectFixed+rm.CorrectStillPresent, conclusive, "no conclusive retest verdicts")
		eval.RetestAccuracy = rm
	}

	return eval, nil
}
