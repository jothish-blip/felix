package report

import (
	"fmt"
	"math"
	"sort"
	"strings"
)

// CalculateFindingScore calculates the deterministic risk score (0-40) for an individual finding.
// It is verification-aware: verified exposures receive full weight, while unverified,
// observed, or confirmed non-exposures (defensive boundaries) receive reduced or zero weight.
func CalculateFindingScore(f Finding) int {
	// Defended / boundary confirmed findings contribute 0 risk
	if NormalizeVerificationStatus(f.Verification.Status) == VerificationNotExposed {
		return 0
	}
	if strings.EqualFold(f.EvidenceDetails.DetectionStatus, "NOT_EXPOSED") {
		return 0
	}
	if f.EvidenceDetails.Details != nil {
		auth := strings.ToUpper(f.EvidenceDetails.Details["auth_state"])
		if auth == "AUTH_REQUIRED" || auth == "FORBIDDEN" || auth == "NOT_FOUND" {
			return 0
		}
	}

	var base float64
	switch NormalizeSeverity(f.Severity) {
	case SeverityCritical:
		base = 40.0
	case SeverityHigh:
		base = 25.0
	case SeverityMedium:
		base = 12.0
	case SeverityLow:
		base = 5.0
	case SeverityInfo:
		base = 1.0
	default:
		base = 1.0
	}

	// Sensitivity & privilege modifier
	cat := NormalizeCategory(f.Category)
	if strings.Contains(cat, "service-key") || strings.Contains(cat, "service-role") ||
		strings.Contains(cat, "aws-secret") || strings.Contains(cat, "private-key") {
		base = math.Min(40.0, base+5.0)
	}

	// Confidence weight
	var confMult float64
	switch NormalizeConfidence(f.Confidence) {
	case ConfidenceHigh:
		confMult = 1.0
	case ConfidenceMedium:
		confMult = 0.75
	case ConfidenceLow:
		confMult = 0.5
	default:
		confMult = 0.75
	}

	// Verification weight
	verMult := 1.0
	if f.Verification.Status != "" {
		switch NormalizeVerificationStatus(f.Verification.Status) {
		case VerificationVerified:
			verMult = 1.0
		case VerificationDetected:
			verMult = 0.8
		case VerificationNotVerified:
			verMult = 0.7
		case VerificationObserved:
			verMult = 0.3
		case VerificationNotExposed:
			verMult = 0.0
		default:
			verMult = 0.5
		}
	}

	score := int(math.Round(base * confMult * verMult))
	if score < 0 {
		return 0
	}
	if score > 40 {
		return 40
	}
	return score
}

func isHardeningCategory(cat string) bool {
	c := NormalizeCategory(cat)
	return strings.HasPrefix(c, "missing-") ||
		strings.HasPrefix(c, "weak-") ||
		c == "cors-wildcard" ||
		c == "api-docs-exposure" ||
		strings.HasPrefix(c, "asset-") ||
		c == "source-map-discovered" ||
		c == "source-map-exposure"
}

// CalculateReportRisk evaluates all findings and correlated security stories
// to produce a bounded (0-100) Felix Risk Score and categorical risk band.
//
// The scoring model is deterministic, explainable, and deliberately distinct from CVSS:
// - Numerical score is the genuine accumulated, weighted evidence across exposures,
//   hardening defense-in-depth findings (capped at 20), and correlated story bonuses (capped at 15).
// - Risk level band is derived from the accumulated score, anchored by the highest eligible
//   confirmed finding severity to prevent high-severity exposures from appearing low-risk.
// - Defended boundaries (NOT_EXPOSED) and passive observations contribute zero risk and
//   cannot trigger severity escalation.
// CalculateRiskBreakdown evaluates all findings and correlated security stories
// using the Felix deterministic scoring model, producing both the overall risk assessment
// and full mathematical reconciliation artifacts (individual weights, adjusted contributions,
// subtotals, and formula).
func CalculateRiskBreakdown(findings []Finding, stories []SecurityStory) ([]CommercialRiskContribution, CommercialScoreBreakdown, string) {
	if len(findings) == 0 {
		return nil, CommercialScoreBreakdown{
			Formula: "0 (no findings)",
		}, "INFORMATIONAL"
	}

	type scoredFinding struct {
		finding Finding
		score   int
	}

	var exposureFindings []scoredFinding
	var hardeningFindings []scoredFinding

	maxEligibleSeverityRank := 0
	maxEligibleSeverity := ""

	for _, f := range findings {
		// Defended / boundary confirmed findings contribute 0 risk and do not escalate risk level
		if NormalizeVerificationStatus(f.Verification.Status) == VerificationNotExposed {
			continue
		}
		if strings.EqualFold(f.EvidenceDetails.DetectionStatus, "NOT_EXPOSED") {
			continue
		}
		if f.EvidenceDetails.Details != nil {
			auth := strings.ToUpper(f.EvidenceDetails.Details["auth_state"])
			if auth == "AUTH_REQUIRED" || auth == "FORBIDDEN" || auth == "NOT_FOUND" {
				continue
			}
		}

		s := f.Score
		if s <= 0 || s > 40 {
			s = CalculateFindingScore(f)
		}
		if s <= 0 {
			continue
		}

		// Track highest eligible confirmed severity for risk-level classification.
		// Eligible findings must be VERIFIED, have positive score, and non-low confidence.
		// Unverified candidates (DETECTED, NOT_VERIFIED), passive observations (OBSERVED),
		// and defended boundaries (NOT_EXPOSED) cannot anchor the severity level.
		// Explicit evidence of verification is mandatory to anchor the categorical risk level.
		// Canonical verification status must be VERIFIED.
		// Documented legacy fallback: when VerificationRecord is unpopulated (legacy schema),
		// require explicit detection-level verification status "VERIFIED".
		normStatus := NormalizeVerificationStatus(f.Verification.Status)
		isConfirmedVerified := false
		if f.Verification.Status != "" {
			isConfirmedVerified = normStatus == VerificationVerified
		} else if strings.EqualFold(f.EvidenceDetails.DetectionStatus, "VERIFIED") {
			isConfirmedVerified = true
		}

		if isConfirmedVerified {
			sevNorm := NormalizeSeverity(f.Severity)
			rank := SeverityRank(sevNorm)
			confNorm := NormalizeConfidence(f.Confidence)
			if confNorm != ConfidenceLow && rank > maxEligibleSeverityRank {
				maxEligibleSeverityRank = rank
				maxEligibleSeverity = sevNorm
			}
		}

		sf := scoredFinding{finding: f, score: s}
		if isHardeningCategory(f.Category) {
			hardeningFindings = append(hardeningFindings, sf)
		} else {
			exposureFindings = append(exposureFindings, sf)
		}
	}

	// Sort descending for deterministic diminishing returns.
	// Deterministic tie-breaking on finding ID.
	sort.Slice(exposureFindings, func(i, j int) bool {
		if exposureFindings[i].score != exposureFindings[j].score {
			return exposureFindings[i].score > exposureFindings[j].score
		}
		return exposureFindings[i].finding.ID < exposureFindings[j].finding.ID
	})
	sort.Slice(hardeningFindings, func(i, j int) bool {
		if hardeningFindings[i].score != hardeningFindings[j].score {
			return hardeningFindings[i].score > hardeningFindings[j].score
		}
		return hardeningFindings[i].finding.ID < hardeningFindings[j].finding.ID
	})

	weights := []float64{1.0, 0.5, 0.3, 0.2}
	var contributions []CommercialRiskContribution

	var exposureAccum float64
	for i, sf := range exposureFindings {
		weight := 0.1
		if i < len(weights) {
			weight = weights[i]
		}
		adj := math.Round(float64(sf.score)*weight*100) / 100
		exposureAccum += float64(sf.score) * weight

		verStatus := string(sf.finding.Verification.Status)
		if verStatus == "" {
			verStatus = sf.finding.EvidenceDetails.DetectionStatus
		}
		if verStatus == "" {
			verStatus = "DETECTED"
		}

		contributions = append(contributions, CommercialRiskContribution{
			FindingID:          sf.finding.ID,
			Title:              SanitizeEvidence(sf.finding.Title),
			Severity:           NormalizeSeverity(sf.finding.Severity),
			VerificationStatus: verStatus,
			Score:              sf.score,
			Weight:             weight,
			AdjustedScore:      adj,
			Model:              "felix_deterministic_v1",
			RiskType:           "EXPOSURE",
			Rationale:          fmt.Sprintf("Raw score %d/40 (weight %.1fx, adjusted %.2f) weighted by severity (%s), confidence (%s), and verification status (%s).", sf.score, weight, adj, sf.finding.Severity, sf.finding.Confidence, verStatus),
			IsAvailable:        true,
		})
	}

	var hardeningAccum float64
	for i, sf := range hardeningFindings {
		weight := 0.1
		if i < len(weights) {
			weight = weights[i]
		}
		adj := math.Round(float64(sf.score)*weight*100) / 100
		hardeningAccum += float64(sf.score) * weight

		verStatus := string(sf.finding.Verification.Status)
		if verStatus == "" {
			verStatus = sf.finding.EvidenceDetails.DetectionStatus
		}
		if verStatus == "" {
			verStatus = "DETECTED"
		}

		contributions = append(contributions, CommercialRiskContribution{
			FindingID:          sf.finding.ID,
			Title:              SanitizeEvidence(sf.finding.Title),
			Severity:           NormalizeSeverity(sf.finding.Severity),
			VerificationStatus: verStatus,
			Score:              sf.score,
			Weight:             weight,
			AdjustedScore:      adj,
			Model:              "felix_deterministic_v1",
			RiskType:           "HARDENING_DEFENSE_IN_DEPTH",
			Rationale:          fmt.Sprintf("Raw score %d/40 (weight %.1fx, adjusted %.2f) defense-in-depth header finding under hardening cap (max 20 pts).", sf.score, weight, adj),
			IsAvailable:        true,
		})
	}

	rawHardeningAccum := hardeningAccum
	if hardeningAccum > 20.0 {
		hardeningAccum = 20.0
	}

	// Story bonus: sum of unique story RiskContributions, capped at +15
	seenStoryIDs := make(map[string]bool)
	var storyBonus float64
	for _, st := range stories {
		storyID := strings.TrimSpace(st.ID)
		if storyID != "" {
			if seenStoryIDs[storyID] {
				continue
			}
			seenStoryIDs[storyID] = true
		}
		contrib := st.RiskContribution
		if contrib < 0 {
			contrib = 0
		}
		storyBonus += float64(contrib)
	}
	if storyBonus > 15.0 {
		storyBonus = 15.0
	}

	totalScore := int(math.Round(exposureAccum + hardeningAccum + storyBonus))
	if totalScore > 100 {
		totalScore = 100
	}
	if totalScore < 0 {
		totalScore = 0
	}

	scoreBandLevel := RiskLevelBand(totalScore)
	level := scoreBandLevel

	if maxEligibleSeverityRank > 0 {
		anchorLevel := "INFORMATIONAL"
		switch maxEligibleSeverity {
		case SeverityCritical:
			anchorLevel = "CRITICAL"
		case SeverityHigh:
			anchorLevel = "HIGH"
		case SeverityMedium:
			anchorLevel = "MEDIUM"
		case SeverityLow:
			anchorLevel = "LOW"
		default:
			anchorLevel = "INFORMATIONAL"
		}

		if SeverityRank(anchorLevel) > SeverityRank(scoreBandLevel) {
			level = anchorLevel
		}
	}

	expSub := math.Round(exposureAccum*100) / 100
	hardSub := math.Round(hardeningAccum*100) / 100
	storySub := math.Round(storyBonus*100) / 100

	formula := fmt.Sprintf("round(%.2f exposure + %.2f hardening + %.2f story bonus) = %d", expSub, hardSub, storySub, totalScore)
	if rawHardeningAccum > 20.0 {
		formula = fmt.Sprintf("round(%.2f exposure + 20.00 hardening [capped from %.2f] + %.2f story bonus) = %d", expSub, rawHardeningAccum, storySub, totalScore)
	}

	breakdown := CommercialScoreBreakdown{
		ExposureSubtotal:  expSub,
		HardeningSubtotal: hardSub,
		StoryBonus:        storySub,
		TotalScore:        totalScore,
		Formula:           formula,
	}

	return contributions, breakdown, level
}

// CalculateReportRisk evaluates all findings and correlated security stories
// to produce a bounded (0-100) Felix Risk Score and categorical risk band.
// It delegates directly to CalculateRiskBreakdown to ensure risk calculation and
// commercial attribution use the identical mathematical engine.
func CalculateReportRisk(findings []Finding, stories []SecurityStory) (int, string) {
	if len(findings) == 0 {
		return 0, "INFORMATIONAL"
	}
	_, breakdown, level := CalculateRiskBreakdown(findings, stories)
	return breakdown.TotalScore, level
}

// RiskLevelBand maps an integer score (0-100) to its standardized risk level label.
func RiskLevelBand(score int) string {
	switch {
	case score >= 80:
		return "CRITICAL"
	case score >= 60:
		return "HIGH"
	case score >= 40:
		return "MEDIUM"
	case score >= 20:
		return "LOW"
	default:
		return "INFORMATIONAL"
	}
}
