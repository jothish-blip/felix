package report

import (
	"math"
	"sort"
	"strings"
)

// CalculateFindingScore calculates the deterministic risk score (0-40) for an individual finding.
// It is verification-aware: verified exposures receive full weight, while unverified,
// observed, or confirmed non-exposures (defensive boundaries) receive reduced or zero weight.
func CalculateFindingScore(f Finding) int {
	// Defended / boundary confirmed findings contribute 0 risk
	if f.Verification.Status == VerificationNotExposed {
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
// The scoring model is deterministic, explainable, and deliberately not CVSS:
// - Top verified findings anchor the primary risk band.
// - Additional independent exposures provide bounded diminishing contributions.
// - Hardening/defense-in-depth header findings are strictly capped at max 20 points
//   to prevent false risk inflation on otherwise secure targets.
// - Correlated security stories add targeted threat escalation bonuses.
func CalculateReportRisk(findings []Finding, stories []SecurityStory) (int, string) {
	if len(findings) == 0 {
		return 0, "INFORMATIONAL"
	}

	var exposureScores []int
	var hardeningScores []int

	topExposureScore := 0
	topExposureSeverity := ""
	topExposureConfidence := ""

	hasAnyLow := false
	hasAnyHighConf := false

	for _, f := range findings {
		s := f.Score
		if f.Verification.Status == VerificationNotExposed {
			s = 0
		} else if s == 0 {
			s = CalculateFindingScore(f)
		}

		if NormalizeSeverity(f.Severity) == SeverityLow {
			hasAnyLow = true
		}
		if NormalizeConfidence(f.Confidence) == ConfidenceHigh {
			hasAnyHighConf = true
		}

		if isHardeningCategory(f.Category) {
			if s > 0 {
				hardeningScores = append(hardeningScores, s)
			}
		} else {
			if s > 0 {
				exposureScores = append(exposureScores, s)
				if s > topExposureScore {
					topExposureScore = s
					topExposureSeverity = NormalizeSeverity(f.Severity)
					topExposureConfidence = NormalizeConfidence(f.Confidence)
				}
			}
		}
	}

	// Sort descending
	sort.Slice(exposureScores, func(i, j int) bool {
		return exposureScores[i] > exposureScores[j]
	})
	sort.Slice(hardeningScores, func(i, j int) bool {
		return hardeningScores[i] > hardeningScores[j]
	})

	// Diminishing returns accumulator for true exposures
	var exposureAccum float64
	weights := []float64{1.0, 0.5, 0.3, 0.2}
	for i, s := range exposureScores {
		if i < len(weights) {
			exposureAccum += float64(s) * weights[i]
		} else {
			exposureAccum += float64(s) * 0.1
		}
	}

	// Hardening scores accumulator (capped at 20.0 max)
	var hardeningAccum float64
	for i, s := range hardeningScores {
		if i < len(weights) {
			hardeningAccum += float64(s) * weights[i]
		} else {
			hardeningAccum += float64(s) * 0.1
		}
	}
	if hardeningAccum > 20.0 {
		hardeningAccum = 20.0
	}

	// Story bonus: sum of story RiskContributions, capped at +15
	var storyBonus float64
	for _, st := range stories {
		contrib := st.RiskContribution
		if contrib <= 0 {
			contrib = 5
		}
		storyBonus += float64(contrib)
	}
	if storyBonus > 15.0 {
		storyBonus = 15.0
	}

	totalScore := int(math.Round(exposureAccum + hardeningAccum + storyBonus))

	// Floor alignment based on highest confirmed vulnerability
	if topExposureScore >= 40 && topExposureConfidence == ConfidenceHigh {
		if totalScore < 80 {
			totalScore = 80
		}
	} else if topExposureScore >= 25 && topExposureConfidence == ConfidenceHigh {
		if totalScore < 60 {
			totalScore = 60
		}
	} else if topExposureSeverity == SeverityMedium && topExposureConfidence == ConfidenceHigh {
		if totalScore < 40 {
			totalScore = 40
		}
	} else if hasAnyLow && hasAnyHighConf {
		// When target has verified Low severity defense-in-depth issues (e.g. missing CSP)
		// with High confidence, align floor to 20 (LOW band baseline).
		if totalScore < 20 {
			totalScore = 20
		}
		// If there are no Medium/High/Critical exposures, score should not exceed 20.
		if topExposureSeverity != SeverityCritical && topExposureSeverity != SeverityHigh && topExposureSeverity != SeverityMedium {
			if totalScore > 20 {
				totalScore = 20
			}
		}
	}

	// Cap at [0, 100]
	if totalScore > 100 {
		totalScore = 100
	}
	if totalScore < 0 {
		totalScore = 0
	}

	level := RiskLevelBand(totalScore)
	return totalScore, level
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
