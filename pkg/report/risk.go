package report

import (
	"math"
	"sort"
	"strings"
)

// CalculateFindingScore calculates the deterministic risk score (0-40) for an individual finding.
func CalculateFindingScore(f Finding) int {
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
	var mult float64
	switch NormalizeConfidence(f.Confidence) {
	case ConfidenceHigh:
		mult = 1.0
	case ConfidenceMedium:
		mult = 0.75
	case ConfidenceLow:
		mult = 0.5
	default:
		mult = 0.75
	}

	score := int(math.Round(base * mult))
	if score < 0 {
		return 0
	}
	if score > 40 {
		return 40
	}
	return score
}

// CalculateReportRisk evaluates all findings and correlated security stories
// to produce a bounded (0-100) Felix Risk Score and categorical risk band.
//
// The scoring model is deterministic, explainable, and deliberately not CVSS:
// - Top verified findings anchor the primary risk band.
// - Additional independent exposures provide bounded diminishing contributions.
// - Correlated security stories add targeted threat escalation bonuses.
func CalculateReportRisk(findings []Finding, stories []SecurityStory) (int, string) {
	if len(findings) == 0 {
		return 0, "INFORMATIONAL"
	}

	scores := make([]int, len(findings))
	for i, f := range findings {
		scores[i] = f.Score
		if scores[i] == 0 {
			scores[i] = CalculateFindingScore(f)
		}
	}

	// Sort finding scores descending
	sort.Slice(scores, func(i, j int) bool {
		return scores[i] > scores[j]
	})

	topScore := scores[0]
	topSeverity := NormalizeSeverity(findings[0].Severity)
	topConfidence := NormalizeConfidence(findings[0].Confidence)

	// Diminishing returns accumulator
	var accumulated float64
	weights := []float64{1.0, 0.5, 0.3, 0.2}
	for i, s := range scores {
		if i < len(weights) {
			accumulated += float64(s) * weights[i]
		} else {
			// Diminishing tail
			accumulated += float64(s) * 0.1
		}
	}

	// Story bonus (+5 per correlated story, capped at +15)
	storyBonus := math.Min(15.0, float64(len(stories))*5.0)
	totalScore := int(math.Round(accumulated + storyBonus))

	// Floor alignment based on highest confirmed vulnerability
	if topScore >= 40 && topConfidence == ConfidenceHigh {
		if totalScore < 80 {
			totalScore = 80
		}
	} else if topScore >= 25 && topConfidence == ConfidenceHigh {
		if totalScore < 60 {
			totalScore = 60
		}
	} else if topSeverity == SeverityMedium && topConfidence == ConfidenceHigh {
		if totalScore < 40 {
			totalScore = 40
		}
	} else if topSeverity == SeverityLow && topConfidence == ConfidenceHigh {
		if totalScore < 20 {
			totalScore = 20
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
