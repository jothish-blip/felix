package verification

import (
	"strings"

	"felix/pkg/report"
)

// ConfidenceLevels.
const (
	ConfidenceHigh   = report.ConfidenceHigh
	ConfidenceMedium = report.ConfidenceMedium
	ConfidenceLow    = report.ConfidenceLow
	ConfidenceNone   = "NONE"
)

// ConfidenceResult bundles the dual-confidence breakdown and overall score.
type ConfidenceResult struct {
	DetectionConfidence    string `json:"detection_confidence"`
	VerificationConfidence string `json:"verification_confidence"`
	OverallConfidence      string `json:"overall_confidence"`
	Score                  int    `json:"score"` // 0-100
	Rationale              string `json:"rationale"`
}

// ComputeConfidence calculates the overall finding confidence and 0-100 score,
// strictly separating detection signal strength from verification evidence strength.
//
// Invariant: High detection confidence NEVER converts an unverified finding into VERIFIED.
func ComputeConfidence(
	detConf string,
	verConf string,
	status report.VerificationStatus,
	hasContradiction bool,
	synthetic bool,
	mandatoryPassed bool,
) ConfidenceResult {
	normDet := report.NormalizeConfidence(detConf)
	normVer := strings.ToUpper(strings.TrimSpace(verConf))
	if normVer == "" {
		normVer = ConfidenceNone
	}

	var overall string
	var score int
	var rationaleParts []string

	// Base score from detection confidence (0-40 range)
	var detScore int
	switch normDet {
	case report.ConfidenceHigh:
		detScore = 40
		rationaleParts = append(rationaleParts, "Detection pattern match is strong")
	case report.ConfidenceMedium:
		detScore = 25
		rationaleParts = append(rationaleParts, "Detection pattern match is moderate")
	case report.ConfidenceLow:
		detScore = 15
		rationaleParts = append(rationaleParts, "Detection pattern match is provisional/heuristic")
	default:
		detScore = 10
		rationaleParts = append(rationaleParts, "Detection signal is weak")
	}

	// Verification contribution (0-60 range)
	var verScore int
	switch normVer {
	case ConfidenceHigh:
		verScore = 60
		rationaleParts = append(rationaleParts, "Direct empirical verification evidence satisfies criteria")
	case ConfidenceMedium:
		verScore = 40
		rationaleParts = append(rationaleParts, "Corroborating evidence partially establishes behavior")
	case ConfidenceLow:
		verScore = 20
		rationaleParts = append(rationaleParts, "Limited verification evidence obtained")
	default: // NONE
		verScore = 0
		rationaleParts = append(rationaleParts, "No independent verification evidence obtained")
	}

	score = detScore + verScore

	// Apply status-specific boundary constraints
	switch status {
	case StatusVerified:
		if !mandatoryPassed {
			// Invariant violation guard: cannot be verified without mandatory criteria passing
			score = 45
			overall = ConfidenceMedium
			rationaleParts = append(rationaleParts, "CRITICAL: Verification incomplete due to unfulfilled mandatory criteria")
		} else {
			if score < 75 {
				score = 75 // Floor for verified finding
			}
			if score > 98 {
				score = 98 // Cap live confidence
			}
			if score >= 80 {
				overall = ConfidenceHigh
			} else {
				overall = ConfidenceMedium
			}
			rationaleParts = append(rationaleParts, "Status is VERIFIED based on satisfied mandatory proof criteria")
		}

	case StatusNotExposed:
		// Affirmative negative evidence under claim-specific criteria
		score = 85
		overall = ConfidenceHigh
		rationaleParts = append(rationaleParts, "Status is NOT_EXPOSED: specific claim disproved under verified negative criteria")

	case StatusDetected:
		// Detection without proof: capped at 65, overall cannot be HIGH
		if score > 65 {
			score = 65
		}
		if score >= 45 {
			overall = ConfidenceMedium
		} else {
			overall = ConfidenceLow
		}
		rationaleParts = append(rationaleParts, "Status is DETECTED: hypothesis remains unverified by empirical testing")

	case StatusNotVerified:
		// Attempted or inconclusive: capped at 55
		if score > 55 {
			score = 55
		}
		if score >= 40 {
			overall = ConfidenceMedium
		} else {
			overall = ConfidenceLow
		}
		rationaleParts = append(rationaleParts, "Status is NOT_VERIFIED: verification evidence is absent, inconclusive, or blocked")

	case StatusObserved:
		// Raw observation: capped at 35
		if score > 35 {
			score = 35
		}
		overall = ConfidenceLow
		rationaleParts = append(rationaleParts, "Status is OBSERVED: raw signal recorded without vulnerability confirmation")

	default:
		overall = ConfidenceLow
		score = 25
	}

	// Contradiction penalty
	if hasContradiction {
		score = score / 2
		if score < 10 {
			score = 10
		}
		overall = ConfidenceLow
		rationaleParts = append(rationaleParts, "PENALTY: Contradictory evidence observed during evaluation")
	}

	// Synthetic fixture provenance note
	if synthetic {
		rationaleParts = append(rationaleParts, "[SYNTHETIC FIXTURE: evaluated in simulated/synthetic environment]")
	}

	return ConfidenceResult{
		DetectionConfidence:    normDet,
		VerificationConfidence: normVer,
		OverallConfidence:      overall,
		Score:                  score,
		Rationale:              strings.Join(rationaleParts, "; "),
	}
}
