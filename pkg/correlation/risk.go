package correlation

import (
	"fmt"
	"math"
	"strings"

	"felix/pkg/report"
)

// AssessPathRisk computes the combined risk score (0-100), categorical risk level,
// and human-readable risk rationale for an attack path.
//
// Core Principles:
// - Anchored by the highest individual component severity.
// - Bounded escalation for verified multi-step attack transitions.
// - Candidate/unverified paths cannot be promoted to Critical.
// - Repeated findings sharing the same root cause do not inflate risk.
func AssessPathRisk(path *AttackPath) (int, string, string) {
	if len(path.Nodes) == 0 {
		return 0, report.SeverityInfo, "Empty path; no findings to evaluate"
	}

	maxScore := 0
	topSeverity := report.SeverityInfo
	var topFinding *NormalizedFinding

	seenRootCauses := make(map[string]bool)
	uniqueDefects := 0

	for i := range path.Nodes {
		n := &path.Nodes[i]
		if n.Score > maxScore {
			maxScore = n.Score
			topSeverity = n.Severity
			topFinding = n
		}

		rcKey := n.NormalizedCategory + "@" + n.Path
		if !seenRootCauses[rcKey] {
			seenRootCauses[rcKey] = true
			uniqueDefects++
		}
	}

	baseScore := float64(maxScore) * 2.0 // Scale 0-40 finding score to 0-80 base
	if baseScore > 80.0 {
		baseScore = 80.0
	}

	var factors []string
	if topFinding != nil {
		factors = append(factors, fmt.Sprintf("Base risk anchored by %s finding '%s' (score: %d)",
			topFinding.Severity, topFinding.Title, topFinding.Score))
	}

	// Multi-step chain contribution (bounded)
	numTransitions := len(path.Edges)
	if numTransitions > 0 && uniqueDefects > 1 {
		transitionBonus := float64(numTransitions) * 5.0
		if transitionBonus > 15.0 {
			transitionBonus = 15.0
		}

		if path.Status == PathVerified {
			baseScore += transitionBonus
			factors = append(factors, fmt.Sprintf("+%.0f pts for %d verified sequential attack transition(s)",
				transitionBonus, numTransitions))
		} else {
			// Candidate paths receive discounted bonus
			candBonus := transitionBonus * 0.4
			baseScore += candBonus
			factors = append(factors, fmt.Sprintf("+%.0f pts potential risk for unconfirmed candidate chain", candBonus))
		}
	} else if uniqueDefects <= 1 && numTransitions > 0 {
		factors = append(factors, "Multiple nodes share common root cause; duplicate risk inflation prevented")
	}

	// External entrypoint weight
	if path.EntryPoint != "" {
		baseScore = math.Min(100.0, baseScore+5.0)
		factors = append(factors, "+5 pts for demonstrated external reachability")
	}

	// Critical terminal impact elevation
	terminalNode := &path.Nodes[len(path.Nodes)-1]
	hasHighImpactOutcome := terminalNode.IsSensitiveData ||
		strings.Contains(terminalNode.NormalizedCategory, "admin") ||
		strings.Contains(terminalNode.NormalizedCategory, "privilege") ||
		strings.Contains(terminalNode.NormalizedCategory, "fulfillment")

	if path.Status == PathVerified && hasHighImpactOutcome && topSeverity == report.SeverityHigh {
		baseScore = math.Max(85.0, baseScore)
		factors = append(factors, "Elevated to CRITICAL due to verified multi-step compromise of protected data or administrative function")
	}

	// Candidate safety cap: an unverified path must NEVER exceed HIGH / 65 pts
	if path.Status != PathVerified {
		if baseScore > 65.0 {
			baseScore = 65.0
			factors = append(factors, "Risk capped at HIGH (65 pts) because path contains unverified candidate transitions")
		}
	}

	finalScore := int(math.Round(baseScore))
	if finalScore < 0 {
		finalScore = 0
	}
	if finalScore > 100 {
		finalScore = 100
	}

	riskLevel := deriveRiskLevel(finalScore, path.Status, topSeverity)
	rationale := strings.Join(factors, "; ")

	return finalScore, riskLevel, rationale
}

func deriveRiskLevel(score int, status PathStatus, topSev string) string {
	if status != PathVerified && score >= 80 {
		return report.SeverityHigh
	}

	switch {
	case score >= 80:
		return report.SeverityCritical
	case score >= 60:
		return report.SeverityHigh
	case score >= 40:
		return report.SeverityMedium
	case score >= 20:
		return report.SeverityLow
	default:
		return report.SeverityInfo
	}
}
