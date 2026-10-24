package correlation

import (
	"errors"
	"fmt"
	"math"
	"strconv"
	"strings"

	"felix/pkg/report"
)

var (
	// ErrEmptyPath indicates that an attack path contains no nodes.
	ErrEmptyPath = errors.New("empty attack path; no findings to evaluate")

	// ErrInvalidFindingScore indicates a finding score outside the normalized [0, 100] range.
	ErrInvalidFindingScore = errors.New("finding score out of valid range [0, 100]")

	// ErrInvalidConfidence indicates an edge confidence value that is NaN, infinite, or outside [0.0, 1.0].
	ErrInvalidConfidence = errors.New("edge confidence out of valid range [0.0, 1.0] or non-finite")

	// ErrInvalidCoefficient indicates a hop coefficient alpha that is NaN, infinite, or negative.
	ErrInvalidCoefficient = errors.New("hop coefficient alpha must be non-negative and finite")
)

// CompoundRiskConfig configures the mathematical compound risk model:
//
//	S_chain = min(100, max_i(w_i) + sum_{j=1}^{k-1} alpha_j * w_j * C_{edge,j})
type CompoundRiskConfig struct {
	// DefaultAlpha is the baseline contribution coefficient for additional hops (default: 1.0).
	DefaultAlpha float64

	// HopCoefficients provides optional per-hop contribution coefficients alpha_j (1-indexed hop number).
	// If a hop index is not present in the map, DefaultAlpha is used.
	HopCoefficients map[int]float64

	// RuleCoefficients provides optional rule-specific multiplier adjustments (e.g. for specific RuleCode).
	RuleCoefficients map[RuleCode]float64

	// MaxRiskScore is the maximum allowed composite risk score (default: 100.0).
	MaxRiskScore float64

	// MinRiskScore is the minimum allowed composite risk score (default: 0.0).
	MinRiskScore float64

	// UnverifiedScoreCap optionally caps candidate or unverified paths (default: 65.0, High band).
	UnverifiedScoreCap float64
}

// DefaultCompoundRiskConfig returns the standard, calibrated centralized configuration
// for FELIX multi-hop attack path compound risk calculation.
func DefaultCompoundRiskConfig() CompoundRiskConfig {
	return CompoundRiskConfig{
		DefaultAlpha:       1.0,
		HopCoefficients:    make(map[int]float64),
		RuleCoefficients:   make(map[RuleCode]float64),
		MaxRiskScore:       100.0,
		MinRiskScore:       0.0,
		UnverifiedScoreCap: 65.0,
	}
}

// GetAlpha returns the contribution coefficient alpha_j for hop j (1-indexed) and rule code.
func (c *CompoundRiskConfig) GetAlpha(hopIndex int, rule RuleCode) float64 {
	alpha := c.DefaultAlpha
	if c.HopCoefficients != nil {
		if custom, ok := c.HopCoefficients[hopIndex]; ok {
			alpha = custom
		}
	}
	if c.RuleCoefficients != nil {
		if ruleMult, ok := c.RuleCoefficients[rule]; ok && ruleMult > 0 {
			alpha *= ruleMult
		}
	}
	return alpha
}

// HopInput represents an individual hop's components in the compound risk summation.
type HopInput struct {
	HopIndex       int      `json:"hop_index"`
	FindingID      string   `json:"finding_id"`
	FindingScore   float64  `json:"finding_score"`
	EdgeConfidence float64  `json:"edge_confidence"`
	Alpha          float64  `json:"alpha"`
	RuleCode       RuleCode `json:"rule_code,omitempty"`
}

// HopContribution captures the calculated numerical contribution of a hop to the chain score.
type HopContribution struct {
	HopIndex         int      `json:"hop_index"`
	SourceFindingID string   `json:"source_finding_id"`
	TargetFindingID string   `json:"target_finding_id"`
	FindingID        string   `json:"finding_id"`
	FindingScore     float64  `json:"finding_score"`
	EdgeConfidence   float64  `json:"edge_confidence"`
	AlphaCoefficient float64  `json:"alpha_coefficient"`
	Contribution     float64  `json:"contribution"`
	RuleCode         RuleCode `json:"rule_code,omitempty"`
	SkippedReason    string   `json:"skipped_reason,omitempty"`
}

// CompoundRiskResult contains the full deterministic outcome and mathematical breakdown of chain risk.
type CompoundRiskResult struct {
	Score            int               `json:"score"`
	Level            string            `json:"level"`
	BaseScore        float64           `json:"base_score"`
	BaseFindingID    string            `json:"base_finding_id"`
	BaseFindingTitle string            `json:"base_finding_title"`
	HopContributions []HopContribution `json:"hop_contributions"`
	RawSum           float64           `json:"raw_sum"`
	Formula          string            `json:"formula"`
	Rationale        string            `json:"rationale"`
	IsVerified       bool              `json:"is_verified"`
	IsCapped         bool              `json:"is_capped"`
}

// NormalizeFindingScore extracts and normalizes a finding's score to the standard 0–100 scale.
func NormalizeFindingScore(n *NormalizedFinding) (float64, error) {
	if n == nil {
		return 0, errors.New("nil finding node")
	}

	score := float64(n.Score)
	if n.Score < 0 || n.Score > 100 {
		return 0, fmt.Errorf("%w: finding %q has invalid score %d", ErrInvalidFindingScore, n.ID, n.Score)
	}

	// If score is 0 but severity is specified, infer default base score on 0-100 scale
	if n.Score == 0 && n.Severity != "" {
		switch strings.ToUpper(strings.TrimSpace(n.Severity)) {
		case report.SeverityCritical:
			score = 85.0
		case report.SeverityHigh:
			score = 65.0
		case report.SeverityMedium:
			score = 40.0
		case report.SeverityLow:
			score = 20.0
		case report.SeverityInfo:
			score = 5.0
		default:
			score = 0.0
		}
	}

	return score, nil
}

// NormalizeConfidence converts confidence representations (string, float, or ValidationStatus)
// into a validated float64 in the range [0.0, 1.0].
func NormalizeConfidence(val any) (float64, error) {
	switch v := val.(type) {
	case float64:
		if math.IsNaN(v) || math.IsInf(v, 0) || v < 0.0 || v > 1.0 {
			return 0, fmt.Errorf("%w: float value %v", ErrInvalidConfidence, v)
		}
		return v, nil
	case float32:
		f := float64(v)
		if math.IsNaN(f) || math.IsInf(f, 0) || f < 0.0 || f > 1.0 {
			return 0, fmt.Errorf("%w: float value %v", ErrInvalidConfidence, f)
		}
		return f, nil
	case int:
		if v < 0 || v > 1 {
			return 0, fmt.Errorf("%w: int value %d", ErrInvalidConfidence, v)
		}
		return float64(v), nil
	case ValidationStatus:
		switch v {
		case ValidationConfirmed:
			return 1.0, nil
		case ValidationPlausible:
			return 0.75, nil
		case ValidationInconclusive:
			return 0.0, nil
		default:
			return 0.50, nil
		}
	case string:
		s := strings.ToUpper(strings.TrimSpace(v))
		switch s {
		case "1", "1.0", "1.00", report.ConfidenceHigh, "CONFIRMED":
			return 1.0, nil
		case "0.75", report.ConfidenceMedium, "PLAUSIBLE":
			return 0.75, nil
		case "0.5", "0.50", report.ConfidenceLow:
			return 0.50, nil
		case "0", "0.0", "0.00", "INCONCLUSIVE", "UNVERIFIED", "NONE":
			return 0.0, nil
		case "":
			return 0.50, nil
		default:
			// Attempt parsing as numeric string
			parsed, err := strconv.ParseFloat(s, 64)
			if err != nil || math.IsNaN(parsed) || math.IsInf(parsed, 0) || parsed < 0.0 || parsed > 1.0 {
				return 0, fmt.Errorf("%w: unparseable string %q", ErrInvalidConfidence, v)
			}
			return parsed, nil
		}
	default:
		return 0.50, nil
	}
}

// CalculateCompoundRiskFormula executes the pure mathematical model:
//
//	S_chain = min(100, max_i(w_i) + sum_{j=1}^{k-1} alpha_j * w_j * C_{edge,j})
func CalculateCompoundRiskFormula(baseScore float64, hops []HopInput, cfg CompoundRiskConfig) (float64, error) {
	if math.IsNaN(baseScore) || math.IsInf(baseScore, 0) || baseScore < 0.0 || baseScore > 100.0 {
		return 0, fmt.Errorf("%w: base score %v", ErrInvalidFindingScore, baseScore)
	}

	sumContributions := 0.0
	for _, hop := range hops {
		if math.IsNaN(hop.FindingScore) || math.IsInf(hop.FindingScore, 0) || hop.FindingScore < 0.0 || hop.FindingScore > 100.0 {
			return 0, fmt.Errorf("%w: hop %d finding score %v", ErrInvalidFindingScore, hop.HopIndex, hop.FindingScore)
		}
		if math.IsNaN(hop.EdgeConfidence) || math.IsInf(hop.EdgeConfidence, 0) || hop.EdgeConfidence < 0.0 || hop.EdgeConfidence > 1.0 {
			return 0, fmt.Errorf("%w: hop %d edge confidence %v", ErrInvalidConfidence, hop.HopIndex, hop.EdgeConfidence)
		}
		if math.IsNaN(hop.Alpha) || math.IsInf(hop.Alpha, 0) || hop.Alpha < 0.0 {
			return 0, fmt.Errorf("%w: hop %d coefficient %v", ErrInvalidCoefficient, hop.HopIndex, hop.Alpha)
		}

		contrib := hop.Alpha * hop.FindingScore * hop.EdgeConfidence
		sumContributions += contrib
	}

	rawTotal := baseScore + sumContributions
	maxCap := cfg.MaxRiskScore
	if maxCap <= 0 || maxCap > 100.0 {
		maxCap = 100.0
	}

	finalScore := math.Min(maxCap, rawTotal)
	if finalScore < cfg.MinRiskScore {
		finalScore = cfg.MinRiskScore
	}

	return finalScore, nil
}

// CalculateCompoundRisk evaluates an AttackPath using the compound risk multiplier model.
// It enforces no double counting, handles duplicate finding IDs/edges, verifies edge confidence,
// and ensures candidate/unverified paths cannot escalate primary risk.
func CalculateCompoundRisk(path *AttackPath, cfg CompoundRiskConfig) (*CompoundRiskResult, error) {
	if path == nil || len(path.Nodes) == 0 {
		return &CompoundRiskResult{
			Score:     0,
			Level:     report.SeverityInfo,
			Rationale: "Empty path; no findings to evaluate",
			Formula:   "S_chain = 0 (empty)",
		}, ErrEmptyPath
	}

	// 1. Validate all node scores and find the base node with max_i(w_i)
	maxScore := -1.0
	baseIdx := 0
	nodeScores := make([]float64, len(path.Nodes))

	for i := range path.Nodes {
		n := &path.Nodes[i]
		score, err := NormalizeFindingScore(n)
		if err != nil {
			return nil, err
		}
		nodeScores[i] = score

		if score > maxScore {
			maxScore = score
			baseIdx = i
		} else if score == maxScore {
			// Tie breaker: higher severity rank or earlier appearance
			if report.SeverityRank(n.Severity) > report.SeverityRank(path.Nodes[baseIdx].Severity) {
				maxScore = score
				baseIdx = i
			}
		}
	}

	baseNode := path.Nodes[baseIdx]
	baseScore := maxScore

	// Single finding chain: retains individual score without edge contributions
	if len(path.Nodes) == 1 {
		intScore := int(math.Round(baseScore))
		isVerified := path.Status == PathVerified || path.Status.IsEvidenceSupported()
		level := deriveRiskLevel(intScore, isVerified, baseNode.Severity)
		formula := fmt.Sprintf("S_chain = min(100, max(w_i)) = min(100, %.1f) = %d", baseScore, intScore)
		rationale := fmt.Sprintf("Single finding chain; risk anchored by %s finding '%s' (score: %d)",
			baseNode.Severity, baseNode.Title, intScore)

		return &CompoundRiskResult{
			Score:            intScore,
			Level:            level,
			BaseScore:        baseScore,
			BaseFindingID:    baseNode.ID,
			BaseFindingTitle: baseNode.Title,
			RawSum:           baseScore,
			Formula:          formula,
			Rationale:        rationale,
			IsVerified:       isVerified,
		}, nil
	}

	// 2. Multi-finding chain: map edges connecting nodes
	// Map edges by (sourceID -> targetID)
	type edgeKey struct {
		src, tgt string
	}
	edgeMap := make(map[edgeKey]Relationship)
	for _, e := range path.Edges {
		k := edgeKey{src: e.SourceFindingID, tgt: e.TargetFindingID}
		// In case of duplicates, preserve first or confirmed edge
		if existing, ok := edgeMap[k]; !ok || existing.ValidationStatus != ValidationConfirmed {
			edgeMap[k] = e
		}
	}

	// Track findings that have already contributed to prevent double counting
	seenFindingIDs := make(map[string]bool)
	seenFindingIDs[baseNode.ID] = true // Base finding can NEVER contribute again

	seenRootCauses := make(map[string]bool)
	baseRootCause := baseNode.NormalizedCategory + "@" + baseNode.Path
	seenRootCauses[baseRootCause] = true

	var hopContributions []HopContribution
	var hopInputs []HopInput
	var formulaTerms []string
	var rationaleFactors []string

	rationaleFactors = append(rationaleFactors, fmt.Sprintf("Base risk anchored by %s finding '%s' (score: %.0f)",
		baseNode.Severity, baseNode.Title, baseScore))

	hopNumber := 1
	var hasBrokenSequence bool
	var hasUnverifiedHop bool

	// Iterate through non-base nodes to calculate eligible contributions
	for i := range path.Nodes {
		node := path.Nodes[i]
		if i == baseIdx || seenFindingIDs[node.ID] {
			continue // Skip base node or duplicate finding ID
		}

		score := nodeScores[i]

		// Locate edge associated with this node transition in the chain
		var matchedEdge Relationship
		var hasEdge bool

		var expectedSrcID, expectedTgtID string
		var expectedEdgeIdx int

		if i < baseIdx {
			// Precedes base node: edge transitions forward towards base (node -> next)
			expectedSrcID = node.ID
			expectedTgtID = path.Nodes[i+1].ID
			expectedEdgeIdx = i
		} else {
			// Follows base node: edge transitions from predecessor towards node (pred -> node)
			expectedSrcID = path.Nodes[i-1].ID
			expectedTgtID = node.ID
			expectedEdgeIdx = i - 1
		}

		// 1. Direct lookup by expected transition endpoints
		if e, ok := edgeMap[edgeKey{src: expectedSrcID, tgt: expectedTgtID}]; ok {
			matchedEdge = e
			hasEdge = true
		} else if expectedEdgeIdx >= 0 && expectedEdgeIdx < len(path.Edges) {
			// 2. Positional lookup: allow for synthetic/anonymous test fixtures where endpoints are omitted,
			// provided the edge does not explicitly conflict with the expected transition endpoints.
			posEdge := path.Edges[expectedEdgeIdx]
			srcMatches := posEdge.SourceFindingID == "" || posEdge.SourceFindingID == expectedSrcID
			tgtMatches := posEdge.TargetFindingID == "" || posEdge.TargetFindingID == expectedTgtID
			if srcMatches && tgtMatches {
				matchedEdge = posEdge
				hasEdge = true
			}
		}

		if !hasEdge {
			hasBrokenSequence = true
		}

		// Evaluate edge confidence
		edgeConf := 0.0
		if hasEdge {
			if matchedEdge.Confidence != "" {
				conf, err := NormalizeConfidence(matchedEdge.Confidence)
				if err != nil {
					return nil, fmt.Errorf("node %s: %w", node.ID, err)
				}
				edgeConf = conf
			} else if matchedEdge.ValidationStatus != "" {
				conf, _ := NormalizeConfidence(matchedEdge.ValidationStatus)
				edgeConf = conf
			} else {
				edgeConf = 0.50
			}

			// If relationship validation status is INCONCLUSIVE, or confidence is zero, hop is unverified
			if matchedEdge.ValidationStatus == ValidationInconclusive || edgeConf == 0.0 {
				edgeConf = 0.0
				hasUnverifiedHop = true
			}
		}

		// Shared Root Cause Guard: prevent duplicate risk inflation if findings share defect
		rcKey := node.NormalizedCategory + "@" + node.Path
		isSharedRootCause := seenRootCauses[rcKey] && rcKey != "@"
		seenRootCauses[rcKey] = true

		alpha := cfg.GetAlpha(hopNumber, matchedEdge.RuleCode)
		if math.IsNaN(alpha) || math.IsInf(alpha, 0) || alpha < 0.0 {
			return nil, fmt.Errorf("%w: hop %d", ErrInvalidCoefficient, hopNumber)
		}

		var hopContrib float64
		var skippedReason string

		if !hasEdge {
			skippedReason = "Missing or mismatched sequence edge connecting node"
			hopContrib = 0.0
		} else if isSharedRootCause {
			skippedReason = "duplicate risk inflation prevented (shared root cause)"
			hopContrib = 0.0
		} else if edgeConf == 0.0 {
			skippedReason = "Zero edge confidence; no risk increase"
			hopContrib = 0.0
		} else {
			hopContrib = alpha * score * edgeConf
		}

		hopContribRecord := HopContribution{
			HopIndex:         hopNumber,
			SourceFindingID: matchedEdge.SourceFindingID,
			TargetFindingID: matchedEdge.TargetFindingID,
			FindingID:        node.ID,
			FindingScore:     score,
			EdgeConfidence:   edgeConf,
			AlphaCoefficient: alpha,
			Contribution:     hopContrib,
			RuleCode:         matchedEdge.RuleCode,
			SkippedReason:    skippedReason,
		}
		hopContributions = append(hopContributions, hopContribRecord)

		if skippedReason == "" {
			hopInputs = append(hopInputs, HopInput{
				HopIndex:       hopNumber,
				FindingID:      node.ID,
				FindingScore:   score,
				EdgeConfidence: edgeConf,
				Alpha:          alpha,
				RuleCode:       matchedEdge.RuleCode,
			})
			formulaTerms = append(formulaTerms, fmt.Sprintf("(%.2f * %.0f * %.2f = +%.1f pts)",
				alpha, score, edgeConf, hopContrib))
			rationaleFactors = append(rationaleFactors, fmt.Sprintf("+%.1f pts from %s '%s' (conf: %.2f)",
				hopContrib, node.Severity, node.Title, edgeConf))
		} else {
			rationaleFactors = append(rationaleFactors, fmt.Sprintf("+0 pts from '%s' (%s)", node.Title, skippedReason))
		}

		seenFindingIDs[node.ID] = true
		hopNumber++
	}

	// 3. Compute raw composite score via the formula
	calculatedScore, err := CalculateCompoundRiskFormula(baseScore, hopInputs, cfg)
	if err != nil {
		return nil, err
	}

	rawSum := calculatedScore
	isCapped := false

	// Candidate/Unverified Path Safeguard:
	// An unverified, candidate, broken, or inconclusive path must NEVER receive Critical or exceed UnverifiedScoreCap (65 pts)
	isVerified := (path.Status == PathVerified || path.Status.IsEvidenceSupported()) && !hasBrokenSequence && !hasUnverifiedHop
	if !isVerified {
		unverifiedCap := cfg.UnverifiedScoreCap
		if unverifiedCap <= 0 {
			unverifiedCap = 65.0
		}
		if calculatedScore > unverifiedCap {
			calculatedScore = unverifiedCap
			isCapped = true
		}
		if hasBrokenSequence {
			rationaleFactors = append(rationaleFactors, fmt.Sprintf("Provisional score capped at %.0f pts (HIGH) due to broken or incomplete edge sequence", unverifiedCap))
		} else if hasUnverifiedHop {
			rationaleFactors = append(rationaleFactors, fmt.Sprintf("Provisional score capped at %.0f pts (HIGH) due to unverified or inconclusive transition in chain", unverifiedCap))
		} else {
			rationaleFactors = append(rationaleFactors, fmt.Sprintf("Provisional score capped at %.0f pts (HIGH) because path is %s", unverifiedCap, path.Status))
		}
	}

	finalScore := int(math.Round(calculatedScore))
	if finalScore < 0 {
		finalScore = 0
	}
	if finalScore > 100 {
		finalScore = 100
	}

	level := deriveRiskLevel(finalScore, isVerified, baseNode.Severity)

	var formulaStr string
	if len(formulaTerms) > 0 {
		formulaStr = fmt.Sprintf("S_chain = min(100, %.1f base + [%s]) = %d",
			baseScore, strings.Join(formulaTerms, " + "), finalScore)
	} else {
		formulaStr = fmt.Sprintf("S_chain = min(100, %.1f base) = %d", baseScore, finalScore)
	}

	rationale := strings.Join(rationaleFactors, "; ")

	return &CompoundRiskResult{
		Score:            finalScore,
		Level:            level,
		BaseScore:        baseScore,
		BaseFindingID:    baseNode.ID,
		BaseFindingTitle: baseNode.Title,
		HopContributions: hopContributions,
		RawSum:           rawSum,
		Formula:          formulaStr,
		Rationale:        rationale,
		IsVerified:       isVerified,
		IsCapped:         isCapped,
	}, nil
}

// AssessPathRisk computes the combined risk score (0-100), categorical risk level,
// and human-readable risk rationale for an attack path using the compound multiplier model:
//
//	S_chain = min(100, max_i(w_i) + sum_{j=1}^{k-1} alpha_j * w_j * C_{edge,j})
//
// This function satisfies backward-compatibility with all existing FELIX callers.
func AssessPathRisk(path *AttackPath) (int, string, string) {
	if path == nil || len(path.Nodes) == 0 {
		return 0, report.SeverityInfo, "Empty path; no findings to evaluate"
	}

	cfg := DefaultCompoundRiskConfig()
	result, err := CalculateCompoundRisk(path, cfg)
	if err != nil {
		// Fallback for malformed input without panic
		if errors.Is(err, ErrEmptyPath) {
			return 0, report.SeverityInfo, "Empty path; no findings to evaluate"
		}
		return 0, report.SeverityInfo, fmt.Sprintf("Risk calculation error: %v", err)
	}

	return result.Score, result.Level, result.Rationale
}

// deriveRiskLevel maps a numeric composite risk score [0, 100] to its categorical band.
// Unverified / Candidate paths cannot be elevated to Critical.
func deriveRiskLevel(score int, isVerified bool, topSev string) string {
	if !isVerified && score >= 80 {
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
