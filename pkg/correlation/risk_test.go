package correlation

import (
	"math"
	"strings"
	"testing"

	"felix/pkg/report"
)

// 1. Empty chain test
func TestRisk_EmptyChain(t *testing.T) {
	emptyPath := &AttackPath{}
	score, level, rationale := AssessPathRisk(emptyPath)
	if score != 0 {
		t.Errorf("expected score 0 for empty path, got %d", score)
	}
	if level != report.SeverityInfo {
		t.Errorf("expected SeverityInfo for empty path, got %s", level)
	}
	if !strings.Contains(rationale, "Empty path") {
		t.Errorf("expected rationale to state empty path, got %s", rationale)
	}

	// Typed error check
	_, err := CalculateCompoundRisk(emptyPath, DefaultCompoundRiskConfig())
	if err != ErrEmptyPath {
		t.Errorf("expected ErrEmptyPath, got %v", err)
	}
}

// 2. Single-finding chain: retains individual score without edge bonuses
func TestRisk_SingleFindingChain(t *testing.T) {
	testCases := []struct {
		name     string
		finding  NormalizedFinding
		expected int
		level    string
	}{
		{
			name:     "Single Medium 40",
			finding:  NormalizedFinding{ID: "F-MED", Title: "Medium Issue", Severity: report.SeverityMedium, Score: 40},
			expected: 40,
			level:    report.SeverityMedium,
		},
		{
			name:     "Single Low 20",
			finding:  NormalizedFinding{ID: "F-LOW", Title: "Low Issue", Severity: report.SeverityLow, Score: 20},
			expected: 20,
			level:    report.SeverityLow,
		},
		{
			name:     "Single High 65",
			finding:  NormalizedFinding{ID: "F-HIGH", Title: "High Issue", Severity: report.SeverityHigh, Score: 65},
			expected: 65,
			level:    report.SeverityHigh,
		},
		{
			name:     "Single Critical 85",
			finding:  NormalizedFinding{ID: "F-CRIT", Title: "Critical Issue", Severity: report.SeverityCritical, Score: 85},
			expected: 85,
			level:    report.SeverityCritical,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			path := &AttackPath{
				Status: PathVerified,
				Nodes:  []NormalizedFinding{tc.finding},
			}
			score, level, rationale := AssessPathRisk(path)
			if score != tc.expected {
				t.Errorf("single finding score mismatch: got %d, expected %d", score, tc.expected)
			}
			if level != tc.level {
				t.Errorf("single finding level mismatch: got %s, expected %s", level, tc.level)
			}
			if !strings.Contains(rationale, "Single finding chain") {
				t.Errorf("expected single finding rationale, got: %s", rationale)
			}
		})
	}
}

// 3. Medium 40 + Low 20 + Low 20 escalation example:
// Base = 40 (Medium), Hop 1: alpha*20*1.0 = 20, Hop 2: alpha*20*1.0 = 20 -> Total = 80 (CRITICAL)
func TestRisk_Escalation_Medium40_Low20_Low20(t *testing.T) {
	n1 := NormalizedFinding{ID: "N1", Title: "Medium Weakness", Severity: report.SeverityMedium, Score: 40}
	n2 := NormalizedFinding{ID: "N2", Title: "Low Finding 1", Severity: report.SeverityLow, Score: 20}
	n3 := NormalizedFinding{ID: "N3", Title: "Low Finding 2", Severity: report.SeverityLow, Score: 20}

	edges := []Relationship{
		{
			SourceFindingID: "N1",
			TargetFindingID: "N2",
			RuleCode:        RuleCOR01,
			Confidence:      "HIGH", // 1.0
			ValidationStatus: ValidationConfirmed,
		},
		{
			SourceFindingID: "N2",
			TargetFindingID: "N3",
			RuleCode:        RuleCOR02,
			Confidence:      "HIGH", // 1.0
			ValidationStatus: ValidationConfirmed,
		},
	}

	path := &AttackPath{
		ID:     "PATH-MED-LOW-LOW",
		Status: PathVerified,
		Nodes:  []NormalizedFinding{n1, n2, n3},
		Edges:  edges,
	}

	cfg := DefaultCompoundRiskConfig()
	res, err := CalculateCompoundRisk(path, cfg)
	if err != nil {
		t.Fatalf("CalculateCompoundRisk failed: %v", err)
	}

	// 40 + (1.0 * 20 * 1.0) + (1.0 * 20 * 1.0) = 80
	if res.Score != 80 {
		t.Errorf("expected composite score 80 (40+20+20), got %d (formula: %s)", res.Score, res.Formula)
	}
	if res.Level != report.SeverityCritical {
		t.Errorf("expected level CRITICAL for score 80, got %s", res.Level)
	}
	if res.BaseScore != 40.0 {
		t.Errorf("expected base score 40.0, got %f", res.BaseScore)
	}
	if len(res.HopContributions) != 2 {
		t.Fatalf("expected 2 hop contributions, got %d", len(res.HopContributions))
	}
	if res.HopContributions[0].Contribution != 20.0 || res.HopContributions[1].Contribution != 20.0 {
		t.Errorf("expected hop contributions 20.0 and 20.0, got %f and %f",
			res.HopContributions[0].Contribution, res.HopContributions[1].Contribution)
	}

	// AssessPathRisk backward compatibility check
	score, level, _ := AssessPathRisk(path)
	if score != 80 || level != report.SeverityCritical {
		t.Errorf("AssessPathRisk returned %d (%s), expected 80 (CRITICAL)", score, level)
	}
}

// 4. Different edge confidence values: higher confidence contributes more
func TestRisk_EdgeConfidenceWeighting(t *testing.T) {
	n1 := NormalizedFinding{ID: "N1", Severity: report.SeverityMedium, Score: 40}
	n2 := NormalizedFinding{ID: "N2", Severity: report.SeverityMedium, Score: 40}

	// High confidence edge (1.0) -> contribution = 40
	pathHigh := &AttackPath{
		Status: PathVerified,
		Nodes:  []NormalizedFinding{n1, n2},
		Edges: []Relationship{
			{SourceFindingID: "N1", TargetFindingID: "N2", Confidence: "HIGH", ValidationStatus: ValidationConfirmed},
		},
	}
	scoreHigh, _, _ := AssessPathRisk(pathHigh)

	// Medium confidence edge (0.75) -> contribution = 30
	pathMed := &AttackPath{
		Status: PathVerified,
		Nodes:  []NormalizedFinding{n1, n2},
		Edges: []Relationship{
			{SourceFindingID: "N1", TargetFindingID: "N2", Confidence: "MEDIUM", ValidationStatus: ValidationPlausible},
		},
	}
	scoreMed, _, _ := AssessPathRisk(pathMed)

	// Low confidence edge (0.50) -> contribution = 20
	pathLow := &AttackPath{
		Status: PathVerified,
		Nodes:  []NormalizedFinding{n1, n2},
		Edges: []Relationship{
			{SourceFindingID: "N1", TargetFindingID: "N2", Confidence: "LOW", ValidationStatus: ValidationPlausible},
		},
	}
	scoreLow, _, _ := AssessPathRisk(pathLow)

	if scoreHigh != 80 {
		t.Errorf("expected High confidence score 80 (40+40), got %d", scoreHigh)
	}
	if scoreMed != 70 {
		t.Errorf("expected Medium confidence score 70 (40+30), got %d", scoreMed)
	}
	if scoreLow != 60 {
		t.Errorf("expected Low confidence score 60 (40+20), got %d", scoreLow)
	}

	if !(scoreHigh > scoreMed && scoreMed > scoreLow) {
		t.Errorf("monotonicity violation across confidence levels: %d > %d > %d", scoreHigh, scoreMed, scoreLow)
	}
}

// 5. Zero-confidence edges: contribute no risk increase
func TestRisk_ZeroConfidenceEdge(t *testing.T) {
	n1 := NormalizedFinding{ID: "N1", Severity: report.SeverityMedium, Score: 40}
	n2 := NormalizedFinding{ID: "N2", Severity: report.SeverityLow, Score: 20}

	pathZeroConf := &AttackPath{
		Status: PathVerified,
		Nodes:  []NormalizedFinding{n1, n2},
		Edges: []Relationship{
			{
				SourceFindingID: "N1",
				TargetFindingID: "N2",
				Confidence:      "0.0",
				ValidationStatus: ValidationInconclusive, // Inconclusive / 0.0 confidence
			},
		},
	}

	score, _, rationale := AssessPathRisk(pathZeroConf)
	if score != 40 {
		t.Errorf("zero-confidence edge must contribute 0 risk: expected 40, got %d", score)
	}
	if !strings.Contains(rationale, "Zero edge confidence") && !strings.Contains(rationale, "+0 pts") {
		t.Errorf("expected rationale to indicate zero edge contribution, got: %s", rationale)
	}
}

// 6. Maximum score cap at 100
func TestRisk_MaxCapAt100(t *testing.T) {
	n1 := NormalizedFinding{ID: "N1", Severity: report.SeverityCritical, Score: 85}
	n2 := NormalizedFinding{ID: "N2", Severity: report.SeverityHigh, Score: 70}
	n3 := NormalizedFinding{ID: "N3", Severity: report.SeverityHigh, Score: 70}

	edges := []Relationship{
		{SourceFindingID: "N1", TargetFindingID: "N2", Confidence: "HIGH", ValidationStatus: ValidationConfirmed},
		{SourceFindingID: "N2", TargetFindingID: "N3", Confidence: "HIGH", ValidationStatus: ValidationConfirmed},
	}

	path := &AttackPath{
		Status: PathVerified,
		Nodes:  []NormalizedFinding{n1, n2, n3},
		Edges:  edges,
	}

	score, level, _ := AssessPathRisk(path)
	if score > 100 {
		t.Errorf("composite score exceeded 100: got %d", score)
	}
	if score != 100 {
		t.Errorf("expected score capped at 100 (85+70+70 = 225 -> 100), got %d", score)
	}
	if level != report.SeverityCritical {
		t.Errorf("expected CRITICAL for 100 score, got %s", level)
	}
}

// 7. Invalid negative or greater-than-100 finding scores
func TestRisk_InvalidFindingScores(t *testing.T) {
	// Negative score
	negPath := &AttackPath{
		Nodes: []NormalizedFinding{
			{ID: "N-NEG", Score: -15, Severity: report.SeverityHigh},
		},
	}
	_, errNeg := CalculateCompoundRisk(negPath, DefaultCompoundRiskConfig())
	if errNeg == nil || !strings.Contains(errNeg.Error(), "out of valid range") {
		t.Errorf("expected error for negative finding score, got: %v", errNeg)
	}

	// Score > 100
	overPath := &AttackPath{
		Nodes: []NormalizedFinding{
			{ID: "N-OVER", Score: 125, Severity: report.SeverityCritical},
		},
	}
	_, errOver := CalculateCompoundRisk(overPath, DefaultCompoundRiskConfig())
	if errOver == nil || !strings.Contains(errOver.Error(), "out of valid range") {
		t.Errorf("expected error for score > 100, got: %v", errOver)
	}
}

// 8. Invalid, missing, NaN, or infinite confidence values
func TestRisk_InvalidConfidenceValues(t *testing.T) {
	testCases := []struct {
		name string
		conf any
	}{
		{"NaN float", math.NaN()},
		{"Positive Inf", math.Inf(1)},
		{"Negative Inf", math.Inf(-1)},
		{"Negative float", -0.25},
		{"Over 1.0 float", 1.50},
		{"Invalid string", "not-a-confidence-level"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := NormalizeConfidence(tc.conf)
			if err == nil {
				t.Errorf("expected error for invalid confidence %v, got nil", tc.conf)
			}
		})
	}
}

// 9. Missing or mismatched edges
func TestRisk_MissingMismatchedEdges(t *testing.T) {
	n1 := NormalizedFinding{ID: "N1", Severity: report.SeverityMedium, Score: 40}
	n2 := NormalizedFinding{ID: "N2", Severity: report.SeverityLow, Score: 20}

	// Path with no edges provided
	pathNoEdge := &AttackPath{
		Status: PathVerified,
		Nodes:  []NormalizedFinding{n1, n2},
		Edges:  nil,
	}

	score, _, rationale := AssessPathRisk(pathNoEdge)
	if score != 40 {
		t.Errorf("missing edge must not contribute risk: expected 40, got %d", score)
	}
	if !strings.Contains(rationale, "Missing sequence edge") && !strings.Contains(rationale, "+0 pts") {
		t.Errorf("expected rationale to note missing edge, got: %s", rationale)
	}
}

// 10. Duplicate finding IDs and duplicate edges
func TestRisk_DuplicateFindingsAndEdges(t *testing.T) {
	n1 := NormalizedFinding{ID: "N1", Severity: report.SeverityMedium, Score: 40}
	n2 := NormalizedFinding{ID: "N2", Severity: report.SeverityLow, Score: 20}
	// Duplicate of N1 in sequence
	n1Dup := NormalizedFinding{ID: "N1", Severity: report.SeverityMedium, Score: 40}

	edges := []Relationship{
		{SourceFindingID: "N1", TargetFindingID: "N2", Confidence: "HIGH", ValidationStatus: ValidationConfirmed},
		// Repeated edge
		{SourceFindingID: "N1", TargetFindingID: "N2", Confidence: "HIGH", ValidationStatus: ValidationConfirmed},
		{SourceFindingID: "N2", TargetFindingID: "N1", Confidence: "HIGH", ValidationStatus: ValidationConfirmed},
	}

	path := &AttackPath{
		Status: PathVerified,
		Nodes:  []NormalizedFinding{n1, n2, n1Dup},
		Edges:  edges,
	}

	res, err := CalculateCompoundRisk(path, DefaultCompoundRiskConfig())
	if err != nil {
		t.Fatalf("CalculateCompoundRisk failed: %v", err)
	}

	// Base = 40 (N1). N2 contributes 20. N1 duplicate contributes 0. Total = 60.
	if res.Score != 60 {
		t.Errorf("duplicate finding ID inflated risk: expected score 60, got %d", res.Score)
	}
}

// 11. Cycle handling: cycle A -> B -> C -> A
func TestRisk_CycleHandling(t *testing.T) {
	nA := NormalizedFinding{ID: "NA", Severity: report.SeverityMedium, Score: 40}
	nB := NormalizedFinding{ID: "NB", Severity: report.SeverityLow, Score: 20}
	nC := NormalizedFinding{ID: "NC", Severity: report.SeverityLow, Score: 20}
	nACycle := NormalizedFinding{ID: "NA", Severity: report.SeverityMedium, Score: 40}

	edges := []Relationship{
		{SourceFindingID: "NA", TargetFindingID: "NB", Confidence: "HIGH", ValidationStatus: ValidationConfirmed},
		{SourceFindingID: "NB", TargetFindingID: "NC", Confidence: "HIGH", ValidationStatus: ValidationConfirmed},
		{SourceFindingID: "NC", TargetFindingID: "NA", Confidence: "HIGH", ValidationStatus: ValidationConfirmed},
	}

	path := &AttackPath{
		Status: PathVerified,
		Nodes:  []NormalizedFinding{nA, nB, nC, nACycle},
		Edges:  edges,
	}

	res, err := CalculateCompoundRisk(path, DefaultCompoundRiskConfig())
	if err != nil {
		t.Fatalf("CalculateCompoundRisk failed: %v", err)
	}

	// Base NA (40) + NB (20) + NC (20) = 80. Cyclic NA must contribute 0. Total = 80.
	if res.Score != 80 {
		t.Errorf("cycle handling failed: expected 80, got %d", res.Score)
	}
}

// 12. Candidate and inconclusive paths do not escalate primary risk
func TestRisk_CandidatePathsCappedAndIsolated(t *testing.T) {
	n1 := NormalizedFinding{ID: "N1", Severity: report.SeverityCritical, Score: 85}
	n2 := NormalizedFinding{ID: "N2", Severity: report.SeverityHigh, Score: 70}

	edges := []Relationship{
		{SourceFindingID: "N1", TargetFindingID: "N2", Confidence: "HIGH", ValidationStatus: ValidationConfirmed},
	}

	// Unverified Candidate Path
	candPath := &AttackPath{
		Status: PathCandidate,
		Nodes:  []NormalizedFinding{n1, n2},
		Edges:  edges,
	}

	res, err := CalculateCompoundRisk(candPath, DefaultCompoundRiskConfig())
	if err != nil {
		t.Fatalf("CalculateCompoundRisk failed: %v", err)
	}

	// Unverified candidate score must be capped at 65 (High band)
	if res.Score > 65 {
		t.Errorf("candidate path exceeded safety cap of 65: got %d", res.Score)
	}
	if res.Level != report.SeverityHigh {
		t.Errorf("candidate path level must not be CRITICAL: got %s", res.Level)
	}
	if !res.IsCapped {
		t.Errorf("expected IsCapped to be true for candidate path")
	}

	// Inconclusive Path
	inconPath := &AttackPath{
		Status: PathInconclusive,
		Nodes:  []NormalizedFinding{n1, n2},
		Edges:  edges,
	}
	scoreIncon, levelIncon, _ := AssessPathRisk(inconPath)
	if scoreIncon > 65 || levelIncon == report.SeverityCritical {
		t.Errorf("inconclusive path escalated risk: score %d, level %s", scoreIncon, levelIncon)
	}
}

// 13. Verified paths correctly affecting composite risk
func TestRisk_VerifiedPathsAffectCompositeRisk(t *testing.T) {
	n1 := NormalizedFinding{ID: "N1", Severity: report.SeverityHigh, Score: 60}
	n2 := NormalizedFinding{ID: "N2", Severity: report.SeverityMedium, Score: 30}

	edges := []Relationship{
		{SourceFindingID: "N1", TargetFindingID: "N2", Confidence: "HIGH", ValidationStatus: ValidationConfirmed},
	}

	verifiedPath := &AttackPath{
		Status: PathVerified,
		Nodes:  []NormalizedFinding{n1, n2},
		Edges:  edges,
	}

	res, err := CalculateCompoundRisk(verifiedPath, DefaultCompoundRiskConfig())
	if err != nil {
		t.Fatalf("CalculateCompoundRisk failed: %v", err)
	}

	// 60 + 30 = 90 (CRITICAL)
	if res.Score != 90 {
		t.Errorf("expected verified path score 90, got %d", res.Score)
	}
	if res.Level != report.SeverityCritical {
		t.Errorf("expected level CRITICAL, got %s", res.Level)
	}
	if !res.IsVerified {
		t.Errorf("expected IsVerified to be true")
	}
}

// 14. Deterministic output across repeated calculations
func TestRisk_DeterministicExecution(t *testing.T) {
	n1 := NormalizedFinding{ID: "N1", Severity: report.SeverityMedium, Score: 45}
	n2 := NormalizedFinding{ID: "N2", Severity: report.SeverityLow, Score: 25}
	edges := []Relationship{
		{SourceFindingID: "N1", TargetFindingID: "N2", Confidence: "HIGH", ValidationStatus: ValidationConfirmed},
	}
	path := &AttackPath{
		Status: PathVerified,
		Nodes:  []NormalizedFinding{n1, n2},
		Edges:  edges,
	}

	score1, lvl1, rat1 := AssessPathRisk(path)
	score2, lvl2, rat2 := AssessPathRisk(path)
	score3, lvl3, rat3 := AssessPathRisk(path)

	if score1 != score2 || score2 != score3 {
		t.Errorf("non-deterministic scores: %d, %d, %d", score1, score2, score3)
	}
	if lvl1 != lvl2 || lvl2 != lvl3 {
		t.Errorf("non-deterministic levels: %s, %s, %s", lvl1, lvl2, lvl3)
	}
	if rat1 != rat2 || rat2 != rat3 {
		t.Errorf("non-deterministic rationale: %s != %s", rat1, rat2)
	}
}

// 15. Individual finding scores remaining unchanged
func TestRisk_InputFindingsImmutability(t *testing.T) {
	origN1 := NormalizedFinding{ID: "N1", Severity: report.SeverityMedium, Score: 40}
	origN2 := NormalizedFinding{ID: "N2", Severity: report.SeverityLow, Score: 20}

	n1 := origN1
	n2 := origN2

	path := &AttackPath{
		Status: PathVerified,
		Nodes:  []NormalizedFinding{n1, n2},
		Edges: []Relationship{
			{SourceFindingID: "N1", TargetFindingID: "N2", Confidence: "HIGH", ValidationStatus: ValidationConfirmed},
		},
	}

	AssessPathRisk(path)

	if path.Nodes[0].Score != origN1.Score || path.Nodes[0].Severity != origN1.Severity {
		t.Errorf("input finding N1 was mutated: score %d vs %d", path.Nodes[0].Score, origN1.Score)
	}
	if path.Nodes[1].Score != origN2.Score || path.Nodes[1].Severity != origN2.Severity {
		t.Errorf("input finding N2 was mutated: score %d vs %d", path.Nodes[1].Score, origN2.Score)
	}
}

// 16. Pure Formula Unit Tests
func TestRisk_PureFormula(t *testing.T) {
	cfg := DefaultCompoundRiskConfig()

	// Base 40, Hops: 20 (conf 1.0), 20 (conf 1.0) -> 80
	hops := []HopInput{
		{HopIndex: 1, FindingScore: 20.0, EdgeConfidence: 1.0, Alpha: 1.0},
		{HopIndex: 2, FindingScore: 20.0, EdgeConfidence: 1.0, Alpha: 1.0},
	}

	score, err := CalculateCompoundRiskFormula(40.0, hops, cfg)
	if err != nil {
		t.Fatalf("CalculateCompoundRiskFormula failed: %v", err)
	}
	if score != 80.0 {
		t.Errorf("expected 80.0, got %f", score)
	}

	// Monotonicity: increasing secondary score increases composite score
	hopsHigher := []HopInput{
		{HopIndex: 1, FindingScore: 30.0, EdgeConfidence: 1.0, Alpha: 1.0},
		{HopIndex: 2, FindingScore: 20.0, EdgeConfidence: 1.0, Alpha: 1.0},
	}
	scoreHigher, _ := CalculateCompoundRiskFormula(40.0, hopsHigher, cfg)
	if scoreHigher <= score {
		t.Errorf("monotonicity failed: scoreHigher (%f) <= score (%f)", scoreHigher, score)
	}
}

// 17. Broken edge sequence: missing middle or tail edge must NOT be reported as verified
func TestRisk_BrokenEdgeSequence(t *testing.T) {
	n1 := NormalizedFinding{ID: "N1", Severity: report.SeverityMedium, Score: 40}
	n2 := NormalizedFinding{ID: "N2", Severity: report.SeverityMedium, Score: 30}
	n3 := NormalizedFinding{ID: "N3", Severity: report.SeverityMedium, Score: 30}

	// Only 1 edge for a 3-node sequence (missing N2 -> N3)
	path := &AttackPath{
		Status: PathVerified, // Claims verified, but edge sequence is incomplete
		Nodes:  []NormalizedFinding{n1, n2, n3},
		Edges: []Relationship{
			{SourceFindingID: "N1", TargetFindingID: "N2", Confidence: "HIGH", ValidationStatus: ValidationConfirmed},
		},
	}

	cfg := DefaultCompoundRiskConfig()
	res, err := CalculateCompoundRisk(path, cfg)
	if err != nil {
		t.Fatalf("CalculateCompoundRisk failed: %v", err)
	}

	// Base 40 + N2 (30) = 70 raw. With broken sequence, path MUST NOT be verified
	if res.IsVerified {
		t.Errorf("path with broken edge sequence was reported as verified!")
	}
	// Score must be capped at 65 (High band)
	if res.Score > 65 {
		t.Errorf("broken path score %d exceeded unverified cap 65", res.Score)
	}
	if res.Level != report.SeverityHigh {
		t.Errorf("expected level High for capped broken path, got %s", res.Level)
	}
	if !res.IsCapped {
		t.Errorf("expected IsCapped = true for broken path with raw score 70")
	}

	// Hop 2 (N3) must have contributed 0 risk
	if len(res.HopContributions) != 2 {
		t.Fatalf("expected 2 hop contributions recorded, got %d", len(res.HopContributions))
	}
	if res.HopContributions[1].Contribution != 0.0 {
		t.Errorf("missing edge hop contributed non-zero risk: %f", res.HopContributions[1].Contribution)
	}
	if !strings.Contains(res.HopContributions[1].SkippedReason, "Missing or mismatched") {
		t.Errorf("expected skipped reason to explain missing/mismatched edge, got: %s", res.HopContributions[1].SkippedReason)
	}
}

// 18. Incorrect edge mapping: edge endpoints pointing to completely different findings
func TestRisk_IncorrectEdgeMapping(t *testing.T) {
	n1 := NormalizedFinding{ID: "N1", Severity: report.SeverityMedium, Score: 40}
	n2 := NormalizedFinding{ID: "N2", Severity: report.SeverityMedium, Score: 40}
	n3 := NormalizedFinding{ID: "N3", Severity: report.SeverityMedium, Score: 40}

	path := &AttackPath{
		Status: PathVerified,
		Nodes:  []NormalizedFinding{n1, n2, n3},
		Edges: []Relationship{
			{SourceFindingID: "N1", TargetFindingID: "N2", Confidence: "HIGH", ValidationStatus: ValidationConfirmed},
			// Mismatched edge connecting UNRELATED_A -> UNRELATED_B instead of N2 -> N3
			{SourceFindingID: "UNRELATED_A", TargetFindingID: "UNRELATED_B", Confidence: "HIGH", ValidationStatus: ValidationConfirmed},
		},
	}

	cfg := DefaultCompoundRiskConfig()
	res, err := CalculateCompoundRisk(path, cfg)
	if err != nil {
		t.Fatalf("CalculateCompoundRisk failed: %v", err)
	}

	if res.IsVerified {
		t.Errorf("path with mismatched edge endpoints was reported as verified!")
	}
	if res.Score > 65 {
		t.Errorf("score %d exceeded unverified cap 65", res.Score)
	}
	if res.HopContributions[1].Contribution != 0.0 {
		t.Errorf("mismatched edge contributed non-zero risk: %f", res.HopContributions[1].Contribution)
	}
}

// 19. Mixed verified and unverified/inconclusive paths
func TestRisk_MixedVerifiedAndUnverifiedEdges(t *testing.T) {
	n1 := NormalizedFinding{ID: "N1", Severity: report.SeverityMedium, Score: 40}
	n2 := NormalizedFinding{ID: "N2", Severity: report.SeverityMedium, Score: 40}
	n3 := NormalizedFinding{ID: "N3", Severity: report.SeverityMedium, Score: 40}

	// Edge 1 is Confirmed (1.0), Edge 2 is Inconclusive (0.0)
	path := &AttackPath{
		Status: PathVerified,
		Nodes:  []NormalizedFinding{n1, n2, n3},
		Edges: []Relationship{
			{SourceFindingID: "N1", TargetFindingID: "N2", Confidence: "HIGH", ValidationStatus: ValidationConfirmed},
			{SourceFindingID: "N2", TargetFindingID: "N3", Confidence: "0.0", ValidationStatus: ValidationInconclusive},
		},
	}

	cfg := DefaultCompoundRiskConfig()
	res, err := CalculateCompoundRisk(path, cfg)
	if err != nil {
		t.Fatalf("CalculateCompoundRisk failed: %v", err)
	}

	// Base 40 + N2 (40) = 80 raw sum. Inconclusive hop contributes 0.
	// Since chain contains an inconclusive transition, path as a whole is NOT fully verified.
	if res.IsVerified {
		t.Errorf("path containing inconclusive transition must not be reported as verified")
	}
	// Raw sum is 80, but capped at 65 (High) because path is not fully verified
	if res.Score > 65 {
		t.Errorf("mixed unverified path escalated to score %d (must be capped at 65)", res.Score)
	}
	if res.Level != report.SeverityHigh {
		t.Errorf("expected SeverityHigh for unverified path, got %s", res.Level)
	}
	if !res.IsCapped {
		t.Errorf("expected IsCapped = true")
	}
	if res.HopContributions[1].Contribution != 0.0 {
		t.Errorf("inconclusive hop contributed non-zero: %f", res.HopContributions[1].Contribution)
	}
}

// 20. Configurable hop coefficients and rule-specific overrides
func TestRisk_ConfigurableCoefficientsAndRuleOverrides(t *testing.T) {
	n1 := NormalizedFinding{ID: "N1", Severity: report.SeverityMedium, Score: 40}
	n2 := NormalizedFinding{ID: "N2", Severity: report.SeverityLow, Score: 20}
	n3 := NormalizedFinding{ID: "N3", Severity: report.SeverityLow, Score: 20}

	path := &AttackPath{
		Status: PathVerified,
		Nodes:  []NormalizedFinding{n1, n2, n3},
		Edges: []Relationship{
			{SourceFindingID: "N1", TargetFindingID: "N2", RuleCode: RuleCOR01, Confidence: "HIGH", ValidationStatus: ValidationConfirmed},
			{SourceFindingID: "N2", TargetFindingID: "N3", RuleCode: RuleCOR02, Confidence: "HIGH", ValidationStatus: ValidationConfirmed},
		},
	}

	cfg := DefaultCompoundRiskConfig()
	// Set hop 1 coefficient to 0.5 (instead of 1.0)
	cfg.HopCoefficients[1] = 0.5
	// Set rule COR02 multiplier to 1.5
	cfg.RuleCoefficients[RuleCOR02] = 1.5

	res, err := CalculateCompoundRisk(path, cfg)
	if err != nil {
		t.Fatalf("CalculateCompoundRisk failed: %v", err)
	}

	// Base = 40.
	// Hop 1 (N2): alpha = 0.5 -> 0.5 * 20 * 1.0 = 10.0
	// Hop 2 (N3): alpha = 1.0 * 1.5 (RuleCOR02) = 1.5 -> 1.5 * 20 * 1.0 = 30.0
	// Total = 40 + 10 + 30 = 80
	if res.HopContributions[0].Contribution != 10.0 {
		t.Errorf("expected Hop 1 contribution 10.0, got %f", res.HopContributions[0].Contribution)
	}
	if res.HopContributions[1].Contribution != 30.0 {
		t.Errorf("expected Hop 2 contribution 30.0, got %f", res.HopContributions[1].Contribution)
	}
	if res.Score != 80 {
		t.Errorf("expected composite score 80 (40+10+30), got %d", res.Score)
	}
}

func TestRisk_Regression_UnverifiedPathScoreBelowCapNotClaimedCapped(t *testing.T) {
	n1 := NormalizedFinding{ID: "F1", Title: "Low Finding", Severity: report.SeverityLow, Score: 5, VerificationStatus: report.VerificationVerified, IsVerified: true}
	n2 := NormalizedFinding{ID: "F2", Title: "Info Finding", Severity: report.SeverityInfo, Score: 3, VerificationStatus: report.VerificationNotVerified, IsCandidate: true}
	edge := Relationship{
		ID: "E1", SourceFindingID: "F1", TargetFindingID: "F2", Type: RelEnables,
		RuleCode: RuleCOR01, ValidationStatus: ValidationPlausible, Confidence: report.ConfidenceMedium,
	}
	path := &AttackPath{
		ID: "PATH-LOW-01", Status: PathCandidate,
		Nodes: []NormalizedFinding{n1, n2},
		Edges: []Relationship{edge},
	}
	cfg := DefaultCompoundRiskConfig()
	res, err := CalculateCompoundRisk(path, cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.IsCapped {
		t.Errorf("path score %d (<= 65) must not be marked as IsCapped", res.Score)
	}
	if strings.Contains(res.Rationale, "capped at 65 pts (HIGH)") {
		t.Errorf("rationale must not claim score was capped at 65 (HIGH) when actual score is %d: %s", res.Score, res.Rationale)
	}
}
