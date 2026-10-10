package correlation

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"felix/pkg/report"
)

// Engine performs evidence-driven correlation, relationship discovery,
// and attack path construction over security assessment findings.
type Engine struct {
	config Config
}

// NewEngine creates a new correlation engine with the specified configuration.
func NewEngine(cfg Config) *Engine {
	if cfg.MaxPathDepth <= 0 {
		cfg.MaxPathDepth = 4
	}
	if cfg.MaxCandidatePaths <= 0 {
		cfg.MaxCandidatePaths = 30
	}
	return &Engine{config: cfg}
}

// Correlate analyzes assessment findings and returns the correlation summary,
// ordered attack paths, and validated relationships.
func (e *Engine) Correlate(ctx context.Context, findings []report.Finding) (*Summary, []AttackPath, []Relationship, error) {
	if len(findings) == 0 {
		return &Summary{
			TotalFindings:     0,
			HighestRiskLevel:  report.SeverityInfo,
			HighestRiskScore:  0,
			RuleStats:         make(map[string]RuleCoverageStat),
		}, nil, nil, nil
	}

	// 1. Finding Normalization
	normalized := NormalizeFindings(findings)

	// 2. Relationship Candidate Generation & Validation
	relationships := EvaluateRules(normalized, e.config)

	// Build finding lookup
	findingMap := make(map[string]NormalizedFinding)
	for _, f := range normalized {
		findingMap[f.ID] = f
	}

	// 3. Attack Path Construction
	paths, limitsReached, truncReason := e.buildAttackPaths(normalized, relationships, findingMap)

	// 4. Path Risk Assessment, Security Stories & Deduplication
	dedupedPaths := e.processPaths(paths)

	// 5. Compile Summary
	summary := e.compileSummary(normalized, relationships, dedupedPaths, limitsReached, truncReason)

	return summary, dedupedPaths, relationships, nil
}

// buildAttackPaths traverses directed relationship sequences to assemble coherent attack paths.
func (e *Engine) buildAttackPaths(
	findings []NormalizedFinding,
	relationships []Relationship,
	findingMap map[string]NormalizedFinding,
) ([]AttackPath, bool, string) {
	// Construct adjacency list of sequential attack transitions
	adj := make(map[string][]Relationship)
	for _, rel := range relationships {
		if rel.Type.IsSequenceType() {
			adj[rel.SourceFindingID] = append(adj[rel.SourceFindingID], rel)
		}
	}

	var rawPaths []AttackPath
	limitsReached := false
	truncReason := ""

	var dfs func(currID string, visited map[string]bool, currentEdges []Relationship, depth int)
	dfs = func(currID string, visited map[string]bool, currentEdges []Relationship, depth int) {
		if len(rawPaths) >= e.config.MaxCandidatePaths {
			limitsReached = true
			truncReason = fmt.Sprintf("Reached configured candidate path threshold (%d paths)", e.config.MaxCandidatePaths)
			return
		}

		if depth >= e.config.MaxPathDepth {
			return
		}

		edges := adj[currID]
		for _, edge := range edges {
			nextID := edge.TargetFindingID
			if visited[nextID] {
				// Prevent cycles
				continue
			}

			newEdges := make([]Relationship, len(currentEdges)+1)
			copy(newEdges, currentEdges)
			newEdges[len(currentEdges)] = edge

			// Assemble candidate path
			nodeIDs := make([]string, len(newEdges)+1)
			nodes := make([]NormalizedFinding, len(newEdges)+1)
			nodeIDs[0] = newEdges[0].SourceFindingID
			nodes[0] = findingMap[nodeIDs[0]]
			for k, ed := range newEdges {
				nodeIDs[k+1] = ed.TargetFindingID
				nodes[k+1] = findingMap[ed.TargetFindingID]
			}

			path := e.constructPath(nodeIDs, nodes, newEdges)
			rawPaths = append(rawPaths, path)

			// Recurse deeper
			visited[nextID] = true
			dfs(nextID, visited, newEdges, depth+1)
			delete(visited, nextID)
		}
	}

	// Initiate traversal from each finding that acts as an entrypoint or initial condition
	for _, f := range findings {
		visited := map[string]bool{f.ID: true}
		dfs(f.ID, visited, nil, 1)
		if limitsReached {
			break
		}
	}

	return rawPaths, limitsReached, truncReason
}

func (e *Engine) constructPath(nodeIDs []string, nodes []NormalizedFinding, edges []Relationship) AttackPath {
	first := nodes[0]
	last := nodes[len(nodes)-1]

	ruleCode := edges[0].RuleCode
	ruleMeta, hasMeta := RuleCatalog[ruleCode]
	titleName := "Security Sequence"
	if hasMeta {
		titleName = ruleMeta.Name
	}
	title := fmt.Sprintf("%s on %s", titleName, last.Path)
	if last.Path == "" || last.Path == "/" {
		title = fmt.Sprintf("%s on %s", titleName, last.Host)
	}

	// Determine Verification Status
	allEdgesConfirmed := true
	anyEdgePlausible := false
	anyEdgeInconclusive := false
	anyInferredHypothesis := false

	for _, ed := range edges {
		switch ed.ValidationStatus {
		case ValidationConfirmed:
		case ValidationPlausible:
			allEdgesConfirmed = false
			anyEdgePlausible = true
		case ValidationInconclusive:
			allEdgesConfirmed = false
			anyEdgeInconclusive = true
		}
	}

	for _, n := range nodes {
		if n.InferredHypothesis {
			anyInferredHypothesis = true
		}
	}

	var status PathStatus
	var conf string
	var assumptions []string
	var missingEvidence []string

	allNodesVerified := true
	anyNodeCandidate := false
	for _, n := range nodes {
		if !n.IsVerified {
			allNodesVerified = false
		}
		if n.IsCandidate {
			anyNodeCandidate = true
		}
	}

	if anyEdgeInconclusive {
		status = PathInconclusive
		conf = report.ConfidenceLow
		missingEvidence = append(missingEvidence, "Evidence connecting intermediate transitions is inconclusive.")
	} else if allEdgesConfirmed && allNodesVerified && !anyInferredHypothesis {
		status = PathVerified
		conf = report.ConfidenceHigh
	} else if anyInferredHypothesis || anyEdgePlausible || anyNodeCandidate {
		status = PathCandidate
		conf = report.ConfidenceMedium
		if anyInferredHypothesis {
			assumptions = append(assumptions, "One or more nodes depend on an inferred workflow hypothesis requiring operator verification.")
		}
		if anyNodeCandidate {
			missingEvidence = append(missingEvidence, "One or more component findings are unconfirmed candidates.")
		}
		if anyEdgePlausible {
			missingEvidence = append(missingEvidence, "One or more connecting transitions are plausible but unconfirmed.")
		}
	} else {
		status = PathObserved
		conf = report.ConfidenceLow
	}

	// Check synthetic fixture flag
	isSynth := false
	for _, n := range nodes {
		if n.SyntheticFixture {
			isSynth = true
			break
		}
	}

	terminalImpact := fmt.Sprintf("Direct exploitation of %s at %s", last.Title, last.Endpoint)
	if status != PathVerified {
		terminalImpact = fmt.Sprintf("Potential exploitation of %s at %s (unverified candidate)", last.Title, last.Endpoint)
	}

	path := AttackPath{
		ID:                fmt.Sprintf("PATH-%s-%s", ruleCode, shortHash(strings.Join(nodeIDs, "->"))),
		Title:             title,
		NodeIDs:           nodeIDs,
		Nodes:             nodes,
		Edges:             edges,
		EntryPoint:        first.Endpoint,
		TargetAsset:       last.Host,
		PrimaryWeakness:   first.Title,
		TerminalImpact:    terminalImpact,
		Status:            status,
		Confidence:        conf,
		Assumptions:       assumptions,
		MissingEvidence:   missingEvidence,
		SyntheticFixture:  isSynth,
		CreatedAt:         time.Now().UTC(),
	}

	// Combined Risk Calculation
	score, riskLevel, rationale := AssessPathRisk(&path)
	path.CombinedRiskScore = score
	path.CombinedRiskLevel = riskLevel
	path.RiskRationale = rationale

	// Security Story & Remediation
	story := GenerateSecurityStory(&path)
	path.SecurityStory = story
	path.Remediation = story.Remediation

	return path
}

// processPaths deduplicates overlapping paths, groups by impact, and sorts by risk.
func (e *Engine) processPaths(paths []AttackPath) []AttackPath {
	if len(paths) == 0 {
		return nil
	}

	seenSequences := make(map[string]bool)
	var deduped []AttackPath

	for _, p := range paths {
		seqKey := strings.Join(p.NodeIDs, "->")
		if seenSequences[seqKey] {
			continue
		}
		seenSequences[seqKey] = true
		deduped = append(deduped, p)
	}

	// Sort paths:
	// 1. CombinedRiskScore descending
	// 2. VERIFIED before CANDIDATE
	// 3. Number of nodes descending
	// 4. Stable ID ascending
	sort.Slice(deduped, func(i, j int) bool {
		pi, pj := deduped[i], deduped[j]
		if pi.CombinedRiskScore != pj.CombinedRiskScore {
			return pi.CombinedRiskScore > pj.CombinedRiskScore
		}
		if (pi.Status == PathVerified) != (pj.Status == PathVerified) {
			return pi.Status == PathVerified
		}
		if len(pi.Nodes) != len(pj.Nodes) {
			return len(pi.Nodes) > len(pj.Nodes)
		}
		return pi.ID < pj.ID
	})

	return deduped
}

func (e *Engine) compileSummary(
	findings []NormalizedFinding,
	relationships []Relationship,
	paths []AttackPath,
	limitsReached bool,
	truncReason string,
) *Summary {
	ruleStats := make(map[string]RuleCoverageStat)
	for code, meta := range RuleCatalog {
		ruleStats[string(code)] = RuleCoverageStat{
			Code: code,
			Name: meta.Name,
		}
	}

	for _, r := range relationships {
		stat := ruleStats[string(r.RuleCode)]
		stat.RelationshipsGenerated++
		ruleStats[string(r.RuleCode)] = stat
	}

	var verifiedCount, candidateCount, inconclusiveCount, observedCount int
	maxRiskScore := 0
	highestRiskLevel := report.SeverityInfo

	seenAssets := make(map[string]bool)
	var affectedAssets []string
	seenRemediations := make(map[string]bool)
	var keyRemediations []string
	isSynth := false

	for _, p := range paths {
		if p.CombinedRiskScore > maxRiskScore {
			maxRiskScore = p.CombinedRiskScore
			highestRiskLevel = p.CombinedRiskLevel
		}

		switch p.Status {
		case PathVerified:
			verifiedCount++
		case PathCandidate:
			candidateCount++
		case PathInconclusive:
			inconclusiveCount++
		case PathObserved:
			observedCount++
		}

		if p.TargetAsset != "" && !seenAssets[p.TargetAsset] {
			seenAssets[p.TargetAsset] = true
			affectedAssets = append(affectedAssets, p.TargetAsset)
		}

		if p.Remediation != "" && !seenRemediations[p.Remediation] && len(keyRemediations) < 3 {
			seenRemediations[p.Remediation] = true
			keyRemediations = append(keyRemediations, p.Remediation)
		}

		if p.SyntheticFixture {
			isSynth = true
		}

		if len(p.Edges) > 0 {
			stat := ruleStats[string(p.Edges[0].RuleCode)]
			stat.PathsGenerated++
			ruleStats[string(p.Edges[0].RuleCode)] = stat
		}
	}

	confirmedRels := 0
	for _, r := range relationships {
		if r.ValidationStatus == ValidationConfirmed {
			confirmedRels++
		}
	}

	return &Summary{
		TotalFindings:            len(findings),
		EvaluatedFindings:        len(findings),
		ExcludedFindings:        0,
		CandidateRelationships:   len(relationships),
		ConfirmedRelationships:   confirmedRels,
		CandidatePaths:           candidateCount,
		VerifiedPaths:            verifiedCount,
		InconclusivePaths:        inconclusiveCount,
		ObservedPaths:            observedCount,
		HighestRiskLevel:         highestRiskLevel,
		HighestRiskScore:         maxRiskScore,
		AffectedAssets:           affectedAssets,
		KeyRemediationPriorities: keyRemediations,
		LimitsReached:            limitsReached,
		TruncationReason:         truncReason,
		SyntheticFixture:         isSynth,
		RuleStats:                ruleStats,
	}
}

func shortHash(s string) string {
	var hash uint32 = 2166136261
	for i := 0; i < len(s); i++ {
		hash ^= uint32(s[i])
		hash *= 16777619
	}
	return fmt.Sprintf("%08x", hash)
}
