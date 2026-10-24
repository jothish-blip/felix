package correlation

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"time"

	"felix/pkg/discovery"
	"felix/pkg/report"
	"felix/pkg/secrets"
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
			AffectedAssets:    []string{},
			AssetAssociations: []AssetAssociation{},
			Relationships:     []Relationship{},
		}, nil, nil, nil
	}

	// Deterministically sort input findings by ID, Fingerprint, then Title
	sortedFindings := make([]report.Finding, len(findings))
	copy(sortedFindings, findings)
	sort.Slice(sortedFindings, func(i, j int) bool {
		if sortedFindings[i].ID != sortedFindings[j].ID {
			return sortedFindings[i].ID < sortedFindings[j].ID
		}
		if sortedFindings[i].Fingerprint != sortedFindings[j].Fingerprint {
			return sortedFindings[i].Fingerprint < sortedFindings[j].Fingerprint
		}
		return sortedFindings[i].Title < sortedFindings[j].Title
	})

	// 1. Finding Normalization
	normalized := NormalizeFindings(sortedFindings)

	// 2. Relationship Candidate Generation & Validation
	relationships := EvaluateRules(normalized, e.config)

	// Build finding lookup
	findingMap := make(map[string]NormalizedFinding)
	for _, f := range normalized {
		findingMap[f.ID] = f
	}

	// 3. Attack Path Construction
	paths, limitsReached, truncReason := e.buildAttackPaths(ctx, normalized, relationships, findingMap)

	// 4. Path Risk Assessment, Security Stories & Deduplication
	dedupedPaths := e.processPaths(paths)

	// 5. Compile Summary
	summary := e.compileSummary(normalized, relationships, dedupedPaths, limitsReached, truncReason)

	return summary, dedupedPaths, relationships, nil
}

// buildAttackPaths traverses directed relationship sequences using an AttackGraph
// to assemble coherent multi-hop and pairwise attack paths.
func (e *Engine) buildAttackPaths(
	ctx context.Context,
	findings []NormalizedFinding,
	relationships []Relationship,
	findingMap map[string]NormalizedFinding,
) ([]AttackPath, bool, string) {
	// Construct the directed attack graph with reference validation & cycle detection
	graph := NewAttackGraph(findings, relationships)

	maxDepth := e.config.MaxPathDepth
	if maxDepth <= 0 {
		maxDepth = 4
	}
	maxCandidatePaths := e.config.MaxCandidatePaths
	if maxCandidatePaths <= 0 {
		maxCandidatePaths = 30
	}
	minPathLength := e.config.MinPathLength
	if minPathLength <= 0 {
		minPathLength = 2
	}

	// Index cycle nodes and cycle back-edges to prevent invalid cyclic paths from being accepted
	cycleNodeMap := make(map[string]bool)
	for _, id := range graph.Validation.CycleNodes {
		cycleNodeMap[id] = true
	}
	cycleEdgeMap := make(map[string]bool)
	for _, edgeDesc := range graph.Validation.CycleEdges {
		cycleEdgeMap[edgeDesc] = true
	}

	var rawPaths []AttackPath
	limitsReached := false
	truncReason := ""
	stepBudget := 5000 // Dense graph search budget
	stepCount := 0

	var dfs func(currID string, visited map[string]bool, currentEdges []Relationship, depth int)
	dfs = func(currID string, visited map[string]bool, currentEdges []Relationship, depth int) {
		stepCount++
		if stepCount >= stepBudget {
			limitsReached = true
			truncReason = fmt.Sprintf("Traversal search budget reached (%d steps) - dense graph protection active", stepBudget)
			return
		}

		if len(rawPaths) >= maxCandidatePaths {
			limitsReached = true
			truncReason = fmt.Sprintf("Reached configured candidate path threshold (%d paths)", maxCandidatePaths)
			return
		}

		select {
		case <-ctx.Done():
			limitsReached = true
			truncReason = "Correlation traversal cancelled: " + ctx.Err().Error()
			return
		default:
		}

		if depth >= maxDepth {
			if len(graph.Adjacency[currID]) > 0 {
				limitsReached = true
				if truncReason == "" {
					truncReason = fmt.Sprintf("Path depth truncated at configured maximum depth (%d transitions)", maxDepth)
				}
			}
			return
		}

		edges := graph.Adjacency[currID]
		for _, gEdge := range edges {
			nextID := gEdge.TargetID
			if visited[nextID] {
				// Prevent cycles: never revisit an ancestor node within the same path
				continue
			}

			// Do not follow back-edges that complete cyclic loops
			edgeDesc := fmt.Sprintf("%s -> %s", currID, nextID)
			if cycleEdgeMap[edgeDesc] {
				continue
			}

			edge := gEdge.Relationship
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

			if len(nodeIDs) >= minPathLength {
				path := e.constructPath(nodeIDs, nodes, newEdges, cycleNodeMap)
				rawPaths = append(rawPaths, path)
			}

			// Recurse deeper along directed transitions
			visited[nextID] = true
			dfs(nextID, visited, newEdges, depth+1)
			delete(visited, nextID)

			if limitsReached {
				return
			}
		}
	}

	// 1. Prioritize eligible graph roots (InDegree == 0, OutDegree > 0)
	// 2. Prioritize entry points (IsEntrypoint == true, OutDegree > 0)
	// 3. Fallback to any remaining connected nodes with OutDegree > 0 to ensure full component reachability
	seenStart := make(map[string]bool)
	var startNodeIDs []string

	for _, root := range graph.EligibleRoots() {
		if !seenStart[root.ID] {
			seenStart[root.ID] = true
			startNodeIDs = append(startNodeIDs, root.ID)
		}
	}

	for _, ep := range graph.EntryPoints() {
		if !seenStart[ep.ID] {
			seenStart[ep.ID] = true
			startNodeIDs = append(startNodeIDs, ep.ID)
		}
	}

	for _, f := range findings {
		if n, ok := graph.Nodes[f.ID]; ok && n.OutDegree > 0 && !seenStart[f.ID] {
			seenStart[f.ID] = true
			startNodeIDs = append(startNodeIDs, f.ID)
		}
	}

	// Execute traversal from each eligible start node
	for _, startID := range startNodeIDs {
		visited := map[string]bool{startID: true}
		dfs(startID, visited, nil, 1)
		if limitsReached {
			break
		}
	}

	if graph.Validation.HasCycle && truncReason == "" {
		truncReason = strings.Join(graph.Validation.Errors, "; ")
	}

	return rawPaths, limitsReached, truncReason
}

func (e *Engine) constructPath(nodeIDs []string, nodes []NormalizedFinding, edges []Relationship, cycleNodeMaps ...map[string]bool) AttackPath {
	var cycleNodeMap map[string]bool
	if len(cycleNodeMaps) > 0 {
		cycleNodeMap = cycleNodeMaps[0]
	}

	first := nodes[0]
	last := nodes[len(nodes)-1]

	ruleCode := edges[0].RuleCode
	ruleMeta, hasMeta := RuleCatalog[ruleCode]
	titleName := "Security Sequence"
	if hasMeta {
		titleName = ruleMeta.Name
	}
	var title string
	if len(nodes) >= 3 {
		title = fmt.Sprintf("Multi-Hop Attack Path (%d Hops): %s to %s on %s",
			len(edges), first.Title, last.Title, last.Path)
		if last.Path == "" || last.Path == "/" {
			title = fmt.Sprintf("Multi-Hop Attack Path (%d Hops): %s to %s on %s",
				len(edges), first.Title, last.Title, last.Host)
		}
	} else {
		title = fmt.Sprintf("%s on %s", titleName, last.Path)
		if last.Path == "" || last.Path == "/" {
			title = fmt.Sprintf("%s on %s", titleName, last.Host)
		}
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

	// Detect whether path traverses cyclic dependencies
	var cyclicInPath []string
	for _, nid := range nodeIDs {
		if cycleNodeMap != nil && cycleNodeMap[nid] {
			cyclicInPath = append(cyclicInPath, nid)
		}
	}

	allNodesVerified := true
	anyNodeCandidate := false
	for _, n := range nodes {
		if !n.IsVerified || n.VerificationStatus != report.VerificationVerified {
			allNodesVerified = false
		}
		if n.IsCandidate || n.VerificationStatus == report.VerificationDetected || n.VerificationStatus == report.VerificationNotVerified {
			anyNodeCandidate = true
		}
	}

	if len(cyclicInPath) > 0 {
		status = PathInconclusive
		conf = report.ConfidenceLow
		missingEvidence = append(missingEvidence, fmt.Sprintf("Path traverses cyclic dependency in attack graph (%s); invalid cyclic relationships cannot form verified chains", strings.Join(cyclicInPath, ", ")))
	} else if anyEdgeInconclusive {
		status = PathInconclusive
		conf = report.ConfidenceLow
		missingEvidence = append(missingEvidence, "Evidence connecting intermediate transitions is inconclusive.")
	} else if allEdgesConfirmed && allNodesVerified && !anyInferredHypothesis && !anyNodeCandidate {
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
		status = PathEvidenceSupported
		conf = report.ConfidenceMedium
	}

	// Check synthetic fixture flag
	isSynth := false
	for _, n := range nodes {
		if n.SyntheticFixture {
			isSynth = true
			break
		}
	}

	lastEP := last.DisplayEndpoint
	if lastEP == "" {
		lastEP = secrets.SanitizeURL(last.Endpoint)
	}
	terminalImpact := fmt.Sprintf("Direct exploitation of %s at %s", last.Title, lastEP)
	if status != PathVerified {
		terminalImpact = fmt.Sprintf("Potential exploitation of %s at %s (unverified candidate)", last.Title, lastEP)
	}

	firstEP := first.DisplayEndpoint
	if firstEP == "" {
		firstEP = secrets.SanitizeURL(first.Endpoint)
	}

	ruleCodes := make([]string, len(edges))
	for i, ed := range edges {
		ruleCodes[i] = string(ed.RuleCode)
	}
	canonicalSeq := fmt.Sprintf("NODES:%s;RULES:%s", strings.Join(nodeIDs, "->"), strings.Join(ruleCodes, "->"))
	hash := shortHash(canonicalSeq)

	primaryRule := string(edges[0].RuleCode)
	if primaryRule == "" {
		primaryRule = "COR"
	}
	var pathID string
	if len(nodeIDs) >= 3 {
		pathID = fmt.Sprintf("PATH-MULTIHOP-%s-%s", primaryRule, hash)
	} else {
		pathID = fmt.Sprintf("PATH-%s-%s", primaryRule, hash)
	}

	path := AttackPath{
		ID:               pathID,
		Title:            title,
		NodeIDs:          nodeIDs,
		Nodes:            nodes,
		Edges:            edges,
		EntryPoint:       firstEP,
		TargetAsset:      last.Host,
		PrimaryWeakness:  first.Title,
		TerminalImpact:   terminalImpact,
		Status:           status,
		Confidence:       conf,
		Assumptions:      assumptions,
		MissingEvidence:  missingEvidence,
		SyntheticFixture: isSynth,
		CreatedAt:        time.Now().UTC(),
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
		var ruleCodes []string
		for _, ed := range p.Edges {
			ruleCodes = append(ruleCodes, string(ed.RuleCode))
		}
		seqKey := fmt.Sprintf("NODES:%s;RULES:%s", strings.Join(p.NodeIDs, "->"), strings.Join(ruleCodes, "->"))
		if seenSequences[seqKey] {
			continue
		}
		seenSequences[seqKey] = true
		deduped = append(deduped, p)
	}

	// Sort paths:
	// 1. Evidence-supported / VERIFIED before CANDIDATE / unverified
	// 2. CombinedRiskScore descending
	// 3. Number of nodes descending (multi-hop paths prioritized)
	// 4. Stable ID ascending
	sort.Slice(deduped, func(i, j int) bool {
		pi, pj := deduped[i], deduped[j]
		verI := pi.Status == PathVerified || pi.Status.IsEvidenceSupported()
		verJ := pj.Status == PathVerified || pj.Status.IsEvidenceSupported()
		if verI != verJ {
			return verI
		}
		if pi.CombinedRiskScore != pj.CombinedRiskScore {
			return pi.CombinedRiskScore > pj.CombinedRiskScore
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

	var verifiedCount, candidateCount, inconclusiveCount, observedCount, evidenceSupportedCount int
	maxRiskScore := 0
	highestRiskLevel := report.SeverityInfo

	// Build AssetAssociations from normalized findings
	var assetAssociations []AssetAssociation
	seenAssocs := make(map[string]bool)
	for _, f := range findings {
		assocKey := fmt.Sprintf("%s:%s", f.ID, f.PrimaryAssetID)
		if !seenAssocs[assocKey] {
			seenAssocs[assocKey] = true
			isExact := f.AssetType == discovery.AssetTypeEndpoint ||
				f.AssetType == discovery.AssetTypeStorage ||
				f.AssetType == discovery.AssetTypeDatabase ||
				f.AssetType == discovery.AssetTypeAPK ||
				f.AssetType == discovery.AssetTypeApplication

			basis := "CANONICAL_ASSET"
			if f.AssetType == discovery.AssetTypeEndpoint {
				basis = "EXACT_ENDPOINT"
			} else if f.AssetType == discovery.AssetTypeStorage {
				basis = "CLOUD_STORAGE_RESOURCE"
			} else if f.AssetType == discovery.AssetTypeDatabase {
				basis = "DATABASE_RESOURCE"
			} else if f.AssetType == discovery.AssetTypeAPK {
				basis = "APK_PACKAGE"
			} else if f.AssetType == discovery.AssetTypeApplication {
				basis = "CANONICAL_APPLICATION"
			}

			assetAssociations = append(assetAssociations, AssetAssociation{
				FindingID:    f.ID,
				AssetID:      f.PrimaryAssetID,
				AssetType:    f.AssetType,
				CanonicalKey: f.CanonicalAssetKey,
				DisplayName:  f.CanonicalAssetKey,
				Basis:        basis,
				Confidence:   f.Confidence,
				IsExact:      isExact,
				Evidence:     f.EvidenceSummary,
			})
		}
	}

	// Collect unique affected assets from findings and attack paths
	seenAssets := make(map[string]bool)
	var affectedAssets []string
	addAsset := func(a string) {
		trimmed := strings.TrimSpace(a)
		if trimmed != "" && !seenAssets[trimmed] {
			seenAssets[trimmed] = true
			affectedAssets = append(affectedAssets, trimmed)
		}
	}

	for _, f := range findings {
		for _, id := range f.AffectedAssetIDs {
			addAsset(id)
		}
		addAsset(f.PrimaryAssetID)
		addAsset(f.CanonicalAssetKey)
	}
	for _, p := range paths {
		addAsset(p.TargetAsset)
	}
	sort.Strings(affectedAssets)

	seenRemediations := make(map[string]bool)
	var keyRemediations []string
	isSynth := false

	for _, p := range paths {
		// Only verified or evidence-supported attack paths may escalate primary assessment risk
		if p.Status == PathVerified || p.Status.IsEvidenceSupported() {
			if p.CombinedRiskScore > maxRiskScore {
				maxRiskScore = p.CombinedRiskScore
				highestRiskLevel = p.CombinedRiskLevel
			}
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
		case PathEvidenceSupported:
			evidenceSupportedCount++
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

	// Compute priority remediation bottlenecks and Edmonds-Karp min-cut
	bottleneckResult := AnalyzeRemediationBottlenecks(paths, findings, NewAttackGraph(findings, relationships))
	if bottleneckResult != nil && bottleneckResult.PrimaryRecommendation != nil {
		topRem := fmt.Sprintf("[%s] %s: %s (disrupts %d/%d verified attack chains)",
			bottleneckResult.PrimaryRecommendation.Type,
			bottleneckResult.PrimaryRecommendation.Name,
			bottleneckResult.PrimaryRecommendation.ActionableFix,
			bottleneckResult.PrimaryRecommendation.DisruptedCount,
			bottleneckResult.PrimaryRecommendation.TotalChainsConsidered,
		)
		keyRemediations = append([]string{topRem}, keyRemediations...)
	}

	return &Summary{
		TotalFindings:            len(findings),
		EvaluatedFindings:        len(findings),
		ExcludedFindings:         0,
		CandidateRelationships:   len(relationships),
		ConfirmedRelationships:   confirmedRels,
		CandidatePaths:           candidateCount,
		VerifiedPaths:            verifiedCount,
		InconclusivePaths:        inconclusiveCount,
		ObservedPaths:            observedCount,
		EvidenceSupportedPaths:   evidenceSupportedCount,
		HighestRiskLevel:         highestRiskLevel,
		HighestRiskScore:         maxRiskScore,
		AffectedAssets:           affectedAssets,
		AssetAssociations:        assetAssociations,
		Relationships:            relationships,
		KeyRemediationPriorities: keyRemediations,
		BottleneckAnalysis:       bottleneckResult,
		LimitsReached:            limitsReached,
		TruncationReason:         truncReason,
		SyntheticFixture:         isSynth,
		RuleStats:                ruleStats,
	}
}

func shortHash(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:8])
}
