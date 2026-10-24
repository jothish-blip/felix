package correlation

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math"
	"sort"
	"strings"

	"felix/pkg/secrets"
)

// RemediationCandidateType classifies the actionable remediation entity.
type RemediationCandidateType string

const (
	CandidateTypeComponent RemediationCandidateType = "COMPONENT"
	CandidateTypeEndpoint  RemediationCandidateType = "ENDPOINT"
	CandidateTypeFinding   RemediationCandidateType = "FINDING"
	CandidateTypeEdge      RemediationCandidateType = "EDGE"
)

// RemediationCandidate represents an actionable choke-point or component
// whose remediation interrupts one or more attack paths.
type RemediationCandidate struct {
	ID                    string                   `json:"id"`
	Type                  RemediationCandidateType `json:"type"`
	Name                  string                   `json:"name"`
	Component             string                   `json:"component,omitempty"`
	Endpoint              string                   `json:"endpoint,omitempty"`
	AssociatedFindingIDs  []string                 `json:"associated_finding_ids"`
	DisruptedPathIDs      []string                 `json:"disrupted_path_ids"`
	DisruptedCount        int                      `json:"disrupted_count"`
	TotalChainsConsidered int                      `json:"total_chains_considered"`
	DisruptionPercentage  float64                  `json:"disruption_percentage"`
	ResidualCount         int                      `json:"residual_count"`
	ResidualPathIDs       []string                 `json:"residual_path_ids"`
	DisruptedRiskSum      int                      `json:"disrupted_risk_sum"`
	UnitCost              float64                  `json:"unit_cost"`
	LeverageScore         float64                  `json:"leverage_score"`
	ActionableFix         string                   `json:"actionable_fix"`
	Rationale             string                   `json:"rationale"`
	VerificationStatus    string                   `json:"verification_status"` // "VERIFIED" or "PROVISIONAL"
	HasAmbiguousMapping   bool                     `json:"has_ambiguous_mapping,omitempty"`
	UncertaintyNotes      string                   `json:"uncertainty_notes,omitempty"`
}

// MinimumCutResult represents the outcome of Edmonds-Karp vertex-splitting minimum cut analysis.
type MinimumCutResult struct {
	CutSize           int                    `json:"cut_size"`
	CutNodes          []string               `json:"cut_node_ids"`
	CutElements       []RemediationCandidate `json:"cut_elements"`
	TotalPathsSevered int                    `json:"total_paths_severed"`
	IsCompleteCut     bool                   `json:"is_complete_cut"`
	Algorithm         string                 `json:"algorithm"`
	CapacityPolicy    string                 `json:"capacity_policy"`
	Explanation       string                 `json:"explanation"`
}

// BottleneckAnalysisResult contains the complete output of the priority remediation bottleneck solver.
type BottleneckAnalysisResult struct {
	TotalVerifiedChains   int                    `json:"total_verified_chains"`
	TotalCandidateChains  int                    `json:"total_candidate_chains"`
	PrimaryRecommendation *RemediationCandidate  `json:"primary_recommendation,omitempty"`
	RankedCandidates      []RemediationCandidate `json:"ranked_candidates"`
	ProvisionalCandidates []RemediationCandidate `json:"provisional_candidates,omitempty"`
	MinimumCut            *MinimumCutResult      `json:"minimum_cut,omitempty"`
	SummaryHeadline       string                 `json:"summary_headline"`
	AnalysisCaveats       []string               `json:"analysis_caveats,omitempty"`
}

// AnalyzeRemediationBottlenecks executes multi-path bottleneck analysis and Edmonds-Karp
// vertex-splitting minimum-cut calculation over the provided attack paths and findings.
func AnalyzeRemediationBottlenecks(paths []AttackPath, findings []NormalizedFinding, graph *AttackGraph) *BottleneckAnalysisResult {
	result := &BottleneckAnalysisResult{
		RankedCandidates:      []RemediationCandidate{},
		ProvisionalCandidates: []RemediationCandidate{},
		AnalysisCaveats:       []string{},
	}

	findingMap := make(map[string]NormalizedFinding, len(findings))
	for _, f := range findings {
		findingMap[f.ID] = f
	}

	// 1. Separate verified/evidence-supported paths from provisional candidate/inconclusive paths
	var verifiedPaths []AttackPath
	var candidatePaths []AttackPath
	seenVerifiedIDs := make(map[string]bool)
	seenCandidateIDs := make(map[string]bool)

	for _, p := range paths {
		isVerified := p.Status == PathVerified || p.Status.IsEvidenceSupported()
		if isVerified {
			if !seenVerifiedIDs[p.ID] {
				seenVerifiedIDs[p.ID] = true
				verifiedPaths = append(verifiedPaths, p)
			}
		} else {
			if !seenCandidateIDs[p.ID] {
				seenCandidateIDs[p.ID] = true
				candidatePaths = append(candidatePaths, p)
			}
		}
	}

	result.TotalVerifiedChains = len(verifiedPaths)
	result.TotalCandidateChains = len(candidatePaths)

	// If no verified paths exist, report honest baseline and evaluate provisional candidates separately
	if len(verifiedPaths) == 0 {
		if len(candidatePaths) > 0 {
			result.SummaryHeadline = fmt.Sprintf("No verified attack chains identified; %d provisional candidate path(s) under review", len(candidatePaths))
			result.AnalysisCaveats = append(result.AnalysisCaveats,
				"Provisional candidates are derived from unverified or candidate attack paths and must not be treated as confirmed exploit bottlenecks.")
			result.ProvisionalCandidates = evaluateCandidatesForPaths(candidatePaths, findingMap, "PROVISIONAL")
		} else {
			result.SummaryHeadline = "No multi-hop attack paths identified; no remediation bottlenecks to compute"
		}
		result.MinimumCut = &MinimumCutResult{
			CutSize:           0,
			CutNodes:          []string{},
			CutElements:       []RemediationCandidate{},
			TotalPathsSevered: 0,
			IsCompleteCut:     true,
			Algorithm:         "Edmonds-Karp Vertex-Splitting Min-Cut",
			CapacityPolicy:    "Unit-cost (cardinality)",
			Explanation:       "No eligible attack paths present to disconnect.",
		}
		return result
	}

	// 2. Compute Disruption for Verified Remediation Candidates
	result.RankedCandidates = evaluateCandidatesForPaths(verifiedPaths, findingMap, "VERIFIED")

	if len(result.RankedCandidates) > 0 {
		best := result.RankedCandidates[0]
		result.PrimaryRecommendation = &best
		result.SummaryHeadline = fmt.Sprintf("Priority remediation at %s: disrupts %d of %d verified attack chains (%.1f%%). Fix: %s",
			best.Name, best.DisruptedCount, best.TotalChainsConsidered, best.DisruptionPercentage, best.ActionableFix)
	}

	// 3. Compute Mathematical Minimum Cut (Edmonds-Karp on Vertex-Split Graph)
	result.MinimumCut = computeMinimumVertexCut(verifiedPaths, findingMap)

	// 4. Also evaluate Provisional Candidates separately if candidate paths exist
	if len(candidatePaths) > 0 {
		result.ProvisionalCandidates = evaluateCandidatesForPaths(candidatePaths, findingMap, "PROVISIONAL")
	}

	return result
}

// evaluateCandidatesForPaths groups findings into actionable remediation candidates
// (components, endpoints, and findings) and calculates exact chain disruption metrics.
func evaluateCandidatesForPaths(targetPaths []AttackPath, findingMap map[string]NormalizedFinding, status string) []RemediationCandidate {
	totalChains := len(targetPaths)
	if totalChains == 0 {
		return nil
	}

	allPathIDs := make([]string, totalChains)
	pathRiskMap := make(map[string]int, totalChains)
	for i, p := range targetPaths {
		allPathIDs[i] = p.ID
		pathRiskMap[p.ID] = p.CombinedRiskScore
	}
	sort.Strings(allPathIDs)

	// Map each candidate key to its affected paths and findings
	type candidateAccumulator struct {
		id           string
		candType     RemediationCandidateType
		name         string
		component    string
		endpoint     string
		findingIDs   map[string]bool
		pathIDs      map[string]bool
		actionFix    string
		isAmbiguous  bool
		ambigNote    string
		unitCost     float64
		sampleCat    string
	}

	accumulators := make(map[string]*candidateAccumulator)

	getOrCreate := func(key string, cType RemediationCandidateType, name, comp, ep, fix string, isAmbig bool, note string) *candidateAccumulator {
		if acc, ok := accumulators[key]; ok {
			return acc
		}
		acc := &candidateAccumulator{
			id:          key,
			candType:    cType,
			name:        name,
			component:   comp,
			endpoint:    ep,
			findingIDs:  make(map[string]bool),
			pathIDs:     make(map[string]bool),
			actionFix:   fix,
			isAmbiguous: isAmbig,
			ambigNote:   note,
			unitCost:    1.0, // default unit cost
		}
		accumulators[key] = acc
		return acc
	}

	for _, p := range targetPaths {
		for _, node := range p.Nodes {
			f, ok := findingMap[node.ID]
			if !ok {
				f = node
			}

			dispEP := f.DisplayEndpoint
			if dispEP == "" {
				dispEP = secrets.SanitizeURL(f.Endpoint)
			}
			if dispEP == "" {
				dispEP = secrets.SanitizeURL(f.Target)
			}

			cat := f.NormalizedCategory
			if cat == "" {
				cat = f.Category
			}

			fixDesc := deriveActionableFixForFinding(f)

			// 1. Component-level candidate (e.g. Shared middleware or control layer)
			compName := deriveComponentName(f)
			if compName != "" {
				compKey := fmt.Sprintf("REM-COMP-%s", shortHex(compName))
				compAcc := getOrCreate(compKey, CandidateTypeComponent, compName, compName, dispEP, fixDesc, false, "")
				compAcc.findingIDs[f.ID] = true
				compAcc.pathIDs[p.ID] = true
				compAcc.sampleCat = cat
			}

			// 2. Endpoint-level candidate (e.g. Endpoint handler/route)
			if dispEP != "" && dispEP != "/" {
				epName := fmt.Sprintf("Endpoint: %s", dispEP)
				epKey := fmt.Sprintf("REM-EP-%s", shortHex(dispEP))
				epAcc := getOrCreate(epKey, CandidateTypeEndpoint, epName, compName, dispEP, fixDesc, false, "")
				epAcc.findingIDs[f.ID] = true
				epAcc.pathIDs[p.ID] = true
				epAcc.sampleCat = cat
			}

			// 3. Finding-level candidate (specific vulnerability instance)
			isAmbig := (dispEP == "" || dispEP == "/") && compName == ""
			ambigNote := ""
			if isAmbig {
				ambigNote = "Finding lacks reliable component or endpoint mapping; candidate isolated to finding ID"
			}
			findKey := fmt.Sprintf("REM-FIND-%s", f.ID)
			findName := fmt.Sprintf("Finding [%s]: %s", f.ID, f.Title)
			findAcc := getOrCreate(findKey, CandidateTypeFinding, findName, compName, dispEP, fixDesc, isAmbig, ambigNote)
			findAcc.findingIDs[f.ID] = true
			findAcc.pathIDs[p.ID] = true
			findAcc.sampleCat = cat
		}
	}

	var candidates []RemediationCandidate
	for _, acc := range accumulators {
		var fIDs []string
		for id := range acc.findingIDs {
			fIDs = append(fIDs, id)
		}
		sort.Strings(fIDs)

		var disruptedPaths []string
		disruptedRiskSum := 0
		for pid := range acc.pathIDs {
			disruptedPaths = append(disruptedPaths, pid)
			disruptedRiskSum += pathRiskMap[pid]
		}
		sort.Strings(disruptedPaths)

		disruptedCount := len(disruptedPaths)
		residualCount := totalChains - disruptedCount
		disruptionPct := (float64(disruptedCount) / float64(totalChains)) * 100.0

		// Residual path IDs: paths in allPathIDs that are NOT in disruptedPaths
		disruptedSet := make(map[string]bool, len(disruptedPaths))
		for _, pid := range disruptedPaths {
			disruptedSet[pid] = true
		}
		var residualPaths []string
		for _, pid := range allPathIDs {
			if !disruptedSet[pid] {
				residualPaths = append(residualPaths, pid)
			}
		}

		// Leverage score combines disrupted chain count, disrupted risk, and unit cost
		leverageScore := (float64(disruptedCount) * 100.0) + (float64(disruptedRiskSum) / 10.0)
		if acc.unitCost > 0 {
			leverageScore /= acc.unitCost
		}

		rationale := fmt.Sprintf("Remediating %s disrupts %d of %d %s attack chain(s) (%.1f%%). Residual unmitigated chains: %d.",
			acc.name, disruptedCount, totalChains, strings.ToLower(status), disruptionPct, residualCount)
		if acc.isAmbiguous {
			rationale += fmt.Sprintf(" Note: %s.", acc.ambigNote)
		}

		candidates = append(candidates, RemediationCandidate{
			ID:                    acc.id,
			Type:                  acc.candType,
			Name:                  acc.name,
			Component:             acc.component,
			Endpoint:              acc.endpoint,
			AssociatedFindingIDs:  fIDs,
			DisruptedPathIDs:      disruptedPaths,
			DisruptedCount:        disruptedCount,
			TotalChainsConsidered: totalChains,
			DisruptionPercentage:  math.Round(disruptionPct*10) / 10,
			ResidualCount:         residualCount,
			ResidualPathIDs:       residualPaths,
			DisruptedRiskSum:      disruptedRiskSum,
			UnitCost:              acc.unitCost,
			LeverageScore:         math.Round(leverageScore*100) / 100,
			ActionableFix:         acc.actionFix,
			Rationale:             rationale,
			VerificationStatus:    status,
			HasAmbiguousMapping:   acc.isAmbiguous,
			UncertaintyNotes:      acc.ambigNote,
		})
	}

	// Deterministic ranking:
	// 1. DisruptedCount descending
	// 2. DisruptedRiskSum descending
	// 3. Type priority: COMPONENT > ENDPOINT > FINDING
	// 4. AssociatedFindingIDs count descending
	// 5. Candidate ID ascending (stable tie-breaker)
	typePriority := func(t RemediationCandidateType) int {
		switch t {
		case CandidateTypeComponent:
			return 3
		case CandidateTypeEndpoint:
			return 2
		default:
			return 1
		}
	}

	sort.Slice(candidates, func(i, j int) bool {
		ci, cj := candidates[i], candidates[j]
		if ci.DisruptedCount != cj.DisruptedCount {
			return ci.DisruptedCount > cj.DisruptedCount
		}
		if ci.DisruptedRiskSum != cj.DisruptedRiskSum {
			return ci.DisruptedRiskSum > cj.DisruptedRiskSum
		}
		if typePriority(ci.Type) != typePriority(cj.Type) {
			return typePriority(ci.Type) > typePriority(cj.Type)
		}
		if len(ci.AssociatedFindingIDs) != len(cj.AssociatedFindingIDs) {
			return len(ci.AssociatedFindingIDs) > len(cj.AssociatedFindingIDs)
		}
		return ci.ID < cj.ID
	})

	return candidates
}

// computeMinimumVertexCut applies the Edmonds-Karp vertex-splitting max-flow min-cut algorithm
// on the verified attack graph to determine the minimum-cardinality set of node remediations
// that completely disconnects all verified entry points from all verified terminal sinks.
func computeMinimumVertexCut(verifiedPaths []AttackPath, findingMap map[string]NormalizedFinding) *MinimumCutResult {
	if len(verifiedPaths) == 0 {
		return &MinimumCutResult{
			CutSize:           0,
			CutNodes:          []string{},
			CutElements:       []RemediationCandidate{},
			TotalPathsSevered: 0,
			IsCompleteCut:     true,
			Algorithm:         "Edmonds-Karp Vertex-Splitting Min-Cut",
			CapacityPolicy:    "Unit-cost (cardinality)",
			Explanation:       "No verified attack paths to disconnect.",
		}
	}

	// Collect unique nodes and directed transitions across verified paths
	nodeSet := make(map[string]bool)
	type edgeTransition struct {
		src, tgt string
	}
	edgeSet := make(map[edgeTransition]bool)
	entrypointSet := make(map[string]bool)
	terminalSet := make(map[string]bool)

	for _, p := range verifiedPaths {
		if len(p.Nodes) == 0 {
			continue
		}
		entrypointSet[p.Nodes[0].ID] = true
		terminalSet[p.Nodes[len(p.Nodes)-1].ID] = true

		for i := 0; i < len(p.Nodes); i++ {
			nodeSet[p.Nodes[i].ID] = true
			if i > 0 {
				edgeSet[edgeTransition{src: p.Nodes[i-1].ID, tgt: p.Nodes[i].ID}] = true
			}
		}
	}

	// If any path has only a single node, that node is an immediate bottleneck
	// that must be in the cut to disconnect that path.
	var immediateCutNodes []string
	for _, p := range verifiedPaths {
		if len(p.Nodes) == 1 {
			immediateCutNodes = append(immediateCutNodes, p.Nodes[0].ID)
		}
	}

	// Build Vertex-Split Flow Network
	// Each node v is split into v_in and v_out with internal capacity = 1.0 (unit cost).
	// SuperSource S* connects to each entrypoint v_in with capacity INF.
	// Each terminal v_out connects to SuperSink T* with capacity INF.
	// Original edges u -> v connect u_out -> v_in with capacity INF.
	const (
		superSource = "__SUPER_SOURCE__"
		superSink   = "__SUPER_SINK__"
		infCapacity = 1000000.0
	)

	nodeIn := func(v string) string { return v + "_in" }
	nodeOut := func(v string) string { return v + "_out" }

	// Adjacency list and capacity matrix
	adj := make(map[string][]string)
	capacity := make(map[string]map[string]float64)

	addDirectedEdge := func(u, v string, capVal float64) {
		if capacity[u] == nil {
			capacity[u] = make(map[string]float64)
		}
		if capacity[v] == nil {
			capacity[v] = make(map[string]float64)
		}
		capacity[u][v] += capVal
		adj[u] = append(adj[u], v)
		adj[v] = append(adj[v], u) // reverse edge in residual network with 0 initial capacity
	}

	// Internal node-splitting edges with unit capacity
	for v := range nodeSet {
		addDirectedEdge(nodeIn(v), nodeOut(v), 1.0)
	}

	// External sequence edges with infinite capacity
	for e := range edgeSet {
		addDirectedEdge(nodeOut(e.src), nodeIn(e.tgt), infCapacity)
	}

	// Super-source to entry points
	for ep := range entrypointSet {
		addDirectedEdge(superSource, nodeIn(ep), infCapacity)
	}

	// Terminal targets to super-sink
	for term := range terminalSet {
		addDirectedEdge(nodeOut(term), superSink, infCapacity)
	}

	// Deterministically sort adjacency lists for reproducible BFS traversal
	for u := range adj {
		sort.Strings(adj[u])
	}

	// Edmonds-Karp BFS Augmenting Path Algorithm
	flow := make(map[string]map[string]float64)
	for u := range capacity {
		flow[u] = make(map[string]float64)
	}

	for {
		// BFS to find shortest path from superSource to superSink in residual network
		parent := make(map[string]string)
		visited := make(map[string]bool)
		queue := []string{superSource}
		visited[superSource] = true

		for len(queue) > 0 {
			curr := queue[0]
			queue = queue[1:]

			if curr == superSink {
				break
			}

			for _, next := range adj[curr] {
				resCap := capacity[curr][next] - flow[curr][next]
				if !visited[next] && resCap > 1e-6 {
					visited[next] = true
					parent[next] = curr
					queue = append(queue, next)
				}
			}
		}

		if !visited[superSink] {
			break // No more augmenting paths; max flow reached
		}

		// Find bottleneck residual capacity along augmenting path
		pathCap := infCapacity
		for curr := superSink; curr != superSource; curr = parent[curr] {
			p := parent[curr]
			resCap := capacity[p][curr] - flow[p][curr]
			if resCap < pathCap {
				pathCap = resCap
			}
		}

		// Augment flow
		for curr := superSink; curr != superSource; curr = parent[curr] {
			p := parent[curr]
			flow[p][curr] += pathCap
			flow[curr][p] -= pathCap
		}
	}

	// Find reachable vertices from superSource in the residual network to identify cut edges
	reachable := make(map[string]bool)
	queue := []string{superSource}
	reachable[superSource] = true

	for len(queue) > 0 {
		curr := queue[0]
		queue = queue[1:]

		for _, next := range adj[curr] {
			resCap := capacity[curr][next] - flow[curr][next]
			if !reachable[next] && resCap > 1e-6 {
				reachable[next] = true
				queue = append(queue, next)
			}
		}
	}

	// A node v is in the vertex cut if its split edge v_in -> v_out has v_in reachable and v_out unreachable
	var cutNodeList []string
	seenCutNodes := make(map[string]bool)

	for v := range nodeSet {
		inV := nodeIn(v)
		outV := nodeOut(v)
		if reachable[inV] && !reachable[outV] {
			if !seenCutNodes[v] {
				seenCutNodes[v] = true
				cutNodeList = append(cutNodeList, v)
			}
		}
	}

	for _, imm := range immediateCutNodes {
		if !seenCutNodes[imm] {
			seenCutNodes[imm] = true
			cutNodeList = append(cutNodeList, imm)
		}
	}

	sort.Strings(cutNodeList)

	// Mathematical reachability verification: verify cut severs all modeled paths
	isComplete := VerifyVertexCutReachability(verifiedPaths, cutNodeList)
	if !isComplete {
		cutSet := make(map[string]bool, len(cutNodeList))
		for _, id := range cutNodeList {
			cutSet[id] = true
		}
		for _, p := range verifiedPaths {
			severed := false
			for _, n := range p.Nodes {
				if cutSet[n.ID] {
					severed = true
					break
				}
			}
			if !severed && len(p.Nodes) > 0 {
				chosen := p.Nodes[0].ID
				cutNodeList = append(cutNodeList, chosen)
				cutSet[chosen] = true
			}
		}
		sort.Strings(cutNodeList)
		isComplete = VerifyVertexCutReachability(verifiedPaths, cutNodeList)
	}

	// Build remediation candidate elements for cut nodes
	var cutElements []RemediationCandidate
	for _, nid := range cutNodeList {
		f := findingMap[nid]
		fix := deriveActionableFixForFinding(f)
		comp := deriveComponentName(f)
		dispEP := f.DisplayEndpoint
		if dispEP == "" {
			dispEP = f.Endpoint
		}
		cutElements = append(cutElements, RemediationCandidate{
			ID:                   fmt.Sprintf("REM-CUT-%s", nid),
			Type:                 CandidateTypeFinding,
			Name:                 fmt.Sprintf("Remediate [%s] %s", nid, f.Title),
			Component:            comp,
			Endpoint:             dispEP,
			AssociatedFindingIDs: []string{nid},
			ActionableFix:        fix,
			VerificationStatus:   "VERIFIED",
			Rationale:            "Member of the minimum-cardinality vertex cut under a unit-cost model disconnecting entry points from terminal targets.",
		})
	}

	explanation := fmt.Sprintf("Minimum-cardinality vertex cut under a unit-cost model (%d node(s)) completely severs all %d verified attack path(s) from entry points to terminal targets.",
		len(cutNodeList), len(verifiedPaths))

	return &MinimumCutResult{
		CutSize:           len(cutNodeList),
		CutNodes:          cutNodeList,
		CutElements:       cutElements,
		TotalPathsSevered: len(verifiedPaths),
		IsCompleteCut:     isComplete,
		Algorithm:         "Edmonds-Karp Vertex-Splitting Min-Cut",
		CapacityPolicy:    "Unit-cost (cardinality)",
		Explanation:       explanation,
	}
}

// VerifyVertexCutReachability verifies that removing cutNodes completely disconnects
// all modeled entrypoints from all modeled terminal sinks across the provided attack paths.
func VerifyVertexCutReachability(verifiedPaths []AttackPath, cutNodes []string) bool {
	if len(verifiedPaths) == 0 {
		return true
	}
	cutSet := make(map[string]bool, len(cutNodes))
	for _, id := range cutNodes {
		cutSet[id] = true
	}
	for _, p := range verifiedPaths {
		if len(p.Nodes) == 0 {
			continue
		}
		severed := false
		for _, n := range p.Nodes {
			if cutSet[n.ID] {
				severed = true
				break
			}
		}
		if !severed {
			return false
		}
	}
	return true
}

// deriveComponentName maps finding characteristics to actionable software component names.
func deriveComponentName(f NormalizedFinding) string {
	cat := strings.ToLower(f.NormalizedCategory)
	if cat == "" {
		cat = strings.ToLower(f.Category)
	}
	res := strings.TrimSpace(f.AffectedResource)

	switch {
	case strings.Contains(cat, "bola") || strings.Contains(cat, "idor"):
		if res != "" {
			return fmt.Sprintf("Object Access Control Middleware [%s]", res)
		}
		return "Object-Level Authorization Middleware"
	case strings.Contains(cat, "jwt") || strings.Contains(cat, "session"):
		return "Authentication Gateway & Session Validator"
	case strings.Contains(cat, "bfla") || strings.Contains(cat, "admin"):
		return "Role-Based Access Control (RBAC) Enforcement"
	case strings.Contains(cat, "leak") || strings.Contains(cat, "js"):
		return "Static Asset Sanitizer & Secrets Bundler"
	case strings.Contains(cat, "workflow") || strings.Contains(cat, "circumvention"):
		return "Workflow State Machine Engine"
	case strings.Contains(cat, "db") || strings.Contains(cat, "sql"):
		return "Database Query Access Layer"
	case strings.Contains(cat, "storage") || strings.Contains(cat, "s3") || strings.Contains(cat, "bucket"):
		return "Cloud Storage Access Policy"
	default:
		if res != "" {
			return fmt.Sprintf("Application Component [%s]", res)
		}
		if f.DisplayEndpoint != "" && f.DisplayEndpoint != "/" {
			return fmt.Sprintf("Endpoint Controller [%s]", f.DisplayEndpoint)
		}
		return ""
	}
}

// deriveActionableFixForFinding synthesizes concrete, non-generic engineering remediation instructions.
func deriveActionableFixForFinding(f NormalizedFinding) string {
	cat := strings.ToLower(f.NormalizedCategory)
	if cat == "" {
		cat = strings.ToLower(f.Category)
	}

	dispEP := f.DisplayEndpoint
	if dispEP == "" {
		dispEP = f.Endpoint
	}

	switch {
	case strings.Contains(cat, "bola") || strings.Contains(cat, "idor"):
		return fmt.Sprintf("Enforce object-level access control on %s. Validate authenticated subject owns target record before querying database.", dispEP)
	case strings.Contains(cat, "jwt") || strings.Contains(cat, "session"):
		return fmt.Sprintf("Enforce cryptographically verified session signature validation and reject expired/forged tokens on %s.", dispEP)
	case strings.Contains(cat, "bfla") || strings.Contains(cat, "admin"):
		return fmt.Sprintf("Require explicit administrator role claims server-side before routing to %s; deny viewer/unprivileged access.", dispEP)
	case strings.Contains(cat, "leak") || strings.Contains(cat, "js"):
		return fmt.Sprintf("Remove internal credentials and shadow route declarations from public JavaScript bundle at %s.", dispEP)
	case strings.Contains(cat, "workflow") || strings.Contains(cat, "circumvention"):
		return fmt.Sprintf("Enforce strict precondition step checks on %s; reject state transitions where preceding steps did not succeed.", dispEP)
	case strings.Contains(cat, "db") || strings.Contains(cat, "sql"):
		return fmt.Sprintf("Use parameterized queries and restrict database user permissions on %s to prevent unauthorized takeover.", dispEP)
	case strings.Contains(cat, "storage") || strings.Contains(cat, "bucket"):
		return fmt.Sprintf("Enable bucket private access policy and revoke anonymous read/list permissions on %s.", dispEP)
	default:
		if dispEP != "" && dispEP != "/" {
			return fmt.Sprintf("Apply strict input validation and access controls at %s to sever the attack chain.", dispEP)
		}
		return fmt.Sprintf("Remediate root cause for finding '%s' to eliminate vulnerability from the attack sequence.", f.Title)
	}
}

func defaultMethod(m string) string {
	m = strings.ToUpper(strings.TrimSpace(m))
	if m == "" {
		return "GET"
	}
	return m
}

func shortHex(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])[:8]
}
