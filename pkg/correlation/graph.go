package correlation

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
)

// GraphNode represents a node in the directed attack graph.
// It references a normalized finding by its stable identifier.
type GraphNode struct {
	ID        string            `json:"id"`
	Finding   NormalizedFinding `json:"finding"`
	InDegree  int               `json:"in_degree"`
	OutDegree int               `json:"out_degree"`
}

// GraphEdge represents a validated directed transition edge between two findings.
type GraphEdge struct {
	ID                 string           `json:"id"`
	SourceID           string           `json:"source_id"`
	TargetID           string           `json:"target_id"`
	Relationship       Relationship     `json:"relationship"`
	RuleCode           RuleCode         `json:"rule_code"`
	Confidence         string           `json:"confidence"`
	ValidationStatus   ValidationStatus `json:"validation_status"`
	EvidenceReferences []string         `json:"evidence_references,omitempty"`
}

// GraphValidationResult captures the outcome of structural validation, reference integrity,
// and cycle detection using topological sorting.
type GraphValidationResult struct {
	IsValid          bool     `json:"is_valid"`
	HasCycle         bool     `json:"has_cycle"`
	CycleNodes       []string `json:"cycle_nodes,omitempty"`
	CycleEdges       []string `json:"cycle_edges,omitempty"`
	Errors           []string `json:"errors,omitempty"`
	Warnings         []string `json:"warnings,omitempty"`
	TopologicalOrder []string `json:"topological_order,omitempty"`
}

// AttackGraph represents an evidence-backed directed acyclic graph (DAG) of security findings
// and causal sequence transitions.
type AttackGraph struct {
	ID         string                  `json:"id"`
	Nodes      map[string]*GraphNode   `json:"nodes"`
	Edges      []*GraphEdge            `json:"edges"`
	Adjacency  map[string][]*GraphEdge `json:"adjacency"` // SourceID -> outgoing edges
	InEdges    map[string][]*GraphEdge `json:"in_edges"`  // TargetID -> incoming edges
	Validation GraphValidationResult   `json:"validation"`
}

// NewAttackGraph constructs an AttackGraph from normalized findings and relationship candidates,
// validating references, rejecting self-loops, deduplicating identical edges, and validating DAG structure.
func NewAttackGraph(findings []NormalizedFinding, relationships []Relationship) *AttackGraph {
	nodes := make(map[string]*GraphNode)
	adj := make(map[string][]*GraphEdge)
	inEdges := make(map[string][]*GraphEdge)
	var edges []*GraphEdge
	var errors []string
	var warnings []string

	// 1. Populate graph nodes from findings
	seenFindingIDs := make(map[string]bool)
	for _, f := range findings {
		if f.ID == "" {
			errors = append(errors, "Finding with empty ID rejected from graph")
			continue
		}
		if seenFindingIDs[f.ID] {
			warnings = append(warnings, fmt.Sprintf("Duplicate finding ID '%s' encountered in graph initialization", f.ID))
			continue
		}
		seenFindingIDs[f.ID] = true
		nodes[f.ID] = &GraphNode{
			ID:      f.ID,
			Finding: f,
		}
	}

	// 2. Validate and insert directed sequence edges
	seenEdgeKeys := make(map[string]bool)
	for _, rel := range relationships {
		// Only sequential attack transitions form graph edges (exclude structural/root-cause rules)
		if !rel.Type.IsSequenceType() {
			continue
		}

		// Self-loop validation
		if rel.SourceFindingID == rel.TargetFindingID {
			errors = append(errors, fmt.Sprintf("Self-loop rejected on node '%s': sequence transition to self is invalid", rel.SourceFindingID))
			continue
		}

		// Reference integrity validation
		srcNode, srcOk := nodes[rel.SourceFindingID]
		tgtNode, tgtOk := nodes[rel.TargetFindingID]
		if !srcOk {
			errors = append(errors, fmt.Sprintf("Invalid edge '%s': source node '%s' does not exist in graph", rel.ID, rel.SourceFindingID))
			continue
		}
		if !tgtOk {
			errors = append(errors, fmt.Sprintf("Invalid edge '%s': target node '%s' does not exist in graph", rel.ID, rel.TargetFindingID))
			continue
		}

		// Duplicate edge suppression
		edgeKey := fmt.Sprintf("%s->%s:%s", rel.SourceFindingID, rel.TargetFindingID, rel.RuleCode)
		if seenEdgeKeys[edgeKey] {
			warnings = append(warnings, fmt.Sprintf("Duplicate edge '%s' -> '%s' (rule %s) suppressed", rel.SourceFindingID, rel.TargetFindingID, rel.RuleCode))
			continue
		}
		seenEdgeKeys[edgeKey] = true

		graphEdge := &GraphEdge{
			ID:                 rel.ID,
			SourceID:           rel.SourceFindingID,
			TargetID:           rel.TargetFindingID,
			Relationship:       rel,
			RuleCode:           rel.RuleCode,
			Confidence:         rel.Confidence,
			ValidationStatus:   rel.ValidationStatus,
			EvidenceReferences: rel.EvidenceReferences,
		}

		edges = append(edges, graphEdge)
		adj[rel.SourceFindingID] = append(adj[rel.SourceFindingID], graphEdge)
		inEdges[rel.TargetFindingID] = append(inEdges[rel.TargetFindingID], graphEdge)
		srcNode.OutDegree++
		tgtNode.InDegree++
	}

	// 3. Sort outgoing edges deterministically for reproducible traversal
	for srcID := range adj {
		sort.Slice(adj[srcID], func(i, j int) bool {
			if adj[srcID][i].RuleCode != adj[srcID][j].RuleCode {
				return adj[srcID][i].RuleCode < adj[srcID][j].RuleCode
			}
			if adj[srcID][i].TargetID != adj[srcID][j].TargetID {
				return adj[srcID][i].TargetID < adj[srcID][j].TargetID
			}
			return adj[srcID][i].ID < adj[srcID][j].ID
		})
	}

	// 4. Stable graph identifier computed over canonical sorted nodes and edges
	var nodeIDList []string
	for id := range nodes {
		nodeIDList = append(nodeIDList, id)
	}
	sort.Strings(nodeIDList)

	var edgeIDList []string
	for _, e := range edges {
		edgeIDList = append(edgeIDList, fmt.Sprintf("%s->%s:%s", e.SourceID, e.TargetID, e.RuleCode))
	}
	sort.Strings(edgeIDList)

	graphHasher := sha256.New()
	graphHasher.Write([]byte(strings.Join(nodeIDList, ",")))
	graphHasher.Write([]byte("|"))
	graphHasher.Write([]byte(strings.Join(edgeIDList, ",")))
	graphID := fmt.Sprintf("GRAPH-%s", hex.EncodeToString(graphHasher.Sum(nil))[:12])

	g := &AttackGraph{
		ID:        graphID,
		Nodes:     nodes,
		Edges:     edges,
		Adjacency: adj,
		InEdges:   inEdges,
		Validation: GraphValidationResult{
			Errors:   errors,
			Warnings: warnings,
		},
	}

	// 5. Run topological sorting and cycle detection
	g.Validation = g.Validate()

	return g
}

// Validate executes Tarjan's strongly connected components (SCC) algorithm
// and Kahn's topological sorting algorithm to isolate exact cyclic components,
// identify cycle back-edges, and produce topological sorting for DAGs.
func (g *AttackGraph) Validate() GraphValidationResult {
	res := GraphValidationResult{
		Errors:   make([]string, len(g.Validation.Errors)),
		Warnings: make([]string, len(g.Validation.Warnings)),
	}
	copy(res.Errors, g.Validation.Errors)
	copy(res.Warnings, g.Validation.Warnings)

	if len(g.Nodes) == 0 {
		res.IsValid = (len(res.Errors) == 0)
		res.HasCycle = false
		return res
	}

	// 1. Identify strongly connected components via Tarjan's algorithm
	sccs := g.computeSCCs()

	var cycleNodes []string
	seenCycleNode := make(map[string]bool)

	for _, scc := range sccs {
		isCyclic := false
		if len(scc) > 1 {
			isCyclic = true
		} else if len(scc) == 1 {
			// Check for self-loop on single-node SCC
			u := scc[0]
			for _, edge := range g.Adjacency[u] {
				if edge.TargetID == u {
					isCyclic = true
					break
				}
			}
		}

		if isCyclic {
			for _, nodeID := range scc {
				if !seenCycleNode[nodeID] {
					seenCycleNode[nodeID] = true
					cycleNodes = append(cycleNodes, nodeID)
				}
			}
		}
	}
	sort.Strings(cycleNodes)

	if len(cycleNodes) > 0 {
		res.HasCycle = true
		res.IsValid = false
		res.CycleNodes = cycleNodes
		res.CycleEdges = g.findCycleEdges(cycleNodes)
		res.Errors = append(res.Errors, fmt.Sprintf("Cycle detected involving %d node(s): %s",
			len(cycleNodes), strings.Join(cycleNodes, ", ")))
		return res
	}

	// 2. Graph is completely acyclic. Compute topological sorting using Kahn's algorithm.
	res.HasCycle = false
	inDegree := make(map[string]int, len(g.Nodes))
	for id, n := range g.Nodes {
		inDegree[id] = n.InDegree
	}

	var zeroIn []string
	for id, deg := range inDegree {
		if deg == 0 {
			zeroIn = append(zeroIn, id)
		}
	}
	sort.Strings(zeroIn)

	var topoOrder []string
	for len(zeroIn) > 0 {
		curr := zeroIn[0]
		zeroIn = zeroIn[1:]
		topoOrder = append(topoOrder, curr)

		for _, edge := range g.Adjacency[curr] {
			inDegree[edge.TargetID]--
			if inDegree[edge.TargetID] == 0 {
				idx := sort.SearchStrings(zeroIn, edge.TargetID)
				zeroIn = append(zeroIn, "")
				copy(zeroIn[idx+1:], zeroIn[idx:])
				zeroIn[idx] = edge.TargetID
			}
		}
	}

	res.TopologicalOrder = topoOrder
	res.IsValid = (len(res.Errors) == 0)
	return res
}

// computeSCCs finds all strongly connected components using Tarjan's algorithm.
func (g *AttackGraph) computeSCCs() [][]string {
	var index int
	indices := make(map[string]int, len(g.Nodes))
	lowlink := make(map[string]int, len(g.Nodes))
	onStack := make(map[string]bool, len(g.Nodes))
	var stack []string
	var sccs [][]string

	var strongConnect func(v string)
	strongConnect = func(v string) {
		indices[v] = index
		lowlink[v] = index
		index++
		stack = append(stack, v)
		onStack[v] = true

		for _, edge := range g.Adjacency[v] {
			w := edge.TargetID
			if _, visited := indices[w]; !visited {
				strongConnect(w)
				if lowlink[w] < lowlink[v] {
					lowlink[v] = lowlink[w]
				}
			} else if onStack[w] {
				if indices[w] < lowlink[v] {
					lowlink[v] = indices[w]
				}
			}
		}

		if lowlink[v] == indices[v] {
			var scc []string
			for {
				w := stack[len(stack)-1]
				stack = stack[:len(stack)-1]
				onStack[w] = false
				scc = append(scc, w)
				if w == v {
					break
				}
			}
			sort.Strings(scc)
			sccs = append(sccs, scc)
		}
	}

	var nodeIDs []string
	for id := range g.Nodes {
		nodeIDs = append(nodeIDs, id)
	}
	sort.Strings(nodeIDs)

	for _, id := range nodeIDs {
		if _, visited := indices[id]; !visited {
			strongConnect(id)
		}
	}

	return sccs
}

// findCycleEdges uses 3-color DFS (0=unvisited, 1=in-stack, 2=completed) to isolate back-edges.
func (g *AttackGraph) findCycleEdges(candidateNodes []string) []string {
	state := make(map[string]int)
	var cycleEdges []string
	seenEdges := make(map[string]bool)

	candidateMap := make(map[string]bool, len(candidateNodes))
	for _, id := range candidateNodes {
		candidateMap[id] = true
	}

	var dfs func(curr string)
	dfs = func(curr string) {
		state[curr] = 1
		for _, edge := range g.Adjacency[curr] {
			tgt := edge.TargetID
			if !candidateMap[tgt] {
				continue
			}
			if state[tgt] == 1 {
				// Back-edge detected
				desc := fmt.Sprintf("%s -> %s", edge.SourceID, edge.TargetID)
				if !seenEdges[desc] {
					seenEdges[desc] = true
					cycleEdges = append(cycleEdges, desc)
				}
			} else if state[tgt] == 0 {
				dfs(tgt)
			}
		}
		state[curr] = 2
	}

	for _, id := range candidateNodes {
		if state[id] == 0 {
			dfs(id)
		}
	}

	sort.Strings(cycleEdges)
	return cycleEdges
}

// EligibleRoots returns nodes that have no incoming sequential edges (InDegree == 0)
// and have at least one outgoing transition edge (OutDegree > 0), ordered deterministically.
func (g *AttackGraph) EligibleRoots() []*GraphNode {
	var roots []*GraphNode
	for _, n := range g.Nodes {
		if n.InDegree == 0 && n.OutDegree > 0 {
			roots = append(roots, n)
		}
	}
	sort.Slice(roots, func(i, j int) bool {
		return roots[i].ID < roots[j].ID
	})
	return roots
}

// EntryPoints returns nodes where IsEntrypoint is true and OutDegree > 0,
// ordered deterministically by ID.
func (g *AttackGraph) EntryPoints() []*GraphNode {
	var entrypoints []*GraphNode
	for _, n := range g.Nodes {
		if n.Finding.IsEntrypoint && n.OutDegree > 0 {
			entrypoints = append(entrypoints, n)
		}
	}
	sort.Slice(entrypoints, func(i, j int) bool {
		return entrypoints[i].ID < entrypoints[j].ID
	})
	return entrypoints
}

// Sinks returns terminal nodes that have incoming transitions (InDegree > 0)
// but no outgoing transitions (OutDegree == 0), ordered deterministically.
func (g *AttackGraph) Sinks() []*GraphNode {
	var sinks []*GraphNode
	for _, n := range g.Nodes {
		if n.InDegree > 0 && n.OutDegree == 0 {
			sinks = append(sinks, n)
		}
	}
	sort.Slice(sinks, func(i, j int) bool {
		return sinks[i].ID < sinks[j].ID
	})
	return sinks
}
