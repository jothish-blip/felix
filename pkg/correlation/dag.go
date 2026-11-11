package correlation

import (
	"container/heap"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"sort"
	"strings"

	"felix/pkg/report"
	"felix/pkg/secrets"
)

// DAGNodeType categorizes the semantic role of an attack graph node.
type DAGNodeType string

const (
	NodeTypeFinding       DAGNodeType = "FINDING"
	NodeTypeCredential    DAGNodeType = "CREDENTIAL"
	NodeTypeRoute         DAGNodeType = "ROUTE"
	NodeTypeCloudResource DAGNodeType = "CLOUD_RESOURCE"
	NodeTypeSensitiveData DAGNodeType = "SENSITIVE_DATA"
	NodeTypeCriticalAsset DAGNodeType = "CRITICAL_ASSET"
	NodeTypeComponent     DAGNodeType = "COMPONENT"
	NodeTypeApplication   DAGNodeType = "APPLICATION"
)

// DAGEdgeType defines the causal transition between two DAG nodes.
type DAGEdgeType string

const (
	DAGEdgeCredToRoute           DAGEdgeType = "CREDENTIAL_TO_ROUTE"
	DAGEdgeSSRFToMetadata        DAGEdgeType = "SSRF_TO_METADATA"
	DAGEdgeTraversalToDisclosure DAGEdgeType = "TRAVERSAL_TO_DISCLOSURE"
	DAGEdgeSQLiToDatabase        DAGEdgeType = "SQLI_TO_DATABASE"
	DAGEdgeBOLAToObjectAccess    DAGEdgeType = "BOLA_TO_OBJECT_ACCESS"
	DAGEdgeMobileSecretToBackend DAGEdgeType = "MOBILE_SECRET_TO_BACKEND"
	DAGEdgeSequenceTransition    DAGEdgeType = "SEQUENCE_TRANSITION"
)

// DAGNode represents an enriched entity in the directed acyclic attack graph.
type DAGNode struct {
	ID                 string                    `json:"id"`
	Type               DAGNodeType               `json:"type"`
	FindingID          string                    `json:"finding_id,omitempty"`
	Finding            *NormalizedFinding        `json:"finding,omitempty"`
	Title              string                    `json:"title"`
	Severity           string                    `json:"severity"`
	Confidence         string                    `json:"confidence"`
	VerificationStatus report.VerificationStatus `json:"verification_status"`
	SourceEngine       string                    `json:"source_engine"`
	EvidenceReferences []string                  `json:"evidence_references,omitempty"`
	AssetAssociation   string                    `json:"asset_association,omitempty"`
	IsCriticalAsset    bool                      `json:"is_critical_asset"`
	IsEntrypoint       bool                      `json:"is_entrypoint"`
	Attributes         map[string]string         `json:"attributes,omitempty"`
	InDegree           int                       `json:"in_degree"`
	OutDegree          int                       `json:"out_degree"`
}

// DAGEdge represents an evidence-supported causal transition in the DAG.
type DAGEdge struct {
	ID                 string           `json:"id"`
	SourceID           string           `json:"source_id"`
	TargetID           string           `json:"target_id"`
	Type               DAGEdgeType      `json:"type"`
	RuleCode           RuleCode         `json:"rule_code"`
	Confidence         string           `json:"confidence"`
	Weight             float64          `json:"weight"`
	EvidenceReferences []string         `json:"evidence_references,omitempty"`
	Explanation        string           `json:"explanation"`
	ValidationStatus   ValidationStatus `json:"validation_status"`
}

// DAGPath models an end-to-end multi-hop breach sequence.
type DAGPath struct {
	ID                string     `json:"id"`
	NodeIDs           []string   `json:"node_ids"`
	Nodes             []*DAGNode `json:"nodes"`
	Edges             []*DAGEdge `json:"edges"`
	TotalWeight       float64    `json:"total_weight"`
	EntryPointID      string     `json:"entry_point_id"`
	TargetNodeID      string     `json:"target_node_id"`
	IsCriticalBreach  bool       `json:"is_critical_breach"`
	CombinedRiskScore int        `json:"combined_risk_score"`
	CombinedRiskLevel string     `json:"combined_risk_level"`
	Explanation       string     `json:"explanation"`
}

// DAGShortestPathResult captures the outcome of Dijkstra's algorithm.
type DAGShortestPathResult struct {
	SourceID          string     `json:"source_id"`
	TargetID          string     `json:"target_id"`
	PathExists        bool       `json:"path_exists"`
	TotalCost         float64    `json:"total_cost"`
	HopCount          int        `json:"hop_count"`
	NodePath          []string   `json:"node_path"`
	EdgePath          []*DAGEdge `json:"edge_path"`
	ReachableCritical bool       `json:"reachable_critical"`
}

// DAGAttackGraph manages the lifecycle, validation, and traversal of a directed acyclic attack graph.
type DAGAttackGraph struct {
	ID           string                  `json:"id"`
	Nodes        map[string]*DAGNode     `json:"nodes"`
	Edges        []*DAGEdge              `json:"edges"`
	Adjacency    map[string][]*DAGEdge   `json:"adjacency"`
	InEdges      map[string][]*DAGEdge   `json:"in_edges"`
	Validation   GraphValidationResult   `json:"validation"`
	RejectCycles bool                    `json:"reject_cycles"`
}

// NewDAGAttackGraph constructs an empty DAGAttackGraph.
func NewDAGAttackGraph(rejectCycles bool) *DAGAttackGraph {
	return &DAGAttackGraph{
		Nodes:        make(map[string]*DAGNode),
		Edges:        make([]*DAGEdge, 0),
		Adjacency:    make(map[string][]*DAGEdge),
		InEdges:      make(map[string][]*DAGEdge),
		RejectCycles: rejectCycles,
	}
}

// CalculateEdgeCost computes the mathematical cost of an edge based on destination severity,
// edge confidence, and destination verification status:
//
//	Cost = BaseCost / (SeverityScore(dst) * ConfidenceWeight(edge) * VerificationWeight(dst))
//
// Higher severity, confidence, and verification yield lower cost (attacker's preferred path).
// All returned weights are strictly > 0.
func CalculateEdgeCost(src *DAGNode, dst *DAGNode, edgeConfidence string) float64 {
	const baseCost = 100.0

	sevWeight := 1.0
	if dst != nil {
		switch strings.ToUpper(dst.Severity) {
		case report.SeverityCritical:
			sevWeight = 4.0
		case report.SeverityHigh:
			sevWeight = 3.0
		case report.SeverityMedium:
			sevWeight = 2.0
		case report.SeverityLow:
			sevWeight = 1.0
		case report.SeverityInfo:
			sevWeight = 0.5
		default:
			if dst.IsCriticalAsset {
				sevWeight = 4.0
			} else {
				sevWeight = 1.0
			}
		}
	}

	confWeight := 0.8
	switch strings.ToUpper(edgeConfidence) {
	case "HIGH":
		confWeight = 1.0
	case "MEDIUM":
		confWeight = 0.8
	case "LOW":
		confWeight = 0.5
	}

	verWeight := 0.7
	if dst != nil {
		switch string(dst.VerificationStatus) {
		case "CONFIRMED", "VERIFIED":
			verWeight = 1.0
		case "POTENTIAL", "PLAUSIBLE", "DETECTED":
			verWeight = 0.7
		case "INCONCLUSIVE", "OBSERVED", "NOT_VERIFIED":
			verWeight = 0.4
		default:
			verWeight = 0.7
		}
	}

	denominator := sevWeight * confWeight * verWeight
	if denominator <= 0.0001 {
		denominator = 0.0001
	}

	cost := baseCost / denominator
	return math.Round(cost*100.0) / 100.0
}

// AddNode inserts a node into the graph with deduplication, attribute sanitization,
// and sensitive data redaction.
func (g *DAGAttackGraph) AddNode(node *DAGNode) error {
	if node == nil {
		return fmt.Errorf("cannot add nil node")
	}
	if node.ID == "" {
		return fmt.Errorf("node must have a non-empty ID")
	}

	if _, exists := g.Nodes[node.ID]; exists {
		return fmt.Errorf("duplicate node ID '%s' rejected", node.ID)
	}

	// Redact sensitive values in node title and attributes
	node.Title = secrets.RedactText(node.Title)
	if node.Attributes != nil {
		sanitizedAttrs := make(map[string]string, len(node.Attributes))
		for k, v := range node.Attributes {
			sanitizedAttrs[k] = secrets.RedactText(v)
		}
		node.Attributes = sanitizedAttrs
	}

	// If node is unverified or marked inconclusive, adjust confidence/status
	if node.VerificationStatus == "" {
		node.VerificationStatus = report.VerificationDetected
	}

	g.Nodes[node.ID] = node
	if _, ok := g.Adjacency[node.ID]; !ok {
		g.Adjacency[node.ID] = make([]*DAGEdge, 0)
	}
	if _, ok := g.InEdges[node.ID]; !ok {
		g.InEdges[node.ID] = make([]*DAGEdge, 0)
	}

	return nil
}

// AddEdge validates references, suppresses duplicate edges, prevents self-loops,
// verifies non-negative edge costs, and rejects cycles if configured.
func (g *DAGAttackGraph) AddEdge(edge *DAGEdge) error {
	if edge == nil {
		return fmt.Errorf("cannot add nil edge")
	}
	if edge.SourceID == "" || edge.TargetID == "" {
		return fmt.Errorf("edge must have non-empty SourceID and TargetID")
	}

	// Self-loop validation
	if edge.SourceID == edge.TargetID {
		return fmt.Errorf("self-loop rejected on node '%s': sequence transition to self is invalid", edge.SourceID)
	}

	// Reference integrity
	srcNode, srcOk := g.Nodes[edge.SourceID]
	if !srcOk {
		return fmt.Errorf("invalid edge '%s': source node '%s' does not exist in graph", edge.ID, edge.SourceID)
	}
	tgtNode, tgtOk := g.Nodes[edge.TargetID]
	if !tgtOk {
		return fmt.Errorf("invalid edge '%s': target node '%s' does not exist in graph", edge.ID, edge.TargetID)
	}

	// Duplicate edge suppression
	for _, existing := range g.Adjacency[edge.SourceID] {
		if existing.TargetID == edge.TargetID && existing.Type == edge.Type && existing.RuleCode == edge.RuleCode {
			return fmt.Errorf("duplicate edge '%s' -> '%s' (type %s) suppressed", edge.SourceID, edge.TargetID, edge.Type)
		}
	}

	// Ensure edge weight is calculated and valid
	if edge.Weight <= 0 || math.IsNaN(edge.Weight) || math.IsInf(edge.Weight, 0) {
		edge.Weight = CalculateEdgeCost(srcNode, tgtNode, edge.Confidence)
	}

	// Redact sensitive values in explanation
	edge.Explanation = secrets.RedactText(edge.Explanation)

	// Temporary addition to test for cycles if reject_cycles is enabled
	g.Adjacency[edge.SourceID] = append(g.Adjacency[edge.SourceID], edge)
	g.InEdges[edge.TargetID] = append(g.InEdges[edge.TargetID], edge)
	g.Edges = append(g.Edges, edge)
	srcNode.OutDegree++
	tgtNode.InDegree++

	if g.RejectCycles {
		val := g.Validate()
		if val.HasCycle {
			// Rollback edge addition
			g.Adjacency[edge.SourceID] = g.Adjacency[edge.SourceID][:len(g.Adjacency[edge.SourceID])-1]
			g.InEdges[edge.TargetID] = g.InEdges[edge.TargetID][:len(g.InEdges[edge.TargetID])-1]
			g.Edges = g.Edges[:len(g.Edges)-1]
			srcNode.OutDegree--
			tgtNode.InDegree--
			return fmt.Errorf("cycle rejected: edge '%s' -> '%s' introduces cycle involving %s",
				edge.SourceID, edge.TargetID, strings.Join(val.CycleNodes, ", "))
		}
	}

	return nil
}

// Validate executes Tarjan's strongly connected components algorithm and Kahn's topological sort.
func (g *DAGAttackGraph) Validate() GraphValidationResult {
	res := GraphValidationResult{
		IsValid:  true,
		HasCycle: false,
	}

	if len(g.Nodes) == 0 {
		return res
	}

	// 1. Tarjan SCC detection
	sccs := g.computeSCCs()
	var cycleNodes []string
	seenCycleNode := make(map[string]bool)

	for _, scc := range sccs {
		isCyclic := false
		if len(scc) > 1 {
			isCyclic = true
		} else if len(scc) == 1 {
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

	// 2. Kahn's algorithm for topological sorting
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
	res.IsValid = len(topoOrder) == len(g.Nodes)
	return res
}

func (g *DAGAttackGraph) computeSCCs() [][]string {
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

	nodeIDs := make([]string, 0, len(g.Nodes))
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

func (g *DAGAttackGraph) findCycleEdges(candidateNodes []string) []string {
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

// FindReachableNodes computes the full set of nodes reachable from startID using BFS traversal.
func (g *DAGAttackGraph) FindReachableNodes(startID string) []string {
	if _, ok := g.Nodes[startID]; !ok {
		return []string{}
	}

	visited := make(map[string]bool)
	queue := []string{startID}
	visited[startID] = true

	for len(queue) > 0 {
		curr := queue[0]
		queue = queue[1:]

		for _, edge := range g.Adjacency[curr] {
			if !visited[edge.TargetID] {
				visited[edge.TargetID] = true
				queue = append(queue, edge.TargetID)
			}
		}
	}

	reachable := make([]string, 0, len(visited))
	for id := range visited {
		reachable = append(reachable, id)
	}
	sort.Strings(reachable)
	return reachable
}

// Dijkstra Item for Priority Queue
type dijkstraItem struct {
	nodeID   string
	cost     float64
	hopCount int
	index    int
}

type dijkstraPriorityQueue []*dijkstraItem

func (pq dijkstraPriorityQueue) Len() int           { return len(pq) }
func (pq dijkstraPriorityQueue) Less(i, j int) bool { return pq[i].cost < pq[j].cost }
func (pq dijkstraPriorityQueue) Swap(i, j int) {
	pq[i], pq[j] = pq[j], pq[i]
	pq[i].index = i
	pq[j].index = j
}
func (pq *dijkstraPriorityQueue) Push(x any) {
	n := len(*pq)
	item := x.(*dijkstraItem)
	item.index = n
	*pq = append(*pq, item)
}
func (pq *dijkstraPriorityQueue) Pop() any {
	old := *pq
	n := len(old)
	item := old[n-1]
	old[n-1] = nil
	item.index = -1
	*pq = old[0 : n-1]
	return item
}

// ShortestPath executes Dijkstra's algorithm to compute the minimum-cost attack path between source and target.
func (g *DAGAttackGraph) ShortestPath(startID, targetID string) (*DAGShortestPathResult, error) {
	if _, ok := g.Nodes[startID]; !ok {
		return nil, fmt.Errorf("start node '%s' does not exist in graph", startID)
	}
	if _, ok := g.Nodes[targetID]; !ok {
		return nil, fmt.Errorf("target node '%s' does not exist in graph", targetID)
	}

	if startID == targetID {
		return &DAGShortestPathResult{
			SourceID:   startID,
			TargetID:   targetID,
			PathExists: true,
			TotalCost:  0,
			HopCount:   0,
			NodePath:   []string{startID},
			EdgePath:   []*DAGEdge{},
		}, nil
	}

	dist := make(map[string]float64)
	prevNode := make(map[string]string)
	prevEdge := make(map[string]*DAGEdge)
	hopCount := make(map[string]int)

	for id := range g.Nodes {
		dist[id] = math.Inf(1)
	}
	dist[startID] = 0

	pq := make(dijkstraPriorityQueue, 0, len(g.Nodes))
	heap.Init(&pq)
	heap.Push(&pq, &dijkstraItem{nodeID: startID, cost: 0, hopCount: 0})

	for pq.Len() > 0 {
		top := heap.Pop(&pq).(*dijkstraItem)
		u := top.nodeID

		if top.cost > dist[u] {
			continue
		}

		if u == targetID {
			break
		}

		for _, edge := range g.Adjacency[u] {
			v := edge.TargetID
			newCost := dist[u] + edge.Weight
			if newCost < dist[v] {
				dist[v] = newCost
				prevNode[v] = u
				prevEdge[v] = edge
				hopCount[v] = hopCount[u] + 1
				heap.Push(&pq, &dijkstraItem{nodeID: v, cost: newCost, hopCount: hopCount[v]})
			}
		}
	}

	if math.IsInf(dist[targetID], 1) {
		return &DAGShortestPathResult{
			SourceID:   startID,
			TargetID:   targetID,
			PathExists: false,
		}, nil
	}

	// Reconstruct path
	var nodePath []string
	var edgePath []*DAGEdge

	curr := targetID
	for curr != startID {
		nodePath = append(nodePath, curr)
		edge := prevEdge[curr]
		edgePath = append(edgePath, edge)
		curr = prevNode[curr]
	}
	nodePath = append(nodePath, startID)

	// Reverse slices
	for i, j := 0, len(nodePath)-1; i < j; i, j = i+1, j-1 {
		nodePath[i], nodePath[j] = nodePath[j], nodePath[i]
	}
	for i, j := 0, len(edgePath)-1; i < j; i, j = i+1, j-1 {
		edgePath[i], edgePath[j] = edgePath[j], edgePath[i]
	}

	tgtNode := g.Nodes[targetID]
	isCritical := tgtNode != nil && (tgtNode.IsCriticalAsset || tgtNode.Type == NodeTypeCriticalAsset)

	return &DAGShortestPathResult{
		SourceID:          startID,
		TargetID:          targetID,
		PathExists:        true,
		TotalCost:         math.Round(dist[targetID]*100.0) / 100.0,
		HopCount:          len(edgePath),
		NodePath:          nodePath,
		EdgePath:          edgePath,
		ReachableCritical: isCritical,
	}, nil
}

// FindShortestPathToCriticalAsset evaluates all critical assets reachable from startID and returns
// the one reachable with the minimum attack cost.
func (g *DAGAttackGraph) FindShortestPathToCriticalAsset(startID string) (*DAGShortestPathResult, error) {
	if _, ok := g.Nodes[startID]; !ok {
		return nil, fmt.Errorf("start node '%s' does not exist in graph", startID)
	}

	reachable := g.FindReachableNodes(startID)
	var bestResult *DAGShortestPathResult
	minCost := math.Inf(1)

	for _, nodeID := range reachable {
		node := g.Nodes[nodeID]
		if node == nil || (!node.IsCriticalAsset && node.Type != NodeTypeCriticalAsset) {
			continue
		}

		res, err := g.ShortestPath(startID, nodeID)
		if err != nil || !res.PathExists {
			continue
		}

		if res.TotalCost < minCost {
			minCost = res.TotalCost
			bestResult = res
		}
	}

	if bestResult == nil {
		return &DAGShortestPathResult{
			SourceID:          startID,
			PathExists:        false,
			ReachableCritical: false,
		}, nil
	}

	return bestResult, nil
}

// InferDAGEdges discovers evidence-supported transitions between findings and assets:
// 1. CREDENTIAL_TO_ROUTE: Credential/token disclosure -> authenticated route access
// 2. SSRF_TO_METADATA: SSRF exposure -> cloud metadata access
// 3. TRAVERSAL_TO_DISCLOSURE: Path traversal -> sensitive file disclosure -> credential exposure
// 4. SQLI_TO_DATABASE: SQL injection -> database access
// 5. BOLA_TO_OBJECT_ACCESS: BOLA -> unauthorized object access
// 6. MOBILE_SECRET_TO_BACKEND: Mobile secret exposure -> backend API / authentication access
func InferDAGEdges(nodes map[string]*DAGNode) []*DAGEdge {
	var inferred []*DAGEdge
	seenKeys := make(map[string]bool)

	// Sort node IDs deterministically
	nodeIDs := make([]string, 0, len(nodes))
	for id := range nodes {
		nodeIDs = append(nodeIDs, id)
	}
	sort.Strings(nodeIDs)

	for _, srcID := range nodeIDs {
		src := nodes[srcID]
		if src == nil {
			continue
		}

		for _, tgtID := range nodeIDs {
			if srcID == tgtID {
				continue
			}
			tgt := nodes[tgtID]
			if tgt == nil {
				continue
			}

			var edgeType DAGEdgeType
			var ruleCode RuleCode
			var explanation string
			var confidence string = "HIGH"

			srcCat := strings.ToUpper(src.Title)
			tgtCat := strings.ToUpper(tgt.Title)
			if src.Finding != nil {
				srcCat = strings.ToUpper(src.Finding.NormalizedCategory + " " + src.Finding.Title)
			}
			if tgt.Finding != nil {
				tgtCat = strings.ToUpper(tgt.Finding.NormalizedCategory + " " + tgt.Finding.Title)
			}

			// 1. CREDENTIAL_TO_ROUTE
			if (src.Type == NodeTypeCredential || strings.Contains(srcCat, "CREDENTIAL") || strings.Contains(srcCat, "TOKEN") || strings.Contains(srcCat, "SECRET")) &&
				(tgt.Type == NodeTypeRoute || tgt.Type == NodeTypeApplication || strings.Contains(tgtCat, "AUTH") || strings.Contains(tgtCat, "ADMIN") || strings.Contains(tgtCat, "ROUTE")) {
				edgeType = DAGEdgeCredToRoute
				ruleCode = RuleCOR02
				explanation = fmt.Sprintf("Exposed credentials from '%s' satisfy authentication prerequisite for route '%s'.", src.Title, tgt.Title)
			}

			// 2. SSRF_TO_METADATA
			if (strings.Contains(srcCat, "SSRF") || strings.Contains(srcCat, "REQUEST FORGERY")) &&
				(tgt.Type == NodeTypeCloudResource || strings.Contains(tgtCat, "METADATA") || strings.Contains(tgtCat, "IMDS") || strings.Contains(tgtCat, "169.254")) {
				edgeType = DAGEdgeSSRFToMetadata
				ruleCode = RuleCOR08
				explanation = fmt.Sprintf("SSRF vulnerability '%s' enables unauthorized querying of cloud metadata service '%s'.", src.Title, tgt.Title)
			}

			// 3. TRAVERSAL_TO_DISCLOSURE
			if (strings.Contains(srcCat, "TRAVERSAL") || strings.Contains(srcCat, "LFI") || strings.Contains(srcCat, "FILE READ")) &&
				(tgt.Type == NodeTypeSensitiveData || tgt.Type == NodeTypeCredential || strings.Contains(tgtCat, "CONFIG") || strings.Contains(tgtCat, "SECRET") || strings.Contains(tgtCat, "SHADOW") || strings.Contains(tgtCat, "ENV")) {
				edgeType = DAGEdgeTraversalToDisclosure
				ruleCode = RuleCOR04
				explanation = fmt.Sprintf("Path traversal flaw '%s' enables arbitrary reading of sensitive configuration/credentials '%s'.", src.Title, tgt.Title)
			}

			// 4. SQLI_TO_DATABASE
			if (strings.Contains(srcCat, "SQL") || strings.Contains(srcCat, "INJECTION")) &&
				(tgt.Type == NodeTypeCriticalAsset || strings.Contains(tgtCat, "DATABASE") || strings.Contains(tgtCat, "DATA STORE") || strings.Contains(tgtCat, "DUMP")) {
				edgeType = DAGEdgeSQLiToDatabase
				ruleCode = RuleCOR03
				explanation = fmt.Sprintf("SQL injection vulnerability '%s' provides arbitrary read/write access to database asset '%s'.", src.Title, tgt.Title)
			}

			// 5. BOLA_TO_OBJECT_ACCESS
			if (strings.Contains(srcCat, "BOLA") || strings.Contains(srcCat, "IDOR") || strings.Contains(srcCat, "OBJECT-LEVEL")) &&
				(tgt.Type == NodeTypeSensitiveData || strings.Contains(tgtCat, "USER") || strings.Contains(tgtCat, "RECORD") || strings.Contains(tgtCat, "DATA")) {
				edgeType = DAGEdgeBOLAToObjectAccess
				ruleCode = RuleCOR03
				explanation = fmt.Sprintf("BOLA flaw '%s' permits horizontal/vertical enumeration of protected object resources '%s'.", src.Title, tgt.Title)
			}

			// 6. MOBILE_SECRET_TO_BACKEND
			if (src.SourceEngine == "ENGINE_6_MOBILE" || strings.Contains(srcCat, "MOBILE") || strings.Contains(srcCat, "DEX")) &&
				(src.Type == NodeTypeCredential || strings.Contains(srcCat, "SECRET") || strings.Contains(srcCat, "API KEY")) &&
				(tgt.Type == NodeTypeRoute || tgt.Type == NodeTypeApplication || strings.Contains(tgtCat, "BACKEND") || strings.Contains(tgtCat, "API")) {
				edgeType = DAGEdgeMobileSecretToBackend
				ruleCode = RuleCOR01
				explanation = fmt.Sprintf("Mobile DEX secret disclosure in '%s' satisfies authentication for backend endpoint '%s'.", src.Title, tgt.Title)
			}

			if edgeType != "" {
				edgeKey := fmt.Sprintf("%s->%s:%s", srcID, tgtID, edgeType)
				if !seenKeys[edgeKey] {
					seenKeys[edgeKey] = true
					weight := CalculateEdgeCost(src, tgt, confidence)
					edgeID := fmt.Sprintf("EDGE-%s", hex.EncodeToString(sha256.New().Sum([]byte(edgeKey)))[:10])
					inferred = append(inferred, &DAGEdge{
						ID:               edgeID,
						SourceID:         srcID,
						TargetID:         tgtID,
						Type:             edgeType,
						RuleCode:         ruleCode,
						Confidence:       confidence,
						Weight:           weight,
						Explanation:      secrets.RedactText(explanation),
						ValidationStatus: ValidationCandidate,
					})
				}
			}
		}
	}

	return inferred
}

// BuildDAGFromNormalizedFindings converts normalized findings and relationships into a validated DAGAttackGraph.
func BuildDAGFromNormalizedFindings(findings []NormalizedFinding, relationships []Relationship, rejectCycles bool) (*DAGAttackGraph, error) {
	dag := NewDAGAttackGraph(rejectCycles)

	for _, f := range findings {
		nodeType := NodeTypeFinding
		isCritical := f.Severity == report.SeverityCritical
		if f.IsSensitiveData {
			nodeType = NodeTypeSensitiveData
		} else if f.IsCloudResource {
			nodeType = NodeTypeCloudResource
		} else if strings.Contains(strings.ToUpper(f.NormalizedCategory), "CREDENTIAL") || strings.Contains(strings.ToUpper(f.Title), "TOKEN") {
			nodeType = NodeTypeCredential
		}

		engine := "ENGINE_UNKNOWN"
		if f.Source != "" {
			engine = f.Source
		}

		node := &DAGNode{
			ID:                 f.ID,
			Type:               nodeType,
			FindingID:          f.ID,
			Finding:            &f,
			Title:              f.Title,
			Severity:           f.Severity,
			Confidence:         f.Confidence,
			VerificationStatus: f.VerificationStatus,
			SourceEngine:       engine,
			EvidenceReferences: []string{f.EvidenceSummary},
			AssetAssociation:   f.CanonicalAssetKey,
			IsCriticalAsset:    isCritical,
			IsEntrypoint:       f.IsEntrypoint,
		}
		if err := dag.AddNode(node); err != nil {
			// duplicate or invalid node
			continue
		}
	}

	// Add relationships
	for _, rel := range relationships {
		if !rel.Type.IsSequenceType() {
			continue
		}
		srcNode, srcOk := dag.Nodes[rel.SourceFindingID]
		tgtNode, tgtOk := dag.Nodes[rel.TargetFindingID]
		if !srcOk || !tgtOk {
			continue
		}

		weight := CalculateEdgeCost(srcNode, tgtNode, rel.Confidence)
		edge := &DAGEdge{
			ID:                 rel.ID,
			SourceID:           rel.SourceFindingID,
			TargetID:           rel.TargetFindingID,
			Type:               DAGEdgeSequenceTransition,
			RuleCode:           rel.RuleCode,
			Confidence:         rel.Confidence,
			Weight:             weight,
			EvidenceReferences: rel.EvidenceReferences,
			Explanation:        rel.Explanation,
			ValidationStatus:   rel.ValidationStatus,
		}
		_ = dag.AddEdge(edge)
	}

	// Also infer domain-specific transitions (SSRF, Traversal, Mobile Secret, SQLi)
	inferredEdges := InferDAGEdges(dag.Nodes)
	for _, edge := range inferredEdges {
		_ = dag.AddEdge(edge)
	}

	dag.Validation = dag.Validate()
	return dag, nil
}

// ToCanonicalJSON serializes the DAGAttackGraph deterministically with sorted nodes and edges,
// returning the canonical JSON bytes and its SHA-256 hash.
func (g *DAGAttackGraph) ToCanonicalJSON() ([]byte, string, error) {
	nodeIDs := make([]string, 0, len(g.Nodes))
	for id := range g.Nodes {
		nodeIDs = append(nodeIDs, id)
	}
	sort.Strings(nodeIDs)

	sortedNodes := make([]*DAGNode, 0, len(nodeIDs))
	for _, id := range nodeIDs {
		sortedNodes = append(sortedNodes, g.Nodes[id])
	}

	sortedEdges := make([]*DAGEdge, len(g.Edges))
	copy(sortedEdges, g.Edges)
	sort.Slice(sortedEdges, func(i, j int) bool {
		if sortedEdges[i].SourceID != sortedEdges[j].SourceID {
			return sortedEdges[i].SourceID < sortedEdges[j].SourceID
		}
		if sortedEdges[i].TargetID != sortedEdges[j].TargetID {
			return sortedEdges[i].TargetID < sortedEdges[j].TargetID
		}
		return sortedEdges[i].Type < sortedEdges[j].Type
	})

	canonicalMap := map[string]any{
		"node_count": len(sortedNodes),
		"edge_count": len(sortedEdges),
		"nodes":      sortedNodes,
		"edges":      sortedEdges,
		"is_valid":   g.Validation.IsValid,
		"has_cycle":  g.Validation.HasCycle,
	}

	canonicalBytes, err := json.Marshal(canonicalMap)
	if err != nil {
		return nil, "", fmt.Errorf("canonical JSON marshaling failed: %w", err)
	}

	hash := sha256.Sum256(canonicalBytes)
	return canonicalBytes, hex.EncodeToString(hash[:]), nil
}

// ToAttackGraph converts a DAGAttackGraph into an AttackGraph for backwards compatibility
// with existing correlation reporting and visualization pipelines.
//
// Documented Adapter Semantics & Lossy Boundaries (DAGAttackGraph -> AttackGraph):
// 1. Attributes: DAGNode.Attributes cannot be represented because AttackGraph GraphNode and NormalizedFinding lack an attributes map.
// 2. Node Evidence: When DAGNode.Finding is nil, only EvidenceReferences[0] is copied into NormalizedFinding.EvidenceSummary; additional references are dropped.
// 3. Discrete Node Types: Specialized types (NodeTypeRoute, NodeTypeCriticalAsset) lack discrete type enums in AttackGraph and map to Severity/IsEntrypoint flags.
// 4. Discrete Edge Types: Specialized DAGEdgeType values (e.g. DAGEdgeSQLiToDatabase) map to standard RelationshipType (RelReaches, RelEnables, RelExposes) via RuleCode.
// 5. Preserved Semantics: Node IDs, Finding IDs, Severity, Confidence, VerificationStatus, AssetAssociation, Edge direction, Weights, ValidationStatus, RuleCode, and Edge EvidenceReferences are preserved.
func (g *DAGAttackGraph) ToAttackGraph() *AttackGraph {
	nodes := make(map[string]*GraphNode, len(g.Nodes))
	adj := make(map[string][]*GraphEdge)
	inEdges := make(map[string][]*GraphEdge)
	var edges []*GraphEdge

	for id, dagNode := range g.Nodes {
		var f NormalizedFinding
		if dagNode.Finding != nil {
			f = *dagNode.Finding
		} else {
			evSummary := ""
			if len(dagNode.EvidenceReferences) > 0 {
				evSummary = dagNode.EvidenceReferences[0]
			}
			f = NormalizedFinding{
				ID:                 dagNode.ID,
				Title:              dagNode.Title,
				Severity:           dagNode.Severity,
				Confidence:         dagNode.Confidence,
				VerificationStatus: dagNode.VerificationStatus,
				Source:             dagNode.SourceEngine,
				EvidenceSummary:    evSummary,
				CanonicalAssetKey:  dagNode.AssetAssociation,
				IsEntrypoint:       dagNode.IsEntrypoint,
			}
		}
		nodes[id] = &GraphNode{
			ID:        id,
			Finding:   f,
			InDegree:  dagNode.InDegree,
			OutDegree: dagNode.OutDegree,
		}
	}

	for _, e := range g.Edges {
		relType := RelEnables
		switch e.RuleCode {
		case RuleCOR01:
			relType = RelReaches
		case RuleCOR02:
			relType = RelEnables
		case RuleCOR03:
			relType = RelExposes
		case RuleCOR04:
			relType = RelExposes
		case RuleCOR08:
			relType = RelEnables
		default:
			relType = RelEnables
		}

		ge := &GraphEdge{
			ID:                 e.ID,
			SourceID:           e.SourceID,
			TargetID:           e.TargetID,
			RuleCode:           e.RuleCode,
			Confidence:         e.Confidence,
			Weight:             e.Weight,
			ValidationStatus:   e.ValidationStatus,
			EvidenceReferences: e.EvidenceReferences,
			Relationship: Relationship{
				ID:                 e.ID,
				SourceFindingID:   e.SourceID,
				TargetFindingID:   e.TargetID,
				Type:               relType,
				RuleCode:           e.RuleCode,
				Confidence:         e.Confidence,
				ValidationStatus:   e.ValidationStatus,
				EvidenceReferences: e.EvidenceReferences,
				Explanation:        e.Explanation,
			},
		}
		edges = append(edges, ge)
		adj[e.SourceID] = append(adj[e.SourceID], ge)
		inEdges[e.TargetID] = append(inEdges[e.TargetID], ge)
	}

	// Sort adjacency deterministically
	for srcID := range adj {
		sort.Slice(adj[srcID], func(i, j int) bool {
			if adj[srcID][i].RuleCode != adj[srcID][j].RuleCode {
				return adj[srcID][i].RuleCode < adj[srcID][j].RuleCode
			}
			return adj[srcID][i].TargetID < adj[srcID][j].TargetID
		})
	}

	ag := &AttackGraph{
		ID:         g.ID,
		Nodes:      nodes,
		Edges:      edges,
		Adjacency:  adj,
		InEdges:    inEdges,
		Validation: g.Validation,
	}

	return ag
}
