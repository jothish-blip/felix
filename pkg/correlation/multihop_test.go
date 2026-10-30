package correlation

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"felix/pkg/report"
)

// Helper to construct normalized test findings with deterministic properties
func makeMultihopFinding(id, title, category, severity string, isVerified, isCandidate, isEntrypoint, isSensitive, isCloud bool, endpoint string) NormalizedFinding {
	host := "api.example.com"
	path := "/api/v1"
	if strings.HasPrefix(endpoint, "http") {
		parts := strings.Split(endpoint, "://")
		if len(parts) > 1 {
			slashIdx := strings.Index(parts[1], "/")
			if slashIdx != -1 {
				host = parts[1][:slashIdx]
				path = parts[1][slashIdx:]
			} else {
				host = parts[1]
				path = "/"
			}
		}
	} else if strings.HasPrefix(endpoint, "/") {
		path = endpoint
	}

	verStatus := report.VerificationObserved
	if isVerified {
		verStatus = report.VerificationVerified
	} else if isCandidate {
		verStatus = report.VerificationDetected
	}

	score := 10
	switch severity {
	case report.SeverityCritical:
		score = 35
	case report.SeverityHigh:
		score = 25
	case report.SeverityMedium:
		score = 15
	case report.SeverityLow:
		score = 10
	case report.SeverityInfo:
		score = 5
	}

	return NormalizedFinding{
		ID:                 id,
		OriginalID:         id,
		Title:              title,
		Category:           category,
		NormalizedCategory: category,
		Severity:           severity,
		Confidence:         report.ConfidenceHigh,
		VerificationStatus: verStatus,
		Target:             host,
		Host:               host,
		Endpoint:           endpoint,
		DisplayEndpoint:    endpoint,
		Path:               path,
		Method:             "GET",
		Score:              score,
		IsVerified:         isVerified,
		IsCandidate:        isCandidate,
		IsEntrypoint:       isEntrypoint,
		IsSensitiveData:    isSensitive,
		IsCloudResource:    isCloud,
		EvidenceSummary:    "Automated synthetic verification indicator",
		EvidenceDetails:    map[string]string{"state": "active"},
		SyntheticFixture:   true,
	}
}

// -----------------------------------------------------------------------------
// 1. Graph Fundamentals
// -----------------------------------------------------------------------------

func TestGraph_Empty(t *testing.T) {
	graph := NewAttackGraph(nil, nil)
	if len(graph.Nodes) != 0 || len(graph.Edges) != 0 {
		t.Fatalf("expected empty graph, got %d nodes, %d edges", len(graph.Nodes), len(graph.Edges))
	}
	if !graph.Validation.IsValid {
		t.Fatalf("empty graph must be valid, got errors: %v", graph.Validation.Errors)
	}
	if graph.Validation.HasCycle {
		t.Fatalf("empty graph cannot have cycles")
	}

	engine := NewEngine(DefaultConfig())
	summary, paths, rels, err := engine.Correlate(context.Background(), nil)
	if err != nil {
		t.Fatalf("unexpected error on nil findings: %v", err)
	}
	if summary.TotalFindings != 0 || len(paths) != 0 || len(rels) != 0 {
		t.Fatalf("expected empty result, got %d findings, %d paths, %d rels",
			summary.TotalFindings, len(paths), len(rels))
	}
}

func TestGraph_OneNode(t *testing.T) {
	f1 := makeMultihopFinding("N1", "Public Entry Route", "api-route", report.SeverityInfo, true, false, true, false, false, "https://api.example.com/api/v1")
	graph := NewAttackGraph([]NormalizedFinding{f1}, nil)
	if len(graph.Nodes) != 1 || len(graph.Edges) != 0 {
		t.Fatalf("expected 1 node and 0 edges, got %d nodes, %d edges", len(graph.Nodes), len(graph.Edges))
	}
	if !graph.Validation.IsValid {
		t.Fatalf("single node graph must be valid, got errors: %v", graph.Validation.Errors)
	}
	if len(graph.EligibleRoots()) != 0 {
		t.Errorf("isolated node with 0 out-degree must not be an eligible root")
	}

	engine := NewEngine(DefaultConfig())
	_, paths, _, err := engine.Correlate(context.Background(), []report.Finding{
		{ID: "N1", Title: "Public Entry Route", Endpoint: "https://api.example.com/api/v1"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(paths) != 0 {
		t.Fatalf("single finding must produce 0 attack paths, got %d", len(paths))
	}
}

func TestGraph_SingleValidEdge(t *testing.T) {
	f1 := makeMultihopFinding("N1", "Public Entrypoint", "api-route", report.SeverityInfo, true, false, true, false, false, "https://api.example.com/api/v1")
	f2 := makeMultihopFinding("N2", "Auth Boundary Flaw", "auth-bypass", report.SeverityHigh, true, false, false, false, false, "https://api.example.com/api/v1/auth")

	rel := Relationship{
		ID:               "REL-01",
		SourceFindingID:  "N1",
		TargetFindingID:  "N2",
		Type:             RelReaches,
		ValidationStatus: ValidationConfirmed,
		Confidence:       report.ConfidenceHigh,
		RuleCode:         RuleCOR01,
	}

	graph := NewAttackGraph([]NormalizedFinding{f1, f2}, []Relationship{rel})
	if len(graph.Nodes) != 2 || len(graph.Edges) != 1 {
		t.Fatalf("expected 2 nodes and 1 edge, got %d nodes, %d edges", len(graph.Nodes), len(graph.Edges))
	}
	if !graph.Validation.IsValid {
		t.Fatalf("expected valid DAG, got errors: %v", graph.Validation.Errors)
	}

	roots := graph.EligibleRoots()
	if len(roots) != 1 || roots[0].ID != "N1" {
		t.Fatalf("expected N1 as only eligible root, got %v", roots)
	}
	sinks := graph.Sinks()
	if len(sinks) != 1 || sinks[0].ID != "N2" {
		t.Fatalf("expected N2 as only sink, got %v", sinks)
	}

	findingMap := map[string]NormalizedFinding{"N1": f1, "N2": f2}
	engine := NewEngine(DefaultConfig())
	paths, _, _ := engine.buildAttackPaths(context.Background(), []NormalizedFinding{f1, f2}, []Relationship{rel}, findingMap)
	if len(paths) != 1 {
		t.Fatalf("expected 1 pairwise path, got %d", len(paths))
	}
	if len(paths[0].Nodes) != 2 {
		t.Fatalf("expected path length 2, got %d", len(paths[0].Nodes))
	}
}

func TestGraph_ThreeNodePath(t *testing.T) {
	// A -> B -> C (3 nodes, 2 hops)
	f1 := makeMultihopFinding("N1", "Customer Route", "api-route", report.SeverityInfo, true, false, true, false, false, "https://api.example.com/customers")
	f2 := makeMultihopFinding("N2", "BOLA on Customer Object", "bola", report.SeverityHigh, true, false, false, false, false, "https://api.example.com/customers/{id}")
	f3 := makeMultihopFinding("N3", "Customer Financial Data Exposure", "sensitive-data-exposure", report.SeverityHigh, true, false, false, true, false, "https://api.example.com/customers/{id}")

	rel1 := Relationship{
		ID:               "REL-01",
		SourceFindingID:  "N1",
		TargetFindingID:  "N2",
		Type:             RelReaches,
		ValidationStatus: ValidationConfirmed,
		Confidence:       report.ConfidenceHigh,
		RuleCode:         RuleCOR01,
	}
	rel2 := Relationship{
		ID:               "REL-02",
		SourceFindingID:  "N2",
		TargetFindingID:  "N3",
		Type:             RelExposes,
		ValidationStatus: ValidationConfirmed,
		Confidence:       report.ConfidenceHigh,
		RuleCode:         RuleCOR03,
	}

	graph := NewAttackGraph([]NormalizedFinding{f1, f2, f3}, []Relationship{rel1, rel2})
	if !graph.Validation.IsValid {
		t.Fatalf("expected valid DAG, got errors: %v", graph.Validation.Errors)
	}
	if len(graph.Validation.TopologicalOrder) != 3 {
		t.Fatalf("expected 3 nodes in topological order, got %d", len(graph.Validation.TopologicalOrder))
	}

	findingMap := map[string]NormalizedFinding{"N1": f1, "N2": f2, "N3": f3}
	engine := NewEngine(DefaultConfig())
	rawPaths, _, _ := engine.buildAttackPaths(context.Background(), []NormalizedFinding{f1, f2, f3}, []Relationship{rel1, rel2}, findingMap)
	paths := engine.processPaths(rawPaths)

	// Primary sorted path must be the full multi-hop path N1 -> N2 -> N3
	if len(paths) == 0 {
		t.Fatalf("expected paths discovered")
	}
	primary := paths[0]
	if len(primary.Nodes) != 3 {
		t.Fatalf("expected primary path to have 3 nodes, got %d (%v)", len(primary.Nodes), primary.NodeIDs)
	}
	if primary.NodeIDs[0] != "N1" || primary.NodeIDs[1] != "N2" || primary.NodeIDs[2] != "N3" {
		t.Fatalf("unexpected node sequence: %v", primary.NodeIDs)
	}
	if !strings.HasPrefix(primary.ID, "PATH-MULTIHOP-") {
		t.Errorf("expected PATH-MULTIHOP- prefix for 3-node path, got %s", primary.ID)
	}
	if primary.Status != PathVerified {
		t.Errorf("expected PathVerified status, got %s", primary.Status)
	}
}

func TestGraph_FourOrMoreNodePath(t *testing.T) {
	// A -> B -> C -> D (4 nodes, 3 hops)
	f1 := makeMultihopFinding("N1", "Public Entrypoint", "api-route", report.SeverityInfo, true, false, true, false, false, "https://api.example.com/customers")
	f2 := makeMultihopFinding("N2", "Auth Boundary Bypass", "jwt-auth-flaw", report.SeverityHigh, true, false, false, false, false, "https://api.example.com/customers/{id}")
	f3 := makeMultihopFinding("N3", "BOLA Tenant Profile", "bola", report.SeverityHigh, true, false, false, false, false, "https://api.example.com/customers/{id}")
	f4 := makeMultihopFinding("N4", "Database Secret Disclosed", "sensitive-data-exposure", report.SeverityCritical, true, false, false, true, false, "https://api.example.com/customers/{id}")

	rel1 := Relationship{ID: "R1", SourceFindingID: "N1", TargetFindingID: "N2", Type: RelReaches, ValidationStatus: ValidationConfirmed, RuleCode: RuleCOR01}
	rel2 := Relationship{ID: "R2", SourceFindingID: "N2", TargetFindingID: "N3", Type: RelEnables, ValidationStatus: ValidationConfirmed, RuleCode: RuleCOR02}
	rel3 := Relationship{ID: "R3", SourceFindingID: "N3", TargetFindingID: "N4", Type: RelExposes, ValidationStatus: ValidationConfirmed, RuleCode: RuleCOR03}

	findingMap := map[string]NormalizedFinding{"N1": f1, "N2": f2, "N3": f3, "N4": f4}
	engine := NewEngine(DefaultConfig())
	rawPaths, _, _ := engine.buildAttackPaths(context.Background(), []NormalizedFinding{f1, f2, f3, f4}, []Relationship{rel1, rel2, rel3}, findingMap)
	paths := engine.processPaths(rawPaths)

	if len(paths) == 0 {
		t.Fatalf("expected paths discovered")
	}
	// The 4-node chain must be top-ranked due to risk + node count
	top := paths[0]
	if len(top.Nodes) != 4 {
		t.Fatalf("expected top path to have 4 nodes, got %d (%v)", len(top.Nodes), top.NodeIDs)
	}
	if top.NodeIDs[0] != "N1" || top.NodeIDs[3] != "N4" {
		t.Fatalf("expected full chain from N1 to N4, got %v", top.NodeIDs)
	}
	if top.Status != PathVerified {
		t.Errorf("expected PathVerified status, got %s", top.Status)
	}
}

func TestGraph_MultipleRoots(t *testing.T) {
	// Root 1 (R1) -> T1 -> S
	// Root 2 (R2) -> T2 -> S
	fR1 := makeMultihopFinding("R1", "Route A", "api-route", report.SeverityInfo, true, false, true, false, false, "https://api.example.com/a")
	fR2 := makeMultihopFinding("R2", "Route B", "api-route", report.SeverityInfo, true, false, true, false, false, "https://api.example.com/b")
	fT1 := makeMultihopFinding("T1", "BOLA A", "bola", report.SeverityHigh, true, false, false, false, false, "https://api.example.com/a/detail")
	fT2 := makeMultihopFinding("T2", "BOLA B", "bola", report.SeverityHigh, true, false, false, false, false, "https://api.example.com/b/detail")
	fS := makeMultihopFinding("S", "Data Exfiltration", "sensitive-data-exposure", report.SeverityHigh, true, false, false, true, false, "https://api.example.com/data")

	rels := []Relationship{
		{ID: "R1-T1", SourceFindingID: "R1", TargetFindingID: "T1", Type: RelReaches, ValidationStatus: ValidationConfirmed, RuleCode: RuleCOR01},
		{ID: "T1-S", SourceFindingID: "T1", TargetFindingID: "S", Type: RelExposes, ValidationStatus: ValidationConfirmed, RuleCode: RuleCOR03},
		{ID: "R2-T2", SourceFindingID: "R2", TargetFindingID: "T2", Type: RelReaches, ValidationStatus: ValidationConfirmed, RuleCode: RuleCOR01},
		{ID: "T2-S", SourceFindingID: "T2", TargetFindingID: "S", Type: RelExposes, ValidationStatus: ValidationConfirmed, RuleCode: RuleCOR03},
	}

	graph := NewAttackGraph([]NormalizedFinding{fR1, fR2, fT1, fT2, fS}, rels)
	roots := graph.EligibleRoots()
	if len(roots) != 2 {
		t.Fatalf("expected 2 eligible roots, got %d", len(roots))
	}

	findingMap := map[string]NormalizedFinding{"R1": fR1, "R2": fR2, "T1": fT1, "T2": fT2, "S": fS}
	engine := NewEngine(DefaultConfig())
	rawPaths, _, _ := engine.buildAttackPaths(context.Background(), []NormalizedFinding{fR1, fR2, fT1, fT2, fS}, rels, findingMap)
	paths := engine.processPaths(rawPaths)

	foundR1 := false
	foundR2 := false
	for _, p := range paths {
		if len(p.Nodes) == 3 {
			if p.NodeIDs[0] == "R1" && p.NodeIDs[2] == "S" {
				foundR1 = true
			}
			if p.NodeIDs[0] == "R2" && p.NodeIDs[2] == "S" {
				foundR2 = true
			}
		}
	}
	if !foundR1 || !foundR2 {
		t.Errorf("expected both independent multi-hop paths to be discovered: R1=%v, R2=%v", foundR1, foundR2)
	}
}

func TestGraph_MultipleSinks(t *testing.T) {
	// R -> N -> Sink 1 (S1)
	// R -> N -> Sink 2 (S2)
	fR := makeMultihopFinding("R", "Root Route", "api-route", report.SeverityInfo, true, false, true, false, false, "https://api.example.com/root")
	fN := makeMultihopFinding("N", "Auth Flaw", "auth-bypass", report.SeverityHigh, true, false, false, false, false, "https://api.example.com/root/action")
	fS1 := makeMultihopFinding("S1", "User Record Disclosed", "sensitive-data-exposure", report.SeverityHigh, true, false, false, true, false, "https://api.example.com/users")
	fS2 := makeMultihopFinding("S2", "Cloud Admin Escalation", "privilege-escalation", report.SeverityCritical, true, false, false, false, true, "https://api.example.com/admin")

	rels := []Relationship{
		{ID: "R-N", SourceFindingID: "R", TargetFindingID: "N", Type: RelEnables, ValidationStatus: ValidationConfirmed, RuleCode: RuleCOR02},
		{ID: "N-S1", SourceFindingID: "N", TargetFindingID: "S1", Type: RelExposes, ValidationStatus: ValidationConfirmed, RuleCode: RuleCOR03},
		{ID: "N-S2", SourceFindingID: "N", TargetFindingID: "S2", Type: RelEnables, ValidationStatus: ValidationConfirmed, RuleCode: RuleCOR05},
	}

	findingMap := map[string]NormalizedFinding{"R": fR, "N": fN, "S1": fS1, "S2": fS2}
	engine := NewEngine(DefaultConfig())
	rawPaths, _, _ := engine.buildAttackPaths(context.Background(), []NormalizedFinding{fR, fN, fS1, fS2}, rels, findingMap)
	paths := engine.processPaths(rawPaths)

	foundS1 := false
	foundS2 := false
	for _, p := range paths {
		if len(p.Nodes) == 3 && p.NodeIDs[0] == "R" {
			if p.NodeIDs[2] == "S1" {
				foundS1 = true
			}
			if p.NodeIDs[2] == "S2" {
				foundS2 = true
			}
		}
	}
	if !foundS1 || !foundS2 {
		t.Errorf("expected both multi-hop branching sinks discovered: S1=%v, S2=%v", foundS1, foundS2)
	}
}

func TestGraph_BranchingAndConvergingPaths(t *testing.T) {
	// Diamond graph:
	//       Root
	//      /    \
	//     B1     B2
	//      \    /
	//       Sink
	fRoot := makeMultihopFinding("R", "API Gateway", "api-route", report.SeverityInfo, true, false, true, false, false, "https://api.example.com/")
	fB1 := makeMultihopFinding("B1", "Route A Auth Bypass", "jwt-auth-flaw", report.SeverityHigh, true, false, false, false, false, "https://api.example.com/a")
	fB2 := makeMultihopFinding("B2", "Route B Session Fixation", "session-flaw", report.SeverityHigh, true, false, false, false, false, "https://api.example.com/b")
	fSink := makeMultihopFinding("Sink", "Tenant Database Dump", "sensitive-data-exposure", report.SeverityCritical, true, false, false, true, false, "https://api.example.com/db")

	rels := []Relationship{
		{ID: "R-B1", SourceFindingID: "R", TargetFindingID: "B1", Type: RelReaches, ValidationStatus: ValidationConfirmed, RuleCode: RuleCOR01},
		{ID: "R-B2", SourceFindingID: "R", TargetFindingID: "B2", Type: RelReaches, ValidationStatus: ValidationConfirmed, RuleCode: RuleCOR01},
		{ID: "B1-Sink", SourceFindingID: "B1", TargetFindingID: "Sink", Type: RelExposes, ValidationStatus: ValidationConfirmed, RuleCode: RuleCOR03},
		{ID: "B2-Sink", SourceFindingID: "B2", TargetFindingID: "Sink", Type: RelExposes, ValidationStatus: ValidationConfirmed, RuleCode: RuleCOR03},
	}

	findingMap := map[string]NormalizedFinding{"R": fRoot, "B1": fB1, "B2": fB2, "Sink": fSink}
	engine := NewEngine(DefaultConfig())
	rawPaths, _, _ := engine.buildAttackPaths(context.Background(), []NormalizedFinding{fRoot, fB1, fB2, fSink}, rels, findingMap)
	paths := engine.processPaths(rawPaths)

	foundBranch1 := false
	foundBranch2 := false
	for _, p := range paths {
		if len(p.Nodes) == 3 {
			if p.NodeIDs[0] == "R" && p.NodeIDs[1] == "B1" && p.NodeIDs[2] == "Sink" {
				foundBranch1 = true
			}
			if p.NodeIDs[0] == "R" && p.NodeIDs[1] == "B2" && p.NodeIDs[2] == "Sink" {
				foundBranch2 = true
			}
		}
	}
	if !foundBranch1 || !foundBranch2 {
		t.Errorf("expected both distinct diamond branches preserved: Branch1=%v, Branch2=%v", foundBranch1, foundBranch2)
	}
}

func TestGraph_DisconnectedComponents(t *testing.T) {
	// Component 1: A1 -> B1 -> C1
	// Component 2: A2 -> B2 -> C2
	fA1 := makeMultihopFinding("A1", "Gateway 1", "api-route", report.SeverityInfo, true, false, true, false, false, "https://svc1.example.com/")
	fB1 := makeMultihopFinding("B1", "BOLA 1", "bola", report.SeverityHigh, true, false, false, false, false, "https://svc1.example.com/items")
	fC1 := makeMultihopFinding("C1", "Data 1", "sensitive-data-exposure", report.SeverityHigh, true, false, false, true, false, "https://svc1.example.com/items")

	fA2 := makeMultihopFinding("A2", "Gateway 2", "api-route", report.SeverityInfo, true, false, true, false, false, "https://svc2.example.com/")
	fB2 := makeMultihopFinding("B2", "BOLA 2", "bola", report.SeverityHigh, true, false, false, false, false, "https://svc2.example.com/records")
	fC2 := makeMultihopFinding("C2", "Data 2", "sensitive-data-exposure", report.SeverityHigh, true, false, false, true, false, "https://svc2.example.com/records")

	rels := []Relationship{
		{ID: "1-1", SourceFindingID: "A1", TargetFindingID: "B1", Type: RelReaches, ValidationStatus: ValidationConfirmed, RuleCode: RuleCOR01},
		{ID: "1-2", SourceFindingID: "B1", TargetFindingID: "C1", Type: RelExposes, ValidationStatus: ValidationConfirmed, RuleCode: RuleCOR03},
		{ID: "2-1", SourceFindingID: "A2", TargetFindingID: "B2", Type: RelReaches, ValidationStatus: ValidationConfirmed, RuleCode: RuleCOR01},
		{ID: "2-2", SourceFindingID: "B2", TargetFindingID: "C2", Type: RelExposes, ValidationStatus: ValidationConfirmed, RuleCode: RuleCOR03},
	}

	allFindings := []NormalizedFinding{fA1, fB1, fC1, fA2, fB2, fC2}
	findingMap := make(map[string]NormalizedFinding)
	for _, f := range allFindings {
		findingMap[f.ID] = f
	}

	engine := NewEngine(DefaultConfig())
	rawPaths, _, _ := engine.buildAttackPaths(context.Background(), allFindings, rels, findingMap)
	paths := engine.processPaths(rawPaths)

	foundComp1 := false
	foundComp2 := false
	for _, p := range paths {
		if len(p.Nodes) == 3 {
			if p.NodeIDs[0] == "A1" && p.NodeIDs[2] == "C1" {
				foundComp1 = true
			}
			if p.NodeIDs[0] == "A2" && p.NodeIDs[2] == "C2" {
				foundComp2 = true
			}
		}
	}
	if !foundComp1 || !foundComp2 {
		t.Errorf("expected paths from both disconnected components: Comp1=%v, Comp2=%v", foundComp1, foundComp2)
	}
}

// -----------------------------------------------------------------------------
// 2. Invalid Structures & Cycle Handling
// -----------------------------------------------------------------------------

func TestGraph_SelfLoop(t *testing.T) {
	f1 := makeMultihopFinding("N1", "Self Loop Target", "api-route", report.SeverityHigh, true, false, true, false, false, "https://api.example.com/loop")
	rel := Relationship{
		ID:               "LOOP-1",
		SourceFindingID:  "N1",
		TargetFindingID:  "N1",
		Type:             RelEnables,
		ValidationStatus: ValidationConfirmed,
		RuleCode:         RuleCOR02,
	}

	graph := NewAttackGraph([]NormalizedFinding{f1}, []Relationship{rel})
	if len(graph.Edges) != 0 {
		t.Fatalf("self-loop edge must be rejected from graph, got %d edges", len(graph.Edges))
	}
	if len(graph.Validation.Errors) == 0 {
		t.Fatalf("expected validation error recorded for self-loop")
	}
}

func TestGraph_TwoNodeCycle(t *testing.T) {
	// A -> B -> A
	fA := makeMultihopFinding("A", "Node A", "auth", report.SeverityHigh, true, false, true, false, false, "https://api.example.com/a")
	fB := makeMultihopFinding("B", "Node B", "authz", report.SeverityHigh, true, false, false, false, false, "https://api.example.com/b")

	relAB := Relationship{ID: "AB", SourceFindingID: "A", TargetFindingID: "B", Type: RelEnables, ValidationStatus: ValidationConfirmed, RuleCode: RuleCOR02}
	relBA := Relationship{ID: "BA", SourceFindingID: "B", TargetFindingID: "A", Type: RelEnables, ValidationStatus: ValidationConfirmed, RuleCode: RuleCOR02}

	graph := NewAttackGraph([]NormalizedFinding{fA, fB}, []Relationship{relAB, relBA})
	if !graph.Validation.HasCycle {
		t.Fatalf("2-node cycle must be detected")
	}
	if graph.Validation.IsValid {
		t.Fatalf("cyclic graph must have IsValid == false")
	}
	if len(graph.Validation.CycleNodes) != 2 {
		t.Fatalf("expected 2 cycle nodes, got %v", graph.Validation.CycleNodes)
	}

	// Traversal must NOT infinite loop, and must NOT produce paths with repeated nodes
	findingMap := map[string]NormalizedFinding{"A": fA, "B": fB}
	engine := NewEngine(DefaultConfig())
	rawPaths, _, _ := engine.buildAttackPaths(context.Background(), []NormalizedFinding{fA, fB}, []Relationship{relAB, relBA}, findingMap)
	paths := engine.processPaths(rawPaths)

	for _, p := range paths {
		seen := make(map[string]bool)
		for _, nid := range p.NodeIDs {
			if seen[nid] {
				t.Fatalf("cycle allowed in finalized attack path: %v", p.NodeIDs)
			}
			seen[nid] = true
		}
	}
}

func TestGraph_LongerCycle(t *testing.T) {
	// A -> B -> C -> A
	fA := makeMultihopFinding("A", "Node A", "auth", report.SeverityHigh, true, false, true, false, false, "https://api.example.com/a")
	fB := makeMultihopFinding("B", "Node B", "authz", report.SeverityHigh, true, false, false, false, false, "https://api.example.com/b")
	fC := makeMultihopFinding("C", "Node C", "cloud", report.SeverityHigh, true, false, false, false, false, "https://api.example.com/c")

	rels := []Relationship{
		{ID: "AB", SourceFindingID: "A", TargetFindingID: "B", Type: RelEnables, ValidationStatus: ValidationConfirmed, RuleCode: RuleCOR02},
		{ID: "BC", SourceFindingID: "B", TargetFindingID: "C", Type: RelEnables, ValidationStatus: ValidationConfirmed, RuleCode: RuleCOR05},
		{ID: "CA", SourceFindingID: "C", TargetFindingID: "A", Type: RelEnables, ValidationStatus: ValidationConfirmed, RuleCode: RuleCOR07},
	}

	graph := NewAttackGraph([]NormalizedFinding{fA, fB, fC}, rels)
	if !graph.Validation.HasCycle {
		t.Fatalf("3-node cycle must be detected by Kahn's algorithm")
	}
	if len(graph.Validation.CycleEdges) == 0 {
		t.Fatalf("expected cycle edges to be isolated")
	}

	findingMap := map[string]NormalizedFinding{"A": fA, "B": fB, "C": fC}
	engine := NewEngine(DefaultConfig())
	rawPaths, _, _ := engine.buildAttackPaths(context.Background(), []NormalizedFinding{fA, fB, fC}, rels, findingMap)
	paths := engine.processPaths(rawPaths)

	for _, p := range paths {
		seen := make(map[string]bool)
		for _, nid := range p.NodeIDs {
			if seen[nid] {
				t.Fatalf("cyclic repetition in path: %v", p.NodeIDs)
			}
			seen[nid] = true
		}
	}
}

func TestGraph_InvalidNodeReference(t *testing.T) {
	f1 := makeMultihopFinding("N1", "Valid Node", "api-route", report.SeverityInfo, true, false, true, false, false, "https://api.example.com/1")
	rel := Relationship{
		ID:               "INV-1",
		SourceFindingID:  "N1",
		TargetFindingID:  "NONEXISTENT",
		Type:             RelReaches,
		ValidationStatus: ValidationConfirmed,
		RuleCode:         RuleCOR01,
	}

	graph := NewAttackGraph([]NormalizedFinding{f1}, []Relationship{rel})
	if len(graph.Edges) != 0 {
		t.Fatalf("edge with non-existent target must be rejected, got %d edges", len(graph.Edges))
	}
	if len(graph.Validation.Errors) == 0 {
		t.Fatalf("expected validation error recorded for missing node reference")
	}
}

func TestGraph_DuplicateEdgeSuppression(t *testing.T) {
	f1 := makeMultihopFinding("N1", "Node 1", "api-route", report.SeverityInfo, true, false, true, false, false, "https://api.example.com/1")
	f2 := makeMultihopFinding("N2", "Node 2", "bola", report.SeverityHigh, true, false, false, false, false, "https://api.example.com/2")

	rel1 := Relationship{ID: "E1", SourceFindingID: "N1", TargetFindingID: "N2", Type: RelReaches, ValidationStatus: ValidationConfirmed, RuleCode: RuleCOR01}
	rel2 := Relationship{ID: "E2", SourceFindingID: "N1", TargetFindingID: "N2", Type: RelReaches, ValidationStatus: ValidationConfirmed, RuleCode: RuleCOR01}

	graph := NewAttackGraph([]NormalizedFinding{f1, f2}, []Relationship{rel1, rel2})
	if len(graph.Edges) != 1 {
		t.Fatalf("duplicate edge must be suppressed: expected 1 edge, got %d", len(graph.Edges))
	}
	if len(graph.Validation.Warnings) == 0 {
		t.Fatalf("expected warning for duplicate edge suppression")
	}
}

func TestGraph_DuplicateFindingSuppression(t *testing.T) {
	f1a := makeMultihopFinding("DUP1", "Finding A", "api-route", report.SeverityInfo, true, false, true, false, false, "https://api.example.com/1")
	f1b := makeMultihopFinding("DUP1", "Finding B", "api-route", report.SeverityInfo, true, false, true, false, false, "https://api.example.com/1")

	graph := NewAttackGraph([]NormalizedFinding{f1a, f1b}, nil)
	if len(graph.Nodes) != 1 {
		t.Fatalf("duplicate finding ID must not duplicate graph node: expected 1, got %d", len(graph.Nodes))
	}
	if len(graph.Validation.Warnings) == 0 {
		t.Fatalf("expected warning for duplicate finding ID")
	}
}

// -----------------------------------------------------------------------------
// 3. Traversal Behavior & Bounded Work
// -----------------------------------------------------------------------------

func TestTraversal_MinPathLengthConfig(t *testing.T) {
	// A -> B -> C
	f1 := makeMultihopFinding("N1", "Node 1", "api-route", report.SeverityInfo, true, false, true, false, false, "https://api.example.com/1")
	f2 := makeMultihopFinding("N2", "Node 2", "bola", report.SeverityHigh, true, false, false, false, false, "https://api.example.com/2")
	f3 := makeMultihopFinding("N3", "Node 3", "sensitive", report.SeverityHigh, true, false, false, true, false, "https://api.example.com/3")

	rels := []Relationship{
		{ID: "1-2", SourceFindingID: "N1", TargetFindingID: "N2", Type: RelReaches, ValidationStatus: ValidationConfirmed, RuleCode: RuleCOR01},
		{ID: "2-3", SourceFindingID: "N2", TargetFindingID: "N3", Type: RelExposes, ValidationStatus: ValidationConfirmed, RuleCode: RuleCOR03},
	}
	findingMap := map[string]NormalizedFinding{"N1": f1, "N2": f2, "N3": f3}

	// Config with MinPathLength = 3: must ONLY emit paths with >= 3 nodes
	cfg := DefaultConfig()
	cfg.MinPathLength = 3
	engine := NewEngine(cfg)

	rawPaths, _, _ := engine.buildAttackPaths(context.Background(), []NormalizedFinding{f1, f2, f3}, rels, findingMap)
	paths := engine.processPaths(rawPaths)

	for _, p := range paths {
		if len(p.Nodes) < 3 {
			t.Fatalf("configured MinPathLength=3 violated: path has %d nodes (%v)", len(p.Nodes), p.NodeIDs)
		}
	}
}

func TestTraversal_DepthLimit(t *testing.T) {
	// A -> B -> C -> D -> E (5 nodes, 4 hops)
	fA := makeMultihopFinding("A", "Node A", "route", report.SeverityInfo, true, false, true, false, false, "/a")
	fB := makeMultihopFinding("B", "Node B", "auth", report.SeverityHigh, true, false, false, false, false, "/b")
	fC := makeMultihopFinding("C", "Node C", "authz", report.SeverityHigh, true, false, false, false, false, "/c")
	fD := makeMultihopFinding("D", "Node D", "data", report.SeverityHigh, true, false, false, true, false, "/d")
	fE := makeMultihopFinding("E", "Node E", "cloud", report.SeverityCritical, true, false, false, false, true, "/e")

	rels := []Relationship{
		{ID: "AB", SourceFindingID: "A", TargetFindingID: "B", Type: RelReaches, ValidationStatus: ValidationConfirmed, RuleCode: RuleCOR01},
		{ID: "BC", SourceFindingID: "B", TargetFindingID: "C", Type: RelEnables, ValidationStatus: ValidationConfirmed, RuleCode: RuleCOR02},
		{ID: "CD", SourceFindingID: "C", TargetFindingID: "D", Type: RelExposes, ValidationStatus: ValidationConfirmed, RuleCode: RuleCOR03},
		{ID: "DE", SourceFindingID: "D", TargetFindingID: "E", Type: RelEnables, ValidationStatus: ValidationConfirmed, RuleCode: RuleCOR08},
	}

	findingMap := map[string]NormalizedFinding{"A": fA, "B": fB, "C": fC, "D": fD, "E": fE}

	// Limit depth to 2 transitions (at most 3 nodes)
	cfg := DefaultConfig()
	cfg.MaxPathDepth = 2
	engine := NewEngine(cfg)

	rawPaths, _, _ := engine.buildAttackPaths(context.Background(), []NormalizedFinding{fA, fB, fC, fD, fE}, rels, findingMap)
	paths := engine.processPaths(rawPaths)

	for _, p := range paths {
		if len(p.Edges) > 2 {
			t.Fatalf("path exceeded MaxPathDepth=2: got %d edges (%v)", len(p.Edges), p.NodeIDs)
		}
	}
}

func TestTraversal_MaxCandidatePathsLimit(t *testing.T) {
	// Dense branching graph with 1 root and 20 parallel branches of depth 2
	fRoot := makeMultihopFinding("ROOT", "Gateway", "api-route", report.SeverityInfo, true, false, true, false, false, "/")
	findings := []NormalizedFinding{fRoot}
	var rels []Relationship
	findingMap := map[string]NormalizedFinding{"ROOT": fRoot}

	for i := 1; i <= 20; i++ {
		bID := fmt.Sprintf("B%d", i)
		sID := fmt.Sprintf("S%d", i)
		fB := makeMultihopFinding(bID, "Branch", "auth", report.SeverityHigh, true, false, false, false, false, fmt.Sprintf("/b%d", i))
		fS := makeMultihopFinding(sID, "Sink", "data", report.SeverityHigh, true, false, false, true, false, fmt.Sprintf("/s%d", i))
		findings = append(findings, fB, fS)
		findingMap[bID] = fB
		findingMap[sID] = fS

		rels = append(rels,
			Relationship{ID: fmt.Sprintf("R-%s", bID), SourceFindingID: "ROOT", TargetFindingID: bID, Type: RelReaches, ValidationStatus: ValidationConfirmed, RuleCode: RuleCOR01},
			Relationship{ID: fmt.Sprintf("%s-%s", bID, sID), SourceFindingID: bID, TargetFindingID: sID, Type: RelExposes, ValidationStatus: ValidationConfirmed, RuleCode: RuleCOR03},
		)
	}

	// Limit to 5 candidate paths
	cfg := DefaultConfig()
	cfg.MaxCandidatePaths = 5
	engine := NewEngine(cfg)

	rawPaths, limitsReached, truncReason := engine.buildAttackPaths(context.Background(), findings, rels, findingMap)
	if !limitsReached {
		t.Fatalf("expected limitsReached to be true")
	}
	if !strings.Contains(truncReason, "candidate path threshold") {
		t.Fatalf("expected candidate path threshold truncation reason, got: %s", truncReason)
	}
	if len(rawPaths) < 5 {
		t.Fatalf("expected at least 5 raw paths generated before truncation, got %d", len(rawPaths))
	}
}

func TestTraversal_ContextCancellation(t *testing.T) {
	f1 := makeMultihopFinding("N1", "Node 1", "api-route", report.SeverityInfo, true, false, true, false, false, "/1")
	f2 := makeMultihopFinding("N2", "Node 2", "auth", report.SeverityHigh, true, false, false, false, false, "/2")
	rel := Relationship{ID: "E1", SourceFindingID: "N1", TargetFindingID: "N2", Type: RelReaches, ValidationStatus: ValidationConfirmed, RuleCode: RuleCOR01}

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel context upfront

	findingMap := map[string]NormalizedFinding{"N1": f1, "N2": f2}
	engine := NewEngine(DefaultConfig())
	_, limitsReached, truncReason := engine.buildAttackPaths(ctx, []NormalizedFinding{f1, f2}, []Relationship{rel}, findingMap)

	if !limitsReached {
		t.Errorf("expected limitsReached=true on cancelled context")
	}
	if !strings.Contains(truncReason, "cancelled") {
		t.Errorf("expected cancellation message in truncReason, got %s", truncReason)
	}
}

func TestTraversal_DeterministicOutput(t *testing.T) {
	// Traversal results must be 100% deterministic regardless of input slice order
	fA := makeMultihopFinding("A", "Route A", "api-route", report.SeverityInfo, true, false, true, false, false, "/a")
	fB := makeMultihopFinding("B", "Flaw B", "auth", report.SeverityHigh, true, false, false, false, false, "/b")
	fC := makeMultihopFinding("C", "Data C", "sensitive", report.SeverityHigh, true, false, false, true, false, "/c")

	rels := []Relationship{
		{ID: "AB", SourceFindingID: "A", TargetFindingID: "B", Type: RelReaches, ValidationStatus: ValidationConfirmed, RuleCode: RuleCOR01},
		{ID: "BC", SourceFindingID: "B", TargetFindingID: "C", Type: RelExposes, ValidationStatus: ValidationConfirmed, RuleCode: RuleCOR03},
	}
	findingMap := map[string]NormalizedFinding{"A": fA, "B": fB, "C": fC}

	engine := NewEngine(DefaultConfig())

	// Run 1: Normal order
	raw1, _, _ := engine.buildAttackPaths(context.Background(), []NormalizedFinding{fA, fB, fC}, rels, findingMap)
	paths1 := engine.processPaths(raw1)

	// Run 2: Reversed order
	raw2, _, _ := engine.buildAttackPaths(context.Background(), []NormalizedFinding{fC, fB, fA}, rels, findingMap)
	paths2 := engine.processPaths(raw2)

	if len(paths1) != len(paths2) {
		t.Fatalf("length mismatch between runs: %d vs %d", len(paths1), len(paths2))
	}
	for i := range paths1 {
		if paths1[i].ID != paths2[i].ID {
			t.Errorf("run %d ID mismatch: %s vs %s", i, paths1[i].ID, paths2[i].ID)
		}
		if strings.Join(paths1[i].NodeIDs, "->") != strings.Join(paths2[i].NodeIDs, "->") {
			t.Errorf("run %d node sequence mismatch: %v vs %v", i, paths1[i].NodeIDs, paths2[i].NodeIDs)
		}
	}
}

// -----------------------------------------------------------------------------
// 4. Security Semantics
// -----------------------------------------------------------------------------

func TestSecuritySemantics_CandidateDoesNotVerifyChain(t *testing.T) {
	// A (Verified) -> B (Candidate) -> C (Verified)
	fA := makeMultihopFinding("A", "Route A", "api-route", report.SeverityInfo, true, false, true, false, false, "/a")
	fB := makeMultihopFinding("B", "Candidate BOLA", "bola", report.SeverityHigh, false, true, false, false, false, "/b") // IsCandidate=true
	fC := makeMultihopFinding("C", "Sensitive Data", "sensitive-data-exposure", report.SeverityHigh, true, false, false, true, false, "/c")

	rels := []Relationship{
		{ID: "AB", SourceFindingID: "A", TargetFindingID: "B", Type: RelReaches, ValidationStatus: ValidationConfirmed, RuleCode: RuleCOR01},
		{ID: "BC", SourceFindingID: "B", TargetFindingID: "C", Type: RelExposes, ValidationStatus: ValidationConfirmed, RuleCode: RuleCOR03},
	}
	findingMap := map[string]NormalizedFinding{"A": fA, "B": fB, "C": fC}

	engine := NewEngine(DefaultConfig())
	rawPaths, _, _ := engine.buildAttackPaths(context.Background(), []NormalizedFinding{fA, fB, fC}, rels, findingMap)
	paths := engine.processPaths(rawPaths)

	for _, p := range paths {
		if p.Status == PathVerified {
			t.Fatalf("SECURITY VIOLATION: Path with unconfirmed candidate node must NEVER be PathVerified (%s)", p.ID)
		}
		if p.Status != PathCandidate {
			t.Errorf("expected PathCandidate status for path with candidate node, got %s", p.Status)
		}
	}
}

func TestSecuritySemantics_OneVerifiedDoesNotVerifyChain(t *testing.T) {
	// A (Verified) -> B (Observed) -> C (Observed)
	fA := makeMultihopFinding("A", "Route A", "api-route", report.SeverityInfo, true, false, true, false, false, "/a")
	fB := makeMultihopFinding("B", "Flaw B", "auth", report.SeverityHigh, false, false, false, false, false, "/b") // NOT verified
	fC := makeMultihopFinding("C", "Flaw C", "data", report.SeverityHigh, false, false, false, true, false, "/c")  // NOT verified

	rels := []Relationship{
		{ID: "AB", SourceFindingID: "A", TargetFindingID: "B", Type: RelReaches, ValidationStatus: ValidationConfirmed, RuleCode: RuleCOR01},
		{ID: "BC", SourceFindingID: "B", TargetFindingID: "C", Type: RelExposes, ValidationStatus: ValidationConfirmed, RuleCode: RuleCOR03},
	}
	findingMap := map[string]NormalizedFinding{"A": fA, "B": fB, "C": fC}

	engine := NewEngine(DefaultConfig())
	rawPaths, _, _ := engine.buildAttackPaths(context.Background(), []NormalizedFinding{fA, fB, fC}, rels, findingMap)
	paths := engine.processPaths(rawPaths)

	for _, p := range paths {
		if p.Status == PathVerified {
			t.Fatalf("SECURITY VIOLATION: Path with unverified intermediate/terminal nodes must NOT be PathVerified")
		}
		if p.Status != PathEvidenceSupported && p.Status != PathObserved {
			t.Errorf("expected evidence-supported or observed status, got %s", p.Status)
		}
	}
}

func TestSecuritySemantics_InconclusiveEdge(t *testing.T) {
	// Edge has ValidationStatus = ValidationInconclusive
	fA := makeMultihopFinding("A", "Route A", "api-route", report.SeverityInfo, true, false, true, false, false, "/a")
	fB := makeMultihopFinding("B", "Flaw B", "auth", report.SeverityHigh, true, false, false, false, false, "/b")
	fC := makeMultihopFinding("C", "Flaw C", "data", report.SeverityHigh, true, false, false, true, false, "/c")

	rels := []Relationship{
		{ID: "AB", SourceFindingID: "A", TargetFindingID: "B", Type: RelReaches, ValidationStatus: ValidationConfirmed, RuleCode: RuleCOR01},
		{ID: "BC", SourceFindingID: "B", TargetFindingID: "C", Type: RelExposes, ValidationStatus: ValidationInconclusive, RuleCode: RuleCOR03},
	}
	findingMap := map[string]NormalizedFinding{"A": fA, "B": fB, "C": fC}

	engine := NewEngine(DefaultConfig())
	rawPaths, _, _ := engine.buildAttackPaths(context.Background(), []NormalizedFinding{fA, fB, fC}, rels, findingMap)
	paths := engine.processPaths(rawPaths)

	for _, p := range paths {
		if len(p.Nodes) == 3 {
			if p.Status != PathInconclusive {
				t.Fatalf("path with inconclusive edge must have PathInconclusive status, got %s", p.Status)
			}
		}
	}
}

func TestSecuritySemantics_DenseGraphStepBudget(t *testing.T) {
	// Construct a synthetic dense graph that would cause combinatorial explosion
	// without step bounds
	var findings []NormalizedFinding
	findingMap := make(map[string]NormalizedFinding)
	var rels []Relationship

	for i := 0; i < 15; i++ {
		id := fmt.Sprintf("N%d", i)
		f := makeMultihopFinding(id, fmt.Sprintf("Node %d", i), "api-route", report.SeverityMedium, true, false, i == 0, false, false, fmt.Sprintf("/%d", i))
		findings = append(findings, f)
		findingMap[id] = f
	}

	// Dense forward connections: N_i -> N_j for all j > i
	relCount := 0
	for i := 0; i < len(findings); i++ {
		for j := i + 1; j < len(findings); j++ {
			relCount++
			rels = append(rels, Relationship{
				ID:               fmt.Sprintf("REL-%d-%d", i, j),
				SourceFindingID:  findings[i].ID,
				TargetFindingID:  findings[j].ID,
				Type:             RelEnables,
				ValidationStatus: ValidationConfirmed,
				RuleCode:         RuleCOR05,
			})
		}
	}

	start := time.Now()
	engine := NewEngine(DefaultConfig())
	rawPaths, limitsReached, truncReason := engine.buildAttackPaths(context.Background(), findings, rels, findingMap)
	duration := time.Since(start)

	if duration > 3*time.Second {
		t.Fatalf("dense graph traversal took too long (%v), budget protection failed", duration)
	}
	if !limitsReached {
		t.Fatalf("dense graph should reach configured candidate or budget threshold")
	}
	if len(rawPaths) == 0 {
		t.Fatalf("expected paths discovered before budget hit")
	}
	t.Logf("Dense graph bounded successfully in %v (%d raw paths, truncReason: %s)", duration, len(rawPaths), truncReason)
}

// -----------------------------------------------------------------------------
// 5. Adversarial Gap Closure & Verification
// -----------------------------------------------------------------------------

func TestAdversarial_CycleWithIndependentComponent(t *testing.T) {
	// Component 1 (Cyclic): A -> B -> C -> A (all verified findings)
	fA := makeMultihopFinding("CYC_A", "Auth Loop A", "auth", report.SeverityHigh, true, false, true, false, false, "https://api.example.com/a")
	fB := makeMultihopFinding("CYC_B", "Auth Loop B", "authz", report.SeverityHigh, true, false, false, false, false, "https://api.example.com/b")
	fC := makeMultihopFinding("CYC_C", "Auth Loop C", "cloud", report.SeverityHigh, true, false, false, false, false, "https://api.example.com/c")

	// Component 2 (Independent Acyclic): X -> Y -> Z (all verified findings)
	fX := makeMultihopFinding("ACYC_X", "Gateway X", "api-route", report.SeverityInfo, true, false, true, false, false, "https://svc.example.com/x")
	fY := makeMultihopFinding("ACYC_Y", "BOLA Y", "bola", report.SeverityHigh, true, false, false, false, false, "https://svc.example.com/x/item")
	fZ := makeMultihopFinding("ACYC_Z", "Sensitive Data Z", "sensitive-data-exposure", report.SeverityHigh, true, false, false, true, false, "https://svc.example.com/x/item")

	rels := []Relationship{
		// Cycle edges
		{ID: "CYC_AB", SourceFindingID: "CYC_A", TargetFindingID: "CYC_B", Type: RelEnables, ValidationStatus: ValidationConfirmed, RuleCode: RuleCOR02},
		{ID: "CYC_BC", SourceFindingID: "CYC_B", TargetFindingID: "CYC_C", Type: RelEnables, ValidationStatus: ValidationConfirmed, RuleCode: RuleCOR05},
		{ID: "CYC_CA", SourceFindingID: "CYC_C", TargetFindingID: "CYC_A", Type: RelEnables, ValidationStatus: ValidationConfirmed, RuleCode: RuleCOR07},
		// Acyclic component edges
		{ID: "ACYC_XY", SourceFindingID: "ACYC_X", TargetFindingID: "ACYC_Y", Type: RelReaches, ValidationStatus: ValidationConfirmed, RuleCode: RuleCOR01},
		{ID: "ACYC_YZ", SourceFindingID: "ACYC_Y", TargetFindingID: "ACYC_Z", Type: RelExposes, ValidationStatus: ValidationConfirmed, RuleCode: RuleCOR03},
	}

	findings := []NormalizedFinding{fA, fB, fC, fX, fY, fZ}
	findingMap := make(map[string]NormalizedFinding)
	for _, f := range findings {
		findingMap[f.ID] = f
	}

	graph := NewAttackGraph(findings, rels)
	if !graph.Validation.HasCycle {
		t.Fatalf("expected graph.Validation.HasCycle == true")
	}

	engine := NewEngine(DefaultConfig())
	rawPaths, _, _ := engine.buildAttackPaths(context.Background(), findings, rels, findingMap)
	paths := engine.processPaths(rawPaths)

	foundAcyclic := false
	for _, p := range paths {
		// 1. Any path involving the cyclic nodes CYC_A, CYC_B, CYC_C must NEVER be PathVerified
		for _, nid := range p.NodeIDs {
			if nid == "CYC_A" || nid == "CYC_B" || nid == "CYC_C" {
				if p.Status == PathVerified {
					t.Fatalf("CRITICAL SECURITY DEFECT: path involving cyclic nodes %v was accepted as PathVerified", p.NodeIDs)
				}
				if p.Status != PathInconclusive {
					t.Errorf("expected PathInconclusive status for cyclic path, got %s", p.Status)
				}
			}
		}

		// 2. The independent acyclic component X -> Y -> Z must be safely preserved and PathVerified
		if len(p.Nodes) == 3 && p.NodeIDs[0] == "ACYC_X" && p.NodeIDs[1] == "ACYC_Y" && p.NodeIDs[2] == "ACYC_Z" {
			foundAcyclic = true
			if p.Status != PathVerified {
				t.Errorf("independent acyclic component was incorrectly degraded: got %s, expected PathVerified", p.Status)
			}
		}
	}

	if !foundAcyclic {
		t.Fatalf("expected independent acyclic path ACYC_X -> ACYC_Y -> ACYC_Z to be discovered and preserved")
	}
}

func TestAdversarial_RealRuleCompositionEndToEnd(t *testing.T) {
	// Exercise Correlate() end-to-end with realistic finding inputs
	f1 := makeFinding("F1", "Public Users API Route", "api-route", report.SeverityInfo, report.ConfidenceHigh, report.VerificationVerified, "https://api.example.com", "https://api.example.com/api/v1/users")
	f2 := makeFinding("F2", "JWT Signature Verification Disabled", "jwt-auth-flaw", report.SeverityHigh, report.ConfidenceHigh, report.VerificationVerified, "https://api.example.com", "https://api.example.com/api/v1/users")
	f2.EvidenceDetails.Details["auth_state"] = "JWT_UNVERIFIED"

	f3 := makeFinding("F3", "BOLA on User Ledger", "bola", report.SeverityHigh, report.ConfidenceHigh, report.VerificationVerified, "https://api.example.com", "https://api.example.com/api/v1/users/{id}")
	f3.EvidenceDetails.Details["bola"] = "true"

	f4 := makeFinding("F4", "Cloud Database Service Key Disclosed", "sensitive-data-exposure", report.SeverityHigh, report.ConfidenceHigh, report.VerificationVerified, "https://api.example.com", "https://api.example.com/api/v1/users/{id}")
	f4.EvidenceDetails.Details["secret_type"] = "service_key"
	f4.EvidenceDetails.Details["credential"] = "true"

	f5 := makeFinding("F5", "Production Supabase Database", "cloudsec-database-exposure", report.SeverityCritical, report.ConfidenceHigh, report.VerificationVerified, "https://supabase.co", "https://db.supabase.co/rest/v1")

	// Negative control 1: Completely unrelated host
	fUnrelated := makeFinding("F_UNRELATED", "Static Marketing CSS Asset", "discovery", report.SeverityInfo, report.ConfidenceHigh, report.VerificationVerified, "https://cdn.otherdomain.org", "https://cdn.otherdomain.org/main.css")

	// Negative control 2: Conflicting tenant boundary
	fConflictingTenant := makeFinding("F_TENANT_ISOLATED", "Isolated Tenant Route", "api-route", report.SeverityInfo, report.ConfidenceHigh, report.VerificationVerified, "https://api.example.com", "https://api.example.com/api/v1/users/isolated")
	fConflictingTenant.EvidenceDetails.Details["tenant_id"] = "isolated-tenant-999"

	engine := NewEngine(DefaultConfig())
	summary, paths, rels, err := engine.Correlate(context.Background(), []report.Finding{
		f1, f2, f3, f4, f5, fUnrelated, fConflictingTenant,
	})
	if err != nil {
		t.Fatalf("Correlate failed: %v", err)
	}

	if summary.VerifiedPaths < 1 {
		t.Errorf("expected at least 1 verified attack path, got %d", summary.VerifiedPaths)
	}

	// Check that F_UNRELATED and F_TENANT_ISOLATED are never connected to the 4-node/5-node chain
	for _, p := range paths {
		for _, nid := range p.NodeIDs {
			if nid == "F_UNRELATED" {
				t.Fatalf("unrelated finding was incorrectly correlated into attack path %s (%v)", p.ID, p.NodeIDs)
			}
		}
	}

	// Check for the multi-hop chain
	var foundMultiHop bool
	for _, p := range paths {
		if len(p.Nodes) >= 3 && p.NodeIDs[0] == "F1" {
			foundMultiHop = true
			if !strings.HasPrefix(p.ID, "PATH-MULTIHOP-") {
				t.Errorf("expected PATH-MULTIHOP- prefix, got %s", p.ID)
			}
		}
	}
	if !foundMultiHop {
		t.Fatalf("expected real rule engine to construct multi-hop attack path starting at F1")
	}

	t.Logf("Real rule composition success: %d relationships, %d paths, %d verified paths",
		len(rels), len(paths), summary.VerifiedPaths)
}

func TestAdversarial_IdenticalNodesDistinctRulesPathIdentity(t *testing.T) {
	// Two paths connecting the same two nodes N1 -> N2, but using distinct rules:
	// Path A uses COR-01 (RelReaches)
	// Path B uses COR-02 (RelEnables)
	f1 := makeMultihopFinding("N1", "Node 1", "api-route", report.SeverityInfo, true, false, true, false, false, "/1")
	f2 := makeMultihopFinding("N2", "Node 2", "auth", report.SeverityHigh, true, false, false, false, false, "/2")

	relA := Relationship{ID: "E_COR01", SourceFindingID: "N1", TargetFindingID: "N2", Type: RelReaches, ValidationStatus: ValidationConfirmed, RuleCode: RuleCOR01}
	relB := Relationship{ID: "E_COR02", SourceFindingID: "N1", TargetFindingID: "N2", Type: RelEnables, ValidationStatus: ValidationConfirmed, RuleCode: RuleCOR02}

	engine := NewEngine(DefaultConfig())

	pathA := engine.constructPath([]string{"N1", "N2"}, []NormalizedFinding{f1, f2}, []Relationship{relA}, nil)
	pathB := engine.constructPath([]string{"N1", "N2"}, []NormalizedFinding{f1, f2}, []Relationship{relB}, nil)

	// 1. Path IDs must be distinct because edge rule differs
	if pathA.ID == pathB.ID {
		t.Fatalf("PATH ID COLLISION: paths with identical nodes but different edge rules produced identical ID: %s", pathA.ID)
	}

	// 2. processPaths must retain BOTH distinct paths, not drop one as a duplicate
	deduped := engine.processPaths([]AttackPath{pathA, pathB})
	if len(deduped) != 2 {
		t.Fatalf("processPaths incorrectly merged paths with different rules: expected 2, got %d", len(deduped))
	}

	// 3. Passing identical path twice must cleanly deduplicate
	dedupedDupe := engine.processPaths([]AttackPath{pathA, pathA})
	if len(dedupedDupe) != 1 {
		t.Fatalf("processPaths failed to deduplicate genuinely identical paths: expected 1, got %d", len(dedupedDupe))
	}
}

func TestAdversarial_TruncationDownstreamSignaling(t *testing.T) {
	// A -> B -> C -> D -> E (Chain of depth 4 transitions / 5 nodes)
	fA := makeMultihopFinding("A", "Node A", "route", report.SeverityInfo, true, false, true, false, false, "/a")
	fB := makeMultihopFinding("B", "Node B", "auth", report.SeverityHigh, true, false, false, false, false, "/b")
	fC := makeMultihopFinding("C", "Node C", "authz", report.SeverityHigh, true, false, false, false, false, "/c")
	fD := makeMultihopFinding("D", "Node D", "data", report.SeverityHigh, true, false, false, true, false, "/d")
	fE := makeMultihopFinding("E", "Node E", "cloud", report.SeverityCritical, true, false, false, false, true, "/e")

	rels := []Relationship{
		{ID: "AB", SourceFindingID: "A", TargetFindingID: "B", Type: RelReaches, ValidationStatus: ValidationConfirmed, RuleCode: RuleCOR01},
		{ID: "BC", SourceFindingID: "B", TargetFindingID: "C", Type: RelEnables, ValidationStatus: ValidationConfirmed, RuleCode: RuleCOR02},
		{ID: "CD", SourceFindingID: "C", TargetFindingID: "D", Type: RelExposes, ValidationStatus: ValidationConfirmed, RuleCode: RuleCOR03},
		{ID: "DE", SourceFindingID: "D", TargetFindingID: "E", Type: RelEnables, ValidationStatus: ValidationConfirmed, RuleCode: RuleCOR08},
	}
	findings := []NormalizedFinding{fA, fB, fC, fD, fE}
	findingMap := map[string]NormalizedFinding{"A": fA, "B": fB, "C": fC, "D": fD, "E": fE}

	// Set MaxPathDepth = 2
	cfg := DefaultConfig()
	cfg.MaxPathDepth = 2
	engine := NewEngine(cfg)

	rawPaths, limitsReached, truncReason := engine.buildAttackPaths(context.Background(), findings, rels, findingMap)
	if !limitsReached {
		t.Fatalf("expected limitsReached == true when deeper valid paths exist beyond MaxPathDepth")
	}
	if !strings.Contains(truncReason, "depth") {
		t.Fatalf("expected truncation reason to mention depth, got: %s", truncReason)
	}
	if len(rawPaths) == 0 {
		t.Fatalf("expected paths discovered before depth limit cutoff")
	}

	summary := engine.compileSummary(findings, rels, rawPaths, limitsReached, truncReason)
	if !summary.LimitsReached {
		t.Fatalf("summary.LimitsReached must be true for downstream consumers")
	}
	if summary.TruncationReason == "" {
		t.Fatalf("summary.TruncationReason must be populated")
	}
}

func TestAdversarial_ExhaustiveVerificationMatrix(t *testing.T) {
	testCases := []struct {
		name           string
		f1Verified     bool
		f1Candidate    bool
		f2Verified     bool
		f2Candidate    bool
		f3Verified     bool
		f3Candidate    bool
		edge1Status    ValidationStatus
		edge2Status    ValidationStatus
		hasHypothesis  bool
		expectedStatus PathStatus
	}{
		{
			name:           "AllNodesVerified_AllEdgesConfirmed",
			f1Verified:     true,
			f2Verified:     true,
			f3Verified:     true,
			edge1Status:    ValidationConfirmed,
			edge2Status:    ValidationConfirmed,
			expectedStatus: PathVerified,
		},
		{
			name:           "OneVerifiedNode_TwoObservedNodes_NeverPromotes",
			f1Verified:     true,
			f2Verified:     false,
			f3Verified:     false,
			edge1Status:    ValidationConfirmed,
			edge2Status:    ValidationConfirmed,
			expectedStatus: PathEvidenceSupported,
		},
		{
			name:           "TwoVerifiedNodes_OneCandidateNode_IsCandidate",
			f1Verified:     true,
			f2Verified:     true,
			f3Candidate:    true,
			edge1Status:    ValidationConfirmed,
			edge2Status:    ValidationConfirmed,
			expectedStatus: PathCandidate,
		},
		{
			name:           "AllNodesVerified_OnePlausibleEdge_IsCandidate",
			f1Verified:     true,
			f2Verified:     true,
			f3Verified:     true,
			edge1Status:    ValidationConfirmed,
			edge2Status:    ValidationPlausible,
			expectedStatus: PathCandidate,
		},
		{
			name:           "AllNodesVerified_OneInconclusiveEdge_IsInconclusive",
			f1Verified:     true,
			f2Verified:     true,
			f3Verified:     true,
			edge1Status:    ValidationConfirmed,
			edge2Status:    ValidationInconclusive,
			expectedStatus: PathInconclusive,
		},
		{
			name:           "AllNodesVerified_WithInferredHypothesis_IsCandidate",
			f1Verified:     true,
			f2Verified:     true,
			f3Verified:     true,
			edge1Status:    ValidationConfirmed,
			edge2Status:    ValidationConfirmed,
			hasHypothesis:  true,
			expectedStatus: PathCandidate,
		},
	}

	engine := NewEngine(DefaultConfig())

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			f1 := makeMultihopFinding("T1", "Node 1", "api-route", report.SeverityInfo, tc.f1Verified, tc.f1Candidate, true, false, false, "/1")
			f2 := makeMultihopFinding("T2", "Node 2", "auth", report.SeverityHigh, tc.f2Verified, tc.f2Candidate, false, false, false, "/2")
			f3 := makeMultihopFinding("T3", "Node 3", "data", report.SeverityHigh, tc.f3Verified, tc.f3Candidate, false, true, false, "/3")
			if tc.hasHypothesis {
				f2.InferredHypothesis = true
			}

			rel1 := Relationship{ID: "E1", SourceFindingID: "T1", TargetFindingID: "T2", Type: RelReaches, ValidationStatus: tc.edge1Status, RuleCode: RuleCOR01}
			rel2 := Relationship{ID: "E2", SourceFindingID: "T2", TargetFindingID: "T3", Type: RelExposes, ValidationStatus: tc.edge2Status, RuleCode: RuleCOR03}

			path := engine.constructPath([]string{"T1", "T2", "T3"}, []NormalizedFinding{f1, f2, f3}, []Relationship{rel1, rel2}, nil)
			if path.Status != tc.expectedStatus {
				t.Fatalf("expected status %s, got %s", tc.expectedStatus, path.Status)
			}
		})
	}
}

func TestAdversarial_EvidenceSupportedPersistenceAndReporting(t *testing.T) {
	// Construct an evidence-supported path
	f1 := makeMultihopFinding("E1", "Node 1", "api-route", report.SeverityInfo, false, false, true, false, false, "/1")
	f2 := makeMultihopFinding("E2", "Node 2", "auth", report.SeverityHigh, false, false, false, false, false, "/2")
	rel := Relationship{ID: "R1", SourceFindingID: "E1", TargetFindingID: "E2", Type: RelReaches, ValidationStatus: ValidationConfirmed, RuleCode: RuleCOR01}

	engine := NewEngine(DefaultConfig())
	path := engine.constructPath([]string{"E1", "E2"}, []NormalizedFinding{f1, f2}, []Relationship{rel}, nil)

	if path.Status != PathEvidenceSupported {
		t.Fatalf("expected PathEvidenceSupported status, got %s", path.Status)
	}

	// Verify AttachAttackPaths with report:
	// Unverified paths (Candidate, Evidence-Supported, Inconclusive) must contribute ZERO unverified risk escalation to primary report risk
	lowFinding := makeFinding("LOW1", "Low Risk Finding", "info", report.SeverityLow, report.ConfidenceHigh, report.VerificationVerified, "https://api.example.com", "https://api.example.com/low")
	rep := report.Report{
		Findings:  []report.Finding{lowFinding},
		RiskScore: 20,
		RiskLevel: report.SeverityLow,
	}

	pathSummary := report.AttackPathSummary{
		ID:                path.ID,
		Title:             path.Title,
		Status:            string(path.Status),
		Confidence:        path.Confidence,
		CombinedRiskScore: 85, // High score
		CombinedRiskLevel: report.SeverityCritical,
	}

	report.AttachAttackPaths(&rep, []report.AttackPathSummary{pathSummary})

	// Primary score must NOT escalate to 85 because path is not VERIFIED
	if rep.RiskScore > 30 {
		t.Fatalf("SECURITY VIOLATION: Evidence-supported unverified attack path escalated primary assessment score (%d > 30)", rep.RiskScore)
	}
	if rep.RiskLevel != report.SeverityLow {
		t.Fatalf("SECURITY VIOLATION: Evidence-supported unverified attack path escalated primary risk level (%s != LOW)", rep.RiskLevel)
	}
}

func TestAdversarial_TarjanSCC_CycleWithDownstreamSink(t *testing.T) {
	// Graph: A -> B -> C -> B (cycle on B, C), and C -> D (acyclic sink)
	fA := makeMultihopFinding("NODE_A", "Entrypoint A", "api-route", report.SeverityInfo, true, false, true, false, false, "/a")
	fB := makeMultihopFinding("NODE_B", "Service B", "auth", report.SeverityHigh, true, false, false, false, false, "/b")
	fC := makeMultihopFinding("NODE_C", "Service C", "authz", report.SeverityHigh, true, false, false, false, false, "/c")
	fD := makeMultihopFinding("NODE_D", "Sink D", "data", report.SeverityCritical, true, false, false, true, false, "/d")

	rels := []Relationship{
		{ID: "AB", SourceFindingID: "NODE_A", TargetFindingID: "NODE_B", Type: RelReaches, ValidationStatus: ValidationConfirmed, RuleCode: RuleCOR01},
		{ID: "BC", SourceFindingID: "NODE_B", TargetFindingID: "NODE_C", Type: RelEnables, ValidationStatus: ValidationConfirmed, RuleCode: RuleCOR02},
		{ID: "CB", SourceFindingID: "NODE_C", TargetFindingID: "NODE_B", Type: RelEnables, ValidationStatus: ValidationConfirmed, RuleCode: RuleCOR05},
		{ID: "CD", SourceFindingID: "NODE_C", TargetFindingID: "NODE_D", Type: RelExposes, ValidationStatus: ValidationConfirmed, RuleCode: RuleCOR03},
	}

	graph := NewAttackGraph([]NormalizedFinding{fA, fB, fC, fD}, rels)
	if !graph.Validation.HasCycle {
		t.Fatalf("expected cycle to be detected")
	}

	// Tarjan's SCC must isolate EXACTLY B and C as cyclic nodes.
	// Neither A (upstream) nor D (downstream sink) may be included in CycleNodes.
	if len(graph.Validation.CycleNodes) != 2 {
		t.Fatalf("expected exactly 2 cycle nodes (B, C), got %v", graph.Validation.CycleNodes)
	}
	cycleMap := make(map[string]bool)
	for _, n := range graph.Validation.CycleNodes {
		cycleMap[n] = true
	}
	if !cycleMap["NODE_B"] || !cycleMap["NODE_C"] {
		t.Fatalf("expected NODE_B and NODE_C in CycleNodes, got %v", graph.Validation.CycleNodes)
	}
	if cycleMap["NODE_A"] {
		t.Errorf("upstream node NODE_A was incorrectly marked as a cycle node")
	}
	if cycleMap["NODE_D"] {
		t.Errorf("downstream sink NODE_D was incorrectly marked as a cycle node")
	}

	// Verify cycle edge isolation: only the back-edge between B and C must be marked as CycleEdges
	if len(graph.Validation.CycleEdges) == 0 {
		t.Fatalf("expected cycle back-edges to be isolated")
	}
	for _, edgeDesc := range graph.Validation.CycleEdges {
		if strings.Contains(edgeDesc, "NODE_D") || strings.Contains(edgeDesc, "NODE_A") {
			t.Errorf("acyclic edge incorrectly marked as cycle edge: %s", edgeDesc)
		}
	}
}

func TestAdversarial_TarjanSCC_FigureEightDoubleCycle(t *testing.T) {
	// Multi-cycle figure-eight: A -> B -> A and A -> C -> A
	fA := makeMultihopFinding("HUB", "Hub A", "auth", report.SeverityHigh, true, false, true, false, false, "/hub")
	fB := makeMultihopFinding("LOOP1", "Loop B", "authz", report.SeverityHigh, true, false, false, false, false, "/b")
	fC := makeMultihopFinding("LOOP2", "Loop C", "cloud", report.SeverityHigh, true, false, false, false, false, "/c")

	rels := []Relationship{
		{ID: "AB", SourceFindingID: "HUB", TargetFindingID: "LOOP1", Type: RelEnables, ValidationStatus: ValidationConfirmed, RuleCode: RuleCOR02},
		{ID: "BA", SourceFindingID: "LOOP1", TargetFindingID: "HUB", Type: RelEnables, ValidationStatus: ValidationConfirmed, RuleCode: RuleCOR05},
		{ID: "AC", SourceFindingID: "HUB", TargetFindingID: "LOOP2", Type: RelEnables, ValidationStatus: ValidationConfirmed, RuleCode: RuleCOR07},
		{ID: "CA", SourceFindingID: "LOOP2", TargetFindingID: "HUB", Type: RelEnables, ValidationStatus: ValidationConfirmed, RuleCode: RuleCOR08},
	}

	graph := NewAttackGraph([]NormalizedFinding{fA, fB, fC}, rels)
	if !graph.Validation.HasCycle {
		t.Fatalf("figure-eight multi-cycle must be detected")
	}
	if len(graph.Validation.CycleNodes) != 3 {
		t.Fatalf("expected all 3 nodes in cyclic SCC, got %v", graph.Validation.CycleNodes)
	}
	if len(graph.Validation.CycleEdges) < 2 {
		t.Fatalf("expected at least 2 back-edges in figure-eight graph, got %v", graph.Validation.CycleEdges)
	}
}

func TestAdversarial_BoundaryConflictPrecision(t *testing.T) {
	testCases := []struct {
		name         string
		d1           map[string]string
		d2           map[string]string
		wantConflict bool
	}{
		{
			name:         "MatchingTenantIDs_NoConflict",
			d1:           map[string]string{"tenant_id": "tenant-alpha"},
			d2:           map[string]string{"tenant_id": "tenant-alpha"},
			wantConflict: false,
		},
		{
			name:         "NormalizedTenantIDs_WhitespaceAndCase_NoConflict",
			d1:           map[string]string{"tenant_id": "  TENANT-ALPHA  "},
			d2:           map[string]string{"tenant_id": "tenant-alpha"},
			wantConflict: false,
		},
		{
			name:         "MismatchedTenantIDs_Conflict",
			d1:           map[string]string{"tenant_id": "tenant-alpha"},
			d2:           map[string]string{"tenant_id": "tenant-beta"},
			wantConflict: true,
		},
		{
			name:         "MatchingAccountIDs_NoConflict",
			d1:           map[string]string{"account_id": "acc-100"},
			d2:           map[string]string{"account_id": "acc-100"},
			wantConflict: false,
		},
		{
			name:         "MismatchedAccountIDs_Conflict",
			d1:           map[string]string{"account_id": "acc-100"},
			d2:           map[string]string{"account_id": "acc-200"},
			wantConflict: true,
		},
		{
			name:         "MismatchedOrgIDs_Conflict",
			d1:           map[string]string{"org_id": "org-corp"},
			d2:           map[string]string{"organization_id": "org-other"},
			wantConflict: true,
		},
		{
			name:         "MissingTenantOnOneSide_NoConflict",
			d1:           map[string]string{"tenant_id": "tenant-alpha"},
			d2:           map[string]string{},
			wantConflict: false,
		},
		{
			name:         "MissingOnBothSides_NoConflict",
			d1:           map[string]string{},
			d2:           map[string]string{},
			wantConflict: false,
		},
		{
			name:         "NilMaps_NoConflict",
			d1:           nil,
			d2:           nil,
			wantConflict: false,
		},
		{
			name:         "CrossKeyPresence_TenantOnF1_AccountOnF2_NoConflict",
			d1:           map[string]string{"tenant_id": "tenant-alpha"},
			d2:           map[string]string{"account_id": "acc-100"},
			wantConflict: false,
		},
		{
			name:         "FreeFormTextInOtherKeys_Ignored_NoConflict",
			d1:           map[string]string{"notes": "tenant-alpha boundary check"},
			d2:           map[string]string{"notes": "tenant-beta boundary check"},
			wantConflict: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			conflict, desc1, desc2 := hasBoundaryConflict(tc.d1, tc.d2)
			if conflict != tc.wantConflict {
				t.Fatalf("hasBoundaryConflict() = %v (desc1=%s, desc2=%s), want %v",
					conflict, desc1, desc2, tc.wantConflict)
			}
		})
	}
}

func TestAdversarial_BoundaryConflict_COR01Integration(t *testing.T) {
	// Rule COR-01: Entry Point to Vulnerable Resource
	f1 := &NormalizedFinding{
		ID:                 "EP1",
		Title:              "Public Users API Route",
		Category:           "api-route",
		IsEntrypoint:       true,
		Host:               "api.example.com",
		Path:               "/api/v1/users",
		Target:             "https://api.example.com/api/v1/users",
		EvidenceDetails:    map[string]string{"tenant_id": "tenant-alpha"},
		VerificationStatus: report.VerificationVerified,
	}

	// Target 1: Conflicting tenant
	f2Conflicting := &NormalizedFinding{
		ID:                 "VULN1",
		Title:              "JWT Auth Flaw",
		Category:           "jwt-auth-flaw",
		Host:               "api.example.com",
		Path:               "/api/v1/users",
		Target:             "https://api.example.com/api/v1/users",
		EvidenceDetails:    map[string]string{"tenant_id": "tenant-beta"},
		VerificationStatus: report.VerificationVerified,
		IsVerified:         true,
	}

	// Target 2: Matching tenant
	f2Matching := &NormalizedFinding{
		ID:                 "VULN2",
		Title:              "JWT Auth Flaw",
		Category:           "jwt-auth-flaw",
		Host:               "api.example.com",
		Path:               "/api/v1/users",
		Target:             "https://api.example.com/api/v1/users",
		EvidenceDetails:    map[string]string{"tenant_id": "tenant-alpha"},
		VerificationStatus: report.VerificationVerified,
		IsVerified:         true,
	}

	// Target 3: Missing tenant (no conflict)
	f2Missing := &NormalizedFinding{
		ID:                 "VULN3",
		Title:              "JWT Auth Flaw",
		Category:           "jwt-auth-flaw",
		Host:               "api.example.com",
		Path:               "/api/v1/users",
		Target:             "https://api.example.com/api/v1/users",
		EvidenceDetails:    map[string]string{},
		VerificationStatus: report.VerificationVerified,
		IsVerified:         true,
	}

	// 1. Conflicting tenant must be rejected
	if _, ok := evaluateCOR01(f1, f2Conflicting); ok {
		t.Fatalf("COR-01 must reject transition between conflicting tenants")
	}

	// 2. Matching tenant must succeed
	if _, ok := evaluateCOR01(f1, f2Matching); !ok {
		t.Fatalf("COR-01 must accept transition between matching tenants")
	}

	// 3. Missing tenant on target must succeed (non-interference)
	if _, ok := evaluateCOR01(f1, f2Missing); !ok {
		t.Fatalf("COR-01 must accept transition when target has no boundary restriction")
	}
}

func TestAdversarial_SummaryPartitioningAndNonDoubleCounting(t *testing.T) {
	// Construct 5 paths with distinct statuses: VERIFIED, CANDIDATE, INCONCLUSIVE, OBSERVED, EVIDENCE_SUPPORTED
	paths := []AttackPath{
		{
			ID:                "P1",
			Status:            PathVerified,
			CombinedRiskScore: 90,
			CombinedRiskLevel: report.SeverityCritical,
		},
		{
			ID:                "P2",
			Status:            PathCandidate,
			CombinedRiskScore: 60,
			CombinedRiskLevel: report.SeverityMedium,
		},
		{
			ID:                "P3",
			Status:            PathInconclusive,
			CombinedRiskScore: 40,
			CombinedRiskLevel: report.SeverityLow,
		},
		{
			ID:                "P4",
			Status:            PathObserved,
			CombinedRiskScore: 50,
			CombinedRiskLevel: report.SeverityMedium,
		},
		{
			ID:                "P5",
			Status:            PathEvidenceSupported,
			CombinedRiskScore: 70,
			CombinedRiskLevel: report.SeverityHigh,
		},
	}

	engine := NewEngine(DefaultConfig())
	summary := engine.compileSummary(nil, nil, paths, false, "")

	if summary.VerifiedPaths != 1 {
		t.Errorf("expected VerifiedPaths = 1, got %d", summary.VerifiedPaths)
	}
	if summary.CandidatePaths != 1 {
		t.Errorf("expected CandidatePaths = 1, got %d", summary.CandidatePaths)
	}
	if summary.InconclusivePaths != 1 {
		t.Errorf("expected InconclusivePaths = 1, got %d", summary.InconclusivePaths)
	}
	if summary.ObservedPaths != 1 {
		t.Errorf("expected ObservedPaths = 1, got %d (must NOT double-count evidence-supported paths)", summary.ObservedPaths)
	}
	if summary.EvidenceSupportedPaths != 1 {
		t.Errorf("expected EvidenceSupportedPaths = 1, got %d", summary.EvidenceSupportedPaths)
	}

	// Exact partition property: sum of counts must equal total paths
	partitionSum := summary.VerifiedPaths + summary.CandidatePaths + summary.InconclusivePaths + summary.ObservedPaths + summary.EvidenceSupportedPaths
	if partitionSum != len(paths) {
		t.Fatalf("PATH PARTITION DEFECT: sum of path categories (%d) != total paths (%d)", partitionSum, len(paths))
	}
}

func TestAdversarial_ComponentFindingRiskRetention(t *testing.T) {
	// Component findings have high individual risk
	f1 := makeFinding("F1", "High Severity Vulnerability", "injection", report.SeverityHigh, report.ConfidenceHigh, report.VerificationVerified, "https://api.example.com", "https://api.example.com/api/v1/search")
	f1.Score = 75
	f1.Severity = report.SeverityHigh

	f2 := makeFinding("F2", "Candidate Finding", "info", report.SeverityLow, report.ConfidenceMedium, report.VerificationDetected, "https://api.example.com", "https://api.example.com/api/v1/other")
	f2.Score = 20
	f2.Severity = report.SeverityLow

	rep := report.Report{
		Findings: []report.Finding{f1, f2},
	}

	// Attach an unverified candidate path with high combined risk
	unverifiedPath := report.AttackPathSummary{
		ID:                "PATH-UNVERIFIED-1",
		Title:             "Candidate Pivot",
		Status:            string(PathCandidate),
		Confidence:        report.ConfidenceMedium,
		CombinedRiskScore: 95,
		CombinedRiskLevel: report.SeverityCritical,
	}

	report.AttachAttackPaths(&rep, []report.AttackPathSummary{unverifiedPath})

	// 1. Finding F1 must retain its individual severity and score in the report finding table
	if len(rep.Findings) != 2 {
		t.Fatalf("expected 2 findings in report, got %d", len(rep.Findings))
	}
	if rep.Findings[0].Severity != report.SeverityHigh {
		t.Errorf("finding F1 severity corrupted: got %s, want HIGH", rep.Findings[0].Severity)
	}

	// 2. Unverified candidate path must NOT escalate assessment risk score to 95
	if rep.RiskScore > 80 {
		t.Fatalf("CRITICAL SECURITY DEFECT: Unverified candidate path escalated overall report risk to %d", rep.RiskScore)
	}
}
