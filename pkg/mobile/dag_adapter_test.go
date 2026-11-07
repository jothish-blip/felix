package mobile

import (
	"testing"

	"felix/pkg/correlation"
	"felix/pkg/discovery"
	"felix/pkg/report"
)

func TestDAG_20_MobileBackendGraph_Adapter(t *testing.T) {
	mbg := NewMobileBackendGraph("com.android.insecurebankv2")

	// 1. Mobile App Node
	mbg.AddNode(&MobileBackendGraphNode{
		ID:          "app:com.android.insecurebankv2",
		Type:        discovery.AssetTypeApplication,
		DisplayName: "InsecureBankv2 Mobile App",
		PackageName: "com.android.insecurebankv2",
	})

	// 2. Discovered Backend Host Node
	mbg.AddNode(&MobileBackendGraphNode{
		ID:          "host:10.0.2.2:8888",
		Type:        discovery.AssetTypeHost,
		DisplayName: "Backend Host (10.0.2.2:8888)",
		Host:        "10.0.2.2",
	})

	// 3. API Endpoint Node
	mbg.AddNode(&MobileBackendGraphNode{
		ID:          "endpoint:10.0.2.2:8888/login#POST",
		Type:        discovery.AssetTypeEndpoint,
		DisplayName: "POST /login",
		Host:        "10.0.2.2",
		Endpoint:    "/login",
	})

	// 4. Security Finding Node
	mbg.AddNode(&MobileBackendGraphNode{
		ID:          "finding:CLEARTEXT-LOGIN-01",
		Type:        discovery.AssetTypeEndpoint,
		DisplayName: "Cleartext HTTP Transmission on /login",
		Host:        "10.0.2.2",
		Endpoint:    "/login",
		Attributes: map[string]string{
			"severity":           report.SeverityHigh,
			"confidence":         "HIGH",
			"verification_state": string(report.VerificationVerified),
		},
	})

	// Add Edges
	mbg.AddEdge("app:com.android.insecurebankv2", "host:10.0.2.2:8888", correlation.RelReaches, correlation.ValidationConfirmed, "HIGH", "Mobile app communicates with backend host")
	mbg.AddEdge("host:10.0.2.2:8888", "endpoint:10.0.2.2:8888/login#POST", correlation.RelExposes, correlation.ValidationConfirmed, "HIGH", "Backend host exposes /login endpoint")
	mbg.AddEdge("endpoint:10.0.2.2:8888/login#POST", "finding:CLEARTEXT-LOGIN-01", correlation.RelEnables, correlation.ValidationConfirmed, "HIGH", "Endpoint exposes cleartext credential transmission")

	// Convert to DAGAttackGraph
	dag, err := mbg.ToDAGAttackGraph(true)
	if err != nil {
		t.Fatalf("mbg.ToDAGAttackGraph failed: %v", err)
	}

	if len(dag.Nodes) != 4 {
		t.Fatalf("expected 4 nodes in converted DAG, got %d", len(dag.Nodes))
	}
	if len(dag.Edges) != 3 {
		t.Fatalf("expected 3 edges in converted DAG, got %d", len(dag.Edges))
	}
	if !dag.Validation.IsValid || dag.Validation.HasCycle {
		t.Fatalf("converted DAG is invalid or has cycle: %v", dag.Validation.Errors)
	}

	// Check node types
	appNode := dag.Nodes["app:com.android.insecurebankv2"]
	if appNode == nil || appNode.Type != correlation.NodeTypeApplication || !appNode.IsEntrypoint {
		t.Fatalf("expected appNode to be NodeTypeApplication and IsEntrypoint=true")
	}

	findingNode := dag.Nodes["finding:CLEARTEXT-LOGIN-01"]
	if findingNode == nil || findingNode.Type != correlation.NodeTypeFinding || findingNode.Severity != report.SeverityHigh {
		t.Fatalf("expected findingNode to be NodeTypeFinding with High severity")
	}

	// Compute ShortestPath from app to finding
	res, err := dag.ShortestPath("app:com.android.insecurebankv2", "finding:CLEARTEXT-LOGIN-01")
	if err != nil {
		t.Fatalf("ShortestPath failed: %v", err)
	}
	if !res.PathExists {
		t.Fatalf("expected path to exist between app and finding")
	}
	if res.HopCount != 3 {
		t.Fatalf("expected 3 hops (App -> Host -> Endpoint -> Finding), got %d", res.HopCount)
	}
}
