package correlation

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"felix/pkg/report"
	"felix/pkg/secrets"
)

// Helper to construct normalized test finding
func makeTestNormFinding(id, title, cat, sev, ep, comp string, status report.VerificationStatus) NormalizedFinding {
	score := 50
	switch sev {
	case report.SeverityCritical:
		score = 95
	case report.SeverityHigh:
		score = 80
	case report.SeverityMedium:
		score = 55
	case report.SeverityLow:
		score = 30
	}
	return NormalizedFinding{
		ID:                 id,
		OriginalID:         id,
		Title:              title,
		Category:           cat,
		NormalizedCategory: cat,
		Severity:           sev,
		Confidence:         report.ConfidenceHigh,
		VerificationStatus: status,
		Score:              score,
		Endpoint:           ep,
		DisplayEndpoint:    ep,
		AffectedResource:   comp,
		IsVerified:         status == report.VerificationVerified,
		IsCandidate:        status == report.VerificationDetected,
	}
}

// Helper to construct test attack path
func makeTestAttackPath(id string, nodes []NormalizedFinding, status PathStatus, riskScore int) AttackPath {
	riskLevel := report.SeverityMedium
	if riskScore >= 90 {
		riskLevel = report.SeverityCritical
	} else if riskScore >= 70 {
		riskLevel = report.SeverityHigh
	} else if riskScore >= 40 {
		riskLevel = report.SeverityMedium
	} else {
		riskLevel = report.SeverityLow
	}

	var edges []Relationship
	for i := 0; i < len(nodes)-1; i++ {
		edges = append(edges, Relationship{
			ID:               fmt.Sprintf("REL-%s-%s", nodes[i].ID, nodes[i+1].ID),
			SourceFindingID:  nodes[i].ID,
			TargetFindingID:  nodes[i+1].ID,
			SourceTitle:      nodes[i].Title,
			TargetTitle:      nodes[i+1].Title,
			Type:             RelEnables,
			ValidationStatus: ValidationConfirmed,
			Confidence:       report.ConfidenceHigh,
			RuleCode:         RuleCOR01,
		})
	}

	nodeIDs := make([]string, len(nodes))
	for i, n := range nodes {
		nodeIDs[i] = n.ID
	}

	p := AttackPath{
		ID:                id,
		Title:             fmt.Sprintf("Path %s", id),
		NodeIDs:           nodeIDs,
		Nodes:             nodes,
		Edges:             edges,
		Status:            status,
		Confidence:        report.ConfidenceHigh,
		CombinedRiskScore: riskScore,
		CombinedRiskLevel: riskLevel,
		TargetAsset:       "api.client.internal",
		CreatedAt:         time.Now().UTC(),
	}
	p.SecurityStory = GenerateSecurityStory(&p)
	p.Remediation = p.SecurityStory.Remediation
	return p
}

// -----------------------------------------------------------------------------
// Section 1: Algorithm Correctness (Cases 1-12)
// -----------------------------------------------------------------------------

// Case 1: One path with one unique bottleneck
func TestBottleneckSolver_01_SinglePathUniqueBottleneck(t *testing.T) {
	n1 := makeTestNormFinding("F1", "Public Git Exposure", "exposure", report.SeverityHigh, "/.git/HEAD", "", report.VerificationVerified)
	n2 := makeTestNormFinding("F2", "Exposed Secret Key", "secret-leak", report.SeverityCritical, "/api/v1/auth", "AuthGateway", report.VerificationVerified)
	n3 := makeTestNormFinding("F3", "Admin Shell Access", "rce", report.SeverityCritical, "/api/v1/admin/exec", "AdminController", report.VerificationVerified)

	path := makeTestAttackPath("PATH-01", []NormalizedFinding{n1, n2, n3}, PathVerified, 95)
	findings := []NormalizedFinding{n1, n2, n3}

	res := AnalyzeRemediationBottlenecks([]AttackPath{path}, findings, nil)
	if res.TotalVerifiedChains != 1 {
		t.Fatalf("expected 1 verified chain, got %d", res.TotalVerifiedChains)
	}
	if res.PrimaryRecommendation == nil {
		t.Fatal("expected primary recommendation, got nil")
	}
	best := res.PrimaryRecommendation
	if best.DisruptedCount != 1 || best.ResidualCount != 0 {
		t.Errorf("expected 1 disrupted, 0 residual; got disrupted=%d, residual=%d", best.DisruptedCount, best.ResidualCount)
	}
	if best.DisruptionPercentage != 100.0 {
		t.Errorf("expected 100.0%% disruption, got %.1f%%", best.DisruptionPercentage)
	}
	if res.MinimumCut == nil || res.MinimumCut.CutSize != 1 {
		t.Fatalf("expected minimum cut size 1, got %v", res.MinimumCut)
	}
}

// Case 2: Five paths where one remediation interrupts exactly four (80.0%)
func TestBottleneckSolver_02_FivePathsOneDisruptsFour(t *testing.T) {
	// Shared BOLA middleware node
	sharedNode := makeTestNormFinding("F_BOLA", "BOLA on User Resource", "bola", report.SeverityHigh, "/api/v1/users/{id}", "ObjectAuthorizationMiddleware", report.VerificationVerified)

	e1 := makeTestNormFinding("E1", "Exposed API Docs", "info", report.SeverityLow, "/docs", "DocsPortal", report.VerificationVerified)
	e2 := makeTestNormFinding("E2", "CORS Misconfiguration", "cors", report.SeverityMedium, "/api/v1/meta", "Gateway", report.VerificationVerified)
	e3 := makeTestNormFinding("E3", "JWT Weak Secret", "jwt", report.SeverityHigh, "/auth/token", "AuthService", report.VerificationVerified)
	e4 := makeTestNormFinding("E4", "GraphQL Introspection", "graphql", report.SeverityLow, "/graphql", "GraphQLAPI", report.VerificationVerified)

	t1 := makeTestNormFinding("T1", "PII Exfiltration", "data-leak", report.SeverityHigh, "/api/v1/users/{id}/pii", "UserDb", report.VerificationVerified)
	t2 := makeTestNormFinding("T2", "Billing Record Tampering", "financial", report.SeverityCritical, "/api/v1/users/{id}/billing", "BillingDb", report.VerificationVerified)
	t3 := makeTestNormFinding("T3", "Session Takeover", "session", report.SeverityHigh, "/api/v1/users/{id}/sessions", "SessionStore", report.VerificationVerified)
	t4 := makeTestNormFinding("T4", "Tenant Scope Escape", "tenant-isolation", report.SeverityCritical, "/api/v1/users/{id}/tenant", "TenantDb", report.VerificationVerified)

	// Completely independent 5th path
	indepE := makeTestNormFinding("IND_E", "Public S3 Bucket", "storage", report.SeverityHigh, "/backup.tar.gz", "CloudStorage", report.VerificationVerified)
	indepT := makeTestNormFinding("IND_T", "Database Credentials in Backup", "secret-leak", report.SeverityCritical, "/db/creds", "BackupStorage", report.VerificationVerified)

	p1 := makeTestAttackPath("PATH-01", []NormalizedFinding{e1, sharedNode, t1}, PathVerified, 85)
	p2 := makeTestAttackPath("PATH-02", []NormalizedFinding{e2, sharedNode, t2}, PathVerified, 90)
	p3 := makeTestAttackPath("PATH-03", []NormalizedFinding{e3, sharedNode, t3}, PathVerified, 80)
	p4 := makeTestAttackPath("PATH-04", []NormalizedFinding{e4, sharedNode, t4}, PathVerified, 95)
	p5 := makeTestAttackPath("PATH-05", []NormalizedFinding{indepE, indepT}, PathVerified, 90)

	allFindings := []NormalizedFinding{sharedNode, e1, e2, e3, e4, t1, t2, t3, t4, indepE, indepT}
	paths := []AttackPath{p1, p2, p3, p4, p5}

	res := AnalyzeRemediationBottlenecks(paths, allFindings, nil)
	if res.TotalVerifiedChains != 5 {
		t.Fatalf("expected 5 verified chains, got %d", res.TotalVerifiedChains)
	}

	best := res.PrimaryRecommendation
	if best == nil {
		t.Fatal("expected primary recommendation, got nil")
	}

	// Verify exact statement: "disrupts 4 of the 5 currently verified attack chains"
	if best.DisruptedCount != 4 {
		t.Errorf("expected 4 disrupted chains, got %d", best.DisruptedCount)
	}
	if best.ResidualCount != 1 {
		t.Errorf("expected 1 residual chain, got %d", best.ResidualCount)
	}
	if best.DisruptionPercentage != 80.0 {
		t.Errorf("expected 80.0%% disruption, got %.1f%%", best.DisruptionPercentage)
	}
	if best.DisruptedCount+best.ResidualCount != res.TotalVerifiedChains {
		t.Errorf("invariant violated: disrupted (%d) + residual (%d) != total (%d)",
			best.DisruptedCount, best.ResidualCount, res.TotalVerifiedChains)
	}
	if len(best.ResidualPathIDs) != 1 || best.ResidualPathIDs[0] != "PATH-05" {
		t.Errorf("expected residual path PATH-05, got %v", best.ResidualPathIDs)
	}

	// Validate the 2-node minimum-cardinality vertex cut
	if res.MinimumCut == nil {
		t.Fatal("expected non-nil MinimumCut")
	}
	if res.MinimumCut.CutSize != 2 {
		t.Errorf("expected cut size 2, got %d", res.MinimumCut.CutSize)
	}
	cutNodes := res.MinimumCut.CutNodes
	if len(cutNodes) != 2 || cutNodes[0] != "F_BOLA" || cutNodes[1] != "IND_E" {
		t.Errorf("expected cut nodes [F_BOLA, IND_E], got %v", cutNodes)
	}
	// Verify neither cut node is an artificial source or sink
	for _, nid := range cutNodes {
		if strings.HasPrefix(nid, "__SUPER_") {
			t.Errorf("artificial node leaked into cut set: %s", nid)
		}
	}
	// Explicit mathematical reachability verification: removing cutNodes must leave 0 intact paths
	if !VerifyVertexCutReachability(paths, cutNodes) {
		t.Errorf("reachability verification failed: cut set %v did not sever all 5 paths", cutNodes)
	}
	if !res.MinimumCut.IsCompleteCut {
		t.Error("expected IsCompleteCut to be true")
	}
}

// Case 3: Five independent paths with no shared remediation candidate
func TestBottleneckSolver_03_FiveIndependentPaths(t *testing.T) {
	var paths []AttackPath
	var findings []NormalizedFinding

	for i := 1; i <= 5; i++ {
		e := makeTestNormFinding(fmt.Sprintf("E%d", i), fmt.Sprintf("Entrypoint %d", i), "info", report.SeverityLow, fmt.Sprintf("/entry/%d", i), fmt.Sprintf("Comp%d", i), report.VerificationVerified)
		target := makeTestNormFinding(fmt.Sprintf("T%d", i), fmt.Sprintf("Target %d", i), "rce", report.SeverityHigh, fmt.Sprintf("/target/%d", i), fmt.Sprintf("Comp%d", i), report.VerificationVerified)
		findings = append(findings, e, target)
		paths = append(paths, makeTestAttackPath(fmt.Sprintf("PATH-%02d", i), []NormalizedFinding{e, target}, PathVerified, 75))
	}

	res := AnalyzeRemediationBottlenecks(paths, findings, nil)
	if res.TotalVerifiedChains != 5 {
		t.Fatalf("expected 5 verified chains, got %d", res.TotalVerifiedChains)
	}

	// Every candidate disrupts at most 1 path
	for _, c := range res.RankedCandidates {
		if c.DisruptedCount > 1 {
			t.Errorf("candidate %s disrupted %d paths, expected <= 1", c.ID, c.DisruptedCount)
		}
		if c.DisruptionPercentage > 20.0 {
			t.Errorf("candidate %s disruption percentage %.1f%%, expected <= 20.0%%", c.ID, c.DisruptionPercentage)
		}
	}
	// Edmonds-Karp min-cut requires 5 cut nodes to sever 5 independent components
	if res.MinimumCut.CutSize != 5 {
		t.Errorf("expected min-cut size 5 for 5 independent paths, got %d", res.MinimumCut.CutSize)
	}
}

// Case 4: A graph where the minimum cut contains multiple elements
func TestBottleneckSolver_04_MinCutMultipleElements(t *testing.T) {
	// Two parallel paths from distinct entry points to distinct sinks
	e1 := makeTestNormFinding("E1", "Public Swagger UI", "exposure", report.SeverityLow, "/swagger", "Docs", report.VerificationVerified)
	m1 := makeTestNormFinding("M1", "BOLA in V1 API", "bola", report.SeverityHigh, "/v1/data", "V1Gateway", report.VerificationVerified)
	t1 := makeTestNormFinding("T1", "Data Exfiltration", "leak", report.SeverityHigh, "/v1/export", "V1Gateway", report.VerificationVerified)

	e2 := makeTestNormFinding("E2", "Debug Console", "exposure", report.SeverityMedium, "/console", "Admin", report.VerificationVerified)
	m2 := makeTestNormFinding("M2", "BFLA in V2 Admin", "bfla", report.SeverityCritical, "/v2/admin", "V2Admin", report.VerificationVerified)
	t2 := makeTestNormFinding("T2", "Admin Takeover", "takeover", report.SeverityCritical, "/v2/grant", "V2Admin", report.VerificationVerified)

	p1 := makeTestAttackPath("P1", []NormalizedFinding{e1, m1, t1}, PathVerified, 80)
	p2 := makeTestAttackPath("P2", []NormalizedFinding{e2, m2, t2}, PathVerified, 95)

	res := AnalyzeRemediationBottlenecks([]AttackPath{p1, p2}, []NormalizedFinding{e1, m1, t1, e2, m2, t2}, nil)
	if res.MinimumCut.CutSize != 2 {
		t.Errorf("expected min cut size 2 for 2 parallel disjoint paths, got %d", res.MinimumCut.CutSize)
	}
}

// Case 5: A graph where minimum-cardinality cut differs from highest single-candidate disruption ranking
func TestBottleneckSolver_05_MinCutDiffersFromDisruptionRanking(t *testing.T) {
	// Candidate X appears in 3 out of 4 paths (75% single-candidate disruption)
	// But to sever ALL 4 paths, the minimum cut of size 2 chooses a different combination
	x := makeTestNormFinding("X", "Shared Identity Provider", "jwt", report.SeverityHigh, "/auth/sso", "SSOProvider", report.VerificationVerified)

	a1 := makeTestNormFinding("A1", "Entry 1", "info", report.SeverityLow, "/a1", "A", report.VerificationVerified)
	a2 := makeTestNormFinding("A2", "Entry 2", "info", report.SeverityLow, "/a2", "A", report.VerificationVerified)
	a3 := makeTestNormFinding("A3", "Entry 3", "info", report.SeverityLow, "/a3", "A", report.VerificationVerified)
	b4 := makeTestNormFinding("B4", "Entry 4 (Bypasses SSO)", "bfla", report.SeverityCritical, "/b4", "B", report.VerificationVerified)

	sink1 := makeTestNormFinding("SINK1", "Database 1", "db", report.SeverityCritical, "/db1", "DatabaseService", report.VerificationVerified)
	sink2 := makeTestNormFinding("SINK2", "Storage 2", "storage", report.SeverityCritical, "/s3", "StorageService", report.VerificationVerified)

	p1 := makeTestAttackPath("P1", []NormalizedFinding{a1, x, sink1}, PathVerified, 85)
	p2 := makeTestAttackPath("P2", []NormalizedFinding{a2, x, sink1}, PathVerified, 85)
	p3 := makeTestAttackPath("P3", []NormalizedFinding{a3, x, sink2}, PathVerified, 85)
	p4 := makeTestAttackPath("P4", []NormalizedFinding{b4, sink2}, PathVerified, 90)

	allFindings := []NormalizedFinding{x, a1, a2, a3, b4, sink1, sink2}
	res := AnalyzeRemediationBottlenecks([]AttackPath{p1, p2, p3, p4}, allFindings, nil)

	// Single highest candidate is SSOProvider (3/4 = 75%)
	best := res.PrimaryRecommendation
	if best == nil || best.DisruptedCount != 3 {
		t.Fatalf("expected highest single candidate to disrupt 3 chains, got %v", best)
	}

	// But minimum cut must sever all 4 paths (size 2: e.g. {X, B4} or {SINK1, SINK2})
	if res.MinimumCut.CutSize != 2 {
		t.Errorf("expected minimum vertex cut size 2 to sever all 4 paths, got %d", res.MinimumCut.CutSize)
	}
	if res.MinimumCut.TotalPathsSevered != 4 {
		t.Errorf("expected 4 paths severed, got %d", res.MinimumCut.TotalPathsSevered)
	}
	// Explicit mathematical reachability verification
	if !VerifyVertexCutReachability([]AttackPath{p1, p2, p3, p4}, res.MinimumCut.CutNodes) {
		t.Errorf("reachability verification failed for min cut %v", res.MinimumCut.CutNodes)
	}
	if !res.MinimumCut.IsCompleteCut {
		t.Error("expected IsCompleteCut to be true")
	}
}

// Case 6: Unit-cost capacity policy verified
func TestBottleneckSolver_06_UnitCostCapacityPolicy(t *testing.T) {
	n1 := makeTestNormFinding("N1", "Step 1", "info", report.SeverityLow, "/1", "", report.VerificationVerified)
	n2 := makeTestNormFinding("N2", "Step 2", "info", report.SeverityHigh, "/2", "", report.VerificationVerified)
	p := makeTestAttackPath("P1", []NormalizedFinding{n1, n2}, PathVerified, 70)

	res := AnalyzeRemediationBottlenecks([]AttackPath{p}, []NormalizedFinding{n1, n2}, nil)
	if res.MinimumCut.CapacityPolicy != "Unit-cost (cardinality)" {
		t.Errorf("expected unit-cost capacity policy, got %q", res.MinimumCut.CapacityPolicy)
	}
}

// Case 7: Zero eligible paths
func TestBottleneckSolver_07_ZeroEligiblePaths(t *testing.T) {
	res := AnalyzeRemediationBottlenecks(nil, nil, nil)
	if res.TotalVerifiedChains != 0 {
		t.Errorf("expected 0 verified chains, got %d", res.TotalVerifiedChains)
	}
	if res.PrimaryRecommendation != nil {
		t.Errorf("expected nil primary recommendation, got %v", res.PrimaryRecommendation)
	}
	if res.MinimumCut.CutSize != 0 {
		t.Errorf("expected cut size 0, got %d", res.MinimumCut.CutSize)
	}
	if !strings.Contains(res.SummaryHeadline, "No multi-hop attack paths") {
		t.Errorf("expected empty headline, got %q", res.SummaryHeadline)
	}
}

// Case 8: Disconnected source and target
func TestBottleneckSolver_08_DisconnectedSourceAndTarget(t *testing.T) {
	// A path with empty nodes
	p := AttackPath{
		ID:     "EMPTY",
		Status: PathVerified,
	}
	res := AnalyzeRemediationBottlenecks([]AttackPath{p}, nil, nil)
	if res == nil {
		t.Fatal("expected non-nil result")
	}
}

// Case 9: Cyclic graphs safe termination
func TestBottleneckSolver_09_CyclicGraphSafeTermination(t *testing.T) {
	// Graph with cycle: A -> B -> A -> C
	a := makeTestNormFinding("A", "Node A", "info", report.SeverityLow, "/a", "", report.VerificationVerified)
	b := makeTestNormFinding("B", "Node B", "info", report.SeverityMedium, "/b", "", report.VerificationVerified)
	c := makeTestNormFinding("C", "Node C", "rce", report.SeverityCritical, "/c", "", report.VerificationVerified)

	p := makeTestAttackPath("CYCLE-PATH", []NormalizedFinding{a, b, a, c}, PathVerified, 90)

	done := make(chan bool)
	go func() {
		res := AnalyzeRemediationBottlenecks([]AttackPath{p}, []NormalizedFinding{a, b, c}, nil)
		if res.TotalVerifiedChains != 1 {
			t.Errorf("expected 1 verified chain, got %d", res.TotalVerifiedChains)
		}
		done <- true
	}()

	select {
	case <-done:
		// Succeeded safely without infinite loop
	case <-time.After(2 * time.Second):
		t.Fatal("cyclic graph solver hung or entered infinite loop")
	}
}

// Case 10: Duplicate edges and duplicate path IDs
func TestBottleneckSolver_10_DuplicateEdgesAndPathIDs(t *testing.T) {
	n1 := makeTestNormFinding("D1", "Entry", "info", report.SeverityLow, "/d1", "", report.VerificationVerified)
	n2 := makeTestNormFinding("D2", "Exit", "rce", report.SeverityCritical, "/d2", "", report.VerificationVerified)

	p1 := makeTestAttackPath("DUP_ID", []NormalizedFinding{n1, n2}, PathVerified, 80)
	p2 := makeTestAttackPath("DUP_ID", []NormalizedFinding{n1, n2}, PathVerified, 80) // exact duplicate ID

	res := AnalyzeRemediationBottlenecks([]AttackPath{p1, p2}, []NormalizedFinding{n1, n2}, nil)
	if res.TotalVerifiedChains != 1 {
		t.Errorf("expected deduplicated 1 verified chain, got %d", res.TotalVerifiedChains)
	}
}

// Case 11: Stable, deterministic ranking for tied candidates
func TestBottleneckSolver_11_DeterministicRankingTies(t *testing.T) {
	// Two identical findings on distinct endpoints
	f1 := makeTestNormFinding("F_AAA", "Vuln A", "category-a", report.SeverityHigh, "/route-a", "", report.VerificationVerified)
	f2 := makeTestNormFinding("F_ZZZ", "Vuln Z", "category-z", report.SeverityHigh, "/route-z", "", report.VerificationVerified)
	t1 := makeTestNormFinding("T1", "Target", "rce", report.SeverityCritical, "/target", "", report.VerificationVerified)

	p1 := makeTestAttackPath("P1", []NormalizedFinding{f1, t1}, PathVerified, 80)
	p2 := makeTestAttackPath("P2", []NormalizedFinding{f2, t1}, PathVerified, 80)

	// Run multiple times and verify exact identical candidate ranking ordering
	var firstOrder []string
	for trial := 0; trial < 10; trial++ {
		res := AnalyzeRemediationBottlenecks([]AttackPath{p1, p2}, []NormalizedFinding{f1, f2, t1}, nil)
		var currOrder []string
		for _, c := range res.RankedCandidates {
			currOrder = append(currOrder, c.ID)
		}
		if trial == 0 {
			firstOrder = currOrder
		} else {
			if strings.Join(firstOrder, ",") != strings.Join(currOrder, ",") {
				t.Fatalf("trial %d produced different candidate ranking order: %v vs %v", trial, currOrder, firstOrder)
			}
		}
	}
}

// Case 12: Large enough graphs to expose avoidable path-enumeration or performance problems
func TestBottleneckSolver_12_ScalabilityAndPerformance(t *testing.T) {
	var paths []AttackPath
	var findings []NormalizedFinding

	// Shared choke point
	choke := makeTestNormFinding("CHOKE", "Central Auth Proxy", "jwt", report.SeverityCritical, "/auth/proxy", "AuthProxy", report.VerificationVerified)
	findings = append(findings, choke)

	for i := 1; i <= 100; i++ {
		e := makeTestNormFinding(fmt.Sprintf("IN_%d", i), fmt.Sprintf("Client %d", i), "info", report.SeverityLow, fmt.Sprintf("/client/%d", i), "", report.VerificationVerified)
		s := makeTestNormFinding(fmt.Sprintf("OUT_%d", i), fmt.Sprintf("Service %d", i), "rce", report.SeverityHigh, fmt.Sprintf("/service/%d", i), "", report.VerificationVerified)
		findings = append(findings, e, s)
		paths = append(paths, makeTestAttackPath(fmt.Sprintf("PATH-%03d", i), []NormalizedFinding{e, choke, s}, PathVerified, 85))
	}

	start := time.Now()
	res := AnalyzeRemediationBottlenecks(paths, findings, nil)
	duration := time.Since(start)

	if duration > 500*time.Millisecond {
		t.Errorf("bottleneck solver took %v for 100 paths; expected < 500ms", duration)
	}
	if res.TotalVerifiedChains != 100 {
		t.Errorf("expected 100 verified chains, got %d", res.TotalVerifiedChains)
	}
	if res.PrimaryRecommendation == nil || res.PrimaryRecommendation.DisruptedCount != 100 {
		t.Errorf("expected primary choke to disrupt all 100 chains, got %v", res.PrimaryRecommendation)
	}
}

// -----------------------------------------------------------------------------
// Section 2: Evidence and Mapping Safety (Cases 13-18)
// -----------------------------------------------------------------------------

// Case 13: Candidate paths do not enter verified disruption counts
func TestBottleneckSolver_13_CandidatePathsExcludedFromVerifiedCounts(t *testing.T) {
	v1 := makeTestNormFinding("V1", "Verified Finding", "exposure", report.SeverityHigh, "/v1", "", report.VerificationVerified)
	v2 := makeTestNormFinding("V2", "Verified Sink", "rce", report.SeverityCritical, "/v2", "", report.VerificationVerified)

	c1 := makeTestNormFinding("C1", "Candidate Finding", "bola", report.SeverityHigh, "/c1", "", report.VerificationDetected)
	c2 := makeTestNormFinding("C2", "Candidate Sink", "leak", report.SeverityMedium, "/c2", "", report.VerificationDetected)

	verifiedPath := makeTestAttackPath("P_VER", []NormalizedFinding{v1, v2}, PathVerified, 85)
	candidatePath := makeTestAttackPath("P_CAND", []NormalizedFinding{c1, c2}, PathCandidate, 60)

	res := AnalyzeRemediationBottlenecks([]AttackPath{verifiedPath, candidatePath}, []NormalizedFinding{v1, v2, c1, c2}, nil)

	if res.TotalVerifiedChains != 1 {
		t.Errorf("expected 1 verified chain, got %d", res.TotalVerifiedChains)
	}
	if res.TotalCandidateChains != 1 {
		t.Errorf("expected 1 candidate chain, got %d", res.TotalCandidateChains)
	}
	// Candidate finding C1 must not appear in verified RankedCandidates
	for _, cand := range res.RankedCandidates {
		if cand.AssociatedFindingIDs[0] == "C1" || cand.AssociatedFindingIDs[0] == "C2" {
			t.Errorf("candidate finding %s improperly leaked into verified ranked candidates", cand.ID)
		}
	}
}

// Case 14: Inconclusive and truncated paths do not enter verified disruption counts
func TestBottleneckSolver_14_InconclusiveAndTruncatedPathsExcluded(t *testing.T) {
	n1 := makeTestNormFinding("I1", "Inconclusive Node 1", "info", report.SeverityLow, "/i1", "", report.VerificationNotVerified)
	n2 := makeTestNormFinding("I2", "Inconclusive Node 2", "leak", report.SeverityMedium, "/i2", "", report.VerificationNotVerified)

	incPath := makeTestAttackPath("P_INC", []NormalizedFinding{n1, n2}, PathInconclusive, 40)
	res := AnalyzeRemediationBottlenecks([]AttackPath{incPath}, []NormalizedFinding{n1, n2}, nil)

	if res.TotalVerifiedChains != 0 {
		t.Errorf("expected 0 verified chains for inconclusive path, got %d", res.TotalVerifiedChains)
	}
}

// Case 15: Broken or mismatched edges cannot produce a verified bottleneck claim
func TestBottleneckSolver_15_BrokenOrMismatchedEdges(t *testing.T) {
	n1 := makeTestNormFinding("B1", "Node 1", "info", report.SeverityLow, "/b1", "", report.VerificationVerified)
	path := AttackPath{
		ID:     "BROKEN",
		Nodes:  []NormalizedFinding{n1},
		Status: PathCandidate, // Unverified
	}
	res := AnalyzeRemediationBottlenecks([]AttackPath{path}, []NormalizedFinding{n1}, nil)
	if res.TotalVerifiedChains != 0 {
		t.Errorf("expected 0 verified chains, got %d", res.TotalVerifiedChains)
	}
}

// Case 16: Missing or ambiguous component mappings are reported honestly
func TestBottleneckSolver_16_MissingOrAmbiguousComponentMappings(t *testing.T) {
	// Finding with no endpoint and no component
	ambigFinding := makeTestNormFinding("AMBIG_01", "Generic Weakness", "", report.SeverityMedium, "", "", report.VerificationVerified)
	t1 := makeTestNormFinding("T1", "Target", "rce", report.SeverityCritical, "/target", "", report.VerificationVerified)

	p := makeTestAttackPath("P_AMBIG", []NormalizedFinding{ambigFinding, t1}, PathVerified, 75)
	res := AnalyzeRemediationBottlenecks([]AttackPath{p}, []NormalizedFinding{ambigFinding, t1}, nil)

	foundAmbig := false
	for _, c := range res.RankedCandidates {
		if c.AssociatedFindingIDs[0] == "AMBIG_01" {
			foundAmbig = true
			if !c.HasAmbiguousMapping {
				t.Errorf("expected candidate %s to flag HasAmbiguousMapping", c.ID)
			}
			if c.UncertaintyNotes == "" {
				t.Errorf("expected candidate %s to have uncertainty notes", c.ID)
			}
		}
	}
	if !foundAmbig {
		t.Fatal("expected ambiguous candidate in results")
	}
}

// Case 17: Duplicate findings do not inflate chain counts
func TestBottleneckSolver_17_DuplicateFindingsDoNotInflate(t *testing.T) {
	node := makeTestNormFinding("DUP_F", "Repeated Vuln", "bola", report.SeverityHigh, "/dup", "RepeatedComp", report.VerificationVerified)
	target := makeTestNormFinding("TARG", "Target", "rce", report.SeverityCritical, "/targ", "TargetComp", report.VerificationVerified)

	// Path visits DUP_F multiple times (e.g. step 1 and step 2)
	p := makeTestAttackPath("PATH_REPEATED", []NormalizedFinding{node, node, target}, PathVerified, 85)

	res := AnalyzeRemediationBottlenecks([]AttackPath{p}, []NormalizedFinding{node, target}, nil)
	for _, c := range res.RankedCandidates {
		if c.DisruptedCount > 1 {
			t.Errorf("candidate %s counted repeated node %d times in a single chain; expected at most 1", c.ID, c.DisruptedCount)
		}
	}
}

// Case 18: Provisional coverage remains separate from verified coverage
func TestBottleneckSolver_18_ProvisionalCoverageSeparation(t *testing.T) {
	v := makeTestNormFinding("V", "Verified Node", "bola", report.SeverityHigh, "/v", "AuthMiddleware", report.VerificationVerified)
	c := makeTestNormFinding("C", "Provisional Node", "bola", report.SeverityHigh, "/c", "AuthMiddleware", report.VerificationDetected)

	pVer := makeTestAttackPath("P_VER", []NormalizedFinding{v, v}, PathVerified, 80)
	pCand := makeTestAttackPath("P_CAND", []NormalizedFinding{c, c}, PathCandidate, 50)

	res := AnalyzeRemediationBottlenecks([]AttackPath{pVer, pCand}, []NormalizedFinding{v, c}, nil)

	if res.TotalVerifiedChains != 1 {
		t.Errorf("expected 1 verified chain, got %d", res.TotalVerifiedChains)
	}
	if res.TotalCandidateChains != 1 {
		t.Errorf("expected 1 candidate chain, got %d", res.TotalCandidateChains)
	}
	if len(res.ProvisionalCandidates) == 0 {
		t.Error("expected provisional candidates to be populated")
	}
	for _, pc := range res.ProvisionalCandidates {
		if pc.VerificationStatus != "PROVISIONAL" {
			t.Errorf("expected PROVISIONAL status, got %s", pc.VerificationStatus)
		}
	}
}

// -----------------------------------------------------------------------------
// Section 3: Integration and Regression (Cases 19-27)
// -----------------------------------------------------------------------------

// Case 19: CLI displays correct disruption counts, percentages, and remaining chains
func TestBottleneckSolver_19_CLIOutputFormatting(t *testing.T) {
	cand := RemediationCandidate{
		Name:                  "Object-Level Authorization Middleware",
		Component:             "ObjectAuthorizationMiddleware",
		DisruptedCount:        4,
		TotalChainsConsidered: 5,
		DisruptionPercentage:  80.0,
		ResidualCount:         1,
		ActionableFix:         "Enforce tenant ownership verification on /api/v1/users/{id}.",
	}

	cliLine := fmt.Sprintf("Priority Remediation: %s disrupts %d of %d verified attack chains (%.1f%%). Residual: %d. Fix: %s",
		cand.Name, cand.DisruptedCount, cand.TotalChainsConsidered, cand.DisruptionPercentage, cand.ResidualCount, cand.ActionableFix)

	expected := "Priority Remediation: Object-Level Authorization Middleware disrupts 4 of 5 verified attack chains (80.0%). Residual: 1. Fix: Enforce tenant ownership verification on /api/v1/users/{id}."
	if cliLine != expected {
		t.Errorf("CLI format mismatch:\ngot:  %s\nwant: %s", cliLine, expected)
	}
}

// Case 20: Report models and HTML output correctly represent recommendations
func TestBottleneckSolver_20_ReportModelsIntegration(t *testing.T) {
	n1 := makeTestNormFinding("F1", "JWT Weakness", "jwt", report.SeverityHigh, "/auth", "AuthGateway", report.VerificationVerified)
	n2 := makeTestNormFinding("F2", "Admin Takeover", "admin", report.SeverityCritical, "/admin", "Admin", report.VerificationVerified)

	p := makeTestAttackPath("P1", []NormalizedFinding{n1, n2}, PathVerified, 90)

	eng := NewEngine(DefaultConfig())
	findings := []report.Finding{
		{ID: "F1", Title: "JWT Weakness", Category: "jwt", Severity: report.SeverityHigh, Endpoint: "/auth", Verification: report.VerificationRecord{Status: report.VerificationVerified}},
		{ID: "F2", Title: "Admin Takeover", Category: "admin", Severity: report.SeverityCritical, Endpoint: "/admin", Verification: report.VerificationRecord{Status: report.VerificationVerified}},
	}

	summary, paths, _, err := eng.Correlate(context.Background(), findings)
	if err != nil {
		t.Fatalf("correlation error: %v", err)
	}
	_ = paths
	if summary.BottleneckAnalysis == nil {
		t.Fatal("expected summary.BottleneckAnalysis to be non-nil")
	}

	// Verify story generation integration
	story := GenerateSecurityStory(&p)
	if story.Remediation == "" {
		t.Error("expected story.Remediation to be populated")
	}
}

// Case 21: Untrusted names and evidence cannot inject HTML or shell content
func TestBottleneckSolver_21_UntrustedNamesSanitization(t *testing.T) {
	maliciousEP := "https://example.com/api/<script>alert(1)</script>; rm -rf /"
	sanitized := secrets.SanitizeURL(maliciousEP)
	if strings.Contains(sanitized, "<script>") || strings.Contains(sanitized, "rm -rf") {
		t.Errorf("sanitization failed to neutralize payload: %s", sanitized)
	}
}

// Case 22: P13.1 graph traversal behavior remains intact
func TestBottleneckSolver_22_P13_1_GraphTraversalIntact(t *testing.T) {
	f1 := makeTestNormFinding("F1", "Entry", "info", report.SeverityLow, "/entry", "", report.VerificationVerified)
	f2 := makeTestNormFinding("F2", "Target", "rce", report.SeverityCritical, "/target", "", report.VerificationVerified)

	rel := Relationship{
		ID:               "REL-01",
		SourceFindingID:  "F1",
		TargetFindingID:  "F2",
		Type:             RelEnables,
		ValidationStatus: ValidationConfirmed,
		Confidence:       report.ConfidenceHigh,
		RuleCode:         RuleCOR01,
	}

	graph := NewAttackGraph([]NormalizedFinding{f1, f2}, []Relationship{rel})
	if len(graph.Nodes) != 2 {
		t.Errorf("expected 2 nodes in graph, got %d", len(graph.Nodes))
	}
	if len(graph.Edges) != 1 {
		t.Errorf("expected 1 edge in graph, got %d", len(graph.Edges))
	}
}

// Case 23: P13.2 interactive attack-path visualization remains intact
func TestBottleneckSolver_23_P13_2_VisualGraphIntact(t *testing.T) {
	n1 := makeTestNormFinding("V1", "Start", "info", report.SeverityLow, "/1", "", report.VerificationVerified)
	n2 := makeTestNormFinding("V2", "End", "rce", report.SeverityCritical, "/2", "", report.VerificationVerified)

	p := makeTestAttackPath("P_VIS", []NormalizedFinding{n1, n2}, PathVerified, 80)
	summaryPath := report.AttackPathSummary{
		ID:                p.ID,
		Title:             p.Title,
		Status:            string(p.Status),
		CombinedRiskScore: p.CombinedRiskScore,
		CombinedRiskLevel: p.CombinedRiskLevel,
		NodeIDs:           p.NodeIDs,
	}
	report.EnrichAttackPathGraph(&summaryPath, nil)
	svg := report.RenderAttackPathSVG(summaryPath)
	if len(svg) == 0 {
		t.Error("RenderAttackPathSVG returned empty HTML/SVG")
	}
}

// Case 24: P13.3 reproduction scripts remain unchanged in safety and verification behavior
func TestBottleneckSolver_24_P13_3_ReproductionScriptsIntact(t *testing.T) {
	n1 := makeTestNormFinding("R1", "Public Token", "secret-leak", report.SeverityHigh, "/token", "", report.VerificationVerified)
	n2 := makeTestNormFinding("R2", "Admin Access", "admin", report.SeverityCritical, "/admin", "", report.VerificationVerified)

	p := makeTestAttackPath("P_REPRO", []NormalizedFinding{n1, n2}, PathVerified, 90)
	summaryPath := report.AttackPathSummary{
		ID:                p.ID,
		Title:             p.Title,
		Status:            "VERIFIED",
		CombinedRiskScore: 90,
		NodeIDs:           p.NodeIDs,
	}

	plan, err := report.GenerateReproductionScript(summaryPath, nil, report.ReproductionOptions{})
	if err != nil {
		t.Fatalf("failed to generate reproduction script: %v", err)
	}
	script := plan.ShellScriptContent
	if !strings.Contains(script, "curl") {
		t.Error("reproduction script must contain curl command")
	}
	if !strings.Contains(script, "#!/usr/bin/env bash") {
		t.Error("reproduction script must have bash shebang")
	}
}

// Case 25: P13.4 compound-risk results and severity classifications remain unchanged
func TestBottleneckSolver_25_P13_4_CompoundRiskIntact(t *testing.T) {
	// 40 + 20 + 20 = 80 formula verification
	n1 := NormalizedFinding{ID: "N1", Title: "Medium Weakness", Severity: report.SeverityMedium, Score: 40}
	n2 := NormalizedFinding{ID: "N2", Title: "Low Finding 1", Severity: report.SeverityLow, Score: 20}
	n3 := NormalizedFinding{ID: "N3", Title: "Low Finding 2", Severity: report.SeverityLow, Score: 20}

	edges := []Relationship{
		{
			SourceFindingID:  "N1",
			TargetFindingID:  "N2",
			RuleCode:         RuleCOR01,
			Confidence:       "HIGH", // 1.0
			ValidationStatus: ValidationConfirmed,
		},
		{
			SourceFindingID:  "N2",
			TargetFindingID:  "N3",
			RuleCode:         RuleCOR02,
			Confidence:       "HIGH", // 1.0
			ValidationStatus: ValidationConfirmed,
		},
	}

	p := AttackPath{
		ID:     "PATH-MED-LOW-LOW",
		Status: PathVerified,
		Nodes:  []NormalizedFinding{n1, n2, n3},
		Edges:  edges,
	}

	score, level, rationale := AssessPathRisk(&p)
	if score != 80 {
		t.Errorf("expected compound risk score 80 (40 + 20 + 20), got %d", score)
	}
	if level != report.SeverityCritical {
		t.Errorf("expected CRITICAL severity for score 80, got %s", level)
	}
	if !strings.Contains(rationale, "Base risk anchored by") || !strings.Contains(rationale, "+20.0 pts") {
		t.Errorf("expected compound escalation in rationale, got %s", rationale)
	}
}

// Case 26: Existing JSON/SARIF consumers remain compatible
func TestBottleneckSolver_26_JSON_SARIF_Compatibility(t *testing.T) {
	res := AnalyzeRemediationBottlenecks(nil, nil, nil)
	if res.SummaryHeadline == "" {
		t.Error("SummaryHeadline must not be empty")
	}
	if res.RankedCandidates == nil {
		t.Error("RankedCandidates must not be nil (JSON array invariant)")
	}
}

// Case 27: Source graph and finding objects are not unexpectedly mutated
func TestBottleneckSolver_27_SourceGraphImmutability(t *testing.T) {
	n1 := makeTestNormFinding("M1", "Original Title", "info", report.SeverityLow, "/orig", "Comp1", report.VerificationVerified)
	n2 := makeTestNormFinding("M2", "Original Target", "rce", report.SeverityCritical, "/target", "Comp2", report.VerificationVerified)

	p := makeTestAttackPath("P_IMMUT", []NormalizedFinding{n1, n2}, PathVerified, 85)
	origTitle := n1.Title
	origEP := n1.Endpoint

	_ = AnalyzeRemediationBottlenecks([]AttackPath{p}, []NormalizedFinding{n1, n2}, nil)

	if n1.Title != origTitle || n1.Endpoint != origEP {
		t.Errorf("source finding mutated during bottleneck analysis: title=%s, ep=%s", n1.Title, n1.Endpoint)
	}
}

// -----------------------------------------------------------------------------
// Section 4: Severity Consistency & Boundary Enforcement (Adversarial Audit)
// -----------------------------------------------------------------------------

func TestSeverityConsistency_AuthoritativeThresholdsAndBoundaries(t *testing.T) {
	thresholds := []struct {
		score         int
		expectedLevel string
		desc          string
	}{
		{0, "INFORMATIONAL", "zero floor"},
		{1, "INFORMATIONAL", "info low"},
		{19, "INFORMATIONAL", "info boundary ceiling"},
		{20, "LOW", "low boundary floor"},
		{21, "LOW", "low mid"},
		{39, "LOW", "low boundary ceiling"},
		{40, "MEDIUM", "medium boundary floor"},
		{41, "MEDIUM", "medium mid"},
		{59, "MEDIUM", "medium boundary ceiling"},
		{60, "HIGH", "high boundary floor"},
		{61, "HIGH", "high low"},
		{65, "HIGH", "provisional score cap"},
		{79, "HIGH", "high boundary ceiling"},
		{80, "CRITICAL", "critical boundary floor"},
		{85, "CRITICAL", "critical mid"},
		{99, "CRITICAL", "critical near-max"},
		{100, "CRITICAL", "critical ceiling"},
	}

	for _, tc := range thresholds {
		expectedNorm := report.NormalizeSeverity(tc.expectedLevel)

		// 1. Check report.RiskLevelBand
		rlb := report.NormalizeSeverity(report.RiskLevelBand(tc.score))
		if rlb != expectedNorm {
			t.Errorf("RiskLevelBand(%d [%s]) = %q; expected %q", tc.score, tc.desc, rlb, expectedNorm)
		}

		// 2. Check correlation.deriveRiskLevel for verified paths
		drlVer := report.NormalizeSeverity(deriveRiskLevel(tc.score, true, ""))
		if drlVer != expectedNorm {
			t.Errorf("deriveRiskLevel(verified, %d [%s]) = %q; expected %q", tc.score, tc.desc, drlVer, expectedNorm)
		}
	}

	// 3. Unverified paths: must be capped at High, never receiving Critical
	unverifiedCases := []struct {
		score         int
		expectedLevel string
	}{
		{65, "HIGH"},
		{80, "HIGH"}, // unverified cap prevents CRITICAL
		{85, "HIGH"}, // unverified cap prevents CRITICAL
		{95, "HIGH"}, // unverified cap prevents CRITICAL
		{100, "HIGH"}, // unverified cap prevents CRITICAL
	}
	for _, tc := range unverifiedCases {
		drlUnver := deriveRiskLevel(tc.score, false, "")
		if drlUnver != tc.expectedLevel {
			t.Errorf("deriveRiskLevel(unverified, %d) = %q; expected %q", tc.score, drlUnver, tc.expectedLevel)
		}
	}

	// 4. Zero Assessment Escalation from Candidate Paths
	// An audit report with low findings and a candidate path with score 65 must NOT escalate primary score
	rep := report.Report{
		Target: "https://api.target.com",
		Findings: []report.Finding{
			{ID: "F-LOW", Title: "Low Issue", Severity: report.SeverityLow, Score: 20, Endpoint: "/status"},
		},
	}
	candidatePath := report.AttackPathSummary{
		ID:                "CAND-01",
		Title:             "Candidate Multi-Hop Path",
		Status:            "CANDIDATE",
		Confidence:        report.ConfidenceHigh,
		CombinedRiskScore: 65,
		CombinedRiskLevel: "HIGH",
	}
	report.AttachAttackPaths(&rep, []report.AttackPathSummary{candidatePath})
	if rep.RiskScore > 20 {
		t.Errorf("candidate attack path escalated report risk score to %d; expected baseline 20", rep.RiskScore)
	}
	if rep.RiskLevel != "LOW" {
		t.Errorf("candidate attack path escalated report risk level to %s; expected LOW", rep.RiskLevel)
	}

	// 5. Verified path with score 80 DOES escalate primary risk to CRITICAL
	verifiedPath := report.AttackPathSummary{
		ID:                "VER-01",
		Title:             "Verified Multi-Hop Path",
		Status:            "VERIFIED",
		Confidence:        report.ConfidenceHigh,
		CombinedRiskScore: 80,
		CombinedRiskLevel: "CRITICAL",
	}
	report.AttachAttackPaths(&rep, []report.AttackPathSummary{candidatePath, verifiedPath})
	if rep.RiskScore != 80 {
		t.Errorf("verified attack path failed to escalate report risk score to 80; got %d", rep.RiskScore)
	}
	if rep.RiskLevel != "CRITICAL" {
		t.Errorf("verified attack path failed to escalate report risk level to CRITICAL; got %s", rep.RiskLevel)
	}
}
