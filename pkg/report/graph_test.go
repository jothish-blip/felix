package report

import (
	"strings"
	"testing"
)

// TestRenderAttackPathSVG_MultiHop verifies that a multi-hop attack path (3+ nodes)
// renders clean SVG containing all nodes, labeled edges, rule badges, and markers.
func TestRenderAttackPathSVG_MultiHop(t *testing.T) {
	path := AttackPathSummary{
		ID:     "CHAIN-TEST-001",
		Title:  "JS Leak to Database Takeover",
		Status: "CONFIRMED",
		GraphNodes: []AttackPathNode{
			{
				ID:                 "F-001",
				Title:              "Client-Side Secret Leak in JS Bundle",
				Severity:           "HIGH",
				VerificationStatus: "VERIFIED",
				Category:           "Information Disclosure",
				Endpoint:           "https://target.com/app.js",
				EvidenceSummary:    "Found exposed internal API token in bundle",
				IsEntrypoint:       true,
			},
			{
				ID:                 "F-002",
				Title:              "Unauthenticated Shadow Route Access",
				Severity:           "CRITICAL",
				VerificationStatus: "VERIFIED",
				Category:           "Broken Access Control",
				Endpoint:           "https://target.com/api/v2/internal/admin",
				EvidenceSummary:    "Shadow route accessible using disclosed token",
			},
			{
				ID:                 "F-003",
				Title:              "BOLA / Object-Level Authorization Bypass",
				Severity:           "HIGH",
				VerificationStatus: "VERIFIED",
				Category:           "BOLA",
				Endpoint:           "https://target.com/api/v2/internal/admin/tenant/42",
				EvidenceSummary:    "Horizontal parameter tampering accessible",
			},
			{
				ID:                 "F-004",
				Title:              "SQL Injection leading to DB Takeover",
				Severity:           "CRITICAL",
				VerificationStatus: "VERIFIED",
				Category:           "Injection",
				Endpoint:           "https://target.com/api/v2/internal/admin/tenant/42/export",
				EvidenceSummary:    "Unsanitized input triggers syntax error in query",
				IsTarget:           true,
			},
		},
		GraphEdges: []AttackPathEdge{
			{
				ID:               "E-001",
				SourceID:         "F-001",
				TargetID:         "F-002",
				SourceTitle:      "Client-Side Secret Leak",
				TargetTitle:      "Shadow Route Access",
				RuleCode:         "COR-AUTH-LEAK",
				RuleName:         "Token Leakage to Shadow Route",
				ValidationStatus: "CONFIRMED",
				Confidence:       "HIGH",
				Explanation:      "Disclosed token authorizes access to internal shadow endpoint",
			},
			{
				ID:               "E-002",
				SourceID:         "F-002",
				TargetID:         "F-003",
				SourceTitle:      "Shadow Route Access",
				TargetTitle:      "BOLA Bypass",
				RuleCode:         "COR-BOLA-AUTH",
				RuleName:         "Shadow Route to Object Level Tampering",
				ValidationStatus: "CONFIRMED",
				Confidence:       "HIGH",
				Explanation:      "Admin route exposes tenant data without authorization barrier",
			},
			{
				ID:               "E-003",
				SourceID:         "F-003",
				TargetID:         "F-004",
				SourceTitle:      "BOLA Bypass",
				TargetTitle:      "SQL Injection",
				RuleCode:         "COR-INJ-EXPLOIT",
				RuleName:         "Tenant Parameter to Injection Sink",
				ValidationStatus: "CONFIRMED",
				Confidence:       "HIGH",
				Explanation:      "Tampered tenant identifier directly enters database query",
			},
		},
	}

	htmlContent := RenderAttackPathSVG(path)
	svgStr := string(htmlContent)

	if !strings.Contains(svgStr, "<svg") || !strings.Contains(svgStr, "</svg>") {
		t.Fatalf("expected valid <svg> block, got: %s", svgStr)
	}

	// Verify all nodes are rendered
	for _, n := range path.GraphNodes {
		if !strings.Contains(svgStr, n.ID) {
			t.Errorf("SVG missing node ID: %s", n.ID)
		}
		if !strings.Contains(svgStr, n.Title) {
			t.Errorf("SVG missing node Title: %s", n.Title)
		}
	}

	// Verify all edges and rule badges are rendered
	for _, e := range path.GraphEdges {
		if !strings.Contains(svgStr, string(e.RuleCode)) {
			t.Errorf("SVG missing rule code badge: %s", e.RuleCode)
		}
	}

	// Verify markers and interactive data attributes
	if !strings.Contains(svgStr, "marker-end=\"url(#arrow-confirmed)\"") {
		t.Errorf("SVG missing confirmed arrow marker")
	}
	if !strings.Contains(svgStr, "data-node-id=\"F-001\"") {
		t.Errorf("SVG missing interactive data-node-id attribute")
	}
	if !strings.Contains(svgStr, "ENTRY POINT") {
		t.Errorf("SVG missing ENTRY POINT badge on first node")
	}
	if !strings.Contains(svgStr, "TARGET ASSET") {
		t.Errorf("SVG missing TARGET ASSET badge on final node")
	}
}

// TestRenderAttackPathSVG_EdgeStyles verifies that confirmed, candidate, and inconclusive
// transitions render with proper dashed/dotted strokes and respective arrow markers.
func TestRenderAttackPathSVG_EdgeStyles(t *testing.T) {
	path := AttackPathSummary{
		ID:     "CHAIN-EDGE-TEST",
		Title:  "Mixed Edge Types",
		Status: "CANDIDATE",
		GraphNodes: []AttackPathNode{
			{ID: "N-1", Title: "Node 1", Severity: "HIGH"},
			{ID: "N-2", Title: "Node 2", Severity: "MEDIUM"},
			{ID: "N-3", Title: "Node 3", Severity: "LOW"},
		},
		GraphEdges: []AttackPathEdge{
			{
				ID:               "E-1",
				SourceID:         "N-1",
				TargetID:         "N-2",
				RuleCode:         "COR-CANDIDATE",
				ValidationStatus: "CANDIDATE",
				Confidence:       "MEDIUM",
			},
			{
				ID:               "E-2",
				SourceID:         "N-2",
				TargetID:         "N-3",
				RuleCode:         "COR-INCONCL",
				ValidationStatus: "INCONCLUSIVE",
				Confidence:       "LOW",
			},
		},
	}

	htmlContent := RenderAttackPathSVG(path)
	svgStr := string(htmlContent)

	// Candidate edge must have dashed stroke and candidate marker
	if !strings.Contains(svgStr, "stroke-dasharray=\"6,4\"") {
		t.Errorf("expected dashed stroke for candidate edge")
	}
	if !strings.Contains(svgStr, "marker-end=\"url(#arrow-candidate)\"") {
		t.Errorf("expected candidate marker for candidate edge")
	}

	// Inconclusive edge must have dotted stroke and inconclusive marker
	if !strings.Contains(svgStr, "stroke-dasharray=\"3,3\"") {
		t.Errorf("expected dotted stroke for inconclusive edge")
	}
	if !strings.Contains(svgStr, "marker-end=\"url(#arrow-inconclusive)\"") {
		t.Errorf("expected inconclusive marker for inconclusive edge")
	}
}

// TestRenderAttackPathSVG_XSSSanitization verifies that hostile HTML payloads
// inside node IDs, titles, endpoints, and evidence summaries are strictly escaped.
func TestRenderAttackPathSVG_XSSSanitization(t *testing.T) {
	hostilePath := AttackPathSummary{
		ID:     "CHAIN-XSS",
		Title:  "<script>alert('pwn')</script>",
		Status: "CONFIRMED",
		GraphNodes: []AttackPathNode{
			{
				ID:                 "N-XSS\" onclick=\"alert(1)",
				Title:              "Hostile <img src=x onerror=alert(1)>",
				Severity:           "HIGH",
				Category:           "<b>Bold</b>",
				Endpoint:           "https://target.com/?q=<script>",
				EvidenceSummary:    "Raw alert('secret') & payload <test>",
				VerificationStatus: "VERIFIED",
			},
			{
				ID:                 "N-TARGET",
				Title:              "Normal Target Node",
				Severity:           "MEDIUM",
				VerificationStatus: "VERIFIED",
			},
		},
		GraphEdges: []AttackPathEdge{
			{
				ID:               "E-XSS",
				SourceID:         "N-XSS\" onclick=\"alert(1)",
				TargetID:         "N-TARGET",
				RuleCode:         "<RULE>",
				RuleName:         "Rule & Exploit",
				ValidationStatus: "CONFIRMED",
				Explanation:      "Exploit: <i>critical</i> & \"unescaped\"",
			},
		},
	}

	htmlContent := RenderAttackPathSVG(hostilePath)
	svgStr := string(htmlContent)

	// Unescaped script tags, img tags, or unescaped quotes in attributes MUST NOT appear
	if strings.Contains(svgStr, "<script>") {
		t.Errorf("raw <script> tag detected in SVG output!")
	}
	if strings.Contains(svgStr, "<img src=x") {
		t.Errorf("raw <img onerror> tag detected in SVG output!")
	}
	if strings.Contains(svgStr, "<b>Bold</b>") {
		t.Errorf("raw <b> tag detected in SVG output!")
	}
	if strings.Contains(svgStr, "<i>critical</i>") {
		t.Errorf("raw <i> tag detected in SVG output!")
	}

	// Must be properly escaped
	if !strings.Contains(svgStr, "&lt;script&gt;") && !strings.Contains(svgStr, "&lt;img") {
		t.Errorf("expected escaped entities in SVG output")
	}
	if !strings.Contains(svgStr, "&amp;") {
		t.Errorf("expected escaped ampersand in SVG output")
	}
}

// TestEnrichAttackPathGraph_BackwardCompatibility verifies that legacy paths lacking
// GraphNodes and GraphEdges are seamlessly reconstructed from Transitions and Findings.
func TestEnrichAttackPathGraph_BackwardCompatibility(t *testing.T) {
	findings := []Finding{
		{ID: "LEGACY-01", Title: "Entry Flaw", Severity: "HIGH", Category: "Auth", Endpoint: "/login", Evidence: "Token leaked"},
		{ID: "LEGACY-02", Title: "Pivot Flaw", Severity: "CRITICAL", Category: "Access", Endpoint: "/api/pivot", Evidence: "Privilege escalated"},
		{ID: "LEGACY-03", Title: "Final Impact", Severity: "CRITICAL", Category: "RCE", Endpoint: "/api/exec", Evidence: "Arbitrary command executed"},
	}

	legacyPath := AttackPathSummary{
		ID:    "CHAIN-LEGACY",
		Title: "Legacy Correlation",
		Transitions: []string{
			"Token leaked at /login",
			"Privilege escalated at /api/pivot",
			"Arbitrary command executed at /api/exec",
		},
	}

	EnrichAttackPathGraph(&legacyPath, findings)

	if len(legacyPath.GraphNodes) != 3 {
		t.Fatalf("expected 3 enriched GraphNodes, got %d", len(legacyPath.GraphNodes))
	}
	if len(legacyPath.GraphEdges) != 2 {
		t.Fatalf("expected 2 enriched GraphEdges, got %d", len(legacyPath.GraphEdges))
	}

	if legacyPath.GraphNodes[0].ID != "LEGACY-01" || !legacyPath.GraphNodes[0].IsEntrypoint {
		t.Errorf("expected first node to be LEGACY-01 entrypoint")
	}
	if legacyPath.GraphNodes[2].ID != "LEGACY-03" || !legacyPath.GraphNodes[2].IsTarget {
		t.Errorf("expected third node to be LEGACY-03 target")
	}

	// Ensure SVG renders without panic or error
	svgContent := RenderAttackPathSVG(legacyPath)
	if !strings.Contains(string(svgContent), "<svg") {
		t.Errorf("enriched legacy path failed to render SVG")
	}
}

// TestGenerateHTML_AttackPathGraphIntegration tests that standard and commercial
// HTML generators include the interactive attack path graph and inspector components.
func TestGenerateHTML_AttackPathGraphIntegration(t *testing.T) {
	rep := Report{
		Target: "https://target.com",
		Summary: Summary{
			TotalFindings: 2,
			CriticalCount: 1,
			HighCount:     1,
		},
		RiskLevel: "CRITICAL",
		RiskScore: 92,
		Findings: []Finding{
			{
				ID:       "FIND-01",
				Title:    "Secret Leak",
				Severity: "HIGH",
				Verification: VerificationRecord{
					Status: VerificationVerified,
				},
				Evidence: "Secret found in script",
			},
			{
				ID:       "FIND-02",
				Title:    "Admin Bypass",
				Severity: "CRITICAL",
				Verification: VerificationRecord{
					Status: VerificationVerified,
				},
				Evidence: "Bypassed admin gate",
			},
		},
		AttackPaths: []AttackPathSummary{
			{
				ID:    "AP-01",
				Title: "Admin Takeover Path",
				Status: "CONFIRMED",
				GraphNodes: []AttackPathNode{
					{ID: "FIND-01", Title: "Secret Leak", Severity: "HIGH", IsEntrypoint: true},
					{ID: "FIND-02", Title: "Admin Bypass", Severity: "CRITICAL", IsTarget: true},
				},
				GraphEdges: []AttackPathEdge{
					{
						ID:               "E-01",
						SourceID:         "FIND-01",
						TargetID:         "FIND-02",
						RuleCode:         "COR-AUTH",
						ValidationStatus: "CONFIRMED",
						Confidence:       "HIGH",
						Explanation:      "Secret unlocks bypass",
					},
				},
			},
		},
	}

	// 1. Test Standard HTML
	stdHTML, err := GenerateHTML(rep)
	if err != nil {
		t.Fatalf("GenerateHTML failed: %v", err)
	}

	expectedStandardSnippets := []string{
		"attack-graph-grid",
		"graph-canvas-card",
		"svg-scroll-container",
		"graph-inspector-card",
		"inspector-reset-btn",
		"id=\"finding-FIND-01\"",
		"id=\"finding-FIND-02\"",
		"function switchAttackPath",
		"function selectGraphNode",
		"function selectGraphEdge",
		"function navigateToFinding",
	}

	for _, snippet := range expectedStandardSnippets {
		if !strings.Contains(stdHTML, snippet) {
			t.Errorf("Standard HTML missing snippet: %s", snippet)
		}
	}

	// 2. Test Commercial HTML
	commReport := BuildCommercialReport(rep)

	commHTML, err := GenerateCommercialHTML(commReport)
	if err != nil {
		t.Fatalf("GenerateCommercialHTML failed: %v", err)
	}

	expectedCommercialSnippets := []string{
		"attack-graph-grid",
		"graph-canvas-card",
		"graph-inspector-card",
		"id=\"finding-FIND-01\"",
		"id=\"finding-FIND-02\"",
		"function switchAttackPath",
		"function selectGraphNode",
		"function selectGraphEdge",
		"function navigateToFinding",
	}

	for _, snippet := range expectedCommercialSnippets {
		if !strings.Contains(commHTML, snippet) {
			t.Errorf("Commercial HTML missing snippet: %s", snippet)
		}
	}

	// 3. Test Offline Guarantee: No external CDNs/fonts
	externalCDNs := []string{
		"fonts.googleapis.com",
		"cdnjs.cloudflare.com",
		"cdn.jsdelivr.net",
		"unpkg.com",
	}
	for _, cdn := range externalCDNs {
		if strings.Contains(stdHTML, cdn) {
			t.Errorf("Standard HTML violates offline constraint by referencing: %s", cdn)
		}
		if strings.Contains(commHTML, cdn) {
			t.Errorf("Commercial HTML violates offline constraint by referencing: %s", cdn)
		}
	}
}

// TestGenerateHTML_EmptyAttackPaths verifies the empty state presentation when
// no multi-hop attack paths were established.
func TestGenerateHTML_EmptyAttackPaths(t *testing.T) {
	rep := Report{
		Target: "https://empty-chains.com",
		Summary: Summary{
			TotalFindings: 1,
			LowCount:      1,
		},
		RiskLevel: "LOW",
		RiskScore: 15,
		Findings: []Finding{
			{ID: "F-01", Title: "Informational Finding", Severity: "LOW"},
		},
		AttackPaths: []AttackPathSummary{},
	}

	stdHTML, err := GenerateHTML(rep)
	if err != nil {
		t.Fatalf("GenerateHTML failed: %v", err)
	}

	if !strings.Contains(stdHTML, "empty-graph-card") {
		t.Errorf("Standard HTML missing empty-graph-card when AttackPaths is empty")
	}
	if !strings.Contains(stdHTML, "No Evidence-Supported Multi-Hop Attack Paths Detected") {
		t.Errorf("Standard HTML missing empty state title")
	}

	commReport := BuildCommercialReport(rep)
	commHTML, err := GenerateCommercialHTML(commReport)
	if err != nil {
		t.Fatalf("GenerateCommercialHTML failed: %v", err)
	}

	if !strings.Contains(commHTML, "empty-graph-card") {
		t.Errorf("Commercial HTML missing empty-graph-card when AttackPaths is empty")
	}
}
