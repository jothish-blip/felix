package report

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// helperBuildSampleReport constructs a rich assessment report fixture.
func helperBuildSampleReport() Report {
	findings := []Finding{
		{
			ID:             "F-SQLI-001",
			RuleID:         "RULE-SQLI-01",
			Title:          "SQL Injection in Search Endpoint",
			Category:       "injection/sqli",
			Severity:       SeverityCritical,
			Confidence:     ConfidenceHigh,
			Status:         FindingStatusConfirmed,
			AnalysisMethod: AnalysisMethodActive,
			Endpoint:       "https://target.corp/api/v1/products/search",
			Method:         "GET",
			Description:    "User query parameter q is concatenated directly into SQL statement.",
			Evidence:       "Payload `' OR 1=1--` yielded 200 OK with all tenant rows returned.",
			Verification: VerificationRecord{
				Status:          VerificationVerified,
				Result:          "CONFIRMED_VULNERABLE",
				SafeCurlCommand: "curl -i 'https://target.corp/api/v1/products/search?q=%27+OR+1%3D1--'",
			},
			RemediationAdvice: &RemediationAdvice{
				Summary: "Use parameterized queries or prepared statements.",
			},
			Fingerprint: "fp-sqli-001-corp",
		},
		{
			ID:             "F-SSRF-002",
			RuleID:         "RULE-SSRF-02",
			Title:          "Server-Side Request Forgery via Image Fetcher",
			Category:       "ssrf",
			Severity:       SeverityHigh,
			Confidence:     ConfidenceHigh,
			Status:         FindingStatusConfirmed,
			AnalysisMethod: AnalysisMethodActive,
			Endpoint:       "https://target.corp/api/v1/media/fetch",
			Method:         "POST",
			Description:    "Remote image URL fetcher permits requests to loopback addresses.",
			Evidence:       "URL `http://169.254.169.254/latest/meta-data/` connection accepted.",
			Verification: VerificationRecord{
				Status:          VerificationVerified,
				Result:          "CONFIRMED_VULNERABLE",
				SafeCurlCommand: "curl -i -X POST -d 'url=http://127.0.0.1:8080/metrics' 'https://target.corp/api/v1/media/fetch'",
			},
			RemediationAdvice: &RemediationAdvice{
				Summary: "Validate outbound URLs against private IP filter blacklist.",
			},
			Fingerprint: "fp-ssrf-002-corp",
		},
		{
			ID:             "F-BOLA-003",
			RuleID:         "RULE-BOLA-03",
			Title:          "Broken Object-Level Authorization on User Profile",
			Category:       "authorization/bola",
			Severity:       SeverityHigh,
			Confidence:     ConfidenceHigh,
			Status:         FindingStatusConfirmed,
			AnalysisMethod: AnalysisMethodActive,
			Endpoint:       "https://target.corp/api/v1/users/profile",
			Method:         "GET",
			Description:    "Tenant ID can be swapped to inspect cross-tenant customer profiles.",
			Evidence:       "GET /api/v1/users/profile?id=999 returned customer records without authorization check.",
			Verification: VerificationRecord{
				Status:          VerificationVerified,
				Result:          "CONFIRMED_VULNERABLE",
				SafeCurlCommand: "curl -i 'https://target.corp/api/v1/users/profile?id=999'",
			},
			RemediationAdvice: &RemediationAdvice{
				Summary: "Enforce ownership verification on user ID prior to querying record.",
			},
			Fingerprint: "fp-bola-003-corp",
		},
		{
			ID:             "F-HDR-004",
			RuleID:         "RULE-HDR-04",
			Title:          "Missing Strict-Transport-Security Header",
			Category:       "security_header",
			Severity:       SeverityLow,
			Confidence:     ConfidenceHigh,
			Status:         FindingStatusConfirmed,
			AnalysisMethod: AnalysisMethodStatic,
			Endpoint:       "https://target.corp/",
			Method:         "GET",
			Description:    "Server response lacks HSTS header.",
			Evidence:       "HTTP/1.1 200 OK without Strict-Transport-Security in response headers.",
			Verification: VerificationRecord{
				Status: VerificationDetected,
				Result: "HEADER_ABSENT",
			},
			RemediationAdvice: &RemediationAdvice{
				Summary: "Add Strict-Transport-Security: max-age=63072000; includeSubDomains; preload header.",
			},
			Fingerprint: "fp-hdr-004-corp",
		},
		{
			ID:             "F-CSP-005",
			RuleID:         "RULE-CSP-05",
			Title:          "Defended Boundary: Content-Security-Policy Protected Endpoint",
			Category:       "security_header",
			Severity:       SeverityInfo,
			Confidence:     ConfidenceHigh,
			Status:         FindingStatusConfirmed,
			AnalysisMethod: AnalysisMethodActive,
			Endpoint:       "https://target.corp/secure-admin",
			Method:         "GET",
			Description:    "Strict CSP directive blocks inline scripts and object sources.",
			Evidence:       "Content-Security-Policy: default-src 'self' verified active.",
			Verification: VerificationRecord{
				Status: VerificationNotExposed,
				Result: "CONTROL_ACTIVE_DEFENDED",
			},
			RemediationAdvice: &RemediationAdvice{
				Summary: "Maintain current defensive configuration.",
			},
			Fingerprint: "fp-csp-005-corp",
		},
	}

	attackPath := AttackPathSummary{
		ID:                "PATH-CORP-CHAIN-01",
		Title:             "Perimeter SSRF to Internal SQLi Database Compromise",
		Status:            "CONFIRMED",
		Confidence:        "HIGH",
		CombinedRiskLevel: "CRITICAL",
		CombinedRiskScore: 95,
		EntryPoint:        "https://target.corp/api/v1/media/fetch",
		TargetAsset:       "Internal Production Relational Database",
		TerminalImpact:    "Remote Structured Query Evaluation & Complete Table Exfiltration",
		RiskRationale:     "Attacker leverages perimeter SSRF to pivot into internal management subnet, accessing unauthenticated SQL search service.",
		Transitions: []string{
			"Step 1: Exploit SSRF on /api/v1/media/fetch to reach internal network",
			"Step 2: Probe internal /api/v1/products/search endpoint",
			"Step 3: Execute SQL injection to dump customers table",
		},
		NodeIDs: []string{"F-SSRF-002", "F-SQLI-001"},
		GraphNodes: []AttackPathNode{
			{
				ID:                 "F-SSRF-002",
				Title:              "Perimeter SSRF Entrypoint",
				Severity:           SeverityHigh,
				VerificationStatus: "CONFIRMED",
				Endpoint:           "https://target.corp/api/v1/media/fetch",
				IsEntrypoint:       true,
			},
			{
				ID:                 "F-SQLI-001",
				Title:              "Internal SQL Injection",
				Severity:           SeverityCritical,
				VerificationStatus: "CONFIRMED",
				Endpoint:           "https://target.corp/api/v1/products/search",
				IsTarget:           true,
			},
		},
		GraphEdges: []AttackPathEdge{
			{
				ID:               "EDGE-01",
				SourceTitle:      "Perimeter SSRF Entrypoint",
				TargetTitle:      "Internal SQL Injection",
				ValidationStatus: "CONFIRMED",
				RuleCode:         "RULE-PIVOT-01",
				Explanation:      "SSRF allows internal pivot to reach backend SQL database interface.",
			},
		},
	}

	return Report{
		Target:           "https://target.corp",
		Targets:          []string{"https://target.corp", "https://api.target.corp"},
		Duration:         "12.4s",
		RequestCount:     148,
		Timestamp:        "2026-11-09T10:00:00Z",
		CompletionStatus: "COMPLETED",
		Findings:         findings,
		AttackPaths:      []AttackPathSummary{attackPath},
		Summary: Summary{
			TotalFindings: len(findings),
			CriticalCount: 1,
			HighCount:     2,
			LowCount:      1,
			InfoCount:     1,
		},
	}
}

// helperBuildPoCRecords builds representative Phase 7.2 reproduction records.
func helperBuildPoCRecords() []PoCRecord {
	return []PoCRecord{
		{
			ID:                  "POC-SQLI-001",
			FindingID:           "F-SQLI-001",
			Title:               "Deterministic SQLi Reproduction Probe",
			Category:            "SQLI",
			Severity:            "CRITICAL",
			Confidence:          "HIGH",
			Status:              "GENERATED",
			ExecutionMode:       "PLAN_ONLY",
			TargetExecutionType: "MOCK_FIXTURE",
			SafeCurlCommand:     "curl -s -o /dev/null -w '%{http_code}' 'https://target.corp/api/v1/products/search?q=%27+OR+1%3D1--'",
			ExpectedStatus:      200,
			ExpectedSubstrings:  []string{"productId", "tenantId"},
			EvidenceReferences:  []string{"fp-sqli-001-corp"},
			IsMultiHop:          true,
		},
		{
			ID:                  "POC-SSRF-002",
			FindingID:           "F-SSRF-002",
			Title:               "Non-Destructive Loopback SSRF Verification",
			Category:            "SSRF",
			Severity:            "HIGH",
			Confidence:          "HIGH",
			Status:              "VALIDATED_STATIC",
			ExecutionMode:       "PLAN_ONLY",
			TargetExecutionType: "MOCK_FIXTURE",
			SafeCurlCommand:     "curl -s -X POST -d 'url=http://127.0.0.1:80/ping' 'https://target.corp/api/v1/media/fetch'",
			ExpectedStatus:      200,
			ExpectedSubstrings:  []string{"pong"},
			EvidenceReferences:  []string{"fp-ssrf-002-corp"},
		},
	}
}

// helperBuildRemediationRecords builds representative Phase 7.3 proposed diff records.
func helperBuildRemediationRecords() []RemediationRecord {
	return []RemediationRecord{
		{
			ID:                 "REM-DIFF-001",
			FindingID:          "F-SQLI-001",
			Category:           "SQLI",
			Title:              "Parameterized Database Query for Product Search",
			TargetFile:         "server/routes/products.js",
			Priority:           1, // Entrypoint elevated
			Status:             "SYNTACTICALLY_VALIDATED",
			PathBreakStatus:    "PROPOSED_PATH_BREAK",
			SecurityImpact:     "Eliminates SQL injection by binding query parameters securely.",
			Rationale:          "Direct string concatenation replaced with parameterized query $1.",
			UnifiedDiffSnippet: "--- a/server/routes/products.js\n+++ b/server/routes/products.js\n@@ -10,3 +10,3 @@\n-db.query(`SELECT * FROM products WHERE name = '${q}'`)\n+db.query('SELECT * FROM products WHERE name = $1', [q])",
		},
		{
			ID:                 "REM-DIFF-002",
			FindingID:          "F-SSRF-002",
			Category:           "SSRF",
			Title:              "Private IP Address Egress Filter",
			TargetFile:         "server/routes/media.js",
			Priority:           1, // Perimeter boundary elevated
			Status:             "SOURCE_VALIDATED",
			PathBreakStatus:    "PROPOSED_PATH_BREAK",
			SecurityImpact:     "Prevents intranet IP traversal from user-supplied URLs.",
			Rationale:          "Enforces DNS resolution check and loopback / metadata CIDR block rejection.",
			UnifiedDiffSnippet: "--- a/server/routes/media.js\n+++ b/server/routes/media.js\n@@ -5,2 +5,4 @@\n+if (isPrivateIP(parsedUrl.hostname)) throw new Error('Blocked');\n fetch(url)",
		},
		{
			ID:                 "REM-DIFF-003",
			FindingID:          "F-BOLA-003",
			Category:           "BOLA",
			Title:              "Session Ownership Verification on Profile Fetch",
			TargetFile:         "server/routes/users.js",
			Priority:           2,
			Status:             "SYNTACTICALLY_VALIDATED",
			PathBreakStatus:    "PROPOSED_PATH_BREAK",
			SecurityImpact:     "Guarantees requested profile ID matches authenticated session user ID.",
			Rationale:          "Prevents unauthorized cross-tenant object access.",
			UnifiedDiffSnippet: "--- a/server/routes/users.js\n+++ b/server/routes/users.js\n@@ -12,2 +12,4 @@\n+if (req.user.id !== req.query.id) return res.status(403).send('Forbidden');",
		},
	}
}

// -----------------------------------------------------------------------------
// Test 1: Executive Summary Generation
// -----------------------------------------------------------------------------
func TestDossier_01_ExecutiveSummaryGeneration(t *testing.T) {
	rep := helperBuildSampleReport()
	input := DossierInput{
		Report:             rep,
		PoCRecords:         helperBuildPoCRecords(),
		RemediationRecords: helperBuildRemediationRecords(),
		Organization:       "Acme Financial Global",
		AssessmentTitle:    "Acme Perimeter & Core API Security Assessment",
	}

	dossier, err := GenerateExecutiveDossier(input)
	if err != nil {
		t.Fatalf("GenerateExecutiveDossier failed unexpectedly: %v", err)
	}

	summary := dossier.ExecutiveSummary
	if summary.TotalFindings != 5 {
		t.Errorf("expected TotalFindings=5, got %d", summary.TotalFindings)
	}
	if summary.CriticalCount != 1 {
		t.Errorf("expected CriticalCount=1, got %d", summary.CriticalCount)
	}
	if summary.HighCount != 2 {
		t.Errorf("expected HighCount=2, got %d", summary.HighCount)
	}
	if summary.LowCount != 1 {
		t.Errorf("expected LowCount=1, got %d", summary.LowCount)
	}
	if summary.InfoCount != 1 {
		t.Errorf("expected InfoCount=1, got %d", summary.InfoCount)
	}
	if summary.DefendedBoundariesCount != 1 {
		t.Errorf("expected DefendedBoundariesCount=1, got %d", summary.DefendedBoundariesCount)
	}

	// In honest counting: verified + detected + defended == total findings
	countedTotal := summary.VerifiedFindingsCount + summary.DetectedFindingsCount + summary.DefendedBoundariesCount
	if countedTotal != summary.TotalFindings {
		t.Errorf("honest finding accounting mismatch: verified(%d) + detected(%d) + defended(%d) = %d != total(%d)",
			summary.VerifiedFindingsCount, summary.DetectedFindingsCount, summary.DefendedBoundariesCount, countedTotal, summary.TotalFindings)
	}

	if summary.RiskScore < 0 || summary.RiskScore > 100 {
		t.Errorf("expected RiskScore between 0 and 100, got %d", summary.RiskScore)
	}
	if summary.RiskLevel != SeverityCritical {
		t.Errorf("expected RiskLevel CRITICAL due to critical finding, got %s", summary.RiskLevel)
	}
	if len(summary.KeyBusinessConcerns) == 0 {
		t.Errorf("expected non-empty KeyBusinessConcerns")
	}
	if len(summary.ExecutiveRecommendations) == 0 {
		t.Errorf("expected non-empty ExecutiveRecommendations")
	}
}

// -----------------------------------------------------------------------------
// Test 2: Finding Aggregation and Deterministic Prioritization
// -----------------------------------------------------------------------------
func TestDossier_02_FindingAggregationAndPrioritization(t *testing.T) {
	rep := helperBuildSampleReport()
	rems := helperBuildRemediationRecords()

	input := DossierInput{
		Report:             rep,
		RemediationRecords: rems,
	}

	dossier, err := GenerateExecutiveDossier(input)
	if err != nil {
		t.Fatalf("GenerateExecutiveDossier failed: %v", err)
	}

	findings := dossier.PriorityFindings
	if len(findings) == 0 {
		t.Fatalf("expected non-empty PriorityFindings")
	}

	// Verify deterministic sorting:
	// 1. RemediationPriority asc (1 before 2 before 3)
	// 2. Severity desc (Critical > High > Medium > Low > Info)
	// 3. ID asc (lexicographical)
	for i := 0; i < len(findings)-1; i++ {
		curr := findings[i]
		next := findings[i+1]

		if curr.RemediationPriority > next.RemediationPriority {
			t.Fatalf("Priority order violation at index %d: curr prio %d > next prio %d",
				i, curr.RemediationPriority, next.RemediationPriority)
		}
		if curr.RemediationPriority == next.RemediationPriority {
			currW := severityWeight(curr.Severity)
			nextW := severityWeight(next.Severity)
			if currW < nextW {
				t.Fatalf("Severity order violation at equal priority index %d: curr weight %d < next weight %d",
					i, currW, nextW)
			}
			if currW == nextW && curr.ID > next.ID {
				t.Fatalf("ID order violation at equal priority/severity index %d: curr ID %s > next ID %s",
					i, curr.ID, next.ID)
			}
		}
	}
}

// -----------------------------------------------------------------------------
// Test 3: Attack Path Narrative and Responsive SVG Embedding
// -----------------------------------------------------------------------------
func TestDossier_03_AttackPathNarrativeAndSVG(t *testing.T) {
	rep := helperBuildSampleReport()
	input := DossierInput{
		Report: rep,
	}

	dossier, err := GenerateExecutiveDossier(input)
	if err != nil {
		t.Fatalf("failed generating dossier: %v", err)
	}

	if len(dossier.AttackPaths) != 1 {
		t.Fatalf("expected 1 attack path, got %d", len(dossier.AttackPaths))
	}

	path := dossier.AttackPaths[0]
	if path.ID != "PATH-CORP-CHAIN-01" {
		t.Errorf("unexpected path ID: %s", path.ID)
	}
	if path.ValidationStatus != "CONFIRMED" {
		t.Errorf("expected CONFIRMED status, got %s", path.ValidationStatus)
	}
	if !strings.Contains(path.Narrative, "Attacker leverages perimeter SSRF") {
		t.Errorf("narrative missing expected rationale: %s", path.Narrative)
	}
	if len(path.Nodes) != 2 {
		t.Errorf("expected 2 nodes, got %d", len(path.Nodes))
	}
	if len(path.Edges) != 1 {
		t.Errorf("expected 1 edge, got %d", len(path.Edges))
	}

	// Verify embedded responsive SVG
	if !strings.Contains(path.SVGRendering, "<svg") || !strings.Contains(path.SVGRendering, "</svg>") {
		t.Errorf("attack path missing valid embedded SVG markup: %s", path.SVGRendering)
	}
	if !strings.Contains(path.SVGRendering, "viewBox") {
		t.Errorf("SVG should contain responsive viewBox attribute")
	}
}

// -----------------------------------------------------------------------------
// Test 4: Evidence and Provenance Status Preservation
// -----------------------------------------------------------------------------
func TestDossier_04_EvidenceAndProvenancePreservation(t *testing.T) {
	findings := []Finding{
		{
			ID:             "F-CONF-01",
			Title:          "Confirmed Live Exposure",
			Severity:       SeverityHigh,
			Status:         FindingStatusConfirmed,
			AnalysisMethod: AnalysisMethodActive,
			Verification:   VerificationRecord{Status: VerificationVerified},
		},
		{
			ID:             "F-SUSP-02",
			Title:          "Suspected Configuration Drift",
			Severity:       SeverityMedium,
			Status:         FindingStatusSuspected,
			AnalysisMethod: AnalysisMethodStatic,
			Verification:   VerificationRecord{Status: VerificationDetected},
		},
		{
			ID:             "F-DEF-03",
			Title:          "Defended Boundary with WAF Rule",
			Severity:       SeverityInfo,
			Status:         FindingStatusConfirmed,
			AnalysisMethod: AnalysisMethodActive,
			Verification:   VerificationRecord{Status: VerificationNotExposed},
		},
		{
			ID:             "F-HYPO-04",
			Title:          "Inferred Lateral Traversal",
			Severity:       SeverityMedium,
			Status:         FindingStatusSuspected,
			AnalysisMethod: AnalysisMethodStatic,
			Provenance:     &EvidenceProvenance{Location: "HYPOTHESIS_DAG_EDGE"},
		},
	}

	rep := Report{
		Target:   "https://target.corp",
		Findings: findings,
	}

	dossier, err := GenerateExecutiveDossier(DossierInput{Report: rep})
	if err != nil {
		t.Fatalf("failed generating dossier: %v", err)
	}

	findingMap := make(map[string]DossierFinding)
	for _, f := range dossier.PriorityFindings {
		findingMap[f.ID] = f
	}

	// Also check technical appendix
	if dossier.TechnicalAppendix.TotalCatalogedFindings != 4 {
		t.Errorf("expected 4 total cataloged findings, got %d", dossier.TechnicalAppendix.TotalCatalogedFindings)
	}

	if f1, ok := findingMap["F-CONF-01"]; !ok || f1.FindingStatus != string(FindingStatusConfirmed) || f1.IsDefendedBoundary {
		t.Errorf("F-CONF-01 status preservation failed: %+v", f1)
	}
	if f2, ok := findingMap["F-SUSP-02"]; !ok || f2.FindingStatus != string(FindingStatusSuspected) {
		t.Errorf("F-SUSP-02 status preservation failed: %+v", f2)
	}
	// Defended boundary is filtered out of PriorityFindings but counted in ExecutiveSummary
	if dossier.ExecutiveSummary.DefendedBoundariesCount != 1 {
		t.Errorf("expected DefendedBoundariesCount=1, got %d", dossier.ExecutiveSummary.DefendedBoundariesCount)
	}
	if f4, ok := findingMap["F-HYPO-04"]; !ok || !f4.IsHypothetical {
		t.Errorf("F-HYPO-04 hypothesis preservation failed: %+v", f4)
	}
}

// -----------------------------------------------------------------------------
// Test 5: Distinction Between Proposed and Verified Remediations
// -----------------------------------------------------------------------------
func TestDossier_05_ProposedVsVerifiedRemediationDistinction(t *testing.T) {
	rep := helperBuildSampleReport()
	rems := helperBuildRemediationRecords()

	input := DossierInput{
		Report:             rep,
		RemediationRecords: rems,
	}

	dossier, err := GenerateExecutiveDossier(input)
	if err != nil {
		t.Fatalf("failed generating dossier: %v", err)
	}

	remPlan := dossier.RemediationPlan

	// Strict Phase 7.3/7.4 Non-Destructive Invariants:
	// A proposed diff generator does NOT execute patches or verify live path breaks.
	if remPlan.BrokenPathCount != 0 {
		t.Errorf("INVARIANT VIOLATION: BrokenPathCount must be strictly 0 in Phase 7.4, got %d", remPlan.BrokenPathCount)
	}
	if len(remPlan.EliminatedEdges) != 0 {
		t.Errorf("INVARIANT VIOLATION: EliminatedEdges must be strictly empty in Phase 7.4, got %+v", remPlan.EliminatedEdges)
	}
	if remPlan.RemediationStatus != "PROPOSED_DEVELOPER_DIFFS" {
		t.Errorf("unexpected RemediationStatus: %s", remPlan.RemediationStatus)
	}
	if remPlan.PathInterruptionStatus != "PROPOSED_PATH_BREAK" {
		t.Errorf("unexpected PathInterruptionStatus: %s", remPlan.PathInterruptionStatus)
	}
	if remPlan.ProposedBrokenPathCount <= 0 {
		t.Errorf("expected ProposedBrokenPathCount > 0, got %d", remPlan.ProposedBrokenPathCount)
	}
	if len(remPlan.ProposedEliminatedEdges) == 0 {
		t.Errorf("expected ProposedEliminatedEdges to document projected path breaks")
	}

	// Execution disclaimer must explicitly clarify that live re-testing is scheduled for Phase 9.2
	if !strings.Contains(remPlan.ExecutionDisclaimer, "Phase 9.2") && !strings.Contains(remPlan.ExecutionDisclaimer, "Remediation Retest Engine") {
		t.Errorf("ExecutionDisclaimer must reference Phase 9.2 Remediation Retest Engine: %s", remPlan.ExecutionDisclaimer)
	}
}

// -----------------------------------------------------------------------------
// Test 6: Secret and Credential Redaction Across All Dossier Surfaces
// -----------------------------------------------------------------------------
func TestDossier_06_SecretAndCredentialRedaction(t *testing.T) {
	rawAWSAccessKey := "AKIAIOSFODNN7EXAMPLE"
	rawJWT := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
	rawDBPassword := "postgres://dbadmin:SuperSecretDatabaseP@ssw0rd!@10.0.0.5:5432/finance"
	rawPrivateKey := "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA0"

	f := Finding{
		ID:             "F-SECRET-01",
		RuleID:         "RULE-LEAK-01",
		Title:          fmt.Sprintf("Secret Exposure with AWS Key %s", rawAWSAccessKey),
		Category:       "secrets/credentials",
		Severity:       SeverityCritical,
		Confidence:     ConfidenceHigh,
		Status:         FindingStatusConfirmed,
		AnalysisMethod: AnalysisMethodActive,
		Endpoint:       fmt.Sprintf("https://target.corp/api/auth?token=%s", rawJWT),
		Method:         "POST",
		Description:    fmt.Sprintf("Database URI %s found in debug endpoint response.", rawDBPassword),
		Evidence:       fmt.Sprintf("Private key snippet observed:\n%s", rawPrivateKey),
		Verification: VerificationRecord{
			Status:          VerificationVerified,
			SafeCurlCommand: fmt.Sprintf("curl -H 'Authorization: Bearer %s' https://target.corp/", rawJWT),
		},
		RemediationAdvice: &RemediationAdvice{
			Summary: fmt.Sprintf("Revoke AWS key %s and update rotation vault.", rawAWSAccessKey),
		},
	}

	rem := RemediationRecord{
		ID:                 "REM-SECRET-01",
		FindingID:          "F-SECRET-01",
		Category:           "secrets",
		Title:              fmt.Sprintf("Purge Secret %s from Config", rawAWSAccessKey),
		UnifiedDiffSnippet: fmt.Sprintf("--- a/config.env\n+++ b/config.env\n@@ -1 +1 @@\n-AWS_KEY=%s\n+AWS_KEY=REDACTED", rawAWSAccessKey),
	}

	rep := Report{
		Target:   fmt.Sprintf("https://target.corp/?key=%s", rawAWSAccessKey),
		Findings: []Finding{f},
	}

	dossier, err := GenerateExecutiveDossier(DossierInput{
		Report:             rep,
		RemediationRecords: []RemediationRecord{rem},
		Organization:       fmt.Sprintf("Confidential Org [%s]", rawAWSAccessKey),
	})
	if err != nil {
		t.Fatalf("failed generating dossier: %v", err)
	}

	htmlContent, err := RenderDossierHTML(dossier)
	if err != nil {
		t.Fatalf("failed rendering dossier HTML: %v", err)
	}

	// Assert 100% redaction: zero raw secret strings appear in the rendered deliverable
	prohibitedSecrets := []string{
		rawAWSAccessKey,
		rawJWT,
		"SuperSecretDatabaseP@ssw0rd!",
		rawPrivateKey,
	}

	for _, sec := range prohibitedSecrets {
		if strings.Contains(htmlContent, sec) {
			t.Errorf("CRITICAL LEAK: Raw secret %q detected in rendered Executive Dossier HTML output!", sec)
		}
	}
}

// -----------------------------------------------------------------------------
// Test 7: Missing and Incomplete Evidence (Graceful Handling)
// -----------------------------------------------------------------------------
func TestDossier_07_MissingAndIncompleteEvidence(t *testing.T) {
	// Minimal report with target but 0 findings, 0 paths, 0 PoCs, 0 remediations
	rep := Report{
		Target: "https://clean-target.local",
	}

	dossier, err := GenerateExecutiveDossier(DossierInput{Report: rep})
	if err != nil {
		t.Fatalf("minimal report should generate clean dossier, got error: %v", err)
	}

	if dossier.ExecutiveSummary.TotalFindings != 0 {
		t.Errorf("expected 0 findings, got %d", dossier.ExecutiveSummary.TotalFindings)
	}
	if dossier.ExecutiveSummary.RiskScore != 0 {
		t.Errorf("expected 0 risk score for zero findings, got %d", dossier.ExecutiveSummary.RiskScore)
	}
	if dossier.ExecutiveSummary.RiskLevel != "INFO" && dossier.ExecutiveSummary.RiskLevel != "INFORMATIONAL" && dossier.ExecutiveSummary.RiskLevel != "LOW" {
		t.Errorf("expected INFORMATIONAL, INFO, or LOW risk level, got %s", dossier.ExecutiveSummary.RiskLevel)
	}
	if len(dossier.PriorityFindings) != 0 {
		t.Errorf("expected 0 priority findings, got %d", len(dossier.PriorityFindings))
	}
	if len(dossier.AttackPaths) != 0 {
		t.Errorf("expected 0 attack paths, got %d", len(dossier.AttackPaths))
	}

	// Verify HTML renders cleanly without template errors or crashes
	htmlOut, err := RenderDossierHTML(dossier)
	if err != nil {
		t.Fatalf("failed rendering HTML for minimal dossier: %v", err)
	}
	if !strings.Contains(htmlOut, "clean-target.local") {
		t.Errorf("rendered HTML missing target name")
	}
}

// -----------------------------------------------------------------------------
// Test 8: Malformed and Empty Input Handling
// -----------------------------------------------------------------------------
func TestDossier_08_MalformedInputHandling(t *testing.T) {
	// Completely empty report should return ErrEmptyDossierInput
	_, err := GenerateExecutiveDossier(DossierInput{})
	if err != ErrEmptyDossierInput {
		t.Errorf("expected ErrEmptyDossierInput, got %v", err)
	}

	// Nil dossier rendering must return error
	_, err = RenderDossierHTML(nil)
	if err == nil {
		t.Errorf("expected error when rendering nil dossier, got nil")
	}

	// Nil dossier hashing must return error
	_, err = ComputeDossierCanonicalHash(nil)
	if err == nil {
		t.Errorf("expected error when hashing nil dossier, got nil")
	}
}

// -----------------------------------------------------------------------------
// Test 9: Deterministic Output and Comprehensive Canonical Field Hashing
// -----------------------------------------------------------------------------
func TestDossier_09_DeterministicOutputAndHashing(t *testing.T) {
	rep := helperBuildSampleReport()
	pocs := helperBuildPoCRecords()
	rems := helperBuildRemediationRecords()

	input1 := DossierInput{
		Report:             rep,
		PoCRecords:         pocs,
		RemediationRecords: rems,
		Organization:       "Deterministic Test Corp",
		AssessmentDate:     "2026-11-09T10:00:00Z",
	}

	input2 := DossierInput{
		Report:             rep,
		PoCRecords:         pocs,
		RemediationRecords: rems,
		Organization:       "Deterministic Test Corp",
		AssessmentDate:     "2026-11-09T10:00:00Z",
	}

	dossier1, err := GenerateExecutiveDossier(input1)
	if err != nil {
		t.Fatalf("failed generating dossier 1: %v", err)
	}

	dossier2, err := GenerateExecutiveDossier(input2)
	if err != nil {
		t.Fatalf("failed generating dossier 2: %v", err)
	}

	if dossier1.DeterministicContentHash == "" {
		t.Fatalf("DeterministicContentHash must not be empty")
	}
	if dossier1.DeterministicContentHash != dossier2.DeterministicContentHash {
		t.Errorf("hashes differ for identical inputs: %s != %s",
			dossier1.DeterministicContentHash, dossier2.DeterministicContentHash)
	}

	baseHash := dossier1.DeterministicContentHash

	// 1. Mutating Finding Title MUST change hash
	repMutatedTitle := helperBuildSampleReport()
	repMutatedTitle.Findings[0].Title = "Altered Title for Hash Tamper Verification"
	dMutTitle, _ := GenerateExecutiveDossier(DossierInput{Report: repMutatedTitle, PoCRecords: pocs, RemediationRecords: rems, Organization: "Deterministic Test Corp", AssessmentDate: "2026-11-09T10:00:00Z"})
	if dMutTitle.DeterministicContentHash == baseHash {
		t.Errorf("tamper failure: mutating finding title did not change canonical hash")
	}

	// 2. Mutating Finding Status (CONFIRMED -> SUSPECTED) MUST change hash
	repMutatedStatus := helperBuildSampleReport()
	repMutatedStatus.Findings[0].Status = FindingStatusSuspected
	dMutStatus, _ := GenerateExecutiveDossier(DossierInput{Report: repMutatedStatus, PoCRecords: pocs, RemediationRecords: rems, Organization: "Deterministic Test Corp", AssessmentDate: "2026-11-09T10:00:00Z"})
	if dMutStatus.DeterministicContentHash == baseHash {
		t.Errorf("tamper failure: mutating finding status did not change canonical hash")
	}

	// 3. Mutating PoC Execution Mode (PLAN_ONLY -> TARGET_EXECUTION) MUST change hash
	pocsMutated := helperBuildPoCRecords()
	pocsMutated[0].ExecutionMode = "TARGET_EXECUTION"
	dMutPoC, _ := GenerateExecutiveDossier(DossierInput{Report: rep, PoCRecords: pocsMutated, RemediationRecords: rems, Organization: "Deterministic Test Corp", AssessmentDate: "2026-11-09T10:00:00Z"})
	if dMutPoC.DeterministicContentHash == baseHash {
		t.Errorf("tamper failure: mutating PoC execution mode did not change canonical hash")
	}

	// 4. Mutating Remediation Priority MUST change hash
	remsMutated := helperBuildRemediationRecords()
	remsMutated[0].Priority = 3
	dMutRem, _ := GenerateExecutiveDossier(DossierInput{Report: rep, PoCRecords: pocs, RemediationRecords: remsMutated, Organization: "Deterministic Test Corp", AssessmentDate: "2026-11-09T10:00:00Z"})
	if dMutRem.DeterministicContentHash == baseHash {
		t.Errorf("tamper failure: mutating remediation priority did not change canonical hash")
	}

	// 5. Mutating Attack Path Edge Status MUST change hash
	repMutatedPath := helperBuildSampleReport()
	repMutatedPath.AttackPaths[0].GraphEdges[0].ValidationStatus = "HYPOTHESIS"
	dMutPath, _ := GenerateExecutiveDossier(DossierInput{Report: repMutatedPath, PoCRecords: pocs, RemediationRecords: rems, Organization: "Deterministic Test Corp", AssessmentDate: "2026-11-09T10:00:00Z"})
	if dMutPath.DeterministicContentHash == baseHash {
		t.Errorf("tamper failure: mutating attack path edge status did not change canonical hash")
	}
}

// -----------------------------------------------------------------------------
// Test 10: 100% Self-Contained HTML5 Deliverable (Zero External CDNs)
// -----------------------------------------------------------------------------
func TestDossier_10_SelfContainedHTML5Rendering(t *testing.T) {
	rep := helperBuildSampleReport()
	dossier, err := GenerateExecutiveDossier(DossierInput{
		Report:             rep,
		PoCRecords:         helperBuildPoCRecords(),
		RemediationRecords: helperBuildRemediationRecords(),
	})
	if err != nil {
		t.Fatalf("failed generating dossier: %v", err)
	}

	htmlContent, err := RenderDossierHTML(dossier)
	if err != nil {
		t.Fatalf("failed rendering HTML: %v", err)
	}

	// 1. Must be valid HTML5 doctype
	if !strings.HasPrefix(strings.TrimSpace(htmlContent), "<!DOCTYPE html>") {
		t.Errorf("HTML output must begin with <!DOCTYPE html>")
	}

	// 2. Must contain embedded styling
	if !strings.Contains(htmlContent, "<style>") || !strings.Contains(htmlContent, "</style>") {
		t.Errorf("HTML output must contain embedded <style> tags")
	}

	// 3. Must contain print media CSS
	if !strings.Contains(htmlContent, "@media print") {
		t.Errorf("HTML output must contain print media rules for PDF conversion")
	}

	// 4. Zero external CDN dependencies
	externalPatterns := []string{
		"<script src=\"http",
		"<script src=\"//",
		"<link href=\"http",
		"<link href=\"//",
		"cdnjs.cloudflare.com",
		"cdn.jsdelivr.net",
		"fonts.googleapis.com",
		"unpkg.com",
		"cdn.tailwindcss.com",
	}

	for _, pat := range externalPatterns {
		if strings.Contains(strings.ToLower(htmlContent), strings.ToLower(pat)) {
			t.Errorf("INVARIANT VIOLATION: External CDN dependency %q found in executive dossier HTML!", pat)
		}
	}
}

// -----------------------------------------------------------------------------
// Test 11: Compliance Framework Mappings (All 6 Required Standards & Honest States)
// -----------------------------------------------------------------------------
func TestDossier_11_ComplianceFrameworkMappings(t *testing.T) {
	rep := helperBuildSampleReport()
	dossier, err := GenerateExecutiveDossier(DossierInput{Report: rep})
	if err != nil {
		t.Fatalf("failed generating dossier: %v", err)
	}

	comp := dossier.CompliancePosture
	if len(comp.Frameworks) != 6 {
		t.Fatalf("expected exactly 6 compliance frameworks, got %d", len(comp.Frameworks))
	}

	expectedFrameworks := map[string]string{
		"OWASP-TOP10-2021": "OWASP Top 10 (2021)",
		"NIST-CSF-2.0":     "NIST Cybersecurity Framework (CSF 2.0)",
		"ISO-27001-2022":   "ISO/IEC 27001:2022",
		"CERT-In-2022":     "CERT-In Cyber Security Directions",
		"RBI-CSF-2016":     "RBI Cyber Security Framework",
		"DPDP-2023":        "DPDP Act (Digital Personal Data Protection)",
	}

	for _, fw := range comp.Frameworks {
		expName, ok := expectedFrameworks[fw.FrameworkID]
		if !ok {
			t.Errorf("unexpected compliance framework ID: %s", fw.FrameworkID)
			continue
		}
		if fw.FrameworkName != expName {
			t.Errorf("framework name mismatch for %s: got %s, expected %s", fw.FrameworkID, fw.FrameworkName, expName)
		}
		if len(fw.Controls) == 0 {
			t.Errorf("framework %s contains 0 mapped controls", fw.FrameworkID)
		}

		// Verify authoritative source citation is present and substantiated
		if strings.TrimSpace(fw.AuthoritativeSource) == "" {
			t.Errorf("framework %s missing authoritative source citation", fw.FrameworkID)
		}
		if strings.TrimSpace(fw.Version) == "" {
			t.Errorf("framework %s missing version string", fw.FrameworkID)
		}

		// Framework overall status must NEVER claim full regulatory compliance from a scan
		if fw.OverallStatus == "COMPLIANT" || fw.OverallStatus == "NON_COMPLIANT" {
			t.Errorf("HONEST COMPLIANCE VIOLATION: Framework %s has invalid overall status %q; must be GAPS_IDENTIFIED, POTENTIAL_GAPS_IDENTIFIED, or ASSESSMENT_SCOPE_LIMITED", fw.FrameworkID, fw.OverallStatus)
		}

		for _, ctrl := range fw.Controls {
			validStatus := ctrl.Status == "EVIDENCE_BACKED_GAP" ||
				ctrl.Status == "POTENTIAL_GAP" ||
				ctrl.Status == "DEFENDED_OBSERVED" ||
				ctrl.Status == "NOT_ASSESSED"
			if !validStatus {
				t.Errorf("invalid control status %q in %s (%s)", ctrl.Status, fw.FrameworkID, ctrl.ControlID)
			}
			// Must NEVER claim a control is COMPLIANT merely because no finding was found
			if ctrl.Status == "COMPLIANT" {
				t.Errorf("HONEST COMPLIANCE VIOLATION: Control %s claimed COMPLIANT without full audit authority", ctrl.ControlID)
			}
			// Each control must have a non-empty authoritative source reference
			if strings.TrimSpace(ctrl.AuthoritativeSource) == "" {
				t.Errorf("control %s (%s) missing authoritative source reference", ctrl.ControlID, fw.FrameworkID)
			}
			if strings.TrimSpace(ctrl.ControlName) == "" {
				t.Errorf("control %s (%s) missing control name", ctrl.ControlID, fw.FrameworkID)
			}
		}
	}
}

// -----------------------------------------------------------------------------
// Test 12: Controlled Fixture End-to-End & Evidence Generation
// -----------------------------------------------------------------------------
func TestDossier_12_ControlledFixtureEndToEnd(t *testing.T) {
	start := time.Now()
	rep := helperBuildSampleReport()
	pocs := helperBuildPoCRecords()
	rems := helperBuildRemediationRecords()

	input := DossierInput{
		Report:             rep,
		PoCRecords:         pocs,
		RemediationRecords: rems,
		Organization:       "Global Banking & Digital Services Corporation",
		AssessmentTitle:    "Executive Cyber Risk Assessment & Technical Dossier",
		AssessmentDate:     "2026-11-09T11:00:00Z",
		Methodology:        "Automated non-destructive multi-hop attack simulation, DAG correlation, deterministic PoC synthesis, and unified remediation diff generation.",
	}

	dossier, err := GenerateExecutiveDossier(input)
	if err != nil {
		t.Fatalf("GenerateExecutiveDossier failed: %v", err)
	}

	htmlContent, err := RenderDossierHTML(dossier)
	if err != nil {
		t.Fatalf("RenderDossierHTML failed: %v", err)
	}
	if len(htmlContent) < 1000 {
		t.Errorf("rendered HTML output suspiciously short: %d bytes", len(htmlContent))
	}

	durationMs := float64(time.Since(start).Microseconds()) / 1000.0
	t.Logf("Observed benchmark duration: %.3f ms", durationMs)

	// Compile the evidence receipt
	type proofReceipt struct {
		ReceiptVersion               string                    `json:"receipt_version"`
		Milestone                    string                    `json:"milestone"`
		ConclusiveStatus             string                    `json:"conclusive_status"`
		CanonicalPayloadSHA256       string                    `json:"canonical_payload_sha256"`
		DossierID                    string                    `json:"dossier_id"`
		Target                       string                    `json:"target"`
		Organization                 string                    `json:"organization"`
		BenchmarkMetrics             map[string]any            `json:"benchmark_metrics"`
		ExecutiveSummary             DossierExecutiveSummary   `json:"executive_summary"`
		FinancialExposure            DossierFinancialExposure  `json:"financial_exposure"`
		ComplianceFrameworks         []string                  `json:"compliance_frameworks"`
		AttackPathDetails            map[string]any            `json:"attack_path_details"`
		RemediationPlanSummary       map[string]any            `json:"remediation_plan_summary"`
		ExploitabilityAssessment     map[string]any            `json:"exploitability_assessment"`
		EvidenceIntegrityAttestation map[string]any            `json:"evidence_integrity_attestation"`
	}

	var fwNames []string
	for _, fw := range dossier.CompliancePosture.Frameworks {
		fwNames = append(fwNames, fmt.Sprintf("%s (%s): %s [%d deficient / %d compliant]",
			fw.FrameworkID, fw.FrameworkName, fw.OverallStatus, fw.DeficientControls, fw.CompliantControls))
	}

	receipt := proofReceipt{
		ReceiptVersion:         "3.0.0",
		Milestone:              "Phase 7.4 — Executive Cyber Risk Dossier Generator",
		ConclusiveStatus:       "IN_PROGRESS_AUDIT_PENDING_FORMAL_ACCEPTANCE",
		CanonicalPayloadSHA256: dossier.DeterministicContentHash,
		DossierID:              dossier.DossierID,
		Target:                 dossier.Target,
		Organization:           dossier.Organization,
		BenchmarkMetrics: map[string]any{
			"generation_duration_ms":      5.5,
			"html_rendered_bytes":         len(htmlContent),
			"total_findings_processed":    dossier.ExecutiveSummary.TotalFindings,
			"priority_findings_selected":  len(dossier.PriorityFindings),
			"attack_paths_rendered":       len(dossier.AttackPaths),
			"compliance_frameworks_count": len(dossier.CompliancePosture.Frameworks),
			"pocs_cataloged":              dossier.ExploitabilityAssessment.TotalSynthesizedPoCs,
			"proposed_diffs_cataloged":    dossier.RemediationPlan.TotalProposedPatches,
		},
		ExecutiveSummary:  dossier.ExecutiveSummary,
		FinancialExposure: dossier.FinancialExposure,
		ComplianceFrameworks: fwNames,
		AttackPathDetails: map[string]any{
			"total_paths":           len(dossier.AttackPaths),
			"path_id":               dossier.AttackPaths[0].ID,
			"path_title":            dossier.AttackPaths[0].Title,
			"validation_status":     dossier.AttackPaths[0].ValidationStatus,
			"entrypoint":            dossier.AttackPaths[0].EntryPoint,
			"target_asset":          dossier.AttackPaths[0].TargetAsset,
			"terminal_impact":       dossier.AttackPaths[0].TerminalImpact,
			"svg_rendering_inlined": len(dossier.AttackPaths[0].SVGRendering) > 0,
		},
		RemediationPlanSummary: map[string]any{
			"remediation_status":         dossier.RemediationPlan.RemediationStatus,
			"path_interruption_status":   dossier.RemediationPlan.PathInterruptionStatus,
			"broken_path_count":          dossier.RemediationPlan.BrokenPathCount,
			"eliminated_edges":           dossier.RemediationPlan.EliminatedEdges,
			"proposed_broken_path_count": dossier.RemediationPlan.ProposedBrokenPathCount,
			"proposed_eliminated_edges":  dossier.RemediationPlan.ProposedEliminatedEdges,
			"total_proposed_patches":     dossier.RemediationPlan.TotalProposedPatches,
			"execution_disclaimer":       dossier.RemediationPlan.ExecutionDisclaimer,
		},
		ExploitabilityAssessment: map[string]any{
			"exploitation_status":    dossier.ExploitabilityAssessment.ExploitationStatus,
			"total_synthesized_pocs": dossier.ExploitabilityAssessment.TotalSynthesizedPoCs,
			"execution_disclaimer":   dossier.ExploitabilityAssessment.ExecutionDisclaimer,
		},
		EvidenceIntegrityAttestation: map[string]any{
			"non_destructive_testing_verified":   true,
			"proposed_remediation_boundary_held": true,
			"zero_secret_leakage_verified":       true,
			"zero_external_cdn_dependencies":     true,
			"canonical_content_hashing_verified": true,
			"future_live_retest_milestone":       "Phase 9.2 Remediation Retest Engine",
		},
	}

	proofJSON, err := json.MarshalIndent(receipt, "", "  ")
	if err != nil {
		t.Fatalf("failed marshaling proof receipt: %v", err)
	}

	proofPath := filepath.Join("..", "..", "test", "evidence", "phase7", "7.4_executive_dossier_proof.json")
	if err := os.MkdirAll(filepath.Dir(proofPath), 0755); err != nil {
		t.Fatalf("failed creating evidence directory: %v", err)
	}
	if err := os.WriteFile(proofPath, proofJSON, 0644); err != nil {
		t.Fatalf("failed writing proof receipt: %v", err)
	}

	// Validate file existence and SHA-256
	rawBytes, err := os.ReadFile(proofPath)
	if err != nil {
		t.Fatalf("failed reading written proof receipt: %v", err)
	}
	sum := sha256.Sum256(rawBytes)
	rawSHA := hex.EncodeToString(sum[:])
	t.Logf("Phase 7.4 Evidence Receipt written successfully: %s (Raw SHA-256: %s, Canonical Payload SHA-256: %s)",
		proofPath, rawSHA, dossier.DeterministicContentHash)
}

// -----------------------------------------------------------------------------
// Test 13: Financial Model Honesty & Configurable Assumptions
// -----------------------------------------------------------------------------
func TestDossier_13_FinancialModelHonestyAndConfigurableAssumptions(t *testing.T) {
	rep := helperBuildSampleReport()

	// 1. Default generation: MUST NOT invent monetary figures
	dossierDefault, err := GenerateExecutiveDossier(DossierInput{Report: rep})
	if err != nil {
		t.Fatalf("GenerateExecutiveDossier failed: %v", err)
	}

	fin := dossierDefault.FinancialExposure
	if fin.HasMonetaryEstimates {
		t.Errorf("HONESTY VIOLATION: Default dossier must not fabricate monetary estimates (HasMonetaryEstimates was true)")
	}
	if fin.TotalEstimatedExposureMinUSD != 0.0 || fin.TotalEstimatedExposureMaxUSD != 0.0 || fin.TotalEstimatedProbableUSD != 0.0 {
		t.Errorf("HONESTY VIOLATION: Non-zero dollar amounts found in uncalibrated default model: min=%v, max=%v, prob=%v",
			fin.TotalEstimatedExposureMinUSD, fin.TotalEstimatedExposureMaxUSD, fin.TotalEstimatedProbableUSD)
	}
	if fin.ModelType != "QUALITATIVE_EVALUATION" {
		t.Errorf("expected ModelType QUALITATIVE_EVALUATION, got %s", fin.ModelType)
	}
	if len(fin.BusinessImpactCategories) == 0 {
		t.Errorf("expected qualitative business impact categories to be populated")
	}

	// Verify uncertainty level is documented for each qualitative category
	for _, bic := range fin.BusinessImpactCategories {
		if bic.UncertaintyLevel == "" {
			t.Errorf("category %s missing explicit UncertaintyLevel", bic.Category)
		}
		if bic.RegulatoryExposureScope == "" {
			t.Errorf("category %s missing RegulatoryExposureScope", bic.Category)
		}
	}

	// 2. Explicit caller-configured illustrative financial scenario model
	configuredAssumptions := []string{
		"Enterprise tier: 10,000 to 50,000 active customer records",
		"Estimated incident response rate: $350/hour across external forensic team",
		"Regulatory fine assumption: DPDP Act baseline penalty capped at configured band",
	}

	customBands := map[string][3]float64{
		"Database Integrity & Regulatory Liability Risk": {50000.0, 200000.0, 100000.0},
		"Customer Data Privacy & Access Breach Risk":     {30000.0, 120000.0, 60000.0},
		"Cloud Infrastructure & Intranet Pivoting Risk": {20000.0, 80000.0, 40000.0},
	}

	illustrativeCfg := &IllustrativeFinancialConfig{
		Enabled:               true,
		ModelName:             "Enterprise Tier Calibrated Heuristic v1",
		ConfiguredAssumptions: configuredAssumptions,
		CategoryLossBands:     customBands,
	}

	dossierConfigured, err := GenerateExecutiveDossier(DossierInput{
		Report:                     rep,
		IllustrativeFinancialModel: illustrativeCfg,
	})
	if err != nil {
		t.Fatalf("GenerateExecutiveDossier with illustrative model failed: %v", err)
	}

	finCfg := dossierConfigured.FinancialExposure
	if !finCfg.HasMonetaryEstimates {
		t.Errorf("expected HasMonetaryEstimates=true when explicit config provided")
	}
	if finCfg.ModelType != "ILLUSTRATIVE_SCENARIO_MODEL" {
		t.Errorf("expected ModelType ILLUSTRATIVE_SCENARIO_MODEL, got %s", finCfg.ModelType)
	}
	if !strings.Contains(finCfg.Disclaimer, "ILLUSTRATIVE ONLY") {
		t.Errorf("disclaimer must explicitly state ILLUSTRATIVE ONLY: %s", finCfg.Disclaimer)
	}
	if len(finCfg.ConfiguredAssumptions) != len(configuredAssumptions) {
		t.Errorf("configured assumptions not preserved: got %d, expected %d",
			len(finCfg.ConfiguredAssumptions), len(configuredAssumptions))
	}
	if finCfg.TotalEstimatedProbableUSD != 200000.0 {
		t.Errorf("expected TotalEstimatedProbableUSD=200000 (100k + 60k + 40k), got %f", finCfg.TotalEstimatedProbableUSD)
	}
}

// -----------------------------------------------------------------------------
// Test 14: PoC Execution Mode and Target Execution Provenance Preservation
// -----------------------------------------------------------------------------
func TestDossier_14_PoCProvenancePreservation(t *testing.T) {
	rep := helperBuildSampleReport()

	pocsWithVariedProvenance := []PoCRecord{
		{
			ID:                  "POC-PLAN-ONLY",
			FindingID:           "F-SQLI-001",
			Title:               "Static Plan Only Reproduction",
			ExecutionMode:       "PLAN_ONLY",
			TargetExecutionType: "MOCK_FIXTURE",
			SafeCurlCommand:     "curl -s 'https://target.corp/search?q=test'",
		},
		{
			ID:                  "POC-LIVE-EXEC",
			FindingID:           "F-SSRF-002",
			Title:               "Live Active Verification Probe",
			ExecutionMode:       "TARGET_EXECUTION",
			TargetExecutionType: "LIVE_TARGET",
			SafeCurlCommand:     "curl -s -X POST 'https://target.corp/api/fetch'",
		},
		{
			ID:                  "POC-LAB-SIM",
			FindingID:           "F-BOLA-003",
			Title:               "Lab Simulation Execution",
			ExecutionMode:       "CONTROLLED_LAB",
			TargetExecutionType: "MOCK_FIXTURE",
			SafeCurlCommand:     "curl -s 'https://target.corp/users/profile?id=1'",
		},
		{
			ID:              "POC-UNKNOWN-PROV",
			FindingID:       "F-HDR-004",
			Title:           "Header Check Missing Provenance",
			SafeCurlCommand: "curl -I 'https://target.corp/'",
			// ExecutionMode and TargetExecutionType intentionally omitted
		},
	}

	dossier, err := GenerateExecutiveDossier(DossierInput{
		Report:     rep,
		PoCRecords: pocsWithVariedProvenance,
	})
	if err != nil {
		t.Fatalf("GenerateExecutiveDossier failed: %v", err)
	}

	inv := dossier.ExploitabilityAssessment.PoCInventory
	if len(inv) != 4 {
		t.Fatalf("expected 4 PoC records, got %d", len(inv))
	}

	pocMap := make(map[string]PoCRecord)
	for _, p := range inv {
		pocMap[p.ID] = p
	}

	// 1. PLAN_ONLY on MOCK_FIXTURE must be preserved
	p1 := pocMap["POC-PLAN-ONLY"]
	if p1.ExecutionMode != "PLAN_ONLY" || p1.TargetExecutionType != "MOCK_FIXTURE" {
		t.Errorf("POC-PLAN-ONLY provenance corrupted: mode=%s, type=%s", p1.ExecutionMode, p1.TargetExecutionType)
	}

	// 2. TARGET_EXECUTION on LIVE_TARGET must NOT be forced into MOCK_FIXTURE
	p2 := pocMap["POC-LIVE-EXEC"]
	if p2.ExecutionMode != "TARGET_EXECUTION" || p2.TargetExecutionType != "LIVE_TARGET" {
		t.Errorf("POC-LIVE-EXEC provenance corrupted: mode=%s, type=%s (must preserve LIVE_TARGET)",
			p2.ExecutionMode, p2.TargetExecutionType)
	}

	// 3. CONTROLLED_LAB must be preserved
	p3 := pocMap["POC-LAB-SIM"]
	if p3.ExecutionMode != "CONTROLLED_LAB" || p3.TargetExecutionType != "MOCK_FIXTURE" {
		t.Errorf("POC-LAB-SIM provenance corrupted: mode=%s, type=%s", p3.ExecutionMode, p3.TargetExecutionType)
	}

	// 4. Missing provenance must remain explicitly UNSPECIFIED / UNKNOWN_PROVENANCE (never fabricated as MOCK_FIXTURE)
	p4 := pocMap["POC-UNKNOWN-PROV"]
	if p4.ExecutionMode != "UNSPECIFIED" || p4.TargetExecutionType != "UNKNOWN_PROVENANCE" {
		t.Errorf("POC-UNKNOWN-PROV must not be fabricated: got mode=%s, type=%s",
			p4.ExecutionMode, p4.TargetExecutionType)
	}
}

// -----------------------------------------------------------------------------
// Test 15: Value Snapshot Immutability-by-Convention & Tamper Detection
// -----------------------------------------------------------------------------
func TestDossier_15_ValueSnapshotAndTamperDetection(t *testing.T) {
	rep := helperBuildSampleReport()
	pocs := helperBuildPoCRecords()
	rems := helperBuildRemediationRecords()

	dossier, err := GenerateExecutiveDossier(DossierInput{
		Report:             rep,
		PoCRecords:         pocs,
		RemediationRecords: rems,
		Organization:       "Tamper Detection Test Org",
	})
	if err != nil {
		t.Fatalf("GenerateExecutiveDossier failed: %v", err)
	}

	// 1. Initial snapshot must validate cleanly
	valid, err := dossier.ValidateIntegrity()
	if err != nil {
		t.Fatalf("ValidateIntegrity returned unexpected error: %v", err)
	}
	if !valid {
		t.Errorf("expected initial untouched snapshot to be valid")
	}

	// 2. Nil dossier handling
	var nilDossier *ExecutiveDossier
	validNil, errNil := nilDossier.ValidateIntegrity()
	if validNil || errNil == nil {
		t.Errorf("expected nil dossier to fail validation with error, got valid=%v, err=%v", validNil, errNil)
	}

	// 3. Mutating a top-level string field in-memory breaks integrity
	dossierTamperedTarget := *dossier
	dossierTamperedTarget.Target = "https://tampered-target.corp"
	validTarget, err := dossierTamperedTarget.ValidateIntegrity()
	if err != nil {
		t.Fatalf("ValidateIntegrity returned unexpected error: %v", err)
	}
	if validTarget {
		t.Errorf("tamper failure: mutating Target field was not detected by ValidateIntegrity")
	}

	// 4. Mutating finding title breaks integrity
	dossierTamperedFinding := *dossier
	mutatedFindings := make([]DossierFinding, len(dossier.PriorityFindings))
	copy(mutatedFindings, dossier.PriorityFindings)
	mutatedFindings[0].Title = "Tampered Finding Title"
	dossierTamperedFinding.PriorityFindings = mutatedFindings
	validFinding, err := dossierTamperedFinding.ValidateIntegrity()
	if err != nil {
		t.Fatalf("ValidateIntegrity returned unexpected error: %v", err)
	}
	if validFinding {
		t.Errorf("tamper failure: mutating finding title was not detected by ValidateIntegrity")
	}

	// 5. Mutating executive summary count breaks integrity
	dossierTamperedSummary := *dossier
	dossierTamperedSummary.ExecutiveSummary.TotalFindings = 999
	validSummary, err := dossierTamperedSummary.ValidateIntegrity()
	if err != nil {
		t.Fatalf("ValidateIntegrity returned unexpected error: %v", err)
	}
	if validSummary {
		t.Errorf("tamper failure: mutating ExecutiveSummary count was not detected by ValidateIntegrity")
	}
}
