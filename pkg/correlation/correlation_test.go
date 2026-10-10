package correlation

import (
	"context"
	"strings"
	"testing"

	"felix/pkg/report"
)

// Helper to create test findings
func makeFinding(id, title, category, severity, confidence string, status report.VerificationStatus, target, endpoint string) report.Finding {
	f := report.Finding{
		ID:         id,
		Title:      title,
		Category:   category,
		Severity:   severity,
		Confidence: confidence,
		Target:     target,
		Endpoint:   endpoint,
		Verification: report.VerificationRecord{
			Status: status,
		},
		EvidenceDetails: report.EvidenceDetails{
			Details: map[string]string{
				"route": endpoint,
			},
		},
	}
	f.Score = report.CalculateFindingScore(f)
	return f
}

// -----------------------------------------------------------------------------
// Section A: Basic Correlation
// -----------------------------------------------------------------------------

func TestCorrelation_EmptyFindings(t *testing.T) {
	engine := NewEngine(DefaultConfig())
	summary, paths, relationships, err := engine.Correlate(context.Background(), nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if summary == nil {
		t.Fatal("expected summary, got nil")
	}
	if summary.TotalFindings != 0 || len(paths) != 0 || len(relationships) != 0 {
		t.Errorf("expected 0 findings/paths/relationships, got findings=%d, paths=%d, rels=%d",
			summary.TotalFindings, len(paths), len(relationships))
	}
}

func TestCorrelation_SingleFinding(t *testing.T) {
	engine := NewEngine(DefaultConfig())
	f := makeFinding("F1", "Exposed Git Repository", "git-exposure", report.SeverityHigh, report.ConfidenceHigh, report.VerificationVerified, "https://example.com", "https://example.com/.git/HEAD")
	summary, paths, relationships, err := engine.Correlate(context.Background(), []report.Finding{f})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if summary.TotalFindings != 1 {
		t.Errorf("expected 1 finding, got %d", summary.TotalFindings)
	}
	if len(paths) != 0 {
		t.Errorf("expected 0 attack paths for single finding, got %d", len(paths))
	}
	if len(relationships) != 0 {
		t.Errorf("expected 0 relationships for single finding, got %d", len(relationships))
	}
}

func TestCorrelation_UnrelatedFindingsDifferentHosts(t *testing.T) {
	engine := NewEngine(DefaultConfig())
	f1 := makeFinding("F1", "API Route Discovered", "api-route", report.SeverityInfo, report.ConfidenceHigh, report.VerificationVerified, "https://api-a.example.com", "https://api-a.example.com/v1/users")
	f2 := makeFinding("F2", "SQL Injection", "sql-injection", report.SeverityCritical, report.ConfidenceHigh, report.VerificationVerified, "https://app-b.example.org", "https://app-b.example.org/search")

	_, paths, relationships, err := engine.Correlate(context.Background(), []report.Finding{f1, f2})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(relationships) != 0 {
		t.Errorf("expected 0 relationships between different hosts, got %d", len(relationships))
	}
	if len(paths) != 0 {
		t.Errorf("expected 0 paths between different hosts, got %d", len(paths))
	}
}

func TestCorrelation_NonSequentialRelationsNeverFormEdges(t *testing.T) {
	engine := NewEngine(DefaultConfig())
	// Two findings sharing a root cause (missing security headers) on same origin
	f1 := makeFinding("F1", "Missing X-Content-Type-Options", "missing-security-headers", report.SeverityLow, report.ConfidenceHigh, report.VerificationVerified, "https://example.com", "https://example.com/app")
	f2 := makeFinding("F2", "Missing Content-Security-Policy", "missing-security-headers", report.SeverityLow, report.ConfidenceHigh, report.VerificationVerified, "https://example.com", "https://example.com/app")

	summary, paths, relationships, err := engine.Correlate(context.Background(), []report.Finding{f1, f2})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// COR-09 groups findings under SHARES_ROOT_CAUSE
	if len(relationships) == 0 {
		t.Fatalf("expected COR-09 root cause relationship, got 0")
	}
	for _, rel := range relationships {
		if rel.Type == RelSharesRootCause {
			if rel.Type.IsSequenceType() {
				t.Errorf("RelSharesRootCause must NOT be a sequence type")
			}
		}
	}
	// Crucial rule: Non-sequential relationships must NEVER form attack paths!
	if len(paths) != 0 {
		t.Errorf("expected 0 attack paths for non-sequential relationship, got %d", len(paths))
	}
	if summary.CandidatePaths != 0 {
		t.Errorf("expected 0 candidate paths in summary, got %d", summary.CandidatePaths)
	}
}

// -----------------------------------------------------------------------------
// Section B: Path Construction & Validation Status
// -----------------------------------------------------------------------------

func TestCorrelation_VerifiedPathStatus(t *testing.T) {
	engine := NewEngine(DefaultConfig())
	// Entrypoint -> confirmed vulnerable SQLi on same path
	f1 := makeFinding("F1", "Publicly Accessible Search Endpoint", "api-route", report.SeverityInfo, report.ConfidenceHigh, report.VerificationVerified, "https://example.com", "https://example.com/search")
	f2 := makeFinding("F2", "SQL Injection on Search Query", "sql-injection", report.SeverityCritical, report.ConfidenceHigh, report.VerificationVerified, "https://example.com", "https://example.com/search")

	_, paths, _, err := engine.Correlate(context.Background(), []report.Finding{f1, f2})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(paths) == 0 {
		t.Fatalf("expected at least 1 path, got 0")
	}
	p := paths[0]
	if p.Status != PathVerified {
		t.Errorf("expected path status VERIFIED, got %s", p.Status)
	}
	if p.CombinedRiskLevel != report.SeverityCritical {
		t.Errorf("expected combined risk CRITICAL, got %s", p.CombinedRiskLevel)
	}
}

func TestCorrelation_CandidatePathWithPlausibleEdge(t *testing.T) {
	engine := NewEngine(DefaultConfig())
	// Entry point confirmed, but downstream auth bypass is unverified (detected only)
	f1 := makeFinding("F1", "API Endpoint /login", "api-route", report.SeverityInfo, report.ConfidenceHigh, report.VerificationVerified, "https://example.com", "https://example.com/login")
	f2 := makeFinding("F2", "Potential Authentication Bypass (Candidate)", "auth-bypass", report.SeverityHigh, report.ConfidenceLow, report.VerificationDetected, "https://example.com", "https://example.com/login")

	_, paths, _, err := engine.Correlate(context.Background(), []report.Finding{f1, f2})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(paths) == 0 {
		t.Fatalf("expected candidate path, got 0")
	}
	p := paths[0]
	if p.Status != PathCandidate {
		t.Errorf("expected path status CANDIDATE, got %s", p.Status)
	}
	// Candidate risk cap: Must not exceed 65 / HIGH
	if p.CombinedRiskScore > 65 {
		t.Errorf("candidate path score must not exceed 65, got %d", p.CombinedRiskScore)
	}
}

func TestCorrelation_CandidatePathWithInferredHypothesis(t *testing.T) {
	engine := NewEngine(DefaultConfig())
	// F1 has hypothesis tag in details
	f1 := makeFinding("F1", "Accessible Endpoint", "api-route", report.SeverityInfo, report.ConfidenceHigh, report.VerificationVerified, "https://example.com", "https://example.com/data")
	f2 := makeFinding("F2", "Data Leak Hypothesis", "information-disclosure", report.SeverityHigh, report.ConfidenceHigh, report.VerificationVerified, "https://example.com", "https://example.com/data")
	f2.EvidenceDetails.Details["hypothesis"] = "true"

	_, paths, _, err := engine.Correlate(context.Background(), []report.Finding{f1, f2})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(paths) == 0 {
		t.Fatalf("expected candidate path, got 0")
	}
	if paths[0].Status != PathCandidate {
		t.Errorf("path containing hypothesis must be CANDIDATE, got %s", paths[0].Status)
	}
}

// -----------------------------------------------------------------------------
// Section C: BOLA and Sensitive Data Exposure (COR-03)
// -----------------------------------------------------------------------------

func TestCorrelation_RuleCOR03_BOLAAndSensitiveData(t *testing.T) {
	engine := NewEngine(DefaultConfig())
	f1 := makeFinding("F1", "Broken Object-Level Authorization on User Profile", "bola", report.SeverityHigh, report.ConfidenceHigh, report.VerificationVerified, "https://api.example.com", "https://api.example.com/users/{id}")
	f1.EvidenceDetails.Details["bola"] = "true"

	f2 := makeFinding("F2", "Sensitive PII and Financial Record Exposure", "sensitive-data-exposure", report.SeverityHigh, report.ConfidenceHigh, report.VerificationVerified, "https://api.example.com", "https://api.example.com/users/{id}")
	f2.EvidenceDetails.Details["sensitive_data"] = "true"

	summary, paths, rels, err := engine.Correlate(context.Background(), []report.Finding{f1, f2})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	foundCOR03 := false
	for _, r := range rels {
		if r.RuleCode == RuleCOR03 {
			foundCOR03 = true
			if r.Type != RelExposes {
				t.Errorf("expected edge type EXPOSES, got %s", r.Type)
			}
			if r.ValidationStatus != ValidationConfirmed {
				t.Errorf("expected confirmed validation status, got %s", r.ValidationStatus)
			}
		}
	}
	if !foundCOR03 {
		t.Errorf("expected COR-03 relationship to be generated")
	}

	if len(paths) == 0 {
		t.Fatalf("expected attack path for COR-03, got 0")
	}
	p := paths[0]
	if p.Status != PathVerified {
		t.Errorf("expected verified path status, got %s", p.Status)
	}
	if !strings.Contains(p.PrimaryWeakness, "Broken Object-Level Authorization") {
		t.Errorf("expected primary weakness to contain BOLA, got %s", p.PrimaryWeakness)
	}
	if summary.VerifiedPaths != 1 {
		t.Errorf("expected 1 verified path in summary, got %d", summary.VerifiedPaths)
	}
}

// -----------------------------------------------------------------------------
// Section D: Authentication to Authorization (COR-02) & Privilege Escalation (COR-05)
// -----------------------------------------------------------------------------

func TestCorrelation_RuleCOR02_AuthToAuthz(t *testing.T) {
	engine := NewEngine(DefaultConfig())
	f1 := makeFinding("F1", "Session Token Fixation", "session-fixation", report.SeverityMedium, report.ConfidenceHigh, report.VerificationVerified, "https://app.example.com", "https://app.example.com/auth/login")
	f1.EvidenceDetails.Details["auth_required"] = "true"

	f2 := makeFinding("F2", "Missing Function-Level Access Control", "bfla", report.SeverityHigh, report.ConfidenceHigh, report.VerificationVerified, "https://app.example.com", "https://app.example.com/admin/settings")
	f2.EvidenceDetails.Details["role_restricted"] = "true"

	_, paths, rels, err := engine.Correlate(context.Background(), []report.Finding{f1, f2})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	foundCOR02 := false
	for _, r := range rels {
		if r.RuleCode == RuleCOR02 {
			foundCOR02 = true
			if r.Type != RelEnables {
				t.Errorf("expected edge type ENABLES, got %s", r.Type)
			}
		}
	}
	if !foundCOR02 {
		t.Errorf("expected COR-02 relationship to be generated")
	}
	if len(paths) == 0 {
		t.Fatalf("expected attack path connecting Auth to Authz")
	}
}

func TestCorrelation_RuleCOR05_PrivilegeEscalation(t *testing.T) {
	engine := NewEngine(DefaultConfig())
	f1 := makeFinding("F1", "Unprivileged User Access to Tenant Dashboard", "api-route", report.SeverityInfo, report.ConfidenceHigh, report.VerificationVerified, "https://app.example.com", "https://app.example.com/user/home")
	f2 := makeFinding("F2", "Privilege Escalation to Organization Administrator", "bfla", report.SeverityHigh, report.ConfidenceHigh, report.VerificationVerified, "https://app.example.com", "https://app.example.com/admin/tenants")

	_, paths, rels, err := engine.Correlate(context.Background(), []report.Finding{f1, f2})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	foundCOR05 := false
	for _, r := range rels {
		if r.RuleCode == RuleCOR05 {
			foundCOR05 = true
		}
	}
	if !foundCOR05 {
		t.Errorf("expected COR-05 privilege escalation relationship")
	}
	if len(paths) == 0 {
		t.Fatalf("expected privilege escalation attack path")
	}
}

// -----------------------------------------------------------------------------
// Section E: Cloud & Business Logic Chains (COR-04, COR-06, COR-08)
// -----------------------------------------------------------------------------

func TestCorrelation_RuleCOR04_PublicCloudToSensitiveData(t *testing.T) {
	engine := NewEngine(DefaultConfig())
	f1 := makeFinding("F1", "Public AWS S3 Bucket Exposed", "cloudsec-s3-public", report.SeverityMedium, report.ConfidenceHigh, report.VerificationVerified, "https://corp-assets.s3.amazonaws.com", "https://corp-assets.s3.amazonaws.com/")
	f2 := makeFinding("F2", "Database Backups Disclosed in Cloud Storage", "sensitive-data-exposure", report.SeverityHigh, report.ConfidenceHigh, report.VerificationVerified, "https://corp-assets.s3.amazonaws.com", "https://corp-assets.s3.amazonaws.com/backup.sql")

	_, paths, rels, err := engine.Correlate(context.Background(), []report.Finding{f1, f2})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	foundCOR04 := false
	for _, r := range rels {
		if r.RuleCode == RuleCOR04 {
			foundCOR04 = true
			if r.Type != RelExposes {
				t.Errorf("expected edge type EXPOSES, got %s", r.Type)
			}
		}
	}
	if !foundCOR04 {
		t.Errorf("expected COR-04 relationship")
	}
	if len(paths) == 0 {
		t.Fatalf("expected attack path connecting public cloud to sensitive data")
	}
}

func TestCorrelation_RuleCOR06_BusinessLogicChains(t *testing.T) {
	engine := NewEngine(DefaultConfig())
	f1 := makeFinding("F1", "Workflow Step Bypass in Checkout", "workflow-circumvention", report.SeverityHigh, report.ConfidenceHigh, report.VerificationVerified, "https://shop.example.com", "https://shop.example.com/checkout/step2")
	f1.EvidenceDetails.Details["workflow_id"] = "WF-CHECKOUT"

	f2 := makeFinding("F2", "Order Fulfillment Without Payment", "unexpected-state-transition", report.SeverityHigh, report.ConfidenceHigh, report.VerificationVerified, "https://shop.example.com", "https://shop.example.com/checkout/fulfill")
	f2.EvidenceDetails.Details["workflow_id"] = "WF-CHECKOUT"

	_, paths, rels, err := engine.Correlate(context.Background(), []report.Finding{f1, f2})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	foundCOR06 := false
	for _, r := range rels {
		if r.RuleCode == RuleCOR06 {
			foundCOR06 = true
		}
	}
	if !foundCOR06 {
		t.Errorf("expected COR-06 relationship")
	}
	if len(paths) == 0 {
		t.Fatalf("expected business logic attack path")
	}
}

func TestCorrelation_RuleCOR08_CloudAndAppDependencies(t *testing.T) {
	engine := NewEngine(DefaultConfig())
	f1 := makeFinding("F1", "Server-Side Request Forgery", "ssrf", report.SeverityHigh, report.ConfidenceHigh, report.VerificationVerified, "https://api.example.com", "https://api.example.com/fetch")
	f2 := makeFinding("F2", "AWS IAM Role Credentials Retrieved via IMDS", "cloud-credential-exposure", report.SeverityCritical, report.ConfidenceHigh, report.VerificationVerified, "https://api.example.com", "http://169.254.169.254/latest/meta-data/iam/security-credentials")

	_, paths, rels, err := engine.Correlate(context.Background(), []report.Finding{f1, f2})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	foundCOR08 := false
	for _, r := range rels {
		if r.RuleCode == RuleCOR08 {
			foundCOR08 = true
		}
	}
	if !foundCOR08 {
		t.Errorf("expected COR-08 relationship")
	}
	if len(paths) == 0 {
		t.Fatalf("expected SSRF -> Cloud IAM attack path")
	}
}

// -----------------------------------------------------------------------------
// Section F: Combined Risk Scoring & Deduplication
// -----------------------------------------------------------------------------

func TestCorrelation_CombinedRiskScoring(t *testing.T) {
	f1 := NormalizedFinding{
		ID:                 "F1",
		Severity:           report.SeverityHigh,
		Score:              35,
		NormalizedCategory: "bola",
		Path:               "/users",
		VerificationStatus: report.VerificationVerified,
	}
	f2 := NormalizedFinding{
		ID:                 "F2",
		Severity:           report.SeverityHigh,
		Score:              38,
		NormalizedCategory: "sensitive-data",
		Path:               "/users/data",
		VerificationStatus: report.VerificationVerified,
	}

	edges := []Relationship{
		{
			Type:             RelEnables,
			ValidationStatus: ValidationConfirmed,
		},
	}

	path := &AttackPath{
		Status: PathVerified,
		Nodes:  []NormalizedFinding{f1, f2},
		Edges:  edges,
	}

	score, level, rationale := AssessPathRisk(path)
	if level != report.SeverityCritical {
		t.Errorf("expected combined risk CRITICAL, got %s (score: %d)", level, score)
	}
	if score <= 70 {
		t.Errorf("expected score > 70 with transition bonus, got %d", score)
	}
	if rationale == "" {
		t.Errorf("expected non-empty risk rationale")
	}
}

func TestCorrelation_CandidateRiskCap(t *testing.T) {
	f1 := NormalizedFinding{
		ID:                 "F1",
		Severity:           report.SeverityCritical,
		Score:              40,
		NormalizedCategory: "ssrf",
		Path:               "/proxy",
		VerificationStatus: report.VerificationDetected,
	}
	f2 := NormalizedFinding{
		ID:                 "F2",
		Severity:           report.SeverityCritical,
		Score:              40,
		NormalizedCategory: "cloud-creds",
		Path:               "/imds",
		VerificationStatus: report.VerificationDetected,
	}

	edges := []Relationship{
		{
			Type:             RelEnables,
			ValidationStatus: ValidationPlausible,
		},
	}

	path := &AttackPath{
		Status: PathCandidate,
		Nodes:  []NormalizedFinding{f1, f2},
		Edges:  edges,
	}

	score, level, rationale := AssessPathRisk(path)
	if score > 65 {
		t.Errorf("candidate path score must be capped at 65, got %d", score)
	}
	if level != report.SeverityHigh {
		t.Errorf("candidate path level must be capped at HIGH, got %s", level)
	}
	if rationale == "" {
		t.Errorf("expected non-empty risk rationale")
	}
}

// -----------------------------------------------------------------------------
// Section G: Pruning & Limits
// -----------------------------------------------------------------------------

func TestCorrelation_MaxCandidatePathsLimit(t *testing.T) {
	cfg := DefaultConfig()
	cfg.MaxCandidatePaths = 2

	engine := NewEngine(cfg)

	// Create 3 separate valid paths with threshold of 2
	f1a := makeFinding("E1", "Entry 1", "api-route", report.SeverityInfo, report.ConfidenceHigh, report.VerificationVerified, "https://example.com", "https://example.com/api/r1")
	f1b := makeFinding("V1", "SQLi 1", "sql-injection", report.SeverityHigh, report.ConfidenceHigh, report.VerificationVerified, "https://example.com", "https://example.com/api/r1")

	f2a := makeFinding("E2", "Entry 2", "api-route", report.SeverityInfo, report.ConfidenceHigh, report.VerificationVerified, "https://example.com", "https://example.com/api/r2")
	f2b := makeFinding("V2", "SQLi 2", "sql-injection", report.SeverityHigh, report.ConfidenceHigh, report.VerificationVerified, "https://example.com", "https://example.com/api/r2")

	f3a := makeFinding("E3", "Entry 3", "api-route", report.SeverityInfo, report.ConfidenceHigh, report.VerificationVerified, "https://example.com", "https://example.com/api/r3")
	f3b := makeFinding("V3", "SQLi 3", "sql-injection", report.SeverityHigh, report.ConfidenceHigh, report.VerificationVerified, "https://example.com", "https://example.com/api/r3")

	findings := []report.Finding{f1a, f1b, f2a, f2b, f3a, f3b}

	summary, paths, _, err := engine.Correlate(context.Background(), findings)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(paths) > cfg.MaxCandidatePaths {
		t.Errorf("paths count %d exceeded MaxCandidatePaths %d", len(paths), cfg.MaxCandidatePaths)
	}
	if !summary.LimitsReached {
		t.Errorf("expected LimitsReached to be true when paths exceeded limit")
	}
	if summary.TruncationReason == "" {
		t.Errorf("expected TruncationReason to explain limit enforcement")
	}
}

// -----------------------------------------------------------------------------
// Section H: Security Story Generation
// -----------------------------------------------------------------------------

func TestCorrelation_SecurityStoryAnsweringQuestions(t *testing.T) {
	engine := NewEngine(DefaultConfig())
	f1 := makeFinding("F1", "Open API Documentation", "api-docs-exposure", report.SeverityInfo, report.ConfidenceHigh, report.VerificationVerified, "https://api.example.com", "https://api.example.com/docs")
	f2 := makeFinding("F2", "Customer Data Query Without Authentication", "auth-bypass", report.SeverityCritical, report.ConfidenceHigh, report.VerificationVerified, "https://api.example.com", "https://api.example.com/docs/customers")

	_, paths, _, err := engine.Correlate(context.Background(), []report.Finding{f1, f2})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(paths) == 0 {
		t.Fatalf("expected at least 1 path, got 0")
	}

	story := paths[0].SecurityStory
	if story.Title == "" {
		t.Errorf("expected non-empty story title")
	}
	if story.Summary == "" {
		t.Errorf("expected non-empty story summary")
	}
	if story.Impact == "" {
		t.Errorf("expected non-empty story impact")
	}
	if len(story.Evidence) == 0 {
		t.Errorf("expected non-empty supporting evidence")
	}
	if story.InvestigateFirst == "" {
		t.Errorf("expected non-empty InvestigateFirst recommendation")
	}
	if story.Remediation == "" {
		t.Errorf("expected non-empty bottleneck remediation guidance")
	}
	if len(story.RelatedIDs) != 2 {
		t.Errorf("expected 2 related IDs in story, got %d", len(story.RelatedIDs))
	}
}
