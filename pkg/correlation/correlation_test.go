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
// Section 1: Basic Correlation Engine Invariants
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

// -----------------------------------------------------------------------------
// Section 2: Validation of All 10 Correlation Rules (Positive & Negative)
// -----------------------------------------------------------------------------

// COR-01: Entry Point to Vulnerable Resource
func TestRuleCOR01_PositiveAndNegative(t *testing.T) {
	engine := NewEngine(DefaultConfig())

	// Positive: Entry point connects to verified vuln on same path
	entry := makeFinding("E1", "Public Search Route", "api-route", report.SeverityInfo, report.ConfidenceHigh, report.VerificationVerified, "https://app.example.com", "https://app.example.com/search")
	vuln := makeFinding("V1", "SQL Injection on Search", "sql-injection", report.SeverityCritical, report.ConfidenceHigh, report.VerificationVerified, "https://app.example.com", "https://app.example.com/search")

	// Negative: Unrelated path
	unrelated := makeFinding("U1", "XSS on Profile", "xss", report.SeverityMedium, report.ConfidenceHigh, report.VerificationVerified, "https://app.example.com", "https://app.example.com/profile")

	_, paths, rels, err := engine.Correlate(context.Background(), []report.Finding{entry, vuln, unrelated})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	foundCOR01 := false
	for _, r := range rels {
		if r.RuleCode == RuleCOR01 {
			foundCOR01 = true
			if r.Type != RelReaches {
				t.Errorf("expected REACHES edge type, got %s", r.Type)
			}
			if r.SourceFindingID != "E1" || r.TargetFindingID != "V1" {
				t.Errorf("unexpected edge endpoints: %s -> %s", r.SourceFindingID, r.TargetFindingID)
			}
		}
	}
	if !foundCOR01 {
		t.Errorf("expected positive COR-01 relationship between E1 and V1")
	}

	// Verify no path connects E1 to U1 (unrelated path)
	for _, p := range paths {
		if len(p.Nodes) == 2 && p.Nodes[0].ID == "E1" && p.Nodes[1].ID == "U1" {
			t.Errorf("negative test failed: E1 should NOT connect to unrelated path U1")
		}
	}
}

// COR-02: Authentication to Authorization
func TestRuleCOR02_PositiveAndNegative(t *testing.T) {
	engine := NewEngine(DefaultConfig())

	// Positive: Session fixation connects to BFLA on protected endpoint
	authFlaw := makeFinding("A1", "Session Token Fixation", "session-fixation", report.SeverityMedium, report.ConfidenceHigh, report.VerificationVerified, "https://app.example.com", "https://app.example.com/auth/login")
	authFlaw.EvidenceDetails.Details["auth_required"] = "true"

	authzFlaw := makeFinding("Z1", "Broken Function Level Access", "bfla", report.SeverityHigh, report.ConfidenceHigh, report.VerificationVerified, "https://app.example.com", "https://app.example.com/admin/settings")

	// Negative: Target endpoint is explicitly anonymous public (auth state rejects)
	anonEndpoint := makeFinding("Z2", "Public Content Access", "bfla", report.SeverityLow, report.ConfidenceHigh, report.VerificationVerified, "https://app.example.com", "https://app.example.com/public/help")
	anonEndpoint.EvidenceDetails.Details["auth_state"] = "ANONYMOUS_PUBLIC"

	_, _, rels, err := engine.Correlate(context.Background(), []report.Finding{authFlaw, authzFlaw, anonEndpoint})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	foundPositive := false
	for _, r := range rels {
		if r.RuleCode == RuleCOR02 && r.TargetFindingID == "Z1" {
			foundPositive = true
			if r.Type != RelEnables {
				t.Errorf("expected ENABLES edge type, got %s", r.Type)
			}
		}
		if r.RuleCode == RuleCOR02 && r.TargetFindingID == "Z2" {
			t.Errorf("negative test failed: ANONYMOUS_PUBLIC destination should be rejected by COR-02")
		}
	}
	if !foundPositive {
		t.Errorf("expected positive COR-02 relationship between A1 and Z1")
	}
}

// COR-03: BOLA and Sensitive Data Exposure
func TestRuleCOR03_PositiveAndNegative(t *testing.T) {
	engine := NewEngine(DefaultConfig())

	// Positive: BOLA on /users/{id} exposes sensitive customer data on same path
	bola := makeFinding("B1", "BOLA on User Object", "bola", report.SeverityHigh, report.ConfidenceHigh, report.VerificationVerified, "https://api.example.com", "https://api.example.com/users/{id}")
	sensData := makeFinding("D1", "PII Record Exposure", "sensitive-data-exposure", report.SeverityHigh, report.ConfidenceHigh, report.VerificationVerified, "https://api.example.com", "https://api.example.com/users/{id}")

	// Negative: Unrelated sensitive data on different endpoint with different affected resource
	unrelatedData := makeFinding("D2", "System Health Log Disclosure", "sensitive-data-exposure", report.SeverityLow, report.ConfidenceHigh, report.VerificationVerified, "https://api.example.com", "https://api.example.com/metrics")

	_, paths, rels, err := engine.Correlate(context.Background(), []report.Finding{bola, sensData, unrelatedData})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	foundCOR03 := false
	for _, r := range rels {
		if r.RuleCode == RuleCOR03 && r.TargetFindingID == "D1" {
			foundCOR03 = true
			if r.Type != RelExposes {
				t.Errorf("expected EXPOSES edge type, got %s", r.Type)
			}
		}
		if r.RuleCode == RuleCOR03 && r.TargetFindingID == "D2" {
			t.Errorf("negative test failed: mismatched endpoint must not match COR-03")
		}
	}
	if !foundCOR03 {
		t.Errorf("expected positive COR-03 relationship between B1 and D1")
	}

	if len(paths) == 0 {
		t.Fatalf("expected attack path for BOLA + Sensitive Data")
	}
	if paths[0].Status != PathVerified {
		t.Errorf("expected verified status, got %s", paths[0].Status)
	}
}

// COR-04: Public Exposure to Sensitive Resource
func TestRuleCOR04_PositiveAndNegative(t *testing.T) {
	engine := NewEngine(DefaultConfig())

	// Positive: Public S3 bucket directly contains database backup
	pubStorage := makeFinding("P1", "Public S3 Storage Bucket", "cloudsec-s3-public", report.SeverityMedium, report.ConfidenceHigh, report.VerificationVerified, "https://storage.example.com", "https://storage.example.com/")
	backupData := makeFinding("D1", "SQL Database Dump Backup", "sensitive-data-exposure", report.SeverityHigh, report.ConfidenceHigh, report.VerificationVerified, "https://storage.example.com", "https://storage.example.com/backup.sql")

	// Negative: Private non-sensitive endpoint on another host
	otherHost := makeFinding("H1", "Static CSS Asset", "discovery", report.SeverityInfo, report.ConfidenceHigh, report.VerificationVerified, "https://cdn.example.org", "https://cdn.example.org/style.css")

	_, paths, rels, err := engine.Correlate(context.Background(), []report.Finding{pubStorage, backupData, otherHost})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	foundCOR04 := false
	for _, r := range rels {
		if r.RuleCode == RuleCOR04 && r.TargetFindingID == "D1" {
			foundCOR04 = true
		}
		if r.RuleCode == RuleCOR04 && r.TargetFindingID == "H1" {
			t.Errorf("negative test failed: non-sensitive asset must not trigger COR-04")
		}
	}
	if !foundCOR04 {
		t.Errorf("expected positive COR-04 relationship between P1 and D1")
	}
	if len(paths) == 0 {
		t.Fatalf("expected attack path connecting public storage to backup")
	}
}

// COR-05: Privilege Escalation
func TestRuleCOR05_PositiveAndNegative(t *testing.T) {
	engine := NewEngine(DefaultConfig())

	// Positive: Unprivileged user route connects to BFLA on /admin
	unpriv := makeFinding("U1", "Unprivileged User Endpoint", "api-route", report.SeverityInfo, report.ConfidenceHigh, report.VerificationVerified, "https://app.example.com", "https://app.example.com/user/profile")
	privEsc := makeFinding("A1", "Privilege Escalation to Tenant Admin", "bfla", report.SeverityHigh, report.ConfidenceHigh, report.VerificationVerified, "https://app.example.com", "https://app.example.com/admin/users")

	// Negative: Low-privilege to low-privilege (no admin / privileged capability)
	peerRoute := makeFinding("U2", "User Settings Route", "api-route", report.SeverityInfo, report.ConfidenceHigh, report.VerificationVerified, "https://app.example.com", "https://app.example.com/user/settings")

	_, _, rels, err := engine.Correlate(context.Background(), []report.Finding{unpriv, privEsc, peerRoute})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	foundCOR05 := false
	for _, r := range rels {
		if r.RuleCode == RuleCOR05 && r.TargetFindingID == "A1" {
			foundCOR05 = true
			if r.Type != RelEnables {
				t.Errorf("expected ENABLES edge type, got %s", r.Type)
			}
		}
		if r.RuleCode == RuleCOR05 && r.TargetFindingID == "U2" {
			t.Errorf("negative test failed: unprivileged-to-unprivileged cannot be privilege escalation")
		}
	}
	if !foundCOR05 {
		t.Errorf("expected positive COR-05 relationship")
	}
}

// COR-06: Business Logic Chains
func TestRuleCOR06_PositiveAndNegative(t *testing.T) {
	engine := NewEngine(DefaultConfig())

	// Positive: Step bypass in order workflow connects to fulfillment without payment in same workflow
	stepBypass := makeFinding("W1", "Payment Step Circumvention", "workflow-circumvention", report.SeverityHigh, report.ConfidenceHigh, report.VerificationVerified, "https://shop.example.com", "https://shop.example.com/checkout/step2")
	stepBypass.EvidenceDetails.Details["workflow_id"] = "WF-CHECKOUT-01"

	fulfillment := makeFinding("W2", "Order Fulfillment Without Payment", "unexpected-state-transition", report.SeverityHigh, report.ConfidenceHigh, report.VerificationVerified, "https://shop.example.com", "https://shop.example.com/checkout/fulfill")
	fulfillment.EvidenceDetails.Details["workflow_id"] = "WF-CHECKOUT-01"

	// Negative: Unrelated workflow
	otherWf := makeFinding("W3", "Profile Update Replay", "workflow-circumvention", report.SeverityMedium, report.ConfidenceHigh, report.VerificationVerified, "https://shop.example.com", "https://shop.example.com/profile/email")
	otherWf.EvidenceDetails.Details["workflow_id"] = "WF-PROFILE-09"

	_, _, rels, err := engine.Correlate(context.Background(), []report.Finding{stepBypass, fulfillment, otherWf})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	foundCOR06 := false
	for _, r := range rels {
		if r.RuleCode == RuleCOR06 && r.TargetFindingID == "W2" {
			foundCOR06 = true
		}
		if r.RuleCode == RuleCOR06 && r.TargetFindingID == "W3" {
			t.Errorf("negative test failed: different workflow IDs must not connect via COR-06")
		}
	}
	if !foundCOR06 {
		t.Errorf("expected positive COR-06 relationship")
	}
}

// COR-07: Session and Identity Dependencies
func TestRuleCOR07_PositiveAndNegative(t *testing.T) {
	engine := NewEngine(DefaultConfig())

	// Positive: Missing session invalidation on logout connects to post-logout data access
	sessionFlaw := makeFinding("S1", "Missing Server-Side Session Invalidation on Logout", "session-invalidation", report.SeverityMedium, report.ConfidenceHigh, report.VerificationVerified, "https://app.example.com", "https://app.example.com/auth/logout")
	resource := makeFinding("R1", "Tenant Financial Data Access", "api-route", report.SeverityHigh, report.ConfidenceHigh, report.VerificationVerified, "https://app.example.com", "https://app.example.com/api/invoices")

	// Negative: Mismatched host
	otherHost := makeFinding("R2", "Third Party API", "api-route", report.SeverityLow, report.ConfidenceHigh, report.VerificationVerified, "https://other.example.org", "https://other.example.org/api/invoices")

	_, _, rels, err := engine.Correlate(context.Background(), []report.Finding{sessionFlaw, resource, otherHost})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	foundCOR07 := false
	for _, r := range rels {
		if r.RuleCode == RuleCOR07 && r.TargetFindingID == "R1" {
			foundCOR07 = true
			if r.Type != RelDependsOn {
				t.Errorf("expected DEPENDS_ON edge type, got %s", r.Type)
			}
		}
		if r.RuleCode == RuleCOR07 && r.TargetFindingID == "R2" {
			t.Errorf("negative test failed: mismatched host must not connect via COR-07")
		}
	}
	if !foundCOR07 {
		t.Errorf("expected positive COR-07 relationship")
	}
}

// COR-08: Cloud and Application Dependencies
func TestRuleCOR08_PositiveAndNegative(t *testing.T) {
	engine := NewEngine(DefaultConfig())

	// Positive: SSRF connects to AWS IMDS metadata credential retrieval
	ssrf := makeFinding("APP1", "Server-Side Request Forgery", "ssrf", report.SeverityHigh, report.ConfidenceHigh, report.VerificationVerified, "https://app.example.com", "https://app.example.com/proxy")
	cloudCreds := makeFinding("CLOUD1", "AWS IMDS IAM Role Credentials Disclosed", "cloud-credential-exposure", report.SeverityCritical, report.ConfidenceHigh, report.VerificationVerified, "https://app.example.com", "http://169.254.169.254/latest/meta-data/iam/security-credentials")

	// Negative: Non-cloud internal resource
	internalPing := makeFinding("INT1", "Internal Loopback Ping", "discovery", report.SeverityInfo, report.ConfidenceHigh, report.VerificationVerified, "https://app.example.com", "https://app.example.com/ping")

	_, _, rels, err := engine.Correlate(context.Background(), []report.Finding{ssrf, cloudCreds, internalPing})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	foundCOR08 := false
	for _, r := range rels {
		if r.RuleCode == RuleCOR08 && r.TargetFindingID == "CLOUD1" {
			foundCOR08 = true
			if r.Type != RelEnables {
				t.Errorf("expected ENABLES edge type, got %s", r.Type)
			}
		}
		if r.RuleCode == RuleCOR08 && r.TargetFindingID == "INT1" {
			t.Errorf("negative test failed: non-cloud target must not match COR-08")
		}
	}
	if !foundCOR08 {
		t.Errorf("expected positive COR-08 relationship")
	}
}

// COR-09: Common Root Cause
func TestRuleCOR09_PositiveAndNegative(t *testing.T) {
	engine := NewEngine(DefaultConfig())

	// Positive: Two missing header findings on the same endpoint share root cause
	hdr1 := makeFinding("H1", "Missing X-Content-Type-Options", "missing-headers", report.SeverityLow, report.ConfidenceHigh, report.VerificationVerified, "https://app.example.com", "https://app.example.com/api/test")
	hdr2 := makeFinding("H2", "Missing Content-Security-Policy", "missing-headers", report.SeverityLow, report.ConfidenceHigh, report.VerificationVerified, "https://app.example.com", "https://app.example.com/api/test")

	// Negative: Completely unrelated defect on different endpoint
	sqli := makeFinding("S1", "SQL Injection", "sql-injection", report.SeverityCritical, report.ConfidenceHigh, report.VerificationVerified, "https://app.example.com", "https://app.example.com/search")

	_, paths, rels, err := engine.Correlate(context.Background(), []report.Finding{hdr1, hdr2, sqli})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	foundCOR09 := false
	for _, r := range rels {
		if r.RuleCode == RuleCOR09 {
			foundCOR09 = true
			if r.Type != RelSharesRootCause {
				t.Errorf("expected SHARES_ROOT_CAUSE, got %s", r.Type)
			}
			if r.Type.IsSequenceType() {
				t.Errorf("SHARES_ROOT_CAUSE must NEVER be a sequence type")
			}
		}
		if r.RuleCode == RuleCOR09 && (r.SourceFindingID == "S1" || r.TargetFindingID == "S1") {
			t.Errorf("negative test failed: SQLi does not share root cause with missing headers")
		}
	}
	if !foundCOR09 {
		t.Errorf("expected positive COR-09 relationship")
	}

	// Verify that COR-09 does NOT produce any attack path
	for _, p := range paths {
		for _, e := range p.Edges {
			if e.RuleCode == RuleCOR09 {
				t.Errorf("critical failure: COR-09 edge must NEVER appear in an attack path")
			}
		}
	}
}

// COR-10: Impact Amplification
func TestRuleCOR10_PositiveAndNegative(t *testing.T) {
	engine := NewEngine(DefaultConfig())

	// Positive: Credentialed CORS reflection amplifies BOLA API
	cors := makeFinding("C1", "Arbitrary CORS Origin Reflection With Credentials", "cors-misconfiguration", report.SeverityHigh, report.ConfidenceHigh, report.VerificationVerified, "https://api.example.com", "https://api.example.com/api/v1")
	bola := makeFinding("B1", "BOLA on Tenant Ledger", "bola", report.SeverityHigh, report.ConfidenceHigh, report.VerificationVerified, "https://api.example.com", "https://api.example.com/api/v1/ledger")

	// Negative: Safe static endpoint without vulnerability
	safeDoc := makeFinding("S1", "Public Documentation", "discovery", report.SeverityInfo, report.ConfidenceHigh, report.VerificationVerified, "https://api.example.com", "https://api.example.com/docs")

	_, _, rels, err := engine.Correlate(context.Background(), []report.Finding{cors, bola, safeDoc})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	foundCOR10 := false
	for _, r := range rels {
		if r.RuleCode == RuleCOR10 && r.TargetFindingID == "B1" {
			foundCOR10 = true
			if r.Type != RelAmplifiesImpact {
				t.Errorf("expected AMPLIFIES_IMPACT, got %s", r.Type)
			}
		}
		if r.RuleCode == RuleCOR10 && r.TargetFindingID == "S1" {
			t.Errorf("negative test failed: safe static doc should not trigger COR-10")
		}
	}
	if !foundCOR10 {
		t.Errorf("expected positive COR-10 relationship")
	}
}

// -----------------------------------------------------------------------------
// Section 3: Attack-Path Verification Correctness
// -----------------------------------------------------------------------------

func TestPathVerification_AllConfirmedAndVerifiedTerminal(t *testing.T) {
	engine := NewEngine(DefaultConfig())
	f1 := makeFinding("F1", "Search Route", "api-route", report.SeverityInfo, report.ConfidenceHigh, report.VerificationVerified, "https://example.com", "https://example.com/search")
	f2 := makeFinding("F2", "SQL Injection", "sql-injection", report.SeverityCritical, report.ConfidenceHigh, report.VerificationVerified, "https://example.com", "https://example.com/search")

	_, paths, _, err := engine.Correlate(context.Background(), []report.Finding{f1, f2})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(paths) == 0 {
		t.Fatalf("expected attack path, got 0")
	}
	if paths[0].Status != PathVerified {
		t.Errorf("expected VERIFIED, got %s", paths[0].Status)
	}
}

func TestPathVerification_OnePlausibleTransition(t *testing.T) {
	engine := NewEngine(DefaultConfig())
	// Terminal finding is candidate -> edge is plausible -> path must be CANDIDATE
	f1 := makeFinding("F1", "Login Route", "api-route", report.SeverityInfo, report.ConfidenceHigh, report.VerificationVerified, "https://example.com", "https://example.com/login")
	f2 := makeFinding("F2", "Auth Bypass (Candidate)", "auth-bypass", report.SeverityHigh, report.ConfidenceMedium, report.VerificationDetected, "https://example.com", "https://example.com/login")

	_, paths, _, err := engine.Correlate(context.Background(), []report.Finding{f1, f2})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(paths) == 0 {
		t.Fatalf("expected candidate path, got 0")
	}
	if paths[0].Status != PathCandidate {
		t.Errorf("expected CANDIDATE, got %s", paths[0].Status)
	}
}

func TestPathVerification_OneInconclusiveTransition(t *testing.T) {
	engine := NewEngine(DefaultConfig())
	f1 := NormalizedFinding{
		ID:                 "F1",
		Title:              "Entry",
		Severity:           report.SeverityInfo,
		VerificationStatus: report.VerificationVerified,
		IsVerified:         true,
	}
	f2 := NormalizedFinding{
		ID:                 "F2",
		Title:              "Terminal",
		Severity:           report.SeverityCritical,
		VerificationStatus: report.VerificationVerified,
		IsVerified:         true,
	}

	// Hand-craft an edge with ValidationInconclusive
	inconclusiveEdge := Relationship{
		ID:               "REL-TEST-INCL",
		SourceFindingID:  "F1",
		TargetFindingID:  "F2",
		Type:             RelEnables,
		ValidationStatus: ValidationInconclusive,
		RuleCode:         RuleCOR01,
	}

	path := engine.constructPath([]string{"F1", "F2"}, []NormalizedFinding{f1, f2}, []Relationship{inconclusiveEdge})
	if path.Status != PathInconclusive {
		t.Errorf("expected INCONCLUSIVE path status when an edge is inconclusive, got %s", path.Status)
	}
}

func TestPathVerification_CandidateIntermediateFinding(t *testing.T) {
	engine := NewEngine(DefaultConfig())
	f1 := NormalizedFinding{
		ID:                 "F1",
		Title:              "Entry Route",
		Severity:           report.SeverityInfo,
		VerificationStatus: report.VerificationVerified,
		IsVerified:         true,
	}
	f2 := NormalizedFinding{
		ID:                 "F2",
		Title:              "Intermediate Step",
		Severity:           report.SeverityMedium,
		VerificationStatus: report.VerificationDetected, // Candidate!
		IsCandidate:        true,
	}
	f3 := NormalizedFinding{
		ID:                 "F3",
		Title:              "Terminal Exploit",
		Severity:           report.SeverityCritical,
		VerificationStatus: report.VerificationVerified,
		IsVerified:         true,
	}

	e1 := Relationship{
		SourceFindingID:  "F1",
		TargetFindingID:  "F2",
		Type:             RelEnables,
		ValidationStatus: ValidationConfirmed,
		RuleCode:         RuleCOR01,
	}
	e2 := Relationship{
		SourceFindingID:  "F2",
		TargetFindingID:  "F3",
		Type:             RelEnables,
		ValidationStatus: ValidationConfirmed,
		RuleCode:         RuleCOR02,
	}

	path := engine.constructPath([]string{"F1", "F2", "F3"}, []NormalizedFinding{f1, f2, f3}, []Relationship{e1, e2})
	if path.Status != PathCandidate {
		t.Errorf("path containing an unconfirmed intermediate candidate must be CANDIDATE, got %s", path.Status)
	}
}

func TestPathVerification_CyclePrevention(t *testing.T) {
	engine := NewEngine(DefaultConfig())

	// Build a cycle: A -> B -> A
	fA := makeFinding("A", "Route A", "workflow-circumvention", report.SeverityHigh, report.ConfidenceHigh, report.VerificationVerified, "https://app.example.com", "https://app.example.com/wf")
	fA.EvidenceDetails.Details["workflow_id"] = "WF-CYCLE"
	fB := makeFinding("B", "Route B", "unexpected-state-transition", report.SeverityHigh, report.ConfidenceHigh, report.VerificationVerified, "https://app.example.com", "https://app.example.com/wf")
	fB.EvidenceDetails.Details["workflow_id"] = "WF-CYCLE"

	summary, paths, _, err := engine.Correlate(context.Background(), []report.Finding{fA, fB})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Cycle must NOT cause infinite recursion or exceed MaxCandidatePaths
	if summary == nil {
		t.Fatal("expected summary")
	}
	for _, p := range paths {
		seen := make(map[string]bool)
		for _, nID := range p.NodeIDs {
			if seen[nID] {
				t.Fatalf("cycle detected in path: node %s appears multiple times in path %s", nID, p.ID)
			}
			seen[nID] = true
		}
	}
}

// -----------------------------------------------------------------------------
// Section 4: Combined-Risk Validation
// -----------------------------------------------------------------------------

func TestRisk_DeterministicCalculation(t *testing.T) {
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

	score1, level1, _ := AssessPathRisk(path)
	score2, level2, _ := AssessPathRisk(path)

	if score1 != score2 || level1 != level2 {
		t.Errorf("risk calculation must be deterministic: %d vs %d", score1, score2)
	}
}

func TestRisk_ScoreBoundsZeroToOneHundred(t *testing.T) {
	// Min bounds
	emptyPath := &AttackPath{}
	scoreMin, levelMin, _ := AssessPathRisk(emptyPath)
	if scoreMin < 0 || scoreMin > 100 || levelMin != report.SeverityInfo {
		t.Errorf("empty path score out of bounds: %d, %s", scoreMin, levelMin)
	}

	// Max bounds with multiple bonuses
	f1 := NormalizedFinding{ID: "F1", Severity: report.SeverityCritical, Score: 40}
	f2 := NormalizedFinding{ID: "F2", Severity: report.SeverityCritical, Score: 40, NormalizedCategory: "admin", Path: "/admin"}
	edges := []Relationship{
		{Type: RelEnables, ValidationStatus: ValidationConfirmed},
		{Type: RelEnables, ValidationStatus: ValidationConfirmed},
		{Type: RelEnables, ValidationStatus: ValidationConfirmed},
	}
	maxPath := &AttackPath{
		Status:     PathVerified,
		EntryPoint: "https://example.com/api",
		Nodes:      []NormalizedFinding{f1, f2},
		Edges:      edges,
	}
	scoreMax, levelMax, _ := AssessPathRisk(maxPath)
	if scoreMax > 100 || scoreMax < 80 || levelMax != report.SeverityCritical {
		t.Errorf("max score out of bounds: %d, %s", scoreMax, levelMax)
	}
}

func TestRisk_SharedRootCauseDoesNotInflateRisk(t *testing.T) {
	// Two nodes sharing identical category and path
	f1 := NormalizedFinding{
		ID:                 "F1",
		Severity:           report.SeverityLow,
		Score:              5,
		NormalizedCategory: "missing-headers",
		Path:               "/app",
	}
	f2 := NormalizedFinding{
		ID:                 "F2",
		Severity:           report.SeverityLow,
		Score:              5,
		NormalizedCategory: "missing-headers",
		Path:               "/app",
	}
	edges := []Relationship{
		{Type: RelEnables, ValidationStatus: ValidationConfirmed},
	}
	path := &AttackPath{
		Status: PathVerified,
		Nodes:  []NormalizedFinding{f1, f2},
		Edges:  edges,
	}

	score, _, rationale := AssessPathRisk(path)
	// Base score: 5 * 2 = 10. No transition bonus because uniqueDefects <= 1!
	if score > 15 {
		t.Errorf("shared root cause should not receive transition bonus, score: %d", score)
	}
	if !strings.Contains(rationale, "duplicate risk inflation prevented") {
		t.Errorf("expected rationale to state duplicate risk inflation prevented, got: %s", rationale)
	}
}

// -----------------------------------------------------------------------------
// Section 5: Evidence & Security Story Integrity
// -----------------------------------------------------------------------------

func TestSecurityStory_SyntheticProvenanceExplicit(t *testing.T) {
	f1 := NormalizedFinding{
		ID:                 "F1",
		Title:              "[SYNTHETIC SIMULATION] Entry",
		Endpoint:           "https://test.local/mock",
		SyntheticFixture:   true,
		VerificationStatus: report.VerificationVerified,
	}
	f2 := NormalizedFinding{
		ID:                 "F2",
		Title:              "[SYNTHETIC SIMULATION] Flaw",
		Endpoint:           "https://test.local/mock/flaw",
		SyntheticFixture:   true,
		VerificationStatus: report.VerificationVerified,
	}
	path := &AttackPath{
		ID:                "PATH-SYNTH-01",
		Title:             "Synthetic Path",
		Status:            PathVerified,
		SyntheticFixture:  true,
		CombinedRiskLevel: report.SeverityHigh,
		CombinedRiskScore: 65,
		Nodes:             []NormalizedFinding{f1, f2},
		Edges: []Relationship{
			{
				SourceFindingID:  "F1",
				TargetFindingID:  "F2",
				Type:             RelEnables,
				ValidationStatus: ValidationConfirmed,
				RuleCode:         RuleCOR01,
			},
		},
	}

	story := GenerateSecurityStory(path)
	if !strings.Contains(story.Title, "[SYNTHETIC FIXTURE]") {
		t.Errorf("story title must declare synthetic fixture provenance: %s", story.Title)
	}
	if !strings.Contains(story.Summary, "SYNTHETIC TEST FIXTURE") {
		t.Errorf("story summary must declare synthetic provenance: %s", story.Summary)
	}
}

func TestSecurityStory_CandidateImpactFramingNotConfirmed(t *testing.T) {
	f1 := NormalizedFinding{
		ID:       "F1",
		Title:    "Candidate Entry",
		Endpoint: "https://example.com/entry",
	}
	f2 := NormalizedFinding{
		ID:          "F2",
		Title:       "Potential Flaw",
		Endpoint:    "https://example.com/flaw",
		IsCandidate: true,
	}
	path := &AttackPath{
		ID:                "PATH-CAND-01",
		Title:             "Candidate Security Sequence",
		Status:            PathCandidate,
		CombinedRiskLevel: report.SeverityHigh,
		CombinedRiskScore: 60,
		Nodes:             []NormalizedFinding{f1, f2},
		Edges: []Relationship{
			{
				SourceFindingID:  "F1",
				TargetFindingID:  "F2",
				Type:             RelEnables,
				ValidationStatus: ValidationPlausible,
				RuleCode:         RuleCOR01,
			},
		},
	}

	story := GenerateSecurityStory(path)
	if !strings.Contains(story.Title, "(Candidate)") {
		t.Errorf("story title for candidate path must contain (Candidate): %s", story.Title)
	}
	if strings.Contains(story.Description, "enables access to") && !strings.Contains(story.Description, "potentially") {
		t.Errorf("unverified candidate description must not declare access as confirmed: %s", story.Description)
	}
}

// -----------------------------------------------------------------------------
// Section 7: Controlled End-to-End Scenarios (A - E)
// -----------------------------------------------------------------------------

// Scenario A — Valid BOLA chain
func TestScenarioA_ValidBOLAChain(t *testing.T) {
	engine := NewEngine(DefaultConfig())

	fEntry := makeFinding("A-ENTRY", "Customer Portal Route", "api-route", report.SeverityInfo, report.ConfidenceHigh, report.VerificationVerified, "https://api.example.com", "https://api.example.com/customers")
	fBola := makeFinding("A-BOLA", "Broken Object-Level Authorization on Customer Record", "bola", report.SeverityHigh, report.ConfidenceHigh, report.VerificationVerified, "https://api.example.com", "https://api.example.com/customers/{id}")
	fBola.EvidenceDetails.Details["bola"] = "true"
	fData := makeFinding("A-DATA", "Customer Financial and Identity Information Disclosed", "sensitive-data-exposure", report.SeverityHigh, report.ConfidenceHigh, report.VerificationVerified, "https://api.example.com", "https://api.example.com/customers/{id}")
	fData.EvidenceDetails.Details["sensitive_data"] = "true"

	summary, paths, rels, err := engine.Correlate(context.Background(), []report.Finding{fEntry, fBola, fData})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if summary.VerifiedPaths < 1 {
		t.Errorf("Scenario A: expected at least 1 verified attack path, got %d", summary.VerifiedPaths)
	}
	if len(rels) < 2 {
		t.Errorf("Scenario A: expected at least 2 relationships (COR-01 + COR-03), got %d", len(rels))
	}
	if len(paths) == 0 || paths[0].Status != PathVerified {
		t.Errorf("Scenario A: expected primary path to be VERIFIED, got %s", paths[0].Status)
	}
}

// Scenario B — Similar-looking but unrelated findings
func TestScenarioB_UnrelatedFindingsNoPath(t *testing.T) {
	engine := NewEngine(DefaultConfig())

	// Two findings share the same origin, but have disjoint routes, different categories, no shared state
	f1 := makeFinding("B-STATIC", "Static Favicon Endpoint", "discovery", report.SeverityInfo, report.ConfidenceHigh, report.VerificationVerified, "https://app.example.com", "https://app.example.com/favicon.ico")
	f2 := makeFinding("B-SQLI", "SQL Injection in Reporting Tool", "sql-injection", report.SeverityCritical, report.ConfidenceHigh, report.VerificationVerified, "https://app.example.com", "https://app.example.com/internal/reports/export")

	summary, paths, _, err := engine.Correlate(context.Background(), []report.Finding{f1, f2})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(paths) != 0 {
		t.Errorf("Scenario B: expected 0 fabricated attack paths between unrelated endpoints, got %d", len(paths))
	}
	if summary.VerifiedPaths != 0 || summary.CandidatePaths != 0 {
		t.Errorf("Scenario B: expected 0 candidate/verified paths in summary")
	}
}

// Scenario C — Incomplete attack chain
func TestScenarioC_IncompleteChainCandidateOrInconclusive(t *testing.T) {
	engine := NewEngine(DefaultConfig())

	// Verified entrypoint + unconfirmed candidate bypass
	fEntry := makeFinding("C-ENTRY", "Web Auth Form", "api-route", report.SeverityInfo, report.ConfidenceHigh, report.VerificationVerified, "https://app.example.com", "https://app.example.com/login")
	fCand := makeFinding("C-CAND", "Suspected Timing Discrepancy (Candidate)", "auth-bypass", report.SeverityMedium, report.ConfidenceLow, report.VerificationDetected, "https://app.example.com", "https://app.example.com/login")

	summary, paths, _, err := engine.Correlate(context.Background(), []report.Finding{fEntry, fCand})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if summary.VerifiedPaths != 0 {
		t.Errorf("Scenario C: unconfirmed chain must NEVER produce verified paths, got %d", summary.VerifiedPaths)
	}
	if len(paths) == 0 {
		t.Fatalf("Scenario C: expected candidate path, got 0")
	}
	if paths[0].Status != PathCandidate {
		t.Errorf("Scenario C: expected path status CANDIDATE, got %s", paths[0].Status)
	}
}

// Scenario D — Common root cause
func TestScenarioD_CommonRootCauseNoPath(t *testing.T) {
	engine := NewEngine(DefaultConfig())

	// Two findings sharing missing headers
	f1 := makeFinding("D-H1", "Missing Referrer-Policy", "missing-security-headers", report.SeverityLow, report.ConfidenceHigh, report.VerificationVerified, "https://app.example.com", "https://app.example.com/home")
	f2 := makeFinding("D-H2", "Missing Permissions-Policy", "missing-security-headers", report.SeverityLow, report.ConfidenceHigh, report.VerificationVerified, "https://app.example.com", "https://app.example.com/home")

	summary, paths, rels, err := engine.Correlate(context.Background(), []report.Finding{f1, f2})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Rule COR-09 correlation exists:
	if len(rels) == 0 {
		t.Errorf("Scenario D: expected root cause relationship to be identified")
	}
	// But NO attack path is fabricated:
	if len(paths) != 0 {
		t.Errorf("Scenario D: common root cause must NOT create an exploit path, got %d", len(paths))
	}
	if summary.CandidatePaths != 0 || summary.VerifiedPaths != 0 {
		t.Errorf("Scenario D: summary paths must be 0")
	}
}

// Scenario E — Synthetic versus live provenance
func TestScenarioE_SyntheticProvenancePreserved(t *testing.T) {
	engine := NewEngine(DefaultConfig())

	f1 := makeFinding("E-SYNTH1", "Synthetic Test Route", "api-route", report.SeverityInfo, report.ConfidenceHigh, report.VerificationVerified, "https://test.local", "https://test.local/order")
	f1.EvidenceDetails.Details["synthetic_fixture"] = "true"
	f2 := makeFinding("E-SYNTH2", "Synthetic Test SQLi", "sql-injection", report.SeverityHigh, report.ConfidenceHigh, report.VerificationVerified, "https://test.local", "https://test.local/order")
	f2.EvidenceDetails.Details["synthetic_fixture"] = "true"

	summary, paths, _, err := engine.Correlate(context.Background(), []report.Finding{f1, f2})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !summary.SyntheticFixture {
		t.Errorf("Scenario E: summary.SyntheticFixture must be true")
	}
	if len(paths) == 0 {
		t.Fatalf("Scenario E: expected path")
	}
	if !paths[0].SyntheticFixture {
		t.Errorf("Scenario E: path.SyntheticFixture must be true")
	}
	if !strings.Contains(paths[0].SecurityStory.Title, "[SYNTHETIC FIXTURE]") {
		t.Errorf("Scenario E: SecurityStory must declare synthetic provenance in title: %s", paths[0].SecurityStory.Title)
	}
}
