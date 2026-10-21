package test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"felix/pkg/compliance"
	"felix/pkg/report"
)

// TestPhase93_ComplianceEvaluation_EndToEnd tests the complete Phase 9.3 compliance evaluation pipeline:
// validated catalog, validated finding-to-control mappings, positive evidence,
// applicability determinations, multi-engine findings, state synthesis, and summary balance.
func TestPhase93_ComplianceEvaluation_EndToEnd(t *testing.T) {
	tmpDir := t.TempDir()

	// 1. Write and Load Validated Catalog with 7 controls
	catalogJSON := `{
		"schema_version": "1.0",
		"id": "nist-sp800-53-eval-e2e",
		"title": "NIST SP 800-53 Comprehensive Evaluation Catalog",
		"version": "5.1.0",
		"framework": "NIST",
		"controls": [
			{
				"id": "AC-2",
				"title": "Account Management",
				"description": "Manage system accounts, identifiers, and credentials.",
				"status": "active"
			},
			{
				"id": "AC-3",
				"title": "Access Enforcement",
				"description": "Enforce approved authorizations for logical access.",
				"status": "active"
			},
			{
				"id": "IA-2",
				"title": "Identification and Authentication",
				"description": "Uniquely identify and authenticate organizational users.",
				"status": "active"
			},
			{
				"id": "SI-10",
				"title": "Information Input Validation",
				"description": "Check information inputs for validity.",
				"status": "active"
			},
			{
				"id": "SC-7",
				"title": "Boundary Protection",
				"description": "Monitor and control communications at external boundary.",
				"status": "active"
			},
			{
				"id": "SC-13",
				"title": "Cryptographic Protection",
				"description": "Implement cryptographic mechanisms to protect data in transit.",
				"status": "active"
			},
			{
				"id": "AU-2",
				"title": "Event Logging",
				"description": "Identify that the system can audit security events.",
				"status": "active"
			}
		]
	}`

	catalogPath := filepath.Join(tmpDir, "catalog.json")
	if err := os.WriteFile(catalogPath, []byte(catalogJSON), 0644); err != nil {
		t.Fatalf("failed writing test catalog: %v", err)
	}

	catalog, err := compliance.LoadCatalog(catalogPath)
	if err != nil {
		t.Fatalf("LoadCatalog failed: %v", err)
	}

	// 2. Write and Load Validated Mapping RuleSet
	rulesetJSON := `{
		"schema_version": "1.0",
		"id": "felix-nist-eval-ruleset",
		"title": "FELIX to NIST SP 800-53 Evaluation Ruleset",
		"version": "1.0.0",
		"target_catalog_id": "nist-sp800-53-eval-e2e",
		"target_catalog_version": "5.1.0",
		"rules": [
			{
				"id": "RULE-SQLI-SI10",
				"source_rule_id": "WEB_SQL_INJECTION",
				"target_control_id": "SI-10",
				"relationship": "direct",
				"rationale": "SQL injection directly violates input validation requirements.",
				"confidence": 1.0
			},
			{
				"id": "RULE-XSS-SI10",
				"source_rule_id": "WEB_XSS",
				"target_control_id": "SI-10",
				"relationship": "direct",
				"rationale": "Cross-site scripting violates output and input sanitization requirements.",
				"confidence": 0.95
			},
			{
				"id": "RULE-AUTH-IA2",
				"source_rule_id": "APISPEC_NO_AUTH",
				"target_control_id": "IA-2",
				"relationship": "direct",
				"rationale": "Unprotected API violates mandatory user identification and authentication.",
				"confidence": 0.95
			},
			{
				"id": "RULE-BOLA-AC3",
				"source_rule_id": "API_BOLA_IDOR",
				"target_control_id": "AC-3",
				"relationship": "direct",
				"rationale": "Object-level authorization bypass violates access enforcement.",
				"confidence": 0.9
			},
			{
				"id": "RULE-AUDIT-SUSPECTED",
				"source_rule_id": "LOG_INSPECTION_ANOMALY",
				"target_control_id": "AU-2",
				"relationship": "partial_evidence",
				"rationale": "Log parsing anomalies provide partial evidence of auditing concerns.",
				"confidence": 0.7
			}
		]
	}`

	rulesetPath := filepath.Join(tmpDir, "ruleset.json")
	if err := os.WriteFile(rulesetPath, []byte(rulesetJSON), 0644); err != nil {
		t.Fatalf("failed writing test ruleset: %v", err)
	}

	ruleSet, err := compliance.LoadMappingRuleSet(rulesetPath)
	if err != nil {
		t.Fatalf("LoadMappingRuleSet failed: %v", err)
	}

	if err := compliance.ValidateMappingRuleSet(ruleSet, catalog); err != nil {
		t.Fatalf("ValidateMappingRuleSet failed: %v", err)
	}

	// 3. Create Multi-Engine Findings with distinct verification states
	findings := []report.Finding{
		// AC-3: Confirmed violation
		{
			ID:           "F-AC3-BOLA",
			Source:       "apisec",
			RuleID:       "API_BOLA_IDOR",
			Category:     "authz",
			Title:        "Broken Object Level Authorization on /api/orders/{id}",
			Severity:     "HIGH",
			Status:       report.FindingStatusConfirmed,
			Evidence:     "User B retrieved order 104 belonging to User A",
			Endpoint:     "/api/orders/104",
			Verification: report.VerificationRecord{Status: report.VerificationVerified},
		},
		// SI-10: Sub-requirement SQLi violated
		{
			ID:           "F-SI10-SQLI",
			Source:       "webvuln",
			RuleID:       "WEB_SQL_INJECTION",
			Category:     "injection",
			Title:        "SQL Injection in Search Query",
			Severity:     "CRITICAL",
			Status:       report.FindingStatusConfirmed,
			Evidence:     "SLEEP(5) induced 5.2s delay",
			Endpoint:     "/api/search",
			Verification: report.VerificationRecord{Status: report.VerificationVerified},
		},
		// AU-2: Suspected observation (inconclusive / inadequate evidence)
		{
			ID:       "F-AU2-SUSPECTED",
			Source:   "crawler",
			RuleID:   "LOG_INSPECTION_ANOMALY",
			Category: "audit",
			Title:    "Potential audit gap in log stream",
			Severity: "LOW",
			Status:   report.FindingStatusSuspected,
			Evidence: "Anomaly score 0.65",
			Endpoint: "/api/logs",
		},
	}

	// Execute Finding-to-Control Mapping
	mappingResult, err := compliance.MapFindings(catalog, ruleSet, findings)
	if err != nil {
		t.Fatalf("MapFindings failed: %v", err)
	}

	// 4. Construct EvaluationContext covering all outcome categories
	ctx := &compliance.EvaluationContext{
		AssessmentID:     "ASM-2026-EVAL-E2E",
		ExecutionID:      "EXEC-001",
		AssessmentStatus: "COMPLETED",
		TargetScope:      []string{"https://api.example.com", "https://app.example.com"},
		Applicability: map[string]compliance.ApplicabilityDetermination{
			// SC-7: Explicitly supported inapplicability
			"SC-7": {
				ControlID:  "SC-7",
				Applicable: false,
				Rationale:  "Containerized internal worker without direct external ingress perimeter",
				Basis:      "CLOUD_VPC_ARCHITECTURE_EXEMPTION_DOC_V2",
			},
		},
		PositiveEvidence: []compliance.PositiveEvidence{
			// SC-13: Compliant from verified positive evidence (TLS 1.3 enforced on all targets in scope)
			{
				ID:          "PE-TLS-001",
				ControlID:   "SC-13",
				Location:    "https://api.example.com",
				Requirement: "transport_encryption",
				Observation: "TLS 1.3 strictly enforced with secure cipher suites; SSLv3/TLS 1.0/1.1 rejected",
				Method:      "ACTIVE_TLS_HANDSHAKE_PROBE",
			},
			{
				ID:          "PE-TLS-002",
				ControlID:   "SC-13",
				Location:    "https://app.example.com",
				Requirement: "transport_encryption",
				Observation: "TLS 1.3 strictly enforced on web application domain",
				Method:      "ACTIVE_TLS_HANDSHAKE_PROBE",
			},
			// SI-10: Sub-requirement XSS satisfied (giving partially_compliant alongside SQLi violation)
			{
				ID:          "PE-XSS-PASS",
				ControlID:   "SI-10",
				Location:    "https://app.example.com",
				Requirement: "WEB_XSS",
				Observation: "Content Security Policy and contextual HTML encoding verified against XSS",
				Method:      "ACTIVE_DOM_AND_HEADER_INSPECTION",
			},
		},
		ExecutionErrors: map[string]string{
			// AC-2: Concrete evaluation error
			"AC-2": "Directory connection timeout after 3 retries (LDAP socket reset by peer)",
		},
	}

	// 5. Execute Evaluation Engine
	fixedTime := time.Date(2026, 10, 21, 16, 30, 0, 0, time.UTC)
	engine := compliance.NewEvaluationEngine(compliance.EvaluationPolicy{
		AllowPartialCompliance: true,
	}).WithClock(func() time.Time { return fixedTime })

	result, err := engine.Evaluate(catalog, mappingResult, findings, ctx)
	if err != nil {
		t.Fatalf("Evaluate failed: %v", err)
	}

	// 6. Verify Exact Outcome for Each Control
	outcomes := make(map[string]compliance.EvaluationState, len(result.Evaluations))
	for _, ev := range result.Evaluations {
		outcomes[ev.ControlID] = ev.State
	}

	// AC-2: error (LDAP timeout)
	if outcomes["AC-2"] != compliance.StateError {
		t.Errorf("expected AC-2 state=error, got %q", outcomes["AC-2"])
	}

	// AC-3: non_compliant (confirmed BOLA finding)
	if outcomes["AC-3"] != compliance.StateNonCompliant {
		t.Errorf("expected AC-3 state=non_compliant, got %q", outcomes["AC-3"])
	}

	// IA-2: not_assessed (no findings, no positive evidence)
	if outcomes["IA-2"] != compliance.StateNotAssessed {
		t.Errorf("expected IA-2 state=not_assessed, got %q", outcomes["IA-2"])
	}

	// SI-10: partially_compliant (SQLi violated, XSS satisfied)
	if outcomes["SI-10"] != compliance.StatePartiallyCompliant {
		t.Errorf("expected SI-10 state=partially_compliant, got %q", outcomes["SI-10"])
	}

	// SC-7: not_applicable (exemption with valid basis)
	if outcomes["SC-7"] != compliance.StateNotApplicable {
		t.Errorf("expected SC-7 state=not_applicable, got %q", outcomes["SC-7"])
	}

	// SC-13: compliant (verified TLS 1.3 positive evidence)
	if outcomes["SC-13"] != compliance.StateCompliant {
		t.Errorf("expected SC-13 state=compliant, got %q", outcomes["SC-13"])
	}

	// AU-2: insufficient_evidence (suspected finding without confirmed proof)
	if outcomes["AU-2"] != compliance.StateInsufficientEvidence {
		t.Errorf("expected AU-2 state=insufficient_evidence, got %q", outcomes["AU-2"])
	}

	// 7. Verify Summary Balance and Integrity
	sum := result.Summary
	if sum.TotalControls != 7 {
		t.Errorf("expected TotalControls=7, got %d", sum.TotalControls)
	}
	if sum.CompliantCount != 1 {
		t.Errorf("expected CompliantCount=1 (SC-13), got %d", sum.CompliantCount)
	}
	if sum.NonCompliantCount != 1 {
		t.Errorf("expected NonCompliantCount=1 (AC-3), got %d", sum.NonCompliantCount)
	}
	if sum.PartiallyCompliantCount != 1 {
		t.Errorf("expected PartiallyCompliantCount=1 (SI-10), got %d", sum.PartiallyCompliantCount)
	}
	if sum.NotApplicableCount != 1 {
		t.Errorf("expected NotApplicableCount=1 (SC-7), got %d", sum.NotApplicableCount)
	}
	if sum.NotAssessedCount != 1 {
		t.Errorf("expected NotAssessedCount=1 (IA-2), got %d", sum.NotAssessedCount)
	}
	if sum.InsufficientEvidenceCount != 1 {
		t.Errorf("expected InsufficientEvidenceCount=1 (AU-2), got %d", sum.InsufficientEvidenceCount)
	}
	if sum.ErrorCount != 1 {
		t.Errorf("expected ErrorCount=1 (AC-2), got %d", sum.ErrorCount)
	}

	totalSum := sum.CompliantCount +
		sum.NonCompliantCount +
		sum.PartiallyCompliantCount +
		sum.NotApplicableCount +
		sum.NotAssessedCount +
		sum.InsufficientEvidenceCount +
		sum.ErrorCount

	if totalSum != sum.TotalControls {
		t.Errorf("summary counts sum (%d) does not match TotalControls (%d)", totalSum, sum.TotalControls)
	}

	// 8. Validate Evaluation Result through Validator
	if err := compliance.ValidateEvaluationResult(result, catalog); err != nil {
		t.Fatalf("ValidateEvaluationResult failed on valid result: %v", err)
	}

	// 9. Verify Deterministic Digest Stability
	digest1 := result.Digest()
	if !strings.HasPrefix(digest1, "sha256:") {
		t.Errorf("expected sha256 prefix on Digest: %q", digest1)
	}
	digest2 := result.Digest()
	if digest1 != digest2 {
		t.Errorf("Digest is not deterministic across repeated calls!")
	}

	// 10. Verify Limitations Disclosure
	notice := result.LimitationsNotice
	if !strings.Contains(notice, "NOT constitute a formal regulatory certification") {
		t.Errorf("LimitationsNotice missing required certification disclaimer: %q", notice)
	}
}
