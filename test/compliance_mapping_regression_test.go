package test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"felix/pkg/compliance"
	"felix/pkg/report"
)

// TestPhase92_FindingToControlMapping_EndToEnd tests the complete Phase 9.2 finding-to-control mapping pipeline:
// catalog loading, ruleset loading, relational validation, multi-engine findings mapping,
// distinct coverage tracking, and non-evaluation boundaries.
func TestPhase92_FindingToControlMapping_EndToEnd(t *testing.T) {
	tmpDir := t.TempDir()

	// 1. Write and Load Validated Catalog
	catalogJSON := `{
		"schema_version": "1.0",
		"id": "nist-sp800-53-sample",
		"title": "NIST SP 800-53 Sample Catalog",
		"version": "5.1.0",
		"framework": "NIST",
		"description": "Security and Privacy Controls for Information Systems and Organizations",
		"source": {
			"name": "NIST Computer Security Resource Center",
			"url": "https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final",
			"publisher": "National Institute of Standards and Technology",
			"is_authoritative": true,
			"limitations": "Informational catalog mapping; target environment compliance depends on formal assessment."
		},
		"controls": [
			{
				"id": "AC-3",
				"title": "Access Enforcement",
				"description": "Enforce approved authorizations for logical access to information and system resources.",
				"status": "active",
				"category": "Access Control",
				"severity": "HIGH"
			},
			{
				"id": "AC-6",
				"title": "Least Privilege",
				"description": "Employ the principle of least privilege, allowing only authorized accesses.",
				"status": "active",
				"category": "Access Control",
				"severity": "HIGH"
			},
			{
				"id": "IA-2",
				"title": "Identification and Authentication",
				"description": "Uniquely identify and authenticate organizational users and processes.",
				"status": "active",
				"category": "Identification and Authentication",
				"severity": "HIGH"
			},
			{
				"id": "SI-10",
				"title": "Information Input Validation",
				"description": "Check the validity of information inputs to prevent injection attacks.",
				"status": "active",
				"category": "System and Information Integrity",
				"severity": "CRITICAL"
			},
			{
				"id": "SC-7",
				"title": "Boundary Protection",
				"description": "Monitor and control communications at external and internal system boundaries.",
				"status": "active",
				"category": "System and Communications Protection",
				"severity": "MEDIUM"
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
		"id": "felix-nist-ruleset",
		"title": "FELIX to NIST SP 800-53 Mappings",
		"version": "1.0.0",
		"target_catalog_id": "nist-sp800-53-sample",
		"target_catalog_version": "5.1.0",
		"rules": [
			{
				"id": "RULE-SQLI-SI10",
				"source_rule_id": "WEB_SQL_INJECTION",
				"source_category": "injection",
				"target_control_id": "SI-10",
				"relationship": "direct",
				"rationale": "SQL injection demonstrates unvalidated information input handling.",
				"confidence": 1.0
			},
			{
				"id": "RULE-SQLI-AC3",
				"source_rule_id": "WEB_SQL_INJECTION",
				"target_control_id": "AC-3",
				"relationship": "partial_evidence",
				"rationale": "SQL injection subverts authorization barriers at the data tier.",
				"confidence": 0.85
			},
			{
				"id": "RULE-API-AUTH-IA2",
				"source_rule_id": "APISPEC_NO_AUTH",
				"target_control_id": "IA-2",
				"relationship": "direct",
				"rationale": "Missing endpoint authentication directly breaches user identification mandates.",
				"confidence": 0.95
			},
			{
				"id": "RULE-CLOUD-S3-AC3",
				"source_rule_id": "AWS_S3_PUBLIC_READ",
				"target_control_id": "AC-3",
				"relationship": "direct",
				"rationale": "Publicly exposed storage buckets bypass access enforcement policies.",
				"confidence": 0.9
			},
			{
				"id": "RULE-CLOUD-S3-SC7",
				"source_rule_id": "AWS_S3_PUBLIC_READ",
				"target_control_id": "SC-7",
				"relationship": "partial_evidence",
				"rationale": "Public object storage breaches system perimeter boundary boundaries.",
				"confidence": 0.8
			},
			{
				"id": "RULE-IAM-OVERPRIV-AC6",
				"source_rule_id": "IAM_WILDCARD_PERMISSIONS",
				"target_control_id": "AC-6",
				"relationship": "direct",
				"rationale": "Wildcard IAM actions violate the principle of least privilege.",
				"confidence": 0.92
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

	// 3. Validate RuleSet with Catalog
	if err := compliance.ValidateMappingRuleSet(ruleSet, catalog); err != nil {
		t.Fatalf("ValidateMappingRuleSet with catalog failed: %v", err)
	}

	// 4. Create Realistic Multi-Engine Findings
	findings := []report.Finding{
		{
			ID:          "FINDING-WEB-001",
			Source:      "webvuln",
			RuleID:      "WEB_SQL_INJECTION",
			Category:    "injection",
			Title:       "SQL Injection in Search Form",
			Severity:    "CRITICAL",
			Evidence:    "SLEEP(5) induced response delay of 5.12s",
			Endpoint:    "/api/v1/search",
			Fingerprint: "fp-sqli-001",
			EvidenceDetails: report.EvidenceDetails{
				Location:    "/api/v1/search?q=test'",
				Observation: "SQL syntax error and time delay confirmed",
			},
		},
		{
			ID:          "FINDING-API-001",
			Source:      "apisec",
			RuleID:      "APISPEC_NO_AUTH",
			Category:    "auth",
			Title:       "Unprotected Management API",
			Severity:    "HIGH",
			Evidence:    "HTTP 200 OK returned sensitive user payload without Authorization",
			Endpoint:    "/api/v1/admin/config",
			Fingerprint: "fp-api-001",
			EvidenceDetails: report.EvidenceDetails{
				Location:    "/api/v1/admin/config",
				Observation: "Endpoint does not declare security requirements",
				HTTPStatus:  200,
			},
		},
		{
			ID:          "FINDING-CLOUD-001",
			Source:      "cloudsec",
			RuleID:      "AWS_S3_PUBLIC_READ",
			Category:    "cloud",
			Title:       "World-Readable S3 Bucket",
			Severity:    "HIGH",
			Evidence:    "Anonymous GET s3://company-reports returned 200 OK",
			Endpoint:    "s3://company-reports",
			Fingerprint: "fp-cloud-001",
			EvidenceDetails: report.EvidenceDetails{
				Location:    "s3://company-reports",
				Observation: "Bucket policy grants s3:GetObject to Principal *",
			},
		},
		{
			ID:       "FINDING-CLOUD-002",
			Source:   "cloudsec",
			RuleID:   "IAM_WILDCARD_PERMISSIONS",
			Category: "cloud",
			Title:    "Overpermissive IAM Role",
			Severity: "MEDIUM",
			// Intentionally empty evidence string & details to test evidence-backed differentiation
			Endpoint:    "arn:aws:iam::123456789012:role/app-worker",
			Fingerprint: "fp-cloud-002",
		},
		{
			ID:       "FINDING-UNMAPPED-001",
			Source:   "hostsec",
			RuleID:   "OPEN_PORT_TELNET",
			Category: "network",
			Title:    "Telnet Service Detected",
			Severity: "MEDIUM",
			Endpoint: "tcp://192.168.1.50:23",
		},
	}

	// 5. Execute Mapping Engine with Fixed Clock for Determinism
	fixedTime := time.Date(2026, 10, 21, 16, 0, 0, 0, time.UTC)
	engine := compliance.NewMappingEngine().WithClock(func() time.Time { return fixedTime })

	result, err := engine.MapFindings(catalog, ruleSet, findings)
	if err != nil {
		t.Fatalf("MapFindings failed: %v", err)
	}

	// 6. Verify Mapping Outcomes
	// FINDING-WEB-001 -> SI-10 (direct), AC-3 (partial_evidence) [2 mappings]
	// FINDING-API-001 -> IA-2 (direct) [1 mapping]
	// FINDING-CLOUD-001 -> AC-3 (direct), SC-7 (partial_evidence) [2 mappings]
	// FINDING-CLOUD-002 -> AC-6 (direct) [1 mapping]
	// FINDING-UNMAPPED-001 -> unmapped [0 mappings]
	// Total expected mappings: 6
	if len(result.Mappings) != 6 {
		t.Fatalf("expected 6 mappings, got %d", len(result.Mappings))
	}
	if len(result.Unmapped) != 1 {
		t.Fatalf("expected 1 unmapped finding, got %d", len(result.Unmapped))
	}
	if result.Unmapped[0].FindingID != "FINDING-UNMAPPED-001" {
		t.Errorf("expected FINDING-UNMAPPED-001 in unmapped, got %q", result.Unmapped[0].FindingID)
	}

	// 7. Verify Distinct Quantitative Coverage Metrics
	cov := result.Coverage
	if cov.TotalFindings != 5 {
		t.Errorf("expected TotalFindings 5, got %d", cov.TotalFindings)
	}
	if cov.MappedFindings != 4 {
		t.Errorf("expected MappedFindings 4 (unique findings), got %d", cov.MappedFindings)
	}
	if cov.UnmappedFindings != 1 {
		t.Errorf("expected UnmappedFindings 1, got %d", cov.UnmappedFindings)
	}
	if cov.TotalMappings != 6 {
		t.Errorf("expected TotalMappings 6, got %d", cov.TotalMappings)
	}
	if cov.MultiMappedFindings != 2 { // WEB-001 and CLOUD-001
		t.Errorf("expected MultiMappedFindings 2, got %d", cov.MultiMappedFindings)
	}
	expectedReferencedControls := []string{"AC-3", "AC-6", "IA-2", "SC-7", "SI-10"}
	if len(cov.ReferencedControls) != len(expectedReferencedControls) {
		t.Errorf("expected %d referenced controls, got %d: %v",
			len(expectedReferencedControls), len(cov.ReferencedControls), cov.ReferencedControls)
	}

	// 8. Verify Evidence Accuracy Invariant
	for _, m := range result.Mappings {
		if m.FindingID == "FINDING-CLOUD-002" {
			if m.HasEvidence {
				t.Errorf("FINDING-CLOUD-002 has no evidence, but HasEvidence was true")
			}
			if m.EvidenceLocation != "" {
				t.Errorf("FINDING-CLOUD-002 has empty evidence, but EvidenceLocation was %q", m.EvidenceLocation)
			}
		} else {
			if !m.HasEvidence {
				t.Errorf("expected HasEvidence=true for %q", m.FindingID)
			}
			if m.EvidenceLocation == "" {
				t.Errorf("expected non-empty EvidenceLocation for %q", m.FindingID)
			}
		}
	}

	// 9. Verify Compliance Evaluation Boundary Invariant
	notice := result.LimitationsNotice
	if !strings.Contains(notice, "NOT constitute a compliance evaluation") {
		t.Errorf("expected LimitationsNotice to disclaim compliance evaluation: %q", notice)
	}

	// Check JSON serialization
	data, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("failed marshaling mapping result: %v", err)
	}

	var jsonMap map[string]any
	if err := json.Unmarshal(data, &jsonMap); err != nil {
		t.Fatalf("failed unmarshaling mapping result JSON: %v", err)
	}

	forbiddenVerdicts := []string{"compliant", "non_compliant", "partially_compliant", "passed", "failed", "evaluation_status", "audit_result"}
	for _, verdict := range forbiddenVerdicts {
		if _, exists := jsonMap[verdict]; exists {
			t.Errorf("forbidden compliance evaluation field %q found in JSON output", verdict)
		}
	}

	// 10. Verify Canonical Provenance & Digest Invariants
	if result.CatalogIdentity != "nist-sp800-53-sample:5.1.0" {
		t.Errorf("unexpected CatalogIdentity: %q", result.CatalogIdentity)
	}
	if !strings.HasPrefix(result.CatalogDigest, "sha256:") {
		t.Errorf("expected sha256 prefix on CatalogDigest: %q", result.CatalogDigest)
	}
	if result.MappingRuleSetIdentity != "felix-nist-ruleset:1.0.0" {
		t.Errorf("unexpected MappingRuleSetIdentity: %q", result.MappingRuleSetIdentity)
	}
	if !strings.HasPrefix(result.MappingRuleSetDigest, "sha256:") {
		t.Errorf("expected sha256 prefix on MappingRuleSetDigest: %q", result.MappingRuleSetDigest)
	}
}
