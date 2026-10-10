package report

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSARIF_StructuralValidityAndSchema(t *testing.T) {
	rep := Report{
		Version: "2.0.0",
		Target:  "https://target.example.com",
		Findings: []Finding{
			{
				ID:          "FELIX-BOLA-01",
				Title:       "BOLA on Order API",
				Category:    "BOLA",
				Severity:    SeverityHigh,
				Confidence:  ConfidenceHigh,
				Target:      "https://target.example.com",
				Endpoint:    "/api/v1/orders/101",
				Method:      "GET",
				Description: "Cross-tenant access allowed to user orders",
				Evidence:    "HTTP 200 OK returned private data",
				Verification: VerificationRecord{
					Status: VerificationVerified,
					Result: "CONFIRMED_VULNERABILITY",
				},
				Score:       85,
				Fingerprint: "fp-bola-01",
			},
		},
	}

	data, err := GenerateSARIF(rep)
	if err != nil {
		t.Fatalf("GenerateSARIF failed: %v", err)
	}

	var sarifLog SARIFLog
	if err := json.Unmarshal(data, &sarifLog); err != nil {
		t.Fatalf("failed to unmarshal generated SARIF: %v", err)
	}

	if sarifLog.Version != "2.1.0" {
		t.Errorf("expected SARIF version 2.1.0, got %s", sarifLog.Version)
	}
	if !strings.Contains(sarifLog.Schema, "sarif-schema-2.1.0.json") {
		t.Errorf("expected SARIF schema URI, got %s", sarifLog.Schema)
	}
	if len(sarifLog.Runs) != 1 {
		t.Fatalf("expected 1 run, got %d", len(sarifLog.Runs))
	}

	run := sarifLog.Runs[0]
	if run.Tool.Driver.Name != "Felix" {
		t.Errorf("expected tool name Felix, got %s", run.Tool.Driver.Name)
	}
	if len(run.Results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(run.Results))
	}

	res := run.Results[0]
	if res.RuleID != "BOLA" {
		t.Errorf("expected ruleId BOLA, got %s", res.RuleID)
	}
	if res.Level != "error" {
		t.Errorf("expected level error for HIGH severity, got %s", res.Level)
	}

	// Verify locations without fake line numbers
	if len(res.Locations) == 0 {
		t.Fatalf("expected at least 1 location")
	}
	loc := res.Locations[0]
	if loc.PhysicalLocation == nil || loc.PhysicalLocation.ArtifactLocation.URI != "/api/v1/orders/101" {
		t.Errorf("expected artifact location URI /api/v1/orders/101, got %v", loc.PhysicalLocation)
	}
	if len(loc.LogicalLocations) == 0 || loc.LogicalLocations[0].Name != "/api/v1/orders/101" {
		t.Errorf("expected logical location name /api/v1/orders/101")
	}

	// Verify properties bag
	if res.Properties["verification_status"] != "VERIFIED" {
		t.Errorf("expected verification_status VERIFIED, got %v", res.Properties["verification_status"])
	}
	if res.Properties["confidence"] != "HIGH" {
		t.Errorf("expected confidence HIGH, got %v", res.Properties["confidence"])
	}
}

func TestSARIF_RuleDeduplication(t *testing.T) {
	rep := Report{
		Target: "https://example.com",
		Findings: []Finding{
			{
				ID:       "FINDING-1",
				Title:    "BOLA Order 1",
				Category: "BOLA",
				Severity: SeverityHigh,
			},
			{
				ID:       "FINDING-2",
				Title:    "BOLA Order 2",
				Category: "BOLA",
				Severity: SeverityCritical,
			},
			{
				ID:       "FINDING-3",
				Title:    "CORS Misconfiguration",
				Category: "CORS",
				Severity: SeverityMedium,
			},
		},
	}

	data, err := GenerateSARIF(rep)
	if err != nil {
		t.Fatalf("GenerateSARIF failed: %v", err)
	}

	var sarifLog SARIFLog
	_ = json.Unmarshal(data, &sarifLog)

	run := sarifLog.Runs[0]
	// 3 findings but only 2 unique categories ("BOLA", "CORS")
	if len(run.Tool.Driver.Rules) != 2 {
		t.Errorf("expected 2 deduplicated rules, got %d", len(run.Tool.Driver.Rules))
	}
	if len(run.Results) != 3 {
		t.Errorf("expected 3 results, got %d", len(run.Results))
	}

	// Check rule indices
	ruleIndexBOLA := -1
	for idx, r := range run.Tool.Driver.Rules {
		if r.ID == "BOLA" {
			ruleIndexBOLA = idx
		}
	}
	if run.Results[0].RuleIndex != ruleIndexBOLA || run.Results[1].RuleIndex != ruleIndexBOLA {
		t.Errorf("expected Results[0] and Results[1] to point to ruleIndex %d", ruleIndexBOLA)
	}
}

func TestSARIF_SeverityLevelMapping(t *testing.T) {
	cases := []struct {
		sev      string
		expected string
	}{
		{SeverityCritical, "error"},
		{SeverityHigh, "error"},
		{SeverityMedium, "warning"},
		{SeverityLow, "note"},
		{SeverityInfo, "none"},
		{"UNKNOWN", "none"},
	}

	for _, tc := range cases {
		lvl := SeverityToSARIFLevel(tc.sev)
		if lvl != tc.expected {
			t.Errorf("Severity %s: expected level %s, got %s", tc.sev, tc.expected, lvl)
		}
	}
}

func TestSARIF_SecretScrubbing(t *testing.T) {
	rawToken := "eyTestHeader123.eyTestPayload456.signatureValue789"
	rawPassword := "password=SuperSecretPassword123!"

	rep := Report{
		Target: "https://example.com",
		Findings: []Finding{
			{
				ID:          "LEAK-01",
				Title:       "Token leak in title: " + rawToken,
				Category:    "SECRETS",
				Severity:    SeverityCritical,
				Description: "Discovered leaked credentials: " + rawPassword,
				Evidence:    "Bearer " + rawToken,
			},
		},
	}

	data, err := GenerateSARIF(rep)
	if err != nil {
		t.Fatalf("GenerateSARIF failed: %v", err)
	}

	dataStr := string(data)
	if strings.Contains(dataStr, rawToken) {
		t.Errorf("CRITICAL SECURITY LEAK: raw JWT token found in SARIF output")
	}
	if strings.Contains(dataStr, "SuperSecretPassword123!") {
		t.Errorf("CRITICAL SECURITY LEAK: raw password found in SARIF output")
	}
	if !strings.Contains(dataStr, "[REDACTED") {
		t.Errorf("expected redacted markers in SARIF output")
	}
}

func TestSARIF_EmptyReportAndFileWriting(t *testing.T) {
	rep := Report{
		Version:  "2.0.0",
		Target:   "https://example.com",
		Findings: []Finding{},
	}

	tmpDir := t.TempDir()
	sarifFile := filepath.Join(tmpDir, "audit.sarif")

	if err := WriteSARIF(rep, sarifFile); err != nil {
		t.Fatalf("WriteSARIF failed: %v", err)
	}

	content, err := os.ReadFile(sarifFile)
	if err != nil {
		t.Fatalf("failed to read written SARIF file: %v", err)
	}

	var sarifLog SARIFLog
	if err := json.Unmarshal(content, &sarifLog); err != nil {
		t.Fatalf("invalid json in written file: %v", err)
	}

	if len(sarifLog.Runs[0].Results) != 0 {
		t.Errorf("expected 0 results in empty report, got %d", len(sarifLog.Runs[0].Results))
	}
}
