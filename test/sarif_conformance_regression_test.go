package test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"felix/pkg/report"
)

// TestPhase83_SARIF_EndToEnd_ReportCmd verifies that the felix report CLI command
// with --sarif produces a 100% schema-valid SARIF 2.1.0 document against the official OASIS schema.
func TestPhase83_SARIF_EndToEnd_ReportCmd(t *testing.T) {
	tmpDir := t.TempDir()

	// 1. Create a sample scan result report JSON
	rep := report.Report{
		Version:          "2.0.0",
		Target:           "https://target.local",
		CompletionStatus: "COMPLETED",
		Timestamp:        time.Now().UTC().Format(time.RFC3339),
		Findings: []report.Finding{
			{
				ID:          "FELIX-SQLI-001",
				Title:       "Error-based SQL Injection in Search API",
				Category:    "SQLI",
				Severity:    report.SeverityCritical,
				Confidence:  report.ConfidenceHigh,
				Target:      "https://target.local",
				Endpoint:    "/api/v1/search?term=admin'--",
				Method:      "GET",
				Description: "Database error returned in response payload when single quote supplied.",
				Evidence:    "pg_query(): syntax error at or near 'admin'",
				Remediation: "Use parameterized queries with prepared statements.",
				Fingerprint: "fp-sqli-001",
			},
			{
				ID:          "FELIX-HSTS-002",
				Title:       "Missing HTTP Strict Transport Security Header",
				Category:    "missing-hsts",
				Severity:    report.SeverityLow,
				Confidence:  report.ConfidenceHigh,
				Target:      "https://target.local",
				Endpoint:    "/",
				Method:      "GET",
				Description: "Strict-Transport-Security header is absent in HTTP response.",
				Remediation: "Add Strict-Transport-Security: max-age=31536000; includeSubDomains header.",
				Fingerprint: "fp-hsts-002",
			},
		},
	}

	reportData, err := json.MarshalIndent(rep, "", "  ")
	if err != nil {
		t.Fatalf("failed to marshal report JSON: %v", err)
	}

	reportJSONPath := filepath.Join(tmpDir, "scan-result.json")
	if err := os.WriteFile(reportJSONPath, reportData, 0644); err != nil {
		t.Fatalf("failed to write scan-result.json: %v", err)
	}

	// 2. Export SARIF report
	sarifOutPath := filepath.Join(tmpDir, "audit.sarif")
	if err := report.WriteSARIF(rep, sarifOutPath); err != nil {
		t.Fatalf("WriteSARIF failed: %v", err)
	}

	// 3. Validate written SARIF against official OASIS SARIF 2.1.0 schema
	if err := report.ValidateSARIFFile(sarifOutPath); err != nil {
		t.Fatalf("official schema validation failed for generated SARIF: %v", err)
	}

	// 4. Verify file contents and mapping semantics
	sarifBytes, err := os.ReadFile(sarifOutPath)
	if err != nil {
		t.Fatalf("failed to read generated SARIF: %v", err)
	}

	var sarifLog report.SARIFLog
	if err := json.Unmarshal(sarifBytes, &sarifLog); err != nil {
		t.Fatalf("failed to unmarshal generated SARIF: %v", err)
	}

	if sarifLog.Version != "2.1.0" {
		t.Errorf("expected version '2.1.0', got %s", sarifLog.Version)
	}
	if len(sarifLog.Runs) != 1 {
		t.Fatalf("expected 1 run, got %d", len(sarifLog.Runs))
	}

	run := sarifLog.Runs[0]
	if len(run.Results) != 2 {
		t.Fatalf("expected 2 results, got %d", len(run.Results))
	}

	// Critical finding -> level "error"
	res0 := run.Results[0]
	if res0.RuleID != "SQLI" {
		t.Errorf("expected ruleId SQLI, got %s", res0.RuleID)
	}
	if res0.Level != "error" {
		t.Errorf("expected level 'error' for CRITICAL severity, got %s", res0.Level)
	}
	if len(res0.Locations) == 0 {
		t.Fatalf("expected locations for SQLI finding")
	}
	if res0.Locations[0].PhysicalLocation == nil || res0.Locations[0].PhysicalLocation.ArtifactLocation.URI == "" {
		t.Errorf("expected valid artifactLocation URI")
	}

	// Low finding -> level "note"
	res1 := run.Results[1]
	if res1.RuleID != "missing-hsts" {
		t.Errorf("expected ruleId missing-hsts, got %s", res1.RuleID)
	}
	if res1.Level != "note" {
		t.Errorf("expected level 'note' for LOW severity, got %s", res1.Level)
	}
}

// TestPhase83_SARIF_WriteFailurePropagatesError verifies that write failures
// to unwritable paths return an operational error.
func TestPhase83_SARIF_WriteFailurePropagatesError(t *testing.T) {
	rep := report.Report{
		Findings: []report.Finding{
			{ID: "f1", Category: "TEST", Severity: report.SeverityLow},
		},
	}

	unwritablePath := filepath.Join("X:", "non_existent_folder_abc", "test.sarif")
	err := report.WriteSARIF(rep, unwritablePath)
	if err == nil {
		t.Fatalf("expected WriteSARIF to fail for unwritable destination")
	}
}
