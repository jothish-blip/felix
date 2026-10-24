package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"felix/pkg/clierror"
	"felix/pkg/report"
)

func TestCLI_Reporting_MultiFormatAndExportReliability(t *testing.T) {
	tmpDir := t.TempDir()

	const canarySecret = "AKIA2233445566778899"

	// Create a canonical report fixture with a canary secret and findings
	f := report.Finding{
		ID:          "FND-CLI-01",
		Title:       "AWS Key Exposure in Client Bundle",
		Description: "Discovered live AWS access key " + canarySecret + " hardcoded in asset bundle.js",
		Severity:    report.SeverityHigh,
		Confidence:  report.ConfidenceHigh,
		Target:      "https://cli-test.target.com",
		Endpoint:    "/bundle.js",
		Category:    "secrets-leak",
		Fingerprint: "fp-cli-test-01",
		Verification: report.VerificationRecord{
			Status: report.VerificationVerified,
			Result: "VERIFIED_CANARY",
		},
	}

	rep := report.BuildReport("https://cli-test.target.com", []report.Finding{f})
	rep.CompletionStatus = "COMPLETED"
	report.RecalculateReportRisk(&rep)

	scanResultPath := filepath.Join(tmpDir, "scan-result.json")
	if err := report.WriteJSON(rep, scanResultPath); err != nil {
		t.Fatalf("failed to write scan result fixture: %v", err)
	}

	t.Run("Multi-format simultaneous export via CLI flags", func(t *testing.T) {
		outHTML := filepath.Join(tmpDir, "cli_multi.html")
		outJSON := filepath.Join(tmpDir, "cli_multi.json")
		outSARIF := filepath.Join(tmpDir, "cli_multi.sarif")

		code := runReport([]string{
			scanResultPath,
			"--html", outHTML,
			"--json", outJSON,
			"--sarif", outSARIF,
			"--silent",
		})

		// Exit code should be 1 (ExitSecurityFail) because high severity finding exists
		if code != clierror.ExitSecurityFail {
			t.Errorf("expected exit code %d (ExitSecurityFail), got: %d", clierror.ExitSecurityFail, code)
		}

		// Verify files exist and are non-empty
		for _, path := range []string{outHTML, outJSON, outSARIF} {
			fi, err := os.Stat(path)
			if err != nil || fi.Size() < 50 {
				t.Errorf("expected generated file %s to be non-empty, err: %v", path, err)
			}
		}

		// Verify canary redaction across all 3 CLI generated files
		for _, path := range []string{outHTML, outJSON, outSARIF} {
			content, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("failed to read %s: %v", path, err)
			}
			if strings.Contains(string(content), canarySecret) {
				t.Errorf("file %s leaked canary secret %s", path, canarySecret)
			}
		}

		// Verify SARIF schema conformance
		if err := report.ValidateSARIFFile(outSARIF); err != nil {
			t.Errorf("CLI generated SARIF failed schema validation: %v", err)
		}
	})

	t.Run("Commercial mode HTML and JSON export", func(t *testing.T) {
		commHTML := filepath.Join(tmpDir, "commercial.html")
		commJSON := filepath.Join(tmpDir, "commercial.json")

		code := runReport([]string{
			scanResultPath,
			"--commercial",
			"--html", commHTML,
			"--json", commJSON,
			"--silent",
		})

		if code != clierror.ExitSecurityFail {
			t.Errorf("expected exit code %d, got: %d", clierror.ExitSecurityFail, code)
		}

		commBytes, err := os.ReadFile(commJSON)
		if err != nil {
			t.Fatalf("failed to read commercial JSON: %v", err)
		}
		var parsed map[string]any
		if err := json.Unmarshal(commBytes, &parsed); err != nil {
			t.Fatalf("failed to parse commercial JSON: %v", err)
		}
		if _, ok := parsed["verified_findings"]; !ok {
			t.Errorf("commercial JSON missing verified_findings key")
		}
	})

	t.Run("Export flag inference by extension (.sarif, .html, .json)", func(t *testing.T) {
		exportSARIF := filepath.Join(tmpDir, "inferred.sarif")
		code := runReport([]string{
			scanResultPath,
			"--export", exportSARIF,
			"--silent",
		})
		if code != clierror.ExitSecurityFail {
			t.Errorf("expected code 1, got %d", code)
		}
		if err := report.ValidateSARIFFile(exportSARIF); err != nil {
			t.Errorf("inferred SARIF export failed validation: %v", err)
		}
	})

	t.Run("Unwritable output destination returns ExitOperational (code 2)", func(t *testing.T) {
		unwritablePath := filepath.Join(tmpDir, "nonexistent_parent_dir", "sub", "report.html")
		code := runReport([]string{
			scanResultPath,
			"--html", unwritablePath,
			"--silent",
		})
		if code != clierror.ExitOperational {
			t.Errorf("expected exit code %d (ExitOperational) on write failure, got: %d", clierror.ExitOperational, code)
		}
	})

	t.Run("Missing scan result argument returns code 2", func(t *testing.T) {
		code := runReport([]string{})
		if code != 2 {
			t.Errorf("expected code 2 for missing scan result argument, got: %d", code)
		}
	})

	t.Run("Corrupted or tampered scan result fails validation", func(t *testing.T) {
		corruptedPath := filepath.Join(tmpDir, "tampered.json")
		// Summary claims 10 findings, but findings list is empty
		tamperedRep := report.Report{
			Target:           "https://example.com",
			Timestamp:        time.Now().UTC().Format(time.RFC3339),
			CompletionStatus: "COMPLETED",
			Summary: report.Summary{
				TotalFindings: 10,
				CriticalCount: 10,
			},
			Findings: nil,
		}
		data, _ := json.Marshal(tamperedRep)
		_ = os.WriteFile(corruptedPath, data, 0600)

		code := runReport([]string{corruptedPath, "--html", filepath.Join(tmpDir, "tampered.html")})
		if code != 2 {
			t.Errorf("expected code 2 for tampered scan result, got: %d", code)
		}
	})
}
