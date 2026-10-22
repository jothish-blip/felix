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

func createConsistencyScanResultJSON(t *testing.T, filePath string) report.Report {
	t.Helper()

	f1 := report.Finding{
		ID:          "FND-CLI-001",
		Title:       "High Risk Exposure",
		Category:    "sqli",
		Severity:    report.SeverityHigh,
		Confidence:  report.ConfidenceHigh,
		Target:      "https://target.example.com",
		Endpoint:    "/api/items",
		Method:      "GET",
		Evidence:    "Database error returned",
		Fingerprint: "fp-cli-001",
		Verification: report.VerificationRecord{
			Status: report.VerificationVerified,
			Result: "CONFIRMED_VULNERABILITY",
		},
		Remediation: "Use prepared statements",
	}

	f2 := report.Finding{
		ID:          "FND-CLI-002",
		Title:       "Information Disclosure",
		Category:    "info-leak",
		Severity:    report.SeverityLow,
		Confidence:  report.ConfidenceMedium,
		Target:      "https://target.example.com",
		Endpoint:    "/api/version",
		Method:      "GET",
		Evidence:    "Server banner exposed",
		Fingerprint: "fp-cli-002",
		Verification: report.VerificationRecord{
			Status: report.VerificationObserved,
			Result: "OBSERVED",
		},
		Remediation: "Suppress banner",
	}

	rep := report.BuildReport("https://target.example.com", []report.Finding{f1, f2})
	rep.Timestamp = time.Now().UTC().Format(time.RFC3339)
	rep.CompletionStatus = "COMPLETED"

	if err := report.WriteJSON(rep, filePath); err != nil {
		t.Fatalf("failed creating test scan result: %v", err)
	}
	return rep
}

func TestCLIReportConsistency_ExportFlags(t *testing.T) {
	tempDir := t.TempDir()
	scanFile := filepath.Join(tempDir, "scan.json")
	origRep := createConsistencyScanResultJSON(t, scanFile)

	htmlOut := filepath.Join(tempDir, "out.html")
	jsonOut := filepath.Join(tempDir, "out.json")
	sarifOut := filepath.Join(tempDir, "out.sarif")

	code := runReport([]string{scanFile, "--html", htmlOut, "--json", jsonOut, "--sarif", sarifOut, "--silent"})
	if code != clierror.ExitSecurityFail {
		t.Fatalf("expected ExitSecurityFail (1) for report with High finding, got %d", code)
	}

	// 1. Verify HTML output
	htmlBytes, err := os.ReadFile(htmlOut)
	if err != nil {
		t.Fatalf("HTML file was not created: %v", err)
	}
	htmlStr := string(htmlBytes)
	if !strings.Contains(htmlStr, "FND-CLI-001") || !strings.Contains(htmlStr, "FND-CLI-002") {
		t.Errorf("HTML missing exported findings")
	}

	// 2. Verify JSON output
	jsonBytes, err := os.ReadFile(jsonOut)
	if err != nil {
		t.Fatalf("JSON file was not created: %v", err)
	}
	var loadedRep report.Report
	if err := json.Unmarshal(jsonBytes, &loadedRep); err != nil {
		t.Fatalf("exported JSON is invalid: %v", err)
	}
	if len(loadedRep.Findings) != len(origRep.Findings) {
		t.Errorf("expected %d findings in JSON export, got %d", len(origRep.Findings), len(loadedRep.Findings))
	}

	// 3. Verify SARIF output
	sarifBytes, err := os.ReadFile(sarifOut)
	if err != nil {
		t.Fatalf("SARIF file was not created: %v", err)
	}
	if err := report.ValidateSARIF(sarifBytes); err != nil {
		t.Fatalf("exported SARIF failed official schema validation: %v", err)
	}
	var sarifLog report.SARIFLog
	if err := json.Unmarshal(sarifBytes, &sarifLog); err != nil {
		t.Fatalf("exported SARIF is invalid JSON: %v", err)
	}
	if len(sarifLog.Runs[0].Results) != len(origRep.Findings) {
		t.Errorf("expected %d SARIF results, got %d", len(origRep.Findings), len(sarifLog.Runs[0].Results))
	}
}

func TestCLIReportConsistency_ExportFlagUnified(t *testing.T) {
	tempDir := t.TempDir()
	scanFile := filepath.Join(tempDir, "scan.json")
	createConsistencyScanResultJSON(t, scanFile)

	testCases := []struct {
		filename    string
		expectCheck func(t *testing.T, path string)
	}{
		{
			filename: "export.html",
			expectCheck: func(t *testing.T, path string) {
				data, err := os.ReadFile(path)
				if err != nil {
					t.Fatalf("failed reading exported HTML: %v", err)
				}
				if !strings.Contains(string(data), "<html") {
					t.Errorf("expected HTML structure")
				}
			},
		},
		{
			filename: "export.json",
			expectCheck: func(t *testing.T, path string) {
				data, err := os.ReadFile(path)
				if err != nil {
					t.Fatalf("failed reading exported JSON: %v", err)
				}
				var r report.Report
				if err := json.Unmarshal(data, &r); err != nil {
					t.Errorf("expected valid JSON report: %v", err)
				}
			},
		},
		{
			filename: "export.sarif",
			expectCheck: func(t *testing.T, path string) {
				data, err := os.ReadFile(path)
				if err != nil {
					t.Fatalf("failed reading exported SARIF: %v", err)
				}
				if err := report.ValidateSARIF(data); err != nil {
					t.Errorf("SARIF failed schema validation: %v", err)
				}
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.filename, func(t *testing.T) {
			outPath := filepath.Join(tempDir, tc.filename)
			code := runReport([]string{scanFile, "--export", outPath, "--silent"})
			if code != clierror.ExitSecurityFail {
				t.Fatalf("expected ExitSecurityFail (1) for report with High finding, got %d", code)
			}
			tc.expectCheck(t, outPath)
		})
	}
}

func TestCLIReportConsistency_CommercialExport(t *testing.T) {
	tempDir := t.TempDir()
	scanFile := filepath.Join(tempDir, "scan.json")
	createConsistencyScanResultJSON(t, scanFile)

	htmlOut := filepath.Join(tempDir, "comm.html")
	jsonOut := filepath.Join(tempDir, "comm.json")

	code := runReport([]string{scanFile, "--commercial", "--html", htmlOut, "--json", jsonOut, "--silent"})
	if code != clierror.ExitSecurityFail {
		t.Fatalf("expected ExitSecurityFail (1) for report with High finding, got %d", code)
	}

	// Verify Commercial HTML
	htmlBytes, err := os.ReadFile(htmlOut)
	if err != nil {
		t.Fatalf("Commercial HTML not created: %v", err)
	}
	htmlStr := string(htmlBytes)
	if !strings.Contains(htmlStr, "Commercial Report 2.0") {
		t.Errorf("expected Commercial Report 2.0 header in commercial HTML")
	}

	// Verify Commercial JSON
	jsonBytes, err := os.ReadFile(jsonOut)
	if err != nil {
		t.Fatalf("Commercial JSON not created: %v", err)
	}
	var commRep report.CommercialReport
	if err := json.Unmarshal(jsonBytes, &commRep); err != nil {
		t.Fatalf("exported Commercial JSON is invalid: %v", err)
	}
	if commRep.SchemaVersion == "" {
		t.Errorf("expected non-empty SchemaVersion in Commercial JSON")
	}
}

func TestCLIReportConsistency_WriteFailureHandling(t *testing.T) {
	tempDir := t.TempDir()
	scanFile := filepath.Join(tempDir, "scan.json")
	createConsistencyScanResultJSON(t, scanFile)

	// Destination in nonexistent directory
	invalidDest := filepath.Join(tempDir, "nonexistent_dir_9999", "out.html")
	code := runReport([]string{scanFile, "--html", invalidDest, "--silent"})
	if code != clierror.ExitOperational {
		t.Errorf("expected ExitOperational (%d) on write failure, got %d", clierror.ExitOperational, code)
	}
}

func TestCLIReportConsistency_MissingOrInvalidScanFile(t *testing.T) {
	tempDir := t.TempDir()

	// 1. Missing scan file
	code := runReport([]string{filepath.Join(tempDir, "does-not-exist.json")})
	if code != 2 {
		t.Errorf("expected exit code 2 for missing scan file, got %d", code)
	}

	// 2. Corrupt scan file
	corruptFile := filepath.Join(tempDir, "corrupt.json")
	_ = os.WriteFile(corruptFile, []byte("not valid json {"), 0644)
	code = runReport([]string{corruptFile})
	if code != 2 {
		t.Errorf("expected exit code 2 for corrupt scan file, got %d", code)
	}
}

func TestCLIReportConsistency_CleanScanReturnsExitSuccess(t *testing.T) {
	tempDir := t.TempDir()
	scanFile := filepath.Join(tempDir, "clean_scan.json")
	cleanRep := report.BuildReport("https://clean.example.com", nil)
	cleanRep.CompletionStatus = "COMPLETED"
	if err := report.WriteJSON(cleanRep, scanFile); err != nil {
		t.Fatalf("failed writing clean scan JSON: %v", err)
	}

	htmlOut := filepath.Join(tempDir, "clean.html")
	jsonOut := filepath.Join(tempDir, "clean.json")
	sarifOut := filepath.Join(tempDir, "clean.sarif")

	code := runReport([]string{scanFile, "--html", htmlOut, "--json", jsonOut, "--sarif", sarifOut, "--silent"})
	if code != clierror.ExitSuccess {
		t.Errorf("expected ExitSuccess (0) for clean scan, got %d", code)
	}

	if _, err := os.Stat(htmlOut); err != nil {
		t.Errorf("expected clean HTML to be written")
	}
	if _, err := os.Stat(jsonOut); err != nil {
		t.Errorf("expected clean JSON to be written")
	}
	if _, err := os.Stat(sarifOut); err != nil {
		t.Errorf("expected clean SARIF to be written")
	}
}
