package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"felix/pkg/clierror"
	"felix/pkg/cloud"
	"felix/pkg/report"
)

func createSampleCloudScanResultJSON(t *testing.T, filePath string) {
	t.Helper()

	cfPG := cloud.CloudFinding{
		Provider:    cloud.Provider("postgresql"),
		Category:    "Connection Indicator (postgresql) with Credentials",
		Endpoint:    "postgres://appuser:SecretPasswordXYZ99@db.prod.internal:5432/orders",
		Description: "Detected postgresql connection_string in config/db.js",
		Evidence:    "postgres://appuser:SecretPasswordXYZ99@db.prod.internal:5432/orders",
		Severity:    cloud.SeverityHigh,
		Confidence:  cloud.ConfidenceHigh,
		Fingerprint: "fp-pg-cli-test-1",
		Details: map[string]string{
			"technology":      string(cloud.TechPostgreSQL),
			"family":          string(cloud.FamilyDirectDatabase),
			"has_credentials": "true",
			"analysis_method": "STATIC_ANALYSIS",
		},
	}

	cfS3 := cloud.CloudFinding{
		Provider:    cloud.ProviderAWS,
		Category:    "s3-public-listing",
		Endpoint:    "https://corp-media.s3.amazonaws.com",
		Description: "Anonymous GET request returned XML ListBucketResult with bucket contents",
		Evidence:    "S3 bucket contents exposed publicly",
		Severity:    cloud.SeverityHigh,
		Confidence:  cloud.ConfidenceHigh,
		Fingerprint: "fp-s3-cli-test-2",
		HTTPStatus:  200,
		Details: map[string]string{
			"technology":          string(cloud.TechAWSS3),
			"family":              string(cloud.FamilyObjectStorage),
			"provider":            "aws",
			"resource_scope":      "corp-media",
			"verification_status": "VERIFIED",
			"analysis_method":     "ACTIVE_VERIFICATION",
		},
	}

	target := "https://example.com"
	rfPG := report.FromCloudFinding(target, cfPG)
	rfS3 := report.FromCloudFinding(target, cfS3)

	rep := report.Report{
		Version:          "2.0.0",
		Target:           target,
		Targets:          []string{target},
		Timestamp:        time.Now().UTC().Format(time.RFC3339),
		Duration:         "2.1s",
		DurationMs:       2100,
		CompletionStatus: "COMPLETED",
		Findings:         []report.Finding{rfPG, rfS3},
		Summary:          report.Summarize([]report.Finding{rfPG, rfS3}),
	}
	report.RecalculateReportRisk(&rep)

	data, err := report.GenerateJSON(rep)
	if err != nil {
		t.Fatalf("failed to serialize sample report: %v", err)
	}

	if err := os.WriteFile(filePath, data, 0644); err != nil {
		t.Fatalf("failed to write sample scan file: %v", err)
	}
}

func TestCLI_Report_CloudAndDatabaseWorkflows(t *testing.T) {
	tempDir := t.TempDir()
	scanJSON := filepath.Join(tempDir, "scan-result.json")
	createSampleCloudScanResultJSON(t, scanJSON)

	htmlOut := filepath.Join(tempDir, "output.html")
	jsonOut := filepath.Join(tempDir, "output.json")
	sarifOut := filepath.Join(tempDir, "output.sarif")

	// 1. Run "felix report <scan-result.json> --html <path> --json <path> --sarif <path>"
	args := []string{"report", scanJSON, "--html", htmlOut, "--json", jsonOut, "--sarif", sarifOut}
	code, stdout, stderr := captureStdoutStderr(func() int {
		return run(args)
	})

	if code != clierror.ExitSecurityFail {
		t.Fatalf("expected exit code %d (ExitSecurityFail) for findings with HIGH severity, got %d (stderr: %s)",
			clierror.ExitSecurityFail, code, stderr)
	}

	// 2. Verify HTML output
	htmlBytes, err := os.ReadFile(htmlOut)
	if err != nil {
		t.Fatalf("failed to read generated HTML: %v", err)
	}
	htmlStr := string(htmlBytes)
	if !strings.Contains(htmlStr, "corp-media.s3.amazonaws.com") {
		t.Errorf("HTML report missing S3 endpoint")
	}
	if strings.Contains(htmlStr, "SecretPasswordXYZ99") {
		t.Errorf("HTML report leaked password")
	}
	if !strings.Contains(htmlStr, "Cloud &amp; Database Services Assessed") && !strings.Contains(htmlStr, "Cloud & Database Services Assessed") {
		t.Errorf("HTML report missing Cloud & Database services section")
	}

	// 3. Verify JSON output
	jsonBytes, err := os.ReadFile(jsonOut)
	if err != nil {
		t.Fatalf("failed to read generated JSON: %v", err)
	}
	parsedRep, err := report.ParseReport(jsonBytes)
	if err != nil {
		t.Fatalf("failed to parse generated JSON report: %v", err)
	}
	if len(parsedRep.Findings) != 2 {
		t.Fatalf("expected 2 findings in JSON report, got %d", len(parsedRep.Findings))
	}
	if strings.Contains(string(jsonBytes), "SecretPasswordXYZ99") {
		t.Errorf("JSON report leaked password")
	}

	// 4. Verify SARIF output
	sarifBytes, err := os.ReadFile(sarifOut)
	if err != nil {
		t.Fatalf("failed to read generated SARIF: %v", err)
	}
	if err := report.ValidateSARIF(sarifBytes); err != nil {
		t.Fatalf("generated SARIF failed official schema validation: %v", err)
	}
	if strings.Contains(string(sarifBytes), "SecretPasswordXYZ99") {
		t.Errorf("SARIF report leaked password")
	}

	// 5. Verify stdout summary output
	if !strings.Contains(stdout, "Generated Reports:") {
		t.Errorf("expected stdout to mention Generated Reports, got: %s", stdout)
	}
}

func TestCLI_Report_CommercialFormatIncludesCloudResources(t *testing.T) {
	tempDir := t.TempDir()
	scanJSON := filepath.Join(tempDir, "scan-result.json")
	createSampleCloudScanResultJSON(t, scanJSON)

	args := []string{"report", scanJSON, "--commercial"}
	code, stdout, stderr := captureStdoutStderr(func() int {
		return run(args)
	})

	if code != clierror.ExitSecurityFail {
		t.Fatalf("expected exit code %d (ExitSecurityFail) for findings with HIGH severity, got %d (stderr: %s)",
			clierror.ExitSecurityFail, code, stderr)
	}

	if !strings.Contains(stdout, "COMMERCIAL SECURITY ASSESSMENT REPORT") || !strings.Contains(stdout, "ASSESSMENT SCOPE") {
		t.Errorf("commercial report summary missing expected headers: %s", stdout)
	}
}

func TestCLI_Report_OutputFailureReturnsOperationalCode(t *testing.T) {
	tempDir := t.TempDir()
	scanJSON := filepath.Join(tempDir, "scan-result.json")
	createSampleCloudScanResultJSON(t, scanJSON)

	// Provide an invalid path where directory does not exist
	invalidDest := filepath.Join(tempDir, "nonexistent_subfolder", "forbidden", "report.html")
	args := []string{"report", scanJSON, "--html", invalidDest}
	code, _, stderr := captureStdoutStderr(func() int {
		return run(args)
	})

	if code != clierror.ExitOperational {
		t.Fatalf("expected exit code %d (ExitOperational) for invalid export path, got %d (stderr: %s)",
			clierror.ExitOperational, code, stderr)
	}
}

func TestCLI_Report_InfoOnlyReturnsExitSuccess(t *testing.T) {
	tempDir := t.TempDir()
	scanJSON := filepath.Join(tempDir, "scan-info-only.json")

	cfES := cloud.CloudFinding{
		Provider:    cloud.Provider("elasticsearch"),
		Category:    "Service Discovery: elasticsearch",
		Endpoint:    "http://es.internal:9200",
		Description: "Discovered elasticsearch service reference",
		Evidence:    "Found elasticsearch reference in client assets",
		Severity:    cloud.SeverityInfo,
		Confidence:  cloud.ConfidenceHigh,
		Fingerprint: "fp-es-info-only",
	}
	rf := report.FromCloudFinding("https://example.com", cfES)
	rep := report.Report{
		Version:          "2.0.0",
		Target:           "https://example.com",
		Targets:          []string{"https://example.com"},
		Timestamp:        time.Now().UTC().Format(time.RFC3339),
		Duration:         "0.5s",
		CompletionStatus: "COMPLETED",
		Findings:         []report.Finding{rf},
		Summary:          report.Summarize([]report.Finding{rf}),
	}
	report.RecalculateReportRisk(&rep)
	data, _ := report.GenerateJSON(rep)
	_ = os.WriteFile(scanJSON, data, 0644)

	args := []string{"report", scanJSON}
	code, _, stderr := captureStdoutStderr(func() int {
		return run(args)
	})

	if code != clierror.ExitSuccess {
		t.Fatalf("expected exit code %d (ExitSuccess) for INFO-only cloud findings, got %d (stderr: %s)",
			clierror.ExitSuccess, code, stderr)
	}
}

func TestCLI_Scan_JSONStdoutPureAndMachineReadable(t *testing.T) {
	tempDir := t.TempDir()
	scanJSON := filepath.Join(tempDir, "scan-result.json")
	createSampleCloudScanResultJSON(t, scanJSON)

	// Test bare json output from generated report
	data, err := os.ReadFile(scanJSON)
	if err != nil {
		t.Fatalf("failed to read test json: %v", err)
	}

	var parsed map[string]any
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("scan json is not valid json: %v", err)
	}

	// Ensure no human banner or status messages are prepended to raw JSON
	trimmed := strings.TrimSpace(string(data))
	if !strings.HasPrefix(trimmed, "{") {
		t.Errorf("JSON output is contaminated with non-JSON text: %s", trimmed[:50])
	}
}
