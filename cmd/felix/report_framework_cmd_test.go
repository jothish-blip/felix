package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"felix/pkg/api"
	"felix/pkg/clierror"
	"felix/pkg/report"
)

func createSampleFrameworkScanResultJSON(t *testing.T, filePath string) {
	t.Helper()

	target := "https://api.example.com"
	now := time.Now().UTC()

	// 1. Spring Boot finding
	apiSpring := api.APIFinding{
		Category:         api.CategoryActuatorEnv,
		Endpoint:         "https://api.example.com/actuator/env",
		Method:           "GET",
		Description:      "Spring Boot Actuator environment exposed configuration properties",
		Evidence:         `{"activeProfiles":["production"]}`,
		Severity:         api.SeverityHigh,
		Confidence:       api.ConfidenceHigh,
		Fingerprint:      "fp-cli-spring-env",
		HTTPStatus:       200,
		Framework:        "Spring Boot",
		FrameworkVersion: "3.2.0",
		Details: map[string]string{
			"framework":         "Spring Boot",
			"framework_version": "3.2.0",
		},
	}
	fSpring := report.FromAPIFinding(target, apiSpring)
	fSpring.Timestamp = now

	// 2. Django finding
	apiDjango := api.APIFinding{
		Category:         api.CategoryDjangoDebugMode,
		Endpoint:         "https://api.example.com/admin/login/",
		Method:           "GET",
		Description:      "Django technical 500 debug page confirmed (DEBUG=True confirmed)",
		Evidence:         "Django Version: 4.2.7\nTraceback exposed",
		Severity:         api.SeverityHigh,
		Confidence:       api.ConfidenceHigh,
		Fingerprint:      "fp-cli-django-debug",
		HTTPStatus:       500,
		Framework:        "Django",
		FrameworkVersion: "4.2.7",
		Details: map[string]string{
			"framework":         "Django",
			"framework_version": "4.2.7",
		},
	}
	fDjango := report.FromAPIFinding(target, apiDjango)
	fDjango.Timestamp = now

	// 3. Node.js finding (informational)
	apiNode := api.APIFinding{
		Category:         api.CategoryNodeRuntimeExposure,
		Endpoint:         "https://api.example.com/health",
		Method:           "GET",
		Description:      "Node.js Express framework identified via HTTP response header",
		Evidence:         "X-Powered-By: Express",
		Severity:         api.SeverityInfo,
		Confidence:       api.ConfidenceHigh,
		Fingerprint:      "fp-cli-node-hdr",
		HTTPStatus:       200,
		Framework:        "Node.js",
		FrameworkVersion: "4.18.2",
		Details: map[string]string{
			"framework":         "Node.js",
			"framework_version": "4.18.2",
		},
	}
	fNode := report.FromAPIFinding(target, apiNode)
	fNode.Timestamp = now

	findings := []report.Finding{fSpring, fDjango, fNode}

	rep := report.Report{
		Version:          "2.0.0",
		Target:           target,
		Targets:          []string{target},
		Timestamp:        now.Format(time.RFC3339),
		Duration:         "1.5s",
		DurationMs:       1500,
		CompletionStatus: "COMPLETED",
		Findings:         findings,
		Summary:          report.Summarize(findings),
		Metadata: map[string]any{
			"frameworks_assessed": []string{"Spring Boot", "Django", "Node.js", "FastAPI"},
		},
	}
	report.RecalculateReportRisk(&rep)

	data, err := report.GenerateJSON(rep)
	if err != nil {
		t.Fatalf("failed to serialize sample framework report: %v", err)
	}

	if err := os.WriteFile(filePath, data, 0644); err != nil {
		t.Fatalf("failed to write sample scan result file: %v", err)
	}
}

func TestCLI_Report_FrameworkWorkflows(t *testing.T) {
	tempDir := t.TempDir()
	scanJSON := filepath.Join(tempDir, "scan-framework.json")
	createSampleFrameworkScanResultJSON(t, scanJSON)

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

	// 2. Verify terminal output prints Backend Frameworks & Runtimes
	if !strings.Contains(stdout, "Backend Frameworks & Runtimes") {
		t.Errorf("stdout missing 'Backend Frameworks & Runtimes' section, stdout:\n%s", stdout)
	}
	if !strings.Contains(stdout, "Spring Boot") || !strings.Contains(stdout, "Django") {
		t.Errorf("stdout missing framework names, stdout:\n%s", stdout)
	}

	// 3. Verify HTML output
	htmlBytes, err := os.ReadFile(htmlOut)
	if err != nil {
		t.Fatalf("failed to read generated HTML: %v", err)
	}
	htmlStr := string(htmlBytes)
	if !strings.Contains(htmlStr, "Backend Frameworks &amp; Runtime Assessment Summary") && !strings.Contains(htmlStr, "Backend Frameworks & Runtime Assessment Summary") {
		t.Errorf("HTML missing framework summary section")
	}
	if !strings.Contains(htmlStr, "Spring Boot") || !strings.Contains(htmlStr, "Django") {
		t.Errorf("HTML missing framework names")
	}
	if !strings.Contains(htmlStr, "filterFindings('FRAMEWORK')") {
		t.Errorf("HTML missing framework filter button")
	}

	// 4. Verify JSON output
	jsonBytes, err := os.ReadFile(jsonOut)
	if err != nil {
		t.Fatalf("failed to read generated JSON: %v", err)
	}
	var repOut report.Report
	if err := json.Unmarshal(jsonBytes, &repOut); err != nil {
		t.Fatalf("failed to parse generated JSON: %v", err)
	}
	if !repOut.HasFrameworkFindings() {
		t.Errorf("parsed JSON report lost HasFrameworkFindings()")
	}
	if len(repOut.DetectedFrameworks()) == 0 {
		t.Errorf("parsed JSON report has 0 detected frameworks")
	}

	// 5. Verify SARIF output
	sarifBytes, err := os.ReadFile(sarifOut)
	if err != nil {
		t.Fatalf("failed to read generated SARIF: %v", err)
	}
	var sarifLog report.SARIFLog
	if err := json.Unmarshal(sarifBytes, &sarifLog); err != nil {
		t.Fatalf("failed to parse generated SARIF: %v", err)
	}
	if len(sarifLog.Runs) == 0 || len(sarifLog.Runs[0].Results) == 0 {
		t.Fatalf("SARIF output has no runs or results")
	}
	foundFWInSARIF := false
	for _, res := range sarifLog.Runs[0].Results {
		if fw, ok := res.Properties["framework"].(string); ok && fw != "" {
			foundFWInSARIF = true
			break
		}
	}
	if !foundFWInSARIF {
		t.Errorf("SARIF results missing framework property in property bag")
	}
}

func TestCLI_Report_FrameworkCommercialMode(t *testing.T) {
	tempDir := t.TempDir()
	scanJSON := filepath.Join(tempDir, "scan-framework.json")
	createSampleFrameworkScanResultJSON(t, scanJSON)

	htmlOut := filepath.Join(tempDir, "commercial.html")
	jsonOut := filepath.Join(tempDir, "commercial.json")

	// Run "felix report <scan-result.json> --commercial --html <path> --json <path>"
	args := []string{"report", scanJSON, "--commercial", "--html", htmlOut, "--json", jsonOut}
	code, stdout, stderr := captureStdoutStderr(func() int {
		return run(args)
	})

	if code != clierror.ExitSecurityFail {
		t.Fatalf("expected exit code %d (ExitSecurityFail), got %d (stderr: %s, stdout: %s)",
			clierror.ExitSecurityFail, code, stderr, stdout)
	}

	// Verify Commercial HTML
	htmlBytes, err := os.ReadFile(htmlOut)
	if err != nil {
		t.Fatalf("failed to read generated Commercial HTML: %v", err)
	}
	htmlStr := string(htmlBytes)
	if !strings.Contains(htmlStr, "Spring Boot") && !strings.Contains(htmlStr, "Django") {
		t.Errorf("Commercial HTML missing framework badges")
	}

	// Verify Commercial JSON
	jsonBytes, err := os.ReadFile(jsonOut)
	if err != nil {
		t.Fatalf("failed to read generated Commercial JSON: %v", err)
	}
	var cr report.CommercialReport
	if err := json.Unmarshal(jsonBytes, &cr); err != nil {
		t.Fatalf("failed to parse generated Commercial JSON: %v", err)
	}
	if len(cr.VerifiedFindings) == 0 {
		t.Fatalf("Commercial report has no verified findings")
	}
	foundFW := false
	for _, vf := range cr.VerifiedFindings {
		if vf.Framework != "" {
			foundFW = true
			break
		}
	}
	if !foundFW {
		t.Errorf("Commercial findings missing Framework field")
	}
}

func TestCLI_Report_FrameworkZeroFindingsClean(t *testing.T) {
	tempDir := t.TempDir()
	scanJSON := filepath.Join(tempDir, "clean-framework.json")

	target := "https://clean.example.com"
	now := time.Now().UTC()

	// Clean report with 0 findings, but frameworks in assessed scope
	rep := report.Report{
		Version:          "2.0.0",
		Target:           target,
		Targets:          []string{target},
		Timestamp:        now.Format(time.RFC3339),
		Duration:         "0.5s",
		CompletionStatus: "COMPLETED",
		Findings:         []report.Finding{},
		Summary:          report.Summarize([]report.Finding{}),
		Metadata: map[string]any{
			"frameworks_assessed": []string{"FastAPI", "Spring Boot"},
		},
	}
	report.RecalculateReportRisk(&rep)

	data, err := report.GenerateJSON(rep)
	if err != nil {
		t.Fatalf("failed serializing report: %v", err)
	}
	if err := os.WriteFile(scanJSON, data, 0644); err != nil {
		t.Fatalf("failed writing file: %v", err)
	}

	htmlOut := filepath.Join(tempDir, "clean.html")
	args := []string{"report", scanJSON, "--html", htmlOut}
	code, stdout, stderr := captureStdoutStderr(func() int {
		return run(args)
	})

	if code != clierror.ExitSuccess {
		t.Fatalf("expected exit code 0 (ExitSuccess) for 0 findings, got %d (stderr: %s, stdout: %s)",
			code, stderr, stdout)
	}

	// Verify terminal output shows clean status for assessed frameworks
	if !strings.Contains(stdout, "Backend Frameworks & Runtimes") {
		t.Errorf("stdout missing 'Backend Frameworks & Runtimes' section, stdout:\n%s", stdout)
	}
	if !strings.Contains(stdout, "FastAPI") || !strings.Contains(stdout, "Spring Boot") {
		t.Errorf("stdout missing assessed framework names, stdout:\n%s", stdout)
	}
}
