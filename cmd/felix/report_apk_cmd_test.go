package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"felix/pkg/report"
)

func TestCLI_APK_Report_HTML(t *testing.T) {
	apkPath := createCLIValidAPK(t)
	tmpDir := t.TempDir()
	reportHTML := filepath.Join(tmpDir, "mobile_audit.html")

	code, out := captureAPKOutput(func() int {
		return runAPK([]string{"--report", reportHTML, apkPath})
	})

	if code != 0 {
		t.Fatalf("expected exit code 0, got %d, output:\n%s", code, out)
	}

	content, err := os.ReadFile(reportHTML)
	if err != nil {
		t.Fatalf("failed reading generated report HTML: %v", err)
	}

	s := string(content)
	if !strings.Contains(s, "com.felix.cli.test") {
		t.Errorf("generated mobile audit HTML missing package name com.felix.cli.test")
	}
	if !strings.Contains(s, "FELIX Mobile Security Assessment Report") && !strings.Contains(s, "Mobile Security Assessment") {
		t.Errorf("generated report HTML missing header title")
	}
}

func TestCLI_APK_Report_SARIF(t *testing.T) {
	apkPath := createCLIValidAPK(t)
	tmpDir := t.TempDir()
	sarifPath := filepath.Join(tmpDir, "audit.sarif")

	code, out := captureAPKOutput(func() int {
		return runAPK([]string{"--sarif", sarifPath, apkPath})
	})

	if code != 0 {
		t.Fatalf("expected exit code 0, got %d, output:\n%s", code, out)
	}

	data, err := os.ReadFile(sarifPath)
	if err != nil {
		t.Fatalf("failed reading generated SARIF file: %v", err)
	}

	var sarif report.SARIFLog
	if err := json.Unmarshal(data, &sarif); err != nil {
		t.Fatalf("failed unmarshaling SARIF JSON: %v", err)
	}

	if sarif.Version != report.SARIFSchemaVersion {
		t.Errorf("expected SARIF version %s, got %s", report.SARIFSchemaVersion, sarif.Version)
	}
	if len(sarif.Runs) == 0 {
		t.Fatalf("SARIF report has 0 runs")
	}
}

func TestCLI_APK_Report_JSON(t *testing.T) {
	apkPath := createCLIValidAPK(t)
	tmpDir := t.TempDir()
	jsonPath := filepath.Join(tmpDir, "audit.json")

	code, out := captureAPKOutput(func() int {
		return runAPK([]string{"--json", jsonPath, apkPath})
	})

	if code != 0 {
		t.Fatalf("expected exit code 0, got %d, output:\n%s", code, out)
	}

	data, err := os.ReadFile(jsonPath)
	if err != nil {
		t.Fatalf("failed reading generated JSON report: %v", err)
	}

	var rep report.Report
	if err := json.Unmarshal(data, &rep); err != nil {
		t.Fatalf("failed unmarshaling report JSON: %v", err)
	}

	if !rep.HasMobileScope() {
		t.Errorf("expected HasMobileScope() true on exported report JSON")
	}
	if rep.MobilePackageName() != "com.felix.cli.test" {
		t.Errorf("expected MobilePackageName 'com.felix.cli.test', got %s", rep.MobilePackageName())
	}
}

func TestCLI_APK_Export_Formats(t *testing.T) {
	apkPath := createCLIValidAPK(t)
	tmpDir := t.TempDir()

	// 1. Export JSON
	exportJSON := filepath.Join(tmpDir, "export.json")
	codeJSON, _ := captureAPKOutput(func() int {
		return runAPK([]string{"--export", exportJSON, apkPath})
	})
	if codeJSON != 0 {
		t.Fatalf("expected exit code 0 for --export json, got %d", codeJSON)
	}
	if stat, err := os.Stat(exportJSON); err != nil || stat.Size() == 0 {
		t.Errorf("--export json produced empty or missing file")
	}

	// 2. Export SARIF
	exportSARIF := filepath.Join(tmpDir, "export.sarif")
	codeSARIF, _ := captureAPKOutput(func() int {
		return runAPK([]string{"--export", exportSARIF, apkPath})
	})
	if codeSARIF != 0 {
		t.Fatalf("expected exit code 0 for --export sarif, got %d", codeSARIF)
	}
	if stat, err := os.Stat(exportSARIF); err != nil || stat.Size() == 0 {
		t.Errorf("--export sarif produced empty or missing file")
	}

	// 3. Export HTML
	exportHTML := filepath.Join(tmpDir, "export.html")
	codeHTML, _ := captureAPKOutput(func() int {
		return runAPK([]string{"--export", exportHTML, apkPath})
	})
	if codeHTML != 0 {
		t.Fatalf("expected exit code 0 for --export html, got %d", codeHTML)
	}
	if stat, err := os.Stat(exportHTML); err != nil || stat.Size() == 0 {
		t.Errorf("--export html produced empty or missing file")
	}
}

func TestCLI_FelixReport_FromAPKScanJSON(t *testing.T) {
	apkPath := createCLIValidAPK(t)
	tmpDir := t.TempDir()
	scanJSON := filepath.Join(tmpDir, "scan-apk.json")

	// Generate canonical JSON assessment file from APK
	codeAPK, _ := captureAPKOutput(func() int {
		return runAPK([]string{"--json", scanJSON, apkPath})
	})
	if codeAPK != 0 {
		t.Fatalf("failed generating scan JSON from APK, exit code %d", codeAPK)
	}

	// Now run `felix report` taking the APK scan JSON and producing HTML and SARIF
	outHTML := filepath.Join(tmpDir, "report-from-scan.html")
	outSARIF := filepath.Join(tmpDir, "report-from-scan.sarif")

	codeReport := runReport([]string{scanJSON, "--html", outHTML, "--sarif", outSARIF})
	if codeReport != 0 {
		t.Fatalf("expected felix report exit code 0, got %d", codeReport)
	}

	// Verify HTML contains mobile assessment summary
	htmlBytes, err := os.ReadFile(outHTML)
	if err != nil {
		t.Fatalf("failed reading output HTML: %v", err)
	}
	htmlStr := string(htmlBytes)
	if !strings.Contains(htmlStr, "Android APK Audit &amp; Mobile Assessment Summary") && !strings.Contains(htmlStr, "Android APK Audit & Mobile Assessment Summary") {
		t.Errorf("HTML generated via felix report missing mobile summary card")
	}
	if !strings.Contains(htmlStr, "com.felix.cli.test") {
		t.Errorf("HTML generated via felix report missing package name")
	}

	// Verify SARIF is valid
	sarifBytes, err := os.ReadFile(outSARIF)
	if err != nil {
		t.Fatalf("failed reading output SARIF: %v", err)
	}
	var sarif report.SARIFLog
	if err := json.Unmarshal(sarifBytes, &sarif); err != nil {
		t.Fatalf("SARIF from felix report invalid: %v", err)
	}
	if sarif.Version != report.SARIFSchemaVersion {
		t.Errorf("unexpected SARIF version %s", sarif.Version)
	}
}
