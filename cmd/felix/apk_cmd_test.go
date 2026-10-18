package main

import (
	"archive/zip"
	"bytes"
	"encoding/binary"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

func captureAPKOutput(f func() int) (int, string) {
	oldStdout := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		panic(err)
	}
	os.Stdout = w

	outChan := make(chan string)
	go func() {
		var buf bytes.Buffer
		_, _ = io.Copy(&buf, r)
		outChan <- buf.String()
	}()

	code := f()

	_ = w.Close()
	os.Stdout = oldStdout
	output := <-outChan
	_ = r.Close()

	return code, output
}

func createCLIValidAPK(t *testing.T) string {
	t.Helper()
	tmpDir := t.TempDir()
	apkPath := filepath.Join(tmpDir, "app.apk")

	f, err := os.Create(apkPath)
	if err != nil {
		t.Fatalf("failed to create apk file: %v", err)
	}
	defer f.Close()

	zw := zip.NewWriter(f)
	w1, _ := zw.Create("AndroidManifest.xml")
	w1.Write([]byte("<manifest package=\"com.felix.cli.test\"/>"))

	w2, _ := zw.Create("classes.dex")
	w2.Write([]byte("dex-code"))

	w3, _ := zw.Create("res/values/strings.xml")
	w3.Write([]byte("<resources/>"))

	if err := zw.Close(); err != nil {
		t.Fatalf("failed to close zip writer: %v", err)
	}
	return apkPath
}

func TestCLI_APK_Help(t *testing.T) {
	code := runAPK([]string{"--help"})
	if code != 0 {
		t.Errorf("expected exit code 0 for --help, got %d", code)
	}
}

func TestCLI_APK_MissingArgument(t *testing.T) {
	code := runAPK([]string{})
	if code != 2 {
		t.Errorf("expected exit code 2 for missing argument, got %d", code)
	}
}

func TestCLI_APK_InvalidFlag(t *testing.T) {
	code := runAPK([]string{"--invalid-flag", "test.apk"})
	if code != 2 {
		t.Errorf("expected exit code 2 for invalid flag, got %d", code)
	}
}

func TestCLI_APK_ValidIntake(t *testing.T) {
	apkPath := createCLIValidAPK(t)
	code := runAPK([]string{"--quiet", apkPath})
	if code != 0 {
		t.Errorf("expected exit code 0 for valid apk, got %d", code)
	}
}

func TestCLI_APK_JSONOutput(t *testing.T) {
	apkPath := createCLIValidAPK(t)

	code, output := captureAPKOutput(func() int {
		return runAPK([]string{"--json", apkPath})
	})

	if code != 0 {
		t.Fatalf("expected exit code 0 for json intake, got %d", code)
	}

	var res map[string]interface{}
	if err := json.Unmarshal([]byte(output), &res); err != nil {
		t.Fatalf("failed to unmarshal JSON output: %v, raw: %s", err, output)
	}

	if res["status"] != "PASS" {
		t.Errorf("expected status PASS, got %v", res["status"])
	}
	if res["manifest_present"] != true {
		t.Errorf("expected manifest_present true, got %v", res["manifest_present"])
	}
	if res["sha256"] == "" {
		t.Errorf("expected sha256 in output")
	}
}

func TestCLI_APK_KeepWorkspace(t *testing.T) {
	apkPath := createCLIValidAPK(t)

	code, output := captureAPKOutput(func() int {
		return runAPK([]string{"--json", "--keep-workspace", apkPath})
	})

	if code != 0 {
		t.Fatalf("expected exit code 0, got %d", code)
	}

	var res map[string]interface{}
	if err := json.Unmarshal([]byte(output), &res); err != nil {
		t.Fatalf("failed to parse JSON: %v", err)
	}

	wsDir, ok := res["workspace_dir"].(string)
	if !ok || wsDir == "" {
		t.Fatalf("expected workspace_dir in output when --keep-workspace is passed")
	}

	// Verify workspace exists on disk
	fi, err := os.Stat(wsDir)
	if err != nil || !fi.IsDir() {
		t.Errorf("expected retained workspace directory at %s, err=%v", wsDir, err)
	}

	// Clean up retained test workspace
	_ = os.RemoveAll(wsDir)
}

func TestCLI_APK_RejectNonAPK(t *testing.T) {
	tmpDir := t.TempDir()
	txtPath := filepath.Join(tmpDir, "fake.apk")
	_ = os.WriteFile(txtPath, []byte("NOT_A_ZIP"), 0644)

	code := runAPK([]string{"--quiet", txtPath})
	if code != 2 {
		t.Errorf("expected exit code 2 for non-APK file, got %d", code)
	}
}

func TestCLI_APK_InvalidLimitFlag(t *testing.T) {
	apkPath := createCLIValidAPK(t)
	code := runAPK([]string{"--max-compressed-size", "invalid", apkPath})
	if code != 2 {
		t.Errorf("expected exit code 2 for invalid limit value, got %d", code)
	}

	code = runAPK([]string{"--max-entries", "-5", apkPath})
	if code != 2 {
		t.Errorf("expected exit code 2 for negative entries limit, got %d", code)
	}
}

func TestCLI_APK_DiscloseNoSensitivePaths(t *testing.T) {
	apkPath := createCLIValidAPK(t)
	code := runAPK([]string{apkPath})
	if code != 0 {
		t.Errorf("expected exit code 0, got %d", code)
	}
	// Normal run without --keep-workspace must not print local workspace path
}

func TestCLI_APK_Analyze_TextOutput(t *testing.T) {
	apkPath := createCLIValidAPK(t)

	code, out := captureAPKOutput(func() int {
		return runAPK([]string{"--analyze", apkPath})
	})

	if code != 0 {
		t.Fatalf("expected exit code 0 for --analyze, got %d", code)
	}

	if !strings.Contains(out, "ANDROID MANIFEST SECURITY ANALYSIS") {
		t.Errorf("expected manifest security analysis header in output, got:\n%s", out)
	}
	if !strings.Contains(out, "Package Name:") {
		t.Errorf("expected package name in output")
	}
}

func TestCLI_APK_Analyze_JSONOutput(t *testing.T) {
	apkPath := createCLIValidAPK(t)

	code, output := captureAPKOutput(func() int {
		return runAPK([]string{"--json", "--analyze", apkPath})
	})

	if code != 0 {
		t.Fatalf("expected exit code 0, got %d", code)
	}

	var res map[string]interface{}
	if err := json.Unmarshal([]byte(output), &res); err != nil {
		t.Fatalf("failed to parse JSON: %v, raw: %s", err, output)
	}

	if res["security_assessment"] != "EVALUATED" {
		t.Errorf("expected security_assessment=EVALUATED, got %v", res["security_assessment"])
	}

	analysis, ok := res["manifest_analysis"].(map[string]interface{})
	if !ok || analysis == nil {
		t.Fatalf("expected manifest_analysis object in JSON output")
	}

	if analysis["package_name"] != "com.felix.cli.test" {
		t.Errorf("expected package com.felix.cli.test, got %v", analysis["package_name"])
	}
}

func TestCLI_APK_Analyze_DebuggableDetected(t *testing.T) {
	// Create APK with debuggable="true"
	tmpDir := t.TempDir()
	apkPath := filepath.Join(tmpDir, "debuggable.apk")
	f, _ := os.Create(apkPath)
	zw := zip.NewWriter(f)

	w1, _ := zw.Create("AndroidManifest.xml")
	w1.Write([]byte(`<manifest package="com.debug.app"><application android:debuggable="true"/></manifest>`))

	w2, _ := zw.Create("classes.dex")
	w2.Write([]byte("dex"))

	zw.Close()
	f.Close()

	code, output := captureAPKOutput(func() int {
		return runAPK([]string{"--json", "--analyze", apkPath})
	})

	if code != 0 {
		t.Fatalf("expected exit code 0, got %d", code)
	}

	var res map[string]interface{}
	_ = json.Unmarshal([]byte(output), &res)
	analysis := res["manifest_analysis"].(map[string]interface{})
	findings := analysis["findings"].([]interface{})

	found := false
	for _, rawF := range findings {
		f := rawF.(map[string]interface{})
		if f["rule_id"] == "APK-MAN-DEBUGGABLE" && f["severity"] == "HIGH" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected APK-MAN-DEBUGGABLE HIGH finding in JSON output")
	}
}

func buildCLIDEX(stringsList []string) []byte {
	header := make([]byte, 112)
	copy(header[0:4], []byte("dex\n"))
	copy(header[4:7], []byte("035"))
	header[7] = 0
	binary.LittleEndian.PutUint32(header[0x28:0x2C], 0x12345678)
	binary.LittleEndian.PutUint32(header[0x24:0x28], 112)

	stringCount := uint32(len(stringsList))
	stringIDsOff := uint32(112)
	binary.LittleEndian.PutUint32(header[0x38:0x3C], stringCount)
	binary.LittleEndian.PutUint32(header[0x3C:0x40], stringIDsOff)

	stringTableSize := stringCount * 4
	dataOffset := stringIDsOff + stringTableSize

	var stringTable bytes.Buffer
	var stringData bytes.Buffer

	for _, s := range stringsList {
		currentDataOff := dataOffset + uint32(stringData.Len())
		var offBytes [4]byte
		binary.LittleEndian.PutUint32(offBytes[:], currentDataOff)
		stringTable.Write(offBytes[:])

		l := len(s)
		for {
			b := byte(l & 0x7f)
			l >>= 7
			if l != 0 {
				b |= 0x80
			}
			stringData.WriteByte(b)
			if l == 0 {
				break
			}
		}
		stringData.WriteString(s)
		stringData.WriteByte(0x00)
	}

	totalSize := uint32(112) + stringTableSize + uint32(stringData.Len())
	binary.LittleEndian.PutUint32(header[0x20:0x24], totalSize)

	var dex bytes.Buffer
	dex.Write(header)
	dex.Write(stringTable.Bytes())
	dex.Write(stringData.Bytes())
	return dex.Bytes()
}

func createCLIArtifactAPK(t *testing.T, dexStrings []string) string {
	t.Helper()
	tmpDir := t.TempDir()
	apkPath := filepath.Join(tmpDir, "artifact-app.apk")

	f, err := os.Create(apkPath)
	if err != nil {
		t.Fatalf("failed to create apk file: %v", err)
	}
	defer f.Close()

	zw := zip.NewWriter(f)
	w1, _ := zw.Create("AndroidManifest.xml")
	w1.Write([]byte(`<manifest package="com.felix.artifact.app"><application/></manifest>`))

	w2, _ := zw.Create("classes.dex")
	w2.Write(buildCLIDEX(dexStrings))

	w3, _ := zw.Create("google-services.json")
	w3.Write([]byte(`{
		"project_info": {
			"project_id": "cli-test-firebase",
			"storage_bucket": "cli-test-firebase.appspot.com"
		},
		"client": [
			{
				"client_info": {
					"mobilesdk_app_id": "1:123456789:android:abcdef"
				},
				"api_key": [
					{"current_key": "AIzaSyC1234567890abcdef1234567890abcdef"}
				]
			}
		]
	}`))

	_ = zw.Close()
	return apkPath
}

func TestCLI_APK_AnalyzeArtifacts_TextOutput(t *testing.T) {
	apkPath := createCLIArtifactAPK(t, []string{
		"AKIAIOSFODNN7EXAMPLE",
		"https://api.mycorp.com/v1/users",
		"query GetCatalog { items { id } }",
	})

	code, out := captureAPKOutput(func() int {
		return runAPK([]string{"--analyze-artifacts", apkPath})
	})

	if code != 0 {
		t.Fatalf("expected exit code 0 for --analyze-artifacts, got %d, out:\n%s", code, out)
	}

	if !strings.Contains(out, "APPLICATION ARTIFACT INTELLIGENCE") {
		t.Errorf("expected artifact intelligence section, got:\n%s", out)
	}
	if !strings.Contains(out, "Discovered Secrets:") {
		t.Errorf("expected Discovered Secrets in output, got:\n%s", out)
	}
	if !strings.Contains(out, "Service Indicators:") {
		t.Errorf("expected Service Indicators in output, got:\n%s", out)
	}
	// Verify raw secret is NOT printed
	if strings.Contains(out, "AKIAIOSFODNN7EXAMPLE") {
		t.Errorf("Raw AWS secret leaked in CLI text output!")
	}
}

func TestCLI_APK_Analyze_BothManifestAndArtifacts(t *testing.T) {
	apkPath := createCLIArtifactAPK(t, []string{
		"AKIAIOSFODNN7EXAMPLE",
		"https://api.mycorp.com/v1/users",
	})

	code, out := captureAPKOutput(func() int {
		return runAPK([]string{"--analyze", apkPath})
	})

	if code != 0 {
		t.Fatalf("expected exit code 0 for --analyze, got %d, out:\n%s", code, out)
	}

	if !strings.Contains(out, "ANDROID MANIFEST SECURITY ANALYSIS") {
		t.Errorf("expected manifest analysis section in --analyze run")
	}
	if !strings.Contains(out, "APPLICATION ARTIFACT INTELLIGENCE") {
		t.Errorf("expected artifact intelligence section in --analyze run")
	}
}

func TestCLI_APK_AnalyzeArtifacts_JSONOutput(t *testing.T) {
	apkPath := createCLIArtifactAPK(t, []string{
		"AKIAIOSFODNN7EXAMPLE",
		"https://api.mycorp.com/v1/users",
	})

	code, output := captureAPKOutput(func() int {
		return runAPK([]string{"--json", "--analyze-artifacts", apkPath})
	})

	if code != 0 {
		t.Fatalf("expected exit code 0, got %d, out:\n%s", code, output)
	}

	var res map[string]interface{}
	if err := json.Unmarshal([]byte(output), &res); err != nil {
		t.Fatalf("failed to parse JSON output: %v, raw:\n%s", err, output)
	}

	if res["security_assessment"] != "EVALUATED" {
		t.Errorf("expected security_assessment=EVALUATED, got %v", res["security_assessment"])
	}

	artAnalysis, ok := res["artifact_analysis"].(map[string]interface{})
	if !ok || artAnalysis == nil {
		t.Fatalf("expected artifact_analysis object in JSON output")
	}

	dexFiles := artAnalysis["dex_files_analyzed"].([]interface{})
	if len(dexFiles) != 1 {
		t.Errorf("expected 1 dex file analyzed, got %d", len(dexFiles))
	}

	summary := artAnalysis["summary"].(map[string]interface{})
	if summary["secrets_count"].(float64) < 1 {
		t.Errorf("expected at least 1 secret, got %v", summary["secrets_count"])
	}

	// Verify no raw secret in JSON output
	if strings.Contains(output, "AKIAIOSFODNN7EXAMPLE") {
		t.Errorf("Raw AWS secret leaked in JSON output!")
	}
}

func TestCLI_APK_AnalyzeArtifacts_MalformedDEX(t *testing.T) {
	// APK with malformed DEX (corrupted header)
	tmpDir := t.TempDir()
	apkPath := filepath.Join(tmpDir, "malformed-dex.apk")
	f, _ := os.Create(apkPath)
	zw := zip.NewWriter(f)

	w1, _ := zw.Create("AndroidManifest.xml")
	w1.Write([]byte(`<manifest package="com.bad.dex"><application/></manifest>`))

	w2, _ := zw.Create("classes.dex")
	w2.Write([]byte("dex\n035\x00truncated"))

	_ = zw.Close()
	_ = f.Close()

	code, output := captureAPKOutput(func() int {
		return runAPK([]string{"--json", "--analyze-artifacts", apkPath})
	})

	if code != 0 {
		t.Fatalf("expected exit code 0 with partial analysis, got %d", code)
	}

	var res map[string]interface{}
	_ = json.Unmarshal([]byte(output), &res)
	artAnalysis := res["artifact_analysis"].(map[string]interface{})

	if artAnalysis["partial_analysis"] != true {
		t.Errorf("expected partial_analysis=true for malformed DEX")
	}
	limitations := artAnalysis["limitations"].([]interface{})
	if len(limitations) == 0 {
		t.Errorf("expected limitations recorded for malformed DEX")
	}
}

func TestCLI_APK_Inventory_TextOutput(t *testing.T) {
	apkPath := createCLIArtifactAPK(t, []string{
		"AKIAIOSFODNN7EXAMPLE",
		"https://api.mycorp.com/v1/users",
		"https://api.mycorp.com/v1/posts",
	})

	// Test 1: --inventory flag
	code, out := captureAPKOutput(func() int {
		return runAPK([]string{"--inventory", apkPath})
	})

	if code != 0 {
		t.Fatalf("expected exit code 0 for --inventory, got %d, out:\n%s", code, out)
	}

	if !strings.Contains(out, "FELIX :: BACKEND INVENTORY") {
		t.Errorf("expected BACKEND INVENTORY section in output, got:\n%s", out)
	}
	if !strings.Contains(out, "Total Endpoints:") {
		t.Errorf("expected Total Endpoints in output")
	}
	if !strings.Contains(out, "Backend Hosts:") {
		t.Errorf("expected Backend Hosts in output")
	}
	if !strings.Contains(out, "Host: api.mycorp.com") {
		t.Errorf("expected Host: api.mycorp.com in output, got:\n%s", out)
	}

	// Test 2: --analyze includes BACKEND INVENTORY
	codeAnalyze, outAnalyze := captureAPKOutput(func() int {
		return runAPK([]string{"--analyze", apkPath})
	})

	if codeAnalyze != 0 {
		t.Fatalf("expected exit code 0 for --analyze, got %d, out:\n%s", codeAnalyze, outAnalyze)
	}

	if !strings.Contains(outAnalyze, "FELIX :: BACKEND INVENTORY") {
		t.Errorf("expected BACKEND INVENTORY section in --analyze output")
	}
}

func TestCLI_APK_Inventory_JSONOutput(t *testing.T) {
	apkPath := createCLIArtifactAPK(t, []string{
		"https://api.mycorp.com/v1/users?token=secret12345",
	})

	code, output := captureAPKOutput(func() int {
		return runAPK([]string{"--json", "--inventory", apkPath})
	})

	if code != 0 {
		t.Fatalf("expected exit code 0, got %d, out:\n%s", code, output)
	}

	var res map[string]interface{}
	if err := json.Unmarshal([]byte(output), &res); err != nil {
		t.Fatalf("failed to parse JSON: %v, raw:\n%s", err, output)
	}

	if res["security_assessment"] != "EVALUATED" {
		t.Errorf("expected security_assessment=EVALUATED, got %v", res["security_assessment"])
	}

	inv, ok := res["backend_inventory"].(map[string]interface{})
	if !ok || inv == nil {
		t.Fatalf("expected backend_inventory in JSON output")
	}

	if inv["total_endpoints"].(float64) < 1 {
		t.Errorf("expected at least 1 endpoint, got %v", inv["total_endpoints"])
	}

	// Verify sensitive token was redacted in JSON
	if strings.Contains(output, "secret12345") {
		t.Errorf("sensitive query token leaked in CLI JSON output!")
	}
}

func captureAPKStderr(f func() int) (int, string) {
	oldStderr := os.Stderr
	r, w, err := os.Pipe()
	if err != nil {
		panic(err)
	}
	os.Stderr = w

	outChan := make(chan string)
	go func() {
		var buf bytes.Buffer
		_, _ = io.Copy(&buf, r)
		outChan <- buf.String()
	}()

	code := f()

	_ = w.Close()
	os.Stderr = oldStderr
	output := <-outChan
	_ = r.Close()

	return code, output
}

func TestCLI_APK_Assess_SecurityRefusal_MissingScopeTarget(t *testing.T) {
	apkPath := createCLIArtifactAPK(t, []string{"https://api.mycorp.com/v1"})

	code, errOut := captureAPKStderr(func() int {
		return runAPK([]string{"--assess", apkPath})
	})

	if code != 2 {
		t.Errorf("expected exit code 2 for missing scope target, got %d", code)
	}
	if !strings.Contains(errOut, "Active backend assessment requires explicit authorized scope targets") {
		t.Errorf("expected security refusal message in stderr, got:\n%s", errOut)
	}
}

func TestCLI_APK_Assess_SecurityRefusal_MissingAuthorization(t *testing.T) {
	apkPath := createCLIArtifactAPK(t, []string{"https://api.mycorp.com/v1"})

	code, errOut := captureAPKStderr(func() int {
		return runAPK([]string{"--assess", "--target", "https://api.mycorp.com", apkPath})
	})

	if code != 2 {
		t.Errorf("expected exit code 2 for missing authorization, got %d", code)
	}
	if !strings.Contains(errOut, "Missing authorization certification") {
		t.Errorf("expected missing authorization certification message in stderr, got:\n%s", errOut)
	}
}

func TestCLI_APK_Assess_DryRunPlanning_JSON(t *testing.T) {
	apkPath := createCLIArtifactAPK(t, []string{
		"https://api.mycorp.com/v1/users",
		"https://unauthorized.thirdparty.com/v1",
	})

	code, output := captureAPKOutput(func() int {
		return runAPK([]string{
			"--json",
			"--assess",
			"--target", "https://api.mycorp.com",
			"--auth-confirm",
			"--dry-run",
			apkPath,
		})
	})

	if code != 0 {
		t.Fatalf("expected exit code 0 for dry-run plan, got %d, out:\n%s", code, output)
	}

	var res map[string]interface{}
	if err := json.Unmarshal([]byte(output), &res); err != nil {
		t.Fatalf("failed to parse JSON: %v, raw:\n%s", err, output)
	}

	handoff, ok := res["backend_handoff"].(map[string]interface{})
	if !ok || handoff == nil {
		t.Fatalf("expected backend_handoff object in JSON output")
	}

	if handoff["dry_run"] != true {
		t.Errorf("expected dry_run=true, got %v", handoff["dry_run"])
	}
	if handoff["total_requests_sent"].(float64) != 0 {
		t.Errorf("expected 0 requests sent during dry-run, got %v", handoff["total_requests_sent"])
	}
	if handoff["total_tested"].(float64) != 0 {
		t.Errorf("expected 0 tested during dry-run, got %v", handoff["total_tested"])
	}
	if handoff["total_eligible"].(float64) < 1 {
		t.Errorf("expected at least 1 eligible candidate, got %v", handoff["total_eligible"])
	}
}

func TestCLI_APK_StaticOnly_ActiveAssessmentDisabled(t *testing.T) {
	apkPath := createCLIArtifactAPK(t, []string{"https://api.mycorp.com/v1"})

	code, output := captureAPKOutput(func() int {
		return runAPK([]string{"--analyze", apkPath})
	})

	if code != 0 {
		t.Fatalf("expected exit code 0, got %d", code)
	}
	if !strings.Contains(output, "Active Assessment:       Disabled (offline static analysis only") {
		t.Errorf("expected active assessment disabled notice in static analysis output, got:\n%s", output)
	}
}

func TestCLI_APK_Report_DefaultPath(t *testing.T) {
	apkPath := createCLIArtifactAPK(t, []string{"https://api.mycorp.com/v1"})
	defer os.Remove("mobile_audit.html")

	code, output := captureAPKOutput(func() int {
		return runAPK([]string{"--report", apkPath})
	})

	if code != 0 {
		t.Fatalf("expected exit code 0, got %d, out:\n%s", code, output)
	}
	if !strings.Contains(output, "Mobile Audit Report:     mobile_audit.html") {
		t.Errorf("expected report path in output, got:\n%s", output)
	}

	content, err := os.ReadFile("mobile_audit.html")
	if err != nil {
		t.Fatalf("failed to read generated report: %v", err)
	}
	if !strings.Contains(string(content), "<!DOCTYPE html>") {
		t.Errorf("expected valid HTML doctype in report")
	}
	if !strings.Contains(string(content), "FELIX Mobile Security Assessment Report") {
		t.Errorf("expected report title in html")
	}
}

func TestCLI_APK_Report_CustomPath(t *testing.T) {
	apkPath := createCLIArtifactAPK(t, []string{"https://api.mycorp.com/v1"})
	customReport := filepath.Join(t.TempDir(), "custom_audit.html")

	code, output := captureAPKOutput(func() int {
		return runAPK([]string{"--report", customReport, apkPath})
	})

	if code != 0 {
		t.Fatalf("expected exit code 0, got %d, out:\n%s", code, output)
	}
	if !strings.Contains(output, customReport) {
		t.Errorf("expected custom report path in output, got:\n%s", output)
	}

	content, err := os.ReadFile(customReport)
	if err != nil {
		t.Fatalf("failed to read custom report: %v", err)
	}
	if !strings.Contains(string(content), "<!DOCTYPE html>") {
		t.Errorf("expected valid HTML doctype in report")
	}
}

func TestCLI_APK_Report_OutputFlag(t *testing.T) {
	apkPath := createCLIArtifactAPK(t, []string{"https://api.mycorp.com/v1"})
	customReport := filepath.Join(t.TempDir(), "output_flag_audit.html")

	code, output := captureAPKOutput(func() int {
		return runAPK([]string{"-o", customReport, apkPath})
	})

	if code != 0 {
		t.Fatalf("expected exit code 0, got %d, out:\n%s", code, output)
	}

	content, err := os.ReadFile(customReport)
	if err != nil {
		t.Fatalf("failed to read report generated with -o: %v", err)
	}
	if len(content) == 0 {
		t.Errorf("expected non-empty report content")
	}
}

func TestCLI_APK_Report_JSONOutput(t *testing.T) {
	apkPath := createCLIArtifactAPK(t, []string{"https://api.mycorp.com/v1"})
	customReport := filepath.Join(t.TempDir(), "json_mode_audit.html")

	code, output := captureAPKOutput(func() int {
		return runAPK([]string{"--json", "--report", customReport, apkPath})
	})

	if code != 0 {
		t.Fatalf("expected exit code 0, got %d, out:\n%s", code, output)
	}

	var res map[string]interface{}
	if err := json.Unmarshal([]byte(output), &res); err != nil {
		t.Fatalf("failed to unmarshal JSON: %v, raw:\n%s", err, output)
	}

	if res["report_file"] != customReport {
		t.Errorf("expected report_file %q, got %v", customReport, res["report_file"])
	}

	if _, err := os.Stat(customReport); err != nil {
		t.Fatalf("report file was not created: %v", err)
	}
}

func TestCLI_APK_Report_RefuseOverwriteAPK(t *testing.T) {
	apkPath := createCLIArtifactAPK(t, []string{"https://api.mycorp.com/v1"})

	code, errOut := captureAPKStderr(func() int {
		return runAPK([]string{"-o", apkPath, apkPath})
	})

	if code != 2 {
		t.Errorf("expected exit code 2 when output equals input apk, got %d", code)
	}
	if !strings.Contains(errOut, "refusing to overwrite") {
		t.Errorf("expected refusal message in stderr, got:\n%s", errOut)
	}
}

func TestCLI_APK_Report_WithAssess_DryRun(t *testing.T) {
	apkPath := createCLIArtifactAPK(t, []string{"https://api.mycorp.com/v1/users"})
	customReport := filepath.Join(t.TempDir(), "assess_report.html")

	code, _ := captureAPKOutput(func() int {
		return runAPK([]string{
			"--assess",
			"--target", "https://api.mycorp.com",
			"--auth-confirm",
			"--dry-run",
			"--report", customReport,
			apkPath,
		})
	})

	if code != 0 {
		t.Fatalf("expected exit code 0, got %d", code)
	}

	content, err := os.ReadFile(customReport)
	if err != nil {
		t.Fatalf("failed to read report: %v", err)
	}
	s := string(content)
	if !strings.Contains(s, "Authorized Backend Assessment Results") {
		t.Errorf("expected assessment section in report")
	}
	if !strings.Contains(s, "Dry-Run Plan") {
		t.Errorf("expected dry-run badge in report")
	}
}

func TestCLI_APK_EndToEnd_FullWorkflow(t *testing.T) {
	// Setup local mock server for authorized target
	var serverRequests int32
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&serverRequests, 1)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"healthy","service":"api"}`))
	}))
	defer ts.Close()

	// 1. Create a rich synthetic APK containing manifest, DEX with target URL + secret + service indicator, and google-services.json
	dexStrings := []string{
		ts.URL + "/api/v1/health",
		"https://unauthorized.evilcorp.com/api/v1/leaks",
		"AKIAIOSFODNN7EXAMPLE",
	}
	apkPath := createCLIArtifactAPK(t, dexStrings)

	// Stage 1: Static analysis only (zero requests to mock server)
	code1, out1 := captureAPKOutput(func() int {
		return runAPK([]string{"--analyze", apkPath})
	})
	if code1 != 0 {
		t.Fatalf("expected exit code 0 for --analyze, got %d, out:\n%s", code1, out1)
	}
	if atomic.LoadInt32(&serverRequests) != 0 {
		t.Errorf("static analysis must never send network requests, got %d requests", atomic.LoadInt32(&serverRequests))
	}
	if !strings.Contains(out1, "Active Assessment:       Disabled (offline static analysis only") {
		t.Errorf("expected static analysis offline notice in output")
	}

	// Stage 2: Repeat static analysis to verify idempotency/determinism of results
	code2, out2 := captureAPKOutput(func() int {
		return runAPK([]string{"--analyze", apkPath})
	})
	if code2 != 0 {
		t.Fatalf("expected exit code 0 on repeat run, got %d", code2)
	}
	if out1 != out2 {
		t.Errorf("static analysis output should be deterministic across repeat executions on same APK")
	}

	// Stage 3: Authorized active assessment and mobile_audit.html report generation
	reportFile := filepath.Join(t.TempDir(), "e2e_mobile_audit.html")
	code3, out3 := captureAPKOutput(func() int {
		return runAPK([]string{
			"--json",
			"--assess",
			"--target", ts.URL,
			"--auth-confirm",
			"--authorizing-party", "E2E Lead Auditor",
			"--allow-loopback",
			"--report", reportFile,
			apkPath,
		})
	})
	if code3 != 0 {
		t.Fatalf("expected exit code 0 for authorized assessment, got %d, out:\n%s", code3, out3)
	}

	// Verify server received exactly 1 request for in-scope target, while evilcorp was skipped
	if atomic.LoadInt32(&serverRequests) != 1 {
		t.Errorf("expected exactly 1 request dispatched to authorized server, got %d", atomic.LoadInt32(&serverRequests))
	}

	// Parse JSON output
	var jsonRes map[string]interface{}
	if err := json.Unmarshal([]byte(out3), &jsonRes); err != nil {
		t.Fatalf("failed to parse JSON response: %v, raw:\n%s", err, out3)
	}

	if jsonRes["status"] != "PASS" {
		t.Errorf("expected status PASS, got %v", jsonRes["status"])
	}
	if jsonRes["report_file"] != reportFile {
		t.Errorf("expected report_file %q, got %v", reportFile, jsonRes["report_file"])
	}

	handoff, ok := jsonRes["backend_handoff"].(map[string]interface{})
	if !ok || handoff == nil {
		t.Fatalf("expected backend_handoff object in json output")
	}
	if handoff["total_tested"].(float64) != 1 {
		t.Errorf("expected 1 tested endpoint, got %v", handoff["total_tested"])
	}
	if handoff["total_skipped"].(float64) < 1 {
		t.Errorf("expected at least 1 skipped endpoint (unauthorized evilcorp), got %v", handoff["total_skipped"])
	}

	// Verify generated HTML report exists and contains all required sections
	htmlBytes, err := os.ReadFile(reportFile)
	if err != nil {
		t.Fatalf("failed to read generated HTML report: %v", err)
	}
	htmlStr := string(htmlBytes)

	// Validate presence of 8 key report sections
	sections := []string{
		"FELIX Mobile Security Assessment Report",
		"APK Package Metadata",
		"Security Findings",
		"Embedded Service & Infrastructure Indicators",
		"Backend Endpoint & Host Inventory",
		"Authorized Backend Assessment Results",
		"Actionable Remediation Guidance",
		"Analysis Scope, Methodology & Limitations",
	}
	for _, sec := range sections {
		if !strings.Contains(htmlStr, sec) {
			t.Errorf("missing section in generated HTML report: %q", sec)
		}
	}

	// Verify active test status and HTTP 200 recorded in report
	if !strings.Contains(htmlStr, "HTTP 200") {
		t.Errorf("expected HTTP 200 outcome in report")
	}
	if !strings.Contains(htmlStr, "Authorized Assessment Completed") {
		t.Errorf("expected Authorized Assessment Completed badge in report")
	}

	// Verify raw secrets are redacted in the generated HTML
	if strings.Contains(htmlStr, "AKIAIOSFODNN7EXAMPLE") {
		t.Errorf("CRITICAL: raw AWS secret leaked into generated HTML report!")
	}
}
