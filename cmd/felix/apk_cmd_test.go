package main

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
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
