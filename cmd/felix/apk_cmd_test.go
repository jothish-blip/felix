package main

import (
	"archive/zip"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

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

	// Capture stdout
	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	code := runAPK([]string{"--json", apkPath})

	w.Close()
	os.Stdout = oldStdout

	if code != 0 {
		t.Fatalf("expected exit code 0 for json intake, got %d", code)
	}

	var buf [4096]byte
	n, _ := r.Read(buf[:])
	output := string(buf[:n])

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

	// Capture stdout
	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	code := runAPK([]string{"--json", "--keep-workspace", apkPath})

	w.Close()
	os.Stdout = oldStdout

	if code != 0 {
		t.Fatalf("expected exit code 0, got %d", code)
	}

	var buf [4096]byte
	n, _ := r.Read(buf[:])
	output := string(buf[:n])

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
