package main

import (
	"archive/zip"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// createCustomAPK creates a test APK with specified entries.
func createCustomAPK(t *testing.T, entries map[string][]byte) string {
	t.Helper()
	tmpDir := t.TempDir()
	apkPath := filepath.Join(tmpDir, "app.apk")

	f, err := os.Create(apkPath)
	if err != nil {
		t.Fatalf("failed to create apk file: %v", err)
	}
	defer f.Close()

	zw := zip.NewWriter(f)
	for name, content := range entries {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatalf("failed to create entry %s: %v", name, err)
		}
		if _, err := w.Write(content); err != nil {
			t.Fatalf("failed to write entry %s: %v", name, err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("failed to close zip: %v", err)
	}
	return apkPath
}

// TestScanAPK_Workflow_Default tests the exact required command:
// felix scan app.apk --export mobile_audit.html
func TestScanAPK_Workflow_Default(t *testing.T) {
	isolatedDir := t.TempDir()
	apkPath := filepath.Join(isolatedDir, "app.apk")

	// Create valid synthetic app.apk in isolatedDir
	f, err := os.Create(apkPath)
	if err != nil {
		t.Fatalf("failed to create apk: %v", err)
	}
	zw := zip.NewWriter(f)
	w1, _ := zw.Create("AndroidManifest.xml")
	w1.Write([]byte(`<manifest package="com.felix.mobile.workflow">
		<application android:debuggable="true" android:allowBackup="true">
			<activity android:name=".MainActivity" android:exported="true" />
		</application>
	</manifest>`))
	w2, _ := zw.Create("classes.dex")
	w2.Write([]byte("dex\n035\x00synthetic-bytecode"))
	_ = zw.Close()
	_ = f.Close()

	// Switch working directory to isolated directory
	origWd, err := os.Getwd()
	if err != nil {
		t.Fatalf("failed to get current wd: %v", err)
	}
	if err := os.Chdir(isolatedDir); err != nil {
		t.Fatalf("failed to chdir to isolatedDir: %v", err)
	}
	defer func() {
		_ = os.Chdir(origWd)
	}()

	// Execute exact required workflow: felix scan app.apk --export mobile_audit.html
	code, output := captureAPKOutput(func() int {
		return runScan([]string{"app.apk", "--export", "mobile_audit.html"})
	})

	if code != 0 {
		t.Fatalf("expected exit code 0, got %d. Output:\n%s", code, output)
	}

	// Verify APK analysis pipeline (not web crawler) was invoked
	if !strings.Contains(output, "FELIX APK Assessment") && !strings.Contains(output, "Exported Report") {
		t.Errorf("expected APK assessment output banner, got:\n%s", output)
	}
	if !strings.Contains(output, "Active Assessment:       Disabled (offline static analysis only") {
		t.Errorf("expected offline static analysis confirmation in output, got:\n%s", output)
	}

	// Verify mobile_audit.html was generated at requested location
	reportPath := filepath.Join(isolatedDir, "mobile_audit.html")
	info, err := os.Stat(reportPath)
	if err != nil {
		t.Fatalf("expected mobile_audit.html to exist at %s: %v", reportPath, err)
	}
	if info.Size() == 0 {
		t.Fatalf("mobile_audit.html is empty")
	}

	reportBytes, err := os.ReadFile(reportPath)
	if err != nil {
		t.Fatalf("failed reading mobile_audit.html: %v", err)
	}
	reportHTML := string(reportBytes)

	// Verify HTML structure and metadata
	if !strings.Contains(reportHTML, "<!DOCTYPE html>") {
		t.Errorf("expected valid HTML5 doctype")
	}
	if !strings.Contains(reportHTML, "com.felix.mobile.workflow") {
		t.Errorf("expected package name in report")
	}
	if !strings.Contains(reportHTML, "app.apk") {
		t.Errorf("expected app.apk filename in report")
	}
}

// TestScanAPK_Workflow_IsolatedOutputDir tests:
// felix scan <fixture.apk> --export <isolated-output-directory>/mobile_audit.html
func TestScanAPK_Workflow_IsolatedOutputDir(t *testing.T) {
	fixtureAPK := createCustomAPK(t, map[string][]byte{
		"AndroidManifest.xml": []byte(`<manifest package="com.felix.fixture.test"/>`),
		"classes.dex":         []byte("dex\n035\x00synthetic"),
	})

	isolatedOutDir := filepath.Join(t.TempDir(), "nested", "reports")
	exportTarget := filepath.Join(isolatedOutDir, "mobile_audit.html")

	code, output := captureAPKOutput(func() int {
		return runScan([]string{fixtureAPK, "--export", exportTarget})
	})

	if code != 0 {
		t.Fatalf("expected exit code 0, got %d. Output:\n%s", code, output)
	}

	info, err := os.Stat(exportTarget)
	if err != nil {
		t.Fatalf("expected report at %s: %v", exportTarget, err)
	}
	if info.Size() == 0 {
		t.Fatalf("report file is empty")
	}
}

// TestScanAPK_OrderIndependenceAndAliases tests various flag orders and aliases:
// - felix scan --export out.html fixture.apk
// - felix scan fixture.apk -e out.html
// - felix scan fixture.apk --out out.html
func TestScanAPK_OrderIndependenceAndAliases(t *testing.T) {
	fixtureAPK := createCustomAPK(t, map[string][]byte{
		"AndroidManifest.xml": []byte(`<manifest package="com.felix.aliases.test"/>`),
		"classes.dex":         []byte("dex\n035\x00synthetic"),
	})

	cases := []struct {
		name string
		args []string
	}{
		{
			name: "FlagBeforeTarget",
			args: []string{"--export", filepath.Join(t.TempDir(), "rep1.html"), fixtureAPK},
		},
		{
			name: "ExportEqualSyntax",
			args: []string{fixtureAPK, "--export=" + filepath.Join(t.TempDir(), "rep2.html")},
		},
		{
			name: "ShortExportFlag",
			args: []string{fixtureAPK, "-e", filepath.Join(t.TempDir(), "rep3.html")},
		},
		{
			name: "OutputFlag",
			args: []string{fixtureAPK, "--output", filepath.Join(t.TempDir(), "rep4.html")},
		},
		{
			name: "OutAliasFlag",
			args: []string{fixtureAPK, "--out", filepath.Join(t.TempDir(), "rep5.html")},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			code, _ := captureAPKOutput(func() int {
				return runScan(tc.args)
			})
			if code != 0 {
				t.Fatalf("expected exit code 0, got %d for args %v", code, tc.args)
			}
		})
	}
}

// TestScanAPK_NegativeAndBoundedInput tests rejection of invalid inputs.
func TestScanAPK_NegativeAndBoundedInput(t *testing.T) {
	t.Run("NonexistentFile", func(t *testing.T) {
		code, _ := captureAPKOutput(func() int {
			return runScan([]string{"nonexistent_file_xyz_987.apk", "--export", "out.html"})
		})
		if code != 2 {
			t.Errorf("expected exit code 2 for nonexistent file, got %d", code)
		}
	})

	t.Run("DirectoryInsteadOfFile", func(t *testing.T) {
		dir := filepath.Join(t.TempDir(), "fake_dir.apk")
		if err := os.MkdirAll(dir, 0755); err != nil {
			t.Fatal(err)
		}
		code, _ := captureAPKOutput(func() int {
			return runScan([]string{dir, "--export", "out.html"})
		})
		if code != 2 {
			t.Errorf("expected exit code 2 for directory input, got %d", code)
		}
	})

	t.Run("EmptyFile", func(t *testing.T) {
		emptyFile := filepath.Join(t.TempDir(), "empty.apk")
		if err := os.WriteFile(emptyFile, []byte{}, 0644); err != nil {
			t.Fatal(err)
		}
		code, _ := captureAPKOutput(func() int {
			return runScan([]string{emptyFile, "--export", "out.html"})
		})
		if code != 2 {
			t.Errorf("expected exit code 2 for empty file, got %d", code)
		}
	})

	t.Run("CorruptedTruncatedZip", func(t *testing.T) {
		corruptFile := filepath.Join(t.TempDir(), "corrupt.apk")
		if err := os.WriteFile(corruptFile, []byte("PK\x03\x04corrupted-truncated-data"), 0644); err != nil {
			t.Fatal(err)
		}
		code, _ := captureAPKOutput(func() int {
			return runScan([]string{corruptFile, "--export", "out.html"})
		})
		if code != 2 {
			t.Errorf("expected exit code 2 for corrupted file, got %d", code)
		}
	})
}

// TestScanAPK_DetectorPositiveAndBenign tests positive vs benign detection.
func TestScanAPK_DetectorPositiveAndBenign(t *testing.T) {
	positiveAPK := createCustomAPK(t, map[string][]byte{
		"AndroidManifest.xml": []byte(`<manifest package="com.felix.positive">
			<application android:debuggable="true" android:allowBackup="true">
				<activity android:name=".ExportedActivity" android:exported="true" />
			</application>
		</manifest>`),
		"classes.dex": []byte("dex\n035\x00synthetic"),
	})

	benignAPK := createCustomAPK(t, map[string][]byte{
		"AndroidManifest.xml": []byte(`<manifest package="com.felix.benign">
			<application android:debuggable="false" android:allowBackup="false">
				<activity android:name=".PrivateActivity" android:exported="false" />
			</application>
		</manifest>`),
		"classes.dex": []byte("dex\n035\x00synthetic"),
	})

	outPos := filepath.Join(t.TempDir(), "pos.html")
	outBen := filepath.Join(t.TempDir(), "ben.html")

	codePos, outPosLog := captureAPKOutput(func() int {
		return runScan([]string{positiveAPK, "--export", outPos})
	})
	if codePos != 0 {
		t.Fatalf("expected code 0, got %d", codePos)
	}

	codeBen, outBenLog := captureAPKOutput(func() int {
		return runScan([]string{benignAPK, "--export", outBen})
	})
	if codeBen != 0 {
		t.Fatalf("expected code 0, got %d", codeBen)
	}

	posBytes, _ := os.ReadFile(outPos)
	benBytes, _ := os.ReadFile(outBen)

	posHTML := string(posBytes)
	benHTML := string(benBytes)

	// Positive fixture should flag debuggable
	if !strings.Contains(posHTML, "Debuggable") && !strings.Contains(outPosLog, "DEBUGGABLE") {
		t.Errorf("expected debuggable finding in positive report or log")
	}

	// Benign fixture should NOT flag debuggable
	if strings.Contains(benHTML, "Application Is Debuggable") || strings.Contains(outBenLog, "FLAGGED_DEBUGGABLE") {
		t.Errorf("benign fixture falsely flagged debuggable")
	}
}

// TestScanAPK_ReportSecurity_XSSAndSecretRedaction tests that HTML report properly
// escapes malicious manifest strings and redacts synthetic secrets.
func TestScanAPK_ReportSecurity_XSSAndSecretRedaction(t *testing.T) {
	// In XML, '<' in attributes must be written as entity '&lt;', which standard XML parsers decode to '<'.
	// Then the HTML report template engine must contextually escape it back to '&lt;'.
	xmlAttributeValue := `&lt;script&gt;alert('pwned')&lt;/script&gt;`
	syntheticSecret := `AKIAIOSFODNN7EXAMPLE`

	apkFile := createCustomAPK(t, map[string][]byte{
		"AndroidManifest.xml": []byte(`<manifest package="com.felix.test">
			<application android:label="` + xmlAttributeValue + `">
				<activity android:name=".MainActivity" android:exported="false" />
			</application>
		</manifest>`),
		"assets/config.json": []byte(`{"aws_key": "` + syntheticSecret + `"}`),
		"classes.dex":        []byte("dex\n035\x00synthetic"),
	})

	outReport := filepath.Join(t.TempDir(), "secured_report.html")

	code, _ := captureAPKOutput(func() int {
		return runScan([]string{apkFile, "--export", outReport})
	})
	if code != 0 {
		t.Fatalf("expected code 0, got %d", code)
	}

	repBytes, err := os.ReadFile(outReport)
	if err != nil {
		t.Fatalf("failed reading report: %v", err)
	}
	repHtml := string(repBytes)

	// XSS check: Raw unescaped <script> tag must NOT be present
	if strings.Contains(repHtml, "<script>alert('pwned')</script>") {
		t.Errorf("XSS payload was not HTML-escaped in report: %s", repHtml)
	}

	// Secret redaction check: Raw AWS secret must NOT be leaked
	if strings.Contains(repHtml, syntheticSecret) {
		t.Errorf("Synthetic AWS secret was not redacted from report HTML!")
	}
}

// TestScanAPK_WebScanNonRegression ensures that web scanning is unaffected
// and isAPKScan correctly identifies non-APK targets.
func TestScanAPK_WebScanNonRegression(t *testing.T) {
	nonAPKs := [][]string{
		{"https://example.com"},
		{"http://localhost:8080/app.apk"}, // URL with scheme is web target, not local APK
		{"--timeout", "10s", "https://api.example.com"},
		{"--help"},
		{"--export", "app.apk", "https://target.com"}, // app.apk is argument to --export, target is URL
	}

	for _, args := range nonAPKs {
		target, isAPK := isAPKScan(args)
		if isAPK {
			t.Errorf("expected isAPKScan(%v) to be false, got true with target %s", args, target)
		}
	}

	apks := [][]string{
		{"app.apk"},
		{"app.apk", "--export", "out.html"},
		{"--export", "out.html", "app.apk"},
		{"-e", "out.html", "path/to/my_application.apk"},
	}

	for _, args := range apks {
		target, isAPK := isAPKScan(args)
		if !isAPK || target == "" {
			t.Errorf("expected isAPKScan(%v) to be true, got false", args)
		}
	}
}
