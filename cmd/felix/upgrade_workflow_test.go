package main

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"felix/pkg/update"
)

func buildTestBinary(t *testing.T, targetDir, version string) string {
	t.Helper()
	binName := "felix"
	if runtime.GOOS == "windows" {
		binName = "felix.exe"
	}
	outPath := filepath.Join(targetDir, fmt.Sprintf("felix_%s_%s", version, binName))

	cmd := exec.Command("go", "build", "-trimpath",
		"-ldflags", fmt.Sprintf("-s -w -X main.Version=%s -X main.Release=TestBuild", version),
		"-o", outPath, ".")
	cmd.Dir = "."
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("failed building test binary version %s: %v\nOutput: %s", version, err, string(out))
	}
	return outPath
}

func fileSHA256(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:]), nil
}

func TestUpgrade_CleanInstallThenUpgrade_WithSentinels(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration upgrade test in short mode")
	}

	buildDir := t.TempDir()
	binA := buildTestBinary(t, buildDir, "1.9.0")
	binB := buildTestBinary(t, buildDir, "2.1.0")

	installDir := filepath.Join(t.TempDir(), "felix_isolated_install")
	dataDir := filepath.Join(t.TempDir(), "felix_isolated_data")
	binName := "felix"
	if runtime.GOOS == "windows" {
		binName = "felix.exe"
	}
	targetExe := filepath.Join(installDir, binName)

	// Step 1: Clean Fresh Install of Version A (1.9.0)
	instCmd := exec.Command(binA, "install")
	instCmd.Env = append(os.Environ(),
		"FELIX_INSTALL_DIR="+installDir,
		"FELIX_DIR="+dataDir,
		"FELIX_NO_PATH_UPDATE=true",
	)
	instOut, instErr := instCmd.CombinedOutput()
	if instErr != nil {
		t.Fatalf("version A install failed: %v\nOutput: %s", instErr, string(instOut))
	}
	if !strings.Contains(string(instOut), "Installed and verified executable") {
		t.Errorf("expected clean installation confirmation, got: %s", string(instOut))
	}

	// Verify installed binary runs version 1.9.0
	chkCmdA := exec.Command(targetExe, "version")
	chkCmdA.Env = append(os.Environ(), "FELIX_DIR="+dataDir)
	chkOutA, chkErrA := chkCmdA.CombinedOutput()
	if chkErrA != nil || !strings.Contains(string(chkOutA), "1.9.0") {
		t.Fatalf("expected version 1.9.0, got: %v (output: %s)", chkErrA, string(chkOutA))
	}

	// Step 2: Establish persistent user sentinels in FELIX_DIR
	if err := os.MkdirAll(dataDir, 0755); err != nil {
		t.Fatalf("failed creating data dir: %v", err)
	}

	configPath := filepath.Join(dataDir, "config.json")
	configData := []byte(`{"timeout":42,"concurrency":7,"scope":"same-origin"}`)
	if err := os.WriteFile(configPath, configData, 0600); err != nil {
		t.Fatalf("failed writing sentinel config: %v", err)
	}

	secretPath := filepath.Join(dataDir, "sentinel_secret.key")
	secretData := []byte("felix-secret-credential-sentinel-value-883311")
	if err := os.WriteFile(secretPath, secretData, 0600); err != nil {
		t.Fatalf("failed writing sentinel secret: %v", err)
	}

	dbPath := filepath.Join(dataDir, "assessments.db")
	dbData := []byte("SQLite format 3\x00synthetic-assessment-history-payload")
	if err := os.WriteFile(dbPath, dbData, 0600); err != nil {
		t.Fatalf("failed writing sentinel database: %v", err)
	}

	userReportPath := filepath.Join(dataDir, "sentinel_report.html")
	userReportData := []byte("<html><body><h1>Sentinel User Report</h1></body></html>")
	if err := os.WriteFile(userReportPath, userReportData, 0644); err != nil {
		t.Fatalf("failed writing sentinel report: %v", err)
	}

	// Record hashes of all sentinels
	configHash, _ := fileSHA256(configPath)
	secretHash, _ := fileSHA256(secretPath)
	dbHash, _ := fileSHA256(dbPath)
	reportHash, _ := fileSHA256(userReportPath)

	// Step 3: Upgrade Version A (1.9.0) -> Version B (2.1.0)
	upgCmd := exec.Command(binB, "install")
	upgCmd.Env = append(os.Environ(),
		"FELIX_INSTALL_DIR="+installDir,
		"FELIX_DIR="+dataDir,
		"FELIX_NO_PATH_UPDATE=true",
	)
	upgOut, upgErr := upgCmd.CombinedOutput()
	if upgErr != nil {
		t.Fatalf("upgrade install failed: %v\nOutput: %s", upgErr, string(upgOut))
	}
	if !strings.Contains(string(upgOut), "Successfully upgraded Felix from v1.9.0 to v2.1.0") {
		t.Errorf("expected upgrade confirmation in output, got: %s", string(upgOut))
	}

	// Step 4: Verify upgraded binary runs and reports version 2.1.0
	chkCmdB := exec.Command(targetExe, "version")
	chkCmdB.Env = append(os.Environ(), "FELIX_DIR="+dataDir)
	chkOutB, chkErrB := chkCmdB.CombinedOutput()
	if chkErrB != nil || !strings.Contains(string(chkOutB), "2.1.0") {
		t.Fatalf("expected version 2.1.0 after upgrade, got: %v (output: %s)", chkErrB, string(chkOutB))
	}

	// Verify doctor passes on upgraded binary
	docCmd := exec.Command(targetExe, "doctor")
	docCmd.Env = append(os.Environ(), "FELIX_DIR="+dataDir)
	docOut, docErr := docCmd.CombinedOutput()
	if docErr != nil {
		t.Fatalf("doctor check failed on upgraded binary: %v\nOutput: %s", docErr, string(docOut))
	}
	if !strings.Contains(string(docOut), "Result: PASS") {
		t.Errorf("expected doctor PASS, got: %s", string(docOut))
	}

	// Step 5: Verify all persistent user data sentinels survived untouched
	newConfigHash, _ := fileSHA256(configPath)
	newSecretHash, _ := fileSHA256(secretPath)
	newDBHash, _ := fileSHA256(dbPath)
	newReportHash, _ := fileSHA256(userReportPath)

	if newConfigHash != configHash {
		t.Errorf("config.json was modified during upgrade! (before: %s, after: %s)", configHash, newConfigHash)
	}
	if newSecretHash != secretHash {
		t.Errorf("secret sentinel was modified during upgrade! (before: %s, after: %s)", secretHash, newSecretHash)
	}
	if newDBHash != dbHash {
		t.Errorf("assessments.db was modified during upgrade! (before: %s, after: %s)", dbHash, newDBHash)
	}
	if newReportHash != reportHash {
		t.Errorf("sentinel report was modified during upgrade! (before: %s, after: %s)", reportHash, newReportHash)
	}

	// Step 6: Verify no lingering staging artifacts exist in installDir
	entries, err := os.ReadDir(installDir)
	if err != nil {
		t.Fatalf("failed reading install dir: %v", err)
	}
	for _, entry := range entries {
		name := entry.Name()
		if strings.Contains(name, ".tmp.") || strings.Contains(name, ".atomic.") {
			t.Errorf("unexpected lingering staging artifact in install dir: %s", name)
		}
	}

	// Step 7: Verify CLI execution from arbitrary outside directory
	outsideCmd := exec.Command(targetExe, "version")
	outsideCmd.Dir = os.TempDir()
	outsideCmd.Env = append(os.Environ(), "FELIX_DIR="+dataDir)
	outsideOut, outsideErr := outsideCmd.CombinedOutput()
	if outsideErr != nil || !strings.Contains(string(outsideOut), "2.1.0") {
		t.Errorf("CLI failed when invoked from arbitrary directory: %v\nOutput: %s", outsideErr, string(outsideOut))
	}
}

func TestUpgrade_SameVersionNoOp(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping in short mode")
	}

	buildDir := t.TempDir()
	binA := buildTestBinary(t, buildDir, "2.0.0")

	installDir := filepath.Join(t.TempDir(), "felix_same_ver_install")
	// Install v2.0.0
	cmd1 := exec.Command(binA, "install")
	cmd1.Env = append(os.Environ(), "FELIX_INSTALL_DIR="+installDir, "FELIX_NO_PATH_UPDATE=true")
	if out, err := cmd1.CombinedOutput(); err != nil {
		t.Fatalf("initial install failed: %v\nOutput: %s", err, string(out))
	}

	// Install v2.0.0 again (same version)
	cmd2 := exec.Command(binA, "install")
	cmd2.Env = append(os.Environ(), "FELIX_INSTALL_DIR="+installDir, "FELIX_NO_PATH_UPDATE=true")
	out2, err2 := cmd2.CombinedOutput()
	if err2 != nil {
		t.Fatalf("same-version install failed: %v\nOutput: %s", err2, string(out2))
	}
	if !strings.Contains(string(out2), "already installed at current version") {
		t.Errorf("expected 'already installed at current version', got: %s", string(out2))
	}
}

func TestUpgrade_DowngradeRejectionAndForceOverride(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping in short mode")
	}

	buildDir := t.TempDir()
	binOld := buildTestBinary(t, buildDir, "1.5.0")
	binNew := buildTestBinary(t, buildDir, "2.5.0")

	installDir := filepath.Join(t.TempDir(), "felix_downgrade_install")
	binName := "felix"
	if runtime.GOOS == "windows" {
		binName = "felix.exe"
	}
	targetExe := filepath.Join(installDir, binName)

	// Step 1: Install newer version 2.5.0
	cmdNew := exec.Command(binNew, "install")
	cmdNew.Env = append(os.Environ(), "FELIX_INSTALL_DIR="+installDir, "FELIX_NO_PATH_UPDATE=true")
	if out, err := cmdNew.CombinedOutput(); err != nil {
		t.Fatalf("v2.5.0 install failed: %v\nOutput: %s", err, string(out))
	}

	// Step 2: Attempt downgrade with v1.5.0 without force
	cmdOld := exec.Command(binOld, "install")
	cmdOld.Env = append(os.Environ(), "FELIX_INSTALL_DIR="+installDir, "FELIX_NO_PATH_UPDATE=true")
	outOld, errOld := cmdOld.CombinedOutput()
	if errOld == nil {
		t.Fatalf("expected downgrade attempt to fail without --force, but it succeeded!\nOutput: %s", string(outOld))
	}
	if !strings.Contains(string(outOld), "Downgrades are rejected without --force") {
		t.Errorf("expected downgrade rejection error, got: %s", string(outOld))
	}

	// Verify installed executable is STILL version 2.5.0
	chkCmd := exec.Command(targetExe, "version")
	chkOut, _ := chkCmd.CombinedOutput()
	if !strings.Contains(string(chkOut), "2.5.0") {
		t.Fatalf("installed version was corrupted by rejected downgrade attempt: %s", string(chkOut))
	}

	// Step 3: Attempt downgrade with --force
	cmdForce := exec.Command(binOld, "install", "--force")
	cmdForce.Env = append(os.Environ(), "FELIX_INSTALL_DIR="+installDir, "FELIX_NO_PATH_UPDATE=true")
	outForce, errForce := cmdForce.CombinedOutput()
	if errForce != nil {
		t.Fatalf("forced downgrade failed: %v\nOutput: %s", errForce, string(outForce))
	}

	// Verify installed executable is now version 1.5.0
	chkCmd2 := exec.Command(targetExe, "version")
	chkOut2, _ := chkCmd2.CombinedOutput()
	if !strings.Contains(string(chkOut2), "1.5.0") {
		t.Fatalf("expected version 1.5.0 after forced downgrade, got: %s", string(chkOut2))
	}
}

func TestUpgrade_RollbackOnPostInstallFailure(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping in short mode")
	}

	buildDir := t.TempDir()
	binGood := buildTestBinary(t, buildDir, "2.0.0")

	installDir := filepath.Join(t.TempDir(), "felix_rollback_install")
	binName := "felix"
	if runtime.GOOS == "windows" {
		binName = "felix.exe"
	}
	targetExe := filepath.Join(installDir, binName)

	// Step 1: Install working version 2.0.0
	cmdGood := exec.Command(binGood, "install")
	cmdGood.Env = append(os.Environ(), "FELIX_INSTALL_DIR="+installDir, "FELIX_NO_PATH_UPDATE=true")
	if out, err := cmdGood.CombinedOutput(); err != nil {
		t.Fatalf("v2.0.0 install failed: %v\nOutput: %s", err, string(out))
	}

	// Step 2: Attempt upgrade with candidate that fails post-install version verification
	badCmd := exec.Command(binGood, "install", "--force")
	badCmd.Env = append(os.Environ(),
		"FELIX_INSTALL_DIR="+installDir,
		"FELIX_NO_PATH_UPDATE=true",
		"FELIX_TEST_FAIL_VERSION=true",
	)
	badOut, badErr := badCmd.CombinedOutput()
	if badErr == nil {
		t.Fatalf("expected candidate to fail post-install self-test, but it succeeded!\nOutput: %s", string(badOut))
	}
	if !strings.Contains(string(badOut), "Post-installation self-test failed") {
		t.Errorf("expected self-test failure message, got: %s", string(badOut))
	}
	if !strings.Contains(string(badOut), "rolled back to previous version") {
		t.Errorf("expected rollback confirmation message, got: %s", string(badOut))
	}

	// Step 3: Verify that rollback occurred and previous good binary 2.0.0 is STILL working!
	chkCmd := exec.Command(targetExe, "version")
	chkOut, chkErr := chkCmd.CombinedOutput()
	if chkErr != nil || !strings.Contains(string(chkOut), "2.0.0") {
		t.Fatalf("rollback failed! Installed binary is broken: %v\nOutput: %s", chkErr, string(chkOut))
	}
}

func TestUpdater_EndToEndPipeline_MockReleaseServer(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping in short mode")
	}

	// 1. Build a real binary for the candidate release
	binDir := t.TempDir()
	candidateExe := buildTestBinary(t, binDir, "3.0.0")

	// 2. Package into a zip archive
	archiveName, err := update.ArchiveName("3.0.0", runtime.GOOS, runtime.GOARCH)
	if err != nil {
		t.Fatalf("archive name error: %v", err)
	}

	archiveBuf := new(bytes.Buffer)
	zw := zip.NewWriter(archiveBuf)
	fIn, err := os.Open(candidateExe)
	if err != nil {
		t.Fatalf("failed opening candidate binary: %v", err)
	}
	targetNameInZip := update.ExecutableName(runtime.GOOS)
	w, err := zw.Create(targetNameInZip)
	if err != nil {
		t.Fatalf("failed adding to zip: %v", err)
	}
	if _, err := io.Copy(w, fIn); err != nil {
		t.Fatalf("failed writing to zip: %v", err)
	}
	fIn.Close()
	zw.Close()

	archiveBytes := archiveBuf.Bytes()
	h := sha256.Sum256(archiveBytes)
	validSHA256 := hex.EncodeToString(h[:])

	// 3. Set up mock HTTP release server
	mockServer := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		path := req.URL.Path
		switch {
		case strings.HasSuffix(path, "/releases/latest"):
			rel := update.GitHubRelease{
				TagName:     "v3.0.0",
				Name:        "Release 3.0.0",
				PublishedAt: time.Now(),
				Assets: []update.GitHubAsset{
					{
						ID:                 101,
						Name:               archiveName,
						Size:               int64(len(archiveBytes)),
						BrowserDownloadURL: "http://" + req.Host + "/download/" + archiveName,
					},
					{
						ID:                 102,
						Name:               "SHA256SUMS",
						Size:               128,
						BrowserDownloadURL: "http://" + req.Host + "/download/SHA256SUMS",
					},
				},
			}
			_ = json.NewEncoder(rw).Encode(rel)
		case strings.HasSuffix(path, "/download/SHA256SUMS"):
			rw.Header().Set("Content-Type", "text/plain")
			_, _ = fmt.Fprintf(rw, "%s  %s\n", validSHA256, archiveName)
		case strings.HasSuffix(path, "/download/"+archiveName):
			rw.Header().Set("Content-Type", "application/zip")
			rw.Header().Set("Content-Length", fmt.Sprintf("%d", len(archiveBytes)))
			_, _ = rw.Write(archiveBytes)
		default:
			http.NotFound(rw, req)
		}
	}))
	defer mockServer.Close()

	t.Setenv("FELIX_UPDATE_API_URL", mockServer.URL)
	t.Setenv("FELIX_UPDATE_ALLOW_LOCAL", "true")

	u := update.NewUpdater("test-owner/test-repo", "2.0.0")

	// Test A: Check latest
	checkRes, err := u.Checker.CheckLatest(context.Background(), "2.0.0")
	if err != nil {
		t.Fatalf("CheckLatest failed: %v", err)
	}
	if !checkRes.UpdateAvailable || checkRes.LatestVersion != "3.0.0" {
		t.Errorf("expected update to 3.0.0 available, got: %+v", checkRes)
	}

	// Test B: Dry run update (downloads, verifies checksum, validates without modifying running binary)
	opts := update.UpdateOptions{
		TargetVersion: "3.0.0",
		DryRun:        true,
	}
	res, err := u.Update(context.Background(), opts)
	if err != nil {
		t.Fatalf("dry-run update failed: %v", err)
	}
	if res.UpdatedVersion != "3.0.0" {
		t.Errorf("expected UpdatedVersion 3.0.0, got: %s", res.UpdatedVersion)
	}
}
