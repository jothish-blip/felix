package main

import (
	"archive/tar"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"felix/pkg/clierror"
	"felix/pkg/cve"
)

// Helper to create a valid test archive
func createValidTestArchive(t *testing.T, dir string) (string, string) {
	t.Helper()
	archivePath := filepath.Join(dir, "valid_test_archive.tar.gz")

	records := []cve.CVERecord{
		{
			CVEID:                 "CVE-2024-8001",
			Source:                cve.SourceOSV,
			CPEPrefix:             "cpe:2.3:a:felix:security_core",
			Vendor:                "felix",
			Product:               "security_core",
			VersionStart:          "1.0.0",
			VersionStartIncluding: true,
			VersionEnd:            "1.2.0",
			VersionEndIncluding:   false,
			CVSSScore:             8.5,
			Severity:              "HIGH",
			Summary:               "Valid archive test vulnerability",
		},
	}

	tmpl := &cve.Template{
		ID: "valid-cli-template",
		Info: cve.TemplateInfo{
			Name:     "Valid CLI Template",
			Author:   "felix",
			Severity: "high",
		},
		HTTP: []cve.HTTPRequestConfig{
			{
				Method: "GET",
				Path:   "/test",
				Matchers: []cve.MatcherConfig{
					{Type: "status", Status: []int{200}},
				},
			},
		},
	}

	if err := cve.CreateOfflineArchive(archivePath, records, []*cve.Template{tmpl}); err != nil {
		t.Fatalf("Failed creating valid test archive: %v", err)
	}

	b, err := os.ReadFile(archivePath)
	if err != nil {
		t.Fatalf("Failed reading archive: %v", err)
	}
	h := sha256.Sum256(b)
	return archivePath, hex.EncodeToString(h[:])
}

// Test 1: Missing archive argument
func TestCVE_CLI_MissingArchiveArgument(t *testing.T) {
	exitCode := runCVEImport([]string{})
	if exitCode != clierror.ExitOperational {
		t.Errorf("Expected exit code %d (ExitOperational), got %d", clierror.ExitOperational, exitCode)
	}
}

// Test 2: Nonexistent archive
func TestCVE_CLI_NonexistentArchive(t *testing.T) {
	nonexistent := filepath.Join(t.TempDir(), "nonexistent.tar.gz")
	exitCode := runCVEImport([]string{nonexistent})
	if exitCode != clierror.ExitOperational {
		t.Errorf("Expected exit code %d (ExitOperational), got %d", clierror.ExitOperational, exitCode)
	}
}

// Test 3: Invalid / corrupted archive
func TestCVE_CLI_InvalidArchive(t *testing.T) {
	tmpDir := t.TempDir()
	corrupted := filepath.Join(tmpDir, "corrupted.tar.gz")
	if err := os.WriteFile(corrupted, []byte("NOT_A_VALID_GZIP_ARCHIVE"), 0644); err != nil {
		t.Fatalf("Failed writing corrupted file: %v", err)
	}

	exitCode := runCVEImport([]string{corrupted})
	if exitCode != clierror.ExitOperational {
		t.Errorf("Expected exit code %d (ExitOperational), got %d", clierror.ExitOperational, exitCode)
	}
}

// Test 4: Invalid manifest (missing manifest.json)
func TestCVE_CLI_InvalidManifest(t *testing.T) {
	tmpDir := t.TempDir()
	archivePath := filepath.Join(tmpDir, "no_manifest.tar.gz")

	f, err := os.Create(archivePath)
	if err != nil {
		t.Fatalf("Failed creating archive: %v", err)
	}
	gw := gzip.NewWriter(f)
	tw := tar.NewWriter(gw)

	data := []byte(`[{"cve_id":"CVE-2024-0001"}]`)
	_ = tw.WriteHeader(&tar.Header{Name: "cve/records.json", Size: int64(len(data)), Mode: 0644, Typeflag: tar.TypeReg})
	_, _ = tw.Write(data)

	_ = tw.Close()
	_ = gw.Close()
	_ = f.Close()

	exitCode := runCVEImport([]string{archivePath})
	if exitCode != clierror.ExitOperational {
		t.Errorf("Expected exit code %d (ExitOperational), got %d", clierror.ExitOperational, exitCode)
	}
}

// Test 5: Invalid checksum
func TestCVE_CLI_InvalidChecksum(t *testing.T) {
	tmpDir := t.TempDir()
	archivePath, _ := createValidTestArchive(t, tmpDir)

	badHash := "0000000000000000000000000000000000000000000000000000000000000000"
	exitCode := runCVEImport([]string{"--checksum", badHash, archivePath})
	if exitCode != clierror.ExitOperational {
		t.Errorf("Expected exit code %d (ExitOperational) for invalid checksum, got %d", clierror.ExitOperational, exitCode)
	}
}

// Test 6: Successful valid archive import
func TestCVE_CLI_SuccessfulValidArchiveImport(t *testing.T) {
	tmpDir := t.TempDir()
	archivePath, validHash := createValidTestArchive(t, tmpDir)
	dbPath := filepath.Join(tmpDir, "cli_success.db")

	// Import with explicit valid checksum
	exitCode := runCVEImport([]string{"--db", dbPath, "--checksum", validHash, archivePath})
	if exitCode != clierror.ExitSuccess {
		t.Errorf("Expected exit code %d (ExitSuccess), got %d", clierror.ExitSuccess, exitCode)
	}

	// Verify database was populated
	store, err := cve.NewStore(dbPath)
	if err != nil {
		t.Fatalf("Failed opening store: %v", err)
	}
	defer store.Close()

	dbStats, err := store.GetStats(t.Context())
	if err != nil || dbStats.TotalRecords != 1 {
		t.Errorf("Expected 1 record in database, got %d (err: %v)", dbStats.TotalRecords, err)
	}
}

// Test 7: Successful valid archive import with sidecar .sha256 file
func TestCVE_CLI_SuccessfulValidArchiveWithSidecarChecksum(t *testing.T) {
	tmpDir := t.TempDir()
	archivePath, validHash := createValidTestArchive(t, tmpDir)
	dbPath := filepath.Join(tmpDir, "cli_sidecar.db")

	// Write sidecar checksum file
	sidecarPath := archivePath + ".sha256"
	if err := os.WriteFile(sidecarPath, []byte(fmt.Sprintf("%s  %s\n", validHash, filepath.Base(archivePath))), 0644); err != nil {
		t.Fatalf("Failed writing sidecar checksum: %v", err)
	}

	exitCode := runCVEImport([]string{"--db", dbPath, archivePath})
	if exitCode != clierror.ExitSuccess {
		t.Errorf("Expected exit code %d (ExitSuccess) with sidecar checksum, got %d", clierror.ExitSuccess, exitCode)
	}
}

// Test 8: CLI sidecar mismatch rejected
func TestCVE_CLI_SidecarMismatchRejection(t *testing.T) {
	tmpDir := t.TempDir()
	archivePath, _ := createValidTestArchive(t, tmpDir)
	dbPath := filepath.Join(tmpDir, "cli_sidecar_mismatch.db")

	// Write bad sidecar
	sidecarPath := archivePath + ".sha256"
	_ = os.WriteFile(sidecarPath, []byte("0000000000000000000000000000000000000000000000000000000000000000  archive.tar.gz\n"), 0644)

	exitCode := runCVEImport([]string{"--db", dbPath, archivePath})
	if exitCode != clierror.ExitOperational {
		t.Errorf("Expected exit code %d (ExitOperational) for sidecar mismatch, got %d", clierror.ExitOperational, exitCode)
	}
}

// Test 9: CLI modifying both archive and sidecar cannot bypass trusted checksum
func TestCVE_CLI_SidecarAndArchiveModified_CannotBypassTrustedChecksum(t *testing.T) {
	tmpDir := t.TempDir()
	archivePath, validHash := createValidTestArchive(t, tmpDir)
	dbPath := filepath.Join(tmpDir, "cli_bypass_attempt.db")

	// Attacker tampers archive
	data, _ := os.ReadFile(archivePath)
	data[len(data)-5] ^= 0xAA
	_ = os.WriteFile(archivePath, data, 0644)

	// Attacker creates matching sidecar for tampered archive
	newHash := sha256.Sum256(data)
	newHashHex := hex.EncodeToString(newHash[:])
	sidecarPath := archivePath + ".sha256"
	_ = os.WriteFile(sidecarPath, []byte(fmt.Sprintf("%s  %s\n", newHashHex, filepath.Base(archivePath))), 0644)

	// User specifies original trusted digest via --checksum
	exitCode := runCVEImport([]string{"--db", dbPath, "--checksum", validHash, archivePath})
	if exitCode != clierror.ExitOperational {
		t.Errorf("Expected exit code %d (ExitOperational) when trusted checksum fails, got %d", clierror.ExitOperational, exitCode)
	}
}

// Test 10: CLI subcommands integration (sync, status, query)
func TestCVE_CLI_Sync_Status_Query_Integration(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "cli_integration.db")

	// 1. Seed database
	syncCode := runCVESync([]string{"--db", dbPath, "--seed"})
	if syncCode != clierror.ExitSuccess {
		t.Errorf("Expected exit code %d for seed sync, got %d", clierror.ExitSuccess, syncCode)
	}

	// 2. Query status
	statusCode := runCVEStatus([]string{"--db", dbPath})
	if statusCode != clierror.ExitSuccess {
		t.Errorf("Expected exit code %d for status, got %d", clierror.ExitSuccess, statusCode)
	}

	// 3. Query known CVE
	queryCode := runCVEQuery([]string{"--db", dbPath, "--cpe", "cpe:2.3:a:apache:tomcat", "--version", "9.0.9"})
	if queryCode != clierror.ExitSuccess {
		t.Errorf("Expected exit code %d for query, got %d", clierror.ExitSuccess, queryCode)
	}
}
