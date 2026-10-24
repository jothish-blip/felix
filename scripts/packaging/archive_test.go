package main

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestCreateZip_PermissionsAndStructure(t *testing.T) {
	tempDir := t.TempDir()
	stageDir := filepath.Join(tempDir, "stage")
	if err := os.MkdirAll(stageDir, 0755); err != nil {
		t.Fatalf("failed to create stage dir: %v", err)
	}

	binPath := filepath.Join(stageDir, "felix.exe")
	if err := os.WriteFile(binPath, []byte("mock-felix-binary-content"), 0755); err != nil {
		t.Fatalf("failed to create binary: %v", err)
	}

	docPath := filepath.Join(stageDir, "README.md")
	if err := os.WriteFile(docPath, []byte("# Felix Documentation"), 0644); err != nil {
		t.Fatalf("failed to create doc: %v", err)
	}

	zipPath := filepath.Join(tempDir, "test_output.zip")
	if err := createZip(stageDir, zipPath); err != nil {
		t.Fatalf("createZip failed: %v", err)
	}

	// Verify zip contents
	zr, err := zip.OpenReader(zipPath)
	if err != nil {
		t.Fatalf("failed opening created zip: %v", err)
	}
	defer zr.Close()

	if len(zr.File) != 2 {
		t.Fatalf("expected 2 files in zip, got %d", len(zr.File))
	}

	foundBin := false
	foundDoc := false
	for _, f := range zr.File {
		if f.Name == "felix.exe" {
			foundBin = true
			if f.Mode()&0111 == 0 {
				t.Errorf("expected felix.exe to have executable permissions, got mode: %v", f.Mode())
			}
		} else if f.Name == "README.md" {
			foundDoc = true
			if f.Mode()&0111 != 0 {
				t.Errorf("expected README.md to not have executable permissions, got mode: %v", f.Mode())
			}
		}
	}

	if !foundBin || !foundDoc {
		t.Errorf("missing expected files in zip: foundBin=%v, foundDoc=%v", foundBin, foundDoc)
	}
}

func TestCreateTarGz_PermissionsAndStructure(t *testing.T) {
	tempDir := t.TempDir()
	stageDir := filepath.Join(tempDir, "stage")
	if err := os.MkdirAll(stageDir, 0755); err != nil {
		t.Fatalf("failed to create stage dir: %v", err)
	}

	binPath := filepath.Join(stageDir, "felix")
	if err := os.WriteFile(binPath, []byte("mock-unix-felix-binary"), 0755); err != nil {
		t.Fatalf("failed to create binary: %v", err)
	}

	docPath := filepath.Join(stageDir, "README.md")
	if err := os.WriteFile(docPath, []byte("# Felix Unix Documentation"), 0644); err != nil {
		t.Fatalf("failed to create doc: %v", err)
	}

	tarPath := filepath.Join(tempDir, "test_output.tar.gz")
	if err := createTarGz(stageDir, tarPath); err != nil {
		t.Fatalf("createTarGz failed: %v", err)
	}

	// Inspect tar contents
	f, err := os.Open(tarPath)
	if err != nil {
		t.Fatalf("failed to open created tar.gz: %v", err)
	}
	defer f.Close()

	gzr, err := gzip.NewReader(f)
	if err != nil {
		t.Fatalf("failed to create gzip reader: %v", err)
	}
	defer gzr.Close()

	tr := tar.NewReader(gzr)
	foundBin := false
	foundDoc := false

	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("failed reading tar header: %v", err)
		}

		if header.Name == "felix" {
			foundBin = true
			if header.Mode != 0755 {
				t.Errorf("expected felix mode 0755 in tar header, got: 0%o", header.Mode)
			}
		} else if header.Name == "README.md" {
			foundDoc = true
			if header.Mode != 0644 {
				t.Errorf("expected README.md mode 0644 in tar header, got: 0%o", header.Mode)
			}
		}
	}

	if !foundBin || !foundDoc {
		t.Errorf("missing expected files in tar: foundBin=%v, foundDoc=%v", foundBin, foundDoc)
	}
}

func TestSha256File(t *testing.T) {
	tempDir := t.TempDir()
	p := filepath.Join(tempDir, "hash_test.bin")
	data := []byte("sha256-calculation-test-payload")
	if err := os.WriteFile(p, data, 0644); err != nil {
		t.Fatalf("failed writing test file: %v", err)
	}

	expected := sha256.Sum256(data)
	expectedHex := hex.EncodeToString(expected[:])

	actualHex, err := sha256File(p)
	if err != nil {
		t.Fatalf("sha256File failed: %v", err)
	}

	if actualHex != expectedHex {
		t.Errorf("sha256 mismatch: expected %s, got %s", expectedHex, actualHex)
	}
}

func TestPackaging_ProductionReleaseSigningFailClosed(t *testing.T) {
	// Verify that production release packaging fails closed when FELIX_APT_SIGNING_KEY is absent
	cmd := exec.Command("go", "run", ".", "9.9.9")
	cmd.Dir = "."
	cmd.Env = append(os.Environ(),
		"FELIX_REQUIRE_PRODUCTION_SIGNING=true",
		"FELIX_APT_SIGNING_KEY=",
	)
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("expected packaging to fail closed when FELIX_APT_SIGNING_KEY is absent in production mode, but it succeeded!\nOutput:\n%s", string(out))
	}
	outStr := string(out)
	if !strings.Contains(outStr, "FATAL: FELIX_APT_SIGNING_KEY is required for production release packaging (fail closed)") {
		t.Errorf("expected fail-closed error message, got:\n%s", outStr)
	}
}

func TestPackaging_RecomputeManifestFailClosedInProduction(t *testing.T) {
	// Verify that --recompute-manifest fails closed when production signing is enforced without a key
	cmd := exec.Command("go", "run", ".", "--recompute-manifest", "9.9.9")
	cmd.Dir = "."
	cmd.Env = append(os.Environ(),
		"FELIX_REQUIRE_PRODUCTION_SIGNING=true",
		"FELIX_APT_SIGNING_KEY=",
	)
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("expected --recompute-manifest to fail closed when FELIX_APT_SIGNING_KEY is absent in production mode, but it succeeded!\nOutput:\n%s", string(out))
	}
	outStr := string(out)
	if !strings.Contains(outStr, "FELIX_APT_SIGNING_KEY is required for production release packaging (fail closed)") {
		t.Errorf("expected fail-closed error message, got:\n%s", outStr)
	}
}
