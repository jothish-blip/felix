package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestBuildDebAndAptRepo(t *testing.T) {
	tmpDir := t.TempDir()

	// 1. Create a dummy executable
	dummyBinPath := filepath.Join(tmpDir, "dummy_felix")
	if err := os.WriteFile(dummyBinPath, []byte("#!/bin/sh\necho Felix 2.0.0\n"), 0755); err != nil {
		t.Fatalf("failed to create dummy binary: %v", err)
	}

	// 2. Build .deb
	debPath := filepath.Join(tmpDir, "felix_2.0.0_amd64.deb")
	cfg := DebConfig{
		Package:      "felix",
		Version:      "2.0.0",
		Architecture: "amd64",
		Maintainer:   "Test Maintainer <test@example.com>",
		Homepage:     "https://github.com/jothish-blip/felix",
		Section:      "utils",
		Priority:     "optional",
		Description:  "Deterministic web security auditor",
		LongDesc:     "Felix test package description",
		BinaryPath:   dummyBinPath,
		OutputPath:   debPath,
	}

	if err := BuildDeb(cfg); err != nil {
		t.Fatalf("BuildDeb failed: %v", err)
	}

	// 3. Verify .deb AR structure
	debBytes, err := os.ReadFile(debPath)
	if err != nil {
		t.Fatalf("reading deb: %v", err)
	}
	if !strings.HasPrefix(string(debBytes), "!<arch>\n") {
		t.Fatalf("expected !<arch>\\n magic, got: %q", string(debBytes[:8]))
	}

	// 4. Verify control extraction
	ctrl, err := extractControlFromDeb(debBytes)
	if err != nil {
		t.Fatalf("extractControlFromDeb failed: %v", err)
	}
	if !strings.Contains(ctrl, "Package: felix") {
		t.Errorf("expected 'Package: felix' in control, got:\n%s", ctrl)
	}
	if !strings.Contains(ctrl, "Version: 2.0.0") {
		t.Errorf("expected 'Version: 2.0.0' in control, got:\n%s", ctrl)
	}
	if !strings.Contains(ctrl, "Architecture: amd64") {
		t.Errorf("expected 'Architecture: amd64' in control, got:\n%s", ctrl)
	}

	// 5. Test APT Repository Generation
	repoDir := filepath.Join(tmpDir, "apt")
	signer, err := GenerateGpgSigner("Felix Test Signer", "Test Repo Key", "test@example.com")
	if err != nil {
		t.Fatalf("GenerateGpgSigner failed: %v", err)
	}

	if err := BuildAptRepo(repoDir, []string{debPath}, signer); err != nil {
		t.Fatalf("BuildAptRepo failed: %v", err)
	}

	// Verify APT files
	expectedFiles := []string{
		"dists/stable/Release",
		"dists/stable/InRelease",
		"dists/stable/Release.gpg",
		"dists/stable/main/binary-amd64/Packages",
		"dists/stable/main/binary-amd64/Packages.gz",
		"pool/main/f/felix/felix_2.0.0_amd64.deb",
		"felix-archive-keyring.gpg",
		"felix.gpg",
	}

	for _, rel := range expectedFiles {
		p := filepath.Join(repoDir, filepath.FromSlash(rel))
		if _, err := os.Stat(p); os.IsNotExist(err) {
			t.Errorf("missing expected APT repo file: %s", rel)
		}
	}

	// Verify Packages content
	pkgBytes, err := os.ReadFile(filepath.Join(repoDir, "dists", "stable", "main", "binary-amd64", "Packages"))
	if err != nil {
		t.Fatalf("reading Packages: %v", err)
	}
	pkgContent := string(pkgBytes)
	if !strings.Contains(pkgContent, "Filename: pool/main/f/felix/felix_2.0.0_amd64.deb") {
		t.Errorf("Packages missing Filename line, got:\n%s", pkgContent)
	}
	if !strings.Contains(pkgContent, "SHA256:") {
		t.Errorf("Packages missing SHA256 line, got:\n%s", pkgContent)
	}

	// Verify InRelease is signed
	inRelBytes, err := os.ReadFile(filepath.Join(repoDir, "dists", "stable", "InRelease"))
	if err != nil {
		t.Fatalf("reading InRelease: %v", err)
	}
	if !strings.Contains(string(inRelBytes), "-----BEGIN PGP SIGNED MESSAGE-----") {
		t.Errorf("InRelease is not clearsigned, got:\n%s", string(inRelBytes))
	}
}

func parseTarGz(data []byte) (map[string][]byte, error) {
	files := make(map[string][]byte)
	gzr, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	defer gzr.Close()
	tr := tar.NewReader(gzr)
	for {
		hdr, err := tr.Next()
		if err != nil {
			if err == io.EOF {
				break
			}
			return nil, err
		}
		if hdr.Typeflag == tar.TypeReg {
			b, err := io.ReadAll(tr)
			if err != nil {
				return nil, err
			}
			files[hdr.Name] = b
		}
	}
	return files, nil
}
