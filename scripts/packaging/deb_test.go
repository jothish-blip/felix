package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/md5"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
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

	members, err := extractArMembers(debBytes)
	if err != nil {
		t.Fatalf("extractArMembers failed: %v", err)
	}

	if _, ok := members["debian-binary"]; !ok {
		t.Errorf("missing debian-binary member in deb")
	}
	if _, ok := members["control.tar.gz"]; !ok {
		t.Errorf("missing control.tar.gz member in deb")
	}
	if _, ok := members["data.tar.gz"]; !ok {
		t.Errorf("missing data.tar.gz member in deb")
	}

	// 4. Verify control extraction and maintainer scripts
	ctrlFiles, ctrlHeaders, err := parseTarGzWithHeaders(members["control.tar.gz"])
	if err != nil {
		t.Fatalf("parsing control.tar.gz: %v", err)
	}

	ctrlText := string(ctrlFiles["./control"])
	if !strings.Contains(ctrlText, "Package: felix") {
		t.Errorf("expected 'Package: felix' in control, got:\n%s", ctrlText)
	}
	if !strings.Contains(ctrlText, "Version: 2.0.0") {
		t.Errorf("expected 'Version: 2.0.0' in control, got:\n%s", ctrlText)
	}
	if !strings.Contains(ctrlText, "Architecture: amd64") {
		t.Errorf("expected 'Architecture: amd64' in control, got:\n%s", ctrlText)
	}

	// Verify maintainer scripts existence and executable permissions (0755)
	for _, script := range []string{"./postinst", "./prerm", "./postrm"} {
		hdr, ok := ctrlHeaders[script]
		if !ok {
			t.Errorf("missing %s in control.tar.gz", script)
			continue
		}
		if hdr.Mode != 0755 {
			t.Errorf("%s mode = %o, expected 0755", script, hdr.Mode)
		}
	}

	postrmScript := string(ctrlFiles["./postrm"])
	if !strings.Contains(postrmScript, "purge") || !strings.Contains(postrmScript, "/etc/felix") {
		t.Errorf("postrm should clean /etc/felix on purge, got:\n%s", postrmScript)
	}
	if strings.Contains(postrmScript, "rm -rf ~/.felix") || strings.Contains(postrmScript, "rm -rf $HOME/.felix") {
		t.Errorf("postrm must NEVER delete user assessment databases in ~/.felix")
	}

	// 5. Verify data.tar.gz contents (binary, man page, completions, changelog)
	dataFiles, dataHeaders, err := parseTarGzWithHeaders(members["data.tar.gz"])
	if err != nil {
		t.Fatalf("parsing data.tar.gz: %v", err)
	}

	expectedDataFiles := map[string]int64{
		"./usr/bin/felix":                                     0755,
		"./usr/share/doc/felix/copyright":                     0644,
		"./usr/share/doc/felix/changelog.Debian.gz":           0644,
		"./usr/share/man/man1/felix.1.gz":                     0644,
		"./usr/share/bash-completion/completions/felix":       0644,
		"./usr/share/zsh/vendor-completions/_felix":           0644,
		"./usr/share/fish/vendor_completions.d/felix.fish":    0644,
	}

	for path, expectedMode := range expectedDataFiles {
		hdr, ok := dataHeaders[path]
		if !ok {
			t.Errorf("missing %s in data.tar.gz", path)
			continue
		}
		if hdr.Mode != expectedMode {
			t.Errorf("%s mode = %o, expected %o", path, hdr.Mode, expectedMode)
		}
		if len(dataFiles[path]) == 0 {
			t.Errorf("%s is empty in data.tar.gz", path)
		}
	}

	// 6. Verify md5sums
	md5Text := string(ctrlFiles["./md5sums"])
	for path := range expectedDataFiles {
		rel := strings.TrimPrefix(path, "./")
		content := dataFiles[path]
		expectedSum := fmt.Sprintf("%x  %s", md5.Sum(content), rel)
		if !strings.Contains(md5Text, expectedSum) {
			t.Errorf("md5sums missing or invalid for %s: expected %q in:\n%s", rel, expectedSum, md5Text)
		}
	}

	// 7. Test APT Repository Generation
	repoDir := filepath.Join(tmpDir, "apt")
	signer, err := GenerateGpgSigner("Felix Test Signer", "Test Repo Key", "test@example.com")
	if err != nil {
		t.Fatalf("GenerateGpgSigner failed: %v", err)
	}

	if err := BuildAptRepo(repoDir, []string{debPath}, signer); err != nil {
		t.Fatalf("BuildAptRepo failed: %v", err)
	}

	// Verify APT files
	expectedRepoFiles := []string{
		"dists/stable/Release",
		"dists/stable/InRelease",
		"dists/stable/Release.gpg",
		"dists/stable/main/binary-amd64/Packages",
		"dists/stable/main/binary-amd64/Packages.gz",
		"pool/main/f/felix/felix_2.0.0_amd64.deb",
		"felix-archive-keyring.gpg",
		"felix.gpg",
	}

	for _, rel := range expectedRepoFiles {
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

func extractArMembers(debData []byte) (map[string][]byte, error) {
	members := make(map[string][]byte)
	r := bytes.NewReader(debData)
	magic := make([]byte, 8)
	if _, err := io.ReadFull(r, magic); err != nil {
		return nil, err
	}
	if string(magic) != "!<arch>\n" {
		return nil, fmt.Errorf("invalid ar magic: %q", string(magic))
	}

	for {
		hdr := make([]byte, 60)
		if _, err := io.ReadFull(r, hdr); err != nil {
			if err == io.EOF {
				break
			}
			return nil, err
		}
		name := strings.TrimSpace(string(hdr[0:16]))
		sizeStr := strings.TrimSpace(string(hdr[48:58]))
		size, err := strconv.ParseInt(sizeStr, 10, 64)
		if err != nil {
			return nil, err
		}

		memberData := make([]byte, size)
		if _, err := io.ReadFull(r, memberData); err != nil {
			return nil, err
		}
		if size%2 != 0 {
			_, _ = r.ReadByte() // skip padding
		}
		members[name] = memberData
	}
	return members, nil
}

func parseTarGzWithHeaders(data []byte) (map[string][]byte, map[string]*tar.Header, error) {
	files := make(map[string][]byte)
	headers := make(map[string]*tar.Header)
	gzr, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, nil, err
	}
	defer gzr.Close()
	tr := tar.NewReader(gzr)
	for {
		hdr, err := tr.Next()
		if err != nil {
			if err == io.EOF {
				break
			}
			return nil, nil, err
		}
		if hdr.Typeflag == tar.TypeReg {
			b, err := io.ReadAll(tr)
			if err != nil {
				return nil, nil, err
			}
			files[hdr.Name] = b
			headers[hdr.Name] = hdr
		}
	}
	return files, headers, nil
}
