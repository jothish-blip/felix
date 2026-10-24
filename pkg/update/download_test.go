package update

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestValidateDownloadURL(t *testing.T) {
	d := NewDownloader("jothish-blip/felix")

	validURLs := []string{
		"https://github.com/jothish-blip/felix/releases/download/v1.0.1/felix_1.0.1_windows_amd64.zip",
		"https://github.com/jothish-blip/felix/releases/download/v1.0.1/SHA256SUMS",
		"https://objects.githubusercontent.com/github-production-release-asset-2e65be/12345/abc?token=xyz",
		"https://github-releases.githubusercontent.com/12345/asset.tar.gz",
	}

	for _, u := range validURLs {
		if err := d.ValidateDownloadURL(u); err != nil {
			t.Errorf("expected URL to be valid, got error for %s: %v", u, err)
		}
	}

	invalidURLs := []string{
		"http://github.com/jothish-blip/felix/releases/download/v1.0.1/felix.zip", // HTTP
		"https://evil.attacker.com/felix.zip",                                     // Untrusted host
		"https://github.com/other-user/malicious/releases/download/v1.0.1/felix.zip", // Untrusted repo
		"ftp://github.com/jothish-blip/felix/releases/download/v1.0.1/felix.zip",  // Non-HTTPS
		"javascript:alert(1)",                                                    // Invalid scheme
	}

	for _, u := range invalidURLs {
		if err := d.ValidateDownloadURL(u); err == nil {
			t.Errorf("expected URL to be rejected, got nil error for %s", u)
		}
	}
}

func TestParseChecksums(t *testing.T) {
	manifest := `
# Comment line
da30a272f4343fe82ffa718e898abe6967b8d2c13ff2584d46e4b68706295608  felix_1.0.0_windows_amd64.zip
91bcc88e0f2067049e1226f9cc94caf39f4479d5989a620cddcc0eb8d3dd8047  felix_1.0.0_linux_amd64.tar.gz
ac23626f28364f791f8d2b513d97eed6299637378194ea2f118b3ceaa3b501b8 *felix_1.0.0_linux_arm64.tar.gz

`
	sums, err := ParseChecksums(strings.NewReader(manifest))
	if err != nil {
		t.Fatalf("unexpected parse error: %v", err)
	}

	if len(sums) != 3 {
		t.Fatalf("expected 3 entries, got %d", len(sums))
	}

	if sums["felix_1.0.0_windows_amd64.zip"] != "da30a272f4343fe82ffa718e898abe6967b8d2c13ff2584d46e4b68706295608" {
		t.Errorf("mismatch in windows zip hash: %s", sums["felix_1.0.0_windows_amd64.zip"])
	}
	if sums["felix_1.0.0_linux_arm64.tar.gz"] != "ac23626f28364f791f8d2b513d97eed6299637378194ea2f118b3ceaa3b501b8" {
		t.Errorf("mismatch in arm64 hash: %s", sums["felix_1.0.0_linux_arm64.tar.gz"])
	}
}

func TestParseChecksums_SecurityValidations(t *testing.T) {
	tests := []struct {
		name        string
		manifest    string
		errContains string
	}{
		{
			name:        "truncated entry without filename",
			manifest:    "da30a272f4343fe82ffa718e898abe6967b8d2c13ff2584d46e4b68706295608\r\n",
			errContains: "missing filename",
		},
		{
			name:        "traversal filename with dot-dot",
			manifest:    "da30a272f4343fe82ffa718e898abe6967b8d2c13ff2584d46e4b68706295608  ../escaped.zip\r\n",
			errContains: "illegal path separators",
		},
		{
			name:        "absolute path filename with slash",
			manifest:    "da30a272f4343fe82ffa718e898abe6967b8d2c13ff2584d46e4b68706295608  /etc/felix.zip\r\n",
			errContains: "illegal path separators",
		},
		{
			name:        "windows path separator",
			manifest:    "da30a272f4343fe82ffa718e898abe6967b8d2c13ff2584d46e4b68706295608  sub\\felix.zip\r\n",
			errContains: "illegal path separators",
		},
		{
			name: "duplicate entries",
			manifest: "da30a272f4343fe82ffa718e898abe6967b8d2c13ff2584d46e4b68706295608  felix.zip\r\n" +
				"da30a272f4343fe82ffa718e898abe6967b8d2c13ff2584d46e4b68706295608  felix.zip\r\n",
			errContains: "duplicate checksum entry",
		},
		{
			name: "conflicting ambiguous digests for same file",
			manifest: "da30a272f4343fe82ffa718e898abe6967b8d2c13ff2584d46e4b68706295608  felix.zip\r\n" +
				"1111111111111111111111111111111111111111111111111111111111111111  felix.zip\r\n",
			errContains: "conflicting digests",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParseChecksums(strings.NewReader(tt.manifest))
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tt.errContains)
			}
			if !strings.Contains(err.Error(), tt.errContains) {
				t.Errorf("expected error containing %q, got: %v", tt.errContains, err)
			}
		})
	}
}

func TestFileSHA256(t *testing.T) {
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "test.txt")
	content := []byte("felix-security-auditor-sha256-test")
	if err := os.WriteFile(testFile, content, 0644); err != nil {
		t.Fatal(err)
	}

	expectedHashBytes := sha256.Sum256(content)
	expectedHash := hex.EncodeToString(expectedHashBytes[:])

	computed, err := FileSHA256(testFile)
	if err != nil {
		t.Fatalf("FileSHA256 failed: %v", err)
	}

	if computed != expectedHash {
		t.Errorf("hash mismatch: expected %s, got %s", expectedHash, computed)
	}
}
