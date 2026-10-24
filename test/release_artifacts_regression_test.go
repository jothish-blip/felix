package test

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"felix/pkg/update"
)

// roundTripFunc implements http.RoundTripper for synthetic HTTP responses.
type artifactTestRoundTripper func(req *http.Request) (*http.Response, error)

func (f artifactTestRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

// TestReleaseArtifacts_NamingAndPlatformResolution verifies artifact naming across all 5 supported platforms
// and ensures unsupported platforms fail closed.
func TestReleaseArtifacts_NamingAndPlatformResolution(t *testing.T) {
	supported := []struct {
		goos            string
		goarch          string
		expectedArchive string
		expectedBin     string
	}{
		{"windows", "amd64", "felix_2.0.0_windows_amd64.zip", "felix.exe"},
		{"linux", "amd64", "felix_2.0.0_linux_amd64.tar.gz", "felix"},
		{"linux", "arm64", "felix_2.0.0_linux_arm64.tar.gz", "felix"},
		{"darwin", "amd64", "felix_2.0.0_darwin_amd64.tar.gz", "felix"},
		{"darwin", "arm64", "felix_2.0.0_darwin_arm64.tar.gz", "felix"},
	}

	for _, tc := range supported {
		t.Run(fmt.Sprintf("%s_%s", tc.goos, tc.goarch), func(t *testing.T) {
			archive, err := update.ArchiveName("2.0.0", tc.goos, tc.goarch)
			if err != nil {
				t.Fatalf("unexpected error for %s/%s: %v", tc.goos, tc.goarch, err)
			}
			if archive != tc.expectedArchive {
				t.Errorf("archive mismatch: expected %q, got %q", tc.expectedArchive, archive)
			}

			bin := update.ExecutableName(tc.goos)
			if bin != tc.expectedBin {
				t.Errorf("binary mismatch: expected %q, got %q", tc.expectedBin, bin)
			}
		})
	}

	unsupported := []struct {
		goos   string
		goarch string
	}{
		{"solaris", "sparc"},
		{"freebsd", "amd64"},
		{"windows", "386"},
		{"linux", "mips64"},
		{"plan9", "386"},
	}

	for _, tc := range unsupported {
		t.Run(fmt.Sprintf("unsupported_%s_%s", tc.goos, tc.goarch), func(t *testing.T) {
			_, err := update.ArchiveName("2.0.0", tc.goos, tc.goarch)
			if err == nil {
				t.Errorf("expected error for unsupported target %s/%s, got nil", tc.goos, tc.goarch)
			}
		})
	}
}

// TestReleaseArtifacts_ChecksumGenerationAndTampering verifies that SHA-256 manifests
// correctly validate pristine artifacts and detect single-byte corruptions.
func TestReleaseArtifacts_ChecksumGenerationAndTampering(t *testing.T) {
	tempDir := t.TempDir()

	// 1. Create synthetic binary artifact
	artifactPath := filepath.Join(tempDir, "felix_2.0.0_windows_amd64.zip")
	content := []byte("PK\x03\x04-synthetic-felix-release-archive-payload-bytes")
	if err := os.WriteFile(artifactPath, content, 0644); err != nil {
		t.Fatalf("failed to write test artifact: %v", err)
	}

	// 2. Compute digest
	hasher := sha256.New()
	hasher.Write(content)
	validDigest := hex.EncodeToString(hasher.Sum(nil))

	// 3. Test FileSHA256 helper
	computed, err := update.FileSHA256(artifactPath)
	if err != nil {
		t.Fatalf("FileSHA256 failed: %v", err)
	}
	if computed != validDigest {
		t.Fatalf("computed digest mismatch: expected %s, got %s", validDigest, computed)
	}

	// 4. Validate pristine manifest consumption
	manifestContent := fmt.Sprintf("%s  felix_2.0.0_windows_amd64.zip\n", validDigest)
	sums, err := update.ParseChecksums(strings.NewReader(manifestContent))
	if err != nil {
		t.Fatalf("ParseChecksums failed on valid manifest: %v", err)
	}
	if sums["felix_2.0.0_windows_amd64.zip"] != validDigest {
		t.Errorf("manifest hash mismatch: expected %s, got %s", validDigest, sums["felix_2.0.0_windows_amd64.zip"])
	}

	// 5. Tamper test: 1-byte modification of artifact
	tamperedContent := append([]byte{}, content...)
	tamperedContent[len(tamperedContent)-1] ^= 0xFF // Flip bits in last byte
	if err := os.WriteFile(artifactPath, tamperedContent, 0644); err != nil {
		t.Fatalf("failed to write tampered artifact: %v", err)
	}

	tamperedDigest, err := update.FileSHA256(artifactPath)
	if err != nil {
		t.Fatalf("FileSHA256 failed on tampered file: %v", err)
	}
	if tamperedDigest == validDigest {
		t.Fatalf("tampered file generated identical digest (tampering undetected!)")
	}
}

// TestReleaseArtifacts_ManifestParsingSecurityValidations verifies rejection of malformed,
// truncated, duplicate, and path-traversing manifest entries.
func TestReleaseArtifacts_ManifestParsingSecurityValidations(t *testing.T) {
	validHash := "da30a272f4343fe82ffa718e898abe6967b8d2c13ff2584d46e4b68706295608"

	cases := []struct {
		name        string
		manifest    string
		expectError bool
		errFragment string
	}{
		{
			name:        "valid standard manifest",
			manifest:    fmt.Sprintf("# Official Manifest\n%s  felix_2.0.0_linux_amd64.tar.gz\n", validHash),
			expectError: false,
		},
		{
			name:        "valid binary-mode manifest with asterisk",
			manifest:    fmt.Sprintf("%s *felix_2.0.0_windows_amd64.zip\n", validHash),
			expectError: false,
		},
		{
			name:        "truncated line without filename",
			manifest:    fmt.Sprintf("%s\n", validHash),
			expectError: true,
			errFragment: "missing filename",
		},
		{
			name:        "path traversal in manifest filename (dot-dot)",
			manifest:    fmt.Sprintf("%s  ../../escaped_target.tar.gz\n", validHash),
			expectError: true,
			errFragment: "illegal path separators",
		},
		{
			name:        "absolute path in manifest filename",
			manifest:    fmt.Sprintf("%s  /etc/shadow\n", validHash),
			expectError: true,
			errFragment: "illegal path separators",
		},
		{
			name:        "windows backslash path in manifest filename",
			manifest:    fmt.Sprintf("%s  subdir\\binary.exe\n", validHash),
			expectError: true,
			errFragment: "illegal path separators",
		},
		{
			name: "duplicate entries for same artifact",
			manifest: fmt.Sprintf("%s  felix_2.0.0_darwin_arm64.tar.gz\n%s  felix_2.0.0_darwin_arm64.tar.gz\n",
				validHash, validHash),
			expectError: true,
			errFragment: "duplicate checksum entry",
		},
		{
			name: "conflicting ambiguous digests for same artifact",
			manifest: fmt.Sprintf("%s  felix_2.0.0_darwin_arm64.tar.gz\n1111111111111111111111111111111111111111111111111111111111111111  felix_2.0.0_darwin_arm64.tar.gz\n",
				validHash),
			expectError: true,
			errFragment: "conflicting digests",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sums, err := update.ParseChecksums(strings.NewReader(tc.manifest))
			if tc.expectError {
				if err == nil {
					t.Fatalf("expected error containing %q, got nil", tc.errFragment)
				}
				if !strings.Contains(err.Error(), tc.errFragment) {
					t.Errorf("expected error containing %q, got: %v", tc.errFragment, err)
				}
			} else {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				if len(sums) == 0 {
					t.Errorf("expected parsed sums, got 0")
				}
			}
		})
	}
}

// TestReleaseArtifacts_ArchiveSecurityZipSlipAndBombs verifies that archive extraction
// safely blocks directory escapes (ZipSlip) and decompression bombs.
func TestReleaseArtifacts_ArchiveSecurityZipSlipAndBombs(t *testing.T) {
	tempDir := t.TempDir()

	t.Run("ZipSlip_PathTraversal_Zip", func(t *testing.T) {
		zipPath := filepath.Join(tempDir, "malicious_zipslip.zip")
		buf := new(bytes.Buffer)
		zw := zip.NewWriter(buf)

		// Create entry attempting traversal outside extraction root
		header := &zip.FileHeader{
			Name:   "../escaped_malicious_file.txt",
			Method: zip.Deflate,
		}
		w, err := zw.CreateHeader(header)
		if err != nil {
			t.Fatalf("failed to create zip header: %v", err)
		}
		if _, err := w.Write([]byte("malicious-payload")); err != nil {
			t.Fatalf("failed to write zip entry: %v", err)
		}
		zw.Close()

		if err := os.WriteFile(zipPath, buf.Bytes(), 0644); err != nil {
			t.Fatalf("failed to write malicious zip: %v", err)
		}

		extractTarget := filepath.Join(tempDir, "extracted_zip")
		err = update.ExtractArchive(zipPath, extractTarget)
		if err == nil {
			t.Fatalf("expected ZipSlip extraction failure, but extraction succeeded!")
		}
		if !strings.Contains(err.Error(), "security violation") && !strings.Contains(err.Error(), "traversal") {
			t.Errorf("expected security violation error, got: %v", err)
		}

		// Ensure escaped file was not written
		escapedCheck := filepath.Join(tempDir, "escaped_malicious_file.txt")
		if _, err := os.Stat(escapedCheck); err == nil {
			t.Fatalf("SECURITY FAILED: escaped file was written to %s", escapedCheck)
		}
	})

	t.Run("ZipSlip_PathTraversal_TarGz", func(t *testing.T) {
		tarPath := filepath.Join(tempDir, "malicious_zipslip.tar.gz")
		buf := new(bytes.Buffer)
		gw := gzip.NewWriter(buf)
		tw := tar.NewWriter(gw)

		header := &tar.Header{
			Name:     "../../etc/escaped_config.conf",
			Mode:     0644,
			Size:     int64(len("malicious-data")),
			Typeflag: tar.TypeReg,
		}
		if err := tw.WriteHeader(header); err != nil {
			t.Fatalf("failed to write tar header: %v", err)
		}
		if _, err := tw.Write([]byte("malicious-data")); err != nil {
			t.Fatalf("failed to write tar content: %v", err)
		}
		tw.Close()
		gw.Close()

		if err := os.WriteFile(tarPath, buf.Bytes(), 0644); err != nil {
			t.Fatalf("failed to write malicious tar: %v", err)
		}

		extractTarget := filepath.Join(tempDir, "extracted_tar")
		err := update.ExtractArchive(tarPath, extractTarget)
		if err == nil {
			t.Fatalf("expected ZipSlip extraction failure for tar.gz, got nil")
		}
		if !strings.Contains(err.Error(), "security violation") && !strings.Contains(err.Error(), "traversal") {
			t.Errorf("expected security violation error, got: %v", err)
		}
	})

	t.Run("Archive_ExcessiveEntries_Rejected", func(t *testing.T) {
		bombPath := filepath.Join(tempDir, "bomb_entry_count.zip")
		buf := new(bytes.Buffer)
		zw := zip.NewWriter(buf)

		// Create 10001 entries to exceed MaxArchiveEntries (10,000)
		for i := 0; i <= update.MaxArchiveEntries; i++ {
			w, err := zw.Create(fmt.Sprintf("file_%d.txt", i))
			if err != nil {
				t.Fatalf("failed creating zip entry: %v", err)
			}
			w.Write([]byte("a"))
		}
		zw.Close()

		if err := os.WriteFile(bombPath, buf.Bytes(), 0644); err != nil {
			t.Fatalf("failed writing bomb zip: %v", err)
		}

		extractTarget := filepath.Join(tempDir, "extracted_bomb")
		err := update.ExtractArchive(bombPath, extractTarget)
		if err == nil {
			t.Fatalf("expected bomb rejection due to entry count limit, got nil")
		}
		if !strings.Contains(err.Error(), "exceeds limit") {
			t.Errorf("expected exceeds limit error, got: %v", err)
		}
	})
}

// TestReleaseArtifacts_EndToEndUpdateIntegrityFailClosed verifies that the full update pipeline
// enforces SHA-256 verification before extraction, fails closed on mismatch, and preserves prior state.
func TestReleaseArtifacts_EndToEndUpdateIntegrityFailClosed(t *testing.T) {
	tempDir := t.TempDir()

	// 1. Create a dummy existing executable
	binName := update.ExecutableName(runtime.GOOS)
	existingBinPath := filepath.Join(tempDir, binName)
	originalContent := []byte("original-valid-felix-binary-v1.0.0")
	if err := os.WriteFile(existingBinPath, originalContent, 0755); err != nil {
		t.Fatalf("failed to create existing binary: %v", err)
	}

	// 2. Create synthetic user data file to ensure data preservation
	userDataPath := filepath.Join(tempDir, "user_assessment_data.db")
	userSecretContent := []byte("confidential-audit-history-and-findings")
	if err := os.WriteFile(userDataPath, userSecretContent, 0600); err != nil {
		t.Fatalf("failed to write user data file: %v", err)
	}

	targetVer := "2.1.0"
	archiveName, err := update.ArchiveName(targetVer, runtime.GOOS, runtime.GOARCH)
	if err != nil {
		t.Fatalf("failed to resolve archive name: %v", err)
	}

	// 3. Create a synthetic release archive containing an executable
	archiveBuf := new(bytes.Buffer)
	if strings.HasSuffix(archiveName, ".zip") {
		zw := zip.NewWriter(archiveBuf)
		w, _ := zw.Create(binName)
		w.Write([]byte("new-felix-binary-v2.1.0"))
		zw.Close()
	} else {
		gw := gzip.NewWriter(archiveBuf)
		tw := tar.NewWriter(gw)
		hdr := &tar.Header{
			Name:     binName,
			Mode:     0755,
			Size:     int64(len("new-felix-binary-v2.1.0")),
			Typeflag: tar.TypeReg,
		}
		tw.WriteHeader(hdr)
		tw.Write([]byte("new-felix-binary-v2.1.0"))
		tw.Close()
		gw.Close()
	}
	archiveBytes := archiveBuf.Bytes()

	archiveHashBytes := sha256.Sum256(archiveBytes)
	authenticHash := hex.EncodeToString(archiveHashBytes[:])
	wrongHash := "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"

	// 4. Test Case A: Manifest specifies wrong hash (tampered or corrupted artifact)
	t.Run("TamperedArtifact_FailsClosed_PreservesUserFiles", func(t *testing.T) {
		u := update.NewUpdater("jothish-blip/felix", "1.0.0")

		// Mock checker returning target release assets
		relJSON := fmt.Sprintf(`{
			"tag_name": "v%s",
			"name": "Release v%s",
			"assets": [
				{"name": "%s", "size": %d, "browser_download_url": "https://github.com/jothish-blip/felix/releases/download/v%s/%s"},
				{"name": "SHA256SUMS", "size": 128, "browser_download_url": "https://github.com/jothish-blip/felix/releases/download/v%s/SHA256SUMS"}
			]
		}`, targetVer, targetVer, archiveName, len(archiveBytes), targetVer, archiveName, targetVer)

		u.Checker.HTTPClient = &http.Client{
			Transport: artifactTestRoundTripper(func(req *http.Request) (*http.Response, error) {
				return &http.Response{
					StatusCode: http.StatusOK,
					Body:       io.NopCloser(strings.NewReader(relJSON)),
					Header:     make(http.Header),
				}, nil
			}),
		}

		u.Downloader.HTTPClient = &http.Client{
			Transport: artifactTestRoundTripper(func(req *http.Request) (*http.Response, error) {
				if strings.HasSuffix(req.URL.Path, "SHA256SUMS") {
					// Manifest contains wrong hash
					manifest := fmt.Sprintf("%s  %s\n", wrongHash, archiveName)
					return &http.Response{
						StatusCode: http.StatusOK,
						Body:       io.NopCloser(strings.NewReader(manifest)),
						Header:     make(http.Header),
					}, nil
				}
				// Serve pristine archive bytes
				return &http.Response{
					StatusCode: http.StatusOK,
					Body:       io.NopCloser(bytes.NewReader(archiveBytes)),
					Header:     make(http.Header),
				}, nil
			}),
		}

		res, err := u.Update(context.Background(), update.UpdateOptions{
			TargetVersion: targetVer,
			DryRun:        true,
		})
		if err == nil {
			t.Fatalf("expected update to fail on SHA-256 mismatch, but got success: %+v", res)
		}
		if !strings.Contains(err.Error(), "SHA256 mismatch") {
			t.Errorf("expected SHA256 mismatch error, got: %v", err)
		}

		// Ensure user files are strictly preserved
		currBin, err := os.ReadFile(existingBinPath)
		if err != nil || !bytes.Equal(currBin, originalContent) {
			t.Fatalf("original binary was corrupted or deleted during failed update")
		}
		currUserData, err := os.ReadFile(userDataPath)
		if err != nil || !bytes.Equal(currUserData, userSecretContent) {
			t.Fatalf("user assessment data was modified or deleted during failed update")
		}
	})

	// 5. Test Case B: Pristine manifest matching authentic digest succeeds
	t.Run("AuthenticArtifact_ChecksumVerified_Success", func(t *testing.T) {
		u := update.NewUpdater("jothish-blip/felix", "1.0.0")

		relJSON := fmt.Sprintf(`{
			"tag_name": "v%s",
			"name": "Release v%s",
			"assets": [
				{"name": "%s", "size": %d, "browser_download_url": "https://github.com/jothish-blip/felix/releases/download/v%s/%s"},
				{"name": "SHA256SUMS", "size": 128, "browser_download_url": "https://github.com/jothish-blip/felix/releases/download/v%s/SHA256SUMS"}
			]
		}`, targetVer, targetVer, archiveName, len(archiveBytes), targetVer, archiveName, targetVer)

		u.Checker.HTTPClient = &http.Client{
			Transport: artifactTestRoundTripper(func(req *http.Request) (*http.Response, error) {
				return &http.Response{
					StatusCode: http.StatusOK,
					Body:       io.NopCloser(strings.NewReader(relJSON)),
					Header:     make(http.Header),
				}, nil
			}),
		}

		u.Downloader.HTTPClient = &http.Client{
			Transport: artifactTestRoundTripper(func(req *http.Request) (*http.Response, error) {
				if strings.HasSuffix(req.URL.Path, "SHA256SUMS") {
					// Manifest with valid authentic hash
					manifest := fmt.Sprintf("%s  %s\n", authenticHash, archiveName)
					return &http.Response{
						StatusCode: http.StatusOK,
						Body:       io.NopCloser(strings.NewReader(manifest)),
						Header:     make(http.Header),
					}, nil
				}
				return &http.Response{
					StatusCode: http.StatusOK,
					Body:       io.NopCloser(bytes.NewReader(archiveBytes)),
					Header:     make(http.Header),
				}, nil
			}),
		}

		res, err := u.Update(context.Background(), update.UpdateOptions{
			TargetVersion: targetVer,
			DryRun:        true,
		})
		if err != nil {
			t.Fatalf("expected update to succeed with matching checksum, got error: %v", err)
		}
		if res.UpdatedVersion != targetVer {
			t.Errorf("expected updated version %s, got %s", targetVer, res.UpdatedVersion)
		}
		if res.ArchiveFile != archiveName {
			t.Errorf("expected archive %s, got %s", archiveName, res.ArchiveFile)
		}
	})
}

// TestReleaseArtifacts_ZeroPrivateKeyLeakage verifies that release archives and packaging staging
// are strictly scanned to ensure zero private keys or credential blocks are ever packaged.
func TestReleaseArtifacts_ZeroPrivateKeyLeakage(t *testing.T) {
	repoRoot, err := filepath.Abs("..")
	if err != nil {
		t.Fatalf("failed finding repo root: %v", err)
	}

	distDir := filepath.Join(repoRoot, "dist")
	if fi, err := os.Stat(distDir); err != nil || !fi.IsDir() {
		t.Skip("dist directory not present; skipping artifact scan")
	}

	disallowedPatterns := []string{
		".priv",
		".key",
		".pem",
		".pfx",
		".asc",
		"id_rsa",
		"id_ed25519",
	}

	disallowedHeaders := [][]byte{
		[]byte("-----BEGIN PGP PRIVATE KEY BLOCK-----"),
		[]byte("-----BEGIN RSA PRIVATE KEY-----"),
		[]byte("-----BEGIN PRIVATE KEY-----"),
		[]byte("-----BEGIN EC PRIVATE KEY-----"),
		[]byte("-----BEGIN OPENSSH PRIVATE KEY-----"),
	}

	entries, err := os.ReadDir(distDir)
	if err != nil {
		t.Fatalf("failed reading dist: %v", err)
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		path := filepath.Join(distDir, entry.Name())
		lower := strings.ToLower(entry.Name())

		if strings.HasSuffix(lower, ".zip") {
			zr, err := zip.OpenReader(path)
			if err != nil {
				continue
			}
			for _, f := range zr.File {
				entryLower := strings.ToLower(f.Name)
				for _, pat := range disallowedPatterns {
					if strings.Contains(entryLower, pat) {
						t.Errorf("SECURITY LEAK: private key or certificate pattern %q found in %s/%s", pat, entry.Name(), f.Name)
					}
				}
				rc, err := f.Open()
				if err == nil {
					data, _ := io.ReadAll(io.LimitReader(rc, 1024*1024))
					rc.Close()
					for _, header := range disallowedHeaders {
						if bytes.Contains(data, header) {
							t.Errorf("SECURITY LEAK: private key block detected in %s/%s", entry.Name(), f.Name)
						}
					}
				}
			}
			zr.Close()
		} else if strings.HasSuffix(lower, ".tar.gz") {
			f, err := os.Open(path)
			if err != nil {
				continue
			}
			gzr, err := gzip.NewReader(f)
			if err == nil {
				tr := tar.NewReader(gzr)
				for {
					hdr, err := tr.Next()
					if err != nil {
						break
					}
					entryLower := strings.ToLower(hdr.Name)
					for _, pat := range disallowedPatterns {
						if strings.Contains(entryLower, pat) {
							t.Errorf("SECURITY LEAK: private key pattern %q found in %s/%s", pat, entry.Name(), hdr.Name)
						}
					}
					if hdr.Typeflag == tar.TypeReg {
						data, _ := io.ReadAll(io.LimitReader(tr, 1024*1024))
						for _, header := range disallowedHeaders {
							if bytes.Contains(data, header) {
								t.Errorf("SECURITY LEAK: private key block detected in %s/%s", entry.Name(), hdr.Name)
							}
						}
					}
				}
				gzr.Close()
			}
			f.Close()
		}
	}
}
