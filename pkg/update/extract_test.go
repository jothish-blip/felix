package update

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"os"
	"path/filepath"
	"testing"
)

func TestSanitizeExtractPath(t *testing.T) {
	destDir := filepath.Clean(t.TempDir())

	validEntries := []string{
		"felix.exe",
		"felix",
		"README.md",
		"sub/folder/file.txt",
	}

	for _, name := range validEntries {
		clean, err := sanitizeExtractPath(destDir, name)
		if err != nil {
			t.Errorf("expected %q to be valid, got error: %v", name, err)
		}
		expectedPrefix := destDir + string(filepath.Separator)
		if filepath.Dir(clean) != destDir && clean[:len(expectedPrefix)] != expectedPrefix {
			t.Errorf("clean path %q does not start with destDir %q", clean, destDir)
		}
	}

	maliciousEntries := []string{
		"../evil.exe",
		"../../evil.exe",
		"subdir/../../evil.exe",
		"/etc/passwd",
		"C:\\Windows\\System32\\cmd.exe",
		"..\\..\\evil.exe",
	}

	for _, name := range maliciousEntries {
		_, err := sanitizeExtractPath(destDir, name)
		if err == nil {
			t.Errorf("expected path traversal entry %q to be rejected, got nil error", name)
		}
	}
}

func TestExtractZip(t *testing.T) {
	tmpDir := t.TempDir()
	zipPath := filepath.Join(tmpDir, "test.zip")
	destDir := filepath.Join(tmpDir, "extracted")

	// Create test zip
	buf := new(bytes.Buffer)
	zw := zip.NewWriter(buf)

	f, err := zw.Create("felix.exe")
	if err != nil {
		t.Fatal(err)
	}
	f.Write([]byte("mock-felix-binary"))

	f2, err := zw.Create("README.md")
	if err != nil {
		t.Fatal(err)
	}
	f2.Write([]byte("# Felix Readme"))
	zw.Close()

	if err := os.WriteFile(zipPath, buf.Bytes(), 0644); err != nil {
		t.Fatal(err)
	}

	// Extract
	if err := ExtractArchive(zipPath, destDir); err != nil {
		t.Fatalf("ExtractArchive failed: %v", err)
	}

	if _, err := os.Stat(filepath.Join(destDir, "felix.exe")); err != nil {
		t.Errorf("felix.exe was not extracted: %v", err)
	}
	if _, err := os.Stat(filepath.Join(destDir, "README.md")); err != nil {
		t.Errorf("README.md was not extracted: %v", err)
	}
}

func TestExtractTarGz(t *testing.T) {
	tmpDir := t.TempDir()
	tarPath := filepath.Join(tmpDir, "test.tar.gz")
	destDir := filepath.Join(tmpDir, "extracted")

	// Create test tar.gz
	buf := new(bytes.Buffer)
	gw := gzip.NewWriter(buf)
	tw := tar.NewWriter(gw)

	content := []byte("mock-linux-felix")
	hdr := &tar.Header{
		Name: "felix",
		Mode: 0755,
		Size: int64(len(content)),
	}
	if err := tw.WriteHeader(hdr); err != nil {
		t.Fatal(err)
	}
	tw.Write(content)

	tw.Close()
	gw.Close()

	if err := os.WriteFile(tarPath, buf.Bytes(), 0644); err != nil {
		t.Fatal(err)
	}

	if err := ExtractArchive(tarPath, destDir); err != nil {
		t.Fatalf("ExtractArchive failed: %v", err)
	}

	if _, err := os.Stat(filepath.Join(destDir, "felix")); err != nil {
		t.Errorf("felix was not extracted: %v", err)
	}
}
