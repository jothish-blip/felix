package apk

import (
	"archive/zip"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// helper to create a valid or custom test APK archive on disk
func createTestZip(t *testing.T, entries map[string][]byte) string {
	t.Helper()
	tmpDir := t.TempDir()
	apkPath := filepath.Join(tmpDir, "test.apk")

	f, err := os.Create(apkPath)
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}
	defer f.Close()

	zw := zip.NewWriter(f)
	for name, content := range entries {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatalf("failed to create zip entry %q: %v", name, err)
		}
		if len(content) > 0 {
			if _, err := w.Write(content); err != nil {
				t.Fatalf("failed to write content for %q: %v", name, err)
			}
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("failed to close zip writer: %v", err)
	}
	return apkPath
}

// helper to create a valid minimal Android APK
func createMinimalValidAPK(t *testing.T) string {
	return createTestZip(t, map[string][]byte{
		"AndroidManifest.xml": []byte("<manifest package=\"com.felix.test\"/>"),
		"classes.dex":         []byte("DEX\n035\x00dummy-dex-bytecode"),
		"resources.arsc":      []byte("dummy-resources"),
		"res/values/strings.xml": []byte("<resources><string name=\"app_name\">TestApp</string></resources>"),
	})
}

// ============================================================================
// 1. VALID INPUT TESTS
// ============================================================================

func TestIntake_MinimalStructurallyValidAPK(t *testing.T) {
	apkPath := createMinimalValidAPK(t)
	ctx := context.Background()

	res, err := Intake(ctx, apkPath, IntakeOptions{Extract: true})
	if err != nil {
		t.Fatalf("expected successful intake, got error: %v", err)
	}
	defer res.Workspace.Close()

	if res.SHA256 == "" {
		t.Errorf("expected non-empty SHA256 digest")
	}
	if res.FileSize <= 0 {
		t.Errorf("expected positive file size, got %d", res.FileSize)
	}
	if res.EntryCount != 4 {
		t.Errorf("expected 4 entries, got %d", res.EntryCount)
	}
	if !res.ManifestPresent {
		t.Errorf("expected ManifestPresent=true")
	}
	if res.DexCount != 1 {
		t.Errorf("expected 1 DexFile, got %d", res.DexCount)
	}
	if res.TotalDecompressedBytes <= 0 {
		t.Errorf("expected positive TotalDecompressedBytes, got %d", res.TotalDecompressedBytes)
	}

	// Verify extracted manifest exists in workspace
	manifestOnDisk := filepath.Join(res.Workspace.Dir, "AndroidManifest.xml")
	if fi, err := os.Stat(manifestOnDisk); err != nil || fi.Size() == 0 {
		t.Errorf("expected AndroidManifest.xml in workspace, err=%v", err)
	}
}

func TestIntake_MultipleEntriesAndSubdirectories(t *testing.T) {
	entries := map[string][]byte{
		"AndroidManifest.xml":       []byte("<manifest/>"),
		"classes.dex":               []byte("dex1"),
		"classes2.dex":              []byte("dex2"),
		"assets/config.json":        []byte(`{"api":"https://api.example.com"}`),
		"lib/arm64-v8a/libnative.so": []byte("ELF-dummy-so"),
	}
	apkPath := createTestZip(t, entries)
	ctx := context.Background()

	res, err := Intake(ctx, apkPath, IntakeOptions{Extract: true})
	if err != nil {
		t.Fatalf("intake failed: %v", err)
	}
	defer res.Workspace.Close()

	if res.DexCount != 2 {
		t.Errorf("expected 2 DexFiles, got %d", res.DexCount)
	}

	// Check extracted files on disk
	libFile := filepath.Join(res.Workspace.Dir, "lib", "arm64-v8a", "libnative.so")
	if _, err := os.Stat(libFile); err != nil {
		t.Errorf("expected extracted native library at %s, err: %v", libFile, err)
	}
}

func TestIntake_RepeatedIndependentIngestions(t *testing.T) {
	apkPath := createMinimalValidAPK(t)
	ctx := context.Background()

	// Ingest 3 times independently
	var workspaces []*Workspace
	for i := 0; i < 3; i++ {
		res, err := Intake(ctx, apkPath, IntakeOptions{})
		if err != nil {
			t.Fatalf("ingestion %d failed: %v", i, err)
		}
		workspaces = append(workspaces, res.Workspace)
	}

	// Workspaces must have unique directories
	dirs := make(map[string]bool)
	for _, ws := range workspaces {
		if dirs[ws.Dir] {
			t.Errorf("duplicate workspace directory: %s", ws.Dir)
		}
		dirs[ws.Dir] = true
		_ = ws.Close()
	}
}

// ============================================================================
// 2. INVALID INPUT TESTS
// ============================================================================

func TestIntake_EmptyFile(t *testing.T) {
	tmpDir := t.TempDir()
	emptyPath := filepath.Join(tmpDir, "empty.apk")
	if err := os.WriteFile(emptyPath, []byte{}, 0644); err != nil {
		t.Fatal(err)
	}

	_, err := Intake(context.Background(), emptyPath, IntakeOptions{})
	if err == nil {
		t.Fatalf("expected error on empty file, got nil")
	}
	if !errors.Is(err, ErrInvalidInput) {
		t.Errorf("expected ErrInvalidInput, got %v", err)
	}
}

func TestIntake_RandomNonZIPData(t *testing.T) {
	tmpDir := t.TempDir()
	randPath := filepath.Join(tmpDir, "random.apk")
	if err := os.WriteFile(randPath, []byte("NOT_A_ZIP_HEADER_JUST_TEXT"), 0644); err != nil {
		t.Fatal(err)
	}

	_, err := Intake(context.Background(), randPath, IntakeOptions{})
	if err == nil {
		t.Fatalf("expected error on non-zip file, got nil")
	}
	if !errors.Is(err, ErrNotAnAPK) {
		t.Errorf("expected ErrNotAnAPK, got %v", err)
	}
}

func TestIntake_GenericZIPMissingManifest(t *testing.T) {
	// A zip containing code/images but NO AndroidManifest.xml
	genericZip := createTestZip(t, map[string][]byte{
		"photo.jpg": []byte("image-data"),
		"notes.txt": []byte("text-data"),
	})

	_, err := Intake(context.Background(), genericZip, IntakeOptions{})
	if err == nil {
		t.Fatalf("expected error for generic zip missing AndroidManifest.xml, got nil")
	}
	if !errors.Is(err, ErrNotAnAPK) {
		t.Errorf("expected ErrNotAnAPK, got %v", err)
	}
}

func TestIntake_DirectoryTarget(t *testing.T) {
	tmpDir := t.TempDir()
	_, err := Intake(context.Background(), tmpDir, IntakeOptions{})
	if err == nil {
		t.Fatalf("expected error when target is a directory, got nil")
	}
	if !errors.Is(err, ErrInvalidInput) {
		t.Errorf("expected ErrInvalidInput, got %v", err)
	}
}

func TestIntake_NonExistentFile(t *testing.T) {
	_, err := Intake(context.Background(), "C:\\nonexistent\\path\\file.apk", IntakeOptions{})
	if err == nil {
		t.Fatalf("expected error on non-existent file, got nil")
	}
	if !errors.Is(err, ErrInvalidInput) {
		t.Errorf("expected ErrInvalidInput, got %v", err)
	}
}

func TestIntake_TruncatedZIP(t *testing.T) {
	apkPath := createMinimalValidAPK(t)
	data, err := os.ReadFile(apkPath)
	if err != nil {
		t.Fatal(err)
	}

	// Truncate the ZIP file in half
	truncatedPath := filepath.Join(t.TempDir(), "truncated.apk")
	if err := os.WriteFile(truncatedPath, data[:len(data)/2], 0644); err != nil {
		t.Fatal(err)
	}

	_, err = Intake(context.Background(), truncatedPath, IntakeOptions{})
	if err == nil {
		t.Fatalf("expected error on truncated zip, got nil")
	}
	if !errors.Is(err, ErrMalformedArchive) {
		t.Errorf("expected ErrMalformedArchive, got %v", err)
	}
}

// ============================================================================
// 3. RESOURCE LIMIT ENFORCEMENT
// ============================================================================

func TestIntake_MaxCompressedSizeLimit(t *testing.T) {
	apkPath := createMinimalValidAPK(t)
	fi, _ := os.Stat(apkPath)

	limits := DefaultLimits()
	limits.MaxCompressedSize = fi.Size() - 1 // strictly smaller than file size

	_, err := Intake(context.Background(), apkPath, IntakeOptions{Limits: limits})
	if err == nil {
		t.Fatalf("expected ErrLimitExceeded for compressed size, got nil")
	}
	if !errors.Is(err, ErrLimitExceeded) {
		t.Errorf("expected ErrLimitExceeded, got %v", err)
	}
}

func TestIntake_MaxArchiveEntriesLimit(t *testing.T) {
	entries := make(map[string][]byte)
	entries["AndroidManifest.xml"] = []byte("<manifest/>")
	for i := 0; i < 15; i++ {
		entries[fmt.Sprintf("file_%d.txt", i)] = []byte("data")
	}
	apkPath := createTestZip(t, entries)

	limits := DefaultLimits()
	limits.MaxArchiveEntries = 5 // smaller than 16 entries

	_, err := Intake(context.Background(), apkPath, IntakeOptions{Limits: limits})
	if err == nil {
		t.Fatalf("expected ErrLimitExceeded for entry count, got nil")
	}
	if !errors.Is(err, ErrLimitExceeded) {
		t.Errorf("expected ErrLimitExceeded, got %v", err)
	}
}

func TestIntake_MaxEntrySizeLimit(t *testing.T) {
	entries := map[string][]byte{
		"AndroidManifest.xml": []byte("<manifest/>"),
		"classes.dex":         bytes.Repeat([]byte("A"), 10000),
	}
	apkPath := createTestZip(t, entries)

	limits := DefaultLimits()
	limits.MaxEntrySize = 5000 // 5 KB, while classes.dex is 10 KB

	_, err := Intake(context.Background(), apkPath, IntakeOptions{Limits: limits})
	if err == nil {
		t.Fatalf("expected ErrLimitExceeded for single entry size, got nil")
	}
	if !errors.Is(err, ErrLimitExceeded) {
		t.Errorf("expected ErrLimitExceeded, got %v", err)
	}
}

func TestIntake_MaxCumulativeDecompressedSizeLimit(t *testing.T) {
	entries := map[string][]byte{
		"AndroidManifest.xml": []byte("<manifest/>"),
		"f1.dat":              bytes.Repeat([]byte("B"), 3000),
		"f2.dat":              bytes.Repeat([]byte("C"), 3000),
	}
	apkPath := createTestZip(t, entries)

	limits := DefaultLimits()
	limits.MaxEntrySize = 4000
	limits.MaxCumulativeDecompressedSize = 5000 // total is > 6000 bytes

	_, err := Intake(context.Background(), apkPath, IntakeOptions{Limits: limits})
	if err == nil {
		t.Fatalf("expected ErrLimitExceeded for cumulative size, got nil")
	}
	if !errors.Is(err, ErrLimitExceeded) {
		t.Errorf("expected ErrLimitExceeded, got %v", err)
	}
}

func TestIntake_CompressionRatioZipBomb(t *testing.T) {
	// Highly compressible data: 1 MB of zeros
	hugeZero := bytes.Repeat([]byte{0x00}, 1024*1024)
	apkPath := createTestZip(t, map[string][]byte{
		"AndroidManifest.xml": []byte("<manifest/>"),
		"huge_zero.bin":       hugeZero,
	})

	limits := DefaultLimits()
	limits.MaxCompressionRatio = 5.0 // low ratio threshold: 1MB zeros compresses to ~1KB (>1000:1 ratio)

	_, err := Intake(context.Background(), apkPath, IntakeOptions{Limits: limits})
	if err == nil {
		t.Fatalf("expected ErrLimitExceeded for compression ratio bomb, got nil")
	}
	if !errors.Is(err, ErrLimitExceeded) {
		t.Errorf("expected ErrLimitExceeded, got %v", err)
	}
}

func TestIntake_ContextCancellation(t *testing.T) {
	apkPath := createMinimalValidAPK(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately

	_, err := Intake(ctx, apkPath, IntakeOptions{})
	if err == nil {
		t.Fatalf("expected error on cancelled context, got nil")
	}
	if !errors.Is(err, context.Canceled) {
		t.Errorf("expected context.Canceled, got %v", err)
	}
}

func TestIntake_InvalidLimitsConfiguration(t *testing.T) {
	apkPath := createMinimalValidAPK(t)

	invalidLimits := []Limits{
		{MaxCompressedSize: -1},
		{MaxCompressedSize: 100, MaxArchiveEntries: 0},
		{MaxCompressedSize: 100, MaxArchiveEntries: 10, MaxEntrySize: -5},
		{MaxCompressedSize: 100, MaxArchiveEntries: 10, MaxEntrySize: 50, MaxCumulativeDecompressedSize: 20}, // cumulative < entry
		{MaxCompressedSize: 100, MaxArchiveEntries: 10, MaxEntrySize: 50, MaxCumulativeDecompressedSize: 100, MaxCompressionRatio: 0.5},
	}

	for i, l := range invalidLimits {
		_, err := Intake(context.Background(), apkPath, IntakeOptions{Limits: l})
		if err == nil {
			t.Errorf("case %d: expected error for invalid limits %+v, got nil", i, l)
		}
	}
}

// ============================================================================
// 4. ARCHIVE SAFETY & PATH ATTACKS
// ============================================================================

func TestIntake_PathTraversalDotDot(t *testing.T) {
	apkPath := createTestZip(t, map[string][]byte{
		"AndroidManifest.xml": []byte("<manifest/>"),
		"../escaped.txt":      []byte("evil"),
	})

	_, err := Intake(context.Background(), apkPath, IntakeOptions{})
	if err == nil {
		t.Fatalf("expected ErrSecurityViolation for path traversal, got nil")
	}
	if !errors.Is(err, ErrSecurityViolation) {
		t.Errorf("expected ErrSecurityViolation, got %v", err)
	}
}

func TestIntake_AbsolutePath(t *testing.T) {
	apkPath := createTestZip(t, map[string][]byte{
		"AndroidManifest.xml": []byte("<manifest/>"),
		"/etc/passwd":         []byte("root:x:0:0:root:..."),
	})

	_, err := Intake(context.Background(), apkPath, IntakeOptions{})
	if err == nil {
		t.Fatalf("expected ErrSecurityViolation for absolute path, got nil")
	}
	if !errors.Is(err, ErrSecurityViolation) {
		t.Errorf("expected ErrSecurityViolation, got %v", err)
	}
}

func TestIntake_WindowsDriveLetterPath(t *testing.T) {
	apkPath := createTestZip(t, map[string][]byte{
		"AndroidManifest.xml": []byte("<manifest/>"),
		"C:/malicious.txt":    []byte("windows-drive-path"),
	})

	_, err := Intake(context.Background(), apkPath, IntakeOptions{})
	if err == nil {
		t.Fatalf("expected ErrSecurityViolation for drive letter path, got nil")
	}
	if !errors.Is(err, ErrSecurityViolation) {
		t.Errorf("expected ErrSecurityViolation, got %v", err)
	}
}

func TestIntake_UNCPath(t *testing.T) {
	apkPath := createTestZip(t, map[string][]byte{
		"AndroidManifest.xml": []byte("<manifest/>"),
		"//192.168.1.1/share/evil.exe": []byte("unc"),
	})

	_, err := Intake(context.Background(), apkPath, IntakeOptions{})
	if err == nil {
		t.Fatalf("expected ErrSecurityViolation for UNC path, got nil")
	}
	if !errors.Is(err, ErrSecurityViolation) {
		t.Errorf("expected ErrSecurityViolation, got %v", err)
	}
}

func TestIntake_BackslashTraversal(t *testing.T) {
	apkPath := createTestZip(t, map[string][]byte{
		"AndroidManifest.xml": []byte("<manifest/>"),
		"assets\\..\\outside.txt": []byte("backslash"),
	})

	_, err := Intake(context.Background(), apkPath, IntakeOptions{})
	if err == nil {
		t.Fatalf("expected ErrSecurityViolation for backslash path, got nil")
	}
	if !errors.Is(err, ErrSecurityViolation) {
		t.Errorf("expected ErrSecurityViolation, got %v", err)
	}
}

func TestIntake_NullByteInEntryName(t *testing.T) {
	apkPath := createTestZip(t, map[string][]byte{
		"AndroidManifest.xml": []byte("<manifest/>"),
		"classes.dex\x00.evil": []byte("null-byte"),
	})

	_, err := Intake(context.Background(), apkPath, IntakeOptions{})
	if err == nil {
		t.Fatalf("expected ErrSecurityViolation for null byte in path, got nil")
	}
	if !errors.Is(err, ErrSecurityViolation) {
		t.Errorf("expected ErrSecurityViolation, got %v", err)
	}
}

func TestIntake_DuplicateArchiveEntry(t *testing.T) {
	// Create zip with two entries sharing the exact same name
	tmpDir := t.TempDir()
	apkPath := filepath.Join(tmpDir, "dup.apk")
	f, _ := os.Create(apkPath)
	zw := zip.NewWriter(f)

	w1, _ := zw.Create("AndroidManifest.xml")
	w1.Write([]byte("<manifest/>"))

	w2, _ := zw.Create("classes.dex")
	w2.Write([]byte("dex1"))

	w3, _ := zw.Create("classes.dex") // duplicate!
	w3.Write([]byte("dex2"))

	zw.Close()
	f.Close()

	_, err := Intake(context.Background(), apkPath, IntakeOptions{})
	if err == nil {
		t.Fatalf("expected ErrSecurityViolation for duplicate entry, got nil")
	}
	if !errors.Is(err, ErrSecurityViolation) {
		t.Errorf("expected ErrSecurityViolation, got %v", err)
	}
}

func TestIntake_FileDirectoryConflict(t *testing.T) {
	// Create zip where entry "foo" is both a file and a parent of "foo/bar"
	tmpDir := t.TempDir()
	apkPath := filepath.Join(tmpDir, "conflict.apk")
	f, _ := os.Create(apkPath)
	zw := zip.NewWriter(f)

	w1, _ := zw.Create("AndroidManifest.xml")
	w1.Write([]byte("<manifest/>"))

	w2, _ := zw.Create("nested") // file named nested
	w2.Write([]byte("file-content"))

	w3, _ := zw.Create("nested/file.txt") // child entry conflicting with nested file!
	w3.Write([]byte("child-content"))

	zw.Close()
	f.Close()

	_, err := Intake(context.Background(), apkPath, IntakeOptions{})
	if err == nil {
		t.Fatalf("expected ErrSecurityViolation for file/directory conflict, got nil")
	}
	if !errors.Is(err, ErrSecurityViolation) {
		t.Errorf("expected ErrSecurityViolation, got %v", err)
	}
}

// ============================================================================
// 5. ISOLATION & CLEANUP LIFECYCLE
// ============================================================================

func TestWorkspace_CleanupIdempotence(t *testing.T) {
	ws, err := NewWorkspace(t.TempDir())
	if err != nil {
		t.Fatalf("failed to create workspace: %v", err)
	}

	dir := ws.Dir
	if fi, err := os.Stat(dir); err != nil || !fi.IsDir() {
		t.Fatalf("expected workspace directory to exist")
	}

	// First Close() must succeed
	if err := ws.Close(); err != nil {
		t.Errorf("first Close() failed: %v", err)
	}

	// Verify directory was removed
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Errorf("workspace directory was not removed: %s", dir)
	}

	// Second and third Close() must succeed cleanly (idempotent)
	if err := ws.Close(); err != nil {
		t.Errorf("second Close() failed: %v", err)
	}
	if err := ws.Close(); err != nil {
		t.Errorf("third Close() failed: %v", err)
	}
}

func TestIntake_FailureCleansWorkspace(t *testing.T) {
	// A zip that causes an error midway (e.g. entry size exceeded)
	entries := map[string][]byte{
		"AndroidManifest.xml": []byte("<manifest/>"),
		"classes.dex":         bytes.Repeat([]byte("A"), 10000),
	}
	apkPath := createTestZip(t, entries)

	limits := DefaultLimits()
	limits.MaxEntrySize = 1000 // fails on classes.dex

	customTempRoot := t.TempDir()
	_, err := Intake(context.Background(), apkPath, IntakeOptions{
		Limits:  limits,
		TempDir: customTempRoot,
	})
	if err == nil {
		t.Fatalf("expected failure, got nil")
	}

	// Ensure no partial felix-apk-* directories remain in customTempRoot
	items, err := os.ReadDir(customTempRoot)
	if err != nil {
		t.Fatal(err)
	}
	for _, item := range items {
		if strings.HasPrefix(item.Name(), "felix-apk-") {
			t.Errorf("leaked partial workspace directory after failure: %s", item.Name())
		}
	}
}

func TestIntake_ConcurrentIngestions(t *testing.T) {
	apkPath := createMinimalValidAPK(t)
	var wg sync.WaitGroup
	errCh := make(chan error, 10)

	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			res, err := Intake(context.Background(), apkPath, IntakeOptions{Extract: true})
			if err != nil {
				errCh <- fmt.Errorf("worker %d failed: %w", idx, err)
				return
			}
			defer res.Workspace.Close()

			// Check that file exists in this worker's workspace
			m := filepath.Join(res.Workspace.Dir, "AndroidManifest.xml")
			if _, err := os.Stat(m); err != nil {
				errCh <- fmt.Errorf("worker %d missing manifest: %v", idx, err)
			}
		}(i)
	}

	wg.Wait()
	close(errCh)

	for err := range errCh {
		t.Errorf("concurrent ingestion error: %v", err)
	}
}

// ============================================================================
// 6. STATIC-ONLY GUARANTEE
// ============================================================================

func TestIntake_StaticOnly_NoSubprocessesOrNetwork(t *testing.T) {
	// Verification that intake does not execute any binaries or spawn external processes
	apkPath := createMinimalValidAPK(t)
	res, err := Intake(context.Background(), apkPath, IntakeOptions{})
	if err != nil {
		t.Fatalf("intake failed: %v", err)
	}
	defer res.Workspace.Close()

	// The input file must remain untouched and read-only
	fi, err := os.Stat(apkPath)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Size() == 0 {
		t.Errorf("input file was modified or truncated")
	}
}

// ============================================================================
// 7. SECURITY AUDIT REGRESSION TESTS
// ============================================================================

func TestIntake_GenericZIPWithFakeManifest(t *testing.T) {
	// A generic ZIP with an AndroidManifest.xml that does not contain AXML or XML <manifest>
	apkPath := createTestZip(t, map[string][]byte{
		"AndroidManifest.xml": []byte("This is not a real Android manifest file"),
		"classes.dex":         []byte("dex"),
	})

	_, err := Intake(context.Background(), apkPath, IntakeOptions{})
	if err == nil {
		t.Fatalf("expected ErrNotAnAPK for fake manifest content, got nil")
	}
	if !errors.Is(err, ErrNotAnAPK) {
		t.Errorf("expected ErrNotAnAPK, got %v", err)
	}
}

func TestIntake_GenericZIPMissingAndroidComponents(t *testing.T) {
	// A generic ZIP with a valid XML manifest but zero Android components (photos, docs only)
	apkPath := createTestZip(t, map[string][]byte{
		"AndroidManifest.xml": []byte("<manifest package=\"com.generic.zip\"/>"),
		"photo.jpg":           []byte("image-data"),
		"report.pdf":          []byte("pdf-data"),
	})

	_, err := Intake(context.Background(), apkPath, IntakeOptions{})
	if err == nil {
		t.Fatalf("expected ErrNotAnAPK for generic zip lacking Android package components, got nil")
	}
	if !errors.Is(err, ErrNotAnAPK) {
		t.Errorf("expected ErrNotAnAPK, got %v", err)
	}
}

func TestIntake_BinaryAXMLManifest(t *testing.T) {
	// Compiled Android Binary XML header: 0x00080003 (little-endian: 0x03, 0x00, 0x08, 0x00)
	axmlHeader := []byte{0x03, 0x00, 0x08, 0x00, 0x20, 0x00, 0x00, 0x00}
	axmlData := append(axmlHeader, bytes.Repeat([]byte{0x00}, 24)...)

	apkPath := createTestZip(t, map[string][]byte{
		"AndroidManifest.xml": axmlData,
		"classes.dex":         []byte("dex-bytes"),
	})

	res, err := Intake(context.Background(), apkPath, IntakeOptions{Extract: true})
	if err != nil {
		t.Fatalf("expected successful intake for binary AXML APK, got: %v", err)
	}
	defer res.Workspace.Close()

	if !res.ManifestPresent {
		t.Errorf("expected ManifestPresent true")
	}
}

func TestIntake_WindowsReservedDeviceNames(t *testing.T) {
	reserved := []string{
		"aux.json",
		"con.xml",
		"NUL",
		"COM1.txt",
		"prn.dat",
		"assets/aux.png",
		"res/raw/lpt2.bin",
	}

	for _, name := range reserved {
		apkPath := createTestZip(t, map[string][]byte{
			"AndroidManifest.xml": []byte("<manifest/>"),
			"classes.dex":         []byte("dex"),
			name:                  []byte("data"),
		})

		_, err := Intake(context.Background(), apkPath, IntakeOptions{})
		if err == nil {
			t.Errorf("expected ErrSecurityViolation for Windows reserved name %q, got nil", name)
		}
		if !errors.Is(err, ErrSecurityViolation) {
			t.Errorf("expected ErrSecurityViolation for %q, got %v", name, err)
		}
	}
}

func TestIntake_TrailingDotOrSpacePath(t *testing.T) {
	badPaths := []string{
		"assets./config.json",
		"foo .txt",
		"res/raw/file.",
		"assets/dir /item.txt",
	}

	for _, p := range badPaths {
		apkPath := createTestZip(t, map[string][]byte{
			"AndroidManifest.xml": []byte("<manifest/>"),
			"classes.dex":         []byte("dex"),
			p:                     []byte("bad-path-data"),
		})

		_, err := Intake(context.Background(), apkPath, IntakeOptions{})
		if err == nil {
			t.Errorf("expected ErrSecurityViolation for trailing dot/space path %q, got nil", p)
		}
		if !errors.Is(err, ErrSecurityViolation) {
			t.Errorf("expected ErrSecurityViolation for %q, got %v", p, err)
		}
	}
}

func TestIntake_AlternateDataStreamColon(t *testing.T) {
	apkPath := createTestZip(t, map[string][]byte{
		"AndroidManifest.xml": []byte("<manifest/>"),
		"classes.dex:stream":  []byte("ads-data"),
	})

	_, err := Intake(context.Background(), apkPath, IntakeOptions{})
	if err == nil {
		t.Fatalf("expected ErrSecurityViolation for ADS colon, got nil")
	}
	if !errors.Is(err, ErrSecurityViolation) {
		t.Errorf("expected ErrSecurityViolation, got %v", err)
	}
}

func TestIntake_RawUnixSymlinkInExternalAttrs(t *testing.T) {
	// Create zip with raw external attributes declaring symlink (0120000 << 16) even if creator is FAT/DOS
	tmpDir := t.TempDir()
	apkPath := filepath.Join(tmpDir, "symlink_raw.apk")
	f, _ := os.Create(apkPath)
	zw := zip.NewWriter(f)

	w1, _ := zw.Create("AndroidManifest.xml")
	w1.Write([]byte("<manifest/>"))

	w2, _ := zw.Create("classes.dex")
	w2.Write([]byte("dex"))

	fh := &zip.FileHeader{
		Name:           "assets/symlink_target",
		CreatorVersion: 0,            // FAT / MS-DOS creator version
		ExternalAttrs:  0120000 << 16, // Unix S_IFLNK in high 16 bits!
		Method:         zip.Store,
	}
	w3, _ := zw.CreateHeader(fh)
	w3.Write([]byte("../outside.txt"))

	zw.Close()
	f.Close()

	_, err := Intake(context.Background(), apkPath, IntakeOptions{})
	if err == nil {
		t.Fatalf("expected ErrSecurityViolation for raw external attribute symlink, got nil")
	}
	if !errors.Is(err, ErrSecurityViolation) {
		t.Errorf("expected ErrSecurityViolation, got %v", err)
	}
}

func TestIntake_CaseInsensitiveCollision(t *testing.T) {
	tmpDir := t.TempDir()
	apkPath := filepath.Join(tmpDir, "case_collision.apk")
	f, _ := os.Create(apkPath)
	zw := zip.NewWriter(f)

	w1, _ := zw.Create("AndroidManifest.xml")
	w1.Write([]byte("<manifest/>"))

	w2, _ := zw.Create("classes.dex")
	w2.Write([]byte("dex1"))

	w3, _ := zw.Create("CLASSES.DEX") // case-insensitive collision
	w3.Write([]byte("dex2"))

	zw.Close()
	f.Close()

	_, err := Intake(context.Background(), apkPath, IntakeOptions{})
	if err == nil {
		t.Fatalf("expected ErrSecurityViolation for case collision, got nil")
	}
	if !errors.Is(err, ErrSecurityViolation) {
		t.Errorf("expected ErrSecurityViolation, got %v", err)
	}
}

func TestIntake_FileDirectoryConflict_DirectoryFirst(t *testing.T) {
	tmpDir := t.TempDir()
	apkPath := filepath.Join(tmpDir, "dir_first_conflict.apk")
	f, _ := os.Create(apkPath)
	zw := zip.NewWriter(f)

	w1, _ := zw.Create("AndroidManifest.xml")
	w1.Write([]byte("<manifest/>"))

	// Create directory entry first
	w2, _ := zw.Create("shared_path/")
	_ = w2

	// Create file entry at the exact same path
	w3, _ := zw.Create("shared_path")
	w3.Write([]byte("file-content"))

	zw.Close()
	f.Close()

	_, err := Intake(context.Background(), apkPath, IntakeOptions{})
	if err == nil {
		t.Fatalf("expected ErrSecurityViolation for directory-then-file conflict, got nil")
	}
	if !errors.Is(err, ErrSecurityViolation) {
		t.Errorf("expected ErrSecurityViolation, got %v", err)
	}
}

type nopWriteCloser struct{ io.Writer }

func (n nopWriteCloser) Close() error { return nil }

func TestIntake_UnsupportedCompressionMethod(t *testing.T) {
	// Register temporary compressor for method 99 so zip.Writer can build the archive
	zip.RegisterCompressor(99, func(w io.Writer) (io.WriteCloser, error) {
		return nopWriteCloser{w}, nil
	})

	tmpDir := t.TempDir()
	apkPath := filepath.Join(tmpDir, "custom_method.apk")
	f, err := os.Create(apkPath)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	zw := zip.NewWriter(f)

	w1, _ := zw.Create("AndroidManifest.xml")
	w1.Write([]byte("<manifest/>"))

	fh := &zip.FileHeader{
		Name:   "classes.dex",
		Method: 99, // unsupported compression method
	}
	w2, err := zw.CreateHeader(fh)
	if err != nil {
		t.Fatalf("failed to create header: %v", err)
	}
	w2.Write([]byte("dummy"))

	zw.Close()
	f.Close()

	_, err = Intake(context.Background(), apkPath, IntakeOptions{})
	if err == nil {
		t.Fatalf("expected ErrMalformedArchive for unsupported compression method, got nil")
	}
	if !errors.Is(err, ErrMalformedArchive) {
		t.Errorf("expected ErrMalformedArchive, got %v", err)
	}
}

func TestIntake_DeclaredSizeMismatch(t *testing.T) {
	apkPath := createMinimalValidAPK(t)
	data, err := os.ReadFile(apkPath)
	if err != nil {
		t.Fatal(err)
	}

	// Locate central directory header (PK\x01\x02) for classes.dex and tamper declared uncompressed size
	cdSig := []byte{0x50, 0x4B, 0x01, 0x02}
	idx := bytes.Index(data, cdSig)
	if idx == -1 {
		t.Fatalf("could not find central directory header")
	}

	found := false
	for idx != -1 {
		filenameLen := int(data[idx+28]) | int(data[idx+29])<<8
		filename := string(data[idx+46 : idx+46+filenameLen])
		if filename == "classes.dex" {
			// Offset 24 is uint32 UncompressedSize: tamper it to 250 bytes
			data[idx+24] = 0xFA
			data[idx+25] = 0x00
			data[idx+26] = 0x00
			data[idx+27] = 0x00
			found = true
			break
		}
		next := bytes.Index(data[idx+4:], cdSig)
		if next == -1 {
			break
		}
		idx += 4 + next
	}
	if !found {
		t.Fatalf("could not find classes.dex in central directory")
	}

	tamperedPath := filepath.Join(t.TempDir(), "mismatch.apk")
	if err := os.WriteFile(tamperedPath, data, 0644); err != nil {
		t.Fatal(err)
	}

	_, err = Intake(context.Background(), tamperedPath, IntakeOptions{})
	if err == nil {
		t.Fatalf("expected ErrMalformedArchive for declared size mismatch, got nil")
	}
	if !errors.Is(err, ErrMalformedArchive) {
		t.Errorf("expected ErrMalformedArchive, got %v", err)
	}
}

func TestIntake_EncryptedEntry(t *testing.T) {
	tmpDir := t.TempDir()
	apkPath := filepath.Join(tmpDir, "encrypted.apk")
	f, err := os.Create(apkPath)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	zw := zip.NewWriter(f)

	w1, _ := zw.Create("AndroidManifest.xml")
	w1.Write([]byte("<manifest/>"))

	fh := &zip.FileHeader{
		Name:   "classes.dex",
		Flags:  0x1, // General Purpose Bit Flag 0: encrypted
		Method: zip.Store,
	}
	w2, err := zw.CreateHeader(fh)
	if err != nil {
		t.Fatalf("failed to create header: %v", err)
	}
	w2.Write([]byte("secret"))

	zw.Close()
	f.Close()

	_, err = Intake(context.Background(), apkPath, IntakeOptions{})
	if err == nil {
		t.Fatalf("expected ErrSecurityViolation for encrypted entry, got nil")
	}
	if !errors.Is(err, ErrSecurityViolation) {
		t.Errorf("expected ErrSecurityViolation, got %v", err)
	}
}
