package update

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCopyExecutable(t *testing.T) {
	tmpDir := t.TempDir()
	src := filepath.Join(tmpDir, "source.bin")
	dst := filepath.Join(tmpDir, "dest.bin")

	data := []byte("felix-binary-payload-data-test")
	if err := os.WriteFile(src, data, 0755); err != nil {
		t.Fatal(err)
	}

	if err := copyExecutable(src, dst); err != nil {
		t.Fatalf("copyExecutable failed: %v", err)
	}

	readBack, err := os.ReadFile(dst)
	if err != nil {
		t.Fatalf("failed reading copied file: %v", err)
	}

	if string(readBack) != string(data) {
		t.Errorf("copied content mismatch: expected %q, got %q", string(data), string(readBack))
	}
}

func TestRollbackRestoration(t *testing.T) {
	tmpDir := t.TempDir()
	originalExe := filepath.Join(tmpDir, "felix.exe")
	backupExe := filepath.Join(tmpDir, "felix.exe.old")

	origContent := []byte("original-v1.0.0-binary")
	if err := os.WriteFile(originalExe, origContent, 0755); err != nil {
		t.Fatal(err)
	}

	// Simulate backup step
	if err := os.Rename(originalExe, backupExe); err != nil {
		t.Fatalf("rename to backup failed: %v", err)
	}

	// Simulate failed install where new binary is broken
	brokenExe := filepath.Join(tmpDir, "felix.exe")
	if err := os.WriteFile(brokenExe, []byte("broken-binary"), 0755); err != nil {
		t.Fatal(err)
	}

	// Trigger rollback
	_ = os.Remove(brokenExe)
	if err := os.Rename(backupExe, originalExe); err != nil {
		t.Fatalf("rollback restoration failed: %v", err)
	}

	// Verify original content was restored intact
	restored, err := os.ReadFile(originalExe)
	if err != nil {
		t.Fatalf("failed reading restored binary: %v", err)
	}

	if string(restored) != string(origContent) {
		t.Errorf("restored content mismatch: expected %q, got %q", string(origContent), string(restored))
	}
}
