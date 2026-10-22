package operator

import (
	"path/filepath"
	"strings"
	"testing"

	"felix/pkg/assessment"
)

func FuzzValidateReportPathContainment(f *testing.F) {
	// Seed corpus: (candidatePath)
	f.Add("report-123.html")
	f.Add("2026/10/report.json")
	f.Add("../etc/passwd")
	f.Add("..\\..\\windows\\system32\\calc.exe")
	f.Add("/etc/shadow")
	f.Add("C:/Windows/System32/cmd.exe")
	f.Add("report.json\x00.html")
	f.Add("nested/../../escape.txt")
	f.Add("")
	f.Add("   ")
	f.Add(".")
	f.Add("..")
	f.Add("/")
	f.Add("\\")
	f.Add(strings.Repeat("../", 20) + "boot.ini")

	tempDir := f.TempDir()
	reportsRoot := filepath.Join(tempDir, "authorized_reports")
	dbPath := filepath.Join(tempDir, "fuzz_store.db")

	store, err := assessment.NewSQLiteStore(dbPath)
	if err != nil {
		f.Fatalf("failed to init sqlite store for fuzzing: %v", err)
	}
	defer store.Close()

	srv, err := NewServer(Config{
		ListenHost:  "127.0.0.1",
		ListenPort:  8383,
		OperatorID:  "fuzz-operator",
		Token:       "fuzz-token-1234567890abcdef",
		Store:       store,
		ReportsRoot: reportsRoot,
	})
	if err != nil {
		f.Fatalf("failed to init operator server for fuzzing: %v", err)
	}

	cleanRoot := filepath.Clean(reportsRoot)

	f.Fuzz(func(t *testing.T, candidate string) {
		resolved, err := srv.validateReportPathContainment(candidate)
		if err != nil {
			// Access denied is expected for traversal or out-of-root paths
			return
		}

		// Invariant 1: Empty or whitespace input must NEVER succeed
		if strings.TrimSpace(candidate) == "" {
			t.Fatalf("empty candidate path passed containment check: %q", candidate)
		}

		// Invariant 2: Null bytes must never succeed
		if strings.ContainsRune(candidate, 0) {
			t.Fatalf("candidate with null byte passed containment check: %q", candidate)
		}

		// Invariant 3: Resolved path must reside within the authorized root
		rel, relErr := filepath.Rel(cleanRoot, resolved)
		if relErr != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			t.Fatalf("path traversal escape: %q resolved to %q outside root %q", candidate, resolved, cleanRoot)
		}
	})
}
