package apk

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// Workspace manages an isolated temporary directory for APK intake and downstream static analysis.
type Workspace struct {
	// Dir is the absolute path to the unique temporary workspace directory.
	Dir string

	// APKPath is the original path to the ingested APK file (kept strictly read-only).
	APKPath string

	// SHA256 is the verified cryptographic digest of the ingested APK file.
	SHA256 string

	// FileSize is the size of the ingested APK file in bytes.
	FileSize int64

	// EntryCount is the total number of validated entries within the APK archive.
	EntryCount int

	// DecompressedBytes is the total uncompressed size of extracted content.
	DecompressedBytes int64

	// ManifestPath is the relative path to AndroidManifest.xml within the workspace.
	ManifestPath string

	// DexFiles lists relative paths to all discovered Dalvik Executable (.dex) files.
	DexFiles []string

	closeOnce sync.Once
	closeErr  error
	isClosed  bool
	mu        sync.Mutex
}

// NewWorkspace creates a secure, unique temporary directory for APK isolation.
// If tempRoot is empty, os.TempDir() is utilized.
func NewWorkspace(tempRoot string) (*Workspace, error) {
	if tempRoot == "" {
		tempRoot = os.TempDir()
	}
	cleanRoot, err := filepath.Abs(filepath.Clean(tempRoot))
	if err != nil {
		return nil, fmt.Errorf("failed to resolve temporary root directory: %w", err)
	}

	// Verify temp root exists and is a directory
	info, err := os.Stat(cleanRoot)
	if err != nil {
		return nil, fmt.Errorf("temporary root directory is inaccessible: %w", err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("temporary root path %q is not a directory", cleanRoot)
	}

	// Create unique directory with random prefix (never derived from untrusted input)
	dir, err := os.MkdirTemp(cleanRoot, "felix-apk-*")
	if err != nil {
		return nil, fmt.Errorf("failed to create isolated temporary workspace: %w", err)
	}

	// Enforce restrictive permissions (read/write/exec by owner only)
	if err := os.Chmod(dir, 0700); err != nil {
		_ = os.RemoveAll(dir)
		return nil, fmt.Errorf("failed to enforce restrictive permissions on workspace %q: %w", dir, err)
	}

	absDir, err := filepath.Abs(dir)
	if err != nil {
		_ = os.RemoveAll(dir)
		return nil, fmt.Errorf("failed to resolve absolute workspace path: %w", err)
	}

	return &Workspace{
		Dir: absDir,
	}, nil
}

// Path returns the absolute path to the isolated workspace directory.
func (w *Workspace) Path() string {
	if w == nil {
		return ""
	}
	return w.Dir
}

// IsClosed returns true if the workspace has already been cleaned up.
func (w *Workspace) IsClosed() bool {
	if w == nil {
		return true
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.isClosed
}

// Close safely and idempotently removes all temporary files and directories in the workspace.
func (w *Workspace) Close() error {
	if w == nil || w.Dir == "" {
		return nil
	}

	w.closeOnce.Do(func() {
		w.mu.Lock()
		defer w.mu.Unlock()

		// Safety verification: Ensure w.Dir is not root or an empty path before removal
		cleanDir := filepath.Clean(w.Dir)
		if cleanDir == "" || cleanDir == "." || cleanDir == "/" || cleanDir == "\\" || filepath.VolumeName(cleanDir) == cleanDir {
			w.closeErr = fmt.Errorf("safety refusal: attempted cleanup of critical root directory %q", cleanDir)
			return
		}

		// Ensure w.Dir contains the felix-apk prefix as an additional sanity guard
		baseName := filepath.Base(cleanDir)
		if !strings.HasPrefix(baseName, "felix-apk-") {
			w.closeErr = fmt.Errorf("safety refusal: workspace directory %q does not match expected felix-apk pattern", cleanDir)
			return
		}

		if err := os.RemoveAll(cleanDir); err != nil {
			w.closeErr = fmt.Errorf("failed to remove workspace directory %q: %w", cleanDir, err)
			return
		}
		w.isClosed = true
	})

	return w.closeErr
}
