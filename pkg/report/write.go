package report

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// writeReportFileSafely safely and atomically writes report content to disk with restricted permissions (0600).
// In accordance with the FELIX export reliability contract:
// 1. If filePath is empty or whitespace, returns an error.
// 2. If the destination parent directory does not exist, returns an error without fabricating directories.
// 3. If filePath refers to an existing directory, returns an error.
// 4. Content is staged in a temporary file in the destination's directory and synced to disk before replacing the target.
// 5. Existing destination files are never truncated or modified until the replacement is safely staged and validated.
// 6. On write or sync failure, temporary files are cleanly removed.
func writeReportFileSafely(filePath string, data []byte) error {
	cleanPath := filepath.Clean(strings.TrimSpace(filePath))
	if cleanPath == "" || cleanPath == "." {
		return errors.New("report output path cannot be empty")
	}

	fi, err := os.Stat(cleanPath)
	if err == nil && fi.IsDir() {
		return fmt.Errorf("cannot write report: %q is a directory", cleanPath)
	}

	dir := filepath.Dir(cleanPath)
	if dir != "" && dir != "." {
		dirFi, err := os.Stat(dir)
		if err != nil {
			return fmt.Errorf("failed to access output directory %q: %w", dir, err)
		}
		if !dirFi.IsDir() {
			return fmt.Errorf("output parent path %q is not a directory", dir)
		}
	}

	// Create temporary staging file in the target directory so rename is within the same filesystem
	tmpFile, err := os.CreateTemp(dir, fmt.Sprintf(".felix-report-tmp-*%s", filepath.Ext(cleanPath)))
	if err != nil {
		return fmt.Errorf("failed to create temporary report file: %w", err)
	}
	tmpName := tmpFile.Name()
	defer func() {
		_ = os.Remove(tmpName) // Clean up staging file if not successfully renamed
	}()

	if _, err := tmpFile.Write(data); err != nil {
		_ = tmpFile.Close()
		return fmt.Errorf("failed to write report data: %w", err)
	}
	if err := tmpFile.Sync(); err != nil {
		_ = tmpFile.Close()
		return fmt.Errorf("failed to sync report data: %w", err)
	}
	if err := tmpFile.Close(); err != nil {
		return fmt.Errorf("failed to close report file: %w", err)
	}

	// Set restricted file permissions (0600)
	_ = os.Chmod(tmpName, 0600)

	// If destination already exists, remove it prior to renaming (required on Windows)
	if _, err := os.Stat(cleanPath); err == nil {
		if err := os.Remove(cleanPath); err != nil {
			return fmt.Errorf("failed to replace existing report file %q: %w", cleanPath, err)
		}
	}

	if err := os.Rename(tmpName, cleanPath); err != nil {
		return fmt.Errorf("failed to finalize report file %q: %w", cleanPath, err)
	}

	return nil
}
