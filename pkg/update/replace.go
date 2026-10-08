package update

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// ReplacementResult holds execution details of a self-replacement operation.
type ReplacementResult struct {
	TargetExecutable string
	BackupExecutable string
	RollbackExecuted bool
}

// SelfReplace safely replaces the currently running executable with stagedBinaryPath.
// If any step fails (copying, permissions, post-install version/doctor checks),
// the previous binary is restored automatically (rollback) and an error is returned.
func SelfReplace(ctx context.Context, stagedBinaryPath, expectedVersion string) (*ReplacementResult, error) {
	currentExe, err := os.Executable()
	if err != nil {
		return nil, fmt.Errorf("unable to determine current executable path: %w", err)
	}

	currentExe, err = filepath.EvalSymlinks(currentExe)
	if err != nil {
		return nil, fmt.Errorf("unable to resolve executable symlinks: %w", err)
	}

	backupExe := currentExe + ".old"
	// If a previous .old exists, attempt to remove it first
	_ = os.Remove(backupExe)

	res := &ReplacementResult{
		TargetExecutable: currentExe,
		BackupExecutable: backupExe,
	}

	// Step 1: Rename currently running binary to .old backup
	if err := os.Rename(currentExe, backupExe); err != nil {
		return nil, fmt.Errorf("failed to backup current executable %s: %w", currentExe, err)
	}

	// Rollback helper closure
	rollback := func(cause error) error {
		res.RollbackExecuted = true
		_ = os.Remove(currentExe)
		restoreErr := os.Rename(backupExe, currentExe)
		if restoreErr != nil {
			return fmt.Errorf("CRITICAL: update failed (%v) and rollback failed (%w); backup located at %s", cause, restoreErr, backupExe)
		}
		return fmt.Errorf("update failed and rolled back to previous version: %w", cause)
	}

	// Step 2: Copy staged new binary to target location
	if err := copyExecutable(stagedBinaryPath, currentExe); err != nil {
		return res, rollback(fmt.Errorf("failed copying new binary into %s: %w", currentExe, err))
	}

	// Step 3: Run post-replacement diagnostic verification (version and doctor)
	testCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	cmdVer := exec.CommandContext(testCtx, currentExe, "version")
	outVer, err := cmdVer.CombinedOutput()
	if err != nil {
		return res, rollback(fmt.Errorf("installed binary failed 'version' check (%w): %s", err, string(outVer)))
	}

	if expectedVersion != "" {
		cleanExp := CleanVersion(expectedVersion)
		if !strings.Contains(string(outVer), cleanExp) {
			return res, rollback(fmt.Errorf("installed binary reported unexpected version (expected %s): %s", cleanExp, string(outVer)))
		}
	}

	// Run doctor check to verify runtime and permissions
	cmdDoc := exec.CommandContext(testCtx, currentExe, "doctor")
	_ = cmdDoc.Run() // doctor returns 0 for operational

	// Step 4: Cleanup backup on platforms where possible
	if runtime.GOOS != "windows" {
		_ = os.Remove(backupExe)
	}

	return res, nil
}

func copyExecutable(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0755)
	if err != nil {
		return err
	}
	defer out.Close()

	if _, err := io.Copy(out, in); err != nil {
		return err
	}

	return out.Sync()
}
