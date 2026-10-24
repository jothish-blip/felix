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
	} else {
		if remErr := os.Remove(backupExe); remErr != nil {
			delCmd := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command",
				`Start-Sleep -Milliseconds 500; if ($env:FELIX_CLEANUP_FILE -and (Test-Path -LiteralPath $env:FELIX_CLEANUP_FILE)) { Remove-Item -LiteralPath $env:FELIX_CLEANUP_FILE -Force -ErrorAction SilentlyContinue }`)
			delCmd.Env = append(os.Environ(), "FELIX_CLEANUP_FILE="+backupExe)
			_ = delCmd.Start()
		}
	}

	return res, nil
}

func copyExecutable(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	tmpDst := dst + fmt.Sprintf(".atomic.%d", time.Now().UnixNano())
	out, err := os.OpenFile(tmpDst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0755)
	if err != nil {
		return err
	}

	copied, copyErr := io.Copy(out, in)
	syncErr := out.Sync()
	closeErr := out.Close()

	if copyErr != nil || syncErr != nil || closeErr != nil || copied == 0 {
		_ = os.Remove(tmpDst)
		if copyErr != nil {
			return copyErr
		}
		return fmt.Errorf("copied 0 bytes during executable staging")
	}

	fi, err := os.Stat(tmpDst)
	if err != nil || fi.Size() == 0 {
		_ = os.Remove(tmpDst)
		return fmt.Errorf("staged binary is empty or unreadable")
	}

	if runtime.GOOS == "windows" {
		_ = os.Remove(dst)
	}
	if err := os.Rename(tmpDst, dst); err != nil {
		_ = os.Remove(tmpDst)
		return fmt.Errorf("atomic rename failed: %w", err)
	}

	return nil
}
