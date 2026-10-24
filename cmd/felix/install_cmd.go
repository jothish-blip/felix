package main

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"felix/pkg/update"
)

func getInstallDir() (string, error) {
	var dir string
	if custom := os.Getenv("FELIX_INSTALL_DIR"); custom != "" {
		dir = custom
	} else if runtime.GOOS == "windows" {
		localApp := os.Getenv("LOCALAPPDATA")
		if localApp != "" {
			dir = filepath.Join(localApp, "Felix", "bin")
		} else {
			home, err := os.UserHomeDir()
			if err != nil {
				return "", err
			}
			dir = filepath.Join(home, ".felix", "bin")
		}
	} else {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		dir = filepath.Join(home, ".felix", "bin")
	}

	cleaned := filepath.Clean(dir)
	if !filepath.IsAbs(cleaned) {
		abs, err := filepath.Abs(cleaned)
		if err != nil {
			return "", fmt.Errorf("invalid installation path %q: %w", dir, err)
		}
		cleaned = abs
	}
	// Reject paths containing dangerous control characters or null bytes
	if strings.ContainsAny(cleaned, "\x00\r\n") {
		return "", fmt.Errorf("invalid characters in installation path %q", dir)
	}
	// Prevent root directory as installation target
	if cleaned == filepath.Dir(cleaned) || cleaned == "/" || cleaned == "\\" {
		return "", fmt.Errorf("refusing to use filesystem root as installation directory: %q", dir)
	}
	return cleaned, nil
}

func runInstall(args []string) int {
	force := false
	for _, a := range args {
		if a == "--help" || a == "-h" || a == "help" {
			printInstallHelp()
			return 0
		}
		if a == "--force" || a == "-f" {
			force = true
		}
	}

	fmt.Println("===========================================================")
	fmt.Println(" FELIX :: CLI Installer")
	fmt.Println("===========================================================")

	selfExe, err := os.Executable()
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Failed to locate current Felix executable: %v\n", err)
		return 2
	}

	installDir, err := getInstallDir()
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Failed to determine installation directory: %v\n", err)
		return 2
	}

	if err := os.MkdirAll(installDir, 0755); err != nil {
		fmt.Fprintf(os.Stderr, "[-] Failed to create installation directory: %v\n", err)
		return 2
	}

	binaryName := "felix"
	if runtime.GOOS == "windows" {
		binaryName = "felix.exe"
	}
	targetPath := filepath.Join(installDir, binaryName)

	// Check if target binary already exists and evaluate version transitions
	var existingVersion string
	if _, err := os.Stat(targetPath); err == nil {
		chkCmd := exec.Command(targetPath, "version")
		if chkOut, chkErr := chkCmd.CombinedOutput(); chkErr == nil {
			for _, line := range strings.Split(string(chkOut), "\n") {
				trimmed := strings.TrimSpace(line)
				if strings.HasPrefix(trimmed, "Version:") {
					existingVersion = strings.TrimSpace(strings.TrimPrefix(trimmed, "Version:"))
					break
				}
			}
		}

		if existingVersion != "" && Version != "" {
			cmp, cmpErr := update.Compare(Version, existingVersion)
			if cmpErr == nil {
				if cmp < 0 && !force {
					fmt.Fprintf(os.Stderr, "[-] Installed version (%s) is newer than candidate version (%s). Downgrades are rejected without --force.\n", existingVersion, Version)
					return 2
				}
				if cmp == 0 && !force {
					fmt.Printf("[+] Felix is already installed at current version (%s). No changes made.\n", existingVersion)
					return 0
				}
			}
		}
	}

	// Copy binary
	srcFile, err := os.Open(selfExe)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Failed to open source executable: %v\n", err)
		return 2
	}
	defer srcFile.Close()

	// Atomic copy: write to temporary file, sync, validate, then rename
	tmpPath := targetPath + fmt.Sprintf(".tmp.%d", time.Now().UnixNano())
	destFile, err := os.OpenFile(tmpPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0755)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Failed to create temporary target executable: %v\n", err)
		return 2
	}

	copied, copyErr := io.Copy(destFile, srcFile)
	syncErr := destFile.Sync()
	closeErr := destFile.Close()

	if copyErr != nil || syncErr != nil || closeErr != nil || copied == 0 {
		_ = os.Remove(tmpPath)
		fmt.Fprintf(os.Stderr, "[-] Failed to copy executable data: %v\n", copyErr)
		return 2
	}

	// Validate staged binary before replacing target
	fi, err := os.Stat(tmpPath)
	if err != nil || fi.Size() == 0 {
		_ = os.Remove(tmpPath)
		fmt.Fprintf(os.Stderr, "[-] Validation failed: staged binary is empty or unreadable\n")
		return 2
	}

	// Backup existing executable for safe rollback
	backupPath := targetPath + ".old"
	_ = os.Remove(backupPath)
	hasBackup := false
	if _, err := os.Stat(targetPath); err == nil {
		if err := os.Rename(targetPath, backupPath); err == nil {
			hasBackup = true
		}
	}

	if err := os.Rename(tmpPath, targetPath); err != nil {
		_ = os.Remove(tmpPath)
		if hasBackup {
			_ = os.Rename(backupPath, targetPath)
		}
		fmt.Fprintf(os.Stderr, "[-] Failed to atomically place executable at %s: %v\n", targetPath, err)
		return 2
	}

	// Post-install self-verification
	verCmd := exec.Command(targetPath, "version")
	verOut, verErr := verCmd.CombinedOutput()
	if verErr != nil {
		_ = os.Remove(targetPath)
		if hasBackup {
			_ = os.Rename(backupPath, targetPath)
			fmt.Fprintf(os.Stderr, "[-] Post-installation self-test failed; rolled back to previous version: %v\nOutput: %s\n", verErr, string(verOut))
		} else {
			fmt.Fprintf(os.Stderr, "[-] Post-installation self-test failed: %v\nOutput: %s\n", verErr, string(verOut))
		}
		return 2
	}

	// Successful verification - clean up backup
	if hasBackup {
		if runtime.GOOS != "windows" {
			_ = os.Remove(backupPath)
		} else {
			if remErr := os.Remove(backupPath); remErr != nil {
				delCmd := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command",
					`Start-Sleep -Milliseconds 500; if ($env:FELIX_CLEANUP_FILE -and (Test-Path -LiteralPath $env:FELIX_CLEANUP_FILE)) { Remove-Item -LiteralPath $env:FELIX_CLEANUP_FILE -Force -ErrorAction SilentlyContinue }`)
				delCmd.Env = append(os.Environ(), "FELIX_CLEANUP_FILE="+backupPath)
				_ = delCmd.Start()
			}
		}
	}

	if existingVersion != "" {
		fmt.Printf("[+] Successfully upgraded Felix from v%s to v%s at: %s\n", existingVersion, Version, targetPath)
	} else {
		fmt.Printf("[+] Installed and verified executable at: %s\n", targetPath)
	}

	// Register in PATH
	if os.Getenv("FELIX_NO_PATH_UPDATE") == "true" {
		fmt.Println("[i] Skipping PATH registration (FELIX_NO_PATH_UPDATE is set).")
	} else if runtime.GOOS == "windows" {
		cmd := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command", `
			$dir = $env:FELIX_INSTALL_TARGET_DIR
			if ($dir) {
				$userPath = [Environment]::GetEnvironmentVariable("Path", "User")
				$paths = @()
				if ($userPath) {
					$paths = $userPath -split ';' | Where-Object { $_ -ne '' }
				}
				if ($paths -notcontains $dir) {
					$newPath = ($paths + $dir) -join ';'
					[Environment]::SetEnvironmentVariable("Path", $newPath, "User")
					Write-Output "PATH_UPDATED"
				} else {
					Write-Output "ALREADY_PRESENT"
				}
			}
		`)
		cmd.Env = append(os.Environ(), "FELIX_INSTALL_TARGET_DIR="+installDir)
		out, err := cmd.Output()
		if err == nil {
			if strings.Contains(string(out), "PATH_UPDATED") {
				fmt.Printf("[+] Added %s to User PATH.\n", installDir)
			} else {
				fmt.Printf("[+] %s is already present in User PATH.\n", installDir)
			}
		}
	} else {
		fmt.Printf("[i] Add %s to your PATH by adding this to ~/.bashrc or ~/.zshrc:\n", installDir)
		fmt.Printf("    export PATH=\"%s:$PATH\"\n", installDir)
	}

	fmt.Println()
	fmt.Println("[✓] Felix CLI installation complete and verified. Open a new terminal session and run:")
	fmt.Println("    felix version")
	fmt.Println("    felix doctor")
	return 0
}

func runUninstall(args []string) int {
	for _, a := range args {
		if a == "--help" || a == "-h" || a == "help" {
			printUninstallHelp()
			return 0
		}
	}

	fmt.Println("===========================================================")
	fmt.Println(" FELIX :: CLI Uninstaller")
	fmt.Println("===========================================================")

	installDir, err := getInstallDir()
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Failed to determine installation directory: %v\n", err)
		return 2
	}

	binaryName := "felix"
	if runtime.GOOS == "windows" {
		binaryName = "felix.exe"
	}
	targetPath := filepath.Clean(filepath.Join(installDir, binaryName))

	// Verify targetPath is strictly inside installDir
	if filepath.Dir(targetPath) != installDir || filepath.Base(targetPath) != binaryName {
		fmt.Fprintf(os.Stderr, "[-] Safety check failed: target path %s escapes install directory %s\n", targetPath, installDir)
		return 2
	}

	lstat, statErr := os.Lstat(targetPath)
	if statErr != nil {
		if os.IsNotExist(statErr) {
			fmt.Printf("[-] Felix executable not found at %s. Nothing to remove.\n", targetPath)
		} else {
			fmt.Fprintf(os.Stderr, "[-] Failed to inspect target %s: %v\n", targetPath, statErr)
			return 2
		}
	} else {
		// Ensure target is a regular file and not a symlink, socket, device, or directory
		if lstat.Mode()&os.ModeSymlink != 0 || lstat.IsDir() {
			fmt.Fprintf(os.Stderr, "[-] Refusing to remove %s: not a regular executable file\n", targetPath)
			return 2
		}

		if err := os.Remove(targetPath); err != nil {
			// On Windows, a running executable cannot be directly deleted by os.Remove due to OS file locking.
			// Atomically rename it to a staging cleanup file inside installDir, then trigger deferred deletion.
			if runtime.GOOS == "windows" {
				tmpDeleted := filepath.Join(installDir, fmt.Sprintf(".felix_uninstall_%d.tmp", time.Now().UnixNano()))
				if renErr := os.Rename(targetPath, tmpDeleted); renErr != nil {
					fmt.Fprintf(os.Stderr, "[-] Failed to remove or stage executable %s: %v (rename: %v)\n", targetPath, err, renErr)
					return 2
				}

				// Launch deferred cleanup with target passed safely via environment variable
				delCmd := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command",
					`Start-Sleep -Milliseconds 500; if ($env:FELIX_CLEANUP_FILE -and (Test-Path -LiteralPath $env:FELIX_CLEANUP_FILE)) { Remove-Item -LiteralPath $env:FELIX_CLEANUP_FILE -Force -ErrorAction SilentlyContinue }`)
				delCmd.Env = append(os.Environ(), "FELIX_CLEANUP_FILE="+tmpDeleted)
				if startErr := delCmd.Start(); startErr != nil {
					// Roll back rename if deferred process failed to spawn
					_ = os.Rename(tmpDeleted, targetPath)
					fmt.Fprintf(os.Stderr, "[-] Failed to spawn deferred cleanup process for %s: %v\n", targetPath, startErr)
					return 2
				}
				fmt.Printf("[+] Removed executable: %s\n", targetPath)
			} else {
				fmt.Fprintf(os.Stderr, "[-] Failed to remove executable %s: %v\n", targetPath, err)
				return 2
			}
		} else {
			fmt.Printf("[+] Removed executable: %s\n", targetPath)
		}
	}

	// Remove install directory only if empty
	_ = os.Remove(installDir)

	// Clean up User PATH on Windows
	if os.Getenv("FELIX_NO_PATH_UPDATE") == "true" {
		fmt.Println("[i] Skipping PATH cleanup (FELIX_NO_PATH_UPDATE is set).")
	} else if runtime.GOOS == "windows" {
		cmd := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command", `
			$dir = $env:FELIX_UNINSTALL_DIR
			if ($dir) {
				$userPath = [Environment]::GetEnvironmentVariable("Path", "User")
				if ($userPath) {
					$paths = $userPath -split ';' | Where-Object { $_ -ne '' -and $_ -ne $dir }
					$newPath = $paths -join ';'
					[Environment]::SetEnvironmentVariable("Path", $newPath, "User")
					Write-Output "PATH_CLEANED"
				}
			}
		`)
		cmd.Env = append(os.Environ(), "FELIX_UNINSTALL_DIR="+installDir)
		_, _ = cmd.Output()
		fmt.Printf("[+] Removed %s from User PATH.\n", installDir)
	}

	fmt.Println()
	fmt.Println("[✓] Felix CLI uninstalled successfully.")
	fmt.Println("[i] Note: User scan results, JSON, and HTML reports were preserved.")
	return 0
}

func printInstallHelp() {
	fmt.Println("Usage: felix install [options]")
	fmt.Println()
	fmt.Println("Installs or upgrades the current Felix binary to the standard user bin directory and configures PATH.")
	fmt.Println()
	fmt.Println("Options:")
	fmt.Println("  --force, -f            Force installation even if already installed or downgrading")
	fmt.Println("  --help, -h             Show this help message")
	fmt.Println()
	fmt.Println("Standard install paths:")
	fmt.Println("  Windows: %LOCALAPPDATA%\\Felix\\bin\\felix.exe")
	fmt.Println("  Linux/macOS: ~/.felix/bin/felix")
	fmt.Println()
	fmt.Println("Environment Variables:")
	fmt.Println("  FELIX_INSTALL_DIR      Override the target installation directory")
	fmt.Println("  FELIX_NO_PATH_UPDATE   Set to 'true' to suppress automatic PATH modifications")
}

func printUninstallHelp() {
	fmt.Println("Usage: felix uninstall")
	fmt.Println()
	fmt.Println("Uninstalls the Felix binary from the standard user bin directory and cleans up PATH.")
	fmt.Println()
	fmt.Println("Environment Variables:")
	fmt.Println("  FELIX_INSTALL_DIR      Override the target directory to uninstall from")
	fmt.Println("  FELIX_NO_PATH_UPDATE   Set to 'true' to suppress automatic PATH modifications")
}
