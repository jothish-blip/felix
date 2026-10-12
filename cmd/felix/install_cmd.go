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
)

func getInstallDir() (string, error) {
	if runtime.GOOS == "windows" {
		localApp := os.Getenv("LOCALAPPDATA")
		if localApp != "" {
			return filepath.Join(localApp, "Felix", "bin"), nil
		}
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".felix", "bin"), nil
}

func runInstall(args []string) int {
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

	if runtime.GOOS == "windows" {
		_ = os.Remove(targetPath)
	}
	if err := os.Rename(tmpPath, targetPath); err != nil {
		_ = os.Remove(tmpPath)
		fmt.Fprintf(os.Stderr, "[-] Failed to atomically place executable at %s: %v\n", targetPath, err)
		return 2
	}

	// Post-install self-verification
	verCmd := exec.Command(targetPath, "version")
	verOut, verErr := verCmd.CombinedOutput()
	if verErr != nil {
		_ = os.Remove(targetPath)
		fmt.Fprintf(os.Stderr, "[-] Post-installation self-test failed: %v\nOutput: %s\n", verErr, string(verOut))
		return 2
	}

	fmt.Printf("[+] Installed and verified executable at: %s\n", targetPath)

	// Register in PATH
	if runtime.GOOS == "windows" {
		cmd := exec.Command("powershell", "-NoProfile", "-Command", fmt.Sprintf(`
			$dir = '%s'
			$userPath = [Environment]::GetEnvironmentVariable("Path", "User")
			$paths = $userPath -split ';' | Where-Object { $_ -ne '' }
			if ($paths -notcontains $dir) {
				$newPath = ($paths + $dir) -join ';'
				[Environment]::SetEnvironmentVariable("Path", $newPath, "User")
				Write-Output "PATH_UPDATED"
			} else {
				Write-Output "ALREADY_PRESENT"
			}
		`, installDir))
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
	targetPath := filepath.Join(installDir, binaryName)

	if _, err := os.Stat(targetPath); os.IsNotExist(err) {
		fmt.Printf("[-] Felix executable not found at %s. Nothing to remove.\n", targetPath)
	} else {
		if err := os.Remove(targetPath); err != nil {
			fmt.Fprintf(os.Stderr, "[-] Failed to remove executable %s: %v\n", targetPath, err)
			return 2
		}
		fmt.Printf("[+] Removed executable: %s\n", targetPath)
	}

	// Remove install directory if empty
	_ = os.Remove(installDir)
	_ = os.Remove(filepath.Dir(installDir))

	// Remove from PATH on Windows
	if runtime.GOOS == "windows" {
		cmd := exec.Command("powershell", "-NoProfile", "-Command", fmt.Sprintf(`
			$dir = '%s'
			$userPath = [Environment]::GetEnvironmentVariable("Path", "User")
			$paths = $userPath -split ';' | Where-Object { $_ -ne '' -and $_ -ne $dir }
			$newPath = $paths -join ';'
			[Environment]::SetEnvironmentVariable("Path", $newPath, "User")
			Write-Output "PATH_CLEANED"
		`, installDir))
		_, _ = cmd.Output()
		fmt.Printf("[+] Removed %s from User PATH.\n", installDir)
	}

	fmt.Println()
	fmt.Println("[✓] Felix CLI uninstalled successfully.")
	fmt.Println("[i] Note: User scan results, JSON, and HTML reports were preserved.")
	return 0
}
