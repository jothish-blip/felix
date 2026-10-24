package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestRunInstall_Help(t *testing.T) {
	for _, flag := range []string{"--help", "-h", "help"} {
		stdout, stderr := captureOutput(func() {
			code := runInstall([]string{flag})
			if code != 0 {
				t.Fatalf("runInstall(%q) expected 0, got %d", flag, code)
			}
		})
		if stderr != "" {
			t.Errorf("unexpected stderr for flag %q: %s", flag, stderr)
		}
		if !strings.Contains(stdout, "Usage: felix install") {
			t.Errorf("expected usage header in stdout, got: %s", stdout)
		}
		if !strings.Contains(stdout, "FELIX_INSTALL_DIR") {
			t.Errorf("expected FELIX_INSTALL_DIR in stdout, got: %s", stdout)
		}
		if !strings.Contains(stdout, "FELIX_NO_PATH_UPDATE") {
			t.Errorf("expected FELIX_NO_PATH_UPDATE in stdout, got: %s", stdout)
		}
	}
}

func TestRunUninstall_Help(t *testing.T) {
	for _, flag := range []string{"--help", "-h", "help"} {
		stdout, stderr := captureOutput(func() {
			code := runUninstall([]string{flag})
			if code != 0 {
				t.Fatalf("runUninstall(%q) expected 0, got %d", flag, code)
			}
		})
		if stderr != "" {
			t.Errorf("unexpected stderr for flag %q: %s", flag, stderr)
		}
		if !strings.Contains(stdout, "Usage: felix uninstall") {
			t.Errorf("expected usage header in stdout, got: %s", stdout)
		}
		if !strings.Contains(stdout, "FELIX_INSTALL_DIR") {
			t.Errorf("expected FELIX_INSTALL_DIR in stdout, got: %s", stdout)
		}
	}
}

func TestRunConfig_Help(t *testing.T) {
	for _, flag := range []string{"--help", "-h", "help"} {
		stdout, stderr := captureOutput(func() {
			code := runConfig([]string{flag})
			if code != 0 {
				t.Fatalf("runConfig(%q) expected 0, got %d", flag, code)
			}
		})
		if stderr != "" {
			t.Errorf("unexpected stderr for flag %q: %s", flag, stderr)
		}
		if !strings.Contains(stdout, "felix config <action>") {
			t.Errorf("expected config usage header, got: %s", stdout)
		}
		if !strings.Contains(stdout, "show") || !strings.Contains(stdout, "reset") {
			t.Errorf("expected config actions in stdout, got: %s", stdout)
		}
	}
}

func TestRunCompletion_Help(t *testing.T) {
	for _, flag := range []string{"--help", "-h", "help"} {
		stdout, stderr := captureOutput(func() {
			code := runCompletion([]string{flag})
			if code != 0 {
				t.Fatalf("runCompletion(%q) expected 0, got %d", flag, code)
			}
		})
		if stderr != "" {
			t.Errorf("unexpected stderr for flag %q: %s", flag, stderr)
		}
		if !strings.Contains(stdout, "felix completion <shell>") {
			t.Errorf("expected completion usage header, got: %s", stdout)
		}
		if !strings.Contains(stdout, "powershell") || !strings.Contains(stdout, "bash") {
			t.Errorf("expected shells in stdout, got: %s", stdout)
		}
	}
}

func TestInstallUninstall_Lifecycle(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration lifecycle test in short mode")
	}

	// 1. Build a temporary real Felix binary for installation testing
	tempBinDir := t.TempDir()
	binName := "felix"
	if runtime.GOOS == "windows" {
		binName = "felix.exe"
	}
	builtExe := filepath.Join(tempBinDir, binName)

	buildCmd := exec.Command("go", "build", "-trimpath", "-o", builtExe, ".")
	if out, err := buildCmd.CombinedOutput(); err != nil {
		t.Fatalf("failed to build test felix binary: %v\nOutput: %s", err, string(out))
	}

	// 2. Set an isolated target installation directory and suppress system PATH modification
	targetInstallDir := filepath.Join(t.TempDir(), "custom_felix_install")
	installedExe := filepath.Join(targetInstallDir, binName)

	// 3. Execute `felix install` using the built executable
	instCmd := exec.Command(builtExe, "install")
	instCmd.Env = append(os.Environ(),
		"FELIX_INSTALL_DIR="+targetInstallDir,
		"FELIX_NO_PATH_UPDATE=true",
	)
	instOut, instErr := instCmd.CombinedOutput()
	if instErr != nil {
		t.Fatalf("felix install failed: %v\nOutput: %s", instErr, string(instOut))
	}
	if !strings.Contains(string(instOut), "complete and verified") {
		t.Errorf("expected installation success output, got: %s", string(instOut))
	}

	// 4. Verify target binary exists and matches expected size
	st, err := os.Stat(installedExe)
	if err != nil {
		t.Fatalf("installed binary not found at %s: %v", installedExe, err)
	}
	if st.Size() == 0 {
		t.Fatalf("installed binary is empty")
	}

	// 5. Verify installed binary executes version and doctor
	verCmd := exec.Command(installedExe, "version")
	verOut, verErr := verCmd.CombinedOutput()
	if verErr != nil {
		t.Fatalf("installed binary version command failed: %v\nOutput: %s", verErr, string(verOut))
	}
	if !strings.Contains(string(verOut), "Felix Security Auditor") {
		t.Errorf("unexpected version output: %s", string(verOut))
	}

	docCmd := exec.Command(installedExe, "doctor")
	docOut, docErr := docCmd.CombinedOutput()
	if docErr != nil {
		t.Fatalf("installed binary doctor command failed: %v\nOutput: %s", docErr, string(docOut))
	}
	if !strings.Contains(string(docOut), "System Diagnostic & Runtime Readiness") {
		t.Errorf("unexpected doctor output: %s", string(docOut))
	}

	// 6. Execute `felix uninstall` using the installed binary
	uninstCmd := exec.Command(installedExe, "uninstall")
	uninstCmd.Env = append(os.Environ(),
		"FELIX_INSTALL_DIR="+targetInstallDir,
		"FELIX_NO_PATH_UPDATE=true",
	)
	uninstOut, uninstErr := uninstCmd.CombinedOutput()
	if uninstErr != nil {
		t.Fatalf("felix uninstall failed: %v\nOutput: %s", uninstErr, string(uninstOut))
	}
	if !strings.Contains(string(uninstOut), "uninstalled successfully") {
		t.Errorf("expected uninstallation success output, got: %s", string(uninstOut))
	}

	// 7. Verify installed binary was removed
	if _, err := os.Stat(installedExe); !os.IsNotExist(err) {
		t.Fatalf("expected binary to be removed, but it still exists at %s", installedExe)
	}

	// 8. Verify running uninstall again is idempotent (does not fail when file is already gone)
	uninstCmd2 := exec.Command(builtExe, "uninstall")
	uninstCmd2.Env = append(os.Environ(),
		"FELIX_INSTALL_DIR="+targetInstallDir,
		"FELIX_NO_PATH_UPDATE=true",
	)
	uninstOut2, uninstErr2 := uninstCmd2.CombinedOutput()
	if uninstErr2 != nil {
		t.Fatalf("idempotent felix uninstall failed: %v\nOutput: %s", uninstErr2, string(uninstOut2))
	}
	if !strings.Contains(string(uninstOut2), "Nothing to remove") {
		t.Errorf("expected 'Nothing to remove' on second uninstall, got: %s", string(uninstOut2))
	}
}

func TestGetInstallDir_Validation(t *testing.T) {
	// 1. Valid custom path
	validTemp := filepath.Join(t.TempDir(), "bin")
	t.Setenv("FELIX_INSTALL_DIR", validTemp)
	dir, err := getInstallDir()
	if err != nil {
		t.Fatalf("expected valid dir, got error: %v", err)
	}
	if dir != filepath.Clean(validTemp) {
		t.Errorf("expected %s, got %s", validTemp, dir)
	}

	// 2. Reject root directory
	root := filepath.VolumeName(validTemp) + string(filepath.Separator)
	if root == "" {
		root = "/"
	}
	t.Setenv("FELIX_INSTALL_DIR", root)
	if _, err := getInstallDir(); err == nil {
		t.Errorf("expected error rejecting filesystem root directory %q, got nil", root)
	}

	// 3. Reject newline and carriage return injection
	t.Setenv("FELIX_INSTALL_DIR", validTemp+"\nmalicious")
	if _, err := getInstallDir(); err == nil {
		t.Errorf("expected error rejecting newline in path, got nil")
	}

	t.Setenv("FELIX_INSTALL_DIR", validTemp+"\rmalicious")
	if _, err := getInstallDir(); err == nil {
		t.Errorf("expected error rejecting carriage return in path, got nil")
	}
}

func TestRunUninstall_RefuseNonRegularFile(t *testing.T) {
	tempDir := t.TempDir()
	t.Setenv("FELIX_INSTALL_DIR", tempDir)
	t.Setenv("FELIX_NO_PATH_UPDATE", "true")

	binaryName := "felix"
	if runtime.GOOS == "windows" {
		binaryName = "felix.exe"
	}
	fakeExeDir := filepath.Join(tempDir, binaryName)
	// Create a DIRECTORY where the binary is expected
	if err := os.Mkdir(fakeExeDir, 0755); err != nil {
		t.Fatalf("failed to create fake dir: %v", err)
	}

	_, stderr := captureOutput(func() {
		code := runUninstall([]string{})
		if code != 2 {
			t.Errorf("expected exit code 2 when target is a directory, got %d", code)
		}
	})

	if !strings.Contains(stderr, "not a regular executable file") {
		t.Errorf("expected stderr to contain 'not a regular executable file', got: %s", stderr)
	}
}
