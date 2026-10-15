package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"felix/pkg/config"
)

func TestRunConfig_Show(t *testing.T) {
	tempDir := t.TempDir()
	t.Setenv("FELIX_DIR", tempDir)

	// 1. Show with default configuration
	stdout, stderr := captureOutput(func() {
		code := runConfig([]string{"show"})
		if code != 0 {
			t.Errorf("expected exit code 0, got %d", code)
		}
	})
	if stderr != "" {
		t.Errorf("expected empty stderr, got: %s", stderr)
	}
	if !strings.Contains(stdout, "Felix Configuration") {
		t.Errorf("expected stdout to contain 'Felix Configuration', got: %s", stdout)
	}
	if !strings.Contains(stdout, "timeout:      10 seconds") {
		t.Errorf("expected stdout to contain default timeout 10 seconds, got: %s", stdout)
	}

	// 2. Show with no args defaults to "show"
	stdout, stderr = captureOutput(func() {
		code := runConfig([]string{})
		if code != 0 {
			t.Errorf("expected exit code 0, got %d", code)
		}
	})
	if !strings.Contains(stdout, "Felix Configuration") {
		t.Errorf("expected stdout to contain 'Felix Configuration', got: %s", stdout)
	}
}

func TestRunConfig_Path(t *testing.T) {
	tempDir := t.TempDir()
	t.Setenv("FELIX_DIR", tempDir)

	stdout, stderr := captureOutput(func() {
		code := runConfig([]string{"path"})
		if code != 0 {
			t.Errorf("expected exit code 0, got %d", code)
		}
	})
	if stderr != "" {
		t.Errorf("expected empty stderr, got: %s", stderr)
	}
	expectedPath := filepath.Join(tempDir, "config.json")
	if !strings.Contains(strings.TrimSpace(stdout), expectedPath) {
		t.Errorf("expected path %q, got stdout %q", expectedPath, stdout)
	}
}

func TestRunConfig_GetAndSet(t *testing.T) {
	tempDir := t.TempDir()
	t.Setenv("FELIX_DIR", tempDir)

	// 1. Get default timeout
	stdout, _ := captureOutput(func() {
		code := runConfig([]string{"get", "timeout"})
		if code != 0 {
			t.Errorf("expected exit code 0, got %d", code)
		}
	})
	if strings.TrimSpace(stdout) != "10" {
		t.Errorf("expected '10', got %q", stdout)
	}

	// 2. Set timeout to 45
	stdout, stderr := captureOutput(func() {
		code := runConfig([]string{"set", "timeout", "45"})
		if code != 0 {
			t.Errorf("expected exit code 0, got %d", code)
		}
	})
	if stderr != "" {
		t.Errorf("expected empty stderr, got: %s", stderr)
	}
	if !strings.Contains(stdout, "Set timeout = 45") {
		t.Errorf("expected success message, got: %s", stdout)
	}

	// 3. Verify Get timeout returns 45
	stdout, _ = captureOutput(func() {
		code := runConfig([]string{"get", "timeout"})
		if code != 0 {
			t.Errorf("expected exit code 0, got %d", code)
		}
	})
	if strings.TrimSpace(stdout) != "45" {
		t.Errorf("expected '45', got %q", stdout)
	}

	// 4. Set concurrency to 20
	runConfig([]string{"set", "concurrency", "20"})
	stdout, _ = captureOutput(func() {
		runConfig([]string{"get", "concurrency"})
	})
	if strings.TrimSpace(stdout) != "20" {
		t.Errorf("expected '20', got %q", stdout)
	}

	// 5. Set scope to subdomains
	runConfig([]string{"set", "scope", "subdomains"})
	stdout, _ = captureOutput(func() {
		runConfig([]string{"get", "scope"})
	})
	if strings.TrimSpace(stdout) != "subdomains" {
		t.Errorf("expected 'subdomains', got %q", stdout)
	}

	// 6. Set max_assets to 500
	runConfig([]string{"set", "max_assets", "500"})
	stdout, _ = captureOutput(func() {
		runConfig([]string{"get", "max_assets"})
	})
	if strings.TrimSpace(stdout) != "500" {
		t.Errorf("expected '500', got %q", stdout)
	}

	// 7. Set allow_private_ips to true
	runConfig([]string{"set", "allow_private_ips", "true"})
	stdout, _ = captureOutput(func() {
		runConfig([]string{"get", "allow_private_ips"})
	})
	if strings.TrimSpace(stdout) != "true" {
		t.Errorf("expected 'true', got %q", stdout)
	}

	// 8. Set insecure_skip_verify to true
	runConfig([]string{"set", "insecure_skip_verify", "true"})
	stdout, _ = captureOutput(func() {
		runConfig([]string{"get", "insecure_skip_verify"})
	})
	if strings.TrimSpace(stdout) != "true" {
		t.Errorf("expected 'true', got %q", stdout)
	}
}

func TestRunConfig_Reset(t *testing.T) {
	tempDir := t.TempDir()
	t.Setenv("FELIX_DIR", tempDir)

	// Set custom timeout
	runConfig([]string{"set", "timeout", "60"})
	stdout, _ := captureOutput(func() {
		runConfig([]string{"get", "timeout"})
	})
	if strings.TrimSpace(stdout) != "60" {
		t.Fatalf("expected timeout 60, got %q", stdout)
	}

	// Reset
	stdout, stderr := captureOutput(func() {
		code := runConfig([]string{"reset"})
		if code != 0 {
			t.Errorf("expected exit code 0, got %d", code)
		}
	})
	if stderr != "" {
		t.Errorf("expected empty stderr, got: %s", stderr)
	}
	if !strings.Contains(stdout, "Restored default configuration") {
		t.Errorf("expected reset message, got: %s", stdout)
	}

	// Verify restored to default
	stdout, _ = captureOutput(func() {
		runConfig([]string{"get", "timeout"})
	})
	if strings.TrimSpace(stdout) != "10" {
		t.Errorf("expected default timeout 10 after reset, got %q", stdout)
	}
}

func TestRunConfig_ErrorsAndRedaction(t *testing.T) {
	tempDir := t.TempDir()
	t.Setenv("FELIX_DIR", tempDir)

	// 1. Missing args for get
	_, stderr := captureOutput(func() {
		code := runConfig([]string{"get"})
		if code != 2 {
			t.Errorf("expected exit code 2, got %d", code)
		}
	})
	if !strings.Contains(stderr, "Usage: felix config get") {
		t.Errorf("expected usage error, got: %s", stderr)
	}

	// 2. Missing args for set
	_, stderr = captureOutput(func() {
		code := runConfig([]string{"set", "timeout"})
		if code != 2 {
			t.Errorf("expected exit code 2, got %d", code)
		}
	})
	if !strings.Contains(stderr, "Usage: felix config set") {
		t.Errorf("expected usage error, got: %s", stderr)
	}

	// 3. Invalid set value
	_, stderr = captureOutput(func() {
		code := runConfig([]string{"set", "timeout", "-10"})
		if code != 2 {
			t.Errorf("expected exit code 2, got %d", code)
		}
	})
	if !strings.Contains(stderr, "must be a positive integer") {
		t.Errorf("expected invalid value error, got: %s", stderr)
	}

	// 4. Unknown config action
	_, stderr = captureOutput(func() {
		code := runConfig([]string{"delete"})
		if code != 2 {
			t.Errorf("expected exit code 2, got %d", code)
		}
	})
	if !strings.Contains(stderr, "Unknown config action") {
		t.Errorf("expected unknown action error, got: %s", stderr)
	}

	// 5. Secret redaction on unknown key in get
	rawSecret := "AKIAIOSFODNN7EXAMPLE"
	_, stderr = captureOutput(func() {
		code := runConfig([]string{"get", rawSecret})
		if code != 2 {
			t.Errorf("expected exit code 2, got %d", code)
		}
	})
	if strings.Contains(stderr, rawSecret) {
		t.Errorf("raw secret leaked in get error output: %s", stderr)
	}
	if !strings.Contains(stderr, "[REDACTED") {
		t.Errorf("expected redacted token in get error output, got: %s", stderr)
	}

	// 6. Secret redaction on unknown key in set
	_, stderr = captureOutput(func() {
		code := runConfig([]string{"set", rawSecret, "some-value"})
		if code != 2 {
			t.Errorf("expected exit code 2, got %d", code)
		}
	})
	if strings.Contains(stderr, rawSecret) {
		t.Errorf("raw secret leaked in set error output: %s", stderr)
	}
	if !strings.Contains(stderr, "[REDACTED") {
		t.Errorf("expected redacted token in set error output, got: %s", stderr)
	}
}

func TestRunConfig_MalformedFileErrorsOut(t *testing.T) {
	tempDir := t.TempDir()
	t.Setenv("FELIX_DIR", tempDir)

	p, err := config.Path()
	if err != nil {
		t.Fatalf("Path() error: %v", err)
	}

	if err := os.WriteFile(p, []byte(`{malformed-json`), 0644); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	// 1. Show with malformed file
	_, stderr := captureOutput(func() {
		code := runConfig([]string{"show"})
		if code != 2 {
			t.Errorf("expected exit code 2 on malformed file in show, got %d", code)
		}
	})
	if !strings.Contains(stderr, "Configuration error") {
		t.Errorf("expected configuration error, got: %s", stderr)
	}

	// 2. Get with malformed file
	_, stderr = captureOutput(func() {
		code := runConfig([]string{"get", "timeout"})
		if code != 2 {
			t.Errorf("expected exit code 2 on malformed file in get, got %d", code)
		}
	})
	if !strings.Contains(stderr, "Configuration error") {
		t.Errorf("expected configuration error, got: %s", stderr)
	}

	// 3. Set with malformed file
	_, stderr = captureOutput(func() {
		code := runConfig([]string{"set", "timeout", "40"})
		if code != 2 {
			t.Errorf("expected exit code 2 on malformed file in set, got %d", code)
		}
	})
	if !strings.Contains(stderr, "Configuration error") {
		t.Errorf("expected configuration error, got: %s", stderr)
	}
}
