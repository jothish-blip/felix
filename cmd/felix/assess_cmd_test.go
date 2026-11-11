package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCLI_Assess_Help(t *testing.T) {
	code, out, _ := captureStdoutStderr(func() int {
		return runAssess([]string{"--help"})
	})

	if code != 0 {
		t.Fatalf("expected exit code 0 for --help, got %d", code)
	}

	expectedStrings := []string{
		"Usage: felix assess",
		"--target",
		"--profile",
		"--output",
		"--auth-confirm",
		"--auth-user-a",
		"--auth-user-b",
		"--auth-admin",
		"--roles-config",
		"--coverage",
		"--roadmap",
	}

	for _, exp := range expectedStrings {
		if !strings.Contains(out, exp) {
			t.Errorf("expected help output to contain %q", exp)
		}
	}
}

func TestCLI_Assess_MissingTarget_Returns2(t *testing.T) {
	code, _, errOut := captureStdoutStderr(func() int {
		return runAssess([]string{})
	})

	if code != 2 {
		t.Fatalf("expected exit code 2 for missing target, got %d", code)
	}
	if !strings.Contains(errOut, "--target is required") {
		t.Errorf("expected error message to mention --target is required, got %q", errOut)
	}
}

func TestCLI_Assess_InvalidProfile_Returns2(t *testing.T) {
	code, _, errOut := captureStdoutStderr(func() int {
		return runAssess([]string{
			"--target", "http://example.com",
			"--profile", "unknown_profile",
			"--output", "./audit_out",
		})
	})

	if code != 2 {
		t.Fatalf("expected exit code 2 for invalid profile, got %d", code)
	}
	if !strings.Contains(errOut, "invalid --profile") {
		t.Errorf("expected error message to mention invalid --profile, got %q", errOut)
	}
}

func TestCLI_Assess_DryRun_FullProfile(t *testing.T) {
	tmpDir := t.TempDir()
	code, out, _ := captureStdoutStderr(func() int {
		return runAssess([]string{
			"--target", "http://127.0.0.1:5000",
			"--profile", "full",
			"--output", tmpDir,
			"--dry-run",
			"--allow-loopback",
		})
	})

	if code != 0 {
		t.Fatalf("expected exit code 0 for dry-run, got %d", code)
	}

	expectedStages := []string{
		"[recon]",
		"[web]",
		"[api]",
		"[auth]",
		"[authz]",
		"[bola]",
		"[bfla]",
		"assessment_report.html",
		"assessment_report.json",
		"assessment_report.sarif",
		"coverage_matrix.json",
		"remediation_roadmap.json",
	}

	for _, s := range expectedStages {
		if !strings.Contains(out, s) {
			t.Errorf("expected dry-run output to contain %q", s)
		}
	}
}

func TestCLI_Assess_RolesConfigFile(t *testing.T) {
	tmpDir := t.TempDir()
	rolesFile := filepath.Join(tmpDir, "roles.json")
	rolesData := map[string]string{
		"user_a": "token_a_123",
		"user_b": "token_b_456",
		"admin":  "token_admin_789",
	}
	raw, err := json.Marshal(rolesData)
	if err != nil {
		t.Fatalf("failed to marshal roles: %v", err)
	}
	if err := os.WriteFile(rolesFile, raw, 0600); err != nil {
		t.Fatalf("failed to write roles file: %v", err)
	}

	code, out, _ := captureStdoutStderr(func() int {
		return runAssess([]string{
			"--target", "http://127.0.0.1:5000",
			"--profile", "api",
			"--output", tmpDir,
			"--roles-config", rolesFile,
			"--dry-run",
			"--allow-loopback",
		})
	})

	if code != 0 {
		t.Fatalf("expected exit code 0 for dry-run with roles config, got %d", code)
	}

	if !strings.Contains(out, "Multi-Role:") {
		t.Errorf("expected output to mention Multi-Role configuration, got %q", out)
	}
}

func TestCLI_Capabilities_Catalogue(t *testing.T) {
	code, out, _ := captureStdoutStderr(func() int {
		return runCapabilities([]string{"--catalogue"})
	})

	if code != 0 {
		t.Fatalf("expected exit code 0 for capabilities --catalogue, got %d", code)
	}

	expectedVulns := []string{
		"VULN-SQLI-001",
		"VULN-XSS-REFLECTED-001",
		"VULN-BOLA-001",
		"VULN-BFLA-001",
		"VULN-BOPLA-001",
		"VULN-SSRF-001",
		"VULN-AUTH-JWT-001",
		"VULN-TRAVERSAL-001",
		"VULN-SECRET-ENTROPY-001",
	}

	for _, v := range expectedVulns {
		if !strings.Contains(out, v) {
			t.Errorf("expected capabilities catalogue to contain %q", v)
		}
	}
}
