package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestTargetCmd_Help(t *testing.T) {
	code := runTarget([]string{"--help"})
	if code != 0 {
		t.Fatalf("expected exit 0 for --help, got %d", code)
	}

	code = runTarget([]string{"help"})
	if code != 0 {
		t.Fatalf("expected exit 0 for help, got %d", code)
	}

	code = runTarget([]string{"validate", "--help"})
	if code != 0 {
		t.Fatalf("expected exit 0 for validate --help, got %d", code)
	}
}

func TestTargetCmd_ValidateValidProfile(t *testing.T) {
	tempDir := t.TempDir()
	profilePath := filepath.Join(tempDir, "felix.target.yml")

	content := `version: 1
target:
  name: "CLI Validation Test Target"
  base_urls:
    - "http://127.0.0.1:8080"
  allowed_hosts:
    - "127.0.0.1"
    - "localhost"
  allowed_methods:
    - "GET"
    - "HEAD"

safety:
  mode: "non_destructive"
  allow_cross_tenant_checks: true
  max_requests: 20
  requests_per_second: 5
  timeout_seconds: 5

tenants:
  - id: "t_alpha"
    identity: "alpha@example.corp"
    resource_ids:
      - "res_101"
  - id: "t_beta"
    identity: "beta@example.corp"
    resource_ids:
      - "res_201"

cross_tenant_tests:
  enabled: true
  comparisons:
    - requester_tenant: "t_beta"
      resource_owner_tenant: "t_alpha"
      resource_id: "res_101"
`
	if err := os.WriteFile(profilePath, []byte(content), 0600); err != nil {
		t.Fatalf("failed writing temp profile: %v", err)
	}

	// 1. Test with --profile flag
	code := runTarget([]string{"validate", "--profile", profilePath})
	if code != 0 {
		t.Fatalf("expected exit code 0 for valid profile, got %d", code)
	}

	// 2. Test with positional path argument
	code = runTarget([]string{"validate", profilePath})
	if code != 0 {
		t.Fatalf("expected exit code 0 for positional profile path, got %d", code)
	}

	// 3. Test direct file invocation
	code = runTarget([]string{profilePath})
	if code != 0 {
		t.Fatalf("expected exit code 0 for direct file invocation, got %d", code)
	}
}

func TestTargetCmd_ValidateMissingOrInvalidFile(t *testing.T) {
	// 1. Missing file path
	code := runTarget([]string{"validate"})
	if code != 2 {
		t.Fatalf("expected exit 2 for missing profile argument, got %d", code)
	}

	// 2. Non-existent file
	code = runTarget([]string{"validate", "--profile", "non_existent_file_9999.yml"})
	if code != 2 {
		t.Fatalf("expected exit 2 for non-existent profile file, got %d", code)
	}

	// 3. Unknown subcommand
	code = runTarget([]string{"unknown_subcommand"})
	if code != 2 {
		t.Fatalf("expected exit 2 for unknown subcommand, got %d", code)
	}
}

func TestTargetCmd_ValidateMalformedProfile(t *testing.T) {
	tempDir := t.TempDir()
	malformedPath := filepath.Join(tempDir, "malformed.yml")

	content := `version: 99
target:
  base_urls: []
`
	if err := os.WriteFile(malformedPath, []byte(content), 0600); err != nil {
		t.Fatalf("failed writing malformed profile: %v", err)
	}

	code := runTarget([]string{"validate", "--profile", malformedPath})
	if code != 2 {
		t.Fatalf("expected exit 2 for malformed profile, got %d", code)
	}
}
