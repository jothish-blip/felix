package main

import (
	"testing"
)

func TestComplianceSyncCLI_Help(t *testing.T) {
	code := runComplianceSync([]string{"--help"})
	if code != 0 {
		t.Errorf("expected exit code 0 for --help, got %d", code)
	}
}

func TestComplianceSyncCLI_MissingAssessment(t *testing.T) {
	code := runComplianceSync([]string{"--platform", "vanta"})
	if code != 2 {
		t.Errorf("expected exit code 2 for missing assessment flag, got %d", code)
	}
}

func TestComplianceSyncCLI_UnknownPlatform(t *testing.T) {
	code := runComplianceSync([]string{"--assessment", "asm-01", "--platform", "unknown-platform"})
	if code != 2 {
		t.Errorf("expected exit code 2 for unknown platform, got %d", code)
	}
}
