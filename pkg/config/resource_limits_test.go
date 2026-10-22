package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestResourceLimits_ConfigFileOversized verifies that LoadWithEnv rejects configuration files
// exceeding MaxConfigFileSize before reading the entire file into memory.
func TestResourceLimits_ConfigFileOversized(t *testing.T) {
	tmpDir := t.TempDir()
	largePath := filepath.Join(tmpDir, "oversized.yaml")

	f, err := os.Create(largePath)
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}
	if err := f.Truncate(MaxConfigFileSize + 1); err != nil {
		f.Close()
		t.Fatalf("failed to truncate: %v", err)
	}
	f.Close()

	_, err = LoadWithEnv(largePath)
	if err == nil {
		t.Fatal("expected LoadWithEnv to reject oversized configuration file, got nil")
	}
	if !strings.Contains(err.Error(), "exceeds maximum permitted limit") {
		t.Fatalf("expected error mentioning maximum permitted limit, got: %v", err)
	}
}

// TestResourceLimits_ParseConfigOversized verifies that ParseConfig rejects in-memory payloads
// exceeding MaxConfigFileSize.
func TestResourceLimits_ParseConfigOversized(t *testing.T) {
	oversized := make([]byte, MaxConfigFileSize+1)
	_, err := ParseConfig(oversized)
	if err == nil {
		t.Fatal("expected ParseConfig to reject oversized byte slice, got nil")
	}
	if !strings.Contains(err.Error(), "exceeds maximum permitted limit") {
		t.Fatalf("expected error mentioning maximum permitted limit, got: %v", err)
	}
}
