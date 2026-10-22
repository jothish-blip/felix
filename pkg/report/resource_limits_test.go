package report

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestResourceLimits_ReportFileOversized verifies that LoadReport rejects files exceeding
// MaxReportFileSize before allocating memory or reading the full file.
func TestResourceLimits_ReportFileOversized(t *testing.T) {
	tmpDir := t.TempDir()
	largePath := filepath.Join(tmpDir, "oversized.json")

	f, err := os.Create(largePath)
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}
	// Truncate creates a sparse file of MaxReportFileSize + 1 byte instantly
	if err := f.Truncate(MaxReportFileSize + 1); err != nil {
		f.Close()
		t.Fatalf("failed to truncate: %v", err)
	}
	f.Close()

	_, err = LoadReport(largePath)
	if err == nil {
		t.Fatal("expected LoadReport to fail on oversized file, got nil")
	}
	if !strings.Contains(err.Error(), "exceeds maximum permitted limit") {
		t.Fatalf("expected error mentioning maximum permitted limit, got: %v", err)
	}
}

// TestResourceLimits_ParseReportOversized verifies that ParseReport rejects oversized payloads.
func TestResourceLimits_ParseReportOversized(t *testing.T) {
	// Allocate a slice exceeding MaxReportFileSize
	oversized := make([]byte, MaxReportFileSize+1)
	_, err := ParseReport(oversized)
	if err == nil {
		t.Fatal("expected ParseReport to reject payload exceeding MaxReportFileSize, got nil")
	}
	if !strings.Contains(err.Error(), "exceeds maximum permitted limit") {
		t.Fatalf("expected error mentioning maximum permitted limit, got: %v", err)
	}
}

// TestResourceLimits_CommercialReportOversized verifies that LoadCommercialReport and
// ParseCommercialReport reject oversized inputs.
func TestResourceLimits_CommercialReportOversized(t *testing.T) {
	tmpDir := t.TempDir()
	largePath := filepath.Join(tmpDir, "oversized_comm.json")

	f, err := os.Create(largePath)
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}
	if err := f.Truncate(MaxReportFileSize + 1); err != nil {
		f.Close()
		t.Fatalf("failed to truncate: %v", err)
	}
	f.Close()

	_, err = LoadCommercialReport(largePath)
	if err == nil {
		t.Fatal("expected LoadCommercialReport to fail on oversized file, got nil")
	}
	if !strings.Contains(err.Error(), "exceeds maximum permitted limit") {
		t.Fatalf("expected error mentioning maximum permitted limit, got: %v", err)
	}

	oversized := make([]byte, MaxReportFileSize+1)
	_, err = ParseCommercialReport(oversized)
	if err == nil {
		t.Fatal("expected ParseCommercialReport to reject payload exceeding MaxReportFileSize, got nil")
	}
	if !strings.Contains(err.Error(), "exceeds maximum permitted limit") {
		t.Fatalf("expected error mentioning maximum permitted limit, got: %v", err)
	}
}

// TestResourceLimits_SARIFFileOversized verifies that ValidateSARIFFile and ValidateSARIF
// reject oversized inputs.
func TestResourceLimits_SARIFFileOversized(t *testing.T) {
	tmpDir := t.TempDir()
	largePath := filepath.Join(tmpDir, "oversized.sarif")

	f, err := os.Create(largePath)
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}
	if err := f.Truncate(MaxReportFileSize + 1); err != nil {
		f.Close()
		t.Fatalf("failed to truncate: %v", err)
	}
	f.Close()

	err = ValidateSARIFFile(largePath)
	if err == nil {
		t.Fatal("expected ValidateSARIFFile to reject oversized file, got nil")
	}
	if !strings.Contains(err.Error(), "exceeds maximum permitted limit") {
		t.Fatalf("expected error mentioning maximum permitted limit, got: %v", err)
	}

	oversized := make([]byte, MaxReportFileSize+1)
	err = ValidateSARIF(oversized)
	if err == nil {
		t.Fatal("expected ValidateSARIF to reject payload exceeding MaxReportFileSize, got nil")
	}
	if !strings.Contains(err.Error(), "exceeds maximum permitted limit") {
		t.Fatalf("expected error mentioning maximum permitted limit, got: %v", err)
	}
}
