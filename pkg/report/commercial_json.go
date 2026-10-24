package report

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// GenerateCommercialJSON serializes a CommercialReport to pretty-printed, indented JSON bytes.
func GenerateCommercialJSON(cr CommercialReport) ([]byte, error) {
	return json.MarshalIndent(cr, "", "  ")
}

// WriteCommercialJSON writes the sanitized CommercialReport JSON to disk with restricted permissions (0600).
func WriteCommercialJSON(cr CommercialReport, filePath string) error {
	data, err := GenerateCommercialJSON(cr)
	if err != nil {
		return err
	}
	return writeReportFileSafely(filePath, data)
}

// ParseCommercialReport deserializes JSON bytes into a CommercialReport struct.
func ParseCommercialReport(data []byte) (CommercialReport, error) {
	if int64(len(data)) > MaxReportFileSize {
		return CommercialReport{}, fmt.Errorf("commercial report payload size (%d bytes) exceeds maximum permitted limit (%d bytes)", len(data), MaxReportFileSize)
	}
	var cr CommercialReport
	if err := json.Unmarshal(data, &cr); err != nil {
		return CommercialReport{}, err
	}
	return cr, nil
}

// LoadCommercialReport loads and parses a CommercialReport from disk.
func LoadCommercialReport(filePath string) (CommercialReport, error) {
	cleanPath := filepath.Clean(filePath)
	fi, err := os.Stat(cleanPath)
	if err != nil {
		return CommercialReport{}, err
	}
	if fi.Size() > MaxReportFileSize {
		return CommercialReport{}, fmt.Errorf("commercial report file %q size (%d bytes) exceeds maximum permitted limit (%d bytes)", filePath, fi.Size(), MaxReportFileSize)
	}
	data, err := os.ReadFile(cleanPath)
	if err != nil {
		return CommercialReport{}, err
	}
	return ParseCommercialReport(data)
}
