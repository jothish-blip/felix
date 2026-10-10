package report

import (
	"encoding/json"
	"os"
)

// GenerateCommercialJSON serializes a CommercialReport to pretty-printed, indented JSON bytes.
func GenerateCommercialJSON(cr CommercialReport) ([]byte, error) {
	return json.MarshalIndent(cr, "", "  ")
}

// WriteCommercialJSON writes the sanitized CommercialReport JSON to disk.
func WriteCommercialJSON(cr CommercialReport, filePath string) error {
	data, err := GenerateCommercialJSON(cr)
	if err != nil {
		return err
	}
	return os.WriteFile(filePath, data, 0644)
}

// ParseCommercialReport deserializes JSON bytes into a CommercialReport struct.
func ParseCommercialReport(data []byte) (CommercialReport, error) {
	var cr CommercialReport
	if err := json.Unmarshal(data, &cr); err != nil {
		return CommercialReport{}, err
	}
	return cr, nil
}

// LoadCommercialReport loads and parses a CommercialReport from disk.
func LoadCommercialReport(filePath string) (CommercialReport, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return CommercialReport{}, err
	}
	return ParseCommercialReport(data)
}
