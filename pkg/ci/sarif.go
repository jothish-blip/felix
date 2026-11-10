package ci

import (
	"encoding/json"
	"fmt"
	"os"

	"felix/pkg/report"
)

// GenerateAndValidateSARIF constructs a SARIF 2.1.0 document from a Report and validates
// it against the OASIS SARIF 2.1.0 JSON Schema.
func GenerateAndValidateSARIF(rep report.Report) ([]byte, error) {
	sarifLog := report.BuildSARIFLog(rep)

	data, err := json.MarshalIndent(sarifLog, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("failed marshaling SARIF log: %w", err)
	}

	if err := report.ValidateSARIF(data); err != nil {
		return nil, fmt.Errorf("SARIF 2.1.0 schema validation failed: %w", err)
	}

	return data, nil
}

// WriteValidatedSARIF serializes a validated SARIF 2.1.0 document to disk.
func WriteValidatedSARIF(rep report.Report, filePath string) error {
	data, err := GenerateAndValidateSARIF(rep)
	if err != nil {
		return err
	}
	return os.WriteFile(filePath, data, 0600)
}
