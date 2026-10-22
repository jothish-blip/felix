package report

import (
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"

	"github.com/santhosh-tekuri/jsonschema/v5"
)

//go:embed schema/sarif-schema-2.1.0.json
var embeddedSARIFSchema []byte

var (
	compiledSchema     *jsonschema.Schema
	compileSchemaOnce  sync.Once
	compileSchemaError error
)

// ValidationError represents a specific schema non-conformance error.
type ValidationError struct {
	Path       string `json:"path"`
	Constraint string `json:"constraint"`
	Message    string `json:"message"`
}

// ValidationResult captures the complete outcome of a SARIF schema validation check.
type ValidationResult struct {
	Valid  bool              `json:"valid"`
	Errors []ValidationError `json:"errors,omitempty"`
}

func (vr ValidationResult) Error() string {
	if vr.Valid || len(vr.Errors) == 0 {
		return ""
	}
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("SARIF 2.1.0 schema validation failed (%d error(s)):\n", len(vr.Errors)))
	for idx, e := range vr.Errors {
		sb.WriteString(fmt.Sprintf("  [%d] at %q: %s (%s)\n", idx+1, e.Path, e.Message, e.Constraint))
	}
	return sb.String()
}

func getCompiledSchema() (*jsonschema.Schema, error) {
	compileSchemaOnce.Do(func() {
		compiler := jsonschema.NewCompiler()
		// draft-04 is standard for SARIF 2.1.0
		compiler.Draft = jsonschema.Draft4

		const schemaName = "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json"
		if err := compiler.AddResource(schemaName, strings.NewReader(string(embeddedSARIFSchema))); err != nil {
			compileSchemaError = fmt.Errorf("failed to add embedded SARIF schema resource: %w", err)
			return
		}

		schema, err := compiler.Compile(schemaName)
		if err != nil {
			compileSchemaError = fmt.Errorf("failed to compile SARIF 2.1.0 schema: %w", err)
			return
		}
		compiledSchema = schema
	})

	return compiledSchema, compileSchemaError
}

// ValidateSARIF validates a raw SARIF byte slice against the official OASIS SARIF 2.1.0 JSON Schema.
// It explicitly distinguishes:
// 1. Schema compilation errors (operational)
// 2. JSON syntax/parsing errors (operational)
// 3. Schema conformance errors (validation failures)
func ValidateSARIF(data []byte) error {
	if int64(len(data)) > MaxReportFileSize {
		return fmt.Errorf("SARIF payload size (%d bytes) exceeds maximum permitted limit (%d bytes)", len(data), MaxReportFileSize)
	}
	schema, err := getCompiledSchema()
	if err != nil {
		return fmt.Errorf("schema compilation error: %w", err)
	}

	var parsed any
	if err := json.Unmarshal(data, &parsed); err != nil {
		return fmt.Errorf("JSON parse error in SARIF document: %w", err)
	}

	if err := schema.Validate(parsed); err != nil {
		var valErr *jsonschema.ValidationError
		if errors.As(err, &valErr) {
			vr := extractValidationErrors(valErr)
			return vr
		}
		return fmt.Errorf("SARIF schema validation error: %w", err)
	}

	return nil
}

// ValidateSARIFFile reads a SARIF file from disk and validates it against the official SARIF 2.1.0 schema.
func ValidateSARIFFile(filePath string) error {
	cleanPath := strings.TrimSpace(filePath)
	if cleanPath == "" {
		return fmt.Errorf("file I/O error: path cannot be empty")
	}

	fi, err := os.Stat(cleanPath)
	if err != nil {
		return fmt.Errorf("file I/O error: failed to stat %q: %w", cleanPath, err)
	}
	if fi.Size() > MaxReportFileSize {
		return fmt.Errorf("file I/O error: SARIF file %q size (%d bytes) exceeds maximum permitted limit (%d bytes)", cleanPath, fi.Size(), MaxReportFileSize)
	}

	data, err := os.ReadFile(cleanPath)
	if err != nil {
		return fmt.Errorf("file I/O error: failed to read %q: %w", cleanPath, err)
	}

	return ValidateSARIF(data)
}

func extractValidationErrors(root *jsonschema.ValidationError) ValidationResult {
	var errs []ValidationError

	var walk func(v *jsonschema.ValidationError)
	walk = func(v *jsonschema.ValidationError) {
		if len(v.Causes) == 0 {
			errs = append(errs, ValidationError{
				Path:       v.InstanceLocation,
				Constraint: v.KeywordLocation,
				Message:    v.Message,
			})
			return
		}
		for _, cause := range v.Causes {
			walk(cause)
		}
	}

	walk(root)

	if len(errs) == 0 {
		errs = append(errs, ValidationError{
			Path:       root.InstanceLocation,
			Constraint: root.KeywordLocation,
			Message:    root.Message,
		})
	}

	return ValidationResult{
		Valid:  false,
		Errors: errs,
	}
}
