package compliance

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"

	"github.com/santhosh-tekuri/jsonschema/v5"
)

// Official NIST OSCAL v1.1.0 JSON schemas embedded directly into the binary
//
//go:embed schema/oscal_assessment-results_schema.json
var embeddedOSCALAssessmentResultsSchema []byte

//go:embed schema/oscal_poam_schema.json
var embeddedOSCALPOAMSchema []byte

const (
	// Official Schema URIs matching $id in NIST OSCAL specifications
	OSCALAssessmentResultsSchemaURI = "http://csrc.nist.gov/ns/oscal/1.1.0/oscal-ar-schema.json"
	OSCALPOAMSchemaURI              = "http://csrc.nist.gov/ns/oscal/1.1.0/oscal-poam-schema.json"
)

var (
	compiledARSchema     *jsonschema.Schema
	compileARSchemaOnce  sync.Once
	compileARSchemaError error

	compiledPOAMSchema     *jsonschema.Schema
	compilePOAMSchemaOnce  sync.Once
	compilePOAMSchemaError error
)

func getCompiledOSCALAssessmentResultsSchema() (*jsonschema.Schema, error) {
	compileARSchemaOnce.Do(func() {
		compiler := jsonschema.NewCompiler()
		compiler.Draft = jsonschema.Draft7

		if err := compiler.AddResource(OSCALAssessmentResultsSchemaURI, bytes.NewReader(embeddedOSCALAssessmentResultsSchema)); err != nil {
			compileARSchemaError = fmt.Errorf("failed adding OSCAL Assessment Results schema resource: %w", err)
			return
		}

		schema, err := compiler.Compile(OSCALAssessmentResultsSchemaURI)
		if err != nil {
			compileARSchemaError = fmt.Errorf("failed compiling official OSCAL Assessment Results schema: %w", err)
			return
		}
		compiledARSchema = schema
	})

	return compiledARSchema, compileARSchemaError
}

func getCompiledOSCALPOAMSchema() (*jsonschema.Schema, error) {
	compilePOAMSchemaOnce.Do(func() {
		compiler := jsonschema.NewCompiler()
		compiler.Draft = jsonschema.Draft7

		if err := compiler.AddResource(OSCALPOAMSchemaURI, bytes.NewReader(embeddedOSCALPOAMSchema)); err != nil {
			compilePOAMSchemaError = fmt.Errorf("failed adding OSCAL POA&M schema resource: %w", err)
			return
		}

		schema, err := compiler.Compile(OSCALPOAMSchemaURI)
		if err != nil {
			compilePOAMSchemaError = fmt.Errorf("failed compiling official OSCAL POA&M schema: %w", err)
			return
		}
		compiledPOAMSchema = schema
	})

	return compiledPOAMSchema, compilePOAMSchemaError
}

// ValidateOSCALAssessmentResultsJSONSchema validates raw JSON bytes against the official NIST OSCAL v1.1.0 Assessment Results JSON Schema.
func ValidateOSCALAssessmentResultsJSONSchema(data []byte) error {
	schema, err := getCompiledOSCALAssessmentResultsSchema()
	if err != nil {
		return fmt.Errorf("OSCAL AR schema initialization failed: %w", err)
	}

	var parsed any
	if err := json.Unmarshal(data, &parsed); err != nil {
		return fmt.Errorf("JSON syntax error: %w", err)
	}

	if err := schema.Validate(parsed); err != nil {
		var valErr *jsonschema.ValidationError
		if errors.As(err, &valErr) {
			return formatSchemaValidationErrors("OSCAL Assessment Results v1.1.0", valErr)
		}
		return fmt.Errorf("OSCAL Assessment Results schema error: %w", err)
	}

	return nil
}

// ValidateOSCALPOAMJSONSchema validates raw JSON bytes against the official NIST OSCAL v1.1.0 POA&M JSON Schema.
func ValidateOSCALPOAMJSONSchema(data []byte) error {
	schema, err := getCompiledOSCALPOAMSchema()
	if err != nil {
		return fmt.Errorf("OSCAL POA&M schema initialization failed: %w", err)
	}

	var parsed any
	if err := json.Unmarshal(data, &parsed); err != nil {
		return fmt.Errorf("JSON syntax error: %w", err)
	}

	if err := schema.Validate(parsed); err != nil {
		var valErr *jsonschema.ValidationError
		if errors.As(err, &valErr) {
			return formatSchemaValidationErrors("OSCAL POA&M v1.1.0", valErr)
		}
		return fmt.Errorf("OSCAL POA&M schema error: %w", err)
	}

	return nil
}

func formatSchemaValidationErrors(modelName string, valErr *jsonschema.ValidationError) error {
	var errs []string
	var collect func(ve *jsonschema.ValidationError)
	collect = func(ve *jsonschema.ValidationError) {
		if ve.Message != "" {
			errs = append(errs, fmt.Sprintf("at %q: %s", ve.InstanceLocation, ve.Message))
		}
		for _, cause := range ve.Causes {
			collect(cause)
		}
	}
	collect(valErr)

	if len(errs) == 0 {
		return fmt.Errorf("%s schema validation error: %v", modelName, valErr)
	}

	return fmt.Errorf("%w: %s schema validation failed (%d error(s)): %s",
		ErrInvalidExport, modelName, len(errs), strings.Join(errs, "; "))
}
