package compliance

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

var (
	// ErrEmptyRuleSetPayload is returned when input data is empty or whitespace.
	ErrEmptyRuleSetPayload = errors.New("empty mapping rule set payload")

	// ErrRuleSetTooLarge is returned when input exceeds MaxCatalogSizeBytes.
	ErrRuleSetTooLarge = fmt.Errorf("mapping rule set payload exceeds maximum permitted size of %d bytes", MaxCatalogSizeBytes)
)

// LoadMappingRuleSet reads, parses, and validates a MappingRuleSet from a file path.
func LoadMappingRuleSet(path string) (*MappingRuleSet, error) {
	cleanPath := strings.TrimSpace(path)
	if cleanPath == "" {
		return nil, errors.New("mapping rule set file path cannot be empty")
	}

	cleanPath = filepath.Clean(cleanPath)
	info, err := os.Stat(cleanPath)
	if err != nil {
		return nil, fmt.Errorf("failed accessing mapping rule set file %q: %w", cleanPath, err)
	}
	if info.IsDir() {
		return nil, fmt.Errorf("mapping rule set path %q is a directory, not a file", cleanPath)
	}
	if info.Size() > MaxCatalogSizeBytes {
		return nil, ErrRuleSetTooLarge
	}

	f, err := os.Open(cleanPath)
	if err != nil {
		return nil, fmt.Errorf("failed opening mapping rule set file %q: %w", cleanPath, err)
	}
	defer f.Close()

	return LoadMappingRuleSetFromReader(f)
}

// LoadMappingRuleSetFromBytes parses and validates a MappingRuleSet from a byte slice.
func LoadMappingRuleSetFromBytes(data []byte) (*MappingRuleSet, error) {
	if len(data) == 0 || len(bytes.TrimSpace(data)) == 0 {
		return nil, ErrEmptyRuleSetPayload
	}
	if len(data) > MaxCatalogSizeBytes {
		return nil, ErrRuleSetTooLarge
	}
	return LoadMappingRuleSetFromReader(bytes.NewReader(data))
}

// LoadMappingRuleSetFromReader safely parses and validates a MappingRuleSet from an io.Reader.
// Enforces payload size limit, nesting depth bounds, duplicate-key detection, unknown field checking,
// and structural semantic validation.
func LoadMappingRuleSetFromReader(r io.Reader) (*MappingRuleSet, error) {
	if r == nil {
		return nil, ErrEmptyRuleSetPayload
	}

	// 1. Read with size limiter
	limitedReader := io.LimitReader(r, MaxCatalogSizeBytes+1)
	rawBytes, err := io.ReadAll(limitedReader)
	if err != nil {
		return nil, fmt.Errorf("failed reading mapping rule set payload: %w", err)
	}

	if len(rawBytes) > MaxCatalogSizeBytes {
		return nil, ErrRuleSetTooLarge
	}

	trimmed := bytes.TrimSpace(rawBytes)
	if len(trimmed) == 0 {
		return nil, ErrEmptyRuleSetPayload
	}

	// 2. Syntax, Nesting Depth, and Duplicate Key Verification
	if err := inspectJSONTokens(trimmed); err != nil {
		return nil, err
	}

	// 3. Strict JSON Decoding with unknown field detection
	var ruleSet MappingRuleSet
	dec := json.NewDecoder(bytes.NewReader(trimmed))
	dec.DisallowUnknownFields()

	if err := dec.Decode(&ruleSet); err != nil {
		return nil, fmt.Errorf("malformed mapping rule set JSON: %w", err)
	}

	// 4. Validate complete rule set semantics
	if err := ValidateMappingRuleSet(&ruleSet, nil); err != nil {
		return nil, err
	}

	return &ruleSet, nil
}
