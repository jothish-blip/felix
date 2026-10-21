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
	// ErrEmptyPayload is returned when input data is empty or whitespace.
	ErrEmptyPayload = errors.New("empty catalog payload")

	// ErrCatalogTooLarge is returned when input exceeds MaxCatalogSizeBytes.
	ErrCatalogTooLarge = fmt.Errorf("catalog payload exceeds maximum permitted size of %d bytes", MaxCatalogSizeBytes)

	// ErrNestingTooDeep is returned when JSON nesting depth exceeds MaxNestingDepth.
	ErrNestingTooDeep = fmt.Errorf("catalog exceeds maximum allowed nesting depth of %d", MaxNestingDepth)
)

// LoadCatalog reads, parses, and validates a ControlCatalog from a file path.
func LoadCatalog(path string) (*ControlCatalog, error) {
	cleanPath := strings.TrimSpace(path)
	if cleanPath == "" {
		return nil, errors.New("catalog file path cannot be empty")
	}

	cleanPath = filepath.Clean(cleanPath)
	info, err := os.Stat(cleanPath)
	if err != nil {
		return nil, fmt.Errorf("failed accessing catalog file %q: %w", cleanPath, err)
	}
	if info.IsDir() {
		return nil, fmt.Errorf("catalog path %q is a directory, not a file", cleanPath)
	}
	if info.Size() > MaxCatalogSizeBytes {
		return nil, ErrCatalogTooLarge
	}

	f, err := os.Open(cleanPath)
	if err != nil {
		return nil, fmt.Errorf("failed opening catalog file %q: %w", cleanPath, err)
	}
	defer f.Close()

	return LoadCatalogFromReader(f)
}

// LoadCatalogFromBytes parses and validates a ControlCatalog from a byte slice.
func LoadCatalogFromBytes(data []byte) (*ControlCatalog, error) {
	if len(data) == 0 || len(bytes.TrimSpace(data)) == 0 {
		return nil, ErrEmptyPayload
	}
	if len(data) > MaxCatalogSizeBytes {
		return nil, ErrCatalogTooLarge
	}
	return LoadCatalogFromReader(bytes.NewReader(data))
}

// LoadCatalogFromReader safely parses and validates a ControlCatalog from an io.Reader.
// Enforces payload size limit, nesting depth bounds, duplicate-key detection, unknown field checking,
// and complete semantic validation.
func LoadCatalogFromReader(r io.Reader) (*ControlCatalog, error) {
	if r == nil {
		return nil, ErrEmptyPayload
	}

	// 1. Read with size limiter
	limitedReader := io.LimitReader(r, MaxCatalogSizeBytes+1)
	rawBytes, err := io.ReadAll(limitedReader)
	if err != nil {
		return nil, fmt.Errorf("failed reading catalog payload: %w", err)
	}

	if len(rawBytes) > MaxCatalogSizeBytes {
		return nil, ErrCatalogTooLarge
	}

	trimmed := bytes.TrimSpace(rawBytes)
	if len(trimmed) == 0 {
		return nil, ErrEmptyPayload
	}

	// 2. Syntax, Nesting Depth, and Duplicate Key Verification
	if err := inspectJSONTokens(trimmed); err != nil {
		return nil, err
	}

	// 3. Strict JSON Decoding with unknown field detection
	var catalog ControlCatalog
	dec := json.NewDecoder(bytes.NewReader(trimmed))
	dec.DisallowUnknownFields()

	if err := dec.Decode(&catalog); err != nil {
		return nil, fmt.Errorf("malformed catalog JSON: %w", err)
	}

	// 4. Validate complete catalog semantics
	if err := ValidateCatalog(&catalog); err != nil {
		return nil, err
	}

	return &catalog, nil
}

// inspectJSONTokens performs a single pass over JSON tokens to verify valid JSON syntax,
// enforce maximum nesting depth, and detect ambiguous duplicate object keys.
func inspectJSONTokens(data []byte) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	type frame struct {
		isObject  bool
		expectKey bool
		keys      map[string]bool
	}

	var stack []*frame

	for {
		tok, err := dec.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("malformed JSON syntax: %w", err)
		}

		switch t := tok.(type) {
		case json.Delim:
			switch t {
			case '{':
				if len(stack) >= MaxNestingDepth {
					return ErrNestingTooDeep
				}
				if len(stack) > 0 && stack[len(stack)-1].isObject && !stack[len(stack)-1].expectKey {
					stack[len(stack)-1].expectKey = true
				}
				stack = append(stack, &frame{isObject: true, expectKey: true, keys: make(map[string]bool)})
			case '[':
				if len(stack) >= MaxNestingDepth {
					return ErrNestingTooDeep
				}
				if len(stack) > 0 && stack[len(stack)-1].isObject && !stack[len(stack)-1].expectKey {
					stack[len(stack)-1].expectKey = true
				}
				stack = append(stack, &frame{isObject: false, expectKey: false})
			case '}', ']':
				if len(stack) == 0 {
					return fmt.Errorf("unexpected closing delimiter %q in JSON", t)
				}
				stack = stack[:len(stack)-1]
			}
		default:
			// Primitive token: string, float64, bool, nil
			if len(stack) > 0 && stack[len(stack)-1].isObject {
				top := stack[len(stack)-1]
				if top.expectKey {
					keyStr, ok := t.(string)
					if !ok {
						return fmt.Errorf("expected string object key, got %T", t)
					}
					if top.keys[keyStr] {
						return fmt.Errorf("ambiguous duplicate object key %q in catalog JSON", keyStr)
					}
					top.keys[keyStr] = true
					top.expectKey = false
				} else {
					top.expectKey = true
				}
			}
		}
	}

	if len(stack) != 0 {
		return errors.New("unclosed delimiters in JSON payload")
	}

	return nil
}
