package compliance

import (
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strings"
)

var (
	// idPattern enforces safe, alphanumeric identifiers with common delimiters (- . _ :).
	idPattern = regexp.MustCompile(`^[a-zA-Z0-9_\.\:\-]+$`)
)

// FieldViolation records a specific validation error on a field or sub-element.
type FieldViolation struct {
	Field   string `json:"field"`
	Code    string `json:"code"`
	Message string `json:"message"`
}

func (fv FieldViolation) String() string {
	if fv.Field != "" {
		return fmt.Sprintf("%s: %s", fv.Field, fv.Message)
	}
	return fv.Message
}

// ValidationError represents one or more schema, structural, or semantic validation failures.
type ValidationError struct {
	CatalogID  string           `json:"catalog_id,omitempty"`
	Violations []FieldViolation `json:"violations"`
}

// Error returns a formatted, deterministic string of all validation violations.
func (ve *ValidationError) Error() string {
	if ve == nil || len(ve.Violations) == 0 {
		return "valid control catalog"
	}
	var sb strings.Builder
	prefix := "control catalog validation failed"
	if ve.CatalogID != "" {
		prefix = fmt.Sprintf("control catalog %q validation failed", ve.CatalogID)
	}
	sb.WriteString(prefix)
	sb.WriteString(fmt.Sprintf(" (%d error(s)): ", len(ve.Violations)))

	messages := make([]string, len(ve.Violations))
	for i, v := range ve.Violations {
		messages[i] = v.String()
	}
	sb.WriteString(strings.Join(messages, "; "))
	return sb.String()
}

// HasViolations returns true if the error contains any field violations.
func (ve *ValidationError) HasViolations() bool {
	return ve != nil && len(ve.Violations) > 0
}

func (ve *ValidationError) addViolation(field, code, message string) {
	ve.Violations = append(ve.Violations, FieldViolation{
		Field:   field,
		Code:    code,
		Message: message,
	})
}

// ValidateCatalog validates a ControlCatalog against FELIX schema rules, structural integrity,
// unique control identifiers, reference syntaxes, and relational consistency.
func ValidateCatalog(catalog *ControlCatalog) error {
	if catalog == nil {
		return &ValidationError{
			Violations: []FieldViolation{
				{Field: "catalog", Code: "NIL_CATALOG", Message: "catalog cannot be nil"},
			},
		}
	}

	ve := &ValidationError{CatalogID: strings.TrimSpace(catalog.ID)}

	// 1. Schema Version Validation
	schemaVer := strings.TrimSpace(catalog.SchemaVersion)
	if schemaVer == "" {
		ve.addViolation("schema_version", "REQUIRED_FIELD", "schema_version is required")
	} else if !isSupportedSchemaVersion(schemaVer) {
		ve.addViolation("schema_version", "UNSUPPORTED_VERSION",
			fmt.Sprintf("unsupported schema_version %q; supported versions: %s, %s, %s",
				schemaVer, SchemaVersion1_0, SchemaVersion1_0_0, SchemaVersion1))
	}

	// 2. Catalog Identifier Validation
	catID := strings.TrimSpace(catalog.ID)
	if catID == "" {
		ve.addViolation("id", "REQUIRED_FIELD", "catalog identifier 'id' is required")
	} else if !idPattern.MatchString(catID) {
		ve.addViolation("id", "INVALID_FORMAT",
			fmt.Sprintf("catalog identifier %q contains invalid characters; must match alphanumeric or [-._:]", catID))
	}

	// 3. Catalog Title Validation
	catTitle := strings.TrimSpace(catalog.Title)
	if catTitle == "" {
		ve.addViolation("title", "REQUIRED_FIELD", "catalog 'title' is required")
	}

	// 4. Catalog Version Validation
	catVer := strings.TrimSpace(catalog.Version)
	if catVer == "" {
		ve.addViolation("version", "REQUIRED_FIELD", "catalog 'version' is required")
	}

	// 5. Source Validation (if present)
	if catalog.Source != nil {
		if catalog.Source.URL != "" {
			if _, err := url.ParseRequestURI(catalog.Source.URL); err != nil {
				ve.addViolation("source.url", "INVALID_URI",
					fmt.Sprintf("invalid source URL %q: %v", catalog.Source.URL, err))
			}
		}
	}

	// 6. Metadata Validation (catalog level)
	validateMetadataValues("metadata", catalog.Metadata, ve)

	// 7. Controls Collection Validation
	if len(catalog.Controls) == 0 {
		ve.addViolation("controls", "EMPTY_COLLECTION", "catalog must contain at least one control definition")
		return ve
	}

	// Collect and validate individual controls
	controlIndex := make(map[string]int) // lowercase ID -> first seen index
	controlOriginalIDs := make(map[string]bool)

	for i, ctrl := range catalog.Controls {
		fieldPrefix := fmt.Sprintf("controls[%d]", i)

		// Control ID
		ctrlID := strings.TrimSpace(ctrl.ID)
		if ctrlID == "" {
			ve.addViolation(fieldPrefix+".id", "REQUIRED_FIELD", "control 'id' is required")
		} else {
			if !idPattern.MatchString(ctrlID) {
				ve.addViolation(fieldPrefix+".id", "INVALID_FORMAT",
					fmt.Sprintf("control identifier %q contains invalid characters; must match alphanumeric or [-._:]", ctrlID))
			}

			// Duplicate ID detection (case-insensitive for collision resistance)
			normID := strings.ToLower(ctrlID)
			if firstIdx, exists := controlIndex[normID]; exists {
				ve.addViolation(fieldPrefix+".id", "DUPLICATE_IDENTIFIER",
					fmt.Sprintf("duplicate control identifier %q (conflicts with controls[%d].id)", ctrlID, firstIdx))
			} else {
				controlIndex[normID] = i
				controlOriginalIDs[ctrlID] = true
			}
		}

		// Control Title
		ctrlTitle := strings.TrimSpace(ctrl.Title)
		if ctrlTitle == "" {
			ve.addViolation(fieldPrefix+".title", "REQUIRED_FIELD", "control 'title' is required")
		}

		// Control Description / Requirement Statement
		ctrlDesc := strings.TrimSpace(ctrl.Description)
		if ctrlDesc == "" {
			ve.addViolation(fieldPrefix+".description", "REQUIRED_FIELD", "control 'description' is required")
		}

		// Control Lifecycle Status
		if ctrl.Status != "" {
			if _, valid := CanonicalControlStatus(string(ctrl.Status)); !valid {
				ve.addViolation(fieldPrefix+".status", "INVALID_STATUS",
					fmt.Sprintf("unsupported control status %q; valid lifecycle states: active, deprecated, draft", ctrl.Status))
			}
		}

		// Control References
		for rIdx, ref := range ctrl.References {
			refPrefix := fmt.Sprintf("%s.references[%d]", fieldPrefix, rIdx)
			if ref.URI != "" {
				parsedURI, err := url.Parse(ref.URI)
				if err != nil || (parsedURI.Scheme == "" && parsedURI.Path == "") {
					ve.addViolation(refPrefix+".uri", "INVALID_URI",
						fmt.Sprintf("invalid reference URI %q", ref.URI))
				}
			}
		}

		// Control Metadata
		validateMetadataValues(fieldPrefix+".metadata", ctrl.Metadata, ve)
	}

	// 8. Relational Validation: RelatedControls references must resolve within catalog
	for i, ctrl := range catalog.Controls {
		fieldPrefix := fmt.Sprintf("controls[%d]", i)
		ctrlID := strings.TrimSpace(ctrl.ID)

		for rIdx, relID := range ctrl.RelatedControls {
			relPrefix := fmt.Sprintf("%s.related_controls[%d]", fieldPrefix, rIdx)
			trimmedRel := strings.TrimSpace(relID)
			if trimmedRel == "" {
				ve.addViolation(relPrefix, "EMPTY_REFERENCE", "related control reference cannot be empty")
				continue
			}
			if trimmedRel == ctrlID {
				ve.addViolation(relPrefix, "SELF_REFERENCE",
					fmt.Sprintf("control %q cannot reference itself in related_controls", ctrlID))
				continue
			}
			if !controlOriginalIDs[trimmedRel] && controlIndex[strings.ToLower(trimmedRel)] == 0 && !controlOriginalIDs[trimmedRel] {
				// Check normalized map
				if _, exists := controlIndex[strings.ToLower(trimmedRel)]; !exists {
					ve.addViolation(relPrefix, "UNRESOLVED_REFERENCE",
						fmt.Sprintf("control %q references non-existent related control %q", ctrlID, trimmedRel))
				}
			}
		}
	}

	if ve.HasViolations() {
		// Deterministic sorting of violations for reproducibility
		sort.SliceStable(ve.Violations, func(i, j int) bool {
			if ve.Violations[i].Field != ve.Violations[j].Field {
				return ve.Violations[i].Field < ve.Violations[j].Field
			}
			return ve.Violations[i].Code < ve.Violations[j].Code
		})
		return ve
	}

	return nil
}

func isSupportedSchemaVersion(v string) bool {
	switch strings.TrimSpace(v) {
	case SchemaVersion1_0, SchemaVersion1_0_0, SchemaVersion1:
		return true
	default:
		return false
	}
}

func validateMetadataValues(fieldPrefix string, meta map[string]any, ve *ValidationError) {
	if len(meta) == 0 {
		return
	}
	for k, v := range meta {
		kTrimmed := strings.TrimSpace(k)
		if kTrimmed == "" {
			ve.addViolation(fieldPrefix, "EMPTY_METADATA_KEY", "metadata key cannot be empty")
			continue
		}
		if v == nil {
			continue
		}
		// Ensure metadata values are serializable primitives or nested maps/slices
		switch val := v.(type) {
		case string, bool, int, int32, int64, float32, float64:
			// valid scalar
		case []any, []string:
			// valid slice
		case map[string]any:
			validateMetadataValues(fmt.Sprintf("%s.%s", fieldPrefix, k), val, ve)
		default:
			ve.addViolation(fmt.Sprintf("%s.%s", fieldPrefix, k), "UNSUPPORTED_TYPE",
				fmt.Sprintf("unsupported metadata value type %T", val))
		}
	}
}
