package compliance

import (
	"strings"
)

// Supported catalog schema versions.
const (
	SchemaVersion1_0   = "1.0"
	SchemaVersion1_0_0 = "1.0.0"
	SchemaVersion1     = "1"
)

// DefaultSchemaVersion is the canonical default catalog schema version for FELIX.
const DefaultSchemaVersion = SchemaVersion1_0

// MaxCatalogSizeBytes defines the maximum allowed size for a catalog payload (10 MB).
const MaxCatalogSizeBytes = 10 * 1024 * 1024

// MaxNestingDepth defines the maximum allowable object/array nesting depth to prevent stack exhaustion.
const MaxNestingDepth = 32

// ControlStatus represents the lifecycle state of a compliance control definition.
type ControlStatus string

const (
	// StatusActive represents a current, enforceable compliance control.
	StatusActive ControlStatus = "active"

	// StatusDeprecated represents a retired or superseded control retained for historical traceability.
	StatusDeprecated ControlStatus = "deprecated"

	// StatusDraft represents a proposed or experimental control not yet formally enacted.
	StatusDraft ControlStatus = "draft"
)

// CanonicalControlStatus normalizes and validates a control status string.
// If the status is empty, it defaults to StatusActive.
func CanonicalControlStatus(s string) (ControlStatus, bool) {
	trimmed := strings.ToLower(strings.TrimSpace(s))
	switch trimmed {
	case "active", "":
		return StatusActive, true
	case "deprecated":
		return StatusDeprecated, true
	case "draft":
		return StatusDraft, true
	default:
		return "", false
	}
}

// CatalogSource documents the provenance, authoritative source, publisher, and licensing of a control catalog.
type CatalogSource struct {
	Name            string `json:"name,omitempty"`
	URL             string `json:"url,omitempty"`
	Publisher       string `json:"publisher,omitempty"`
	License         string `json:"license,omitempty"`
	IsAuthoritative bool   `json:"is_authoritative,omitempty"`
	Limitations     string `json:"limitations,omitempty"`
}

// ControlReference links a control definition to an external standard, clause, or authoritative URI.
type ControlReference struct {
	Source      string `json:"source,omitempty"`
	URI         string `json:"uri,omitempty"`
	Section     string `json:"section,omitempty"`
	Description string `json:"description,omitempty"`
}

// Control represents an individual compliance requirement, benchmark item, or operational security control.
type Control struct {
	ID              string             `json:"id"`
	Title           string             `json:"title"`
	Description     string             `json:"description"`
	Status          ControlStatus      `json:"status,omitempty"`
	Category        string             `json:"category,omitempty"`
	Severity        string             `json:"severity,omitempty"`
	References      []ControlReference `json:"references,omitempty"`
	RelatedControls []string           `json:"related_controls,omitempty"`
	Metadata        map[string]any     `json:"metadata,omitempty"`
}

// ControlCatalog represents a complete, self-contained compliance control catalog.
// It serves as the single source of truth for benchmark requirements and control definitions.
type ControlCatalog struct {
	SchemaVersion string         `json:"schema_version"`
	ID            string         `json:"id"`
	Title         string         `json:"title"`
	Version       string         `json:"version"`
	Framework     string         `json:"framework,omitempty"`
	Description   string         `json:"description,omitempty"`
	Source        *CatalogSource `json:"source,omitempty"`
	Controls      []Control      `json:"controls"`
	Metadata      map[string]any `json:"metadata,omitempty"`
}

// Identity returns the unique, version-qualified identity for the catalog.
// Format: "<id>:<version>" or "<id>" if version is unspecified.
func (c *ControlCatalog) Identity() string {
	if c == nil {
		return ""
	}
	id := strings.TrimSpace(c.ID)
	ver := strings.TrimSpace(c.Version)
	if id == "" {
		return ""
	}
	if ver == "" {
		return id
	}
	return id + ":" + ver
}

// LimitationsNotice returns an explicit statement of source, authority, and accreditation boundaries.
// Structural validation guarantees schema conformity but does not certify external audit compliance.
func (c *ControlCatalog) LimitationsNotice() string {
	var sb strings.Builder
	sb.WriteString("FELIX Control Catalog Notice: Structural and semantic validation certifies ")
	sb.WriteString("that this catalog satisfies the FELIX compliance schema. ")
	sb.WriteString("Validation does NOT constitute official framework certification, accreditation by standard bodies, ")
	sb.WriteString("or verification that assessed target systems satisfy any control requirements.")
	if c != nil && c.Source != nil && c.Source.Limitations != "" {
		sb.WriteString(" Source notes: ")
		sb.WriteString(strings.TrimSpace(c.Source.Limitations))
	}
	return sb.String()
}
