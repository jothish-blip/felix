package compliance

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
	"strings"
	"time"
)

// MappingRelationship defines the relationship between a security finding and a compliance control.
// Invariant: Mapping represents technical relevance or evidence linkage; it NEVER represents a compliance evaluation state.
type MappingRelationship string

const (
	// RelationshipDirect indicates the finding directly demonstrates technical exposure or non-conformity against the control requirement.
	RelationshipDirect MappingRelationship = "direct"

	// RelationshipPartialEvidence indicates the finding provides partial evidence relevant to the control requirement.
	RelationshipPartialEvidence MappingRelationship = "partial_evidence"

	// RelationshipIndirect indicates the finding is contextual or indirectly related to the control domain.
	RelationshipIndirect MappingRelationship = "indirect"
)

// CanonicalMappingRelationship normalizes and validates a mapping relationship string.
func CanonicalMappingRelationship(s string) (MappingRelationship, bool) {
	trimmed := strings.ToLower(strings.TrimSpace(s))
	switch trimmed {
	case "direct":
		return RelationshipDirect, true
	case "partial_evidence":
		return RelationshipPartialEvidence, true
	case "indirect":
		return RelationshipIndirect, true
	default:
		return "", false
	}
}

// MappingRule specifies how a class of security findings associates with a specific compliance control.
type MappingRule struct {
	ID                   string              `json:"id"`
	SourceRuleID         string              `json:"source_rule_id,omitempty"`
	SourceCategory       string              `json:"source_category,omitempty"`
	TargetCatalogID      string              `json:"target_catalog_id,omitempty"`
	TargetCatalogVersion string              `json:"target_catalog_version,omitempty"`
	TargetControlID      string              `json:"target_control_id"`
	Relationship         MappingRelationship `json:"relationship"`
	Rationale            string              `json:"rationale"`
	Confidence           float64             `json:"confidence,omitempty"`
	Metadata             map[string]any      `json:"metadata,omitempty"`
}

// MappingRuleSet defines a versioned, self-contained collection of finding-to-control mapping rules.
type MappingRuleSet struct {
	SchemaVersion        string         `json:"schema_version"`
	ID                   string         `json:"id"`
	Title                string         `json:"title"`
	Version              string         `json:"version"`
	TargetCatalogID      string         `json:"target_catalog_id,omitempty"`
	TargetCatalogVersion string         `json:"target_catalog_version,omitempty"`
	Rules                []MappingRule  `json:"rules"`
	Metadata             map[string]any `json:"metadata,omitempty"`
}

// Identity returns the unique, version-qualified identity for the ruleset.
func (rs *MappingRuleSet) Identity() string {
	if rs == nil {
		return ""
	}
	id := strings.TrimSpace(rs.ID)
	ver := strings.TrimSpace(rs.Version)
	if id == "" {
		return ""
	}
	if ver == "" {
		return id
	}
	return id + ":" + ver
}

// FindingControlMapping represents an instantiated relevance linkage between an observed finding and a compliance control.
// This structure explicitly does NOT contain compliance evaluation verdicts (e.g. compliant, non_compliant, pass, fail).
type FindingControlMapping struct {
	MappingID          string              `json:"mapping_id"`
	RuleID             string              `json:"rule_id"`
	FindingID          string              `json:"finding_id"`
	FindingRuleID      string              `json:"finding_rule_id,omitempty"`
	FindingFingerprint string              `json:"finding_fingerprint,omitempty"`
	FindingSeverity    string              `json:"finding_severity,omitempty"`
	FindingLocation    string              `json:"finding_location,omitempty"`
	CatalogID          string              `json:"catalog_id"`
	CatalogVersion     string              `json:"catalog_version,omitempty"`
	ControlID          string              `json:"control_id"`
	Relationship       MappingRelationship `json:"relationship"`
	Rationale          string              `json:"rationale"`
	Confidence         float64             `json:"confidence"`
	HasEvidence        bool                `json:"has_evidence"`
	EvidenceLocation   string              `json:"evidence_location,omitempty"`
	MappingVersion     string              `json:"mapping_version,omitempty"`
	CreatedAt          time.Time           `json:"created_at,omitempty"`
}

// UnmappedFinding documents a security finding for which no mapping rule was applicable in the target catalog.
type UnmappedFinding struct {
	FindingID string `json:"finding_id"`
	RuleID    string `json:"rule_id,omitempty"`
	Category  string `json:"category,omitempty"`
	Title     string `json:"title,omitempty"`
	Severity  string `json:"severity,omitempty"`
	Reason    string `json:"reason"`
}

// MappingCoverage summarizes quantitative metrics regarding finding-to-control mapping coverage.
// Notice: This measures mapping rule coverage over findings, NOT compliance or audit satisfaction.
type MappingCoverage struct {
	TotalFindings         int      `json:"total_findings"`
	MappedFindings        int      `json:"mapped_findings"`
	UnmappedFindings      int      `json:"unmapped_findings"`
	AmbiguousFindings     int      `json:"ambiguous_findings"`
	TotalMappings         int      `json:"total_mappings"`
	MultiMappedFindings   int      `json:"multi_mapped_findings"`
	ReferencedControls    []string `json:"referenced_controls"`
	CatalogID             string   `json:"catalog_id"`
	CatalogVersion        string   `json:"catalog_version,omitempty"`
	MappingRuleSetID      string   `json:"mapping_ruleset_id,omitempty"`
	MappingRuleSetVersion string   `json:"mapping_ruleset_version,omitempty"`
}

// MappingResult contains the complete output of evaluating a set of findings against a control catalog with a mapping ruleset.
type MappingResult struct {
	Mappings               []FindingControlMapping `json:"mappings"`
	Unmapped               []UnmappedFinding       `json:"unmapped,omitempty"`
	Coverage               MappingCoverage         `json:"coverage"`
	CatalogIdentity        string                  `json:"catalog_identity"`
	CatalogDigest          string                  `json:"catalog_digest,omitempty"`
	MappingRuleSetIdentity string                  `json:"mapping_ruleset_identity,omitempty"`
	MappingRuleSetDigest   string                  `json:"mapping_ruleset_digest,omitempty"`
	LimitationsNotice      string                  `json:"limitations_notice"`
}

// MappingLimitationsNotice returns the standard disclaimer establishing that mapping != compliance evaluation.
func MappingLimitationsNotice() string {
	return "FELIX Finding-to-Control Mapping Notice: A mapping indicates that a security finding is relevant to a compliance control requirement. A mapping does NOT constitute a compliance evaluation, audit determination, certification, or proof that a control is satisfied or violated. Full compliance evaluation is performed in subsequent evaluation phases."
}

// Canonical structures for deterministic hashing of MappingRuleSet
type canonicalRuleSet struct {
	SchemaVersion        string          `json:"schema_version"`
	ID                   string          `json:"id"`
	Title                string          `json:"title"`
	Version              string          `json:"version"`
	TargetCatalogID      string          `json:"target_catalog_id,omitempty"`
	TargetCatalogVersion string          `json:"target_catalog_version,omitempty"`
	Rules                []canonicalRule `json:"rules"`
	Metadata             map[string]any  `json:"metadata,omitempty"`
}

type canonicalRule struct {
	ID                   string         `json:"id"`
	SourceRuleID         string         `json:"source_rule_id,omitempty"`
	SourceCategory       string         `json:"source_category,omitempty"`
	TargetCatalogID      string         `json:"target_catalog_id,omitempty"`
	TargetCatalogVersion string         `json:"target_catalog_version,omitempty"`
	TargetControlID      string         `json:"target_control_id"`
	Relationship         string         `json:"relationship"`
	Rationale            string         `json:"rationale"`
	Confidence           float64        `json:"confidence,omitempty"`
	Metadata             map[string]any `json:"metadata,omitempty"`
}

func buildCanonicalRuleSet(rs *MappingRuleSet) canonicalRuleSet {
	crs := canonicalRuleSet{
		SchemaVersion:        strings.TrimSpace(rs.SchemaVersion),
		ID:                   strings.TrimSpace(rs.ID),
		Title:                strings.TrimSpace(rs.Title),
		Version:              strings.TrimSpace(rs.Version),
		TargetCatalogID:      strings.TrimSpace(rs.TargetCatalogID),
		TargetCatalogVersion: strings.TrimSpace(rs.TargetCatalogVersion),
		Metadata:             canonicalizeMetadata(rs.Metadata),
	}

	if len(rs.Rules) > 0 {
		crs.Rules = make([]canonicalRule, len(rs.Rules))
		for i, r := range rs.Rules {
			rel, _ := CanonicalMappingRelationship(string(r.Relationship))
			crs.Rules[i] = canonicalRule{
				ID:                   strings.TrimSpace(r.ID),
				SourceRuleID:         strings.TrimSpace(r.SourceRuleID),
				SourceCategory:       strings.TrimSpace(r.SourceCategory),
				TargetCatalogID:      strings.TrimSpace(r.TargetCatalogID),
				TargetCatalogVersion: strings.TrimSpace(r.TargetCatalogVersion),
				TargetControlID:      strings.TrimSpace(r.TargetControlID),
				Relationship:         string(rel),
				Rationale:            strings.TrimSpace(r.Rationale),
				Confidence:           r.Confidence,
				Metadata:             canonicalizeMetadata(r.Metadata),
			}
		}

		// Sort rules deterministically by ID, TargetControlID, SourceRuleID
		sort.SliceStable(crs.Rules, func(a, b int) bool {
			if crs.Rules[a].ID != crs.Rules[b].ID {
				return crs.Rules[a].ID < crs.Rules[b].ID
			}
			if crs.Rules[a].TargetControlID != crs.Rules[b].TargetControlID {
				return crs.Rules[a].TargetControlID < crs.Rules[b].TargetControlID
			}
			return crs.Rules[a].SourceRuleID < crs.Rules[b].SourceRuleID
		})
	}

	return crs
}

// Digest computes a deterministic SHA-256 digest of the canonicalized mapping ruleset content.
func (rs *MappingRuleSet) Digest() string {
	if rs == nil {
		return ""
	}
	canonical := buildCanonicalRuleSet(rs)
	data, err := json.Marshal(canonical)
	if err != nil {
		return ""
	}
	h := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(h[:])
}
