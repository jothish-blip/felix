package compliance

import (
	"fmt"
	"strings"
)

// MappingValidationError represents one or more validation errors on a MappingRuleSet.
type MappingValidationError struct {
	RuleSetID  string           `json:"ruleset_id,omitempty"`
	Violations []FieldViolation `json:"violations"`
}

// Error returns a formatted, deterministic string of all validation violations.
func (ve *MappingValidationError) Error() string {
	if ve == nil || len(ve.Violations) == 0 {
		return "valid mapping rule set"
	}
	var sb strings.Builder
	prefix := "mapping rule set validation failed"
	if ve.RuleSetID != "" {
		prefix = fmt.Sprintf("mapping rule set %q validation failed", ve.RuleSetID)
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
func (ve *MappingValidationError) HasViolations() bool {
	return ve != nil && len(ve.Violations) > 0
}

func (ve *MappingValidationError) addViolation(field, code, message string) {
	ve.Violations = append(ve.Violations, FieldViolation{
		Field:   field,
		Code:    code,
		Message: message,
	})
}

// ValidateMappingRuleSet validates a MappingRuleSet against FELIX schema rules, internal consistency,
// unique rule identifiers, relationship types, confidence bounds, and optional target catalog controls.
func ValidateMappingRuleSet(rs *MappingRuleSet, cat *ControlCatalog) error {
	if rs == nil {
		return &MappingValidationError{
			Violations: []FieldViolation{
				{Field: "ruleset", Code: "NIL_RULESET", Message: "mapping rule set cannot be nil"},
			},
		}
	}

	ve := &MappingValidationError{RuleSetID: strings.TrimSpace(rs.ID)}

	// 1. Schema Version Validation
	schemaVer := strings.TrimSpace(rs.SchemaVersion)
	if schemaVer == "" {
		ve.addViolation("schema_version", "REQUIRED_FIELD", "schema_version is required")
	} else if !isSupportedSchemaVersion(schemaVer) {
		ve.addViolation("schema_version", "UNSUPPORTED_VERSION",
			fmt.Sprintf("unsupported schema_version %q; supported versions: %s, %s, %s",
				schemaVer, SchemaVersion1_0, SchemaVersion1_0_0, SchemaVersion1))
	}

	// 2. RuleSet ID Validation
	rsID := strings.TrimSpace(rs.ID)
	if rsID == "" {
		ve.addViolation("id", "REQUIRED_FIELD", "mapping rule set identifier 'id' is required")
	} else if !idPattern.MatchString(rsID) {
		ve.addViolation("id", "INVALID_FORMAT",
			fmt.Sprintf("mapping rule set identifier %q contains invalid characters; must match alphanumeric or [-._:]", rsID))
	}

	// 3. Title Validation
	if strings.TrimSpace(rs.Title) == "" {
		ve.addViolation("title", "REQUIRED_FIELD", "title is required")
	}

	// 4. Version Validation
	if strings.TrimSpace(rs.Version) == "" {
		ve.addViolation("version", "REQUIRED_FIELD", "version is required")
	}

	// 5. Target Catalog Compatibility (if catalog provided)
	var validControls map[string]bool
	if cat != nil {
		if strings.TrimSpace(cat.ID) != "" && strings.TrimSpace(rs.TargetCatalogID) != "" &&
			!strings.EqualFold(strings.TrimSpace(rs.TargetCatalogID), strings.TrimSpace(cat.ID)) {
			ve.addViolation("target_catalog_id", "CATALOG_MISMATCH",
				fmt.Sprintf("ruleset target_catalog_id %q does not match catalog ID %q", rs.TargetCatalogID, cat.ID))
		}

		if strings.TrimSpace(cat.Version) != "" && strings.TrimSpace(rs.TargetCatalogVersion) != "" &&
			rs.TargetCatalogVersion != "*" &&
			!strings.EqualFold(strings.TrimSpace(rs.TargetCatalogVersion), strings.TrimSpace(cat.Version)) {
			ve.addViolation("target_catalog_version", "VERSION_MISMATCH",
				fmt.Sprintf("ruleset target_catalog_version %q does not match catalog version %q", rs.TargetCatalogVersion, cat.Version))
		}

		validControls = make(map[string]bool, len(cat.Controls))
		for _, ctrl := range cat.Controls {
			validControls[strings.TrimSpace(ctrl.ID)] = true
		}
	}

	// 6. Rules Validation
	seenRuleIDs := make(map[string]int, len(rs.Rules))
	seenMappingDefs := make(map[string]string, len(rs.Rules))

	for i, rule := range rs.Rules {
		prefix := fmt.Sprintf("rules[%d]", i)

		// Rule ID
		rID := strings.TrimSpace(rule.ID)
		if rID == "" {
			ve.addViolation(prefix+".id", "REQUIRED_FIELD", "rule id is required")
		} else if !idPattern.MatchString(rID) {
			ve.addViolation(prefix+".id", "INVALID_FORMAT",
				fmt.Sprintf("rule id %q contains invalid characters; must match alphanumeric or [-._:]", rID))
		} else {
			if prevIdx, seen := seenRuleIDs[rID]; seen {
				ve.addViolation(prefix+".id", "DUPLICATE_RULE_ID",
					fmt.Sprintf("duplicate rule ID %q (previously defined at rules[%d])", rID, prevIdx))
			} else {
				seenRuleIDs[rID] = i
			}
		}

		// Source matching requirement: at least one of SourceRuleID or SourceCategory must be present
		srcRule := strings.TrimSpace(rule.SourceRuleID)
		srcCat := strings.TrimSpace(rule.SourceCategory)
		if srcRule == "" && srcCat == "" {
			ve.addViolation(prefix, "MISSING_SOURCE",
				fmt.Sprintf("rule %q must specify at least one of source_rule_id or source_category", rID))
		}

		// Target Control ID
		tgtCtrl := strings.TrimSpace(rule.TargetControlID)
		if tgtCtrl == "" {
			ve.addViolation(prefix+".target_control_id", "REQUIRED_FIELD",
				fmt.Sprintf("rule %q target_control_id is required", rID))
		} else if cat != nil && !validControls[tgtCtrl] {
			ve.addViolation(prefix+".target_control_id", "UNKNOWN_CONTROL",
				fmt.Sprintf("rule %q references unknown target control ID %q in catalog %q", rID, tgtCtrl, cat.ID))
		}

		// Relationship
		relStr := strings.TrimSpace(string(rule.Relationship))
		if relStr == "" {
			ve.addViolation(prefix+".relationship", "REQUIRED_FIELD",
				fmt.Sprintf("rule %q relationship is required", rID))
		} else {
			_, ok := CanonicalMappingRelationship(relStr)
			if !ok {
				ve.addViolation(prefix+".relationship", "UNSUPPORTED_RELATIONSHIP",
					fmt.Sprintf("rule %q has unsupported relationship %q; supported: direct, partial_evidence, indirect", rID, relStr))
			}
		}

		// Confidence bounds: must be between 0.0 and 1.0 (if specified)
		if rule.Confidence < 0.0 || rule.Confidence > 1.0 {
			ve.addViolation(prefix+".confidence", "INVALID_CONFIDENCE",
				fmt.Sprintf("rule %q confidence must be between 0.0 and 1.0, got %v", rID, rule.Confidence))
		}

		// Rationale
		if strings.TrimSpace(rule.Rationale) == "" {
			ve.addViolation(prefix+".rationale", "REQUIRED_FIELD",
				fmt.Sprintf("rule %q rationale is required", rID))
		}

		// Target catalog ID compatibility within rule
		if rule.TargetCatalogID != "" {
			ruleTgtCat := strings.TrimSpace(rule.TargetCatalogID)
			if rs.TargetCatalogID != "" && !strings.EqualFold(ruleTgtCat, strings.TrimSpace(rs.TargetCatalogID)) {
				ve.addViolation(prefix+".target_catalog_id", "CATALOG_MISMATCH",
					fmt.Sprintf("rule %q target_catalog_id %q does not match ruleset target_catalog_id %q", rID, ruleTgtCat, rs.TargetCatalogID))
			}
			if cat != nil && strings.TrimSpace(cat.ID) != "" && !strings.EqualFold(ruleTgtCat, strings.TrimSpace(cat.ID)) {
				ve.addViolation(prefix+".target_catalog_id", "CATALOG_MISMATCH",
					fmt.Sprintf("rule %q target_catalog_id %q does not match catalog ID %q", rID, ruleTgtCat, cat.ID))
			}
		}

		// Duplicate Mapping Rule Detection (same source, target control, and relationship)
		if rID != "" && tgtCtrl != "" && relStr != "" {
			mappingKey := fmt.Sprintf("%s|%s|%s|%s",
				strings.ToLower(srcRule),
				strings.ToLower(srcCat),
				strings.ToLower(tgtCtrl),
				strings.ToLower(relStr),
			)
			if prevRuleID, exists := seenMappingDefs[mappingKey]; exists {
				ve.addViolation(prefix, "DUPLICATE_MAPPING_RULE",
					fmt.Sprintf("duplicate mapping rule: rule %q has identical mapping definition to rule %q", rID, prevRuleID))
			} else {
				seenMappingDefs[mappingKey] = rID
			}
		}
	}

	if ve.HasViolations() {
		return ve
	}
	return nil
}
