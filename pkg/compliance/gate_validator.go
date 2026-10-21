package compliance

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
)

var (
	// ErrInvalidGatePolicy indicates that a compliance gate policy fails schema or semantic validation.
	ErrInvalidGatePolicy = errors.New("invalid compliance gate policy")
)

// ValidateGatePolicy performs strict validation on a ComplianceGatePolicy instance.
func ValidateGatePolicy(p *ComplianceGatePolicy) error {
	if p == nil {
		return fmt.Errorf("%w: policy cannot be nil", ErrInvalidGatePolicy)
	}

	// 1. Schema Version
	v := strings.TrimSpace(p.SchemaVersion)
	if v == "" {
		return fmt.Errorf("%w: schema_version is required (supported: %q, %q)", ErrInvalidGatePolicy, "1.0", "1")
	}
	if v != "1.0" && v != "1" {
		return fmt.Errorf("%w: unsupported schema_version %q (supported: %q, %q)", ErrInvalidGatePolicy, p.SchemaVersion, "1.0", "1")
	}

	// 2. ID and Version
	if strings.TrimSpace(p.ID) == "" {
		return fmt.Errorf("%w: policy id cannot be empty", ErrInvalidGatePolicy)
	}
	if strings.TrimSpace(p.Version) == "" {
		return fmt.Errorf("%w: policy version cannot be empty", ErrInvalidGatePolicy)
	}

	// 3. Enum validations
	if p.PartiallyCompliantPolicy != "" {
		pc := strings.ToLower(strings.TrimSpace(p.PartiallyCompliantPolicy))
		if pc != "fail" && pc != "allow" {
			return fmt.Errorf("%w: invalid partially_compliant_policy %q: must be 'fail' or 'allow'", ErrInvalidGatePolicy, p.PartiallyCompliantPolicy)
		}
	}

	if p.UnassessedPolicy != "" {
		up := strings.ToLower(strings.TrimSpace(p.UnassessedPolicy))
		if up != "fail_closed" && up != "indeterminate" && up != "allow" {
			return fmt.Errorf("%w: invalid unassessed_policy %q: must be 'fail_closed', 'indeterminate', or 'allow'", ErrInvalidGatePolicy, p.UnassessedPolicy)
		}
	}

	if p.InsufficientEvidencePolicy != "" {
		ip := strings.ToLower(strings.TrimSpace(p.InsufficientEvidencePolicy))
		if ip != "fail_closed" && ip != "indeterminate" && ip != "allow" {
			return fmt.Errorf("%w: invalid insufficient_evidence_policy %q: must be 'fail_closed', 'indeterminate', or 'allow'", ErrInvalidGatePolicy, p.InsufficientEvidencePolicy)
		}
	}

	if p.NotApplicablePolicy != "" {
		nap := strings.ToLower(strings.TrimSpace(p.NotApplicablePolicy))
		if nap != "ignore" && nap != "fail" {
			return fmt.Errorf("%w: invalid not_applicable_policy %q: must be 'ignore' or 'fail'", ErrInvalidGatePolicy, p.NotApplicablePolicy)
		}
	}

	// 4. Threshold limits
	if p.MaxNonCompliant != nil && *p.MaxNonCompliant < 0 {
		return fmt.Errorf("%w: max_non_compliant cannot be negative (%d)", ErrInvalidGatePolicy, *p.MaxNonCompliant)
	}
	if p.MaxPartiallyCompliant != nil && *p.MaxPartiallyCompliant < 0 {
		return fmt.Errorf("%w: max_partially_compliant cannot be negative (%d)", ErrInvalidGatePolicy, *p.MaxPartiallyCompliant)
	}
	if p.MaxOverdueSLA != nil && *p.MaxOverdueSLA < 0 {
		return fmt.Errorf("%w: max_overdue_sla cannot be negative (%d)", ErrInvalidGatePolicy, *p.MaxOverdueSLA)
	}

	// 5. Percentages
	if p.MinCompliancePercent != nil {
		pct := *p.MinCompliancePercent
		if pct < 0.0 || pct > 100.0 {
			return fmt.Errorf("%w: min_compliance_percent must be between 0.0 and 100.0 (got %.2f)", ErrInvalidGatePolicy, pct)
		}
	}
	if p.MinAssessedPercent != nil {
		pct := *p.MinAssessedPercent
		if pct < 0.0 || pct > 100.0 {
			return fmt.Errorf("%w: min_assessed_percent must be between 0.0 and 100.0 (got %.2f)", ErrInvalidGatePolicy, pct)
		}
	}

	// 6. Severity ceiling
	if p.MaxFindingSeverity != "" {
		sev := strings.ToUpper(strings.TrimSpace(p.MaxFindingSeverity))
		found := false
		for _, s := range SupportedSeverities {
			if s == sev {
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("%w: invalid max_finding_severity %q: must be one of CRITICAL, HIGH, MEDIUM, LOW, INFO", ErrInvalidGatePolicy, p.MaxFindingSeverity)
		}
	}

	return nil
}

// LoadGatePolicy loads and strictly validates a ComplianceGatePolicy from a file.
func LoadGatePolicy(path string) (*ComplianceGatePolicy, error) {
	cleanPath := strings.TrimSpace(path)
	if cleanPath == "" {
		return nil, fmt.Errorf("%w: policy path cannot be empty", ErrInvalidGatePolicy)
	}

	info, err := os.Stat(cleanPath)
	if err != nil {
		return nil, fmt.Errorf("failed opening gate policy file %q: %w", cleanPath, err)
	}
	if info.Size() > 5*1024*1024 {
		return nil, fmt.Errorf("%w: gate policy file %q exceeds maximum allowed size (5MB)", ErrInvalidGatePolicy, cleanPath)
	}

	data, err := os.ReadFile(cleanPath)
	if err != nil {
		return nil, fmt.Errorf("failed reading gate policy file %q: %w", cleanPath, err)
	}

	return LoadGatePolicyFromBytes(data)
}

// LoadGatePolicyFromBytes unmarshals and validates a ComplianceGatePolicy from JSON or simple YAML.
func LoadGatePolicyFromBytes(data []byte) (*ComplianceGatePolicy, error) {
	trimmed := strings.TrimSpace(string(data))
	if len(trimmed) == 0 {
		return nil, fmt.Errorf("%w: gate policy data is empty", ErrInvalidGatePolicy)
	}

	var pol ComplianceGatePolicy

	if strings.HasPrefix(trimmed, "{") {
		// Strict JSON unmarshaling with unknown fields rejection
		dec := json.NewDecoder(bytes.NewReader(data))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&pol); err != nil {
			return nil, fmt.Errorf("%w: malformed JSON policy: %w", ErrInvalidGatePolicy, err)
		}
	} else {
		// Attempt standard JSON first
		dec := json.NewDecoder(bytes.NewReader(data))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&pol); err == nil && pol.SchemaVersion != "" {
			// Succeeded with JSON
		} else {
			// Parse YAML
			yamlPol, err := unmarshalYAMLGatePolicy(data)
			if err != nil {
				return nil, fmt.Errorf("%w: malformed policy document (not valid JSON or YAML): %w", ErrInvalidGatePolicy, err)
			}
			pol = *yamlPol
		}
	}

	if err := ValidateGatePolicy(&pol); err != nil {
		return nil, err
	}

	return &pol, nil
}

// unmarshalYAMLGatePolicy parses basic YAML key-value and list structures for gate policy.
func unmarshalYAMLGatePolicy(data []byte) (*ComplianceGatePolicy, error) {
	lines := strings.Split(string(data), "\n")
	pol := &ComplianceGatePolicy{}

	var currentList *[]string

	for lineIdx, rawLine := range lines {
		line := rawLine
		if commentIdx := strings.Index(line, "#"); commentIdx != -1 {
			line = line[:commentIdx]
		}
		trimmed := strings.TrimSpace(line)
		if len(trimmed) == 0 {
			continue
		}

		// Check for list item continuation
		if strings.HasPrefix(trimmed, "- ") {
			if currentList == nil {
				return nil, fmt.Errorf("line %d: unexpected list element outside list field", lineIdx+1)
			}
			val := strings.Trim(strings.TrimSpace(trimmed[2:]), `"'`)
			*currentList = append(*currentList, val)
			continue
		}

		// Field header or key: value
		colonIdx := strings.Index(trimmed, ":")
		if colonIdx == -1 {
			return nil, fmt.Errorf("line %d: syntax error, expected 'key: value'", lineIdx+1)
		}

		key := strings.ToLower(strings.TrimSpace(trimmed[:colonIdx]))
		val := strings.Trim(strings.TrimSpace(trimmed[colonIdx+1:]), `"'`)

		// Reset active list
		currentList = nil

		switch key {
		case "schema_version":
			pol.SchemaVersion = val
		case "id":
			pol.ID = val
		case "name":
			pol.Name = val
		case "version":
			pol.Version = val
		case "description":
			pol.Description = val
		case "target_catalog":
			pol.TargetCatalog = val
		case "target_catalog_version":
			pol.TargetCatalogVersion = val
		case "enforced_controls":
			currentList = &pol.EnforcedControls
			if val != "" && val != "[]" {
				pol.EnforcedControls = parseYAMLInlineList(val)
			}
		case "enforced_categories":
			currentList = &pol.EnforcedCategories
			if val != "" && val != "[]" {
				pol.EnforcedCategories = parseYAMLInlineList(val)
			}
		case "partially_compliant_policy":
			pol.PartiallyCompliantPolicy = val
		case "unassessed_policy":
			pol.UnassessedPolicy = val
		case "insufficient_evidence_policy":
			pol.InsufficientEvidencePolicy = val
		case "not_applicable_policy":
			pol.NotApplicablePolicy = val
		case "max_non_compliant":
			n, err := strconv.Atoi(val)
			if err != nil {
				return nil, fmt.Errorf("line %d: invalid integer for max_non_compliant %q", lineIdx+1, val)
			}
			pol.MaxNonCompliant = &n
		case "max_partially_compliant":
			n, err := strconv.Atoi(val)
			if err != nil {
				return nil, fmt.Errorf("line %d: invalid integer for max_partially_compliant %q", lineIdx+1, val)
			}
			pol.MaxPartiallyCompliant = &n
		case "min_compliance_percent":
			f, err := strconv.ParseFloat(val, 64)
			if err != nil {
				return nil, fmt.Errorf("line %d: invalid float for min_compliance_percent %q", lineIdx+1, val)
			}
			pol.MinCompliancePercent = &f
		case "min_assessed_percent":
			f, err := strconv.ParseFloat(val, 64)
			if err != nil {
				return nil, fmt.Errorf("line %d: invalid float for min_assessed_percent %q", lineIdx+1, val)
			}
			pol.MinAssessedPercent = &f
		case "max_finding_severity":
			pol.MaxFindingSeverity = val
		case "require_integrity":
			b, err := strconv.ParseBool(val)
			if err != nil {
				return nil, fmt.Errorf("line %d: invalid boolean for require_integrity %q", lineIdx+1, val)
			}
			pol.RequireIntegrity = &b
		case "require_hmac":
			b, err := strconv.ParseBool(val)
			if err != nil {
				return nil, fmt.Errorf("line %d: invalid boolean for require_hmac %q", lineIdx+1, val)
			}
			pol.RequireHMAC = &b
		case "strict_integrity":
			b, err := strconv.ParseBool(val)
			if err != nil {
				return nil, fmt.Errorf("line %d: invalid boolean for strict_integrity %q", lineIdx+1, val)
			}
			pol.StrictIntegrity = &b
		case "fail_on_overdue_sla":
			b, err := strconv.ParseBool(val)
			if err != nil {
				return nil, fmt.Errorf("line %d: invalid boolean for fail_on_overdue_sla %q", lineIdx+1, val)
			}
			pol.FailOnOverdueSLA = &b
		case "max_overdue_sla":
			n, err := strconv.Atoi(val)
			if err != nil {
				return nil, fmt.Errorf("line %d: invalid integer for max_overdue_sla %q", lineIdx+1, val)
			}
			pol.MaxOverdueSLA = &n
		default:
			return nil, fmt.Errorf("line %d: unknown field %q in gate policy", lineIdx+1, key)
		}
	}

	return pol, nil
}

func parseYAMLInlineList(s string) []string {
	trimmed := strings.Trim(strings.TrimSpace(s), "[]")
	if len(trimmed) == 0 {
		return nil
	}
	parts := strings.Split(trimmed, ",")
	res := make([]string, 0, len(parts))
	for _, p := range parts {
		item := strings.Trim(strings.TrimSpace(p), `"'`)
		if len(item) > 0 {
			res = append(res, item)
		}
	}
	return res
}
