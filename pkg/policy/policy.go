package policy

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"

	"felix/pkg/report"
)

// Supported policy schema versions.
const (
	Version1_0 = "1.0"
	Version1   = "1"
)

// ThresholdPolicy represents a versioned, declarative security threshold policy.
// It specifies the maximum permitted finding counts by severity for automated CI/CD gating.
type ThresholdPolicy struct {
	Version         string           `json:"version"`
	Name            string           `json:"name,omitempty"`
	Description     string           `json:"description,omitempty"`
	MaxCritical     *int             `json:"max_critical,omitempty"`
	MaxHigh         *int             `json:"max_high,omitempty"`
	MaxMedium       *int             `json:"max_medium,omitempty"`
	MaxLow          *int             `json:"max_low,omitempty"`
	Thresholds      map[string]*int  `json:"thresholds,omitempty"`
	FailOnViolation *bool            `json:"fail_on_violation,omitempty"`
	FailOnUnknown   *bool            `json:"fail_on_unknown,omitempty"`
	EvaluationScope string           `json:"evaluation_scope,omitempty"` // "all" (default), "new", "new_and_regressed"
	FailOnNewOnly   *bool            `json:"fail_on_new_only,omitempty"`
}

// ShouldFailOnNewOnly returns true if only NEW findings should trigger policy thresholds.
func (p *ThresholdPolicy) ShouldFailOnNewOnly() bool {
	if p.FailOnNewOnly != nil && *p.FailOnNewOnly {
		return true
	}
	return strings.EqualFold(strings.TrimSpace(p.EvaluationScope), "new")
}

// GetEvaluationScope returns the canonical evaluation scope ("all", "new", "new_and_regressed").
func (p *ThresholdPolicy) GetEvaluationScope() string {
	s := strings.ToLower(strings.TrimSpace(p.EvaluationScope))
	if s == "" {
		if p.FailOnNewOnly != nil && *p.FailOnNewOnly {
			return "new"
		}
		return "all"
	}
	return s
}

// ShouldFailOnViolation returns true if threshold violations should trigger a policy failure.
// Defaults to true when omitted.
func (p *ThresholdPolicy) ShouldFailOnViolation() bool {
	if p.FailOnViolation == nil {
		return true
	}
	return *p.FailOnViolation
}

// ShouldFailOnUnknown returns true if findings with unparseable or unrecognized severities
// should trigger a policy failure. Defaults to false (unrecognized findings are tracked and explained).
func (p *ThresholdPolicy) ShouldFailOnUnknown() bool {
	if p.FailOnUnknown == nil {
		return false
	}
	return *p.FailOnUnknown
}

// ParseSeverity standardizes a raw severity string into a canonical FELIX severity
// and explicitly reports whether the raw string was a recognized severity tier.
//
// In conformance with the FELIX honest finding model:
// Findings without a recognized severity are NEVER silently coerced to LOW or INFO.
func ParseSeverity(raw string) (canonical string, recognized bool) {
	s := strings.ToUpper(strings.TrimSpace(raw))
	switch s {
	case report.SeverityCritical, "CRIT":
		return report.SeverityCritical, true
	case report.SeverityHigh:
		return report.SeverityHigh, true
	case report.SeverityMedium, "MED", "MODERATE":
		return report.SeverityMedium, true
	case report.SeverityLow:
		return report.SeverityLow, true
	case report.SeverityInfo, "INFORMATIONAL", "NOTE":
		return report.SeverityInfo, true
	case report.SeverityUnknown:
		return report.SeverityUnknown, false
	default:
		if s == "" {
			return report.SeverityUnknown, false
		}
		return report.SeverityUnknown, false
	}
}

// Validate checks that the policy conforms to FELIX policy schema constraints:
// - Supported version (1.0 or 1).
// - Non-negative threshold limits.
// - Canonical severity names in thresholds map.
// - No conflicting definitions between top-level (e.g. max_critical) and thresholds map.
func (p *ThresholdPolicy) Validate() error {
	v := strings.TrimSpace(p.Version)
	if v == "" {
		return fmt.Errorf("policy version is required (supported: %s, %s)", Version1_0, Version1)
	}
	if v != Version1_0 && v != Version1 {
		return fmt.Errorf("unsupported policy version %q (supported: %s, %s)", p.Version, Version1_0, Version1)
	}

	if p.EvaluationScope != "" {
		s := strings.ToLower(strings.TrimSpace(p.EvaluationScope))
		if s != "all" && s != "new" && s != "new_and_regressed" {
			return fmt.Errorf("invalid evaluation_scope %q: must be 'all', 'new', or 'new_and_regressed'", p.EvaluationScope)
		}
	}

	// Helper to check negative limits
	checkNonNegative := func(sev string, val *int) error {
		if val != nil && *val < 0 {
			return fmt.Errorf("threshold for severity %s cannot be negative (got %d)", sev, *val)
		}
		return nil
	}

	if err := checkNonNegative(report.SeverityCritical, p.MaxCritical); err != nil {
		return err
	}
	if err := checkNonNegative(report.SeverityHigh, p.MaxHigh); err != nil {
		return err
	}
	if err := checkNonNegative(report.SeverityMedium, p.MaxMedium); err != nil {
		return err
	}
	if err := checkNonNegative(report.SeverityLow, p.MaxLow); err != nil {
		return err
	}

	// Validate thresholds map keys and values
	for rawKey, val := range p.Thresholds {
		normKey := strings.ToUpper(strings.TrimSpace(rawKey))
		switch normKey {
		case report.SeverityCritical, report.SeverityHigh, report.SeverityMedium, report.SeverityLow, report.SeverityInfo, report.SeverityUnknown:
			// Valid canonical severity
		default:
			return fmt.Errorf("invalid severity %q in thresholds map: must be one of CRITICAL, HIGH, MEDIUM, LOW, INFO, UNKNOWN", rawKey)
		}

		if err := checkNonNegative(normKey, val); err != nil {
			return err
		}
	}

	// Check for conflicting definitions between top-level fields and thresholds map
	checkConflict := func(sev string, topVal *int) error {
		if topVal == nil || p.Thresholds == nil {
			return nil
		}
		for rawKey, mapVal := range p.Thresholds {
			if strings.ToUpper(strings.TrimSpace(rawKey)) == sev && mapVal != nil {
				if *topVal != *mapVal {
					return fmt.Errorf("conflicting threshold definition for severity %s: max_%s=%d but thresholds[%s]=%d",
						sev, strings.ToLower(sev), *topVal, rawKey, *mapVal)
				}
			}
		}
		return nil
	}

	if err := checkConflict(report.SeverityCritical, p.MaxCritical); err != nil {
		return err
	}
	if err := checkConflict(report.SeverityHigh, p.MaxHigh); err != nil {
		return err
	}
	if err := checkConflict(report.SeverityMedium, p.MaxMedium); err != nil {
		return err
	}
	if err := checkConflict(report.SeverityLow, p.MaxLow); err != nil {
		return err
	}

	return nil
}

// GetThreshold returns the configured allowed maximum count for a severity.
// If the severity was not configured in the policy, configured will be false.
// This preserves the crucial distinction between:
// - A severity not configured in the policy (configured = false).
// - A severity configured with a maximum of zero (configured = true, limit = 0).
// - A severity configured with a positive maximum (configured = true, limit > 0).
func (p *ThresholdPolicy) GetThreshold(sev string) (limit int, configured bool) {
	norm := strings.ToUpper(strings.TrimSpace(sev))

	// Check explicit top-level fields first
	switch norm {
	case report.SeverityCritical:
		if p.MaxCritical != nil {
			return *p.MaxCritical, true
		}
	case report.SeverityHigh:
		if p.MaxHigh != nil {
			return *p.MaxHigh, true
		}
	case report.SeverityMedium:
		if p.MaxMedium != nil {
			return *p.MaxMedium, true
		}
	case report.SeverityLow:
		if p.MaxLow != nil {
			return *p.MaxLow, true
		}
	}

	// Check thresholds map
	if p.Thresholds != nil {
		for k, v := range p.Thresholds {
			if strings.ToUpper(strings.TrimSpace(k)) == norm && v != nil {
				return *v, true
			}
		}
	}

	return 0, false
}

// NormalizedThresholds returns a deterministic map of all configured severity thresholds.
func (p *ThresholdPolicy) NormalizedThresholds() map[string]int {
	res := make(map[string]int)
	for _, sev := range []string{
		report.SeverityCritical,
		report.SeverityHigh,
		report.SeverityMedium,
		report.SeverityLow,
		report.SeverityInfo,
		report.SeverityUnknown,
	} {
		if limit, ok := p.GetThreshold(sev); ok {
			res[sev] = limit
		}
	}
	return res
}

// Digest returns a deterministic hex-encoded SHA-256 digest of the canonical normalized policy configuration.
func (p *ThresholdPolicy) Digest() string {
	type canonicalPolicy struct {
		Version         string         `json:"version"`
		Name            string         `json:"name"`
		Thresholds      map[string]int `json:"thresholds"`
		FailOnViolation bool           `json:"fail_on_violation"`
		FailOnUnknown   bool           `json:"fail_on_unknown"`
	}

	type canonicalPolicyExtended struct {
		Version         string         `json:"version"`
		Name            string         `json:"name"`
		Thresholds      map[string]int `json:"thresholds"`
		FailOnViolation bool           `json:"fail_on_violation"`
		FailOnUnknown   bool           `json:"fail_on_unknown"`
		EvaluationScope string         `json:"evaluation_scope,omitempty"`
	}

	scope := p.GetEvaluationScope()
	if scope == "all" {
		scope = ""
	}
	cp := canonicalPolicyExtended{
		Version:         strings.TrimSpace(p.Version),
		Name:            strings.TrimSpace(p.Name),
		Thresholds:      p.NormalizedThresholds(),
		FailOnViolation: p.ShouldFailOnViolation(),
		FailOnUnknown:   p.ShouldFailOnUnknown(),
		EvaluationScope: scope,
	}

	bytes, _ := json.Marshal(cp)
	h := sha256.Sum256(bytes)
	return hex.EncodeToString(h[:])
}

// LoadPolicy reads and validates a ThresholdPolicy from a file.
func LoadPolicy(path string) (*ThresholdPolicy, error) {
	cleanPath := strings.TrimSpace(path)
	if cleanPath == "" {
		return nil, fmt.Errorf("policy path cannot be empty")
	}

	data, err := os.ReadFile(cleanPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read policy file %q: %w", cleanPath, err)
	}

	return LoadPolicyFromBytes(data)
}

// LoadPolicyFromBytes unmarshals and validates a ThresholdPolicy from raw JSON or YAML bytes.
func LoadPolicyFromBytes(data []byte) (*ThresholdPolicy, error) {
	trimmed := strings.TrimSpace(string(data))
	if trimmed == "" {
		return nil, fmt.Errorf("empty policy data")
	}

	var pol *ThresholdPolicy
	if strings.HasPrefix(trimmed, "{") {
		var p ThresholdPolicy
		if err := json.Unmarshal(data, &p); err != nil {
			return nil, fmt.Errorf("malformed JSON policy: %w", err)
		}
		pol = &p
	} else {
		// Attempt JSON unmarshaling first
		var p ThresholdPolicy
		if err := json.Unmarshal(data, &p); err == nil && p.Version != "" {
			pol = &p
		} else {
			yamlPol, yamlErr := unmarshalYAMLPolicy(data)
			if yamlErr != nil {
				return nil, fmt.Errorf("malformed policy file: %w", yamlErr)
			}
			pol = yamlPol
		}
	}

	if err := pol.Validate(); err != nil {
		return nil, fmt.Errorf("invalid policy: %w", err)
	}

	return pol, nil
}

// unmarshalYAMLPolicy parses a simple YAML policy document into ThresholdPolicy.
func unmarshalYAMLPolicy(data []byte) (*ThresholdPolicy, error) {
	lines := strings.Split(string(data), "\n")
	pol := &ThresholdPolicy{}
	inThresholdsSection := false

	for lineNum, line := range lines {
		// Strip comments
		if idx := strings.Index(line, "#"); idx != -1 {
			line = line[:idx]
		}
		rawLine := line
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}

		// Check indentation to detect if inside thresholds map
		indent := len(rawLine) - len(strings.TrimLeft(rawLine, " \t"))
		if indent == 0 {
			inThresholdsSection = false
		}

		colonIdx := strings.Index(trimmed, ":")
		if colonIdx == -1 {
			return nil, fmt.Errorf("line %d: invalid yaml syntax %q", lineNum+1, trimmed)
		}

		key := strings.ToLower(strings.TrimSpace(trimmed[:colonIdx]))
		val := strings.TrimSpace(trimmed[colonIdx+1:])
		val = strings.Trim(val, `"'`)

		if key == "thresholds" && val == "" {
			inThresholdsSection = true
			if pol.Thresholds == nil {
				pol.Thresholds = make(map[string]*int)
			}
			continue
		}

		if inThresholdsSection && indent > 0 {
			if pol.Thresholds == nil {
				pol.Thresholds = make(map[string]*int)
			}
			num, err := strconv.Atoi(val)
			if err != nil {
				return nil, fmt.Errorf("line %d: invalid integer value for threshold %q: %v", lineNum+1, key, err)
			}
			pol.Thresholds[key] = &num
			continue
		}

		switch key {
		case "version":
			pol.Version = val
		case "name":
			pol.Name = val
		case "description":
			pol.Description = val
		case "max_critical":
			num, err := strconv.Atoi(val)
			if err != nil {
				return nil, fmt.Errorf("line %d: invalid integer for max_critical: %v", lineNum+1, err)
			}
			pol.MaxCritical = &num
		case "max_high":
			num, err := strconv.Atoi(val)
			if err != nil {
				return nil, fmt.Errorf("line %d: invalid integer for max_high: %v", lineNum+1, err)
			}
			pol.MaxHigh = &num
		case "max_medium":
			num, err := strconv.Atoi(val)
			if err != nil {
				return nil, fmt.Errorf("line %d: invalid integer for max_medium: %v", lineNum+1, err)
			}
			pol.MaxMedium = &num
		case "max_low":
			num, err := strconv.Atoi(val)
			if err != nil {
				return nil, fmt.Errorf("line %d: invalid integer for max_low: %v", lineNum+1, err)
			}
			pol.MaxLow = &num
		case "fail_on_violation":
			b, err := strconv.ParseBool(val)
			if err != nil {
				return nil, fmt.Errorf("line %d: invalid boolean for fail_on_violation: %v", lineNum+1, err)
			}
			pol.FailOnViolation = &b
		case "fail_on_unknown":
			b, err := strconv.ParseBool(val)
			if err != nil {
				return nil, fmt.Errorf("line %d: invalid boolean for fail_on_unknown: %v", lineNum+1, err)
			}
			pol.FailOnUnknown = &b
		}
	}

	return pol, nil
}
