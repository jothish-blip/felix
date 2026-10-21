package compliance

import (
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"
)

var (
	// ErrInvalidPolicy is returned when a remediation policy fails validation.
	ErrInvalidPolicy = errors.New("invalid remediation SLA policy")

	// ErrNoMatchingPolicy is returned when no enabled policy applies to a finding.
	ErrNoMatchingPolicy = errors.New("no matching remediation SLA policy found")

	// ErrNoMatchingRule is returned when a policy does not define a deadline for a finding's severity.
	ErrNoMatchingRule = errors.New("no matching SLA rule for finding severity")
)

// Supported canonical severity values for SLA policy rules.
var SupportedSeverities = []string{
	"CRITICAL",
	"HIGH",
	"MEDIUM",
	"LOW",
	"INFO",
}

// RemediationSLAPolicy defines a versioned, configurable SLA policy mapping finding severities to remediation deadlines.
type RemediationSLAPolicy struct {
	ID                   string            `json:"id"`
	Version              string            `json:"version"`
	Enabled              bool              `json:"enabled"`
	Description          string            `json:"description,omitempty"`
	Priority             int               `json:"priority"`
	Rules                map[string]string `json:"rules"`                  // map[severity]durationString, e.g. "CRITICAL": "24h", "HIGH": "7d"
	DefaultRule          string            `json:"default_rule,omitempty"` // For unknown/unmapped severities (e.g. "30d")
	ApplicableCategories []string          `json:"applicable_categories,omitempty"`
	ApplicableSources    []string          `json:"applicable_sources,omitempty"`
	CreatedAt            time.Time         `json:"created_at"`
	UpdatedAt            time.Time         `json:"updated_at"`
}

// ParseSLADuration parses a human-readable duration string into a time.Duration.
// Supports standard Go duration units (e.g. "24h", "48h") and day notation (e.g. "7d", "30d", "90d").
// Enforces that duration is strictly positive and within safe limits (max 3650 days = 10 years).
func ParseSLADuration(s string) (time.Duration, error) {
	trimmed := strings.TrimSpace(s)
	if trimmed == "" {
		return 0, errors.New("empty duration string")
	}

	// Support day format: e.g. "7d", "30d", "90D"
	if strings.HasSuffix(trimmed, "d") || strings.HasSuffix(trimmed, "D") {
		daysStr := trimmed[:len(trimmed)-1]
		days, err := strconv.Atoi(daysStr)
		if err != nil {
			return 0, fmt.Errorf("invalid day duration %q: %w", trimmed, err)
		}
		if days <= 0 {
			return 0, fmt.Errorf("duration must be positive; got %d days", days)
		}
		if days > 3650 {
			return 0, fmt.Errorf("duration exceeds maximum allowed limit (3650 days); got %d days", days)
		}
		return time.Duration(days) * 24 * time.Hour, nil
	}

	d, err := time.ParseDuration(trimmed)
	if err != nil {
		return 0, fmt.Errorf("invalid duration format %q: %w", trimmed, err)
	}
	if d <= 0 {
		return 0, fmt.Errorf("duration must be strictly positive; got %v", d)
	}
	if d > 3650*24*time.Hour {
		return 0, fmt.Errorf("duration exceeds maximum allowed limit (10 years); got %v", d)
	}
	return d, nil
}

// FormatSLADuration formats a time.Duration into a concise human-readable SLA string (e.g. "24h", "7d", "30d").
func FormatSLADuration(d time.Duration) string {
	if d <= 0 {
		return "0h"
	}
	hours := d / time.Hour
	if hours%24 == 0 && hours >= 24 {
		days := hours / 24
		return fmt.Sprintf("%dd", days)
	}
	return fmt.Sprintf("%dh", hours)
}

// ValidateRemediationPolicy performs comprehensive validation on an SLA policy.
// Invariant: Malformed policies, non-positive durations, or ambiguous severities are rejected.
func ValidateRemediationPolicy(p *RemediationSLAPolicy) error {
	if p == nil {
		return fmt.Errorf("%w: policy cannot be nil", ErrInvalidPolicy)
	}
	if strings.TrimSpace(p.ID) == "" {
		return fmt.Errorf("%w: policy ID cannot be empty", ErrInvalidPolicy)
	}
	if strings.TrimSpace(p.Version) == "" {
		return fmt.Errorf("%w: policy version cannot be empty", ErrInvalidPolicy)
	}
	if len(p.Rules) == 0 {
		return fmt.Errorf("%w: policy must define at least one severity rule", ErrInvalidPolicy)
	}

	for sev, durStr := range p.Rules {
		normSev := strings.ToUpper(strings.TrimSpace(sev))
		validSev := false
		for _, s := range SupportedSeverities {
			if normSev == s {
				validSev = true
				break
			}
		}
		if !validSev && normSev != "UNKNOWN" {
			return fmt.Errorf("%w: unsupported severity %q in rule; must be one of CRITICAL, HIGH, MEDIUM, LOW, INFO, UNKNOWN", ErrInvalidPolicy, sev)
		}

		dur, err := ParseSLADuration(durStr)
		if err != nil {
			return fmt.Errorf("%w: invalid duration for severity %s: %v", ErrInvalidPolicy, sev, err)
		}
		if dur <= 0 {
			return fmt.Errorf("%w: non-positive duration for severity %s", ErrInvalidPolicy, sev)
		}
	}

	if p.DefaultRule != "" {
		d, err := ParseSLADuration(p.DefaultRule)
		if err != nil {
			return fmt.Errorf("%w: invalid default_rule duration %q: %v", ErrInvalidPolicy, p.DefaultRule, err)
		}
		if d <= 0 {
			return fmt.Errorf("%w: non-positive default_rule duration", ErrInvalidPolicy)
		}
	}

	return nil
}

// DefaultRemediationSLAPolicy returns the canonical configurable default SLA policy for FELIX.
// Note: These values reflect standard example engineering SLAs and do not constitute universal regulatory mandates.
func DefaultRemediationSLAPolicy() *RemediationSLAPolicy {
	return &RemediationSLAPolicy{
		ID:          "felix-default-sla",
		Version:     "1.0.0",
		Enabled:     true,
		Description: "FELIX Default Configurable Remediation SLA Policy (example baseline: Critical 24h, High 7d, Medium 30d, Low 90d, Info 180d)",
		Priority:    10,
		Rules: map[string]string{
			"CRITICAL": "24h",
			"HIGH":     "7d",
			"MEDIUM":   "30d",
			"LOW":      "90d",
			"INFO":     "180d",
		},
		DefaultRule: "30d",
		CreatedAt:   time.Now().UTC(),
		UpdatedAt:   time.Now().UTC(),
	}
}

// ResolveDurationForSeverity retrieves the duration matching the given severity under this policy.
// If the severity is not explicitly mapped:
// - Uses DefaultRule if defined.
// - Returns ErrNoMatchingRule if no default rule exists (prevents silent permissive fallback).
func (p *RemediationSLAPolicy) ResolveDurationForSeverity(severity string) (time.Duration, string, error) {
	norm := strings.ToUpper(strings.TrimSpace(severity))
	if norm == "" {
		norm = "UNKNOWN"
	}

	for sev, durStr := range p.Rules {
		if strings.ToUpper(strings.TrimSpace(sev)) == norm {
			d, err := ParseSLADuration(durStr)
			if err != nil {
				return 0, "", err
			}
			return d, fmt.Sprintf("rule:%s=%s", norm, durStr), nil
		}
	}

	if p.DefaultRule != "" {
		d, err := ParseSLADuration(p.DefaultRule)
		if err != nil {
			return 0, "", err
		}
		return d, fmt.Sprintf("default_rule=%s", p.DefaultRule), nil
	}

	return 0, "", fmt.Errorf("%w: severity %q has no assigned rule and no default_rule in policy %s:%s",
		ErrNoMatchingRule, severity, p.ID, p.Version)
}

// MatchesFinding checks if a policy applies to a finding based on category and source filters.
func (p *RemediationSLAPolicy) MatchesFinding(category, source string) bool {
	if !p.Enabled {
		return false
	}

	cleanCat := strings.ToLower(strings.TrimSpace(category))
	cleanSrc := strings.ToLower(strings.TrimSpace(source))

	if len(p.ApplicableCategories) > 0 {
		matched := false
		for _, c := range p.ApplicableCategories {
			if strings.EqualFold(strings.TrimSpace(c), cleanCat) {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}

	if len(p.ApplicableSources) > 0 {
		matched := false
		for _, s := range p.ApplicableSources {
			if strings.EqualFold(strings.TrimSpace(s), cleanSrc) {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}

	return true
}

// SelectMatchingPolicy deterministically selects the highest-priority applicable policy for a finding.
// Conflicts between identical priority policies are resolved deterministically by lexicographical Policy ID ascending.
func SelectMatchingPolicy(policies []RemediationSLAPolicy, category, source string) (*RemediationSLAPolicy, error) {
	var applicable []*RemediationSLAPolicy
	for i := range policies {
		if policies[i].MatchesFinding(category, source) {
			applicable = append(applicable, &policies[i])
		}
	}

	if len(applicable) == 0 {
		return nil, ErrNoMatchingPolicy
	}

	sort.SliceStable(applicable, func(i, j int) bool {
		if applicable[i].Priority != applicable[j].Priority {
			return applicable[i].Priority > applicable[j].Priority // Higher priority first
		}
		return applicable[i].ID < applicable[j].ID // Deterministic tie-breaker
	})

	return applicable[0], nil
}
