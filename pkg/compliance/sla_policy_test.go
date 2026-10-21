package compliance

import (
	"errors"
	"testing"
	"time"
)

func TestSLAPolicy_1_ValidDefaultPolicy(t *testing.T) {
	policy := DefaultRemediationSLAPolicy()
	if err := ValidateRemediationPolicy(policy); err != nil {
		t.Fatalf("DefaultRemediationSLAPolicy failed validation: %v", err)
	}

	critDur, ruleCrit, err := policy.ResolveDurationForSeverity("CRITICAL")
	if err != nil {
		t.Fatalf("failed resolving CRITICAL: %v", err)
	}
	if critDur != 24*time.Hour {
		t.Errorf("expected 24h for CRITICAL, got %v", critDur)
	}
	if ruleCrit != "rule:CRITICAL=24h" {
		t.Errorf("expected rule:CRITICAL=24h, got %s", ruleCrit)
	}

	highDur, _, _ := policy.ResolveDurationForSeverity("HIGH")
	if highDur != 7*24*time.Hour {
		t.Errorf("expected 7d for HIGH, got %v", highDur)
	}

	medDur, _, _ := policy.ResolveDurationForSeverity("MEDIUM")
	if medDur != 30*24*time.Hour {
		t.Errorf("expected 30d for MEDIUM, got %v", medDur)
	}

	lowDur, _, _ := policy.ResolveDurationForSeverity("LOW")
	if lowDur != 90*24*time.Hour {
		t.Errorf("expected 90d for LOW, got %v", lowDur)
	}

	infoDur, _, _ := policy.ResolveDurationForSeverity("INFO")
	if infoDur != 180*24*time.Hour {
		t.Errorf("expected 180d for INFO, got %v", infoDur)
	}

	// Unknown severity resolves to DefaultRule
	unkDur, ruleUnk, err := policy.ResolveDurationForSeverity("UNKNOWN")
	if err != nil {
		t.Fatalf("failed resolving UNKNOWN: %v", err)
	}
	if unkDur != 30*24*time.Hour {
		t.Errorf("expected default 30d for UNKNOWN, got %v", unkDur)
	}
	if ruleUnk != "default_rule=30d" {
		t.Errorf("expected default_rule=30d, got %s", ruleUnk)
	}
}

func TestSLAPolicy_2_DurationParsingAndBoundaries(t *testing.T) {
	cases := []struct {
		input       string
		expected    time.Duration
		expectError bool
	}{
		{"24h", 24 * time.Hour, false},
		{"48h", 48 * time.Hour, false},
		{"1d", 24 * time.Hour, false},
		{"7d", 7 * 24 * time.Hour, false},
		{"30d", 30 * 24 * time.Hour, false},
		{"90D", 90 * 24 * time.Hour, false},
		{"3650d", 3650 * 24 * time.Hour, false},
		{"", 0, true},
		{"0h", 0, true},
		{"0d", 0, true},
		{"-5h", 0, true},
		{"-1d", 0, true},
		{"3651d", 0, true}, // Exceeds 10 years
		{"invalid-str", 0, true},
	}

	for _, tc := range cases {
		d, err := ParseSLADuration(tc.input)
		if tc.expectError {
			if err == nil {
				t.Errorf("expected error for ParseSLADuration(%q), got %v", tc.input, d)
			}
		} else {
			if err != nil {
				t.Errorf("unexpected error for ParseSLADuration(%q): %v", tc.input, err)
			}
			if d != tc.expected {
				t.Errorf("ParseSLADuration(%q) = %v, expected %v", tc.input, d, tc.expected)
			}
		}
	}
}

func TestSLAPolicy_3_ValidationRejections(t *testing.T) {
	// Nil policy
	if err := ValidateRemediationPolicy(nil); !errors.Is(err, ErrInvalidPolicy) {
		t.Errorf("expected ErrInvalidPolicy for nil, got %v", err)
	}

	// Missing ID
	p1 := DefaultRemediationSLAPolicy()
	p1.ID = ""
	if err := ValidateRemediationPolicy(p1); err == nil {
		t.Errorf("expected error for empty policy ID")
	}

	// Missing Version
	p2 := DefaultRemediationSLAPolicy()
	p2.Version = "   "
	if err := ValidateRemediationPolicy(p2); err == nil {
		t.Errorf("expected error for empty policy Version")
	}

	// Empty rules
	p3 := DefaultRemediationSLAPolicy()
	p3.Rules = map[string]string{}
	if err := ValidateRemediationPolicy(p3); err == nil {
		t.Errorf("expected error for empty rules map")
	}

	// Unsupported severity name
	p4 := DefaultRemediationSLAPolicy()
	p4.Rules["CATASTROPHIC"] = "1h"
	if err := ValidateRemediationPolicy(p4); err == nil {
		t.Errorf("expected error for unsupported severity in rules")
	}

	// Non-positive duration in rule
	p5 := DefaultRemediationSLAPolicy()
	p5.Rules["CRITICAL"] = "-24h"
	if err := ValidateRemediationPolicy(p5); err == nil {
		t.Errorf("expected error for negative duration in rules")
	}

	// Non-positive default rule
	p6 := DefaultRemediationSLAPolicy()
	p6.DefaultRule = "0h"
	if err := ValidateRemediationPolicy(p6); err == nil {
		t.Errorf("expected error for non-positive default_rule")
	}
}

func TestSLAPolicy_4_MissingSeverityWithoutDefaultRule(t *testing.T) {
	// Policy without default rule must fail closed when severity is unknown
	policy := &RemediationSLAPolicy{
		ID:       "strict-policy",
		Version:  "1.0.0",
		Enabled:  true,
		Priority: 10,
		Rules: map[string]string{
			"CRITICAL": "24h",
			"HIGH":     "7d",
		},
		DefaultRule: "", // Explicitly empty
	}

	// Resolving MEDIUM or UNKNOWN must return ErrNoMatchingRule (no silent fallback)
	_, _, err := policy.ResolveDurationForSeverity("MEDIUM")
	if !errors.Is(err, ErrNoMatchingRule) {
		t.Errorf("expected ErrNoMatchingRule for unmapped severity without default_rule, got %v", err)
	}

	_, _, err = policy.ResolveDurationForSeverity("UNKNOWN")
	if !errors.Is(err, ErrNoMatchingRule) {
		t.Errorf("expected ErrNoMatchingRule for UNKNOWN without default_rule, got %v", err)
	}
}

func TestSLAPolicy_5_DeterministicPolicySelectionAndPrecedence(t *testing.T) {
	policies := []RemediationSLAPolicy{
		{
			ID:                   "api-sla-standard",
			Version:              "1.0.0",
			Enabled:              true,
			Priority:             20,
			ApplicableCategories: []string{"authz", "auth"},
			Rules:                map[string]string{"HIGH": "5d"},
		},
		{
			ID:                   "api-sla-high-priority",
			Version:              "1.0.0",
			Enabled:              true,
			Priority:             50, // Higher priority must win
			ApplicableCategories: []string{"authz"},
			Rules:                map[string]string{"HIGH": "2d"},
		},
		{
			ID:       "global-fallback-sla",
			Version:  "1.0.0",
			Enabled:  true,
			Priority: 5,
			Rules:    map[string]string{"HIGH": "14d"},
		},
		{
			ID:       "disabled-sla",
			Version:  "1.0.0",
			Enabled:  false, // Disabled should be ignored
			Priority: 100,
			Rules:    map[string]string{"HIGH": "1d"},
		},
	}

	// Finding matching category "authz" must select api-sla-high-priority (Priority 50)
	sel, err := SelectMatchingPolicy(policies, "authz", "api")
	if err != nil {
		t.Fatalf("SelectMatchingPolicy failed: %v", err)
	}
	if sel.ID != "api-sla-high-priority" {
		t.Errorf("expected policy api-sla-high-priority, got %s", sel.ID)
	}

	// Finding matching category "auth" must select api-sla-standard (Priority 20)
	selAuth, err := SelectMatchingPolicy(policies, "auth", "api")
	if err != nil {
		t.Fatalf("SelectMatchingPolicy failed: %v", err)
	}
	if selAuth.ID != "api-sla-standard" {
		t.Errorf("expected policy api-sla-standard, got %s", selAuth.ID)
	}

	// Finding matching category "sqli" must select global-fallback-sla (Priority 5)
	selGlobal, err := SelectMatchingPolicy(policies, "sqli", "webvuln")
	if err != nil {
		t.Fatalf("SelectMatchingPolicy failed: %v", err)
	}
	if selGlobal.ID != "global-fallback-sla" {
		t.Errorf("expected policy global-fallback-sla, got %s", selGlobal.ID)
	}

	// Identical priority tie-breaker is deterministic (lexicographical ID ascending)
	tiePolicies := []RemediationSLAPolicy{
		{ID: "policy-z", Version: "1.0", Enabled: true, Priority: 10, Rules: map[string]string{"HIGH": "7d"}},
		{ID: "policy-a", Version: "1.0", Enabled: true, Priority: 10, Rules: map[string]string{"HIGH": "7d"}},
	}
	selTie, err := SelectMatchingPolicy(tiePolicies, "any", "any")
	if err != nil {
		t.Fatalf("SelectMatchingPolicy tie failed: %v", err)
	}
	if selTie.ID != "policy-a" {
		t.Errorf("expected tie-breaker policy-a, got %s", selTie.ID)
	}
}
