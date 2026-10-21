package policy

import (
	"os"
	"path/filepath"
	"testing"

	"felix/pkg/report"
)

// 1. Validation for supported schema versions and malformed files
func TestPolicy_VersionValidation(t *testing.T) {
	// Valid versions: 1.0 and 1
	for _, v := range []string{Version1_0, Version1} {
		p := &ThresholdPolicy{
			Version: v,
			Name:    "valid-version-policy",
		}
		if err := p.Validate(); err != nil {
			t.Errorf("expected version %q to be valid, got: %v", v, err)
		}
	}

	// Invalid versions
	for _, v := range []string{"", "2.0", "v1", "0.9", "latest"} {
		p := &ThresholdPolicy{
			Version: v,
		}
		if err := p.Validate(); err == nil {
			t.Errorf("expected version %q to be rejected, got nil error", v)
		}
	}
}

// 2. Validation for negative threshold values
func TestPolicy_NegativeThresholdValidation(t *testing.T) {
	negVal := -1
	zeroVal := 0

	// Top-level negative values
	testCases := []struct {
		name   string
		policy ThresholdPolicy
	}{
		{"negative critical", ThresholdPolicy{Version: "1.0", MaxCritical: &negVal}},
		{"negative high", ThresholdPolicy{Version: "1.0", MaxHigh: &negVal}},
		{"negative medium", ThresholdPolicy{Version: "1.0", MaxMedium: &negVal}},
		{"negative low", ThresholdPolicy{Version: "1.0", MaxLow: &negVal}},
		{"negative map threshold", ThresholdPolicy{
			Version: "1.0",
			Thresholds: map[string]*int{
				"critical": &negVal,
			},
		}},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.policy.Validate(); err == nil {
				t.Errorf("expected negative threshold to fail validation, got nil error")
			}
		})
	}

	// Zero values must be valid
	validZero := &ThresholdPolicy{
		Version:     "1.0",
		MaxCritical: &zeroVal,
		MaxHigh:     &zeroVal,
	}
	if err := validZero.Validate(); err != nil {
		t.Errorf("expected zero thresholds to be valid, got: %v", err)
	}
}

// 3. Validation for invalid severity names in thresholds map
func TestPolicy_InvalidSeverityNames(t *testing.T) {
	zero := 0
	p := &ThresholdPolicy{
		Version: "1.0",
		Thresholds: map[string]*int{
			"SUPER_CRITICAL": &zero,
		},
	}
	if err := p.Validate(); err == nil {
		t.Errorf("expected invalid severity name SUPER_CRITICAL to be rejected, got nil error")
	}
}

// 4. Validation for conflicting definitions between top-level fields and thresholds map
func TestPolicy_ConflictingThresholdEntries(t *testing.T) {
	val0 := 0
	val1 := 1

	// Conflicting: max_critical=0 vs thresholds.critical=1
	pConflict := &ThresholdPolicy{
		Version:     "1.0",
		MaxCritical: &val0,
		Thresholds: map[string]*int{
			"critical": &val1,
		},
	}
	if err := pConflict.Validate(); err == nil {
		t.Fatalf("expected conflicting definitions for critical to be rejected, got nil error")
	}

	// Concordant: max_critical=1 vs thresholds.critical=1 -> valid
	pConcordant := &ThresholdPolicy{
		Version:     "1.0",
		MaxCritical: &val1,
		Thresholds: map[string]*int{
			"critical": &val1,
		},
	}
	if err := pConcordant.Validate(); err != nil {
		t.Fatalf("expected concordant definitions to pass validation, got: %v", err)
	}
}

// 5. Distinction between unconfigured vs zero vs positive
func TestPolicy_DistinguishUnconfiguredVsZeroVsPositive(t *testing.T) {
	zero := 0
	five := 5

	p := &ThresholdPolicy{
		Version:     "1.0",
		MaxCritical: &zero,
		MaxHigh:     &five,
		// MaxMedium is unconfigured (nil)
		// MaxLow is unconfigured (nil)
	}

	// Critical: configured with 0
	critLimit, critConfigured := p.GetThreshold(report.SeverityCritical)
	if !critConfigured || critLimit != 0 {
		t.Fatalf("expected Critical to be configured with limit 0, got configured=%v limit=%d", critConfigured, critLimit)
	}

	// High: configured with 5
	highLimit, highConfigured := p.GetThreshold(report.SeverityHigh)
	if !highConfigured || highLimit != 5 {
		t.Fatalf("expected High to be configured with limit 5, got configured=%v limit=%d", highConfigured, highLimit)
	}

	// Medium: NOT configured
	medLimit, medConfigured := p.GetThreshold(report.SeverityMedium)
	if medConfigured {
		t.Fatalf("expected Medium to be unconfigured, got configured=true limit=%d", medLimit)
	}

	// Low: NOT configured
	lowLimit, lowConfigured := p.GetThreshold(report.SeverityLow)
	if lowConfigured {
		t.Fatalf("expected Low to be unconfigured, got configured=true limit=%d", lowLimit)
	}
}

// 6. Loading policy file: valid, malformed, nonexistent
func TestPolicy_FileLoading(t *testing.T) {
	tempDir := t.TempDir()

	// Valid policy file
	validPath := filepath.Join(tempDir, "policy_valid.json")
	validJSON := `{
		"version": "1.0",
		"name": "ci-release-gate",
		"max_critical": 0,
		"max_high": 2,
		"fail_on_violation": true
	}`
	_ = os.WriteFile(validPath, []byte(validJSON), 0644)

	pol, err := LoadPolicy(validPath)
	if err != nil {
		t.Fatalf("expected valid policy to load, got: %v", err)
	}
	if pol.Name != "ci-release-gate" {
		t.Errorf("expected policy name ci-release-gate, got %s", pol.Name)
	}
	if limit, ok := pol.GetThreshold(report.SeverityCritical); !ok || limit != 0 {
		t.Errorf("expected Critical limit 0, got %d (configured: %v)", limit, ok)
	}

	// Nonexistent file
	if _, err := LoadPolicy(filepath.Join(tempDir, "missing.json")); err == nil {
		t.Errorf("expected error for nonexistent policy file, got nil")
	}

	// Malformed JSON
	malformedPath := filepath.Join(tempDir, "malformed.json")
	_ = os.WriteFile(malformedPath, []byte(`{ invalid json`), 0644)
	if _, err := LoadPolicy(malformedPath); err == nil {
		t.Errorf("expected error for malformed policy JSON, got nil")
	}
}

// 7. Deterministic digest computation
func TestPolicy_DeterministicDigest(t *testing.T) {
	zero := 0
	three := 3
	p1 := &ThresholdPolicy{
		Version:     "1.0",
		Name:        "test-policy",
		MaxCritical: &zero,
		MaxHigh:     &three,
	}
	p2 := &ThresholdPolicy{
		Version: "1.0",
		Name:    "test-policy",
		Thresholds: map[string]*int{
			"CRITICAL": &zero,
			"HIGH":     &three,
		},
	}

	d1 := p1.Digest()
	d2 := p2.Digest()
	if d1 != d2 {
		t.Fatalf("expected normalized equivalent policies to produce identical digest, got %s != %s", d1, d2)
	}
	if len(d1) != 64 {
		t.Fatalf("expected 64-char hex SHA-256 digest, got len %d (%s)", len(d1), d1)
	}
}

// 8. ParseSeverity honest classification
func TestPolicy_ParseSeverityHonestClassification(t *testing.T) {
	testCases := []struct {
		input      string
		expected   string
		recognized bool
	}{
		{"CRITICAL", report.SeverityCritical, true},
		{"critical", report.SeverityCritical, true},
		{"CRIT", report.SeverityCritical, true},
		{"HIGH", report.SeverityHigh, true},
		{"high", report.SeverityHigh, true},
		{"MEDIUM", report.SeverityMedium, true},
		{"MED", report.SeverityMedium, true},
		{"MODERATE", report.SeverityMedium, true},
		{"LOW", report.SeverityLow, true},
		{"low", report.SeverityLow, true},
		{"INFO", report.SeverityInfo, true},
		{"INFORMATIONAL", report.SeverityInfo, true},
		{"NOTE", report.SeverityInfo, true},
		// Unknowns must NOT be coerced to Low or Info
		{"UNKNOWN", report.SeverityUnknown, false},
		{"", report.SeverityUnknown, false},
		{"MYSTERY_SEV", report.SeverityUnknown, false},
		{"URGENT", report.SeverityUnknown, false},
	}

	for _, tc := range testCases {
		t.Run(tc.input, func(t *testing.T) {
			canon, rec := ParseSeverity(tc.input)
			if canon != tc.expected || rec != tc.recognized {
				t.Fatalf("ParseSeverity(%q): expected (%s, %v), got (%s, %v)",
					tc.input, tc.expected, tc.recognized, canon, rec)
			}
		})
	}
}
