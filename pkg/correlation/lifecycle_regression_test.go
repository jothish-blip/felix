package correlation

import (
	"testing"

	"felix/pkg/report"
)

// TestFindingFingerprint_IdentityProperties tests stability and sensitivity of ComputeStableFingerprint.
func TestFindingFingerprint_IdentityProperties(t *testing.T) {
	base := report.Finding{
		Category: "Injection",
		RuleID:   "CWE-89",
		Severity: "HIGH",
		Target:   "https://example.com/api",
		Endpoint: "/users",
		Method:   "GET",
		Title:    "SQL Injection in /users",
		EvidenceDetails: report.EvidenceDetails{
			Details: map[string]string{
				"parameter": "id",
			},
		},
	}

	fpBase := ComputeStableFingerprint(base)

	// 1. Invariant: 64-character lowercase hex digest
	if len(fpBase) != 64 {
		t.Fatalf("expected 64-char fingerprint, got %d: %q", len(fpBase), fpBase)
	}

	// 2. Stability: changes in non-identity descriptive fields (Title, Description) do not alter fingerprint
	variant := base
	variant.Title = "Different Descriptive Title for the Same Vulnerability"
	variant.Description = "Updated forensic description notes"
	fpVariant := ComputeStableFingerprint(variant)

	if fpBase != fpVariant {
		t.Errorf("fingerprint unstable across descriptive changes: base=%s variant=%s", fpBase, fpVariant)
	}

	// 3. Sensitivity: changes in identity fields (endpoint, parameter, method) MUST alter fingerprint
	diffEndpoint := base
	diffEndpoint.Endpoint = "/orders"
	if ComputeStableFingerprint(diffEndpoint) == fpBase {
		t.Errorf("fingerprint failed to differentiate distinct endpoints")
	}

	diffParam := base
	diffParam.EvidenceDetails.Details = map[string]string{
		"parameter": "filter",
	}
	if ComputeStableFingerprint(diffParam) == fpBase {
		t.Errorf("fingerprint failed to differentiate distinct parameters")
	}

	diffMethod := base
	diffMethod.Method = "POST"
	if ComputeStableFingerprint(diffMethod) == fpBase {
		t.Errorf("fingerprint failed to differentiate distinct HTTP methods")
	}
}

// TestFindingLifecycle_Transitions verifies lifecycle delta categorization between assessments.
func TestFindingLifecycle_Transitions(t *testing.T) {
	f1 := report.Finding{
		ID:       "f1",
		Category: "Injection",
		RuleID:   "CWE-89",
		Severity: "HIGH",
		Target:   "https://example.com",
		Endpoint: "/login",
		Title:    "SQL Injection",
	}

	f2 := report.Finding{
		ID:       "f2",
		Category: "XSS",
		RuleID:   "CWE-79",
		Severity: "MEDIUM",
		Target:   "https://example.com",
		Endpoint: "/search",
		Title:    "Reflected XSS",
	}

	// Case 1: Unchanged finding between completed assessments
	cmpUnchanged := CompareFindingsWithOptions([]report.Finding{f1}, []report.Finding{f1}, ComparisonOptions{
		CurrentCompleted: true,
	})
	if cmpUnchanged.UnchangedCount != 1 || cmpUnchanged.NewCount != 0 || cmpUnchanged.ResolvedCount != 0 {
		t.Errorf("expected 1 unchanged finding, got: new=%d, resolved=%d, unchanged=%d",
			cmpUnchanged.NewCount, cmpUnchanged.ResolvedCount, cmpUnchanged.UnchangedCount)
	}

	// Case 2: Severity change (escalated from HIGH to CRITICAL -> Regressed with severity increase)
	f1Escalated := f1
	f1Escalated.Severity = "CRITICAL"
	cmpChanged := CompareFindingsWithOptions([]report.Finding{f1}, []report.Finding{f1Escalated}, ComparisonOptions{
		CurrentCompleted: true,
	})
	if cmpChanged.RegressedCount != 1 || cmpChanged.SeverityIncreasedCount != 1 {
		t.Errorf("expected 1 regressed finding with severity increase, got regressed=%d, increased=%d",
			cmpChanged.RegressedCount, cmpChanged.SeverityIncreasedCount)
	}

	// Case 3: Completely new finding (no baseline)
	cmpNew := CompareFindingsWithOptions(nil, []report.Finding{f2}, ComparisonOptions{
		CurrentCompleted: true,
	})
	if cmpNew.NewCount != 1 {
		t.Errorf("expected 1 new finding, got %d", cmpNew.NewCount)
	}
}

// TestFindingLifecycle_IncompleteAssessmentFalseResolvedDefense ensures that incomplete,
// interrupted, or failed current assessments NEVER falsely claim baseline findings are resolved.
func TestFindingLifecycle_IncompleteAssessmentFalseResolvedDefense(t *testing.T) {
	fBase := report.Finding{
		ID:       "critical-vuln",
		Category: "Injection",
		RuleID:   "CWE-89",
		Severity: "CRITICAL",
		Target:   "https://example.com",
		Endpoint: "/db",
		Title:    "Critical SQLi",
	}

	// Current assessment produced 0 findings because it was cancelled or failed mid-scan!
	currentFindings := []report.Finding{}

	cmp := CompareFindingsWithOptions([]report.Finding{fBase}, currentFindings, ComparisonOptions{
		CurrentCompleted: false, // Incomplete/failed assessment!
	})

	// Security Invariant: Zero resolved claims when current assessment is incomplete
	if cmp.ResolvedCount > 0 {
		t.Fatalf("SECURITY VIOLATION: incomplete assessment falsely claimed %d finding(s) resolved",
			cmp.ResolvedCount)
	}

	// Invariant: The baseline finding must be recognized as unverified/unassessed, NOT resolved
	if cmp.UnverifiedCount != 1 && cmp.UnassessedCount != 1 && cmp.PersistentCount != 1 {
		t.Errorf("expected finding to be unverified or persistent, got: unverified=%d, unassessed=%d, persistent=%d",
			cmp.UnverifiedCount, cmp.UnassessedCount, cmp.PersistentCount)
	}
	if cmp.NewCount != 0 {
		t.Errorf("unexpected new findings: %d", cmp.NewCount)
	}
}
