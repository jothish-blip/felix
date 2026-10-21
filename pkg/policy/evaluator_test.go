package policy

import (
	"fmt"
	"strings"
	"testing"

	"felix/pkg/clierror"
	"felix/pkg/report"
)

func makeTestFinding(id, title, sev, target string) report.Finding {
	return report.Finding{
		ID:       id,
		Title:    title,
		Severity: sev,
		Target:   target,
		Category: "test-vuln",
		Endpoint: "/" + id,
		Method:   "GET",
		EvidenceDetails: report.EvidenceDetails{
			Details: map[string]string{
				"assessment_id": "ASM-TEST-001",
				"tenant_id":     "TENANT-A",
			},
		},
	}
}

// 1. Boundary Semantics: exact boundary vs one above boundary
func TestEvaluator_BoundarySemantics(t *testing.T) {
	zero := 0
	three := 3

	pol := &ThresholdPolicy{
		Version:     "1.0",
		Name:        "boundary-test",
		MaxCritical: &zero,
		MaxHigh:     &three,
	}

	ctx := EvaluationContext{
		AssessmentID: "ASM-TEST-001",
		ClientID:     "TENANT-A",
		Status:       "COMPLETED",
	}

	// Case A: Exact maximum boundary (3 High findings, limit is 3) -> PASSED
	findingsExact := []report.Finding{
		makeTestFinding("f1", "High 1", "HIGH", "https://example.com/api/1"),
		makeTestFinding("f2", "High 2", "HIGH", "https://example.com/api/2"),
		makeTestFinding("f3", "High 3", "HIGH", "https://example.com/api/3"),
	}

	decExact, err := EvaluatePolicy(pol, findingsExact, ctx)
	if err != nil {
		t.Fatalf("unexpected evaluation error: %v", err)
	}
	if !decExact.Passed {
		t.Fatalf("expected exact boundary (3 observed vs 3 allowed) to pass, got failed (violations: %+v)", decExact.Violations)
	}
	if decExact.ExitCode() != clierror.ExitSuccess {
		t.Fatalf("expected exit code 0 for exact boundary pass, got %d", decExact.ExitCode())
	}

	// Case B: One above boundary (4 High findings, limit is 3) -> FAILED
	findingsAbove := append(findingsExact, makeTestFinding("f4", "High 4", "HIGH", "https://example.com/api/4"))
	decAbove, err := EvaluatePolicy(pol, findingsAbove, ctx)
	if err != nil {
		t.Fatalf("unexpected evaluation error: %v", err)
	}
	if decAbove.Passed {
		t.Fatalf("expected 4 observed vs 3 allowed to fail, got passed")
	}
	if decAbove.ExitCode() != clierror.ExitSecurityFail {
		t.Fatalf("expected exit code 1 (ExitSecurityFail) for threshold violation, got %d", decAbove.ExitCode())
	}
	if len(decAbove.Violations) != 1 || decAbove.Violations[0].Severity != "HIGH" {
		t.Fatalf("expected 1 HIGH violation, got %+v", decAbove.Violations)
	}

	// Case C: Maximum Critical = 0, observed 1 Critical -> FAILED
	findingsCrit := []report.Finding{
		makeTestFinding("fc1", "Crit 1", "CRITICAL", "https://example.com/api/crit"),
	}
	decCrit, err := EvaluatePolicy(pol, findingsCrit, ctx)
	if err != nil {
		t.Fatalf("unexpected evaluation error: %v", err)
	}
	if decCrit.Passed {
		t.Fatalf("expected 1 Critical vs 0 allowed to fail, got passed")
	}
	if decCrit.ExitCode() != clierror.ExitSecurityFail {
		t.Fatalf("expected exit code 1 for Critical violation, got %d", decCrit.ExitCode())
	}
}

// 2. Unconfigured Severity Thresholds: do not fail when a severity is not configured
func TestEvaluator_UnconfiguredSeverityDoesNotFail(t *testing.T) {
	zero := 0

	// Policy only configures Critical = 0. High and Medium are unconfigured.
	pol := &ThresholdPolicy{
		Version:     "1.0",
		Name:        "crit-only-gate",
		MaxCritical: &zero,
		// MaxHigh and MaxMedium are omitted
	}

	ctx := EvaluationContext{
		AssessmentID: "ASM-TEST-001",
		ClientID:     "TENANT-A",
		Status:       "COMPLETED",
	}

	findings := []report.Finding{
		makeTestFinding("fh1", "High 1", "HIGH", "https://example.com/1"),
		makeTestFinding("fh2", "High 2", "HIGH", "https://example.com/2"),
		makeTestFinding("fm1", "Med 1", "MEDIUM", "https://example.com/3"),
	}

	dec, err := EvaluatePolicy(pol, findings, ctx)
	if err != nil {
		t.Fatalf("unexpected evaluation error: %v", err)
	}
	if !dec.Passed {
		t.Fatalf("expected policy to pass when unconfigured severities are present, got violations: %+v", dec.Violations)
	}
	if dec.ExitCode() != clierror.ExitSuccess {
		t.Fatalf("expected ExitSuccess (0), got %d", dec.ExitCode())
	}
}

// 3. Informational Findings: never count as Low findings
func TestEvaluator_InfoFindingsNeverCountAsLow(t *testing.T) {
	zero := 0

	// MaxLow = 0: Zero Low findings permitted.
	pol := &ThresholdPolicy{
		Version: "1.0",
		MaxLow:  &zero,
	}

	ctx := EvaluationContext{
		AssessmentID: "ASM-TEST-001",
		ClientID:     "TENANT-A",
		Status:       "COMPLETED",
	}

	// 5 Informational findings, 0 Low findings
	findings := []report.Finding{
		makeTestFinding("fi1", "Info 1", "INFO", "https://example.com/1"),
		makeTestFinding("fi2", "Info 2", "INFORMATIONAL", "https://example.com/2"),
		makeTestFinding("fi3", "Info 3", "NOTE", "https://example.com/3"),
		makeTestFinding("fi4", "Info 4", "info", "https://example.com/4"),
		makeTestFinding("fi5", "Info 5", "INFO", "https://example.com/5"),
	}

	dec, err := EvaluatePolicy(pol, findings, ctx)
	if err != nil {
		t.Fatalf("unexpected evaluation error: %v", err)
	}
	if !dec.Passed {
		t.Fatalf("expected 5 INFO findings with MaxLow=0 to pass without violation, got violations: %+v", dec.Violations)
	}
	if dec.ObservedCounts["LOW"] != 0 {
		t.Fatalf("expected observed LOW count 0, got %d", dec.ObservedCounts["LOW"])
	}
	if dec.ObservedCounts["INFO"] != 5 {
		t.Fatalf("expected observed INFO count 5, got %d", dec.ObservedCounts["INFO"])
	}
}

// 4. Duplicate Findings: deduplication prevents double-counting
func TestEvaluator_DuplicateFindingsDeduplicated(t *testing.T) {
	one := 1

	// MaxMedium = 1
	pol := &ThresholdPolicy{
		Version:   "1.0",
		MaxMedium: &one,
	}

	ctx := EvaluationContext{
		AssessmentID: "ASM-TEST-001",
		ClientID:     "TENANT-A",
		Status:       "COMPLETED",
	}

	// Two identical duplicate findings on same target and category
	f1 := makeTestFinding("fdup1", "CORS Exposure", "MEDIUM", "https://example.com/api")
	f1.Category = "cors-misconfiguration"
	f1.Endpoint = "/api"
	f1.Method = "GET"

	f2 := makeTestFinding("fdup2", "CORS Exposure", "MEDIUM", "https://example.com/api")
	f2.Category = "cors-misconfiguration"
	f2.Endpoint = "/api"
	f2.Method = "GET"

	dec, err := EvaluatePolicy(pol, []report.Finding{f1, f2}, ctx)
	if err != nil {
		t.Fatalf("unexpected evaluation error: %v", err)
	}
	// After deduplication, should count as 1 Medium finding -> within limit of 1 -> PASSED
	if !dec.Passed {
		t.Fatalf("expected duplicate findings to be deduplicated and pass limit of 1, got failed (violations: %+v)", dec.Violations)
	}
	if dec.ObservedCounts["MEDIUM"] != 1 {
		t.Fatalf("expected deduplicated MEDIUM count 1, got %d", dec.ObservedCounts["MEDIUM"])
	}
}

// 5. Unknown Severity Findings: never silently classified as Low or Info
func TestEvaluator_UnknownSeverityHonestTracking(t *testing.T) {
	zero := 0

	pol := &ThresholdPolicy{
		Version: "1.0",
		MaxLow:  &zero, // zero Low permitted
	}

	ctx := EvaluationContext{
		AssessmentID: "ASM-TEST-001",
		ClientID:     "TENANT-A",
		Status:       "COMPLETED",
	}

	findings := []report.Finding{
		makeTestFinding("fu1", "Unknown 1", "UNKNOWN", "https://example.com/1"),
		makeTestFinding("fu2", "Mystery 2", "SPECIAL_TIER", "https://example.com/2"),
	}

	dec, err := EvaluatePolicy(pol, findings, ctx)
	if err != nil {
		t.Fatalf("unexpected evaluation error: %v", err)
	}

	// Must NOT be coerced to Low (MaxLow=0 would otherwise fail!)
	if dec.ObservedCounts["LOW"] != 0 {
		t.Fatalf("expected UNKNOWN severities NOT to increment LOW count, got LOW=%d", dec.ObservedCounts["LOW"])
	}
	if dec.ObservedCounts["UNKNOWN"] != 2 {
		t.Fatalf("expected UNKNOWN count 2, got %d", dec.ObservedCounts["UNKNOWN"])
	}
	if len(dec.UnrecognizedFindings) != 2 {
		t.Fatalf("expected 2 unrecognized findings documented, got %d", len(dec.UnrecognizedFindings))
	}

	// If FailOnUnknown is enabled, it must fail with an explicit violation
	failUnknown := true
	polStrict := &ThresholdPolicy{
		Version:       "1.0",
		FailOnUnknown: &failUnknown,
	}

	decStrict, err := EvaluatePolicy(polStrict, findings, ctx)
	if err != nil {
		t.Fatalf("unexpected evaluation error: %v", err)
	}
	if decStrict.Passed {
		t.Fatalf("expected FailOnUnknown to trigger policy failure, got passed")
	}
	if decStrict.ExitCode() != clierror.ExitSecurityFail {
		t.Fatalf("expected ExitSecurityFail (1), got %d", decStrict.ExitCode())
	}
}

// 6. Operational Failure Safeguards:
// Untrustworthy results (FAILED, CANCELLED, INTERRUPTED, PARTIAL, COMPLETED_WITH_ERRORS)
// must NEVER pass policy merely because zero findings exist! Must return exit code 2.
func TestEvaluator_UntrustworthyAssessmentReturnsExitCodeTwo(t *testing.T) {
	zero := 0
	pol := &ThresholdPolicy{
		Version:     "1.0",
		MaxCritical: &zero,
		MaxHigh:     &zero,
	}

	untrustworthyStatuses := []string{
		"FAILED",
		"CANCELLED",
		"INTERRUPTED",
		"COMPLETED_WITH_ERRORS",
		"PARTIAL",
		"INSUFFICIENT_COVERAGE",
		"INCOMPLETE",
		"BLOCKED",
		"ERROR",
	}

	for _, st := range untrustworthyStatuses {
		t.Run("status_"+st, func(t *testing.T) {
			ctx := EvaluationContext{
				AssessmentID: "ASM-TEST-001",
				ClientID:     "TENANT-A",
				Status:       st,
			}

			// Even with 0 findings, an untrustworthy assessment must NEVER pass!
			dec, err := EvaluatePolicy(pol, []report.Finding{}, ctx)
			if err != nil {
				t.Fatalf("unexpected evaluation error: %v", err)
			}

			if dec.Reliable {
				t.Fatalf("expected Reliable=false for status %s, got true", st)
			}
			if dec.Passed {
				t.Fatalf("expected Passed=false for status %s, got true", st)
			}
			if dec.ExitCode() != clierror.ExitOperational {
				t.Fatalf("expected ExitCode 2 (ExitOperational) for status %s, got %d", st, dec.ExitCode())
			}
		})
	}

	// Execution error also returns ExitOperational (2)
	ctxErr := EvaluationContext{
		AssessmentID:   "ASM-TEST-001",
		ClientID:       "TENANT-A",
		Status:         "COMPLETED",
		ExecutionError: fmt.Errorf("underlying network failure"),
	}
	decErr, _ := EvaluatePolicy(pol, []report.Finding{}, ctxErr)
	if decErr.ExitCode() != clierror.ExitOperational {
		t.Fatalf("expected ExitCode 2 for operational error, got %d", decErr.ExitCode())
	}
}

// 7. Scope and Tenant Isolation: cross-tenant or mismatched assessment rejects evaluation
func TestEvaluator_IsolationEnforcement(t *testing.T) {
	zero := 0
	pol := &ThresholdPolicy{
		Version:     "1.0",
		MaxCritical: &zero,
	}

	// Finding from a different assessment ID
	foreignAsmFinding := makeTestFinding("f1", "Vuln", "HIGH", "https://example.com")
	foreignAsmFinding.EvidenceDetails.Details["assessment_id"] = "ASM-FOREIGN-999"

	ctx := EvaluationContext{
		AssessmentID: "ASM-LOCAL-001",
		ClientID:     "TENANT-A",
		Status:       "COMPLETED",
	}

	_, err := EvaluatePolicy(pol, []report.Finding{foreignAsmFinding}, ctx)
	if err == nil || !strings.Contains(err.Error(), "isolation violation") {
		t.Fatalf("expected isolation violation error for foreign assessment finding, got: %v", err)
	}

	// Finding from a different tenant
	foreignTenantFinding := makeTestFinding("f2", "Vuln", "HIGH", "https://example.com")
	foreignTenantFinding.EvidenceDetails.Details["assessment_id"] = "ASM-LOCAL-001"
	foreignTenantFinding.EvidenceDetails.Details["tenant_id"] = "TENANT-ATTACKER"

	_, err = EvaluatePolicy(pol, []report.Finding{foreignTenantFinding}, ctx)
	if err == nil || !strings.Contains(err.Error(), "Tenant isolation violation") {
		t.Fatalf("expected tenant isolation violation error for foreign tenant finding, got: %v", err)
	}

	// Finding with out-of-scope target
	scopedCtx := EvaluationContext{
		AssessmentID: "ASM-LOCAL-001",
		ClientID:     "TENANT-A",
		Status:       "COMPLETED",
		TargetScope:  []string{"https://app.target.com"},
	}
	outOfScopeFinding := makeTestFinding("f3", "Vuln", "HIGH", "https://attacker.com/evil")
	outOfScopeFinding.EvidenceDetails.Details["assessment_id"] = "ASM-LOCAL-001"
	outOfScopeFinding.EvidenceDetails.Details["tenant_id"] = "TENANT-A"

	_, err = EvaluatePolicy(pol, []report.Finding{outOfScopeFinding}, scopedCtx)
	if err == nil || !strings.Contains(err.Error(), "Scope isolation violation") {
		t.Fatalf("expected scope isolation violation for out-of-scope finding, got: %v", err)
	}

	// Finding with missing scope metadata (empty target) cannot silently pass
	missingScopeFinding := makeTestFinding("f4", "Vuln", "HIGH", "")
	missingScopeFinding.Target = ""
	missingScopeFinding.Endpoint = ""
	missingScopeFinding.EvidenceDetails.Location = ""
	missingScopeFinding.EvidenceDetails.Details["assessment_id"] = "ASM-LOCAL-001"
	missingScopeFinding.EvidenceDetails.Details["tenant_id"] = "TENANT-A"

	_, err = EvaluatePolicy(pol, []report.Finding{missingScopeFinding}, scopedCtx)
	if err == nil || !strings.Contains(err.Error(), "Scope isolation violation") {
		t.Fatalf("expected scope isolation violation for finding with missing scope metadata, got: %v", err)
	}
}

// 8. Multiple Simultaneous Violations and Deterministic Summary Formatting
func TestEvaluator_MultipleViolationsAndSummaryFormat(t *testing.T) {
	zero := 0
	one := 1

	pol := &ThresholdPolicy{
		Version:     "1.0",
		Name:        "production-strict-gate",
		MaxCritical: &zero,
		MaxHigh:     &one,
		MaxMedium:   &zero,
	}

	ctx := EvaluationContext{
		AssessmentID: "ASM-TEST-001",
		ClientID:     "TENANT-A",
		Status:       "COMPLETED",
	}

	findings := []report.Finding{
		makeTestFinding("fc1", "SQLi", "CRITICAL", "https://example.com/1"),
		makeTestFinding("fh1", "CSRF", "HIGH", "https://example.com/2"),
		makeTestFinding("fh2", "IDOR", "HIGH", "https://example.com/3"),
		makeTestFinding("fm1", "Missing Header", "MEDIUM", "https://example.com/4"),
		makeTestFinding("fi1", "Server Banner", "INFO", "https://example.com/5"),
	}

	dec, err := EvaluatePolicy(pol, findings, ctx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if dec.Passed {
		t.Fatalf("expected multiple violations to fail policy, got passed")
	}
	if len(dec.Violations) != 3 {
		t.Fatalf("expected 3 violations (CRITICAL, HIGH, MEDIUM), got %d: %+v", len(dec.Violations), dec.Violations)
	}

	// Verify deterministic sorting: CRITICAL first, then HIGH, then MEDIUM
	if dec.Violations[0].Severity != "CRITICAL" {
		t.Errorf("expected first violation to be CRITICAL, got %s", dec.Violations[0].Severity)
	}
	if dec.Violations[1].Severity != "HIGH" {
		t.Errorf("expected second violation to be HIGH, got %s", dec.Violations[1].Severity)
	}
	if dec.Violations[2].Severity != "MEDIUM" {
		t.Errorf("expected third violation to be MEDIUM, got %s", dec.Violations[2].Severity)
	}

	summary := FormatDecisionSummary(dec)
	if !strings.Contains(summary, "SECURITY POLICY EVALUATION") {
		t.Errorf("expected summary header, got: %s", summary)
	}
	if !strings.Contains(summary, "FAILED (Threshold Exceeded)") {
		t.Errorf("expected FAILED verdict in summary, got: %s", summary)
	}
	if !strings.Contains(summary, "[VIOLATION]") {
		t.Errorf("expected [VIOLATION] marker in summary, got: %s", summary)
	}
}
