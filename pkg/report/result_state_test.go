package report

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestResultStates_CanonicalEnumsAndValidation(t *testing.T) {
	canonicalStates := []FindingStatus{
		FindingStatusConfirmed,
		FindingStatusSuspected,
		FindingStatusInconclusive,
		FindingStatusNotTested,
		FindingStatusError,
	}

	for _, s := range canonicalStates {
		if !IsValidFindingStatus(s) {
			t.Errorf("expected IsValidFindingStatus(%q) to be true", s)
		}
		if err := ValidateFindingStatus(s); err != nil {
			t.Errorf("expected ValidateFindingStatus(%q) to be nil, got %v", s, err)
		}
	}

	invalidStates := []FindingStatus{
		"",
		"UNKNOWN",
		"PASS",
		"FAILED_STATE",
		"INVALID",
		"NONE",
		"123",
	}

	for _, s := range invalidStates {
		if IsValidFindingStatus(s) {
			t.Errorf("expected IsValidFindingStatus(%q) to be false", s)
		}
		if err := ValidateFindingStatus(s); err == nil {
			t.Errorf("expected ValidateFindingStatus(%q) to return error, got nil", s)
		}
	}
}

func TestResultStates_NormalizeAliases(t *testing.T) {
	testCases := []struct {
		input    FindingStatus
		expected FindingStatus
	}{
		// CONFIRMED aliases
		{"confirmed", FindingStatusConfirmed},
		{"CONFIRMED", FindingStatusConfirmed},
		{"VERIFIED", FindingStatusConfirmed},
		{"verified", FindingStatusConfirmed},
		{"PROVEN", FindingStatusConfirmed},
		{"proven", FindingStatusConfirmed},

		// SUSPECTED aliases
		{"suspected", FindingStatusSuspected},
		{"SUSPECTED", FindingStatusSuspected},
		{"DETECTED", FindingStatusSuspected},
		{"detected", FindingStatusSuspected},
		{"CANDIDATE", FindingStatusSuspected},
		{"candidate", FindingStatusSuspected},
		{"POTENTIAL", FindingStatusSuspected},
		{"potential", FindingStatusSuspected},
		{"UNVERIFIED", FindingStatusSuspected},
		{"unverified", FindingStatusSuspected},

		// INCONCLUSIVE aliases
		{"inconclusive", FindingStatusInconclusive},
		{"INCONCLUSIVE", FindingStatusInconclusive},
		{"INDETERMINATE", FindingStatusInconclusive},
		{"indeterminate", FindingStatusInconclusive},
		{"UNDETERMINED", FindingStatusInconclusive},
		{"undetermined", FindingStatusInconclusive},
		{"NOT_EXPOSED", FindingStatusInconclusive},
		{"not_exposed", FindingStatusInconclusive},

		// NOT_TESTED aliases
		{"not_tested", FindingStatusNotTested},
		{"NOT_TESTED", FindingStatusNotTested},
		{"NOT-TESTED", FindingStatusNotTested},
		{"NOTTESTED", FindingStatusNotTested},
		{"BLOCKED", FindingStatusNotTested},
		{"blocked", FindingStatusNotTested},
		{"SKIPPED", FindingStatusNotTested},
		{"skipped", FindingStatusNotTested},
		{"OMITTED", FindingStatusNotTested},
		{"omitted", FindingStatusNotTested},
		{"UNTESTED", FindingStatusNotTested},
		{"untested", FindingStatusNotTested},

		// ERROR aliases
		{"error", FindingStatusError},
		{"ERROR", FindingStatusError},
		{"FAIL", FindingStatusError},
		{"fail", FindingStatusError},
		{"FAILED", FindingStatusError},
		{"failed", FindingStatusError},
		{"FAILURE", FindingStatusError},
		{"failure", FindingStatusError},
		{"ERR", FindingStatusError},
		{"err", FindingStatusError},
		{"CRASH", FindingStatusError},
		{"crash", FindingStatusError},
		{"TIMEOUT", FindingStatusError},
		{"timeout", FindingStatusError},

		// Unrecognized/fallback: must safely default to INCONCLUSIVE and never to SUSPECTED or CONFIRMED
		{"UNKNOWN_INVALID_STATUS", FindingStatusInconclusive},
		{"", FindingStatusInconclusive},
		{"GARBAGE_STATUS", FindingStatusInconclusive},
		{"12345", FindingStatusInconclusive},
	}

	for _, tc := range testCases {
		got := NormalizeFindingStatus(tc.input)
		if got != tc.expected {
			t.Errorf("NormalizeFindingStatus(%q) = %q, want %q", tc.input, got, tc.expected)
		}
	}

	// Security invariant: unknown or malformed input must NEVER silently become SUSPECTED or CONFIRMED
	invalidInputs := []string{"", "UNKNOWN", "MALFORMED", "UNRECOGNIZED_STATUS", "FOOBAR", "null"}
	for _, raw := range invalidInputs {
		norm := NormalizeFindingStatus(FindingStatus(raw))
		if norm == FindingStatusSuspected {
			t.Errorf("SECURITY INVARIANT VIOLATED: invalid status %q silently normalized to SUSPECTED", raw)
		}
		if norm == FindingStatusConfirmed {
			t.Errorf("SECURITY INVARIANT VIOLATED: invalid status %q silently normalized to CONFIRMED", raw)
		}

		// ParseFindingStatus must return an explicit error
		if _, err := ParseFindingStatus(raw); err == nil {
			t.Errorf("ParseFindingStatus(%q) expected error for malformed input, got nil", raw)
		}
	}
}

func TestResultStates_ActualSemantics_NoFalseSecurityInference(t *testing.T) {
	// 1. TIMEOUT: Network transport error must NOT infer an exposure or protection
	timeoutFinding := Finding{
		ID:       "fnd-timeout",
		Title:    "Connection Timeout Test",
		Status:   NormalizeFindingStatus("TIMEOUT"),
		Severity: SeverityHigh,
	}
	if timeoutFinding.Status != FindingStatusError {
		t.Errorf("TIMEOUT alias must normalize to ERROR, got %s", timeoutFinding.Status)
	}
	if timeoutFinding.Status == FindingStatusSuspected || timeoutFinding.Status == FindingStatusConfirmed {
		t.Errorf("DEFECT: TIMEOUT was inferred as a security finding")
	}

	// 2. BLOCKED: Safety policy boundary must NOT infer protection or confirmed vulnerability
	blockedFinding := Finding{
		ID:       "fnd-blocked",
		Title:    "Scope Blocked Destination",
		Status:   NormalizeFindingStatus("BLOCKED"),
		Severity: SeverityCritical,
	}
	if blockedFinding.Status != FindingStatusNotTested {
		t.Errorf("BLOCKED alias must normalize to NOT_TESTED, got %s", blockedFinding.Status)
	}
	if blockedFinding.Status == FindingStatusConfirmed || blockedFinding.Status == FindingStatusSuspected {
		t.Errorf("DEFECT: BLOCKED check was inferred as a vulnerability")
	}

	// 3. SKIPPED: Omitted checks must NOT produce confirmed findings
	skippedFinding := Finding{
		ID:       "fnd-skipped",
		Title:    "Precondition Skipped Test",
		Status:   NormalizeFindingStatus("SKIPPED"),
		Severity: SeverityMedium,
	}
	if skippedFinding.Status != FindingStatusNotTested {
		t.Errorf("SKIPPED alias must normalize to NOT_TESTED, got %s", skippedFinding.Status)
	}

	// 4. NOT_EXPOSED: Access barrier (401/403) maps to INCONCLUSIVE in finding lifecycle
	notExposedFinding := Finding{
		ID:       "fnd-not-exposed",
		Title:    "Access Boundary 403 Observed",
		Status:   NormalizeFindingStatus("NOT_EXPOSED"),
		Severity: SeverityMedium,
	}
	if notExposedFinding.Status != FindingStatusInconclusive {
		t.Errorf("NOT_EXPOSED alias must normalize to INCONCLUSIVE, got %s", notExposedFinding.Status)
	}
	if notExposedFinding.Status == FindingStatusConfirmed {
		t.Errorf("DEFECT: NOT_EXPOSED was inferred as CONFIRMED")
	}
}

func TestResultStates_StateTransitions(t *testing.T) {
	// From CONFIRMED: cannot transition to any other status (proven findings cannot be demoted)
	forbiddenFromConfirmed := []FindingStatus{
		FindingStatusSuspected,
		FindingStatusInconclusive,
		FindingStatusNotTested,
		FindingStatusError,
	}
	for _, to := range forbiddenFromConfirmed {
		if IsValidFindingStatusTransition(FindingStatusConfirmed, to) {
			t.Errorf("transition CONFIRMED -> %s should be invalid", to)
		}
	}
	if !IsValidFindingStatusTransition(FindingStatusConfirmed, FindingStatusConfirmed) {
		t.Errorf("transition CONFIRMED -> CONFIRMED should be valid (identity)")
	}

	// From SUSPECTED: can transition to any valid status
	validFromSuspected := []FindingStatus{
		FindingStatusConfirmed,
		FindingStatusSuspected,
		FindingStatusInconclusive,
		FindingStatusNotTested,
		FindingStatusError,
	}
	for _, to := range validFromSuspected {
		if !IsValidFindingStatusTransition(FindingStatusSuspected, to) {
			t.Errorf("transition SUSPECTED -> %s should be valid", to)
		}
	}

	// From INCONCLUSIVE: can transition to other states
	validFromInconclusive := []FindingStatus{
		FindingStatusConfirmed,
		FindingStatusSuspected,
		FindingStatusInconclusive,
		FindingStatusNotTested,
		FindingStatusError,
	}
	for _, to := range validFromInconclusive {
		if !IsValidFindingStatusTransition(FindingStatusInconclusive, to) {
			t.Errorf("transition INCONCLUSIVE -> %s should be valid", to)
		}
	}

	// From NOT_TESTED: can transition to other states upon execution
	validFromNotTested := []FindingStatus{
		FindingStatusConfirmed,
		FindingStatusSuspected,
		FindingStatusInconclusive,
		FindingStatusNotTested,
		FindingStatusError,
	}
	for _, to := range validFromNotTested {
		if !IsValidFindingStatusTransition(FindingStatusNotTested, to) {
			t.Errorf("transition NOT_TESTED -> %s should be valid", to)
		}
	}

	// From ERROR: can transition upon retry/re-execution
	validFromError := []FindingStatus{
		FindingStatusConfirmed,
		FindingStatusSuspected,
		FindingStatusInconclusive,
		FindingStatusNotTested,
		FindingStatusError,
	}
	for _, to := range validFromError {
		if !IsValidFindingStatusTransition(FindingStatusError, to) {
			t.Errorf("transition ERROR -> %s should be valid", to)
		}
	}

	// Invalid inputs
	if IsValidFindingStatusTransition("INVALID", FindingStatusConfirmed) {
		t.Errorf("transition from invalid status should be rejected")
	}
	if IsValidFindingStatusTransition(FindingStatusSuspected, "INVALID") {
		t.Errorf("transition to invalid status should be rejected")
	}
}

func TestResultStates_SummarizeAndByStatus(t *testing.T) {
	findings := []Finding{
		{ID: "f1", Status: FindingStatusConfirmed, Severity: SeverityCritical},
		{ID: "f2", Status: FindingStatusConfirmed, Severity: SeverityHigh},
		{ID: "f3", Status: FindingStatusSuspected, Severity: SeverityMedium},
		{ID: "f4", Status: FindingStatusSuspected, Severity: SeverityLow},
		{ID: "f5", Status: FindingStatusSuspected, Severity: SeverityInfo},
		{ID: "f6", Status: FindingStatusInconclusive, Severity: SeverityMedium},
		{ID: "f7", Status: FindingStatusNotTested, Severity: SeverityLow},
		{ID: "f8", Status: FindingStatusError, Severity: SeverityMedium},
	}

	s := Summarize(findings)

	if s.TotalFindings != 8 {
		t.Errorf("expected 8 total findings, got %d", s.TotalFindings)
	}
	if s.ConfirmedCount != 2 {
		t.Errorf("expected 2 confirmed findings, got %d", s.ConfirmedCount)
	}
	if s.SuspectedCount != 3 {
		t.Errorf("expected 3 suspected findings, got %d", s.SuspectedCount)
	}
	if s.InconclusiveStatusCount != 1 {
		t.Errorf("expected 1 inconclusive finding, got %d", s.InconclusiveStatusCount)
	}
	if s.NotTestedCount != 1 {
		t.Errorf("expected 1 not tested finding, got %d", s.NotTestedCount)
	}
	if s.ErrorCount != 1 {
		t.Errorf("expected 1 error finding, got %d", s.ErrorCount)
	}

	if s.ByStatus[FindingStatusConfirmed] != 2 {
		t.Errorf("ByStatus[CONFIRMED] = %d, want 2", s.ByStatus[FindingStatusConfirmed])
	}
	if s.ByStatus[FindingStatusSuspected] != 3 {
		t.Errorf("ByStatus[SUSPECTED] = %d, want 3", s.ByStatus[FindingStatusSuspected])
	}
	if s.ByStatus[FindingStatusInconclusive] != 1 {
		t.Errorf("ByStatus[INCONCLUSIVE] = %d, want 1", s.ByStatus[FindingStatusInconclusive])
	}
	if s.ByStatus[FindingStatusNotTested] != 1 {
		t.Errorf("ByStatus[NOT_TESTED] = %d, want 1", s.ByStatus[FindingStatusNotTested])
	}
	if s.ByStatus[FindingStatusError] != 1 {
		t.Errorf("ByStatus[ERROR] = %d, want 1", s.ByStatus[FindingStatusError])
	}

	// Empty findings
	emptySummary := Summarize(nil)
	if emptySummary.TotalFindings != 0 || emptySummary.ConfirmedCount != 0 {
		t.Errorf("expected empty summary for nil findings")
	}
}

func TestResultStates_PrioritizeOrdering(t *testing.T) {
	fError := Finding{ID: "f-err", Status: FindingStatusError, Severity: SeverityCritical, Category: "cat-a", Endpoint: "/a"}
	fNotTested := Finding{ID: "f-nt", Status: FindingStatusNotTested, Severity: SeverityCritical, Category: "cat-b", Endpoint: "/b"}
	fInconclusive := Finding{ID: "f-inc", Status: FindingStatusInconclusive, Severity: SeverityCritical, Category: "cat-c", Endpoint: "/c"}
	fSuspected := Finding{ID: "f-susp", Status: FindingStatusSuspected, Severity: SeverityCritical, Category: "cat-d", Endpoint: "/d"}
	fConfirmed := Finding{ID: "f-conf", Status: FindingStatusConfirmed, Severity: SeverityCritical, Category: "cat-e", Endpoint: "/e"}

	input := []Finding{fError, fSuspected, fNotTested, fConfirmed, fInconclusive}
	prioritized := Prioritize(input)

	if len(prioritized) != 5 {
		t.Fatalf("expected 5 prioritized findings, got %d", len(prioritized))
	}

	// Precedence order: CONFIRMED > SUSPECTED > INCONCLUSIVE > NOT_TESTED > ERROR
	expectedOrder := []FindingStatus{
		FindingStatusConfirmed,
		FindingStatusSuspected,
		FindingStatusInconclusive,
		FindingStatusNotTested,
		FindingStatusError,
	}

	for i, exp := range expectedOrder {
		if prioritized[i].Status != exp {
			t.Errorf("prioritized index %d: expected status %s, got %s (ID: %s)", i, exp, prioritized[i].Status, prioritized[i].ID)
		}
	}
}

func TestResultStates_DeduplicationPreservation(t *testing.T) {
	// Guard 1: SUSPECTED finding cannot be upgraded to CONFIRMED without active verification or static proof
	fSuspected := Finding{
		Target:         "https://example.com",
		Category:       "cors-wildcard",
		Endpoint:       "https://example.com/api",
		Method:         "GET",
		Title:          "CORS Wildcard",
		Status:         FindingStatusSuspected,
		AnalysisMethod: AnalysisMethodStatic,
		Verification: VerificationRecord{
			Status: VerificationDetected,
			Result: "Pattern detected in bundle",
		},
	}

	// Unverified active probe candidate claiming CONFIRMED
	fUnverifiedProbe := Finding{
		Target:         "https://example.com",
		Category:       "cors-wildcard",
		Endpoint:       "https://example.com/api",
		Method:         "GET",
		Title:          "CORS Wildcard",
		Status:         FindingStatusConfirmed,
		AnalysisMethod: AnalysisMethodActive,
		Verification: VerificationRecord{
			Status: VerificationNotVerified, // Not verified!
			Result: "Probe did not succeed",
		},
	}

	merged := DeduplicateFindings([]Finding{fSuspected, fUnverifiedProbe})
	if len(merged) != 1 {
		t.Fatalf("expected 1 merged finding, got %d", len(merged))
	}
	if merged[0].Status == FindingStatusConfirmed {
		t.Errorf("SUSPECTED finding was illegally upgraded to CONFIRMED by an unverified probe")
	}

	// Guard 2: Contradictory evidence and limitations preserved
	fVerified := Finding{
		Target:         "https://example.com",
		Category:       "sql-injection",
		Endpoint:       "https://example.com/search",
		Method:         "GET",
		Title:          "SQL Injection",
		Status:         FindingStatusConfirmed,
		AnalysisMethod: AnalysisMethodActive,
		Verification: VerificationRecord{
			Status:            VerificationVerified,
			Result:            "Empirically proven via time-delay payload",
			ReproductionSteps: []string{"curl -H 'X-Test: 1' https://example.com/search"},
		},
		Evidence: "Response time: 5.2s",
	}

	fProtectedCondition := Finding{
		Target:         "https://example.com",
		Category:       "sql-injection",
		Endpoint:       "https://example.com/search",
		Method:         "GET",
		Title:          "SQL Injection",
		Status:         FindingStatusInconclusive,
		AnalysisMethod: AnalysisMethodActive,
		Verification: VerificationRecord{
			Status:      VerificationNotExposed,
			Result:      "WAF blocked payload with 403 Forbidden under IP rate limit",
			Limitations: []string{"WAF rate limiting triggers after 3 consecutive requests"},
		},
		Evidence: "HTTP 403 Forbidden received from Cloudflare WAF",
		EvidenceDetails: EvidenceDetails{
			NegativeEvidence: "WAF blocked subsequent probe with 403 Forbidden",
		},
	}

	mergedProtected := DeduplicateFindings([]Finding{fVerified, fProtectedCondition})
	if len(mergedProtected) != 1 {
		t.Fatalf("expected 1 merged finding, got %d", len(mergedProtected))
	}

	// Status must stay CONFIRMED
	if mergedProtected[0].Status != FindingStatusConfirmed {
		t.Errorf("CONFIRMED finding lost its verified status during merge, got %s", mergedProtected[0].Status)
	}

	// But contradictory evidence and limitations MUST be preserved!
	if !strings.Contains(mergedProtected[0].Evidence, "HTTP 403 Forbidden") {
		t.Errorf("expected merged evidence to retain WAF block note, got: %s", mergedProtected[0].Evidence)
	}
	if mergedProtected[0].EvidenceDetails.NegativeEvidence == "" {
		t.Errorf("expected negative evidence to be preserved")
	}
	if len(mergedProtected[0].Verification.Limitations) == 0 {
		t.Errorf("expected verification limitations to be preserved")
	}
	// Material verification result changes must NOT be concealed!
	if !strings.Contains(mergedProtected[0].Verification.Result, "WAF blocked payload with 403 Forbidden") {
		t.Errorf("expected merged verification result to retain contradictory check note, got: %s", mergedProtected[0].Verification.Result)
	}

	// Guard 3: Reverse ordering (INCONCLUSIVE first, then CONFIRMED)
	mergedReverse := DeduplicateFindings([]Finding{fProtectedCondition, fVerified})
	if len(mergedReverse) != 1 {
		t.Fatalf("expected 1 merged finding, got %d", len(mergedReverse))
	}
	if mergedReverse[0].Status != FindingStatusConfirmed {
		t.Errorf("expected upgraded status CONFIRMED when valid proof arrives, got %s", mergedReverse[0].Status)
	}
	if mergedReverse[0].EvidenceDetails.NegativeEvidence == "" {
		t.Errorf("expected earlier negative evidence to be preserved when upgraded to CONFIRMED")
	}
}

func TestResultStates_ReportExports(t *testing.T) {
	findings := []Finding{
		{ID: "f-conf", Status: FindingStatusConfirmed, Severity: SeverityHigh, Title: "Confirmed Bug", Target: "https://example.com", Endpoint: "/a"},
		{ID: "f-susp", Status: FindingStatusSuspected, Severity: SeverityMedium, Title: "Suspected Issue", Target: "https://example.com", Endpoint: "/b"},
		{ID: "f-inc", Status: FindingStatusInconclusive, Severity: SeverityLow, Title: "Inconclusive Check", Target: "https://example.com", Endpoint: "/c"},
		{ID: "f-nt", Status: FindingStatusNotTested, Severity: SeverityLow, Title: "Skipped Check", Target: "https://example.com", Endpoint: "/d"},
		{ID: "f-err", Status: FindingStatusError, Severity: SeverityInfo, Title: "Errored Check", Target: "https://example.com", Endpoint: "/e"},
	}

	rep := BuildReport("https://example.com", findings)

	// 1. JSON Export
	jsonBytes, err := GenerateJSON(rep)
	if err != nil {
		t.Fatalf("GenerateJSON failed: %v", err)
	}
	var roundTrip Report
	if err := json.Unmarshal(jsonBytes, &roundTrip); err != nil {
		t.Fatalf("failed to unmarshal JSON report: %v", err)
	}
	if roundTrip.Summary.ConfirmedCount != 1 || roundTrip.Summary.SuspectedCount != 1 ||
		roundTrip.Summary.InconclusiveStatusCount != 1 || roundTrip.Summary.NotTestedCount != 1 ||
		roundTrip.Summary.ErrorCount != 1 {
		t.Errorf("JSON export summary status count mismatch: %+v", roundTrip.Summary)
	}

	// 2. SARIF Export
	sarifLog := BuildSARIFLog(rep)
	if len(sarifLog.Runs) == 0 || len(sarifLog.Runs[0].Results) != 5 {
		t.Fatalf("expected 5 results in SARIF run, got %d", len(sarifLog.Runs[0].Results))
	}
	for _, res := range sarifLog.Runs[0].Results {
		st, ok := res.Properties["status"]
		if !ok || st == "" {
			t.Errorf("SARIF result missing status property: %+v", res.Properties)
		}
	}

	// 3. HTML Export
	htmlStr, err := GenerateHTML(rep)
	if err != nil {
		t.Fatalf("GenerateHTML failed: %v", err)
	}
	if !strings.Contains(htmlStr, "badge-CONFIRMED") {
		t.Errorf("HTML report missing badge-CONFIRMED")
	}
	if !strings.Contains(htmlStr, "badge-SUSPECTED") {
		t.Errorf("HTML report missing badge-SUSPECTED")
	}
	if !strings.Contains(htmlStr, "badge-INCONCLUSIVE") {
		t.Errorf("HTML report missing badge-INCONCLUSIVE")
	}
}
