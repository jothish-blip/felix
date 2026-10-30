package report

import (
	"strings"
	"testing"
)

// TestReport_ZeroFindingsAndCleanScans verifies that clean assessments pass integrity checks
// and produce honest zero-finding representations across formats.
func TestReport_ZeroFindingsAndCleanScans(t *testing.T) {
	rep := Report{
		Target:           "https://safe.example.com",
		CompletionStatus: "COMPLETED",
		Summary: Summary{
			TotalFindings: 0,
			CriticalCount: 0,
			HighCount:     0,
			MediumCount:   0,
			LowCount:      0,
			InfoCount:     0,
		},
		Findings: []Finding{},
	}

	if err := ValidateReportIntegrity(rep); err != nil {
		t.Fatalf("clean zero-finding report failed integrity check: %v", err)
	}

	// Verify JSON generation
	jsonData, err := GenerateJSON(rep)
	if err != nil {
		t.Fatalf("GenerateJSON failed on clean report: %v", err)
	}
	if !strings.Contains(string(jsonData), `"total_findings": 0`) {
		t.Errorf("expected total_findings 0 in JSON output")
	}

	// Verify Commercial JSON generation
	cr := BuildCommercialReport(rep)
	commData, err := GenerateCommercialJSON(cr)
	if err != nil {
		t.Fatalf("GenerateCommercialJSON failed on clean report: %v", err)
	}
	if len(commData) == 0 {
		t.Errorf("GenerateCommercialJSON returned empty bytes")
	}

	// Verify SARIF output conforms to official 2.1.0 schema
	sarifData, err := GenerateSARIF(rep)
	if err != nil {
		t.Fatalf("GenerateSARIF failed on clean report: %v", err)
	}
	if err := ValidateSARIF(sarifData); err != nil {
		t.Fatalf("clean SARIF failed schema validation: %v", err)
	}
}

// TestReport_MultipleSeveritiesAndReconciliation verifies integrity checks when multiple severities are present.
func TestReport_MultipleSeveritiesAndReconciliation(t *testing.T) {
	findings := []Finding{
		{ID: "C1", Title: "RCE", Severity: SeverityCritical, Category: "Injection"},
		{ID: "H1", Title: "SQLi", Severity: SeverityHigh, Category: "Injection"},
		{ID: "M1", Title: "XSS", Severity: SeverityMedium, Category: "XSS"},
		{ID: "L1", Title: "Clickjacking", Severity: SeverityLow, Category: "Headers"},
		{ID: "I1", Title: "Version Banner", Severity: SeverityInfo, Category: "Information"},
	}

	rep := Report{
		Target:           "https://target.example.com",
		CompletionStatus: "COMPLETED",
		Summary: Summary{
			TotalFindings: 5,
			CriticalCount: 1,
			HighCount:     1,
			MediumCount:   1,
			LowCount:      1,
			InfoCount:     1,
		},
		Findings: findings,
	}

	if err := ValidateReportIntegrity(rep); err != nil {
		t.Fatalf("valid multi-severity report failed integrity check: %v", err)
	}

	// Test SARIF validation with findings
	sarifData, err := GenerateSARIF(rep)
	if err != nil {
		t.Fatalf("GenerateSARIF failed: %v", err)
	}
	if err := ValidateSARIF(sarifData); err != nil {
		t.Fatalf("SARIF with findings failed schema validation: %v", err)
	}
}

// TestReport_IntegrityFailureScenarios covers all negative and corruption scenarios in ValidateReportIntegrity.
func TestReport_IntegrityFailureScenarios(t *testing.T) {
	baseFinding := Finding{ID: "F1", Title: "Test", Severity: SeverityHigh}

	tests := []struct {
		name        string
		rep         Report
		errContains string
	}{
		{
			name: "missing target and empty targets",
			rep: Report{
				Target:           "",
				Targets:          nil,
				CompletionStatus: "COMPLETED",
				Findings:         []Finding{baseFinding},
			},
			errContains: "missing assessment target or target scope",
		},
		{
			name: "summary claims findings but findings slice is empty",
			rep: Report{
				Target:           "https://example.com",
				CompletionStatus: "COMPLETED",
				Summary: Summary{
					TotalFindings: 3,
					HighCount:     3,
				},
				Findings: []Finding{}, // empty!
			},
			errContains: "summary claims 3 finding(s), but findings collection is empty",
		},
		{
			name: "severity breakdown contradicts summary total",
			rep: Report{
				Target:           "https://example.com",
				CompletionStatus: "COMPLETED",
				Summary: Summary{
					TotalFindings: 1,
					HighCount:     2,
				},
				Findings: []Finding{baseFinding},
			},
			errContains: "contradicts summary total",
		},
		{
			name: "individual severity count mismatch",
			rep: Report{
				Target:           "https://example.com",
				CompletionStatus: "COMPLETED",
				Summary: Summary{
					TotalFindings: 2,
					HighCount:     2, // Claims 2 High
				},
				Findings: []Finding{baseFinding, {ID: "F2", Title: "Low Finding", Severity: SeverityLow}},
			},
			errContains: "high finding count mismatch",
		},
		{
			name: "failed assessment claiming positive risk score",
			rep: Report{
				Target:             "https://example.com",
				CompletionStatus:   "FAILED",
				RiskScoreAvailable: true,
				RiskScore:          65,
				Findings:           []Finding{baseFinding},
			},
			errContains: "assessment status is FAILED but claims positive risk score",
		},
		{
			name: "cancelled assessment claiming positive risk score",
			rep: Report{
				Target:             "https://example.com",
				CompletionStatus:   "CANCELLED",
				RiskScoreAvailable: true,
				RiskScore:          40,
				Findings:           []Finding{baseFinding},
			},
			errContains: "assessment status is CANCELLED but claims positive risk score",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateReportIntegrity(tt.rep)
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tt.errContains)
			}
			if !strings.Contains(err.Error(), tt.errContains) {
				t.Errorf("error %q does not contain expected %q", err.Error(), tt.errContains)
			}
		})
	}
}

// TestReport_Regression_VerificationRateAttemptedReconciliation verifies that
// Summarize correctly derives AttemptedCount from genuine active verification operations,
// preserving distinct semantic rates between VerificationRateAttempted and VerificationRateTotal.
//
// In NodeGoat:
// - 5 missing security headers actively audited and verified (Attempted: true, Status: VERIFIED)
// - 1 session cookie on unencrypted HTTP (Attempted: false, Status: OBSERVED)
// - 1 runtime header / framework disclosure (Attempted: false, Status: OBSERVED)
// - 1 public source map observed during crawl (Attempted: false, Status: OBSERVED)
//
// Metrics reconcile:
// Total Findings: 8
// Attempted Verifications: 5
// Verified Findings: 5
// Observed Inventory: 3
// VerificationRateAttempted = 5/5 = 100.0%
// VerificationRateTotal = 5/8 = 62.5%
func TestReport_Regression_VerificationRateAttemptedReconciliation(t *testing.T) {
	findings := []Finding{
		{
			ID:       "H1",
			Title:    "Missing Content-Security-Policy",
			Severity: SeverityMedium,
			Verification: VerificationRecord{
				Status:             VerificationVerified,
				Attempted:          true,
				VerificationMethod: "header_audit",
			},
			Status: FindingStatusConfirmed,
		},
		{
			ID:       "H2",
			Title:    "Missing X-Content-Type-Options",
			Severity: SeverityLow,
			Verification: VerificationRecord{
				Status:             VerificationVerified,
				Attempted:          true,
				VerificationMethod: "header_audit",
			},
			Status: FindingStatusConfirmed,
		},
		{
			ID:       "H3",
			Title:    "Missing Referrer-Policy",
			Severity: SeverityLow,
			Verification: VerificationRecord{
				Status:             VerificationVerified,
				Attempted:          true,
				VerificationMethod: "header_audit",
			},
			Status: FindingStatusConfirmed,
		},
		{
			ID:       "H4",
			Title:    "Missing Permissions-Policy",
			Severity: SeverityLow,
			Verification: VerificationRecord{
				Status:             VerificationVerified,
				Attempted:          true,
				VerificationMethod: "header_audit",
			},
			Status: FindingStatusConfirmed,
		},
		{
			ID:       "H5",
			Title:    "Missing Strict-Transport-Security",
			Severity: SeverityLow,
			Verification: VerificationRecord{
				Status:             VerificationVerified,
				Attempted:          true,
				VerificationMethod: "header_audit",
			},
			Status: FindingStatusConfirmed,
		},
		{
			ID:       "C1",
			Title:    "Session Cookie Missing Secure Flag (Target over HTTP)",
			Severity: SeverityLow,
			Verification: VerificationRecord{
				Status:             VerificationObserved,
				Attempted:          false,
				AnalysisMethod:     AnalysisMethodStatic,
				VerificationMethod: "cookie_attribute_inspection",
			},
			Status: FindingStatusConfirmed,
		},
		{
			ID:       "F1",
			Title:    "Node.js Express Framework Identified",
			Severity: SeverityInfo,
			Verification: VerificationRecord{
				Status:             VerificationObserved,
				Attempted:          false,
				AnalysisMethod:     AnalysisMethodStatic,
				VerificationMethod: "response_header_inspection",
			},
			Status: FindingStatusConfirmed,
		},
		{
			ID:       "S1",
			Title:    "Public JavaScript Source Map Discovered",
			Severity: SeverityInfo,
			Verification: VerificationRecord{
				Status:             VerificationObserved,
				Attempted:          false,
				AnalysisMethod:     AnalysisMethodStatic,
				VerificationMethod: "discovery_crawl",
			},
			Status: FindingStatusConfirmed,
		},
	}

	summary := Summarize(findings)

	if summary.TotalFindings != 8 {
		t.Fatalf("expected total findings 8, got %d", summary.TotalFindings)
	}
	if summary.VerifiedCount != 5 {
		t.Fatalf("expected verified count 5, got %d", summary.VerifiedCount)
	}
	if summary.ObservedCount != 3 {
		t.Fatalf("expected observed count 3, got %d", summary.ObservedCount)
	}
	if summary.AttemptedCount != 5 {
		t.Fatalf("expected attempted count 5, got %d (passive observations must not be counted as attempted verifications)", summary.AttemptedCount)
	}

	expectedRateAttempted := 100.0
	if summary.VerificationRateAttempted != expectedRateAttempted {
		t.Errorf("expected VerificationRateAttempted %.1f, got %.1f", expectedRateAttempted, summary.VerificationRateAttempted)
	}
	expectedRateTotal := 62.5
	if summary.VerificationRateTotal != expectedRateTotal {
		t.Errorf("expected VerificationRateTotal %.1f, got %.1f", expectedRateTotal, summary.VerificationRateTotal)
	}

	statusSum := summary.VerifiedCount + summary.DetectedCount + summary.NotVerifiedCount + summary.ObservedCount + summary.NotExposedCount
	if statusSum != summary.TotalFindings {
		t.Errorf("sum of verification status counts (%d) does not equal total findings (%d)", statusSum, summary.TotalFindings)
	}
}

// TestReport_Regression_Stage5_MixedVerificationOutcomes tests all 9 verification metric scenarios
// required by Stage 5 of the verification metric semantics audit.
func TestReport_Regression_Stage5_MixedVerificationOutcomes(t *testing.T) {
	// Scenario 1: Attempted + confirmed verified vulnerability
	f1 := Finding{
		ID:       "SCENARIO-1",
		Title:    "SQL Injection in Search Endpoint",
		Severity: SeverityCritical,
		Verification: VerificationRecord{
			Status:             VerificationVerified,
			Attempted:          true,
			AnalysisMethod:     AnalysisMethodActive,
			VerificationMethod: "error_based_sqli_probe",
		},
		Status: FindingStatusConfirmed,
	}

	// Scenario 2: Attempted + inconclusive
	f2 := Finding{
		ID:       "SCENARIO-2",
		Title:    "Potential SSRF on Webhook URL",
		Severity: SeverityHigh,
		Verification: VerificationRecord{
			Status:             VerificationNotVerified,
			Attempted:          true,
			AnalysisMethod:     AnalysisMethodActive,
			VerificationMethod: "active_get_probe",
			Result:             "Response timeout during callback verification",
		},
		Status: FindingStatusInconclusive,
	}

	// Scenario 3: Passive observation where no verification attempted
	f3 := Finding{
		ID:       "SCENARIO-3",
		Title:    "Public JavaScript Source Map Discovered",
		Severity: SeverityInfo,
		Verification: VerificationRecord{
			Status:             VerificationObserved,
			Attempted:          false,
			AnalysisMethod:     AnalysisMethodStatic,
			VerificationMethod: "discovery_crawl",
		},
		Status: FindingStatusConfirmed,
	}

	// Scenario 4: Verified configuration weakness (security header audit)
	f4 := Finding{
		ID:       "SCENARIO-4",
		Title:    "Missing Content-Security-Policy",
		Severity: SeverityMedium,
		Verification: VerificationRecord{
			Status:             VerificationVerified,
			Attempted:          true,
			AnalysisMethod:     AnalysisMethodActive,
			VerificationMethod: "header_audit",
		},
		Status: FindingStatusConfirmed,
	}

	// Scenario 5: Negative control boundary
	f5 := Finding{
		ID:       "SCENARIO-5",
		Title:    "Admin API Route Endpoint",
		Severity: SeverityInfo,
		Verification: VerificationRecord{
			Status:             VerificationNotExposed,
			Attempted:          true,
			AnalysisMethod:     AnalysisMethodActive,
			VerificationMethod: "auth_barrier_check",
		},
		Status: FindingStatusConfirmed,
	}

	// Scenario 6: Registered policy never executed (safety block or skipped)
	f6 := Finding{
		ID:       "SCENARIO-6",
		Title:    "Hardcoded AWS Secret Key In Source",
		Severity: SeverityCritical,
		Verification: VerificationRecord{
			Status:             VerificationNotVerified,
			Attempted:          false,
			AnalysisMethod:     AnalysisMethodStatic,
			VerificationMethod: "safety_block",
			Result:             "Safety policy blocked live credential probe",
		},
		Status: FindingStatusNotTested,
	}

	// Scenario 7: Timeout/error path
	f7 := Finding{
		ID:       "SCENARIO-7",
		Title:    "Path Traversal Probe",
		Severity: SeverityHigh,
		Verification: VerificationRecord{
			Status:             VerificationNotVerified,
			Attempted:          true,
			AnalysisMethod:     AnalysisMethodActive,
			VerificationMethod: "traversal_probe",
			Result:             "Connection reset by peer during probe execution",
		},
		Status: FindingStatusError,
	}

	// Scenario 8: Mixture report asserting attempted-rate vs total-rate
	mixedFindings := []Finding{f1, f2, f3, f4, f5, f6, f7}
	sum := Summarize(mixedFindings)

	if sum.TotalFindings != 7 {
		t.Fatalf("expected total findings 7, got %d", sum.TotalFindings)
	}
	// Attempted: f1, f2, f4, f5, f7 = 5
	if sum.AttemptedCount != 5 {
		t.Errorf("expected AttemptedCount 5, got %d", sum.AttemptedCount)
	}
	// Verified: f1, f4 = 2
	if sum.VerifiedCount != 2 {
		t.Errorf("expected VerifiedCount 2, got %d", sum.VerifiedCount)
	}
	// NotVerified: f2, f6, f7 = 3
	if sum.NotVerifiedCount != 3 {
		t.Errorf("expected NotVerifiedCount 3, got %d", sum.NotVerifiedCount)
	}
	// Observed: f3 = 1
	if sum.ObservedCount != 1 {
		t.Errorf("expected ObservedCount 1, got %d", sum.ObservedCount)
	}
	// NotExposed: f5 = 1
	if sum.NotExposedCount != 1 {
		t.Errorf("expected NotExposedCount 1, got %d", sum.NotExposedCount)
	}

	// VerificationRateAttempted: 2 / 5 * 100 = 40.0%
	expectedAttemptedRate := 40.0
	if sum.VerificationRateAttempted != expectedAttemptedRate {
		t.Errorf("expected VerificationRateAttempted %.1f, got %.1f", expectedAttemptedRate, sum.VerificationRateAttempted)
	}

	// VerificationRateTotal: 2 / 7 * 100 = 28.6%
	expectedTotalRate := 28.6
	if sum.VerificationRateTotal != expectedTotalRate {
		t.Errorf("expected VerificationRateTotal %.1f, got %.1f", expectedTotalRate, sum.VerificationRateTotal)
	}

	// Status counts check
	if sum.ByStatus[FindingStatusConfirmed] != 4 { // f1, f3, f4, f5
		t.Errorf("expected 4 Confirmed, got %d", sum.ByStatus[FindingStatusConfirmed])
	}
	if sum.ByStatus[FindingStatusInconclusive] != 1 { // f2
		t.Errorf("expected 1 Inconclusive, got %d", sum.ByStatus[FindingStatusInconclusive])
	}
	if sum.ByStatus[FindingStatusNotTested] != 1 { // f6
		t.Errorf("expected 1 NotTested, got %d", sum.ByStatus[FindingStatusNotTested])
	}
	if sum.ByStatus[FindingStatusError] != 1 { // f7
		t.Errorf("expected 1 Error, got %d", sum.ByStatus[FindingStatusError])
	}

	// Scenario 9: Zero attempts and zero findings (confirming 0.0%, no panics or NaNs)
	zeroFindings := []Finding{}
	zeroSum := Summarize(zeroFindings)
	if zeroSum.TotalFindings != 0 || zeroSum.AttemptedCount != 0 || zeroSum.VerifiedCount != 0 {
		t.Errorf("expected 0 for all counts in empty findings, got total=%d attempted=%d verified=%d",
			zeroSum.TotalFindings, zeroSum.AttemptedCount, zeroSum.VerifiedCount)
	}
	if zeroSum.VerificationRateAttempted != 0.0 || zeroSum.VerificationRateTotal != 0.0 {
		t.Errorf("expected 0.0 rates for empty findings, got attempted=%.1f total=%.1f",
			zeroSum.VerificationRateAttempted, zeroSum.VerificationRateTotal)
	}

	// Zero attempts with passive observations only
	passiveOnly := []Finding{f3}
	passiveSum := Summarize(passiveOnly)
	if passiveSum.TotalFindings != 1 {
		t.Errorf("expected TotalFindings 1, got %d", passiveSum.TotalFindings)
	}
	if passiveSum.AttemptedCount != 0 {
		t.Errorf("expected AttemptedCount 0 for passive-only findings, got %d", passiveSum.AttemptedCount)
	}
	if passiveSum.VerificationRateAttempted != 0.0 {
		t.Errorf("expected VerificationRateAttempted 0.0 when AttemptedCount is 0, got %.1f", passiveSum.VerificationRateAttempted)
	}
	if passiveSum.VerificationRateTotal != 0.0 {
		t.Errorf("expected VerificationRateTotal 0.0 when VerifiedCount is 0, got %.1f", passiveSum.VerificationRateTotal)
	}
}

// TestReport_Regression_JuiceShop23FindingsReconciliation verifies that
// Juice Shop's 23 findings accurately reconcile AttemptedCount = 18 and
// VerificationRateAttempted = 16.7%, ensuring passive observations with
// residual scanner analysis methods do not artificially inflate AttemptedCount.
func TestReport_Regression_JuiceShop23FindingsReconciliation(t *testing.T) {
	findings := []Finding{
		// 3 Verified Security Headers (Attempted: true, Status: VERIFIED)
		{ID: "API-CSP", Title: "Missing Content-Security-Policy", Severity: SeverityLow, Verification: VerificationRecord{Status: VerificationVerified, Attempted: true, PolicyID: "POL-SEC-01", VerificationMethod: "response_header_audit"}, Status: FindingStatusConfirmed},
		{ID: "API-PERM", Title: "Missing Permissions-Policy", Severity: SeverityInfo, Verification: VerificationRecord{Status: VerificationVerified, Attempted: true, PolicyID: "POL-SEC-01", VerificationMethod: "response_header_audit"}, Status: FindingStatusConfirmed},
		{ID: "API-REF", Title: "Missing Referrer-Policy", Severity: SeverityInfo, Verification: VerificationRecord{Status: VerificationVerified, Attempted: true, PolicyID: "POL-SEC-01", VerificationMethod: "response_header_audit"}, Status: FindingStatusConfirmed},

		// 2 Passive Observations (metrics and api-docs, Attempted: false, Status: OBSERVED, Method: discovery_crawl)
		{ID: "API-METRICS", Title: "Public metrics endpoint", Severity: SeverityLow, AnalysisMethod: AnalysisMethodActive, Verification: VerificationRecord{Status: VerificationObserved, Attempted: false, PolicyID: "POL-DISC-01", VerificationMethod: "discovery_crawl", AnalysisMethod: AnalysisMethodStatic}, Status: FindingStatusConfirmed},
		{ID: "API-DOCS", Title: "Publicly accessible API docs", Severity: SeverityInfo, AnalysisMethod: AnalysisMethodActive, Verification: VerificationRecord{Status: VerificationObserved, Attempted: false, PolicyID: "POL-DISC-01", VerificationMethod: "discovery_crawl", AnalysisMethod: AnalysisMethodStatic}, Status: FindingStatusConfirmed},

		// 4 CORS Wildcard Candidates (Attempted: true, Status: NOT_VERIFIED, Status: INCONCLUSIVE)
		{ID: "API-CORS-1", Title: "CORS wildcard", Severity: SeverityInfo, Verification: VerificationRecord{Status: VerificationNotVerified, Attempted: true, PolicyID: "POL-APISEC-01", VerificationMethod: "api_heuristic"}, Status: FindingStatusInconclusive},
		{ID: "API-CORS-2", Title: "CORS wildcard", Severity: SeverityInfo, Verification: VerificationRecord{Status: VerificationNotVerified, Attempted: true, PolicyID: "POL-APISEC-01", VerificationMethod: "api_heuristic"}, Status: FindingStatusInconclusive},
		{ID: "API-CORS-3", Title: "CORS wildcard", Severity: SeverityInfo, Verification: VerificationRecord{Status: VerificationNotVerified, Attempted: true, PolicyID: "POL-APISEC-01", VerificationMethod: "api_heuristic"}, Status: FindingStatusInconclusive},
		{ID: "API-CORS-4", Title: "CORS wildcard", Severity: SeverityInfo, Verification: VerificationRecord{Status: VerificationNotVerified, Attempted: true, PolicyID: "POL-APISEC-01", VerificationMethod: "api_heuristic"}, Status: FindingStatusInconclusive},

		// 11 Discovered API routes (Attempted: true, Status: NOT_VERIFIED, Status: INCONCLUSIVE)
		{ID: "API-EP-1", Title: "/api/Challenges", Severity: SeverityInfo, Verification: VerificationRecord{Status: VerificationNotVerified, Attempted: true, PolicyID: "POL-APISEC-01", VerificationMethod: "api_heuristic"}, Status: FindingStatusInconclusive},
		{ID: "API-EP-2", Title: "/api/Feedbacks", Severity: SeverityInfo, Verification: VerificationRecord{Status: VerificationNotVerified, Attempted: true, PolicyID: "POL-APISEC-01", VerificationMethod: "api_heuristic"}, Status: FindingStatusInconclusive},
		{ID: "API-EP-3", Title: "/api/Products", Severity: SeverityInfo, Verification: VerificationRecord{Status: VerificationNotVerified, Attempted: true, PolicyID: "POL-APISEC-01", VerificationMethod: "api_heuristic"}, Status: FindingStatusInconclusive},
		{ID: "API-EP-4", Title: "/api/Quantitys", Severity: SeverityInfo, Verification: VerificationRecord{Status: VerificationNotVerified, Attempted: true, PolicyID: "POL-APISEC-01", VerificationMethod: "api_heuristic"}, Status: FindingStatusInconclusive},
		{ID: "API-EP-5", Title: "/api/Recycles", Severity: SeverityInfo, Verification: VerificationRecord{Status: VerificationNotVerified, Attempted: true, PolicyID: "POL-APISEC-01", VerificationMethod: "api_heuristic"}, Status: FindingStatusInconclusive},
		{ID: "API-EP-6", Title: "/api/SecurityQuestions", Severity: SeverityInfo, Verification: VerificationRecord{Status: VerificationNotVerified, Attempted: true, PolicyID: "POL-APISEC-01", VerificationMethod: "api_heuristic"}, Status: FindingStatusInconclusive},
		{ID: "API-EP-7", Title: "/api/Addresss", Severity: SeverityInfo, Verification: VerificationRecord{Status: VerificationNotVerified, Attempted: true, PolicyID: "POL-APISEC-01", VerificationMethod: "api_heuristic"}, Status: FindingStatusInconclusive},
		{ID: "API-EP-8", Title: "/api/BasketItems", Severity: SeverityInfo, Verification: VerificationRecord{Status: VerificationNotVerified, Attempted: true, PolicyID: "POL-APISEC-01", VerificationMethod: "api_heuristic"}, Status: FindingStatusInconclusive},
		{ID: "API-EP-9", Title: "/api/Complaints", Severity: SeverityInfo, Verification: VerificationRecord{Status: VerificationNotVerified, Attempted: true, PolicyID: "POL-APISEC-01", VerificationMethod: "api_heuristic"}, Status: FindingStatusInconclusive},
		{ID: "API-EP-10", Title: "/api/SecurityAnswers", Severity: SeverityInfo, Verification: VerificationRecord{Status: VerificationNotVerified, Attempted: true, PolicyID: "POL-APISEC-01", VerificationMethod: "api_heuristic"}, Status: FindingStatusInconclusive},
		{ID: "API-EP-11", Title: "/api/Users", Severity: SeverityInfo, Verification: VerificationRecord{Status: VerificationNotVerified, Attempted: true, PolicyID: "POL-APISEC-01", VerificationMethod: "api_heuristic"}, Status: FindingStatusInconclusive},

		// 3 Quota-blocked API routes (Attempted: false, Status: NOT_VERIFIED, Status: NOT_TESTED, Method: safety_block)
		{ID: "API-BLOCK-1", Title: "/api/Deliverys", Severity: SeverityInfo, Verification: VerificationRecord{Status: VerificationNotVerified, Attempted: false, PolicyID: "POL-APISEC-01", VerificationMethod: "safety_block"}, Status: FindingStatusNotTested},
		{ID: "API-BLOCK-2", Title: "/api/Hints", Severity: SeverityInfo, Verification: VerificationRecord{Status: VerificationNotVerified, Attempted: false, PolicyID: "POL-APISEC-01", VerificationMethod: "safety_block"}, Status: FindingStatusNotTested},
		{ID: "API-BLOCK-3", Title: "/api/Cards", Severity: SeverityInfo, Verification: VerificationRecord{Status: VerificationNotVerified, Attempted: false, PolicyID: "POL-APISEC-01", VerificationMethod: "safety_block"}, Status: FindingStatusNotTested},
	}

	summary := Summarize(findings)

	if summary.TotalFindings != 23 {
		t.Fatalf("expected total findings 23, got %d", summary.TotalFindings)
	}
	if summary.VerifiedCount != 3 {
		t.Fatalf("expected verified count 3, got %d", summary.VerifiedCount)
	}
	if summary.ObservedCount != 2 {
		t.Fatalf("expected observed count 2, got %d", summary.ObservedCount)
	}
	if summary.NotVerifiedCount != 18 {
		t.Fatalf("expected not verified count 18, got %d", summary.NotVerifiedCount)
	}
	if summary.AttemptedCount != 18 {
		t.Fatalf("expected attempted count 18 (3 verified + 4 CORS + 11 API routes), got %d (passive observations must not be counted as attempted)", summary.AttemptedCount)
	}

	expectedRateAttempted := 16.7 // 3 / 18 * 100 = 16.666% -> 16.7%
	if summary.VerificationRateAttempted != expectedRateAttempted {
		t.Errorf("expected VerificationRateAttempted %.1f, got %.1f", expectedRateAttempted, summary.VerificationRateAttempted)
	}
	expectedRateTotal := 13.0 // 3 / 23 * 100 = 13.04% -> 13.0%
	if summary.VerificationRateTotal != expectedRateTotal {
		t.Errorf("expected VerificationRateTotal %.1f, got %.1f", expectedRateTotal, summary.VerificationRateTotal)
	}
}

// TestReport_Regression_WebGoatSevenFindings verifies that WebGoat's canonical
// seven findings (5 verified headers + 2 defended protected routes) produce
// AttemptedCount = 7, VerifiedCount = 5, NotExposedCount = 2, NotVerifiedCount = 0,
// and VerificationRateAttempted = 71.4%. It also validates extensions with
// passive observations, safety-blocked checks, and zero-finding cases.
func TestReport_Regression_WebGoatSevenFindings(t *testing.T) {
	// Base 7 WebGoat findings
	h1 := Finding{ID: "WG-CSP", Title: "Missing Content-Security-Policy", Severity: SeverityLow, Verification: VerificationRecord{Status: VerificationVerified, Attempted: true, PolicyID: "POL-APISEC-01", VerificationMethod: "response_header_audit"}, Status: FindingStatusConfirmed}
	h2 := Finding{ID: "WG-XFO", Title: "Missing X-Frame-Options", Severity: SeverityLow, Verification: VerificationRecord{Status: VerificationVerified, Attempted: true, PolicyID: "POL-APISEC-01", VerificationMethod: "response_header_audit"}, Status: FindingStatusConfirmed}
	h3 := Finding{ID: "WG-PERM", Title: "Missing Permissions-Policy", Severity: SeverityInfo, Verification: VerificationRecord{Status: VerificationVerified, Attempted: true, PolicyID: "POL-APISEC-01", VerificationMethod: "response_header_audit"}, Status: FindingStatusConfirmed}
	h4 := Finding{ID: "WG-REF", Title: "Missing Referrer-Policy", Severity: SeverityInfo, Verification: VerificationRecord{Status: VerificationVerified, Attempted: true, PolicyID: "POL-APISEC-01", VerificationMethod: "response_header_audit"}, Status: FindingStatusConfirmed}
	h5 := Finding{ID: "WG-XCTO", Title: "Missing X-Content-Type-Options", Severity: SeverityInfo, Verification: VerificationRecord{Status: VerificationVerified, Attempted: true, PolicyID: "POL-APISEC-01", VerificationMethod: "response_header_audit"}, Status: FindingStatusConfirmed}
	d1 := Finding{ID: "WG-TEL-1", Title: "Laravel Telescope interface requires authentication (observed login redirect)", Category: "laravel-telescope-restricted", Severity: SeverityInfo, Verification: VerificationRecord{Status: VerificationNotExposed, Attempted: true, PolicyID: "POL-APISEC-01", VerificationMethod: "diagnostic_barrier_check"}, Status: FindingStatusInconclusive}
	d2 := Finding{ID: "WG-TEL-2", Title: "Laravel Telescope API requires authentication (observed login redirect)", Category: "laravel-telescope-restricted", Severity: SeverityInfo, Verification: VerificationRecord{Status: VerificationNotExposed, Attempted: true, PolicyID: "POL-APISEC-01", VerificationMethod: "diagnostic_barrier_check"}, Status: FindingStatusInconclusive}

	webgoatFindings := []Finding{h1, h2, h3, h4, h5, d1, d2}
	sum := Summarize(webgoatFindings)

	if sum.TotalFindings != 7 {
		t.Fatalf("expected TotalFindings 7, got %d", sum.TotalFindings)
	}
	if sum.AttemptedCount != 7 {
		t.Errorf("expected AttemptedCount 7, got %d", sum.AttemptedCount)
	}
	if sum.VerifiedCount != 5 {
		t.Errorf("expected VerifiedCount 5, got %d", sum.VerifiedCount)
	}
	if sum.NotExposedCount != 2 {
		t.Errorf("expected NotExposedCount 2, got %d", sum.NotExposedCount)
	}
	if sum.NotVerifiedCount != 0 {
		t.Errorf("expected NotVerifiedCount 0, got %d", sum.NotVerifiedCount)
	}
	if sum.ObservedCount != 0 {
		t.Errorf("expected ObservedCount 0, got %d", sum.ObservedCount)
	}
	if sum.ConfirmedCount != 5 {
		t.Errorf("expected ConfirmedCount 5, got %d", sum.ConfirmedCount)
	}
	if sum.InconclusiveCount != 2 {
		t.Errorf("expected InconclusiveCount 2, got %d", sum.InconclusiveCount)
	}
	if sum.VerificationRateAttempted != 71.4 {
		t.Errorf("expected VerificationRateAttempted 71.4, got %.1f", sum.VerificationRateAttempted)
	}
	if sum.VerificationRateTotal != 71.4 {
		t.Errorf("expected VerificationRateTotal 71.4, got %.1f", sum.VerificationRateTotal)
	}

	// Extension 1: WebGoat + 1 passive observation (8 findings total)
	obs := Finding{ID: "WG-OBS", Title: "Public static script bundle", Category: "public-client-bundle", Severity: SeverityInfo, Verification: VerificationRecord{Status: VerificationObserved, Attempted: false, PolicyID: "POL-DISC-01", VerificationMethod: "discovery_crawl"}, Status: FindingStatusConfirmed}
	withObs := append(webgoatFindings, obs)
	sumObs := Summarize(withObs)

	if sumObs.TotalFindings != 8 {
		t.Errorf("expected TotalFindings 8, got %d", sumObs.TotalFindings)
	}
	if sumObs.AttemptedCount != 7 {
		t.Errorf("expected AttemptedCount 7 (passive observation must not be counted as attempted), got %d", sumObs.AttemptedCount)
	}
	if sumObs.VerifiedCount != 5 {
		t.Errorf("expected VerifiedCount 5, got %d", sumObs.VerifiedCount)
	}
	if sumObs.NotExposedCount != 2 {
		t.Errorf("expected NotExposedCount 2, got %d", sumObs.NotExposedCount)
	}
	if sumObs.ObservedCount != 1 {
		t.Errorf("expected ObservedCount 1, got %d", sumObs.ObservedCount)
	}
	if sumObs.VerificationRateAttempted != 71.4 { // 5 / 7 * 100 = 71.4%
		t.Errorf("expected VerificationRateAttempted 71.4, got %.1f", sumObs.VerificationRateAttempted)
	}
	if sumObs.VerificationRateTotal != 62.5 { // 5 / 8 * 100 = 62.5%
		t.Errorf("expected VerificationRateTotal 62.5, got %.1f", sumObs.VerificationRateTotal)
	}

	// Extension 2: WebGoat + 1 safety-blocked check (8 findings total)
	blk := Finding{ID: "WG-BLK", Title: "Live credential probe blocked", Category: "hardcoded-secret", Severity: SeverityHigh, Verification: VerificationRecord{Status: VerificationNotVerified, Attempted: false, PolicyID: "POL-SEC-01", VerificationMethod: "safety_block", Result: "Probe blocked by safety policy"}, Status: FindingStatusNotTested}
	withBlk := append(webgoatFindings, blk)
	sumBlk := Summarize(withBlk)

	if sumBlk.TotalFindings != 8 {
		t.Errorf("expected TotalFindings 8, got %d", sumBlk.TotalFindings)
	}
	if sumBlk.AttemptedCount != 7 {
		t.Errorf("expected AttemptedCount 7 (safety-blocked check must not be counted as attempted), got %d", sumBlk.AttemptedCount)
	}
	if sumBlk.VerifiedCount != 5 {
		t.Errorf("expected VerifiedCount 5, got %d", sumBlk.VerifiedCount)
	}
	if sumBlk.NotExposedCount != 2 {
		t.Errorf("expected NotExposedCount 2, got %d", sumBlk.NotExposedCount)
	}
	if sumBlk.NotVerifiedCount != 1 {
		t.Errorf("expected NotVerifiedCount 1, got %d", sumBlk.NotVerifiedCount)
	}
	if sumBlk.BlockedCount != 1 {
		t.Errorf("expected BlockedCount 1, got %d", sumBlk.BlockedCount)
	}
	if sumBlk.NotTestedCount != 1 {
		t.Errorf("expected NotTestedCount 1, got %d", sumBlk.NotTestedCount)
	}
	if sumBlk.VerificationRateAttempted != 71.4 {
		t.Errorf("expected VerificationRateAttempted 71.4, got %.1f", sumBlk.VerificationRateAttempted)
	}
	if sumBlk.VerificationRateTotal != 62.5 {
		t.Errorf("expected VerificationRateTotal 62.5, got %.1f", sumBlk.VerificationRateTotal)
	}
}
