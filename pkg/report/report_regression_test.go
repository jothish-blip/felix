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
