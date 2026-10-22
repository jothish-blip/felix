package report

import (
	"testing"
)

func TestValidateReportIntegrity(t *testing.T) {
	t.Run("Valid report with findings reconciles", func(t *testing.T) {
		f1 := Finding{
			ID:       "f1",
			Title:    "SQLi",
			Severity: SeverityCritical,
		}
		f2 := Finding{
			ID:       "f2",
			Title:    "XSS",
			Severity: SeverityMedium,
		}
		rep := BuildReport("https://example.com", []Finding{f1, f2})
		rep.CompletionStatus = "COMPLETED"

		if err := ValidateReportIntegrity(rep); err != nil {
			t.Fatalf("expected valid report to pass integrity validation: %v", err)
		}
	})

	t.Run("Valid zero-finding assessment passes", func(t *testing.T) {
		rep := BuildReport("https://clean.example.com", nil)
		rep.CompletionStatus = "COMPLETED"

		if err := ValidateReportIntegrity(rep); err != nil {
			t.Fatalf("expected valid zero-finding report to pass: %v", err)
		}
	})

	t.Run("Missing assessment target fails", func(t *testing.T) {
		rep := Report{
			Target:           "",
			Targets:          nil,
			CompletionStatus: "COMPLETED",
		}
		if err := ValidateReportIntegrity(rep); err == nil {
			t.Fatalf("expected error for missing target, got nil")
		}
	})

	t.Run("Summary claims findings but collection is empty", func(t *testing.T) {
		rep := Report{
			Target:           "https://example.com",
			CompletionStatus: "COMPLETED",
			Summary: Summary{
				TotalFindings: 3,
				CriticalCount: 3,
			},
			Findings: nil, // Findings lost!
		}
		if err := ValidateReportIntegrity(rep); err == nil {
			t.Fatalf("expected error when summary claims findings but collection is empty, got nil")
		}
	})

	t.Run("Contradictory severity totals fail", func(t *testing.T) {
		f1 := Finding{
			ID:       "f1",
			Severity: SeverityLow,
		}
		rep := Report{
			Target:           "https://example.com",
			CompletionStatus: "COMPLETED",
			Summary: Summary{
				TotalFindings: 1,
				CriticalCount: 1, // Claims Critical, but finding is Low!
			},
			Findings: []Finding{f1},
		}
		if err := ValidateReportIntegrity(rep); err == nil {
			t.Fatalf("expected error for contradictory severity totals, got nil")
		}
	})

	t.Run("Failed assessment claiming positive risk score fails", func(t *testing.T) {
		rep := Report{
			Target:             "https://example.com",
			CompletionStatus:   "FAILED",
			RiskScoreAvailable: true,
			RiskScore:          85, // Failed scans must not have available risk score
		}
		if err := ValidateReportIntegrity(rep); err == nil {
			t.Fatalf("expected error for failed assessment claiming positive risk score, got nil")
		}
	})
}
