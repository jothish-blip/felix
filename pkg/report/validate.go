package report

import (
	"errors"
	"fmt"
	"strings"
)

// ValidateReportIntegrity validates that a deserialized or exported report satisfies baseline
// data integrity invariants without silently treating corrupt or missing data as a valid zero-finding scan.
func ValidateReportIntegrity(rep Report) error {
	primaryTarget := strings.TrimSpace(rep.Target)
	if primaryTarget == "" && len(rep.Targets) == 0 {
		return errors.New("invalid report: missing assessment target or target scope")
	}

	sumTotal := rep.Summary.CriticalCount + rep.Summary.HighCount + rep.Summary.MediumCount + rep.Summary.LowCount + rep.Summary.InfoCount
	if rep.Summary.TotalFindings > 0 && sumTotal == 0 {
		sumTotal = rep.Summary.TotalFindings
	}

	// Invariant 1: If summary claims findings exist, but Findings array is empty, data was omitted or corrupted
	if sumTotal > 0 && len(rep.Findings) == 0 {
		return fmt.Errorf("invalid report: summary claims %d finding(s), but findings collection is empty", sumTotal)
	}

	// Invariant 2: If findings exist, verify severity totals reconcile with finding population
	if len(rep.Findings) > 0 {
		var actualCritical, actualHigh, actualMedium, actualLow, actualInfo int
		for _, f := range rep.Findings {
			switch NormalizeSeverity(f.Severity) {
			case SeverityCritical:
				actualCritical++
			case SeverityHigh:
				actualHigh++
			case SeverityMedium:
				actualMedium++
			case SeverityLow:
				actualLow++
			case SeverityInfo:
				actualInfo++
			}
		}
		actualTotal := actualCritical + actualHigh + actualMedium + actualLow + actualInfo

		// If summary counts were explicitly provided, check reconciliation
		if sumTotal > 0 {
			if rep.Summary.TotalFindings > 0 && rep.Summary.TotalFindings != actualTotal {
				return fmt.Errorf("invalid report: summary total findings (%d) contradicts actual findings count (%d)", rep.Summary.TotalFindings, actualTotal)
			}
			if sumTotal != actualTotal {
				return fmt.Errorf("invalid report: severity breakdown total (%d) contradicts summary total (%d)", actualTotal, sumTotal)
			}
			if rep.Summary.CriticalCount != actualCritical {
				return fmt.Errorf("invalid report: critical finding count mismatch: summary claims %d, but findings contain %d", rep.Summary.CriticalCount, actualCritical)
			}
			if rep.Summary.HighCount != actualHigh {
				return fmt.Errorf("invalid report: high finding count mismatch: summary claims %d, but findings contain %d", rep.Summary.HighCount, actualHigh)
			}
			if rep.Summary.MediumCount != actualMedium {
				return fmt.Errorf("invalid report: medium finding count mismatch: summary claims %d, but findings contain %d", rep.Summary.MediumCount, actualMedium)
			}
			if rep.Summary.LowCount != actualLow {
				return fmt.Errorf("invalid report: low finding count mismatch: summary claims %d, but findings contain %d", rep.Summary.LowCount, actualLow)
			}
			if rep.Summary.InfoCount != actualInfo {
				return fmt.Errorf("invalid report: info finding count mismatch: summary claims %d, but findings contain %d", rep.Summary.InfoCount, actualInfo)
			}
		}
	}

	// Invariant 3: Check completion status and risk availability
	status := strings.ToUpper(strings.TrimSpace(rep.CompletionStatus))
	if status == "FAILED" || status == "BLOCKED" || status == "CANCELLED" || status == "INTERRUPTED" {
		if rep.RiskScoreAvailable && rep.RiskScore > 0 {
			return fmt.Errorf("invalid report: assessment status is %s but claims positive risk score (%d)", status, rep.RiskScore)
		}
	}

	return nil
}
