package compliance

import (
	"fmt"
	"strings"
)

// ValidateLimitations validates an array of ComplianceLimitation records for schema correctness.
func ValidateLimitations(lims []ComplianceLimitation) error {
	for i, l := range lims {
		if strings.TrimSpace(l.ID) == "" {
			return fmt.Errorf("limitation [%d] has empty ID", i)
		}
		if _, ok := CanonicalLimitationCategory(string(l.Category)); !ok {
			return fmt.Errorf("limitation %q has invalid category %q", l.ID, l.Category)
		}
		if _, ok := CanonicalLimitationSeverity(string(l.Severity)); !ok {
			return fmt.Errorf("limitation %q has invalid severity %q", l.ID, l.Severity)
		}
		if strings.TrimSpace(l.Title) == "" {
			return fmt.Errorf("limitation %q has empty title", l.ID)
		}
		if strings.TrimSpace(l.Description) == "" {
			return fmt.Errorf("limitation %q has empty description", l.ID)
		}
	}
	return nil
}

// ValidateDeterminationConsistency strictly verifies that an evaluation result or dossier summary
// does not contain contradictory, misleading, or false-compliance claims.
func ValidateDeterminationConsistency(eval *EvaluationResult, coverage *CoverageBasis, lims []ComplianceLimitation) error {
	if eval == nil {
		return fmt.Errorf("cannot validate determination consistency of nil evaluation")
	}

	sum := eval.Summary

	// 1. A non-empty catalog with zero assessed controls cannot claim any compliant controls
	if sum.TotalControls > 0 && sum.AssessedControls == 0 && sum.CompliantCount > 0 {
		return fmt.Errorf("false compliance detected: 0 controls were assessed, but compliant_count is %d", sum.CompliantCount)
	}

	// 2. Control state validation: not_assessed, insufficient_evidence, and error must not be marked compliant
	for _, ce := range eval.Evaluations {
		ctrlID := ce.ControlID
		switch ce.State {
		case StateNotAssessed:
			if strings.Contains(strings.ToLower(ce.Rationale), "satisfied") || strings.Contains(strings.ToLower(ce.Rationale), "compliant") {
				return fmt.Errorf("contradictory evaluation for control %s: state is not_assessed but rationale claims compliance: %q", ctrlID, ce.Rationale)
			}
		case StateInsufficientEvidence:
			if strings.Contains(strings.ToLower(ce.Rationale), "satisfied") || strings.Contains(strings.ToLower(ce.Rationale), "fully compliant") {
				return fmt.Errorf("contradictory evaluation for control %s: state is insufficient_evidence but rationale claims satisfaction: %q", ctrlID, ce.Rationale)
			}
		case StateError:
			if len(ce.SupportingEvidence) > 0 {
				return fmt.Errorf("contradictory evaluation for control %s: state is error but positive supporting evidence is linked", ctrlID)
			}
		case StateNotApplicable:
			if len(ce.SupportingEvidence) > 0 {
				return fmt.Errorf("contradictory evaluation for control %s: state is not_applicable but supporting evidence is linked", ctrlID)
			}
		}
	}

	// 3. not_applicable controls cannot be included in compliant_count
	if sum.CompliantCount > sum.ApplicableControls {
		return fmt.Errorf("false compliance detected: compliant_count (%d) exceeds applicable_controls (%d)",
			sum.CompliantCount, sum.ApplicableControls)
	}

	// 4. Coverage basis consistency: checked denominator must be defensible
	if coverage != nil {
		if coverage.ApplicableControls != (coverage.TotalCatalogControls - coverage.NotApplicableControls) {
			return fmt.Errorf("invalid coverage denominator: applicable (%d) != total (%d) - not_applicable (%d)",
				coverage.ApplicableControls, coverage.TotalCatalogControls, coverage.NotApplicableControls)
		}
		if coverage.AssessedControls > coverage.ApplicableControls {
			return fmt.Errorf("invalid coverage count: assessed (%d) cannot exceed applicable controls (%d)",
				coverage.AssessedControls, coverage.ApplicableControls)
		}
		if coverage.ComplianceRatePercent > 100.0 {
			return fmt.Errorf("invalid compliance rate %.2f%% exceeds 100%%", coverage.ComplianceRatePercent)
		}
		if coverage.AssessedCoveragePercent > 100.0 {
			return fmt.Errorf("invalid assessed coverage %.2f%% exceeds 100%%", coverage.AssessedCoveragePercent)
		}
	}

	// 5. If unassessed controls exist, an unassessed limitation must be disclosed
	if sum.NotAssessedCount > 0 && len(lims) > 0 {
		hasUnassessedLim := false
		for _, l := range lims {
			if l.Category == LimitationCategoryCoverage && (l.ID == "LIM-COV-UNASSESSED" || l.ID == "LIM-COV-INCOMPLETE") {
				hasUnassessedLim = true
				break
			}
		}
		if !hasUnassessedLim {
			return fmt.Errorf("transparency violation: evaluation has %d unassessed controls but lacks coverage limitation disclosure", sum.NotAssessedCount)
		}
	}

	// 6. If execution errors exist, an error limitation must be disclosed
	if sum.ErrorCount > 0 && len(lims) > 0 {
		hasErrorLim := false
		for _, l := range lims {
			if l.Category == LimitationCategoryEvaluation && (l.ID == "LIM-EVAL-ERROR" || l.ID == "LIM-EVAL-FAILURES") {
				hasErrorLim = true
				break
			}
		}
		if !hasErrorLim {
			return fmt.Errorf("transparency violation: evaluation has %d error controls but lacks evaluation error limitation disclosure", sum.ErrorCount)
		}
	}

	return nil
}
