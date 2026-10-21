package compliance

import (
	"fmt"
	"strings"
)

// EvaluationValidationError represents one or more validation errors on an evaluation context or result.
type EvaluationValidationError struct {
	AssessmentID string           `json:"assessment_id,omitempty"`
	Violations   []FieldViolation `json:"violations"`
}

func (ve *EvaluationValidationError) Error() string {
	if ve == nil || len(ve.Violations) == 0 {
		return "valid compliance evaluation"
	}
	var sb strings.Builder
	prefix := "compliance evaluation validation failed"
	if ve.AssessmentID != "" {
		prefix = fmt.Sprintf("compliance evaluation for assessment %q validation failed", ve.AssessmentID)
	}
	sb.WriteString(prefix)
	sb.WriteString(fmt.Sprintf(" (%d error(s)): ", len(ve.Violations)))

	messages := make([]string, len(ve.Violations))
	for i, v := range ve.Violations {
		messages[i] = v.String()
	}
	sb.WriteString(strings.Join(messages, "; "))
	return sb.String()
}

func (ve *EvaluationValidationError) HasViolations() bool {
	return ve != nil && len(ve.Violations) > 0
}

func (ve *EvaluationValidationError) addViolation(field, code, message string) {
	ve.Violations = append(ve.Violations, FieldViolation{
		Field:   field,
		Code:    code,
		Message: message,
	})
}

// ValidateEvaluationContext validates assessment context, applicability determinations, and positive evidence records.
func ValidateEvaluationContext(ctx *EvaluationContext, cat *ControlCatalog) error {
	if ctx == nil {
		return &EvaluationValidationError{
			Violations: []FieldViolation{
				{Field: "context", Code: "NIL_CONTEXT", Message: "evaluation context cannot be nil"},
			},
		}
	}

	ve := &EvaluationValidationError{AssessmentID: strings.TrimSpace(ctx.AssessmentID)}

	if strings.TrimSpace(ctx.AssessmentID) == "" {
		ve.addViolation("assessment_id", "REQUIRED_FIELD", "assessment_id is required")
	}

	var validControls map[string]bool
	if cat != nil {
		validControls = make(map[string]bool, len(cat.Controls))
		for _, ctrl := range cat.Controls {
			validControls[strings.TrimSpace(ctrl.ID)] = true
		}
	}

	// Validate applicability determinations
	if ctx.Applicability != nil {
		for cID, det := range ctx.Applicability {
			cleanCID := strings.TrimSpace(cID)
			if cleanCID == "" {
				ve.addViolation("applicability", "REQUIRED_FIELD", "applicability control_id is required")
				continue
			}
			if validControls != nil && !validControls[cleanCID] {
				ve.addViolation(fmt.Sprintf("applicability[%s]", cleanCID), "UNKNOWN_CONTROL",
					fmt.Sprintf("applicability references unknown control ID %q in catalog %q", cleanCID, cat.ID))
			}
			if !det.Applicable {
				if strings.TrimSpace(det.Rationale) == "" {
					ve.addViolation(fmt.Sprintf("applicability[%s].rationale", cleanCID), "REQUIRED_FIELD",
						fmt.Sprintf("inapplicability determination for control %q requires non-empty rationale", cleanCID))
				}
				if strings.TrimSpace(det.Basis) == "" {
					ve.addViolation(fmt.Sprintf("applicability[%s].basis", cleanCID), "REQUIRED_FIELD",
						fmt.Sprintf("inapplicability determination for control %q requires non-empty basis", cleanCID))
				}
			}
		}
	}

	// Validate positive evidence records
	for i, pe := range ctx.PositiveEvidence {
		prefix := fmt.Sprintf("positive_evidence[%d]", i)
		cleanCID := strings.TrimSpace(pe.ControlID)
		if cleanCID == "" {
			ve.addViolation(prefix+".control_id", "REQUIRED_FIELD", "positive evidence control_id is required")
		} else if validControls != nil && !validControls[cleanCID] {
			ve.addViolation(prefix+".control_id", "UNKNOWN_CONTROL",
				fmt.Sprintf("positive evidence references unknown control ID %q in catalog %q", cleanCID, cat.ID))
		}
		if strings.TrimSpace(pe.Observation) == "" {
			ve.addViolation(prefix+".observation", "REQUIRED_FIELD", "positive evidence observation is required")
		}
		if strings.TrimSpace(pe.Method) == "" {
			ve.addViolation(prefix+".method", "REQUIRED_FIELD", "positive evidence method is required")
		}
	}

	// Validate execution errors
	if ctx.ExecutionErrors != nil && validControls != nil {
		for cID := range ctx.ExecutionErrors {
			cleanCID := strings.TrimSpace(cID)
			if !validControls[cleanCID] {
				ve.addViolation(fmt.Sprintf("execution_errors[%s]", cleanCID), "UNKNOWN_CONTROL",
					fmt.Sprintf("execution error references unknown control ID %q in catalog %q", cleanCID, cat.ID))
			}
		}
	}

	if ve.HasViolations() {
		return ve
	}
	return nil
}

// ValidateEvaluationResult verifies structural integrity, state validity, and summary balance of an EvaluationResult.
func ValidateEvaluationResult(res *EvaluationResult, cat *ControlCatalog) error {
	if res == nil {
		return &EvaluationValidationError{
			Violations: []FieldViolation{
				{Field: "result", Code: "NIL_RESULT", Message: "evaluation result cannot be nil"},
			},
		}
	}

	ve := &EvaluationValidationError{AssessmentID: strings.TrimSpace(res.AssessmentID)}

	if strings.TrimSpace(res.AssessmentID) == "" {
		ve.addViolation("assessment_id", "REQUIRED_FIELD", "assessment_id is required")
	}

	if strings.TrimSpace(res.CatalogIdentity) == "" {
		ve.addViolation("catalog_identity", "REQUIRED_FIELD", "catalog_identity is required")
	}

	var validControls map[string]bool
	if cat != nil {
		if cat.Identity() != "" && res.CatalogIdentity != "" && !strings.EqualFold(res.CatalogIdentity, cat.Identity()) {
			ve.addViolation("catalog_identity", "CATALOG_MISMATCH",
				fmt.Sprintf("result catalog identity %q does not match catalog %q", res.CatalogIdentity, cat.Identity()))
		}

		validControls = make(map[string]bool, len(cat.Controls))
		for _, ctrl := range cat.Controls {
			validControls[strings.TrimSpace(ctrl.ID)] = true
		}
	}

	seenControls := make(map[string]bool, len(res.Evaluations))
	counts := make(map[EvaluationState]int)

	for i, ev := range res.Evaluations {
		prefix := fmt.Sprintf("evaluations[%d]", i)
		cID := strings.TrimSpace(ev.ControlID)

		if cID == "" {
			ve.addViolation(prefix+".control_id", "REQUIRED_FIELD", "evaluation control_id is required")
		} else {
			if seenControls[cID] {
				ve.addViolation(prefix+".control_id", "DUPLICATE_EVALUATION",
					fmt.Sprintf("duplicate evaluation record for control %q", cID))
			}
			seenControls[cID] = true

			if validControls != nil && !validControls[cID] {
				ve.addViolation(prefix+".control_id", "UNKNOWN_CONTROL",
					fmt.Sprintf("evaluation references unknown control %q in catalog %q", cID, cat.ID))
			}
		}

		if err := ValidateEvaluationState(ev.State); err != nil {
			ve.addViolation(prefix+".state", "INVALID_STATE", err.Error())
		} else {
			counts[ev.State]++
		}

		if strings.TrimSpace(ev.Rationale) == "" {
			ve.addViolation(prefix+".rationale", "REQUIRED_FIELD",
				fmt.Sprintf("evaluation rationale for control %q is required", cID))
		}

		// State-evidence consistency checks
		switch ev.State {
		case StateCompliant:
			if len(ev.SupportingEvidence) == 0 {
				ve.addViolation(prefix, "INCONSISTENT_STATE",
					fmt.Sprintf("control %q cannot be compliant without supporting evidence", cID))
			}
			if len(ev.ContradictingEvidence) > 0 || len(ev.FindingIDs) > 0 {
				ve.addViolation(prefix, "INCONSISTENT_STATE",
					fmt.Sprintf("control %q cannot be compliant with contradicting evidence or violating findings", cID))
			}
		case StateNonCompliant:
			if len(ev.ContradictingEvidence) == 0 && len(ev.FindingIDs) == 0 {
				ve.addViolation(prefix, "INCONSISTENT_STATE",
					fmt.Sprintf("control %q cannot be non_compliant without contradicting evidence or finding IDs", cID))
			}
		case StatePartiallyCompliant:
			if len(ev.SupportingEvidence) == 0 || (len(ev.ContradictingEvidence) == 0 && len(ev.FindingIDs) == 0) {
				ve.addViolation(prefix, "INCONSISTENT_STATE",
					fmt.Sprintf("control %q cannot be partially_compliant without both supporting and contradicting evidence", cID))
			}
		case StateNotApplicable:
			if len(ev.ContradictingEvidence) > 0 || len(ev.FindingIDs) > 0 {
				ve.addViolation(prefix, "INCONSISTENT_STATE",
					fmt.Sprintf("control %q cannot be not_applicable with contradicting evidence or finding IDs", cID))
			}
		case StateNotAssessed:
			if len(ev.SupportingEvidence) > 0 || len(ev.ContradictingEvidence) > 0 || len(ev.FindingIDs) > 0 {
				ve.addViolation(prefix, "INCONSISTENT_STATE",
					fmt.Sprintf("control %q cannot be not_assessed with supporting evidence, contradicting evidence, or finding IDs", cID))
			}
		case StateError:
			if len(ev.SupportingEvidence) > 0 {
				ve.addViolation(prefix, "INCONSISTENT_STATE",
					fmt.Sprintf("control %q cannot be in error state with supporting compliance evidence", cID))
			}
		}
	}

	// Verify all catalog controls are evaluated
	if validControls != nil {
		for ctrlID := range validControls {
			if !seenControls[ctrlID] {
				ve.addViolation("evaluations", "MISSING_EVALUATION",
					fmt.Sprintf("missing evaluation record for catalog control %q", ctrlID))
			}
		}
	}

	// Verify summary arithmetic consistency
	sum := res.Summary
	if sum.TotalControls != len(res.Evaluations) {
		ve.addViolation("summary.total_controls", "SUMMARY_MISMATCH",
			fmt.Sprintf("summary total_controls (%d) does not match evaluations count (%d)", sum.TotalControls, len(res.Evaluations)))
	}
	if sum.CompliantCount != counts[StateCompliant] {
		ve.addViolation("summary.compliant_count", "SUMMARY_MISMATCH",
			fmt.Sprintf("summary compliant_count (%d) does not match record count (%d)", sum.CompliantCount, counts[StateCompliant]))
	}
	if sum.NonCompliantCount != counts[StateNonCompliant] {
		ve.addViolation("summary.non_compliant_count", "SUMMARY_MISMATCH",
			fmt.Sprintf("summary non_compliant_count (%d) does not match record count (%d)", sum.NonCompliantCount, counts[StateNonCompliant]))
	}
	if sum.PartiallyCompliantCount != counts[StatePartiallyCompliant] {
		ve.addViolation("summary.partially_compliant_count", "SUMMARY_MISMATCH",
			fmt.Sprintf("summary partially_compliant_count (%d) does not match record count (%d)", sum.PartiallyCompliantCount, counts[StatePartiallyCompliant]))
	}
	if sum.NotAssessedCount != counts[StateNotAssessed] {
		ve.addViolation("summary.not_assessed_count", "SUMMARY_MISMATCH",
			fmt.Sprintf("summary not_assessed_count (%d) does not match record count (%d)", sum.NotAssessedCount, counts[StateNotAssessed]))
	}
	if sum.InsufficientEvidenceCount != counts[StateInsufficientEvidence] {
		ve.addViolation("summary.insufficient_evidence_count", "SUMMARY_MISMATCH",
			fmt.Sprintf("summary insufficient_evidence_count (%d) does not match record count (%d)", sum.InsufficientEvidenceCount, counts[StateInsufficientEvidence]))
	}
	if sum.NotApplicableCount != counts[StateNotApplicable] {
		ve.addViolation("summary.not_applicable_count", "SUMMARY_MISMATCH",
			fmt.Sprintf("summary not_applicable_count (%d) does not match record count (%d)", sum.NotApplicableCount, counts[StateNotApplicable]))
	}
	if sum.ErrorCount != counts[StateError] {
		ve.addViolation("summary.error_count", "SUMMARY_MISMATCH",
			fmt.Sprintf("summary error_count (%d) does not match record count (%d)", sum.ErrorCount, counts[StateError]))
	}

	if ve.HasViolations() {
		return ve
	}
	return nil
}
