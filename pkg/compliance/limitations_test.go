package compliance

import (
	"context"
	"strings"
	"testing"
	"time"
)

// 1. CoverageBasis calculation with explicit denominator and formula
func TestLimitations_1_CalculateCoverageBasis(t *testing.T) {
	sum := EvaluationSummary{
		TotalControls:             10,
		NotApplicableCount:        2,
		CompliantCount:            5,
		NonCompliantCount:         1,
		PartiallyCompliantCount:   1,
		InsufficientEvidenceCount: 1,
		ErrorCount:                0,
		AssessedControls:          8,
		ApplicableControls:        8,
	}

	cb := CalculateCoverageBasis(sum)

	if cb.TotalCatalogControls != 10 {
		t.Errorf("expected 10 total catalog controls, got %d", cb.TotalCatalogControls)
	}
	if cb.NotApplicableControls != 2 {
		t.Errorf("expected 2 not applicable, got %d", cb.NotApplicableControls)
	}
	if cb.ApplicableControls != 8 {
		t.Errorf("expected 8 applicable controls, got %d", cb.ApplicableControls)
	}
	if cb.AssessedControls != 8 {
		t.Errorf("expected 8 assessed controls, got %d", cb.AssessedControls)
	}
	if cb.UnassessedControls != 0 {
		t.Errorf("expected 0 unassessed controls, got %d", cb.UnassessedControls)
	}
	if cb.AssessedCoveragePercent != 100.0 {
		t.Errorf("expected 100.0%% coverage, got %.2f%%", cb.AssessedCoveragePercent)
	}
	// 5 compliant / 8 applicable = 62.5%
	expectedComplianceRate := 62.5
	if cb.ComplianceRatePercent != expectedComplianceRate {
		t.Errorf("expected %.2f%% compliance rate, got %.2f%%", expectedComplianceRate, cb.ComplianceRatePercent)
	}
	if !strings.Contains(cb.DenominatorDescription, "8 applicable controls") {
		t.Errorf("expected explicit denominator in description, got: %s", cb.DenominatorDescription)
	}
}

// 2. Unassessed controls must generate LIM-COV-UNASSESSED and reduce evaluated coverage
func TestLimitations_2_UnassessedControls_GenerateLimitations(t *testing.T) {
	eval := &EvaluationResult{
		AssessmentID:    "ASM-UNASSESSED-TEST",
		CatalogIdentity: "nist-sp800-53-sample:5.1.0",
		Evaluations: []ControlEvaluationRecord{
			{ControlID: "AC-1", State: StateCompliant, Rationale: "Verified active", SupportingEvidence: []string{"PE-1"}},
			{ControlID: "AC-2", State: StateNotAssessed, Rationale: "No scanner covered this control"},
			{ControlID: "AC-3", State: StateNotApplicable, Rationale: "Cloud provider managed"},
		},
		Summary: EvaluationSummary{
			TotalControls:      3,
			CompliantCount:     1,
			NotAssessedCount:   1,
			NotApplicableCount: 1,
			ApplicableControls: 2,
			AssessedControls:   1,
		},
	}

	lims := DeriveLimitationsFromEvaluation(eval, nil)
	foundUnassessed := false
	foundDisclaimer := false
	for _, l := range lims {
		if l.ID == "LIM-COV-UNASSESSED" && l.AffectedItem == "AC-2" {
			foundUnassessed = true
			if l.Severity != LimitationSeverityWarning {
				t.Errorf("expected WARNING severity, got %s", l.Severity)
			}
		}
		if l.ID == "LIM-CERT-DISCLAIMER" {
			foundDisclaimer = true
		}
	}

	if !foundUnassessed {
		t.Errorf("expected LIM-COV-UNASSESSED limitation for control AC-2")
	}
	if !foundDisclaimer {
		t.Errorf("expected LIM-CERT-DISCLAIMER disclaimer limitation")
	}

	cb := CalculateCoverageBasis(eval.Summary)
	if cb.UnassessedControls != 1 {
		t.Errorf("expected 1 unassessed control, got %d", cb.UnassessedControls)
	}
	if cb.AssessedCoveragePercent != 50.0 {
		t.Errorf("expected 50.0%% assessed coverage, got %.1f%%", cb.AssessedCoveragePercent)
	}
}

// 3. Insufficient evidence and execution error generate corresponding limitations
func TestLimitations_3_InsufficientEvidenceAndErrors(t *testing.T) {
	eval := &EvaluationResult{
		AssessmentID:    "ASM-INSUF-ERR",
		CatalogIdentity: "cat:1.0",
		Evaluations: []ControlEvaluationRecord{
			{ControlID: "SC-1", State: StateInsufficientEvidence, Rationale: "Network traffic logs ambiguous"},
			{ControlID: "SC-2", State: StateError, Rationale: "Scanner crashed with OOM"},
		},
		Summary: EvaluationSummary{
			TotalControls:             2,
			InsufficientEvidenceCount: 1,
			ErrorCount:                1,
			ApplicableControls:        2,
			AssessedControls:          2,
		},
	}

	lims := DeriveLimitationsFromEvaluation(eval, nil)
	foundInsuff := false
	foundError := false
	for _, l := range lims {
		if l.ID == "LIM-EVID-INSUFFICIENT" && l.AffectedItem == "SC-1" {
			foundInsuff = true
		}
		if l.ID == "LIM-EVAL-ERROR" && l.AffectedItem == "SC-2" {
			foundError = true
			if l.Severity != LimitationSeverityCritical {
				t.Errorf("expected CRITICAL severity for error control, got %s", l.Severity)
			}
		}
	}

	if !foundInsuff {
		t.Errorf("expected LIM-EVID-INSUFFICIENT for SC-1")
	}
	if !foundError {
		t.Errorf("expected LIM-EVAL-ERROR for SC-2")
	}
}

// 4. ValidateDeterminationConsistency catches false compliance contradictions
func TestLimitations_4_ValidateDeterminationConsistency_CatchesContradictions(t *testing.T) {
	// A: 0 assessed controls but claims 2 compliant
	evalFalseComp := &EvaluationResult{
		AssessmentID: "ASM-FALSE",
		Summary: EvaluationSummary{
			TotalControls:    5,
			AssessedControls: 0,
			CompliantCount:   2,
		},
	}
	if err := ValidateDeterminationConsistency(evalFalseComp, nil, nil); err == nil {
		t.Errorf("expected error for 0 assessed controls with positive compliant count")
	}

	// B: Control state is not_assessed but rationale claims compliance
	evalContradictory := &EvaluationResult{
		AssessmentID: "ASM-CONTRADICTORY",
		Evaluations: []ControlEvaluationRecord{
			{ControlID: "AC-1", State: StateNotAssessed, Rationale: "Control requirement satisfied completely"},
		},
		Summary: EvaluationSummary{TotalControls: 1, NotAssessedCount: 1, AssessedControls: 0},
	}
	if err := ValidateDeterminationConsistency(evalContradictory, nil, nil); err == nil {
		t.Errorf("expected error for not_assessed control with satisfied rationale")
	}

	// C: compliant count exceeds applicable controls
	evalOverflow := &EvaluationResult{
		AssessmentID: "ASM-OVERFLOW",
		Summary: EvaluationSummary{
			TotalControls:      3,
			NotApplicableCount: 2,
			ApplicableControls: 1,
			CompliantCount:     2, // 2 > 1!
		},
	}
	if err := ValidateDeterminationConsistency(evalOverflow, nil, nil); err == nil {
		t.Errorf("expected error when compliant count exceeds applicable controls")
	}
}

// 5. DeduplicateAndSortLimitations is strictly deterministic
func TestLimitations_5_DeduplicateAndSortLimitations_Determinism(t *testing.T) {
	lims := []ComplianceLimitation{
		{ID: "LIM-03", Category: LimitationCategoryScope, Severity: LimitationSeverityInfo, Title: "Info Scope", AffectedItem: "AC-1", Description: "Desc A"},
		{ID: "LIM-01", Category: LimitationCategoryIntegrity, Severity: LimitationSeverityCritical, Title: "Critical Tamper", AffectedItem: "AC-2", Description: "Desc B"},
		{ID: "LIM-02", Category: LimitationCategoryCoverage, Severity: LimitationSeverityWarning, Title: "Warning Coverage", AffectedItem: "AC-3", Description: "Desc C"},
		{ID: "LIM-01", Category: LimitationCategoryIntegrity, Severity: LimitationSeverityCritical, Title: "Critical Tamper Duplicate", AffectedItem: "AC-2", Description: "Desc B"},
	}

	sorted := DeduplicateAndSortLimitations(lims)
	if len(sorted) != 3 {
		t.Fatalf("expected 3 unique limitations after deduplication, got %d", len(sorted))
	}

	// CRITICAL must come first
	if sorted[0].Severity != LimitationSeverityCritical {
		t.Errorf("expected first limitation to be CRITICAL, got %s", sorted[0].Severity)
	}
	// WARNING must come second
	if sorted[1].Severity != LimitationSeverityWarning {
		t.Errorf("expected second limitation to be WARNING, got %s", sorted[1].Severity)
	}
	// INFO must come third
	if sorted[2].Severity != LimitationSeverityInfo {
		t.Errorf("expected third limitation to be INFO, got %s", sorted[2].Severity)
	}
}

// 6. Dossier preserves structured limitations and includes them in logical digest
func TestLimitations_6_Dossier_StructuredLimitationsAndDigest(t *testing.T) {
	store := newTestStore(t)
	clock := NewMockClock(time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC))
	svc := NewDossierService(store, clock)

	evalRes := sampleValidEvaluationResult("ASM-DOSSIER-LIM")
	_ = store.SaveEvaluationResult(evalRes)

	dossier, err := svc.GenerateDossier(context.Background(), GenerateDossierRequest{
		AssessmentID: "ASM-DOSSIER-LIM",
		CatalogID:    "nist-sp800-53-sample",
	})
	if err != nil {
		t.Fatalf("GenerateDossier failed: %v", err)
	}

	if len(dossier.StructuredLimitations) == 0 {
		t.Fatalf("expected non-empty StructuredLimitations in dossier")
	}
	if dossier.CoverageBasis == nil {
		t.Fatalf("expected non-nil CoverageBasis in dossier")
	}

	// Changing limitations MUST change the dossier's logical digest
	origDigest := dossier.LogicalDigest
	cloned := *dossier
	cloned.Summary.Limitations = append([]string{}, dossier.Summary.Limitations...)
	cloned.Summary.Limitations = append(cloned.Summary.Limitations, "Newly discovered scope boundary limitation")

	newDigest := ComputeDossierLogicalDigest(&cloned)
	if newDigest == origDigest {
		t.Errorf("expected logical digest to change when limitations change, but got identical digest %s", origDigest)
	}
}

// 7. OSCAL export includes formal certification disclaimer and limitation properties
func TestLimitations_7_OSCALExport_LimitationProperties(t *testing.T) {
	store := newTestStore(t)
	clock := NewMockClock(time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC))
	exportSvc := NewExportService(store, clock)

	evalRes := sampleValidEvaluationResult("ASM-OSCAL-LIM")
	_ = store.SaveEvaluationResult(evalRes)

	doc, err := exportSvc.GenerateOSCALAssessmentResults(context.Background(), ExportRequest{
		AssessmentID: "ASM-OSCAL-LIM",
		CatalogID:    "nist-sp800-53-sample",
	})
	if err != nil {
		t.Fatalf("GenerateOSCALAssessmentResults failed: %v", err)
	}

	foundDisclaimer := false
	foundAssessedControls := false
	for _, prop := range doc.AssessmentResults.Metadata.Props {
		if prop.Name == "formal-certification-disclaimer" {
			foundDisclaimer = true
		}
		if prop.Name == "assessed-controls" {
			foundAssessedControls = true
		}
	}

	if !foundDisclaimer {
		t.Errorf("expected formal-certification-disclaimer prop in OSCAL metadata")
	}
	if !foundAssessedControls {
		t.Errorf("expected assessed-controls prop in OSCAL metadata")
	}

	// Must pass official OSCAL schema validation 100%
	if err := ValidateOSCALAssessmentResults(doc); err != nil {
		t.Fatalf("official OSCAL validation failed with limitation props: %v", err)
	}
}
