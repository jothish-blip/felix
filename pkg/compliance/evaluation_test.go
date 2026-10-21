package compliance

import (
	"reflect"
	"strings"
	"testing"
	"time"

	"felix/pkg/report"
)

func evalTestCatalog() *ControlCatalog {
	return &ControlCatalog{
		SchemaVersion: SchemaVersion1_0,
		ID:            "catalog-nist-eval",
		Title:         "NIST SP 800-53 Evaluation Catalog",
		Version:       "5.1.0",
		Framework:     "NIST",
		Controls: []Control{
			{
				ID:          "AC-3",
				Title:       "Access Enforcement",
				Description: "Enforce approved authorizations for logical access.",
				Status:      StatusActive,
				Category:    "Access Control",
			},
			{
				ID:          "IA-2",
				Title:       "Identification and Authentication",
				Description: "Uniquely identify and authenticate organizational users.",
				Status:      StatusActive,
				Category:    "Identification and Authentication",
			},
			{
				ID:          "SI-10",
				Title:       "Information Input Validation",
				Description: "Check information inputs for validity.",
				Status:      StatusActive,
				Category:    "System and Information Integrity",
			},
			{
				ID:          "SC-7",
				Title:       "Boundary Protection",
				Description: "Monitor and control communications at external boundary.",
				Status:      StatusActive,
				Category:    "System and Communications Protection",
			},
		},
	}
}

func evalTestRuleSet() *MappingRuleSet {
	return &MappingRuleSet{
		SchemaVersion:        SchemaVersion1_0,
		ID:                   "ruleset-eval",
		Title:                "Evaluation Ruleset",
		Version:              "1.0.0",
		TargetCatalogID:      "catalog-nist-eval",
		TargetCatalogVersion: "5.1.0",
		Rules: []MappingRule{
			{
				ID:              "RULE-SQLI-SI10",
				SourceRuleID:    "WEB_SQL_INJECTION",
				TargetControlID: "SI-10",
				Relationship:    RelationshipDirect,
				Rationale:       "SQL injection directly indicates lack of input validation.",
				Confidence:      1.0,
			},
			{
				ID:              "RULE-AUTH-IA2",
				SourceRuleID:    "APISPEC_NO_AUTH",
				TargetControlID: "IA-2",
				Relationship:    RelationshipDirect,
				Rationale:       "Unprotected endpoint violates authentication.",
				Confidence:      0.95,
			},
			{
				ID:              "RULE-AC3",
				SourceRuleID:    "IDOR_BOLA",
				TargetControlID: "AC-3",
				Relationship:    RelationshipDirect,
				Rationale:       "Object level access breach violates access enforcement.",
				Confidence:      0.9,
			},
		},
	}
}

// 1. Sufficient positive evidence produces compliant when control semantics support that conclusion
func TestEvalScenario1_SufficientPositiveEvidenceProducesCompliant(t *testing.T) {
	cat := evalTestCatalog()
	engine := NewEvaluationEngine()

	ctx := &EvaluationContext{
		AssessmentID:     "ASM-2026-001",
		AssessmentStatus: "COMPLETED",
		PositiveEvidence: []PositiveEvidence{
			{
				ID:          "PE-001",
				ControlID:   "SI-10",
				Location:    "/api/v1/search",
				Requirement: "input_validation",
				Observation: "Parameterized prepared statements and input validation confirmed on /api/v1/search",
				Method:      "ACTIVE_PROBE_CONFIRMATION",
			},
		},
	}

	res, err := engine.Evaluate(cat, nil, nil, ctx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var si10Rec *ControlEvaluationRecord
	for i := range res.Evaluations {
		if res.Evaluations[i].ControlID == "SI-10" {
			si10Rec = &res.Evaluations[i]
			break
		}
	}

	if si10Rec == nil {
		t.Fatalf("missing evaluation record for SI-10")
	}
	if si10Rec.State != StateCompliant {
		t.Errorf("expected StateCompliant for verified positive evidence, got %q", si10Rec.State)
	}
	if len(si10Rec.SupportingEvidence) == 0 {
		t.Errorf("expected supporting evidence to be preserved in record")
	}
}

// 2. A verified applicable violation produces non_compliant
func TestEvalScenario2_VerifiedViolationProducesNonCompliant(t *testing.T) {
	cat := evalTestCatalog()
	rs := evalTestRuleSet()
	engine := NewEvaluationEngine()

	finding := report.Finding{
		ID:       "F-SQLI-01",
		RuleID:   "WEB_SQL_INJECTION",
		Category: "injection",
		Title:    "SQL Injection in Search Form",
		Severity: "CRITICAL",
		Status:   report.FindingStatusConfirmed,
		Evidence: "SLEEP(5) induced response delay of 5.1s",
		Endpoint: "/api/search",
		Verification: report.VerificationRecord{
			Status: report.VerificationVerified,
		},
	}

	mappingRes, err := MapFindings(cat, rs, []report.Finding{finding})
	if err != nil {
		t.Fatalf("mapping failed: %v", err)
	}

	ctx := &EvaluationContext{
		AssessmentID:     "ASM-2026-001",
		AssessmentStatus: "COMPLETED",
	}

	res, err := engine.Evaluate(cat, mappingRes, []report.Finding{finding}, ctx)
	if err != nil {
		t.Fatalf("evaluation failed: %v", err)
	}

	var si10Rec *ControlEvaluationRecord
	for i := range res.Evaluations {
		if res.Evaluations[i].ControlID == "SI-10" {
			si10Rec = &res.Evaluations[i]
			break
		}
	}

	if si10Rec == nil {
		t.Fatalf("missing evaluation record for SI-10")
	}
	if si10Rec.State != StateNonCompliant {
		t.Errorf("expected StateNonCompliant for verified finding, got %q", si10Rec.State)
	}
	if len(si10Rec.FindingIDs) != 1 || si10Rec.FindingIDs[0] != "F-SQLI-01" {
		t.Errorf("expected finding F-SQLI-01 in record, got %v", si10Rec.FindingIDs)
	}
	if len(si10Rec.ContradictingEvidence) == 0 {
		t.Errorf("expected contradicting evidence recorded")
	}
}

// 3. Mixed requirement-level evidence produces partially_compliant only when supported
func TestEvalScenario3_MixedRequirementEvidenceProducesPartiallyCompliant(t *testing.T) {
	cat := evalTestCatalog()
	rs := evalTestRuleSet()
	engine := NewEvaluationEngine(EvaluationPolicy{AllowPartialCompliance: true})

	// Add second rule targeting SI-10 for distinct sub-requirement
	rs.Rules = append(rs.Rules, MappingRule{
		ID:              "RULE-XSS-SI10",
		SourceRuleID:    "WEB_XSS",
		TargetControlID: "SI-10",
		Relationship:    RelationshipDirect,
		Rationale:       "XSS demonstrates unvalidated input",
		Confidence:      1.0,
	})

	findingViolating := report.Finding{
		ID:       "F-SQLI",
		RuleID:   "WEB_SQL_INJECTION",
		Severity: "HIGH",
		Status:   report.FindingStatusConfirmed,
		Evidence: "SQLi confirmed",
		Endpoint: "/api/search",
	}

	mappingRes, err := MapFindings(cat, rs, []report.Finding{findingViolating})
	if err != nil {
		t.Fatalf("mapping failed: %v", err)
	}

	ctx := &EvaluationContext{
		AssessmentID:     "ASM-2026-001",
		AssessmentStatus: "COMPLETED",
		PositiveEvidence: []PositiveEvidence{
			{
				ID:          "PE-XSS-PASS",
				ControlID:   "SI-10",
				Requirement: "WEB_XSS",
				Location:    "/api/search",
				Observation: "HTML contextual encoding verified against XSS payloads",
				Method:      "ACTIVE_PROBE",
			},
		},
	}

	res, err := engine.Evaluate(cat, mappingRes, []report.Finding{findingViolating}, ctx)
	if err != nil {
		t.Fatalf("evaluation failed: %v", err)
	}

	var si10Rec *ControlEvaluationRecord
	for i := range res.Evaluations {
		if res.Evaluations[i].ControlID == "SI-10" {
			si10Rec = &res.Evaluations[i]
			break
		}
	}

	if si10Rec == nil {
		t.Fatalf("missing evaluation record for SI-10")
	}
	if si10Rec.State != StatePartiallyCompliant {
		t.Errorf("expected StatePartiallyCompliant for mixed sub-requirements, got %q", si10Rec.State)
	}
}

// 4. No findings without adequate positive evidence does not produce compliant
func TestEvalScenario4_NoFindingsWithoutPositiveEvidenceDoesNotProduceCompliant(t *testing.T) {
	cat := evalTestCatalog()
	engine := NewEvaluationEngine()

	// Completed assessment, zero findings, zero positive evidence
	ctx := &EvaluationContext{
		AssessmentID:     "ASM-2026-001",
		AssessmentStatus: "COMPLETED",
	}

	res, err := engine.Evaluate(cat, nil, nil, ctx)
	if err != nil {
		t.Fatalf("evaluation failed: %v", err)
	}

	for _, ev := range res.Evaluations {
		if ev.State == StateCompliant {
			t.Errorf("control %s was marked compliant merely from absence of findings!", ev.ControlID)
		}
	}
	if res.Summary.CompliantCount != 0 {
		t.Errorf("CompliantCount must be 0 when no positive evidence exists, got %d", res.Summary.CompliantCount)
	}
}

// 5. A control with no performed assessment is not_assessed
func TestEvalScenario5_ControlWithNoPerformedAssessmentIsNotAssessed(t *testing.T) {
	cat := evalTestCatalog()
	engine := NewEvaluationEngine()

	ctx := &EvaluationContext{
		AssessmentID:     "ASM-2026-001",
		AssessmentStatus: "COMPLETED",
	}

	res, err := engine.Evaluate(cat, nil, nil, ctx)
	if err != nil {
		t.Fatalf("evaluation failed: %v", err)
	}

	for _, ev := range res.Evaluations {
		if ev.State != StateNotAssessed {
			t.Errorf("expected control %s to be not_assessed, got %q", ev.ControlID, ev.State)
		}
	}
	if res.Summary.NotAssessedCount != len(cat.Controls) {
		t.Errorf("expected all %d controls to be not_assessed, got %d", len(cat.Controls), res.Summary.NotAssessedCount)
	}
}

// 6. Inadequate evidence produces insufficient_evidence
func TestEvalScenario6_InadequateEvidenceProducesInsufficientEvidence(t *testing.T) {
	cat := evalTestCatalog()
	rs := evalTestRuleSet()
	engine := NewEvaluationEngine()

	// Finding is suspected/inconclusive, lacks confirmed proof
	suspectedFinding := report.Finding{
		ID:       "F-SUSPECTED",
		RuleID:   "WEB_SQL_INJECTION",
		Status:   report.FindingStatusSuspected,
		Severity: "MEDIUM",
		Evidence: "HTTP 500 returned on quote probe, unverified",
		Endpoint: "/api/items",
		Verification: report.VerificationRecord{
			Status: report.VerificationObserved, // not verified
		},
	}

	mappingRes, err := MapFindings(cat, rs, []report.Finding{suspectedFinding})
	if err != nil {
		t.Fatalf("mapping failed: %v", err)
	}

	ctx := &EvaluationContext{
		AssessmentID:     "ASM-2026-001",
		AssessmentStatus: "COMPLETED",
	}

	res, err := engine.Evaluate(cat, mappingRes, []report.Finding{suspectedFinding}, ctx)
	if err != nil {
		t.Fatalf("evaluation failed: %v", err)
	}

	var si10Rec *ControlEvaluationRecord
	for i := range res.Evaluations {
		if res.Evaluations[i].ControlID == "SI-10" {
			si10Rec = &res.Evaluations[i]
			break
		}
	}

	if si10Rec == nil {
		t.Fatalf("missing record for SI-10")
	}
	if si10Rec.State != StateInsufficientEvidence {
		t.Errorf("expected StateInsufficientEvidence for suspected unverified finding, got %q", si10Rec.State)
	}
}

// 7. Explicitly supported inapplicability produces not_applicable
func TestEvalScenario7_ExplicitlySupportedInapplicabilityProducesNotApplicable(t *testing.T) {
	cat := evalTestCatalog()
	engine := NewEvaluationEngine()

	ctx := &EvaluationContext{
		AssessmentID:     "ASM-2026-001",
		AssessmentStatus: "COMPLETED",
		Applicability: map[string]ApplicabilityDetermination{
			"SC-7": {
				ControlID:  "SC-7",
				Applicable: false,
				Rationale:  "Target is an internal headless microservice without perimeter gateway",
				Basis:      "ARCHITECTURE_SPEC_SECTION_4_INTERNAL_ONLY",
			},
		},
	}

	res, err := engine.Evaluate(cat, nil, nil, ctx)
	if err != nil {
		t.Fatalf("evaluation failed: %v", err)
	}

	var sc7Rec *ControlEvaluationRecord
	for i := range res.Evaluations {
		if res.Evaluations[i].ControlID == "SC-7" {
			sc7Rec = &res.Evaluations[i]
			break
		}
	}

	if sc7Rec == nil {
		t.Fatalf("missing record for SC-7")
	}
	if sc7Rec.State != StateNotApplicable {
		t.Errorf("expected StateNotApplicable for supported exemption, got %q", sc7Rec.State)
	}
	if !strings.Contains(sc7Rec.Rationale, "microservice") {
		t.Errorf("expected rationale preserved, got %q", sc7Rec.Rationale)
	}
	if len(sc7Rec.EvidenceReferences) == 0 || sc7Rec.EvidenceReferences[0] != "ARCHITECTURE_SPEC_SECTION_4_INTERNAL_ONLY" {
		t.Errorf("expected basis recorded in evidence references")
	}
}

// 8. An unsupported inapplicability claim is rejected or classified appropriately
func TestEvalScenario8_UnsupportedInapplicabilityClaimClassifiedAppropriately(t *testing.T) {
	cat := evalTestCatalog()
	engine := NewEvaluationEngine()

	// Empty rationale and basis
	ctx := &EvaluationContext{
		AssessmentID:     "ASM-2026-001",
		AssessmentStatus: "COMPLETED",
		Applicability: map[string]ApplicabilityDetermination{
			"SC-7": {
				ControlID:  "SC-7",
				Applicable: false,
				Rationale:  "", // unsupported: empty
				Basis:      "",
			},
		},
	}

	res, err := engine.Evaluate(cat, nil, nil, ctx)
	if err != nil {
		t.Fatalf("evaluation failed: %v", err)
	}

	var sc7Rec *ControlEvaluationRecord
	for i := range res.Evaluations {
		if res.Evaluations[i].ControlID == "SC-7" {
			sc7Rec = &res.Evaluations[i]
			break
		}
	}

	if sc7Rec == nil {
		t.Fatalf("missing record for SC-7")
	}
	// Must not be falsely accepted as StateNotApplicable or StateCompliant
	if sc7Rec.State != StateInsufficientEvidence {
		t.Errorf("expected StateInsufficientEvidence for unsupported inapplicability, got %q", sc7Rec.State)
	}
}

// 9. Evaluation execution failures produce error, never compliant
func TestEvalScenario9_EvaluationExecutionFailuresProduceError(t *testing.T) {
	cat := evalTestCatalog()
	engine := NewEvaluationEngine()

	ctx := &EvaluationContext{
		AssessmentID:     "ASM-2026-001",
		AssessmentStatus: "COMPLETED",
		ExecutionErrors: map[string]string{
			"IA-2": "Scanner crash: probe worker terminated unexpectedly with exit code 137 (OOM)",
		},
	}

	res, err := engine.Evaluate(cat, nil, nil, ctx)
	if err != nil {
		t.Fatalf("evaluation failed: %v", err)
	}

	var ia2Rec *ControlEvaluationRecord
	for i := range res.Evaluations {
		if res.Evaluations[i].ControlID == "IA-2" {
			ia2Rec = &res.Evaluations[i]
			break
		}
	}

	if ia2Rec == nil {
		t.Fatalf("missing record for IA-2")
	}
	if ia2Rec.State != StateError {
		t.Errorf("expected StateError for execution error, got %q", ia2Rec.State)
	}
	if !strings.Contains(ia2Rec.Rationale, "Scanner crash") {
		t.Errorf("expected error rationale recorded, got %q", ia2Rec.Rationale)
	}
}

// 10. Incomplete or cancelled assessment coverage cannot produce a falsely conclusive compliant outcome
func TestEvalScenario10_IncompleteOrCancelledAssessmentCannotProduceCompliant(t *testing.T) {
	cat := evalTestCatalog()
	engine := NewEvaluationEngine()

	cancelledStatuses := []string{"CANCELLED", "FAILED", "INTERRUPTED", "SKIPPED"}
	for _, status := range cancelledStatuses {
		ctx := &EvaluationContext{
			AssessmentID:     "ASM-2026-001",
			AssessmentStatus: status,
			PositiveEvidence: []PositiveEvidence{
				{
					ID:          "PE-001",
					ControlID:   "SI-10",
					Observation: "Pre-cancellation probe",
					Method:      "ACTIVE_PROBE",
				},
			},
		}

		res, err := engine.Evaluate(cat, nil, nil, ctx)
		if err != nil {
			t.Fatalf("evaluation failed: %v", err)
		}

		for _, ev := range res.Evaluations {
			if ev.State == StateCompliant {
				t.Errorf("incomplete assessment status %q produced falsely compliant outcome on %s", status, ev.ControlID)
			}
		}
	}
}

// 11. A mapping without supporting evidence does not prove a violation
func TestEvalScenario11_MappingWithoutSupportingEvidenceDoesNotProveViolation(t *testing.T) {
	cat := evalTestCatalog()
	rs := evalTestRuleSet()
	engine := NewEvaluationEngine()

	// Finding has NO concrete evidence
	noEvidenceFinding := report.Finding{
		ID:       "F-NO-EV",
		RuleID:   "WEB_SQL_INJECTION",
		Title:    "Heuristic query observation",
		Endpoint: "/search",
	}

	mappingRes, err := MapFindings(cat, rs, []report.Finding{noEvidenceFinding})
	if err != nil {
		t.Fatalf("mapping failed: %v", err)
	}

	ctx := &EvaluationContext{
		AssessmentID:     "ASM-2026-001",
		AssessmentStatus: "COMPLETED",
	}

	res, err := engine.Evaluate(cat, mappingRes, []report.Finding{noEvidenceFinding}, ctx)
	if err != nil {
		t.Fatalf("evaluation failed: %v", err)
	}

	var si10Rec *ControlEvaluationRecord
	for i := range res.Evaluations {
		if res.Evaluations[i].ControlID == "SI-10" {
			si10Rec = &res.Evaluations[i]
			break
		}
	}

	if si10Rec == nil {
		t.Fatalf("missing record for SI-10")
	}
	if si10Rec.State == StateNonCompliant {
		t.Errorf("mapping without concrete evidence falsely produced non_compliant verdict!")
	}
	if si10Rec.State != StateInsufficientEvidence {
		t.Errorf("expected StateInsufficientEvidence, got %q", si10Rec.State)
	}
}

// 12. Invalid or unverifiable evidence cannot establish compliance
func TestEvalScenario12_InvalidOrUnverifiableEvidenceCannotEstablishCompliance(t *testing.T) {
	cat := evalTestCatalog()
	engine := NewEvaluationEngine()

	// Missing observation and method
	ctx := &EvaluationContext{
		AssessmentID:     "ASM-2026-001",
		AssessmentStatus: "COMPLETED",
		PositiveEvidence: []PositiveEvidence{
			{
				ID:          "PE-INVALID",
				ControlID:   "SI-10",
				Observation: "", // empty
				Method:      "", // empty
			},
		},
	}

	res, err := engine.Evaluate(cat, nil, nil, ctx)
	if err != nil {
		t.Fatalf("evaluation failed: %v", err)
	}

	var si10Rec *ControlEvaluationRecord
	for i := range res.Evaluations {
		if res.Evaluations[i].ControlID == "SI-10" {
			si10Rec = &res.Evaluations[i]
			break
		}
	}

	if si10Rec == nil {
		t.Fatalf("missing record for SI-10")
	}
	if si10Rec.State == StateCompliant {
		t.Errorf("invalid evidence falsely established compliance!")
	}
}

// 13. Conflicting positive and negative evidence is handled according to defined policy
func TestEvalScenario13_ConflictingPositiveAndNegativeEvidenceHandledByPolicy(t *testing.T) {
	cat := evalTestCatalog()
	rs := evalTestRuleSet()
	engine := NewEvaluationEngine()

	// Confirmed violation on /api/search
	violation := report.Finding{
		ID:       "F-VULN",
		RuleID:   "WEB_SQL_INJECTION",
		Severity: "HIGH",
		Status:   report.FindingStatusConfirmed,
		Evidence: "Differential response observed",
		Endpoint: "/api/search",
	}

	mappingRes, err := MapFindings(cat, rs, []report.Finding{violation})
	if err != nil {
		t.Fatalf("mapping failed: %v", err)
	}

	// Positive evidence claiming /api/search is defended/passed on the same location
	ctx := &EvaluationContext{
		AssessmentID:     "ASM-2026-001",
		AssessmentStatus: "COMPLETED",
		PositiveEvidence: []PositiveEvidence{
			{
				ID:          "PE-CONTRADICT",
				ControlID:   "SI-10",
				Location:    "/api/search", // EXACT SAME LOCATION
				Observation: "Input validation strictly passes on /api/search",
				Method:      "ACTIVE_PROBE",
			},
		},
	}

	res, err := engine.Evaluate(cat, mappingRes, []report.Finding{violation}, ctx)
	if err != nil {
		t.Fatalf("evaluation failed: %v", err)
	}

	var si10Rec *ControlEvaluationRecord
	for i := range res.Evaluations {
		if res.Evaluations[i].ControlID == "SI-10" {
			si10Rec = &res.Evaluations[i]
			break
		}
	}

	if si10Rec == nil {
		t.Fatalf("missing record for SI-10")
	}
	// Direct unresolvable contradiction on same target must produce insufficient_evidence
	if si10Rec.State != StateInsufficientEvidence {
		t.Errorf("expected StateInsufficientEvidence for direct contradiction, got %q", si10Rec.State)
	}
	if !strings.Contains(si10Rec.Rationale, "Conflicting positive and negative evidence") {
		t.Errorf("expected contradiction rationale, got %q", si10Rec.Rationale)
	}
}

// 14. Multiple findings mapped to one control produce one control evaluation record
func TestEvalScenario14_MultipleFindingsProduceOneRecord(t *testing.T) {
	cat := evalTestCatalog()
	rs := evalTestRuleSet()
	engine := NewEvaluationEngine()

	f1 := report.Finding{
		ID:       "F-1",
		RuleID:   "WEB_SQL_INJECTION",
		Status:   report.FindingStatusConfirmed,
		Severity: "HIGH",
		Evidence: "SQLi 1",
		Endpoint: "/api/search",
	}
	f2 := report.Finding{
		ID:       "F-2",
		RuleID:   "WEB_SQL_INJECTION",
		Status:   report.FindingStatusConfirmed,
		Severity: "CRITICAL",
		Evidence: "SQLi 2",
		Endpoint: "/api/login",
	}

	mappingRes, err := MapFindings(cat, rs, []report.Finding{f1, f2})
	if err != nil {
		t.Fatalf("mapping failed: %v", err)
	}

	ctx := &EvaluationContext{
		AssessmentID:     "ASM-2026-001",
		AssessmentStatus: "COMPLETED",
	}

	res, err := engine.Evaluate(cat, mappingRes, []report.Finding{f1, f2}, ctx)
	if err != nil {
		t.Fatalf("evaluation failed: %v", err)
	}

	si10Count := 0
	for _, ev := range res.Evaluations {
		if ev.ControlID == "SI-10" {
			si10Count++
			if len(ev.FindingIDs) != 2 {
				t.Errorf("expected 2 finding IDs aggregated into single record, got %d", len(ev.FindingIDs))
			}
		}
	}
	if si10Count != 1 {
		t.Errorf("expected exactly 1 evaluation record for SI-10, got %d", si10Count)
	}
}

// 15. Unknown control references are rejected or explicitly classified
func TestEvalScenario15_UnknownControlReferencesRejected(t *testing.T) {
	cat := evalTestCatalog()
	engine := NewEvaluationEngine()

	ctx := &EvaluationContext{
		AssessmentID:     "ASM-2026-001",
		AssessmentStatus: "COMPLETED",
		Applicability: map[string]ApplicabilityDetermination{
			"ZZ-NONEXISTENT": {
				ControlID:  "ZZ-NONEXISTENT",
				Applicable: false,
				Rationale:  "Invalid control ID",
				Basis:      "NONE",
			},
		},
	}

	_, err := engine.Evaluate(cat, nil, nil, ctx)
	if err == nil || !strings.Contains(err.Error(), "unknown control ID") {
		t.Errorf("expected unknown control ID error, got: %v", err)
	}
}

// 16. Catalog-version mismatches are rejected
func TestEvalScenario16_CatalogVersionMismatchesRejected(t *testing.T) {
	catV1 := evalTestCatalog()
	catV1.Version = "5.1.0"

	catV2 := evalTestCatalog()
	catV2.Version = "6.0.0"

	rs := evalTestRuleSet()

	// Mapping against catV1
	mappingRes, err := MapFindings(catV1, rs, nil)
	if err != nil {
		t.Fatalf("mapping failed: %v", err)
	}

	engine := NewEvaluationEngine()
	ctx := &EvaluationContext{AssessmentID: "ASM-2026-001"}

	// Evaluate against catV2 with mapping generated for catV1
	_, err = engine.Evaluate(catV2, mappingRes, nil, ctx)
	if err == nil || !strings.Contains(err.Error(), "catalog version mismatch") {
		t.Errorf("expected catalog version mismatch error, got: %v", err)
	}
}

// 17. Invalid evaluation states are rejected
func TestEvalScenario17_InvalidEvaluationStatesRejected(t *testing.T) {
	invalidStates := []EvaluationState{"passed", "failed", "good", "bad", "100%", ""}
	for _, badState := range invalidStates {
		if err := ValidateEvaluationState(badState); err == nil {
			t.Errorf("expected error for invalid state %q", badState)
		}
	}

	validStates := []EvaluationState{
		StateCompliant,
		StateNonCompliant,
		StatePartiallyCompliant,
		StateNotAssessed,
		StateInsufficientEvidence,
		StateNotApplicable,
		StateError,
	}
	for _, goodState := range validStates {
		if err := ValidateEvaluationState(goodState); err != nil {
			t.Errorf("expected valid state %q to pass, got: %v", goodState, err)
		}
	}
}

// 18. Nil, empty, malformed, and inconsistent inputs are handled safely
func TestEvalScenario18_NilEmptyMalformedInputsHandledSafely(t *testing.T) {
	engine := NewEvaluationEngine()
	cat := evalTestCatalog()
	ctx := &EvaluationContext{AssessmentID: "ASM-2026-001"}

	if _, err := engine.Evaluate(nil, nil, nil, ctx); err == nil {
		t.Errorf("expected error for nil catalog")
	}
	if _, err := engine.Evaluate(cat, nil, nil, nil); err == nil {
		t.Errorf("expected error for nil context")
	}
	if _, err := engine.Evaluate(cat, nil, nil, &EvaluationContext{AssessmentID: ""}); err == nil {
		t.Errorf("expected error for empty assessment ID")
	}
	if err := ValidateEvaluationResult(nil, cat); err == nil {
		t.Errorf("expected error for nil result in validator")
	}
}

// 19. Reordering findings and evidence does not change semantic outcomes
func TestEvalScenario19_ReorderingFindingsDoesNotChangeOutcomes(t *testing.T) {
	cat := evalTestCatalog()
	rs := evalTestRuleSet()

	f1 := report.Finding{ID: "F-1", RuleID: "WEB_SQL_INJECTION", Status: report.FindingStatusConfirmed, Evidence: "ev1"}
	f2 := report.Finding{ID: "F-2", RuleID: "APISPEC_NO_AUTH", Status: report.FindingStatusConfirmed, Evidence: "ev2"}

	findingsA := []report.Finding{f1, f2}
	findingsB := []report.Finding{f2, f1}

	mappingA, _ := MapFindings(cat, rs, findingsA)
	mappingB, _ := MapFindings(cat, rs, findingsB)

	fixedClock := func() time.Time { return time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC) }
	engine := NewEvaluationEngine().WithClock(fixedClock)

	ctx := &EvaluationContext{
		AssessmentID:     "ASM-2026-001",
		AssessmentStatus: "COMPLETED",
	}

	resA, errA := engine.Evaluate(cat, mappingA, findingsA, ctx)
	resB, errB := engine.Evaluate(cat, mappingB, findingsB, ctx)

	if errA != nil || errB != nil {
		t.Fatalf("evaluation errors: %v / %v", errA, errB)
	}

	if !reflect.DeepEqual(resA.Evaluations, resB.Evaluations) {
		t.Errorf("evaluations differ under input finding reordering!")
	}
	if resA.Digest() != resB.Digest() {
		t.Errorf("semantic digest differs under input finding reordering!")
	}
}

// 20. Evaluation summaries count each control exactly once
func TestEvalScenario20_EvaluationSummariesCountEachControlExactlyOnce(t *testing.T) {
	cat := evalTestCatalog()
	rs := evalTestRuleSet()
	engine := NewEvaluationEngine()

	findings := []report.Finding{
		{ID: "F-1", RuleID: "WEB_SQL_INJECTION", Status: report.FindingStatusConfirmed, Evidence: "ev"},
		{ID: "F-2", RuleID: "WEB_SQL_INJECTION", Status: report.FindingStatusConfirmed, Evidence: "ev"},
		{ID: "F-3", RuleID: "APISPEC_NO_AUTH", Status: report.FindingStatusConfirmed, Evidence: "ev"},
	}

	mappingRes, _ := MapFindings(cat, rs, findings)

	ctx := &EvaluationContext{
		AssessmentID:     "ASM-2026-001",
		AssessmentStatus: "COMPLETED",
		Applicability: map[string]ApplicabilityDetermination{
			"SC-7": {ControlID: "SC-7", Applicable: false, Rationale: "Internal only", Basis: "POLICY_1"},
		},
	}

	res, err := engine.Evaluate(cat, mappingRes, findings, ctx)
	if err != nil {
		t.Fatalf("evaluation failed: %v", err)
	}

	sum := res.Summary
	if sum.TotalControls != len(cat.Controls) {
		t.Errorf("expected TotalControls %d, got %d", len(cat.Controls), sum.TotalControls)
	}

	countedTotal := sum.CompliantCount +
		sum.NonCompliantCount +
		sum.PartiallyCompliantCount +
		sum.NotAssessedCount +
		sum.InsufficientEvidenceCount +
		sum.NotApplicableCount +
		sum.ErrorCount

	if countedTotal != sum.TotalControls {
		t.Errorf("sum of state counts (%d) does not match total controls (%d)", countedTotal, sum.TotalControls)
	}
}

// 21. Evaluation provenance references correct assessment, catalog, and mapping-rule version
func TestEvalScenario21_ProvenanceReferencesCorrectVersions(t *testing.T) {
	cat := evalTestCatalog()
	rs := evalTestRuleSet()
	engine := NewEvaluationEngine()

	mappingRes, _ := MapFindings(cat, rs, nil)

	ctx := &EvaluationContext{
		AssessmentID:     "ASM-PROV-999",
		ExecutionID:      "EXEC-001",
		AssessmentStatus: "COMPLETED",
	}

	res, err := engine.Evaluate(cat, mappingRes, nil, ctx)
	if err != nil {
		t.Fatalf("evaluation failed: %v", err)
	}

	if res.AssessmentID != "ASM-PROV-999" {
		t.Errorf("expected AssessmentID 'ASM-PROV-999', got %q", res.AssessmentID)
	}
	if res.CatalogIdentity != cat.Identity() {
		t.Errorf("expected CatalogIdentity %q, got %q", cat.Identity(), res.CatalogIdentity)
	}
	if res.MappingRuleSetIdentity != rs.Identity() {
		t.Errorf("expected MappingRuleSetIdentity %q, got %q", rs.Identity(), res.MappingRuleSetIdentity)
	}

	for _, ev := range res.Evaluations {
		if ev.AssessmentID != "ASM-PROV-999" {
			t.Errorf("evaluation record missing AssessmentID")
		}
		if ev.CatalogID != cat.ID || ev.CatalogVersion != cat.Version {
			t.Errorf("evaluation record missing catalog provenance")
		}
	}
}

// 22. Evaluation outcomes never rely on unsupported framework claims
func TestEvalScenario22_LimitationsNoticeEnforced(t *testing.T) {
	cat := evalTestCatalog()
	engine := NewEvaluationEngine()
	ctx := &EvaluationContext{AssessmentID: "ASM-2026-001"}

	res, err := engine.Evaluate(cat, nil, nil, ctx)
	if err != nil {
		t.Fatalf("evaluation failed: %v", err)
	}

	notice := res.LimitationsNotice
	if !strings.Contains(notice, "NOT constitute a formal regulatory certification") {
		t.Errorf("missing regulatory certification warning in notice: %q", notice)
	}
	if !strings.Contains(notice, "bounded strictly by the assessed scope") {
		t.Errorf("missing scope bounding statement in notice: %q", notice)
	}

	// Validate output with validator
	if err := ValidateEvaluationResult(res, cat); err != nil {
		t.Errorf("ValidateEvaluationResult failed on valid result: %v", err)
	}
}

// ============================================================================
// TARGETED SEMANTIC RISK VERIFICATION TESTS (RISKS 1 - 8)
// ============================================================================

// Risk 1: Positive evidence scope
func TestSemanticRisk1_PositiveEvidenceScope(t *testing.T) {
	cat := evalTestCatalog()
	engine := NewEvaluationEngine()

	// Sub-test A: Multiple requirements - only 1 satisfied -> insufficient_evidence
	t.Run("MultipleRequirements_PartialCoverage_InsufficientEvidence", func(t *testing.T) {
		ctx := &EvaluationContext{
			AssessmentID:     "ASM-RISK1-001",
			AssessmentStatus: "COMPLETED",
			ControlRequirements: map[string][]string{
				"SI-10": {"SQL_INJECTION", "CROSS_SITE_SCRIPTING", "COMMAND_INJECTION"},
			},
			PositiveEvidence: []PositiveEvidence{
				{
					ID:          "PE-XSS-ONLY",
					ControlID:   "SI-10",
					Requirement: "CROSS_SITE_SCRIPTING",
					Observation: "XSS sanitized",
					Method:      "ACTIVE_PROBE",
				},
			},
		}

		res, err := engine.Evaluate(cat, nil, nil, ctx)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		var si10 *ControlEvaluationRecord
		for i := range res.Evaluations {
			if res.Evaluations[i].ControlID == "SI-10" {
				si10 = &res.Evaluations[i]
				break
			}
		}

		if si10.State != StateInsufficientEvidence {
			t.Errorf("expected StateInsufficientEvidence when only 1 of 3 requirements satisfied, got %q", si10.State)
		}
		if !strings.Contains(si10.Rationale, "verified 1 of 3") {
			t.Errorf("expected rationale noting partial requirement coverage, got %q", si10.Rationale)
		}
	})

	// Sub-test B: Multiple requirements - all satisfied -> compliant
	t.Run("MultipleRequirements_FullCoverage_Compliant", func(t *testing.T) {
		ctx := &EvaluationContext{
			AssessmentID:     "ASM-RISK1-002",
			AssessmentStatus: "COMPLETED",
			ControlRequirements: map[string][]string{
				"SI-10": {"SQL_INJECTION", "CROSS_SITE_SCRIPTING"},
			},
			PositiveEvidence: []PositiveEvidence{
				{
					ID:          "PE-SQLI",
					ControlID:   "SI-10",
					Requirement: "SQL_INJECTION",
					Observation: "SQLi parameterized queries verified",
					Method:      "CODE_AND_PROBE",
				},
				{
					ID:          "PE-XSS",
					ControlID:   "SI-10",
					Requirement: "CROSS_SITE_SCRIPTING",
					Observation: "XSS contextual encoding verified",
					Method:      "CODE_AND_PROBE",
				},
			},
		}

		res, err := engine.Evaluate(cat, nil, nil, ctx)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		var si10 *ControlEvaluationRecord
		for i := range res.Evaluations {
			if res.Evaluations[i].ControlID == "SI-10" {
				si10 = &res.Evaluations[i]
				break
			}
		}

		if si10.State != StateCompliant {
			t.Errorf("expected StateCompliant when all requirements satisfied, got %q", si10.State)
		}
	})

	// Sub-test C: Incomplete target scope coverage -> insufficient_evidence
	t.Run("IncompleteTargetScope_InsufficientEvidence", func(t *testing.T) {
		ctx := &EvaluationContext{
			AssessmentID:     "ASM-RISK1-003",
			AssessmentStatus: "COMPLETED",
			TargetScope:      []string{"https://api.example.com", "https://app.example.com"},
			PositiveEvidence: []PositiveEvidence{
				{
					ID:          "PE-API-ONLY",
					ControlID:   "SC-7",
					Location:    "https://api.example.com", // covers only 1 of 2 targets
					Observation: "Perimeter gateway firewall enforced on API",
					Method:      "ACTIVE_PROBE",
				},
			},
		}

		res, err := engine.Evaluate(cat, nil, nil, ctx)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		var sc7 *ControlEvaluationRecord
		for i := range res.Evaluations {
			if res.Evaluations[i].ControlID == "SC-7" {
				sc7 = &res.Evaluations[i]
				break
			}
		}

		if sc7 == nil {
			t.Fatalf("missing record for SC-7")
		}
		if sc7.State != StateInsufficientEvidence {
			t.Errorf("expected StateInsufficientEvidence for partial target scope coverage, got %q", sc7.State)
		}
		if !strings.Contains(sc7.Rationale, "covers 1 of 2 targets") {
			t.Errorf("expected rationale noting incomplete target scope, got %q", sc7.Rationale)
		}
	})
}

// Risk 2: Execution-error precedence
func TestSemanticRisk2_ExecutionErrorPrecedence(t *testing.T) {
	cat := evalTestCatalog()
	rs := evalTestRuleSet()
	engine := NewEvaluationEngine()

	// Control SI-10 has BOTH a confirmed violation AND an execution error on a secondary probe
	finding := report.Finding{
		ID:           "F-SQLI-CONFIRMED",
		RuleID:       "WEB_SQL_INJECTION",
		Status:       report.FindingStatusConfirmed,
		Evidence:     "SQL syntax error delay 5s",
		Endpoint:     "/api/search",
		Verification: report.VerificationRecord{Status: report.VerificationVerified},
	}

	mappingRes, err := MapFindings(cat, rs, []report.Finding{finding})
	if err != nil {
		t.Fatalf("mapping error: %v", err)
	}

	ctx := &EvaluationContext{
		AssessmentID:     "ASM-RISK2-001",
		AssessmentStatus: "COMPLETED",
		ExecutionErrors: map[string]string{
			"SI-10": "Secondary fuzzing worker timed out on port 8443",
			"SC-7":  "Boundary analyzer failed: missing VPC flow logs",
		},
	}

	res, err := engine.Evaluate(cat, mappingRes, []report.Finding{finding}, ctx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var si10, sc7, ia2 *ControlEvaluationRecord
	for i := range res.Evaluations {
		switch res.Evaluations[i].ControlID {
		case "SI-10":
			si10 = &res.Evaluations[i]
		case "SC-7":
			sc7 = &res.Evaluations[i]
		case "IA-2":
			ia2 = &res.Evaluations[i]
		}
	}

	// 1. SI-10 has a confirmed violation: violation must NOT be overridden by execution error
	if si10.State != StateNonCompliant {
		t.Errorf("expected SI-10 state=non_compliant despite execution error, got %q", si10.State)
	}
	if !strings.Contains(si10.Rationale, "partial execution error also occurred") {
		t.Errorf("expected note about partial execution error in rationale, got %q", si10.Rationale)
	}

	// 2. SC-7 has NO confirmed violations, so execution error produces StateError
	if sc7.State != StateError {
		t.Errorf("expected SC-7 state=error without findings, got %q", sc7.State)
	}

	// 3. IA-2 has NO error and NO findings: unaffected, produces StateNotAssessed
	if ia2.State != StateNotAssessed {
		t.Errorf("expected IA-2 state=not_assessed, got %q", ia2.State)
	}
}

// Risk 3: Incomplete assessments
func TestSemanticRisk3_IncompleteAssessments(t *testing.T) {
	cat := evalTestCatalog()
	rs := evalTestRuleSet()
	engine := NewEvaluationEngine()

	// Finding observed before cancellation
	finding := report.Finding{
		ID:           "F-SQLI-EARLY",
		RuleID:       "WEB_SQL_INJECTION",
		Status:       report.FindingStatusConfirmed,
		Evidence:     "Vulnerability proof",
		Endpoint:     "/api/search",
		Verification: report.VerificationRecord{Status: report.VerificationVerified},
	}

	mappingRes, _ := MapFindings(cat, rs, []report.Finding{finding})

	ctx := &EvaluationContext{
		AssessmentID:     "ASM-RISK3-001",
		AssessmentStatus: "CANCELLED",
		PositiveEvidence: []PositiveEvidence{
			{
				ID:          "PE-AUTH",
				ControlID:   "IA-2",
				Observation: "Auth check attempted",
				Method:      "ACTIVE_PROBE",
			},
		},
	}

	res, err := engine.Evaluate(cat, mappingRes, []report.Finding{finding}, ctx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	for _, ev := range res.Evaluations {
		// Zero controls can be compliant
		if ev.State == StateCompliant {
			t.Errorf("control %s was marked compliant in cancelled assessment!", ev.ControlID)
		}
		// Independently verified violation is accurately recorded
		if ev.ControlID == "SI-10" {
			if ev.State != StateNonCompliant {
				t.Errorf("expected verified violation to be non_compliant, got %q", ev.State)
			}
			if !strings.Contains(ev.Rationale, "CANCELLED") {
				t.Errorf("expected rationale to state assessment was cancelled: %q", ev.Rationale)
			}
		}
	}
}

// Risk 4: Partial compliance
func TestSemanticRisk4_PartialComplianceOnlyForMeaningfulSubRequirements(t *testing.T) {
	cat := evalTestCatalog()
	rs := evalTestRuleSet()
	engine := NewEvaluationEngine(EvaluationPolicy{AllowPartialCompliance: true})

	// Different severities for the same requirement does NOT produce partially_compliant
	f1 := report.Finding{
		ID:       "F-HIGH",
		RuleID:   "WEB_SQL_INJECTION",
		Severity: "HIGH",
		Status:   report.FindingStatusConfirmed,
		Evidence: "ev1",
	}
	f2 := report.Finding{
		ID:       "F-LOW",
		RuleID:   "WEB_SQL_INJECTION",
		Severity: "LOW",
		Status:   report.FindingStatusConfirmed,
		Evidence: "ev2",
	}

	mappingRes, _ := MapFindings(cat, rs, []report.Finding{f1, f2})
	ctx := &EvaluationContext{
		AssessmentID:     "ASM-RISK4-001",
		AssessmentStatus: "COMPLETED",
	}

	res, err := engine.Evaluate(cat, mappingRes, []report.Finding{f1, f2}, ctx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var si10 *ControlEvaluationRecord
	for i := range res.Evaluations {
		if res.Evaluations[i].ControlID == "SI-10" {
			si10 = &res.Evaluations[i]
			break
		}
	}

	// Must be non_compliant, NOT partially_compliant!
	if si10.State != StateNonCompliant {
		t.Errorf("expected non_compliant for multiple findings of different severities, got %q", si10.State)
	}
}

// Risk 5: Evidence contradictions
func TestSemanticRisk5_EvidenceContradictions(t *testing.T) {
	cat := evalTestCatalog()
	rs := evalTestRuleSet()
	engine := NewEvaluationEngine()

	// Finding: SQLi confirmed on /api/search
	finding := report.Finding{
		ID:           "F-SQLI",
		RuleID:       "WEB_SQL_INJECTION",
		Status:       report.FindingStatusConfirmed,
		Evidence:     "differential response confirmed",
		Endpoint:     "/api/search",
		Verification: report.VerificationRecord{Status: report.VerificationVerified},
	}

	mappingRes, _ := MapFindings(cat, rs, []report.Finding{finding})

	// Positive evidence: SQLi defended on /api/search
	ctx := &EvaluationContext{
		AssessmentID:     "ASM-RISK5-001",
		AssessmentStatus: "COMPLETED",
		PositiveEvidence: []PositiveEvidence{
			{
				ID:          "PE-CONTRADICTION",
				ControlID:   "SI-10",
				Requirement: "WEB_SQL_INJECTION",
				Location:    "/api/search",
				Observation: "SQL injection strictly defended by WAF and input sanitization",
				Method:      "ACTIVE_PROBE",
			},
		},
	}

	res, err := engine.Evaluate(cat, mappingRes, []report.Finding{finding}, ctx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var si10 *ControlEvaluationRecord
	for i := range res.Evaluations {
		if res.Evaluations[i].ControlID == "SI-10" {
			si10 = &res.Evaluations[i]
			break
		}
	}

	if si10.State != StateInsufficientEvidence {
		t.Errorf("expected StateInsufficientEvidence for direct contradiction, got %q", si10.State)
	}
}

// Risk 6: Applicability
func TestSemanticRisk6_ApplicabilityExplicitSupportedOnly(t *testing.T) {
	cat := evalTestCatalog()
	engine := NewEvaluationEngine()

	// A: Valid applicability exemption -> not_applicable
	ctxValid := &EvaluationContext{
		AssessmentID:     "ASM-RISK6-001",
		AssessmentStatus: "COMPLETED",
		Applicability: map[string]ApplicabilityDetermination{
			"SC-7": {
				ControlID:  "SC-7",
				Applicable: false,
				Rationale:  "Target system is an isolated air-gapped component",
				Basis:      "AIR_GAP_POLICY_SEC_3",
			},
		},
	}

	resValid, err := engine.Evaluate(cat, nil, nil, ctxValid)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	for _, ev := range resValid.Evaluations {
		if ev.ControlID == "SC-7" && ev.State != StateNotApplicable {
			t.Errorf("expected SC-7 state=not_applicable, got %q", ev.State)
		}
		if ev.ControlID != "SC-7" && ev.State == StateNotApplicable {
			t.Errorf("control %s was unexpectedly marked not_applicable!", ev.ControlID)
		}
	}

	// B: Inapplicable claim with empty rationale or basis is rejected
	ctxInvalid := &EvaluationContext{
		AssessmentID:     "ASM-RISK6-002",
		AssessmentStatus: "COMPLETED",
		Applicability: map[string]ApplicabilityDetermination{
			"SC-7": {
				ControlID:  "SC-7",
				Applicable: false,
				Rationale:  "", // EMPTY
				Basis:      "", // EMPTY
			},
		},
	}

	resInvalid, err := engine.Evaluate(cat, nil, nil, ctxInvalid)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	for _, ev := range resInvalid.Evaluations {
		if ev.ControlID == "SC-7" && ev.State == StateNotApplicable {
			t.Errorf("unsupported inapplicability claim with empty rationale was falsely accepted!")
		}
	}
}

// Risk 7: State validation
func TestSemanticRisk7_StateValidation_InconsistentCombinations(t *testing.T) {
	cat := evalTestCatalog()

	// Sub-test A: StateCompliant with 0 supporting evidence -> REJECTED
	resNoEv := &EvaluationResult{
		AssessmentID:    "ASM-TEST",
		CatalogIdentity: cat.Identity(),
		Evaluations: []ControlEvaluationRecord{
			{
				ControlID:          "SI-10",
				State:              StateCompliant,
				Rationale:          "Falsely claiming compliant without evidence",
				SupportingEvidence: []string{}, // EMPTY
			},
			{ControlID: "AC-3", State: StateNotAssessed, Rationale: "none"},
			{ControlID: "IA-2", State: StateNotAssessed, Rationale: "none"},
			{ControlID: "SC-7", State: StateNotAssessed, Rationale: "none"},
		},
		Summary: EvaluationSummary{TotalControls: 4, CompliantCount: 1, NotAssessedCount: 3},
	}
	err := ValidateEvaluationResult(resNoEv, cat)
	if err == nil || !strings.Contains(err.Error(), "cannot be compliant without supporting evidence") {
		t.Errorf("expected error for compliant without supporting evidence, got: %v", err)
	}

	// Sub-test B: StateCompliant with contradicting evidence -> REJECTED
	resContra := &EvaluationResult{
		AssessmentID:    "ASM-TEST",
		CatalogIdentity: cat.Identity(),
		Evaluations: []ControlEvaluationRecord{
			{
				ControlID:             "SI-10",
				State:                 StateCompliant,
				Rationale:             "Compliant",
				SupportingEvidence:    []string{"PE-1"},
				ContradictingEvidence: []string{"VULN-1"}, // CONTRADICTING!
			},
			{ControlID: "AC-3", State: StateNotAssessed, Rationale: "none"},
			{ControlID: "IA-2", State: StateNotAssessed, Rationale: "none"},
			{ControlID: "SC-7", State: StateNotAssessed, Rationale: "none"},
		},
		Summary: EvaluationSummary{TotalControls: 4, CompliantCount: 1, NotAssessedCount: 3},
	}
	err = ValidateEvaluationResult(resContra, cat)
	if err == nil || !strings.Contains(err.Error(), "cannot be compliant with contradicting evidence") {
		t.Errorf("expected error for compliant with contradicting evidence, got: %v", err)
	}

	// Sub-test C: StateNonCompliant with 0 findings and 0 contradicting evidence -> REJECTED
	resNoVuln := &EvaluationResult{
		AssessmentID:    "ASM-TEST",
		CatalogIdentity: cat.Identity(),
		Evaluations: []ControlEvaluationRecord{
			{
				ControlID:             "SI-10",
				State:                 StateNonCompliant,
				Rationale:             "Non compliant without evidence",
				ContradictingEvidence: []string{},
				FindingIDs:            []string{},
			},
			{ControlID: "AC-3", State: StateNotAssessed, Rationale: "none"},
			{ControlID: "IA-2", State: StateNotAssessed, Rationale: "none"},
			{ControlID: "SC-7", State: StateNotAssessed, Rationale: "none"},
		},
		Summary: EvaluationSummary{TotalControls: 4, NonCompliantCount: 1, NotAssessedCount: 3},
	}
	err = ValidateEvaluationResult(resNoVuln, cat)
	if err == nil || !strings.Contains(err.Error(), "cannot be non_compliant without contradicting evidence") {
		t.Errorf("expected error for non_compliant without evidence, got: %v", err)
	}

	// Sub-test D: StatePartiallyCompliant without both supporting and contradicting -> REJECTED
	resPartNoSupp := &EvaluationResult{
		AssessmentID:    "ASM-TEST",
		CatalogIdentity: cat.Identity(),
		Evaluations: []ControlEvaluationRecord{
			{
				ControlID:             "SI-10",
				State:                 StatePartiallyCompliant,
				Rationale:             "Partially compliant without supporting evidence",
				SupportingEvidence:    []string{}, // MISSING!
				ContradictingEvidence: []string{"VULN-1"},
				FindingIDs:            []string{"F-1"},
			},
			{ControlID: "AC-3", State: StateNotAssessed, Rationale: "none"},
			{ControlID: "IA-2", State: StateNotAssessed, Rationale: "none"},
			{ControlID: "SC-7", State: StateNotAssessed, Rationale: "none"},
		},
		Summary: EvaluationSummary{TotalControls: 4, PartiallyCompliantCount: 1, NotAssessedCount: 3},
	}
	err = ValidateEvaluationResult(resPartNoSupp, cat)
	if err == nil || !strings.Contains(err.Error(), "cannot be partially_compliant without both") {
		t.Errorf("expected error for partially_compliant missing supporting evidence, got: %v", err)
	}
}

// Risk 8: Determinism
func TestSemanticRisk8_Determinism(t *testing.T) {
	cat := evalTestCatalog()
	rs := evalTestRuleSet()

	f1 := report.Finding{ID: "F-1", RuleID: "WEB_SQL_INJECTION", Status: report.FindingStatusConfirmed, Evidence: "ev1"}
	f2 := report.Finding{ID: "F-2", RuleID: "APISPEC_NO_AUTH", Status: report.FindingStatusConfirmed, Evidence: "ev2"}
	f3 := report.Finding{ID: "F-3", RuleID: "IDOR_BOLA", Status: report.FindingStatusConfirmed, Evidence: "ev3"}

	// Permutation A
	orderA := []report.Finding{f1, f2, f3}
	// Permutation B
	orderB := []report.Finding{f3, f1, f2}
	// Permutation C
	orderC := []report.Finding{f2, f3, f1}

	mapA, _ := MapFindings(cat, rs, orderA)
	mapB, _ := MapFindings(cat, rs, orderB)
	mapC, _ := MapFindings(cat, rs, orderC)

	// Note: Engine with different execution clock timestamps
	clockA := func() time.Time { return time.Date(2026, 10, 21, 10, 0, 0, 0, time.UTC) }
	clockB := func() time.Time { return time.Date(2026, 10, 21, 11, 0, 0, 0, time.UTC) } // different timestamp!

	engineA := NewEvaluationEngine().WithClock(clockA)
	engineB := NewEvaluationEngine().WithClock(clockB)

	ctx := &EvaluationContext{
		AssessmentID:     "ASM-DET-001",
		AssessmentStatus: "COMPLETED",
	}

	resA, errA := engineA.Evaluate(cat, mapA, orderA, ctx)
	resB, errB := engineB.Evaluate(cat, mapB, orderB, ctx)
	resC, errC := engineA.Evaluate(cat, mapC, orderC, ctx)

	if errA != nil || errB != nil || errC != nil {
		t.Fatalf("unexpected evaluation errors: %v, %v, %v", errA, errB, errC)
	}

	// Verify states are 100% identical
	for i := range resA.Evaluations {
		if resA.Evaluations[i].State != resB.Evaluations[i].State || resA.Evaluations[i].State != resC.Evaluations[i].State {
			t.Errorf("evaluation state differs under input reordering on %s", resA.Evaluations[i].ControlID)
		}
	}

	// Verify semantic digest is byte-for-byte identical despite different execution timestamps!
	if resA.Digest() != resB.Digest() {
		t.Errorf("Digest() was affected by volatile timestamps or finding order! \nDigestA: %s\nDigestB: %s",
			resA.Digest(), resB.Digest())
	}
	if resA.Digest() != resC.Digest() {
		t.Errorf("Digest() differed under permutation C!")
	}
}
