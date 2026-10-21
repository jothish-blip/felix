package compliance

import (
	"testing"
	"time"

	"felix/pkg/clierror"
)

func samplePassingEvaluationResult() *EvaluationResult {
	now := time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC)
	return &EvaluationResult{
		AssessmentID:    "ASM-PASS-01",
		CatalogIdentity: "nist-sp800-53-sample:5.1.0",
		CatalogDigest:   "sha256:1111111111111111111111111111111111111111111111111111111111111111",
		EvaluatedAt:     now,
		EngineVersion:   "1.0.0",
		Evaluations: []ControlEvaluationRecord{
			{
				EvaluationID:       "eval:ASM-PASS-01:AC-1",
				ControlID:          "AC-1",
				ControlTitle:       "Access Control Policy",
				State:              StateCompliant,
				Rationale:          "Access control policy verified and enforced",
				SupportingEvidence: []string{"Positive verification PE-AC1: Signed policy active"},
				EvaluatedAt:        now,
			},
			{
				EvaluationID:       "eval:ASM-PASS-01:AC-3",
				ControlID:          "AC-3",
				ControlTitle:       "Access Enforcement",
				State:              StateCompliant,
				Rationale:          "Authorization enforced on all endpoints",
				SupportingEvidence: []string{"Positive verification PE-AC3: RBAC enforced"},
				EvaluatedAt:        now,
			},
		},
		Summary: EvaluationSummary{
			TotalControls:      2,
			CompliantCount:     2,
			ApplicableControls: 2,
			AssessedControls:   2,
		},
		LimitationsNotice: EvaluationLimitationsNotice(),
	}
}

func sampleViolatingEvaluationResult() *EvaluationResult {
	now := time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC)
	return &EvaluationResult{
		AssessmentID:    "ASM-VIOLATION-01",
		CatalogIdentity: "nist-sp800-53-sample:5.1.0",
		CatalogDigest:   "sha256:2222222222222222222222222222222222222222222222222222222222222222",
		EvaluatedAt:     now,
		EngineVersion:   "1.0.0",
		Evaluations: []ControlEvaluationRecord{
			{
				EvaluationID:       "eval:ASM-VIOLATION-01:AC-1",
				ControlID:          "AC-1",
				ControlTitle:       "Access Control Policy",
				State:              StateCompliant,
				Rationale:          "Policy active",
				SupportingEvidence: []string{"PE-AC1: verified"},
				EvaluatedAt:        now,
			},
			{
				EvaluationID:          "eval:ASM-VIOLATION-01:AC-3",
				ControlID:             "AC-3",
				ControlTitle:          "Access Enforcement",
				State:                 StateNonCompliant,
				Rationale:             "BOLA vulnerability detected on /users/:id",
				FindingIDs:            []string{"F-BOLA-001"},
				ContradictingEvidence: []string{"Finding F-BOLA-001: unauthorized object access"},
				EvaluatedAt:           now,
			},
		},
		Summary: EvaluationSummary{
			TotalControls:      2,
			CompliantCount:     1,
			NonCompliantCount:  1,
			ApplicableControls: 2,
			AssessedControls:   2,
		},
		LimitationsNotice: EvaluationLimitationsNotice(),
	}
}

func TestGate_1_PassingEvaluation_Exits0(t *testing.T) {
	eval := samplePassingEvaluationResult()
	policy := &ComplianceGatePolicy{
		SchemaVersion:        "1.0",
		ID:                   "gate-strict",
		Version:              "1.0.0",
		TargetCatalog:        "nist-sp800-53-sample",
		EnforcedControls:     []string{"AC-1", "AC-3"},
		MinCompliancePercent: ptrFloat(100.0),
	}

	service := NewComplianceGateService()
	res := service.EvaluateEvaluationResult(eval, policy, GateOptions{
		AssessmentStatus: "COMPLETED",
	})

	if res.ExitCode != clierror.ExitSuccess {
		t.Fatalf("expected ExitSuccess (0), got %d (decision: %s, errors: %v, violations: %v)",
			res.ExitCode, res.Decision, res.OperationalErrors, res.Violations)
	}
	if res.Decision != GateStatusPassed {
		t.Errorf("expected GateStatusPassed, got %s", res.Decision)
	}
	if len(res.Violations) > 0 {
		t.Errorf("expected 0 violations, got %v", res.Violations)
	}
}

func TestGate_2_NonCompliantControl_Exits1(t *testing.T) {
	eval := sampleViolatingEvaluationResult()
	policy := &ComplianceGatePolicy{
		SchemaVersion: "1.0",
		ID:            "gate-default",
		Version:       "1.0.0",
		TargetCatalog: "nist-sp800-53-sample",
	}

	service := NewComplianceGateService()
	res := service.EvaluateEvaluationResult(eval, policy, GateOptions{
		AssessmentStatus: "COMPLETED",
	})

	if res.ExitCode != clierror.ExitSecurityFail {
		t.Fatalf("expected ExitSecurityFail (1) for non-compliant control, got %d (decision: %s)",
			res.ExitCode, res.Decision)
	}
	if res.Decision != GateStatusPolicyFailed {
		t.Errorf("expected GateStatusPolicyFailed, got %s", res.Decision)
	}
	if len(res.Violations) == 0 {
		t.Errorf("expected violations, got none")
	}
}

func TestGate_3_EnforcedControl_MissingOrFailed(t *testing.T) {
	eval := samplePassingEvaluationResult()
	// Require SC-8 which does not exist in passing eval
	policy := &ComplianceGatePolicy{
		SchemaVersion:    "1.0",
		ID:               "gate-enforce-missing",
		Version:          "1.0.0",
		EnforcedControls: []string{"AC-1", "SC-8"},
	}

	service := NewComplianceGateService()
	res := service.EvaluateEvaluationResult(eval, policy, GateOptions{
		AssessmentStatus: "COMPLETED",
	})

	if res.ExitCode != clierror.ExitSecurityFail {
		t.Fatalf("expected ExitSecurityFail (1) for missing enforced control, got %d", res.ExitCode)
	}
	if res.Decision != GateStatusPolicyFailed {
		t.Errorf("expected GateStatusPolicyFailed, got %s", res.Decision)
	}
}

func TestGate_4_IncompleteAssessment_Exits2(t *testing.T) {
	eval := samplePassingEvaluationResult()
	policy := &ComplianceGatePolicy{
		SchemaVersion: "1.0",
		ID:            "gate-status-check",
		Version:       "1.0.0",
	}

	service := NewComplianceGateService()

	for _, badStatus := range []string{"FAILED", "CANCELLED", "INTERRUPTED", "DRAFT"} {
		res := service.EvaluateEvaluationResult(eval, policy, GateOptions{
			AssessmentStatus: badStatus,
		})
		if res.ExitCode != clierror.ExitOperational {
			t.Errorf("status %q: expected ExitOperational (2), got %d", badStatus, res.ExitCode)
		}
		if res.Decision != GateStatusOperationalFailed {
			t.Errorf("status %q: expected GateStatusOperationalFailed, got %s", badStatus, res.Decision)
		}
	}
}

func TestGate_5_ControlExecutionError_Exits2(t *testing.T) {
	eval := samplePassingEvaluationResult()
	eval.Evaluations[1].State = StateError
	eval.Evaluations[1].Rationale = "Scanner crashed evaluating AC-3"
	eval.Summary.ErrorCount = 1
	eval.Summary.CompliantCount = 1

	policy := &ComplianceGatePolicy{
		SchemaVersion: "1.0",
		ID:            "gate-error-check",
		Version:       "1.0.0",
	}

	service := NewComplianceGateService()
	res := service.EvaluateEvaluationResult(eval, policy, GateOptions{
		AssessmentStatus: "COMPLETED",
	})

	if res.ExitCode != clierror.ExitOperational {
		t.Fatalf("expected ExitOperational (2) for control error, got %d", res.ExitCode)
	}
	if res.Decision != GateStatusOperationalFailed {
		t.Errorf("expected GateStatusOperationalFailed, got %s", res.Decision)
	}
}

func TestGate_6_PartiallyCompliant_PolicyMatrix(t *testing.T) {
	eval := samplePassingEvaluationResult()
	eval.Evaluations[1].State = StatePartiallyCompliant
	eval.Evaluations[1].Rationale = "Sub-requirement 1 satisfied, sub-requirement 2 untested"
	eval.Summary.CompliantCount = 1
	eval.Summary.PartiallyCompliantCount = 1

	service := NewComplianceGateService()

	// Case A: Default (PartiallyCompliantPolicy == "fail") -> Exit 1
	policyFail := &ComplianceGatePolicy{
		SchemaVersion:            "1.0",
		ID:                       "gate-pc-fail",
		Version:                  "1.0.0",
		PartiallyCompliantPolicy: "fail",
	}
	resFail := service.EvaluateEvaluationResult(eval, policyFail, GateOptions{AssessmentStatus: "COMPLETED"})
	if resFail.ExitCode != clierror.ExitSecurityFail {
		t.Errorf("expected ExitSecurityFail (1) for partially compliant with fail policy, got %d", resFail.ExitCode)
	}

	// Case B: Allowed (PartiallyCompliantPolicy == "allow") with relaxed min compliance -> Exit 0
	policyAllow := &ComplianceGatePolicy{
		SchemaVersion:            "1.0",
		ID:                       "gate-pc-allow",
		Version:                  "1.0.0",
		PartiallyCompliantPolicy: "allow",
		MinCompliancePercent:     ptrFloat(50.0), // 1/2 = 50%
	}
	resAllow := service.EvaluateEvaluationResult(eval, policyAllow, GateOptions{AssessmentStatus: "COMPLETED"})
	if resAllow.ExitCode != clierror.ExitSuccess {
		t.Errorf("expected ExitSuccess (0) for partially compliant with allow policy, got %d (violations: %v)",
			resAllow.ExitCode, resAllow.Violations)
	}
}

func TestGate_7_UnassessedAndInsufficientEvidence_Policies(t *testing.T) {
	now := time.Now().UTC()
	eval := &EvaluationResult{
		AssessmentID:    "ASM-UNASS-01",
		CatalogIdentity: "nist-sp800-53-sample:5.1.0",
		EvaluatedAt:     now,
		EngineVersion:   "1.0.0",
		Evaluations: []ControlEvaluationRecord{
			{
				EvaluationID: "eval:ASM:AC-1",
				ControlID:    "AC-1",
				State:        StateNotAssessed,
				Rationale:    "Not scanned",
			},
		},
		Summary: EvaluationSummary{
			TotalControls:    1,
			NotAssessedCount: 1,
		},
	}

	service := NewComplianceGateService()

	// Case A: Unassessed policy == "indeterminate" -> Exit 2
	policyIndet := &ComplianceGatePolicy{
		SchemaVersion:    "1.0",
		ID:               "gate-unass-indet",
		Version:          "1.0.0",
		UnassessedPolicy: "indeterminate",
	}
	resIndet := service.EvaluateEvaluationResult(eval, policyIndet, GateOptions{AssessmentStatus: "COMPLETED"})
	if resIndet.ExitCode != clierror.ExitOperational || resIndet.Decision != GateStatusIndeterminate {
		t.Errorf("expected ExitOperational (2) and GateStatusIndeterminate, got code=%d, decision=%s",
			resIndet.ExitCode, resIndet.Decision)
	}

	// Case B: Unassessed policy == "fail_closed" -> Exit 1
	policyFail := &ComplianceGatePolicy{
		SchemaVersion:    "1.0",
		ID:               "gate-unass-fail",
		Version:          "1.0.0",
		UnassessedPolicy: "fail_closed",
	}
	resFail := service.EvaluateEvaluationResult(eval, policyFail, GateOptions{AssessmentStatus: "COMPLETED"})
	if resFail.ExitCode != clierror.ExitSecurityFail || resFail.Decision != GateStatusPolicyFailed {
		t.Errorf("expected ExitSecurityFail (1) and GateStatusPolicyFailed, got code=%d, decision=%s",
			resFail.ExitCode, resFail.Decision)
	}
}

func TestGate_8_CatalogMismatch_Exits2(t *testing.T) {
	eval := samplePassingEvaluationResult()
	policy := &ComplianceGatePolicy{
		SchemaVersion: "1.0",
		ID:            "gate-mismatch",
		Version:       "1.0.0",
		TargetCatalog: "pci-dss-v4", // Mismatch with nist-sp800-53-sample
	}

	service := NewComplianceGateService()
	res := service.EvaluateEvaluationResult(eval, policy, GateOptions{AssessmentStatus: "COMPLETED"})

	if res.ExitCode != clierror.ExitOperational {
		t.Fatalf("expected ExitOperational (2) for catalog mismatch, got %d", res.ExitCode)
	}
	if res.Decision != GateStatusOperationalFailed {
		t.Errorf("expected GateStatusOperationalFailed, got %s", res.Decision)
	}
}

func TestGate_9_CompliancePercentageThreshold(t *testing.T) {
	now := time.Now().UTC()
	// 1 compliant out of 2 applicable controls = 50.0%
	eval := &EvaluationResult{
		AssessmentID:    "ASM-PCT-01",
		CatalogIdentity: "nist-sample:1.0",
		EvaluatedAt:     now,
		EngineVersion:   "1.0.0",
		Evaluations: []ControlEvaluationRecord{
			{EvaluationID: "1", ControlID: "C1", State: StateCompliant},
			{EvaluationID: "2", ControlID: "C2", State: StateNotAssessed},
		},
		Summary: EvaluationSummary{
			TotalControls:      2,
			CompliantCount:     1,
			NotAssessedCount:   1,
			ApplicableControls: 2,
		},
	}

	service := NewComplianceGateService()

	// Policy requires 80% compliance, unassessed allowed
	policy := &ComplianceGatePolicy{
		SchemaVersion:        "1.0",
		ID:                   "gate-min-80",
		Version:              "1.0.0",
		UnassessedPolicy:     "allow",
		MinCompliancePercent: ptrFloat(80.0),
	}

	res := service.EvaluateEvaluationResult(eval, policy, GateOptions{AssessmentStatus: "COMPLETED"})
	if res.ExitCode != clierror.ExitSecurityFail {
		t.Fatalf("expected ExitSecurityFail (1) for 50%% < 80%% threshold, got %d", res.ExitCode)
	}
}

func TestGate_10_PolicyValidation_Rules(t *testing.T) {
	// 1. Missing version
	p1 := &ComplianceGatePolicy{ID: "test"}
	if err := ValidateGatePolicy(p1); err == nil {
		t.Error("expected error for missing schema_version")
	}

	// 2. Unsupported version
	p2 := &ComplianceGatePolicy{SchemaVersion: "99.0", ID: "test", Version: "1.0"}
	if err := ValidateGatePolicy(p2); err == nil {
		t.Error("expected error for unsupported schema_version")
	}

	// 3. Negative limits
	neg := -1
	p3 := &ComplianceGatePolicy{SchemaVersion: "1.0", ID: "test", Version: "1.0", MaxNonCompliant: &neg}
	if err := ValidateGatePolicy(p3); err == nil {
		t.Error("expected error for negative max_non_compliant")
	}

	// 4. Invalid percentage (>100)
	pct := 105.0
	p4 := &ComplianceGatePolicy{SchemaVersion: "1.0", ID: "test", Version: "1.0", MinCompliancePercent: &pct}
	if err := ValidateGatePolicy(p4); err == nil {
		t.Error("expected error for min_compliance_percent > 100")
	}

	// 5. Invalid enum
	p5 := &ComplianceGatePolicy{SchemaVersion: "1.0", ID: "test", Version: "1.0", PartiallyCompliantPolicy: "invalid-choice"}
	if err := ValidateGatePolicy(p5); err == nil {
		t.Error("expected error for invalid partially_compliant_policy")
	}

	// 6. Valid policy passes
	pValid := &ComplianceGatePolicy{
		SchemaVersion: "1.0",
		ID:            "valid-gate",
		Version:       "1.0.0",
	}
	if err := ValidateGatePolicy(pValid); err != nil {
		t.Errorf("expected valid policy to pass, got: %v", err)
	}
}

func TestGate_11_JSONAndYAMLLoader(t *testing.T) {
	jsonPolicy := `{
  "schema_version": "1.0",
  "id": "policy-json",
  "name": "JSON Gate Policy",
  "version": "1.0.0",
  "target_catalog": "nist-sp800-53",
  "enforced_controls": ["AC-1", "AC-3"],
  "min_compliance_percent": 95.5,
  "max_non_compliant": 0
}`

	pol1, err := LoadGatePolicyFromBytes([]byte(jsonPolicy))
	if err != nil {
		t.Fatalf("LoadGatePolicyFromBytes JSON failed: %v", err)
	}
	if pol1.ID != "policy-json" || len(pol1.EnforcedControls) != 2 || *pol1.MinCompliancePercent != 95.5 {
		t.Errorf("unexpected parsed JSON policy: %+v", pol1)
	}

	yamlPolicy := `
schema_version: "1.0"
id: policy-yaml
name: "YAML Gate Policy"
version: "1.0.0"
target_catalog: "nist-sp800-53"
enforced_controls:
  - AC-1
  - AC-3
min_compliance_percent: 90.0
max_non_compliant: 1
require_integrity: true
`
	pol2, err := LoadGatePolicyFromBytes([]byte(yamlPolicy))
	if err != nil {
		t.Fatalf("LoadGatePolicyFromBytes YAML failed: %v", err)
	}
	if pol2.ID != "policy-yaml" || len(pol2.EnforcedControls) != 2 || *pol2.MinCompliancePercent != 90.0 || !*pol2.RequireIntegrity {
		t.Errorf("unexpected parsed YAML policy: %+v", pol2)
	}

	// Rejection of unknown field
	badJSON := `{"schema_version": "1.0", "id": "p", "version": "1.0", "unknown_field_xyz": 123}`
	_, errBad := LoadGatePolicyFromBytes([]byte(badJSON))
	if errBad == nil {
		t.Error("expected error for unknown JSON field in gate policy")
	}
}

func TestGate_12_DossierAdapter(t *testing.T) {
	dossier := &ComplianceDossier{
		Identity: DossierIdentity{
			DossierID:      "dossier-01",
			AssessmentID:   "ASM-DOSSIER-01",
			CatalogID:      "nist-sp800-53-sample",
			CatalogVersion: "5.1.0",
			GeneratedAt:    time.Now().UTC(),
		},
		Controls: []DossierControlResult{
			{
				ControlID:       "AC-1",
				ControlTitle:    "Access Control Policy",
				EvaluationState: StateCompliant,
				Rationale:       "Verified",
			},
			{
				ControlID:       "AC-3",
				ControlTitle:    "Access Enforcement",
				EvaluationState: StateCompliant,
				Rationale:       "Verified",
			},
		},
		Summary: DossierAssessmentSummary{
			TotalControls:      2,
			CompliantCount:     2,
			ApplicableControls: 2,
			AssessedControls:   2,
		},
	}

	policy := &ComplianceGatePolicy{
		SchemaVersion:    "1.0",
		ID:               "dossier-gate",
		Version:          "1.0.0",
		EnforcedControls: []string{"AC-1", "AC-3"},
	}

	service := NewComplianceGateService()
	res := service.EvaluateDossier(dossier, policy, GateOptions{
		AssessmentStatus: "COMPLETED",
	})

	if res.ExitCode != clierror.ExitSuccess {
		t.Fatalf("expected ExitSuccess (0) for dossier gate, got %d", res.ExitCode)
	}
	if res.Decision != GateStatusPassed {
		t.Errorf("expected GateStatusPassed, got %s", res.Decision)
	}
}

func ptrFloat(f float64) *float64 {
	return &f
}
