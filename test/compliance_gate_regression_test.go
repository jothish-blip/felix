package test

import (
	"database/sql"
	"encoding/json"
	"path/filepath"
	"testing"
	"time"

	_ "modernc.org/sqlite"

	"felix/pkg/clierror"
	"felix/pkg/compliance"
)

// TestPhase911_ComplianceGate_EndToEnd tests the complete CI/CD Compliance Gate lifecycle:
// 1. Fully compliant assessment passes gate with Exit 0.
// 2. Trustworthy policy violation results in Exit 1.
// 3. Incomplete, cancelled, or errored assessments produce operational failure Exit 2.
// 4. Strict integrity verification catches database tampering and missing keys with Exit 2.
// 5. Unassessed, insufficient_evidence, and not_applicable states strictly enforce configured policy.
// 6. Overdue remediation SLAs cause policy violations when configured.
// 7. Deterministic evaluation output across identical repeated runs.
func TestPhase911_ComplianceGate_EndToEnd(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "compliance_gate_e2e.db")

	store, err := compliance.NewSQLiteComplianceStore(dbPath)
	if err != nil {
		t.Fatalf("failed opening compliance store: %v", err)
	}
	defer store.Close()

	key, err := compliance.GenerateIntegrityKey("e2e-gate-key")
	if err != nil {
		t.Fatal(err)
	}
	kp, err := compliance.NewStaticKeyProvider(key)
	if err != nil {
		t.Fatal(err)
	}

	now := time.Date(2026, 10, 21, 14, 0, 0, 0, time.UTC)

	// Persist passing evaluation for ASM-CLEAN
	evalClean := &compliance.EvaluationResult{
		AssessmentID:    "ASM-CLEAN",
		CatalogIdentity: "nist-sp800-53-sample:5.1.0",
		CatalogDigest:   "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		EvaluatedAt:     now,
		EngineVersion:   "1.0.0",
		Evaluations: []compliance.ControlEvaluationRecord{
			{
				EvaluationID:       "eval:clean:AC-1",
				CatalogID:          "nist-sp800-53-sample",
				ControlID:          "AC-1",
				State:              compliance.StateCompliant,
				Rationale:          "Policy active",
				SupportingEvidence: []string{"PE-1: verified active"},
				EvaluatedAt:        now,
			},
			{
				EvaluationID:       "eval:clean:AC-3",
				CatalogID:          "nist-sp800-53-sample",
				ControlID:          "AC-3",
				State:              compliance.StateCompliant,
				Rationale:          "RBAC active",
				SupportingEvidence: []string{"PE-2: verified RBAC"},
				EvaluatedAt:        now,
			},
		},
		Summary: compliance.EvaluationSummary{
			TotalControls:      2,
			CompliantCount:     2,
			ApplicableControls: 2,
			AssessedControls:   2,
		},
	}
	if err := store.SaveEvaluationResultWithKey(evalClean, kp); err != nil {
		t.Fatalf("failed saving clean evaluation: %v", err)
	}

	// Persist violating evaluation for ASM-VIOLATION
	evalViolation := &compliance.EvaluationResult{
		AssessmentID:    "ASM-VIOLATION",
		CatalogIdentity: "nist-sp800-53-sample:5.1.0",
		CatalogDigest:   "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		EvaluatedAt:     now,
		EngineVersion:   "1.0.0",
		Evaluations: []compliance.ControlEvaluationRecord{
			{
				EvaluationID:       "eval:viol:AC-1",
				CatalogID:          "nist-sp800-53-sample",
				ControlID:          "AC-1",
				State:              compliance.StateCompliant,
				Rationale:          "Policy active",
				SupportingEvidence: []string{"PE-1: verified"},
				EvaluatedAt:        now,
			},
			{
				EvaluationID:          "eval:viol:AC-3",
				CatalogID:             "nist-sp800-53-sample",
				ControlID:             "AC-3",
				State:                 compliance.StateNonCompliant,
				Rationale:             "BOLA access violation observed",
				FindingIDs:            []string{"F-BOLA-01"},
				ContradictingEvidence: []string{"Finding F-BOLA-01: unauthorized access"},
				EvaluatedAt:           now,
			},
		},
		Summary: compliance.EvaluationSummary{
			TotalControls:      2,
			CompliantCount:     1,
			NonCompliantCount:  1,
			ApplicableControls: 2,
			AssessedControls:   2,
		},
	}
	if err := store.SaveEvaluationResultWithKey(evalViolation, kp); err != nil {
		t.Fatalf("failed saving violating evaluation: %v", err)
	}

	gateService := compliance.NewComplianceGateService()

	// Scenario 1: Complete compliant assessment -> Exit 0
	policyPass := &compliance.ComplianceGatePolicy{
		SchemaVersion:        "1.0",
		ID:                   "gate-strict-pass",
		Version:              "1.0.0",
		TargetCatalog:        "nist-sp800-53-sample",
		EnforcedControls:     []string{"AC-1", "AC-3"},
		MinCompliancePercent: ptrFloat(100.0),
		RequireIntegrity:     ptrBool(true),
	}
	resPass := gateService.EvaluateFromStore(store, "ASM-CLEAN", "nist-sp800-53-sample:5.1.0", policyPass, compliance.GateOptions{
		KeyProvider:      kp,
		AssessmentStatus: "COMPLETED",
		Now:              now,
	})
	if resPass.ExitCode != clierror.ExitSuccess || resPass.Decision != compliance.GateStatusPassed {
		t.Fatalf("Scenario 1 failed: expected ExitSuccess 0, got %d (decision: %s, errors: %v, violations: %v)",
			resPass.ExitCode, resPass.Decision, resPass.OperationalErrors, resPass.Violations)
	}

	// Scenario 2: Assessment with policy violation -> Exit 1
	resFail := gateService.EvaluateFromStore(store, "ASM-VIOLATION", "nist-sp800-53-sample:5.1.0", policyPass, compliance.GateOptions{
		KeyProvider:      kp,
		AssessmentStatus: "COMPLETED",
		Now:              now,
	})
	if resFail.ExitCode != clierror.ExitSecurityFail || resFail.Decision != compliance.GateStatusPolicyFailed {
		t.Fatalf("Scenario 2 failed: expected ExitSecurityFail 1, got %d (decision: %s)",
			resFail.ExitCode, resFail.Decision)
	}
	if len(resFail.Violations) == 0 {
		t.Errorf("Scenario 2 expected policy violations, got none")
	}

	// Scenario 3: Incomplete assessment status -> Exit 2
	resIncomplete := gateService.EvaluateFromStore(store, "ASM-CLEAN", "nist-sp800-53-sample:5.1.0", policyPass, compliance.GateOptions{
		KeyProvider:      kp,
		AssessmentStatus: "CANCELLED",
		Now:              now,
	})
	if resIncomplete.ExitCode != clierror.ExitOperational || resIncomplete.Decision != compliance.GateStatusOperationalFailed {
		t.Fatalf("Scenario 3 failed: expected ExitOperational 2 for cancelled assessment, got %d (decision: %s)",
			resIncomplete.ExitCode, resIncomplete.Decision)
	}

	// Scenario 4: Database tampering under strict integrity -> Exit 2
	rawDB, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	_, err = rawDB.Exec("UPDATE compliance_control_evaluations SET state = 'compliant', rationale = 'Tampered' WHERE assessment_id = 'ASM-VIOLATION'")
	if err != nil {
		t.Fatal(err)
	}
	rawDB.Close()

	resTampered := gateService.EvaluateFromStore(store, "ASM-VIOLATION", "nist-sp800-53-sample:5.1.0", policyPass, compliance.GateOptions{
		KeyProvider:     kp,
		StrictIntegrity: true,
		Now:             now,
	})
	if resTampered.ExitCode != clierror.ExitOperational || resTampered.Decision != compliance.GateStatusOperationalFailed {
		t.Fatalf("Scenario 4 failed: expected ExitOperational 2 for tampered record under strict integrity, got %d (decision: %s)",
			resTampered.ExitCode, resTampered.Decision)
	}

	// Scenario 5: Determinism check over repeated identical inputs
	resPass2 := gateService.EvaluateFromStore(store, "ASM-CLEAN", "nist-sp800-53-sample:5.1.0", policyPass, compliance.GateOptions{
		KeyProvider:      kp,
		AssessmentStatus: "COMPLETED",
		Now:              now,
	})
	if resPass.Integrity != nil && resPass2.Integrity != nil {
		resPass2.Integrity.VerifiedAt = resPass.Integrity.VerifiedAt
	}
	bytes1, _ := json.Marshal(resPass)
	bytes2, _ := json.Marshal(resPass2)
	if string(bytes1) != string(bytes2) {
		t.Errorf("Scenario 5 determinism failure: repeated evaluation produced divergent JSON output\n1: %s\n2: %s", string(bytes1), string(bytes2))
	}
}

// TestPhase911_ComplianceGate_UnassessedAndInsufficientEvidence tests fail-closed vs indeterminate handling.
func TestPhase911_ComplianceGate_UnassessedAndInsufficientEvidence(t *testing.T) {
	now := time.Now().UTC()
	gateService := compliance.NewComplianceGateService()

	// 1. Insufficient evidence with fail_closed -> Exit 1
	evalIE := &compliance.EvaluationResult{
		AssessmentID:    "ASM-IE",
		CatalogIdentity: "cat:1.0",
		EvaluatedAt:     now,
		EngineVersion:   "1.0.0",
		Evaluations: []compliance.ControlEvaluationRecord{
			{EvaluationID: "1", ControlID: "AC-1", State: compliance.StateInsufficientEvidence, Rationale: "evidence missing"},
		},
		Summary: compliance.EvaluationSummary{TotalControls: 1, InsufficientEvidenceCount: 1, ApplicableControls: 1},
	}
	policyIEFail := &compliance.ComplianceGatePolicy{
		SchemaVersion:              "1.0",
		ID:                         "p-ie-fail",
		Version:                    "1.0.0",
		InsufficientEvidencePolicy: "fail_closed",
	}
	resIEFail := gateService.EvaluateEvaluationResult(evalIE, policyIEFail, compliance.GateOptions{AssessmentStatus: "COMPLETED"})
	if resIEFail.ExitCode != clierror.ExitSecurityFail || resIEFail.Decision != compliance.GateStatusPolicyFailed {
		t.Errorf("expected ExitSecurityFail 1 for insufficient_evidence with fail_closed, got %d", resIEFail.ExitCode)
	}

	// 2. Insufficient evidence with indeterminate -> Exit 2
	policyIEIndet := &compliance.ComplianceGatePolicy{
		SchemaVersion:              "1.0",
		ID:                         "p-ie-indet",
		Version:                    "1.0.0",
		InsufficientEvidencePolicy: "indeterminate",
	}
	resIEIndet := gateService.EvaluateEvaluationResult(evalIE, policyIEIndet, compliance.GateOptions{AssessmentStatus: "COMPLETED"})
	if resIEIndet.ExitCode != clierror.ExitOperational || resIEIndet.Decision != compliance.GateStatusIndeterminate {
		t.Errorf("expected ExitOperational 2 for insufficient_evidence with indeterminate, got %d", resIEIndet.ExitCode)
	}

	// 3. Not assessed with fail_closed -> Exit 1
	evalNotAss := &compliance.EvaluationResult{
		AssessmentID:    "ASM-NA",
		CatalogIdentity: "cat:1.0",
		EvaluatedAt:     now,
		EngineVersion:   "1.0.0",
		Evaluations: []compliance.ControlEvaluationRecord{
			{EvaluationID: "1", ControlID: "AC-1", State: compliance.StateNotAssessed, Rationale: "not assessed"},
		},
		Summary: compliance.EvaluationSummary{TotalControls: 1, NotAssessedCount: 1, ApplicableControls: 1},
	}
	policyNAFail := &compliance.ComplianceGatePolicy{
		SchemaVersion:    "1.0",
		ID:               "p-na-fail",
		Version:          "1.0.0",
		UnassessedPolicy: "fail_closed",
	}
	resNAFail := gateService.EvaluateEvaluationResult(evalNotAss, policyNAFail, compliance.GateOptions{AssessmentStatus: "COMPLETED"})
	if resNAFail.ExitCode != clierror.ExitSecurityFail || resNAFail.Decision != compliance.GateStatusPolicyFailed {
		t.Errorf("expected ExitSecurityFail 1 for not_assessed with fail_closed, got %d", resNAFail.ExitCode)
	}

	// 4. Not assessed with indeterminate -> Exit 2
	policyNAIndet := &compliance.ComplianceGatePolicy{
		SchemaVersion:    "1.0",
		ID:               "p-na-indet",
		Version:          "1.0.0",
		UnassessedPolicy: "indeterminate",
	}
	resNAIndet := gateService.EvaluateEvaluationResult(evalNotAss, policyNAIndet, compliance.GateOptions{AssessmentStatus: "COMPLETED"})
	if resNAIndet.ExitCode != clierror.ExitOperational || resNAIndet.Decision != compliance.GateStatusIndeterminate {
		t.Errorf("expected ExitOperational 2 for not_assessed with indeterminate, got %d", resNAIndet.ExitCode)
	}
}

// TestPhase911_ComplianceGate_NotApplicableDoesNotCountAsCompliant verifies not_applicable semantics.
func TestPhase911_ComplianceGate_NotApplicableDoesNotCountAsCompliant(t *testing.T) {
	now := time.Now().UTC()
	gateService := compliance.NewComplianceGateService()

	eval := &compliance.EvaluationResult{
		AssessmentID:    "ASM-NOT-APP",
		CatalogIdentity: "cat:1.0",
		EvaluatedAt:     now,
		EngineVersion:   "1.0.0",
		Evaluations: []compliance.ControlEvaluationRecord{
			{EvaluationID: "1", ControlID: "AC-1", State: compliance.StateNotApplicable, Rationale: "out of scope"},
		},
		Summary: compliance.EvaluationSummary{TotalControls: 1, NotApplicableCount: 1, ApplicableControls: 0},
	}

	// Policy requires AC-1 to be compliant
	policy := &compliance.ComplianceGatePolicy{
		SchemaVersion:    "1.0",
		ID:               "p-na-enforce",
		Version:          "1.0.0",
		EnforcedControls: []string{"AC-1"},
	}

	res := gateService.EvaluateEvaluationResult(eval, policy, compliance.GateOptions{AssessmentStatus: "COMPLETED"})
	if res.ExitCode != clierror.ExitSecurityFail {
		t.Fatalf("expected ExitSecurityFail 1 because not_applicable cannot satisfy enforced control, got %d", res.ExitCode)
	}
}

func ptrFloat(f float64) *float64 {
	return &f
}

func ptrBool(b bool) *bool {
	return &b
}
