package compliance

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"felix/pkg/report"
)

func setupTestDossierStore(t *testing.T) *SQLiteComplianceStore {
	t.Helper()
	store, err := NewSQLiteComplianceStore(":memory:")
	if err != nil {
		t.Fatalf("failed creating test sqlite store: %v", err)
	}
	return store
}

func sampleEvaluationWithAllStates(assessmentID string) *EvaluationResult {
	evalTime := time.Date(2026, 10, 21, 10, 0, 0, 0, time.UTC)
	return &EvaluationResult{
		CatalogIdentity:        "nist-sp800-53-sample:5.1.0",
		CatalogDigest:          "sha256:1111111111111111111111111111111111111111111111111111111111111111",
		MappingRuleSetIdentity: "ruleset-sample:1.0.0",
		MappingRuleSetDigest:   "sha256:2222222222222222222222222222222222222222222222222222222222222222",
		AssessmentID:           assessmentID,
		ExecutionID:            "EXEC-DOSSIER-001",
		EvaluatedAt:            evalTime,
		EngineVersion:          CurrentEvaluationEngineVersion,
		Summary: EvaluationSummary{
			TotalControls:             7,
			CompliantCount:            1,
			NonCompliantCount:         1,
			PartiallyCompliantCount:   1,
			NotAssessedCount:          1,
			InsufficientEvidenceCount: 1,
			NotApplicableCount:        1,
			ErrorCount:                1,
			ApplicableControls:        6,
			AssessedControls:          6,
		},
		Evaluations: []ControlEvaluationRecord{
			{
				EvaluationID:       fmt.Sprintf("eval:%s:AC-1", assessmentID),
				CatalogID:          "nist-sp800-53-sample",
				CatalogVersion:     "5.1.0",
				ControlID:          "AC-1",
				ControlTitle:       "Policy and Procedures",
				AssessmentID:       assessmentID,
				ExecutionID:        "EXEC-DOSSIER-001",
				State:              StateCompliant,
				Rationale:          "Policy document verified active",
				SupportingEvidence: []string{"Access control policy approved 2026-01"},
				EvaluatedAt:        evalTime,
				EngineVersion:      CurrentEvaluationEngineVersion,
			},
			{
				EvaluationID:          fmt.Sprintf("eval:%s:AC-2", assessmentID),
				CatalogID:             "nist-sp800-53-sample",
				CatalogVersion:        "5.1.0",
				ControlID:             "AC-2",
				ControlTitle:          "Account Management",
				AssessmentID:          assessmentID,
				ExecutionID:           "EXEC-DOSSIER-001",
				State:                 StateNonCompliant,
				Rationale:             "Dormant privileged accounts found",
				FindingIDs:            []string{"F-DORMANT-01"},
				ContradictingEvidence: []string{"3 admin accounts unused > 90 days"},
				EvaluatedAt:           evalTime,
				EngineVersion:         CurrentEvaluationEngineVersion,
			},
			{
				EvaluationID:          fmt.Sprintf("eval:%s:AC-3", assessmentID),
				CatalogID:             "nist-sp800-53-sample",
				CatalogVersion:        "5.1.0",
				ControlID:             "AC-3",
				ControlTitle:          "Access Enforcement",
				AssessmentID:          assessmentID,
				ExecutionID:           "EXEC-DOSSIER-001",
				State:                 StatePartiallyCompliant,
				Rationale:             "Role-based access enforced except on diagnostic endpoint",
				FindingIDs:            []string{"F-BOLA-01"},
				SupportingEvidence:    []string{"RBAC active on API gateways"},
				ContradictingEvidence: []string{"BOLA on /debug/orders"},
				EvaluatedAt:           evalTime,
				EngineVersion:         CurrentEvaluationEngineVersion,
			},
			{
				EvaluationID:   fmt.Sprintf("eval:%s:AC-4", assessmentID),
				CatalogID:      "nist-sp800-53-sample",
				CatalogVersion: "5.1.0",
				ControlID:      "AC-4",
				ControlTitle:   "Information Flow Enforcement",
				AssessmentID:   assessmentID,
				ExecutionID:    "EXEC-DOSSIER-001",
				State:          StateNotAssessed,
				Rationale:      "Egress filtering was out of scope for assessment",
				EvaluatedAt:    evalTime,
				EngineVersion:  CurrentEvaluationEngineVersion,
			},
			{
				EvaluationID:   fmt.Sprintf("eval:%s:AC-5", assessmentID),
				CatalogID:      "nist-sp800-53-sample",
				CatalogVersion: "5.1.0",
				ControlID:      "AC-5",
				ControlTitle:   "Separation of Duties",
				AssessmentID:   assessmentID,
				ExecutionID:    "EXEC-DOSSIER-001",
				State:          StateInsufficientEvidence,
				Rationale:      "Audit logs lacked role change audit trails",
				EvaluatedAt:    evalTime,
				EngineVersion:  CurrentEvaluationEngineVersion,
			},
			{
				EvaluationID:   fmt.Sprintf("eval:%s:AC-6", assessmentID),
				CatalogID:      "nist-sp800-53-sample",
				CatalogVersion: "5.1.0",
				ControlID:      "AC-6",
				ControlTitle:   "Least Privilege",
				AssessmentID:   assessmentID,
				ExecutionID:    "EXEC-DOSSIER-001",
				State:          StateNotApplicable,
				Rationale:      "Target is a single-tenant isolated microservice",
				EvaluatedAt:    evalTime,
				EngineVersion:  CurrentEvaluationEngineVersion,
			},
			{
				EvaluationID:   fmt.Sprintf("eval:%s:AC-7", assessmentID),
				CatalogID:      "nist-sp800-53-sample",
				CatalogVersion: "5.1.0",
				ControlID:      "AC-7",
				ControlTitle:   "Unsuccessful Logon Attempts",
				AssessmentID:   assessmentID,
				ExecutionID:    "EXEC-DOSSIER-001",
				State:          StateError,
				Rationale:      "Auth service rate limiter caused scanner timeout error",
				EvaluatedAt:    evalTime,
				EngineVersion:  CurrentEvaluationEngineVersion,
			},
		},
	}
}

// ============================================================================
// A. DOSSIER GENERATION TESTS
// ============================================================================

func TestDossier_1_GenerateFromValidAssessment_AllStatesPreserved(t *testing.T) {
	store := setupTestDossierStore(t)
	defer store.Close()

	clock := NewMockClock(time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC))
	svc := NewDossierService(store, clock)

	evalRes := sampleEvaluationWithAllStates("ASM-DOSSIER-ALLSTATES")
	key, _ := GenerateIntegrityKey("dossier-test-key")
	kp, _ := NewStaticKeyProvider(key)

	if err := store.SaveEvaluationResultWithKey(evalRes, kp); err != nil {
		t.Fatalf("SaveEvaluationResultWithKey failed: %v", err)
	}

	dossier, err := svc.GenerateDossier(context.Background(), GenerateDossierRequest{
		AssessmentID: "ASM-DOSSIER-ALLSTATES",
		CatalogID:    "nist-sp800-53-sample",
		KeyProvider:  kp,
	})
	if err != nil {
		t.Fatalf("GenerateDossier failed: %v", err)
	}

	if dossier.Identity.AssessmentID != "ASM-DOSSIER-ALLSTATES" {
		t.Errorf("expected assessment ID ASM-DOSSIER-ALLSTATES, got %s", dossier.Identity.AssessmentID)
	}
	if dossier.Identity.CatalogID != "nist-sp800-53-sample" {
		t.Errorf("expected catalog ID nist-sp800-53-sample, got %s", dossier.Identity.CatalogID)
	}
	if dossier.Summary.TotalControls != 7 {
		t.Errorf("expected 7 controls in summary, got %d", dossier.Summary.TotalControls)
	}

	// Verify all 7 states preserved
	statesFound := make(map[EvaluationState]bool)
	for _, c := range dossier.Controls {
		statesFound[c.EvaluationState] = true
	}

	for _, expectedState := range []EvaluationState{
		StateCompliant, StateNonCompliant, StatePartiallyCompliant,
		StateNotAssessed, StateInsufficientEvidence, StateNotApplicable, StateError,
	} {
		if !statesFound[expectedState] {
			t.Errorf("expected state %s to be preserved in dossier controls", expectedState)
		}
	}

	// Overall status with errors should be COMPLETED_WITH_ERRORS
	if dossier.Summary.OverallStatus != "COMPLETED_WITH_ERRORS" {
		t.Errorf("expected COMPLETED_WITH_ERRORS, got %s", dossier.Summary.OverallStatus)
	}

	// Logical digest must be non-empty and well-formed
	if !strings.HasPrefix(dossier.LogicalDigest, "sha256:") {
		t.Errorf("invalid logical digest: %s", dossier.LogicalDigest)
	}
}

func TestDossier_2_IncludeRemediationAndSLASummary(t *testing.T) {
	store := setupTestDossierStore(t)
	defer store.Close()

	clock := NewMockClock(time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC))
	svc := NewDossierService(store, clock)
	baseTime := clock.Now().UTC()

	key, _ := GenerateIntegrityKey("dossier-rem-key")
	kp, _ := NewStaticKeyProvider(key)

	evalRes := sampleValidEvaluationResult("ASM-DOSSIER-REM")
	if err := store.SaveEvaluationResultWithKey(evalRes, kp); err != nil {
		t.Fatalf("SaveEvaluationResultWithKey failed: %v", err)
	}

	// Save remediation record for finding F-BOLA-01 under control AC-3
	remID := "rem:dossier:1"
	rec := &RemediationRecord{
		ID:           remID,
		FindingID:    "F-BOLA-01",
		AssessmentID: "ASM-DOSSIER-REM",
		CatalogID:    "nist-sp800-53-sample:5.1.0",
		ControlID:    "AC-3",
		Severity:     "HIGH",
		AssignedAt:   baseTime,
		SLAStartTime: baseTime,
		Deadline:     baseTime.Add(7 * 24 * time.Hour),
		Status:       RemediationStatusRemediated,
		CompletedAt:  &[]time.Time{baseTime.Add(24 * time.Hour)}[0],
		CreatedAt:    baseTime,
	}
	_ = store.SaveRemediationRecordWithKey(rec, &RemediationHistoryEvent{
		ID:            GenerateRemediationEventID(remID),
		RemediationID: remID,
		EventType:     HistoryEventAssigned,
		ToStatus:      RemediationStatusOpen,
		Timestamp:     baseTime,
	}, kp)
	_ = store.SaveRemediationRecordWithKey(rec, &RemediationHistoryEvent{
		ID:            GenerateRemediationEventID(remID),
		RemediationID: remID,
		EventType:     HistoryEventStatusChanged,
		FromStatus:    RemediationStatusOpen,
		ToStatus:      RemediationStatusRemediated,
		Timestamp:     baseTime.Add(24 * time.Hour),
	}, kp)

	dossier, err := svc.GenerateDossier(context.Background(), GenerateDossierRequest{
		AssessmentID:       "ASM-DOSSIER-REM",
		CatalogID:          "nist-sp800-53-sample",
		IncludeRemediation: true,
		IncludeSLA:         true,
		IncludeMTTR:        true,
		KeyProvider:        kp,
	})
	if err != nil {
		t.Fatalf("GenerateDossier failed: %v", err)
	}

	if len(dossier.Remediation) != 1 {
		t.Fatalf("expected 1 remediation entry, got %d", len(dossier.Remediation))
	}
	if dossier.Remediation[0].RemediationID != remID {
		t.Errorf("expected remediation ID %s, got %s", remID, dossier.Remediation[0].RemediationID)
	}
	if !dossier.Remediation[0].VerifiedCompletion {
		t.Errorf("expected VerifiedCompletion true, got false")
	}

	// Verify control AC-3 has embedded remediation summary
	var ac3Ctrl *DossierControlResult
	for i := range dossier.Controls {
		if dossier.Controls[i].ControlID == "AC-3" {
			ac3Ctrl = &dossier.Controls[i]
			break
		}
	}
	if ac3Ctrl == nil || ac3Ctrl.Remediation == nil {
		t.Fatalf("expected remediation summary on control AC-3")
	}
	if ac3Ctrl.Remediation.RecordID != remID {
		t.Errorf("expected control remediation record %s, got %s", remID, ac3Ctrl.Remediation.RecordID)
	}

	// Verify MTTR summary snapshot
	if dossier.Summary.MTTRSummary == nil || !dossier.Summary.MTTRSummary.HasData {
		t.Errorf("expected valid MTTRSummary in dossier summary")
	}
}

func TestDossier_2b_IncludeFindingsMetadata(t *testing.T) {
	store := setupTestDossierStore(t)
	defer store.Close()

	clock := NewMockClock(time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC))
	svc := NewDossierService(store, clock)

	evalRes := sampleValidEvaluationResult("ASM-DOSSIER-FINDINGS")
	_ = store.SaveEvaluationResult(evalRes)

	findings := []report.Finding{
		{
			ID:        "F-BOLA-01",
			RuleID:    "apisec-bola-01",
			Title:     "Broken Object Level Authorization in Orders API",
			Severity:  "CRITICAL",
			Category:  "authorization",
			Framework: "apisec",
		},
	}

	dossier, err := svc.GenerateDossier(context.Background(), GenerateDossierRequest{
		AssessmentID: "ASM-DOSSIER-FINDINGS",
		CatalogID:    "nist-sp800-53-sample",
		Findings:     findings,
	})
	if err != nil {
		t.Fatalf("GenerateDossier failed: %v", err)
	}

	if len(dossier.Findings) != 1 {
		t.Fatalf("expected 1 finding entry, got %d", len(dossier.Findings))
	}
	f := dossier.Findings[0]
	if f.FindingID != "F-BOLA-01" {
		t.Errorf("expected finding ID F-BOLA-01, got %s", f.FindingID)
	}
	if f.Title != "Broken Object Level Authorization in Orders API" {
		t.Errorf("expected title preserved, got %s", f.Title)
	}
	if f.RuleID != "apisec-bola-01" {
		t.Errorf("expected rule ID apisec-bola-01, got %s", f.RuleID)
	}
	if len(f.AssociatedControlIDs) == 0 || f.AssociatedControlIDs[0] != "AC-3" {
		t.Errorf("expected association to AC-3, got %v", f.AssociatedControlIDs)
	}
}

func TestDossier_3_MissingEvaluationReturnsNotFound(t *testing.T) {
	store := setupTestDossierStore(t)
	defer store.Close()

	svc := NewDossierService(store, nil)
	_, err := svc.GenerateDossier(context.Background(), GenerateDossierRequest{
		AssessmentID: "NONEXISTENT",
		CatalogID:    "nist-5",
	})
	if err == nil || !errors.Is(err, ErrNotFound) {
		t.Errorf("expected ErrNotFound for nonexistent evaluation, got %v", err)
	}
}

func TestDossier_4_MismatchedCatalogRejectionInStrictMode(t *testing.T) {
	store := setupTestDossierStore(t)
	defer store.Close()

	svc := NewDossierService(store, nil)
	evalRes := sampleValidEvaluationResult("ASM-CAT-MISMATCH")
	_ = store.SaveEvaluationResult(evalRes)

	// Provide a catalog with a different version
	cat := &ControlCatalog{
		SchemaVersion: "1.0",
		ID:            "nist-sp800-53-sample",
		Title:         "NIST SP 800-53",
		Version:       "9.9.9", // Mismatched! Evaluation targeted 5.1.0
		Controls: []Control{
			{ID: "AC-3", Title: "Access Enforcement", Description: "Desc"},
		},
	}

	// In strict mode -> fails closed
	_, err := svc.GenerateDossier(context.Background(), GenerateDossierRequest{
		AssessmentID:    "ASM-CAT-MISMATCH",
		CatalogID:       "nist-sp800-53-sample",
		Catalog:         cat,
		StrictIntegrity: true,
	})
	if err == nil || !errors.Is(err, ErrIntegrityMismatch) {
		t.Errorf("expected ErrIntegrityMismatch in strict mode for catalog mismatch, got %v", err)
	}

	// In default mode -> succeeds with explicit warning in limitations
	dossier, err := svc.GenerateDossier(context.Background(), GenerateDossierRequest{
		AssessmentID: "ASM-CAT-MISMATCH",
		CatalogID:    "nist-sp800-53-sample",
		Catalog:      cat,
	})
	if err != nil {
		t.Fatalf("GenerateDossier default mode failed: %v", err)
	}
	foundWarning := false
	for _, lim := range dossier.Summary.Limitations {
		if strings.Contains(lim, "catalog version mismatch") {
			foundWarning = true
			break
		}
	}
	if !foundWarning {
		t.Errorf("expected catalog version mismatch warning in limitations")
	}
}

// ============================================================================
// B. INTEGRITY AND TAMPERING TESTS
// ============================================================================

func TestDossier_Integrity_TamperedEvaluationDetected(t *testing.T) {
	store := setupTestDossierStore(t)
	defer store.Close()

	key, _ := GenerateIntegrityKey("dossier-tamper-key")
	kp, _ := NewStaticKeyProvider(key)
	svc := NewDossierService(store, nil)

	evalRes := sampleValidEvaluationResult("ASM-TAMPER-TEST")
	if err := store.SaveEvaluationResultWithKey(evalRes, kp); err != nil {
		t.Fatalf("SaveEvaluationResultWithKey failed: %v", err)
	}

	// Tamper with control evaluation rationale directly in SQLite
	_, err := store.db.Exec("UPDATE compliance_control_evaluations SET rationale = 'TAMPERED RATIONALE' WHERE assessment_id = 'ASM-TAMPER-TEST'")
	if err != nil {
		t.Fatalf("db tamper failed: %v", err)
	}

	// Case 1: Strict integrity mode must fail closed with ErrIntegrityMismatch
	_, strictErr := svc.GenerateDossier(context.Background(), GenerateDossierRequest{
		AssessmentID:    "ASM-TAMPER-TEST",
		CatalogID:       "nist-sp800-53-sample",
		KeyProvider:     kp,
		StrictIntegrity: true,
	})
	if strictErr == nil || !errors.Is(strictErr, ErrIntegrityMismatch) {
		t.Fatalf("expected strict mode to fail closed with ErrIntegrityMismatch, got %v", strictErr)
	}

	// Case 2: Default mode returns dossier marked PARTIAL with explicit limitations
	dossier, err := svc.GenerateDossier(context.Background(), GenerateDossierRequest{
		AssessmentID: "ASM-TAMPER-TEST",
		CatalogID:    "nist-sp800-53-sample",
		KeyProvider:  kp,
	})
	if err != nil {
		t.Fatalf("default mode failed unexpectedly: %v", err)
	}
	if dossier.Identity.CompletenessStatus != DossierCompletenessPartial {
		t.Errorf("expected CompletenessStatus PARTIAL, got %s", dossier.Identity.CompletenessStatus)
	}
	if len(dossier.Integrity.IntegrityFailures) == 0 {
		t.Errorf("expected IntegrityFailures to be recorded")
	}
}

func TestDossier_Integrity_LegacyUnverifiedHandling(t *testing.T) {
	store := setupTestDossierStore(t)
	defer store.Close()

	svc := NewDossierService(store, nil)
	evalRes := sampleValidEvaluationResult("ASM-LEGACY-TEST")
	if err := store.SaveEvaluationResult(evalRes); err != nil {
		t.Fatalf("SaveEvaluationResult failed: %v", err)
	}

	// Simulate a genuine pre-integrity legacy record (empty integrity_version marker, no integrity row)
	_, _ = store.db.Exec("UPDATE compliance_evaluation_results SET integrity_version = '' WHERE assessment_id = 'ASM-LEGACY-TEST'")
	_, _ = store.db.Exec("DELETE FROM compliance_integrity_records WHERE result_id LIKE 'evalres:ASM-LEGACY-TEST%'")

	dossier, err := svc.GenerateDossier(context.Background(), GenerateDossierRequest{
		AssessmentID: "ASM-LEGACY-TEST",
		CatalogID:    "nist-sp800-53-sample",
	})
	if err != nil {
		t.Fatalf("GenerateDossier failed: %v", err)
	}

	if len(dossier.Integrity.UnverifiedLegacyRecords) == 0 {
		t.Errorf("expected legacy record to be logged in UnverifiedLegacyRecords")
	}
}

// ============================================================================
// C. VALIDATION AND LOGICAL DIGEST TESTS
// ============================================================================

func TestDossier_Validation_MissingRequiredIdentityRejected(t *testing.T) {
	d := &ComplianceDossier{
		Identity: DossierIdentity{
			SchemaVersion: CurrentDossierSchemaVersion,
			// AssessmentID missing!
			CatalogID:   "nist-5",
			GeneratedAt: time.Now().UTC(),
		},
		Summary: DossierAssessmentSummary{},
	}
	err := ValidateDossier(d)
	if err == nil || !strings.Contains(err.Error(), "identity.assessment_id is required") {
		t.Errorf("expected validation error for missing assessment_id, got %v", err)
	}
}

func TestDossier_Validation_UnsupportedSchemaRejected(t *testing.T) {
	d := &ComplianceDossier{
		Identity: DossierIdentity{
			SchemaVersion: "unsupported.schema.v99",
			AssessmentID:  "ASM-1",
			CatalogID:     "nist-5",
			GeneratedAt:   time.Now().UTC(),
		},
	}
	err := ValidateDossier(d)
	if err == nil || !errors.Is(err, ErrUnsupportedDossierSchema) {
		t.Errorf("expected ErrUnsupportedDossierSchema, got %v", err)
	}
}

func TestDossier_Validation_DuplicateIdentifiersRejected(t *testing.T) {
	d := &ComplianceDossier{
		Identity: DossierIdentity{
			SchemaVersion: CurrentDossierSchemaVersion,
			AssessmentID:  "ASM-DUP",
			CatalogID:     "nist-5",
			GeneratedAt:   time.Now().UTC(),
		},
		Summary: DossierAssessmentSummary{
			TotalControls: 2,
		},
		Controls: []DossierControlResult{
			{ControlID: "AC-1", EvaluationState: StateCompliant, Rationale: "ok"},
			{ControlID: "AC-1", EvaluationState: StateCompliant, Rationale: "ok"}, // Duplicate!
		},
	}
	err := ValidateDossier(d)
	if err == nil || !strings.Contains(err.Error(), "duplicate control_id") {
		t.Errorf("expected duplicate control_id error, got %v", err)
	}
}

func TestDossier_Validation_ContradictoryCountsRejected(t *testing.T) {
	d := &ComplianceDossier{
		Identity: DossierIdentity{
			SchemaVersion: CurrentDossierSchemaVersion,
			AssessmentID:  "ASM-COUNT",
			CatalogID:     "nist-5",
			GeneratedAt:   time.Now().UTC(),
		},
		Summary: DossierAssessmentSummary{
			TotalControls:  5, // Contradicts controls slice length (1)
			CompliantCount: 1,
		},
		Controls: []DossierControlResult{
			{ControlID: "AC-1", EvaluationState: StateCompliant, Rationale: "ok"},
		},
	}
	err := ValidateDossier(d)
	if err == nil || !strings.Contains(err.Error(), "summary.total_controls (5) does not match controls count (1)") {
		t.Errorf("expected contradictory total_controls error, got %v", err)
	}
}

func TestDossier_Validation_VerifiedClaimWithoutStatusRejected(t *testing.T) {
	d := &ComplianceDossier{
		Identity: DossierIdentity{
			SchemaVersion: CurrentDossierSchemaVersion,
			AssessmentID:  "ASM-EV-VER",
			CatalogID:     "nist-5",
			GeneratedAt:   time.Now().UTC(),
		},
		Summary: DossierAssessmentSummary{
			TotalControls:      1,
			CompliantCount:     1,
			TotalEvidenceLinks: 1,
		},
		Controls: []DossierControlResult{
			{ControlID: "AC-1", EvaluationState: StateCompliant, Rationale: "ok"},
		},
		Evidence: []DossierEvidenceEntry{
			{
				EvidenceID:         "ev:1",
				ControlID:          "AC-1",
				EvidenceType:       "supporting",
				VerificationStatus: "UNVERIFIED", // Unverified!
				Verified:           true,         // Contradictory claim of verified!
			},
		},
	}
	err := ValidateDossier(d)
	if err == nil || !strings.Contains(err.Error(), "marked verified=true but verification_status is") {
		t.Errorf("expected error for unverified evidence claiming verified=true, got %v", err)
	}
}

func TestDossier_Digest_DeterministicAcrossRepeatedGeneration(t *testing.T) {
	store := setupTestDossierStore(t)
	defer store.Close()

	clock1 := NewMockClock(time.Date(2026, 10, 21, 10, 0, 0, 0, time.UTC))
	svc1 := NewDossierService(store, clock1)

	evalRes := sampleValidEvaluationResult("ASM-DIGEST-STABLE")
	_ = store.SaveEvaluationResult(evalRes)

	d1, err := svc1.GenerateDossier(context.Background(), GenerateDossierRequest{
		AssessmentID: "ASM-DIGEST-STABLE",
		CatalogID:    "nist-sp800-53-sample",
	})
	if err != nil {
		t.Fatalf("svc1.GenerateDossier failed: %v", err)
	}

	// Second service with DIFFERENT clock time and different generation timestamp
	clock2 := NewMockClock(time.Date(2026, 10, 25, 18, 30, 0, 0, time.UTC))
	svc2 := NewDossierService(store, clock2)

	d2, err := svc2.GenerateDossier(context.Background(), GenerateDossierRequest{
		AssessmentID: "ASM-DIGEST-STABLE",
		CatalogID:    "nist-sp800-53-sample",
	})
	if err != nil {
		t.Fatalf("svc2.GenerateDossier failed: %v", err)
	}

	// GeneratedAt must differ
	if d1.Identity.GeneratedAt.Equal(d2.Identity.GeneratedAt) {
		t.Errorf("expected different generated_at timestamps")
	}

	// But logical content digest MUST be identical!
	if d1.LogicalDigest != d2.LogicalDigest {
		t.Errorf("expected identical logical digests across different generation times: d1=%s, d2=%s",
			d1.LogicalDigest, d2.LogicalDigest)
	}
}

func TestDossier_Digest_ChangesWhenMaterialContentChanges(t *testing.T) {
	store := setupTestDossierStore(t)
	defer store.Close()

	clock := NewMockClock(time.Date(2026, 10, 21, 10, 0, 0, 0, time.UTC))
	svc := NewDossierService(store, clock)

	evalRes := sampleValidEvaluationResult("ASM-DIGEST-MUTATE")
	_ = store.SaveEvaluationResult(evalRes)

	dOrig, err := svc.GenerateDossier(context.Background(), GenerateDossierRequest{
		AssessmentID: "ASM-DIGEST-MUTATE",
		CatalogID:    "nist-sp800-53-sample",
	})
	if err != nil {
		t.Fatalf("GenerateDossier failed: %v", err)
	}

	// Clone dossier and change a material field (e.g. control state)
	dMutated := *dOrig
	dMutated.Controls = append([]DossierControlResult{}, dOrig.Controls...)
	dMutated.Controls[0].Rationale = "ALTERED MATERIAL RATIONALE"

	mutatedDigest := ComputeDossierLogicalDigest(&dMutated)
	if mutatedDigest == dOrig.LogicalDigest {
		t.Errorf("expected logical digest to change when material content changes")
	}
}

func TestDossier_ExportAndImportRoundTrip(t *testing.T) {
	store := setupTestDossierStore(t)
	defer store.Close()

	clock := NewMockClock(time.Date(2026, 10, 21, 10, 0, 0, 0, time.UTC))
	svc := NewDossierService(store, clock)

	evalRes := sampleValidEvaluationResult("ASM-ROUNDTRIP")
	_ = store.SaveEvaluationResult(evalRes)

	dossier, err := svc.GenerateDossier(context.Background(), GenerateDossierRequest{
		AssessmentID: "ASM-ROUNDTRIP",
		CatalogID:    "nist-sp800-53-sample",
	})
	if err != nil {
		t.Fatalf("GenerateDossier failed: %v", err)
	}

	jsonBytes, err := dossier.ToPrettyJSON()
	if err != nil {
		t.Fatalf("ToPrettyJSON failed: %v", err)
	}

	loaded, err := LoadDossierFromJSON(jsonBytes)
	if err != nil {
		t.Fatalf("LoadDossierFromJSON failed: %v", err)
	}

	if loaded.Identity.AssessmentID != dossier.Identity.AssessmentID {
		t.Errorf("roundtrip assessment ID mismatch: got %s, expected %s",
			loaded.Identity.AssessmentID, dossier.Identity.AssessmentID)
	}
	if loaded.LogicalDigest != dossier.LogicalDigest {
		t.Errorf("roundtrip logical digest mismatch: got %s, expected %s",
			loaded.LogicalDigest, dossier.LogicalDigest)
	}
}
