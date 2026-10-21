package test

import (
	"context"
	"database/sql"
	"path/filepath"
	"strings"
	"testing"
	"time"

	_ "modernc.org/sqlite"

	"felix/pkg/clierror"
	"felix/pkg/compliance"
)

// TestPhase912_LimitationsAndEvidenceBoundaries_E2E validates complete evidence boundaries,
// explicit coverage calculations, limitation tracking, and false-compliance protections.
func TestPhase912_LimitationsAndEvidenceBoundaries_E2E(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "limitations_e2e.db")

	store, err := compliance.NewSQLiteComplianceStore(dbPath)
	if err != nil {
		t.Fatalf("failed opening compliance store: %v", err)
	}
	defer store.Close()

	key, _ := compliance.GenerateIntegrityKey("e2e-lim-key")
	kp, _ := compliance.NewStaticKeyProvider(key)
	clock := compliance.NewMockClock(time.Date(2026, 10, 21, 14, 0, 0, 0, time.UTC))

	// ------------------------------------------------------------------------
	// SCENARIO 1: Empty findings list does NOT imply compliance
	// An assessment with zero findings where controls were never evaluated
	// must remain not_assessed and cannot claim compliance.
	// ------------------------------------------------------------------------
	t.Run("Scenario1_EmptyFindings_NeverImpliesCompliance", func(t *testing.T) {
		cat := &compliance.ControlCatalog{
			SchemaVersion: compliance.DefaultSchemaVersion,
			ID:            "nist-sample",
			Version:       "1.0.0",
			Title:         "NIST Sample Catalog",
			Controls: []compliance.Control{
				{ID: "AC-1", Title: "Access Control Policy", Description: "Policy requirements"},
				{ID: "AC-2", Title: "Account Management", Description: "Account management requirements"},
			},
		}

		engine := compliance.NewEvaluationEngine(compliance.DefaultEvaluationPolicy())
		evalCtx := &compliance.EvaluationContext{
			AssessmentID:     "ASM-EMPTY-FINDINGS",
			AssessmentStatus: "COMPLETED",
		}

		// Empty findings and empty positive evidence
		res, err := engine.Evaluate(cat, nil, nil, evalCtx)
		if err != nil {
			t.Fatalf("evaluation failed: %v", err)
		}

		if res.Summary.CompliantCount != 0 {
			t.Errorf("zero findings falsely produced compliant controls: %d", res.Summary.CompliantCount)
		}
		if res.Summary.NotAssessedCount != 2 {
			t.Errorf("expected 2 not_assessed controls for empty findings, got %d", res.Summary.NotAssessedCount)
		}

		cb := compliance.CalculateCoverageBasis(res.Summary)
		if cb.ComplianceRatePercent != 0.0 {
			t.Errorf("expected 0.0%% compliance rate for unassessed controls, got %.2f%%", cb.ComplianceRatePercent)
		}
		if cb.AssessedCoveragePercent != 0.0 {
			t.Errorf("expected 0.0%% assessed coverage, got %.2f%%", cb.AssessedCoveragePercent)
		}
	})

	// ------------------------------------------------------------------------
	// SCENARIO 2: Mapping alone does not establish control compliance or violation
	// ------------------------------------------------------------------------
	t.Run("Scenario2_MappingAlone_DoesNotEstablishCompliance", func(t *testing.T) {
		notice := compliance.MappingLimitationsNotice()
		if !strings.Contains(notice, "does NOT constitute a compliance evaluation") {
			t.Errorf("mapping notice missing explicit non-evaluation disclaimer: %s", notice)
		}
	})

	// ------------------------------------------------------------------------
	// SCENARIO 3: Seven evaluation states retain discrete semantics
	// not_assessed, insufficient_evidence, not_applicable, and error must NEVER
	// count as compliant.
	// ------------------------------------------------------------------------
	t.Run("Scenario3_SevenStates_RetainSemantics", func(t *testing.T) {
		sum := compliance.EvaluationSummary{
			TotalControls:             7,
			CompliantCount:            1,
			NonCompliantCount:         1,
			PartiallyCompliantCount:   1,
			NotAssessedCount:          1,
			InsufficientEvidenceCount: 1,
			NotApplicableCount:        1,
			ErrorCount:                1,
			ApplicableControls:        6, // 7 - 1 (not applicable)
			AssessedControls:          5, // 6 - 1 (not assessed)
		}

		cb := compliance.CalculateCoverageBasis(sum)
		// Compliance rate must be 1 compliant / 6 applicable = 16.67%, NOT 1 / 1 = 100%!
		expectedRate := (1.0 / 6.0) * 100.0
		diff := cb.ComplianceRatePercent - expectedRate
		if diff < -0.01 || diff > 0.01 {
			t.Errorf("expected compliance rate ~%.2f%%, got %.2f%%", expectedRate, cb.ComplianceRatePercent)
		}
		if cb.NotApplicableControls != 1 {
			t.Errorf("expected 1 not applicable control, got %d", cb.NotApplicableControls)
		}
	})

	// ------------------------------------------------------------------------
	// SCENARIO 4: Dossier preserves structured limitations and includes them in logical digest
	// ------------------------------------------------------------------------
	t.Run("Scenario4_Dossier_PreservesLimitations_AffectsDigest", func(t *testing.T) {
		evalTime := time.Date(2026, 10, 21, 14, 0, 0, 0, time.UTC)
		evalRes := &compliance.EvaluationResult{
			AssessmentID:    "ASM-DOSSIER-E2E",
			CatalogIdentity: "nist-sample:1.0.0",
			CatalogDigest:   "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			EvaluatedAt:     evalTime,
			EngineVersion:   "1.0.0",
			Evaluations: []compliance.ControlEvaluationRecord{
				{
					EvaluationID:       "eval:e2e:AC-1",
					CatalogID:          "nist-sample",
					CatalogVersion:     "1.0.0",
					ControlID:          "AC-1",
					ControlTitle:       "Policy",
					AssessmentID:       "ASM-DOSSIER-E2E",
					State:              compliance.StateCompliant,
					Rationale:          "Policy active",
					SupportingEvidence: []string{"PE-1"},
					EngineVersion:      "1.0.0",
					EvaluatedAt:        evalTime,
					Limitations:        "Logical checks only",
				},
				{
					EvaluationID:   "eval:e2e:AC-2",
					CatalogID:      "nist-sample",
					CatalogVersion: "1.0.0",
					ControlID:      "AC-2",
					ControlTitle:   "Account Mgmt",
					AssessmentID:   "ASM-DOSSIER-E2E",
					State:          compliance.StateNotAssessed,
					Rationale:      "No test performed",
					EngineVersion:  "1.0.0",
					EvaluatedAt:    evalTime,
				},
			},
			Summary: compliance.EvaluationSummary{
				TotalControls:      2,
				CompliantCount:     1,
				NotAssessedCount:   1,
				ApplicableControls: 2,
				AssessedControls:   1,
			},
		}
		if err := store.SaveEvaluationResultWithKey(evalRes, kp); err != nil {
			t.Fatalf("failed saving evaluation: %v", err)
		}

		dossierSvc := compliance.NewDossierService(store, clock)
		dossier, err := dossierSvc.GenerateDossier(context.Background(), compliance.GenerateDossierRequest{
			AssessmentID: "ASM-DOSSIER-E2E",
			CatalogID:    "nist-sample",
		})
		if err != nil {
			t.Fatalf("failed generating dossier: %v", err)
		}

		if len(dossier.StructuredLimitations) == 0 {
			t.Fatalf("expected non-empty StructuredLimitations in dossier")
		}

		// Mutating a material limitation MUST change the logical digest
		origDigest := dossier.LogicalDigest
		cloned := *dossier
		cloned.Summary.Limitations = append([]string{}, dossier.Summary.Limitations...)
		cloned.Summary.Limitations = append(cloned.Summary.Limitations, "Newly identified scope limitation")
		newDigest := compliance.ComputeDossierLogicalDigest(&cloned)
		if newDigest == origDigest {
			t.Errorf("dossier logical digest did not change when limitations changed")
		}
	})

	// ------------------------------------------------------------------------
	// SCENARIO 5: Normalized JSON & OSCAL exports preserve limitations and pass schema validation
	// ------------------------------------------------------------------------
	t.Run("Scenario5_Exports_PreserveLimitationsAndValidate", func(t *testing.T) {
		exportSvc := compliance.NewExportService(store, clock)

		// 1. Normalized JSON
		exp, err := exportSvc.GenerateNormalizedExport(context.Background(), compliance.ExportRequest{
			AssessmentID: "ASM-DOSSIER-E2E",
			CatalogID:    "nist-sample",
		})
		if err != nil {
			t.Fatalf("GenerateNormalizedJSON failed: %v", err)
		}
		if len(exp.StructuredLimitations) == 0 {
			t.Errorf("normalized export missing StructuredLimitations")
		}
		if exp.CoverageBasis == nil {
			t.Errorf("normalized export missing CoverageBasis")
		}
		if err := compliance.ValidateNormalizedExport(exp); err != nil {
			t.Fatalf("ValidateNormalizedExport failed: %v", err)
		}

		// 2. OSCAL Assessment Results
		docAR, err := exportSvc.GenerateOSCALAssessmentResults(context.Background(), compliance.ExportRequest{
			AssessmentID: "ASM-DOSSIER-E2E",
			CatalogID:    "nist-sample",
		})
		if err != nil {
			t.Fatalf("GenerateOSCALAssessmentResults failed: %v", err)
		}

		// Official schema validation must pass cleanly
		if err := compliance.ValidateOSCALAssessmentResults(docAR); err != nil {
			t.Fatalf("ValidateOSCALAssessmentResults failed official schema validation: %v", err)
		}
	})

	// ------------------------------------------------------------------------
	// SCENARIO 6: CI/CD Gates cannot turn unassessed or missing evidence into a false pass
	// ------------------------------------------------------------------------
	t.Run("Scenario6_ComplianceGate_EnforcesBoundaries", func(t *testing.T) {
		gateSvc := compliance.NewComplianceGateService()

		// Policy enforcing 100% compliance rate
		strictPolicy := &compliance.ComplianceGatePolicy{
			SchemaVersion:        "1.0",
			ID:                   "strict-gate",
			Version:              "1.0.0",
			TargetCatalog:        "nist-sample",
			MinCompliancePercent: ptrFloat(100.0),
			UnassessedPolicy:     "fail_closed",
		}

		// ASM-DOSSIER-E2E has 1 compliant and 1 unassessed (50% compliance rate)
		res := gateSvc.EvaluateFromStore(store, "ASM-DOSSIER-E2E", "nist-sample:1.0.0", strictPolicy, compliance.GateOptions{
			KeyProvider:      kp,
			AssessmentStatus: "COMPLETED",
			Now:              clock.Now(),
		})

		if res.ExitCode != clierror.ExitSecurityFail || res.Decision != compliance.GateStatusPolicyFailed {
			t.Fatalf("gate must fail with ExitSecurityFail (1) for 50%% compliance rate under 100%% requirement, got %d (decision: %s)",
				res.ExitCode, res.Decision)
		}

		if len(res.StructuredLimitations) == 0 {
			t.Errorf("gate result missing StructuredLimitations")
		}
		if res.CoverageBasis == nil {
			t.Errorf("gate result missing CoverageBasis")
		}
	})

	// ------------------------------------------------------------------------
	// SCENARIO 7: Legacy unverified records remain identified in limitations
	// ------------------------------------------------------------------------
	t.Run("Scenario7_LegacyUnverifiedRecords_RemainIdentified", func(t *testing.T) {
		evalLegacy := &compliance.EvaluationResult{
			AssessmentID:    "ASM-LEGACY-LIM",
			CatalogIdentity: "nist-sample:1.0.0",
			CatalogDigest:   "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
			EvaluatedAt:     time.Date(2026, 10, 21, 10, 0, 0, 0, time.UTC),
			EngineVersion:   "1.0.0",
			Evaluations: []compliance.ControlEvaluationRecord{
				{
					EvaluationID:       "eval:leg:AC-1",
					CatalogID:          "nist-sample",
					CatalogVersion:     "1.0.0",
					ControlID:          "AC-1",
					State:              compliance.StateCompliant,
					Rationale:          "Verified",
					SupportingEvidence: []string{"PE-1"},
				},
			},
			Summary: compliance.EvaluationSummary{
				TotalControls:      1,
				CompliantCount:     1,
				ApplicableControls: 1,
				AssessedControls:   1,
			},
		}

		// Save WITHOUT key provider -> legacy plain digest
		if err := store.SaveEvaluationResult(evalLegacy); err != nil {
			t.Fatalf("failed saving legacy evaluation: %v", err)
		}

		// Mark as legacy by stripping integrity_version in DB
		rawDB, errOpen := sql.Open("sqlite", dbPath)
		if errOpen != nil {
			t.Fatal(errOpen)
		}
		_, err = rawDB.Exec("UPDATE compliance_evaluation_results SET integrity_version = NULL WHERE assessment_id = 'ASM-LEGACY-LIM'")
		if err != nil {
			t.Fatal(err)
		}
		_, err = rawDB.Exec("DELETE FROM compliance_integrity_records WHERE result_id LIKE '%ASM-LEGACY-LIM%'")
		if err != nil {
			t.Fatal(err)
		}
		rawDB.Close()

		dossierSvc := compliance.NewDossierService(store, clock)
		dossier, err := dossierSvc.GenerateDossier(context.Background(), compliance.GenerateDossierRequest{
			AssessmentID: "ASM-LEGACY-LIM",
			CatalogID:    "nist-sample",
		})
		if err != nil {
			t.Fatalf("GenerateDossier failed: %v", err)
		}

		foundLegacyLim := false
		for _, lim := range dossier.StructuredLimitations {
			if lim.ID == "LIM-INT-LEGACY" {
				foundLegacyLim = true
				break
			}
		}
		if !foundLegacyLim {
			t.Errorf("expected LIM-INT-LEGACY in structured limitations for legacy unverified record")
		}
	})
}
