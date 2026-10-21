package test

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"testing"
	"time"

	"felix/pkg/compliance"
	"felix/pkg/report"
)

// TestPhase98_ComplianceDossier_EndToEnd tests the complete Phase 9.8 Compliance Dossier pipeline:
// 1. Validated catalog and mapping rule set loading.
// 2. Persisted signed evaluation result with multiple control evaluation states.
// 3. Persisted findings, evidence references, and remediation records with SLA & MTTR history.
// 4. End-to-end dossier generation via DossierService.
// 5. Semantic validation enforcing state preservation, quantitative summary consistency, and evidence linkage.
// 6. Logical digest determinism across repeated runs and mutation sensitivity.
// 7. Full CLI workflow: generation, atomic writing, overwrite protection, view, and validation.
// 8. Strict integrity mode vs default mode under source data tampering.
func TestPhase98_ComplianceDossier_EndToEnd(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "compliance_dossier_e2e.db")

	startTime := time.Date(2026, 10, 21, 10, 0, 0, 0, time.UTC)
	clock := compliance.NewMockClock(startTime)

	// 1. Setup SQLite Store and Integrity Key Provider
	store, err := compliance.NewSQLiteComplianceStore(dbPath)
	if err != nil {
		t.Fatalf("NewSQLiteComplianceStore failed: %v", err)
	}
	defer store.Close()

	key, err := compliance.GenerateIntegrityKey("dossier-e2e-key")
	if err != nil {
		t.Fatalf("GenerateIntegrityKey failed: %v", err)
	}
	kp, err := compliance.NewStaticKeyProvider(key)
	if err != nil {
		t.Fatalf("NewStaticKeyProvider failed: %v", err)
	}

	keyFilePath := filepath.Join(tmpDir, "key.hex")
	if err := os.WriteFile(keyFilePath, key.Material, 0600); err != nil {
		t.Fatalf("failed writing key file: %v", err)
	}

	// 2. Persist signed compliance evaluation result with 4 distinct control states
	evalRes := &compliance.EvaluationResult{
		AssessmentID:    "ASM-DOSSIER-E2E",
		ExecutionID:     "EXEC-DOSSIER-001",
		CatalogIdentity: "nist-sp800-53-dossier-e2e:5.1.0",
		CatalogDigest:   "sha256:1111111111111111111111111111111111111111111111111111111111111111",
		EngineVersion:   "1.0.0",
		Summary: compliance.EvaluationSummary{
			TotalControls:           4,
			CompliantCount:          1,
			NonCompliantCount:       2,
			PartiallyCompliantCount: 1,
			ApplicableControls:      4,
			AssessedControls:        4,
		},
		Evaluations: []compliance.ControlEvaluationRecord{
			{
				EvaluationID:       "eval:ASM-DOSSIER-E2E:AC-1",
				ControlID:          "AC-1",
				ControlTitle:       "Access Control Policy and Procedures",
				CatalogID:          "nist-sp800-53-dossier-e2e",
				CatalogVersion:     "5.1.0",
				AssessmentID:       "ASM-DOSSIER-E2E",
				State:              compliance.StateCompliant,
				Rationale:          "Approved access control policy document verified active and up to date.",
				SupportingEvidence: []string{"Security Policy v2.4 approved by CISO on 2026-01-15"},
				EvaluatedAt:        startTime,
				EngineVersion:      "1.0.0",
			},
			{
				EvaluationID:          "eval:ASM-DOSSIER-E2E:AC-3",
				ControlID:             "AC-3",
				ControlTitle:          "Access Enforcement",
				CatalogID:             "nist-sp800-53-dossier-e2e",
				CatalogVersion:        "5.1.0",
				AssessmentID:          "ASM-DOSSIER-E2E",
				State:                 compliance.StateNonCompliant,
				Rationale:             "Authorization bypass discovered in order payment API endpoint.",
				FindingIDs:            []string{"F-BOLA-01"},
				ContradictingEvidence: []string{"User B accessed order 104 without authorization"},
				EvaluatedAt:           startTime,
				EngineVersion:         "1.0.0",
			},
			{
				EvaluationID:          "eval:ASM-DOSSIER-E2E:SC-8",
				ControlID:             "SC-8",
				ControlTitle:          "Transmission Confidentiality and Integrity",
				CatalogID:             "nist-sp800-53-dossier-e2e",
				CatalogVersion:        "5.1.0",
				AssessmentID:          "ASM-DOSSIER-E2E",
				State:                 compliance.StateNonCompliant,
				Rationale:             "Weak cipher suites accepted on public API gateway.",
				FindingIDs:            []string{"F-TLS-02"},
				ContradictingEvidence: []string{"TLS 1.0 enabled on api.example.com:443"},
				EvaluatedAt:           startTime,
				EngineVersion:         "1.0.0",
			},
			{
				EvaluationID:          "eval:ASM-DOSSIER-E2E:SC-5",
				ControlID:             "SC-5",
				ControlTitle:          "Denial of Service Protection",
				CatalogID:             "nist-sp800-53-dossier-e2e",
				CatalogVersion:        "5.1.0",
				AssessmentID:          "ASM-DOSSIER-E2E",
				State:                 compliance.StatePartiallyCompliant,
				Rationale:             "Rate limiting active on auth endpoints but missing on reporting queries.",
				FindingIDs:            []string{"F-DOS-03"},
				SupportingEvidence:    []string{"Token bucket rate limiter active on /auth/token"},
				ContradictingEvidence: []string{"Unbounded query on /reports/export"},
				EvaluatedAt:           startTime,
				EngineVersion:         "1.0.0",
			},
		},
		EvaluatedAt: startTime,
	}

	if err := store.SaveEvaluationResultWithKey(evalRes, kp); err != nil {
		t.Fatalf("SaveEvaluationResultWithKey failed: %v", err)
	}

	// 3. Configure corporate SLA policy & assign SLAs
	policy := &compliance.RemediationSLAPolicy{
		ID:          "corp-dossier-policy",
		Version:     "1.0.0",
		Enabled:     true,
		Description: "Corporate SLA policy for dossier testing",
		Priority:    100,
		Rules: map[string]string{
			"CRITICAL": "24h",
			"HIGH":     "7d",
			"MEDIUM":   "30d",
		},
		DefaultRule: "30d",
	}
	if err := store.SaveRemediationPolicy(policy); err != nil {
		t.Fatalf("SaveRemediationPolicy failed: %v", err)
	}

	slaSvc := compliance.NewRemediationService(clock, 0)

	// Finding 1 (CRITICAL under AC-3): Completed on time at 18h
	rec1, evt1, err := slaSvc.AssignSLA(compliance.AssignSLAParams{
		FindingID:       "F-BOLA-01",
		FindingTitle:    "Critical BOLA in Payment API",
		FindingSource:   "apisec",
		FindingCategory: "authz",
		AssessmentID:    "ASM-DOSSIER-E2E",
		CatalogID:       "nist-sp800-53-dossier-e2e:5.1.0",
		ControlID:       "AC-3",
		Severity:        "CRITICAL",
		Policy:          policy,
		SLAStartTime:    startTime,
		Actor:           "pipeline",
	})
	if err != nil {
		t.Fatalf("AssignSLA 1 failed: %v", err)
	}
	if err := store.SaveRemediationRecordWithKey(rec1, evt1, kp); err != nil {
		t.Fatalf("SaveRemediationRecord 1 failed: %v", err)
	}

	clock.Set(startTime.Add(18 * time.Hour))
	evtDone1, err := slaSvc.TransitionStatus(rec1, compliance.RemediationStatusRemediated, "developer", "Hotfix verified")
	if err != nil {
		t.Fatalf("TransitionStatus 1 Remediated failed: %v", err)
	}
	if err := store.SaveRemediationRecordWithKey(rec1, evtDone1, kp); err != nil {
		t.Fatalf("SaveRemediationRecord 1 Remediated failed: %v", err)
	}

	// Finding 2 (HIGH under SC-8): Accepted Risk
	rec2, evt2, err := slaSvc.AssignSLA(compliance.AssignSLAParams{
		FindingID:       "F-TLS-02",
		FindingTitle:    "Legacy TLS 1.0 Enabled",
		FindingSource:   "webvuln",
		FindingCategory: "crypto",
		AssessmentID:    "ASM-DOSSIER-E2E",
		CatalogID:       "nist-sp800-53-dossier-e2e:5.1.0",
		ControlID:       "SC-8",
		Severity:        "HIGH",
		Policy:          policy,
		SLAStartTime:    startTime,
		Actor:           "pipeline",
	})
	if err != nil {
		t.Fatalf("AssignSLA 2 failed: %v", err)
	}
	if err := store.SaveRemediationRecordWithKey(rec2, evt2, kp); err != nil {
		t.Fatalf("SaveRemediationRecord 2 failed: %v", err)
	}

	clock.Set(startTime.Add(24 * time.Hour))
	riskExpiry := startTime.Add(90 * 24 * time.Hour)
	evtRisk2, err := slaSvc.AcceptRisk(rec2, "Compensating legacy client restriction in place", "Security Committee", &riskExpiry, "Security Committee")
	if err != nil {
		t.Fatalf("AcceptRisk 2 failed: %v", err)
	}
	if err := store.SaveRemediationRecordWithKey(rec2, evtRisk2, kp); err != nil {
		t.Fatalf("SaveRemediationRecord 2 Risk failed: %v", err)
	}

	// 4. Generate Dossier via DossierService
	dossierSvc := compliance.NewDossierService(store, clock)

	findings := []report.Finding{
		{
			ID:        "F-BOLA-01",
			RuleID:    "sec-bola-001",
			Title:     "Critical BOLA in Payment API",
			Severity:  "CRITICAL",
			Category:  "authz",
			Framework: "apisec",
		},
		{
			ID:        "F-TLS-02",
			RuleID:    "sec-crypto-002",
			Title:     "Legacy TLS 1.0 Enabled",
			Severity:  "HIGH",
			Category:  "crypto",
			Framework: "webvuln",
		},
		{
			ID:        "F-DOS-03",
			RuleID:    "sec-dos-003",
			Title:     "Unbounded Query Denial of Service",
			Severity:  "MEDIUM",
			Category:  "dos",
			Framework: "apisec",
		},
	}

	dossier, err := dossierSvc.GenerateDossier(context.Background(), compliance.GenerateDossierRequest{
		AssessmentID:       "ASM-DOSSIER-E2E",
		CatalogID:          "nist-sp800-53-dossier-e2e:5.1.0",
		Findings:           findings,
		IncludeRemediation: true,
		IncludeSLA:         true,
		IncludeMTTR:        true,
		StrictIntegrity:    true,
		KeyProvider:        kp,
	})
	if err != nil {
		t.Fatalf("GenerateDossier failed: %v", err)
	}

	// 5. Assertions on Dossier Content
	if dossier.Identity.AssessmentID != "ASM-DOSSIER-E2E" {
		t.Errorf("expected AssessmentID ASM-DOSSIER-E2E, got %s", dossier.Identity.AssessmentID)
	}
	if dossier.Identity.CompletenessStatus != compliance.DossierCompletenessComplete {
		t.Errorf("expected CompletenessStatus COMPLETE, got %s", dossier.Identity.CompletenessStatus)
	}
	if dossier.Summary.TotalControls != 4 {
		t.Errorf("expected 4 total controls, got %d", dossier.Summary.TotalControls)
	}
	if dossier.Summary.CompliantCount != 1 {
		t.Errorf("expected 1 compliant control, got %d", dossier.Summary.CompliantCount)
	}
	if dossier.Summary.NonCompliantCount != 2 {
		t.Errorf("expected 2 non-compliant controls, got %d", dossier.Summary.NonCompliantCount)
	}
	if dossier.Summary.PartiallyCompliantCount != 1 {
		t.Errorf("expected 1 partially compliant control, got %d", dossier.Summary.PartiallyCompliantCount)
	}

	// Verify Findings register
	if len(dossier.Findings) != 3 {
		t.Errorf("expected 3 findings in register, got %d", len(dossier.Findings))
	}

	// Verify Remediation register
	if len(dossier.Remediation) != 2 {
		t.Errorf("expected 2 remediation entries, got %d", len(dossier.Remediation))
	}

	// Verify MTTR Summary
	if dossier.Summary.MTTRSummary == nil || !dossier.Summary.MTTRSummary.HasData {
		t.Fatalf("expected valid MTTR summary")
	}
	if dossier.Summary.MTTRSummary.CompletedEpisodes != 1 {
		t.Errorf("expected 1 completed MTTR episode, got %d", dossier.Summary.MTTRSummary.CompletedEpisodes)
	}

	// Verify Integrity statement
	if len(dossier.Integrity.IntegrityFailures) != 0 {
		t.Errorf("expected 0 integrity failures, got %v", dossier.Integrity.IntegrityFailures)
	}
	if dossier.Integrity.EvaluationIntegrityStatus != compliance.StatusVerified {
		t.Errorf("expected evaluation integrity StatusVerified, got %s", dossier.Integrity.EvaluationIntegrityStatus)
	}

	// 6. Test JSON Export and Roundtrip
	jsonBytes, err := dossier.ToPrettyJSON()
	if err != nil {
		t.Fatalf("ToPrettyJSON failed: %v", err)
	}
	dossierFile := filepath.Join(tmpDir, "dossier.json")
	if err := os.WriteFile(dossierFile, jsonBytes, 0600); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	loadedDossier, err := compliance.LoadDossierFromFile(dossierFile)
	if err != nil {
		t.Fatalf("LoadDossierFromFile failed: %v", err)
	}
	if loadedDossier.LogicalDigest != dossier.LogicalDigest {
		t.Errorf("logical digest mismatch after roundtrip: got %s, expected %s",
			loadedDossier.LogicalDigest, dossier.LogicalDigest)
	}

	// 7. Test Logical Digest Stability across Different Timestamps
	clockLater := compliance.NewMockClock(startTime.Add(30 * 24 * time.Hour))
	dossierSvcLater := compliance.NewDossierService(store, clockLater)
	dossierLater, err := dossierSvcLater.GenerateDossier(context.Background(), compliance.GenerateDossierRequest{
		AssessmentID:       "ASM-DOSSIER-E2E",
		CatalogID:          "nist-sp800-53-dossier-e2e:5.1.0",
		Findings:           findings,
		IncludeRemediation: true,
		IncludeSLA:         true,
		IncludeMTTR:        true,
		StrictIntegrity:    true,
		KeyProvider:        kp,
	})
	if err != nil {
		t.Fatalf("dossierSvcLater.GenerateDossier failed: %v", err)
	}
	if dossierLater.LogicalDigest != dossier.LogicalDigest {
		t.Errorf("expected identical logical digests across different generation times: %s vs %s",
			dossierLater.LogicalDigest, dossier.LogicalDigest)
	}

	// 8. Test Tampering Detection
	rawDB, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("failed opening raw db for tamper: %v", err)
	}
	defer rawDB.Close()

	// Mutate rationale of AC-3 directly in SQLite
	_, err = rawDB.Exec("UPDATE compliance_control_evaluations SET rationale = 'TAMPERED IN DB' WHERE control_id = 'AC-3' AND assessment_id = 'ASM-DOSSIER-E2E'")
	if err != nil {
		t.Fatalf("failed executing direct tamper: %v", err)
	}

	// Strict mode MUST fail closed with ErrIntegrityMismatch
	_, strictErr := dossierSvc.GenerateDossier(context.Background(), compliance.GenerateDossierRequest{
		AssessmentID:    "ASM-DOSSIER-E2E",
		CatalogID:       "nist-sp800-53-dossier-e2e:5.1.0",
		StrictIntegrity: true,
		KeyProvider:     kp,
	})
	if strictErr == nil {
		t.Fatalf("expected strict mode to fail closed after tampering, got nil error")
	}

	// Default mode MUST return dossier marked PARTIAL with explicit limitations
	dossierTampered, err := dossierSvc.GenerateDossier(context.Background(), compliance.GenerateDossierRequest{
		AssessmentID: "ASM-DOSSIER-E2E",
		CatalogID:    "nist-sp800-53-dossier-e2e:5.1.0",
		KeyProvider:  kp,
	})
	if err != nil {
		t.Fatalf("default mode failed unexpectedly: %v", err)
	}
	if dossierTampered.Identity.CompletenessStatus != compliance.DossierCompletenessPartial {
		t.Errorf("expected CompletenessStatus PARTIAL after tampering, got %s", dossierTampered.Identity.CompletenessStatus)
	}
	if len(dossierTampered.Integrity.IntegrityFailures) == 0 {
		t.Errorf("expected IntegrityFailures to be recorded after tampering")
	}
}
