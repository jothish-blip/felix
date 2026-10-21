package compliance

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"felix/pkg/report"
)

// ============================================================================
// AREA 1: LOGICAL DIGEST SENSITIVITY AND VOLATILE METADATA IMMUNITY
// ============================================================================

func TestDossier_Targeted_Digest_MaterialSourceIdentities(t *testing.T) {
	store := setupTestDossierStore(t)
	defer store.Close()

	clock := NewMockClock(time.Date(2026, 10, 21, 10, 0, 0, 0, time.UTC))
	svc := NewDossierService(store, clock)

	evalRes := sampleValidEvaluationResult("ASM-DIGEST-VERIFY")
	if err := store.SaveEvaluationResult(evalRes); err != nil {
		t.Fatalf("SaveEvaluationResult failed: %v", err)
	}

	dossier, err := svc.GenerateDossier(context.Background(), GenerateDossierRequest{
		AssessmentID: "ASM-DIGEST-VERIFY",
		CatalogID:    "nist-sp800-53-sample",
	})
	if err != nil {
		t.Fatalf("GenerateDossier failed: %v", err)
	}

	baseDigest := dossier.LogicalDigest
	if !strings.HasPrefix(baseDigest, "sha256:") {
		t.Fatalf("expected sha256 prefix for digest, got %q", baseDigest)
	}

	// 1. Changing ANY material source identity MUST change the logical digest
	materialMutations := []struct {
		name   string
		mutate func(d *ComplianceDossier)
	}{
		{"assessment_id", func(d *ComplianceDossier) { d.Identity.AssessmentID = "ASM-MUTATED-99" }},
		{"execution_id", func(d *ComplianceDossier) { d.Identity.ExecutionID = "EXEC-MUTATED-99" }},
		{"catalog_id", func(d *ComplianceDossier) { d.Identity.CatalogID = "cat-mutated-99" }},
		{"catalog_version", func(d *ComplianceDossier) { d.Identity.CatalogVersion = "9.9.9" }},
		{"catalog_digest", func(d *ComplianceDossier) {
			d.Identity.CatalogDigest = "sha256:9999999999999999999999999999999999999999999999999999999999999999"
		}},
		{"mapping_ruleset_id", func(d *ComplianceDossier) { d.Identity.MappingRuleSetID = "ruleset-mutated" }},
		{"mapping_ruleset_version", func(d *ComplianceDossier) { d.Identity.MappingRuleSetVersion = "2.0.0" }},
		{"mapping_ruleset_digest", func(d *ComplianceDossier) {
			d.Identity.MappingRuleSetDigest = "sha256:8888888888888888888888888888888888888888888888888888888888888888"
		}},
		{"applicable_policy_id", func(d *ComplianceDossier) { d.Identity.ApplicablePolicyID = "pol-mutated" }},
		{"applicable_policy_version", func(d *ComplianceDossier) { d.Identity.ApplicablePolicyVersion = "3.1.0" }},
		{"generation_mode", func(d *ComplianceDossier) { d.Identity.GenerationMode = DossierModeStrict }},
		{"completeness_status", func(d *ComplianceDossier) { d.Identity.CompletenessStatus = DossierCompletenessPartial }},
		{"control_rationale", func(d *ComplianceDossier) { d.Controls[0].Rationale = "Mutated rationale test" }},
		{"control_state", func(d *ComplianceDossier) { d.Controls[0].EvaluationState = StateCompliant }},
		{"summary_compliant_count", func(d *ComplianceDossier) { d.Summary.CompliantCount = 99 }},
	}

	for _, tc := range materialMutations {
		t.Run("material_"+tc.name, func(t *testing.T) {
			cloned := *dossier
			cloned.Controls = make([]DossierControlResult, len(dossier.Controls))
			copy(cloned.Controls, dossier.Controls)
			tc.mutate(&cloned)

			newDigest := ComputeDossierLogicalDigest(&cloned)
			if newDigest == baseDigest {
				t.Errorf("digest failed to change when mutating material field %q", tc.name)
			}
		})
	}

	// 2. Changing explicitly excluded volatile metadata MUST NOT change the logical digest
	volatileMutations := []struct {
		name   string
		mutate func(d *ComplianceDossier)
	}{
		{"generated_at", func(d *ComplianceDossier) { d.Identity.GeneratedAt = d.Identity.GeneratedAt.Add(48 * time.Hour) }},
		{"dossier_id", func(d *ComplianceDossier) { d.Identity.DossierID = "dossier:random-uuid-999" }},
		{"felix_version", func(d *ComplianceDossier) { d.Identity.FelixVersion = "9.9.9-test" }},
		{"source_revision", func(d *ComplianceDossier) { d.Identity.SourceRevision = "git-commit-abcdef123" }},
		{"logical_digest_field_itself", func(d *ComplianceDossier) {
			d.LogicalDigest = "sha256:0000000000000000000000000000000000000000000000000000000000000000"
		}},
	}

	for _, tc := range volatileMutations {
		t.Run("volatile_"+tc.name, func(t *testing.T) {
			cloned := *dossier
			tc.mutate(&cloned)

			newDigest := ComputeDossierLogicalDigest(&cloned)
			if newDigest != baseDigest {
				t.Errorf("digest incorrectly changed when mutating volatile field %q:\n  expected: %s\n  got:      %s",
					tc.name, baseDigest, newDigest)
			}
		})
	}
}

// ============================================================================
// AREA 3: EVIDENCE AND RECORD ASSOCIATION
// ============================================================================

func TestDossier_Targeted_CrossAssessmentAndExecutionEvidence(t *testing.T) {
	store := setupTestDossierStore(t)
	defer store.Close()

	clock := NewMockClock(time.Date(2026, 10, 21, 10, 0, 0, 0, time.UTC))
	svc := NewDossierService(store, clock)

	evalRes := sampleValidEvaluationResult("ASM-CROSS-01")
	if err := store.SaveEvaluationResult(evalRes); err != nil {
		t.Fatalf("SaveEvaluationResult failed: %v", err)
	}

	// Finding with cross-assessment provenance
	crossAssFinding := report.Finding{
		ID:       "F-CROSS-ASS",
		RuleID:   "RULE-AC-2",
		Title:    "Finding from another assessment",
		Severity: "HIGH",
		Category: "ACCESS_CONTROL",
		Provenance: &report.EvidenceProvenance{
			AssessmentID: "ASM-OTHER-PROJECT", // mismatch!
			ExecutionID:  "EXEC-DOSSIER-001",
		},
	}

	// Strict mode MUST fail closed on cross-assessment finding
	_, errStrictAss := svc.GenerateDossier(context.Background(), GenerateDossierRequest{
		AssessmentID:    "ASM-CROSS-01",
		CatalogID:       "nist-sp800-53-sample",
		Findings:        []report.Finding{crossAssFinding},
		StrictIntegrity: true,
	})
	if errStrictAss == nil {
		t.Fatal("expected strict mode to fail closed on cross-assessment finding, got nil error")
	}
	if !errors.Is(errStrictAss, ErrIntegrityMismatch) {
		t.Fatalf("expected ErrIntegrityMismatch for cross-assessment finding, got: %v", errStrictAss)
	}

	// Default mode MUST exclude cross-assessment finding and record limitation with partial coverage
	dossierDefAss, errDefAss := svc.GenerateDossier(context.Background(), GenerateDossierRequest{
		AssessmentID:    "ASM-CROSS-01",
		CatalogID:       "nist-sp800-53-sample",
		Findings:        []report.Finding{crossAssFinding},
		StrictIntegrity: false,
	})
	if errDefAss != nil {
		t.Fatalf("expected default mode to report limitation on cross-assessment finding, got error: %v", errDefAss)
	}
	if dossierDefAss.Identity.CompletenessStatus == DossierCompletenessComplete {
		t.Errorf("expected completeness status PARTIAL on cross-assessment finding, got %s", dossierDefAss.Identity.CompletenessStatus)
	}
	hasLimitation := false
	for _, lim := range dossierDefAss.Summary.Limitations {
		if strings.Contains(lim, "cross-assessment") {
			hasLimitation = true
			break
		}
	}
	if !hasLimitation {
		t.Errorf("expected cross-assessment limitation in dossier summary, got: %v", dossierDefAss.Summary.Limitations)
	}

	// Finding with cross-execution provenance
	crossExecFinding := report.Finding{
		ID:       "F-CROSS-EXEC",
		RuleID:   "RULE-AC-2",
		Title:    "Finding from another scan execution",
		Severity: "HIGH",
		Category: "ACCESS_CONTROL",
		Provenance: &report.EvidenceProvenance{
			AssessmentID: "ASM-CROSS-01",
			ExecutionID:  "EXEC-OLD-SCAN-999", // mismatch with EXEC-DOSSIER-001!
		},
	}

	// Strict mode MUST fail closed on cross-execution finding
	_, errStrictExec := svc.GenerateDossier(context.Background(), GenerateDossierRequest{
		AssessmentID:    "ASM-CROSS-01",
		CatalogID:       "nist-sp800-53-sample",
		Findings:        []report.Finding{crossExecFinding},
		StrictIntegrity: true,
	})
	if errStrictExec == nil {
		t.Fatal("expected strict mode to fail closed on cross-execution finding, got nil error")
	}
	if !errors.Is(errStrictExec, ErrIntegrityMismatch) {
		t.Fatalf("expected ErrIntegrityMismatch for cross-execution finding, got: %v", errStrictExec)
	}
}

func TestDossier_Targeted_FindingsLinkedToWrongControl(t *testing.T) {
	store := setupTestDossierStore(t)
	defer store.Close()

	clock := NewMockClock(time.Date(2026, 10, 21, 10, 0, 0, 0, time.UTC))
	svc := NewDossierService(store, clock)

	ruleset := &MappingRuleSet{
		SchemaVersion: "1.0",
		ID:            "ruleset-sample",
		Version:       "1.0.0",
		Rules: []MappingRule{
			{
				ID:              "MR-01",
				SourceRuleID:    "RULE-DORMANT",
				TargetControlID: "AC-1", // maps to AC-1, NOT AC-2!
				Relationship:    RelationshipDirect,
				Rationale:       "Dormant accounts map to AC-1 policy",
			},
		},
	}

	evalRes := sampleEvaluationWithAllStates("ASM-WRONG-CTRL")
	evalRes.MappingRuleSetIdentity = ruleset.Identity()
	evalRes.MappingRuleSetDigest = ruleset.Digest()
	if err := store.SaveEvaluationResult(evalRes); err != nil {
		t.Fatalf("SaveEvaluationResult failed: %v", err)
	}

	findings := []report.Finding{
		{
			ID:       "F-DORMANT-01",
			RuleID:   "RULE-DORMANT",
			Title:    "Dormant admin accounts",
			Severity: "HIGH",
		},
	}

	// Strict mode: finding linked to wrong control according to mapping ruleset must fail closed
	_, errStrict := svc.GenerateDossier(context.Background(), GenerateDossierRequest{
		AssessmentID:    "ASM-WRONG-CTRL",
		CatalogID:       "nist-sp800-53-sample",
		MappingRuleSet:  ruleset,
		Findings:        findings,
		StrictIntegrity: true,
	})
	if errStrict == nil {
		t.Fatal("expected strict mode to fail closed when finding is linked to wrong control, got nil")
	}
	if !errors.Is(errStrict, ErrIntegrityMismatch) {
		t.Fatalf("expected ErrIntegrityMismatch, got: %v", errStrict)
	}

	// Default mode: reports limitation, sets partial coverage, and does not assert verified linkage
	dossierDef, errDef := svc.GenerateDossier(context.Background(), GenerateDossierRequest{
		AssessmentID:    "ASM-WRONG-CTRL",
		CatalogID:       "nist-sp800-53-sample",
		MappingRuleSet:  ruleset,
		Findings:        findings,
		StrictIntegrity: false,
	})
	if errDef != nil {
		t.Fatalf("expected default mode to report limitation on wrong control, got error: %v", errDef)
	}
	if dossierDef.Identity.CompletenessStatus == DossierCompletenessComplete {
		t.Errorf("expected completeness status PARTIAL on wrong control mapping, got %s", dossierDef.Identity.CompletenessStatus)
	}
	hasLimitation := false
	for _, lim := range dossierDef.Summary.Limitations {
		if strings.Contains(lim, "wrong control") || strings.Contains(lim, "contradicts mapping") {
			hasLimitation = true
			break
		}
	}
	if !hasLimitation {
		t.Errorf("expected wrong control limitation in summary, got: %v", dossierDef.Summary.Limitations)
	}
}

func TestDossier_Targeted_RemediationLinkedToUnrelatedFindingOrControl(t *testing.T) {
	store := setupTestDossierStore(t)
	defer store.Close()

	clock := NewMockClock(time.Date(2026, 10, 21, 10, 0, 0, 0, time.UTC))
	svc := NewDossierService(store, clock)

	evalRes := sampleValidEvaluationResult("ASM-REM-UNRELATED")
	// In evalRes: AC-2 has finding F-DORMANT-01, AC-3 has F-BOLA-01. AC-1 has no findings.
	if err := store.SaveEvaluationResult(evalRes); err != nil {
		t.Fatalf("SaveEvaluationResult failed: %v", err)
	}

	// Sub-case A: Remediation record referencing an unassessed control (AC-99)
	remUnassessed := &RemediationRecord{
		ID:           "REM-UNRELATED-CTRL",
		FindingID:    "F-DORMANT-01",
		ControlID:    "AC-99", // unassessed control!
		AssessmentID: "ASM-REM-UNRELATED",
		Status:       RemediationStatusOpen,
		Severity:     "HIGH",
		AssignedAt:   time.Date(2026, 10, 21, 10, 0, 0, 0, time.UTC),
		SLAStartTime: time.Date(2026, 10, 21, 10, 0, 0, 0, time.UTC),
		Deadline:     time.Date(2026, 10, 28, 10, 0, 0, 0, time.UTC),
	}
	if err := store.SaveRemediationRecord(remUnassessed, nil); err != nil {
		t.Fatalf("SaveRemediationRecord failed: %v", err)
	}

	// Strict mode MUST fail closed on remediation referencing unassessed control
	_, errStrictCtrl := svc.GenerateDossier(context.Background(), GenerateDossierRequest{
		AssessmentID:       "ASM-REM-UNRELATED",
		CatalogID:          "nist-sp800-53-sample",
		IncludeRemediation: true,
		StrictIntegrity:    true,
	})
	if errStrictCtrl == nil {
		t.Fatal("expected strict mode to fail closed on remediation with unassessed control, got nil")
	}
	if !errors.Is(errStrictCtrl, ErrIntegrityMismatch) {
		t.Fatalf("expected ErrIntegrityMismatch, got: %v", errStrictCtrl)
	}

	// Sub-case B: Remediation record referencing an unrelated finding (F-BOLA-01 linked to AC-2 instead of AC-3)
	remUnrelatedFinding := &RemediationRecord{
		ID:           "REM-UNRELATED-FINDING",
		FindingID:    "F-BOLA-01", // BOLA is evaluated under AC-3, NOT AC-2!
		ControlID:    "AC-2",
		AssessmentID: "ASM-REM-UNRELATED",
		Status:       RemediationStatusOpen,
		Severity:     "HIGH",
		AssignedAt:   time.Date(2026, 10, 21, 10, 0, 0, 0, time.UTC),
		SLAStartTime: time.Date(2026, 10, 21, 10, 0, 0, 0, time.UTC),
		Deadline:     time.Date(2026, 10, 28, 10, 0, 0, 0, time.UTC),
	}
	if err := store.SaveRemediationRecord(remUnrelatedFinding, nil); err != nil {
		t.Fatalf("SaveRemediationRecord failed: %v", err)
	}

	// Strict mode MUST fail closed on unrelated finding association
	_, errStrictFinding := svc.GenerateDossier(context.Background(), GenerateDossierRequest{
		AssessmentID:       "ASM-REM-UNRELATED",
		CatalogID:          "nist-sp800-53-sample",
		IncludeRemediation: true,
		StrictIntegrity:    true,
	})
	if errStrictFinding == nil {
		t.Fatal("expected strict mode to fail closed on remediation with unrelated finding, got nil")
	}
	if !errors.Is(errStrictFinding, ErrIntegrityMismatch) {
		t.Fatalf("expected ErrIntegrityMismatch, got: %v", errStrictFinding)
	}

	// Default mode reports limitations, marks partial coverage, and excludes the invalid remediation records
	dossierDef, errDef := svc.GenerateDossier(context.Background(), GenerateDossierRequest{
		AssessmentID:       "ASM-REM-UNRELATED",
		CatalogID:          "nist-sp800-53-sample",
		IncludeRemediation: true,
		StrictIntegrity:    false,
	})
	if errDef != nil {
		t.Fatalf("expected default mode to report limitations without crashing, got error: %v", errDef)
	}
	if dossierDef.Identity.CompletenessStatus == DossierCompletenessComplete {
		t.Errorf("expected completeness status PARTIAL on unrelated remediation, got %s", dossierDef.Identity.CompletenessStatus)
	}
}

func TestDossier_Targeted_MismatchedCatalogAndMappingIdentities(t *testing.T) {
	store := setupTestDossierStore(t)
	defer store.Close()

	clock := NewMockClock(time.Date(2026, 10, 21, 10, 0, 0, 0, time.UTC))
	svc := NewDossierService(store, clock)

	evalRes := sampleValidEvaluationResult("ASM-MISMATCH-TEST")
	// evalRes has CatalogIdentity: "nist-sp800-53-sample:5.1.0"
	// and MappingRuleSetIdentity: "ruleset-sample:1.0.0"
	if err := store.SaveEvaluationResult(evalRes); err != nil {
		t.Fatalf("SaveEvaluationResult failed: %v", err)
	}

	// 1. Mismatched catalog version in strict mode
	mismatchedCat := &ControlCatalog{
		SchemaVersion: "1.0",
		ID:            "nist-sp800-53-sample",
		Version:       "6.0.0", // version mismatch!
		Controls:      []Control{{ID: "AC-1", Title: "Policy", Status: "active"}},
	}
	_, errCatStrict := svc.GenerateDossier(context.Background(), GenerateDossierRequest{
		AssessmentID:    "ASM-MISMATCH-TEST",
		CatalogID:       "nist-sp800-53-sample",
		Catalog:         mismatchedCat,
		StrictIntegrity: true,
	})
	if errCatStrict == nil || !errors.Is(errCatStrict, ErrIntegrityMismatch) {
		t.Fatalf("expected ErrIntegrityMismatch for catalog version mismatch in strict mode, got: %v", errCatStrict)
	}

	// 2. Mismatched mapping ruleset in strict mode
	mismatchedRuleset := &MappingRuleSet{
		SchemaVersion: "1.0",
		ID:            "ruleset-other-framework", // mismatch!
		Version:       "1.0.0",
	}
	_, errRuleStrict := svc.GenerateDossier(context.Background(), GenerateDossierRequest{
		AssessmentID:    "ASM-MISMATCH-TEST",
		CatalogID:       "nist-sp800-53-sample",
		MappingRuleSet:  mismatchedRuleset,
		StrictIntegrity: true,
	})
	if errRuleStrict == nil || !errors.Is(errRuleStrict, ErrIntegrityMismatch) {
		t.Fatalf("expected ErrIntegrityMismatch for mapping ruleset mismatch in strict mode, got: %v", errRuleStrict)
	}
}

func TestDossier_Targeted_LegacyRecordsNeverMarkedVerified(t *testing.T) {
	store := setupTestDossierStore(t)
	defer store.Close()

	clock := NewMockClock(time.Date(2026, 10, 21, 10, 0, 0, 0, time.UTC))
	svc := NewDossierService(store, clock)

	evalRes := sampleValidEvaluationResult("ASM-LEGACY-VERIF")
	if err := store.SaveEvaluationResult(evalRes); err != nil {
		t.Fatalf("SaveEvaluationResult failed: %v", err)
	}

	// Simulate genuine pre-integrity legacy record (no integrity version marker, no integrity row)
	_, _ = store.db.Exec("UPDATE compliance_evaluation_results SET integrity_version = '' WHERE assessment_id = 'ASM-LEGACY-VERIF'")
	_, _ = store.db.Exec("DELETE FROM compliance_integrity_records WHERE result_id LIKE 'evalres:ASM-LEGACY-VERIF%'")

	dossier, err := svc.GenerateDossier(context.Background(), GenerateDossierRequest{
		AssessmentID: "ASM-LEGACY-VERIF",
		CatalogID:    "nist-sp800-53-sample",
	})
	if err != nil {
		t.Fatalf("GenerateDossier failed: %v", err)
	}

	// Verify that the evaluation integrity status is unverified legacy
	if dossier.Integrity.EvaluationIntegrityStatus == StatusVerified {
		t.Errorf("legacy record must NEVER be marked verified")
	}
	if dossier.Integrity.EvaluationIntegrityStatus != StatusUnverifiedLegacy {
		t.Errorf("expected StatusUnverifiedLegacy, got %s", dossier.Integrity.EvaluationIntegrityStatus)
	}

	// Verified source records must NOT contain the legacy evaluation
	for _, rec := range dossier.Integrity.VerifiedSourceRecords {
		if strings.Contains(rec, "ASM-LEGACY-VERIF") {
			t.Errorf("legacy record must NOT be in VerifiedSourceRecords: %s", rec)
		}
	}

	// Must be present in UnverifiedLegacyRecords
	foundLegacy := false
	for _, rec := range dossier.Integrity.UnverifiedLegacyRecords {
		if strings.Contains(rec, "ASM-LEGACY-VERIF") {
			foundLegacy = true
			break
		}
	}
	if !foundLegacy {
		t.Errorf("expected legacy record in UnverifiedLegacyRecords, got: %v", dossier.Integrity.UnverifiedLegacyRecords)
	}

	// Evidence entries must be marked UNVERIFIED with Verified=false
	for _, ev := range dossier.Evidence {
		if ev.Verified {
			t.Errorf("evidence entry under legacy evaluation must have Verified=false, got true for %s", ev.EvidenceID)
		}
		if ev.VerificationStatus == "VERIFIED" {
			t.Errorf("evidence entry under legacy evaluation must not have VerificationStatus=VERIFIED for %s", ev.EvidenceID)
		}
	}
}

// ============================================================================
// AREA 4: OUTPUT SAFETY AND HOSTILE/TRUNCATED INPUTS
// ============================================================================

func TestDossier_Targeted_LoadingHostileAndTruncatedInputs(t *testing.T) {
	// 1. Truncated JSON
	truncatedJSON := []byte(`{"identity": {"schema_version": "felix.compliance.dossier.v1", "assessment_id": "ASM`)
	_, errTrunc := LoadDossierFromJSON(truncatedJSON)
	if errTrunc == nil {
		t.Error("expected error for truncated JSON payload, got nil")
	}

	// 2. Empty payload
	_, errEmpty := LoadDossierFromJSON([]byte(""))
	if errEmpty == nil {
		t.Error("expected error for empty JSON payload, got nil")
	}

	// 3. Malformed JSON with unknown fields (DisallowUnknownFields)
	unknownFieldJSON := []byte(`{
		"identity": {
			"schema_version": "felix.compliance.dossier.v1",
			"assessment_id": "ASM-01",
			"catalog_id": "cat-01",
			"generated_at": "2026-10-21T10:00:00Z"
		},
		"unauthorized_payload": "injection"
	}`)
	_, errUnknown := LoadDossierFromJSON(unknownFieldJSON)
	if errUnknown == nil {
		t.Error("expected error for unknown fields in JSON payload, got nil")
	}

	// 4. Dossier with tampered logical digest
	validJSON := []byte(`{
		"identity": {
			"dossier_id": "dossier:ASM-01:cat-01",
			"schema_version": "felix.compliance.dossier.v1",
			"generated_at": "2026-10-21T10:00:00Z",
			"assessment_id": "ASM-01",
			"catalog_id": "cat-01",
			"generation_mode": "default",
			"completeness_status": "PARTIAL"
		},
		"summary": {
			"overall_status": "COMPLETED",
			"completion_status": "COMPLETED",
			"total_controls": 0
		},
		"controls": [],
		"findings": [],
		"evidence": [],
		"remediation": [],
		"integrity": {
			"limitations_notice": "notice",
			"dossier_authenticity_statement": "statement"
		},
		"logical_digest": "sha256:0000000000000000000000000000000000000000000000000000000000000000"
	}`)
	_, errTamperedDigest := LoadDossierFromJSON(validJSON)
	if errTamperedDigest == nil || !errors.Is(errTamperedDigest, ErrDossierDigestMismatch) {
		t.Errorf("expected ErrDossierDigestMismatch for tampered logical digest, got: %v", errTamperedDigest)
	}

	// 5. Unsupported schema version
	unsupportedSchemaJSON := []byte(`{
		"identity": {
			"schema_version": "felix.compliance.dossier.v999",
			"assessment_id": "ASM-01",
			"catalog_id": "cat-01",
			"generated_at": "2026-10-21T10:00:00Z"
		}
	}`)
	_, errUnsupportedSchema := LoadDossierFromJSON(unsupportedSchemaJSON)
	if errUnsupportedSchema == nil || !errors.Is(errUnsupportedSchema, ErrUnsupportedDossierSchema) {
		t.Errorf("expected ErrUnsupportedDossierSchema, got: %v", errUnsupportedSchema)
	}

	// 6. Directory passed to LoadDossierFromFile
	tmpDir := t.TempDir()
	_, errDir := LoadDossierFromFile(tmpDir)
	if errDir == nil {
		t.Error("expected error when passing directory to LoadDossierFromFile, got nil")
	}

	// 7. Non-existent file passed to LoadDossierFromFile
	nonExistent := filepath.Join(tmpDir, "non_existent.json")
	_, errNonExist := LoadDossierFromFile(nonExistent)
	if errNonExist == nil {
		t.Error("expected error for non-existent file, got nil")
	}

	// 8. Empty path passed to LoadDossierFromFile
	_, errEmptyPath := LoadDossierFromFile("")
	if errEmptyPath == nil {
		t.Error("expected error for empty file path, got nil")
	}
}
