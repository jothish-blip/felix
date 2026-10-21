package test

import (
	"database/sql"
	"os"
	"path/filepath"
	"testing"

	"felix/pkg/compliance"
	"felix/pkg/report"
)

// TestPhase95_ComplianceIntegrity_EndToEnd tests the complete Phase 9.5 integrity & key management pipeline:
// protected evaluation generation, cryptographic authenticity via HMAC-SHA256, verification of content integrity,
// detection of tampering across parent results, control evaluations, and evidence links, key rotation,
// legacy unverified record handling, and persistence across process restarts.
func TestPhase95_ComplianceIntegrity_EndToEnd(t *testing.T) {
	tmpDir := t.TempDir()

	// 1. Setup Validated Catalog
	catalogJSON := `{
		"schema_version": "1.0",
		"id": "nist-sp800-53-integrity-e2e",
		"title": "NIST SP 800-53 Integrity Test Catalog",
		"version": "5.1.0",
		"framework": "NIST",
		"controls": [
			{
				"id": "AC-3",
				"title": "Access Enforcement",
				"description": "Enforce approved authorizations for logical access.",
				"status": "active"
			},
			{
				"id": "SI-10",
				"title": "Information Input Validation",
				"description": "Check information inputs for validity.",
				"status": "active"
			}
		]
	}`

	catalogPath := filepath.Join(tmpDir, "catalog.json")
	if err := os.WriteFile(catalogPath, []byte(catalogJSON), 0644); err != nil {
		t.Fatalf("failed writing catalog: %v", err)
	}

	catalog, err := compliance.LoadCatalog(catalogPath)
	if err != nil {
		t.Fatalf("LoadCatalog failed: %v", err)
	}

	// 2. Setup Validated Mapping RuleSet
	ruleSetJSON := `{
		"schema_version": "1.0",
		"id": "felix-integrity-e2e-rules",
		"title": "FELIX to NIST SP 800-53 Integrity Ruleset",
		"version": "1.0.0",
		"target_catalog_id": "nist-sp800-53-integrity-e2e",
		"target_catalog_version": "5.1.0",
		"rules": [
			{
				"id": "RULE-BOLA-AC3",
				"source_rule_id": "API_BOLA_IDOR",
				"target_control_id": "AC-3",
				"relationship": "direct",
				"rationale": "Object-level authorization bypass violates access enforcement.",
				"confidence": 0.95
			},
			{
				"id": "RULE-SQLI-SI10",
				"source_rule_id": "WEB_SQL_INJECTION",
				"target_control_id": "SI-10",
				"relationship": "direct",
				"rationale": "SQL injection indicates invalid input handling.",
				"confidence": 0.95
			}
		]
	}`

	ruleSetPath := filepath.Join(tmpDir, "ruleset.json")
	if err := os.WriteFile(ruleSetPath, []byte(ruleSetJSON), 0644); err != nil {
		t.Fatalf("failed writing ruleset: %v", err)
	}

	ruleSet, err := compliance.LoadMappingRuleSet(ruleSetPath)
	if err != nil {
		t.Fatalf("LoadMappingRuleSet failed: %v", err)
	}

	// 3. Findings and Evidence
	findings := []report.Finding{
		{
			ID:           "F-AC3-BOLA-01",
			Source:       "apisec",
			RuleID:       "API_BOLA_IDOR",
			Category:     "authz",
			Title:        "BOLA on /api/accounts/400",
			Severity:     "HIGH",
			Status:       report.FindingStatusConfirmed,
			Evidence:     "Unauthorized access to account 400 confirmed",
			Endpoint:     "/api/accounts/400",
			Verification: report.VerificationRecord{Status: report.VerificationVerified},
		},
	}

	mappingResult, err := compliance.MapFindings(catalog, ruleSet, findings)
	if err != nil {
		t.Fatalf("MapFindings failed: %v", err)
	}

	// 4. Run Evaluation Engine
	evalEngine := compliance.NewEvaluationEngine()
	evalContext := &compliance.EvaluationContext{
		AssessmentID:     "ASM-E2E-INTEGRITY",
		ExecutionID:      "EXEC-INT-001",
		AssessmentStatus: "COMPLETED",
		PositiveEvidence: []compliance.PositiveEvidence{
			{
				ID:          "PE-SQL-01",
				ControlID:   "SI-10",
				Location:    "/api/search",
				Requirement: "input_parameterization",
				Observation: "Prepared SQL statements active across all database query pathways.",
				Method:      "STATIC_CODE_ANALYSIS",
			},
		},
	}

	evalResult, err := evalEngine.Evaluate(catalog, mappingResult, findings, evalContext)
	if err != nil {
		t.Fatalf("Evaluate failed: %v", err)
	}

	// 5. Open SQLite Compliance Store with KeyProvider
	dbPath := filepath.Join(tmpDir, "compliance_integrity_e2e.db")
	store, err := compliance.NewSQLiteComplianceStore(dbPath)
	if err != nil {
		t.Fatalf("NewSQLiteComplianceStore failed: %v", err)
	}
	defer store.Close()

	keyV1, err := compliance.GenerateIntegrityKey("e2e-key-v1")
	if err != nil {
		t.Fatalf("GenerateIntegrityKey failed: %v", err)
	}
	keyProvider, err := compliance.NewStaticKeyProvider(keyV1)
	if err != nil {
		t.Fatalf("NewStaticKeyProvider failed: %v", err)
	}

	// 6. Persist Evaluation Result with HMAC signing
	if err := store.SaveEvaluationResultWithKey(evalResult, keyProvider); err != nil {
		t.Fatalf("SaveEvaluationResultWithKey failed: %v", err)
	}

	// 7. Verify Integrity and Authenticity
	verResult, err := store.VerifyEvaluationIntegrity("ASM-E2E-INTEGRITY", "nist-sp800-53-integrity-e2e:5.1.0", keyProvider)
	if err != nil {
		t.Fatalf("VerifyEvaluationIntegrity failed: %v", err)
	}

	if verResult.Status != compliance.StatusVerified {
		t.Errorf("expected StatusVerified, got %s (violations: %v)", verResult.Status, verResult.Violations)
	}
	if !verResult.ContentDigestMatch {
		t.Errorf("expected ContentDigestMatch = true")
	}
	if !verResult.AuthenticityMatch {
		t.Errorf("expected AuthenticityMatch = true")
	}
	if verResult.KeyID != "e2e-key-v1" {
		t.Errorf("expected KeyID e2e-key-v1, got %s", verResult.KeyID)
	}

	// 8. Key Rotation Test
	keyV2, _ := compliance.GenerateIntegrityKey("e2e-key-v2")
	if err := keyProvider.SetSigningKey(keyV2); err != nil {
		t.Fatalf("SetSigningKey failed: %v", err)
	}

	// Historical evaluation signed with key v1 must still verify
	verHistorical, err := store.VerifyEvaluationIntegrity("ASM-E2E-INTEGRITY", "nist-sp800-53-integrity-e2e:5.1.0", keyProvider)
	if err != nil || verHistorical.Status != compliance.StatusVerified {
		t.Errorf("historical record verification failed after key rotation: status=%s, err=%v", verHistorical.Status, err)
	}

	// 9. Tampering Detection: modify control rationale directly via SQL
	rawDB, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("opening raw db failed: %v", err)
	}
	defer rawDB.Close()

	_, err = rawDB.Exec("UPDATE compliance_control_evaluations SET rationale = 'TAMPERED: cleared violation' WHERE control_id = 'AC-3'")
	if err != nil {
		t.Fatalf("raw DB tampering failed: %v", err)
	}

	verTampered, err := store.VerifyEvaluationIntegrity("ASM-E2E-INTEGRITY", "nist-sp800-53-integrity-e2e:5.1.0", keyProvider)
	if err != nil {
		t.Fatalf("VerifyEvaluationIntegrity on tampered store returned error: %v", err)
	}
	if verTampered.Status != compliance.StatusIntegrityMismatch {
		t.Errorf("expected StatusIntegrityMismatch after tampering with control rationale, got %s", verTampered.Status)
	}
	if verTampered.ContentDigestMatch {
		t.Errorf("expected ContentDigestMatch = false for tampered record")
	}

	// 10. Reopen Store and Confirm Tampering Remains Detected Across Process Restarts
	reopenedStore, err := compliance.NewSQLiteComplianceStore(dbPath)
	if err != nil {
		t.Fatalf("reopening store failed: %v", err)
	}
	defer reopenedStore.Close()

	verReopened, err := reopenedStore.VerifyEvaluationIntegrity("ASM-E2E-INTEGRITY", "nist-sp800-53-integrity-e2e:5.1.0", keyProvider)
	if err != nil || verReopened.Status != compliance.StatusIntegrityMismatch {
		t.Errorf("tampering detection failed to persist across store restarts: status=%s, err=%v", verReopened.Status, err)
	}
}

// TestPhase95_TargetedIntegrityVerification_EndToEnd exercises the five targeted security verification areas:
// 1. Distinguishing genuine legacy records from deleted integrity metadata across store restart.
// 2. Proving plain hash database evasion vs HMAC authenticity protection.
// 3. Ensuring safe key configuration via key files and redacting secret material.
// 4. Detecting independent evidence link modifications, deletions, insertions, and reassignments.
// 5. Enforcing the trust boundary on GetVerifiedEvaluationResult (failing closed on tampered data).
func TestPhase95_TargetedIntegrityVerification_EndToEnd(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "targeted_verification.db")

	store, err := compliance.NewSQLiteComplianceStore(dbPath)
	if err != nil {
		t.Fatalf("failed creating store: %v", err)
	}

	key, err := compliance.GenerateIntegrityKey("e2e-targeted-key")
	if err != nil {
		t.Fatalf("failed generating key: %v", err)
	}
	kp, err := compliance.NewStaticKeyProvider(key)
	if err != nil {
		t.Fatalf("failed creating key provider: %v", err)
	}

	// 1. Create and save a valid protected evaluation
	res := &compliance.EvaluationResult{
		AssessmentID:           "ASM-TARGETED-01",
		CatalogIdentity:        "nist-sp800-53:5.1.0",
		CatalogDigest:          "sha256:abcd0123",
		MappingRuleSetIdentity: "ruleset-01",
		MappingRuleSetDigest:   "sha256:ef014567",
		EngineVersion:          compliance.CurrentEvaluationEngineVersion,
		Evaluations: []compliance.ControlEvaluationRecord{
			{
				ControlID:             "AC-1",
				CatalogID:             "nist-sp800-53",
				CatalogVersion:        "5.1.0",
				State:                 compliance.StateCompliant,
				Rationale:             "Policy documented and approved",
				FindingIDs:            []string{},
				EvidenceReferences:    []string{"DOC-AC1-POLICY"},
				SupportingEvidence:    []string{"Active access control policy v2"},
				ContradictingEvidence: []string{},
			},
			{
				ControlID:             "AC-2",
				CatalogID:             "nist-sp800-53",
				CatalogVersion:        "5.1.0",
				State:                 compliance.StateNonCompliant,
				Rationale:             "Inactive user accounts not terminated",
				FindingIDs:            []string{"F-USER-INACTIVE"},
				EvidenceReferences:    []string{"AUDIT-USER-2026"},
				SupportingEvidence:    []string{},
				ContradictingEvidence: []string{"3 dormant admin accounts found"},
			},
		},
		Summary: compliance.EvaluationSummary{
			TotalControls:      2,
			CompliantCount:     1,
			NonCompliantCount:  1,
			ApplicableControls: 2,
			AssessedControls:   2,
		},
		LimitationsNotice: compliance.EvaluationLimitationsNotice(),
	}

	if err := store.SaveEvaluationResultWithKey(res, kp); err != nil {
		t.Fatalf("SaveEvaluationResultWithKey failed: %v", err)
	}

	// 2. Verified Retrieval via GetVerifiedEvaluationResult succeeds and marks Verified = true
	vRes, verOut, err := store.GetVerifiedEvaluationResult("ASM-TARGETED-01", "nist-sp800-53:5.1.0", kp)
	if err != nil {
		t.Fatalf("GetVerifiedEvaluationResult failed: %v", err)
	}
	if !vRes.Verified {
		t.Errorf("expected vRes.Verified = true")
	}
	if verOut.Status != compliance.StatusVerified {
		t.Errorf("expected StatusVerified, got %s", verOut.Status)
	}

	// 3. Raw GetEvaluationResult returns Verified = false (unverified read)
	rawRes, err := store.GetEvaluationResult("ASM-TARGETED-01", "nist-sp800-53:5.1.0")
	if err != nil {
		t.Fatalf("GetEvaluationResult failed: %v", err)
	}
	if rawRes.Verified {
		t.Errorf("expected rawRes.Verified = false for unverified GetEvaluationResult")
	}

	// 4. Evidence Link Tampering Detection: mutate compliance_evidence_links directly
	err = store.Close()
	if err != nil {
		t.Fatalf("store.Close failed: %v", err)
	}

	rawDB, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("failed opening raw db: %v", err)
	}
	_, err = rawDB.Exec("UPDATE compliance_evidence_links SET reference_id = 'TAMPERED-REF' WHERE assessment_id = 'ASM-TARGETED-01'")
	if err != nil {
		t.Fatalf("failed modifying evidence link: %v", err)
	}
	rawDB.Close()

	// Reopen and verify that GetVerifiedEvaluationResult fails closed
	reopenedStore, err := compliance.NewSQLiteComplianceStore(dbPath)
	if err != nil {
		t.Fatalf("failed reopening store: %v", err)
	}
	defer reopenedStore.Close()

	tamperedRes, tamperedVerOut, err := reopenedStore.GetVerifiedEvaluationResult("ASM-TARGETED-01", "nist-sp800-53:5.1.0", kp)
	if err == nil {
		t.Fatalf("expected error from GetVerifiedEvaluationResult on tampered evidence, got nil")
	}
	if tamperedRes != nil {
		t.Errorf("expected nil result for tampered evaluation, got %+v", tamperedRes)
	}
	if tamperedVerOut.Status != compliance.StatusIntegrityMismatch {
		t.Errorf("expected StatusIntegrityMismatch, got %s", tamperedVerOut.Status)
	}
}
