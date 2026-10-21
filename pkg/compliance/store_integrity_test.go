package compliance

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// 1. Valid save and verify with plain hash (content integrity only)
func TestStoreIntegrity_1_ValidSaveAndVerify_PlainHash(t *testing.T) {
	store := newTestStore(t)
	res := sampleValidEvaluationResult("ASM-INT-PLAIN")

	if err := store.SaveEvaluationResult(res); err != nil {
		t.Fatalf("SaveEvaluationResult failed: %v", err)
	}

	result, err := store.VerifyEvaluationIntegrity("ASM-INT-PLAIN", "nist-sp800-53-sample", nil)
	if err != nil {
		t.Fatalf("VerifyEvaluationIntegrity failed: %v", err)
	}

	if result.Status != StatusIntegrityOnly {
		t.Errorf("expected StatusIntegrityOnly, got %s (violations: %v)", result.Status, result.Violations)
	}
	if !result.ContentDigestMatch {
		t.Errorf("expected ContentDigestMatch = true")
	}
	if result.AuthenticityMatch {
		t.Errorf("expected AuthenticityMatch = false for plain hash")
	}
	if !result.EvidenceIntegrity.MetadataVerified {
		t.Errorf("expected EvidenceIntegrity.MetadataVerified = true")
	}
}

// 2. Valid save and verify with KeyProvider (cryptographic authenticity)
func TestStoreIntegrity_2_ValidSaveAndVerify_HMACSigned(t *testing.T) {
	store := newTestStore(t)
	key, _ := GenerateIntegrityKey("compliance-prod-key-1")
	kp, _ := NewStaticKeyProvider(key)

	res := sampleValidEvaluationResult("ASM-INT-HMAC")
	if err := store.SaveEvaluationResultWithKey(res, kp); err != nil {
		t.Fatalf("SaveEvaluationResultWithKey failed: %v", err)
	}

	result, err := store.VerifyEvaluationIntegrity("ASM-INT-HMAC", "nist-sp800-53-sample", kp)
	if err != nil {
		t.Fatalf("VerifyEvaluationIntegrity failed: %v", err)
	}

	if result.Status != StatusVerified {
		t.Errorf("expected StatusVerified, got %s (violations: %v)", result.Status, result.Violations)
	}
	if !result.ContentDigestMatch {
		t.Errorf("expected ContentDigestMatch = true")
	}
	if !result.AuthenticityMatch {
		t.Errorf("expected AuthenticityMatch = true for HMAC-signed record")
	}
	if result.KeyID != "compliance-prod-key-1" {
		t.Errorf("expected key ID compliance-prod-key-1, got %s", result.KeyID)
	}
	if result.Algorithm != AlgorithmHMACSHA256 {
		t.Errorf("expected algorithm %s, got %s", AlgorithmHMACSHA256, result.Algorithm)
	}

	// Verify integrity record directly in DB
	intRec, err := store.GetIntegrityRecord(result.ResultID)
	if err != nil {
		t.Fatalf("GetIntegrityRecord failed: %v", err)
	}
	if intRec.KeyID != "compliance-prod-key-1" || intRec.SignatureTag == "" {
		t.Errorf("unexpected integrity record values: %+v", intRec)
	}
}

// 3. Tampering with parent result fields is detected
func TestStoreIntegrity_3_ParentTamperingDetected(t *testing.T) {
	store := newTestStore(t)
	key, _ := GenerateIntegrityKey("compliance-key")
	kp, _ := NewStaticKeyProvider(key)

	res := sampleValidEvaluationResult("ASM-INT-PARENT")
	_ = store.SaveEvaluationResultWithKey(res, kp)

	// Tamper with parent result record via direct SQL
	_, err := store.db.Exec("UPDATE compliance_evaluation_results SET catalog_identity = 'malicious-catalog:9.9' WHERE assessment_id = ?", "ASM-INT-PARENT")
	if err != nil {
		t.Fatalf("direct SQL update failed: %v", err)
	}

	result, err := store.VerifyEvaluationIntegrity("ASM-INT-PARENT", "malicious-catalog:9.9", kp)
	if err != nil {
		t.Fatalf("VerifyEvaluationIntegrity failed: %v", err)
	}

	if result.Status != StatusIntegrityMismatch {
		t.Errorf("expected StatusIntegrityMismatch for tampered parent record, got %s", result.Status)
	}
	if result.ContentDigestMatch {
		t.Errorf("expected ContentDigestMatch = false")
	}
}

// 4. Tampering with control evaluations is detected
func TestStoreIntegrity_4_ControlTamperingDetected(t *testing.T) {
	store := newTestStore(t)
	key, _ := GenerateIntegrityKey("compliance-key")
	kp, _ := NewStaticKeyProvider(key)

	res := sampleValidEvaluationResult("ASM-INT-CTRL")
	_ = store.SaveEvaluationResultWithKey(res, kp)

	// Tamper: flip non_compliant state to compliant via direct SQL
	_, err := store.db.Exec("UPDATE compliance_control_evaluations SET state = 'compliant', rationale = 'Tampered: silently claiming compliant' WHERE assessment_id = ? AND control_id = 'AC-3'", "ASM-INT-CTRL")
	if err != nil {
		t.Fatalf("direct SQL update failed: %v", err)
	}

	result, err := store.VerifyEvaluationIntegrity("ASM-INT-CTRL", "nist-sp800-53-sample", kp)
	if err != nil {
		t.Fatalf("VerifyEvaluationIntegrity failed: %v", err)
	}

	if result.Status != StatusIntegrityMismatch {
		t.Errorf("expected StatusIntegrityMismatch for tampered control record, got %s", result.Status)
	}
	if result.ContentDigestMatch {
		t.Errorf("expected ContentDigestMatch = false")
	}
	if result.AuthenticityMatch {
		t.Errorf("expected AuthenticityMatch = false")
	}
}

// 5. Tampering with evidence references is detected
func TestStoreIntegrity_5_EvidenceTamperingDetected(t *testing.T) {
	store := newTestStore(t)
	key, _ := GenerateIntegrityKey("compliance-key")
	kp, _ := NewStaticKeyProvider(key)

	res := sampleValidEvaluationResult("ASM-INT-EV")
	_ = store.SaveEvaluationResultWithKey(res, kp)

	// Tamper: alter reference_id in compliance_evidence_links
	_, err := store.db.Exec("UPDATE compliance_evidence_links SET reference_id = 'TAMPERED-REF' WHERE assessment_id = ?", "ASM-INT-EV")
	if err != nil {
		t.Fatalf("direct SQL update failed: %v", err)
	}

	result, err := store.VerifyEvaluationIntegrity("ASM-INT-EV", "nist-sp800-53-sample", kp)
	if err != nil {
		t.Fatalf("VerifyEvaluationIntegrity failed: %v", err)
	}

	if result.Status != StatusIntegrityMismatch {
		t.Errorf("expected StatusIntegrityMismatch for tampered evidence links, got %s", result.Status)
	}
}

// 6. Missing integrity record on protected vs legacy evaluations
func TestStoreIntegrity_6_MissingIntegrityRecord_LegacyDetected(t *testing.T) {
	store := newTestStore(t)

	// 6A. Genuine pre-integrity legacy record (integrity_version is empty)
	resLegacy := sampleValidEvaluationResult("ASM-INT-GENUINE-LEGACY")
	resIDLegacy := computeEvaluationResultID(resLegacy)
	catID, catVer := extractCatalogIDAndVersion(resLegacy.CatalogIdentity, resLegacy.Evaluations)

	// Insert evaluation record directly without integrity_version or integrity record
	_, err := store.db.Exec(`
		INSERT INTO compliance_evaluation_results (
			id, assessment_id, catalog_identity, catalog_id, catalog_version,
			catalog_digest, engine_version, result_digest, total_controls, compliant_count,
			non_compliant_count, partially_compliant_count, not_assessed_count,
			insufficient_evidence_count, not_applicable_count, error_count,
			applicable_controls, assessed_controls, evaluated_at, created_at, updated_at,
			integrity_version
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1, 1, 0, 0, 0, 0, 0, 0, 1, 1, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, '');
	`, resIDLegacy, resLegacy.AssessmentID, resLegacy.CatalogIdentity, catID, catVer, resLegacy.CatalogDigest, resLegacy.EngineVersion, resLegacy.Digest())
	if err != nil {
		t.Fatalf("failed inserting legacy evaluation record: %v", err)
	}

	resultLegacy, err := store.VerifyEvaluationIntegrity("ASM-INT-GENUINE-LEGACY", "nist-sp800-53-sample", nil)
	if err != nil {
		t.Fatalf("VerifyEvaluationIntegrity on legacy record failed: %v", err)
	}
	if resultLegacy.Status != StatusUnverifiedLegacy {
		t.Errorf("expected StatusUnverifiedLegacy for genuine pre-integrity record, got %s", resultLegacy.Status)
	}

	// 6B. Protected record whose integrity record was deleted (TAMPERING)
	resProtected := sampleValidEvaluationResult("ASM-INT-DELETED-INTEGRITY")
	_ = store.SaveEvaluationResult(resProtected)

	// Delete integrity record from protected evaluation
	_, err = store.db.Exec("DELETE FROM compliance_integrity_records WHERE result_id LIKE 'evalres:ASM-INT-DELETED-INTEGRITY%'")
	if err != nil {
		t.Fatalf("direct SQL delete failed: %v", err)
	}

	resultDeleted, err := store.VerifyEvaluationIntegrity("ASM-INT-DELETED-INTEGRITY", "nist-sp800-53-sample", nil)
	if err != nil {
		t.Fatalf("VerifyEvaluationIntegrity failed: %v", err)
	}

	// Must be flagged as INTEGRITY_MISMATCH (tampering), NEVER misclassified as legacy unverified!
	if resultDeleted.Status != StatusIntegrityMismatch {
		t.Errorf("expected StatusIntegrityMismatch for protected record with deleted integrity metadata, got %s", resultDeleted.Status)
	}
}

// 7. Deleted or detached control row is detected
func TestStoreIntegrity_7_DeletedControlRowDetected(t *testing.T) {
	store := newTestStore(t)
	key, _ := GenerateIntegrityKey("compliance-key")
	kp, _ := NewStaticKeyProvider(key)

	res := sampleValidEvaluationResult("ASM-INT-DELETE-ROW")
	_ = store.SaveEvaluationResultWithKey(res, kp)

	// Delete one control evaluation row directly from SQLite
	_, err := store.db.Exec("DELETE FROM compliance_control_evaluations WHERE assessment_id = ? AND control_id = 'SI-10'", "ASM-INT-DELETE-ROW")
	if err != nil {
		t.Fatalf("direct SQL delete failed: %v", err)
	}

	result, err := store.VerifyEvaluationIntegrity("ASM-INT-DELETE-ROW", "nist-sp800-53-sample", kp)
	if err != nil {
		t.Fatalf("VerifyEvaluationIntegrity failed: %v", err)
	}

	if result.Status != StatusIntegrityMismatch {
		t.Errorf("expected StatusIntegrityMismatch when control row is deleted, got %s", result.Status)
	}
}

// 8. Unknown or missing key is safely reported
func TestStoreIntegrity_8_UnknownOrMissingKey(t *testing.T) {
	store := newTestStore(t)
	key1, _ := GenerateIntegrityKey("key-1")
	kp1, _ := NewStaticKeyProvider(key1)

	res := sampleValidEvaluationResult("ASM-INT-KEY-TEST")
	_ = store.SaveEvaluationResultWithKey(res, kp1)

	// 1. Verify with KeyProvider that doesn't know key-1
	key2, _ := GenerateIntegrityKey("key-2")
	kp2, _ := NewStaticKeyProvider(key2)

	result1, err := store.VerifyEvaluationIntegrity("ASM-INT-KEY-TEST", "nist-sp800-53-sample", kp2)
	if err != nil {
		t.Fatalf("expected verification result, got error: %v", err)
	}
	if result1.Status != StatusUnknownKey {
		t.Errorf("expected StatusUnknownKey, got %s", result1.Status)
	}

	// 2. Verify with nil KeyProvider on HMAC-signed record
	result2, err := store.VerifyEvaluationIntegrity("ASM-INT-KEY-TEST", "nist-sp800-53-sample", nil)
	if err != nil {
		t.Fatalf("expected verification result, got error: %v", err)
	}
	if result2.Status != StatusVerificationUnavailable {
		t.Errorf("expected StatusVerificationUnavailable when key provider is nil for signed record, got %s", result2.Status)
	}
}

// 9. Reopening database preserves integrity verification
func TestStoreIntegrity_9_PersistenceSurvivesClosure(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "compliance_integrity_survive.db")

	key, _ := GenerateIntegrityKey("survive-key")
	kp, _ := NewStaticKeyProvider(key)

	// 1. Open, save with key, and close
	store1, err := NewSQLiteComplianceStore(dbPath)
	if err != nil {
		t.Fatalf("NewSQLiteComplianceStore 1 failed: %v", err)
	}
	res := sampleValidEvaluationResult("ASM-INT-SURVIVE")
	if err := store1.SaveEvaluationResultWithKey(res, kp); err != nil {
		t.Fatalf("SaveEvaluationResultWithKey failed: %v", err)
	}
	if err := store1.Close(); err != nil {
		t.Fatalf("store1.Close failed: %v", err)
	}

	// 2. Reopen and verify
	store2, err := NewSQLiteComplianceStore(dbPath)
	if err != nil {
		t.Fatalf("NewSQLiteComplianceStore 2 failed: %v", err)
	}
	defer store2.Close()

	result, err := store2.VerifyEvaluationIntegrity("ASM-INT-SURVIVE", "nist-sp800-53-sample", kp)
	if err != nil {
		t.Fatalf("VerifyEvaluationIntegrity on reopened store failed: %v", err)
	}
	if result.Status != StatusVerified {
		t.Errorf("expected StatusVerified on reopened store, got %s (violations: %v)", result.Status, result.Violations)
	}
}

// 10. Concern 1: Distinguish legacy records from removed integrity metadata across database reopening
func TestStoreIntegrity_10_Concern1_ReopenedScenarios(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "concern1_test.db")

	store, err := NewSQLiteComplianceStore(dbPath)
	if err != nil {
		t.Fatalf("failed opening store: %v", err)
	}

	key, _ := GenerateIntegrityKey("c1-key")
	kp, _ := NewStaticKeyProvider(key)

	// A: Genuine pre-integrity legacy evaluation
	resLegacy := sampleValidEvaluationResult("ASM-C1-LEGACY")
	resIDLegacy := computeEvaluationResultID(resLegacy)
	catID, catVer := extractCatalogIDAndVersion(resLegacy.CatalogIdentity, resLegacy.Evaluations)
	_, err = store.db.Exec(`
		INSERT INTO compliance_evaluation_results (
			id, assessment_id, catalog_identity, catalog_id, catalog_version,
			catalog_digest, engine_version, result_digest, total_controls, compliant_count,
			non_compliant_count, partially_compliant_count, not_assessed_count,
			insufficient_evidence_count, not_applicable_count, error_count,
			applicable_controls, assessed_controls, evaluated_at, created_at, updated_at,
			integrity_version
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1, 1, 0, 0, 0, 0, 0, 0, 1, 1, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, '');
	`, resIDLegacy, resLegacy.AssessmentID, resLegacy.CatalogIdentity, catID, catVer, resLegacy.CatalogDigest, resLegacy.EngineVersion, resLegacy.Digest())
	if err != nil {
		t.Fatalf("failed inserting legacy evaluation: %v", err)
	}

	// B: Protected evaluation with deleted integrity row
	resDeleted := sampleValidEvaluationResult("ASM-C1-DELETED")
	if err := store.SaveEvaluationResultWithKey(resDeleted, kp); err != nil {
		t.Fatalf("failed saving protected evaluation: %v", err)
	}
	resIDDeleted := computeEvaluationResultID(resDeleted)
	if _, err := store.db.Exec("DELETE FROM compliance_integrity_records WHERE result_id = ?", resIDDeleted); err != nil {
		t.Fatalf("failed deleting integrity row: %v", err)
	}

	// C: Protected evaluation with corrupted integrity metadata
	resCorrupt := sampleValidEvaluationResult("ASM-C1-CORRUPT")
	if err := store.SaveEvaluationResultWithKey(resCorrupt, kp); err != nil {
		t.Fatalf("failed saving protected evaluation: %v", err)
	}
	resIDCorrupt := computeEvaluationResultID(resCorrupt)
	if _, err := store.db.Exec("UPDATE compliance_integrity_records SET format_version = 'corrupted-v9', canonical_digest = 'bad-sha' WHERE result_id = ?", resIDCorrupt); err != nil {
		t.Fatalf("failed corrupting integrity row: %v", err)
	}

	// Close database
	if err := store.Close(); err != nil {
		t.Fatalf("failed closing store: %v", err)
	}

	// Reopen database and verify all three scenarios persist
	reopened, err := NewSQLiteComplianceStore(dbPath)
	if err != nil {
		t.Fatalf("failed reopening store: %v", err)
	}
	defer reopened.Close()

	// Scenario A: Genuine legacy evaluation reports UNVERIFIED_LEGACY
	verLegacy, err := reopened.VerifyEvaluationIntegrity("ASM-C1-LEGACY", "nist-sp800-53-sample", kp)
	if err != nil {
		t.Fatalf("VerifyEvaluationIntegrity legacy failed: %v", err)
	}
	if verLegacy.Status != StatusUnverifiedLegacy {
		t.Errorf("expected StatusUnverifiedLegacy for genuine legacy, got %s", verLegacy.Status)
	}

	// Scenario B: Protected evaluation with deleted integrity row reports INTEGRITY_MISMATCH (never unverified legacy!)
	verDeleted, err := reopened.VerifyEvaluationIntegrity("ASM-C1-DELETED", "nist-sp800-53-sample", kp)
	if err != nil {
		t.Fatalf("VerifyEvaluationIntegrity deleted failed: %v", err)
	}
	if verDeleted.Status != StatusIntegrityMismatch {
		t.Errorf("expected StatusIntegrityMismatch for deleted integrity row, got %s", verDeleted.Status)
	}

	// Scenario C: Corrupted integrity metadata reports INTEGRITY_MISMATCH
	verCorrupt, err := reopened.VerifyEvaluationIntegrity("ASM-C1-CORRUPT", "nist-sp800-53-sample", kp)
	if err != nil {
		t.Fatalf("VerifyEvaluationIntegrity corrupt failed: %v", err)
	}
	if verCorrupt.Status != StatusIntegrityMismatch {
		t.Errorf("expected StatusIntegrityMismatch for corrupted metadata, got %s", verCorrupt.Status)
	}
}

// 11. Concern 2: Plain-hash evasion vs HMAC authenticity protection
func TestStoreIntegrity_11_Concern2_PlainHashEvasionVsHMACProtection(t *testing.T) {
	store := newTestStore(t)
	key, _ := GenerateIntegrityKey("c2-hmac-key")
	kp, _ := NewStaticKeyProvider(key)

	// 11A: Plain hash (AlgorithmNone): Attacker modifies content AND recomputes local digest
	resPlain := sampleValidEvaluationResult("ASM-C2-PLAIN")
	if err := store.SaveEvaluationResult(resPlain); err != nil {
		t.Fatalf("SaveEvaluationResult failed: %v", err)
	}
	resIDPlain := computeEvaluationResultID(resPlain)

	// Mutate control evaluation rationale in SQLite
	_, err := store.db.Exec("UPDATE compliance_control_evaluations SET rationale = 'attacker-modified-rationale' WHERE result_id = ?", resIDPlain)
	if err != nil {
		t.Fatalf("failed updating rationale: %v", err)
	}

	// Re-query the mutated evaluation and compute the new matching canonical digest
	mutatedRes, _, err := store.getEvaluationResultUnlocked(resIDPlain, "")
	if err != nil {
		t.Fatalf("failed retrieving mutated res: %v", err)
	}
	// Query all evidence links for this evaluation result
	var links []EvaluationEvidenceRecord
	evRows, err := store.db.Query(`
		SELECT l.id, l.evaluation_id, l.assessment_id, l.control_id, l.evidence_type, l.reference_id, COALESCE(l.detail, ''), l.created_at
		FROM compliance_evidence_links l
		JOIN compliance_control_evaluations c ON l.evaluation_id = c.id
		WHERE c.result_id = ?
		ORDER BY l.control_id ASC, l.evaluation_id ASC, l.evidence_type ASC, l.reference_id ASC;
	`, resIDPlain)
	if err != nil {
		t.Fatalf("failed querying evidence links: %v", err)
	}
	defer evRows.Close()
	for evRows.Next() {
		var rec EvaluationEvidenceRecord
		if err := evRows.Scan(&rec.ID, &rec.EvaluationID, &rec.AssessmentID, &rec.ControlID, &rec.EvidenceType, &rec.ReferenceID, &rec.Detail, &rec.CreatedAt); err != nil {
			t.Fatalf("failed scanning link: %v", err)
		}
		links = append(links, rec)
	}

	newPayload, err := BuildCanonicalIntegrityPayload(mutatedRes, links)
	if err != nil {
		t.Fatalf("failed building canonical payload: %v", err)
	}
	newDigest, _, err := ComputeCanonicalDigest(newPayload)
	if err != nil {
		t.Fatalf("failed computing canonical digest: %v", err)
	}

	// Attacker updates stored digest to match the forged content
	_, err = store.db.Exec("UPDATE compliance_integrity_records SET canonical_digest = ? WHERE result_id = ?", newDigest, resIDPlain)
	if err != nil {
		t.Fatalf("failed updating canonical digest: %v", err)
	}

	// In plain hash mode, local digest check passes (INTEGRITY_ONLY) because no secret key binds authenticity!
	verPlain, err := store.VerifyEvaluationIntegrity("ASM-C2-PLAIN", "nist-sp800-53-sample", nil)
	if err != nil {
		t.Fatalf("VerifyEvaluationIntegrity failed: %v", err)
	}
	if verPlain.Status != StatusIntegrityOnly {
		t.Errorf("expected StatusIntegrityOnly for forged plain digest, got %s (violations: %v)", verPlain.Status, verPlain.Violations)
	}

	// 11B: HMAC mode (AlgorithmHMACSHA256): Attacker attempts same attack, but cannot forge HMAC signature tag!
	resHMAC := sampleValidEvaluationResult("ASM-C2-HMAC")
	if err := store.SaveEvaluationResultWithKey(resHMAC, kp); err != nil {
		t.Fatalf("SaveEvaluationResultWithKey failed: %v", err)
	}
	resIDHMAC := computeEvaluationResultID(resHMAC)

	// Mutate rationale
	_, err = store.db.Exec("UPDATE compliance_control_evaluations SET rationale = 'attacker-modified-rationale' WHERE result_id = ?", resIDHMAC)
	if err != nil {
		t.Fatalf("failed updating rationale: %v", err)
	}
	// Re-query and update canonical_digest
	mutatedHMAC, _, err := store.getEvaluationResultUnlocked(resIDHMAC, "")
	if err != nil {
		t.Fatalf("failed retrieving mutated HMAC res: %v", err)
	}
	newHMACPayload, _ := BuildCanonicalIntegrityPayload(mutatedHMAC, links)
	newHMACDigest, _, _ := ComputeCanonicalDigest(newHMACPayload)
	_, _ = store.db.Exec("UPDATE compliance_integrity_records SET canonical_digest = ? WHERE result_id = ?", newHMACDigest, resIDHMAC)

	// Verification MUST FAIL CLOSED with StatusIntegrityMismatch because HMAC signature tag does not match!
	verHMAC, err := store.VerifyEvaluationIntegrity("ASM-C2-HMAC", "nist-sp800-53-sample", kp)
	if err != nil {
		t.Fatalf("VerifyEvaluationIntegrity HMAC failed: %v", err)
	}
	if verHMAC.Status != StatusIntegrityMismatch {
		t.Errorf("expected StatusIntegrityMismatch for forged HMAC content, got %s", verHMAC.Status)
	}

	// 11C: HMAC fails closed when key is missing (never silently falls back to plain hash)
	verNoKey, err := store.VerifyEvaluationIntegrity("ASM-C2-HMAC", "nist-sp800-53-sample", nil)
	if err != nil {
		t.Fatalf("VerifyEvaluationIntegrity nil key failed: %v", err)
	}
	if verNoKey.Status != StatusVerificationUnavailable {
		t.Errorf("expected StatusVerificationUnavailable when key provider is nil for HMAC record, got %s", verNoKey.Status)
	}
}

// 12. Concern 3: Audit CLI secret exposure and safe key file handling
func TestStoreIntegrity_12_Concern3_KeyManagementAndRedaction(t *testing.T) {
	// 12A: Key shorter than 32 bytes is rejected
	shortKey := &IntegrityKey{
		ID:        "short-key",
		Algorithm: AlgorithmHMACSHA256,
		Material:  []byte("too-short-key"),
	}
	if err := shortKey.Validate(); !errors.Is(err, ErrInvalidKeyMaterial) {
		t.Errorf("expected ErrInvalidKeyMaterial for short key, got %v", err)
	}

	// 12B: Secret redaction in String() and JSON
	validKey, err := GenerateIntegrityKey("redaction-test")
	if err != nil {
		t.Fatalf("GenerateIntegrityKey failed: %v", err)
	}
	strRep := validKey.String()
	if strRep == "" || string(validKey.Material) != "" && string(validKey.Material) == strRep {
		t.Errorf("String() leaked key material: %s", strRep)
	}
	jsonBytes, err := json.Marshal(validKey)
	if err != nil {
		t.Fatalf("json.Marshal failed: %v", err)
	}
	if string(jsonBytes) == "" || string(validKey.Material) != "" && string(validKey.Material) == string(jsonBytes) {
		t.Errorf("json.Marshal leaked key material: %s", string(jsonBytes))
	}
	var unmarshaled map[string]any
	_ = json.Unmarshal(jsonBytes, &unmarshaled)
	if _, exists := unmarshaled["material"]; exists {
		t.Errorf("json representation contained material key")
	}

	// 12C: Safe key file provider loads valid hex or raw key without leakage
	tmpDir := t.TempDir()
	keyFilePath := filepath.Join(tmpDir, "compliance.key")
	hexKey := hex.EncodeToString(validKey.Material)
	if err := os.WriteFile(keyFilePath, []byte(hexKey+"\n"), 0600); err != nil {
		t.Fatalf("failed writing key file: %v", err)
	}

	loadedKey, err := LoadKeyFromFile(keyFilePath, "file-key-1")
	if err != nil {
		t.Fatalf("LoadKeyFromFile failed: %v", err)
	}
	if loadedKey.ID != "file-key-1" {
		t.Errorf("expected key ID file-key-1, got %s", loadedKey.ID)
	}
	if len(loadedKey.Material) < 32 {
		t.Errorf("expected at least 32 bytes material, got %d", len(loadedKey.Material))
	}
}

// 13. Concern 4: Authoritative evidence link mutations in compliance_evidence_links
func TestStoreIntegrity_13_Concern4_EvidenceLinkAuthoritativeMutations(t *testing.T) {
	key, _ := GenerateIntegrityKey("c4-key")
	kp, _ := NewStaticKeyProvider(key)

	// 13A: Modify an evidence-link row
	t.Run("ModifyEvidenceLinkRow", func(t *testing.T) {
		store := newTestStore(t)
		res := sampleValidEvaluationResult("ASM-C4-MOD")
		_ = store.SaveEvaluationResultWithKey(res, kp)

		_, err := store.db.Exec("UPDATE compliance_evidence_links SET reference_id = 'tampered-finding-999' WHERE assessment_id = 'ASM-C4-MOD'")
		if err != nil {
			t.Fatalf("direct SQL update failed: %v", err)
		}

		result, err := store.VerifyEvaluationIntegrity("ASM-C4-MOD", "nist-sp800-53-sample", kp)
		if err != nil {
			t.Fatalf("VerifyEvaluationIntegrity failed: %v", err)
		}
		if result.Status != StatusIntegrityMismatch {
			t.Errorf("expected StatusIntegrityMismatch for modified evidence link, got %s", result.Status)
		}
	})

	// 13B: Delete an evidence-link row
	t.Run("DeleteEvidenceLinkRow", func(t *testing.T) {
		store := newTestStore(t)
		res := sampleValidEvaluationResult("ASM-C4-DEL")
		_ = store.SaveEvaluationResultWithKey(res, kp)

		_, err := store.db.Exec("DELETE FROM compliance_evidence_links WHERE id = (SELECT id FROM compliance_evidence_links WHERE assessment_id = 'ASM-C4-DEL' LIMIT 1)")
		if err != nil {
			t.Fatalf("direct SQL delete failed: %v", err)
		}

		result, err := store.VerifyEvaluationIntegrity("ASM-C4-DEL", "nist-sp800-53-sample", kp)
		if err != nil {
			t.Fatalf("VerifyEvaluationIntegrity failed: %v", err)
		}
		if result.Status != StatusIntegrityMismatch {
			t.Errorf("expected StatusIntegrityMismatch for deleted evidence link, got %s", result.Status)
		}
	})

	// 13C: Insert an unexpected evidence-link row
	t.Run("InsertUnexpectedEvidenceLinkRow", func(t *testing.T) {
		store := newTestStore(t)
		res := sampleValidEvaluationResult("ASM-C4-INS")
		_ = store.SaveEvaluationResultWithKey(res, kp)

		resID := computeEvaluationResultID(res)
		var evalID string
		_ = store.db.QueryRow("SELECT id FROM compliance_control_evaluations WHERE result_id = ? LIMIT 1", resID).Scan(&evalID)

		_, err := store.db.Exec(`
			INSERT INTO compliance_evidence_links (
				id, evaluation_id, assessment_id, catalog_id, control_id, evidence_type, reference_id, detail, created_at
			) VALUES ('evlink:injected', ?, 'ASM-C4-INS', 'nist-sp800-53-sample', 'AC-1', 'finding', 'INJECTED-FINDING', '', CURRENT_TIMESTAMP)
		`, evalID)
		if err != nil {
			t.Fatalf("direct SQL insert failed: %v", err)
		}

		result, err := store.VerifyEvaluationIntegrity("ASM-C4-INS", "nist-sp800-53-sample", kp)
		if err != nil {
			t.Fatalf("VerifyEvaluationIntegrity failed: %v", err)
		}
		if result.Status != StatusIntegrityMismatch {
			t.Errorf("expected StatusIntegrityMismatch for unexpected inserted evidence link, got %s", result.Status)
		}
	})

	// 13D: Reassign evidence reference to different control
	t.Run("ReassignEvidenceControlID", func(t *testing.T) {
		store := newTestStore(t)
		res := sampleValidEvaluationResult("ASM-C4-REASSIGN")
		_ = store.SaveEvaluationResultWithKey(res, kp)

		_, err := store.db.Exec("UPDATE compliance_evidence_links SET control_id = 'AC-99-MISMATCH' WHERE assessment_id = 'ASM-C4-REASSIGN'")
		if err != nil {
			t.Fatalf("direct SQL update failed: %v", err)
		}

		result, err := store.VerifyEvaluationIntegrity("ASM-C4-REASSIGN", "nist-sp800-53-sample", kp)
		if err != nil {
			t.Fatalf("VerifyEvaluationIntegrity failed: %v", err)
		}
		if result.Status != StatusIntegrityMismatch {
			t.Errorf("expected StatusIntegrityMismatch for reassigned evidence link, got %s", result.Status)
		}
	})
}

// 14. Concern 5: Enforcement path and GetVerifiedEvaluationResult trust boundary
func TestStoreIntegrity_14_Concern5_EnforcementPath(t *testing.T) {
	store := newTestStore(t)
	key, _ := GenerateIntegrityKey("c5-key")
	kp, _ := NewStaticKeyProvider(key)

	res := sampleValidEvaluationResult("ASM-C5-ENFORCE")
	if err := store.SaveEvaluationResultWithKey(res, kp); err != nil {
		t.Fatalf("SaveEvaluationResultWithKey failed: %v", err)
	}

	// 14A: Valid verified retrieval marks res.Verified = true
	verifiedRes, verResult, err := store.GetVerifiedEvaluationResult("ASM-C5-ENFORCE", "nist-sp800-53-sample", kp)
	if err != nil {
		t.Fatalf("GetVerifiedEvaluationResult failed: %v", err)
	}
	if !verifiedRes.Verified {
		t.Errorf("expected verifiedRes.Verified = true")
	}
	if verResult.Status != StatusVerified {
		t.Errorf("expected verResult.Status = StatusVerified, got %s", verResult.Status)
	}

	// 14B: Raw unverified retrieval via GetEvaluationResult has Verified = false
	rawRes, err := store.GetEvaluationResult("ASM-C5-ENFORCE", "nist-sp800-53-sample")
	if err != nil {
		t.Fatalf("GetEvaluationResult failed: %v", err)
	}
	if rawRes.Verified {
		t.Errorf("expected rawRes.Verified = false for unverified GetEvaluationResult")
	}

	// 14C: Tampered record retrieval via GetVerifiedEvaluationResult fails closed
	resID := computeEvaluationResultID(res)
	_, _ = store.db.Exec("UPDATE compliance_control_evaluations SET state = 'error' WHERE result_id = ?", resID)

	tamperedRes, tamperedVerResult, err := store.GetVerifiedEvaluationResult("ASM-C5-ENFORCE", "nist-sp800-53-sample", kp)
	if !errors.Is(err, ErrIntegrityMismatch) {
		t.Errorf("expected ErrIntegrityMismatch for tampered GetVerifiedEvaluationResult, got %v", err)
	}
	if tamperedRes != nil {
		t.Errorf("expected nil evaluation result for tampered record, got %+v", tamperedRes)
	}
	if tamperedVerResult.Status != StatusIntegrityMismatch {
		t.Errorf("expected tamperedVerResult.Status = StatusIntegrityMismatch, got %s", tamperedVerResult.Status)
	}
}
