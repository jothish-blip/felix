package compliance

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

// 1. Canonicalization produces identical digest regardless of ordering
func TestIntegrity_CanonicalOrderingIndependence(t *testing.T) {
	evalTime := time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC)

	// Result 1: Control B then A, Finding 2 then 1, Evidence 2 then 1
	res1 := &EvaluationResult{
		CatalogIdentity:        "nist-test:5.1.0",
		CatalogDigest:          "sha256:catalogdigest",
		MappingRuleSetIdentity: "ruleset-test:1.0",
		MappingRuleSetDigest:   "sha256:rulesetdigest",
		AssessmentID:           "ASM-ORDER",
		ExecutionID:            "EXEC-ORDER-1",
		EvaluatedAt:            evalTime,
		EngineVersion:          CurrentEvaluationEngineVersion,
		LimitationsNotice:      EvaluationLimitationsNotice(),
		Summary: EvaluationSummary{
			TotalControls: 2, CompliantCount: 1, NonCompliantCount: 1,
			ApplicableControls: 2, AssessedControls: 2,
		},
		Evaluations: []ControlEvaluationRecord{
			{
				ControlID:             "CTRL-B",
				State:                 StateCompliant,
				Rationale:             "Compliant",
				SupportingEvidence:    []string{"supp-z", "supp-a"},
				EvidenceReferences:    []string{"ref-2", "ref-1"},
				CatalogID:             "nist-test",
				CatalogVersion:        "5.1.0",
				EngineVersion:         CurrentEvaluationEngineVersion,
				MappingRuleSetVersion: "1.0",
			},
			{
				ControlID:             "CTRL-A",
				State:                 StateNonCompliant,
				Rationale:             "Non-compliant",
				FindingIDs:            []string{"F-02", "F-01"},
				ContradictingEvidence: []string{"contra-2", "contra-1"},
				CatalogID:             "nist-test",
				CatalogVersion:        "5.1.0",
				EngineVersion:         CurrentEvaluationEngineVersion,
				MappingRuleSetVersion: "1.0",
			},
		},
	}

	evLinks1 := []EvaluationEvidenceRecord{
		{ControlID: "CTRL-B", EvidenceType: "supporting", ReferenceID: "supp-z"},
		{ControlID: "CTRL-A", EvidenceType: "finding", ReferenceID: "F-02"},
		{ControlID: "CTRL-B", EvidenceType: "supporting", ReferenceID: "supp-a"},
		{ControlID: "CTRL-A", EvidenceType: "finding", ReferenceID: "F-01"},
	}

	// Result 2: Same data, different slice orderings
	res2 := &EvaluationResult{
		CatalogIdentity:        "nist-test:5.1.0",
		CatalogDigest:          "sha256:catalogdigest",
		MappingRuleSetIdentity: "ruleset-test:1.0",
		MappingRuleSetDigest:   "sha256:rulesetdigest",
		AssessmentID:           "ASM-ORDER",
		ExecutionID:            "EXEC-ORDER-1",
		EvaluatedAt:            evalTime,
		EngineVersion:          CurrentEvaluationEngineVersion,
		LimitationsNotice:      EvaluationLimitationsNotice(),
		Summary: EvaluationSummary{
			TotalControls: 2, CompliantCount: 1, NonCompliantCount: 1,
			ApplicableControls: 2, AssessedControls: 2,
		},
		Evaluations: []ControlEvaluationRecord{
			{
				ControlID:             "CTRL-A",
				State:                 StateNonCompliant,
				Rationale:             "Non-compliant",
				FindingIDs:            []string{"F-01", "F-02"},
				ContradictingEvidence: []string{"contra-1", "contra-2"},
				CatalogID:             "nist-test",
				CatalogVersion:        "5.1.0",
				EngineVersion:         CurrentEvaluationEngineVersion,
				MappingRuleSetVersion: "1.0",
			},
			{
				ControlID:             "CTRL-B",
				State:                 StateCompliant,
				Rationale:             "Compliant",
				SupportingEvidence:    []string{"supp-a", "supp-z"},
				EvidenceReferences:    []string{"ref-1", "ref-2"},
				CatalogID:             "nist-test",
				CatalogVersion:        "5.1.0",
				EngineVersion:         CurrentEvaluationEngineVersion,
				MappingRuleSetVersion: "1.0",
			},
		},
	}

	evLinks2 := []EvaluationEvidenceRecord{
		{ControlID: "CTRL-A", EvidenceType: "finding", ReferenceID: "F-01"},
		{ControlID: "CTRL-A", EvidenceType: "finding", ReferenceID: "F-02"},
		{ControlID: "CTRL-B", EvidenceType: "supporting", ReferenceID: "supp-a"},
		{ControlID: "CTRL-B", EvidenceType: "supporting", ReferenceID: "supp-z"},
	}

	payload1, err := BuildCanonicalIntegrityPayload(res1, evLinks1)
	if err != nil {
		t.Fatalf("BuildCanonicalIntegrityPayload 1 failed: %v", err)
	}
	digest1, bytes1, err := ComputeCanonicalDigest(payload1)
	if err != nil {
		t.Fatalf("ComputeCanonicalDigest 1 failed: %v", err)
	}

	payload2, err := BuildCanonicalIntegrityPayload(res2, evLinks2)
	if err != nil {
		t.Fatalf("BuildCanonicalIntegrityPayload 2 failed: %v", err)
	}
	digest2, bytes2, err := ComputeCanonicalDigest(payload2)
	if err != nil {
		t.Fatalf("ComputeCanonicalDigest 2 failed: %v", err)
	}

	if digest1 != digest2 {
		t.Errorf("expected deterministic identical digests, got %s != %s", digest1, digest2)
	}
	if string(bytes1) != string(bytes2) {
		t.Errorf("expected identical canonical bytes, got differences")
	}
}

// 2. Semantic field changes alter integrity digest
func TestIntegrity_SemanticChangesAlterDigest(t *testing.T) {
	resOriginal := sampleValidEvaluationResult("ASM-MUTATE")
	payloadOrig, err := BuildCanonicalIntegrityPayload(resOriginal, nil)
	if err != nil {
		t.Fatalf("BuildCanonicalIntegrityPayload failed: %v", err)
	}
	origDigest, _, _ := ComputeCanonicalDigest(payloadOrig)

	// Mutate state
	resMutatedState := sampleValidEvaluationResult("ASM-MUTATE")
	resMutatedState.Evaluations[0].State = StateCompliant
	resMutatedState.Evaluations[0].SupportingEvidence = []string{"new-defense"}
	resMutatedState.Evaluations[0].FindingIDs = nil
	resMutatedState.Evaluations[0].ContradictingEvidence = nil
	resMutatedState.Summary.CompliantCount = 2
	resMutatedState.Summary.NonCompliantCount = 0
	payloadState, _ := BuildCanonicalIntegrityPayload(resMutatedState, nil)
	stateDigest, _, _ := ComputeCanonicalDigest(payloadState)
	if stateDigest == origDigest {
		t.Errorf("altering control state failed to alter integrity digest!")
	}

	// Mutate rationale
	resMutatedRationale := sampleValidEvaluationResult("ASM-MUTATE")
	resMutatedRationale.Evaluations[0].Rationale = "ALTERED RATIONALE"
	payloadRat, _ := BuildCanonicalIntegrityPayload(resMutatedRationale, nil)
	ratDigest, _, _ := ComputeCanonicalDigest(payloadRat)
	if ratDigest == origDigest {
		t.Errorf("altering control rationale failed to alter integrity digest!")
	}

	// Mutate catalog version
	resMutatedCat := sampleValidEvaluationResult("ASM-MUTATE")
	resMutatedCat.CatalogIdentity = "nist-sp800-53-sample:6.0.0"
	payloadCat, _ := BuildCanonicalIntegrityPayload(resMutatedCat, nil)
	catDigest, _, _ := ComputeCanonicalDigest(payloadCat)
	if catDigest == origDigest {
		t.Errorf("altering catalog identity failed to alter integrity digest!")
	}
}

// 3. Volatile fields (database row timestamps) do not alter integrity digest
func TestIntegrity_VolatileFieldsExcluded(t *testing.T) {
	res1 := sampleValidEvaluationResult("ASM-VOLATILE")
	res2 := sampleValidEvaluationResult("ASM-VOLATILE")

	evLinks1 := []EvaluationEvidenceRecord{
		{ID: "link-1", ControlID: "AC-3", EvidenceType: "finding", ReferenceID: "F-1", CreatedAt: time.Now()},
	}
	evLinks2 := []EvaluationEvidenceRecord{
		{ID: "link-different-id", ControlID: "AC-3", EvidenceType: "finding", ReferenceID: "F-1", CreatedAt: time.Now().Add(24 * time.Hour)},
	}

	payload1, _ := BuildCanonicalIntegrityPayload(res1, evLinks1)
	payload2, _ := BuildCanonicalIntegrityPayload(res2, evLinks2)

	d1, _, _ := ComputeCanonicalDigest(payload1)
	d2, _, _ := ComputeCanonicalDigest(payload2)

	if d1 != d2 {
		t.Errorf("volatile timestamp differences altered the canonical digest: %s != %s", d1, d2)
	}
}

// 4. Nil and malformed input safety
func TestIntegrity_NilInputSafety(t *testing.T) {
	_, err := BuildCanonicalIntegrityPayload(nil, nil)
	if err == nil {
		t.Errorf("expected error for nil evaluation result")
	}

	_, _, err = ComputeCanonicalDigest(nil)
	if err == nil {
		t.Errorf("expected error for nil canonical payload")
	}

	_, err = ComputeAuthenticityTag(nil, nil)
	if err == nil {
		t.Errorf("expected error for nil key")
	}

	if VerifyAuthenticityTag(nil, nil, "") {
		t.Errorf("expected false for nil key")
	}

	result := VerifyCanonicalIntegrity(context.Background(), nil, nil, nil)
	if result.Status != StatusOperationalFailure {
		t.Errorf("expected StatusOperationalFailure for nil inputs, got %s", result.Status)
	}
}

// 5. Key management: generation, validation, and secret redaction
func TestKeyManagement_GenerationAndRedaction(t *testing.T) {
	key, err := GenerateIntegrityKey("test-key-2026")
	if err != nil {
		t.Fatalf("GenerateIntegrityKey failed: %v", err)
	}

	if key.ID != "test-key-2026" {
		t.Errorf("unexpected key ID: %s", key.ID)
	}
	if len(key.Material) != MinimumHMACKeyBytes {
		t.Errorf("expected %d bytes, got %d", MinimumHMACKeyBytes, len(key.Material))
	}
	if err := key.Validate(); err != nil {
		t.Errorf("generated key failed validation: %v", err)
	}

	// Secret material must NEVER be exposed in String()
	strRep := key.String()
	hexMaterial := hex.EncodeToString(key.Material)
	if strings.Contains(strRep, hexMaterial) || strings.Contains(strRep, string(key.Material)) {
		t.Errorf("CRITICAL SECURITY DEFECT: key material leaked in String() output: %s", strRep)
	}

	// Secret material must NEVER be exposed in JSON serialization
	jsonData, err := json.Marshal(key)
	if err != nil {
		t.Fatalf("json.Marshal failed: %v", err)
	}
	if strings.Contains(string(jsonData), hexMaterial) || strings.Contains(string(jsonData), "material") {
		t.Errorf("CRITICAL SECURITY DEFECT: key material leaked in JSON serialization: %s", string(jsonData))
	}
}

// 6. Key management: invalid key length and malformed ID rejection
func TestKeyManagement_ValidationErrors(t *testing.T) {
	// Empty ID
	_, err := GenerateIntegrityKey("   ")
	if !errors.Is(err, ErrInvalidKeyID) {
		t.Errorf("expected ErrInvalidKeyID, got %v", err)
	}

	// Short key material (< 32 bytes)
	shortKey := &IntegrityKey{
		ID:        "short-key",
		Algorithm: AlgorithmHMACSHA256,
		Material:  []byte("short-secret-less-than-32-bytes"),
	}
	err = shortKey.Validate()
	if !errors.Is(err, ErrInvalidKeyMaterial) {
		t.Errorf("expected ErrInvalidKeyMaterial, got %v", err)
	}

	// Unsupported algorithm
	badAlgKey := &IntegrityKey{
		ID:        "bad-alg",
		Algorithm: "DES",
		Material:  make([]byte, 32),
	}
	if err := badAlgKey.Validate(); err == nil {
		t.Errorf("expected error for unsupported algorithm DES")
	}
}

// 7. Key rotation: historical records verify with old key, new records sign with new key
func TestKeyManagement_KeyRotation(t *testing.T) {
	ctx := context.Background()

	// Initial key 1
	keyV1, _ := GenerateIntegrityKey("key-2026-v1")
	provider, err := NewStaticKeyProvider(keyV1)
	if err != nil {
		t.Fatalf("NewStaticKeyProvider failed: %v", err)
	}

	// Sign payload with key 1
	payload := []byte("canonical-compliance-payload-v1")
	tagV1, err := ComputeAuthenticityTag(payload, keyV1)
	if err != nil {
		t.Fatalf("ComputeAuthenticityTag failed: %v", err)
	}

	// Verify with provider key 1
	k, err := provider.GetVerificationKey(ctx, "key-2026-v1")
	if err != nil || !VerifyAuthenticityTag(payload, k, tagV1) {
		t.Fatalf("verification with key v1 failed: %v", err)
	}

	// Rotate signing key to key 2
	keyV2, _ := GenerateIntegrityKey("key-2026-v2")
	if err := provider.SetSigningKey(keyV2); err != nil {
		t.Fatalf("SetSigningKey failed: %v", err)
	}

	// Active signing key is now key 2
	activeKey, err := provider.GetSigningKey(ctx)
	if err != nil || activeKey.ID != "key-2026-v2" {
		t.Errorf("expected active signing key key-2026-v2, got %v", activeKey)
	}

	// Historical payload signed with key 1 STILL verifies via historical verification key lookup
	histKey, err := provider.GetVerificationKey(ctx, "key-2026-v1")
	if err != nil {
		t.Fatalf("historical verification key lookup failed after rotation: %v", err)
	}
	if !VerifyAuthenticityTag(payload, histKey, tagV1) {
		t.Errorf("historical tag verification failed after key rotation!")
	}
}

// 8. Retired key cannot be used for signing
func TestKeyManagement_RetiredKey(t *testing.T) {
	ctx := context.Background()
	retiredKey, _ := GenerateIntegrityKey("retired-key")
	retiredKey.RetiredAt = time.Now().UTC().Add(-1 * time.Hour) // Retired 1 hr ago

	provider, _ := NewStaticKeyProvider(nil)
	err := provider.SetSigningKey(retiredKey)
	if !errors.Is(err, ErrKeyRetired) {
		t.Errorf("expected ErrKeyRetired when setting retired signing key, got: %v", err)
	}

	// Ensure retired key can still be registered as verification key for historical data
	err = provider.AddVerificationKey(retiredKey)
	if err != nil {
		t.Errorf("expected retired key to be allowed as verification key: %v", err)
	}

	k, err := provider.GetVerificationKey(ctx, "retired-key")
	if err != nil || k.ID != "retired-key" {
		t.Errorf("failed retrieving retired verification key: %v", err)
	}
}

// 9. EnvKeyProvider loading from environment
func TestKeyManagement_EnvKeyProvider(t *testing.T) {
	ctx := context.Background()
	secretHex := hex.EncodeToString([]byte("0123456789abcdef0123456789abcdef")) // 32 bytes
	envVal := "prod-key-1:" + secretHex

	t.Setenv("TEST_FELIX_KEY", envVal)
	provider := NewEnvKeyProvider("TEST_FELIX_KEY")

	signingKey, err := provider.GetSigningKey(ctx)
	if err != nil {
		t.Fatalf("GetSigningKey from env failed: %v", err)
	}
	if signingKey.ID != "prod-key-1" {
		t.Errorf("expected key ID prod-key-1, got %s", signingKey.ID)
	}
	if len(signingKey.Material) != 32 {
		t.Errorf("expected 32 bytes material, got %d", len(signingKey.Material))
	}

	verKey, err := provider.GetVerificationKey(ctx, "prod-key-1")
	if err != nil || verKey.ID != "prod-key-1" {
		t.Errorf("GetVerificationKey failed: %v", err)
	}

	_, err = provider.GetVerificationKey(ctx, "nonexistent-key")
	if !errors.Is(err, ErrUnknownKey) {
		t.Errorf("expected ErrUnknownKey, got %v", err)
	}
}

// 10. Verification detects tampered HMAC tag
func TestIntegrity_TamperedHMACTag(t *testing.T) {
	key, _ := GenerateIntegrityKey("key-1")
	kp, _ := NewStaticKeyProvider(key)

	res := sampleValidEvaluationResult("ASM-HMAC-TAMPER")
	rec, err := ProtectEvaluationResult(context.Background(), res, nil, kp)
	if err != nil {
		t.Fatalf("ProtectEvaluationResult failed: %v", err)
	}

	payload, _ := BuildCanonicalIntegrityPayload(res, nil)

	// Tamper with signature tag
	tagBytes, _ := hex.DecodeString(rec.SignatureTag)
	tagBytes[0] ^= 0xFF
	rec.SignatureTag = hex.EncodeToString(tagBytes)

	verResult := VerifyCanonicalIntegrity(context.Background(), payload, rec, kp)
	if verResult.Status != StatusIntegrityMismatch {
		t.Errorf("expected StatusIntegrityMismatch for tampered HMAC tag, got %s", verResult.Status)
	}
	if verResult.AuthenticityMatch {
		t.Errorf("expected AuthenticityMatch = false for tampered HMAC tag")
	}
}

// 11. Verification detects tampered content digest
func TestIntegrity_TamperedContentDigest(t *testing.T) {
	res := sampleValidEvaluationResult("ASM-DIGEST-TAMPER")
	rec, err := ProtectEvaluationResult(context.Background(), res, nil, nil)
	if err != nil {
		t.Fatalf("ProtectEvaluationResult failed: %v", err)
	}

	payload, _ := BuildCanonicalIntegrityPayload(res, nil)

	// Tamper with recorded digest
	rec.CanonicalDigest = "sha256:0000000000000000000000000000000000000000000000000000000000000000"

	verResult := VerifyCanonicalIntegrity(context.Background(), payload, rec, nil)
	if verResult.Status != StatusIntegrityMismatch {
		t.Errorf("expected StatusIntegrityMismatch for tampered content digest, got %s", verResult.Status)
	}
	if verResult.ContentDigestMatch {
		t.Errorf("expected ContentDigestMatch = false")
	}
}

// 12. Verification detects row count mismatch (detached controls or evidence)
func TestIntegrity_RowCountMismatch(t *testing.T) {
	res := sampleValidEvaluationResult("ASM-ROW-COUNT")
	rec, _ := ProtectEvaluationResult(context.Background(), res, nil, nil)

	payload, _ := BuildCanonicalIntegrityPayload(res, nil)

	// Tamper with record control count
	rec.ControlCount = rec.ControlCount + 1

	verResult := VerifyCanonicalIntegrity(context.Background(), payload, rec, nil)
	if verResult.Status != StatusIntegrityMismatch {
		t.Errorf("expected StatusIntegrityMismatch for control count mismatch, got %s", verResult.Status)
	}
}

// 13. Constant-time comparison prevents timing leakage
func TestIntegrity_ConstantTimeComparison(t *testing.T) {
	key, _ := GenerateIntegrityKey("timing-test-key")
	data := []byte("timing-test-payload")

	mac := hmac.New(sha256.New, key.Material)
	mac.Write(data)
	validTag := hex.EncodeToString(mac.Sum(nil))

	if !VerifyAuthenticityTag(data, key, validTag) {
		t.Errorf("valid tag failed verification")
	}

	invalidTag := validTag[:len(validTag)-2] + "ff"
	if VerifyAuthenticityTag(data, key, invalidTag) {
		t.Errorf("invalid tag succeeded verification")
	}
}
