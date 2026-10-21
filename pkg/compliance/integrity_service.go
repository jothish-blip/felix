package compliance

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
)

// BuildCanonicalIntegrityPayload transforms an EvaluationResult and its associated evidence links
// into a deterministic, immutable CanonicalIntegrityPayload.
func BuildCanonicalIntegrityPayload(res *EvaluationResult, evidenceLinks []EvaluationEvidenceRecord) (*CanonicalIntegrityPayload, error) {
	if res == nil {
		return nil, errors.New("cannot build canonical integrity payload from nil evaluation result")
	}

	payload := &CanonicalIntegrityPayload{
		FormatVersion:          CurrentIntegrityFormatVersion,
		ResultID:               computeEvaluationResultID(res),
		AssessmentID:           strings.TrimSpace(res.AssessmentID),
		ExecutionID:            strings.TrimSpace(res.ExecutionID),
		CatalogIdentity:        strings.TrimSpace(res.CatalogIdentity),
		CatalogDigest:          strings.TrimSpace(res.CatalogDigest),
		MappingRuleSetIdentity: strings.TrimSpace(res.MappingRuleSetIdentity),
		MappingRuleSetDigest:   strings.TrimSpace(res.MappingRuleSetDigest),
		EngineVersion:          strings.TrimSpace(res.EngineVersion),
		LimitationsNotice:      strings.TrimSpace(res.LimitationsNotice),
		Summary:                res.Summary,
		Controls:               make([]CanonicalControlEntry, len(res.Evaluations)),
		EvidenceLinks:          make([]CanonicalEvidenceLinkEntry, len(evidenceLinks)),
	}

	// 1. Process and sort control evaluations
	for i, ev := range res.Evaluations {
		fIDs := append([]string(nil), ev.FindingIDs...)
		sort.Strings(fIDs)

		evRefs := append([]string(nil), ev.EvidenceReferences...)
		sort.Strings(evRefs)

		suppEv := append([]string(nil), ev.SupportingEvidence...)
		sort.Strings(suppEv)

		contraEv := append([]string(nil), ev.ContradictingEvidence...)
		sort.Strings(contraEv)

		payload.Controls[i] = CanonicalControlEntry{
			ControlID:             strings.TrimSpace(ev.ControlID),
			ControlTitle:          strings.TrimSpace(ev.ControlTitle),
			CatalogID:             strings.TrimSpace(ev.CatalogID),
			CatalogVersion:        strings.TrimSpace(ev.CatalogVersion),
			State:                 string(ev.State),
			Rationale:             strings.TrimSpace(ev.Rationale),
			Limitations:           strings.TrimSpace(ev.Limitations),
			FindingIDs:            fIDs,
			EvidenceReferences:    evRefs,
			SupportingEvidence:    suppEv,
			ContradictingEvidence: contraEv,
		}
	}

	sort.SliceStable(payload.Controls, func(i, j int) bool {
		return payload.Controls[i].ControlID < payload.Controls[j].ControlID
	})

	// 2. Process and sort evidence links
	for i, link := range evidenceLinks {
		payload.EvidenceLinks[i] = CanonicalEvidenceLinkEntry{
			EvaluationID:  strings.TrimSpace(link.EvaluationID),
			ControlID:     strings.TrimSpace(link.ControlID),
			EvidenceType:  strings.TrimSpace(link.EvidenceType),
			ReferenceID:   strings.TrimSpace(link.ReferenceID),
			Detail:        strings.TrimSpace(link.Detail),
			ContentDigest: "metadata-bound",
		}
	}

	sort.SliceStable(payload.EvidenceLinks, func(i, j int) bool {
		if payload.EvidenceLinks[i].ControlID != payload.EvidenceLinks[j].ControlID {
			return payload.EvidenceLinks[i].ControlID < payload.EvidenceLinks[j].ControlID
		}
		if payload.EvidenceLinks[i].EvaluationID != payload.EvidenceLinks[j].EvaluationID {
			return payload.EvidenceLinks[i].EvaluationID < payload.EvidenceLinks[j].EvaluationID
		}
		if payload.EvidenceLinks[i].EvidenceType != payload.EvidenceLinks[j].EvidenceType {
			return payload.EvidenceLinks[i].EvidenceType < payload.EvidenceLinks[j].EvidenceType
		}
		return payload.EvidenceLinks[i].ReferenceID < payload.EvidenceLinks[j].ReferenceID
	})

	return payload, nil
}

// ComputeCanonicalDigest marshals the payload deterministically and returns its SHA-256 digest.
func ComputeCanonicalDigest(payload *CanonicalIntegrityPayload) (string, []byte, error) {
	if payload == nil {
		return "", nil, errors.New("cannot compute digest of nil canonical payload")
	}

	canonicalBytes, err := json.Marshal(payload)
	if err != nil {
		return "", nil, fmt.Errorf("failed marshaling canonical integrity payload: %w", err)
	}

	h := sha256.Sum256(canonicalBytes)
	digest := "sha256:" + hex.EncodeToString(h[:])
	return digest, canonicalBytes, nil
}

// ComputeEvidenceManifestDigest computes a SHA-256 digest of the canonical evidence link manifest.
func ComputeEvidenceManifestDigest(links []CanonicalEvidenceLinkEntry) (string, error) {
	linksCopy := append([]CanonicalEvidenceLinkEntry(nil), links...)
	sort.SliceStable(linksCopy, func(i, j int) bool {
		if linksCopy[i].ControlID != linksCopy[j].ControlID {
			return linksCopy[i].ControlID < linksCopy[j].ControlID
		}
		if linksCopy[i].EvaluationID != linksCopy[j].EvaluationID {
			return linksCopy[i].EvaluationID < linksCopy[j].EvaluationID
		}
		if linksCopy[i].EvidenceType != linksCopy[j].EvidenceType {
			return linksCopy[i].EvidenceType < linksCopy[j].EvidenceType
		}
		return linksCopy[i].ReferenceID < linksCopy[j].ReferenceID
	})

	data, err := json.Marshal(linksCopy)
	if err != nil {
		return "", fmt.Errorf("failed marshaling evidence manifest: %w", err)
	}
	h := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(h[:]), nil
}

// ComputeAuthenticityTag calculates an HMAC-SHA256 signature tag over the canonical payload bytes.
func ComputeAuthenticityTag(canonicalBytes []byte, key *IntegrityKey) (string, error) {
	if key == nil {
		return "", ErrNoKeyConfigured
	}
	if err := key.Validate(); err != nil {
		return "", err
	}

	mac := hmac.New(sha256.New, key.Material)
	mac.Write(canonicalBytes)
	return hex.EncodeToString(mac.Sum(nil)), nil
}

// VerifyAuthenticityTag verifies an HMAC-SHA256 signature tag using constant-time comparison.
func VerifyAuthenticityTag(canonicalBytes []byte, key *IntegrityKey, recordedTagHex string) bool {
	if key == nil || errValidate(key) != nil {
		return false
	}

	recordedBytes, err := hex.DecodeString(strings.TrimSpace(recordedTagHex))
	if err != nil || len(recordedBytes) != sha256.Size {
		return false
	}

	mac := hmac.New(sha256.New, key.Material)
	mac.Write(canonicalBytes)
	expectedMAC := mac.Sum(nil)

	return subtle.ConstantTimeCompare(expectedMAC, recordedBytes) == 1
}

func errValidate(key *IntegrityKey) error {
	return key.Validate()
}

// ProtectEvaluationResult generates integrity and authenticity metadata for an evaluation result.
func ProtectEvaluationResult(ctx context.Context, res *EvaluationResult, evidenceLinks []EvaluationEvidenceRecord, keyProvider KeyProvider) (*IntegrityRecord, error) {
	if res == nil {
		return nil, ErrInvalidEvaluation
	}

	payload, err := BuildCanonicalIntegrityPayload(res, evidenceLinks)
	if err != nil {
		return nil, err
	}

	canonicalDigest, canonicalBytes, err := ComputeCanonicalDigest(payload)
	if err != nil {
		return nil, err
	}

	manifestDigest, err := ComputeEvidenceManifestDigest(payload.EvidenceLinks)
	if err != nil {
		return nil, err
	}

	now := time.Now().UTC()
	record := &IntegrityRecord{
		ResultID:               payload.ResultID,
		FormatVersion:          CurrentIntegrityFormatVersion,
		CanonicalDigest:        canonicalDigest,
		AuthenticityAlgorithm:  AlgorithmNone,
		EvidenceManifestDigest: manifestDigest,
		ControlCount:           len(payload.Controls),
		EvidenceCount:          len(payload.EvidenceLinks),
		ProtectedAt:            now,
		VerifiedAt:             now,
	}

	// Sign with KeyProvider if configured
	if keyProvider != nil {
		signingKey, err := keyProvider.GetSigningKey(ctx)
		if err == nil && signingKey != nil {
			tag, err := ComputeAuthenticityTag(canonicalBytes, signingKey)
			if err != nil {
				return nil, fmt.Errorf("failed computing authenticity tag: %w", err)
			}
			record.AuthenticityAlgorithm = AlgorithmHMACSHA256
			record.KeyID = signingKey.ID
			record.SignatureTag = tag
		} else if err != nil && !errors.Is(err, ErrNoKeyConfigured) {
			return nil, fmt.Errorf("key provider failure: %w", err)
		}
	}

	return record, nil
}

// VerifyCanonicalIntegrity performs full content integrity and authenticity verification.
func VerifyCanonicalIntegrity(
	ctx context.Context,
	payload *CanonicalIntegrityPayload,
	record *IntegrityRecord,
	keyProvider KeyProvider,
) *IntegrityVerificationResult {
	if payload == nil || record == nil {
		return &IntegrityVerificationResult{
			Status:            StatusOperationalFailure,
			Violations:        []string{"nil payload or integrity record provided"},
			VerifiedAt:        time.Now().UTC(),
			LimitationsNotice: IntegrityLimitationsNotice(),
		}
	}

	result := &IntegrityVerificationResult{
		ResultID:          payload.ResultID,
		AssessmentID:      payload.AssessmentID,
		CatalogIdentity:   payload.CatalogIdentity,
		FormatVersion:     record.FormatVersion,
		KeyID:             record.KeyID,
		Algorithm:         record.AuthenticityAlgorithm,
		VerifiedAt:        time.Now().UTC(),
		LimitationsNotice: IntegrityLimitationsNotice(),
		EvidenceIntegrity: EvidenceIntegrityReport{
			TotalEvidenceLinks: len(payload.EvidenceLinks),
			ContentNote:        "Original external evidence bytes not stored in local DB; evidence metadata and control bindings verified",
		},
	}

	// 1. Verify format version
	if record.FormatVersion != CurrentIntegrityFormatVersion {
		result.Status = StatusIntegrityMismatch
		result.Violations = append(result.Violations,
			fmt.Sprintf("unsupported format version %q; expected %q", record.FormatVersion, CurrentIntegrityFormatVersion))
		return result
	}

	// 2. Verify result identity binding
	if payload.ResultID != record.ResultID {
		result.Status = StatusIntegrityMismatch
		result.Violations = append(result.Violations,
			fmt.Sprintf("result ID mismatch: recorded %q, recomputed %q", record.ResultID, payload.ResultID))
	}

	// 2. Verify row counts
	if record.ControlCount != len(payload.Controls) {
		result.Status = StatusIntegrityMismatch
		result.Violations = append(result.Violations,
			fmt.Sprintf("control count mismatch: recorded %d, actual %d", record.ControlCount, len(payload.Controls)))
	}
	if record.EvidenceCount != len(payload.EvidenceLinks) {
		result.Status = StatusIntegrityMismatch
		result.Violations = append(result.Violations,
			fmt.Sprintf("evidence link count mismatch: recorded %d, actual %d", record.EvidenceCount, len(payload.EvidenceLinks)))
	}

	// 3. Verify content SHA-256 digest
	computedDigest, canonicalBytes, err := ComputeCanonicalDigest(payload)
	if err != nil {
		result.Status = StatusOperationalFailure
		result.Violations = append(result.Violations, fmt.Sprintf("failed computing canonical digest: %v", err))
		return result
	}

	if computedDigest == record.CanonicalDigest {
		result.ContentDigestMatch = true
	} else {
		result.ContentDigestMatch = false
		result.Violations = append(result.Violations,
			fmt.Sprintf("content digest mismatch: recorded %s, recomputed %s", record.CanonicalDigest, computedDigest))
	}

	// 4. Verify evidence manifest digest
	manifestDigest, err := ComputeEvidenceManifestDigest(payload.EvidenceLinks)
	if err != nil {
		result.Violations = append(result.Violations, fmt.Sprintf("failed computing evidence manifest digest: %v", err))
	} else if manifestDigest != record.EvidenceManifestDigest {
		result.EvidenceIntegrity.MetadataVerified = false
		result.Violations = append(result.Violations,
			fmt.Sprintf("evidence manifest digest mismatch: recorded %s, recomputed %s", record.EvidenceManifestDigest, manifestDigest))
	} else {
		result.EvidenceIntegrity.MetadataVerified = true
	}

	// 5. Verify Authenticity (HMAC)
	if record.AuthenticityAlgorithm == AlgorithmHMACSHA256 {
		if keyProvider == nil {
			result.Status = StatusVerificationUnavailable
			result.Violations = append(result.Violations, "record is HMAC-signed but no key provider is available")
			return result
		}

		verKey, err := keyProvider.GetVerificationKey(ctx, record.KeyID)
		if err != nil {
			if errors.Is(err, ErrUnknownKey) {
				result.Status = StatusUnknownKey
				result.Violations = append(result.Violations, fmt.Sprintf("verification key %q is unknown or retired", record.KeyID))
			} else {
				result.Status = StatusVerificationUnavailable
				result.Violations = append(result.Violations, fmt.Sprintf("failed acquiring verification key %q: %v", record.KeyID, err))
			}
			return result
		}

		if VerifyAuthenticityTag(canonicalBytes, verKey, record.SignatureTag) {
			result.AuthenticityMatch = true
		} else {
			result.AuthenticityMatch = false
			result.Violations = append(result.Violations, "authenticity signature tag mismatch (tampering detected)")
		}
	}

	// 6. Final Status Determination
	if len(result.Violations) > 0 {
		result.Status = StatusIntegrityMismatch
		return result
	}

	if record.AuthenticityAlgorithm == AlgorithmHMACSHA256 && result.AuthenticityMatch && result.ContentDigestMatch {
		result.Status = StatusVerified
	} else if result.ContentDigestMatch {
		result.Status = StatusIntegrityOnly
	} else {
		result.Status = StatusIntegrityMismatch
	}

	return result
}
