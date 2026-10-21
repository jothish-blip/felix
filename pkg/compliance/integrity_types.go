package compliance

import (
	"errors"
	"fmt"
	"time"
)

// CurrentIntegrityFormatVersion defines the versioned envelope format for compliance integrity verification.
const CurrentIntegrityFormatVersion = "felix.compliance.integrity.v1"

// Authenticity algorithms supported by FELIX compliance integrity layer.
const (
	AlgorithmNone       = "NONE"
	AlgorithmHMACSHA256 = "HMAC-SHA256"
)

// VerificationStatus classifies the outcome of an integrity and authenticity verification check.
type VerificationStatus string

const (
	// StatusVerified indicates that both cryptographic authenticity (e.g. HMAC-SHA256) and
	// content integrity (SHA-256 digest) match the recorded evaluation data.
	StatusVerified VerificationStatus = "VERIFIED"

	// StatusIntegrityOnly indicates that the content SHA-256 digest matches the recorded evaluation data,
	// but cryptographic authenticity verification was not performed (unauthenticated hash, no key provider).
	StatusIntegrityOnly VerificationStatus = "INTEGRITY_ONLY"

	// StatusIntegrityMismatch indicates that tampering, corruption, unauthorized modification,
	// or unexpected row detachment was detected.
	StatusIntegrityMismatch VerificationStatus = "INTEGRITY_MISMATCH"

	// StatusUnverifiedLegacy indicates that the record was persisted prior to integrity support
	// or without integrity metadata, and therefore cannot be cryptographically verified.
	StatusUnverifiedLegacy VerificationStatus = "UNVERIFIED_LEGACY"

	// StatusUnknownKey indicates that the record was signed with a key that is missing, unknown,
	// or retired in the verification provider.
	StatusUnknownKey VerificationStatus = "UNKNOWN_KEY"

	// StatusVerificationUnavailable indicates that an operational or configuration failure
	// prevented verification from completing (e.g. misconfigured key provider).
	StatusVerificationUnavailable VerificationStatus = "VERIFICATION_UNAVAILABLE"

	// StatusOperationalFailure indicates an operational storage, database, or I/O failure.
	StatusOperationalFailure VerificationStatus = "OPERATIONAL_FAILURE"
)

var (
	// ErrIntegrityMismatch is returned when persisted data does not match its recorded integrity digest or signature.
	ErrIntegrityMismatch = errors.New("compliance integrity verification failed: tampering or corruption detected")

	// ErrMissingVerificationMaterial is returned when an evaluation has no associated integrity metadata.
	ErrMissingVerificationMaterial = errors.New("compliance integrity verification failed: missing integrity metadata")

	// ErrUnknownKey is returned when the key required to verify authenticity is not available.
	ErrUnknownKey = errors.New("compliance integrity verification failed: unknown or retired key")

	// ErrUnsupportedFormat is returned when an integrity record uses an unknown or unsupported format version.
	ErrUnsupportedFormat = errors.New("compliance integrity verification failed: unsupported integrity format version")

	// ErrInvalidIntegrityData is returned when integrity metadata is structurally invalid or malformed.
	ErrInvalidIntegrityData = errors.New("compliance integrity verification failed: invalid integrity metadata")

	// ErrVerificationUnavailable is returned when key or operational prerequisites for verification are missing.
	ErrVerificationUnavailable = errors.New("compliance integrity verification unavailable")
)

// IntegrityRecord represents the stored integrity and authenticity metadata for an EvaluationResult.
type IntegrityRecord struct {
	ResultID               string    `json:"result_id"`
	FormatVersion          string    `json:"format_version"`
	CanonicalDigest        string    `json:"canonical_digest"`
	AuthenticityAlgorithm  string    `json:"authenticity_algorithm"`
	KeyID                  string    `json:"key_id,omitempty"`
	SignatureTag           string    `json:"signature_tag,omitempty"`
	EvidenceManifestDigest string    `json:"evidence_manifest_digest,omitempty"`
	ControlCount           int       `json:"control_count"`
	EvidenceCount          int       `json:"evidence_count"`
	ProtectedAt            time.Time `json:"protected_at"`
	VerifiedAt             time.Time `json:"verified_at,omitempty"`
}

// EvidenceIntegrityReport provides a granular assessment of evidence link relationships and content integrity.
type EvidenceIntegrityReport struct {
	TotalEvidenceLinks int      `json:"total_evidence_links"`
	MetadataVerified   bool     `json:"metadata_verified"`
	ContentVerified    bool     `json:"content_verified"`
	ContentNote        string   `json:"content_note,omitempty"`
	Violations         []string `json:"violations,omitempty"`
}

// IntegrityVerificationResult encapsulates the complete verification outcome for an evaluation result.
type IntegrityVerificationResult struct {
	ResultID           string                  `json:"result_id"`
	AssessmentID       string                  `json:"assessment_id"`
	CatalogIdentity    string                  `json:"catalog_identity"`
	Status             VerificationStatus      `json:"status"`
	FormatVersion      string                  `json:"format_version,omitempty"`
	KeyID              string                  `json:"key_id,omitempty"`
	Algorithm          string                  `json:"algorithm,omitempty"`
	ContentDigestMatch bool                    `json:"content_digest_match"`
	AuthenticityMatch  bool                    `json:"authenticity_match"`
	EvidenceIntegrity  EvidenceIntegrityReport `json:"evidence_integrity"`
	Violations         []string                `json:"violations,omitempty"`
	VerifiedAt         time.Time               `json:"verified_at"`
	LimitationsNotice  string                  `json:"limitations_notice,omitempty"`
}

// CanonicalIntegrityPayload represents the deterministic, versioned representation of an EvaluationResult
// used for computing SHA-256 digests and HMAC-SHA256 authenticity tags.
// Excludes non-semantic volatile values (e.g. database timestamps, verification run times).
type CanonicalIntegrityPayload struct {
	FormatVersion          string                       `json:"format_version"`
	ResultID               string                       `json:"result_id"`
	AssessmentID           string                       `json:"assessment_id"`
	ExecutionID            string                       `json:"execution_id,omitempty"`
	CatalogIdentity        string                       `json:"catalog_identity"`
	CatalogDigest          string                       `json:"catalog_digest"`
	MappingRuleSetIdentity string                       `json:"mapping_ruleset_identity,omitempty"`
	MappingRuleSetDigest   string                       `json:"mapping_ruleset_digest,omitempty"`
	EngineVersion          string                       `json:"engine_version"`
	LimitationsNotice      string                       `json:"limitations_notice"`
	Summary                EvaluationSummary            `json:"summary"`
	Controls               []CanonicalControlEntry      `json:"controls"`
	EvidenceLinks          []CanonicalEvidenceLinkEntry `json:"evidence_links"`
}

// CanonicalControlEntry captures the immutable, evidence-backed evaluation outcome for a single control.
type CanonicalControlEntry struct {
	ControlID             string   `json:"control_id"`
	ControlTitle          string   `json:"control_title,omitempty"`
	CatalogID             string   `json:"catalog_id"`
	CatalogVersion        string   `json:"catalog_version,omitempty"`
	State                 string   `json:"state"`
	Rationale             string   `json:"rationale"`
	Limitations           string   `json:"limitations,omitempty"`
	FindingIDs            []string `json:"finding_ids,omitempty"`
	EvidenceReferences    []string `json:"evidence_references,omitempty"`
	SupportingEvidence    []string `json:"supporting_evidence,omitempty"`
	ContradictingEvidence []string `json:"contradicting_evidence,omitempty"`
}

// CanonicalEvidenceLinkEntry captures a normalized evidence link binding a finding, reference,
// or proof item to a specific control evaluation.
type CanonicalEvidenceLinkEntry struct {
	EvaluationID  string `json:"evaluation_id,omitempty"`
	ControlID     string `json:"control_id"`
	EvidenceType  string `json:"evidence_type"` // "finding", "reference", "supporting", "contradicting"
	ReferenceID   string `json:"reference_id"`
	Detail        string `json:"detail,omitempty"`
	ContentDigest string `json:"content_digest,omitempty"`
}

// IntegrityLimitationsNotice returns the standard boundary statement regarding database-local integrity.
func IntegrityLimitationsNotice() string {
	return "FELIX Compliance Integrity Notice: Content integrity verification (AlgorithmNone / SHA-256) detects accidental corruption, storage errors, and row detachment, but cannot guarantee cryptographic authenticity; an attacker with database write access to both evaluation and integrity tables can compute and store matching digests. Cryptographic authenticity requires a protected key (AlgorithmHMACSHA256). The persisted integrity_version marker in compliance_evaluation_results ensures that deleting compliance_integrity_records cannot cause a protected evaluation to be misclassified as legacy unverified. Limitation: in a shared SQLite file where an attacker possesses full table write access, an attacker who modifies both compliance_evaluation_results (clearing the marker) and deletes the integrity row can simulate a legacy record unless the database is cryptographically sealed or external audit logs are maintained. Without an external tamper-evident append-only log or distributed witness, database-local MACs cannot independently prevent complete database replacement, truncation, or point-in-time rollback."
}

// CurrentRemediationIntegrityFormatVersion defines the version format for remediation records.
const CurrentRemediationIntegrityFormatVersion = "felix.remediation.integrity.v1"

// RemediationIntegrityRecord captures the stored integrity and authenticity metadata for a remediation record.
type RemediationIntegrityRecord struct {
	RemediationID         string     `json:"remediation_id"`
	FormatVersion         string     `json:"format_version"`
	CanonicalDigest       string     `json:"canonical_digest"`
	AuthenticityAlgorithm string     `json:"authenticity_algorithm"`
	KeyID                 string     `json:"key_id,omitempty"`
	SignatureTag          string     `json:"signature_tag,omitempty"`
	EventCount            int        `json:"event_count"`
	HistoryChainDigest    string     `json:"history_chain_digest"`
	ProtectedAt           time.Time  `json:"protected_at"`
	VerifiedAt            *time.Time `json:"verified_at,omitempty"`
}

// RemediationIntegrityVerificationResult captures the outcome of verifying a remediation record and its history.
type RemediationIntegrityVerificationResult struct {
	RemediationID         string             `json:"remediation_id"`
	Status                VerificationStatus `json:"status"`
	CanonicalDigestMatch  bool               `json:"canonical_digest_match"`
	HistoryChainMatch     bool               `json:"history_chain_match"`
	AuthenticityMatch     bool               `json:"authenticity_match"`
	Algorithm             string             `json:"algorithm"`
	KeyID                 string             `json:"key_id,omitempty"`
	RecordedDigest        string             `json:"recorded_digest,omitempty"`
	ComputedDigest        string             `json:"computed_digest,omitempty"`
	RecordedHistoryDigest string             `json:"recorded_history_digest,omitempty"`
	ComputedHistoryDigest string             `json:"computed_history_digest,omitempty"`
	EventCount            int                `json:"event_count"`
	Violations            []string           `json:"violations,omitempty"`
	VerifiedAt            time.Time          `json:"verified_at"`
}

func (r *RemediationIntegrityVerificationResult) Error() string {
	if r == nil || r.Status == StatusVerified || r.Status == StatusIntegrityOnly {
		return ""
	}
	return fmt.Sprintf("remediation integrity verification %s: %s (violations: %v)", r.RemediationID, r.Status, r.Violations)
}

func (r *IntegrityVerificationResult) Error() string {
	if r == nil || r.Status == StatusVerified || r.Status == StatusIntegrityOnly {
		return ""
	}
	return fmt.Sprintf("integrity verification %s: %s (violations: %v)", r.ResultID, r.Status, r.Violations)
}
