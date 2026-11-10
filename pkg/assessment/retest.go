package assessment

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"felix/pkg/crawler"
	"felix/pkg/report"
	"felix/pkg/secrets"
	"github.com/google/uuid"
)

// -----------------------------------------------------------------------------
// Remediation Retest Engine Constants & Status Enums
// -----------------------------------------------------------------------------

// RetestTransitionStatus defines the auditable outcome of a finding retest.
type RetestTransitionStatus string

const (
	// StatusRemediatedVerified indicates the previously verified defect was retested with valid coverage
	// and fresh empirical evidence proves the defect is no longer reproducible.
	StatusRemediatedVerified RetestTransitionStatus = "REMEDIATED_VERIFIED"

	// StatusRemainingUnresolved indicates the original defect was reproduced by the new test.
	StatusRemainingUnresolved RetestTransitionStatus = "REMAINING_UNRESOLVED"

	// StatusInconclusive indicates execution or evidence is insufficient to prove remediation
	// (e.g. timeout, connection reset, scanner error, or ambiguous defensive response).
	StatusInconclusive RetestTransitionStatus = "INCONCLUSIVE"

	// StatusNotRetested indicates the finding was not tested, was skipped, or had no safe probe.
	StatusNotRetested RetestTransitionStatus = "NOT_RETESTED"

	// StatusOutOfScopeOrAssetUnavailable indicates the target asset is unreachable, down, or no longer authorized.
	StatusOutOfScopeOrAssetUnavailable RetestTransitionStatus = "OUT_OF_SCOPE_OR_ASSET_UNAVAILABLE"

	// StatusNewFinding indicates a fresh defect discovered in the child assessment not present in the original.
	StatusNewFinding RetestTransitionStatus = "NEW_FINDING"
)

// RetestMode specifies whether a full reassessment or targeted proof-probe replay is conducted.
type RetestMode string

const (
	RetestModeFull     RetestMode = "FULL_REASSESSMENT"
	RetestModeTargeted RetestMode = "TARGETED_RETEST"
)

var (
	// ErrOriginalAssessmentNotFound indicates the referenced baseline assessment does not exist in store.
	ErrOriginalAssessmentNotFound = errors.New("retest failed: original baseline assessment not found")

	// ErrOriginalAssessmentNotEligible indicates the assessment is not in a terminal completed state.
	ErrOriginalAssessmentNotEligible = errors.New("retest failed: original assessment is not in COMPLETED or COMPLETED_WITH_ERRORS state")

	// ErrRetestScopeUnauthorized indicates the caller or target scope is not authorized for retest.
	ErrRetestScopeUnauthorized = errors.New("retest failed: unauthorized client context or target scope")

	// ErrDestructiveProbeRejected indicates a historical probe was rejected by the safety guardrail.
	ErrDestructiveProbeRejected = errors.New("retest safety violation: destructive or state-altering probe rejected")
)

// -----------------------------------------------------------------------------
// Retest Engine Models
// -----------------------------------------------------------------------------

// -----------------------------------------------------------------------------
// Authenticated Evidence Models & Trust Architecture
// -----------------------------------------------------------------------------

// EvidenceType defines the cryptographic evidence taxonomy.
type EvidenceType string

const (
	EvidenceTypeSQLiControlledBehavioral EvidenceType = "SQLI_CONTROLLED_BEHAVIORAL"
	EvidenceTypeSQLiDBInstrumentation   EvidenceType = "SQLI_DB_INSTRUMENTATION"
	EvidenceTypeBOLADualPrincipal        EvidenceType = "BOLA_DUAL_PRINCIPAL"
	EvidenceTypeAuthAppProvenance        EvidenceType = "AUTH_APP_PROVENANCE"
	EvidenceTypeCORSBrowserSuite         EvidenceType = "CORS_BROWSER_SUITE"
)

// EvidenceOutcome defines the deterministic verdict of an evidence record.
type EvidenceOutcome string

const (
	EvidenceOutcomeRemediatedConfirmed EvidenceOutcome = "REMEDIATED_CONFIRMED"
	EvidenceOutcomeDefectReproduced     EvidenceOutcome = "DEFECT_REPRODUCED"
	EvidenceOutcomeInconclusive         EvidenceOutcome = "INCONCLUSIVE"
)

// EvidencePayload represents the canonical structured evidence record.
type EvidencePayload struct {
	EvidenceID         string          `json:"evidence_id"`
	EvidenceType       EvidenceType    `json:"evidence_type"`
	IssuerID           string          `json:"issuer_id"`
	TargetURL          string          `json:"target_url"`
	AssetID            string          `json:"asset_id,omitempty"`
	Endpoint           string          `json:"endpoint"`
	FindingID          string          `json:"finding_id"`
	OriginalFindingRef string          `json:"original_finding_ref"`
	RetestExecutionID  string          `json:"retest_execution_id,omitempty"`
	IssuedAt           time.Time       `json:"issued_at"`
	ExpiresAt          time.Time       `json:"expires_at"`
	VerificationMethod string          `json:"verification_method"`
	Outcome            EvidenceOutcome `json:"outcome"`
	Details            map[string]any  `json:"details,omitempty"`
}

// EvidenceSignature contains the cryptographic signature and key identifier.
type EvidenceSignature struct {
	Algorithm    string `json:"algorithm"` // Always "Ed25519"
	KeyID        string `json:"key_id"`
	SignatureHex string `json:"signature_hex"`
}

// SignedEvidenceRecord encapsulates a canonical evidence payload, its canonical digest, and signature.
type SignedEvidenceRecord struct {
	Payload         EvidencePayload   `json:"payload"`
	CanonicalDigest string            `json:"canonical_digest"`
	Signature       EvidenceSignature `json:"signature"`
}

// EvidenceVerificationOptions specifies verification criteria and independent trust anchor registry.
type EvidenceVerificationOptions struct {
	Registry          TrustedKeyRegistry
	ExpectedTargetURL string
	ExpectedAssetID   string
	ExpectedEndpoint  string
	ExpectedFindingID string
	ExecutionID       string
	MaxAge            time.Duration
}

// EvidenceVerificationResult details the outcome of verifying a SignedEvidenceRecord.
type EvidenceVerificationResult struct {
	Valid             bool         `json:"valid"`
	KeyTrusted        bool         `json:"key_trusted"`
	DigestMatched     bool         `json:"digest_matched"`
	SignatureVerified bool         `json:"signature_verified"`
	EvidenceID        string       `json:"evidence_id"`
	EvidenceType      EvidenceType `json:"evidence_type"`
	IssuerID          string       `json:"issuer_id"`
	KeyID             string       `json:"key_id"`
	FailureReason     string       `json:"failure_reason,omitempty"`
	VerifiedAt        time.Time    `json:"verified_at"`
}

// TrustedEvidenceContext defines independent, auditor-verified trust anchors
// for evaluating remediation outcomes. Unauthenticated caller-supplied booleans,
// strings, references, target headers, and target JSON self-assertions are strictly
// rejected as independent proof unless verified through an authenticated SignedEvidenceRecord.
//
// CRITICAL TRUST BOUNDARY:
// Evaluators MUST NEVER trust a pre-populated VerifiedEvidence or caller boolean as proof.
// The actual SignedRecord must be directly verified against ProtectedRegistry during evaluation.
type TrustedEvidenceContext struct {
	// SignedRecord is the raw cryptographically signed evidence record submitted for verification.
	SignedRecord *SignedEvidenceRecord `json:"signed_record,omitempty"`

	// ProtectedRegistry is the protected application-level trusted-key registry.
	ProtectedRegistry TrustedKeyRegistry `json:"-"`

	// RetestExecutionID binds the evidence to the current retest execution context.
	RetestExecutionID string `json:"retest_execution_id,omitempty"`

	// VerifiedEvidence is populated ONLY as informational output after internal evaluation.
	// IT IS NEVER READ OR TRUSTED AS INPUT BY evaluateResponseCondition.
	VerifiedEvidence *EvidenceVerificationResult `json:"verified_evidence,omitempty"`

	// Unauthenticated caller-supplied fields (REJECTED as independent proof on their own)
	SQLiControlledBehavioralVerified bool   `json:"sqli_controlled_behavioral_verified,omitempty"`
	SQLiTrustedInstrumentationRef    string `json:"sqli_trusted_instrumentation_ref,omitempty"`
	BOLATrustedDualPrincipal         bool   `json:"bola_trusted_dual_principal,omitempty"`
	BOLAOwnerAccessVerified          bool   `json:"bola_owner_access_verified,omitempty"`
	BOLAOwnerPrincipalID             string `json:"bola_owner_principal_id,omitempty"`
	BOLAUnauthorizedPrincipalID      string `json:"bola_unauthorized_principal_id,omitempty"`
	BOLAProtectedObjectID            string `json:"bola_protected_object_id,omitempty"`
	AuthApplicationProvenanceVerified bool   `json:"auth_application_provenance_verified,omitempty"`
	AuthProvenanceMechanism           string `json:"auth_provenance_mechanism,omitempty"`
	CORSBrowserVerificationCompleted bool   `json:"cors_browser_verification_completed,omitempty"`
}

// ProofProbe captures the exact deterministic, non-destructive probe required to reproduce a defect.
type ProofProbe struct {
	FindingID           string                  `json:"finding_id"`
	OriginalFindingRef  string                  `json:"original_finding_ref"`
	TargetURL           string                  `json:"target_url"`
	Endpoint            string                  `json:"endpoint"`
	Method              string                  `json:"method"`
	Headers             map[string]string       `json:"headers,omitempty"`
	Parameters          map[string]string       `json:"parameters,omitempty"`
	Payload             string                  `json:"payload,omitempty"`
	OriginalEvidence    string                  `json:"original_evidence"`
	ProofCondition      string                  `json:"proof_condition"`
	SafeCurlCommand     string                  `json:"safe_curl_command,omitempty"`
	IsDestructive       bool                    `json:"is_destructive"`
	IsEligible          bool                    `json:"is_eligible"`
	IneligibilityReason string                  `json:"ineligibility_reason,omitempty"`
	TrustedEvidence     *TrustedEvidenceContext `json:"trusted_evidence,omitempty"`
	SignedEvidence      *SignedEvidenceRecord   `json:"signed_evidence,omitempty"`
	ExecutionID         string                  `json:"execution_id,omitempty"`
}

// FindingTransitionRecord documents the explicit, auditable transition of an individual finding.
type FindingTransitionRecord struct {
	OriginalFindingID    string                 `json:"original_finding_id,omitempty"`
	ChildFindingID       string                 `json:"child_finding_id,omitempty"`
	Fingerprint          string                 `json:"fingerprint"`
	RuleID               string                 `json:"rule_id"`
	Title                string                 `json:"title"`
	Severity             string                 `json:"severity"`
	OriginalStatus       string                 `json:"original_status"`
	OriginalVerification string                 `json:"original_verification"`
	TransitionStatus     RetestTransitionStatus `json:"transition_status"`
	Rationale            string                 `json:"rationale"`
	ProbeReplayed        bool                   `json:"probe_replayed"`
	FreshEvidence        string                 `json:"fresh_evidence,omitempty"`
	HTTPStatusObserved   int                    `json:"http_status_observed,omitempty"`
	ResponseEvidenceRef  string                 `json:"response_evidence_ref,omitempty"`
	TransitionedAt       time.Time              `json:"transitioned_at"`
	Classification       string                 `json:"evidence_classification"` // LIVE_TARGET, FIXTURE, MOCK, SYNTHETIC
}

// EngineCoverageSummary details the execution outcome and coverage of an individual engine module.
type EngineCoverageSummary struct {
	EngineID           string   `json:"engine_id"`
	EngineName         string   `json:"engine_name"`
	EngineVersion      string   `json:"engine_version"`
	Attempted          bool     `json:"attempted"`
	Executed           bool     `json:"executed"`
	Success            bool     `json:"success"`
	CoverageStatus     string   `json:"coverage_status"` // "FULL", "PARTIAL", "SKIPPED", "MISSING", "FAILED"
	AssetsCovered      []string `json:"assets_covered,omitempty"`
	TargetsTested      []string `json:"targets_tested,omitempty"` // Retained for backwards compatibility
	CategoriesCovered  []string `json:"categories_covered,omitempty"`
	ChecksRun          int      `json:"checks_run"`
	FindingCount       int      `json:"finding_count"`
	Errors             []string `json:"errors,omitempty"`
	SkippedChecks      []string `json:"skipped_checks,omitempty"`
	CoverageGaps       []string `json:"coverage_gaps,omitempty"`
	SkippedReason      string   `json:"skipped_reason,omitempty"`
	EvidenceProvenance string   `json:"evidence_provenance,omitempty"`
}

// FullAssessmentComparison provides a deterministic, machine-readable comparison between baseline and child assessments.
type FullAssessmentComparison struct {
	OriginalAssessmentID     string                           `json:"original_assessment_id"`
	OriginalAssessmentRef    string                           `json:"original_assessment_ref"`
	ChildAssessmentID        string                           `json:"child_assessment_id"`
	ChildAssessmentRef       string                           `json:"child_assessment_ref"`
	RetestMode               RetestMode                       `json:"retest_mode"`
	ExecutedAt               time.Time                        `json:"executed_at"`
	DurationMs               int64                            `json:"duration_ms"`

	// Scope and Target Assets
	OriginalScopeMode        string                           `json:"original_scope_mode"`
	OriginalTargets          []string                         `json:"original_targets"`
	ChildTargets             []string                         `json:"child_targets"`
	ScopeCoverage            string                           `json:"scope_coverage"` // FULL_OVERLAP, PARTIAL_OVERLAP, DISJOINT

	// Assets and Endpoints
	OriginalEndpoints        []string                         `json:"original_endpoints,omitempty"`
	ChildEndpoints           []string                         `json:"child_endpoints,omitempty"`
	EndpointsCovered         int                              `json:"endpoints_covered"`
	EndpointsGained          []string                         `json:"endpoints_gained,omitempty"`
	EndpointsLost            []string                         `json:"endpoints_lost,omitempty"`

	// Engine & Category Coverage
	EngineCoverage           map[string]EngineCoverageSummary `json:"engine_coverage"`
	CategoryCoverage         map[string]string                `json:"category_coverage"`
	DisclosedGaps            []string                         `json:"disclosed_gaps,omitempty"`
	CoverageGained           []string                         `json:"coverage_gained,omitempty"`
	CoverageLost             []string                         `json:"coverage_lost,omitempty"`

	// Finding Outcome Counts
	OriginalFindingCount     int                              `json:"original_finding_count"`
	ChildFindingCount        int                              `json:"child_finding_count"`
	RemediatedVerifiedCount  int                              `json:"remediated_verified_count"`
	SimulatedRemediatedCount int                              `json:"simulated_remediated_count"`
	RemainingUnresolvedCount int                              `json:"remaining_unresolved_count"`
	InconclusiveCount        int                              `json:"inconclusive_count"`
	NotRetestedCount         int                              `json:"not_retested_count"`
	UnavailableCount         int                              `json:"unavailable_count"`
	NewFindingCount          int                              `json:"new_finding_count"`

	// Severity Distributions
	OriginalSeverityDist     map[string]int                   `json:"original_severity_distribution"`
	ChildSeverityDist        map[string]int                   `json:"child_severity_distribution"`

	// Explicit Transitions
	Transitions              []FindingTransitionRecord        `json:"transitions"`

	// Cleanliness Determination
	IsAssessmentClean        bool                             `json:"is_assessment_clean"`
	CleanlinessExplanation   string                           `json:"cleanliness_explanation"`

	// Evidence Classification
	EvidenceClassification   string                           `json:"evidence_classification"`
}

// ComputeCanonicalEvidenceDigest computes deterministic sha256:<hex> digest of the canonical evidence payload.
func ComputeCanonicalEvidenceDigest(payload EvidencePayload) (string, error) {
	norm := payload
	if !norm.IssuedAt.IsZero() {
		norm.IssuedAt = norm.IssuedAt.UTC().Truncate(time.Second)
	}
	if !norm.ExpiresAt.IsZero() {
		norm.ExpiresAt = norm.ExpiresAt.UTC().Truncate(time.Second)
	}
	b, err := json.Marshal(norm)
	if err != nil {
		return "", fmt.Errorf("canonical evidence json marshaling failed: %w", err)
	}
	h := sha256.Sum256(b)
	return fmt.Sprintf("sha256:%x", h), nil
}

// SignEvidenceRecord signs an evidence payload using an AttestationSigner.
func SignEvidenceRecord(payload EvidencePayload, signer AttestationSigner) (*SignedEvidenceRecord, error) {
	if signer == nil {
		return nil, errors.New("signer cannot be nil")
	}
	digest, err := ComputeCanonicalEvidenceDigest(payload)
	if err != nil {
		return nil, err
	}
	signEnvelope := fmt.Sprintf("FELIX_EVIDENCE_V1:%s:%s", digest, signer.KeyID())
	sigBytes, err := signer.Sign([]byte(signEnvelope))
	if err != nil {
		return nil, fmt.Errorf("failed signing evidence payload: %w", err)
	}
	return &SignedEvidenceRecord{
		Payload:         payload,
		CanonicalDigest: digest,
		Signature: EvidenceSignature{
			Algorithm:    "Ed25519",
			KeyID:        signer.KeyID(),
			SignatureHex: hex.EncodeToString(sigBytes),
		},
	}, nil
}

// NewEvidenceSignerAuthority creates an independent in-memory evidence signer and its corresponding TrustedKey.
// Limitation Notice: InMemoryEd25519Signer is an in-memory test/lab signer. In production environments,
// evidence signing must be performed by dedicated hardware security modules (HSM) or cloud KMS.
func NewEvidenceSignerAuthority(keyID, authority, description string) (AttestationSigner, TrustedKey, error) {
	signer, err := GenerateEd25519Signer(keyID)
	if err != nil {
		return nil, TrustedKey{}, err
	}
	tk := TrustedKey{
		KeyID:       signer.KeyID(),
		PublicKey:   signer.PublicKey(),
		Authority:   authority,
		Description: description,
	}
	return signer, tk, nil
}

// VerifySignedEvidence verifies a SignedEvidenceRecord against independent trust anchors and matching criteria.
// An embedded public key or self-assertion NEVER establishes trust.
func VerifySignedEvidence(rec SignedEvidenceRecord, opts EvidenceVerificationOptions) (*EvidenceVerificationResult, error) {
	now := time.Now().UTC()
	res := &EvidenceVerificationResult{
		EvidenceID:   rec.Payload.EvidenceID,
		EvidenceType: rec.Payload.EvidenceType,
		IssuerID:     rec.Payload.IssuerID,
		KeyID:        rec.Signature.KeyID,
		VerifiedAt:   now,
	}

	// 1. Basic structural checks
	if rec.Payload.EvidenceID == "" {
		res.FailureReason = "evidence record missing mandatory evidence_id"
		return res, nil
	}
	if rec.Signature.SignatureHex == "" || rec.Signature.KeyID == "" {
		res.FailureReason = "evidence record missing mandatory signature or key_id"
		return res, nil
	}

	// 2. Canonical Digest Verification (Tamper detection)
	recomputedDigest, err := ComputeCanonicalEvidenceDigest(rec.Payload)
	if err != nil {
		res.FailureReason = fmt.Sprintf("failed recomputing canonical digest: %v", err)
		return res, nil
	}
	if recomputedDigest != rec.CanonicalDigest {
		res.FailureReason = fmt.Sprintf("canonical digest mismatch (expected %s, got %s): record has been altered", rec.CanonicalDigest, recomputedDigest)
		return res, nil
	}
	res.DigestMatched = true

	// 3. Expiration and MaxAge verification
	if !rec.Payload.ExpiresAt.IsZero() && now.After(rec.Payload.ExpiresAt) {
		res.FailureReason = fmt.Sprintf("evidence record expired at %s (current time: %s)", rec.Payload.ExpiresAt.Format(time.RFC3339), now.Format(time.RFC3339))
		return res, nil
	}
	if opts.MaxAge > 0 && !rec.Payload.IssuedAt.IsZero() && now.Sub(rec.Payload.IssuedAt) > opts.MaxAge {
		res.FailureReason = fmt.Sprintf("evidence record exceeds maximum allowable age (%v)", opts.MaxAge)
		return res, nil
	}
	if !rec.Payload.IssuedAt.IsZero() && rec.Payload.IssuedAt.After(now.Add(5*time.Minute)) {
		res.FailureReason = "evidence record issued_at timestamp is in the future"
		return res, nil
	}

	// 4. Target & Asset Scope Verification
	if opts.ExpectedTargetURL != "" && !urlsMatchOrContained(rec.Payload.TargetURL, opts.ExpectedTargetURL) {
		res.FailureReason = fmt.Sprintf("evidence target_url %q does not match expected target %q", rec.Payload.TargetURL, opts.ExpectedTargetURL)
		return res, nil
	}
	if opts.ExpectedEndpoint != "" && (rec.Payload.Endpoint == "" || !endpointsMatch(rec.Payload.Endpoint, opts.ExpectedEndpoint)) {
		res.FailureReason = fmt.Sprintf("evidence endpoint %q does not match expected endpoint %q", rec.Payload.Endpoint, opts.ExpectedEndpoint)
		return res, nil
	}
	if opts.ExpectedFindingID != "" {
		matchedFinding := rec.Payload.FindingID == opts.ExpectedFindingID || rec.Payload.OriginalFindingRef == opts.ExpectedFindingID
		if !matchedFinding {
			res.FailureReason = fmt.Sprintf("evidence finding ref %q does not match expected finding %q", rec.Payload.FindingID, opts.ExpectedFindingID)
			return res, nil
		}
	}
	if opts.ExpectedAssetID != "" && rec.Payload.AssetID != "" && rec.Payload.AssetID != opts.ExpectedAssetID {
		res.FailureReason = fmt.Sprintf("evidence asset_id %q does not match expected asset %q", rec.Payload.AssetID, opts.ExpectedAssetID)
		return res, nil
	}
	if opts.ExecutionID != "" && rec.Payload.RetestExecutionID != "" && rec.Payload.RetestExecutionID != opts.ExecutionID {
		res.FailureReason = fmt.Sprintf("evidence execution_id %q does not match current retest execution %q", rec.Payload.RetestExecutionID, opts.ExecutionID)
		return res, nil
	}

	// 5. Independent Trusted Key Registry Verification
	if opts.Registry == nil {
		res.FailureReason = "no independent trusted key registry configured; cannot establish key trustworthiness"
		return res, nil
	}
	trustedKey, ok := opts.Registry.LookupKey(rec.Signature.KeyID)
	if !ok {
		res.FailureReason = fmt.Sprintf("evidence signing key %q is unknown (not present in trusted key registry)", rec.Signature.KeyID)
		return res, nil
	}
	if len(trustedKey.PublicKey) != ed25519.PublicKeySize {
		res.FailureReason = fmt.Sprintf("trusted key %q has invalid public key length", rec.Signature.KeyID)
		return res, nil
	}
	if trustedKey.Authority != "" && rec.Payload.IssuerID != "" && trustedKey.Authority != rec.Payload.IssuerID {
		res.FailureReason = fmt.Sprintf("trusted key authority %q does not match evidence issuer_id %q", trustedKey.Authority, rec.Payload.IssuerID)
		return res, nil
	}
	res.KeyTrusted = true

	// 6. Cryptographic Signature Verification
	sigBytes, err := hex.DecodeString(rec.Signature.SignatureHex)
	if err != nil || len(sigBytes) != ed25519.SignatureSize {
		res.FailureReason = "evidence signature is not valid hex or does not match Ed25519 signature size"
		return res, nil
	}
	expectedEnvelope := fmt.Sprintf("FELIX_EVIDENCE_V1:%s:%s", rec.CanonicalDigest, rec.Signature.KeyID)
	if !ed25519.Verify(trustedKey.PublicKey, []byte(expectedEnvelope), sigBytes) {
		res.FailureReason = "cryptographic Ed25519 signature verification failed: signature invalid for trusted public key"
		return res, nil
	}
	res.SignatureVerified = true

	// 7. Outcome and Method Validation
	if rec.Payload.Outcome != EvidenceOutcomeRemediatedConfirmed {
		res.FailureReason = fmt.Sprintf("evidence outcome %q does not confirm remediation", rec.Payload.Outcome)
		return res, nil
	}

	// 8. Specific Payload Details Validation per EvidenceType
	switch rec.Payload.EvidenceType {
	case EvidenceTypeSQLiControlledBehavioral:
		if getBoolDetail(rec.Payload.Details, "positive_control_reproduced") != true {
			res.FailureReason = "SQLi behavioral evidence missing verified positive-control reproduction proof"
			return res, nil
		}
		if getBoolDetail(rec.Payload.Details, "retest_safe") != true {
			res.FailureReason = "SQLi behavioral evidence missing verified safe controlled retest proof"
			return res, nil
		}
	case EvidenceTypeSQLiDBInstrumentation:
		if getStringDetail(rec.Payload.Details, "db_query_hash") == "" && getStringDetail(rec.Payload.Details, "db_log_ref") == "" {
			res.FailureReason = "SQLi DB instrumentation evidence missing query hash or db log reference"
			return res, nil
		}
	case EvidenceTypeBOLADualPrincipal:
		pA := getStringDetail(rec.Payload.Details, "principal_owner")
		pB := getStringDetail(rec.Payload.Details, "principal_unauthorized")
		if pA == "" || pB == "" || pA == pB {
			res.FailureReason = "BOLA evidence requires two distinct authenticated principals (owner != unauthorized)"
			return res, nil
		}
		if getBoolDetail(rec.Payload.Details, "owner_access_verified") != true {
			res.FailureReason = "BOLA evidence missing positive control proof of legitimate owner access"
			return res, nil
		}
		if getBoolDetail(rec.Payload.Details, "unauthorized_denied") != true {
			res.FailureReason = "BOLA evidence missing proof of unauthorized principal access denial"
			return res, nil
		}
		if getBoolDetail(rec.Payload.Details, "zero_data_leakage") != true {
			res.FailureReason = "BOLA evidence failed zero object data leakage guarantee"
			return res, nil
		}
	case EvidenceTypeAuthAppProvenance:
		if getStringDetail(rec.Payload.Details, "auth_mechanism") == "" {
			res.FailureReason = "Auth provenance evidence missing verified application authentication mechanism"
			return res, nil
		}
	case EvidenceTypeCORSBrowserSuite:
		if getStringDetail(rec.Payload.Details, "browser_runner_id") == "" {
			res.FailureReason = "CORS evidence missing authenticated browser runner identity"
			return res, nil
		}
		if getBoolDetail(rec.Payload.Details, "untrusted_origin_isolated") != true {
			res.FailureReason = "CORS browser suite failed untrusted origin isolation check"
			return res, nil
		}
	default:
		res.FailureReason = fmt.Sprintf("unsupported or unknown evidence type %q", rec.Payload.EvidenceType)
		return res, nil
	}

	res.Valid = true
	return res, nil
}

func urlsMatchOrContained(u1, u2 string) bool {
	parsed1, err1 := url.Parse(u1)
	parsed2, err2 := url.Parse(u2)
	if err1 != nil || err2 != nil {
		return strings.EqualFold(u1, u2)
	}
	return strings.EqualFold(parsed1.Host, parsed2.Host) && strings.EqualFold(parsed1.Path, parsed2.Path)
}

func endpointsMatch(ep1, ep2 string) bool {
	norm1 := strings.TrimRight(strings.ToLower(ep1), "/")
	norm2 := strings.TrimRight(strings.ToLower(ep2), "/")
	return norm1 == norm2
}

func getBoolDetail(m map[string]any, k string) bool {
	if m == nil {
		return false
	}
	v, ok := m[k]
	if !ok {
		return false
	}
	if b, ok := v.(bool); ok {
		return b
	}
	return false
}

func getStringDetail(m map[string]any, k string) string {
	if m == nil {
		return ""
	}
	v, ok := m[k]
	if !ok {
		return ""
	}
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}

// RetestOptions configures the execution of a remediation retest run.
type RetestOptions struct {
	Mode               RetestMode
	Auth               TenantAuthContext
	OperatorID         string
	TimeoutDuration    time.Duration
	Concurrency        int
	AllowLoopback      bool
	AllowPrivateIPs    bool
	InsecureSkipVerify bool
	SigningKey         AttestationSigner // Phase 9.1 signer (must be trusted production key)
	SigningOptions     AttestationOptions
	CustomHTTPClient   *http.Client      // Injected client for test harnesses / labs
	ProgressFunc       func(msg string)
	EvidenceClass      string            // LIVE_TARGET, FIXTURE, MOCK, SYNTHETIC
	MockFreshFindings  []report.Finding  // For unit tests simulating fresh findings
	EngineRegistry     *EngineRegistry   // Explicit engine registry for full mode orchestration
	TrustedRegistry    TrustedKeyRegistry     // Independent trusted-key registry for evidence verification
	EvidenceRecords    []SignedEvidenceRecord // Independently authenticated evidence records supplied for retest
	ScopeManifestPath  string                 // Path to declarative scope manifest (Phase 9.4)
	ScopeManifest      *PentestManifest       // Pre-parsed pentest manifest for pre-flight guardrail enforcement
}

// DefaultRetestOptions returns standard production options.
// Notice: Auth defaults to empty TenantAuthContext (fail-closed).
// Privileged administrative or tenant context must be explicitly supplied by authenticated caller.
func DefaultRetestOptions() RetestOptions {
	return RetestOptions{
		Mode:            RetestModeFull,
		Auth:            TenantAuthContext{}, // Fails closed unless trusted credentials provided
		TimeoutDuration: 30 * time.Second,
		Concurrency:     4,
		EvidenceClass:   "LIVE_TARGET",
		ProgressFunc:    func(string) {},
	}
}

// RetestResult bundles the complete child assessment, execution, comparison, dossier, and attestation.
type RetestResult struct {
	OriginalAssessment *Assessment
	ChildAssessment    *Assessment
	ChildExecution     *AssessmentExecution
	ChildSnapshot      *AssessmentSnapshot
	Comparison         *FullAssessmentComparison
	Dossier            *report.ExecutiveDossier
	Attestation        *AttestationLetter // Non-nil ONLY if trusted signing key was available
	AttestationStatus  string             // "SIGNED", "UNSIGNED_NO_KEY", "INVALID_SNAPSHOT"
	AttestationReason  string             // Audit explanation of attestation status
	RetestMode         RetestMode
	SkippedChecks      []string           // Explicit list of checks skipped in targeted mode
}

// -----------------------------------------------------------------------------
// Retest Engine
// -----------------------------------------------------------------------------

// RetestEngine coordinates baseline validation, probe replay, child assessment generation, and comparison.
type RetestEngine struct {
	store              Store
	registry           *EngineRegistry
	trustedKeyRegistry TrustedKeyRegistry // Protected application-level trusted-key authority registry
}

// NewRetestEngine constructs a RetestEngine bound to an authoritative assessment Store and optional application-level trusted key registry.
func NewRetestEngine(store Store, trustedKeys ...TrustedKeyRegistry) *RetestEngine {
	var tr TrustedKeyRegistry
	if len(trustedKeys) > 0 {
		tr = trustedKeys[0]
	}
	return &RetestEngine{
		store:              store,
		registry:           DefaultEngineRegistry(store),
		trustedKeyRegistry: tr,
	}
}

// SetTrustedKeyRegistry sets the protected application-level trusted-key registry.
func (e *RetestEngine) SetTrustedKeyRegistry(reg TrustedKeyRegistry) {
	e.trustedKeyRegistry = reg
}

// GetTrustedKeyRegistry returns the protected application-level trusted-key registry.
func (e *RetestEngine) GetTrustedKeyRegistry() TrustedKeyRegistry {
	return e.trustedKeyRegistry
}

// SetEngineRegistry sets the engine registry used by the retest engine.
func (e *RetestEngine) SetEngineRegistry(reg *EngineRegistry) {
	e.registry = reg
}

// GetEngineRegistry returns the engine registry, initializing default if needed.
func (e *RetestEngine) GetEngineRegistry() *EngineRegistry {
	if e.registry == nil {
		e.registry = DefaultEngineRegistry(e.store)
	}
	return e.registry
}

// FindingStatusVerifiedDefect defines the exact status required for historical finding remediation retesting.
const FindingStatusVerifiedDefect report.FindingStatus = "VERIFIED_DEFECT"

// IsEligibleVerifiedDefect evaluates whether a baseline finding qualifies for active remediation retest.
// Under the strict FELIX truth model, ONLY a historical finding whose status is exactly "VERIFIED_DEFECT"
// may enter remediation transition processing.
// Findings with any other status (including CONFIRMED, VERIFIED, POTENTIAL, SUSPECTED, UNVERIFIED,
// SIMULATED, or empty) are strictly rejected. Combinations of separate status and verification fields
// are NOT accepted as substitutes for the exact required status.
// Furthermore, the finding must contain actual reproduction evidence (a safe reproducible request,
// meaningful reproduction steps, or a substantive recorded observation). Metadata-only method and target
// URL describe a possible probe but do not demonstrate a reproducible defect and are strictly rejected.
func IsEligibleVerifiedDefect(af AssessmentFinding) (bool, string) {
	if af.Status != FindingStatusVerifiedDefect {
		return false, fmt.Sprintf("finding status %q is not VERIFIED_DEFECT (only historical findings with status exactly VERIFIED_DEFECT are eligible for remediation transition)", af.Status)
	}

	// Reject mock-only or synthetic fixtures
	if af.VerificationRecord.SyntheticFixture {
		return false, "finding is marked as synthetic fixture without live empirical verification evidence"
	}

	// Require actual reproduction evidence: safe curl command, meaningful reproduction steps, or substantive observation.
	// Metadata-only HTTP method and target URL are strictly insufficient to demonstrate a reproducible defect.
	hasCurl := strings.TrimSpace(af.VerificationRecord.SafeCurlCommand) != ""
	hasObservation := strings.TrimSpace(af.EvidenceDetails.Observation) != ""
	hasSteps := false
	for _, step := range af.VerificationRecord.ReproductionSteps {
		if strings.TrimSpace(step) != "" {
			hasSteps = true
			break
		}
	}

	if !hasCurl && !hasObservation && !hasSteps {
		return false, "finding lacks sufficient deterministic reproduction evidence for proof probe replay (safe curl command, reproduction steps, or substantive observation required; metadata-only method/URL is insufficient)"
	}

	return true, ""
}

// ExtractProofProbe builds a ProofProbe from an eligible verified defect.
func ExtractProofProbe(af AssessmentFinding) (ProofProbe, bool) {
	eligible, reason := IsEligibleVerifiedDefect(af)
	if !eligible {
		return ProofProbe{
			FindingID:           af.ID,
			OriginalFindingRef:  af.OriginalFindingID,
			IsEligible:          false,
			IneligibilityReason: reason,
		}, false
	}

	method := strings.ToUpper(strings.TrimSpace(af.Method))
	if method == "" {
		if af.EvidenceDetails.HTTPMethod != "" {
			method = strings.ToUpper(strings.TrimSpace(af.EvidenceDetails.HTTPMethod))
		} else {
			method = "GET"
		}
	}

	targetURL := af.TargetURL
	if targetURL == "" {
		targetURL = af.Endpoint
	}

	// Safety Check: Reject destructive operations
	isDestructive := isDestructiveOperation(method, targetURL, af.Endpoint)

	proofCond := determineProofCondition(af)

	headers := map[string]string{"Accept": "*/*"}
	payload := af.EvidenceDetails.Observation
	if af.VerificationRecord.SafeCurlCommand != "" {
		for k, v := range parseCurlHeaders(af.VerificationRecord.SafeCurlCommand) {
			headers[k] = v
		}
		if d := parseCurlData(af.VerificationRecord.SafeCurlCommand); d != "" {
			payload = d
		}
	}

	return ProofProbe{
		FindingID:          af.ID,
		OriginalFindingRef: af.OriginalFindingID,
		TargetURL:          targetURL,
		Endpoint:           af.Endpoint,
		Method:             method,
		Headers:            headers,
		Payload:            payload,
		OriginalEvidence:   af.EvidenceDetails.Observation,
		ProofCondition:     proofCond,
		SafeCurlCommand:    af.VerificationRecord.SafeCurlCommand,
		IsDestructive:      isDestructive,
		IsEligible:         !isDestructive,
		IneligibilityReason: func() string {
			if isDestructive {
				return "probe targets state-altering or destructive path rejected by non-destructive safety policy"
			}
			return ""
		}(),
	}, !isDestructive
}

// parseCurlHeaders extracts -H 'Key: Value' or -H "Key: Value" from curl command.
func parseCurlHeaders(curlCmd string) map[string]string {
	headers := make(map[string]string)
	parts := strings.Split(curlCmd, " -H ")
	if len(parts) <= 1 {
		parts = strings.Split(curlCmd, " --header ")
	}
	for i := 1; i < len(parts); i++ {
		p := strings.TrimSpace(parts[i])
		if len(p) == 0 {
			continue
		}
		var val string
		if p[0] == '\'' {
			if end := strings.IndexByte(p[1:], '\''); end != -1 {
				val = p[1 : 1+end]
			}
		} else if p[0] == '"' {
			if end := strings.IndexByte(p[1:], '"'); end != -1 {
				val = p[1 : 1+end]
			}
		} else {
			fields := strings.Fields(p)
			if len(fields) > 0 {
				val = fields[0]
			}
		}
		if colon := strings.IndexByte(val, ':'); colon != -1 {
			k := strings.TrimSpace(val[:colon])
			v := strings.TrimSpace(val[colon+1:])
			if k != "" {
				headers[k] = v
			}
		}
	}
	return headers
}

// parseCurlData extracts -d '...' or --data '...' from curl command.
func parseCurlData(curlCmd string) string {
	dataFlags := []string{" -d ", " --data ", " --data-raw "}
	for _, flag := range dataFlags {
		idx := strings.Index(curlCmd, flag)
		if idx != -1 {
			rem := strings.TrimSpace(curlCmd[idx+len(flag):])
			if len(rem) > 0 {
				if rem[0] == '\'' {
					if end := strings.IndexByte(rem[1:], '\''); end != -1 {
						return rem[1 : 1+end]
					}
				} else if rem[0] == '"' {
					if end := strings.IndexByte(rem[1:], '"'); end != -1 {
						return rem[1 : 1+end]
					}
				}
			}
		}
	}
	return ""
}

// isDestructiveOperation identifies dangerous actions (payments, account deletions, destructive admin).
func isDestructiveOperation(method, targetURL, endpoint string) bool {
	combined := strings.ToLower(targetURL + " " + endpoint)

	dangerousKeywords := []string{
		"/checkout", "/pay", "/charge", "/billing/submit",
		"/delete-account", "/destroy", "/purge", "/wipe",
		"/transfer", "/admin/drop", "/reset-database",
		"/cancel", "/reset",
	}

	for _, kw := range dangerousKeywords {
		if strings.Contains(combined, kw) {
			return true
		}
	}

	// Deletes on sensitive routes
	if method == "DELETE" && (strings.Contains(combined, "/user") || strings.Contains(combined, "/account")) {
		return true
	}

	return false
}

// determineProofCondition infers the empirical proof condition from rule ID and category.
func determineProofCondition(af AssessmentFinding) string {
	rule := strings.ToUpper(af.RuleID)
	cat := strings.ToLower(af.Category)

	switch {
	case strings.Contains(rule, "SQLI") || strings.Contains(cat, "sql"):
		return "SQL_SYNTAX_ERROR_OR_DATA_LEAK"
	case strings.Contains(rule, "XSS") || strings.Contains(cat, "xss"):
		return "UNESCAPED_PAYLOAD_REFLECTION"
	case strings.Contains(rule, "IDOR") || strings.Contains(rule, "BOLA") || strings.Contains(cat, "bola"):
		return "UNAUTHORIZED_OBJECT_ACCESS_200"
	case strings.Contains(rule, "BFLA") || strings.Contains(cat, "bfla"):
		return "PRIVILEGE_ESCALATION_SUCCESS_200"
	case strings.Contains(rule, "HSTS") || strings.Contains(rule, "HEADER"):
		return "MISSING_SECURITY_HEADER"
	case strings.Contains(rule, "CORS"):
		return "PERMISSIVE_CORS_WILDCARD"
	case strings.Contains(rule, "AUTH") || strings.Contains(cat, "auth"):
		return "UNAUTHENTICATED_ACCESS_GRANTED"
	default:
		return "ACTIVE_VULNERABILITY_REPRODUCTION"
	}
}

// ReplayProofProbe executes a non-destructive HTTP proof probe against the target.
func ReplayProofProbe(
	ctx context.Context,
	client *http.Client,
	probe ProofProbe,
	baseline AssessmentFinding,
	timeout time.Duration,
	evidenceClass string,
	registry ...TrustedKeyRegistry,
) FindingTransitionRecord {
	now := time.Now().UTC()
	origID := baseline.OriginalFindingID
	if origID == "" {
		origID = baseline.ID
	}
	rec := FindingTransitionRecord{
		OriginalFindingID:    origID,
		Fingerprint:          baseline.Fingerprint,
		RuleID:               baseline.RuleID,
		Title:                baseline.Title,
		Severity:             baseline.Severity,
		OriginalStatus:       string(baseline.Status),
		OriginalVerification: string(baseline.VerificationStatus),
		TransitionedAt:       now,
		Classification:       evidenceClass,
	}

	if evidenceClass == "" {
		rec.Classification = "LIVE_TARGET"
	}
	if probe.SignedEvidence != nil && probe.SignedEvidence.Payload.Details != nil {
		if cls, ok := probe.SignedEvidence.Payload.Details["evidence_class"].(string); ok && cls != "" {
			rec.Classification = cls
		}
	}

	// Bind authenticated evidence record and protected registry to probe context
	var trustedReg TrustedKeyRegistry
	if len(registry) > 0 && registry[0] != nil {
		trustedReg = registry[0]
	}
	if probe.SignedEvidence != nil {
		if probe.TrustedEvidence == nil {
			probe.TrustedEvidence = &TrustedEvidenceContext{}
		}
		probe.TrustedEvidence.SignedRecord = probe.SignedEvidence
		probe.TrustedEvidence.ProtectedRegistry = trustedReg
		probe.TrustedEvidence.RetestExecutionID = probe.ExecutionID
	} else if probe.TrustedEvidence != nil {
		probe.TrustedEvidence.ProtectedRegistry = trustedReg
		if probe.TrustedEvidence.RetestExecutionID == "" {
			probe.TrustedEvidence.RetestExecutionID = probe.ExecutionID
		}
	}

	// Safety check 1: Ineligible finding
	if !probe.IsEligible {
		rec.TransitionStatus = StatusNotRetested
		rec.Rationale = fmt.Sprintf("ineligible for verified remediation transition: %s", probe.IneligibilityReason)
		rec.ProbeReplayed = false
		return rec
	}

	// Safety check 2: Destructive operation
	if probe.IsDestructive {
		rec.TransitionStatus = StatusNotRetested
		rec.Rationale = "destructive or state-altering probe rejected by non-destructive safety policy"
		rec.ProbeReplayed = false
		return rec
	}

	// Validate target URL format
	u, err := url.Parse(probe.TargetURL)
	if err != nil || u.Scheme == "" || u.Host == "" {
		rec.TransitionStatus = StatusOutOfScopeOrAssetUnavailable
		rec.Rationale = fmt.Sprintf("malformed or unresolvable target URL %q", probe.TargetURL)
		rec.ProbeReplayed = false
		return rec
	}

	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	reqCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	method := probe.Method
	if method == "" {
		method = "GET"
	}

	var bodyReader io.Reader
	if probe.Payload != "" && (method == "POST" || method == "PUT" || method == "PATCH") {
		bodyReader = strings.NewReader(probe.Payload)
	}

	req, err := http.NewRequestWithContext(reqCtx, method, probe.TargetURL, bodyReader)
	if err != nil {
		rec.TransitionStatus = StatusInconclusive
		rec.Rationale = fmt.Sprintf("failed constructing HTTP request: %v", err)
		rec.ProbeReplayed = false
		return rec
	}

	req.Header.Set("User-Agent", "FELIX-Retest-Engine/3.0 (Security Audit Verification; Non-Destructive)")
	req.Header.Set("Accept", "*/*")
	for k, v := range probe.Headers {
		req.Header.Set(k, v)
	}

	resp, err := client.Do(req)
	rec.ProbeReplayed = true

	if err != nil {
		errLower := strings.ToLower(err.Error())
		// Distinguish timeout, connection refused, or network failure
		if errors.Is(err, context.DeadlineExceeded) || strings.Contains(errLower, "timeout") || strings.Contains(errLower, "deadline exceeded") {
			rec.TransitionStatus = StatusInconclusive
			rec.Rationale = fmt.Sprintf("probe execution timed out after %s (cannot prove remediation)", timeout)
			return rec
		}
		if strings.Contains(errLower, "connection refused") ||
			strings.Contains(errLower, "actively refused") ||
			strings.Contains(errLower, "connectex") ||
			strings.Contains(errLower, "no such host") ||
			strings.Contains(errLower, "network is unreachable") {
			rec.TransitionStatus = StatusOutOfScopeOrAssetUnavailable
			rec.Rationale = fmt.Sprintf("target asset unavailable / connection failed: %v", err)
			return rec
		}
		rec.TransitionStatus = StatusInconclusive
		rec.Rationale = fmt.Sprintf("transport error during probe replay: %v", err)
		return rec
	}
	defer resp.Body.Close()

	rec.HTTPStatusObserved = resp.StatusCode
	bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 256*1024)) // 256 KB max
	bodySnippet := secrets.RedactText(string(bodyBytes))

	// Evaluate Response against Proof Condition
	rec.TransitionStatus, rec.Rationale = evaluateResponseCondition(
		resp.StatusCode,
		resp.Header,
		bodySnippet,
		probe.ProofCondition,
		baseline,
		probe.TrustedEvidence,
	)
	rec.FreshEvidence = fmt.Sprintf("HTTP %d; Content-Length: %d; Response snippet: %s",
		resp.StatusCode, len(bodyBytes), truncateSnippet(bodySnippet, 120))
	rec.ResponseEvidenceRef = fmt.Sprintf("resp_%s_%d", baseline.OriginalFindingID, now.Unix())

	return rec
}

// constructNeutralControlURL replaces SQL injection syntax in query parameters with a benign neutral literal.
func constructNeutralControlURL(targetURL string) string {
	u, err := url.Parse(targetURL)
	if err != nil {
		return ""
	}
	q := u.Query()
	if len(q) == 0 {
		return ""
	}
	modified := false
	for k, vals := range q {
		for i, v := range vals {
			vLower := strings.ToLower(v)
			if strings.Contains(v, "'") || strings.Contains(v, "\"") || strings.Contains(v, "--") ||
				strings.Contains(vLower, " or ") || strings.Contains(vLower, " union ") ||
				strings.Contains(vLower, "%27") || strings.Contains(vLower, "1=1") {
				q[k][i] = "felix_ctrl_safe_literal_probe"
				modified = true
			}
		}
	}
	if !modified {
		return ""
	}
	u.RawQuery = q.Encode()
	return u.String()
}

// verifyConsistentZeroExpansion verifies that the exploit probe and neutral control probe
// produced consistent non-expanded responses, proving the parameter was treated as a safe literal.
func verifyConsistentZeroExpansion(exploitBody, ctrlBody string) bool {
	exploitLower := strings.ToLower(exploitBody)
	ctrlLower := strings.ToLower(ctrlBody)

	if hasSQLErrors(exploitLower) || hasSQLErrors(ctrlLower) {
		return false
	}
	// Check for result set expansion: if exploit has users/results and control doesn't
	hasExploitZero := strings.Contains(exploitLower, `"results":[]`) || strings.Contains(exploitLower, `"results": []`) ||
		strings.Contains(exploitLower, `"users":[]`) || strings.Contains(exploitLower, `"users": []`) ||
		strings.Contains(exploitLower, `"count":0`) || strings.Contains(exploitLower, `"count": 0`) ||
		strings.Contains(exploitLower, `"total":0`) || strings.Contains(exploitLower, `"total": 0`)
	hasCtrlZero := strings.Contains(ctrlLower, `"results":[]`) || strings.Contains(ctrlLower, `"results": []`) ||
		strings.Contains(ctrlLower, `"users":[]`) || strings.Contains(ctrlLower, `"users": []`) ||
		strings.Contains(ctrlLower, `"count":0`) || strings.Contains(ctrlLower, `"count": 0`) ||
		strings.Contains(ctrlLower, `"total":0`) || strings.Contains(ctrlLower, `"total": 0`)

	if hasExploitZero && hasCtrlZero {
		return true
	}
	diff := len(exploitBody) - len(ctrlBody)
	if diff < 0 {
		diff = -diff
	}
	return diff < 16
}

// hasSQLErrors inspects body for standard SQL syntax error or exception signatures.
func hasSQLErrors(body string) bool {
	lower := strings.ToLower(body)
	sqlErrors := []string{
		"syntax error", "sqlite3", "sqlite", "mysql_fetch", "ora-01756", "ora-", "pg_query",
		"pg_", "unterminated quotation mark", "sql exception", "sql command",
	}
	for _, e := range sqlErrors {
		if strings.Contains(lower, e) {
			return true
		}
	}
	return false
}

// hasDataLeak checks whether baseline observation data persists in the response body.
func hasDataLeak(body, observation string) bool {
	if observation == "" || len(observation) <= 8 {
		return false
	}
	return strings.Contains(strings.ToLower(body), strings.ToLower(observation))
}

// getHeader retrieves header value using CanonicalHeaderKey or case-insensitive fallback for direct map literals.
func getHeader(headers http.Header, key string) string {
	if val := headers.Get(key); val != "" {
		return val
	}
	target := strings.ToLower(key)
	for k, v := range headers {
		if strings.ToLower(k) == target && len(v) > 0 {
			return v[0]
		}
	}
	return ""
}

// verifyRetestEvidence independently validates the raw SignedEvidenceRecord in tCtx
// against the protected application-level TrustedKeyRegistry.
//
// CRITICAL TRUST BOUNDARY:
// Pre-populated `tCtx.VerifiedEvidence` results, caller booleans, target headers,
// and JSON self-assertions are STRICTLY IGNORED. Verification is freshly executed
// against the authoritative registry, binding TargetURL, AssetID, Endpoint, FindingID,
// and ExecutionID.
func verifyRetestEvidence(tCtx *TrustedEvidenceContext, baseline AssessmentFinding, expectedType EvidenceType) (*EvidenceVerificationResult, bool) {
	if tCtx == nil || tCtx.SignedRecord == nil || tCtx.ProtectedRegistry == nil {
		return nil, false
	}
	origID := baseline.OriginalFindingID
	if origID == "" {
		origID = baseline.ID
	}
	vRes, err := VerifySignedEvidence(*tCtx.SignedRecord, EvidenceVerificationOptions{
		Registry:          tCtx.ProtectedRegistry,
		ExpectedTargetURL: baseline.TargetURL,
		ExpectedAssetID:   baseline.TargetID,
		ExpectedEndpoint:  baseline.Endpoint,
		ExpectedFindingID: origID,
		ExecutionID:       tCtx.RetestExecutionID,
		MaxAge:            24 * time.Hour,
	})
	if err != nil || vRes == nil || !vRes.Valid || vRes.EvidenceType != expectedType {
		return nil, false
	}
	return vRes, true
}

// evaluateResponseCondition evaluates HTTP response against original proof conditions,
// strictly enforcing truth in engineering and robust evidentiary standards for REMEDIATED_VERIFIED.
// Target-asserted response headers (e.g. X-Backend-Query-Parameterized, X-BOLA-Positive-Control,
// X-Application-Auth-Status) or target-generated JSON fields (sanitized, positive_control_verified,
// auth_layer) are untrusted observations and strictly rejected as independent proof of remediation.
func evaluateResponseCondition(
	status int,
	headers http.Header,
	body string,
	proofCond string,
	baseline AssessmentFinding,
	trusted ...*TrustedEvidenceContext,
) (RetestTransitionStatus, string) {
	rule := strings.ToUpper(baseline.RuleID)
	lowerBody := strings.ToLower(body)

	var tCtx *TrustedEvidenceContext
	if len(trusted) > 0 && trusted[0] != nil {
		tCtx = trusted[0]
	}

	// -------------------------------------------------------------------------
	// 1. Perimeter, Edge, and WAF Filtering Detection (Fails closed to INCONCLUSIVE)
	// -------------------------------------------------------------------------
	wafIndicators := []string{
		"cloudflare", "akamai", "imperva", "incapsula", "mod_security", "modsecurity",
		"web application firewall", "waf", "security policy", "blocked by", "request blocked",
		"attack detected", "challenge-platform", "ray id", "sucuri",
	}
	for _, w := range wafIndicators {
		if strings.Contains(lowerBody, w) {
			return StatusInconclusive, fmt.Sprintf("HTTP %d received with edge/WAF interference indicators (%q); edge block does not prove code remediation", status, w)
		}
	}
	if getHeader(headers, "cf-ray") != "" || strings.Contains(strings.ToLower(getHeader(headers, "server")), "cloudflare") ||
		getHeader(headers, "x-akamai-transformed") != "" || getHeader(headers, "x-sucuri-id") != "" {
		return StatusInconclusive, fmt.Sprintf("HTTP %d received with perimeter/WAF headers; intermediary filtering does not prove code remediation", status)
	}

	// -------------------------------------------------------------------------
	// 2. HTTP 401 Unauthorized or HTTP 403 Forbidden
	// -------------------------------------------------------------------------
	if status == http.StatusUnauthorized || status == http.StatusForbidden {
		isBOLA := strings.Contains(rule, "BOLA") || strings.Contains(rule, "IDOR")
		isAuthOrAccessControl := strings.Contains(rule, "AUTH-BYPASS") || strings.Contains(rule, "BFLA") ||
			strings.Contains(rule, "PRIVILEGE") || isBOLA

		if isAuthOrAccessControl {
			// Check for protected object data leakage first
			if baseline.EvidenceDetails.Observation != "" && len(baseline.EvidenceDetails.Observation) > 8 &&
				strings.Contains(lowerBody, strings.ToLower(baseline.EvidenceDetails.Observation)) {
				return StatusRemainingUnresolved, "protected object data still disclosed in error response; vulnerability remains active"
			}

			// BOLA/IDOR requires an independently authenticated dual-principal evidence record.
			// Target-asserted positive-control flags, caller identity headers, injected verification results,
			// and caller booleans are untrusted and strictly rejected as independent proof.
			if isBOLA {
				if vRes, ok := verifyRetestEvidence(tCtx, baseline, EvidenceTypeBOLADualPrincipal); ok {
					return StatusRemediatedVerified, fmt.Sprintf("object-level authorization verified via independent authenticated dual-principal evidence (%s): legitimate owner access confirmed and unauthorized principal denied (HTTP %d %s)", vRes.EvidenceID, status, http.StatusText(status))
				}
				return StatusInconclusive, fmt.Sprintf("HTTP %d received; BOLA/IDOR remediation requires independently authenticated dual-principal evidence record (caller booleans, injected results, and target headers untrusted; inconclusive)", status)
			}

			// For Authentication Bypass / BFLA:
			// Requires independently authenticated application-origin evidence record.
			// Transport-layer status, target headers, injected verification results, and unauthenticated caller booleans are untrusted.
			if vRes, ok := verifyRetestEvidence(tCtx, baseline, EvidenceTypeAuthAppProvenance); ok {
				return StatusRemediatedVerified, fmt.Sprintf("application authentication layer decision verified via independent application-provenance evidence (%s): HTTP %d %s", vRes.EvidenceID, status, http.StatusText(status))
			}

			return StatusInconclusive, fmt.Sprintf("HTTP %d received; response originates from HTTP transport and cannot establish trustworthy application-layer provenance without independently authenticated evidence record (inconclusive)", status)
		}

		// For other defect types (e.g. SQLi, XSS), 401/403 indicates expired auth or generic block
		return StatusInconclusive, fmt.Sprintf("HTTP %d received; authentication may be expired or edge filter triggered (does not prove code-level defect remediation)", status)
	}

	// -------------------------------------------------------------------------
	// 3. HTTP 404 Not Found (Asset / Route Unavailable)
	// -------------------------------------------------------------------------
	if status == http.StatusNotFound {
		return StatusOutOfScopeOrAssetUnavailable, "HTTP 404 Not Found received; target endpoint or resource route is no longer available (asset unavailable)"
	}

	// -------------------------------------------------------------------------
	// 4. Server Errors (HTTP 500 / 502 / 503 / 504)
	// -------------------------------------------------------------------------
	if status >= 500 {
		if strings.Contains(lowerBody, "syntax error") ||
			strings.Contains(lowerBody, "sqlite") ||
			strings.Contains(lowerBody, "mysql") ||
			strings.Contains(lowerBody, "pg_") ||
			strings.Contains(lowerBody, "sql exception") {
			return StatusRemainingUnresolved, "SQL syntax error observed in 500 response; defect remains active"
		}
		return StatusInconclusive, fmt.Sprintf("HTTP %d server error received; target server instability prevents verified remediation determination", status)
	}

	// -------------------------------------------------------------------------
	// 5. Client Validation / Bad Request (HTTP 400 & 422) - NEVER REMEDIATED_VERIFIED
	// -------------------------------------------------------------------------
	if status == http.StatusBadRequest || status == http.StatusUnprocessableEntity {
		sqlErrors := []string{"syntax error", "sqlite", "mysql", "ora-", "pg_", "unterminated quotation mark", "sql exception", "sql command"}
		for _, e := range sqlErrors {
			if strings.Contains(lowerBody, e) {
				return StatusRemainingUnresolved, fmt.Sprintf("SQL syntax error or exception %q observed in HTTP %d response; defect remains active", e, status)
			}
		}

		if strings.Contains(lowerBody, "<script>") || strings.Contains(lowerBody, "<script ") || strings.Contains(lowerBody, "alert(") {
			return StatusRemainingUnresolved, fmt.Sprintf("unescaped attack payload reflected in HTTP %d response; XSS remains exploitable", status)
		}

		if strings.Contains(lowerBody, "root:x:") || strings.Contains(lowerBody, "[boot loader]") {
			return StatusRemainingUnresolved, fmt.Sprintf("sensitive file contents exposed in HTTP %d response; path traversal remains active", status)
		}

		return StatusInconclusive, fmt.Sprintf("HTTP %d received; error response lacks positive vulnerability-specific proof of remediation (inconclusive)", status)
	}

	// -------------------------------------------------------------------------
	// 6. HTTP 200 / 2xx Proof Condition Evaluation
	// -------------------------------------------------------------------------
	switch proofCond {
	case "SQL_SYNTAX_ERROR_OR_DATA_LEAK":
		// (a) Defect symptoms check
		sqlErrors := []string{
			"syntax error", "sqlite3", "sqlite", "mysql_fetch", "ora-01756", "ora-", "pg_query",
			"pg_", "unterminated quotation mark", "sql exception", "sql command",
		}
		for _, e := range sqlErrors {
			if strings.Contains(lowerBody, e) {
				return StatusRemainingUnresolved, fmt.Sprintf("SQL error %q still present in response body; defect remains reproducible", e)
			}
		}
		// (b) Baseline observation data leak check
		if baseline.EvidenceDetails.Observation != "" && len(baseline.EvidenceDetails.Observation) > 8 &&
			strings.Contains(lowerBody, strings.ToLower(baseline.EvidenceDetails.Observation)) {
			return StatusRemainingUnresolved, "original exploit data leak condition persists in response; SQL injection remains reproducible"
		}
		// (c) Empty response body fails closed
		if len(strings.TrimSpace(body)) == 0 {
			return StatusInconclusive, "empty response body received; lacks positive vulnerability-specific evidence of safe SQL query execution (inconclusive)"
		}
		// (d) Trusted Evidence Requirement:
		// Target-generated assertions (X-Backend-Query-Parameterized, "sanitized": true, "parameterized": true,
		// results/count fields), caller booleans, and injected verification results are strictly rejected as independent proof.
		// Remediation requires independently authenticated evidence (validated positive/negative behavioral controls
		// or trusted backend database instrumentation) verified freshly against the protected application-level key registry.
		vResBehavioral, okB := verifyRetestEvidence(tCtx, baseline, EvidenceTypeSQLiControlledBehavioral)
		vResDB, okDB := verifyRetestEvidence(tCtx, baseline, EvidenceTypeSQLiDBInstrumentation)
		if okB {
			return StatusRemediatedVerified, fmt.Sprintf("defect verified remediated: independent authenticated evidence (%s) verified safe parameter handling with positive/negative controls", vResBehavioral.EvidenceID)
		}
		if okDB {
			return StatusRemediatedVerified, fmt.Sprintf("defect verified remediated: independent authenticated database instrumentation evidence (%s) verified prepared statement execution", vResDB.EvidenceID)
		}
		return StatusInconclusive, "HTTP 200 received without independently authenticated evidence record (caller booleans, injected verification results, unauthenticated references, or target response assertions cannot prove parameterization; inconclusive)"

	case "UNESCAPED_PAYLOAD_REFLECTION":
		// (a) Executable browser behavior check (unescaped tags or attribute handlers)
		executablePayloads := []string{"<script>", "<script ", "<img ", "<svg ", "<iframe", "javascript:", " onerror=", " onload="}
		for _, exp := range executablePayloads {
			if strings.Contains(lowerBody, exp) {
				return StatusRemainingUnresolved, fmt.Sprintf("attack payload %q rendered in executable browser context in DOM response; XSS remains exploitable", exp)
			}
		}
		// (b) Response-string encoding alone in HTTP replay CANNOT prove browser DOM context safety.
		// Contextual verification requires headless browser execution. Without browser execution, fail closed to INCONCLUSIVE.
		return StatusInconclusive, "response string encoding observed, but without live browser DOM execution-context verification, client-side sink execution safety cannot be proven (inconclusive)"

	case "MISSING_SECURITY_HEADER":
		if strings.Contains(rule, "HSTS") {
			// 1. Transport check: RFC 6797 §7.2 requires HTTPS. Over plain HTTP, UAs MUST ignore HSTS.
			if strings.HasPrefix(strings.ToLower(baseline.TargetURL), "http://") {
				return StatusInconclusive, "Strict-Transport-Security header evaluated over unencrypted plain HTTP transport; RFC 6797 requires secure HTTPS transport (header is ineffective)"
			}
			hstsHeader := getHeader(headers, "Strict-Transport-Security")
			if hstsHeader == "" {
				return StatusRemainingUnresolved, "Strict-Transport-Security header remains missing"
			}
			lowerHSTS := strings.ToLower(hstsHeader)
			// RFC 6797 §6.1.1: max-age=0 explicitly deletes/disables HSTS policy
			if strings.Contains(lowerHSTS, "max-age=0") || strings.Contains(lowerHSTS, "max-age = 0") || strings.Contains(lowerHSTS, `max-age="0"`) {
				return StatusRemainingUnresolved, "Strict-Transport-Security configured with max-age=0 (disables HSTS policy; defect remains unresolved)"
			}
			if !strings.Contains(lowerHSTS, "max-age") {
				return StatusRemainingUnresolved, "Strict-Transport-Security missing mandatory max-age directive"
			}
			return StatusRemediatedVerified, "defect verified remediated: Strict-Transport-Security header is securely configured (max-age > 0 over HTTPS)"
		}

		if strings.Contains(rule, "X-CONTENT-TYPE") || strings.Contains(rule, "NOSNIFF") {
			xcto := getHeader(headers, "X-Content-Type-Options")
			if !strings.EqualFold(strings.TrimSpace(xcto), "nosniff") {
				return StatusRemainingUnresolved, "X-Content-Type-Options: nosniff remains missing or invalid"
			}
			// Authoritative Content-Type required for nosniff to be effective
			contentType := strings.TrimSpace(getHeader(headers, "Content-Type"))
			if contentType == "" {
				return StatusInconclusive, "X-Content-Type-Options: nosniff header present but Content-Type header is missing; authoritative MIME type required for effective MIME-sniffing protection (inconclusive)"
			}
			return StatusRemediatedVerified, "defect verified remediated: X-Content-Type-Options: nosniff configured with authoritative Content-Type"
		}

		if strings.Contains(rule, "CSP") || strings.Contains(rule, "CONTENT-SECURITY-POLICY") {
			csp := getHeader(headers, "Content-Security-Policy")
			if csp == "" {
				return StatusRemainingUnresolved, "Content-Security-Policy header remains missing"
			}
			lowerCSP := strings.ToLower(csp)
			if strings.Contains(lowerCSP, "unsafe-inline") && !strings.Contains(lowerCSP, "nonce-") && !strings.Contains(lowerCSP, "sha256-") {
				return StatusRemainingUnresolved, "Content-Security-Policy contains unsafe-inline without nonce or hash; script injection defense remains ineffective"
			}
			return StatusRemediatedVerified, "defect verified remediated: Content-Security-Policy header securely configured"
		}

		return StatusInconclusive, "security header verification status inconclusive"

	case "PERMISSIVE_CORS_WILDCARD":
		origin := strings.TrimSpace(getHeader(headers, "Access-Control-Allow-Origin"))
		creds := strings.TrimSpace(getHeader(headers, "Access-Control-Allow-Credentials"))

		// 1. Wildcard origin: whether credentials are true or false, wildcard origin remains insecure
		if origin == "*" {
			if strings.EqualFold(creds, "true") {
				return StatusRemainingUnresolved, "permissive CORS wildcard with credentials allowed; defect remains active"
			}
			return StatusRemainingUnresolved, "Access-Control-Allow-Origin remains wildcard (*); permissive cross-origin defect remains active"
		}

		// 2. Insecure null origin
		if strings.EqualFold(origin, "null") {
			return StatusRemainingUnresolved, "Access-Control-Allow-Origin: null is insecure and exploitable via sandboxed iframes; defect remains active"
		}

		// 3. Dynamic origin reflection: untrusted origin reflected
		if strings.Contains(strings.ToLower(origin), "evil.com") || strings.Contains(strings.ToLower(origin), "attacker") {
			return StatusRemainingUnresolved, "Access-Control-Allow-Origin dynamically reflects untrusted request origin; arbitrary cross-origin defect remains active"
		}

		// 4. Complete browser-level verification requirement:
		// Review the complete browser security behavior, including untrusted-origin reflection, credentials,
		// preflight where applicable, and relevant response headers. Do not declare remediation merely because
		// Access-Control-Allow-Origin is absent or appears restricted on a single HTTP request.
		// Requires independently authenticated browser suite evidence record.
		if vRes, ok := verifyRetestEvidence(tCtx, baseline, EvidenceTypeCORSBrowserSuite); ok {
			return StatusRemediatedVerified, fmt.Sprintf("defect verified remediated: independent authenticated browser suite evidence (%s) confirmed secure cross-origin isolation", vRes.EvidenceID)
		}
		return StatusInconclusive, "CORS browser security behavior requires independently verified signed browser-runner evidence; caller-supplied completion flag, injected results, or single response observation cannot prove remediation without browser execution verification (inconclusive)"

	case "UNAUTHORIZED_OBJECT_ACCESS_200":
		// (a) Check for unauthorized object disclosure
		if baseline.EvidenceDetails.Observation != "" && len(baseline.EvidenceDetails.Observation) > 8 &&
			strings.Contains(lowerBody, strings.ToLower(baseline.EvidenceDetails.Observation)) {
			return StatusRemainingUnresolved, "unauthorized object disclosure observed matching baseline defect; BOLA remains active"
		}
		if len(strings.TrimSpace(body)) == 0 {
			return StatusInconclusive, "empty response body received; lacks positive confirmation of object authorization enforcement (inconclusive)"
		}

		// (b) Target-asserted denial phrases or JSON authorization errors:
		// Denial phrases or error messages alone cannot prove remediation without verified dual-principal evidence.
		isDenial := strings.Contains(lowerBody, "denied") || strings.Contains(lowerBody, "forbidden") ||
			strings.Contains(lowerBody, "unauthorized") || strings.Contains(lowerBody, "not permitted") ||
			strings.Contains(lowerBody, "access control") || strings.Contains(lowerBody, `"error"`)
		if isDenial {
			if vRes, ok := verifyRetestEvidence(tCtx, baseline, EvidenceTypeBOLADualPrincipal); ok {
				return StatusRemediatedVerified, fmt.Sprintf("object-level authorization control verified: independent authenticated dual-principal evidence (%s) confirmed legitimate owner access and unauthorized principal denial without object data disclosure", vRes.EvidenceID)
			}
			return StatusInconclusive, "HTTP 200 received with denial phrase or error message; denial phrase alone cannot prove BOLA remediation without independently verified signed dual-principal evidence record (inconclusive)"
		}

		// (c) Trusted Evidence Requirement:
		if vRes, ok := verifyRetestEvidence(tCtx, baseline, EvidenceTypeBOLADualPrincipal); ok {
			return StatusRemediatedVerified, fmt.Sprintf("object-level authorization control verified: independent authenticated dual-principal evidence (%s) confirmed legitimate owner access and unauthorized principal denial without object data disclosure", vRes.EvidenceID)
		}

		// (d) Without denial and without verified authorization control, protected object remains accessible -> REMAINING_UNRESOLVED
		return StatusRemainingUnresolved, "unauthorized object still accessible via endpoint (HTTP 200 returned without verified object-level authorization control); IDOR/BOLA remains active"

	default:
		// Default to INCONCLUSIVE whenever proof is insufficient under truth-in-engineering model
		if strings.Contains(lowerBody, "error") || strings.Contains(lowerBody, "exception") {
			return StatusRemainingUnresolved, "error conditions observed matching baseline defect behavior"
		}
		return StatusInconclusive, "insufficient empirical evidence to prove vulnerability remediation; defaulting to inconclusive under truth-in-engineering model"
	}
}

func truncateSnippet(s string, maxLen int) string {
	clean := strings.ReplaceAll(s, "\n", " ")
	clean = strings.ReplaceAll(clean, "\r", "")
	clean = strings.TrimSpace(clean)
	if len(clean) <= maxLen {
		return clean
	}
	return clean[:maxLen] + "..."
}

// -----------------------------------------------------------------------------
// Full Assessment Comparison Builder
// -----------------------------------------------------------------------------

// IsSimulatedEvidenceClassification checks whether a classification represents a test fixture,
// mock, or synthetic simulation rather than a real live target verification.
func IsSimulatedEvidenceClassification(c string) bool {
	u := strings.ToUpper(strings.TrimSpace(c))
	return u == "SIMULATED_FIXTURE" || u == "FIXTURE" || u == "MOCK" || u == "SYNTHETIC"
}

// CompareAssessments constructs a FullAssessmentComparison across all dimensions.
func CompareAssessments(
	original *Assessment,
	child *Assessment,
	baselineFindings []AssessmentFinding,
	childFindings []AssessmentFinding,
	mode RetestMode,
	engineSummaries map[string]EngineCoverageSummary,
	transitions []FindingTransitionRecord,
	evidenceClass string,
	durationMs int64,
) *FullAssessmentComparison {
	now := time.Now().UTC()

	origTargets := make([]string, 0, len(original.Targets))
	for _, t := range original.Targets {
		origTargets = append(origTargets, t.TargetURL)
	}
	sort.Strings(origTargets)

	childTargets := make([]string, 0, len(child.Targets))
	for _, t := range child.Targets {
		childTargets = append(childTargets, t.TargetURL)
	}
	sort.Strings(childTargets)

	scopeCov, _ := ComputeScopeCoverage(origTargets, childTargets)

	// Collect endpoints
	origEndpointMap := make(map[string]bool)
	for _, f := range baselineFindings {
		ep := f.Endpoint
		if ep == "" {
			ep = f.TargetURL
		}
		if ep != "" {
			origEndpointMap[ep] = true
		}
	}
	childEndpointMap := make(map[string]bool)
	for _, f := range childFindings {
		ep := f.Endpoint
		if ep == "" {
			ep = f.TargetURL
		}
		if ep != "" {
			childEndpointMap[ep] = true
		}
	}

	origEndpoints := make([]string, 0, len(origEndpointMap))
	for ep := range origEndpointMap {
		origEndpoints = append(origEndpoints, ep)
	}
	sort.Strings(origEndpoints)

	childEndpoints := make([]string, 0, len(childEndpointMap))
	for ep := range childEndpointMap {
		childEndpoints = append(childEndpoints, ep)
	}
	sort.Strings(childEndpoints)

	var gainedEPs, lostEPs []string
	for ep := range childEndpointMap {
		if !origEndpointMap[ep] {
			gainedEPs = append(gainedEPs, ep)
		}
	}
	for ep := range origEndpointMap {
		if !childEndpointMap[ep] {
			lostEPs = append(lostEPs, ep)
		}
	}
	sort.Strings(gainedEPs)
	sort.Strings(lostEPs)

	// Tally outcome counts
	var (
		remediatedCount          int
		simulatedRemediatedCount int
		remainingCount           int
		inconclusiveCount        int
		notRetestedCount         int
		unavailableCount         int
		newFindingCount          int
	)

	for _, tr := range transitions {
		switch tr.TransitionStatus {
		case StatusRemediatedVerified:
			if IsSimulatedEvidenceClassification(tr.Classification) || IsSimulatedEvidenceClassification(evidenceClass) {
				simulatedRemediatedCount++
			} else {
				remediatedCount++
			}
		case StatusRemainingUnresolved:
			remainingCount++
		case StatusInconclusive:
			inconclusiveCount++
		case StatusNotRetested:
			notRetestedCount++
		case StatusOutOfScopeOrAssetUnavailable:
			unavailableCount++
		case StatusNewFinding:
			newFindingCount++
		}
	}

	// Calculate severity distributions
	origDist := map[string]int{
		report.SeverityCritical: 0,
		report.SeverityHigh:     0,
		report.SeverityMedium:   0,
		report.SeverityLow:      0,
		report.SeverityInfo:     0,
	}
	for _, f := range baselineFindings {
		sev := report.NormalizeSeverity(f.Severity)
		origDist[sev]++
	}

	childDist := map[string]int{
		report.SeverityCritical: 0,
		report.SeverityHigh:     0,
		report.SeverityMedium:   0,
		report.SeverityLow:      0,
		report.SeverityInfo:     0,
	}
	for _, f := range childFindings {
		sev := report.NormalizeSeverity(f.Severity)
		childDist[sev]++
	}

	// Category and Engine coverage
	catCoverage := make(map[string]string)
	var disclosedGaps []string
	for name, eng := range engineSummaries {
		if eng.CoverageStatus == "MISSING" || eng.CoverageStatus == "FAILED" || eng.CoverageStatus == "SKIPPED" {
			disclosedGaps = append(disclosedGaps, fmt.Sprintf("%s: %s (%s)", name, eng.CoverageStatus, eng.SkippedReason))
		}
		catCoverage[name] = eng.CoverageStatus
	}
	sort.Strings(disclosedGaps)

	comp := &FullAssessmentComparison{
		OriginalAssessmentID:     original.ID,
		OriginalAssessmentRef:    original.Ref,
		ChildAssessmentID:        child.ID,
		ChildAssessmentRef:       child.Ref,
		RetestMode:               mode,
		ExecutedAt:               now,
		DurationMs:               durationMs,
		OriginalScopeMode:        original.ScopeMode,
		OriginalTargets:          origTargets,
		ChildTargets:             childTargets,
		ScopeCoverage:            scopeCov,
		OriginalEndpoints:        origEndpoints,
		ChildEndpoints:           childEndpoints,
		EndpointsCovered:         len(childEndpoints),
		EndpointsGained:          gainedEPs,
		EndpointsLost:            lostEPs,
		EngineCoverage:           engineSummaries,
		CategoryCoverage:         catCoverage,
		DisclosedGaps:            disclosedGaps,
		OriginalFindingCount:     len(baselineFindings),
		ChildFindingCount:        len(childFindings),
		RemediatedVerifiedCount:  remediatedCount,
		SimulatedRemediatedCount: simulatedRemediatedCount,
		RemainingUnresolvedCount: remainingCount,
		InconclusiveCount:        inconclusiveCount,
		NotRetestedCount:         notRetestedCount,
		UnavailableCount:         unavailableCount,
		NewFindingCount:          newFindingCount,
		OriginalSeverityDist:     origDist,
		ChildSeverityDist:        childDist,
		Transitions:              transitions,
		EvidenceClassification:   evidenceClass,
	}

	comp.IsAssessmentClean, comp.CleanlinessExplanation = evaluateCleanliness(comp)
	return comp
}

// evaluateCleanliness calculates whether an assessment can truthfully be declared clean.
func evaluateCleanliness(c *FullAssessmentComparison) (bool, string) {
	var reasons []string
	if c.RemainingUnresolvedCount > 0 {
		reasons = append(reasons, fmt.Sprintf("%d defect(s) remain unresolved", c.RemainingUnresolvedCount))
	}
	if c.SimulatedRemediatedCount > 0 {
		reasons = append(reasons, fmt.Sprintf("%d finding(s) have only simulated/fixture evidence (live empirical remediation proof required for clean status)", c.SimulatedRemediatedCount))
	}
	if IsSimulatedEvidenceClassification(c.EvidenceClassification) {
		reasons = append(reasons, fmt.Sprintf("assessment evidence classification is %s (live empirical target assessment required for clean status)", c.EvidenceClassification))
	}
	if c.NewFindingCount > 0 {
		reasons = append(reasons, fmt.Sprintf("%d fresh finding(s) discovered in child assessment", c.NewFindingCount))
	}
	if c.InconclusiveCount > 0 {
		reasons = append(reasons, fmt.Sprintf("%d finding(s) inconclusive / ambiguous", c.InconclusiveCount))
	}
	if c.NotRetestedCount > 0 {
		reasons = append(reasons, fmt.Sprintf("%d finding(s) not retested / skipped", c.NotRetestedCount))
	}
	if c.UnavailableCount > 0 {
		reasons = append(reasons, fmt.Sprintf("%d asset(s) unavailable / out of scope", c.UnavailableCount))
	}
	if len(c.DisclosedGaps) > 0 {
		reasons = append(reasons, fmt.Sprintf("%d engine coverage gap(s) disclosed", len(c.DisclosedGaps)))
	}

	if len(reasons) == 0 {
		return true, "All previously verified defects were confirmed remediated with proof probes; zero unresolved, new, inconclusive, or untested findings remain; full engine coverage verified."
	}
	return false, fmt.Sprintf("Assessment cannot be declared clean: %s.", strings.Join(reasons, "; "))
}

// -----------------------------------------------------------------------------
// Retest Engine Execution
// -----------------------------------------------------------------------------

// ExecuteRetest performs the complete remediation retest workflow against a baseline assessment.
func (e *RetestEngine) ExecuteRetest(
	ctx context.Context,
	originalAssessmentID string,
	opts RetestOptions,
) (*RetestResult, error) {
	startTime := time.Now().UTC()
	if e.store == nil {
		return nil, errors.New("retest engine store cannot be nil")
	}

	originalAssessmentID = strings.TrimSpace(originalAssessmentID)
	if originalAssessmentID == "" {
		return nil, errors.New("original assessment ID is required")
	}

	if opts.ProgressFunc == nil {
		opts.ProgressFunc = func(string) {}
	}
	opts.ProgressFunc(fmt.Sprintf("Loading original assessment %q from append-only SQLite store...", originalAssessmentID))

	// 1. Load Original Assessment & Validate Immutability
	original, err := e.store.GetAssessment(originalAssessmentID)
	if err != nil {
		// Attempt ref lookup
		origByRef, errRef := e.store.GetAssessmentByRef(originalAssessmentID)
		if errRef != nil || origByRef == nil {
			return nil, fmt.Errorf("%w: %s (%v)", ErrOriginalAssessmentNotFound, originalAssessmentID, err)
		}
		original = origByRef
	}

	// Validate Tenant Authorization
	if !opts.Auth.IsAdmin() && !opts.Auth.Authorizes(original.ClientID, "", "") {
		return nil, ErrRetestScopeUnauthorized
	}

	// Validate Baseline Integrity & Completion State
	if original.Status != StatusCompleted && original.Status != StatusCompletedWithErrors {
		return nil, fmt.Errorf("%w: current status is %s", ErrOriginalAssessmentNotEligible, original.Status)
	}

	// 2. Load Original Scope, Targets, Exclusions, and Findings
	origTargets, err := e.store.GetTargets(original.ID)
	if err != nil {
		return nil, fmt.Errorf("failed retrieving original targets: %w", err)
	}
	if len(origTargets) == 0 {
		return nil, errors.New("original assessment has no target scope")
	}

	origExclusions, _ := e.store.GetExclusions(original.ID)
	origScopeRules, _ := e.store.GetScopeRules(original.ID)
	origAuthRec, _ := e.store.GetAuthorization(original.ID)

	baselineFindings, err := e.store.GetFindings(original.ID, "")
	if err != nil {
		return nil, fmt.Errorf("failed loading baseline findings: %w", err)
	}

	opts.ProgressFunc(fmt.Sprintf("Baseline loaded: %d targets, %d baseline findings.", len(origTargets), len(baselineFindings)))

	// 3. Create Child Assessment linked to Parent (Never mutate original)
	now := time.Now().UTC()
	suffix := strings.ToUpper(uuid.New().String()[:8])
	childID := fmt.Sprintf("asm-retest-%s-%d-%s", original.ID, now.Unix(), suffix)
	childRef := fmt.Sprintf("ASM-RETEST-%s-%s", original.Ref, suffix)

	modeDesc := "Full Reassessment"
	if opts.Mode == RetestModeTargeted {
		modeDesc = "Targeted Retest"
	}

	configSnap := map[string]interface{}{
		"parent_assessment_id":  original.ID,
		"parent_assessment_ref": original.Ref,
		"retest_mode":           string(opts.Mode),
		"operator_id":           opts.OperatorID,
		"retested_at":           now.Format(time.RFC3339),
	}
	configSnapBytes, _ := json.Marshal(configSnap)

	child := &Assessment{
		ID:                 childID,
		Ref:                childRef,
		ClientID:           original.ClientID,
		Name:               fmt.Sprintf("%s (%s)", original.Name, modeDesc),
		Description:        fmt.Sprintf("Remediation retest linked to parent baseline %s (%s). Operating mode: %s.", original.Ref, original.ID, modeDesc),
		AssessmentType:     original.AssessmentType,
		Status:             StatusRunning,
		CreatedAt:          now,
		UpdatedAt:          now,
		StartedAt:          &now,
		ScopeMode:          original.ScopeMode,
		ConfigSnapshotJSON: string(configSnapBytes),
	}

	if err := e.store.CreateAssessment(child); err != nil {
		return nil, fmt.Errorf("failed creating child retest assessment: %w", err)
	}

	// Link targets, exclusions, and scope rules to child
	for _, t := range origTargets {
		childTgt := t
		childTgt.ID = fmt.Sprintf("tgt-%s-%s", child.ID, uuid.New().String()[:8])
		childTgt.AssessmentID = child.ID
		_ = e.store.AddTarget(&childTgt)
		child.Targets = append(child.Targets, childTgt)
	}
	for _, ex := range origExclusions {
		childEx := ex
		childEx.ID = fmt.Sprintf("ex-%s-%s", child.ID, uuid.New().String()[:8])
		childEx.AssessmentID = child.ID
		_ = e.store.AddExclusion(&childEx)
		child.Exclusions = append(child.Exclusions, childEx)
	}
	for _, sr := range origScopeRules {
		childSr := sr
		childSr.ID = fmt.Sprintf("sr-%s-%s", child.ID, uuid.New().String()[:8])
		childSr.AssessmentID = child.ID
		_ = e.store.AddScopeRule(&childSr)
		child.ScopeRules = append(child.ScopeRules, childSr)
	}
	if origAuthRec != nil {
		childAuth := *origAuthRec
		childAuth.ID = fmt.Sprintf("auth-%s-%s", child.ID, uuid.New().String()[:8])
		childAuth.AssessmentID = child.ID
		_ = e.store.SetAuthorization(&childAuth)
		child.Authorization = &childAuth
	}

	// 4. Setup Safe HTTP Client
	httpClient := opts.CustomHTTPClient
	if httpClient == nil {
		httpClient = &http.Client{
			Timeout: opts.TimeoutDuration,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if len(via) >= 5 {
					return errors.New("stopped after 5 redirects")
				}
				// Verify redirect target is in-scope
				targetHost := req.URL.Hostname()
				inScope := false
				for _, t := range origTargets {
					if u, err := url.Parse(t.TargetURL); err == nil && strings.EqualFold(u.Hostname(), targetHost) {
						inScope = true
						break
					}
				}
				if !inScope && !opts.AllowLoopback {
					return fmt.Errorf("redirect blocked: destination %s is outside authorized assessment scope", targetHost)
				}
				return nil
			},
		}
	}

	manifest := opts.ScopeManifest
	if manifest == nil && opts.ScopeManifestPath != "" {
		if m, err := ParsePentestManifestFile(opts.ScopeManifestPath); err == nil {
			manifest = m
		}
	}
	if manifest != nil {
		if gt, err := NewGuardrailTransport(manifest, GuardrailOptions{
			BaseTransport: httpClient.Transport,
			SSRF: crawler.SafeTransportOptions{
				Timeout:         opts.TimeoutDuration,
				AllowLoopback:   opts.AllowLoopback,
				AllowPrivateIPs: opts.AllowPrivateIPs,
			},
		}); err == nil {
			httpClient.Transport = gt
		}
	}

	// 5. Setup Target Maps and Scope Validator for Independent Verification
	childExecutionID := fmt.Sprintf("exec-%s-%d", child.ID, now.Unix())
	origTargetURLs := make([]string, 0, len(origTargets))
	targetMap := make(map[string]AssessmentTarget, len(origTargets))
	for _, t := range origTargets {
		origTargetURLs = append(origTargetURLs, t.TargetURL)
		targetMap[t.ID] = t
	}
	scopeValidator := NewScopeValidator(original.ScopeMode, origTargetURLs, origScopeRules, origExclusions)

	// Authoritative application trust boundary:
	// Prioritize engine's protected registry. Ordinary requests cannot substitute their own registry.
	trustedRegistry := e.trustedKeyRegistry
	if trustedRegistry == nil && opts.Auth.IsAdmin() && opts.TrustedRegistry != nil {
		trustedRegistry = opts.TrustedRegistry
	}

	// 6. Execute Probes for Baseline Findings
	transitions := make([]FindingTransitionRecord, 0, len(baselineFindings))
	evidenceClass := opts.EvidenceClass
	if evidenceClass == "" {
		evidenceClass = "LIVE_TARGET"
	}

	opts.ProgressFunc(fmt.Sprintf("Evaluating %d baseline findings for proof probe replay...", len(baselineFindings)))

	for _, bf := range baselineFindings {
		probe, eligible := ExtractProofProbe(bf)
		probe.ExecutionID = childExecutionID
		origID := bf.OriginalFindingID
		if origID == "" {
			origID = bf.ID
		}

		if !eligible {
			// Ineligible baseline findings (e.g. SUSPECTED, UNVERIFIED, MOCK)
			tr := FindingTransitionRecord{
				OriginalFindingID:    origID,
				Fingerprint:          bf.Fingerprint,
				RuleID:               bf.RuleID,
				Title:                bf.Title,
				Severity:             bf.Severity,
				OriginalStatus:       string(bf.Status),
				OriginalVerification: string(bf.VerificationStatus),
				TransitionStatus:     StatusNotRetested,
				Rationale:            fmt.Sprintf("ineligible for verified remediation transition: %s", probe.IneligibilityReason),
				ProbeReplayed:        false,
				TransitionedAt:       time.Now().UTC(),
				Classification:       evidenceClass,
			}
			transitions = append(transitions, tr)
			continue
		}

		// Independent Target Scope Validation:
		// Target scope must be independently validated before any probe execution over the wire.
		u, errParse := url.Parse(probe.TargetURL)
		probeHost := ""
		if errParse == nil {
			probeHost = strings.ToLower(u.Hostname())
		}
		isLoopback := opts.AllowLoopback && (probeHost == "localhost" || probeHost == "127.0.0.1" || probeHost == "::1")

		if !isLoopback && !scopeValidator.IsAllowed(probe.TargetURL) {
			isExcluded, excReason := scopeValidator.IsExcluded(probe.TargetURL)
			rationale := fmt.Sprintf("target URL %q is outside authorized assessment scope (probe execution prevented)", probe.TargetURL)
			if isExcluded {
				rationale = fmt.Sprintf("target URL %q matches active exclusion rule: %s (probe execution prevented)", probe.TargetURL, excReason)
			}
			tr := FindingTransitionRecord{
				OriginalFindingID:    origID,
				Fingerprint:          bf.Fingerprint,
				RuleID:               bf.RuleID,
				Title:                bf.Title,
				Severity:             bf.Severity,
				OriginalStatus:       string(bf.Status),
				OriginalVerification: string(bf.VerificationStatus),
				TransitionStatus:     StatusOutOfScopeOrAssetUnavailable,
				Rationale:            rationale,
				ProbeReplayed:        false,
				TransitionedAt:       time.Now().UTC(),
				Classification:       evidenceClass,
			}
			transitions = append(transitions, tr)
			continue
		}

		// Attach authenticated evidence if provided in options matching this finding
		for _, rec := range opts.EvidenceRecords {
			if rec.Payload.FindingID == bf.ID || rec.Payload.OriginalFindingRef == origID || rec.Payload.FindingID == origID {
				probe.SignedEvidence = &rec
				break
			}
		}

		// Replay eligible proof probe
		opts.ProgressFunc(fmt.Sprintf("Replaying deterministic proof probe for %s (%s)...", bf.OriginalFindingID, bf.RuleID))
		tr := ReplayProofProbe(ctx, httpClient, probe, bf, opts.TimeoutDuration, evidenceClass, trustedRegistry)
		transitions = append(transitions, tr)
	}

	// 7. Engine Execution & Coverage Tracking
	var skippedChecks []string
	engineSummaries := make(map[string]EngineCoverageSummary)

	// Collect fresh findings
	var freshFindings []AssessmentFinding

	// Add unresolved findings back as active child findings
	for _, tr := range transitions {
		if tr.TransitionStatus == StatusRemainingUnresolved {
			// Defect reproduced -> create child finding
			childFnd := AssessmentFinding{
				ID:                 fmt.Sprintf("fnd_%s_%s", child.ID, uuid.New().String()[:8]),
				AssessmentID:       child.ID,
				ExecutionID:        childExecutionID,
				TargetID:           origTargets[0].ID,
				OriginalFindingID:  tr.OriginalFindingID,
				RuleID:             tr.RuleID,
				Title:              tr.Title,
				Severity:           tr.Severity,
				Status:             FindingStatusVerifiedDefect,
				VerificationStatus: report.VerificationVerified,
				AnalysisMethod:     report.AnalysisMethodActive,
				Fingerprint:        tr.Fingerprint,
				CreatedAt:          time.Now().UTC(),
				EvidenceDetails: report.EvidenceDetails{
					Observation: tr.FreshEvidence,
				},
				VerificationRecord: report.VerificationRecord{
					Status: report.VerificationVerified,
					Result: "Reproduced by deterministic remediation retest proof probe",
				},
			}
			freshFindings = append(freshFindings, childFnd)
		}
	}

	if opts.Mode == RetestModeTargeted {
		// Document explicitly which checks are skipped in targeted mode
		skippedChecks = []string{
			"Passive URL Discovery & Full Crawl (CrawlEngine)",
			"Whole-Site Attack Surface Inventory Sweeps (AssetDiscovery)",
			"Unrelated Endpoint & Parameter Fuzzing (FuzzEngine)",
			"Broad Category Scans for Non-Defect Endpoints (Scanner)",
			"Static Client Asset & Library Parsing (StaticAnalysis)",
		}

		engineSummaries["retest_probes"] = EngineCoverageSummary{
			EngineID:           "retest_probes",
			EngineName:         "Targeted Proof Probe Replayer",
			EngineVersion:      "3.0.0",
			Attempted:          true,
			Executed:           true,
			Success:            true,
			CoverageStatus:     "FULL",
			AssetsCovered:      origTargetURLs,
			TargetsTested:      origTargetURLs,
			ChecksRun:          len(transitions),
			FindingCount:       len(freshFindings),
			EvidenceProvenance: "targeted_retest_probe_replayer:v3.0.0",
		}

		broadEngines := []struct {
			id    string
			alias string
			name  string
			why   string
		}{
			{AssessmentTypeWebSecurity, "discovery", "Asset Discovery & Web Security Engine", "Skipped in targeted retest mode: active proof probes replayed without full crawl"},
			{AssessmentTypeWebVulnerability, "webvuln", "Web Application Vulnerability Engine", "Broad vulnerability scanner skipped in targeted retest mode"},
			{AssessmentTypeAPISecurity, "apisec", "OWASP API Security Top 10 Engine", "Full API surface scanner skipped in targeted retest mode"},
			{AssessmentTypeSessionSecurity, "sessionsec", "Session & Cookie Security Engine", "Session configuration scanner skipped in targeted retest mode"},
			{AssessmentTypeBOLA, "authz", "BOLA / IDOR Authorization Engine", "Full cross-object access sweep skipped in targeted retest mode"},
		}
		for _, be := range broadEngines {
			sum := EngineCoverageSummary{
				EngineID:           be.id,
				EngineName:         be.name,
				EngineVersion:      "3.0.0",
				Attempted:          false,
				Executed:           false,
				Success:            false,
				CoverageStatus:     "SKIPPED",
				SkippedReason:      be.why,
				SkippedChecks:      []string{be.why},
				EvidenceProvenance: "targeted_mode:skipped",
			}
			engineSummaries[be.id] = sum
			if be.alias != "" {
				engineSummaries[be.alias] = sum
			}
		}
	} else {
		// Full Reassessment Mode: Invoke actual assessment engine orchestration
		opts.ProgressFunc("Orchestrating registered assessment engines against authorized scope...")

		reg := opts.EngineRegistry
		if reg == nil {
			reg = e.GetEngineRegistry()
		}

		// Check if engine registry is empty
		if reg == nil || len(reg.engines) == 0 {
			engineSummaries["registry"] = EngineCoverageSummary{
				EngineID:           "engine_registry",
				EngineName:         "Assessment Engine Registry",
				EngineVersion:      "3.0.0",
				Attempted:          true,
				Executed:           false,
				Success:            false,
				CoverageStatus:     "MISSING",
				CoverageGaps:       []string{"empty engine registry: zero assessment engines available for full reassessment"},
				SkippedReason:      "No assessment engines registered",
				EvidenceProvenance: "engine_orchestration:unregistered",
			}
		} else {
			// Determine applicable suite of engines for full mode
			suite := []string{
				AssessmentTypeWebSecurity,
				AssessmentTypeAPISecurity,
				AssessmentTypeWebVulnerability,
				AssessmentTypeSessionSecurity,
				AssessmentTypeBOLA,
			}

			if original.AssessmentType != "" && original.AssessmentType != AssessmentTypeFull {
				normType := NormalizeAssessmentType(original.AssessmentType)
				hasType := false
				for _, s := range suite {
					if NormalizeAssessmentType(s) == normType {
						hasType = true
						break
					}
				}
				if !hasType {
					suite = append([]string{original.AssessmentType}, suite...)
				}
			}

			execCtx := &EngineExecutionContext{
				Store:           e.store,
				Assessment:      child,
				Execution:       &AssessmentExecution{ID: childExecutionID, AssessmentID: child.ID},
				RunnableTargets: origTargetURLs,
				TargetMap:       targetMap,
				ScopeValidator:  scopeValidator,
				HTTPClient:      httpClient,
				ProgressFunc:    opts.ProgressFunc,
				Options: ExecutionOptions{
					AllowLoopback:   opts.AllowLoopback,
					AllowPrivateIPs: opts.AllowPrivateIPs,
					Concurrency:     opts.Concurrency,
					TimeoutDuration: opts.TimeoutDuration,
				},
				ConfigSnapshot: ScanConfigSnapshot{
					TimeoutSeconds: int(opts.TimeoutDuration.Seconds()),
					Concurrency:    opts.Concurrency,
				},
			}

			for _, engType := range suite {
				runner, err := reg.Get(engType)
				if err != nil || runner == nil {
					// Missing engine in registry
					engineSummaries[engType] = EngineCoverageSummary{
						EngineID:           engType,
						EngineName:         engType,
						EngineVersion:      "3.0.0",
						Attempted:          false,
						Executed:           false,
						Success:            false,
						CoverageStatus:     "MISSING",
						CoverageGaps:       []string{fmt.Sprintf("engine %q is not registered in engine registry", engType)},
						SkippedReason:      fmt.Sprintf("required engine %q missing from registry: %v", engType, err),
						EvidenceProvenance: "engine_orchestration:missing",
					}
					continue
				}

				caps := runner.Capabilities()
				displayName := caps.DisplayName
				if displayName == "" {
					displayName = engType
				}

				summary := EngineCoverageSummary{
					EngineID:           caps.AssessmentType,
					EngineName:         displayName,
					EngineVersion:      "3.0.0",
					Attempted:          true,
					Executed:           true,
					CategoriesCovered:  caps.CoverageCategories,
					EvidenceProvenance: fmt.Sprintf("engine_orchestration:%s:v3.0.0", caps.AssessmentType),
				}

				opts.ProgressFunc(fmt.Sprintf("Executing assessment engine %s (%s)...", displayName, caps.AssessmentType))
				engOut, runErr := runner.Execute(ctx, execCtx)

				if runErr != nil {
					summary.Success = false
					summary.CoverageStatus = "FAILED"
					summary.Errors = []string{runErr.Error()}
					summary.CoverageGaps = []string{fmt.Sprintf("engine %s failed during execution: %v", caps.AssessmentType, runErr)}
				} else {
					summary.Success = true
					summary.CoverageStatus = "FULL"

					if engOut != nil {
						summary.AssetsCovered = engOut.AssessedTargets
						summary.TargetsTested = engOut.AssessedTargets
						summary.ChecksRun = engOut.RequestCount
						if summary.ChecksRun == 0 {
							summary.ChecksRun = len(origTargetURLs)
						}

						for target, errMsg := range engOut.TargetErrors {
							summary.Errors = append(summary.Errors, fmt.Sprintf("%s: %s", target, errMsg))
						}

						totalFindingsFromEngine := 0

						for _, rf := range engOut.ReportFindings {
							totalFindingsFromEngine++
							af := ToAssessmentFinding(child.ID, childExecutionID, origTargets[0].ID, rf)
							isNew := isFindingNew(af, baselineFindings)
							freshFindings = append(freshFindings, af)

							if isNew {
								tr := FindingTransitionRecord{
									ChildFindingID:       af.ID,
									Fingerprint:          af.Fingerprint,
									RuleID:               af.RuleID,
									Title:                af.Title,
									Severity:             af.Severity,
									OriginalStatus:       "N/A",
									OriginalVerification: "N/A",
									TransitionStatus:     StatusNewFinding,
									Rationale:            fmt.Sprintf("fresh finding discovered by %s during full reassessment", displayName),
									TransitionedAt:       time.Now().UTC(),
									Classification:       evidenceClass,
								}
								transitions = append(transitions, tr)
							}
						}

						for _, af := range engOut.AssessmentFindings {
							totalFindingsFromEngine++
							af.AssessmentID = child.ID
							af.ExecutionID = childExecutionID
							isNew := isFindingNew(af, baselineFindings)
							freshFindings = append(freshFindings, af)

							if isNew {
								tr := FindingTransitionRecord{
									ChildFindingID:       af.ID,
									Fingerprint:          af.Fingerprint,
									RuleID:               af.RuleID,
									Title:                af.Title,
									Severity:             af.Severity,
									OriginalStatus:       "N/A",
									OriginalVerification: "N/A",
									TransitionStatus:     StatusNewFinding,
									Rationale:            fmt.Sprintf("fresh finding discovered by %s during full reassessment", displayName),
									TransitionedAt:       time.Now().UTC(),
									Classification:       evidenceClass,
								}
								transitions = append(transitions, tr)
							}
						}

						summary.FindingCount = totalFindingsFromEngine
					}
				}

				engineSummaries[caps.AssessmentType] = summary
				for _, alias := range caps.Aliases {
					engineSummaries[alias] = summary
				}
				if caps.AssessmentType == AssessmentTypeWebSecurity {
					engineSummaries["discovery"] = summary
				} else if caps.AssessmentType == AssessmentTypeWebVulnerability {
					engineSummaries["webvuln"] = summary
				} else if caps.AssessmentType == AssessmentTypeAPISecurity {
					engineSummaries["apisec"] = summary
				} else if caps.AssessmentType == AssessmentTypeBOLA {
					engineSummaries["authz"] = summary
				}
			}
		}

		// Also incorporate any unit-test mock fresh findings if provided
		for _, mf := range opts.MockFreshFindings {
			af := ToAssessmentFinding(child.ID, childExecutionID, origTargets[0].ID, mf)
			isNew := isFindingNew(af, baselineFindings)
			freshFindings = append(freshFindings, af)

			if isNew {
				tr := FindingTransitionRecord{
					ChildFindingID:       af.ID,
					Fingerprint:          af.Fingerprint,
					RuleID:               af.RuleID,
					Title:                af.Title,
					Severity:             af.Severity,
					OriginalStatus:       "N/A",
					OriginalVerification: "N/A",
					TransitionStatus:     StatusNewFinding,
					Rationale:            "fresh finding discovered during full reassessment not present in baseline",
					TransitionedAt:       time.Now().UTC(),
					Classification:       evidenceClass,
				}
				transitions = append(transitions, tr)
			}
		}
	}

	durationMs := time.Since(startTime).Milliseconds()

	// 8. Full Assessment Comparison
	comparison := CompareAssessments(
		original,
		child,
		baselineFindings,
		freshFindings,
		opts.Mode,
		engineSummaries,
		transitions,
		evidenceClass,
		durationMs,
	)

	// 9. Persist Child Execution, Findings, and Snapshot
	childExecution := &AssessmentExecution{
		ID:               childExecutionID,
		AssessmentID:     child.ID,
		Status:           StatusCompleted,
		InitiationSource: "retest_engine",
		StartedAt:        now,
		CompletedAt:      &now,
		DurationMs:       durationMs,
		TargetCount:      len(origTargets),
		FindingCount:     len(freshFindings),
	}
	_ = e.store.CreateExecution(childExecution)

	// Persist all fresh findings
	for i := range freshFindings {
		freshFindings[i].ExecutionID = childExecution.ID
	}
	_ = e.store.SaveFindings(freshFindings)

	compJSON, _ := json.Marshal(comparison)
	childSnapshot := &AssessmentSnapshot{
		ID:             fmt.Sprintf("snp-%s-%d", child.ID, now.Unix()),
		SnapshotRef:    fmt.Sprintf("SNP-%s", child.Ref),
		AssessmentID:   child.ID,
		AssessmentRef:  child.Ref,
		ExecutionID:    childExecution.ID,
		ClientID:       child.ClientID,
		Name:           child.Name,
		AssessmentType: child.AssessmentType,
		Status:         StatusCompleted,
		IsComplete:     true,
		StartedAt:      now,
		CompletedAt:    &now,
		DurationMs:     durationMs,
		TargetCount:    len(origTargets),
		FindingCount:   len(freshFindings),
		ScopeMode:      child.ScopeMode,
		Metadata: map[string]string{
			"retest_comparison":          string(compJSON),
			"remediated_verified_count":  fmt.Sprintf("%d", comparison.RemediatedVerifiedCount),
			"simulated_remediated_count": fmt.Sprintf("%d", comparison.SimulatedRemediatedCount),
			"is_clean":                   fmt.Sprintf("%t", comparison.IsAssessmentClean),
		},
		CreatedAt:      now,
	}
	_ = e.store.CreateSnapshot(childSnapshot, freshFindings, nil)

	// Mark child completed
	_ = e.store.UpdateAssessmentStatus(child.ID, StatusCompleted)
	child.Status = StatusCompleted

	// 9. Dossier Integration (Phase 7.4)
	reportFindings := make([]report.Finding, 0, len(freshFindings))
	for _, f := range freshFindings {
		reportFindings = append(reportFindings, ToReportFinding(f))
	}
	rep := report.BuildMultiTargetReport(comparison.ChildTargets, reportFindings)
	dossier, _ := report.GenerateExecutiveDossier(report.DossierInput{
		Report:          rep,
		Organization:    original.ClientID,
		AssessmentTitle: child.Name,
		Methodology:     "Deterministic Proof Probe Replay and Comparative Remediation Retesting",
		Metadata: map[string]any{
			"remediated_verified_count":  comparison.RemediatedVerifiedCount,
			"simulated_remediated_count": comparison.SimulatedRemediatedCount,
			"is_clean":                   comparison.IsAssessmentClean,
		},
	})

	// 10. Phase 9.1 Attestation Letter Integration
	var attestationLetter *AttestationLetter
	attestationStatus := "UNSIGNED_NO_KEY"
	attestationReason := "Attestation letter not issued: trusted signing key was not provided for this retest execution. Ephemeral keys are prohibited by policy."

	if opts.SigningKey != nil {
		keyID := strings.TrimSpace(opts.SigningKey.KeyID())
		if keyID == "" {
			attestationStatus = "INVALID_SIGNER_KEY"
			attestationReason = "Attestation failed: signing key has empty KeyID"
		} else if comparison.SimulatedRemediatedCount > 0 || IsSimulatedEvidenceClassification(comparison.EvidenceClassification) {
			attestationStatus = "REJECTED_SIMULATED_EVIDENCE"
			attestationReason = fmt.Sprintf("Attestation letter withheld: assessment relies on simulated/fixture evidence (%d simulated finding(s)); Phase 9.1 attestation prohibited from claiming live remediation without live empirical proof", comparison.SimulatedRemediatedCount)
		} else {
			// Build Snapshot for Attestation
			attSnap, errSnap := BuildAttestationSnapshot(
				*child,
				Client{ID: child.ClientID, Name: child.ClientID},
				childExecution,
				freshFindings,
				[]string{"Deterministic Proof Probe Replay", "Comparative Remediation Retesting"},
				nil,
				comparison.DisclosedGaps,
			)
			if errSnap == nil {
				letter, errLetter := GenerateAttestationLetter(attSnap, opts.SigningKey, opts.SigningOptions)
				if errLetter == nil {
					// Verify with public key
					vRes, errV := VerifyAttestationLetter(*letter, opts.SigningKey.PublicKey())
					if errV == nil && vRes.Valid {
						attestationLetter = letter
						attestationStatus = "SIGNED"
						attestationReason = fmt.Sprintf("Cryptographically sealed and verified with authoritative key ID %q", keyID)
					} else {
						attestationStatus = "SIGNATURE_VERIFICATION_FAILED"
						attestationReason = fmt.Sprintf("Attestation verification failed: %v", errV)
					}
				} else {
					attestationStatus = "GENERATION_FAILED"
					attestationReason = fmt.Sprintf("Attestation generation failed: %v", errLetter)
				}
			} else {
				attestationStatus = "SNAPSHOT_BUILD_FAILED"
				attestationReason = fmt.Sprintf("Attestation snapshot build failed: %v", errSnap)
			}
		}
	}

	opts.ProgressFunc("Retest completed successfully.")

	return &RetestResult{
		OriginalAssessment: original,
		ChildAssessment:    child,
		ChildExecution:     childExecution,
		ChildSnapshot:      childSnapshot,
		Comparison:         comparison,
		Dossier:            dossier,
		Attestation:        attestationLetter,
		AttestationStatus:  attestationStatus,
		AttestationReason:  attestationReason,
		RetestMode:         opts.Mode,
		SkippedChecks:      skippedChecks,
	}, nil
}

// FormatRetestComparisonTable renders a clean CLI summary table of the comparison.
func FormatRetestComparisonTable(comp *FullAssessmentComparison) string {
	var b strings.Builder
	b.WriteString("================================================================================\n")
	b.WriteString("FELIX REMEDIATION RETEST & ASSESSMENT COMPARISON REPORT\n")
	b.WriteString("================================================================================\n\n")

	b.WriteString(fmt.Sprintf("Baseline Assessment : %s (%s)\n", comp.OriginalAssessmentRef, comp.OriginalAssessmentID))
	b.WriteString(fmt.Sprintf("Child Retest Run    : %s (%s)\n", comp.ChildAssessmentRef, comp.ChildAssessmentID))
	b.WriteString(fmt.Sprintf("Operating Mode      : %s\n", comp.RetestMode))
	b.WriteString(fmt.Sprintf("Execution Duration  : %d ms\n", comp.DurationMs))
	b.WriteString(fmt.Sprintf("Scope Coverage      : %s (%d targets)\n\n", comp.ScopeCoverage, len(comp.ChildTargets)))

	b.WriteString("--------------------------------------------------------------------------------\n")
	b.WriteString("FINDING OUTCOME SUMMARY\n")
	b.WriteString("--------------------------------------------------------------------------------\n")
	b.WriteString(fmt.Sprintf("  Baseline Findings Total  : %d\n", comp.OriginalFindingCount))
	b.WriteString(fmt.Sprintf("  [+] Remediated Verified  : %d\n", comp.RemediatedVerifiedCount))
	if comp.SimulatedRemediatedCount > 0 {
		b.WriteString(fmt.Sprintf("  [~] Simulated Fixture    : %d (Excluded from live clean decisions)\n", comp.SimulatedRemediatedCount))
	}
	b.WriteString(fmt.Sprintf("  [-] Remaining Unresolved : %d\n", comp.RemainingUnresolvedCount))
	b.WriteString(fmt.Sprintf("  [?] Inconclusive / Error : %d\n", comp.InconclusiveCount))
	b.WriteString(fmt.Sprintf("  [*] Not Retested / Skip  : %d\n", comp.NotRetestedCount))
	b.WriteString(fmt.Sprintf("  [!] Asset Unavailable    : %d\n", comp.UnavailableCount))
	b.WriteString(fmt.Sprintf("  [+] Fresh New Findings   : %d\n", comp.NewFindingCount))
	b.WriteString(fmt.Sprintf("  Current Active Findings  : %d\n\n", comp.ChildFindingCount))

	b.WriteString("--------------------------------------------------------------------------------\n")
	b.WriteString("PER-FINDING TRANSITION AUDIT TRAIL\n")
	b.WriteString("--------------------------------------------------------------------------------\n")
	for i, tr := range comp.Transitions {
		b.WriteString(fmt.Sprintf("%2d. [%s] %s (%s)\n", i+1, tr.TransitionStatus, tr.Title, tr.RuleID))
		b.WriteString(fmt.Sprintf("    Severity: %-8s | Probe Replayed: %v | Original Status: %s\n",
			tr.Severity, tr.ProbeReplayed, tr.OriginalStatus))
		b.WriteString(fmt.Sprintf("    Rationale: %s\n", tr.Rationale))
		if tr.FreshEvidence != "" {
			b.WriteString(fmt.Sprintf("    Evidence:  %s\n", tr.FreshEvidence))
		}
		b.WriteString("\n")
	}

	b.WriteString("--------------------------------------------------------------------------------\n")
	b.WriteString("AUDIT CLEANLINESS DETERMINATION\n")
	b.WriteString("--------------------------------------------------------------------------------\n")
	if comp.IsAssessmentClean {
		b.WriteString("STATUS: CLEAN (Zero unresolved vulnerabilities or coverage gaps)\n")
	} else {
		b.WriteString("STATUS: NOT CLEAN\n")
	}
	b.WriteString(fmt.Sprintf("Reason: %s\n", comp.CleanlinessExplanation))

	if len(comp.DisclosedGaps) > 0 {
		b.WriteString("\nDisclosed Coverage Gaps:\n")
		for _, g := range comp.DisclosedGaps {
			b.WriteString(fmt.Sprintf("  - %s\n", g))
		}
	}
	b.WriteString("================================================================================\n")

	return b.String()
}

// GetParentAssessmentID returns the parent assessment ID linked to a retest assessment.
func GetParentAssessmentID(a *Assessment) string {
	if a == nil || a.ConfigSnapshotJSON == "" {
		return ""
	}
	var m map[string]interface{}
	if err := json.Unmarshal([]byte(a.ConfigSnapshotJSON), &m); err == nil {
		if pid, ok := m["parent_assessment_id"].(string); ok {
			return pid
		}
	}
	return ""
}

// isFindingNew determines whether a child finding represents a newly introduced security defect
// not present in the baseline assessment findings.
func isFindingNew(f AssessmentFinding, baseline []AssessmentFinding) bool {
	for _, b := range baseline {
		if b.Fingerprint != "" && f.Fingerprint != "" && b.Fingerprint == f.Fingerprint {
			return false
		}
		if b.RuleID != "" && f.RuleID != "" && b.RuleID == f.RuleID && b.Endpoint != "" && f.Endpoint != "" && b.Endpoint == f.Endpoint {
			return false
		}
	}
	return true
}
