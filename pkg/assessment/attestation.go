package assessment

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"felix/pkg/report"
	"felix/pkg/secrets"
)

var (
	// ErrAssessmentNotCompleted indicates the assessment has not reached a terminal completed state.
	ErrAssessmentNotCompleted = errors.New("cannot generate attestation letter: assessment is not in COMPLETED or COMPLETED_WITH_ERRORS status")

	// ErrMissingTargets indicates the assessment has no defined authorized target scope.
	ErrMissingTargets = errors.New("cannot generate attestation letter: assessment has no authorized targets")

	// ErrMissingIdentity indicates essential client or assessment identification is absent.
	ErrMissingIdentity = errors.New("cannot generate attestation letter: client or assessment identity missing")

	// ErrTamperedSnapshot indicates the assessment snapshot does not match the signed digest.
	ErrTamperedSnapshot = errors.New("attestation verification failed: snapshot digest mismatch (tampering detected)")

	// ErrInvalidSignature indicates the Ed25519 digital signature is invalid.
	ErrInvalidSignature = errors.New("attestation verification failed: invalid Ed25519 signature")

	// ErrKeyMismatch indicates the public key does not match the expected key ID or identity.
	ErrKeyMismatch = errors.New("attestation verification failed: public key mismatch")

	// ErrUntrustedKey indicates the signing key is not independently trusted.
	ErrUntrustedKey = errors.New("attestation verification failed: signing key is untrusted (embedded public key cannot independently establish trust)")

	// ErrKeyIDMismatch indicates the signing KeyID does not match the expected KeyID.
	ErrKeyIDMismatch = errors.New("attestation verification failed: KeyID does not match expected trusted key ID")

	// ErrFalseZeroVulnerabilityClaim indicates an attestation erroneously claims zero vulnerabilities despite existing findings.
	ErrFalseZeroVulnerabilityClaim = errors.New("truthfulness invariant violation: attestation cannot claim zero Critical/High vulnerabilities when unresolved findings exist")
)

// -----------------------------------------------------------------------------
// Cryptographic Signer Abstraction
// -----------------------------------------------------------------------------

// AttestationSigner defines the cryptographic signing interface for assessment attestations.
type AttestationSigner interface {
	// KeyID returns the public identifier for the active signing key.
	KeyID() string

	// PublicKey returns the Ed25519 public key.
	PublicKey() ed25519.PublicKey

	// Sign computes an Ed25519 signature over the provided data.
	Sign(data []byte) ([]byte, error)
}

// InMemoryEd25519Signer implements AttestationSigner using an in-memory key pair.
type InMemoryEd25519Signer struct {
	keyID      string
	publicKey  ed25519.PublicKey
	privateKey ed25519.PrivateKey
}

// NewInMemoryEd25519Signer constructs a signer with provided Ed25519 keys.
func NewInMemoryEd25519Signer(keyID string, pub ed25519.PublicKey, priv ed25519.PrivateKey) (*InMemoryEd25519Signer, error) {
	if strings.TrimSpace(keyID) == "" {
		return nil, errors.New("keyID cannot be empty")
	}
	if len(pub) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("invalid public key size: expected %d bytes, got %d", ed25519.PublicKeySize, len(pub))
	}
	if len(priv) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("invalid private key size: expected %d bytes, got %d", ed25519.PrivateKeySize, len(priv))
	}
	return &InMemoryEd25519Signer{
		keyID:      keyID,
		publicKey:  pub,
		privateKey: priv,
	}, nil
}

// GenerateEd25519Signer generates a fresh Ed25519 key pair and returns an AttestationSigner.
func GenerateEd25519Signer(keyID string) (*InMemoryEd25519Signer, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed generating Ed25519 key pair: %w", err)
	}
	if keyID == "" {
		fingerprint := sha256.Sum256(pub)
		keyID = fmt.Sprintf("KEY-FELIX-%s", hex.EncodeToString(fingerprint[:8]))
	}
	return &InMemoryEd25519Signer{
		keyID:      keyID,
		publicKey:  pub,
		privateKey: priv,
	}, nil
}

func (s *InMemoryEd25519Signer) KeyID() string {
	return s.keyID
}

func (s *InMemoryEd25519Signer) PublicKey() ed25519.PublicKey {
	return s.publicKey
}

func (s *InMemoryEd25519Signer) Sign(data []byte) ([]byte, error) {
	if len(s.privateKey) == 0 {
		return nil, errors.New("private key is not available")
	}
	return ed25519.Sign(s.privateKey, data), nil
}

// -----------------------------------------------------------------------------
// Canonical Assessment Snapshot Data Models
// -----------------------------------------------------------------------------

// TargetSnapshot captures an authorized assessment target in canonical form.
type TargetSnapshot struct {
	TargetURL   string `json:"target_url"`
	TargetType  string `json:"target_type"`
	ScopeStatus string `json:"scope_status"`
	Label       string `json:"label,omitempty"`
}

// ExclusionSnapshot captures an explicit exclusion in canonical form.
type ExclusionSnapshot struct {
	Pattern       string `json:"pattern"`
	ExclusionType string `json:"exclusion_type"`
	Reason        string `json:"reason,omitempty"`
}

// FindingSummaryItem captures finding counts by severity and confirmation level.
type FindingSummaryItem struct {
	Severity           string `json:"severity"`
	TotalCount         int    `json:"total_count"`
	ConfirmedCount     int    `json:"confirmed_count"`     // Empirically verified via active replay
	SuspectedCount     int    `json:"suspected_count"`     // Heuristic match without active proof
	InconclusiveCount  int    `json:"inconclusive_count"`
	RemediatedCount    int    `json:"remediated_count"`    // Confirmed remediated via retest
}

// SignificantExposure captures individual high/critical findings for transparent disclosure.
type SignificantExposure struct {
	FindingID          string  `json:"finding_id"`
	RuleID             string  `json:"rule_id,omitempty"`
	Title              string  `json:"title"`
	Severity           string  `json:"severity"`
	CVSS               float64 `json:"cvss,omitempty"`
	Status             string  `json:"status"`
	AnalysisMethod     string  `json:"analysis_method"`
	VerificationStatus string  `json:"verification_status"`
	TargetEndpoint     string  `json:"target_endpoint"`
	IsRemediated       bool    `json:"is_remediated"`
}

// AttestationSnapshot encapsulates the immutable, sanitized historical assessment snapshot for cryptographic attestation.
type AttestationSnapshot struct {
	AssessmentID         string                `json:"assessment_id"`
	AssessmentRef        string                `json:"assessment_ref"`
	AssessmentName       string                `json:"assessment_name"`
	AssessmentType       string                `json:"assessment_type"`
	ExecutionID          string                `json:"execution_id,omitempty"`
	ClientID             string                `json:"client_id"`
	ClientName           string                `json:"client_name"`
	ClientOrganization   string                `json:"client_organization,omitempty"`
	ScopeMode            string                `json:"scope_mode"`
	SigningKeyID         string                `json:"signing_key_id"` // Cryptographically bound signing key ID
	StartedAt            string                `json:"started_at"`
	CompletedAt          string                `json:"completed_at"`
	DurationMs           int64                 `json:"duration_ms"`
	TestingMethodology   []string              `json:"testing_methodology"`
	Targets              []TargetSnapshot      `json:"targets"`
	Exclusions           []ExclusionSnapshot   `json:"exclusions,omitempty"`
	FindingSummaries     []FindingSummaryItem  `json:"finding_summaries"`
	SignificantExposures []SignificantExposure `json:"significant_exposures,omitempty"`
	TotalFindingsCount   int                   `json:"total_findings_count"`
	ConfirmedFindings    int                   `json:"confirmed_findings"`
	SuspectedFindings    int                   `json:"suspected_findings"`
	UntestedAreas        []string              `json:"untested_areas,omitempty"`
	Limitations          []string              `json:"limitations,omitempty"`
}

// AttestationSignature encapsulates digital signature proof and key identification.
type AttestationSignature struct {
	Algorithm      string    `json:"algorithm"`        // "Ed25519"
	KeyID          string    `json:"key_id"`           // Identifier of the public key
	PublicKeyHex   string    `json:"public_key_hex"`   // Hex-encoded 32-byte Ed25519 public key
	SignatureHex   string    `json:"signature_hex"`    // Hex-encoded 64-byte Ed25519 signature
	SignedAt       time.Time `json:"signed_at"`        // Timestamp of signature execution
	SignerIdentity string    `json:"signer_identity"`  // Attestation authority name/identity
}

// AttestationLetter represents the complete, cryptographically verified Letter of Attestation.
type AttestationLetter struct {
	LetterID             string                `json:"letter_id"`
	LetterVersion        string                `json:"letter_version"`
	IssuedAt             time.Time             `json:"issued_at"`
	Issuer               string                `json:"issuer"`
	CanonicalDigest      string                `json:"canonical_digest"` // SHA-256 of canonical snapshot (sha256:<hex>)
	Signature            AttestationSignature  `json:"signature"`
	Snapshot             AttestationSnapshot   `json:"snapshot"`
	ExecutiveStatement   string                `json:"executive_statement"`
	RegulatoryDisclaimer string                `json:"regulatory_disclaimer"`
}

// AttestationOptions provides configurable parameters for generating an attestation letter.
type AttestationOptions struct {
	IssuerName           string
	SignerIdentity       string
	MethodologyStandards []string
	AdditionalNotes      string
	CustomLimitations    []string
}

// DefaultAttestationOptions returns standard options.
func DefaultAttestationOptions() AttestationOptions {
	return AttestationOptions{
		IssuerName:     "FELIX Automated Security Assessment Authority",
		SignerIdentity: "FELIX Cryptographic Attestation Engine v3.0",
		MethodologyStandards: []string{
			"OWASP Web Security Testing Guide (WSTG v4.2)",
			"CWE/SANS Top 25 Most Dangerous Software Weaknesses",
			"Deterministic Active DAST Payload Replay",
			"Cryptographic Evidence Lineage Verification",
		},
	}
}

// -----------------------------------------------------------------------------
// Snapshot Extraction & Canonical Digest
// -----------------------------------------------------------------------------

// BuildAttestationSnapshot compiles an Assessment, Client, Execution, and Findings into a normalized snapshot.
func BuildAttestationSnapshot(
	asm Assessment,
	client Client,
	exec *AssessmentExecution,
	findings []AssessmentFinding,
	methodologies []string,
	untestedAreas []string,
	limitations []string,
) (AttestationSnapshot, error) {
	if strings.TrimSpace(asm.ID) == "" {
		return AttestationSnapshot{}, fmt.Errorf("%w: assessment ID is required", ErrMissingIdentity)
	}
	if strings.TrimSpace(client.Name) == "" && strings.TrimSpace(asm.ClientID) == "" {
		return AttestationSnapshot{}, fmt.Errorf("%w: client identity is required", ErrMissingIdentity)
	}
	if len(asm.Targets) == 0 {
		return AttestationSnapshot{}, ErrMissingTargets
	}
	if asm.Status != StatusCompleted && asm.Status != StatusCompletedWithErrors {
		return AttestationSnapshot{}, fmt.Errorf("%w: current status is %s", ErrAssessmentNotCompleted, asm.Status)
	}

	clientName := client.Name
	if clientName == "" {
		clientName = asm.ClientID
	}
	clientOrg := client.Organization
	if clientOrg == "" {
		clientOrg = clientName
	}

	var startedAt, completedAt string
	var durationMs int64
	if asm.StartedAt != nil {
		startedAt = asm.StartedAt.UTC().Format(time.RFC3339)
	}
	if asm.CompletedAt != nil {
		completedAt = asm.CompletedAt.UTC().Format(time.RFC3339)
	}
	if asm.StartedAt != nil && asm.CompletedAt != nil {
		durationMs = asm.CompletedAt.Sub(*asm.StartedAt).Milliseconds()
	}

	var executionID string
	if exec != nil {
		executionID = exec.ID
		if startedAt == "" && !exec.StartedAt.IsZero() {
			startedAt = exec.StartedAt.UTC().Format(time.RFC3339)
		}
		if completedAt == "" && exec.CompletedAt != nil {
			completedAt = exec.CompletedAt.UTC().Format(time.RFC3339)
		}
		if durationMs == 0 && exec.DurationMs > 0 {
			durationMs = exec.DurationMs
		}
	}

	// 1. Normalized Targets
	targets := make([]TargetSnapshot, 0, len(asm.Targets))
	for _, t := range asm.Targets {
		targets = append(targets, TargetSnapshot{
			TargetURL:   t.TargetURL,
			TargetType:  string(t.TargetType),
			ScopeStatus: t.ScopeStatus,
			Label:       t.Label,
		})
	}
	sort.Slice(targets, func(i, j int) bool {
		return targets[i].TargetURL < targets[j].TargetURL
	})

	// 2. Normalized Exclusions
	exclusions := make([]ExclusionSnapshot, 0, len(asm.Exclusions))
	for _, ex := range asm.Exclusions {
		exclusions = append(exclusions, ExclusionSnapshot{
			Pattern:       ex.Pattern,
			ExclusionType: ex.ExclusionType,
			Reason:        ex.Reason,
		})
	}
	sort.Slice(exclusions, func(i, j int) bool {
		return exclusions[i].Pattern < exclusions[j].Pattern
	})

	// 3. Finding Summaries & Breakdown
	sevCounts := map[string]*FindingSummaryItem{
		report.SeverityCritical: {Severity: report.SeverityCritical},
		report.SeverityHigh:     {Severity: report.SeverityHigh},
		report.SeverityMedium:   {Severity: report.SeverityMedium},
		report.SeverityLow:      {Severity: report.SeverityLow},
		report.SeverityInfo:     {Severity: report.SeverityInfo},
	}

	var totalFindings, confirmedTotal, suspectedTotal int
	var significantExposures []SignificantExposure

	for _, f := range findings {
		sev := strings.ToUpper(strings.TrimSpace(f.Severity))
		item, ok := sevCounts[sev]
		if !ok {
			item = &FindingSummaryItem{Severity: sev}
			sevCounts[sev] = item
		}

		item.TotalCount++
		totalFindings++

		isConfirmed := f.Status == report.FindingStatusConfirmed || f.VerificationStatus == report.VerificationVerified
		if isConfirmed {
			item.ConfirmedCount++
			confirmedTotal++
		} else {
			item.SuspectedCount++
			suspectedTotal++
		}

		// Enumerate Significant Exposures (Critical & High)
		if sev == report.SeverityCritical || sev == report.SeverityHigh {
			significantExposures = append(significantExposures, SignificantExposure{
				FindingID:          f.OriginalFindingID,
				RuleID:             f.RuleID,
				Title:              f.Title,
				Severity:           sev,
				Status:             string(f.Status),
				AnalysisMethod:     string(f.AnalysisMethod),
				VerificationStatus: string(f.VerificationStatus),
				TargetEndpoint:     f.TargetID,
				IsRemediated:       false,
			})
		}
	}

	orderedSeverities := []string{
		report.SeverityCritical,
		report.SeverityHigh,
		report.SeverityMedium,
		report.SeverityLow,
		report.SeverityInfo,
	}
	findingSummaries := make([]FindingSummaryItem, 0, len(orderedSeverities))
	for _, s := range orderedSeverities {
		if item, ok := sevCounts[s]; ok {
			findingSummaries = append(findingSummaries, *item)
		}
	}

	sort.Slice(significantExposures, func(i, j int) bool {
		if significantExposures[i].Severity != significantExposures[j].Severity {
			return report.SeverityRank(significantExposures[i].Severity) > report.SeverityRank(significantExposures[j].Severity)
		}
		return significantExposures[i].FindingID < significantExposures[j].FindingID
	})

	if len(methodologies) == 0 {
		methodologies = []string{"Automated Dynamic Application Security Testing (DAST)"}
	}
	sort.Strings(methodologies)
	sort.Strings(untestedAreas)
	sort.Strings(limitations)

	return AttestationSnapshot{
		AssessmentID:         asm.ID,
		AssessmentRef:        asm.Ref,
		AssessmentName:       asm.Name,
		AssessmentType:       asm.AssessmentType,
		ExecutionID:          executionID,
		ClientID:             asm.ClientID,
		ClientName:           clientName,
		ClientOrganization:   clientOrg,
		ScopeMode:            asm.ScopeMode,
		SigningKeyID:         "",
		StartedAt:            startedAt,
		CompletedAt:          completedAt,
		DurationMs:           durationMs,
		TestingMethodology:   methodologies,
		Targets:              targets,
		Exclusions:           exclusions,
		FindingSummaries:     findingSummaries,
		SignificantExposures: significantExposures,
		TotalFindingsCount:   totalFindings,
		ConfirmedFindings:    confirmedTotal,
		SuspectedFindings:    suspectedTotal,
		UntestedAreas:        untestedAreas,
		Limitations:          limitations,
	}, nil
}

// BuildAttestationSnapshotFromStoredSnapshot converts an internal AssessmentSnapshot and its findings
// into an immutable AttestationSnapshot.
func BuildAttestationSnapshotFromStoredSnapshot(
	stored *AssessmentSnapshot,
	findings []AssessmentFinding,
	client *Client,
	methodologies []string,
	untestedAreas []string,
	limitations []string,
) (AttestationSnapshot, error) {
	if stored == nil {
		return AttestationSnapshot{}, errors.New("stored assessment snapshot cannot be nil")
	}
	if !stored.IsComplete && stored.Status != StatusCompleted && stored.Status != StatusCompletedWithErrors {
		return AttestationSnapshot{}, fmt.Errorf("%w: current status is %s", ErrAssessmentNotCompleted, stored.Status)
	}
	if len(stored.ScopedTargets) == 0 && stored.TargetCount == 0 {
		return AttestationSnapshot{}, ErrMissingTargets
	}

	clientName := stored.ClientID
	clientOrg := stored.ClientID
	if client != nil {
		if client.Name != "" {
			clientName = client.Name
		}
		if client.Organization != "" {
			clientOrg = client.Organization
		}
	}

	var startedAt, completedAt string
	if !stored.StartedAt.IsZero() {
		startedAt = stored.StartedAt.UTC().Format(time.RFC3339)
	}
	if stored.CompletedAt != nil {
		completedAt = stored.CompletedAt.UTC().Format(time.RFC3339)
	}

	targets := make([]TargetSnapshot, 0, len(stored.ScopedTargets))
	for _, u := range stored.ScopedTargets {
		targets = append(targets, TargetSnapshot{
			TargetURL:   u,
			TargetType:  "URL",
			ScopeStatus: "APPROVED",
		})
	}
	if len(targets) == 0 && stored.TargetCount > 0 {
		targets = append(targets, TargetSnapshot{
			TargetURL:   "configured-targets",
			TargetType:  "TARGET_GROUP",
			ScopeStatus: "APPROVED",
		})
	}
	sort.Slice(targets, func(i, j int) bool {
		return targets[i].TargetURL < targets[j].TargetURL
	})

	sevCounts := map[string]*FindingSummaryItem{
		report.SeverityCritical: {Severity: report.SeverityCritical},
		report.SeverityHigh:     {Severity: report.SeverityHigh},
		report.SeverityMedium:   {Severity: report.SeverityMedium},
		report.SeverityLow:      {Severity: report.SeverityLow},
		report.SeverityInfo:     {Severity: report.SeverityInfo},
	}

	var totalFindings, confirmedTotal, suspectedTotal int
	var significantExposures []SignificantExposure

	for _, f := range findings {
		sev := strings.ToUpper(strings.TrimSpace(f.Severity))
		item, ok := sevCounts[sev]
		if !ok {
			item = &FindingSummaryItem{Severity: sev}
			sevCounts[sev] = item
		}

		item.TotalCount++
		totalFindings++

		isConfirmed := f.Status == report.FindingStatusConfirmed || f.VerificationStatus == report.VerificationVerified
		if isConfirmed {
			item.ConfirmedCount++
			confirmedTotal++
		} else {
			item.SuspectedCount++
			suspectedTotal++
		}

		if sev == report.SeverityCritical || sev == report.SeverityHigh {
			significantExposures = append(significantExposures, SignificantExposure{
				FindingID:          f.OriginalFindingID,
				RuleID:             f.RuleID,
				Title:              f.Title,
				Severity:           sev,
				Status:             string(f.Status),
				AnalysisMethod:     string(f.AnalysisMethod),
				VerificationStatus: string(f.VerificationStatus),
				TargetEndpoint:     f.TargetID,
				IsRemediated:       false,
			})
		}
	}

	orderedSeverities := []string{
		report.SeverityCritical,
		report.SeverityHigh,
		report.SeverityMedium,
		report.SeverityLow,
		report.SeverityInfo,
	}
	findingSummaries := make([]FindingSummaryItem, 0, len(orderedSeverities))
	for _, s := range orderedSeverities {
		if item, ok := sevCounts[s]; ok {
			findingSummaries = append(findingSummaries, *item)
		}
	}

	sort.Slice(significantExposures, func(i, j int) bool {
		if significantExposures[i].Severity != significantExposures[j].Severity {
			return report.SeverityRank(significantExposures[i].Severity) > report.SeverityRank(significantExposures[j].Severity)
		}
		return significantExposures[i].FindingID < significantExposures[j].FindingID
	})

	if len(methodologies) == 0 {
		methodologies = []string{"Automated Dynamic Application Security Testing (DAST)"}
	}
	sort.Strings(methodologies)
	sort.Strings(untestedAreas)
	sort.Strings(limitations)

	return AttestationSnapshot{
		AssessmentID:         stored.AssessmentID,
		AssessmentRef:        stored.AssessmentRef,
		AssessmentName:       stored.Name,
		AssessmentType:       stored.AssessmentType,
		ExecutionID:          stored.ExecutionID,
		ClientID:             stored.ClientID,
		ClientName:           clientName,
		ClientOrganization:   clientOrg,
		ScopeMode:            stored.ScopeMode,
		SigningKeyID:         "",
		StartedAt:            startedAt,
		CompletedAt:          completedAt,
		DurationMs:           stored.DurationMs,
		TestingMethodology:   methodologies,
		Targets:              targets,
		FindingSummaries:     findingSummaries,
		SignificantExposures: significantExposures,
		TotalFindingsCount:   totalFindings,
		ConfirmedFindings:    confirmedTotal,
		SuspectedFindings:    suspectedTotal,
		UntestedAreas:        untestedAreas,
		Limitations:          limitations,
	}, nil
}

// IngestHistoricalSnapshot loads a persisted snapshot, findings, and client record from the assessment Store
// and compiles them into an immutable AttestationSnapshot.
func IngestHistoricalSnapshot(
	store Store,
	snapshotID string,
	auth TenantAuthContext,
	methodologies []string,
	untestedAreas []string,
	limitations []string,
) (AttestationSnapshot, error) {
	if store == nil {
		return AttestationSnapshot{}, errors.New("assessment store cannot be nil")
	}
	if strings.TrimSpace(snapshotID) == "" {
		return AttestationSnapshot{}, errors.New("snapshotID cannot be empty")
	}

	snap, err := store.GetSnapshot(snapshotID, auth)
	if err != nil {
		return AttestationSnapshot{}, fmt.Errorf("failed retrieving snapshot %s: %w", snapshotID, err)
	}
	if snap == nil {
		return AttestationSnapshot{}, fmt.Errorf("snapshot %s not found: %w", snapshotID, ErrSnapshotNotFound)
	}

	findings, err := store.GetSnapshotFindings(snapshotID, auth)
	if err != nil {
		return AttestationSnapshot{}, fmt.Errorf("failed retrieving findings for snapshot %s: %w", snapshotID, err)
	}

	var client *Client
	if snap.ClientID != "" {
		if c, err := store.GetClient(snap.ClientID); err == nil && c != nil {
			client = c
		}
	}

	return BuildAttestationSnapshotFromStoredSnapshot(snap, findings, client, methodologies, untestedAreas, limitations)
}

// ComputeCanonicalSnapshotBytes deterministically marshals the AttestationSnapshot into bytes.
func ComputeCanonicalSnapshotBytes(snapshot AttestationSnapshot) ([]byte, error) {
	return json.Marshal(snapshot)
}

// ComputeCanonicalSnapshotDigest computes the SHA-256 digest of the canonical snapshot bytes.
func ComputeCanonicalSnapshotDigest(snapshot AttestationSnapshot) (string, []byte, error) {
	canonicalBytes, err := ComputeCanonicalSnapshotBytes(snapshot)
	if err != nil {
		return "", nil, fmt.Errorf("failed marshaling canonical snapshot: %w", err)
	}
	hash := sha256.Sum256(canonicalBytes)
	digestHex := fmt.Sprintf("sha256:%s", hex.EncodeToString(hash[:]))
	return digestHex, hash[:], nil
}

// -----------------------------------------------------------------------------
// Attestation Letter Generation & Signing
// -----------------------------------------------------------------------------

// BuildExecutiveStatement creates a truthful, transparent executive summary.
// It explicitly blocks false claims of zero vulnerabilities if critical/high findings remain.
func BuildExecutiveStatement(snapshot AttestationSnapshot) (string, error) {
	var criticalCount, highCount int
	for _, sum := range snapshot.FindingSummaries {
		if strings.EqualFold(sum.Severity, report.SeverityCritical) {
			criticalCount += sum.TotalCount
		} else if strings.EqualFold(sum.Severity, report.SeverityHigh) {
			highCount += sum.TotalCount
		}
	}

	var b strings.Builder
	b.WriteString(fmt.Sprintf("FELIX security audit conducted for %s (%s). ", snapshot.ClientName, snapshot.ClientOrganization))
	b.WriteString(fmt.Sprintf("A total of %d authorized targets were assessed under scope mode %q between %s and %s. ",
		len(snapshot.Targets), snapshot.ScopeMode, snapshot.StartedAt, snapshot.CompletedAt))

	if criticalCount == 0 && highCount == 0 {
		b.WriteString("Within the defined scope and assessment timeframe, zero Critical or High severity vulnerabilities were identified. ")
		b.WriteString(fmt.Sprintf("A total of %d lower-severity findings (%d confirmed, %d suspected) were documented for remediation.",
			snapshot.TotalFindingsCount, snapshot.ConfirmedFindings, snapshot.SuspectedFindings))
	} else {
		b.WriteString(fmt.Sprintf("The assessment identified %d unresolved significant security exposure(s) (%d Critical, %d High) ",
			criticalCount+highCount, criticalCount, highCount))
		b.WriteString(fmt.Sprintf("out of %d total findings (%d confirmed via active verification, %d suspected). ",
			snapshot.TotalFindingsCount, snapshot.ConfirmedFindings, snapshot.SuspectedFindings))
		b.WriteString("Immediate engineering remediation is advised for confirmed high/critical findings.")
	}

	return b.String(), nil
}

// GenerateAttestationLetter compiles, digests, and signs a Letter of Attestation.
func GenerateAttestationLetter(
	snapshot AttestationSnapshot,
	signer AttestationSigner,
	opts AttestationOptions,
) (*AttestationLetter, error) {
	if signer == nil {
		return nil, errors.New("attestation signer cannot be nil")
	}
	keyID := strings.TrimSpace(signer.KeyID())
	if keyID == "" {
		return nil, errors.New("attestation signer KeyID cannot be empty")
	}
	if len(snapshot.Targets) == 0 {
		return nil, ErrMissingTargets
	}
	if strings.TrimSpace(snapshot.AssessmentID) == "" || strings.TrimSpace(snapshot.ClientName) == "" {
		return nil, ErrMissingIdentity
	}

	// Cryptographic Key Identity Binding:
	// The signer's KeyID is permanently and immutably bound into the canonical snapshot before digesting.
	if snapshot.SigningKeyID == "" {
		snapshot.SigningKeyID = keyID
	} else if !strings.EqualFold(snapshot.SigningKeyID, keyID) {
		return nil, fmt.Errorf("%w: snapshot signing key ID %q does not match signer key ID %q",
			ErrKeyIDMismatch, snapshot.SigningKeyID, keyID)
	}

	now := time.Now().UTC()
	letterID := fmt.Sprintf("ATT-%s-%d", snapshot.AssessmentID, now.Unix())

	issuer := opts.IssuerName
	if issuer == "" {
		issuer = "FELIX Automated Security Assessment Authority"
	}
	signerIdentity := opts.SignerIdentity
	if signerIdentity == "" {
		signerIdentity = "FELIX Cryptographic Attestation Engine"
	}

	// Truthfulness check: ensure executive statement does not misrepresent findings
	execStmt, err := BuildExecutiveStatement(snapshot)
	if err != nil {
		return nil, err
	}

	// Compute canonical snapshot digest (includes SigningKeyID in the canonical payload)
	digestHex, digestBytes, err := ComputeCanonicalSnapshotDigest(snapshot)
	if err != nil {
		return nil, fmt.Errorf("failed computing snapshot digest: %w", err)
	}

	// Digital Signature: Ed25519 signature over the SHA-256 canonical digest bytes
	sigBytes, err := signer.Sign(digestBytes)
	if err != nil {
		return nil, fmt.Errorf("failed computing Ed25519 digital signature: %w", err)
	}

	pubKey := signer.PublicKey()
	pubKeyHex := hex.EncodeToString(pubKey)
	sigHex := hex.EncodeToString(sigBytes)

	disclaimer := "IMPORTANT NOTICE: This Letter of Attestation represents an assessment outcome at a specific point in time " +
		"within the stated target scope and methodology. It does not constitute a formal regulatory compliance certification " +
		"(e.g. SOC 2, ISO 27001, PCI-DSS) or guarantee immunity from future security compromise."

	return &AttestationLetter{
		LetterID:        letterID,
		LetterVersion:   "3.0.0",
		IssuedAt:        now,
		Issuer:          issuer,
		CanonicalDigest: digestHex,
		Signature: AttestationSignature{
			Algorithm:      "Ed25519",
			KeyID:          keyID,
			PublicKeyHex:   pubKeyHex,
			SignatureHex:   sigHex,
			SignedAt:       now,
			SignerIdentity: signerIdentity,
		},
		Snapshot:             snapshot,
		ExecutiveStatement:   execStmt,
		RegulatoryDisclaimer: disclaimer,
	}, nil
}

// -----------------------------------------------------------------------------
// Independent Public-Key & Tamper Verification
// -----------------------------------------------------------------------------

// TrustedKey anchors an authorized signing key with its expected KeyID and public key.
type TrustedKey struct {
	KeyID       string            `json:"key_id"`
	PublicKey   ed25519.PublicKey `json:"public_key"`
	Authority   string            `json:"authority,omitempty"`
	Description string            `json:"description,omitempty"`
}

// TrustedKeyRegistry defines an interface for resolving trusted keys by KeyID.
type TrustedKeyRegistry interface {
	LookupKey(keyID string) (TrustedKey, bool)
}

// MapKeyRegistry implements TrustedKeyRegistry with an in-memory key map.
type MapKeyRegistry map[string]TrustedKey

func (m MapKeyRegistry) LookupKey(keyID string) (TrustedKey, bool) {
	k, ok := m[keyID]
	return k, ok
}

// VerificationOptions specifies independent trust anchors and matching criteria for verification.
type VerificationOptions struct {
	TrustedPublicKey ed25519.PublicKey   // Independently supplied trusted public key
	TrustedKey       *TrustedKey         // Independently supplied trusted key with KeyID and public key
	ExpectedKeyID    string              // Optional expected KeyID (must match letter.Signature.KeyID if set)
	Registry         TrustedKeyRegistry  // Optional trusted key registry lookup by letter.Signature.KeyID
}

// AttestationVerificationResult details the outcome of an independent signature verification.
type AttestationVerificationResult struct {
	Valid              bool      `json:"valid"`               // True ONLY if DigestMatched, SignatureVerified, AND KeyTrusted
	KeyTrusted         bool      `json:"key_trusted"`          // True if public key is independently verified through trust anchor
	DigestMatched      bool      `json:"digest_matched"`       // True if snapshot canonical digest matches CanonicalDigest
	SignatureVerified  bool      `json:"signature_verified"`   // True if Ed25519 signature is mathematically valid
	OfflineVerifiable  bool      `json:"offline_verifiable"`
	LetterID           string    `json:"letter_id"`
	AssessmentID       string    `json:"assessment_id"`
	KeyID              string    `json:"key_id"`
	Algorithm          string    `json:"algorithm"`
	RecomputedDigest   string    `json:"recomputed_digest"`
	ExpectedDigest     string    `json:"expected_digest"`
	TrustedKeySource   string    `json:"trusted_key_source"`   // "DIRECT_KEY", "TRUSTED_REGISTRY", or "UNTRUSTED"
	VerifiedAt         time.Time `json:"verified_at"`
	FailureReason      string    `json:"failure_reason,omitempty"`
}

// VerifyAttestationLetterAdvanced verifies an AttestationLetter against independent trust anchors.
// An embedded public key in the letter is treated as informational metadata and NEVER establishes trust.
func VerifyAttestationLetterAdvanced(letter AttestationLetter, opts VerificationOptions) (*AttestationVerificationResult, error) {
	now := time.Now().UTC()
	res := &AttestationVerificationResult{
		Valid:             false,
		KeyTrusted:        false,
		DigestMatched:     false,
		SignatureVerified: false,
		LetterID:          letter.LetterID,
		AssessmentID:      letter.Snapshot.AssessmentID,
		KeyID:             letter.Signature.KeyID,
		Algorithm:         letter.Signature.Algorithm,
		ExpectedDigest:    letter.CanonicalDigest,
		TrustedKeySource:  "UNTRUSTED",
		OfflineVerifiable: true,
		VerifiedAt:        now,
	}

	// 0. Verify KeyID identity binding invariants
	envelopeKeyID := strings.TrimSpace(letter.Signature.KeyID)
	if envelopeKeyID == "" {
		res.FailureReason = "attestation letter signature metadata has empty KeyID"
		return res, ErrUntrustedKey
	}
	snapshotKeyID := strings.TrimSpace(letter.Snapshot.SigningKeyID)
	if snapshotKeyID == "" {
		res.FailureReason = "attestation snapshot is missing cryptographically bound SigningKeyID"
		return res, ErrKeyIDMismatch
	}
	if !strings.EqualFold(envelopeKeyID, snapshotKeyID) {
		res.FailureReason = fmt.Sprintf("key ID binding violation: envelope KeyID %q does not match signed snapshot SigningKeyID %q",
			envelopeKeyID, snapshotKeyID)
		return res, ErrKeyIDMismatch
	}

	// 1. Recompute canonical snapshot digest
	recomputedDigestHex, recomputedDigestBytes, err := ComputeCanonicalSnapshotDigest(letter.Snapshot)
	if err != nil {
		res.FailureReason = fmt.Sprintf("failed recomputing snapshot digest: %v", err)
		return res, err
	}
	res.RecomputedDigest = recomputedDigestHex

	// 2. Check for snapshot content tampering
	if recomputedDigestHex != letter.CanonicalDigest {
		res.DigestMatched = false
		res.FailureReason = fmt.Sprintf("snapshot content tampering detected: recomputed %s != expected %s",
			recomputedDigestHex, letter.CanonicalDigest)
		return res, ErrTamperedSnapshot
	}
	res.DigestMatched = true

	// 3. Decode signature bytes
	sigBytes, err := hex.DecodeString(letter.Signature.SignatureHex)
	if err != nil || len(sigBytes) != ed25519.SignatureSize {
		res.FailureReason = "invalid or malformed signature hex in metadata"
		return res, ErrInvalidSignature
	}

	// 4. Resolve Trusted Public Key Anchor
	var trustedKey ed25519.PublicKey

	if opts.TrustedKey != nil {
		if len(opts.TrustedKey.PublicKey) != ed25519.PublicKeySize {
			res.FailureReason = "invalid public key size in trusted key anchor"
			return res, ErrUntrustedKey
		}
		trustedKey = opts.TrustedKey.PublicKey
		res.TrustedKeySource = "DIRECT_KEY"
		if opts.TrustedKey.KeyID != "" && !strings.EqualFold(envelopeKeyID, opts.TrustedKey.KeyID) {
			res.FailureReason = fmt.Sprintf("key ID mismatch: letter has %q but trusted key specifies %q",
				envelopeKeyID, opts.TrustedKey.KeyID)
			return res, ErrKeyIDMismatch
		}
	} else if len(opts.TrustedPublicKey) == ed25519.PublicKeySize {
		trustedKey = opts.TrustedPublicKey
		res.TrustedKeySource = "DIRECT_KEY"
	} else if opts.Registry != nil {
		tk, ok := opts.Registry.LookupKey(envelopeKeyID)
		if !ok || len(tk.PublicKey) != ed25519.PublicKeySize {
			// Diagnostic: check mathematical validity with embedded key if possible
			if embKey, err := hex.DecodeString(letter.Signature.PublicKeyHex); err == nil && len(embKey) == ed25519.PublicKeySize {
				res.SignatureVerified = ed25519.Verify(ed25519.PublicKey(embKey), recomputedDigestBytes, sigBytes)
			}
			res.FailureReason = fmt.Sprintf("signing key ID %q is not present in trusted key registry", envelopeKeyID)
			return res, ErrUntrustedKey
		}
		if tk.KeyID != "" && !strings.EqualFold(tk.KeyID, envelopeKeyID) {
			res.FailureReason = fmt.Sprintf("registry key ID %q does not match letter key ID %q", tk.KeyID, envelopeKeyID)
			return res, ErrKeyIDMismatch
		}
		trustedKey = tk.PublicKey
		res.TrustedKeySource = "TRUSTED_REGISTRY"
	} else {
		// No trusted anchor supplied: an embedded public key can NEVER independently establish trust!
		if embKey, err := hex.DecodeString(letter.Signature.PublicKeyHex); err == nil && len(embKey) == ed25519.PublicKeySize {
			res.SignatureVerified = ed25519.Verify(ed25519.PublicKey(embKey), recomputedDigestBytes, sigBytes)
		}
		res.FailureReason = "verification rejected: no trusted public key or registry supplied (embedded key is untrusted metadata)"
		return res, ErrUntrustedKey
	}

	// 5. Verify KeyID if an expected KeyID was specified
	if opts.ExpectedKeyID != "" && !strings.EqualFold(envelopeKeyID, opts.ExpectedKeyID) {
		res.FailureReason = fmt.Sprintf("key ID mismatch: letter has %q but expected %q", envelopeKeyID, opts.ExpectedKeyID)
		return res, ErrKeyIDMismatch
	}

	// 6. Verify that letter metadata matches the trusted public key
	trustedHex := hex.EncodeToString(trustedKey)
	if !strings.EqualFold(trustedHex, letter.Signature.PublicKeyHex) {
		res.FailureReason = fmt.Sprintf("public key mismatch: letter claims %s but trusted key is %s",
			letter.Signature.PublicKeyHex, trustedHex)
		return res, ErrKeyMismatch
	}

	// 7. Verify cryptographic signature using the trusted key
	if !ed25519.Verify(trustedKey, recomputedDigestBytes, sigBytes) {
		res.SignatureVerified = false
		res.FailureReason = "cryptographic Ed25519 signature verification failed (signature or key tampered)"
		return res, ErrInvalidSignature
	}

	res.SignatureVerified = true
	res.KeyTrusted = true
	res.Valid = true
	return res, nil
}

// VerifyAttestationLetter independently verifies an AttestationLetter using an independently trusted Ed25519 public key.
// Supplying a nil or empty key rejects the letter with ErrUntrustedKey.
func VerifyAttestationLetter(letter AttestationLetter, trustedPubKey ed25519.PublicKey) (*AttestationVerificationResult, error) {
	return VerifyAttestationLetterAdvanced(letter, VerificationOptions{
		TrustedPublicKey: trustedPubKey,
	})
}

// VerifyAttestationLetterWithTrustedKey independently verifies an AttestationLetter using an authoritative TrustedKey anchor.
func VerifyAttestationLetterWithTrustedKey(letter AttestationLetter, key TrustedKey) (*AttestationVerificationResult, error) {
	return VerifyAttestationLetterAdvanced(letter, VerificationOptions{
		TrustedKey:    &key,
		ExpectedKeyID: key.KeyID,
	})
}

// VerifyAttestationLetterWithRegistry independently verifies an AttestationLetter using an authorized TrustedKeyRegistry.
func VerifyAttestationLetterWithRegistry(letter AttestationLetter, registry TrustedKeyRegistry) (*AttestationVerificationResult, error) {
	return VerifyAttestationLetterAdvanced(letter, VerificationOptions{
		Registry: registry,
	})
}

// -----------------------------------------------------------------------------
// Human-Readable Attestation Document Renderer
// -----------------------------------------------------------------------------

// RenderAttestationLetterMarkdown formats the signed attestation letter into a professional Markdown document.
func RenderAttestationLetterMarkdown(letter AttestationLetter) string {
	var b strings.Builder

	b.WriteString("# LETTER OF ATTESTATION\n")
	b.WriteString("### Independent Cryptographic Assessment Summary\n\n")

	b.WriteString(fmt.Sprintf("**Attestation Letter ID:** `%s`\n", letter.LetterID))
	b.WriteString(fmt.Sprintf("**Issued By:** %s\n", letter.Issuer))
	b.WriteString(fmt.Sprintf("**Date of Issuance:** %s\n\n", letter.IssuedAt.Format("2006-01-02 15:04:05 UTC")))
	b.WriteString("---\n\n")

	// 1. Client & Assessment Identification
	b.WriteString("## 1. Assessment Identification & Client Context\n")
	b.WriteString(fmt.Sprintf("- **Client Organization:** %s\n", letter.Snapshot.ClientOrganization))
	b.WriteString(fmt.Sprintf("- **Client Identity:** %s (`%s`)\n", letter.Snapshot.ClientName, letter.Snapshot.ClientID))
	b.WriteString(fmt.Sprintf("- **Assessment Name:** %s\n", letter.Snapshot.AssessmentName))
	b.WriteString(fmt.Sprintf("- **Assessment Reference:** `%s` (`%s`)\n", letter.Snapshot.AssessmentRef, letter.Snapshot.AssessmentID))
	if letter.Snapshot.ExecutionID != "" {
		b.WriteString(fmt.Sprintf("- **Execution Run ID:** `%s`\n", letter.Snapshot.ExecutionID))
	}
	b.WriteString(fmt.Sprintf("- **Audit Type:** %s\n", letter.Snapshot.AssessmentType))
	b.WriteString(fmt.Sprintf("- **Assessment Window:** %s to %s (Duration: %d ms)\n\n",
		letter.Snapshot.StartedAt, letter.Snapshot.CompletedAt, letter.Snapshot.DurationMs))

	// 2. Scope & Exclusions
	b.WriteString("## 2. Authorized Scope & Target Boundaries\n")
	b.WriteString(fmt.Sprintf("**Scope Enforcement Mode:** `%s`\n\n", letter.Snapshot.ScopeMode))
	b.WriteString("**Authorized Target Assets:**\n")
	for i, t := range letter.Snapshot.Targets {
		label := ""
		if t.Label != "" {
			label = fmt.Sprintf(" (%s)", t.Label)
		}
		b.WriteString(fmt.Sprintf("%d. `%s` [%s]%s\n", i+1, t.TargetURL, t.TargetType, label))
	}
	b.WriteString("\n")

	if len(letter.Snapshot.Exclusions) > 0 {
		b.WriteString("**Explicit Exclusions & Forbidden Paths:**\n")
		for _, ex := range letter.Snapshot.Exclusions {
			reason := ""
			if ex.Reason != "" {
				reason = fmt.Sprintf(" — *%s*", ex.Reason)
			}
			b.WriteString(fmt.Sprintf("- `%s` [%s]%s\n", ex.Pattern, ex.ExclusionType, reason))
		}
		b.WriteString("\n")
	}

	// 3. Testing Methodology
	b.WriteString("## 3. Testing Methodology & Standards\n")
	for _, m := range letter.Snapshot.TestingMethodology {
		b.WriteString(fmt.Sprintf("- %s\n", m))
	}
	b.WriteString("\n")

	// 4. Executive Summary
	b.WriteString("## 4. Executive Security Statement\n")
	b.WriteString(letter.ExecutiveStatement + "\n\n")

	// 5. Findings Summary Table
	b.WriteString("## 5. Finding Severity & Verification Breakdown\n\n")
	b.WriteString("*Coverage Note: Finding population is attested in aggregate by severity and verification state in the summary table below. Individual itemized disclosure is reserved for Significant Security Exposures (Critical and High severity findings).*\n\n")
	b.WriteString("| Severity | Total Identified | Confirmed (Active Verification) | Suspected (Heuristic Match) | Remediated |\n")
	b.WriteString("| :--- | :---: | :---: | :---: | :---: |\n")
	for _, sum := range letter.Snapshot.FindingSummaries {
		b.WriteString(fmt.Sprintf("| **%s** | %d | %d | %d | %d |\n",
			sum.Severity, sum.TotalCount, sum.ConfirmedCount, sum.SuspectedCount, sum.RemediatedCount))
	}
	b.WriteString("\n")

	// Significant Exposures
	if len(letter.Snapshot.SignificantExposures) > 0 {
		b.WriteString("### Significant Security Exposures Identified\n")
		for i, exp := range letter.Snapshot.SignificantExposures {
			b.WriteString(fmt.Sprintf("%d. **[%s] %s** (`%s`)\n", i+1, exp.Severity, exp.Title, exp.FindingID))
			b.WriteString(fmt.Sprintf("   - Target: `%s` | Method: `%s` | Verification: `%s`\n",
				exp.TargetEndpoint, exp.AnalysisMethod, exp.VerificationStatus))
		}
		b.WriteString("\n")
	}

	// 6. Limitations & Untested Areas
	if len(letter.Snapshot.UntestedAreas) > 0 || len(letter.Snapshot.Limitations) > 0 {
		b.WriteString("## 6. Audit Limitations & Scope Constraints\n")
		for _, u := range letter.Snapshot.UntestedAreas {
			b.WriteString(fmt.Sprintf("- **Untested Boundary:** %s\n", u))
		}
		for _, l := range letter.Snapshot.Limitations {
			b.WriteString(fmt.Sprintf("- **Technical Constraint:** %s\n", l))
		}
		b.WriteString("\n")
	}

	// 7. Cryptographic Integrity & Offline Verification Instructions
	b.WriteString("## 7. Cryptographic Authenticity Proof\n\n")
	b.WriteString("> **DIGITAL ATTESTATION GUARANTEE:** This Letter of Attestation is sealed with an Ed25519 digital signature. ")
	b.WriteString("The signature binds the canonical assessment snapshot to the signing authority's private key, enabling ")
	b.WriteString("independent offline mathematical verification of provenance and content integrity.\n\n")

	b.WriteString(fmt.Sprintf("- **Canonical Snapshot SHA-256:** `%s`\n", letter.CanonicalDigest))
	b.WriteString(fmt.Sprintf("- **Signing Algorithm:** `%s`\n", letter.Signature.Algorithm))
	b.WriteString(fmt.Sprintf("- **Signer Key ID:** `%s`\n", letter.Signature.KeyID))
	b.WriteString(fmt.Sprintf("- **Bound Snapshot Key ID:** `%s`\n", letter.Snapshot.SigningKeyID))
	b.WriteString(fmt.Sprintf("- **Signer Authority:** %s\n", letter.Signature.SignerIdentity))
	b.WriteString(fmt.Sprintf("- **Public Key (Hex):** `%s` *(informational metadata; verifiers must independently anchor key trust)*\n", letter.Signature.PublicKeyHex))
	b.WriteString(fmt.Sprintf("- **Digital Signature (Hex):**\n```\n%s\n```\n\n", letter.Signature.SignatureHex))

	b.WriteString("### Offline Verification Procedure:\n")
	b.WriteString("1. Obtain the authoritative Ed25519 public key from an independent, trusted out-of-band source matching `Signer Key ID`.\n")
	b.WriteString("2. Extract the canonical snapshot JSON and compute its SHA-256 digest.\n")
	b.WriteString("3. Verify that the SHA-256 digest matches `Canonical Snapshot SHA-256`.\n")
	b.WriteString("4. Verify that `Public Key (Hex)` in metadata matches the independently trusted public key.\n")
	b.WriteString("5. Use the trusted public key to verify `Digital Signature` over the 32-byte SHA-256 digest.\n")
	b.WriteString("6. Verification establishes trust only when both content integrity and key trust are proven.\n\n")

	// 8. Regulatory Disclaimer
	b.WriteString("---\n")
	b.WriteString(fmt.Sprintf("*%s*\n", secrets.RedactText(letter.RegulatoryDisclaimer)))

	return b.String()
}
