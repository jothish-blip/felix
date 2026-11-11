package commercial

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"felix/pkg/assessment"
	"felix/pkg/report"

	_ "modernc.org/sqlite"
)

// -----------------------------------------------------------------------------
// Licensing Constants & Standard Feature Identifiers
// -----------------------------------------------------------------------------

// LicenseTier specifies the operational entitlement tier.
type LicenseTier string

const (
	TierCommunity         LicenseTier = "COMMUNITY"
	TierProfessional      LicenseTier = "PROFESSIONAL"
	TierEnterprise        LicenseTier = "ENTERPRISE"
	TierAirGappedEnterprise LicenseTier = "AIRGAPPED_ENTERPRISE"
)

// DeploymentType specifies the authorized execution environment.
type DeploymentType string

const (
	DeploymentAirGapped   DeploymentType = "OFFLINE_AIRGAPPED"
	DeploymentOnPremise   DeploymentType = "ON_PREMISE"
	DeploymentHybrid      DeploymentType = "HYBRID"
	DeploymentContainer   DeploymentType = "CONTAINERIZED"
)

// Standard FELIX feature identifiers for enterprise entitlement gates.
const (
	FeatureCPaaS               = "commercial.cpaas"
	FeatureDrift               = "commercial.drift"
	FeatureDueDiligence        = "report.due_diligence"
	FeatureExecutiveDossier    = "report.executive_dossier"
	FeatureComplianceVanta     = "compliance.vanta"
	FeatureComplianceDrata     = "compliance.drata"
	FeatureAttestationExport   = "assessment.attestation_export"
	FeatureMobileAPK           = "mobile.apk_audit"
	FeatureCloudSecurity       = "cloudsec.audit"
	FeatureAirGappedExport     = "licensing.airgap_export"
	FeatureZeroCredentialRecon = "recon.zero_credential"
	FeatureCustomCronSchedules = "cpaas.custom_cron"
	FeatureUnlimitedTargets    = "assessment.unlimited_targets"
	FeatureScanBasic           = "scan.basic"

	// Feature Aliases
	FeatureCommercialCPaaS    = FeatureCPaaS
	FeatureCommercialDrift    = FeatureDrift
	FeatureReportDueDiligence = FeatureDueDiligence
)

// GenesisHash is the fixed predecessor digest for the first usage record in the hash chain.
const GenesisHash = "0000000000000000000000000000000000000000000000000000000000000000"

// DefinitionOfBillableUsage formally defines when metered procurement consumption becomes billable:
// 1. Metered usage becomes billable strictly upon terminal COMPLETED or COMPLETED_WITH_ERRORS
//    assessment status, committed to the durable append-only SQLite ledger with an Ed25519 signature
//    and unbroken SHA-256 hash-chain linkage.
// 2. Pre-flight rejected, failed, aborted, cancelled, or interrupted operations release reservations
//    via ReleaseExecution without consuming billable quota (0 quota consumed, 0 ledger entries created).
// 3. Duplicate usage submissions, replayed operations, and negative/zero quantities are strictly rejected.
const DefinitionOfBillableUsage = "COMMITTED_UPON_TERMINAL_ASSESSMENT_COMPLETION_TO_DURABLE_LEDGER_ONLY"

// Standard Sentinel Errors
var (
	ErrLicenseNotFound            = errors.New("licensing: active license not installed")
	ErrInvalidLicenseSignature    = errors.New("licensing: cryptographic ed25519 signature verification failed")
	ErrUntrustedSigningKey        = errors.New("licensing: issuer signing key is not recognized in trusted registry")
	ErrRevokedSigningKey          = errors.New("licensing: issuer signing key has been revoked")
	ErrLicenseExpired             = errors.New("licensing: license has expired past validity window")
	ErrLicenseNotYetValid         = errors.New("licensing: license not-before timestamp is in the future")
	ErrClockRollbackDetected      = errors.New("licensing: clock rollback or timestamp inversion detected")
	ErrFeatureNotEntitled         = errors.New("licensing: requested feature is not permitted under current license tier/entitlements")
	ErrUsageQuotaExhausted        = errors.New("licensing: assessment usage quota has been fully exhausted")
	ErrConcurrencyLimitExceeded   = errors.New("licensing: maximum concurrent assessment execution limit reached")
	ErrTargetLimitExceeded        = errors.New("licensing: assessment target count exceeds license limit per assessment")
	ErrInvalidUsageChain          = errors.New("licensing: usage record hash chain or sequence continuity is broken")
	ErrDuplicateReservation       = errors.New("licensing: operation ID already has an active execution reservation")
	ErrReservationNotFound        = errors.New("licensing: execution reservation not found or already closed")
	ErrExportSignatureInvalid     = errors.New("licensing: usage export cryptographic signature verification failed")
	ErrInvalidUsageRecord         = errors.New("licensing: usage record payload failed validation")
	ErrKeySubstitutionDetected     = errors.New("licensing: key substitution detected: embedded key does not match trusted registry")
	ErrReplayDetected              = errors.New("licensing: replay attack detected: operation has already been committed")
	ErrDuplicateUsageSubmission    = errors.New("licensing: duplicate usage submission detected")
	ErrIntegerOverflow             = errors.New("licensing: integer overflow detected in quota calculation")
	ErrSnapshotRollbackDetected    = errors.New("licensing: database snapshot rollback detected via out-of-band anchor")
	ErrInvalidQuantity             = errors.New("licensing: usage quantity must be positive")
	ErrInvalidTargetCount          = errors.New("licensing: target count cannot be negative")
)

// -----------------------------------------------------------------------------
// License Data Models
// -----------------------------------------------------------------------------

// LicenseEntitlements defines explicit operational bounds granted by a license.
type LicenseEntitlements struct {
	MaxAssessments             int64    `json:"max_assessments"`               // -1 for unlimited
	MaxConcurrentAssessments   int      `json:"max_concurrent_assessments"`   // e.g., 1, 4, 16, 32
	MaxTargetsPerAssessment    int      `json:"max_targets_per_assessment"`    // -1 for unlimited
	MaxHistoricalRetentionDays int      `json:"max_historical_retention_days"` // e.g., 30, 90, 365
	AllowedFeatures            []string `json:"allowed_features"`
	AllowedProfiles            []string `json:"allowed_profiles"`
	AllowAirGappedExport       bool     `json:"allow_air_gapped_export"`
	AllowOfflineExecution      bool     `json:"allow_offline_execution"`
	AllowCustomCronSchedules   bool     `json:"allow_custom_cron_schedules"`
}

// LicensePayload defines the canonical, serializable content of an enterprise license.
type LicensePayload struct {
	LicenseID        string              `json:"license_id"`
	OrganizationID   string              `json:"organization_id"`
	OrganizationName string              `json:"organization_name"`
	ProductID        string              `json:"product_id"`
	LicenseTier      LicenseTier         `json:"license_tier"`
	DeploymentType   DeploymentType      `json:"deployment_type"`
	Version          string              `json:"version"`
	IssuerKeyID      string              `json:"issuer_key_id"`
	IssuedAt         time.Time           `json:"issued_at"`
	NotBefore        time.Time           `json:"not_before"`
	ExpiresAt        time.Time           `json:"expires_at"`
	Entitlements     LicenseEntitlements `json:"entitlements"`
	ContractMetadata map[string]string   `json:"contract_metadata,omitempty"`
}

// SignedLicense encapsulates the signed token, its canonical serialized payload, and signature.
type SignedLicense struct {
	Payload          LicensePayload `json:"payload"`
	CanonicalPayload string         `json:"canonical_payload"`
	PayloadDigest    string         `json:"payload_digest"` // SHA-256 hex
	IssuerKeyID      string         `json:"issuer_key_id"`
	SignatureHex     string         `json:"signature_hex"`
	PublicKeyHex     string         `json:"public_key_hex"` // Subject public key identifier
}

// TrustedLicenseKey models an authorized signing authority anchor.
type TrustedLicenseKey struct {
	KeyID            string            `json:"key_id"`
	PublicKey        ed25519.PublicKey `json:"public_key"`
	Authority        string            `json:"authority"`
	Description      string            `json:"description,omitempty"`
	Revoked          bool              `json:"revoked"`
	RevokedAt        *time.Time        `json:"revoked_at,omitempty"`
	RevocationReason string            `json:"revocation_reason,omitempty"`
}

// LicenseKeyRegistry defines lookup for trusted licensing signing keys.
type LicenseKeyRegistry interface {
	LookupLicenseKey(keyID string) (TrustedLicenseKey, bool)
}

// MapLicenseKeyRegistry implements an in-memory LicenseKeyRegistry.
type MapLicenseKeyRegistry map[string]TrustedLicenseKey

// NewMapLicenseKeyRegistry initializes an empty MapLicenseKeyRegistry.
func NewMapLicenseKeyRegistry() MapLicenseKeyRegistry {
	return make(MapLicenseKeyRegistry)
}

// LookupLicenseKey looks up a key by KeyID.
func (m MapLicenseKeyRegistry) LookupLicenseKey(keyID string) (TrustedLicenseKey, bool) {
	k, ok := m[keyID]
	return k, ok
}

// RegisterKey registers a public key in the map registry.
func (m MapLicenseKeyRegistry) RegisterKey(keyID string, pubKey ed25519.PublicKey) error {
	m[keyID] = TrustedLicenseKey{KeyID: keyID, PublicKey: pubKey}
	return nil
}

// RevokeKey marks a key as revoked in the map registry.
func (m MapLicenseKeyRegistry) RevokeKey(keyID string, reason string) error {
	if k, ok := m[keyID]; ok {
		k.Revoked = true
		k.RevocationReason = reason
		m[keyID] = k
		return nil
	}
	return errors.New("key not found in registry")
}

// LicenseValidationResult details the outcome of verifying a SignedLicense.
type LicenseValidationResult struct {
	Valid          bool                `json:"valid"`
	LicenseID      string              `json:"license_id"`
	OrganizationID string              `json:"organization_id"`
	Tier           LicenseTier         `json:"tier"`
	IssuerKeyID    string              `json:"issuer_key_id"`
	IssuedAt       time.Time           `json:"issued_at"`
	ExpiresAt      time.Time           `json:"expires_at"`
	DaysRemaining  int                 `json:"days_remaining"`
	Entitlements   LicenseEntitlements `json:"entitlements"`
	SignerVerified bool                `json:"signer_verified"`
	IsAirGapped    bool                `json:"is_air_gapped"`
	ValidatedAt    time.Time           `json:"validated_at"`
}

// -----------------------------------------------------------------------------
// Usage Accounting & Hash-Chain Ledger Models
// -----------------------------------------------------------------------------

// UsageRecord represents an individual, tamper-evident billable assessment event.
type UsageRecord struct {
	RecordID             string            `json:"record_id"`
	SequenceNumber       int64             `json:"sequence_number"` // Strictly monotonic (1, 2, 3...)
	LicenseID            string            `json:"license_id"`
	OrganizationID       string            `json:"organization_id"`
	OperationID          string            `json:"operation_id"`
	Feature              string            `json:"feature"`
	Quantity             int64             `json:"quantity"` // Typically 1 for assessment
	Timestamp            time.Time         `json:"timestamp"`
	Status               string            `json:"status"` // COMPLETED, PARTIAL, FAILED
	Metadata             map[string]string `json:"metadata,omitempty"`
	PreviousRecordDigest string            `json:"previous_record_digest"` // SHA-256 of predecessor
	RecordDigest         string            `json:"record_digest"`          // SHA-256 of this canonical record
	SignerKeyID          string            `json:"signer_key_id"`
	SignatureHex         string            `json:"signature_hex"` // Ed25519 signature over canonical record bytes
}

// UsageReservation represents a transient concurrency lock and quota hold.
type UsageReservation struct {
	ReservationID string    `json:"reservation_id"`
	OperationID   string    `json:"operation_id"`
	LicenseID     string    `json:"license_id"`
	Feature       string    `json:"feature"`
	Quantity      int64     `json:"quantity"`
	TargetCount   int       `json:"target_count"`
	CreatedAt     time.Time `json:"created_at"`
	ExpiresAt     time.Time `json:"expires_at"`
	Committed     bool      `json:"committed"`
	Released      bool      `json:"released"`
	mgr           *LicenseManager
}

// Commit implements assessment.EnforcerReservation.
func (r *UsageReservation) Commit(status string, metadata map[string]string) error {
	if r == nil || r.mgr == nil {
		return errors.New("licensing: unlinked reservation cannot commit")
	}
	_, err := r.mgr.CommitExecution(r, status, metadata)
	return err
}

// Release implements assessment.EnforcerReservation.
func (r *UsageReservation) Release(reason string) error {
	if r == nil || r.mgr == nil {
		return nil
	}
	return r.mgr.ReleaseExecution(r, reason)
}

// SignedUsageExport aggregates historical usage records into an air-gapped verifiable bundle.
type SignedUsageExport struct {
	ExportID              string        `json:"export_id"`
	GeneratedAt           time.Time     `json:"generated_at"`
	LicenseID             string        `json:"license_id"`
	OrganizationID        string        `json:"organization_id"`
	TotalRecords          int           `json:"total_records"`
	FirstSequence         int64         `json:"first_sequence"`
	LastSequence          int64         `json:"last_sequence"`
	TotalQuantityConsumed int64         `json:"total_quantity_consumed"`
	FinalHashChainDigest  string        `json:"final_hash_chain_digest"`
	Records               []UsageRecord `json:"records"`
	ExportDigest          string        `json:"export_digest"`
	SignerKeyID           string        `json:"signer_key_id"`
	SignerPublicKeyHex    string        `json:"signer_public_key_hex,omitempty"`
	SignatureHex          string        `json:"signature_hex"`
}

// QuotaReport provides current licensing utilization metrics.
type QuotaReport struct {
	LicenseID            string      `json:"license_id"`
	OrganizationName     string      `json:"organization_name"`
	Tier                 LicenseTier `json:"tier"`
	DeploymentType       DeploymentType `json:"deployment_type"`
	MaxAssessments       int64       `json:"max_assessments"`
	ConsumedAssessments  int64       `json:"consumed_assessments"`
	ReservedAssessments  int64       `json:"reserved_assessments"`
	RemainingAssessments int64       `json:"remaining_assessments"` // -1 for unlimited
	ActiveConcurrency    int         `json:"active_concurrency"`
	MaxConcurrency       int         `json:"max_concurrency"`
	ExpiresAt            time.Time   `json:"expires_at"`
	DaysUntilExpiry      int         `json:"days_until_expiry"`
	IsExpired            bool        `json:"is_expired"`
	IsAirGapped          bool        `json:"is_air_gapped"`
}

// ExportVerificationResult details the outcome of verifying an exported usage audit bundle.
type ExportVerificationResult struct {
	Verified              bool      `json:"verified"`
	ExportID              string    `json:"export_id"`
	LicenseID             string    `json:"license_id"`
	TotalRecords          int       `json:"total_records"`
	TotalQuantityConsumed int64     `json:"total_quantity_consumed"`
	FirstSequence         int64     `json:"first_sequence"`
	LastSequence          int64     `json:"last_sequence"`
	ChainContinuous       bool      `json:"chain_continuous"`
	ExportSignatureValid  bool      `json:"export_signature_valid"`
	RecordSignaturesValid bool      `json:"record_signatures_valid"`
	VerifiedAt            time.Time `json:"verified_at"`
	Issues                []string  `json:"issues,omitempty"`
}

// -----------------------------------------------------------------------------
// Cryptographic Serialization and Signing Helpers
// -----------------------------------------------------------------------------

// ComputeCanonicalLicensePayload serializes a LicensePayload into deterministic canonical JSON and computes its SHA-256 digest.
func ComputeCanonicalLicensePayload(payload LicensePayload) ([]byte, string, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(payload); err != nil {
		return nil, "", fmt.Errorf("licensing: failed canonically encoding payload: %w", err)
	}
	canonBytes := bytes.TrimRight(buf.Bytes(), "\n")
	sum := sha256.Sum256(canonBytes)
	return canonBytes, hex.EncodeToString(sum[:]), nil
}

// SignLicensePayload signs an enterprise license payload with an issuer private Ed25519 key.
func SignLicensePayload(payload LicensePayload, keyID string, privKey ed25519.PrivateKey) (*SignedLicense, error) {
	if len(privKey) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("licensing: invalid private key size %d, expected %d", len(privKey), ed25519.PrivateKeySize)
	}
	canonBytes, digestHex, err := ComputeCanonicalLicensePayload(payload)
	if err != nil {
		return nil, err
	}
	sig := ed25519.Sign(privKey, canonBytes)
	pubKey := privKey.Public().(ed25519.PublicKey)

	return &SignedLicense{
		Payload:          payload,
		CanonicalPayload: string(canonBytes),
		PayloadDigest:    digestHex,
		IssuerKeyID:      keyID,
		SignatureHex:     hex.EncodeToString(sig),
		PublicKeyHex:     hex.EncodeToString(pubKey),
	}, nil
}

// ComputeUsageRecordDigest computes the canonical serialized bytes and SHA-256 digest for an individual usage record.
func ComputeUsageRecordDigest(record UsageRecord) ([]byte, string, error) {
	// Exclude RecordDigest and SignatureHex from canonical computation
	type canonRecordPayload struct {
		RecordID             string            `json:"record_id"`
		SequenceNumber       int64             `json:"sequence_number"`
		LicenseID            string            `json:"license_id"`
		OrganizationID       string            `json:"organization_id"`
		OperationID          string            `json:"operation_id"`
		Feature              string            `json:"feature"`
		Quantity             int64             `json:"quantity"`
		Timestamp            string            `json:"timestamp"`
		Status               string            `json:"status"`
		Metadata             map[string]string `json:"metadata,omitempty"`
		PreviousRecordDigest string            `json:"previous_record_digest"`
		SignerKeyID          string            `json:"signer_key_id"`
	}

	payload := canonRecordPayload{
		RecordID:             record.RecordID,
		SequenceNumber:       record.SequenceNumber,
		LicenseID:            record.LicenseID,
		OrganizationID:       record.OrganizationID,
		OperationID:          record.OperationID,
		Feature:              record.Feature,
		Quantity:             record.Quantity,
		Timestamp:            record.Timestamp.UTC().Format(time.RFC3339Nano),
		Status:               record.Status,
		Metadata:             record.Metadata,
		PreviousRecordDigest: record.PreviousRecordDigest,
		SignerKeyID:          record.SignerKeyID,
	}

	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(payload); err != nil {
		return nil, "", fmt.Errorf("licensing: failed encoding usage record: %w", err)
	}
	canonBytes := bytes.TrimRight(buf.Bytes(), "\n")
	sum := sha256.Sum256(canonBytes)
	return canonBytes, hex.EncodeToString(sum[:]), nil
}

// ComputeExportDigest computes canonical bytes and digest for an exported usage bundle.
func ComputeExportDigest(export SignedUsageExport) ([]byte, string, error) {
	type canonExportPayload struct {
		ExportID              string        `json:"export_id"`
		GeneratedAt           string        `json:"generated_at"`
		LicenseID             string        `json:"license_id"`
		OrganizationID        string        `json:"organization_id"`
		TotalRecords          int           `json:"total_records"`
		FirstSequence         int64         `json:"first_sequence"`
		LastSequence          int64         `json:"last_sequence"`
		TotalQuantityConsumed int64         `json:"total_quantity_consumed"`
		FinalHashChainDigest  string        `json:"final_hash_chain_digest"`
		Records               []UsageRecord `json:"records"`
		SignerKeyID           string        `json:"signer_key_id"`
		SignerPublicKeyHex    string        `json:"signer_public_key_hex,omitempty"`
	}

	payload := canonExportPayload{
		ExportID:              export.ExportID,
		GeneratedAt:           export.GeneratedAt.UTC().Format(time.RFC3339Nano),
		LicenseID:             export.LicenseID,
		OrganizationID:        export.OrganizationID,
		TotalRecords:          export.TotalRecords,
		FirstSequence:         export.FirstSequence,
		LastSequence:          export.LastSequence,
		TotalQuantityConsumed: export.TotalQuantityConsumed,
		FinalHashChainDigest:  export.FinalHashChainDigest,
		Records:               export.Records,
		SignerKeyID:           export.SignerKeyID,
		SignerPublicKeyHex:    export.SignerPublicKeyHex,
	}

	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(payload); err != nil {
		return nil, "", fmt.Errorf("licensing: failed encoding usage export: %w", err)
	}
	canonBytes := bytes.TrimRight(buf.Bytes(), "\n")
	sum := sha256.Sum256(canonBytes)
	return canonBytes, hex.EncodeToString(sum[:]), nil
}

// -----------------------------------------------------------------------------
// Persistent SQLite License & Metered Usage Store
// -----------------------------------------------------------------------------

// LicenseStore handles durable, ACID-compliant persistence for installed licenses and hash-chained usage records.
type LicenseStore struct {
	db     *sql.DB
	dbPath string
	mu     sync.RWMutex
	closed bool
}

// NewLicenseStore initializes or connects to an SQLite database with WAL and immediate transactional locking.
func NewLicenseStore(dbPath string) (*LicenseStore, error) {
	if dbPath != ":memory:" && !strings.HasPrefix(dbPath, "file:") {
		dir := filepath.Dir(dbPath)
		if err := os.MkdirAll(dir, 0750); err != nil {
			return nil, fmt.Errorf("licensing: failed creating store directory: %w", err)
		}
	}

	dsn := dbPath
	if dbPath != ":memory:" && !strings.Contains(dbPath, "?") {
		dsn = fmt.Sprintf("%s?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=synchronous(NORMAL)&_pragma=foreign_keys(ON)", dbPath)
	}

	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("licensing: failed opening sqlite database: %w", err)
	}

	if dbPath == ":memory:" {
		db.SetMaxOpenConns(1)
	} else {
		db.SetMaxOpenConns(10)
		db.SetMaxIdleConns(5)
		db.SetConnMaxLifetime(time.Hour)
	}

	store := &LicenseStore{
		db:     db,
		dbPath: dbPath,
	}

	if err := store.initSchema(); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("licensing: failed initializing database schema: %w", err)
	}

	return store, nil
}

func (s *LicenseStore) initSchema() error {
	queries := []string{
		`CREATE TABLE IF NOT EXISTS felix_installed_licenses (
			license_id TEXT PRIMARY KEY,
			organization_id TEXT NOT NULL,
			tier TEXT NOT NULL,
			deployment_type TEXT NOT NULL,
			raw_json TEXT NOT NULL,
			canonical_payload TEXT NOT NULL,
			payload_digest TEXT NOT NULL,
			issuer_key_id TEXT NOT NULL,
			signature_hex TEXT NOT NULL,
			installed_at TEXT NOT NULL,
			is_active INTEGER NOT NULL DEFAULT 0
		);`,
		`CREATE TABLE IF NOT EXISTS felix_usage_ledger (
			sequence_number INTEGER PRIMARY KEY,
			record_id TEXT UNIQUE NOT NULL,
			license_id TEXT NOT NULL,
			organization_id TEXT NOT NULL,
			operation_id TEXT NOT NULL,
			feature TEXT NOT NULL,
			quantity INTEGER NOT NULL,
			timestamp TEXT NOT NULL,
			status TEXT NOT NULL,
			metadata_json TEXT,
			previous_digest TEXT NOT NULL,
			record_digest TEXT NOT NULL,
			signer_key_id TEXT NOT NULL,
			signature_hex TEXT NOT NULL
		);`,
		`CREATE TABLE IF NOT EXISTS felix_license_state (
			state_key TEXT PRIMARY KEY,
			state_value TEXT NOT NULL,
			updated_at TEXT NOT NULL
		);`,
		`CREATE INDEX IF NOT EXISTS idx_usage_license ON felix_usage_ledger(license_id);`,
		`CREATE INDEX IF NOT EXISTS idx_usage_timestamp ON felix_usage_ledger(timestamp);`,
	}

	for _, q := range queries {
		if _, err := s.db.Exec(q); err != nil {
			return err
		}
	}
	return nil
}

// Close gracefully closes the persistent database.
func (s *LicenseStore) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	return s.db.Close()
}

// SaveInstalledLicense saves or updates an installed license.
func (s *LicenseStore) SaveInstalledLicense(lic *SignedLicense, setActive bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return errors.New("licensing: store is closed")
	}

	rawJSON, err := json.Marshal(lic)
	if err != nil {
		return fmt.Errorf("licensing: failed marshaling signed license: %w", err)
	}

	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	if setActive {
		if _, err := tx.Exec(`UPDATE felix_installed_licenses SET is_active = 0`); err != nil {
			return err
		}
	}

	activeVal := 0
	if setActive {
		activeVal = 1
	}

	nowStr := time.Now().UTC().Format(time.RFC3339)
	query := `INSERT INTO felix_installed_licenses 
		(license_id, organization_id, tier, deployment_type, raw_json, canonical_payload, payload_digest, issuer_key_id, signature_hex, installed_at, is_active)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(license_id) DO UPDATE SET
			raw_json = excluded.raw_json,
			canonical_payload = excluded.canonical_payload,
			payload_digest = excluded.payload_digest,
			signature_hex = excluded.signature_hex,
			is_active = excluded.is_active;`

	if _, err := tx.Exec(query,
		lic.Payload.LicenseID,
		lic.Payload.OrganizationID,
		string(lic.Payload.LicenseTier),
		string(lic.Payload.DeploymentType),
		string(rawJSON),
		lic.CanonicalPayload,
		lic.PayloadDigest,
		lic.IssuerKeyID,
		lic.SignatureHex,
		nowStr,
		activeVal,
	); err != nil {
		return err
	}

	if setActive {
		if _, err := tx.Exec(`INSERT INTO felix_license_state (state_key, state_value, updated_at) 
			VALUES ('active_license_id', ?, ?)
			ON CONFLICT(state_key) DO UPDATE SET state_value = excluded.state_value, updated_at = excluded.updated_at`,
			lic.Payload.LicenseID, nowStr); err != nil {
			return err
		}
	}

	return tx.Commit()
}

// GetActiveLicense retrieves the currently active license, if installed.
func (s *LicenseStore) GetActiveLicense() (*SignedLicense, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.closed {
		return nil, errors.New("licensing: store is closed")
	}

	var rawJSON string
	err := s.db.QueryRow(`SELECT raw_json FROM felix_installed_licenses WHERE is_active = 1 LIMIT 1`).Scan(&rawJSON)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrLicenseNotFound
	}
	if err != nil {
		return nil, err
	}

	var lic SignedLicense
	if err := json.Unmarshal([]byte(rawJSON), &lic); err != nil {
		return nil, fmt.Errorf("licensing: corrupted stored license JSON: %w", err)
	}
	return &lic, nil
}

// AppendUsageRecord appends a signed usage record to the immutable hash chain within an ACID transaction.
func (s *LicenseStore) AppendUsageRecord(rec *UsageRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return errors.New("licensing: store is closed")
	}

	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	// Verify sequence continuity against high watermark
	var currentMaxSeq sql.NullInt64
	var lastDigest sql.NullString
	if err := tx.QueryRow(`SELECT MAX(sequence_number) FROM felix_usage_ledger`).Scan(&currentMaxSeq); err != nil {
		return err
	}

	expectedSeq := int64(1)
	expectedPrevDigest := GenesisHash
	if currentMaxSeq.Valid && currentMaxSeq.Int64 > 0 {
		expectedSeq = currentMaxSeq.Int64 + 1
		if err := tx.QueryRow(`SELECT record_digest FROM felix_usage_ledger WHERE sequence_number = ?`, currentMaxSeq.Int64).Scan(&lastDigest); err != nil {
			return err
		}
		if lastDigest.Valid {
			expectedPrevDigest = lastDigest.String
		}
	}

	if rec.SequenceNumber != expectedSeq {
		return fmt.Errorf("%w: sequence mismatch (expected %d, got %d)", ErrInvalidUsageChain, expectedSeq, rec.SequenceNumber)
	}
	if rec.PreviousRecordDigest != expectedPrevDigest {
		return fmt.Errorf("%w: previous digest mismatch at sequence %d", ErrInvalidUsageChain, rec.SequenceNumber)
	}

	metaJSON, _ := json.Marshal(rec.Metadata)
	nowStr := rec.Timestamp.UTC().Format(time.RFC3339Nano)

	query := `INSERT INTO felix_usage_ledger
		(sequence_number, record_id, license_id, organization_id, operation_id, feature, quantity, timestamp, status, metadata_json, previous_digest, record_digest, signer_key_id, signature_hex)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);`

	if _, err := tx.Exec(query,
		rec.SequenceNumber,
		rec.RecordID,
		rec.LicenseID,
		rec.OrganizationID,
		rec.OperationID,
		rec.Feature,
		rec.Quantity,
		nowStr,
		rec.Status,
		string(metaJSON),
		rec.PreviousRecordDigest,
		rec.RecordDigest,
		rec.SignerKeyID,
		rec.SignatureHex,
	); err != nil {
		return fmt.Errorf("licensing: failed inserting usage record: %w", err)
	}

	// Update state cache
	stateQuery := `INSERT INTO felix_license_state (state_key, state_value, updated_at) 
		VALUES (?, ?, ?) 
		ON CONFLICT(state_key) DO UPDATE SET state_value = excluded.state_value, updated_at = excluded.updated_at`

	if _, err := tx.Exec(stateQuery, "high_watermark_sequence", fmt.Sprintf("%d", rec.SequenceNumber), nowStr); err != nil {
		return err
	}
	if _, err := tx.Exec(stateQuery, "last_recorded_timestamp", nowStr, nowStr); err != nil {
		return err
	}

	return tx.Commit()
}

// GetLedgerState retrieves current sequence watermark, total consumed quantity, and last recorded timestamp.
func (s *LicenseStore) GetLedgerState() (int64, int64, time.Time, string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.closed {
		return 0, 0, time.Time{}, GenesisHash, errors.New("licensing: store is closed")
	}

	var maxSeq sql.NullInt64
	var totalQty sql.NullInt64
	var lastTimeStr sql.NullString
	var lastDigest sql.NullString

	_ = s.db.QueryRow(`SELECT MAX(sequence_number), SUM(quantity), MAX(timestamp) FROM felix_usage_ledger`).Scan(&maxSeq, &totalQty, &lastTimeStr)

	seq := int64(0)
	qty := int64(0)
	lastDigestStr := GenesisHash
	lastTime := time.Time{}

	if maxSeq.Valid && maxSeq.Int64 > 0 {
		seq = maxSeq.Int64
		_ = s.db.QueryRow(`SELECT record_digest FROM felix_usage_ledger WHERE sequence_number = ?`, seq).Scan(&lastDigest)
		if lastDigest.Valid {
			lastDigestStr = lastDigest.String
		}
	}
	if totalQty.Valid {
		qty = totalQty.Int64
	}
	if lastTimeStr.Valid {
		if t, err := time.Parse(time.RFC3339Nano, lastTimeStr.String); err == nil {
			lastTime = t
		}
	}

	return seq, qty, lastTime, lastDigestStr, nil
}

// GetAllUsageRecords retrieves all persisted usage records in ascending sequence order.
func (s *LicenseStore) GetAllUsageRecords() ([]UsageRecord, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.closed {
		return nil, errors.New("licensing: store is closed")
	}

	rows, err := s.db.Query(`SELECT sequence_number, record_id, license_id, organization_id, operation_id, feature, quantity, timestamp, status, metadata_json, previous_digest, record_digest, signer_key_id, signature_hex FROM felix_usage_ledger ORDER BY sequence_number ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var records []UsageRecord
	for rows.Next() {
		var rec UsageRecord
		var metaJSON sql.NullString
		var timeStr string

		if err := rows.Scan(
			&rec.SequenceNumber,
			&rec.RecordID,
			&rec.LicenseID,
			&rec.OrganizationID,
			&rec.OperationID,
			&rec.Feature,
			&rec.Quantity,
			&timeStr,
			&rec.Status,
			&metaJSON,
			&rec.PreviousRecordDigest,
			&rec.RecordDigest,
			&rec.SignerKeyID,
			&rec.SignatureHex,
		); err != nil {
			return nil, err
		}

		if t, err := time.Parse(time.RFC3339Nano, timeStr); err == nil {
			rec.Timestamp = t
		} else if t, err := time.Parse(time.RFC3339, timeStr); err == nil {
			rec.Timestamp = t
		}
		if metaJSON.Valid && metaJSON.String != "" {
			_ = json.Unmarshal([]byte(metaJSON.String), &rec.Metadata)
		}
		records = append(records, rec)
	}
	return records, rows.Err()
}

// HasCommittedOperation returns whether an operation ID has already been committed to the durable usage ledger.
func (s *LicenseStore) HasCommittedOperation(opID string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.closed || opID == "" {
		return false
	}
	var count int
	err := s.db.QueryRow("SELECT COUNT(*) FROM felix_usage_ledger WHERE operation_id = ?", opID).Scan(&count)
	return err == nil && count > 0
}

// GetAllCommittedOperationIDs retrieves all unique operation IDs committed to the ledger.
func (s *LicenseStore) GetAllCommittedOperationIDs() ([]string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.closed {
		return nil, errors.New("licensing: store is closed")
	}
	rows, err := s.db.Query("SELECT DISTINCT operation_id FROM felix_usage_ledger")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err == nil && id != "" {
			ids = append(ids, id)
		}
	}
	return ids, rows.Err()
}

// CheckIntegrity performs an SQLite integrity check and returns an error if corruption is detected.
func (s *LicenseStore) CheckIntegrity() error {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.closed {
		return errors.New("licensing: store is closed")
	}
	var res string
	if err := s.db.QueryRow("PRAGMA integrity_check;").Scan(&res); err != nil {
		return fmt.Errorf("licensing: database integrity check query failed: %w", err)
	}
	if !strings.EqualFold(res, "ok") {
		return fmt.Errorf("licensing: database corruption detected: %s", res)
	}
	return nil
}

// -----------------------------------------------------------------------------
// Enterprise License Manager
// -----------------------------------------------------------------------------

// LicenseManagerConfig provides dependencies and runtime options for the LicenseManager.
type LicenseManagerConfig struct {
	Store              *LicenseStore
	KeyRegistry        LicenseKeyRegistry
	LocalSignerKeyID   string
	LocalSignerPrivKey ed25519.PrivateKey // For signing local usage records
	DefaultToCommunity bool
	ReferenceTime      *time.Time // Optional mock time for boundary testing
	TimeAnchorPath     string     // Out-of-band anchor file path for rollback/snapshot restore detection
}

// LicenseManager is the central interface enforcing enterprise entitlements, concurrency, and metered usage.
type LicenseManager struct {
	store              *LicenseStore
	keyRegistry        LicenseKeyRegistry
	localSignerKeyID   string
	localSignerPrivKey ed25519.PrivateKey
	defaultCommunity   bool
	referenceTime      *time.Time
	timeAnchorPath     string

	mu                  sync.RWMutex
	activeLicense       *SignedLicense
	activeConcurrency   int
	consumedAssessments int64
	reservedAssessments int64
	lastKnownSequence   int64
	lastKnownDigest     string
	lastRecordedTime    time.Time
	activeReservations  map[string]*UsageReservation
	committedOps        map[string]struct{}
}

// NewLicenseManager creates and initializes a LicenseManager with persisted state recovery.
func NewLicenseManager(cfg LicenseManagerConfig) (*LicenseManager, error) {
	if cfg.Store == nil {
		return nil, errors.New("licensing: LicenseStore is required")
	}

	mgr := &LicenseManager{
		store:              cfg.Store,
		keyRegistry:        cfg.KeyRegistry,
		localSignerKeyID:   cfg.LocalSignerKeyID,
		localSignerPrivKey: cfg.LocalSignerPrivKey,
		defaultCommunity:   cfg.DefaultToCommunity,
		referenceTime:      cfg.ReferenceTime,
		timeAnchorPath:     cfg.TimeAnchorPath,
		activeReservations: make(map[string]*UsageReservation),
		committedOps:        make(map[string]struct{}),
		lastKnownDigest:    GenesisHash,
	}

	// Recover persistent state from SQLite
	seq, qty, lastTime, lastDigest, err := cfg.Store.GetLedgerState()
	if err != nil {
		return nil, fmt.Errorf("licensing: failed recovering ledger state: %w", err)
	}
	mgr.lastKnownSequence = seq
	mgr.consumedAssessments = qty
	mgr.lastRecordedTime = lastTime
	mgr.lastKnownDigest = lastDigest

	// Load previously committed operation IDs for replay detection
	if ops, err := cfg.Store.GetAllCommittedOperationIDs(); err == nil {
		for _, op := range ops {
			mgr.committedOps[op] = struct{}{}
		}
	}

	// Verify out-of-band anchor on startup against database restore
	if mgr.timeAnchorPath != "" {
		if err := mgr.checkAnchorStartup(mgr.now()); err != nil {
			return nil, err
		}
	}

	// Recover active license, if one was installed
	if activeLic, err := cfg.Store.GetActiveLicense(); err == nil && activeLic != nil {
		mgr.activeLicense = activeLic
	}

	return mgr, nil
}

func (m *LicenseManager) checkAnchorStartup(now time.Time) error {
	if m.timeAnchorPath == "" {
		return nil
	}
	stat, err := os.Stat(m.timeAnchorPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return nil
	}
	if stat.ModTime().After(now.Add(2 * time.Second)) {
		return fmt.Errorf("%w: anchor file modtime (%s) is in the future relative to system clock (%s)", ErrClockRollbackDetected, stat.ModTime().Format(time.RFC3339), now.Format(time.RFC3339))
	}
	data, err := os.ReadFile(m.timeAnchorPath)
	if err != nil {
		return nil
	}
	var anchor struct {
		TimestampUnixNano int64  `json:"timestamp_unix_nano"`
		Sequence          int64  `json:"sequence"`
		Digest            string `json:"digest"`
	}
	if err := json.Unmarshal(data, &anchor); err == nil {
		if anchor.TimestampUnixNano > now.UnixNano() {
			return fmt.Errorf("%w: anchor timestamp is ahead of system clock", ErrClockRollbackDetected)
		}
		if anchor.Sequence > m.lastKnownSequence {
			return fmt.Errorf("%w: anchor sequence %d exceeds database sequence %d (snapshot rollback detected)", ErrSnapshotRollbackDetected, anchor.Sequence, m.lastKnownSequence)
		}
	}
	return nil
}

func (m *LicenseManager) checkTimeAnchor(now time.Time) error {
	if m.timeAnchorPath == "" {
		return nil
	}
	stat, err := os.Stat(m.timeAnchorPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return nil
	}
	if stat.ModTime().After(now.Add(2 * time.Second)) {
		return fmt.Errorf("%w: anchor file modtime (%s) is in the future relative to system clock (%s)", ErrClockRollbackDetected, stat.ModTime().Format(time.RFC3339), now.Format(time.RFC3339))
	}
	data, err := os.ReadFile(m.timeAnchorPath)
	if err != nil {
		return nil
	}
	var anchor struct {
		TimestampUnixNano int64  `json:"timestamp_unix_nano"`
		Sequence          int64  `json:"sequence"`
		Digest            string `json:"digest"`
	}
	if err := json.Unmarshal(data, &anchor); err == nil {
		if anchor.TimestampUnixNano > now.UnixNano() {
			return fmt.Errorf("%w: anchor timestamp is ahead of system clock", ErrClockRollbackDetected)
		}
		if anchor.Sequence > m.lastKnownSequence {
			return fmt.Errorf("%w: anchor sequence %d exceeds database sequence %d (snapshot rollback detected)", ErrSnapshotRollbackDetected, anchor.Sequence, m.lastKnownSequence)
		}
	}
	return nil
}

func (m *LicenseManager) updateTimeAnchor(t time.Time, seq int64, digest string) {
	if m.timeAnchorPath == "" {
		return
	}
	anchor := struct {
		TimestampUnixNano int64  `json:"timestamp_unix_nano"`
		Sequence          int64  `json:"sequence"`
		Digest            string `json:"digest"`
	}{
		TimestampUnixNano: t.UnixNano(),
		Sequence:          seq,
		Digest:            digest,
	}
	data, err := json.Marshal(anchor)
	if err == nil {
		_ = os.WriteFile(m.timeAnchorPath, data, 0600)
		_ = os.Chtimes(m.timeAnchorPath, t, t)
	}
}

func (m *LicenseManager) now() time.Time {
	if m.referenceTime != nil {
		return *m.referenceTime
	}
	return time.Now().UTC()
}

// SetReferenceTime overrides the internal clock for deterministic testing of boundaries and clock rollback.
func (m *LicenseManager) SetReferenceTime(t *time.Time) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.referenceTime = t
}

// VerifyLicense validates an Ed25519 signed license token against trusted public keys, validity window, and clock conditions.
func (m *LicenseManager) VerifyLicense(signedLicense *SignedLicense) (*LicenseValidationResult, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.verifyLicenseLocked(signedLicense)
}

func (m *LicenseManager) verifyLicenseLocked(signedLicense *SignedLicense) (*LicenseValidationResult, error) {
	if signedLicense == nil {
		return nil, errors.New("licensing: signed license is nil")
	}

	// 1. Independent trust anchor verification: IssuerKeyID MUST exist in trusted registry
	if signedLicense.IssuerKeyID == "" {
		return nil, ErrUntrustedSigningKey
	}
	if m.keyRegistry == nil {
		return nil, fmt.Errorf("%w: no trusted key registry configured", ErrUntrustedSigningKey)
	}

	trustedKey, ok := m.keyRegistry.LookupLicenseKey(signedLicense.IssuerKeyID)
	if !ok || len(trustedKey.PublicKey) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("%w: key ID %q not found or malformed", ErrUntrustedSigningKey, signedLicense.IssuerKeyID)
	}
	if trustedKey.Revoked {
		return nil, fmt.Errorf("%w: key ID %q revoked (reason: %s)", ErrRevokedSigningKey, signedLicense.IssuerKeyID, trustedKey.RevocationReason)
	}

	// 2. Cryptographic signature verification over canonical payload
	canonBytes, digestHex, err := ComputeCanonicalLicensePayload(signedLicense.Payload)
	if err != nil {
		return nil, fmt.Errorf("licensing: canonical serialization error: %w", err)
	}
	if digestHex != signedLicense.PayloadDigest {
		return nil, fmt.Errorf("%w: payload digest mismatch", ErrInvalidLicenseSignature)
	}

	sigBytes, err := hex.DecodeString(signedLicense.SignatureHex)
	if err != nil || len(sigBytes) != ed25519.SignatureSize {
		return nil, fmt.Errorf("%w: invalid ed25519 signature format", ErrInvalidLicenseSignature)
	}

	if !ed25519.Verify(trustedKey.PublicKey, canonBytes, sigBytes) {
		return nil, ErrInvalidLicenseSignature
	}

	// 3. Validity Window and Clock Rollback Checks
	now := m.now()

	// Suspicious timestamp check: IssuedAt > ExpiresAt or NotBefore > ExpiresAt
	if !signedLicense.Payload.IssuedAt.IsZero() && !signedLicense.Payload.ExpiresAt.IsZero() && signedLicense.Payload.IssuedAt.After(signedLicense.Payload.ExpiresAt) {
		return nil, fmt.Errorf("%w: issued_at is after expires_at", ErrInvalidLicenseSignature)
	}

	// Clock rollback checks: current time prior to issuance or prior to last recorded usage
	if !signedLicense.Payload.IssuedAt.IsZero() && now.Before(signedLicense.Payload.IssuedAt) {
		return nil, fmt.Errorf("%w: current clock (%s) is before license issuance (%s)", ErrClockRollbackDetected, now.Format(time.RFC3339), signedLicense.Payload.IssuedAt.Format(time.RFC3339))
	}
	if !m.lastRecordedTime.IsZero() && now.Before(m.lastRecordedTime) {
		return nil, fmt.Errorf("%w: current clock (%s) is prior to last verified usage event (%s)", ErrClockRollbackDetected, now.Format(time.RFC3339), m.lastRecordedTime.Format(time.RFC3339))
	}

	// Validity Window checks
	if !signedLicense.Payload.NotBefore.IsZero() && now.Before(signedLicense.Payload.NotBefore) {
		return nil, fmt.Errorf("%w: not valid before %s (current: %s)", ErrLicenseNotYetValid, signedLicense.Payload.NotBefore.Format(time.RFC3339), now.Format(time.RFC3339))
	}
	if !signedLicense.Payload.ExpiresAt.IsZero() && now.After(signedLicense.Payload.ExpiresAt) {
		return nil, fmt.Errorf("%w: expired on %s (current: %s)", ErrLicenseExpired, signedLicense.Payload.ExpiresAt.Format(time.RFC3339), now.Format(time.RFC3339))
	}

	daysRemaining := 0
	if !signedLicense.Payload.ExpiresAt.IsZero() {
		daysRemaining = int(signedLicense.Payload.ExpiresAt.Sub(now).Hours() / 24)
	}

	return &LicenseValidationResult{
		Valid:          true,
		LicenseID:      signedLicense.Payload.LicenseID,
		OrganizationID: signedLicense.Payload.OrganizationID,
		Tier:           signedLicense.Payload.LicenseTier,
		IssuerKeyID:    signedLicense.IssuerKeyID,
		IssuedAt:       signedLicense.Payload.IssuedAt,
		ExpiresAt:      signedLicense.Payload.ExpiresAt,
		DaysRemaining:  daysRemaining,
		Entitlements:   signedLicense.Payload.Entitlements,
		SignerVerified: true,
		IsAirGapped:    signedLicense.Payload.DeploymentType == DeploymentAirGapped,
		ValidatedAt:    now,
	}, nil
}

// InstallLicense verifies and installs an active license into the manager and persistent storage.
func (m *LicenseManager) InstallLicense(signedLicense *SignedLicense) (*LicenseValidationResult, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	valResult, err := m.verifyLicenseLocked(signedLicense)
	if err != nil {
		return nil, err
	}

	if err := m.store.SaveInstalledLicense(signedLicense, true); err != nil {
		return nil, fmt.Errorf("licensing: failed saving installed license: %w", err)
	}
	m.activeLicense = signedLicense
	return valResult, nil
}

// KeyRegistry returns the registry of trusted issuer keys.
func (m *LicenseManager) KeyRegistry() LicenseKeyRegistry {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.keyRegistry
}

// GetActiveLicense returns the currently active license, or default Community baseline if permitted.
func (m *LicenseManager) GetActiveLicense() (*SignedLicense, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.activeLicense != nil {
		return m.activeLicense, nil
	}
	if m.defaultCommunity {
		return m.buildDefaultCommunityLicense(), nil
	}
	return nil, ErrLicenseNotFound
}

// buildDefaultCommunityLicense creates an unauthenticated community baseline entitlement.
func (m *LicenseManager) buildDefaultCommunityLicense() *SignedLicense {
	return &SignedLicense{
		Payload: LicensePayload{
			LicenseID:        "COMMUNITY-DEFAULT",
			OrganizationID:   "COMMUNITY",
			OrganizationName: "Community Evaluation",
			ProductID:        "FELIX-CORE",
			LicenseTier:      TierCommunity,
			DeploymentType:   DeploymentOnPremise,
			Version:          "1.0.0",
			IssuedAt:         m.now(),
			NotBefore:        m.now().Add(-time.Hour),
			ExpiresAt:        m.now().Add(365 * 24 * time.Hour),
			Entitlements: LicenseEntitlements{
				MaxAssessments:             10,
				MaxConcurrentAssessments:   1,
				MaxTargetsPerAssessment:    5,
				MaxHistoricalRetentionDays: 14,
				AllowedFeatures: []string{
					FeatureZeroCredentialRecon,
					FeatureScanBasic,
				},
				AllowedProfiles:          []string{"standard"},
				AllowAirGappedExport:     false,
				AllowOfflineExecution:    true,
				AllowCustomCronSchedules: false,
			},
		},
		IssuerKeyID:  "KEY-COMMUNITY-BUILTIN",
		SignatureHex: "COMMUNITY_UNSIGNED",
	}
}

// CheckFeature verifies whether a feature is permitted under the active license.
func (m *LicenseManager) CheckFeature(feature string) error {
	lic, err := m.GetActiveLicense()
	if err != nil {
		return err
	}

	// Community tier rejects enterprise features
	if lic.Payload.LicenseTier == TierCommunity {
		for _, f := range lic.Payload.Entitlements.AllowedFeatures {
			if strings.EqualFold(f, feature) {
				return nil
			}
		}
		return fmt.Errorf("%w: feature %q requires Professional or Enterprise tier", ErrFeatureNotEntitled, feature)
	}

	// Verify against allowed features
	for _, f := range lic.Payload.Entitlements.AllowedFeatures {
		if strings.EqualFold(f, feature) || f == "*" {
			return nil
		}
	}
	return fmt.Errorf("%w: feature %q is not included in active license", ErrFeatureNotEntitled, feature)
}

// ReserveExecution atomically reserves a concurrency slot and quota unit prior to assessment execution.
func (m *LicenseManager) ReserveExecution(ctx context.Context, opID string, feature string, targetCount int) (*UsageReservation, error) {
	if ctx != nil && ctx.Err() != nil {
		return nil, ctx.Err()
	}

	if targetCount < 0 {
		return nil, ErrInvalidTargetCount
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	now := m.now()
	// Monotonic time validation against recorded ledger time and anchor
	if !m.lastRecordedTime.IsZero() && now.Before(m.lastRecordedTime) {
		return nil, fmt.Errorf("%w: reservation timestamp inverted", ErrClockRollbackDetected)
	}
	if err := m.checkTimeAnchor(now); err != nil {
		return nil, err
	}

	// Replay defense: verify operation ID has not already been committed
	if _, committed := m.committedOps[opID]; committed || (m.store != nil && m.store.HasCommittedOperation(opID)) {
		return nil, fmt.Errorf("%w: operation %s has already been committed", ErrReplayDetected, opID)
	}

	lic := m.activeLicense
	if lic == nil {
		if m.defaultCommunity {
			lic = m.buildDefaultCommunityLicense()
		} else {
			return nil, ErrLicenseNotFound
		}
	}

	// 1. Verify license validity
	if _, err := m.verifyLicenseLocked(lic); err != nil && lic.Payload.LicenseTier != TierCommunity {
		return nil, err
	}

	// 2. Feature entitlement check
	if feature != "" {
		featureAllowed := false
		for _, f := range lic.Payload.Entitlements.AllowedFeatures {
			if strings.EqualFold(f, feature) || f == "*" {
				featureAllowed = true
				break
			}
		}
		if !featureAllowed {
			return nil, fmt.Errorf("%w: feature %q", ErrFeatureNotEntitled, feature)
		}
	}

	// 3. Target limits check
	maxTargets := lic.Payload.Entitlements.MaxTargetsPerAssessment
	if maxTargets > 0 && targetCount > maxTargets {
		return nil, fmt.Errorf("%w: requested %d targets, limit is %d", ErrTargetLimitExceeded, targetCount, maxTargets)
	}

	// 4. Concurrency check
	maxConcurrent := lic.Payload.Entitlements.MaxConcurrentAssessments
	if maxConcurrent > 0 && m.activeConcurrency >= maxConcurrent {
		return nil, fmt.Errorf("%w: active %d >= max %d", ErrConcurrencyLimitExceeded, m.activeConcurrency, maxConcurrent)
	}

	// 5. Usage quota and integer overflow check
	if m.consumedAssessments > math.MaxInt64-m.reservedAssessments-1 {
		return nil, ErrIntegerOverflow
	}
	maxAssessments := lic.Payload.Entitlements.MaxAssessments
	if maxAssessments != -1 {
		if (m.consumedAssessments + m.reservedAssessments + 1) > maxAssessments {
			return nil, fmt.Errorf("%w: consumed %d + reserved %d >= max %d", ErrUsageQuotaExhausted, m.consumedAssessments, m.reservedAssessments, maxAssessments)
		}
	}

	// 6. Check duplicate active operation
	for _, res := range m.activeReservations {
		if res.OperationID == opID && !res.Committed && !res.Released {
			return nil, ErrDuplicateReservation
		}
	}

	resID := fmt.Sprintf("RES-%s-%d", opID, time.Now().UnixNano())
	reservation := &UsageReservation{
		ReservationID: resID,
		OperationID:   opID,
		LicenseID:     lic.Payload.LicenseID,
		Feature:       feature,
		Quantity:      1,
		TargetCount:   targetCount,
		CreatedAt:     m.now(),
		ExpiresAt:     m.now().Add(30 * time.Minute),
		mgr:           m,
	}

	m.activeConcurrency++
	m.reservedAssessments++
	m.activeReservations[resID] = reservation

	return reservation, nil
}

// CommitExecution atomically commits billable consumption into the immutable persistent hash-chain ledger.
func (m *LicenseManager) CommitExecution(res *UsageReservation, status string, metadata map[string]string) (*UsageRecord, error) {
	if res == nil {
		return nil, errors.New("licensing: reservation is nil")
	}
	if res.Quantity <= 0 {
		return nil, ErrInvalidQuantity
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	activeRes, exists := m.activeReservations[res.ReservationID]
	if !exists || activeRes.Committed || activeRes.Released {
		return nil, ErrReservationNotFound
	}

	// Duplicate usage submission check
	if activeRes.Committed || (m.store != nil && m.store.HasCommittedOperation(res.OperationID)) {
		return nil, fmt.Errorf("%w: operation %s already committed", ErrDuplicateUsageSubmission, res.OperationID)
	}

	now := m.now()
	// Monotonic time validation
	if !m.lastRecordedTime.IsZero() && now.Before(m.lastRecordedTime) {
		return nil, fmt.Errorf("%w: commit timestamp inverted", ErrClockRollbackDetected)
	}

	// Out-of-band anchor check
	if err := m.checkTimeAnchor(now); err != nil {
		return nil, err
	}

	nextSeq := m.lastKnownSequence + 1
	prevDigest := m.lastKnownDigest
	recID := fmt.Sprintf("USG-REC-%08d", nextSeq)

	record := UsageRecord{
		RecordID:             recID,
		SequenceNumber:       nextSeq,
		LicenseID:            res.LicenseID,
		OrganizationID:       m.activeLicenseOrgID(),
		OperationID:          res.OperationID,
		Feature:              res.Feature,
		Quantity:             res.Quantity,
		Timestamp:            now,
		Status:               status,
		Metadata:             metadata,
		PreviousRecordDigest: prevDigest,
		SignerKeyID:          m.localSignerKeyID,
	}

	canonBytes, digestHex, err := ComputeUsageRecordDigest(record)
	if err != nil {
		return nil, fmt.Errorf("licensing: failed computing usage record digest: %w", err)
	}
	record.RecordDigest = digestHex

	// Sign usage record with local Ed25519 signer key
	if len(m.localSignerPrivKey) == ed25519.PrivateKeySize {
		sig := ed25519.Sign(m.localSignerPrivKey, canonBytes)
		record.SignatureHex = hex.EncodeToString(sig)
	} else {
		record.SignatureHex = "LOCAL_UNSIGNED"
	}

	// Persist to SQLite store
	if err := m.store.AppendUsageRecord(&record); err != nil {
		return nil, fmt.Errorf("licensing: failed persisting usage record: %w", err)
	}

	// Update in-memory state
	m.lastKnownSequence = nextSeq
	m.lastKnownDigest = digestHex
	m.consumedAssessments += res.Quantity
	m.lastRecordedTime = now
	m.reservedAssessments--
	m.activeConcurrency--
	activeRes.Committed = true
	delete(m.activeReservations, res.ReservationID)

	if m.committedOps == nil {
		m.committedOps = make(map[string]struct{})
	}
	m.committedOps[res.OperationID] = struct{}{}
	m.updateTimeAnchor(now, nextSeq, digestHex)

	return &record, nil
}

// ReleaseExecution releases a reservation without consuming billable quota (e.g. on guardrail failure or cancellation).
func (m *LicenseManager) ReleaseExecution(res *UsageReservation, reason string) error {
	if res == nil {
		return errors.New("licensing: reservation is nil")
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	activeRes, exists := m.activeReservations[res.ReservationID]
	if !exists || activeRes.Committed || activeRes.Released {
		return ErrReservationNotFound
	}

	activeRes.Released = true
	m.activeConcurrency--
	m.reservedAssessments--
	delete(m.activeReservations, res.ReservationID)

	return nil
}

func (m *LicenseManager) activeLicenseOrgID() string {
	if m.activeLicense != nil {
		return m.activeLicense.Payload.OrganizationID
	}
	return "COMMUNITY"
}

// GetQuotaReport calculates current usage, active concurrency, and remaining balance.
func (m *LicenseManager) GetQuotaReport() (QuotaReport, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	lic := m.activeLicense
	if lic == nil {
		if m.defaultCommunity {
			lic = m.buildDefaultCommunityLicense()
		} else {
			return QuotaReport{}, ErrLicenseNotFound
		}
	}

	maxAssessments := lic.Payload.Entitlements.MaxAssessments
	remaining := int64(-1)
	if maxAssessments != -1 {
		remaining = maxAssessments - (m.consumedAssessments + m.reservedAssessments)
		if remaining < 0 {
			remaining = 0
		}
	}

	now := m.now()
	daysUntilExpiry := 0
	isExpired := false
	if !lic.Payload.ExpiresAt.IsZero() {
		daysUntilExpiry = int(lic.Payload.ExpiresAt.Sub(now).Hours() / 24)
		if now.After(lic.Payload.ExpiresAt) {
			isExpired = true
		}
	}

	return QuotaReport{
		LicenseID:            lic.Payload.LicenseID,
		OrganizationName:     lic.Payload.OrganizationName,
		Tier:                 lic.Payload.LicenseTier,
		DeploymentType:       lic.Payload.DeploymentType,
		MaxAssessments:       maxAssessments,
		ConsumedAssessments:  m.consumedAssessments,
		ReservedAssessments:  m.reservedAssessments,
		RemainingAssessments: remaining,
		ActiveConcurrency:    m.activeConcurrency,
		MaxConcurrency:       lic.Payload.Entitlements.MaxConcurrentAssessments,
		ExpiresAt:            lic.Payload.ExpiresAt,
		DaysUntilExpiry:      daysUntilExpiry,
		IsExpired:            isExpired,
		IsAirGapped:          lic.Payload.DeploymentType == DeploymentAirGapped,
	}, nil
}

// ExportSignedUsage gathers historical usage records and packages them into a signed, air-gapped verifiable export.
func (m *LicenseManager) ExportSignedUsage(ctx context.Context) (*SignedUsageExport, error) {
	if ctx != nil && ctx.Err() != nil {
		return nil, ctx.Err()
	}

	m.mu.RLock()
	defer m.mu.RUnlock()

	records, err := m.store.GetAllUsageRecords()
	if err != nil {
		return nil, fmt.Errorf("licensing: failed retrieving usage records: %w", err)
	}

	now := m.now()
	exportID := fmt.Sprintf("EXP-%s-%d", m.activeLicenseOrgID(), now.Unix())
	firstSeq := int64(0)
	lastSeq := int64(0)
	finalDigest := GenesisHash
	totalConsumed := int64(0)

	if len(records) > 0 {
		firstSeq = records[0].SequenceNumber
		lastSeq = records[len(records)-1].SequenceNumber
		finalDigest = records[len(records)-1].RecordDigest
		for _, r := range records {
			totalConsumed += r.Quantity
		}
	}

	export := SignedUsageExport{
		ExportID:              exportID,
		GeneratedAt:           now,
		LicenseID:             m.activeLicenseID(),
		OrganizationID:        m.activeLicenseOrgID(),
		TotalRecords:          len(records),
		FirstSequence:         firstSeq,
		LastSequence:          lastSeq,
		TotalQuantityConsumed: totalConsumed,
		FinalHashChainDigest:  finalDigest,
		Records:               records,
		SignerKeyID:           m.localSignerKeyID,
	}

	if len(m.localSignerPrivKey) == ed25519.PrivateKeySize {
		export.SignerPublicKeyHex = hex.EncodeToString(m.localSignerPrivKey.Public().(ed25519.PublicKey))
	}

	canonBytes, digestHex, err := ComputeExportDigest(export)
	if err != nil {
		return nil, fmt.Errorf("licensing: failed computing export digest: %w", err)
	}
	export.ExportDigest = digestHex

	if len(m.localSignerPrivKey) == ed25519.PrivateKeySize {
		sig := ed25519.Sign(m.localSignerPrivKey, canonBytes)
		export.SignatureHex = hex.EncodeToString(sig)
	} else {
		export.SignatureHex = "EXPORT_UNSIGNED"
	}

	return &export, nil
}

func (m *LicenseManager) activeLicenseID() string {
	if m.activeLicense != nil {
		return m.activeLicense.Payload.LicenseID
	}
	return "COMMUNITY-DEFAULT"
}

// AsEnforcer returns an adapter that satisfies assessment.LicenseEnforcer.
func (m *LicenseManager) AsEnforcer() assessment.LicenseEnforcer {
	return &licenseEnforcerAdapter{mgr: m}
}

type licenseEnforcerAdapter struct {
	mgr *LicenseManager
}

func (a *licenseEnforcerAdapter) ReserveExecution(ctx context.Context, opID string, feature string, targetCount int) (assessment.EnforcerReservation, error) {
	return a.mgr.ReserveExecution(ctx, opID, feature, targetCount)
}

// VerifyUsageExport independently audits an exported usage bundle for cryptographic and chain integrity.
// The verifier parameter MUST be either an independent LicenseKeyRegistry (preferred for multi-key trust)
// or an explicitly trusted ed25519.PublicKey.
// It NEVER trusts a public key solely because it is embedded in the export!
func VerifyUsageExport(export *SignedUsageExport, verifier interface{}) (*ExportVerificationResult, error) {
	if export == nil {
		return nil, errors.New("licensing: export is nil")
	}
	switch v := verifier.(type) {
	case LicenseKeyRegistry:
		return VerifyUsageExportWithRegistry(export, v)
	case ed25519.PublicKey:
		return VerifyUsageExportWithKey(export, v)
	default:
		return nil, errors.New("licensing: verifier must be LicenseKeyRegistry or ed25519.PublicKey")
	}
}

// VerifyUsageExportWithRegistry independently audits an exported usage bundle using an independent trusted key registry.
func VerifyUsageExportWithRegistry(export *SignedUsageExport, trustedRegistry LicenseKeyRegistry) (*ExportVerificationResult, error) {
	if export == nil {
		return nil, errors.New("licensing: export is nil")
	}
	if trustedRegistry == nil {
		return nil, errors.New("licensing: trusted key registry is required for independent verification")
	}

	var issues []string
	now := time.Now().UTC()

	// 1. Resolve trusted public key strictly from independent registry using SignerKeyID
	if export.SignerKeyID == "" {
		issues = append(issues, "missing signer key ID in export header")
	}

	var trustedPubKey ed25519.PublicKey
	if export.SignerKeyID != "" {
		keyRecord, ok := trustedRegistry.LookupLicenseKey(export.SignerKeyID)
		if !ok || len(keyRecord.PublicKey) != ed25519.PublicKeySize {
			issues = append(issues, fmt.Sprintf("untrusted signer key %q: key ID not found in trusted registry", export.SignerKeyID))
		} else if keyRecord.Revoked {
			issues = append(issues, fmt.Sprintf("revoked signer key %q: key ID has been revoked in registry (reason: %s)", export.SignerKeyID, keyRecord.RevocationReason))
		} else {
			trustedPubKey = keyRecord.PublicKey
		}
	}

	// 2. Key substitution defense:
	// If the export contains an embedded public key (attacker attempt to self-sign or substitute),
	// it MUST match the trusted key from the registry. The embedded key is NEVER used as a trust anchor!
	if export.SignerPublicKeyHex != "" && len(trustedPubKey) == ed25519.PublicKeySize {
		expectedHex := hex.EncodeToString(trustedPubKey)
		if !strings.EqualFold(export.SignerPublicKeyHex, expectedHex) {
			issues = append(issues, fmt.Sprintf("key substitution detected: embedded public key %q does not match trusted registry key %q", export.SignerPublicKeyHex, expectedHex))
		}
	}

	return verifyUsageExportInternal(export, trustedPubKey, issues, now)
}

// VerifyUsageExportWithKey independently audits an exported usage bundle using an explicitly provided trusted public key.
func VerifyUsageExportWithKey(export *SignedUsageExport, trustedPubKey ed25519.PublicKey) (*ExportVerificationResult, error) {
	if export == nil {
		return nil, errors.New("licensing: export is nil")
	}
	var issues []string
	now := time.Now().UTC()
	if len(trustedPubKey) != ed25519.PublicKeySize {
		issues = append(issues, "invalid or empty trusted public key")
	}
	if export.SignerPublicKeyHex != "" && len(trustedPubKey) == ed25519.PublicKeySize {
		expectedHex := hex.EncodeToString(trustedPubKey)
		if !strings.EqualFold(export.SignerPublicKeyHex, expectedHex) {
			issues = append(issues, fmt.Sprintf("key substitution detected: embedded public key %q does not match trusted key %q", export.SignerPublicKeyHex, expectedHex))
		}
	}
	return verifyUsageExportInternal(export, trustedPubKey, issues, now)
}

func verifyUsageExportInternal(export *SignedUsageExport, trustedPubKey ed25519.PublicKey, issues []string, now time.Time) (*ExportVerificationResult, error) {
	// 1. Verify export outer signature
	sigValid := false
	if len(trustedPubKey) == ed25519.PublicKeySize {
		canonBytes, digestHex, err := ComputeExportDigest(*export)
		if err != nil {
			issues = append(issues, fmt.Sprintf("failed recomputing export digest: %v", err))
		} else if digestHex != export.ExportDigest {
			issues = append(issues, "export digest mismatch")
		} else {
			sigBytes, err := hex.DecodeString(export.SignatureHex)
			if err != nil || len(sigBytes) != ed25519.SignatureSize {
				issues = append(issues, "invalid export signature hex")
			} else {
				sigValid = ed25519.Verify(trustedPubKey, canonBytes, sigBytes)
				if !sigValid {
					issues = append(issues, "export outer ed25519 signature verification failed")
				}
			}
		}
	} else {
		issues = append(issues, "no trusted public key available for export signature validation")
	}

	// 2. Verify internal records hash chain and record signatures
	chainContinuous := true
	recSigsValid := true
	expectedPrevDigest := GenesisHash
	totalCalcQty := int64(0)

	for i, r := range export.Records {
		expectedSeq := int64(i + 1)
		if r.SequenceNumber != expectedSeq {
			chainContinuous = false
			issues = append(issues, fmt.Sprintf("record index %d sequence mismatch: expected %d, got %d", i, expectedSeq, r.SequenceNumber))
		}
		if r.PreviousRecordDigest != expectedPrevDigest {
			chainContinuous = false
			issues = append(issues, fmt.Sprintf("record sequence %d previous digest mismatch: expected %s, got %s", r.SequenceNumber, expectedPrevDigest, r.PreviousRecordDigest))
		}

		canonRecBytes, recDigestHex, err := ComputeUsageRecordDigest(r)
		if err != nil || recDigestHex != r.RecordDigest {
			chainContinuous = false
			issues = append(issues, fmt.Sprintf("record sequence %d content tampered: digest mismatch", r.SequenceNumber))
		}

		if len(trustedPubKey) == ed25519.PublicKeySize {
			recSigBytes, err := hex.DecodeString(r.SignatureHex)
			if err != nil || len(recSigBytes) != ed25519.SignatureSize || !ed25519.Verify(trustedPubKey, canonRecBytes, recSigBytes) {
				recSigsValid = false
				issues = append(issues, fmt.Sprintf("record sequence %d signature verification failed", r.SequenceNumber))
			}
		}

		expectedPrevDigest = r.RecordDigest
		totalCalcQty += r.Quantity
	}

	if export.TotalQuantityConsumed != totalCalcQty {
		issues = append(issues, fmt.Sprintf("total quantity mismatch: header=%d, calculated=%d", export.TotalQuantityConsumed, totalCalcQty))
	}
	if len(export.Records) > 0 && export.FinalHashChainDigest != export.Records[len(export.Records)-1].RecordDigest {
		issues = append(issues, "final hash chain digest mismatch")
	}

	overallVerified := sigValid && chainContinuous && recSigsValid && len(issues) == 0

	return &ExportVerificationResult{
		Verified:              overallVerified,
		ExportID:              export.ExportID,
		LicenseID:             export.LicenseID,
		TotalRecords:          export.TotalRecords,
		TotalQuantityConsumed: export.TotalQuantityConsumed,
		FirstSequence:         export.FirstSequence,
		LastSequence:          export.LastSequence,
		ChainContinuous:       chainContinuous,
		ExportSignatureValid:  sigValid,
		RecordSignaturesValid: recSigsValid,
		VerifiedAt:            now,
		Issues:                issues,
	}, nil
}

// -----------------------------------------------------------------------------
// Global License Manager Singleton & Safe Dev/Test Mode
// -----------------------------------------------------------------------------

var (
	globalLicenseManager  *LicenseManager
	globalLicenseMu       sync.RWMutex
	devTestMode           bool
	devTestExplicitlySet  bool
	devTestMu             sync.RWMutex
)

const (
	// DevTestModeEnvVar defines the environment variable for developer test execution.
	DevTestModeEnvVar = "FELIX_DEV_TEST_MODE"
	// DevTestModeToken is the exact secret token required to prevent accidental production bypass.
	DevTestModeToken = "FELIX_UNRESTRICTED_DEV_TEST_PASS"
)

func isTestContext() bool {
	if len(os.Args) > 0 {
		arg0 := strings.ToLower(os.Args[0])
		if strings.HasSuffix(arg0, ".test") || strings.HasSuffix(arg0, ".test.exe") || strings.Contains(arg0, "go-build") {
			return true
		}
	}
	for _, arg := range os.Args {
		if strings.HasPrefix(arg, "-test.") {
			return true
		}
	}
	if flag.Lookup("test.v") != nil || flag.Lookup("test.run") != nil {
		return true
	}
	return false
}

func init() {
	assessment.SetGlobalLicenseEnforcer(GetGlobalLicenseManager().AsEnforcer())
	report.SetGlobalFeatureGate(GetGlobalLicenseManager())
}

// IsDevTestMode returns whether the explicit test mode is currently active.
func IsDevTestMode() bool {
	devTestMu.RLock()
	defer devTestMu.RUnlock()
	if devTestExplicitlySet {
		return devTestMode
	}
	envVal := os.Getenv(DevTestModeEnvVar)
	if envVal == "false" {
		return false
	}
	if envVal == DevTestModeToken || envVal == "true" {
		return true
	}
	return isTestContext()
}

// SetDevTestMode sets the dev/test mode for isolated test suites.
func SetDevTestMode(enabled bool) {
	devTestMu.Lock()
	devTestExplicitlySet = true
	devTestMode = enabled
	devTestMu.Unlock()

	ResetGlobalLicenseManager()
	assessment.SetGlobalLicenseEnforcer(GetGlobalLicenseManager().AsEnforcer())
	report.SetGlobalFeatureGate(GetGlobalLicenseManager())
}

// GetGlobalLicenseManager returns the global singleton license manager.
func GetGlobalLicenseManager() *LicenseManager {
	globalLicenseMu.RLock()
	mgr := globalLicenseManager
	globalLicenseMu.RUnlock()
	if mgr != nil {
		return mgr
	}

	globalLicenseMu.Lock()
	defer globalLicenseMu.Unlock()
	if globalLicenseManager != nil {
		return globalLicenseManager
	}

	store, _ := NewLicenseStore(":memory:")
	reg := NewMapLicenseKeyRegistry()

	var defaultLic *SignedLicense
	if IsDevTestMode() {
		pub, priv, _ := ed25519.GenerateKey(nil)
		keyID := "TEST-DEV-ISSUER-KEY"
		_ = reg.RegisterKey(keyID, pub)
		now := time.Now().UTC()
		payload := LicensePayload{
			LicenseID:        "DEV-TEST-LICENSE-001",
			OrganizationID:   "ORG-INTERNAL-DEV",
			OrganizationName: "Internal Development / Test",
			ProductID:        "felix-enterprise",
			LicenseTier:      TierEnterprise,
			DeploymentType:   DeploymentContainer,
			Version:          "1.0.0",
			IssuerKeyID:      keyID,
			IssuedAt:         now.Add(-1 * time.Hour),
			NotBefore:        now.Add(-1 * time.Hour),
			ExpiresAt:        now.Add(365 * 24 * time.Hour),
			Entitlements: LicenseEntitlements{
				MaxAssessments:           -1,
				MaxConcurrentAssessments: 10,
				MaxTargetsPerAssessment:  -1,
				AllowedFeatures:          []string{"*"},
				AllowAirGappedExport:     true,
				AllowOfflineExecution:    true,
			},
		}
		signed, _ := SignLicensePayload(payload, keyID, priv)
		defaultLic = signed
	}

	m, _ := NewLicenseManager(LicenseManagerConfig{
		Store:              store,
		KeyRegistry:        reg,
		LocalSignerKeyID:   "LOCAL-USAGE-SIGNER-01",
		DefaultToCommunity: true,
	})
	if defaultLic != nil {
		_, _ = m.InstallLicense(defaultLic)
	}

	globalLicenseManager = m
	return globalLicenseManager
}

// SetGlobalLicenseManager overrides the global singleton license manager.
func SetGlobalLicenseManager(m *LicenseManager) {
	globalLicenseMu.Lock()
	globalLicenseManager = m
	globalLicenseMu.Unlock()
	if m != nil {
		assessment.SetGlobalLicenseEnforcer(m.AsEnforcer())
		report.SetGlobalFeatureGate(m)
	}
}

// ResetGlobalLicenseManager resets the global singleton to nil.
func ResetGlobalLicenseManager() {
	globalLicenseMu.Lock()
	defer globalLicenseMu.Unlock()
	globalLicenseManager = nil
}
