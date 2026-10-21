package compliance

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"felix/pkg/config"
	_ "modernc.org/sqlite"
)

var (
	// ErrNotFound is returned when an evaluation or record is not found in the compliance store.
	ErrNotFound = errors.New("compliance record not found")

	// ErrConflictingEvaluation is returned when an evaluation is submitted with an existing ID but conflicting semantic content.
	ErrConflictingEvaluation = errors.New("conflicting compliance evaluation content for existing record")

	// ErrInvalidEvaluation is returned when an evaluation fails pre-persistence validation.
	ErrInvalidEvaluation = errors.New("invalid compliance evaluation record")
)

// EvaluationFilter specifies criteria for querying individual control evaluation records.
type EvaluationFilter struct {
	AssessmentID   string          `json:"assessment_id,omitempty"`
	CatalogID      string          `json:"catalog_id,omitempty"`
	CatalogVersion string          `json:"catalog_version,omitempty"`
	ControlID      string          `json:"control_id,omitempty"`
	State          EvaluationState `json:"state,omitempty"`
	Limit          int             `json:"limit,omitempty"`
	Offset         int             `json:"offset,omitempty"`
}

// EvaluationResultFilter specifies criteria for querying evaluation results.
type EvaluationResultFilter struct {
	AssessmentID string `json:"assessment_id,omitempty"`
	CatalogID    string `json:"catalog_id,omitempty"`
	Limit        int    `json:"limit,omitempty"`
	Offset       int    `json:"offset,omitempty"`
}

// EvaluationResultSummary provides a high-level summary of a persisted evaluation result.
type EvaluationResultSummary struct {
	ResultID               string            `json:"result_id"`
	AssessmentID           string            `json:"assessment_id"`
	ExecutionID            string            `json:"execution_id,omitempty"`
	CatalogIdentity        string            `json:"catalog_identity"`
	CatalogID              string            `json:"catalog_id"`
	CatalogVersion         string            `json:"catalog_version"`
	CatalogDigest          string            `json:"catalog_digest"`
	MappingRuleSetIdentity string            `json:"mapping_ruleset_identity,omitempty"`
	MappingRuleSetDigest   string            `json:"mapping_ruleset_digest,omitempty"`
	ResultDigest           string            `json:"result_digest"`
	EngineVersion          string            `json:"engine_version"`
	EvaluatedAt            time.Time         `json:"evaluated_at"`
	Summary                EvaluationSummary `json:"summary"`
	LimitationsNotice      string            `json:"limitations_notice"`
}

// EvaluationEvidenceRecord represents an evidence item linked to an evaluation record.
type EvaluationEvidenceRecord struct {
	ID           string    `json:"id"`
	EvaluationID string    `json:"evaluation_id"`
	AssessmentID string    `json:"assessment_id"`
	ControlID    string    `json:"control_id"`
	EvidenceType string    `json:"evidence_type"` // "supporting", "contradicting", "reference", "finding"
	ReferenceID  string    `json:"reference_id"`
	Detail       string    `json:"detail,omitempty"`
	CreatedAt    time.Time `json:"created_at"`
}

// ComplianceStore defines the durable persistence contract for compliance evaluations and evidence records.
type ComplianceStore interface {
	// SaveEvaluationResult atomically persists a complete, validated evaluation result and its evidence records.
	SaveEvaluationResult(res *EvaluationResult) error

	// SaveEvaluationResultWithKey persists an evaluation result protected by the provided KeyProvider.
	SaveEvaluationResultWithKey(res *EvaluationResult, keyProvider KeyProvider) error

	// VerifyEvaluationIntegrity verifies the content integrity and authenticity of a persisted evaluation.
	VerifyEvaluationIntegrity(assessmentID, catalogID string, keyProvider KeyProvider) (*IntegrityVerificationResult, error)

	// GetVerifiedEvaluationResult retrieves an EvaluationResult and verifies its content integrity and authenticity.
	// If the record has been tampered with or corrupted, it fails closed, returning ErrIntegrityMismatch and nil result.
	GetVerifiedEvaluationResult(assessmentID, catalogID string, keyProvider KeyProvider) (*EvaluationResult, *IntegrityVerificationResult, error)

	// GetIntegrityRecord retrieves the stored integrity metadata for an evaluation result ID.
	GetIntegrityRecord(resultID string) (*IntegrityRecord, error)

	// GetEvaluationResult retrieves an EvaluationResult by assessmentID and catalogID (or evaluation result ID)
	// without cryptographic integrity verification.
	// CAUTION: Data returned by GetEvaluationResult represents raw, unverified database state. Callers requiring
	// trusted, tamper-checked evaluations must use GetVerifiedEvaluationResult or VerifyEvaluationIntegrity.
	GetEvaluationResult(assessmentID, catalogID string) (*EvaluationResult, error)

	// GetControlEvaluation retrieves a single control evaluation record by evaluationID.
	GetControlEvaluation(evaluationID string) (*ControlEvaluationRecord, error)

	// ListControlEvaluations queries control evaluation records matching filter criteria.
	ListControlEvaluations(filter EvaluationFilter) ([]ControlEvaluationRecord, error)

	// ListEvaluationResults queries evaluation results matching filter criteria.
	ListEvaluationResults(filter EvaluationResultFilter) ([]EvaluationResultSummary, error)

	// GetEvaluationEvidence retrieves the evidence records or references associated with an evaluation.
	GetEvaluationEvidence(evaluationID string) ([]EvaluationEvidenceRecord, error)

	// EvaluationExists checks if an evaluation result already exists for the assessment and catalog.
	EvaluationExists(assessmentID, catalogID string) (bool, error)

	// Remediation SLA Persistence methods (Phase 9.6)
	SaveRemediationPolicy(policy *RemediationSLAPolicy) error
	GetRemediationPolicy(policyID string) (*RemediationSLAPolicy, error)
	ListRemediationPolicies() ([]RemediationSLAPolicy, error)
	SaveRemediationRecord(rec *RemediationRecord, event *RemediationHistoryEvent) error
	GetRemediationRecord(id string) (*RemediationRecord, error)
	GetRemediationRecordByFinding(findingID string) (*RemediationRecord, error)
	ListRemediationRecords(filter RemediationFilter) ([]RemediationRecord, error)
	GetRemediationHistory(remediationID string) ([]RemediationHistoryEvent, error)
	ListRemediationRecordsWithHistory(filter RemediationFilter) ([]RemediationRecord, map[string][]RemediationHistoryEvent, error)
	SaveRemediationRecordWithKey(rec *RemediationRecord, event *RemediationHistoryEvent, keyProvider KeyProvider) error
	VerifyRemediationIntegrity(remediationID string, keyProvider KeyProvider) (*RemediationIntegrityVerificationResult, error)
	GetRemediationIntegrityRecord(remediationID string) (*RemediationIntegrityRecord, error)

	// Close releases storage resources.
	Close() error
}

// SQLiteComplianceStore implements ComplianceStore using an embedded SQLite database.
type SQLiteComplianceStore struct {
	db *sql.DB
	mu sync.RWMutex
}

// DefaultComplianceDBPath returns the default path to ~/.felix/compliance.db.
func DefaultComplianceDBPath() (string, error) {
	dir, err := config.Dir()
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return "", fmt.Errorf("failed creating felix directory: %w", err)
	}
	return filepath.Join(dir, "compliance.db"), nil
}

// NewSQLiteComplianceStore opens or creates an SQLite database for compliance persistence.
// If dbPath is empty, DefaultComplianceDBPath() is used.
// If dbPath is ":memory:", an isolated in-memory database is created.
func NewSQLiteComplianceStore(dbPath string) (*SQLiteComplianceStore, error) {
	if dbPath == "" {
		p, err := DefaultComplianceDBPath()
		if err != nil {
			return nil, err
		}
		dbPath = p
	}

	dsn := dbPath
	if dbPath == ":memory:" {
		dsn = ":memory:?_pragma=foreign_keys(1)&_pragma=busy_timeout(5000)"
	} else if !strings.Contains(dbPath, "?") {
		dsn = fmt.Sprintf("%s?_pragma=foreign_keys(1)&_pragma=busy_timeout(5000)", dbPath)
	}

	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("failed opening compliance database at %s: %w", dbPath, err)
	}

	// Configure connection pragmas for performance, integrity, and safety
	pragmas := []string{
		"PRAGMA foreign_keys = ON;",
		"PRAGMA journal_mode = WAL;",
		"PRAGMA busy_timeout = 5000;",
		"PRAGMA synchronous = NORMAL;",
	}
	for _, pragma := range pragmas {
		if _, err := db.Exec(pragma); err != nil {
			// Some pragmas (like WAL) may fail or be no-ops on :memory: DBs; ignore if in-memory
			if dbPath != ":memory:" {
				db.Close()
				return nil, fmt.Errorf("failed executing %s: %w", pragma, err)
			}
		}
	}

	store := &SQLiteComplianceStore{db: db}
	if err := store.migrate(); err != nil {
		db.Close()
		return nil, fmt.Errorf("compliance database migration failed: %w", err)
	}

	return store, nil
}

// NewSQLiteComplianceStoreWithDB initializes a SQLiteComplianceStore with an existing *sql.DB.
func NewSQLiteComplianceStoreWithDB(db *sql.DB) (*SQLiteComplianceStore, error) {
	if db == nil {
		return nil, errors.New("db cannot be nil")
	}
	store := &SQLiteComplianceStore{db: db}
	if err := store.migrate(); err != nil {
		return nil, fmt.Errorf("compliance database migration failed: %w", err)
	}
	return store, nil
}

func (s *SQLiteComplianceStore) migrate() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// 1. Ensure schema_migrations exists
	_, err := s.db.Exec(`
		CREATE TABLE IF NOT EXISTS compliance_schema_migrations (
			version INTEGER PRIMARY KEY,
			applied_at TIMESTAMP NOT NULL
		);
	`)
	if err != nil {
		return fmt.Errorf("failed creating compliance_schema_migrations table: %w", err)
	}

	var currentVersion int
	row := s.db.QueryRow("SELECT COALESCE(MAX(version), 0) FROM compliance_schema_migrations")
	if err := row.Scan(&currentVersion); err != nil {
		return fmt.Errorf("failed reading schema version: %w", err)
	}

	// Migration 1: Compliance evaluation core tables
	if currentVersion < 1 {
		tx, err := s.db.Begin()
		if err != nil {
			return err
		}
		defer tx.Rollback()

		schemaV1 := `
		CREATE TABLE IF NOT EXISTS compliance_evaluation_results (
			id TEXT PRIMARY KEY,
			assessment_id TEXT NOT NULL,
			execution_id TEXT,
			catalog_identity TEXT NOT NULL,
			catalog_id TEXT NOT NULL,
			catalog_version TEXT NOT NULL,
			catalog_digest TEXT NOT NULL,
			mapping_ruleset_identity TEXT,
			mapping_ruleset_digest TEXT,
			engine_version TEXT NOT NULL,
			result_digest TEXT NOT NULL,
			limitations_notice TEXT,
			total_controls INTEGER NOT NULL,
			compliant_count INTEGER NOT NULL,
			non_compliant_count INTEGER NOT NULL,
			partially_compliant_count INTEGER NOT NULL,
			not_assessed_count INTEGER NOT NULL,
			insufficient_evidence_count INTEGER NOT NULL,
			not_applicable_count INTEGER NOT NULL,
			error_count INTEGER NOT NULL,
			applicable_controls INTEGER NOT NULL,
			assessed_controls INTEGER NOT NULL,
			evaluated_at TIMESTAMP NOT NULL,
			created_at TIMESTAMP NOT NULL,
			updated_at TIMESTAMP NOT NULL
		);

		CREATE INDEX IF NOT EXISTS idx_eval_results_assessment ON compliance_evaluation_results(assessment_id);
		CREATE INDEX IF NOT EXISTS idx_eval_results_catalog ON compliance_evaluation_results(catalog_id, catalog_version);

		CREATE TABLE IF NOT EXISTS compliance_control_evaluations (
			id TEXT PRIMARY KEY,
			result_id TEXT NOT NULL REFERENCES compliance_evaluation_results(id) ON DELETE CASCADE,
			assessment_id TEXT NOT NULL,
			execution_id TEXT,
			catalog_id TEXT NOT NULL,
			catalog_version TEXT NOT NULL,
			control_id TEXT NOT NULL,
			control_title TEXT,
			state TEXT NOT NULL,
			rationale TEXT NOT NULL,
			engine_version TEXT NOT NULL,
			mapping_ruleset_version TEXT,
			mapping_ruleset_digest TEXT,
			limitations TEXT,
			finding_ids_json TEXT,
			evidence_references_json TEXT,
			supporting_evidence_json TEXT,
			contradicting_evidence_json TEXT,
			evaluated_at TIMESTAMP NOT NULL,
			created_at TIMESTAMP NOT NULL
		);

		CREATE INDEX IF NOT EXISTS idx_ctrl_evals_result_id ON compliance_control_evaluations(result_id);
		CREATE INDEX IF NOT EXISTS idx_ctrl_evals_assessment_control ON compliance_control_evaluations(assessment_id, control_id);
		CREATE INDEX IF NOT EXISTS idx_ctrl_evals_catalog_control ON compliance_control_evaluations(catalog_id, control_id);
		CREATE INDEX IF NOT EXISTS idx_ctrl_evals_state ON compliance_control_evaluations(state);

		CREATE TABLE IF NOT EXISTS compliance_evidence_links (
			id TEXT PRIMARY KEY,
			evaluation_id TEXT NOT NULL REFERENCES compliance_control_evaluations(id) ON DELETE CASCADE,
			assessment_id TEXT NOT NULL,
			catalog_id TEXT NOT NULL,
			control_id TEXT NOT NULL,
			evidence_type TEXT NOT NULL,
			reference_id TEXT NOT NULL,
			detail TEXT,
			created_at TIMESTAMP NOT NULL
		);

		CREATE INDEX IF NOT EXISTS idx_ev_links_evaluation_id ON compliance_evidence_links(evaluation_id);
		CREATE INDEX IF NOT EXISTS idx_ev_links_assessment_control ON compliance_evidence_links(assessment_id, control_id);
		CREATE INDEX IF NOT EXISTS idx_ev_links_reference_id ON compliance_evidence_links(reference_id);
		`

		if _, err := tx.Exec(schemaV1); err != nil {
			return fmt.Errorf("failed executing migration v1: %w", err)
		}

		if _, err := tx.Exec("INSERT INTO compliance_schema_migrations (version, applied_at) VALUES (1, ?)", time.Now().UTC()); err != nil {
			return fmt.Errorf("failed recording migration v1: %w", err)
		}

		if err := tx.Commit(); err != nil {
			return fmt.Errorf("failed committing migration v1: %w", err)
		}
	}

	// Migration 2: Compliance integrity and authenticity records
	if currentVersion < 2 {
		tx, err := s.db.Begin()
		if err != nil {
			return err
		}
		defer tx.Rollback()

		schemaV2 := `
		CREATE TABLE IF NOT EXISTS compliance_integrity_records (
			result_id TEXT PRIMARY KEY REFERENCES compliance_evaluation_results(id) ON DELETE CASCADE,
			format_version TEXT NOT NULL,
			canonical_digest TEXT NOT NULL,
			authenticity_algorithm TEXT NOT NULL,
			key_id TEXT,
			signature_tag TEXT,
			evidence_manifest_digest TEXT,
			control_count INTEGER NOT NULL,
			evidence_count INTEGER NOT NULL,
			protected_at TIMESTAMP NOT NULL,
			verified_at TIMESTAMP
		);

		CREATE INDEX IF NOT EXISTS idx_integrity_key ON compliance_integrity_records(key_id);
		`

		if _, err := tx.Exec(schemaV2); err != nil {
			return fmt.Errorf("failed executing migration v2: %w", err)
		}

		if _, err := tx.Exec("INSERT INTO compliance_schema_migrations (version, applied_at) VALUES (2, ?)", time.Now().UTC()); err != nil {
			return fmt.Errorf("failed recording migration v2: %w", err)
		}

		if err := tx.Commit(); err != nil {
			return fmt.Errorf("failed committing migration v2: %w", err)
		}
	}

	// Migration 3: Add integrity_version marker to compliance_evaluation_results
	if currentVersion < 3 {
		tx, err := s.db.Begin()
		if err != nil {
			return err
		}
		defer tx.Rollback()

		schemaV3 := `
		ALTER TABLE compliance_evaluation_results ADD COLUMN integrity_version TEXT DEFAULT '';
		`

		if _, err := tx.Exec(schemaV3); err != nil {
			return fmt.Errorf("failed executing migration v3: %w", err)
		}

		if _, err := tx.Exec("INSERT INTO compliance_schema_migrations (version, applied_at) VALUES (3, ?)", time.Now().UTC()); err != nil {
			return fmt.Errorf("failed recording migration v3: %w", err)
		}

		if err := tx.Commit(); err != nil {
			return fmt.Errorf("failed committing migration v3: %w", err)
		}
	}

	// Migration 4: Remediation SLA policies, records, and auditable history
	if currentVersion < 4 {
		tx, err := s.db.Begin()
		if err != nil {
			return err
		}
		defer tx.Rollback()

		schemaV4 := `
		CREATE TABLE IF NOT EXISTS compliance_remediation_policies (
			id TEXT PRIMARY KEY,
			version TEXT NOT NULL,
			enabled INTEGER NOT NULL DEFAULT 1,
			description TEXT,
			priority INTEGER NOT NULL DEFAULT 0,
			policy_json TEXT NOT NULL,
			created_at TIMESTAMP NOT NULL,
			updated_at TIMESTAMP NOT NULL
		);

		CREATE TABLE IF NOT EXISTS compliance_remediation_records (
			id TEXT PRIMARY KEY,
			finding_id TEXT NOT NULL,
			finding_source TEXT NOT NULL,
			finding_title TEXT,
			finding_category TEXT,
			assessment_id TEXT,
			catalog_id TEXT,
			control_id TEXT,
			evaluation_id TEXT,
			severity TEXT NOT NULL,
			severity_source TEXT NOT NULL,
			policy_id TEXT NOT NULL,
			policy_version TEXT NOT NULL,
			policy_rule_matched TEXT,
			assigned_at TIMESTAMP NOT NULL,
			sla_start_time TIMESTAMP NOT NULL,
			deadline TIMESTAMP NOT NULL,
			time_basis TEXT NOT NULL,
			status TEXT NOT NULL,
			completed_at TIMESTAMP,
			risk_acceptance_json TEXT,
			reopen_count INTEGER NOT NULL DEFAULT 0,
			reopened_at TIMESTAMP,
			evidence_references_json TEXT,
			created_at TIMESTAMP NOT NULL,
			updated_at TIMESTAMP NOT NULL
		);

		CREATE INDEX IF NOT EXISTS idx_rem_finding ON compliance_remediation_records(finding_id);
		CREATE INDEX IF NOT EXISTS idx_rem_assessment ON compliance_remediation_records(assessment_id);
		CREATE INDEX IF NOT EXISTS idx_rem_status ON compliance_remediation_records(status);
		CREATE INDEX IF NOT EXISTS idx_rem_deadline ON compliance_remediation_records(deadline);

		CREATE TABLE IF NOT EXISTS compliance_remediation_history (
			id TEXT PRIMARY KEY,
			remediation_id TEXT NOT NULL REFERENCES compliance_remediation_records(id) ON DELETE CASCADE,
			event_type TEXT NOT NULL,
			from_status TEXT,
			to_status TEXT,
			actor TEXT,
			reason TEXT,
			details_json TEXT,
			timestamp TIMESTAMP NOT NULL
		);

		CREATE INDEX IF NOT EXISTS idx_rem_hist_rem_id ON compliance_remediation_history(remediation_id);
		`

		if _, err := tx.Exec(schemaV4); err != nil {
			return fmt.Errorf("failed executing migration v4: %w", err)
		}

		if _, err := tx.Exec("INSERT INTO compliance_schema_migrations (version, applied_at) VALUES (4, ?)", time.Now().UTC()); err != nil {
			return fmt.Errorf("failed recording migration v4: %w", err)
		}

		if err := tx.Commit(); err != nil {
			return fmt.Errorf("failed committing migration v4: %w", err)
		}
	}

	// Migration 5: Remediation record integrity and authenticity tracking
	if currentVersion < 5 {
		tx, err := s.db.Begin()
		if err != nil {
			return err
		}
		defer tx.Rollback()

		schemaV5 := `
		ALTER TABLE compliance_remediation_records ADD COLUMN integrity_version TEXT DEFAULT '';

		CREATE TABLE IF NOT EXISTS compliance_remediation_integrity_records (
			remediation_id TEXT PRIMARY KEY REFERENCES compliance_remediation_records(id) ON DELETE CASCADE,
			format_version TEXT NOT NULL,
			canonical_digest TEXT NOT NULL,
			authenticity_algorithm TEXT NOT NULL,
			key_id TEXT,
			signature_tag TEXT,
			event_count INTEGER NOT NULL,
			history_chain_digest TEXT NOT NULL,
			protected_at TIMESTAMP NOT NULL,
			verified_at TIMESTAMP
		);

		CREATE INDEX IF NOT EXISTS idx_rem_integrity_key ON compliance_remediation_integrity_records(key_id);
		`

		if _, err := tx.Exec(schemaV5); err != nil {
			return fmt.Errorf("failed executing migration v5: %w", err)
		}

		if _, err := tx.Exec("INSERT INTO compliance_schema_migrations (version, applied_at) VALUES (5, ?)", time.Now().UTC()); err != nil {
			return fmt.Errorf("failed recording migration v5: %w", err)
		}

		if err := tx.Commit(); err != nil {
			return fmt.Errorf("failed committing migration v5: %w", err)
		}
	}

	return nil
}

func computeResultID(assessmentID, catalogID string) string {
	cleanAss := strings.TrimSpace(assessmentID)
	cleanCat := strings.TrimSpace(catalogID)
	if strings.HasPrefix(cleanAss, "evalres:") && cleanCat == "" {
		return cleanAss
	}
	return fmt.Sprintf("evalres:%s:%s", cleanAss, cleanCat)
}

func extractCatalogIDAndVersion(identity string, evs []ControlEvaluationRecord) (string, string) {
	trimmed := strings.TrimSpace(identity)
	var catID, catVer string
	if parts := strings.SplitN(trimmed, ":", 2); len(parts) == 2 {
		catID = parts[0]
		catVer = parts[1]
	} else {
		catID = trimmed
	}

	if catVer == "" && len(evs) > 0 && evs[0].CatalogVersion != "" {
		catVer = evs[0].CatalogVersion
	}
	if catID == "" && len(evs) > 0 && evs[0].CatalogID != "" {
		catID = evs[0].CatalogID
	}
	return catID, catVer
}

func shortDigest(digest string) string {
	d := strings.TrimSpace(digest)
	if idx := strings.Index(d, ":"); idx != -1 {
		d = d[idx+1:]
	}
	if len(d) > 8 {
		return d[:8]
	}
	return d
}

// computeEvaluationResultID generates a unique, deterministic identity for an evaluation result.
// Incorporates assessment ID, catalog ID, catalog version, execution ID, and mapping ruleset identity/digest.
// Guarantees:
// 1. Separate evaluations with different catalog revisions, ruleset versions, or execution IDs receive distinct IDs.
// 2. Repeated runs with identical inputs produce identical IDs for idempotent handling.
func computeEvaluationResultID(res *EvaluationResult) string {
	if res == nil {
		return ""
	}
	cleanAss := strings.TrimSpace(res.AssessmentID)
	catID, catVer := extractCatalogIDAndVersion(res.CatalogIdentity, res.Evaluations)
	cleanCat := strings.TrimSpace(catID)
	cleanVer := strings.TrimSpace(catVer)
	cleanExec := strings.TrimSpace(res.ExecutionID)
	cleanRuleID := strings.TrimSpace(res.MappingRuleSetIdentity)
	cleanRuleDigest := strings.TrimSpace(res.MappingRuleSetDigest)
	cleanCatDigest := strings.TrimSpace(res.CatalogDigest)

	parts := []string{"evalres", cleanAss, cleanCat}
	if cleanVer != "" {
		parts = append(parts, cleanVer)
	}
	if cleanExec != "" {
		parts = append(parts, cleanExec)
	}
	if cleanRuleID != "" {
		parts = append(parts, cleanRuleID)
	} else if cleanRuleDigest != "" {
		parts = append(parts, "rd="+shortDigest(cleanRuleDigest))
	}
	if cleanCatDigest != "" && cleanVer == "" {
		parts = append(parts, "cd="+shortDigest(cleanCatDigest))
	}

	return strings.Join(parts, ":")
}

// SaveEvaluationResult atomically persists an entire EvaluationResult and its evidence records
// with content-integrity protection.
func (s *SQLiteComplianceStore) SaveEvaluationResult(res *EvaluationResult) error {
	return s.SaveEvaluationResultWithKey(res, nil)
}

// SaveEvaluationResultWithKey atomically persists an entire EvaluationResult, its evidence records,
// and cryptographically binds its integrity and authenticity via the provided KeyProvider.
// Enforces pre-persistence validation, atomic transaction boundaries, idempotent retry handling,
// and rejection of conflicting content under the same result identity.
func (s *SQLiteComplianceStore) SaveEvaluationResultWithKey(res *EvaluationResult, keyProvider KeyProvider) error {
	if res == nil {
		return fmt.Errorf("%w: evaluation result cannot be nil", ErrInvalidEvaluation)
	}

	// 1. Pre-persistence semantic validation
	if err := ValidateEvaluationResult(res, nil); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidEvaluation, err)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	catID, catVer := extractCatalogIDAndVersion(res.CatalogIdentity, res.Evaluations)
	resultID := computeEvaluationResultID(res)
	resultDigest := res.Digest()
	now := time.Now().UTC()

	// 2. Begin atomic transaction
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("failed beginning transaction: %w", err)
	}
	defer tx.Rollback()

	// 3. Idempotency & Duplicate Check
	var existingDigest string
	err = tx.QueryRow("SELECT result_digest FROM compliance_evaluation_results WHERE id = ?", resultID).Scan(&existingDigest)
	if err == nil {
		// Existing record found
		if existingDigest == resultDigest {
			// Identical retry: idempotent success
			return nil
		}
		// Conflicting semantic content
		return fmt.Errorf("%w: evaluation for assessment %q and catalog %q already exists with digest %s (submitted %s)",
			ErrConflictingEvaluation, res.AssessmentID, res.CatalogIdentity, existingDigest, resultDigest)
	} else if !errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("failed checking existing evaluation: %w", err)
	}

	// 4. Insert into compliance_evaluation_results
	sum := res.Summary
	evalTime := res.EvaluatedAt
	if evalTime.IsZero() {
		evalTime = now
	}

	insertResultSQL := `
	INSERT INTO compliance_evaluation_results (
		id, assessment_id, execution_id, catalog_identity, catalog_id, catalog_version,
		catalog_digest, mapping_ruleset_identity, mapping_ruleset_digest, engine_version,
		result_digest, limitations_notice, total_controls, compliant_count, non_compliant_count,
		partially_compliant_count, not_assessed_count, insufficient_evidence_count,
		not_applicable_count, error_count, applicable_controls, assessed_controls,
		evaluated_at, created_at, updated_at, integrity_version
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
	`

	_, err = tx.Exec(insertResultSQL,
		resultID, res.AssessmentID, res.ExecutionID, res.CatalogIdentity, catID, catVer,
		res.CatalogDigest, res.MappingRuleSetIdentity, res.MappingRuleSetDigest, res.EngineVersion,
		resultDigest, res.LimitationsNotice, sum.TotalControls, sum.CompliantCount, sum.NonCompliantCount,
		sum.PartiallyCompliantCount, sum.NotAssessedCount, sum.InsufficientEvidenceCount,
		sum.NotApplicableCount, sum.ErrorCount, sum.ApplicableControls, sum.AssessedControls,
		evalTime, now, now, CurrentIntegrityFormatVersion,
	)
	if err != nil {
		return fmt.Errorf("failed inserting evaluation result: %w", err)
	}

	// 5. Insert control evaluations and evidence links
	insertCtrlSQL := `
	INSERT INTO compliance_control_evaluations (
		id, result_id, assessment_id, execution_id, catalog_id, catalog_version,
		control_id, control_title, state, rationale, engine_version,
		mapping_ruleset_version, mapping_ruleset_digest, limitations,
		finding_ids_json, evidence_references_json, supporting_evidence_json,
		contradicting_evidence_json, evaluated_at, created_at
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
	`

	insertLinkSQL := `
	INSERT INTO compliance_evidence_links (
		id, evaluation_id, assessment_id, catalog_id, control_id,
		evidence_type, reference_id, detail, created_at
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);
	`

	var allEvidenceRecords []EvaluationEvidenceRecord

	for idx, ev := range res.Evaluations {
		ctrlEvalID := ev.EvaluationID
		if ctrlEvalID == "" {
			ctrlEvalID = fmt.Sprintf("eval:%s:%s", resultID, ev.ControlID)
		} else {
			// Check if this ctrlEvalID is already used by a DIFFERENT result_id to prevent collision
			var existingResultID string
			err := tx.QueryRow("SELECT result_id FROM compliance_control_evaluations WHERE id = ?", ctrlEvalID).Scan(&existingResultID)
			if err == nil && existingResultID != resultID {
				ctrlEvalID = fmt.Sprintf("%s:%s", resultID, ev.ControlID)
			}
		}

		findingIDsJSON, _ := json.Marshal(ev.FindingIDs)
		evRefsJSON, _ := json.Marshal(ev.EvidenceReferences)
		suppEvJSON, _ := json.Marshal(ev.SupportingEvidence)
		contraEvJSON, _ := json.Marshal(ev.ContradictingEvidence)

		evTime := ev.EvaluatedAt
		if evTime.IsZero() {
			evTime = evalTime
		}

		evCatID := ev.CatalogID
		if evCatID == "" {
			evCatID = catID
		}
		evCatVer := ev.CatalogVersion
		if evCatVer == "" {
			evCatVer = catVer
		}
		evEngineVer := ev.EngineVersion
		if evEngineVer == "" {
			evEngineVer = res.EngineVersion
		}
		evRuleVer := ev.MappingRuleSetVersion
		if evRuleVer == "" {
			evRuleVer = res.MappingRuleSetIdentity
		}
		evRuleDigest := ev.MappingRuleSetDigest
		if evRuleDigest == "" {
			evRuleDigest = res.MappingRuleSetDigest
		}

		res.Evaluations[idx].EvaluationID = ctrlEvalID
		res.Evaluations[idx].CatalogID = evCatID
		res.Evaluations[idx].CatalogVersion = evCatVer
		res.Evaluations[idx].EngineVersion = evEngineVer
		res.Evaluations[idx].MappingRuleSetVersion = evRuleVer
		res.Evaluations[idx].MappingRuleSetDigest = evRuleDigest
		res.Evaluations[idx].EvaluatedAt = evTime

		_, err = tx.Exec(insertCtrlSQL,
			ctrlEvalID, resultID, res.AssessmentID, ev.ExecutionID, evCatID, evCatVer,
			ev.ControlID, ev.ControlTitle, string(ev.State), ev.Rationale, evEngineVer,
			evRuleVer, evRuleDigest, ev.Limitations,
			string(findingIDsJSON), string(evRefsJSON), string(suppEvJSON), string(contraEvJSON),
			evTime, now,
		)
		if err != nil {
			return fmt.Errorf("failed inserting control evaluation %s: %w", ev.ControlID, err)
		}

		// Insert structured evidence links and track for integrity binding
		linkCounter := 0

		for _, fID := range ev.FindingIDs {
			linkID := fmt.Sprintf("evlink:%s:%s:finding:%d", resultID, ev.ControlID, linkCounter)
			linkCounter++
			if _, err := tx.Exec(insertLinkSQL, linkID, ctrlEvalID, res.AssessmentID, evCatID, ev.ControlID, "finding", fID, "", now); err != nil {
				return fmt.Errorf("failed inserting finding evidence link: %w", err)
			}
			allEvidenceRecords = append(allEvidenceRecords, EvaluationEvidenceRecord{
				ID:           linkID,
				EvaluationID: ctrlEvalID,
				AssessmentID: res.AssessmentID,
				ControlID:    ev.ControlID,
				EvidenceType: "finding",
				ReferenceID:  fID,
				CreatedAt:    now,
			})
		}

		for _, ref := range ev.EvidenceReferences {
			linkID := fmt.Sprintf("evlink:%s:%s:ref:%d", resultID, ev.ControlID, linkCounter)
			linkCounter++
			if _, err := tx.Exec(insertLinkSQL, linkID, ctrlEvalID, res.AssessmentID, evCatID, ev.ControlID, "reference", ref, "", now); err != nil {
				return fmt.Errorf("failed inserting reference evidence link: %w", err)
			}
			allEvidenceRecords = append(allEvidenceRecords, EvaluationEvidenceRecord{
				ID:           linkID,
				EvaluationID: ctrlEvalID,
				AssessmentID: res.AssessmentID,
				ControlID:    ev.ControlID,
				EvidenceType: "reference",
				ReferenceID:  ref,
				CreatedAt:    now,
			})
		}

		for _, supp := range ev.SupportingEvidence {
			linkID := fmt.Sprintf("evlink:%s:%s:supp:%d", resultID, ev.ControlID, linkCounter)
			linkCounter++
			if _, err := tx.Exec(insertLinkSQL, linkID, ctrlEvalID, res.AssessmentID, evCatID, ev.ControlID, "supporting", fmt.Sprintf("supp-%d", idx), supp, now); err != nil {
				return fmt.Errorf("failed inserting supporting evidence link: %w", err)
			}
			allEvidenceRecords = append(allEvidenceRecords, EvaluationEvidenceRecord{
				ID:           linkID,
				EvaluationID: ctrlEvalID,
				AssessmentID: res.AssessmentID,
				ControlID:    ev.ControlID,
				EvidenceType: "supporting",
				ReferenceID:  fmt.Sprintf("supp-%d", idx),
				Detail:       supp,
				CreatedAt:    now,
			})
		}

		for _, contra := range ev.ContradictingEvidence {
			linkID := fmt.Sprintf("evlink:%s:%s:contra:%d", resultID, ev.ControlID, linkCounter)
			linkCounter++
			if _, err := tx.Exec(insertLinkSQL, linkID, ctrlEvalID, res.AssessmentID, evCatID, ev.ControlID, "contradicting", fmt.Sprintf("contra-%d", idx), contra, now); err != nil {
				return fmt.Errorf("failed inserting contradicting evidence link: %w", err)
			}
			allEvidenceRecords = append(allEvidenceRecords, EvaluationEvidenceRecord{
				ID:           linkID,
				EvaluationID: ctrlEvalID,
				AssessmentID: res.AssessmentID,
				ControlID:    ev.ControlID,
				EvidenceType: "contradicting",
				ReferenceID:  fmt.Sprintf("contra-%d", idx),
				Detail:       contra,
				CreatedAt:    now,
			})
		}
	}

	// 6. Generate and persist integrity and authenticity metadata
	integrityRec, err := ProtectEvaluationResult(context.Background(), res, allEvidenceRecords, keyProvider)
	if err != nil {
		return fmt.Errorf("failed generating integrity record: %w", err)
	}

	insertIntegritySQL := `
	INSERT INTO compliance_integrity_records (
		result_id, format_version, canonical_digest, authenticity_algorithm,
		key_id, signature_tag, evidence_manifest_digest, control_count,
		evidence_count, protected_at, verified_at
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
	`

	_, err = tx.Exec(insertIntegritySQL,
		integrityRec.ResultID, integrityRec.FormatVersion, integrityRec.CanonicalDigest,
		integrityRec.AuthenticityAlgorithm, integrityRec.KeyID, integrityRec.SignatureTag,
		integrityRec.EvidenceManifestDigest, integrityRec.ControlCount, integrityRec.EvidenceCount,
		integrityRec.ProtectedAt, integrityRec.VerifiedAt,
	)
	if err != nil {
		return fmt.Errorf("failed inserting integrity record: %w", err)
	}

	// 7. Commit transaction atomically
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed committing evaluation transaction: %w", err)
	}

	return nil
}

// GetEvaluationResult retrieves an EvaluationResult by assessmentID and catalogID (or resultID).
// Supports exact result ID lookup, version-qualified catalog identity (e.g. "nist:5.1.0"),
// or unversioned catalog ID (returning the latest evaluated result for that assessment and catalog).
func (s *SQLiteComplianceStore) GetEvaluationResult(assessmentID, catalogID string) (*EvaluationResult, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	res, _, err := s.getEvaluationResultUnlocked(assessmentID, catalogID)
	return res, err
}

func (s *SQLiteComplianceStore) getEvaluationResultUnlocked(assessmentID, catalogID string) (*EvaluationResult, string, error) {
	cleanAss := strings.TrimSpace(assessmentID)
	cleanCat := strings.TrimSpace(catalogID)

	likePattern := ""
	if cleanCat != "" {
		likePattern = "evalres:" + cleanAss + ":" + cleanCat + "%"
	}

	querySQL := `
	SELECT id, assessment_id, execution_id, catalog_identity, catalog_digest,
	       mapping_ruleset_identity, mapping_ruleset_digest, engine_version,
	       COALESCE(limitations_notice, ''), total_controls, compliant_count, non_compliant_count,
	       partially_compliant_count, not_assessed_count, insufficient_evidence_count,
	       not_applicable_count, error_count, applicable_controls, assessed_controls,
	       evaluated_at, COALESCE(integrity_version, '')
	FROM compliance_evaluation_results
	WHERE id = ? OR (assessment_id = ? AND (? = '' OR catalog_id = ? OR catalog_identity = ? OR id LIKE ?))
	ORDER BY evaluated_at DESC, created_at DESC
	LIMIT 1;
	`

	var (
		resID, assID, catIdentity, catDigest, engineVer, limitationsNotice string
		execID, ruleSetID, ruleSetDigest, integrityVer                     sql.NullString
		total, comp, nonComp, partComp, notAss, insuff, notApp, errCount   int
		applicable, assessed                                               int
		evaluatedAt                                                        time.Time
	)

	row := s.db.QueryRow(querySQL, cleanAss, cleanAss, cleanCat, cleanCat, cleanCat, likePattern)
	err := row.Scan(
		&resID, &assID, &execID, &catIdentity, &catDigest,
		&ruleSetID, &ruleSetDigest, &engineVer, &limitationsNotice,
		&total, &comp, &nonComp, &partComp, &notAss, &insuff,
		&notApp, &errCount, &applicable, &assessed, &evaluatedAt,
		&integrityVer,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, "", ErrNotFound
	}
	if err != nil {
		return nil, "", fmt.Errorf("failed querying evaluation result: %w", err)
	}

	// Query control evaluations
	ctrlQuerySQL := `
	SELECT id, assessment_id, execution_id, catalog_id, catalog_version,
	       control_id, control_title, state, rationale, engine_version,
	       mapping_ruleset_version, mapping_ruleset_digest, limitations,
	       finding_ids_json, evidence_references_json, supporting_evidence_json,
	       contradicting_evidence_json, evaluated_at
	FROM compliance_control_evaluations
	WHERE result_id = ?
	ORDER BY control_id ASC;
	`

	rows, err := s.db.Query(ctrlQuerySQL, resID)
	if err != nil {
		return nil, "", fmt.Errorf("failed querying control evaluations: %w", err)
	}
	defer rows.Close()

	var evaluations []ControlEvaluationRecord
	for rows.Next() {
		var (
			recID, recAssID, cID, cTitle, stateStr, rationale, recEngineVer string
			catID, catVer                                                   string
			recExecID, rsVer, rsDigest, lim                                 sql.NullString
			fIDsJSON, refsJSON, suppJSON, contraJSON                        string
			recEvalAt                                                       time.Time
		)

		err := rows.Scan(
			&recID, &recAssID, &recExecID, &catID, &catVer,
			&cID, &cTitle, &stateStr, &rationale, &recEngineVer,
			&rsVer, &rsDigest, &lim,
			&fIDsJSON, &refsJSON, &suppJSON, &contraJSON,
			&recEvalAt,
		)
		if err != nil {
			return nil, "", fmt.Errorf("failed scanning control evaluation row: %w", err)
		}

		var fIDs, refs, supp, contra []string
		_ = json.Unmarshal([]byte(fIDsJSON), &fIDs)
		_ = json.Unmarshal([]byte(refsJSON), &refs)
		_ = json.Unmarshal([]byte(suppJSON), &supp)
		_ = json.Unmarshal([]byte(contraJSON), &contra)

		if fIDs == nil {
			fIDs = []string{}
		}
		if refs == nil {
			refs = []string{}
		}
		if supp == nil {
			supp = []string{}
		}
		if contra == nil {
			contra = []string{}
		}

		evalState, _ := CanonicalEvaluationState(stateStr)

		evaluations = append(evaluations, ControlEvaluationRecord{
			EvaluationID:          recID,
			CatalogID:             catID,
			CatalogVersion:        catVer,
			ControlID:             cID,
			ControlTitle:          cTitle,
			AssessmentID:          recAssID,
			ExecutionID:           recExecID.String,
			State:                 evalState,
			Rationale:             rationale,
			FindingIDs:            fIDs,
			EvidenceReferences:    refs,
			SupportingEvidence:    supp,
			ContradictingEvidence: contra,
			EvaluatedAt:           recEvalAt,
			EngineVersion:         recEngineVer,
			MappingRuleSetVersion: rsVer.String,
			MappingRuleSetDigest:  rsDigest.String,
			Limitations:           lim.String,
		})
	}
	if err := rows.Err(); err != nil {
		return nil, "", fmt.Errorf("error reading control evaluations: %w", err)
	}

	res := &EvaluationResult{
		CatalogIdentity:        catIdentity,
		CatalogDigest:          catDigest,
		MappingRuleSetIdentity: ruleSetID.String,
		MappingRuleSetDigest:   ruleSetDigest.String,
		AssessmentID:           assID,
		ExecutionID:            execID.String,
		EvaluatedAt:            evaluatedAt,
		EngineVersion:          engineVer,
		Evaluations:            evaluations,
		Summary: EvaluationSummary{
			TotalControls:             total,
			CompliantCount:            comp,
			NonCompliantCount:         nonComp,
			PartiallyCompliantCount:   partComp,
			NotAssessedCount:          notAss,
			InsufficientEvidenceCount: insuff,
			NotApplicableCount:        notApp,
			ErrorCount:                errCount,
			ApplicableControls:        applicable,
			AssessedControls:          assessed,
		},
		LimitationsNotice: limitationsNotice,
		IntegrityVersion:  integrityVer.String,
	}

	covBasis := CalculateCoverageBasis(res.Summary)
	res.CoverageBasis = &covBasis
	res.StructuredLimitations = DeriveLimitationsFromEvaluation(res, nil)

	return res, resID, nil
}

// VerifyEvaluationIntegrity verifies the content integrity and authenticity of a persisted evaluation.
func (s *SQLiteComplianceStore) VerifyEvaluationIntegrity(assessmentID, catalogID string, keyProvider KeyProvider) (*IntegrityVerificationResult, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	// 1. Retrieve the evaluation result and its database result ID
	res, resultID, err := s.getEvaluationResultUnlocked(assessmentID, catalogID)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return nil, ErrNotFound
		}
		return &IntegrityVerificationResult{
			Status:            StatusOperationalFailure,
			Violations:        []string{fmt.Sprintf("failed retrieving evaluation result: %v", err)},
			VerifiedAt:        time.Now().UTC(),
			LimitationsNotice: IntegrityLimitationsNotice(),
		}, nil
	}

	// 2. Query all evidence links for this evaluation result
	evidenceQuery := `
		SELECT l.id, l.evaluation_id, c.control_id, l.control_id, l.evidence_type, l.reference_id, l.detail, l.created_at
		FROM compliance_evidence_links l
		JOIN compliance_control_evaluations c ON l.evaluation_id = c.id
		WHERE c.result_id = ?
		ORDER BY l.control_id ASC, l.evaluation_id ASC, l.evidence_type ASC, l.reference_id ASC;
	`
	rows, err := s.db.Query(evidenceQuery, resultID)
	if err != nil {
		return &IntegrityVerificationResult{
			ResultID:          resultID,
			AssessmentID:      res.AssessmentID,
			CatalogIdentity:   res.CatalogIdentity,
			Status:            StatusOperationalFailure,
			Violations:        []string{fmt.Sprintf("failed querying evidence links: %v", err)},
			VerifiedAt:        time.Now().UTC(),
			LimitationsNotice: IntegrityLimitationsNotice(),
		}, nil
	}
	defer rows.Close()

	var evidenceLinks []EvaluationEvidenceRecord
	for rows.Next() {
		var rec EvaluationEvidenceRecord
		var cControlID string
		var detail sql.NullString
		if err := rows.Scan(&rec.ID, &rec.EvaluationID, &cControlID, &rec.ControlID, &rec.EvidenceType, &rec.ReferenceID, &detail, &rec.CreatedAt); err != nil {
			return &IntegrityVerificationResult{
				ResultID:          resultID,
				AssessmentID:      res.AssessmentID,
				CatalogIdentity:   res.CatalogIdentity,
				Status:            StatusOperationalFailure,
				Violations:        []string{fmt.Sprintf("failed scanning evidence link: %v", err)},
				VerifiedAt:        time.Now().UTC(),
				LimitationsNotice: IntegrityLimitationsNotice(),
			}, nil
		}
		rec.Detail = detail.String

		// Relational consistency: ensure evidence link control_id matches parent evaluation control_id
		if cControlID != rec.ControlID {
			return &IntegrityVerificationResult{
				ResultID:          resultID,
				AssessmentID:      res.AssessmentID,
				CatalogIdentity:   res.CatalogIdentity,
				FormatVersion:     res.IntegrityVersion,
				Status:            StatusIntegrityMismatch,
				Violations:        []string{fmt.Sprintf("evidence link %s references evaluation for control %q but claims control %q (inconsistent relationship)", rec.ID, cControlID, rec.ControlID)},
				VerifiedAt:        time.Now().UTC(),
				LimitationsNotice: IntegrityLimitationsNotice(),
				EvidenceIntegrity: EvidenceIntegrityReport{
					TotalEvidenceLinks: len(evidenceLinks),
					MetadataVerified:   false,
					ContentVerified:    false,
					ContentNote:        "Inconsistent evidence link parent binding",
				},
			}, nil
		}

		evidenceLinks = append(evidenceLinks, rec)
	}

	// 3. Query the stored integrity record
	var rec IntegrityRecord
	var keyID, sigTag, evManifest sql.NullString
	var verAt sql.NullTime

	queryIntegrity := `
		SELECT result_id, format_version, canonical_digest, authenticity_algorithm,
		       key_id, signature_tag, evidence_manifest_digest, control_count,
		       evidence_count, protected_at, verified_at
		FROM compliance_integrity_records
		WHERE result_id = ?;
	`
	err = s.db.QueryRow(queryIntegrity, resultID).Scan(
		&rec.ResultID, &rec.FormatVersion, &rec.CanonicalDigest, &rec.AuthenticityAlgorithm,
		&keyID, &sigTag, &evManifest, &rec.ControlCount,
		&rec.EvidenceCount, &rec.ProtectedAt, &verAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		if res.IntegrityVersion != "" {
			// Expected integrity protection, but the integrity metadata row was deleted or stripped!
			return &IntegrityVerificationResult{
				ResultID:          resultID,
				AssessmentID:      res.AssessmentID,
				CatalogIdentity:   res.CatalogIdentity,
				FormatVersion:     res.IntegrityVersion,
				Status:            StatusIntegrityMismatch,
				Violations:        []string{fmt.Sprintf("integrity protection metadata missing for protected record (expected format %s; integrity row deleted or stripped)", res.IntegrityVersion)},
				VerifiedAt:        time.Now().UTC(),
				LimitationsNotice: IntegrityLimitationsNotice(),
				EvidenceIntegrity: EvidenceIntegrityReport{
					TotalEvidenceLinks: len(evidenceLinks),
					MetadataVerified:   false,
					ContentVerified:    false,
					ContentNote:        "Integrity metadata deleted or removed",
				},
			}, nil
		}

		// Genuine pre-integrity legacy evaluation (no integrity_version marker)
		return &IntegrityVerificationResult{
			ResultID:          resultID,
			AssessmentID:      res.AssessmentID,
			CatalogIdentity:   res.CatalogIdentity,
			Status:            StatusUnverifiedLegacy,
			Violations:        []string{"no integrity metadata found for evaluation record (legacy unverified)"},
			VerifiedAt:        time.Now().UTC(),
			LimitationsNotice: IntegrityLimitationsNotice(),
			EvidenceIntegrity: EvidenceIntegrityReport{
				TotalEvidenceLinks: len(evidenceLinks),
				MetadataVerified:   false,
				ContentVerified:    false,
				ContentNote:        "Legacy record without integrity metadata",
			},
		}, nil
	}
	if err != nil {
		return &IntegrityVerificationResult{
			ResultID:          resultID,
			AssessmentID:      res.AssessmentID,
			CatalogIdentity:   res.CatalogIdentity,
			Status:            StatusOperationalFailure,
			Violations:        []string{fmt.Sprintf("failed reading integrity record: %v", err)},
			VerifiedAt:        time.Now().UTC(),
			LimitationsNotice: IntegrityLimitationsNotice(),
		}, nil
	}

	rec.KeyID = keyID.String
	rec.SignatureTag = sigTag.String
	rec.EvidenceManifestDigest = evManifest.String
	rec.VerifiedAt = verAt.Time

	// 4. Build canonical payload from current database state
	payload, err := BuildCanonicalIntegrityPayload(res, evidenceLinks)
	if err != nil {
		return &IntegrityVerificationResult{
			ResultID:          resultID,
			AssessmentID:      res.AssessmentID,
			CatalogIdentity:   res.CatalogIdentity,
			Status:            StatusOperationalFailure,
			Violations:        []string{fmt.Sprintf("failed building canonical payload: %v", err)},
			VerifiedAt:        time.Now().UTC(),
			LimitationsNotice: IntegrityLimitationsNotice(),
		}, nil
	}

	// 5. Verify canonical integrity and authenticity
	verResult := VerifyCanonicalIntegrity(context.Background(), payload, &rec, keyProvider)

	// If verified, update verified_at timestamp in database
	if verResult.Status == StatusVerified || verResult.Status == StatusIntegrityOnly {
		_, _ = s.db.Exec("UPDATE compliance_integrity_records SET verified_at = ? WHERE result_id = ?", time.Now().UTC(), resultID)
	}

	return verResult, nil
}

// GetVerifiedEvaluationResult retrieves an EvaluationResult and verifies its content integrity and authenticity.
// If the record has been tampered with or corrupted, it fails closed, returning ErrIntegrityMismatch and nil result.
// If verification succeeds (StatusVerified or StatusIntegrityOnly), res.Verified is set to true.
func (s *SQLiteComplianceStore) GetVerifiedEvaluationResult(assessmentID, catalogID string, keyProvider KeyProvider) (*EvaluationResult, *IntegrityVerificationResult, error) {
	verResult, err := s.VerifyEvaluationIntegrity(assessmentID, catalogID, keyProvider)
	if err != nil {
		return nil, nil, err
	}
	if verResult.Status == StatusIntegrityMismatch {
		return nil, verResult, ErrIntegrityMismatch
	}

	res, err := s.GetEvaluationResult(assessmentID, catalogID)
	if err != nil {
		return nil, verResult, err
	}

	if verResult.Status == StatusVerified || verResult.Status == StatusIntegrityOnly {
		res.Verified = true
	} else {
		res.Verified = false
	}

	return res, verResult, nil
}

// GetIntegrityRecord retrieves the stored integrity metadata for an evaluation result ID.
func (s *SQLiteComplianceStore) GetIntegrityRecord(resultID string) (*IntegrityRecord, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var rec IntegrityRecord
	var keyID, sigTag, evManifest sql.NullString
	var verAt sql.NullTime

	queryIntegrity := `
		SELECT result_id, format_version, canonical_digest, authenticity_algorithm,
		       key_id, signature_tag, evidence_manifest_digest, control_count,
		       evidence_count, protected_at, verified_at
		FROM compliance_integrity_records
		WHERE result_id = ?;
	`
	err := s.db.QueryRow(queryIntegrity, strings.TrimSpace(resultID)).Scan(
		&rec.ResultID, &rec.FormatVersion, &rec.CanonicalDigest, &rec.AuthenticityAlgorithm,
		&keyID, &sigTag, &evManifest, &rec.ControlCount,
		&rec.EvidenceCount, &rec.ProtectedAt, &verAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("failed reading integrity record: %w", err)
	}

	rec.KeyID = keyID.String
	rec.SignatureTag = sigTag.String
	rec.EvidenceManifestDigest = evManifest.String
	rec.VerifiedAt = verAt.Time
	return &rec, nil
}

// GetControlEvaluation retrieves a single control evaluation record by evaluationID.
func (s *SQLiteComplianceStore) GetControlEvaluation(evaluationID string) (*ControlEvaluationRecord, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	cleanID := strings.TrimSpace(evaluationID)
	querySQL := `
	SELECT id, assessment_id, execution_id, catalog_id, catalog_version,
	       control_id, control_title, state, rationale, engine_version,
	       mapping_ruleset_version, mapping_ruleset_digest, limitations,
	       finding_ids_json, evidence_references_json, supporting_evidence_json,
	       contradicting_evidence_json, evaluated_at
	FROM compliance_control_evaluations
	WHERE id = ? OR id LIKE ?
	ORDER BY evaluated_at DESC, created_at DESC
	LIMIT 1;
	`

	var (
		recID, recAssID, cID, cTitle, stateStr, rationale, recEngineVer string
		catID, catVer                                                   string
		recExecID, rsVer, rsDigest, lim                                 sql.NullString
		fIDsJSON, refsJSON, suppJSON, contraJSON                        string
		recEvalAt                                                       time.Time
	)

	likePattern := "%:" + cleanID
	row := s.db.QueryRow(querySQL, cleanID, likePattern)
	err := row.Scan(
		&recID, &recAssID, &recExecID, &catID, &catVer,
		&cID, &cTitle, &stateStr, &rationale, &recEngineVer,
		&rsVer, &rsDigest, &lim,
		&fIDsJSON, &refsJSON, &suppJSON, &contraJSON,
		&recEvalAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("failed querying control evaluation: %w", err)
	}

	var fIDs, refs, supp, contra []string
	_ = json.Unmarshal([]byte(fIDsJSON), &fIDs)
	_ = json.Unmarshal([]byte(refsJSON), &refs)
	_ = json.Unmarshal([]byte(suppJSON), &supp)
	_ = json.Unmarshal([]byte(contraJSON), &contra)

	evalState, _ := CanonicalEvaluationState(stateStr)

	return &ControlEvaluationRecord{
		EvaluationID:          recID,
		CatalogID:             catID,
		CatalogVersion:        catVer,
		ControlID:             cID,
		ControlTitle:          cTitle,
		AssessmentID:          recAssID,
		ExecutionID:           recExecID.String,
		State:                 evalState,
		Rationale:             rationale,
		FindingIDs:            fIDs,
		EvidenceReferences:    refs,
		SupportingEvidence:    supp,
		ContradictingEvidence: contra,
		EvaluatedAt:           recEvalAt,
		EngineVersion:         recEngineVer,
		MappingRuleSetVersion: rsVer.String,
		MappingRuleSetDigest:  rsDigest.String,
		Limitations:           lim.String,
	}, nil
}

// ListControlEvaluations queries control evaluation records matching filter criteria.
func (s *SQLiteComplianceStore) ListControlEvaluations(filter EvaluationFilter) ([]ControlEvaluationRecord, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var whereClauses []string
	var args []any

	if filter.AssessmentID != "" {
		whereClauses = append(whereClauses, "assessment_id = ?")
		args = append(args, strings.TrimSpace(filter.AssessmentID))
	}
	if filter.CatalogID != "" {
		whereClauses = append(whereClauses, "catalog_id = ?")
		args = append(args, strings.TrimSpace(filter.CatalogID))
	}
	if filter.CatalogVersion != "" {
		whereClauses = append(whereClauses, "catalog_version = ?")
		args = append(args, strings.TrimSpace(filter.CatalogVersion))
	}
	if filter.ControlID != "" {
		whereClauses = append(whereClauses, "control_id = ?")
		args = append(args, strings.TrimSpace(filter.ControlID))
	}
	if filter.State != "" {
		whereClauses = append(whereClauses, "state = ?")
		args = append(args, string(filter.State))
	}

	querySQL := `
	SELECT id, assessment_id, execution_id, catalog_id, catalog_version,
	       control_id, control_title, state, rationale, engine_version,
	       mapping_ruleset_version, mapping_ruleset_digest, limitations,
	       finding_ids_json, evidence_references_json, supporting_evidence_json,
	       contradicting_evidence_json, evaluated_at
	FROM compliance_control_evaluations
	`

	if len(whereClauses) > 0 {
		querySQL += " WHERE " + strings.Join(whereClauses, " AND ")
	}

	querySQL += " ORDER BY assessment_id ASC, control_id ASC"

	if filter.Limit > 0 {
		querySQL += fmt.Sprintf(" LIMIT %d", filter.Limit)
		if filter.Offset > 0 {
			querySQL += fmt.Sprintf(" OFFSET %d", filter.Offset)
		}
	}

	rows, err := s.db.Query(querySQL, args...)
	if err != nil {
		return nil, fmt.Errorf("failed querying control evaluations: %w", err)
	}
	defer rows.Close()

	records := make([]ControlEvaluationRecord, 0)
	for rows.Next() {
		var (
			recID, recAssID, cID, cTitle, stateStr, rationale, recEngineVer string
			catID, catVer                                                   string
			recExecID, rsVer, rsDigest, lim                                 sql.NullString
			fIDsJSON, refsJSON, suppJSON, contraJSON                        string
			recEvalAt                                                       time.Time
		)

		err := rows.Scan(
			&recID, &recAssID, &recExecID, &catID, &catVer,
			&cID, &cTitle, &stateStr, &rationale, &recEngineVer,
			&rsVer, &rsDigest, &lim,
			&fIDsJSON, &refsJSON, &suppJSON, &contraJSON,
			&recEvalAt,
		)
		if err != nil {
			return nil, fmt.Errorf("failed scanning control evaluation: %w", err)
		}

		var fIDs, refs, supp, contra []string
		_ = json.Unmarshal([]byte(fIDsJSON), &fIDs)
		_ = json.Unmarshal([]byte(refsJSON), &refs)
		_ = json.Unmarshal([]byte(suppJSON), &supp)
		_ = json.Unmarshal([]byte(contraJSON), &contra)

		evalState, _ := CanonicalEvaluationState(stateStr)

		records = append(records, ControlEvaluationRecord{
			EvaluationID:          recID,
			CatalogID:             catID,
			CatalogVersion:        catVer,
			ControlID:             cID,
			ControlTitle:          cTitle,
			AssessmentID:          recAssID,
			ExecutionID:           recExecID.String,
			State:                 evalState,
			Rationale:             rationale,
			FindingIDs:            fIDs,
			EvidenceReferences:    refs,
			SupportingEvidence:    supp,
			ContradictingEvidence: contra,
			EvaluatedAt:           recEvalAt,
			EngineVersion:         recEngineVer,
			MappingRuleSetVersion: rsVer.String,
			MappingRuleSetDigest:  rsDigest.String,
			Limitations:           lim.String,
		})
	}

	return records, rows.Err()
}

// ListEvaluationResults queries evaluation results matching filter criteria.
func (s *SQLiteComplianceStore) ListEvaluationResults(filter EvaluationResultFilter) ([]EvaluationResultSummary, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var whereClauses []string
	var args []any

	if filter.AssessmentID != "" {
		whereClauses = append(whereClauses, "assessment_id = ?")
		args = append(args, strings.TrimSpace(filter.AssessmentID))
	}
	if filter.CatalogID != "" {
		whereClauses = append(whereClauses, "catalog_id = ?")
		args = append(args, strings.TrimSpace(filter.CatalogID))
	}

	querySQL := `
	SELECT id, assessment_id, execution_id, catalog_identity, catalog_id, catalog_version,
	       catalog_digest, mapping_ruleset_identity, mapping_ruleset_digest, engine_version,
	       result_digest, limitations_notice, total_controls, compliant_count, non_compliant_count,
	       partially_compliant_count, not_assessed_count, insufficient_evidence_count,
	       not_applicable_count, error_count, applicable_controls, assessed_controls,
	       evaluated_at
	FROM compliance_evaluation_results
	`

	if len(whereClauses) > 0 {
		querySQL += " WHERE " + strings.Join(whereClauses, " AND ")
	}

	querySQL += " ORDER BY evaluated_at DESC, id ASC"

	if filter.Limit > 0 {
		querySQL += fmt.Sprintf(" LIMIT %d", filter.Limit)
		if filter.Offset > 0 {
			querySQL += fmt.Sprintf(" OFFSET %d", filter.Offset)
		}
	}

	rows, err := s.db.Query(querySQL, args...)
	if err != nil {
		return nil, fmt.Errorf("failed querying evaluation results: %w", err)
	}
	defer rows.Close()

	summaries := make([]EvaluationResultSummary, 0)
	for rows.Next() {
		var (
			resID, assID, catIdentity, catID, catVer, catDigest, engineVer, resDigest, limitationsNotice string
			execID, ruleSetID, ruleSetDigest                                                             sql.NullString
			total, comp, nonComp, partComp, notAss, insuff, notApp, errCount                             int
			applicable, assessed                                                                         int
			evaluatedAt                                                                                  time.Time
		)

		err := rows.Scan(
			&resID, &assID, &execID, &catIdentity, &catID, &catVer,
			&catDigest, &ruleSetID, &ruleSetDigest, &engineVer,
			&resDigest, &limitationsNotice, &total, &comp, &nonComp,
			&partComp, &notAss, &insuff, &notApp, &errCount, &applicable, &assessed,
			&evaluatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("failed scanning evaluation result summary: %w", err)
		}

		summaries = append(summaries, EvaluationResultSummary{
			ResultID:               resID,
			AssessmentID:           assID,
			ExecutionID:            execID.String,
			CatalogIdentity:        catIdentity,
			CatalogID:              catID,
			CatalogVersion:         catVer,
			CatalogDigest:          catDigest,
			MappingRuleSetIdentity: ruleSetID.String,
			MappingRuleSetDigest:   ruleSetDigest.String,
			ResultDigest:           resDigest,
			EngineVersion:          engineVer,
			EvaluatedAt:            evaluatedAt,
			Summary: EvaluationSummary{
				TotalControls:             total,
				CompliantCount:            comp,
				NonCompliantCount:         nonComp,
				PartiallyCompliantCount:   partComp,
				NotAssessedCount:          notAss,
				InsufficientEvidenceCount: insuff,
				NotApplicableCount:        notApp,
				ErrorCount:                errCount,
				ApplicableControls:        applicable,
				AssessedControls:          assessed,
			},
			LimitationsNotice: limitationsNotice,
		})
	}

	return summaries, rows.Err()
}

// GetEvaluationEvidence retrieves the evidence records or references associated with an evaluation.
func (s *SQLiteComplianceStore) GetEvaluationEvidence(evaluationID string) ([]EvaluationEvidenceRecord, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	cleanID := strings.TrimSpace(evaluationID)
	likePattern := "%" + cleanID

	querySQL := `
	SELECT id, evaluation_id, assessment_id, control_id, evidence_type, reference_id, detail, created_at
	FROM compliance_evidence_links
	WHERE evaluation_id = ? OR evaluation_id LIKE ? OR id = ?
	ORDER BY evidence_type ASC, id ASC;
	`

	rows, err := s.db.Query(querySQL, cleanID, likePattern, cleanID)
	if err != nil {
		return nil, fmt.Errorf("failed querying evidence links: %w", err)
	}
	defer rows.Close()

	records := make([]EvaluationEvidenceRecord, 0)
	for rows.Next() {
		var (
			id, evalID, assID, ctrlID, evType, refID string
			detail                                   sql.NullString
			createdAt                                time.Time
		)

		if err := rows.Scan(&id, &evalID, &assID, &ctrlID, &evType, &refID, &detail, &createdAt); err != nil {
			return nil, fmt.Errorf("failed scanning evidence link: %w", err)
		}

		records = append(records, EvaluationEvidenceRecord{
			ID:           id,
			EvaluationID: evalID,
			AssessmentID: assID,
			ControlID:    ctrlID,
			EvidenceType: evType,
			ReferenceID:  refID,
			Detail:       detail.String,
			CreatedAt:    createdAt,
		})
	}

	return records, rows.Err()
}

// EvaluationExists checks if an evaluation result already exists for the assessment and catalog.
func (s *SQLiteComplianceStore) EvaluationExists(assessmentID, catalogID string) (bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	cleanAss := strings.TrimSpace(assessmentID)
	cleanCat := strings.TrimSpace(catalogID)

	likePattern := ""
	if cleanCat != "" {
		likePattern = "evalres:" + cleanAss + ":" + cleanCat + "%"
	}

	query := `
		SELECT COUNT(1) FROM compliance_evaluation_results
		WHERE id = ? OR (assessment_id = ? AND (? = '' OR catalog_id = ? OR catalog_identity = ? OR id LIKE ?))
	`
	var count int
	err := s.db.QueryRow(query, cleanAss, cleanAss, cleanCat, cleanCat, cleanCat, likePattern).Scan(&count)
	if err != nil {
		return false, fmt.Errorf("failed checking evaluation existence: %w", err)
	}
	return count > 0, nil
}

// Close closes the database connection.
func (s *SQLiteComplianceStore) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.db != nil {
		return s.db.Close()
	}
	return nil
}
