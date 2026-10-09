package assessment

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"felix/pkg/config"
	"felix/pkg/discovery"
	"felix/pkg/report"
	_ "modernc.org/sqlite"
)

// Store defines the persistent storage interface for Felix assessments.
type Store interface {
	// Client Management
	CreateClient(c *Client) error
	GetClient(id string) (*Client, error)
	ListClients(includeArchived bool) ([]Client, error)
	UpdateClient(c *Client) error
	ArchiveClient(id string) error

	// Assessment Management
	CreateAssessment(a *Assessment) error
	GetAssessment(id string) (*Assessment, error)
	GetAssessmentByRef(ref string) (*Assessment, error)
	ListAssessments(clientID string) ([]Assessment, error)
	UpdateAssessment(a *Assessment) error
	UpdateAssessmentStatus(id string, status AssessmentStatus) error

	// Targets
	AddTarget(t *AssessmentTarget) error
	GetTargets(assessmentID string) ([]AssessmentTarget, error)
	RemoveTarget(id string) error

	// Authorization Records
	SetAuthorization(auth *AuthorizationRecord) error
	GetAuthorization(assessmentID string) (*AuthorizationRecord, error)
	UpdateAuthorizationStatus(id string, status AuthorizationStatus) error

	// Scope and Exclusions
	AddScopeRule(r *ScopeRule) error
	GetScopeRules(assessmentID string) ([]ScopeRule, error)
	AddExclusion(e *Exclusion) error
	GetExclusions(assessmentID string) ([]Exclusion, error)

	// Executions (Runs)
	CreateExecution(exec *AssessmentExecution) error
	GetExecution(id string) (*AssessmentExecution, error)
	ListExecutions(assessmentID string) ([]AssessmentExecution, error)
	UpdateExecution(exec *AssessmentExecution) error

	// Findings and Traceability
	SaveFindings(findings []AssessmentFinding) error
	GetFindings(assessmentID string, executionID string) ([]AssessmentFinding, error)

	// Attack-Surface Inventory
	SaveInventory(assets []discovery.Asset, relations []discovery.Relation) error
	GetInventory(assessmentID string, executionID string, assetType string, inScopeOnly bool) ([]discovery.Asset, []discovery.Relation, error)
	GetInventorySummary(assessmentID string, executionID string) (*discovery.InventorySummary, error)

	// Report Records
	SaveReport(r *ReportRecord) error
	GetReports(assessmentID string) ([]ReportRecord, error)

	// Interrupted run recovery
	DetectAndRecoverInterruptedRuns() (int, error)

	// Close database
	Close() error
}

// SQLiteStore is the concrete SQLite implementation of Store.
type SQLiteStore struct {
	db *sql.DB
	mu sync.RWMutex
}

// DefaultDBPath returns the path to ~/.felix/assessments.db.
func DefaultDBPath() (string, error) {
	dir, err := config.Dir()
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return "", fmt.Errorf("failed to create felix directory: %w", err)
	}
	return filepath.Join(dir, "assessments.db"), nil
}

// NewSQLiteStore opens or creates an SQLite database at the specified path.
// If dbPath is empty, DefaultDBPath() is used.
func NewSQLiteStore(dbPath string) (*SQLiteStore, error) {
	if dbPath == "" {
		p, err := DefaultDBPath()
		if err != nil {
			return nil, err
		}
		dbPath = p
	}

	// Open SQLite with modernc.org/sqlite
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open database at %s: %w", dbPath, err)
	}

	// Configure connection pragmas for performance and data safety
	pragmas := []string{
		"PRAGMA foreign_keys = ON;",
		"PRAGMA journal_mode = WAL;",
		"PRAGMA busy_timeout = 5000;",
		"PRAGMA synchronous = NORMAL;",
	}
	for _, pragma := range pragmas {
		if _, err := db.Exec(pragma); err != nil {
			db.Close()
			return nil, fmt.Errorf("failed to execute %s: %w", pragma, err)
		}
	}

	store := &SQLiteStore{db: db}
	if err := store.migrate(); err != nil {
		db.Close()
		return nil, fmt.Errorf("database migration failed: %w", err)
	}

	return store, nil
}

func (s *SQLiteStore) migrate() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// 1. Ensure migrations table exists
	_, err := s.db.Exec(`
		CREATE TABLE IF NOT EXISTS schema_migrations (
			version INTEGER PRIMARY KEY,
			applied_at TIMESTAMP NOT NULL
		);
	`)
	if err != nil {
		return fmt.Errorf("failed to create schema_migrations table: %w", err)
	}

	var currentVersion int
	row := s.db.QueryRow("SELECT COALESCE(MAX(version), 0) FROM schema_migrations")
	if err := row.Scan(&currentVersion); err != nil {
		return fmt.Errorf("failed to read schema version: %w", err)
	}

	// Migration 1: Initial assessment core schema
	if currentVersion < 1 {
		tx, err := s.db.Begin()
		if err != nil {
			return err
		}
		defer tx.Rollback()

		schemaV1 := `
		CREATE TABLE clients (
			id TEXT PRIMARY KEY,
			name TEXT NOT NULL,
			organization TEXT,
			contact_name TEXT,
			contact_email TEXT,
			notes TEXT,
			created_at TIMESTAMP NOT NULL,
			updated_at TIMESTAMP NOT NULL,
			archived INTEGER NOT NULL DEFAULT 0
		);

		CREATE TABLE assessments (
			id TEXT PRIMARY KEY,
			ref TEXT UNIQUE NOT NULL,
			client_id TEXT NOT NULL REFERENCES clients(id) ON DELETE RESTRICT,
			name TEXT NOT NULL,
			description TEXT,
			assessment_type TEXT NOT NULL,
			status TEXT NOT NULL,
			created_at TIMESTAMP NOT NULL,
			updated_at TIMESTAMP NOT NULL,
			started_at TIMESTAMP,
			completed_at TIMESTAMP,
			scope_mode TEXT NOT NULL DEFAULT 'same-origin',
			config_snapshot_json TEXT,
			finding_count INTEGER NOT NULL DEFAULT 0
		);

		CREATE INDEX idx_assessments_client_id ON assessments(client_id);
		CREATE INDEX idx_assessments_status ON assessments(status);

		CREATE TABLE assessment_targets (
			id TEXT PRIMARY KEY,
			assessment_id TEXT NOT NULL REFERENCES assessments(id) ON DELETE CASCADE,
			target_url TEXT NOT NULL,
			target_type TEXT NOT NULL,
			scope_status TEXT NOT NULL DEFAULT 'APPROVED',
			label TEXT,
			created_at TIMESTAMP NOT NULL
		);

		CREATE INDEX idx_targets_assessment_id ON assessment_targets(assessment_id);

		CREATE TABLE authorizations (
			id TEXT PRIMARY KEY,
			assessment_id TEXT NOT NULL REFERENCES assessments(id) ON DELETE CASCADE,
			authorizing_party TEXT NOT NULL,
			authorization_method TEXT NOT NULL,
			date_received TIMESTAMP NOT NULL,
			valid_from TIMESTAMP,
			valid_until TIMESTAMP,
			scope_doc_ref TEXT,
			internal_notes TEXT,
			status TEXT NOT NULL DEFAULT 'PENDING',
			created_at TIMESTAMP NOT NULL,
			updated_at TIMESTAMP NOT NULL
		);

		CREATE INDEX idx_authorizations_assessment_id ON authorizations(assessment_id);

		CREATE TABLE scope_rules (
			id TEXT PRIMARY KEY,
			assessment_id TEXT NOT NULL REFERENCES assessments(id) ON DELETE CASCADE,
			rule_type TEXT NOT NULL,
			pattern TEXT NOT NULL,
			created_at TIMESTAMP NOT NULL
		);

		CREATE TABLE exclusions (
			id TEXT PRIMARY KEY,
			assessment_id TEXT NOT NULL REFERENCES assessments(id) ON DELETE CASCADE,
			exclusion_type TEXT NOT NULL,
			pattern TEXT NOT NULL,
			reason TEXT,
			created_at TIMESTAMP NOT NULL
		);

		CREATE TABLE assessment_executions (
			id TEXT PRIMARY KEY,
			assessment_id TEXT NOT NULL REFERENCES assessments(id) ON DELETE CASCADE,
			status TEXT NOT NULL,
			started_at TIMESTAMP NOT NULL,
			completed_at TIMESTAMP,
			duration_ms INTEGER,
			request_count INTEGER,
			error_message TEXT,
			config_snapshot TEXT NOT NULL
		);

		CREATE INDEX idx_executions_assessment_id ON assessment_executions(assessment_id);

		CREATE TABLE assessment_findings (
			id TEXT PRIMARY KEY,
			assessment_id TEXT NOT NULL REFERENCES assessments(id) ON DELETE CASCADE,
			execution_id TEXT NOT NULL REFERENCES assessment_executions(id) ON DELETE CASCADE,
			target_id TEXT NOT NULL REFERENCES assessment_targets(id) ON DELETE CASCADE,
			original_finding_id TEXT NOT NULL,
			title TEXT NOT NULL,
			category TEXT NOT NULL,
			severity TEXT NOT NULL,
			confidence TEXT NOT NULL,
			verification_status TEXT NOT NULL,
			target_url TEXT NOT NULL,
			endpoint TEXT NOT NULL,
			method TEXT NOT NULL,
			fingerprint TEXT NOT NULL,
			score INTEGER NOT NULL DEFAULT 0,
			evidence_json TEXT NOT NULL,
			verification_json TEXT NOT NULL,
			remediation TEXT,
			created_at TIMESTAMP NOT NULL
		);

		CREATE INDEX idx_findings_assessment_id ON assessment_findings(assessment_id);
		CREATE INDEX idx_findings_execution_id ON assessment_findings(execution_id);
		CREATE INDEX idx_findings_severity ON assessment_findings(severity);

		CREATE TABLE assessment_reports (
			id TEXT PRIMARY KEY,
			assessment_id TEXT NOT NULL REFERENCES assessments(id) ON DELETE CASCADE,
			execution_id TEXT NOT NULL REFERENCES assessment_executions(id) ON DELETE CASCADE,
			format TEXT NOT NULL,
			file_path TEXT NOT NULL,
			felix_version TEXT NOT NULL,
			status TEXT NOT NULL,
			created_at TIMESTAMP NOT NULL
		);

		CREATE INDEX idx_reports_assessment_id ON assessment_reports(assessment_id);

		INSERT INTO schema_migrations (version, applied_at) VALUES (1, CURRENT_TIMESTAMP);
		`

		if _, err := tx.Exec(schemaV1); err != nil {
			return fmt.Errorf("migration v1 failed: %w", err)
		}

		if err := tx.Commit(); err != nil {
			return err
		}
	}

	// Migration 2: Unified attack-surface inventory (assets & relations)
	if currentVersion < 2 {
		tx, err := s.db.Begin()
		if err != nil {
			return err
		}
		defer tx.Rollback()

		schemaV2 := `
		CREATE TABLE IF NOT EXISTS assessment_inventory_assets (
			id TEXT PRIMARY KEY,
			assessment_id TEXT NOT NULL REFERENCES assessments(id) ON DELETE CASCADE,
			execution_id TEXT NOT NULL REFERENCES assessment_executions(id) ON DELETE CASCADE,
			target_id TEXT,
			asset_type TEXT NOT NULL,
			canonical_id TEXT NOT NULL,
			parent_id TEXT,
			display_name TEXT NOT NULL,
			source_asset TEXT,
			discovery_method TEXT NOT NULL,
			discovery_status TEXT NOT NULL,
			confidence TEXT NOT NULL,
			in_scope INTEGER NOT NULL DEFAULT 1,
			metadata_json TEXT,
			evidence_json TEXT,
			fingerprint TEXT NOT NULL,
			first_seen TIMESTAMP NOT NULL,
			last_seen TIMESTAMP NOT NULL
		);

		CREATE INDEX IF NOT EXISTS idx_inv_assets_asm_id ON assessment_inventory_assets(assessment_id);
		CREATE INDEX IF NOT EXISTS idx_inv_assets_exec_id ON assessment_inventory_assets(execution_id);
		CREATE INDEX IF NOT EXISTS idx_inv_assets_type ON assessment_inventory_assets(asset_type);
		CREATE INDEX IF NOT EXISTS idx_inv_assets_fingerprint ON assessment_inventory_assets(fingerprint);

		CREATE TABLE IF NOT EXISTS assessment_inventory_relations (
			id TEXT PRIMARY KEY,
			assessment_id TEXT NOT NULL REFERENCES assessments(id) ON DELETE CASCADE,
			execution_id TEXT NOT NULL REFERENCES assessment_executions(id) ON DELETE CASCADE,
			source_asset_id TEXT NOT NULL,
			target_asset_id TEXT NOT NULL,
			relation_type TEXT NOT NULL,
			evidence TEXT,
			confidence TEXT NOT NULL,
			created_at TIMESTAMP NOT NULL
		);

		CREATE INDEX IF NOT EXISTS idx_inv_relations_asm_id ON assessment_inventory_relations(assessment_id);
		CREATE INDEX IF NOT EXISTS idx_inv_relations_exec_id ON assessment_inventory_relations(execution_id);
		CREATE INDEX IF NOT EXISTS idx_inv_relations_source ON assessment_inventory_relations(source_asset_id);
		CREATE INDEX IF NOT EXISTS idx_inv_relations_target ON assessment_inventory_relations(target_asset_id);

		INSERT INTO schema_migrations (version, applied_at) VALUES (2, CURRENT_TIMESTAMP);
		`

		if _, err := tx.Exec(schemaV2); err != nil {
			return fmt.Errorf("migration v2 failed: %w", err)
		}

		if err := tx.Commit(); err != nil {
			return err
		}
	}

	return nil
}

// Close closes the underlying SQLite database connection.
func (s *SQLiteStore) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.db.Close()
}

// --- Client Methods ---

func (s *SQLiteStore) CreateClient(c *Client) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now().UTC()
	if c.CreatedAt.IsZero() {
		c.CreatedAt = now
	}
	c.UpdatedAt = now

	_, err := s.db.Exec(`
		INSERT INTO clients (id, name, organization, contact_name, contact_email, notes, created_at, updated_at, archived)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, c.ID, c.Name, c.Organization, c.ContactName, c.ContactEmail, c.Notes, c.CreatedAt, c.UpdatedAt, boolToInt(c.Archived))
	return err
}

func (s *SQLiteStore) GetClient(idOrName string) (*Client, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	row := s.db.QueryRow(`
		SELECT id, name, organization, contact_name, contact_email, notes, created_at, updated_at, archived
		FROM clients WHERE id = ? OR name = ?
	`, idOrName, idOrName)

	var c Client
	var archivedInt int
	err := row.Scan(&c.ID, &c.Name, &c.Organization, &c.ContactName, &c.ContactEmail, &c.Notes, &c.CreatedAt, &c.UpdatedAt, &archivedInt)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("client %s not found", idOrName)
	}
	if err != nil {
		return nil, err
	}
	c.Archived = archivedInt == 1
	return &c, nil
}

func (s *SQLiteStore) ListClients(includeArchived bool) ([]Client, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	query := `SELECT id, name, organization, contact_name, contact_email, notes, created_at, updated_at, archived FROM clients`
	if !includeArchived {
		query += ` WHERE archived = 0`
	}
	query += ` ORDER BY created_at DESC`

	rows, err := s.db.Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var clients []Client
	for rows.Next() {
		var c Client
		var archivedInt int
		if err := rows.Scan(&c.ID, &c.Name, &c.Organization, &c.ContactName, &c.ContactEmail, &c.Notes, &c.CreatedAt, &c.UpdatedAt, &archivedInt); err != nil {
			return nil, err
		}
		c.Archived = archivedInt == 1
		clients = append(clients, c)
	}
	return clients, rows.Err()
}

func (s *SQLiteStore) UpdateClient(c *Client) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	c.UpdatedAt = time.Now().UTC()
	res, err := s.db.Exec(`
		UPDATE clients
		SET name = ?, organization = ?, contact_name = ?, contact_email = ?, notes = ?, updated_at = ?, archived = ?
		WHERE id = ?
	`, c.Name, c.Organization, c.ContactName, c.ContactEmail, c.Notes, c.UpdatedAt, boolToInt(c.Archived), c.ID)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return fmt.Errorf("client %s not found", c.ID)
	}
	return nil
}

func (s *SQLiteStore) ArchiveClient(idOrName string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	res, err := s.db.Exec(`
		UPDATE clients SET archived = 1, updated_at = ? WHERE id = ? OR name = ?
	`, time.Now().UTC(), idOrName, idOrName)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return fmt.Errorf("client %s not found", idOrName)
	}
	return nil
}

// --- Assessment Methods ---

func (s *SQLiteStore) CreateAssessment(a *Assessment) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now().UTC()
	if a.CreatedAt.IsZero() {
		a.CreatedAt = now
	}
	a.UpdatedAt = now
	if a.Status == "" {
		a.Status = StatusDraft
	}
	if a.ScopeMode == "" {
		a.ScopeMode = "same-origin"
	}

	_, err := s.db.Exec(`
		INSERT INTO assessments (id, ref, client_id, name, description, assessment_type, status, created_at, updated_at, started_at, completed_at, scope_mode, config_snapshot_json, finding_count)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, a.ID, a.Ref, a.ClientID, a.Name, a.Description, a.AssessmentType, a.Status, a.CreatedAt, a.UpdatedAt, a.StartedAt, a.CompletedAt, a.ScopeMode, a.ConfigSnapshotJSON, a.FindingCount)
	return err
}

func (s *SQLiteStore) GetAssessment(idOrRef string) (*Assessment, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	row := s.db.QueryRow(`
		SELECT id, ref, client_id, name, description, assessment_type, status, created_at, updated_at, started_at, completed_at, scope_mode, config_snapshot_json, finding_count
		FROM assessments WHERE id = ? OR ref = ?
	`, idOrRef, idOrRef)

	var a Assessment
	err := row.Scan(&a.ID, &a.Ref, &a.ClientID, &a.Name, &a.Description, &a.AssessmentType, &a.Status, &a.CreatedAt, &a.UpdatedAt, &a.StartedAt, &a.CompletedAt, &a.ScopeMode, &a.ConfigSnapshotJSON, &a.FindingCount)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("assessment %s not found", idOrRef)
	}
	if err != nil {
		return nil, err
	}

	return &a, nil
}

func (s *SQLiteStore) GetAssessmentByRef(ref string) (*Assessment, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	row := s.db.QueryRow(`
		SELECT id, ref, client_id, name, description, assessment_type, status, created_at, updated_at, started_at, completed_at, scope_mode, config_snapshot_json, finding_count
		FROM assessments WHERE ref = ?
	`, ref)

	var a Assessment
	err := row.Scan(&a.ID, &a.Ref, &a.ClientID, &a.Name, &a.Description, &a.AssessmentType, &a.Status, &a.CreatedAt, &a.UpdatedAt, &a.StartedAt, &a.CompletedAt, &a.ScopeMode, &a.ConfigSnapshotJSON, &a.FindingCount)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("assessment reference %s not found", ref)
	}
	if err != nil {
		return nil, err
	}

	return &a, nil
}

func (s *SQLiteStore) resolveAssessmentID(idOrRef string) string {
	if idOrRef == "" {
		return ""
	}
	var id string
	_ = s.db.QueryRow(`SELECT id FROM assessments WHERE id = ? OR ref = ? LIMIT 1`, idOrRef, idOrRef).Scan(&id)
	if id != "" {
		return id
	}
	return idOrRef
}

func (s *SQLiteStore) resolveClientID(idOrName string) string {
	if idOrName == "" {
		return ""
	}
	var id string
	_ = s.db.QueryRow(`SELECT id FROM clients WHERE id = ? OR name = ? LIMIT 1`, idOrName, idOrName).Scan(&id)
	if id != "" {
		return id
	}
	return idOrName
}

func (s *SQLiteStore) ListAssessments(clientID string) ([]Assessment, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	clientID = s.resolveClientID(clientID)

	query := `SELECT id, ref, client_id, name, description, assessment_type, status, created_at, updated_at, started_at, completed_at, scope_mode, config_snapshot_json, finding_count FROM assessments`
	var args []any
	if clientID != "" {
		query += ` WHERE client_id = ?`
		args = append(args, clientID)
	}
	query += ` ORDER BY created_at DESC`

	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var assessments []Assessment
	for rows.Next() {
		var a Assessment
		if err := rows.Scan(&a.ID, &a.Ref, &a.ClientID, &a.Name, &a.Description, &a.AssessmentType, &a.Status, &a.CreatedAt, &a.UpdatedAt, &a.StartedAt, &a.CompletedAt, &a.ScopeMode, &a.ConfigSnapshotJSON, &a.FindingCount); err != nil {
			return nil, err
		}
		assessments = append(assessments, a)
	}
	return assessments, rows.Err()
}

func (s *SQLiteStore) UpdateAssessment(a *Assessment) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	a.UpdatedAt = time.Now().UTC()
	res, err := s.db.Exec(`
		UPDATE assessments
		SET name = ?, description = ?, assessment_type = ?, status = ?, updated_at = ?, started_at = ?, completed_at = ?, scope_mode = ?, config_snapshot_json = ?, finding_count = ?
		WHERE id = ?
	`, a.Name, a.Description, a.AssessmentType, a.Status, a.UpdatedAt, a.StartedAt, a.CompletedAt, a.ScopeMode, a.ConfigSnapshotJSON, a.FindingCount, a.ID)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return fmt.Errorf("assessment %s not found", a.ID)
	}
	return nil
}

func (s *SQLiteStore) UpdateAssessmentStatus(id string, status AssessmentStatus) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	id = s.resolveAssessmentID(id)
	now := time.Now().UTC()
	var err error
	if status == StatusRunning {
		_, err = s.db.Exec(`UPDATE assessments SET status = ?, started_at = ?, updated_at = ? WHERE id = ?`, status, now, now, id)
	} else if status == StatusCompleted || status == StatusCompletedWithErrors || status == StatusFailed || status == StatusCancelled {
		_, err = s.db.Exec(`UPDATE assessments SET status = ?, completed_at = ?, updated_at = ? WHERE id = ?`, status, now, now, id)
	} else {
		_, err = s.db.Exec(`UPDATE assessments SET status = ?, updated_at = ? WHERE id = ?`, status, now, id)
	}
	return err
}

// --- Targets ---

func (s *SQLiteStore) AddTarget(t *AssessmentTarget) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	t.AssessmentID = s.resolveAssessmentID(t.AssessmentID)
	if t.CreatedAt.IsZero() {
		t.CreatedAt = time.Now().UTC()
	}
	if t.ScopeStatus == "" {
		t.ScopeStatus = "APPROVED"
	}
	if t.TargetType == "" {
		t.TargetType = TargetWebsite
	}

	_, err := s.db.Exec(`
		INSERT INTO assessment_targets (id, assessment_id, target_url, target_type, scope_status, label, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)
	`, t.ID, t.AssessmentID, t.TargetURL, t.TargetType, t.ScopeStatus, t.Label, t.CreatedAt)
	return err
}

func (s *SQLiteStore) GetTargets(assessmentID string) ([]AssessmentTarget, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	assessmentID = s.resolveAssessmentID(assessmentID)
	rows, err := s.db.Query(`
		SELECT id, assessment_id, target_url, target_type, scope_status, label, created_at
		FROM assessment_targets WHERE assessment_id = ? ORDER BY created_at ASC
	`, assessmentID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var targets []AssessmentTarget
	for rows.Next() {
		var t AssessmentTarget
		if err := rows.Scan(&t.ID, &t.AssessmentID, &t.TargetURL, &t.TargetType, &t.ScopeStatus, &t.Label, &t.CreatedAt); err != nil {
			return nil, err
		}
		targets = append(targets, t)
	}
	return targets, rows.Err()
}

func (s *SQLiteStore) RemoveTarget(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	res, err := s.db.Exec(`DELETE FROM assessment_targets WHERE id = ?`, id)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return fmt.Errorf("target %s not found", id)
	}
	return nil
}

// --- Authorization ---

func (s *SQLiteStore) SetAuthorization(auth *AuthorizationRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	auth.AssessmentID = s.resolveAssessmentID(auth.AssessmentID)
	now := time.Now().UTC()
	if auth.CreatedAt.IsZero() {
		auth.CreatedAt = now
	}
	auth.UpdatedAt = now

	// Check if record exists
	var existingID string
	err := s.db.QueryRow(`SELECT id FROM authorizations WHERE assessment_id = ?`, auth.AssessmentID).Scan(&existingID)
	if err == sql.ErrNoRows {
		_, err = s.db.Exec(`
			INSERT INTO authorizations (id, assessment_id, authorizing_party, authorization_method, date_received, valid_from, valid_until, scope_doc_ref, internal_notes, status, created_at, updated_at)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		`, auth.ID, auth.AssessmentID, auth.AuthorizingParty, auth.AuthorizationMethod, auth.DateReceived, auth.ValidFrom, auth.ValidUntil, auth.ScopeDocRef, auth.InternalNotes, auth.Status, auth.CreatedAt, auth.UpdatedAt)
		return err
	} else if err != nil {
		return err
	}

	_, err = s.db.Exec(`
		UPDATE authorizations
		SET authorizing_party = ?, authorization_method = ?, date_received = ?, valid_from = ?, valid_until = ?, scope_doc_ref = ?, internal_notes = ?, status = ?, updated_at = ?
		WHERE id = ?
	`, auth.AuthorizingParty, auth.AuthorizationMethod, auth.DateReceived, auth.ValidFrom, auth.ValidUntil, auth.ScopeDocRef, auth.InternalNotes, auth.Status, auth.UpdatedAt, existingID)
	return err
}

func (s *SQLiteStore) GetAuthorization(assessmentID string) (*AuthorizationRecord, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	assessmentID = s.resolveAssessmentID(assessmentID)
	row := s.db.QueryRow(`
		SELECT id, assessment_id, authorizing_party, authorization_method, date_received, valid_from, valid_until, scope_doc_ref, internal_notes, status, created_at, updated_at
		FROM authorizations WHERE assessment_id = ?
	`, assessmentID)

	var auth AuthorizationRecord
	err := row.Scan(&auth.ID, &auth.AssessmentID, &auth.AuthorizingParty, &auth.AuthorizationMethod, &auth.DateReceived, &auth.ValidFrom, &auth.ValidUntil, &auth.ScopeDocRef, &auth.InternalNotes, &auth.Status, &auth.CreatedAt, &auth.UpdatedAt)
	if err == sql.ErrNoRows {
		return nil, nil // No authorization recorded yet
	}
	if err != nil {
		return nil, err
	}
	return &auth, nil
}

func (s *SQLiteStore) UpdateAuthorizationStatus(id string, status AuthorizationStatus) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	res, err := s.db.Exec(`UPDATE authorizations SET status = ?, updated_at = ? WHERE id = ?`, status, time.Now().UTC(), id)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return fmt.Errorf("authorization %s not found", id)
	}
	return nil
}

// --- Scope Rules & Exclusions ---

func (s *SQLiteStore) AddScopeRule(r *ScopeRule) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	r.AssessmentID = s.resolveAssessmentID(r.AssessmentID)
	if r.CreatedAt.IsZero() {
		r.CreatedAt = time.Now().UTC()
	}
	_, err := s.db.Exec(`
		INSERT INTO scope_rules (id, assessment_id, rule_type, pattern, created_at)
		VALUES (?, ?, ?, ?, ?)
	`, r.ID, r.AssessmentID, r.RuleType, r.Pattern, r.CreatedAt)
	return err
}

func (s *SQLiteStore) GetScopeRules(assessmentID string) ([]ScopeRule, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	assessmentID = s.resolveAssessmentID(assessmentID)
	rows, err := s.db.Query(`
		SELECT id, assessment_id, rule_type, pattern, created_at
		FROM scope_rules WHERE assessment_id = ? ORDER BY created_at ASC
	`, assessmentID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var rules []ScopeRule
	for rows.Next() {
		var r ScopeRule
		if err := rows.Scan(&r.ID, &r.AssessmentID, &r.RuleType, &r.Pattern, &r.CreatedAt); err != nil {
			return nil, err
		}
		rules = append(rules, r)
	}
	return rules, rows.Err()
}

func (s *SQLiteStore) AddExclusion(e *Exclusion) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	e.AssessmentID = s.resolveAssessmentID(e.AssessmentID)
	if e.CreatedAt.IsZero() {
		e.CreatedAt = time.Now().UTC()
	}
	_, err := s.db.Exec(`
		INSERT INTO exclusions (id, assessment_id, exclusion_type, pattern, reason, created_at)
		VALUES (?, ?, ?, ?, ?, ?)
	`, e.ID, e.AssessmentID, e.ExclusionType, e.Pattern, e.Reason, e.CreatedAt)
	return err
}

func (s *SQLiteStore) GetExclusions(assessmentID string) ([]Exclusion, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	assessmentID = s.resolveAssessmentID(assessmentID)
	rows, err := s.db.Query(`
		SELECT id, assessment_id, exclusion_type, pattern, reason, created_at
		FROM exclusions WHERE assessment_id = ? ORDER BY created_at ASC
	`, assessmentID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var exclusions []Exclusion
	for rows.Next() {
		var e Exclusion
		if err := rows.Scan(&e.ID, &e.AssessmentID, &e.ExclusionType, &e.Pattern, &e.Reason, &e.CreatedAt); err != nil {
			return nil, err
		}
		exclusions = append(exclusions, e)
	}
	return exclusions, rows.Err()
}

// --- Executions ---

func (s *SQLiteStore) CreateExecution(exec *AssessmentExecution) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	exec.AssessmentID = s.resolveAssessmentID(exec.AssessmentID)
	if exec.StartedAt.IsZero() {
		exec.StartedAt = time.Now().UTC()
	}
	cfgJSON, err := json.Marshal(exec.ConfigSnapshot)
	if err != nil {
		return fmt.Errorf("failed to serialize scan config snapshot: %w", err)
	}

	_, err = s.db.Exec(`
		INSERT INTO assessment_executions (id, assessment_id, status, started_at, completed_at, duration_ms, request_count, error_message, config_snapshot)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, exec.ID, exec.AssessmentID, exec.Status, exec.StartedAt, exec.CompletedAt, exec.DurationMs, exec.RequestCount, exec.ErrorMessage, string(cfgJSON))
	return err
}

func (s *SQLiteStore) GetExecution(id string) (*AssessmentExecution, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	row := s.db.QueryRow(`
		SELECT id, assessment_id, status, started_at, completed_at, duration_ms, request_count, error_message, config_snapshot
		FROM assessment_executions WHERE id = ?
	`, id)

	var exec AssessmentExecution
	var cfgJSON string
	err := row.Scan(&exec.ID, &exec.AssessmentID, &exec.Status, &exec.StartedAt, &exec.CompletedAt, &exec.DurationMs, &exec.RequestCount, &exec.ErrorMessage, &cfgJSON)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("execution %s not found", id)
	}
	if err != nil {
		return nil, err
	}

	_ = json.Unmarshal([]byte(cfgJSON), &exec.ConfigSnapshot)
	return &exec, nil
}

func (s *SQLiteStore) ListExecutions(assessmentID string) ([]AssessmentExecution, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	assessmentID = s.resolveAssessmentID(assessmentID)
	rows, err := s.db.Query(`
		SELECT id, assessment_id, status, started_at, completed_at, duration_ms, request_count, error_message, config_snapshot
		FROM assessment_executions WHERE assessment_id = ? ORDER BY started_at DESC
	`, assessmentID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var execs []AssessmentExecution
	for rows.Next() {
		var exec AssessmentExecution
		var cfgJSON string
		if err := rows.Scan(&exec.ID, &exec.AssessmentID, &exec.Status, &exec.StartedAt, &exec.CompletedAt, &exec.DurationMs, &exec.RequestCount, &exec.ErrorMessage, &cfgJSON); err != nil {
			return nil, err
		}
		_ = json.Unmarshal([]byte(cfgJSON), &exec.ConfigSnapshot)
		execs = append(execs, exec)
	}
	return execs, rows.Err()
}

func (s *SQLiteStore) UpdateExecution(exec *AssessmentExecution) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	cfgJSON, err := json.Marshal(exec.ConfigSnapshot)
	if err != nil {
		return fmt.Errorf("failed to serialize scan config snapshot: %w", err)
	}

	res, err := s.db.Exec(`
		UPDATE assessment_executions
		SET status = ?, completed_at = ?, duration_ms = ?, request_count = ?, error_message = ?, config_snapshot = ?
		WHERE id = ?
	`, exec.Status, exec.CompletedAt, exec.DurationMs, exec.RequestCount, exec.ErrorMessage, string(cfgJSON), exec.ID)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return fmt.Errorf("execution %s not found", exec.ID)
	}
	return nil
}

// --- Findings ---

func (s *SQLiteStore) SaveFindings(findings []AssessmentFinding) error {
	if len(findings) == 0 {
		return nil
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	stmt, err := tx.Prepare(`
		INSERT INTO assessment_findings (
			id, assessment_id, execution_id, target_id, original_finding_id,
			title, category, severity, confidence, verification_status,
			target_url, endpoint, method, fingerprint, score,
			evidence_json, verification_json, remediation, created_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`)
	if err != nil {
		return err
	}
	defer stmt.Close()

	for _, f := range findings {
		evJSON, err := json.Marshal(f.EvidenceDetails)
		if err != nil {
			evJSON = []byte("{}")
		}
		verJSON, err := json.Marshal(f.VerificationRecord)
		if err != nil {
			verJSON = []byte("{}")
		}
		if f.CreatedAt.IsZero() {
			f.CreatedAt = time.Now().UTC()
		}

		_, err = stmt.Exec(
			f.ID, f.AssessmentID, f.ExecutionID, f.TargetID, f.OriginalFindingID,
			f.Title, f.Category, f.Severity, f.Confidence, string(f.VerificationStatus),
			f.TargetURL, f.Endpoint, f.Method, f.Fingerprint, f.Score,
			string(evJSON), string(verJSON), f.Remediation, f.CreatedAt,
		)
		if err != nil {
			return fmt.Errorf("failed to insert finding %s: %w", f.ID, err)
		}
	}

	// Update finding count on assessment record
	_, err = tx.Exec(`
		UPDATE assessments
		SET finding_count = (SELECT COUNT(*) FROM assessment_findings WHERE assessment_id = ?),
		    updated_at = ?
		WHERE id = ?
	`, findings[0].AssessmentID, time.Now().UTC(), findings[0].AssessmentID)
	if err != nil {
		return err
	}

	return tx.Commit()
}

func (s *SQLiteStore) GetFindings(assessmentID string, executionID string) ([]AssessmentFinding, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	assessmentID = s.resolveAssessmentID(assessmentID)
	query := `
		SELECT id, assessment_id, execution_id, target_id, original_finding_id,
		       title, category, severity, confidence, verification_status,
		       target_url, endpoint, method, fingerprint, score,
		       evidence_json, verification_json, remediation, created_at
		FROM assessment_findings
		WHERE assessment_id = ?
	`
	var args []any
	args = append(args, assessmentID)

	if executionID != "" {
		query += ` AND execution_id = ?`
		args = append(args, executionID)
	}
	query += ` ORDER BY score DESC, created_at ASC`

	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var findings []AssessmentFinding
	for rows.Next() {
		var f AssessmentFinding
		var evJSON, verJSON string
		var verStatus string

		err := rows.Scan(
			&f.ID, &f.AssessmentID, &f.ExecutionID, &f.TargetID, &f.OriginalFindingID,
			&f.Title, &f.Category, &f.Severity, &f.Confidence, &verStatus,
			&f.TargetURL, &f.Endpoint, &f.Method, &f.Fingerprint, &f.Score,
			&evJSON, &verJSON, &f.Remediation, &f.CreatedAt,
		)
		if err != nil {
			return nil, err
		}

		f.VerificationStatus = report.VerificationStatus(verStatus)
		_ = json.Unmarshal([]byte(evJSON), &f.EvidenceDetails)
		_ = json.Unmarshal([]byte(verJSON), &f.VerificationRecord)
		findings = append(findings, f)
	}
	return findings, rows.Err()
}

// --- Reports ---

func (s *SQLiteStore) SaveReport(r *ReportRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	r.AssessmentID = s.resolveAssessmentID(r.AssessmentID)
	if r.CreatedAt.IsZero() {
		r.CreatedAt = time.Now().UTC()
	}
	_, err := s.db.Exec(`
		INSERT INTO assessment_reports (id, assessment_id, execution_id, format, file_path, felix_version, status, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)
	`, r.ID, r.AssessmentID, r.ExecutionID, r.Format, r.FilePath, r.FelixVersion, r.Status, r.CreatedAt)
	return err
}

func (s *SQLiteStore) GetReports(assessmentID string) ([]ReportRecord, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	assessmentID = s.resolveAssessmentID(assessmentID)
	rows, err := s.db.Query(`
		SELECT id, assessment_id, execution_id, format, file_path, felix_version, status, created_at
		FROM assessment_reports WHERE assessment_id = ? ORDER BY created_at DESC
	`, assessmentID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var reports []ReportRecord
	for rows.Next() {
		var r ReportRecord
		if err := rows.Scan(&r.ID, &r.AssessmentID, &r.ExecutionID, &r.Format, &r.FilePath, &r.FelixVersion, &r.Status, &r.CreatedAt); err != nil {
			return nil, err
		}
		reports = append(reports, r)
	}
	return reports, rows.Err()
}

// --- Interrupted Run Recovery ---

func (s *SQLiteStore) DetectAndRecoverInterruptedRuns() (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now().UTC()
	res, err := s.db.Exec(`
		UPDATE assessment_executions
		SET status = ?, completed_at = ?, error_message = ?
		WHERE status = ?
	`, StatusFailed, now, "Interrupted: process terminated unexpectedly during execution", StatusRunning)
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()

	// Update assessments that were left in RUNNING
	if n > 0 {
		_, _ = s.db.Exec(`
			UPDATE assessments
			SET status = ?, completed_at = ?, updated_at = ?
			WHERE status = ?
		`, StatusFailed, now, now, StatusRunning)
	}

	return int(n), nil
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

// --- Attack-Surface Inventory Methods ---

func (s *SQLiteStore) SaveInventory(assets []discovery.Asset, relations []discovery.Relation) error {
	if len(assets) == 0 && len(relations) == 0 {
		return nil
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	if len(assets) > 0 {
		stmtAsset, err := tx.Prepare(`
			INSERT INTO assessment_inventory_assets (
				id, assessment_id, execution_id, target_id, asset_type, canonical_id,
				parent_id, display_name, source_asset, discovery_method, discovery_status,
				confidence, in_scope, metadata_json, evidence_json, fingerprint, first_seen, last_seen
			) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
			ON CONFLICT(id) DO UPDATE SET
				last_seen = excluded.last_seen,
				discovery_status = excluded.discovery_status,
				metadata_json = excluded.metadata_json,
				evidence_json = excluded.evidence_json
		`)
		if err != nil {
			return err
		}
		defer stmtAsset.Close()

		for _, a := range assets {
			a.AssessmentID = s.resolveAssessmentID(a.AssessmentID)
			metaJSON, _ := json.Marshal(a.Metadata)
			evJSON, _ := json.Marshal(a.Evidence)
			inScopeInt := 0
			if a.InScope {
				inScopeInt = 1
			}
			if a.FirstSeen.IsZero() {
				a.FirstSeen = time.Now().UTC()
			}
			if a.LastSeen.IsZero() {
				a.LastSeen = a.FirstSeen
			}
			if a.Fingerprint == "" {
				a.Fingerprint = a.ComputeFingerprint()
			}

			_, err = stmtAsset.Exec(
				a.ID, a.AssessmentID, a.ExecutionID, a.TargetID, string(a.Type), a.CanonicalID,
				a.ParentID, a.DisplayName, a.SourceAsset, a.DiscoveryMethod, string(a.DiscoveryStatus),
				string(a.Confidence), inScopeInt, string(metaJSON), string(evJSON), a.Fingerprint, a.FirstSeen, a.LastSeen,
			)
			if err != nil {
				return fmt.Errorf("failed to insert inventory asset %s: %w", a.ID, err)
			}
		}
	}

	if len(relations) > 0 {
		stmtRel, err := tx.Prepare(`
			INSERT OR IGNORE INTO assessment_inventory_relations (
				id, assessment_id, execution_id, source_asset_id, target_asset_id,
				relation_type, evidence, confidence, created_at
			) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
		`)
		if err != nil {
			return err
		}
		defer stmtRel.Close()

		for _, r := range relations {
			r.AssessmentID = s.resolveAssessmentID(r.AssessmentID)
			if r.CreatedAt.IsZero() {
				r.CreatedAt = time.Now().UTC()
			}
			_, err = stmtRel.Exec(
				r.ID, r.AssessmentID, r.ExecutionID, r.SourceAssetID, r.TargetAssetID,
				string(r.RelationType), r.Evidence, string(r.Confidence), r.CreatedAt,
			)
			if err != nil {
				return fmt.Errorf("failed to insert inventory relation %s: %w", r.ID, err)
			}
		}
	}

	return tx.Commit()
}

func (s *SQLiteStore) GetInventory(assessmentID string, executionID string, assetType string, inScopeOnly bool) ([]discovery.Asset, []discovery.Relation, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	assessmentID = s.resolveAssessmentID(assessmentID)
	query := `
		SELECT id, assessment_id, execution_id, target_id, asset_type, canonical_id,
		       parent_id, display_name, source_asset, discovery_method, discovery_status,
		       confidence, in_scope, metadata_json, evidence_json, fingerprint, first_seen, last_seen
		FROM assessment_inventory_assets
		WHERE assessment_id = ?
	`
	args := []any{assessmentID}
	if executionID != "" {
		query += " AND execution_id = ?"
		args = append(args, executionID)
	}
	if assetType != "" {
		query += " AND asset_type = ?"
		args = append(args, assetType)
	}
	if inScopeOnly {
		query += " AND in_scope = 1"
	}
	query += " ORDER BY asset_type ASC, canonical_id ASC"

	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()

	var assets []discovery.Asset
	for rows.Next() {
		var a discovery.Asset
		var aType, status, conf string
		var inScopeInt int
		var metaJSON, evJSON string
		err := rows.Scan(
			&a.ID, &a.AssessmentID, &a.ExecutionID, &a.TargetID, &aType, &a.CanonicalID,
			&a.ParentID, &a.DisplayName, &a.SourceAsset, &a.DiscoveryMethod, &status,
			&conf, &inScopeInt, &metaJSON, &evJSON, &a.Fingerprint, &a.FirstSeen, &a.LastSeen,
		)
		if err != nil {
			return nil, nil, err
		}
		a.Type = discovery.AssetType(aType)
		a.DiscoveryStatus = discovery.DiscoveryStatus(status)
		a.Confidence = discovery.Confidence(conf)
		a.InScope = inScopeInt == 1
		if metaJSON != "" {
			_ = json.Unmarshal([]byte(metaJSON), &a.Metadata)
		}
		if evJSON != "" {
			_ = json.Unmarshal([]byte(evJSON), &a.Evidence)
		}
		assets = append(assets, a)
	}

	// Relations query
	relQuery := `
		SELECT id, assessment_id, execution_id, source_asset_id, target_asset_id,
		       relation_type, evidence, confidence, created_at
		FROM assessment_inventory_relations
		WHERE assessment_id = ?
	`
	relArgs := []any{assessmentID}
	if executionID != "" {
		relQuery += " AND execution_id = ?"
		relArgs = append(relArgs, executionID)
	}
	relQuery += " ORDER BY relation_type ASC, created_at ASC"

	relRows, err := s.db.Query(relQuery, relArgs...)
	if err != nil {
		return assets, nil, err
	}
	defer relRows.Close()

	var relations []discovery.Relation
	for relRows.Next() {
		var r discovery.Relation
		var rType, conf string
		err := relRows.Scan(
			&r.ID, &r.AssessmentID, &r.ExecutionID, &r.SourceAssetID, &r.TargetAssetID,
			&rType, &r.Evidence, &conf, &r.CreatedAt,
		)
		if err != nil {
			return assets, nil, err
		}
		r.RelationType = discovery.RelationType(rType)
		r.Confidence = discovery.Confidence(conf)
		relations = append(relations, r)
	}

	return assets, relations, nil
}

func (s *SQLiteStore) GetInventorySummary(assessmentID string, executionID string) (*discovery.InventorySummary, error) {
	assets, relations, err := s.GetInventory(assessmentID, executionID, "", false)
	if err != nil {
		return nil, err
	}
	inv := discovery.NewInventory()
	inv.Assets = assets
	inv.Relations = relations
	sum := inv.Summary()
	return &sum, nil
}

