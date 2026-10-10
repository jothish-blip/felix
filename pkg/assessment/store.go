package assessment

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"felix/pkg/apisec"
	"felix/pkg/auth"
	"felix/pkg/authz"
	"felix/pkg/businesslogic"
	"felix/pkg/cloudsec"
	"felix/pkg/config"
	"felix/pkg/correlation"
	"felix/pkg/discovery"
	"felix/pkg/report"
	"felix/pkg/sessionsec"
	"felix/pkg/verification"
	"felix/pkg/webvuln"
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

	// Authentication Intelligence (Stage 3)
	SaveAuthInventory(authInv auth.AuthInventory) error
	GetAuthInventory(assessmentID string, executionID string, category string) (*auth.AuthInventory, error)
	GetAuthSummary(assessmentID string, executionID string) (*auth.AuthSummary, error)

	// Authorization Intelligence (Stage 4)
	SaveAuthzPolicy(assessmentID string, policy *authz.AuthzPolicy) error
	GetAuthzPolicy(assessmentID string) (*authz.AuthzPolicy, error)
	SaveAuthzResults(results []authz.AuthzTestResult) error
	GetAuthzResults(assessmentID string, executionID string, category string) ([]authz.AuthzTestResult, error)
	GetAuthzSummary(assessmentID string, executionID string) (*authz.AuthzSummary, error)

	// API Security Engine (Stage 5)
	SaveAPISecRun(record *apisec.RunRecord) error
	GetAPISecRun(assessmentID string, executionID string) (*apisec.RunRecord, error)
	SaveAPISecResults(results []apisec.Result) error
	GetAPISecResults(assessmentID string, executionID string, category string, state string) ([]apisec.Result, error)
	GetAPISecSummary(assessmentID string, executionID string) (*apisec.Summary, error)

	// Web Vulnerability Engine (Stage 6)
	SaveWebVulnRun(record *webvuln.RunRecord) error
	GetWebVulnRun(assessmentID string, executionID string) (*webvuln.RunRecord, error)
	SaveWebVulnResults(results []webvuln.Result) error
	GetWebVulnResults(assessmentID string, executionID string, category string, state string) ([]webvuln.Result, error)
	GetWebVulnSummary(assessmentID string, executionID string) (*webvuln.Summary, error)

	// Session & Identity Security Engine (Stage 7)
	SaveSessionSecRun(record *sessionsec.RunRecord) error
	GetSessionSecRun(assessmentID string, executionID string) (*sessionsec.RunRecord, error)
	SaveSessionSecResults(results []sessionsec.Result) error
	GetSessionSecResults(assessmentID string, executionID string, category string, state string) ([]sessionsec.Result, error)
	GetSessionSecSummary(assessmentID string, executionID string) (*sessionsec.Summary, error)

	// Cloud Security Engine (Stage 8)
	SaveCloudSecRun(record *cloudsec.RunRecord) error
	GetCloudSecRun(assessmentID string, executionID string) (*cloudsec.RunRecord, error)
	SaveCloudSecResults(results []cloudsec.Result) error
	GetCloudSecResults(assessmentID string, executionID string, provider string, service string, state string) ([]cloudsec.Result, error)
	GetCloudSecSummary(assessmentID string, executionID string) (*cloudsec.Summary, error)

	// Business Logic Security Engine (Stage 9)
	SaveBusinessLogicRun(record *businesslogic.RunRecord) error
	GetBusinessLogicRun(assessmentID string, executionID string) (*businesslogic.RunRecord, error)
	SaveBusinessLogicResults(results []businesslogic.Result) error
	GetBusinessLogicResults(assessmentID string, executionID string, category string, state string) ([]businesslogic.Result, error)
	GetBusinessLogicSummary(assessmentID string, executionID string) (*businesslogic.Summary, error)

	// Correlation & Attack Path Engine (Stage 10)
	SaveCorrelationRun(record *correlation.RunRecord) error
	GetCorrelationRun(assessmentID string, executionID string) (*correlation.RunRecord, error)
	SaveAttackPaths(assessmentID string, executionID string, paths []correlation.AttackPath) error
	GetAttackPaths(assessmentID string, executionID string, status string, minRisk string) ([]correlation.AttackPath, error)
	GetCorrelationSummary(assessmentID string, executionID string) (*correlation.Summary, error)

	// Verification Engine 2.0 (Stage 11)
	SaveVerificationRun(record *verification.VerificationRunRecord) error
	GetVerificationRun(assessmentID string, executionID string) (*verification.VerificationRunRecord, error)
	SaveVerificationResults(assessmentID string, executionID string, results []verification.VerificationResult) error
	GetVerificationResults(assessmentID string, executionID string, status string) ([]verification.VerificationResult, error)
	GetVerificationSummary(assessmentID string, executionID string) (*verification.VerificationSummary, error)

	// Report Records
	SaveReport(r *ReportRecord) error
	GetReports(assessmentID string) ([]ReportRecord, error)
	GetReport(id string) (*ReportRecord, error)

	// Finding Reviews (Stage 13)
	SaveFindingReview(review *FindingReview) error
	GetFindingReview(assessmentID string, findingID string) (*FindingReview, error)
	ListFindingReviews(assessmentID string) ([]FindingReview, error)

	// Report Deliveries (Stage 13)
	CreateReportDelivery(delivery *ReportDelivery) error
	GetReportDelivery(id string) (*ReportDelivery, error)
	ListReportDeliveries(assessmentID string) ([]ReportDelivery, error)
	UpdateReportDeliveryStatus(id string, status DeliveryStatus, notes string, timestamp *time.Time) error

	// Audit Events (Stage 13)
	RecordAuditEvent(event *AuditEvent) error
	ListAuditEvents(assessmentID string, limit int) ([]AuditEvent, error)

	// Scan Job Leases & Concurrency (Stage 13)
	AcquireScanJobLease(lease *ScanJobLease) error
	HeartbeatScanJobLease(assessmentID string, progress string) error
	ReleaseScanJobLease(assessmentID string, status string, errMsg string) error
	GetActiveScanJobLease(assessmentID string) (*ScanJobLease, error)
	RecoverStaleScanJobLeases(staleDuration time.Duration) (int, error)

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

	// Migration 3: Dedicated Authentication Intelligence subsystem (surfaces, cookies, tokens)
	if currentVersion < 3 {
		tx, err := s.db.Begin()
		if err != nil {
			return err
		}
		defer tx.Rollback()

		schemaV3 := `
		CREATE TABLE IF NOT EXISTS assessment_auth_surfaces (
			id TEXT PRIMARY KEY,
			assessment_id TEXT NOT NULL REFERENCES assessments(id) ON DELETE CASCADE,
			execution_id TEXT NOT NULL REFERENCES assessment_executions(id) ON DELETE CASCADE,
			target_id TEXT,
			canonical_id TEXT NOT NULL,
			category TEXT NOT NULL,
			subtype TEXT NOT NULL,
			identifier TEXT NOT NULL,
			endpoint_id TEXT,
			app_id TEXT,
			discovery_method TEXT NOT NULL,
			confidence TEXT NOT NULL,
			verification_status TEXT NOT NULL,
			auth_state TEXT NOT NULL,
			in_scope INTEGER NOT NULL DEFAULT 1,
			explanation TEXT,
			evidence_json TEXT,
			metadata_json TEXT,
			created_at TIMESTAMP NOT NULL,
			updated_at TIMESTAMP NOT NULL
		);

		CREATE INDEX IF NOT EXISTS idx_auth_surfaces_asm_id ON assessment_auth_surfaces(assessment_id);
		CREATE INDEX IF NOT EXISTS idx_auth_surfaces_exec_id ON assessment_auth_surfaces(execution_id);
		CREATE INDEX IF NOT EXISTS idx_auth_surfaces_cat ON assessment_auth_surfaces(category);

		CREATE TABLE IF NOT EXISTS assessment_auth_cookies (
			id TEXT PRIMARY KEY,
			assessment_id TEXT NOT NULL REFERENCES assessments(id) ON DELETE CASCADE,
			execution_id TEXT NOT NULL REFERENCES assessment_executions(id) ON DELETE CASCADE,
			target_id TEXT,
			name TEXT NOT NULL,
			domain TEXT,
			path TEXT,
			is_secure INTEGER NOT NULL DEFAULT 0,
			is_http_only INTEGER NOT NULL DEFAULT 0,
			same_site TEXT NOT NULL,
			max_age INTEGER,
			expires TEXT,
			purpose TEXT NOT NULL,
			is_session INTEGER NOT NULL DEFAULT 0,
			has_security_issue INTEGER NOT NULL DEFAULT 0,
			security_defects_json TEXT,
			source_url TEXT NOT NULL,
			created_at TIMESTAMP NOT NULL
		);

		CREATE INDEX IF NOT EXISTS idx_auth_cookies_asm_id ON assessment_auth_cookies(assessment_id);
		CREATE INDEX IF NOT EXISTS idx_auth_cookies_session ON assessment_auth_cookies(is_session);

		CREATE TABLE IF NOT EXISTS assessment_auth_tokens (
			id TEXT PRIMARY KEY,
			assessment_id TEXT NOT NULL REFERENCES assessments(id) ON DELETE CASCADE,
			execution_id TEXT NOT NULL REFERENCES assessment_executions(id) ON DELETE CASCADE,
			target_id TEXT,
			token_type TEXT NOT NULL,
			subtype TEXT NOT NULL,
			name TEXT NOT NULL,
			location TEXT NOT NULL,
			format TEXT NOT NULL,
			algorithm TEXT,
			evidence_summary TEXT,
			source_asset TEXT,
			created_at TIMESTAMP NOT NULL
		);

		CREATE INDEX IF NOT EXISTS idx_auth_tokens_asm_id ON assessment_auth_tokens(assessment_id);

		INSERT INTO schema_migrations (version, applied_at) VALUES (3, CURRENT_TIMESTAMP);
		`

		if _, err := tx.Exec(schemaV3); err != nil {
			return fmt.Errorf("migration v3 failed: %w", err)
		}

		if err := tx.Commit(); err != nil {
			return err
		}
	}

	// Migration 4: Authorization & Access Control Intelligence (Stage 4)
	if currentVersion < 4 {
		tx, err := s.db.Begin()
		if err != nil {
			return err
		}
		defer tx.Rollback()

		schemaV4 := `
		CREATE TABLE IF NOT EXISTS assessment_authz_policies (
			id TEXT PRIMARY KEY,
			assessment_id TEXT NOT NULL REFERENCES assessments(id) ON DELETE CASCADE,
			authorization_doc TEXT,
			allow_write_tests INTEGER NOT NULL DEFAULT 0,
			policy_json TEXT NOT NULL,
			created_at TIMESTAMP NOT NULL,
			updated_at TIMESTAMP NOT NULL
		);

		CREATE INDEX IF NOT EXISTS idx_authz_policies_asm_id ON assessment_authz_policies(assessment_id);

		CREATE TABLE IF NOT EXISTS assessment_authz_results (
			id TEXT PRIMARY KEY,
			test_case_id TEXT NOT NULL,
			assessment_id TEXT NOT NULL REFERENCES assessments(id) ON DELETE CASCADE,
			execution_id TEXT NOT NULL REFERENCES assessment_executions(id) ON DELETE CASCADE,
			category TEXT NOT NULL,
			verification_state TEXT NOT NULL,
			endpoint TEXT NOT NULL,
			method TEXT NOT NULL,
			primary_identity TEXT NOT NULL,
			baseline_identity TEXT,
			target_resource TEXT,
			observed_status INTEGER NOT NULL,
			baseline_status INTEGER,
			disclosed_data INTEGER NOT NULL DEFAULT 0,
			property_modified INTEGER NOT NULL DEFAULT 0,
			evidence_summary TEXT NOT NULL,
			redacted_request TEXT,
			redacted_response TEXT,
			correlated_category TEXT,
			finding_id TEXT,
			created_at TIMESTAMP NOT NULL
		);

		CREATE INDEX IF NOT EXISTS idx_authz_results_asm_id ON assessment_authz_results(assessment_id);
		CREATE INDEX IF NOT EXISTS idx_authz_results_exec_id ON assessment_authz_results(execution_id);
		CREATE INDEX IF NOT EXISTS idx_authz_results_cat ON assessment_authz_results(category);
		CREATE INDEX IF NOT EXISTS idx_authz_results_state ON assessment_authz_results(verification_state);

		INSERT INTO schema_migrations (version, applied_at) VALUES (4, CURRENT_TIMESTAMP);
		`

		if _, err := tx.Exec(schemaV4); err != nil {
			return fmt.Errorf("migration v4 failed: %w", err)
		}

		if err := tx.Commit(); err != nil {
			return err
		}
	}

	// Migration 5: API Security Engine (Stage 5)
	if currentVersion < 5 {
		tx, err := s.db.Begin()
		if err != nil {
			return err
		}
		defer tx.Rollback()

		schemaV5 := `
		CREATE TABLE IF NOT EXISTS assessment_apisec_runs (
			id TEXT PRIMARY KEY,
			assessment_id TEXT NOT NULL REFERENCES assessments(id) ON DELETE CASCADE,
			execution_id TEXT NOT NULL REFERENCES assessment_executions(id) ON DELETE CASCADE,
			total_tests INTEGER NOT NULL DEFAULT 0,
			categories_assessed INTEGER NOT NULL DEFAULT 0,
			verified_count INTEGER NOT NULL DEFAULT 0,
			candidate_count INTEGER NOT NULL DEFAULT 0,
			coverage_json TEXT NOT NULL,
			created_at TIMESTAMP NOT NULL
		);

		CREATE INDEX IF NOT EXISTS idx_apisec_runs_asm_id ON assessment_apisec_runs(assessment_id);
		CREATE INDEX IF NOT EXISTS idx_apisec_runs_exec_id ON assessment_apisec_runs(execution_id);

		CREATE TABLE IF NOT EXISTS assessment_apisec_results (
			id TEXT PRIMARY KEY,
			assessment_id TEXT NOT NULL REFERENCES assessments(id) ON DELETE CASCADE,
			execution_id TEXT NOT NULL REFERENCES assessment_executions(id) ON DELETE CASCADE,
			category TEXT NOT NULL,
			owasp_code TEXT NOT NULL,
			test_name TEXT NOT NULL,
			endpoint TEXT NOT NULL,
			method TEXT NOT NULL,
			verification_state TEXT NOT NULL,
			severity TEXT NOT NULL,
			confidence TEXT NOT NULL,
			observed_status INTEGER,
			evidence_summary TEXT NOT NULL,
			evidence_details_json TEXT,
			finding_id TEXT,
			created_at TIMESTAMP NOT NULL
		);

		CREATE INDEX IF NOT EXISTS idx_apisec_res_asm_id ON assessment_apisec_results(assessment_id);
		CREATE INDEX IF NOT EXISTS idx_apisec_res_exec_id ON assessment_apisec_results(execution_id);
		CREATE INDEX IF NOT EXISTS idx_apisec_res_cat ON assessment_apisec_results(category);
		CREATE INDEX IF NOT EXISTS idx_apisec_res_state ON assessment_apisec_results(verification_state);

		INSERT INTO schema_migrations (version, applied_at) VALUES (5, CURRENT_TIMESTAMP);
		`

		if _, err := tx.Exec(schemaV5); err != nil {
			return fmt.Errorf("migration v5 failed: %w", err)
		}

		if err := tx.Commit(); err != nil {
			return err
		}
	}

	// Migration 6: Web Vulnerability Engine (Stage 6)
	if currentVersion < 6 {
		tx, err := s.db.Begin()
		if err != nil {
			return err
		}
		defer tx.Rollback()

		schemaV6 := `
		CREATE TABLE IF NOT EXISTS assessment_webvuln_runs (
			id TEXT PRIMARY KEY,
			assessment_id TEXT NOT NULL REFERENCES assessments(id) ON DELETE CASCADE,
			execution_id TEXT NOT NULL REFERENCES assessment_executions(id) ON DELETE CASCADE,
			total_tests INTEGER NOT NULL DEFAULT 0,
			categories_assessed INTEGER NOT NULL DEFAULT 0,
			verified_count INTEGER NOT NULL DEFAULT 0,
			candidate_count INTEGER NOT NULL DEFAULT 0,
			observed_count INTEGER NOT NULL DEFAULT 0,
			coverage_json TEXT NOT NULL,
			created_at TIMESTAMP NOT NULL
		);

		CREATE INDEX IF NOT EXISTS idx_webvuln_runs_asm_id ON assessment_webvuln_runs(assessment_id);
		CREATE INDEX IF NOT EXISTS idx_webvuln_runs_exec_id ON assessment_webvuln_runs(execution_id);

		CREATE TABLE IF NOT EXISTS assessment_webvuln_results (
			id TEXT PRIMARY KEY,
			assessment_id TEXT NOT NULL REFERENCES assessments(id) ON DELETE CASCADE,
			execution_id TEXT NOT NULL REFERENCES assessment_executions(id) ON DELETE CASCADE,
			category TEXT NOT NULL,
			vuln_code TEXT NOT NULL,
			test_name TEXT NOT NULL,
			endpoint TEXT NOT NULL,
			method TEXT NOT NULL,
			verification_state TEXT NOT NULL,
			severity TEXT NOT NULL,
			confidence TEXT NOT NULL,
			observed_status INTEGER,
			evidence_summary TEXT NOT NULL,
			evidence_details_json TEXT,
			finding_id TEXT,
			created_at TIMESTAMP NOT NULL
		);

		CREATE INDEX IF NOT EXISTS idx_webvuln_res_asm_id ON assessment_webvuln_results(assessment_id);
		CREATE INDEX IF NOT EXISTS idx_webvuln_res_exec_id ON assessment_webvuln_results(execution_id);
		CREATE INDEX IF NOT EXISTS idx_webvuln_res_cat ON assessment_webvuln_results(category);
		CREATE INDEX IF NOT EXISTS idx_webvuln_res_state ON assessment_webvuln_results(verification_state);

		INSERT INTO schema_migrations (version, applied_at) VALUES (6, CURRENT_TIMESTAMP);
		`

		if _, err := tx.Exec(schemaV6); err != nil {
			return fmt.Errorf("migration v6 failed: %w", err)
		}

		if err := tx.Commit(); err != nil {
			return err
		}
	}

	// Migration 7: Session & Identity Security Engine (Stage 7)
	if currentVersion < 7 {
		tx, err := s.db.Begin()
		if err != nil {
			return err
		}
		defer tx.Rollback()

		schemaV7 := `
		CREATE TABLE IF NOT EXISTS assessment_sessionsec_runs (
			id TEXT PRIMARY KEY,
			assessment_id TEXT NOT NULL REFERENCES assessments(id) ON DELETE CASCADE,
			execution_id TEXT NOT NULL REFERENCES assessment_executions(id) ON DELETE CASCADE,
			total_tests INTEGER NOT NULL DEFAULT 0,
			categories_assessed INTEGER NOT NULL DEFAULT 0,
			verified_count INTEGER NOT NULL DEFAULT 0,
			candidate_count INTEGER NOT NULL DEFAULT 0,
			observed_count INTEGER NOT NULL DEFAULT 0,
			inconclusive_count INTEGER NOT NULL DEFAULT 0,
			blocked_count INTEGER NOT NULL DEFAULT 0,
			coverage_json TEXT NOT NULL,
			created_at TIMESTAMP NOT NULL
		);

		CREATE INDEX IF NOT EXISTS idx_sessionsec_runs_asm_id ON assessment_sessionsec_runs(assessment_id);
		CREATE INDEX IF NOT EXISTS idx_sessionsec_runs_exec_id ON assessment_sessionsec_runs(execution_id);

		CREATE TABLE IF NOT EXISTS assessment_sessionsec_results (
			id TEXT PRIMARY KEY,
			assessment_id TEXT NOT NULL REFERENCES assessments(id) ON DELETE CASCADE,
			execution_id TEXT NOT NULL REFERENCES assessment_executions(id) ON DELETE CASCADE,
			category TEXT NOT NULL,
			vuln_code TEXT NOT NULL,
			test_id TEXT NOT NULL,
			test_name TEXT NOT NULL,
			wstg_ref TEXT NOT NULL,
			endpoint TEXT NOT NULL,
			method TEXT NOT NULL,
			verification_state TEXT NOT NULL,
			severity TEXT NOT NULL,
			confidence TEXT NOT NULL,
			observed_status INTEGER,
			state_before TEXT,
			state_after TEXT,
			evidence_summary TEXT NOT NULL,
			evidence_details_json TEXT,
			finding_id TEXT,
			created_at TIMESTAMP NOT NULL
		);

		CREATE INDEX IF NOT EXISTS idx_sessionsec_res_asm_id ON assessment_sessionsec_results(assessment_id);
		CREATE INDEX IF NOT EXISTS idx_sessionsec_res_exec_id ON assessment_sessionsec_results(execution_id);
		CREATE INDEX IF NOT EXISTS idx_sessionsec_res_cat ON assessment_sessionsec_results(category);
		CREATE INDEX IF NOT EXISTS idx_sessionsec_res_state ON assessment_sessionsec_results(verification_state);

		INSERT INTO schema_migrations (version, applied_at) VALUES (7, CURRENT_TIMESTAMP);
		`

		if _, err := tx.Exec(schemaV7); err != nil {
			return fmt.Errorf("migration v7 failed: %w", err)
		}

		if err := tx.Commit(); err != nil {
			return err
		}
	}

	// Migration 8: Real Cloud Security Engine (Stage 8)
	if currentVersion < 8 {
		tx, err := s.db.Begin()
		if err != nil {
			return err
		}
		defer tx.Rollback()

		schemaV8 := `
		CREATE TABLE IF NOT EXISTS assessment_cloudsec_runs (
			id TEXT PRIMARY KEY,
			assessment_id TEXT NOT NULL REFERENCES assessments(id) ON DELETE CASCADE,
			execution_id TEXT NOT NULL REFERENCES assessment_executions(id) ON DELETE CASCADE,
			mode TEXT NOT NULL,
			provider TEXT NOT NULL,
			scope_identifier TEXT NOT NULL,
			verified_principal TEXT,
			total_checks INTEGER NOT NULL DEFAULT 0,
			services_assessed INTEGER NOT NULL DEFAULT 0,
			verified_count INTEGER NOT NULL DEFAULT 0,
			candidate_count INTEGER NOT NULL DEFAULT 0,
			observed_count INTEGER NOT NULL DEFAULT 0,
			coverage_json TEXT NOT NULL,
			created_at TIMESTAMP NOT NULL
		);

		CREATE INDEX IF NOT EXISTS idx_cloudsec_runs_asm_id ON assessment_cloudsec_runs(assessment_id);
		CREATE INDEX IF NOT EXISTS idx_cloudsec_runs_exec_id ON assessment_cloudsec_runs(execution_id);
		CREATE INDEX IF NOT EXISTS idx_cloudsec_runs_provider ON assessment_cloudsec_runs(provider);

		CREATE TABLE IF NOT EXISTS assessment_cloudsec_results (
			id TEXT PRIMARY KEY,
			assessment_id TEXT NOT NULL REFERENCES assessments(id) ON DELETE CASCADE,
			execution_id TEXT NOT NULL REFERENCES assessment_executions(id) ON DELETE CASCADE,
			provider TEXT NOT NULL,
			mode TEXT NOT NULL,
			service TEXT NOT NULL,
			check_id TEXT NOT NULL,
			check_name TEXT NOT NULL,
			resource_id TEXT NOT NULL,
			region TEXT,
			verification_state TEXT NOT NULL,
			severity TEXT NOT NULL,
			confidence TEXT NOT NULL,
			evidence_summary TEXT NOT NULL,
			evidence_details_json TEXT,
			finding_id TEXT,
			created_at TIMESTAMP NOT NULL
		);

		CREATE INDEX IF NOT EXISTS idx_cloudsec_res_asm_id ON assessment_cloudsec_results(assessment_id);
		CREATE INDEX IF NOT EXISTS idx_cloudsec_res_exec_id ON assessment_cloudsec_results(execution_id);
		CREATE INDEX IF NOT EXISTS idx_cloudsec_res_prov ON assessment_cloudsec_results(provider);
		CREATE INDEX IF NOT EXISTS idx_cloudsec_res_svc ON assessment_cloudsec_results(service);
		CREATE INDEX IF NOT EXISTS idx_cloudsec_res_state ON assessment_cloudsec_results(verification_state);

		INSERT INTO schema_migrations (version, applied_at) VALUES (8, CURRENT_TIMESTAMP);
		`

		if _, err := tx.Exec(schemaV8); err != nil {
			return fmt.Errorf("migration v8 failed: %w", err)
		}

		if err := tx.Commit(); err != nil {
			return err
		}
	}

	// Migration 9: Business Logic Security Engine (Stage 9)
	if currentVersion < 9 {
		tx, err := s.db.Begin()
		if err != nil {
			return err
		}
		defer tx.Rollback()

		schemaV9 := `
		CREATE TABLE IF NOT EXISTS assessment_businesslogic_runs (
			id TEXT PRIMARY KEY,
			assessment_id TEXT NOT NULL REFERENCES assessments(id) ON DELETE CASCADE,
			execution_id TEXT NOT NULL REFERENCES assessment_executions(id) ON DELETE CASCADE,
			target_url TEXT NOT NULL,
			total_checks INTEGER NOT NULL DEFAULT 0,
			categories_assessed INTEGER NOT NULL DEFAULT 0,
			workflows_modeled INTEGER NOT NULL DEFAULT 0,
			verified_count INTEGER NOT NULL DEFAULT 0,
			candidate_count INTEGER NOT NULL DEFAULT 0,
			observed_count INTEGER NOT NULL DEFAULT 0,
			inconclusive_count INTEGER NOT NULL DEFAULT 0,
			blocked_count INTEGER NOT NULL DEFAULT 0,
			not_vulnerable_count INTEGER NOT NULL DEFAULT 0,
			synthetic_fixture BOOLEAN NOT NULL DEFAULT 0,
			coverage_json TEXT NOT NULL,
			created_at TIMESTAMP NOT NULL
		);

		CREATE INDEX IF NOT EXISTS idx_bizlogic_runs_asm_id ON assessment_businesslogic_runs(assessment_id);
		CREATE INDEX IF NOT EXISTS idx_bizlogic_runs_exec_id ON assessment_businesslogic_runs(execution_id);

		CREATE TABLE IF NOT EXISTS assessment_businesslogic_results (
			id TEXT PRIMARY KEY,
			assessment_id TEXT NOT NULL REFERENCES assessments(id) ON DELETE CASCADE,
			execution_id TEXT NOT NULL REFERENCES assessment_executions(id) ON DELETE CASCADE,
			category TEXT NOT NULL,
			check_id TEXT NOT NULL,
			check_name TEXT NOT NULL,
			workflow_id TEXT NOT NULL,
			workflow_name TEXT NOT NULL,
			endpoint TEXT NOT NULL,
			method TEXT NOT NULL,
			verification_state TEXT NOT NULL,
			severity TEXT NOT NULL,
			confidence TEXT NOT NULL,
			observed_status INTEGER DEFAULT 0,
			state_before TEXT,
			state_after TEXT,
			evidence_summary TEXT NOT NULL,
			evidence_details_json TEXT,
			finding_id TEXT,
			created_at TIMESTAMP NOT NULL
		);

		CREATE INDEX IF NOT EXISTS idx_bizlogic_res_asm_id ON assessment_businesslogic_results(assessment_id);
		CREATE INDEX IF NOT EXISTS idx_bizlogic_res_exec_id ON assessment_businesslogic_results(execution_id);
		CREATE INDEX IF NOT EXISTS idx_bizlogic_res_cat ON assessment_businesslogic_results(category);
		CREATE INDEX IF NOT EXISTS idx_bizlogic_res_wf ON assessment_businesslogic_results(workflow_id);
		CREATE INDEX IF NOT EXISTS idx_bizlogic_res_state ON assessment_businesslogic_results(verification_state);

		INSERT INTO schema_migrations (version, applied_at) VALUES (9, CURRENT_TIMESTAMP);
		`

		if _, err := tx.Exec(schemaV9); err != nil {
			return fmt.Errorf("migration v9 failed: %w", err)
		}

		if err := tx.Commit(); err != nil {
			return err
		}
	}

	// Migration 10: Correlation & Attack Path Engine (Stage 10)
	if currentVersion < 10 {
		tx, err := s.db.Begin()
		if err != nil {
			return err
		}
		defer tx.Rollback()

		schemaV10 := `
		CREATE TABLE IF NOT EXISTS assessment_correlation_runs (
			id TEXT PRIMARY KEY,
			assessment_id TEXT NOT NULL REFERENCES assessments(id) ON DELETE CASCADE,
			execution_id TEXT NOT NULL REFERENCES assessment_executions(id) ON DELETE CASCADE,
			total_findings INTEGER NOT NULL DEFAULT 0,
			candidate_relationships INTEGER NOT NULL DEFAULT 0,
			candidate_paths INTEGER NOT NULL DEFAULT 0,
			verified_paths INTEGER NOT NULL DEFAULT 0,
			highest_risk TEXT NOT NULL,
			coverage_json TEXT NOT NULL,
			synthetic_fixture BOOLEAN NOT NULL DEFAULT 0,
			created_at TIMESTAMP NOT NULL
		);

		CREATE INDEX IF NOT EXISTS idx_correlation_runs_asm_id ON assessment_correlation_runs(assessment_id);
		CREATE INDEX IF NOT EXISTS idx_correlation_runs_exec_id ON assessment_correlation_runs(execution_id);

		CREATE TABLE IF NOT EXISTS assessment_attack_paths (
			id TEXT PRIMARY KEY,
			assessment_id TEXT NOT NULL REFERENCES assessments(id) ON DELETE CASCADE,
			execution_id TEXT NOT NULL REFERENCES assessment_executions(id) ON DELETE CASCADE,
			title TEXT NOT NULL,
			entry_point TEXT,
			target_asset TEXT NOT NULL,
			primary_weakness TEXT NOT NULL,
			terminal_impact TEXT NOT NULL,
			status TEXT NOT NULL,
			confidence TEXT NOT NULL,
			combined_risk_level TEXT NOT NULL,
			combined_risk_score INTEGER NOT NULL,
			risk_rationale TEXT,
			node_ids_json TEXT NOT NULL,
			nodes_json TEXT NOT NULL,
			edges_json TEXT NOT NULL,
			security_story_json TEXT NOT NULL,
			remediation TEXT NOT NULL,
			synthetic_fixture BOOLEAN NOT NULL DEFAULT 0,
			created_at TIMESTAMP NOT NULL
		);

		CREATE INDEX IF NOT EXISTS idx_attack_paths_asm_id ON assessment_attack_paths(assessment_id);
		CREATE INDEX IF NOT EXISTS idx_attack_paths_exec_id ON assessment_attack_paths(execution_id);
		CREATE INDEX IF NOT EXISTS idx_attack_paths_status ON assessment_attack_paths(status);
		CREATE INDEX IF NOT EXISTS idx_attack_paths_risk ON assessment_attack_paths(combined_risk_level);

		INSERT INTO schema_migrations (version, applied_at) VALUES (10, CURRENT_TIMESTAMP);
		`

		if _, err := tx.Exec(schemaV10); err != nil {
			return fmt.Errorf("migration v10 failed: %w", err)
		}

		if err := tx.Commit(); err != nil {
			return err
		}
	}

	// Migration 11: Verification Engine 2.0 (Stage 11)
	if currentVersion < 11 {
		tx, err := s.db.Begin()
		if err != nil {
			return err
		}
		defer tx.Rollback()

		schemaV11 := `
		CREATE TABLE IF NOT EXISTS assessment_verification_runs (
			id TEXT PRIMARY KEY,
			assessment_id TEXT NOT NULL REFERENCES assessments(id) ON DELETE CASCADE,
			execution_id TEXT NOT NULL REFERENCES assessment_executions(id) ON DELETE CASCADE,
			total_findings INTEGER NOT NULL DEFAULT 0,
			attempted_count INTEGER NOT NULL DEFAULT 0,
			verified_count INTEGER NOT NULL DEFAULT 0,
			detected_count INTEGER NOT NULL DEFAULT 0,
			observed_count INTEGER NOT NULL DEFAULT 0,
			not_verified_count INTEGER NOT NULL DEFAULT 0,
			not_exposed_count INTEGER NOT NULL DEFAULT 0,
			blocked_count INTEGER NOT NULL DEFAULT 0,
			inconclusive_count INTEGER NOT NULL DEFAULT 0,
			synthetic_count INTEGER NOT NULL DEFAULT 0,
			coverage_json TEXT NOT NULL,
			verifier_version TEXT NOT NULL,
			created_at TIMESTAMP NOT NULL
		);

		CREATE INDEX IF NOT EXISTS idx_verification_runs_asm_id ON assessment_verification_runs(assessment_id);
		CREATE INDEX IF NOT EXISTS idx_verification_runs_exec_id ON assessment_verification_runs(execution_id);

		CREATE TABLE IF NOT EXISTS assessment_verification_results (
			id TEXT PRIMARY KEY,
			assessment_id TEXT NOT NULL REFERENCES assessments(id) ON DELETE CASCADE,
			execution_id TEXT NOT NULL REFERENCES assessment_executions(id) ON DELETE CASCADE,
			finding_id TEXT NOT NULL,
			status TEXT NOT NULL,
			policy_id TEXT NOT NULL,
			verification_method TEXT NOT NULL,
			attempted BOOLEAN NOT NULL DEFAULT 0,
			detection_confidence TEXT NOT NULL,
			verification_confidence TEXT NOT NULL,
			overall_confidence TEXT NOT NULL,
			confidence_score INTEGER NOT NULL DEFAULT 0,
			confidence_rationale TEXT,
			reproduction_json TEXT,
			criteria_results_json TEXT,
			limitations_json TEXT,
			safety_decision TEXT,
			block_reason TEXT,
			failure_reason TEXT,
			inconclusive_reason TEXT,
			synthetic_fixture BOOLEAN NOT NULL DEFAULT 0,
			created_at TIMESTAMP NOT NULL
		);

		CREATE INDEX IF NOT EXISTS idx_ver_res_asm_id ON assessment_verification_results(assessment_id);
		CREATE INDEX IF NOT EXISTS idx_ver_res_exec_id ON assessment_verification_results(execution_id);
		CREATE INDEX IF NOT EXISTS idx_ver_res_finding_id ON assessment_verification_results(finding_id);
		CREATE INDEX IF NOT EXISTS idx_ver_res_status ON assessment_verification_results(status);

		INSERT INTO schema_migrations (version, applied_at) VALUES (11, CURRENT_TIMESTAMP);
		`

		if _, err := tx.Exec(schemaV11); err != nil {
			return fmt.Errorf("migration v11 failed: %w", err)
		}

		if err := tx.Commit(); err != nil {
			return err
		}
	}

	// Migration 12: Stage 13 Operator Engine (Finding Reviews, Report Delivery, Audit Events, Scan Leases)
	if currentVersion < 12 {
		tx, err := s.db.Begin()
		if err != nil {
			return err
		}
		defer tx.Rollback()

		schemaV12 := `
		CREATE TABLE IF NOT EXISTS finding_reviews (
			id TEXT PRIMARY KEY,
			assessment_id TEXT NOT NULL REFERENCES assessments(id) ON DELETE CASCADE,
			finding_id TEXT NOT NULL,
			review_status TEXT NOT NULL DEFAULT 'PENDING',
			reviewed_by TEXT NOT NULL,
			reviewed_at TIMESTAMP NOT NULL,
			notes TEXT,
			created_at TIMESTAMP NOT NULL,
			updated_at TIMESTAMP NOT NULL,
			UNIQUE(assessment_id, finding_id)
		);

		CREATE INDEX IF NOT EXISTS idx_finding_reviews_asm_id ON finding_reviews(assessment_id);
		CREATE INDEX IF NOT EXISTS idx_finding_reviews_finding_id ON finding_reviews(finding_id);
		CREATE INDEX IF NOT EXISTS idx_finding_reviews_status ON finding_reviews(review_status);

		CREATE TABLE IF NOT EXISTS report_deliveries (
			id TEXT PRIMARY KEY,
			assessment_id TEXT NOT NULL REFERENCES assessments(id) ON DELETE CASCADE,
			report_id TEXT NOT NULL REFERENCES assessment_reports(id) ON DELETE CASCADE,
			delivery_status TEXT NOT NULL,
			recipient_name TEXT NOT NULL,
			recipient_email TEXT NOT NULL,
			delivery_method TEXT NOT NULL,
			tracking_reference TEXT,
			notes TEXT,
			dispatched_at TIMESTAMP,
			delivered_at TIMESTAMP,
			operator_id TEXT NOT NULL,
			created_at TIMESTAMP NOT NULL,
			updated_at TIMESTAMP NOT NULL
		);

		CREATE INDEX IF NOT EXISTS idx_report_deliveries_asm_id ON report_deliveries(assessment_id);
		CREATE INDEX IF NOT EXISTS idx_report_deliveries_report_id ON report_deliveries(report_id);
		CREATE INDEX IF NOT EXISTS idx_report_deliveries_status ON report_deliveries(delivery_status);

		CREATE TABLE IF NOT EXISTS operator_audit_events (
			id TEXT PRIMARY KEY,
			assessment_id TEXT,
			operator_id TEXT NOT NULL,
			action_type TEXT NOT NULL,
			entity_type TEXT NOT NULL,
			entity_id TEXT NOT NULL,
			details_json TEXT,
			created_at TIMESTAMP NOT NULL
		);

		CREATE INDEX IF NOT EXISTS idx_audit_events_asm_id ON operator_audit_events(assessment_id);
		CREATE INDEX IF NOT EXISTS idx_audit_events_action ON operator_audit_events(action_type);
		CREATE INDEX IF NOT EXISTS idx_audit_events_created_at ON operator_audit_events(created_at);

		CREATE TABLE IF NOT EXISTS scan_job_leases (
			id TEXT PRIMARY KEY,
			execution_id TEXT NOT NULL,
			operator_id TEXT NOT NULL,
			acquired_at TIMESTAMP NOT NULL,
			heartbeat_at TIMESTAMP NOT NULL,
			status TEXT NOT NULL,
			error_message TEXT,
			progress_message TEXT
		);

		CREATE INDEX IF NOT EXISTS idx_job_leases_status ON scan_job_leases(status);
		CREATE INDEX IF NOT EXISTS idx_job_leases_heartbeat ON scan_job_leases(heartbeat_at);

		INSERT INTO schema_migrations (version, applied_at) VALUES (12, CURRENT_TIMESTAMP);
		`

		if _, err := tx.Exec(schemaV12); err != nil {
			return fmt.Errorf("migration v12 failed: %w", err)
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

func (s *SQLiteStore) GetReport(id string) (*ReportRecord, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var r ReportRecord
	err := s.db.QueryRow(`
		SELECT id, assessment_id, execution_id, format, file_path, felix_version, status, created_at
		FROM assessment_reports WHERE id = ?
	`, id).Scan(&r.ID, &r.AssessmentID, &r.ExecutionID, &r.Format, &r.FilePath, &r.FelixVersion, &r.Status, &r.CreatedAt)
	if err != nil {
		return nil, err
	}
	return &r, nil
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

// SaveAuthInventory persists authentication surfaces, cookies, and tokens atomically.
func (s *SQLiteStore) SaveAuthInventory(authInv auth.AuthInventory) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback()

	// 1. Insert Authentication Surfaces
	surfaceStmt, err := tx.Prepare(`
		INSERT OR REPLACE INTO assessment_auth_surfaces (
			id, assessment_id, execution_id, target_id, canonical_id, category, subtype,
			identifier, endpoint_id, app_id, discovery_method, confidence, verification_status,
			auth_state, in_scope, explanation, evidence_json, metadata_json, created_at, updated_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`)
	if err != nil {
		return fmt.Errorf("failed to prepare auth surfaces statement: %w", err)
	}
	defer surfaceStmt.Close()

	for _, sf := range authInv.Surfaces {
		evJSON, _ := json.Marshal(sf.Evidence)
		metaJSON, _ := json.Marshal(sf.Metadata)
		inScopeInt := 0
		if sf.InScope {
			inScopeInt = 1
		}

		_, err := surfaceStmt.Exec(
			sf.ID, sf.AssessmentID, sf.ExecutionID, sf.TargetID, sf.CanonicalID,
			string(sf.Category), string(sf.Subtype), sf.Identifier, sf.EndpointID,
			sf.AppID, sf.DiscoveryMethod, string(sf.Confidence), string(sf.VerificationStatus),
			string(sf.AuthState), inScopeInt, sf.Explanation, string(evJSON), string(metaJSON),
			sf.CreatedAt, sf.UpdatedAt,
		)
		if err != nil {
			return fmt.Errorf("failed to insert auth surface %s: %w", sf.CanonicalID, err)
		}
	}

	// 2. Insert Cookies
	cookieStmt, err := tx.Prepare(`
		INSERT OR REPLACE INTO assessment_auth_cookies (
			id, assessment_id, execution_id, target_id, name, domain, path, is_secure,
			is_http_only, same_site, max_age, expires, purpose, is_session, has_security_issue,
			security_defects_json, source_url, created_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`)
	if err != nil {
		return fmt.Errorf("failed to prepare auth cookies statement: %w", err)
	}
	defer cookieStmt.Close()

	for _, ck := range authInv.Cookies {
		defectsJSON, _ := json.Marshal(ck.SecurityDefects)
		secInt := 0
		if ck.IsSecure {
			secInt = 1
		}
		httpOnlyInt := 0
		if ck.IsHTTPOnly {
			httpOnlyInt = 1
		}
		sessInt := 0
		if ck.IsSession {
			sessInt = 1
		}
		hasIssueInt := 0
		if ck.HasSecurityIssue {
			hasIssueInt = 1
		}

		_, err := cookieStmt.Exec(
			ck.ID, ck.AssessmentID, ck.ExecutionID, ck.TargetID, ck.Name, ck.Domain,
			ck.Path, secInt, httpOnlyInt, ck.SameSite, ck.MaxAge, ck.Expires,
			string(ck.Purpose), sessInt, hasIssueInt, string(defectsJSON), ck.SourceURL,
			ck.CreatedAt,
		)
		if err != nil {
			return fmt.Errorf("failed to insert auth cookie %s: %w", ck.Name, err)
		}
	}

	// 3. Insert Token Artifacts
	tokenStmt, err := tx.Prepare(`
		INSERT OR REPLACE INTO assessment_auth_tokens (
			id, assessment_id, execution_id, target_id, token_type, subtype, name,
			location, format, algorithm, evidence_summary, source_asset, created_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`)
	if err != nil {
		return fmt.Errorf("failed to prepare auth tokens statement: %w", err)
	}
	defer tokenStmt.Close()

	for _, tk := range authInv.Tokens {
		_, err := tokenStmt.Exec(
			tk.ID, tk.AssessmentID, tk.ExecutionID, tk.TargetID, tk.TokenType,
			string(tk.Subtype), tk.Name, tk.Location, tk.Format, tk.Algorithm,
			tk.EvidenceSummary, tk.SourceAsset, tk.CreatedAt,
		)
		if err != nil {
			return fmt.Errorf("failed to insert auth token %s: %w", tk.Name, err)
		}
	}

	return tx.Commit()
}

// GetAuthInventory retrieves stored authentication surfaces, cookies, and tokens for an assessment.
func (s *SQLiteStore) GetAuthInventory(assessmentID string, executionID string, category string) (*auth.AuthInventory, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	res := &auth.AuthInventory{}

	// Surfaces Query
	query := `
		SELECT id, assessment_id, execution_id, target_id, canonical_id, category, subtype,
		       identifier, endpoint_id, app_id, discovery_method, confidence, verification_status,
		       auth_state, in_scope, explanation, evidence_json, metadata_json, created_at, updated_at
		FROM assessment_auth_surfaces
		WHERE assessment_id = ?
	`
	args := []any{assessmentID}
	if executionID != "" {
		query += " AND execution_id = ?"
		args = append(args, executionID)
	}
	if category != "" {
		query += " AND category = ?"
		args = append(args, category)
	}
	query += " ORDER BY category ASC, canonical_id ASC"

	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		var sf auth.AuthSurface
		var cat, sub, conf, vStatus, aState string
		var inScopeInt int
		var evJSON, metaJSON string

		err := rows.Scan(
			&sf.ID, &sf.AssessmentID, &sf.ExecutionID, &sf.TargetID, &sf.CanonicalID,
			&cat, &sub, &sf.Identifier, &sf.EndpointID, &sf.AppID, &sf.DiscoveryMethod,
			&conf, &vStatus, &aState, &inScopeInt, &sf.Explanation, &evJSON, &metaJSON,
			&sf.CreatedAt, &sf.UpdatedAt,
		)
		if err != nil {
			return nil, err
		}

		sf.Category = auth.AuthCategory(cat)
		sf.Subtype = auth.AuthSubtype(sub)
		sf.Confidence = auth.Confidence(conf)
		sf.VerificationStatus = auth.VerificationStatus(vStatus)
		sf.AuthState = auth.AuthState(aState)
		sf.InScope = inScopeInt == 1
		if evJSON != "" {
			_ = json.Unmarshal([]byte(evJSON), &sf.Evidence)
		}
		if metaJSON != "" {
			_ = json.Unmarshal([]byte(metaJSON), &sf.Metadata)
		}

		res.Surfaces = append(res.Surfaces, sf)
	}

	// Cookies Query
	cQuery := `
		SELECT id, assessment_id, execution_id, target_id, name, domain, path, is_secure,
		       is_http_only, same_site, max_age, expires, purpose, is_session, has_security_issue,
		       security_defects_json, source_url, created_at
		FROM assessment_auth_cookies
		WHERE assessment_id = ?
	`
	cArgs := []any{assessmentID}
	if executionID != "" {
		cQuery += " AND execution_id = ?"
		cArgs = append(cArgs, executionID)
	}
	cQuery += " ORDER BY is_session DESC, name ASC"

	cRows, err := s.db.Query(cQuery, cArgs...)
	if err != nil {
		return nil, err
	}
	defer cRows.Close()

	for cRows.Next() {
		var ck auth.CookieMetadata
		var secInt, httpOnlyInt, sessInt, hasIssueInt int
		var purposeStr, defectsJSON string

		err := cRows.Scan(
			&ck.ID, &ck.AssessmentID, &ck.ExecutionID, &ck.TargetID, &ck.Name, &ck.Domain,
			&ck.Path, &secInt, &httpOnlyInt, &ck.SameSite, &ck.MaxAge, &ck.Expires,
			&purposeStr, &sessInt, &hasIssueInt, &defectsJSON, &ck.SourceURL, &ck.CreatedAt,
		)
		if err != nil {
			return nil, err
		}

		ck.IsSecure = secInt == 1
		ck.IsHTTPOnly = httpOnlyInt == 1
		ck.IsSession = sessInt == 1
		ck.HasSecurityIssue = hasIssueInt == 1
		ck.Purpose = auth.CookiePurpose(purposeStr)
		if defectsJSON != "" {
			_ = json.Unmarshal([]byte(defectsJSON), &ck.SecurityDefects)
		}

		res.Cookies = append(res.Cookies, ck)
	}

	// Tokens Query
	tQuery := `
		SELECT id, assessment_id, execution_id, target_id, token_type, subtype, name,
		       location, format, algorithm, evidence_summary, source_asset, created_at
		FROM assessment_auth_tokens
		WHERE assessment_id = ?
	`
	tArgs := []any{assessmentID}
	if executionID != "" {
		tQuery += " AND execution_id = ?"
		tArgs = append(tArgs, executionID)
	}
	tQuery += " ORDER BY token_type ASC, name ASC"

	tRows, err := s.db.Query(tQuery, tArgs...)
	if err != nil {
		return nil, err
	}
	defer tRows.Close()

	for tRows.Next() {
		var tk auth.TokenArtifact
		var subStr string

		err := tRows.Scan(
			&tk.ID, &tk.AssessmentID, &tk.ExecutionID, &tk.TargetID, &tk.TokenType,
			&subStr, &tk.Name, &tk.Location, &tk.Format, &tk.Algorithm,
			&tk.EvidenceSummary, &tk.SourceAsset, &tk.CreatedAt,
		)
		if err != nil {
			return nil, err
		}

		tk.Subtype = auth.AuthSubtype(subStr)
		res.Tokens = append(res.Tokens, tk)
	}

	return res, nil
}

// GetAuthSummary calculates the authentication summary for an assessment.
func (s *SQLiteStore) GetAuthSummary(assessmentID string, executionID string) (*auth.AuthSummary, error) {
	inv, err := s.GetAuthInventory(assessmentID, executionID, "")
	if err != nil {
		return nil, err
	}
	engine := auth.NewEngine()
	sum := engine.GenerateSummary(*inv)
	return &sum, nil
}

// --- Authorization Intelligence Methods (Stage 4) ---

func (s *SQLiteStore) SaveAuthzPolicy(assessmentID string, policy *authz.AuthzPolicy) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if policy == nil {
		return nil
	}

	now := time.Now().UTC()
	allowWriteInt := 0
	if policy.AllowWriteTests {
		allowWriteInt = 1
	}

	safeJSON := policy.SafeMetadata()

	// Check if policy already exists
	var existingID string
	err := s.db.QueryRow("SELECT id FROM assessment_authz_policies WHERE assessment_id = ?", assessmentID).Scan(&existingID)
	if err == sql.ErrNoRows {
		// Insert
		newID := fmt.Sprintf("pol-%d", time.Now().UnixNano())
		_, err = s.db.Exec(`
			INSERT INTO assessment_authz_policies (
				id, assessment_id, authorization_doc, allow_write_tests, policy_json, created_at, updated_at
			) VALUES (?, ?, ?, ?, ?, ?, ?)
		`, newID, assessmentID, policy.AuthorizationDoc, allowWriteInt, safeJSON, now, now)
		return err
	} else if err != nil {
		return err
	}

	// Update existing
	_, err = s.db.Exec(`
		UPDATE assessment_authz_policies
		SET authorization_doc = ?, allow_write_tests = ?, policy_json = ?, updated_at = ?
		WHERE id = ?
	`, policy.AuthorizationDoc, allowWriteInt, safeJSON, now, existingID)
	return err
}

func (s *SQLiteStore) GetAuthzPolicy(assessmentID string) (*authz.AuthzPolicy, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var policyJSON string
	err := s.db.QueryRow("SELECT policy_json FROM assessment_authz_policies WHERE assessment_id = ?", assessmentID).Scan(&policyJSON)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	return authz.ParsePolicy([]byte(policyJSON))
}

func (s *SQLiteStore) SaveAuthzResults(results []authz.AuthzTestResult) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if len(results) == 0 {
		return nil
	}

	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	stmt, err := tx.Prepare(`
		INSERT INTO assessment_authz_results (
			id, test_case_id, assessment_id, execution_id, category, verification_state,
			endpoint, method, primary_identity, baseline_identity, target_resource,
			observed_status, baseline_status, disclosed_data, property_modified,
			evidence_summary, redacted_request, redacted_response, correlated_category,
			finding_id, created_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`)
	if err != nil {
		return err
	}
	defer stmt.Close()

	for _, r := range results {
		disclosedInt := 0
		if r.DisclosedData {
			disclosedInt = 1
		}
		propModInt := 0
		if r.PropertyModified {
			propModInt = 1
		}

		findingID := ""
		if r.Finding != nil {
			findingID = r.Finding.ID
		}

		now := r.CreatedAt
		if now.IsZero() {
			now = time.Now().UTC()
		}

		_, err := stmt.Exec(
			r.ID, r.TestCaseID, r.AssessmentID, r.ExecutionID, string(r.Category), string(r.VerificationState),
			r.Endpoint, r.Method, r.PrimaryIdentity, r.BaselineIdentity, r.TargetResource,
			r.ObservedStatus, r.BaselineStatus, disclosedInt, propModInt,
			r.EvidenceSummary, r.RedactedRequest, r.RedactedResponse, string(r.CorrelatedCategory),
			findingID, now,
		)
		if err != nil {
			return err
		}
	}

	return tx.Commit()
}

func (s *SQLiteStore) GetAuthzResults(assessmentID string, executionID string, category string) ([]authz.AuthzTestResult, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	query := `
		SELECT id, test_case_id, assessment_id, execution_id, category, verification_state,
		       endpoint, method, primary_identity, baseline_identity, target_resource,
		       observed_status, baseline_status, disclosed_data, property_modified,
		       evidence_summary, redacted_request, redacted_response, correlated_category,
		       finding_id, created_at
		FROM assessment_authz_results
		WHERE assessment_id = ?
	`
	args := []any{assessmentID}

	if executionID != "" {
		query += " AND execution_id = ?"
		args = append(args, executionID)
	}
	if category != "" {
		query += " AND category = ?"
		args = append(args, category)
	}

	query += " ORDER BY category ASC, endpoint ASC"

	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var results []authz.AuthzTestResult
	for rows.Next() {
		var r authz.AuthzTestResult
		var catStr, stateStr, corrCatStr, findingID string
		var disclosedInt, propModInt int

		err := rows.Scan(
			&r.ID, &r.TestCaseID, &r.AssessmentID, &r.ExecutionID, &catStr, &stateStr,
			&r.Endpoint, &r.Method, &r.PrimaryIdentity, &r.BaselineIdentity, &r.TargetResource,
			&r.ObservedStatus, &r.BaselineStatus, &disclosedInt, &propModInt,
			&r.EvidenceSummary, &r.RedactedRequest, &r.RedactedResponse, &corrCatStr,
			&findingID, &r.CreatedAt,
		)
		if err != nil {
			return nil, err
		}

		r.Category = authz.Category(catStr)
		r.VerificationState = authz.VerificationState(stateStr)
		r.CorrelatedCategory = authz.Category(corrCatStr)
		r.DisclosedData = disclosedInt == 1
		r.PropertyModified = propModInt == 1

		results = append(results, r)
	}

	return results, nil
}

func (s *SQLiteStore) GetAuthzSummary(assessmentID string, executionID string) (*authz.AuthzSummary, error) {
	results, err := s.GetAuthzResults(assessmentID, executionID, "")
	if err != nil {
		return nil, err
	}

	summary := &authz.AuthzSummary{
		TotalTests:        len(results),
		CategoryBreakdown: make(map[string]int),
		VerifiedBreakdown: make(map[string]int),
	}

	for _, r := range results {
		summary.CategoryBreakdown[string(r.Category)]++
		switch r.VerificationState {
		case authz.StateVerified:
			summary.VerifiedCount++
			summary.VerifiedBreakdown[string(r.Category)]++
		case authz.StateCandidate:
			summary.CandidateCount++
		case authz.StateInconclusive:
			summary.InconclusiveCount++
		case authz.StateNotVulnerable:
			summary.NotVulnerableCount++
		}
	}

	return summary, nil
}

// --- API Security Engine Methods (Stage 5) ---

func (s *SQLiteStore) SaveAPISecRun(record *apisec.RunRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	query := `
		INSERT INTO assessment_apisec_runs (
			id, assessment_id, execution_id, total_tests, categories_assessed,
			verified_count, candidate_count, coverage_json, created_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
	`
	now := record.CreatedAt
	if now.IsZero() {
		now = time.Now().UTC()
	}

	_, err := s.db.Exec(query,
		record.ID, record.AssessmentID, record.ExecutionID, record.TotalTests,
		record.CategoriesAssessed, record.VerifiedCount, record.CandidateCount,
		record.CoverageJSON, now,
	)
	return err
}

func (s *SQLiteStore) GetAPISecRun(assessmentID string, executionID string) (*apisec.RunRecord, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	query := `
		SELECT id, assessment_id, execution_id, total_tests, categories_assessed,
		       verified_count, candidate_count, coverage_json, created_at
		FROM assessment_apisec_runs
		WHERE assessment_id = ?
	`
	args := []any{assessmentID}
	if executionID != "" {
		query += " AND execution_id = ?"
		args = append(args, executionID)
	}
	query += " ORDER BY created_at DESC LIMIT 1"

	var rec apisec.RunRecord
	err := s.db.QueryRow(query, args...).Scan(
		&rec.ID, &rec.AssessmentID, &rec.ExecutionID, &rec.TotalTests,
		&rec.CategoriesAssessed, &rec.VerifiedCount, &rec.CandidateCount,
		&rec.CoverageJSON, &rec.CreatedAt,
	)
	if err != nil {
		return nil, err
	}
	return &rec, nil
}

func (s *SQLiteStore) SaveAPISecResults(results []apisec.Result) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	stmt, err := tx.Prepare(`
		INSERT INTO assessment_apisec_results (
			id, assessment_id, execution_id, category, owasp_code, test_name,
			endpoint, method, verification_state, severity, confidence,
			observed_status, evidence_summary, evidence_details_json, finding_id, created_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`)
	if err != nil {
		return err
	}
	defer stmt.Close()

	for _, r := range results {
		var detailsJSON string
		if len(r.EvidenceDetails) > 0 {
			b, _ := json.Marshal(r.EvidenceDetails)
			detailsJSON = string(b)
		}

		findingID := r.CorrelatedID
		if findingID == "" && r.Finding != nil {
			findingID = r.Finding.ID
		}

		now := r.CreatedAt
		if now.IsZero() {
			now = time.Now().UTC()
		}

		_, err := stmt.Exec(
			r.ID, r.AssessmentID, r.ExecutionID, string(r.Category), r.OWASPCode, r.TestName,
			r.Endpoint, r.Method, string(r.VerificationState), r.Severity, r.Confidence,
			r.ObservedStatus, r.EvidenceSummary, detailsJSON, findingID, now,
		)
		if err != nil {
			return err
		}
	}

	return tx.Commit()
}

func (s *SQLiteStore) GetAPISecResults(assessmentID string, executionID string, category string, state string) ([]apisec.Result, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	query := `
		SELECT id, assessment_id, execution_id, category, owasp_code, test_name,
		       endpoint, method, verification_state, severity, confidence,
		       observed_status, evidence_summary, evidence_details_json, finding_id, created_at
		FROM assessment_apisec_results
		WHERE assessment_id = ?
	`
	args := []any{assessmentID}
	if executionID != "" {
		query += " AND execution_id = ?"
		args = append(args, executionID)
	}
	if category != "" {
		query += " AND (category = ? OR owasp_code = ?)"
		args = append(args, category, category)
	}
	if state != "" {
		query += " AND verification_state = ?"
		args = append(args, state)
	}
	query += " ORDER BY owasp_code ASC, endpoint ASC"

	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var results []apisec.Result
	for rows.Next() {
		var r apisec.Result
		var catStr, stateStr, detailsJSON, findingID string
		var observedStatus sql.NullInt64

		err := rows.Scan(
			&r.ID, &r.AssessmentID, &r.ExecutionID, &catStr, &r.OWASPCode, &r.TestName,
			&r.Endpoint, &r.Method, &stateStr, &r.Severity, &r.Confidence,
			&observedStatus, &r.EvidenceSummary, &detailsJSON, &findingID, &r.CreatedAt,
		)
		if err != nil {
			return nil, err
		}

		if observedStatus.Valid {
			r.ObservedStatus = int(observedStatus.Int64)
		}
		r.Category = apisec.OWASPCategory(catStr)
		r.VerificationState = apisec.VerificationState(stateStr)
		r.CorrelatedID = findingID
		if detailsJSON != "" {
			_ = json.Unmarshal([]byte(detailsJSON), &r.EvidenceDetails)
		}

		results = append(results, r)
	}
	return results, nil
}

func (s *SQLiteStore) GetAPISecSummary(assessmentID string, executionID string) (*apisec.Summary, error) {
	// 1. Try to load saved RunRecord
	run, err := s.GetAPISecRun(assessmentID, executionID)
	if err == nil && run != nil && run.CoverageJSON != "" {
		var covMap map[string]apisec.CategoryCoverage
		if err := json.Unmarshal([]byte(run.CoverageJSON), &covMap); err == nil {
			obsCount := run.ObservedCount
			if obsCount == 0 {
				for _, cov := range covMap {
					obsCount += cov.Observations
				}
			}
			summary := &apisec.Summary{
				TotalTests:        run.TotalTests,
				CategoriesCovered: run.CategoriesAssessed,
				VerifiedCount:     run.VerifiedCount,
				CandidateCount:    run.CandidateCount,
				ObservedCount:     obsCount,
				CoverageMap:       covMap,
			}
			return summary, nil
		}
	}

	// 2. Fallback to computing from raw results
	results, err := s.GetAPISecResults(assessmentID, executionID, "", "")
	if err != nil {
		return nil, err
	}

	summary := &apisec.Summary{
		TotalTests:  len(results),
		CoverageMap: make(map[string]apisec.CategoryCoverage),
	}
	for _, r := range results {
		switch r.VerificationState {
		case apisec.StateVerified:
			summary.VerifiedCount++
		case apisec.StateCandidate:
			summary.CandidateCount++
		case apisec.StateObserved:
			summary.ObservedCount++
		case apisec.StateInconclusive:
			summary.InconclusiveCount++
		case apisec.StateNotVulnerable:
			summary.NotVulnerableCount++
		}
	}
	summary.CategoriesCovered = len(summary.CoverageMap)
	return summary, nil
}

// --- Web Vulnerability Engine Methods (Stage 6) ---

func (s *SQLiteStore) SaveWebVulnRun(record *webvuln.RunRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	query := `
		INSERT INTO assessment_webvuln_runs (
			id, assessment_id, execution_id, total_tests, categories_assessed,
			verified_count, candidate_count, observed_count, coverage_json, created_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`
	now := record.CreatedAt
	if now.IsZero() {
		now = time.Now().UTC()
	}

	_, err := s.db.Exec(query,
		record.ID, record.AssessmentID, record.ExecutionID, record.TotalTests,
		record.CategoriesAssessed, record.VerifiedCount, record.CandidateCount,
		record.ObservedCount, record.CoverageJSON, now,
	)
	return err
}

func (s *SQLiteStore) GetWebVulnRun(assessmentID string, executionID string) (*webvuln.RunRecord, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	query := `
		SELECT id, assessment_id, execution_id, total_tests, categories_assessed,
		       verified_count, candidate_count, observed_count, coverage_json, created_at
		FROM assessment_webvuln_runs
		WHERE assessment_id = ?
	`
	args := []any{assessmentID}
	if executionID != "" {
		query += " AND execution_id = ?"
		args = append(args, executionID)
	}
	query += " ORDER BY created_at DESC LIMIT 1"

	var rec webvuln.RunRecord
	err := s.db.QueryRow(query, args...).Scan(
		&rec.ID, &rec.AssessmentID, &rec.ExecutionID, &rec.TotalTests,
		&rec.CategoriesAssessed, &rec.VerifiedCount, &rec.CandidateCount,
		&rec.ObservedCount, &rec.CoverageJSON, &rec.CreatedAt,
	)
	if err != nil {
		return nil, err
	}
	return &rec, nil
}

func (s *SQLiteStore) SaveWebVulnResults(results []webvuln.Result) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	stmt, err := tx.Prepare(`
		INSERT INTO assessment_webvuln_results (
			id, assessment_id, execution_id, category, vuln_code, test_name,
			endpoint, method, verification_state, severity, confidence,
			observed_status, evidence_summary, evidence_details_json, finding_id, created_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`)
	if err != nil {
		return err
	}
	defer stmt.Close()

	for _, r := range results {
		var detailsJSON string
		if len(r.EvidenceDetails) > 0 {
			b, _ := json.Marshal(r.EvidenceDetails)
			detailsJSON = string(b)
		}

		findingID := r.CorrelatedID
		if findingID == "" && r.Finding != nil {
			findingID = r.Finding.ID
		}

		now := r.CreatedAt
		if now.IsZero() {
			now = time.Now().UTC()
		}

		_, err := stmt.Exec(
			r.ID, r.AssessmentID, r.ExecutionID, string(r.Category), r.VulnCode, r.TestName,
			r.Endpoint, r.Method, string(r.VerificationState), r.Severity, r.Confidence,
			r.ObservedStatus, r.EvidenceSummary, detailsJSON, findingID, now,
		)
		if err != nil {
			return err
		}
	}

	return tx.Commit()
}

func (s *SQLiteStore) GetWebVulnResults(assessmentID string, executionID string, category string, state string) ([]webvuln.Result, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	query := `
		SELECT id, assessment_id, execution_id, category, vuln_code, test_name,
		       endpoint, method, verification_state, severity, confidence,
		       observed_status, evidence_summary, evidence_details_json, finding_id, created_at
		FROM assessment_webvuln_results
		WHERE assessment_id = ?
	`
	args := []any{assessmentID}
	if executionID != "" {
		query += " AND execution_id = ?"
		args = append(args, executionID)
	}
	if category != "" {
		query += " AND (category = ? OR vuln_code = ?)"
		args = append(args, category, category)
	}
	if state != "" {
		query += " AND verification_state = ?"
		args = append(args, state)
	}
	query += " ORDER BY vuln_code ASC, endpoint ASC"

	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var results []webvuln.Result
	for rows.Next() {
		var r webvuln.Result
		var catStr, stateStr, detailsJSON, findingID string
		var observedStatus sql.NullInt64

		err := rows.Scan(
			&r.ID, &r.AssessmentID, &r.ExecutionID, &catStr, &r.VulnCode, &r.TestName,
			&r.Endpoint, &r.Method, &stateStr, &r.Severity, &r.Confidence,
			&observedStatus, &r.EvidenceSummary, &detailsJSON, &findingID, &r.CreatedAt,
		)
		if err != nil {
			return nil, err
		}

		if observedStatus.Valid {
			r.ObservedStatus = int(observedStatus.Int64)
		}
		r.Category = webvuln.VulnCategory(catStr)
		r.VerificationState = webvuln.VerificationState(stateStr)
		r.CorrelatedID = findingID
		if detailsJSON != "" {
			_ = json.Unmarshal([]byte(detailsJSON), &r.EvidenceDetails)
		}

		results = append(results, r)
	}
	return results, nil
}

func (s *SQLiteStore) GetWebVulnSummary(assessmentID string, executionID string) (*webvuln.Summary, error) {
	// 1. Try to load saved RunRecord
	run, err := s.GetWebVulnRun(assessmentID, executionID)
	if err == nil && run != nil && run.CoverageJSON != "" {
		var covMap map[string]webvuln.CategoryCoverage
		if err := json.Unmarshal([]byte(run.CoverageJSON), &covMap); err == nil {
			summary := &webvuln.Summary{
				TotalTests:        run.TotalTests,
				CategoriesCovered: run.CategoriesAssessed,
				VerifiedCount:     run.VerifiedCount,
				CandidateCount:    run.CandidateCount,
				ObservedCount:     run.ObservedCount,
				CoverageMap:       covMap,
			}
			return summary, nil
		}
	}

	// 2. Fallback to computing from raw results
	results, err := s.GetWebVulnResults(assessmentID, executionID, "", "")
	if err != nil {
		return nil, err
	}

	summary := &webvuln.Summary{
		TotalTests:  len(results),
		CoverageMap: make(map[string]webvuln.CategoryCoverage),
	}
	for _, r := range results {
		switch r.VerificationState {
		case webvuln.StateVerified:
			summary.VerifiedCount++
		case webvuln.StateCandidate:
			summary.CandidateCount++
		case webvuln.StateObserved:
			summary.ObservedCount++
		case webvuln.StateInconclusive:
			summary.InconclusiveCount++
		case webvuln.StateNotVulnerable:
			summary.NotVulnerableCount++
		}
	}
	summary.CategoriesCovered = len(summary.CoverageMap)
	return summary, nil
}

// -------------------------------------------------------------------------
// Stage 7: Session & Identity Security Engine Persistence
// -------------------------------------------------------------------------

func (s *SQLiteStore) SaveSessionSecRun(record *sessionsec.RunRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	query := `
		INSERT INTO assessment_sessionsec_runs (
			id, assessment_id, execution_id, total_tests, categories_assessed,
			verified_count, candidate_count, observed_count, inconclusive_count, blocked_count,
			coverage_json, created_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET
			total_tests = excluded.total_tests,
			categories_assessed = excluded.categories_assessed,
			verified_count = excluded.verified_count,
			candidate_count = excluded.candidate_count,
			observed_count = excluded.observed_count,
			inconclusive_count = excluded.inconclusive_count,
			blocked_count = excluded.blocked_count,
			coverage_json = excluded.coverage_json;
	`
	now := record.CreatedAt
	if now.IsZero() {
		now = time.Now().UTC()
	}

	_, err := s.db.Exec(
		query,
		record.ID, record.AssessmentID, record.ExecutionID,
		record.TotalTests, record.CategoriesAssessed,
		record.VerifiedCount, record.CandidateCount, record.ObservedCount,
		record.InconclusiveCount, record.BlockedCount,
		record.CoverageJSON, now,
	)
	return err
}

func (s *SQLiteStore) GetSessionSecRun(assessmentID string, executionID string) (*sessionsec.RunRecord, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	query := `
		SELECT id, assessment_id, execution_id, total_tests, categories_assessed,
		       verified_count, candidate_count, observed_count, inconclusive_count, blocked_count,
		       coverage_json, created_at
		FROM assessment_sessionsec_runs
		WHERE assessment_id = ?
	`
	args := []interface{}{assessmentID}
	if executionID != "" {
		query += " AND execution_id = ?"
		args = append(args, executionID)
	}
	query += " ORDER BY created_at DESC LIMIT 1"

	var rec sessionsec.RunRecord
	err := s.db.QueryRow(query, args...).Scan(
		&rec.ID, &rec.AssessmentID, &rec.ExecutionID,
		&rec.TotalTests, &rec.CategoriesAssessed,
		&rec.VerifiedCount, &rec.CandidateCount, &rec.ObservedCount,
		&rec.InconclusiveCount, &rec.BlockedCount,
		&rec.CoverageJSON, &rec.CreatedAt,
	)
	if err != nil {
		return nil, err
	}
	return &rec, nil
}

func (s *SQLiteStore) SaveSessionSecResults(results []sessionsec.Result) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	stmt, err := tx.Prepare(`
		INSERT INTO assessment_sessionsec_results (
			id, assessment_id, execution_id, category, vuln_code, test_id, test_name, wstg_ref,
			endpoint, method, verification_state, severity, confidence,
			observed_status, state_before, state_after, evidence_summary, evidence_details_json, finding_id, created_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`)
	if err != nil {
		return err
	}
	defer stmt.Close()

	for _, r := range results {
		var detailsJSON string
		if len(r.EvidenceDetails) > 0 {
			b, _ := json.Marshal(r.EvidenceDetails)
			detailsJSON = string(b)
		}

		findingID := ""
		if r.Finding != nil {
			findingID = r.Finding.ID
		}

		now := r.CreatedAt
		if now.IsZero() {
			now = time.Now().UTC()
		}

		_, err := stmt.Exec(
			r.ID, r.AssessmentID, r.ExecutionID, string(r.Category), r.VulnCode, r.TestID, r.TestName, r.WSTGRef,
			r.Endpoint, r.Method, string(r.VerificationState), r.Severity, r.Confidence,
			r.ObservedStatus, string(r.StateBefore), string(r.StateAfter), r.EvidenceSummary, detailsJSON, findingID, now,
		)
		if err != nil {
			return err
		}
	}

	return tx.Commit()
}

func (s *SQLiteStore) GetSessionSecResults(assessmentID string, executionID string, category string, state string) ([]sessionsec.Result, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	query := `
		SELECT id, assessment_id, execution_id, category, vuln_code, test_id, test_name, wstg_ref,
		       endpoint, method, verification_state, severity, confidence,
		       observed_status, state_before, state_after, evidence_summary, evidence_details_json, finding_id, created_at
		FROM assessment_sessionsec_results
		WHERE assessment_id = ?
	`
	args := []interface{}{assessmentID}

	if executionID != "" {
		query += " AND execution_id = ?"
		args = append(args, executionID)
	}
	if category != "" {
		query += " AND category = ?"
		args = append(args, category)
	}
	if state != "" {
		query += " AND verification_state = ?"
		args = append(args, state)
	}

	query += " ORDER BY created_at ASC"

	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var results []sessionsec.Result
	for rows.Next() {
		var r sessionsec.Result
		var catStr, stateStr, beforeStr, afterStr, detailsJSON, findingID sql.NullString
		var obsStatus sql.NullInt64

		err := rows.Scan(
			&r.ID, &r.AssessmentID, &r.ExecutionID, &catStr, &r.VulnCode, &r.TestID, &r.TestName, &r.WSTGRef,
			&r.Endpoint, &r.Method, &stateStr, &r.Severity, &r.Confidence,
			&obsStatus, &beforeStr, &afterStr, &r.EvidenceSummary, &detailsJSON, &findingID, &r.CreatedAt,
		)
		if err != nil {
			return nil, err
		}

		if catStr.Valid {
			r.Category = sessionsec.SessionCategory(catStr.String)
		}
		if stateStr.Valid {
			r.VerificationState = sessionsec.VerificationState(stateStr.String)
		}
		if beforeStr.Valid {
			r.StateBefore = sessionsec.SessionState(beforeStr.String)
		}
		if afterStr.Valid {
			r.StateAfter = sessionsec.SessionState(afterStr.String)
		}
		if obsStatus.Valid {
			r.ObservedStatus = int(obsStatus.Int64)
		}
		if detailsJSON.Valid && detailsJSON.String != "" {
			_ = json.Unmarshal([]byte(detailsJSON.String), &r.EvidenceDetails)
		}

		results = append(results, r)
	}
	return results, nil
}

func (s *SQLiteStore) GetSessionSecSummary(assessmentID string, executionID string) (*sessionsec.Summary, error) {
	// 1. Try to load saved RunRecord
	run, err := s.GetSessionSecRun(assessmentID, executionID)
	if err == nil && run != nil && run.CoverageJSON != "" {
		var covMap map[string]sessionsec.CategoryCoverage
		if err := json.Unmarshal([]byte(run.CoverageJSON), &covMap); err == nil {
			summary := &sessionsec.Summary{
				TotalTests:        run.TotalTests,
				CategoriesCovered: run.CategoriesAssessed,
				VerifiedCount:     run.VerifiedCount,
				CandidateCount:    run.CandidateCount,
				ObservedCount:     run.ObservedCount,
				InconclusiveCount: run.InconclusiveCount,
				BlockedCount:      run.BlockedCount,
				CoverageMap:       covMap,
			}
			return summary, nil
		}
	}

	// 2. Fallback to computing from raw results
	results, err := s.GetSessionSecResults(assessmentID, executionID, "", "")
	if err != nil {
		return nil, err
	}

	summary := &sessionsec.Summary{
		TotalTests:  len(results),
		CoverageMap: make(map[string]sessionsec.CategoryCoverage),
	}
	for _, r := range results {
		switch r.VerificationState {
		case sessionsec.StateVerified:
			summary.VerifiedCount++
		case sessionsec.StateCandidate:
			summary.CandidateCount++
		case sessionsec.StateObserved:
			summary.ObservedCount++
		case sessionsec.StateInconclusive:
			summary.InconclusiveCount++
		case sessionsec.StateNotVulnerable:
			summary.NotVulnerableCount++
		}
	}
	summary.CategoriesCovered = len(summary.CoverageMap)
	return summary, nil
}

// ============================================================================
// Cloud Security Engine (Stage 8)
// ============================================================================

func (s *SQLiteStore) SaveCloudSecRun(record *cloudsec.RunRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	query := `
		INSERT INTO assessment_cloudsec_runs (
			id, assessment_id, execution_id, mode, provider,
			scope_identifier, verified_principal,
			total_checks, services_assessed,
			verified_count, candidate_count, observed_count,
			coverage_json, created_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET
			total_checks = excluded.total_checks,
			services_assessed = excluded.services_assessed,
			verified_count = excluded.verified_count,
			candidate_count = excluded.candidate_count,
			observed_count = excluded.observed_count,
			coverage_json = excluded.coverage_json;
	`
	now := record.CreatedAt
	if now.IsZero() {
		now = time.Now().UTC()
	}

	_, err := s.db.Exec(
		query,
		record.ID, record.AssessmentID, record.ExecutionID,
		string(record.Mode), string(record.Provider),
		record.ScopeIdentifier, record.VerifiedPrincipal,
		record.TotalChecks, record.ServicesAssessed,
		record.VerifiedCount, record.CandidateCount, record.ObservedCount,
		record.CoverageJSON, now,
	)
	return err
}

func (s *SQLiteStore) GetCloudSecRun(assessmentID string, executionID string) (*cloudsec.RunRecord, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	query := `
		SELECT id, assessment_id, execution_id, mode, provider,
		       scope_identifier, verified_principal,
		       total_checks, services_assessed,
		       verified_count, candidate_count, observed_count,
		       coverage_json, created_at
		FROM assessment_cloudsec_runs
		WHERE assessment_id = ?
	`
	args := []interface{}{assessmentID}
	if executionID != "" {
		query += " AND execution_id = ?"
		args = append(args, executionID)
	}
	query += " ORDER BY created_at DESC LIMIT 1"

	var rec cloudsec.RunRecord
	var modeStr, provStr string
	var princ sql.NullString
	err := s.db.QueryRow(query, args...).Scan(
		&rec.ID, &rec.AssessmentID, &rec.ExecutionID, &modeStr, &provStr,
		&rec.ScopeIdentifier, &princ,
		&rec.TotalChecks, &rec.ServicesAssessed,
		&rec.VerifiedCount, &rec.CandidateCount, &rec.ObservedCount,
		&rec.CoverageJSON, &rec.CreatedAt,
	)
	if err != nil {
		return nil, err
	}
	rec.Mode = cloudsec.AssessmentMode(modeStr)
	rec.Provider = cloudsec.Provider(provStr)
	if princ.Valid {
		rec.VerifiedPrincipal = princ.String
	}
	return &rec, nil
}

func (s *SQLiteStore) SaveCloudSecResults(results []cloudsec.Result) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	stmt, err := tx.Prepare(`
		INSERT INTO assessment_cloudsec_results (
			id, assessment_id, execution_id, provider, mode, service, check_id, check_name,
			resource_id, region, verification_state, severity, confidence,
			evidence_summary, evidence_details_json, finding_id, created_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`)
	if err != nil {
		return err
	}
	defer stmt.Close()

	for _, r := range results {
		var detailsJSON string
		if len(r.EvidenceDetails) > 0 {
			b, _ := json.Marshal(r.EvidenceDetails)
			detailsJSON = string(b)
		}

		findingID := ""
		if r.Finding != nil {
			findingID = r.Finding.ID
		}

		now := r.CreatedAt
		if now.IsZero() {
			now = time.Now().UTC()
		}

		_, err := stmt.Exec(
			r.ID, r.AssessmentID, r.ExecutionID, string(r.Provider), string(r.Mode), r.Service, r.CheckID, r.CheckName,
			r.ResourceID, r.Region, string(r.VerificationState), r.Severity, r.Confidence,
			r.EvidenceSummary, detailsJSON, findingID, now,
		)
		if err != nil {
			return err
		}
	}

	return tx.Commit()
}

func (s *SQLiteStore) GetCloudSecResults(assessmentID string, executionID string, provider string, service string, state string) ([]cloudsec.Result, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	query := `
		SELECT id, assessment_id, execution_id, provider, mode, service, check_id, check_name,
		       resource_id, region, verification_state, severity, confidence,
		       evidence_summary, evidence_details_json, finding_id, created_at
		FROM assessment_cloudsec_results
		WHERE assessment_id = ?
	`
	args := []interface{}{assessmentID}

	if executionID != "" {
		query += " AND execution_id = ?"
		args = append(args, executionID)
	}
	if provider != "" {
		query += " AND provider = ?"
		args = append(args, provider)
	}
	if service != "" {
		query += " AND service = ?"
		args = append(args, service)
	}
	if state != "" {
		query += " AND verification_state = ?"
		args = append(args, state)
	}

	query += " ORDER BY created_at ASC"

	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var results []cloudsec.Result
	for rows.Next() {
		var r cloudsec.Result
		var provStr, modeStr, stateStr, regionStr, detailsJSON, findingID sql.NullString

		err := rows.Scan(
			&r.ID, &r.AssessmentID, &r.ExecutionID, &provStr, &modeStr, &r.Service, &r.CheckID, &r.CheckName,
			&r.ResourceID, &regionStr, &stateStr, &r.Severity, &r.Confidence,
			&r.EvidenceSummary, &detailsJSON, &findingID, &r.CreatedAt,
		)
		if err != nil {
			return nil, err
		}

		if provStr.Valid {
			r.Provider = cloudsec.Provider(provStr.String)
		}
		if modeStr.Valid {
			r.Mode = cloudsec.AssessmentMode(modeStr.String)
		}
		if regionStr.Valid {
			r.Region = regionStr.String
		}
		if stateStr.Valid {
			r.VerificationState = cloudsec.VerificationState(stateStr.String)
		}
		if detailsJSON.Valid && detailsJSON.String != "" {
			_ = json.Unmarshal([]byte(detailsJSON.String), &r.EvidenceDetails)
		}

		results = append(results, r)
	}
	return results, nil
}

func (s *SQLiteStore) GetCloudSecSummary(assessmentID string, executionID string) (*cloudsec.Summary, error) {
	// 1. Try to load saved RunRecord
	run, err := s.GetCloudSecRun(assessmentID, executionID)
	if err == nil && run != nil && run.CoverageJSON != "" {
		var covMap map[string]cloudsec.ServiceCoverage
		if err := json.Unmarshal([]byte(run.CoverageJSON), &covMap); err == nil {
			summary := &cloudsec.Summary{
				Mode:               run.Mode,
				Provider:           run.Provider,
				TargetScope:        run.ScopeIdentifier,
				VerifiedPrincipal:  run.VerifiedPrincipal,
				SyntheticFixture:   run.SyntheticFixture,
				TotalChecks:        run.TotalChecks,
				ServicesAssessed:   run.ServicesAssessed,
				VerifiedCount:      run.VerifiedCount,
				CandidateCount:     run.CandidateCount,
				ObservedCount:      run.ObservedCount,
				ServiceCoverageMap: covMap,
			}
			for _, cov := range covMap {
				summary.InconclusiveCount += cov.Inconclusive
				summary.NotVulnerableCount += cov.NotVulnerable
				summary.BlockedCount += cov.Blocked
			}
			return summary, nil
		}
	}

	// 2. Fallback to computing from raw results
	results, err := s.GetCloudSecResults(assessmentID, executionID, "", "", "")
	if err != nil {
		return nil, err
	}

	summary := &cloudsec.Summary{
		TotalChecks:        len(results),
		ServiceCoverageMap: make(map[string]cloudsec.ServiceCoverage),
	}
	for _, r := range results {
		summary.Mode = r.Mode
		summary.Provider = r.Provider

		cov := summary.ServiceCoverageMap[r.Service]
		cov.Provider = r.Provider
		cov.Service = r.Service
		cov.ChecksRun++

		switch r.VerificationState {
		case cloudsec.StateVerified:
			summary.VerifiedCount++
			cov.Verified++
		case cloudsec.StateCandidate:
			summary.CandidateCount++
			cov.Candidates++
		case cloudsec.StateObserved:
			summary.ObservedCount++
			cov.Observations++
		case cloudsec.StateInconclusive:
			summary.InconclusiveCount++
			cov.Inconclusive++
		case cloudsec.StateNotVulnerable:
			summary.NotVulnerableCount++
			cov.NotVulnerable++
		}
		summary.ServiceCoverageMap[r.Service] = cov
	}
	summary.ServicesAssessed = len(summary.ServiceCoverageMap)
	return summary, nil
}

// ============================================================================
// Business Logic Security Engine (Stage 9)
// ============================================================================

func (s *SQLiteStore) SaveBusinessLogicRun(record *businesslogic.RunRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	query := `
		INSERT INTO assessment_businesslogic_runs (
			id, assessment_id, execution_id, target_url,
			total_checks, categories_assessed, workflows_modeled,
			verified_count, candidate_count, observed_count,
			inconclusive_count, blocked_count, not_vulnerable_count,
			synthetic_fixture, coverage_json, created_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`
	_, err := s.db.Exec(
		query,
		record.ID,
		record.AssessmentID,
		record.ExecutionID,
		record.TargetURL,
		record.TotalChecks,
		record.CategoriesAssessed,
		record.WorkflowsModeled,
		record.VerifiedCount,
		record.CandidateCount,
		record.ObservedCount,
		record.InconclusiveCount,
		record.BlockedCount,
		record.NotVulnerableCount,
		record.SyntheticFixture,
		record.CoverageJSON,
		record.CreatedAt,
	)
	return err
}

func (s *SQLiteStore) GetBusinessLogicRun(assessmentID string, executionID string) (*businesslogic.RunRecord, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	query := `
		SELECT id, assessment_id, execution_id, target_url,
		       total_checks, categories_assessed, workflows_modeled,
		       verified_count, candidate_count, observed_count,
		       inconclusive_count, blocked_count, not_vulnerable_count,
		       synthetic_fixture, coverage_json, created_at
		FROM assessment_businesslogic_runs
		WHERE assessment_id = ?
	`
	args := []interface{}{assessmentID}
	if executionID != "" {
		query += " AND execution_id = ?"
		args = append(args, executionID)
	}
	query += " ORDER BY created_at DESC LIMIT 1"

	var rec businesslogic.RunRecord
	err := s.db.QueryRow(query, args...).Scan(
		&rec.ID,
		&rec.AssessmentID,
		&rec.ExecutionID,
		&rec.TargetURL,
		&rec.TotalChecks,
		&rec.CategoriesAssessed,
		&rec.WorkflowsModeled,
		&rec.VerifiedCount,
		&rec.CandidateCount,
		&rec.ObservedCount,
		&rec.InconclusiveCount,
		&rec.BlockedCount,
		&rec.NotVulnerableCount,
		&rec.SyntheticFixture,
		&rec.CoverageJSON,
		&rec.CreatedAt,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &rec, nil
}

func (s *SQLiteStore) SaveBusinessLogicResults(results []businesslogic.Result) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	stmt, err := tx.Prepare(`
		INSERT INTO assessment_businesslogic_results (
			id, assessment_id, execution_id, category, check_id, check_name,
			workflow_id, workflow_name, endpoint, method,
			verification_state, severity, confidence,
			observed_status, state_before, state_after,
			evidence_summary, evidence_details_json, finding_id, created_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`)
	if err != nil {
		return err
	}
	defer stmt.Close()

	for _, r := range results {
		var detailsJSON string
		if len(r.EvidenceDetails) > 0 {
			b, _ := json.Marshal(r.EvidenceDetails)
			detailsJSON = string(b)
		}
		var findingID string
		if r.Finding != nil {
			findingID = r.Finding.ID
		}

		_, err := stmt.Exec(
			r.ID,
			r.AssessmentID,
			r.ExecutionID,
			string(r.Category),
			r.CheckID,
			r.CheckName,
			r.WorkflowID,
			r.WorkflowName,
			r.Endpoint,
			r.Method,
			string(r.VerificationState),
			r.Severity,
			r.Confidence,
			r.ObservedStatus,
			r.StateBefore,
			r.StateAfter,
			r.EvidenceSummary,
			detailsJSON,
			findingID,
			r.CreatedAt,
		)
		if err != nil {
			return err
		}
	}

	return tx.Commit()
}

func (s *SQLiteStore) GetBusinessLogicResults(assessmentID string, executionID string, category string, state string) ([]businesslogic.Result, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	query := `
		SELECT id, assessment_id, execution_id, category, check_id, check_name,
		       workflow_id, workflow_name, endpoint, method,
		       verification_state, severity, confidence,
		       observed_status, state_before, state_after,
		       evidence_summary, evidence_details_json, finding_id, created_at
		FROM assessment_businesslogic_results
		WHERE assessment_id = ?
	`
	args := []interface{}{assessmentID}
	if executionID != "" {
		query += " AND execution_id = ?"
		args = append(args, executionID)
	}
	if category != "" {
		query += " AND category = ?"
		args = append(args, category)
	}
	if state != "" {
		query += " AND verification_state = ?"
		args = append(args, state)
	}
	query += " ORDER BY created_at ASC"

	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var results []businesslogic.Result
	for rows.Next() {
		var r businesslogic.Result
		var catStr, stateStr, detailsJSON, findingID sql.NullString
		var stateBefore, stateAfter sql.NullString

		err := rows.Scan(
			&r.ID,
			&r.AssessmentID,
			&r.ExecutionID,
			&catStr,
			&r.CheckID,
			&r.CheckName,
			&r.WorkflowID,
			&r.WorkflowName,
			&r.Endpoint,
			&r.Method,
			&stateStr,
			&r.Severity,
			&r.Confidence,
			&r.ObservedStatus,
			&stateBefore,
			&stateAfter,
			&r.EvidenceSummary,
			&detailsJSON,
			&findingID,
			&r.CreatedAt,
		)
		if err != nil {
			return nil, err
		}

		if catStr.Valid {
			r.Category = businesslogic.BLCategory(catStr.String)
		}
		if stateStr.Valid {
			r.VerificationState = businesslogic.VerificationState(stateStr.String)
		}
		if stateBefore.Valid {
			r.StateBefore = stateBefore.String
		}
		if stateAfter.Valid {
			r.StateAfter = stateAfter.String
		}
		if detailsJSON.Valid && detailsJSON.String != "" {
			var details map[string]string
			if err := json.Unmarshal([]byte(detailsJSON.String), &details); err == nil {
				r.EvidenceDetails = details
			}
		}

		results = append(results, r)
	}

	return results, nil
}

func (s *SQLiteStore) GetBusinessLogicSummary(assessmentID string, executionID string) (*businesslogic.Summary, error) {
	// 1. Try to load saved RunRecord
	run, err := s.GetBusinessLogicRun(assessmentID, executionID)
	if err == nil && run != nil && run.CoverageJSON != "" {
		var covMap map[string]businesslogic.CategoryCoverage
		if err := json.Unmarshal([]byte(run.CoverageJSON), &covMap); err == nil {
			summary := &businesslogic.Summary{
				TargetURL:           run.TargetURL,
				TotalChecks:         run.TotalChecks,
				CategoriesAssessed:  run.CategoriesAssessed,
				WorkflowsModeled:    run.WorkflowsModeled,
				VerifiedCount:      run.VerifiedCount,
				CandidateCount:     run.CandidateCount,
				ObservedCount:      run.ObservedCount,
				InconclusiveCount:  run.InconclusiveCount,
				BlockedCount:       run.BlockedCount,
				NotVulnerableCount: run.NotVulnerableCount,
				SyntheticFixture:   run.SyntheticFixture,
				CategoryCoverageMap: covMap,
			}
			return summary, nil
		}
	}

	// 2. Fallback to computing from raw results
	results, err := s.GetBusinessLogicResults(assessmentID, executionID, "", "")
	if err != nil {
		return nil, err
	}

	summary := &businesslogic.Summary{
		TotalChecks:         len(results),
		CategoryCoverageMap: make(map[string]businesslogic.CategoryCoverage),
	}
	for _, r := range results {
		catKey := string(r.Category)
		cov := summary.CategoryCoverageMap[catKey]
		cov.Category = r.Category
		cov.ChecksRun++

		switch r.VerificationState {
		case businesslogic.StateVerified:
			summary.VerifiedCount++
			cov.Verified++
		case businesslogic.StateCandidate:
			summary.CandidateCount++
			cov.Candidates++
		case businesslogic.StateObserved:
			summary.ObservedCount++
			cov.Observations++
		case businesslogic.StateInconclusive:
			summary.InconclusiveCount++
			cov.Inconclusive++
		case businesslogic.StateBlockedBySafety:
			summary.BlockedCount++
			cov.Blocked++
		case businesslogic.StateNotVulnerable:
			summary.NotVulnerableCount++
			cov.NotVulnerable++
		}
		summary.CategoryCoverageMap[catKey] = cov
	}
	summary.CategoriesAssessed = len(summary.CategoryCoverageMap)
	return summary, nil
}

// --- Correlation & Attack Path Engine Methods (Stage 10) ---

func (s *SQLiteStore) SaveCorrelationRun(record *correlation.RunRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	query := `
		INSERT INTO assessment_correlation_runs (
			id, assessment_id, execution_id, total_findings,
			candidate_relationships, candidate_paths, verified_paths,
			highest_risk, coverage_json, synthetic_fixture, created_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET
			total_findings = excluded.total_findings,
			candidate_relationships = excluded.candidate_relationships,
			candidate_paths = excluded.candidate_paths,
			verified_paths = excluded.verified_paths,
			highest_risk = excluded.highest_risk,
			coverage_json = excluded.coverage_json,
			synthetic_fixture = excluded.synthetic_fixture,
			created_at = excluded.created_at
	`
	_, err := s.db.Exec(
		query,
		record.ID,
		record.AssessmentID,
		record.ExecutionID,
		record.TotalFindings,
		record.CandidateRelationships,
		record.CandidatePaths,
		record.VerifiedPaths,
		record.HighestRisk,
		record.CoverageJSON,
		record.SyntheticFixture,
		record.CreatedAt,
	)
	return err
}

func (s *SQLiteStore) GetCorrelationRun(assessmentID string, executionID string) (*correlation.RunRecord, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	query := `
		SELECT id, assessment_id, execution_id, total_findings,
		       candidate_relationships, candidate_paths, verified_paths,
		       highest_risk, coverage_json, synthetic_fixture, created_at
		FROM assessment_correlation_runs
		WHERE assessment_id = ?
	`
	args := []interface{}{assessmentID}
	if executionID != "" {
		query += " AND execution_id = ?"
		args = append(args, executionID)
	}
	query += " ORDER BY created_at DESC LIMIT 1"

	var rec correlation.RunRecord
	err := s.db.QueryRow(query, args...).Scan(
		&rec.ID,
		&rec.AssessmentID,
		&rec.ExecutionID,
		&rec.TotalFindings,
		&rec.CandidateRelationships,
		&rec.CandidatePaths,
		&rec.VerifiedPaths,
		&rec.HighestRisk,
		&rec.CoverageJSON,
		&rec.SyntheticFixture,
		&rec.CreatedAt,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &rec, nil
}

func (s *SQLiteStore) SaveAttackPaths(assessmentID string, executionID string, paths []correlation.AttackPath) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	stmt, err := tx.Prepare(`
		INSERT INTO assessment_attack_paths (
			id, assessment_id, execution_id, title, entry_point, target_asset,
			primary_weakness, terminal_impact, status, confidence,
			combined_risk_level, combined_risk_score, risk_rationale,
			node_ids_json, nodes_json, edges_json, security_story_json,
			remediation, synthetic_fixture, created_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET
			title = excluded.title,
			entry_point = excluded.entry_point,
			target_asset = excluded.target_asset,
			primary_weakness = excluded.primary_weakness,
			terminal_impact = excluded.terminal_impact,
			status = excluded.status,
			confidence = excluded.confidence,
			combined_risk_level = excluded.combined_risk_level,
			combined_risk_score = excluded.combined_risk_score,
			risk_rationale = excluded.risk_rationale,
			node_ids_json = excluded.node_ids_json,
			nodes_json = excluded.nodes_json,
			edges_json = excluded.edges_json,
			security_story_json = excluded.security_story_json,
			remediation = excluded.remediation,
			synthetic_fixture = excluded.synthetic_fixture,
			created_at = excluded.created_at
	`)
	if err != nil {
		return err
	}
	defer stmt.Close()

	for _, p := range paths {
		nodeIDsJSON, _ := json.Marshal(p.NodeIDs)
		nodesJSON, _ := json.Marshal(p.Nodes)
		edgesJSON, _ := json.Marshal(p.Edges)
		storyJSON, _ := json.Marshal(p.SecurityStory)

		createdAt := p.CreatedAt
		if createdAt.IsZero() {
			createdAt = time.Now()
		}

		dbID := p.ID
		if executionID != "" && !strings.Contains(dbID, executionID) {
			suffix := executionID
			if len(suffix) > 8 {
				suffix = suffix[:8]
			}
			dbID = fmt.Sprintf("%s-%s", p.ID, suffix)
		}

		_, err := stmt.Exec(
			dbID,
			assessmentID,
			executionID,
			p.Title,
			p.EntryPoint,
			p.TargetAsset,
			p.PrimaryWeakness,
			p.TerminalImpact,
			string(p.Status),
			p.Confidence,
			p.CombinedRiskLevel,
			p.CombinedRiskScore,
			p.RiskRationale,
			string(nodeIDsJSON),
			string(nodesJSON),
			string(edgesJSON),
			string(storyJSON),
			p.Remediation,
			p.SyntheticFixture,
			createdAt,
		)
		if err != nil {
			return err
		}
	}

	return tx.Commit()
}

func (s *SQLiteStore) GetAttackPaths(assessmentID string, executionID string, status string, minRisk string) ([]correlation.AttackPath, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	query := `
		SELECT id, assessment_id, execution_id, title, entry_point, target_asset,
		       primary_weakness, terminal_impact, status, confidence,
		       combined_risk_level, combined_risk_score, risk_rationale,
		       node_ids_json, nodes_json, edges_json, security_story_json,
		       remediation, synthetic_fixture, created_at
		FROM assessment_attack_paths
		WHERE assessment_id = ?
	`
	args := []interface{}{assessmentID}
	if executionID != "" {
		query += " AND execution_id = ?"
		args = append(args, executionID)
	}
	if status != "" {
		query += " AND status = ?"
		args = append(args, status)
	}
	if minRisk != "" {
		switch strings.ToUpper(minRisk) {
		case "CRITICAL":
			query += " AND combined_risk_level = 'CRITICAL'"
		case "HIGH":
			query += " AND combined_risk_level IN ('CRITICAL', 'HIGH')"
		case "MEDIUM":
			query += " AND combined_risk_level IN ('CRITICAL', 'HIGH', 'MEDIUM')"
		}
	}
	query += " ORDER BY combined_risk_score DESC, created_at ASC"

	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var paths []correlation.AttackPath
	for rows.Next() {
		var p correlation.AttackPath
		var asmID, execID, entryPoint, rationale sql.NullString
		var statusStr string
		var nodeIDsJSON, nodesJSON, edgesJSON, storyJSON sql.NullString

		err := rows.Scan(
			&p.ID,
			&asmID,
			&execID,
			&p.Title,
			&entryPoint,
			&p.TargetAsset,
			&p.PrimaryWeakness,
			&p.TerminalImpact,
			&statusStr,
			&p.Confidence,
			&p.CombinedRiskLevel,
			&p.CombinedRiskScore,
			&rationale,
			&nodeIDsJSON,
			&nodesJSON,
			&edgesJSON,
			&storyJSON,
			&p.Remediation,
			&p.SyntheticFixture,
			&p.CreatedAt,
		)
		if err != nil {
			return nil, err
		}

		p.Status = correlation.PathStatus(statusStr)
		if entryPoint.Valid {
			p.EntryPoint = entryPoint.String
		}
		if rationale.Valid {
			p.RiskRationale = rationale.String
		}
		if nodeIDsJSON.Valid && nodeIDsJSON.String != "" {
			_ = json.Unmarshal([]byte(nodeIDsJSON.String), &p.NodeIDs)
		}
		if nodesJSON.Valid && nodesJSON.String != "" {
			_ = json.Unmarshal([]byte(nodesJSON.String), &p.Nodes)
		}
		if edgesJSON.Valid && edgesJSON.String != "" {
			_ = json.Unmarshal([]byte(edgesJSON.String), &p.Edges)
		}
		if storyJSON.Valid && storyJSON.String != "" {
			_ = json.Unmarshal([]byte(storyJSON.String), &p.SecurityStory)
		}

		paths = append(paths, p)
	}

	return paths, nil
}

func (s *SQLiteStore) GetCorrelationSummary(assessmentID string, executionID string) (*correlation.Summary, error) {
	run, err := s.GetCorrelationRun(assessmentID, executionID)
	if err == nil && run != nil && run.CoverageJSON != "" {
		var sum correlation.Summary
		if err := json.Unmarshal([]byte(run.CoverageJSON), &sum); err == nil {
			return &sum, nil
		}
	}

	paths, err := s.GetAttackPaths(assessmentID, executionID, "", "")
	if err != nil {
		return nil, err
	}

	sum := &correlation.Summary{
		CandidatePaths: len(paths),
		RuleStats:      make(map[string]correlation.RuleCoverageStat),
		AffectedAssets: make([]string, 0),
	}

	assetMap := make(map[string]bool)
	maxScore := 0
	highestRisk := report.SeverityInfo

	for _, p := range paths {
		if p.TargetAsset != "" && !assetMap[p.TargetAsset] {
			assetMap[p.TargetAsset] = true
			sum.AffectedAssets = append(sum.AffectedAssets, p.TargetAsset)
		}
		switch p.Status {
		case correlation.PathVerified:
			sum.VerifiedPaths++
		case correlation.PathCandidate:
			// candidate paths
		case correlation.PathInconclusive:
			sum.InconclusivePaths++
		case correlation.PathObserved:
			sum.ObservedPaths++
		}
		if p.CombinedRiskScore > maxScore {
			maxScore = p.CombinedRiskScore
			highestRisk = p.CombinedRiskLevel
		}
		for _, e := range p.Edges {
			codeStr := string(e.RuleCode)
			st := sum.RuleStats[codeStr]
			st.Code = e.RuleCode
			st.PathsGenerated++
			sum.RuleStats[codeStr] = st
		}
	}

	sum.HighestRiskScore = maxScore
	sum.HighestRiskLevel = highestRisk

	return sum, nil
}

// --- Verification Engine 2.0 Store Methods (Stage 11) ---

func (s *SQLiteStore) SaveVerificationRun(run *verification.VerificationRunRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	query := `
		INSERT OR REPLACE INTO assessment_verification_runs (
			id, assessment_id, execution_id, total_findings,
			attempted_count, verified_count, detected_count, observed_count,
			not_verified_count, not_exposed_count, blocked_count, inconclusive_count,
			synthetic_count, coverage_json, verifier_version, created_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`
	_, err := s.db.Exec(query,
		run.ID, run.AssessmentID, run.ExecutionID, run.TotalFindings,
		run.AttemptedCount, run.VerifiedCount, run.DetectedCount, run.ObservedCount,
		run.NotVerifiedCount, run.NotExposedCount, run.BlockedCount, run.InconclusiveCount,
		run.SyntheticCount, run.CoverageJSON, run.VerifierVersion, run.CreatedAt,
	)
	return err
}

func (s *SQLiteStore) GetVerificationRun(assessmentID string, executionID string) (*verification.VerificationRunRecord, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var run verification.VerificationRunRecord
	query := `
		SELECT id, assessment_id, execution_id, total_findings,
		       attempted_count, verified_count, detected_count, observed_count,
		       not_verified_count, not_exposed_count, blocked_count, inconclusive_count,
		       synthetic_count, coverage_json, verifier_version, created_at
		FROM assessment_verification_runs
		WHERE assessment_id = ? AND execution_id = ?
		ORDER BY created_at DESC LIMIT 1
	`
	err := s.db.QueryRow(query, assessmentID, executionID).Scan(
		&run.ID, &run.AssessmentID, &run.ExecutionID, &run.TotalFindings,
		&run.AttemptedCount, &run.VerifiedCount, &run.DetectedCount, &run.ObservedCount,
		&run.NotVerifiedCount, &run.NotExposedCount, &run.BlockedCount, &run.InconclusiveCount,
		&run.SyntheticCount, &run.CoverageJSON, &run.VerifierVersion, &run.CreatedAt,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	return &run, nil
}

func (s *SQLiteStore) SaveVerificationResults(assessmentID string, executionID string, results []verification.VerificationResult) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	// Clear previous results for this execution to support reruns
	_, _ = tx.Exec("DELETE FROM assessment_verification_results WHERE assessment_id = ? AND execution_id = ?", assessmentID, executionID)

	stmt, err := tx.Prepare(`
		INSERT INTO assessment_verification_results (
			id, assessment_id, execution_id, finding_id, status,
			policy_id, verification_method, attempted,
			detection_confidence, verification_confidence, overall_confidence,
			confidence_score, confidence_rationale, reproduction_json,
			criteria_results_json, limitations_json, safety_decision,
			block_reason, failure_reason, inconclusive_reason,
			synthetic_fixture, created_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`)
	if err != nil {
		return err
	}
	defer stmt.Close()

	for _, r := range results {
		reproJSON, _ := json.Marshal(r.Reproduction)
		critJSON, _ := json.Marshal(r.CriteriaResults)
		limJSON, _ := json.Marshal(r.Limitations)

		_, err := stmt.Exec(
			r.ID, assessmentID, executionID, r.FindingID, string(r.Status),
			r.PolicyID, r.VerificationMethod, boolToInt(r.Attempted),
			r.DetectionConfidence, r.VerificationConfidence, r.OverallConfidence,
			r.ConfidenceScore, r.ConfidenceRationale, string(reproJSON),
			string(critJSON), string(limJSON), r.SafetyDecision,
			r.BlockReason, r.FailureReason, r.InconclusiveReason,
			boolToInt(r.SyntheticFixture), r.CompletedAt,
		)
		if err != nil {
			return err
		}
	}

	return tx.Commit()
}

func (s *SQLiteStore) GetVerificationResults(assessmentID string, executionID string, status string) ([]verification.VerificationResult, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	query := `
		SELECT id, assessment_id, execution_id, finding_id, status,
		       policy_id, verification_method, attempted,
		       detection_confidence, verification_confidence, overall_confidence,
		       confidence_score, confidence_rationale, reproduction_json,
		       criteria_results_json, limitations_json, safety_decision,
		       block_reason, failure_reason, inconclusive_reason,
		       synthetic_fixture, created_at
		FROM assessment_verification_results
		WHERE assessment_id = ? AND execution_id = ?
	`
	args := []any{assessmentID, executionID}
	if status != "" {
		query += " AND status = ?"
		args = append(args, strings.ToUpper(status))
	}
	query += " ORDER BY created_at ASC"

	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var results []verification.VerificationResult
	for rows.Next() {
		var r verification.VerificationResult
		var statusStr string
		var attemptedInt int
		var synthInt int
		var confRat, reproJSON, critJSON, limJSON sql.NullString
		var safetyDec, blockReason, failReason, inconcReason sql.NullString

		err := rows.Scan(
			&r.ID, &r.AssessmentID, &r.ExecutionID, &r.FindingID, &statusStr,
			&r.PolicyID, &r.VerificationMethod, &attemptedInt,
			&r.DetectionConfidence, &r.VerificationConfidence, &r.OverallConfidence,
			&r.ConfidenceScore, &confRat, &reproJSON,
			&critJSON, &limJSON, &safetyDec,
			&blockReason, &failReason, &inconcReason,
			&synthInt, &r.CompletedAt,
		)
		if err != nil {
			return nil, err
		}

		r.Status = report.VerificationStatus(statusStr)
		r.Attempted = attemptedInt == 1
		r.SyntheticFixture = synthInt == 1
		if confRat.Valid {
			r.ConfidenceRationale = confRat.String
		}
		if reproJSON.Valid && reproJSON.String != "" {
			_ = json.Unmarshal([]byte(reproJSON.String), &r.Reproduction)
		}
		if critJSON.Valid && critJSON.String != "" {
			_ = json.Unmarshal([]byte(critJSON.String), &r.CriteriaResults)
		}
		if limJSON.Valid && limJSON.String != "" {
			_ = json.Unmarshal([]byte(limJSON.String), &r.Limitations)
		}
		if safetyDec.Valid {
			r.SafetyDecision = safetyDec.String
		}
		if blockReason.Valid {
			r.BlockReason = blockReason.String
		}
		if failReason.Valid {
			r.FailureReason = failReason.String
		}
		if inconcReason.Valid {
			r.InconclusiveReason = inconcReason.String
		}

		results = append(results, r)
	}

	return results, nil
}

func (s *SQLiteStore) GetVerificationSummary(assessmentID string, executionID string) (*verification.VerificationSummary, error) {
	run, err := s.GetVerificationRun(assessmentID, executionID)
	if err == nil && run != nil && run.CoverageJSON != "" {
		var sum verification.VerificationSummary
		if err := json.Unmarshal([]byte(run.CoverageJSON), &sum); err == nil {
			return &sum, nil
		}
	}

	results, err := s.GetVerificationResults(assessmentID, executionID, "")
	if err != nil {
		return nil, err
	}

	sum := &verification.VerificationSummary{
		TotalFindings: len(results),
		CategoryStats: make(map[string]verification.CategoryVerificationStat),
	}

	for _, r := range results {
		if r.Attempted {
			sum.AttemptedCount++
		}
		if r.SyntheticFixture {
			sum.SyntheticCount++
		}
		if r.SafetyDecision == verification.DecisionBlocked {
			sum.BlockedCount++
		}
		if r.InconclusiveReason != "" {
			sum.InconclusiveCount++
		}

		switch r.Status {
		case verification.StatusVerified:
			sum.VerifiedCount++
		case verification.StatusDetected:
			sum.DetectedCount++
		case verification.StatusObserved:
			sum.ObservedCount++
		case verification.StatusNotVerified:
			sum.NotVerifiedCount++
		case verification.StatusNotExposed:
			sum.NotExposedCount++
		}
	}

	if sum.AttemptedCount > 0 {
		sum.VerificationRateAttempted = float64(sum.VerifiedCount) / float64(sum.AttemptedCount) * 100.0
	}
	if sum.TotalFindings > 0 {
		sum.VerificationRateTotal = float64(sum.VerifiedCount) / float64(sum.TotalFindings) * 100.0
	}

	return sum, nil
}
