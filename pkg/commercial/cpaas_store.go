package commercial

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

	_ "modernc.org/sqlite"
)

var (
	ErrScheduleNotFound   = errors.New("cpaas: schedule not found")
	ErrExecutionNotFound  = errors.New("cpaas: execution not found")
	ErrDuplicateExecution = errors.New("cpaas: duplicate execution for scheduled period")
	ErrStoreClosed        = errors.New("cpaas: store is closed")
)

// CPaaSStore manages persistent SQLite storage for CPaaS schedules, executions, drift reports, and alert logs.
type CPaaSStore struct {
	db     *sql.DB
	dbPath string
	mu     sync.RWMutex
	closed bool
}

// NewCPaaSStore creates or opens an SQLite database for CPaaS operations.
func NewCPaaSStore(dbPath string) (*CPaaSStore, error) {
	if dbPath != ":memory:" && !strings.HasPrefix(dbPath, "file:") {
		dir := filepath.Dir(dbPath)
		if err := os.MkdirAll(dir, 0750); err != nil {
			return nil, fmt.Errorf("cpaas: failed creating database directory: %w", err)
		}
	}

	dsn := dbPath
	if dbPath != ":memory:" && !strings.Contains(dbPath, "?") {
		dsn = fmt.Sprintf("%s?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=synchronous(NORMAL)&_pragma=foreign_keys(ON)", dbPath)
	}

	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("cpaas: failed opening sqlite database: %w", err)
	}

	// Optimize connection pool
	if dbPath == ":memory:" {
		db.SetMaxOpenConns(1) // in-memory must share single connection
	} else {
		db.SetMaxOpenConns(10)
		db.SetMaxIdleConns(5)
		db.SetConnMaxLifetime(time.Hour)
	}

	store := &CPaaSStore{
		db:     db,
		dbPath: dbPath,
	}

	if err := store.migrate(); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("cpaas: migration failed: %w", err)
	}

	return store, nil
}

// NewCPaaSStoreWithDB constructs a CPaaSStore using an existing shared *sql.DB (e.g. from assessment.SQLiteStore).
func NewCPaaSStoreWithDB(db *sql.DB) (*CPaaSStore, error) {
	if db == nil {
		return nil, errors.New("cpaas: db cannot be nil")
	}
	store := &CPaaSStore{
		db:     db,
		dbPath: "shared",
	}
	if err := store.migrate(); err != nil {
		return nil, fmt.Errorf("cpaas: migration failed on shared db: %w", err)
	}
	return store, nil
}

func (s *CPaaSStore) migrate() error {
	schema := `
	CREATE TABLE IF NOT EXISTS cpaas_schedules (
		id TEXT PRIMARY KEY,
		client_id TEXT NOT NULL,
		name TEXT NOT NULL,
		schedule_type TEXT NOT NULL,
		cron_expr TEXT NOT NULL,
		targets_json TEXT NOT NULL,
		profile TEXT NOT NULL,
		options_json TEXT,
		notify_json TEXT,
		webhook_secret TEXT,
		enabled INTEGER NOT NULL DEFAULT 1,
		created_at TEXT NOT NULL,
		updated_at TEXT NOT NULL,
		last_run_at TEXT,
		next_run_at TEXT
	);

	CREATE INDEX IF NOT EXISTS idx_cpaas_sched_client ON cpaas_schedules(client_id);
	CREATE INDEX IF NOT EXISTS idx_cpaas_sched_enabled ON cpaas_schedules(enabled);
	CREATE INDEX IF NOT EXISTS idx_cpaas_sched_next_run ON cpaas_schedules(next_run_at);

	CREATE TABLE IF NOT EXISTS cpaas_executions (
		id TEXT PRIMARY KEY,
		schedule_id TEXT NOT NULL,
		client_id TEXT NOT NULL,
		trigger_type TEXT NOT NULL,
		status TEXT NOT NULL,
		idempotency_key TEXT UNIQUE,
		scheduled_for TEXT NOT NULL,
		started_at TEXT,
		completed_at TEXT,
		assessment_id TEXT,
		execution_id TEXT,
		drift_report_id TEXT,
		findings_count INTEGER NOT NULL DEFAULT 0,
		verified_defects_count INTEGER NOT NULL DEFAULT 0,
		alerts_dispatched INTEGER NOT NULL DEFAULT 0,
		error_message TEXT,
		FOREIGN KEY(schedule_id) REFERENCES cpaas_schedules(id)
	);

	CREATE INDEX IF NOT EXISTS idx_cpaas_exec_sched ON cpaas_executions(schedule_id);
	CREATE INDEX IF NOT EXISTS idx_cpaas_exec_status ON cpaas_executions(status);
	CREATE INDEX IF NOT EXISTS idx_cpaas_exec_idemp ON cpaas_executions(idempotency_key);

	CREATE TABLE IF NOT EXISTS cpaas_drift_reports (
		id TEXT PRIMARY KEY,
		schedule_id TEXT NOT NULL,
		baseline_assessment_id TEXT NOT NULL,
		current_assessment_id TEXT NOT NULL,
		report_json TEXT NOT NULL,
		total_drift_events INTEGER NOT NULL DEFAULT 0,
		newly_verified_count INTEGER NOT NULL DEFAULT 0,
		created_at TEXT NOT NULL
	);

	CREATE INDEX IF NOT EXISTS idx_cpaas_drift_sched ON cpaas_drift_reports(schedule_id);

	CREATE TABLE IF NOT EXISTS cpaas_alert_log (
		id TEXT PRIMARY KEY,
		finding_fingerprint TEXT NOT NULL,
		assessment_id TEXT NOT NULL,
		schedule_id TEXT NOT NULL,
		provider TEXT NOT NULL,
		status_code INTEGER NOT NULL,
		receipt_id TEXT,
		delivered_at TEXT NOT NULL,
		UNIQUE(finding_fingerprint, provider, schedule_id)
	);

	CREATE INDEX IF NOT EXISTS idx_cpaas_alert_fp ON cpaas_alert_log(finding_fingerprint);
	`

	_, err := s.db.Exec(schema)
	return err
}

// Close gracefully closes the SQLite database connection.
func (s *CPaaSStore) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	return s.db.Close()
}

// SaveSchedule creates or updates a CPaaS schedule configuration.
func (s *CPaaSStore) SaveSchedule(ctx context.Context, sched *ScheduleConfig) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return ErrStoreClosed
	}

	targetsJSON, err := json.Marshal(sched.TargetURLs)
	if err != nil {
		return fmt.Errorf("cpaas: failed marshaling targets: %w", err)
	}

	optsJSON, err := json.Marshal(sched.Options)
	if err != nil {
		return fmt.Errorf("cpaas: failed marshaling execution options: %w", err)
	}

	notifyJSON, err := json.Marshal(sched.NotificationTargets)
	if err != nil {
		return fmt.Errorf("cpaas: failed marshaling notification targets: %w", err)
	}

	enabledInt := 0
	if sched.Enabled {
		enabledInt = 1
	}

	var lastRunStr, nextRunStr *string
	if sched.LastRunAt != nil {
		t := sched.LastRunAt.UTC().Format(time.RFC3339Nano)
		lastRunStr = &t
	}
	if sched.NextRunAt != nil {
		t := sched.NextRunAt.UTC().Format(time.RFC3339Nano)
		nextRunStr = &t
	}

	query := `
	INSERT INTO cpaas_schedules (
		id, client_id, name, schedule_type, cron_expr, targets_json, profile,
		options_json, notify_json, webhook_secret, enabled, created_at, updated_at, last_run_at, next_run_at
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	ON CONFLICT(id) DO UPDATE SET
		client_id = excluded.client_id,
		name = excluded.name,
		schedule_type = excluded.schedule_type,
		cron_expr = excluded.cron_expr,
		targets_json = excluded.targets_json,
		profile = excluded.profile,
		options_json = excluded.options_json,
		notify_json = excluded.notify_json,
		webhook_secret = excluded.webhook_secret,
		enabled = excluded.enabled,
		updated_at = excluded.updated_at,
		last_run_at = excluded.last_run_at,
		next_run_at = excluded.next_run_at;
	`

	_, err = s.db.ExecContext(ctx, query,
		sched.ID, sched.ClientID, sched.Name, string(sched.ScheduleType), sched.CronExpr,
		string(targetsJSON), sched.Profile, string(optsJSON), string(notifyJSON),
		sched.WebhookSecret, enabledInt, sched.CreatedAt.UTC().Format(time.RFC3339Nano),
		sched.UpdatedAt.UTC().Format(time.RFC3339Nano),
		lastRunStr, nextRunStr,
	)
	return err
}

// GetSchedule retrieves a schedule by its unique ID.
func (s *CPaaSStore) GetSchedule(ctx context.Context, id string) (*ScheduleConfig, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.closed {
		return nil, ErrStoreClosed
	}

	query := `
	SELECT id, client_id, name, schedule_type, cron_expr, targets_json, profile,
	       options_json, notify_json, webhook_secret, enabled, created_at, updated_at, last_run_at, next_run_at
	FROM cpaas_schedules WHERE id = ?;
	`

	row := s.db.QueryRowContext(ctx, query, id)
	return scanSchedule(row)
}

// ListSchedules retrieves schedules matching client ID and enabled filters.
func (s *CPaaSStore) ListSchedules(ctx context.Context, clientID string, enabledOnly bool) ([]ScheduleConfig, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.closed {
		return nil, ErrStoreClosed
	}

	var sb strings.Builder
	sb.WriteString(`
	SELECT id, client_id, name, schedule_type, cron_expr, targets_json, profile,
	       options_json, notify_json, webhook_secret, enabled, created_at, updated_at, last_run_at, next_run_at
	FROM cpaas_schedules WHERE 1=1
	`)

	var args []interface{}
	if clientID != "" {
		sb.WriteString(" AND client_id = ?")
		args = append(args, clientID)
	}
	if enabledOnly {
		sb.WriteString(" AND enabled = 1")
	}
	sb.WriteString(" ORDER BY created_at ASC;")

	rows, err := s.db.QueryContext(ctx, sb.String(), args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var schedules []ScheduleConfig
	for rows.Next() {
		sched, err := scanSchedule(rows)
		if err != nil {
			return nil, err
		}
		schedules = append(schedules, *sched)
	}
	return schedules, rows.Err()
}

// UpdateScheduleNextRun updates the last run and next run timestamps for a schedule.
func (s *CPaaSStore) UpdateScheduleNextRun(ctx context.Context, id string, lastRun *time.Time, nextRun *time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return ErrStoreClosed
	}

	var lastRunStr, nextRunStr *string
	if lastRun != nil {
		t := lastRun.UTC().Format(time.RFC3339Nano)
		lastRunStr = &t
	}
	if nextRun != nil {
		t := nextRun.UTC().Format(time.RFC3339Nano)
		nextRunStr = &t
	}

	query := `UPDATE cpaas_schedules SET last_run_at = ?, next_run_at = ?, updated_at = ? WHERE id = ?;`
	nowStr := time.Now().UTC().Format(time.RFC3339Nano)
	_, err := s.db.ExecContext(ctx, query, lastRunStr, nextRunStr, nowStr, id)
	return err
}

// DeleteSchedule removes a schedule configuration and its associated executions.
func (s *CPaaSStore) DeleteSchedule(ctx context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return ErrStoreClosed
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	if _, err := tx.ExecContext(ctx, "DELETE FROM cpaas_executions WHERE schedule_id = ?;", id); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, "DELETE FROM cpaas_drift_reports WHERE schedule_id = ?;", id); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, "DELETE FROM cpaas_alert_log WHERE schedule_id = ?;", id); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, "DELETE FROM cpaas_schedules WHERE id = ?;", id); err != nil {
		return err
	}

	return tx.Commit()
}

// CreateExecution persists a new scheduled execution record.
// Returns ErrDuplicateExecution if idempotencyKey already exists.
func (s *CPaaSStore) CreateExecution(ctx context.Context, exec *ScheduledExecution) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return ErrStoreClosed
	}

	var startedStr, completedStr *string
	if exec.StartedAt != nil {
		t := exec.StartedAt.UTC().Format(time.RFC3339Nano)
		startedStr = &t
	}
	if exec.CompletedAt != nil {
		t := exec.CompletedAt.UTC().Format(time.RFC3339Nano)
		completedStr = &t
	}

	query := `
	INSERT INTO cpaas_executions (
		id, schedule_id, client_id, trigger_type, status, idempotency_key,
		scheduled_for, started_at, completed_at, assessment_id, execution_id,
		drift_report_id, findings_count, verified_defects_count, alerts_dispatched, error_message
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
	`

	_, err := s.db.ExecContext(ctx, query,
		exec.ID, exec.ScheduleID, exec.ClientID, exec.TriggerType, string(exec.Status),
		exec.IdempotencyKey, exec.ScheduledFor.UTC().Format(time.RFC3339Nano),
		startedStr, completedStr, exec.AssessmentID, exec.ExecutionID, exec.DriftReportID,
		exec.FindingsCount, exec.VerifiedDefectsCount, exec.AlertsDispatched, exec.ErrorMessage,
	)

	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "unique") {
			return ErrDuplicateExecution
		}
		return err
	}
	return nil
}

// GetExecution fetches an execution by ID.
func (s *CPaaSStore) GetExecution(ctx context.Context, id string) (*ScheduledExecution, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.closed {
		return nil, ErrStoreClosed
	}

	query := `
	SELECT id, schedule_id, client_id, trigger_type, status, idempotency_key,
	       scheduled_for, started_at, completed_at, assessment_id, execution_id,
	       drift_report_id, findings_count, verified_defects_count, alerts_dispatched, error_message
	FROM cpaas_executions WHERE id = ?;
	`
	row := s.db.QueryRowContext(ctx, query, id)
	return scanExecution(row)
}

// UpdateExecution updates status, metrics, and error information for an execution.
func (s *CPaaSStore) UpdateExecution(ctx context.Context, exec *ScheduledExecution) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return ErrStoreClosed
	}

	var startedStr, completedStr *string
	if exec.StartedAt != nil {
		t := exec.StartedAt.UTC().Format(time.RFC3339Nano)
		startedStr = &t
	}
	if exec.CompletedAt != nil {
		t := exec.CompletedAt.UTC().Format(time.RFC3339Nano)
		completedStr = &t
	}

	query := `
	UPDATE cpaas_executions SET
		status = ?, started_at = ?, completed_at = ?, assessment_id = ?, execution_id = ?,
		drift_report_id = ?, findings_count = ?, verified_defects_count = ?, alerts_dispatched = ?, error_message = ?
	WHERE id = ?;
	`
	_, err := s.db.ExecContext(ctx, query,
		string(exec.Status), startedStr, completedStr, exec.AssessmentID, exec.ExecutionID,
		exec.DriftReportID, exec.FindingsCount, exec.VerifiedDefectsCount, exec.AlertsDispatched,
		exec.ErrorMessage, exec.ID,
	)
	return err
}

// ListPendingExecutions retrieves executions in PENDING state awaiting runner worker pickup.
func (s *CPaaSStore) ListPendingExecutions(ctx context.Context) ([]ScheduledExecution, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.closed {
		return nil, ErrStoreClosed
	}

	query := `
	SELECT id, schedule_id, client_id, trigger_type, status, idempotency_key,
	       scheduled_for, started_at, completed_at, assessment_id, execution_id,
	       drift_report_id, findings_count, verified_defects_count, alerts_dispatched, error_message
	FROM cpaas_executions WHERE status = 'PENDING' ORDER BY scheduled_for ASC;
	`
	rows, err := s.db.QueryContext(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var list []ScheduledExecution
	for rows.Next() {
		exec, err := scanExecution(rows)
		if err != nil {
			return nil, err
		}
		list = append(list, *exec)
	}
	return list, rows.Err()
}

// SaveDriftReport persists a calculated attack-surface drift report.
func (s *CPaaSStore) SaveDriftReport(ctx context.Context, rep *DriftReport) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return ErrStoreClosed
	}

	repJSON, err := json.Marshal(rep)
	if err != nil {
		return fmt.Errorf("cpaas: failed marshaling drift report: %w", err)
	}

	query := `
	INSERT INTO cpaas_drift_reports (
		id, schedule_id, baseline_assessment_id, current_assessment_id,
		report_json, total_drift_events, newly_verified_count, created_at
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?);
	`
	_, err = s.db.ExecContext(ctx, query,
		rep.ID, rep.ScheduleID, rep.BaselineAssessmentID, rep.CurrentAssessmentID,
		string(repJSON), rep.TotalDriftEvents, rep.NewlyVerifiedDefectsCount,
		rep.CreatedAt.UTC().Format(time.RFC3339Nano),
	)
	return err
}

// GetDriftReport loads a drift report by ID.
func (s *CPaaSStore) GetDriftReport(ctx context.Context, id string) (*DriftReport, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.closed {
		return nil, ErrStoreClosed
	}

	query := `SELECT report_json FROM cpaas_drift_reports WHERE id = ?;`
	var repJSON string
	if err := s.db.QueryRowContext(ctx, query, id).Scan(&repJSON); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, errors.New("cpaas: drift report not found")
		}
		return nil, err
	}

	var rep DriftReport
	if err := json.Unmarshal([]byte(repJSON), &rep); err != nil {
		return nil, fmt.Errorf("cpaas: failed unmarshaling drift report: %w", err)
	}
	return &rep, nil
}

// GetLatestDriftReportForSchedule retrieves the most recent drift report recorded for a schedule.
func (s *CPaaSStore) GetLatestDriftReportForSchedule(ctx context.Context, scheduleID string) (*DriftReport, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.closed {
		return nil, ErrStoreClosed
	}

	query := `SELECT report_json FROM cpaas_drift_reports WHERE schedule_id = ? ORDER BY created_at DESC LIMIT 1;`
	var repJSON string
	if err := s.db.QueryRowContext(ctx, query, scheduleID).Scan(&repJSON); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil // none exists yet
		}
		return nil, err
	}

	var rep DriftReport
	if err := json.Unmarshal([]byte(repJSON), &rep); err != nil {
		return nil, fmt.Errorf("cpaas: failed unmarshaling drift report: %w", err)
	}
	return &rep, nil
}

// IsAlertDelivered checks whether an alert has already been dispatched for this finding fingerprint, provider, and schedule.
func (s *CPaaSStore) IsAlertDelivered(ctx context.Context, findingFingerprint, provider, scheduleID string) (bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.closed {
		return false, ErrStoreClosed
	}

	query := `SELECT COUNT(1) FROM cpaas_alert_log WHERE finding_fingerprint = ? AND provider = ? AND schedule_id = ?;`
	var count int
	if err := s.db.QueryRowContext(ctx, query, findingFingerprint, provider, scheduleID).Scan(&count); err != nil {
		return false, err
	}
	return count > 0, nil
}

// RecordAlertDelivery logs an alert dispatch for idempotency and duplicate suppression.
func (s *CPaaSStore) RecordAlertDelivery(ctx context.Context, id, findingFingerprint, assessmentID, scheduleID, provider string, statusCode int, receiptID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return ErrStoreClosed
	}

	query := `
	INSERT INTO cpaas_alert_log (
		id, finding_fingerprint, assessment_id, schedule_id, provider, status_code, receipt_id, delivered_at
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
	ON CONFLICT(finding_fingerprint, provider, schedule_id) DO NOTHING;
	`
	_, err := s.db.ExecContext(ctx, query,
		id, findingFingerprint, assessmentID, scheduleID, provider, statusCode, receiptID,
		time.Now().UTC().Format(time.RFC3339Nano),
	)
	return err
}

// Helper scanner functions

type scanner interface {
	Scan(dest ...interface{}) error
}

func scanSchedule(s scanner) (*ScheduleConfig, error) {
	var (
		cfg                                      ScheduleConfig
		typeStr, targetsJSON, optsJSON, notifyJSON string
		webhookSecret                            sql.NullString
		enabledInt                               int
		createdAtStr, updatedAtStr               string
		lastRunStr, nextRunStr                   sql.NullString
	)

	err := s.Scan(
		&cfg.ID, &cfg.ClientID, &cfg.Name, &typeStr, &cfg.CronExpr, &targetsJSON, &cfg.Profile,
		&optsJSON, &notifyJSON, &webhookSecret, &enabledInt, &createdAtStr, &updatedAtStr, &lastRunStr, &nextRunStr,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrScheduleNotFound
		}
		return nil, err
	}

	cfg.ScheduleType = ScheduleType(typeStr)
	cfg.Enabled = enabledInt == 1
	if webhookSecret.Valid {
		cfg.WebhookSecret = webhookSecret.String
	}

	if err := json.Unmarshal([]byte(targetsJSON), &cfg.TargetURLs); err != nil {
		return nil, err
	}
	if optsJSON != "" {
		_ = json.Unmarshal([]byte(optsJSON), &cfg.Options)
	}
	if notifyJSON != "" {
		_ = json.Unmarshal([]byte(notifyJSON), &cfg.NotificationTargets)
	}

	if t, err := time.Parse(time.RFC3339Nano, createdAtStr); err == nil {
		cfg.CreatedAt = t
	}
	if t, err := time.Parse(time.RFC3339Nano, updatedAtStr); err == nil {
		cfg.UpdatedAt = t
	}
	if lastRunStr.Valid {
		if t, err := time.Parse(time.RFC3339Nano, lastRunStr.String); err == nil {
			cfg.LastRunAt = &t
		}
	}
	if nextRunStr.Valid {
		if t, err := time.Parse(time.RFC3339Nano, nextRunStr.String); err == nil {
			cfg.NextRunAt = &t
		}
	}

	return &cfg, nil
}

func scanExecution(s scanner) (*ScheduledExecution, error) {
	var (
		exec                                            ScheduledExecution
		statusStr, scheduledStr                         string
		startedStr, completedStr, driftReportID, errMsg sql.NullString
		assessID, execID                                sql.NullString
	)

	err := s.Scan(
		&exec.ID, &exec.ScheduleID, &exec.ClientID, &exec.TriggerType, &statusStr,
		&exec.IdempotencyKey, &scheduledStr, &startedStr, &completedStr,
		&assessID, &execID, &driftReportID, &exec.FindingsCount,
		&exec.VerifiedDefectsCount, &exec.AlertsDispatched, &errMsg,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrExecutionNotFound
		}
		return nil, err
	}

	exec.Status = ExecutionStatus(statusStr)
	if t, err := time.Parse(time.RFC3339Nano, scheduledStr); err == nil {
		exec.ScheduledFor = t
	}
	if startedStr.Valid {
		if t, err := time.Parse(time.RFC3339Nano, startedStr.String); err == nil {
			exec.StartedAt = &t
		}
	}
	if completedStr.Valid {
		if t, err := time.Parse(time.RFC3339Nano, completedStr.String); err == nil {
			exec.CompletedAt = &t
		}
	}
	if assessID.Valid {
		exec.AssessmentID = assessID.String
	}
	if execID.Valid {
		exec.ExecutionID = execID.String
	}
	if driftReportID.Valid {
		exec.DriftReportID = driftReportID.String
	}
	if errMsg.Valid {
		exec.ErrorMessage = errMsg.String
	}

	return &exec, nil
}
