package assessment

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"felix/pkg/correlation"
	"felix/pkg/report"
	"github.com/google/uuid"
)

// CreateExecution persists a new execution record, initializing timestamps and ownership metadata.
func (s *SQLiteStore) CreateExecution(exec *AssessmentExecution) error {
	if exec == nil {
		return fmt.Errorf("execution cannot be nil")
	}

	if exec.ID == "" {
		exec.ID = "exec-" + uuid.New().String()
	}
	exec.AssessmentID = s.resolveAssessmentID(exec.AssessmentID)

	now := time.Now().UTC()
	if exec.CreatedAt.IsZero() {
		exec.CreatedAt = now
	}
	if exec.UpdatedAt.IsZero() {
		exec.UpdatedAt = now
	}
	if exec.StartedAt.IsZero() {
		exec.StartedAt = now
	}
	if exec.InitiationSource == "" {
		exec.InitiationSource = "manual"
	}
	if exec.Status == "" {
		exec.Status = StatusRunning
	}

	// Populate client_id and assessment_type from parent assessment if omitted
	if exec.AssessmentID != "" && (exec.ClientID == "" || exec.AssessmentType == "") {
		if asm, err := s.GetAssessment(exec.AssessmentID); err == nil && asm != nil {
			if exec.ClientID == "" {
				exec.ClientID = asm.ClientID
			}
			if exec.AssessmentType == "" {
				exec.AssessmentType = asm.AssessmentType
			}
		}
	}

	if exec.Provenance != nil {
		exec.ConfigSnapshot.Provenance = exec.Provenance
	} else if exec.ConfigSnapshot.Provenance != nil {
		exec.Provenance = exec.ConfigSnapshot.Provenance
	}

	cfgJSON, err := json.Marshal(exec.ConfigSnapshot)
	if err != nil {
		return fmt.Errorf("failed to serialize scan config snapshot: %w", err)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	var schedFor any
	if exec.ScheduledFor != nil {
		schedFor = *exec.ScheduledFor
	}

	var compAt any
	if exec.CompletedAt != nil {
		compAt = *exec.CompletedAt
	}

	var hbAt any
	if exec.HeartbeatAt != nil {
		hbAt = *exec.HeartbeatAt
	}

	var leaseExp any
	if exec.LeaseExpiresAt != nil {
		leaseExp = *exec.LeaseExpiresAt
	}

	var lastRec any
	if exec.LastRecoveryAt != nil {
		lastRec = *exec.LastRecoveryAt
	}

	// Pre-check 1: Idempotency Key conflict check
	if exec.IdempotencyKey != "" && exec.AssessmentID != "" {
		var existingID string
		err := s.db.QueryRow(`
			SELECT id FROM assessment_executions
			WHERE assessment_id = ? AND idempotency_key = ? AND (tenant_id = ? OR tenant_id = '' OR ? = '')
			LIMIT 1
		`, exec.AssessmentID, exec.IdempotencyKey, exec.TenantID, exec.TenantID).Scan(&existingID)
		if err == nil && existingID != "" {
			return fmt.Errorf("%w: execution %s already exists for key %s", ErrIdempotencyConflict, existingID, exec.IdempotencyKey)
		}
	}

	// Pre-check 2: Scheduled occurrence conflict check
	if exec.ScheduleID != "" && exec.ScheduledFor != nil {
		var existingID string
		err := s.db.QueryRow(`
			SELECT id FROM assessment_executions
			WHERE schedule_id = ? AND scheduled_for = ?
			LIMIT 1
		`, exec.ScheduleID, *exec.ScheduledFor).Scan(&existingID)
		if err == nil && existingID != "" {
			return fmt.Errorf("%w: execution %s already exists for schedule %s occurrence", ErrIdempotencyConflict, existingID, exec.ScheduleID)
		}
	}

	// Pre-check 3: Overlapping active execution check
	if exec.Status == StatusRunning || exec.Status == StatusQueued {
		var activeID, activeStatus string
		err := s.db.QueryRow(`
			SELECT id, status FROM assessment_executions
			WHERE assessment_id = ? AND status IN ('RUNNING', 'QUEUED') AND id != ?
			LIMIT 1
		`, exec.AssessmentID, exec.ID).Scan(&activeID, &activeStatus)
		if err == nil && activeID != "" {
			return fmt.Errorf("%w: assessment %s already has active execution %s in status %s", ErrExecutionOverlap, exec.AssessmentID, activeID, activeStatus)
		}
	}

	_, err = s.db.Exec(`
		INSERT INTO assessment_executions (
			id, assessment_id, schedule_id, scheduled_for, client_id, tenant_id, account_id,
			initiation_source, assessment_type, status, started_at, completed_at, duration_ms,
			request_count, target_count, finding_count, snapshot_id, error_message, config_snapshot,
			worker_id, heartbeat_at, lease_expires_at, recovery_attempts, last_recovery_at,
			recovery_reason, checkpoint_json, idempotency_key, created_at, updated_at
		)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`,
		exec.ID, exec.AssessmentID, exec.ScheduleID, schedFor, exec.ClientID, exec.TenantID, exec.AccountID,
		exec.InitiationSource, exec.AssessmentType, string(exec.Status), exec.StartedAt, compAt, exec.DurationMs,
		exec.RequestCount, exec.TargetCount, exec.FindingCount, exec.SnapshotID, exec.ErrorMessage, string(cfgJSON),
		exec.WorkerID, hbAt, leaseExp, exec.RecoveryAttempts, lastRec,
		exec.RecoveryReason, exec.CheckpointJSON, exec.IdempotencyKey, exec.CreatedAt, exec.UpdatedAt,
	)
	if err != nil {
		errStr := err.Error()
		if strings.Contains(errStr, "idx_active_assessment_execution") {
			return fmt.Errorf("%w: assessment %s already has active execution in progress", ErrExecutionOverlap, exec.AssessmentID)
		}
		if strings.Contains(errStr, "idx_executions_idempotency") || (strings.Contains(errStr, "UNIQUE constraint failed") && strings.Contains(errStr, "idempotency_key")) {
			return fmt.Errorf("%w: duplicate execution with key %s", ErrIdempotencyConflict, exec.IdempotencyKey)
		}
		if strings.Contains(errStr, "idx_executions_sched_occurrence") || (strings.Contains(errStr, "UNIQUE constraint failed") && strings.Contains(errStr, "schedule_id")) {
			return fmt.Errorf("%w: duplicate scheduled occurrence", ErrIdempotencyConflict)
		}
		return err
	}
	return nil
}

// GetExecution retrieves a single execution record by ID with complete metadata.
func (s *SQLiteStore) GetExecution(id string) (*AssessmentExecution, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	row := s.db.QueryRow(`
		SELECT id, assessment_id, schedule_id, scheduled_for, client_id, tenant_id, account_id,
		       initiation_source, assessment_type, status, started_at, completed_at, duration_ms,
		       request_count, target_count, finding_count, snapshot_id, error_message, config_snapshot,
		       worker_id, heartbeat_at, lease_expires_at, recovery_attempts, last_recovery_at,
		       recovery_reason, checkpoint_json, idempotency_key, created_at, updated_at
		FROM assessment_executions WHERE id = ?
	`, id)

	exec, err := scanExecutionRow(row)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("execution %s not found: %w", id, ErrExecutionNotFound)
		}
		return nil, err
	}
	return exec, nil
}

// GetExecutionHistory retrieves an execution record by ID, enforcing tenant authorization boundaries.
func (s *SQLiteStore) GetExecutionHistory(id string, auth TenantAuthContext) (*AssessmentExecution, error) {
	exec, err := s.GetExecution(id)
	if err != nil {
		return nil, err
	}

	if !auth.Authorizes(exec.ClientID, exec.TenantID, exec.AccountID) {
		return nil, ErrExecutionUnauthorized
	}

	return exec, nil
}

// ListExecutions lists all executions for an assessment, ordered newest first.
func (s *SQLiteStore) ListExecutions(assessmentID string) ([]AssessmentExecution, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	assessmentID = s.resolveAssessmentID(assessmentID)
	rows, err := s.db.Query(`
		SELECT id, assessment_id, schedule_id, scheduled_for, client_id, tenant_id, account_id,
		       initiation_source, assessment_type, status, started_at, completed_at, duration_ms,
		       request_count, target_count, finding_count, snapshot_id, error_message, config_snapshot,
		       worker_id, heartbeat_at, lease_expires_at, recovery_attempts, last_recovery_at,
		       recovery_reason, checkpoint_json, idempotency_key, created_at, updated_at
		FROM assessment_executions WHERE assessment_id = ? ORDER BY started_at DESC
	`, assessmentID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var execs []AssessmentExecution
	for rows.Next() {
		exec, err := scanExecutionRows(rows)
		if err != nil {
			return nil, err
		}
		execs = append(execs, *exec)
	}
	return execs, rows.Err()
}

// ListExecutionHistory retrieves queryable, paginated execution history enforcing tenant authorization.
func (s *SQLiteStore) ListExecutionHistory(opts ExecutionListOptions) ([]AssessmentExecution, int, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	query := `
		SELECT id, assessment_id, schedule_id, scheduled_for, client_id, tenant_id, account_id,
		       initiation_source, assessment_type, status, started_at, completed_at, duration_ms,
		       request_count, target_count, finding_count, snapshot_id, error_message, config_snapshot,
		       worker_id, heartbeat_at, lease_expires_at, recovery_attempts, last_recovery_at,
		       recovery_reason, checkpoint_json, idempotency_key, created_at, updated_at
		FROM assessment_executions
		WHERE 1=1
	`
	countQuery := `SELECT COUNT(*) FROM assessment_executions WHERE 1=1`

	var args []any
	var countArgs []any

	// Tenant boundary enforcement
	if !opts.Auth.IsAdmin() {
		if opts.Auth.TenantID != "" {
			query += ` AND tenant_id = ?`
			countQuery += ` AND tenant_id = ?`
			args = append(args, opts.Auth.TenantID)
			countArgs = append(countArgs, opts.Auth.TenantID)
		}
		if opts.Auth.AccountID != "" {
			query += ` AND account_id = ?`
			countQuery += ` AND account_id = ?`
			args = append(args, opts.Auth.AccountID)
			countArgs = append(countArgs, opts.Auth.AccountID)
		}
		if opts.Auth.ClientID != "" {
			query += ` AND client_id = ?`
			countQuery += ` AND client_id = ?`
			args = append(args, opts.Auth.ClientID)
			countArgs = append(countArgs, opts.Auth.ClientID)
		}
	} else {
		// Admin explicit filters
		if opts.TenantID != "" {
			query += ` AND tenant_id = ?`
			countQuery += ` AND tenant_id = ?`
			args = append(args, opts.TenantID)
			countArgs = append(countArgs, opts.TenantID)
		}
		if opts.AccountID != "" {
			query += ` AND account_id = ?`
			countQuery += ` AND account_id = ?`
			args = append(args, opts.AccountID)
			countArgs = append(countArgs, opts.AccountID)
		}
		if opts.ClientID != "" {
			query += ` AND client_id = ?`
			countQuery += ` AND client_id = ?`
			args = append(args, opts.ClientID)
			countArgs = append(countArgs, opts.ClientID)
		}
	}

	if opts.AssessmentID != "" {
		asmID := s.resolveAssessmentID(opts.AssessmentID)
		query += ` AND assessment_id = ?`
		countQuery += ` AND assessment_id = ?`
		args = append(args, asmID)
		countArgs = append(countArgs, asmID)
	}

	if opts.ScheduleID != "" {
		query += ` AND schedule_id = ?`
		countQuery += ` AND schedule_id = ?`
		args = append(args, opts.ScheduleID)
		countArgs = append(countArgs, opts.ScheduleID)
	}

	if opts.Status != "" {
		query += ` AND status = ?`
		countQuery += ` AND status = ?`
		args = append(args, string(opts.Status))
		countArgs = append(countArgs, string(opts.Status))
	}

	if opts.InitiationSource != "" {
		query += ` AND initiation_source = ?`
		countQuery += ` AND initiation_source = ?`
		args = append(args, opts.InitiationSource)
		countArgs = append(countArgs, opts.InitiationSource)
	}

	if opts.Since != nil {
		query += ` AND COALESCE(started_at, created_at) >= ?`
		countQuery += ` AND COALESCE(started_at, created_at) >= ?`
		args = append(args, *opts.Since)
		countArgs = append(countArgs, *opts.Since)
	}

	if opts.Until != nil {
		query += ` AND COALESCE(started_at, created_at) <= ?`
		countQuery += ` AND COALESCE(started_at, created_at) <= ?`
		args = append(args, *opts.Until)
		countArgs = append(countArgs, *opts.Until)
	}

	var totalCount int
	if err := s.db.QueryRow(countQuery, countArgs...).Scan(&totalCount); err != nil {
		return nil, 0, fmt.Errorf("failed counting executions: %w", err)
	}

	query += ` ORDER BY COALESCE(started_at, created_at) DESC, id DESC`
	if opts.Limit > 0 {
		query += ` LIMIT ?`
		args = append(args, opts.Limit)
		if opts.Offset > 0 {
			query += ` OFFSET ?`
			args = append(args, opts.Offset)
		}
	}

	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("failed querying execution history: %w", err)
	}
	defer rows.Close()

	var records []AssessmentExecution
	for rows.Next() {
		exec, err := scanExecutionRows(rows)
		if err != nil {
			return nil, 0, fmt.Errorf("failed scanning execution row: %w", err)
		}
		if opts.Auth.Authorizes(exec.ClientID, exec.TenantID, exec.AccountID) {
			records = append(records, *exec)
		}
	}

	return records, totalCount, nil
}

// UpdateExecution updates an execution record, validating the state machine transition and ensuring idempotent terminal finalization.
func (s *SQLiteStore) UpdateExecution(exec *AssessmentExecution) error {
	if exec == nil || exec.ID == "" {
		return fmt.Errorf("valid execution ID required")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	// Query existing status to validate state machine rules
	var existingStatus string
	var existingCompAt sql.NullTime
	var existingSnapID sql.NullString
	var existingWorker sql.NullString
	var existingLeaseExp sql.NullTime
	err := s.db.QueryRow(`
		SELECT status, completed_at, snapshot_id, worker_id, lease_expires_at FROM assessment_executions WHERE id = ?
	`, exec.ID).Scan(&existingStatus, &existingCompAt, &existingSnapID, &existingWorker, &existingLeaseExp)

	// Ownership fencing: If ownership was claimed by another worker, reject stale update
	if existingWorker.Valid && existingWorker.String != "" && exec.WorkerID != "" && existingWorker.String != exec.WorkerID {
		return fmt.Errorf("%w: worker %s lost ownership to %s", ErrLeaseLost, exec.WorkerID, existingWorker.String)
	}
	// If worker's lease expired in the past and execution is not already terminal
	if existingWorker.Valid && existingWorker.String == exec.WorkerID && existingLeaseExp.Valid && existingLeaseExp.Time.Before(time.Now().UTC()) && !IsTerminalExecutionStatus(AssessmentStatus(existingStatus)) {
		return fmt.Errorf("%w: worker %s lease expired at %s", ErrLeaseLost, exec.WorkerID, existingLeaseExp.Time)
	}

	if err == sql.ErrNoRows {
		return fmt.Errorf("execution %s not found: %w", exec.ID, ErrExecutionNotFound)
	}
	if err != nil {
		return fmt.Errorf("failed querying existing execution: %w", err)
	}

	curStatus := AssessmentStatus(existingStatus)

	// Idempotent finalization: if already terminal and updated to the identical terminal status
	if IsTerminalExecutionStatus(curStatus) && curStatus == exec.Status {
		// If DB record has no snapshot_id yet and incoming update provides one, attach it safely
		if (!existingSnapID.Valid || existingSnapID.String == "") && exec.SnapshotID != "" {
			_, err = s.db.Exec(`UPDATE assessment_executions SET snapshot_id = ?, updated_at = ? WHERE id = ?`,
				exec.SnapshotID, time.Now().UTC(), exec.ID)
			return err
		}
		return nil
	}

	// Validate state transition
	if !IsValidExecutionTransition(curStatus, exec.Status) {
		return fmt.Errorf("%w: cannot transition from %s to %s", ErrInvalidStateTransition, curStatus, exec.Status)
	}

	now := time.Now().UTC()
	exec.UpdatedAt = now
	if IsTerminalExecutionStatus(exec.Status) && exec.CompletedAt == nil {
		exec.CompletedAt = &now
	}

	if exec.Provenance != nil {
		exec.ConfigSnapshot.Provenance = exec.Provenance
	} else if exec.ConfigSnapshot.Provenance != nil {
		exec.Provenance = exec.ConfigSnapshot.Provenance
	}

	cfgJSON, err := json.Marshal(exec.ConfigSnapshot)
	if err != nil {
		return fmt.Errorf("failed to serialize scan config snapshot: %w", err)
	}

	var compAt any
	if exec.CompletedAt != nil {
		compAt = *exec.CompletedAt
	}

	var hbAt any
	if exec.HeartbeatAt != nil {
		hbAt = *exec.HeartbeatAt
	}

	var leaseExp any
	if exec.LeaseExpiresAt != nil {
		leaseExp = *exec.LeaseExpiresAt
	}

	var lastRec any
	if exec.LastRecoveryAt != nil {
		lastRec = *exec.LastRecoveryAt
	}

	res, err := s.db.Exec(`
		UPDATE assessment_executions
		SET status = ?, completed_at = ?, duration_ms = ?, request_count = ?,
		    target_count = ?, finding_count = ?, snapshot_id = ?, error_message = ?,
		    config_snapshot = ?, worker_id = ?, heartbeat_at = ?, lease_expires_at = ?,
		    recovery_attempts = ?, last_recovery_at = ?, recovery_reason = ?,
		    checkpoint_json = ?, idempotency_key = ?, updated_at = ?
		WHERE id = ? AND (worker_id IS NULL OR worker_id = '' OR worker_id = ? OR ? = '')
	`,
		string(exec.Status), compAt, exec.DurationMs, exec.RequestCount,
		exec.TargetCount, exec.FindingCount, exec.SnapshotID, exec.ErrorMessage,
		string(cfgJSON), exec.WorkerID, hbAt, leaseExp,
		exec.RecoveryAttempts, lastRec, exec.RecoveryReason,
		exec.CheckpointJSON, exec.IdempotencyKey, exec.UpdatedAt, exec.ID, exec.WorkerID, exec.WorkerID,
	)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return fmt.Errorf("execution %s not found", exec.ID)
	}
	return nil
}

// scanExecutionRow scans a single execution row from *sql.Row
func scanExecutionRow(row *sql.Row) (*AssessmentExecution, error) {
	var exec AssessmentExecution
	var statusStr string
	var cfgJSON sql.NullString
	var schedID, clientID, tenantID, accountID, initSource, asmType, snapID, errMsg sql.NullString
	var schedFor, compAt, created, updated sql.NullTime
	var durMs, reqCount, tgtCount, fndCount, recAttempts sql.NullInt64
	var workerID, recReason, chkJSON, idempKey sql.NullString
	var hbAt, leaseExp, lastRec sql.NullTime

	err := row.Scan(
		&exec.ID, &exec.AssessmentID, &schedID, &schedFor, &clientID, &tenantID, &accountID,
		&initSource, &asmType, &statusStr, &exec.StartedAt, &compAt, &durMs,
		&reqCount, &tgtCount, &fndCount, &snapID, &errMsg, &cfgJSON,
		&workerID, &hbAt, &leaseExp, &recAttempts, &lastRec,
		&recReason, &chkJSON, &idempKey, &created, &updated,
	)
	if err != nil {
		return nil, err
	}

	exec.Status = AssessmentStatus(statusStr)
	if schedID.Valid {
		exec.ScheduleID = schedID.String
	}
	if schedFor.Valid {
		exec.ScheduledFor = &schedFor.Time
	}
	if clientID.Valid {
		exec.ClientID = clientID.String
	}
	if tenantID.Valid {
		exec.TenantID = tenantID.String
	}
	if accountID.Valid {
		exec.AccountID = accountID.String
	}
	if initSource.Valid {
		exec.InitiationSource = initSource.String
	} else {
		exec.InitiationSource = "manual"
	}
	if asmType.Valid {
		exec.AssessmentType = asmType.String
	}
	if compAt.Valid {
		exec.CompletedAt = &compAt.Time
	}
	if durMs.Valid {
		exec.DurationMs = durMs.Int64
	}
	if reqCount.Valid {
		exec.RequestCount = int(reqCount.Int64)
	}
	if tgtCount.Valid {
		exec.TargetCount = int(tgtCount.Int64)
	}
	if fndCount.Valid {
		exec.FindingCount = int(fndCount.Int64)
	}
	if snapID.Valid {
		exec.SnapshotID = snapID.String
	}
	if errMsg.Valid {
		exec.ErrorMessage = errMsg.String
	}
	if workerID.Valid {
		exec.WorkerID = workerID.String
	}
	if hbAt.Valid {
		exec.HeartbeatAt = &hbAt.Time
	}
	if leaseExp.Valid {
		exec.LeaseExpiresAt = &leaseExp.Time
	}
	if recAttempts.Valid {
		exec.RecoveryAttempts = int(recAttempts.Int64)
	}
	if lastRec.Valid {
		exec.LastRecoveryAt = &lastRec.Time
	}
	if recReason.Valid {
		exec.RecoveryReason = recReason.String
	}
	if chkJSON.Valid {
		exec.CheckpointJSON = chkJSON.String
	}
	if idempKey.Valid {
		exec.IdempotencyKey = idempKey.String
	}
	if idempKey.Valid {
		exec.IdempotencyKey = idempKey.String
	}
	if created.Valid {
		exec.CreatedAt = created.Time
	} else {
		exec.CreatedAt = exec.StartedAt
	}
	if updated.Valid {
		exec.UpdatedAt = updated.Time
	} else {
		exec.UpdatedAt = exec.CreatedAt
	}
	if cfgJSON.Valid && cfgJSON.String != "" {
		_ = json.Unmarshal([]byte(cfgJSON.String), &exec.ConfigSnapshot)
		if exec.ConfigSnapshot.Provenance != nil {
			exec.Provenance = exec.ConfigSnapshot.Provenance
		}
	}

	return &exec, nil
}

// scanExecutionRows scans a single execution row from *sql.Rows
func scanExecutionRows(rows *sql.Rows) (*AssessmentExecution, error) {
	var exec AssessmentExecution
	var statusStr string
	var cfgJSON sql.NullString
	var schedID, clientID, tenantID, accountID, initSource, asmType, snapID, errMsg sql.NullString
	var schedFor, compAt, created, updated sql.NullTime
	var durMs, reqCount, tgtCount, fndCount, recAttempts sql.NullInt64
	var workerID, recReason, chkJSON, idempKey sql.NullString
	var hbAt, leaseExp, lastRec sql.NullTime

	err := rows.Scan(
		&exec.ID, &exec.AssessmentID, &schedID, &schedFor, &clientID, &tenantID, &accountID,
		&initSource, &asmType, &statusStr, &exec.StartedAt, &compAt, &durMs,
		&reqCount, &tgtCount, &fndCount, &snapID, &errMsg, &cfgJSON,
		&workerID, &hbAt, &leaseExp, &recAttempts, &lastRec,
		&recReason, &chkJSON, &idempKey, &created, &updated,
	)
	if err != nil {
		return nil, err
	}

	exec.Status = AssessmentStatus(statusStr)
	if schedID.Valid {
		exec.ScheduleID = schedID.String
	}
	if schedFor.Valid {
		exec.ScheduledFor = &schedFor.Time
	}
	if clientID.Valid {
		exec.ClientID = clientID.String
	}
	if tenantID.Valid {
		exec.TenantID = tenantID.String
	}
	if accountID.Valid {
		exec.AccountID = accountID.String
	}
	if initSource.Valid {
		exec.InitiationSource = initSource.String
	} else {
		exec.InitiationSource = "manual"
	}
	if asmType.Valid {
		exec.AssessmentType = asmType.String
	}
	if compAt.Valid {
		exec.CompletedAt = &compAt.Time
	}
	if durMs.Valid {
		exec.DurationMs = durMs.Int64
	}
	if reqCount.Valid {
		exec.RequestCount = int(reqCount.Int64)
	}
	if tgtCount.Valid {
		exec.TargetCount = int(tgtCount.Int64)
	}
	if fndCount.Valid {
		exec.FindingCount = int(fndCount.Int64)
	}
	if snapID.Valid {
		exec.SnapshotID = snapID.String
	}
	if errMsg.Valid {
		exec.ErrorMessage = errMsg.String
	}
	if workerID.Valid {
		exec.WorkerID = workerID.String
	}
	if hbAt.Valid {
		exec.HeartbeatAt = &hbAt.Time
	}
	if leaseExp.Valid {
		exec.LeaseExpiresAt = &leaseExp.Time
	}
	if recAttempts.Valid {
		exec.RecoveryAttempts = int(recAttempts.Int64)
	}
	if lastRec.Valid {
		exec.LastRecoveryAt = &lastRec.Time
	}
	if recReason.Valid {
		exec.RecoveryReason = recReason.String
	}
	if chkJSON.Valid {
		exec.CheckpointJSON = chkJSON.String
	}
	if idempKey.Valid {
		exec.IdempotencyKey = idempKey.String
	}
	if created.Valid {
		exec.CreatedAt = created.Time
	} else {
		exec.CreatedAt = exec.StartedAt
	}
	if updated.Valid {
		exec.UpdatedAt = updated.Time
	} else {
		exec.UpdatedAt = exec.CreatedAt
	}
	if cfgJSON.Valid && cfgJSON.String != "" {
		_ = json.Unmarshal([]byte(cfgJSON.String), &exec.ConfigSnapshot)
		if exec.ConfigSnapshot.Provenance != nil {
			exec.Provenance = exec.ConfigSnapshot.Provenance
		}
	}

	return &exec, nil
}

// CompareExecutionHistory compares findings between two execution history records, enforcing tenant isolation.
func (s *SQLiteStore) CompareExecutionHistory(baselineExecID, currentExecID string, auth TenantAuthContext) (*correlation.AssessmentComparison, error) {
	baseExec, err := s.GetExecutionHistory(baselineExecID, auth)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve baseline execution %s: %w", baselineExecID, err)
	}

	curExec, err := s.GetExecutionHistory(currentExecID, auth)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve current execution %s: %w", currentExecID, err)
	}

	// Strict tenant boundary enforcement: cross-tenant comparisons are denied.
	if baseExec.TenantID != "" && curExec.TenantID != "" && baseExec.TenantID != curExec.TenantID {
		return nil, fmt.Errorf("cross-tenant comparison denied (baseline tenant %q != current tenant %q): %w", baseExec.TenantID, curExec.TenantID, ErrExecutionUnauthorized)
	}
	if baseExec.AccountID != "" && curExec.AccountID != "" && baseExec.AccountID != curExec.AccountID {
		return nil, fmt.Errorf("cross-account comparison denied (baseline account %q != current account %q): %w", baseExec.AccountID, curExec.AccountID, ErrExecutionUnauthorized)
	}

	// Incompatible assessment types cannot be directly compared
	if baseExec.AssessmentType != "" && curExec.AssessmentType != "" && !AreAssessmentTypesCompatible(baseExec.AssessmentType, curExec.AssessmentType) {
		return nil, fmt.Errorf("incompatible assessment types (%q vs %q): %w", baseExec.AssessmentType, curExec.AssessmentType, ErrIncompatibleAssessmentScope)
	}

	// Prevent comparing an execution against itself as a baseline
	if baseExec.ID == curExec.ID {
		return nil, fmt.Errorf("an execution (%s) cannot be compared against itself as a baseline", curExec.ID)
	}

	// Prevent incompatible assessment scopes
	if baseExec.AssessmentID != "" && curExec.AssessmentID != "" && baseExec.AssessmentID != curExec.AssessmentID {
		baseTgts, _ := s.GetTargets(baseExec.AssessmentID)
		compTgts, _ := s.GetTargets(curExec.AssessmentID)
		if !areAssessmentTargetsCompatible(baseTgts, compTgts) {
			return nil, fmt.Errorf("incompatible assessment scopes (baseline %s != current %s): %w",
				baseExec.AssessmentID, curExec.AssessmentID, ErrIncompatibleAssessmentScope)
		}
	}

	// Retrieve baseline findings (from snapshot if present, otherwise direct execution findings)
	var baseAFs []AssessmentFinding
	if baseExec.SnapshotID != "" {
		if findings, err := s.GetSnapshotFindings(baseExec.SnapshotID, auth); err == nil && len(findings) > 0 {
			baseAFs = findings
		}
	}
	if len(baseAFs) == 0 {
		if findings, err := s.GetFindings(baseExec.AssessmentID, baseExec.ID); err == nil {
			baseAFs = findings
		}
	}

	// Retrieve current findings
	var curAFs []AssessmentFinding
	if curExec.SnapshotID != "" {
		if findings, err := s.GetSnapshotFindings(curExec.SnapshotID, auth); err == nil && len(findings) > 0 {
			curAFs = findings
		}
	}
	if len(curAFs) == 0 {
		if findings, err := s.GetFindings(curExec.AssessmentID, curExec.ID); err == nil {
			curAFs = findings
		}
	}

	opts := correlation.ComparisonOptions{
		CurrentCompleted: curExec.Status == StatusCompleted || curExec.Status == StatusCompletedWithErrors,
	}

	// If current run has a snapshot, inspect detailed completeness, failed targets, and categories
	if curExec.SnapshotID != "" {
		if curSnap, err := s.GetSnapshot(curExec.SnapshotID, auth); err == nil && curSnap != nil {
			if curSnap.IsInconclusive() || !curSnap.IsComplete {
				opts.CurrentCompleted = false
				opts.Inconclusive = curSnap.IsInconclusive()
			}
			opts.ScopedTargets = curSnap.ScopedTargets
			opts.AssessedTargets = curSnap.GetAssessedTargets()
			opts.FailedTargets = curSnap.GetFailedTargets()
			opts.SkippedTargets = curSnap.GetSkippedTargets()
			opts.ScopedCategories = curSnap.GetCoveredCategories()
			opts.FailedCategories = curSnap.GetFailedCategories()
			opts.SkippedCategories = curSnap.GetSkippedCategories()
		}
	}

	// If scoped targets are still empty, populate from parent assessment approved targets
	if len(opts.ScopedTargets) == 0 && curExec.AssessmentID != "" {
		if tgts, err := s.GetTargets(curExec.AssessmentID); err == nil {
			for _, t := range tgts {
				if t.ScopeStatus == "APPROVED" || t.ScopeStatus == "" {
					opts.ScopedTargets = append(opts.ScopedTargets, t.TargetURL)
				}
			}
		}
	}

	baseReportFindings := make([]report.Finding, len(baseAFs))
	for i, af := range baseAFs {
		baseReportFindings[i] = ToReportFinding(af)
	}

	curReportFindings := make([]report.Finding, len(curAFs))
	for i, af := range curAFs {
		curReportFindings[i] = ToReportFinding(af)
	}

	// Inspect historical resolution events in finding_lifecycle_events to recognize genuine reappearance regressions
	for _, af := range curAFs {
		fp := af.Fingerprint
		if fp == "" {
			rf := ToReportFinding(af)
			fp = correlation.ComputeStableFingerprint(rf)
		}
		foundInBase := false
		for _, baf := range baseAFs {
			bfp := baf.Fingerprint
			if bfp == "" {
				brf := ToReportFinding(baf)
				bfp = correlation.ComputeStableFingerprint(brf)
			}
			if bfp == fp {
				foundInBase = true
				break
			}
		}
		if !foundInBase {
			var resolvedEvtCount int
			err := s.db.QueryRow(`
				SELECT COUNT(*) FROM finding_lifecycle_events
				WHERE fingerprint = ? AND current_state = 'RESOLVED' AND qualifying_assessment = 1
			`, fp).Scan(&resolvedEvtCount)
			if err == nil && resolvedEvtCount > 0 {
				if opts.ResolvedFingerprints == nil {
					opts.ResolvedFingerprints = make(map[string]bool)
				}
				opts.ResolvedFingerprints[fp] = true
			}
		}
	}

	comp := correlation.CompareFindingsWithOptions(baseReportFindings, curReportFindings, opts)
	comp.BaselineExecutionID = baseExec.ID
	comp.CurrentExecutionID = curExec.ID
	comp.BaselineSnapshotID = baseExec.SnapshotID
	comp.CurrentSnapshotID = curExec.SnapshotID

	return &comp, nil
}


// GetExecutionByIdempotencyKey retrieves an execution by tenant, assessment, and idempotency key.
func (s *SQLiteStore) GetExecutionByIdempotencyKey(tenantID, assessmentID, idempotencyKey string) (*AssessmentExecution, error) {
	if idempotencyKey == "" {
		return nil, fmt.Errorf("idempotency key cannot be empty")
	}
	s.mu.RLock()
	defer s.mu.RUnlock()

	assessmentID = s.resolveAssessmentID(assessmentID)
	row := s.db.QueryRow(`
		SELECT id, assessment_id, schedule_id, scheduled_for, client_id, tenant_id, account_id,
		       initiation_source, assessment_type, status, started_at, completed_at, duration_ms,
		       request_count, target_count, finding_count, snapshot_id, error_message, config_snapshot,
		       worker_id, heartbeat_at, lease_expires_at, recovery_attempts, last_recovery_at,
		       recovery_reason, checkpoint_json, idempotency_key, created_at, updated_at
		FROM assessment_executions
		WHERE assessment_id = ? AND idempotency_key = ?
		  AND (tenant_id = ? OR tenant_id = '' OR ? = '')
		LIMIT 1
	`, assessmentID, idempotencyKey, tenantID, tenantID)

	exec, err := scanExecutionRow(row)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, ErrExecutionNotFound
		}
		return nil, err
	}
	return exec, nil
}

// HasActiveExecution returns true and the active execution ID if an execution is currently RUNNING or QUEUED for the assessment.
func (s *SQLiteStore) HasActiveExecution(assessmentID string) (bool, string, error) {
	if assessmentID == "" {
		return false, "", nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()

	assessmentID = s.resolveAssessmentID(assessmentID)
	var activeID string
	err := s.db.QueryRow(`
		SELECT id FROM assessment_executions
		WHERE assessment_id = ? AND status IN ('RUNNING', 'QUEUED')
		LIMIT 1
	`, assessmentID).Scan(&activeID)
	if err == sql.ErrNoRows {
		return false, "", nil
	}
	if err != nil {
		return false, "", err
	}
	return true, activeID, nil
}
