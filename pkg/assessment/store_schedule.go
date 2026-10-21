package assessment

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
)

// CreateSchedule persists a new assessment schedule with recurrence validation and tenant authorization checks.
func (s *SQLiteStore) CreateSchedule(sched *AssessmentSchedule, auth TenantAuthContext) error {
	if sched == nil {
		return fmt.Errorf("%w: schedule cannot be nil", ErrScheduleInvalid)
	}
	if sched.Name == "" {
		return fmt.Errorf("%w: name is required", ErrScheduleInvalid)
	}
	if sched.AssessmentID == "" {
		return fmt.Errorf("%w: assessment_id is required", ErrScheduleInvalid)
	}
	if sched.RecurrenceType == "" {
		return fmt.Errorf("%w: recurrence_type is required", ErrScheduleInvalid)
	}

	// Verify underlying assessment existence and access
	asm, err := s.GetAssessment(sched.AssessmentID)
	if err != nil {
		return fmt.Errorf("underlying assessment invalid: %w", err)
	}

	// Normalize tenant/account/client from assessment if omitted
	if sched.ClientID == "" {
		sched.ClientID = asm.ClientID
	}
	if sched.TenantID == "" && auth.TenantID != "" {
		sched.TenantID = auth.TenantID
	}
	if sched.AccountID == "" && auth.AccountID != "" {
		sched.AccountID = auth.AccountID
	}

	// Enforce tenant authorization boundaries
	if !auth.Authorizes(sched.ClientID, sched.TenantID, sched.AccountID) {
		return ErrScheduleUnauthorized
	}
	if !auth.Authorizes(asm.ClientID, sched.TenantID, sched.AccountID) {
		return ErrScheduleUnauthorized
	}

	// Default timezone and catch up policy
	if sched.Timezone == "" {
		sched.Timezone = "UTC"
	}
	if sched.CatchUpPolicy == "" {
		sched.CatchUpPolicy = "once"
	}

	// Validate recurrence configuration
	if err := ValidateRecurrence(sched.RecurrenceType, sched.RecurrenceExpr, sched.IntervalSeconds, sched.Timezone); err != nil {
		return fmt.Errorf("%w: %v", ErrScheduleInvalid, err)
	}

	now := time.Now().UTC()
	if sched.NextDueAt.IsZero() {
		nextDue, err := CalculateInitialNextDue(sched.RecurrenceType, sched.RecurrenceExpr, sched.IntervalSeconds, sched.Timezone, now)
		if err != nil {
			return fmt.Errorf("%w: failed calculating next due: %v", ErrScheduleInvalid, err)
		}
		sched.NextDueAt = nextDue
	}

	if sched.ID == "" {
		sched.ID = uuid.New().String()
	}
	sched.CreatedAt = now
	sched.UpdatedAt = now

	execOptsJSON, err := json.Marshal(sched.ExecutionOptions)
	if err != nil {
		return fmt.Errorf("failed marshaling execution options: %w", err)
	}

	isEnabledInt := 0
	if sched.IsEnabled {
		isEnabledInt = 1
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	_, err = s.db.Exec(`
		INSERT INTO assessment_schedules (
			id, name, description, assessment_id, client_id, tenant_id, account_id,
			recurrence_type, recurrence_expr, interval_seconds, timezone, is_enabled,
			catch_up_policy, execution_options_json, next_due_at, last_dispatched_at,
			last_completed_at, last_execution_id, dispatch_count, failure_count,
			consecutive_failures, last_error, created_at, updated_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`,
		sched.ID, sched.Name, sched.Description, sched.AssessmentID, sched.ClientID, sched.TenantID, sched.AccountID,
		string(sched.RecurrenceType), sched.RecurrenceExpr, sched.IntervalSeconds, sched.Timezone, isEnabledInt,
		sched.CatchUpPolicy, string(execOptsJSON), sched.NextDueAt, sched.LastDispatchedAt,
		sched.LastCompletedAt, sched.LastExecutionID, sched.DispatchCount, sched.FailureCount,
		sched.ConsecutiveFailures, sched.LastError, sched.CreatedAt, sched.UpdatedAt,
	)
	if err != nil {
		return fmt.Errorf("failed inserting assessment schedule: %w", err)
	}

	return nil
}

// GetSchedule retrieves an assessment schedule by ID, enforcing tenant authorization.
func (s *SQLiteStore) GetSchedule(id string, auth TenantAuthContext) (*AssessmentSchedule, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	row := s.db.QueryRow(`
		SELECT id, name, description, assessment_id, client_id, tenant_id, account_id,
		       recurrence_type, recurrence_expr, interval_seconds, timezone, is_enabled,
		       catch_up_policy, execution_options_json, next_due_at, last_dispatched_at,
		       last_completed_at, last_execution_id, dispatch_count, failure_count,
		       consecutive_failures, last_error, created_at, updated_at
		FROM assessment_schedules
		WHERE id = ?
	`, id)

	sched, err := scanScheduleRow(row)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, ErrScheduleNotFound
		}
		return nil, fmt.Errorf("failed querying schedule: %w", err)
	}

	if !auth.Authorizes(sched.ClientID, sched.TenantID, sched.AccountID) {
		return nil, ErrScheduleUnauthorized
	}

	return sched, nil
}

// ListSchedules lists schedules matching the options and authorized for the caller.
func (s *SQLiteStore) ListSchedules(opts ScheduleListOptions) ([]AssessmentSchedule, int, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	query := `
		SELECT id, name, description, assessment_id, client_id, tenant_id, account_id,
		       recurrence_type, recurrence_expr, interval_seconds, timezone, is_enabled,
		       catch_up_policy, execution_options_json, next_due_at, last_dispatched_at,
		       last_completed_at, last_execution_id, dispatch_count, failure_count,
		       consecutive_failures, last_error, created_at, updated_at
		FROM assessment_schedules
		WHERE 1=1
	`
	countQuery := `SELECT COUNT(*) FROM assessment_schedules WHERE 1=1`

	var args []any
	var countArgs []any

	// Authorization enforcement
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
		// Admin filters
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
		query += ` AND assessment_id = ?`
		countQuery += ` AND assessment_id = ?`
		args = append(args, opts.AssessmentID)
		countArgs = append(countArgs, opts.AssessmentID)
	}

	if opts.IsEnabled != nil {
		enInt := 0
		if *opts.IsEnabled {
			enInt = 1
		}
		query += ` AND is_enabled = ?`
		countQuery += ` AND is_enabled = ?`
		args = append(args, enInt)
		countArgs = append(countArgs, enInt)
	}

	var totalCount int
	if err := s.db.QueryRow(countQuery, countArgs...).Scan(&totalCount); err != nil {
		return nil, 0, fmt.Errorf("failed counting schedules: %w", err)
	}

	query += ` ORDER BY next_due_at ASC, id ASC`
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
		return nil, 0, fmt.Errorf("failed querying schedules: %w", err)
	}
	defer rows.Close()

	var schedules []AssessmentSchedule
	for rows.Next() {
		sched, err := scanScheduleRows(rows)
		if err != nil {
			return nil, 0, fmt.Errorf("failed scanning schedule row: %w", err)
		}
		if opts.Auth.Authorizes(sched.ClientID, sched.TenantID, sched.AccountID) {
			schedules = append(schedules, *sched)
		}
	}

	return schedules, totalCount, nil
}

// UpdateSchedule updates an existing assessment schedule with authorization verification.
func (s *SQLiteStore) UpdateSchedule(sched *AssessmentSchedule, auth TenantAuthContext) error {
	if sched == nil || sched.ID == "" {
		return fmt.Errorf("%w: valid schedule ID required", ErrScheduleInvalid)
	}

	existing, err := s.GetSchedule(sched.ID, auth)
	if err != nil {
		return err
	}

	// Verify authorization
	if !auth.Authorizes(existing.ClientID, existing.TenantID, existing.AccountID) {
		return ErrScheduleUnauthorized
	}
	if !auth.Authorizes(sched.ClientID, sched.TenantID, sched.AccountID) {
		return ErrScheduleUnauthorized
	}

	// If recurrence changed, validate
	if sched.RecurrenceType != "" || sched.RecurrenceExpr != "" {
		recType := sched.RecurrenceType
		if recType == "" {
			recType = existing.RecurrenceType
		}
		recExpr := sched.RecurrenceExpr
		if recExpr == "" {
			recExpr = existing.RecurrenceExpr
		}
		tz := sched.Timezone
		if tz == "" {
			tz = existing.Timezone
		}
		interval := sched.IntervalSeconds
		if interval == 0 {
			interval = existing.IntervalSeconds
		}

		if err := ValidateRecurrence(recType, recExpr, interval, tz); err != nil {
			return fmt.Errorf("%w: %v", ErrScheduleInvalid, err)
		}
	}

	if sched.Timezone == "" {
		sched.Timezone = existing.Timezone
	}
	if sched.CatchUpPolicy == "" {
		sched.CatchUpPolicy = existing.CatchUpPolicy
	}
	if sched.NextDueAt.IsZero() {
		sched.NextDueAt = existing.NextDueAt
	}

	execOptsJSON, err := json.Marshal(sched.ExecutionOptions)
	if err != nil {
		return fmt.Errorf("failed marshaling execution options: %w", err)
	}

	isEnabledInt := 0
	if sched.IsEnabled {
		isEnabledInt = 1
	}

	sched.UpdatedAt = time.Now().UTC()

	s.mu.Lock()
	defer s.mu.Unlock()

	res, err := s.db.Exec(`
		UPDATE assessment_schedules SET
			name = ?,
			description = ?,
			recurrence_type = ?,
			recurrence_expr = ?,
			interval_seconds = ?,
			timezone = ?,
			is_enabled = ?,
			catch_up_policy = ?,
			execution_options_json = ?,
			next_due_at = ?,
			updated_at = ?
		WHERE id = ?
	`,
		sched.Name, sched.Description, string(sched.RecurrenceType), sched.RecurrenceExpr,
		sched.IntervalSeconds, sched.Timezone, isEnabledInt, sched.CatchUpPolicy,
		string(execOptsJSON), sched.NextDueAt, sched.UpdatedAt, sched.ID,
	)
	if err != nil {
		return fmt.Errorf("failed updating schedule: %w", err)
	}
	rowsAff, _ := res.RowsAffected()
	if rowsAff == 0 {
		return ErrScheduleNotFound
	}

	return nil
}

// DeleteSchedule deletes an assessment schedule and associated dispatch history.
func (s *SQLiteStore) DeleteSchedule(id string, auth TenantAuthContext) error {
	existing, err := s.GetSchedule(id, auth)
	if err != nil {
		return err
	}

	if !auth.Authorizes(existing.ClientID, existing.TenantID, existing.AccountID) {
		return ErrScheduleUnauthorized
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	_, _ = tx.Exec(`DELETE FROM schedule_dispatch_records WHERE schedule_id = ?`, id)
	res, err := tx.Exec(`DELETE FROM assessment_schedules WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("failed deleting schedule: %w", err)
	}
	rowsAff, _ := res.RowsAffected()
	if rowsAff == 0 {
		return ErrScheduleNotFound
	}

	return tx.Commit()
}

// ClaimDueSchedules atomically selects and claims all enabled schedules whose next_due_at <= now,
// updating next_due_at and last_dispatched_at immediately within a transaction to prevent duplicate
// dispatch across multiple instances or scheduler loops.
func (s *SQLiteStore) ClaimDueSchedules(now time.Time, limit int) ([]*AssessmentSchedule, error) {
	if limit <= 0 {
		limit = 50
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	rows, err := tx.Query(`
		SELECT id, name, description, assessment_id, client_id, tenant_id, account_id,
		       recurrence_type, recurrence_expr, interval_seconds, timezone, is_enabled,
		       catch_up_policy, execution_options_json, next_due_at, last_dispatched_at,
		       last_completed_at, last_execution_id, dispatch_count, failure_count,
		       consecutive_failures, last_error, created_at, updated_at
		FROM assessment_schedules
		WHERE is_enabled = 1 AND next_due_at <= ?
		ORDER BY next_due_at ASC
		LIMIT ?
	`, now, limit)
	if err != nil {
		return nil, fmt.Errorf("failed querying due schedules: %w", err)
	}

	var dueSchedules []*AssessmentSchedule
	for rows.Next() {
		sched, err := scanScheduleRows(rows)
		if err != nil {
			rows.Close()
			return nil, fmt.Errorf("failed scanning due schedule: %w", err)
		}
		dueSchedules = append(dueSchedules, sched)
	}
	rows.Close()

	var claimed []*AssessmentSchedule
	for _, sched := range dueSchedules {
		var newNextDue time.Time
		newIsEnabled := sched.IsEnabled

		if sched.RecurrenceType == RecurrenceOnce {
			// One-time execution disables schedule after claim
			newIsEnabled = false
			newNextDue = sched.NextDueAt
		} else {
			calcNext, err := CalculateNextDue(sched.RecurrenceType, sched.RecurrenceExpr, sched.IntervalSeconds, sched.Timezone, sched.NextDueAt)
			if err != nil {
				calcNext = sched.NextDueAt.Add(24 * time.Hour)
			}
			newNextDue, _ = ApplyCatchUp(calcNext, now, sched.RecurrenceType, sched.RecurrenceExpr, sched.IntervalSeconds, sched.Timezone, sched.CatchUpPolicy)
		}

		dispatchedAt := now
		isEnabledInt := 0
		if newIsEnabled {
			isEnabledInt = 1
		}

		res, err := tx.Exec(`
			UPDATE assessment_schedules SET
				next_due_at = ?,
				last_dispatched_at = ?,
				dispatch_count = dispatch_count + 1,
				is_enabled = ?,
				updated_at = ?
			WHERE id = ? AND next_due_at = ?
		`, newNextDue, dispatchedAt, isEnabledInt, now, sched.ID, sched.NextDueAt)
		if err != nil {
			return nil, fmt.Errorf("failed claiming schedule %s: %w", sched.ID, err)
		}

		rowsAff, _ := res.RowsAffected()
		if rowsAff > 0 {
			// Schedule successfully claimed by this worker
			sched.LastDispatchedAt = &dispatchedAt
			sched.DispatchCount++
			sched.IsEnabled = newIsEnabled
			sched.NextDueAt = newNextDue
			claimed = append(claimed, sched)
		}
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("failed committing schedule claims: %w", err)
	}

	return claimed, nil
}

// RecordScheduleDispatch records a schedule execution attempt and updates telemetry.
func (s *SQLiteStore) RecordScheduleDispatch(record *ScheduleDispatchRecord) error {
	if record == nil {
		return fmt.Errorf("record cannot be nil")
	}
	if record.ID == "" {
		record.ID = uuid.New().String()
	}
	if record.CreatedAt.IsZero() {
		record.CreatedAt = time.Now().UTC()
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	var existingID string
	err = tx.QueryRow(`
		SELECT id FROM schedule_dispatch_records
		WHERE id = ? OR (schedule_id = ? AND scheduled_for = ?)
		LIMIT 1
	`, record.ID, record.ScheduleID, record.ScheduledFor).Scan(&existingID)
	if err == nil && existingID != "" {
		_, err = tx.Exec(`
			UPDATE schedule_dispatch_records SET
				execution_id = COALESCE(NULLIF(?, ''), execution_id),
				completed_at = COALESCE(?, completed_at),
				status = ?,
				error_message = ?
			WHERE id = ?
		`, record.ExecutionID, record.CompletedAt, record.Status, record.ErrorMessage, existingID)
		record.ID = existingID
	} else {
		_, err = tx.Exec(`
			INSERT INTO schedule_dispatch_records (
				id, schedule_id, assessment_id, execution_id, tenant_id, account_id,
				scheduled_for, dispatched_at, completed_at, status, error_message, created_at
			) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		`,
			record.ID, record.ScheduleID, record.AssessmentID, record.ExecutionID,
			record.TenantID, record.AccountID, record.ScheduledFor, record.DispatchedAt,
			record.CompletedAt, record.Status, record.ErrorMessage, record.CreatedAt,
		)
	}
	if err != nil {
		return fmt.Errorf("failed recording dispatch: %w", err)
	}

	// Update schedule aggregate status if completed or failed
	now := time.Now().UTC()
	if record.Status == "COMPLETED" {
		_, _ = tx.Exec(`
			UPDATE assessment_schedules SET
				last_completed_at = ?,
				last_execution_id = ?,
				consecutive_failures = 0,
				updated_at = ?
			WHERE id = ?
		`, record.CompletedAt, record.ExecutionID, now, record.ScheduleID)
	} else if record.Status == "FAILED" {
		_, _ = tx.Exec(`
			UPDATE assessment_schedules SET
				failure_count = failure_count + 1,
				consecutive_failures = consecutive_failures + 1,
				last_error = ?,
				updated_at = ?
			WHERE id = ?
		`, record.ErrorMessage, now, record.ScheduleID)
	}

	return tx.Commit()
}

// GetScheduleDispatches retrieves execution records for a schedule, verifying tenant authorization.
func (s *SQLiteStore) GetScheduleDispatches(scheduleID string, auth TenantAuthContext) ([]ScheduleDispatchRecord, error) {
	sched, err := s.GetSchedule(scheduleID, auth)
	if err != nil {
		return nil, err
	}

	if !auth.Authorizes(sched.ClientID, sched.TenantID, sched.AccountID) {
		return nil, ErrScheduleUnauthorized
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	rows, err := s.db.Query(`
		SELECT id, schedule_id, assessment_id, execution_id, tenant_id, account_id,
		       scheduled_for, dispatched_at, completed_at, status, error_message, created_at
		FROM schedule_dispatch_records
		WHERE schedule_id = ?
		ORDER BY dispatched_at DESC
	`, scheduleID)
	if err != nil {
		return nil, fmt.Errorf("failed querying schedule dispatches: %w", err)
	}
	defer rows.Close()

	var records []ScheduleDispatchRecord
	for rows.Next() {
		var rec ScheduleDispatchRecord
		var execID, accID, errMsg sql.NullString
		var compAt sql.NullTime

		err := rows.Scan(
			&rec.ID, &rec.ScheduleID, &rec.AssessmentID, &execID, &rec.TenantID, &accID,
			&rec.ScheduledFor, &rec.DispatchedAt, &compAt, &rec.Status, &errMsg, &rec.CreatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("failed scanning dispatch record: %w", err)
		}
		if execID.Valid {
			rec.ExecutionID = execID.String
		}
		if accID.Valid {
			rec.AccountID = accID.String
		}
		if compAt.Valid {
			rec.CompletedAt = &compAt.Time
		}
		if errMsg.Valid {
			rec.ErrorMessage = errMsg.String
		}
		records = append(records, rec)
	}

	return records, nil
}

// Helper scanner for single row
func scanScheduleRow(row *sql.Row) (*AssessmentSchedule, error) {
	var sched AssessmentSchedule
	var desc, accID, lastExecID, lastErr sql.NullString
	var lastDisp, lastComp sql.NullTime
	var isEnInt int
	var execOptsJSON string
	var recType string

	err := row.Scan(
		&sched.ID, &sched.Name, &desc, &sched.AssessmentID, &sched.ClientID, &sched.TenantID, &accID,
		&recType, &sched.RecurrenceExpr, &sched.IntervalSeconds, &sched.Timezone, &isEnInt,
		&sched.CatchUpPolicy, &execOptsJSON, &sched.NextDueAt, &lastDisp,
		&lastComp, &lastExecID, &sched.DispatchCount, &sched.FailureCount,
		&sched.ConsecutiveFailures, &lastErr, &sched.CreatedAt, &sched.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}

	sched.RecurrenceType = RecurrenceType(recType)
	sched.IsEnabled = isEnInt == 1
	if desc.Valid {
		sched.Description = desc.String
	}
	if accID.Valid {
		sched.AccountID = accID.String
	}
	if lastExecID.Valid {
		sched.LastExecutionID = lastExecID.String
	}
	if lastErr.Valid {
		sched.LastError = lastErr.String
	}
	if lastDisp.Valid {
		sched.LastDispatchedAt = &lastDisp.Time
	}
	if lastComp.Valid {
		sched.LastCompletedAt = &lastComp.Time
	}
	_ = json.Unmarshal([]byte(execOptsJSON), &sched.ExecutionOptions)

	return &sched, nil
}

// Helper scanner for rows
func scanScheduleRows(rows *sql.Rows) (*AssessmentSchedule, error) {
	var sched AssessmentSchedule
	var desc, accID, lastExecID, lastErr sql.NullString
	var lastDisp, lastComp sql.NullTime
	var isEnInt int
	var execOptsJSON string
	var recType string

	err := rows.Scan(
		&sched.ID, &sched.Name, &desc, &sched.AssessmentID, &sched.ClientID, &sched.TenantID, &accID,
		&recType, &sched.RecurrenceExpr, &sched.IntervalSeconds, &sched.Timezone, &isEnInt,
		&sched.CatchUpPolicy, &execOptsJSON, &sched.NextDueAt, &lastDisp,
		&lastComp, &lastExecID, &sched.DispatchCount, &sched.FailureCount,
		&sched.ConsecutiveFailures, &lastErr, &sched.CreatedAt, &sched.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}

	sched.RecurrenceType = RecurrenceType(recType)
	sched.IsEnabled = isEnInt == 1
	if desc.Valid {
		sched.Description = desc.String
	}
	if accID.Valid {
		sched.AccountID = accID.String
	}
	if lastExecID.Valid {
		sched.LastExecutionID = lastExecID.String
	}
	if lastErr.Valid {
		sched.LastError = lastErr.String
	}
	if lastDisp.Valid {
		sched.LastDispatchedAt = &lastDisp.Time
	}
	if lastComp.Valid {
		sched.LastCompletedAt = &lastComp.Time
	}
	_ = json.Unmarshal([]byte(execOptsJSON), &sched.ExecutionOptions)

	return &sched, nil
}


// GetScheduleDispatchByOccurrence retrieves the dispatch record for a specific schedule occurrence.
func (s *SQLiteStore) GetScheduleDispatchByOccurrence(scheduleID string, scheduledFor time.Time) (*ScheduleDispatchRecord, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	row := s.db.QueryRow(`
		SELECT id, schedule_id, assessment_id, execution_id, tenant_id, account_id,
		       scheduled_for, dispatched_at, completed_at, status, error_message, created_at
		FROM schedule_dispatch_records
		WHERE schedule_id = ? AND scheduled_for = ?
		LIMIT 1
	`, scheduleID, scheduledFor.UTC())

	var disp ScheduleDispatchRecord
	var execID, tenantID, accountID, errMsg sql.NullString
	var compAt sql.NullTime
	err := row.Scan(
		&disp.ID, &disp.ScheduleID, &disp.AssessmentID, &execID, &tenantID, &accountID,
		&disp.ScheduledFor, &disp.DispatchedAt, &compAt, &disp.Status, &errMsg, &disp.CreatedAt,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	if execID.Valid {
		disp.ExecutionID = execID.String
	}
	if tenantID.Valid {
		disp.TenantID = tenantID.String
	}
	if accountID.Valid {
		disp.AccountID = accountID.String
	}
	if errMsg.Valid {
		disp.ErrorMessage = errMsg.String
	}
	if compAt.Valid {
		disp.CompletedAt = &compAt.Time
	}

	return &disp, nil
}
