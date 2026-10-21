package assessment

import (
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"felix/pkg/notify"
	"felix/pkg/secrets"
)

var (
	ErrNotificationNotFound  = errors.New("notification not found")
	ErrNotificationDuplicate = errors.New("notification already exists for this tenant and deduplication key")
)

func nullIfEmpty(s string) interface{} {
	if s == "" {
		return nil
	}
	return s
}

// EnqueueNotification inserts a notification into the persistent outbox.
// Duplicate events matching (tenant_id, dedup_key) are safely suppressed without error.
func (s *SQLiteStore) EnqueueNotification(n *notify.Notification) error {
	if n == nil {
		return errors.New("notification cannot be nil")
	}
	if strings.TrimSpace(n.ID) == "" {
		return errors.New("notification ID cannot be empty")
	}
	if strings.TrimSpace(n.TenantID) == "" {
		return errors.New("notification tenant_id cannot be empty")
	}
	if strings.TrimSpace(n.EventType) == "" {
		return errors.New("notification event_type cannot be empty")
	}
	if strings.TrimSpace(n.DedupKey) == "" {
		return errors.New("notification dedup_key cannot be empty")
	}

	if n.DeliveryStatus == "" {
		n.DeliveryStatus = notify.DeliveryStatusPending
	}
	if n.MaxAttempts <= 0 {
		n.MaxAttempts = 3
	}
	now := time.Now().UTC()
	if n.CreatedAt.IsZero() {
		n.CreatedAt = now
	}
	if n.UpdatedAt.IsZero() {
		n.UpdatedAt = now
	}

	findingIDsJSON := n.FindingIDsJSON()
	payloadJSON := n.PayloadJSON
	if strings.TrimSpace(payloadJSON) == "" {
		payloadJSON = "{}"
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	query := `
	INSERT INTO notification_outbox (
		id, tenant_id, account_id, assessment_id, execution_id, baseline_execution_id,
		event_type, severity, title, message, finding_ids_json, classification,
		dedup_key, delivery_status, attempt_count, max_attempts, next_retry_at,
		last_error, leased_by, lease_expires_at, payload_json, created_at, updated_at
	) VALUES (
		?, ?, ?, ?, ?, ?,
		?, ?, ?, ?, ?, ?,
		?, ?, ?, ?, ?,
		?, ?, ?, ?, ?, ?
	)
	ON CONFLICT(tenant_id, dedup_key) DO NOTHING;
	`

	res, err := s.db.Exec(query,
		n.ID, n.TenantID, nullIfEmpty(n.AccountID), nullIfEmpty(n.AssessmentID), nullIfEmpty(n.ExecutionID), nullIfEmpty(n.BaselineExecutionID),
		n.EventType, n.Severity, secrets.RedactText(n.Title), secrets.RedactText(n.Message), findingIDsJSON, nullIfEmpty(n.Classification),
		n.DedupKey, n.DeliveryStatus, n.AttemptCount, n.MaxAttempts, n.NextRetryAt,
		nullIfEmpty(secrets.RedactText(n.LastError)), nullIfEmpty(n.LeasedBy), n.LeaseExpiresAt, payloadJSON, n.CreatedAt, n.UpdatedAt,
	)
	if err != nil {
		return fmt.Errorf("failed to enqueue notification: %w", err)
	}

	rows, _ := res.RowsAffected()
	if rows == 0 {
		// Existing event for this tenant and dedup key; suppressed idempotently
		return ErrNotificationDuplicate
	}

	return nil
}

// GetNotification fetches a notification record by ID with tenant boundary validation.
func (s *SQLiteStore) GetNotification(id string, auth TenantAuthContext) (*notify.Notification, error) {
	if strings.TrimSpace(id) == "" {
		return nil, errors.New("notification ID cannot be empty")
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	query := `
	SELECT id, tenant_id, account_id, assessment_id, execution_id, baseline_execution_id,
	       event_type, severity, title, message, finding_ids_json, classification,
	       dedup_key, delivery_status, attempt_count, max_attempts, next_retry_at,
	       last_error, leased_by, lease_expires_at, payload_json, created_at, updated_at
	FROM notification_outbox
	WHERE id = ?;
	`

	var n notify.Notification
	var accID, asmID, execID, baseExecID, classif, lastErr, leasedBy sql.NullString
	var fndIDsJSON, payloadJSON string
	var nextRetry, leaseExp sql.NullTime

	err := s.db.QueryRow(query, id).Scan(
		&n.ID, &n.TenantID, &accID, &asmID, &execID, &baseExecID,
		&n.EventType, &n.Severity, &n.Title, &n.Message, &fndIDsJSON, &classif,
		&n.DedupKey, &n.DeliveryStatus, &n.AttemptCount, &n.MaxAttempts, &nextRetry,
		&lastErr, &leasedBy, &leaseExp, &payloadJSON, &n.CreatedAt, &n.UpdatedAt,
	)
	if err == sql.ErrNoRows {
		return nil, ErrNotificationNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get notification: %w", err)
	}

	if accID.Valid {
		n.AccountID = accID.String
	}
	if asmID.Valid {
		n.AssessmentID = asmID.String
	}
	if execID.Valid {
		n.ExecutionID = execID.String
	}
	if baseExecID.Valid {
		n.BaselineExecutionID = baseExecID.String
	}
	if classif.Valid {
		n.Classification = classif.String
	}
	if lastErr.Valid {
		n.LastError = lastErr.String
	}
	if leasedBy.Valid {
		n.LeasedBy = leasedBy.String
	}
	if nextRetry.Valid {
		t := nextRetry.Time.UTC()
		n.NextRetryAt = &t
	}
	if leaseExp.Valid {
		t := leaseExp.Time.UTC()
		n.LeaseExpiresAt = &t
	}
	n.PayloadJSON = payloadJSON
	n.SetFindingIDsFromJSON(fndIDsJSON)

	// Authorization verification: non-admin callers can only access their own tenant's records
	if !auth.IsAdmin() && (auth.TenantID == "" || auth.TenantID != n.TenantID) {
		return nil, ErrNotificationNotFound
	}

	return &n, nil
}

// ListNotifications retrieves a filtered list of notifications for the authorized scope.
func (s *SQLiteStore) ListNotifications(filter notify.NotificationFilter, auth TenantAuthContext) ([]*notify.Notification, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var conds []string
	var args []interface{}

	if !auth.IsAdmin() {
		if auth.TenantID != "" {
			conds = append(conds, "tenant_id = ?")
			args = append(args, auth.TenantID)
		} else {
			conds = append(conds, "1 = 0")
		}
	} else if filter.TenantID != "" {
		conds = append(conds, "tenant_id = ?")
		args = append(args, filter.TenantID)
	}

	if filter.AccountID != "" {
		conds = append(conds, "account_id = ?")
		args = append(args, filter.AccountID)
	}
	if filter.AssessmentID != "" {
		conds = append(conds, "assessment_id = ?")
		args = append(args, filter.AssessmentID)
	}
	if filter.ExecutionID != "" {
		conds = append(conds, "execution_id = ?")
		args = append(args, filter.ExecutionID)
	}
	if filter.EventType != "" {
		conds = append(conds, "event_type = ?")
		args = append(args, filter.EventType)
	}
	if filter.DeliveryStatus != "" && strings.ToUpper(filter.DeliveryStatus) != "ALL" {
		conds = append(conds, "delivery_status = ?")
		args = append(args, strings.ToUpper(filter.DeliveryStatus))
	}

	whereClause := ""
	if len(conds) > 0 {
		whereClause = "WHERE " + strings.Join(conds, " AND ")
	}

	limit := filter.Limit
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	offset := filter.Offset
	if offset < 0 {
		offset = 0
	}

	query := fmt.Sprintf(`
	SELECT id, tenant_id, account_id, assessment_id, execution_id, baseline_execution_id,
	       event_type, severity, title, message, finding_ids_json, classification,
	       dedup_key, delivery_status, attempt_count, max_attempts, next_retry_at,
	       last_error, leased_by, lease_expires_at, payload_json, created_at, updated_at
	FROM notification_outbox
	%s
	ORDER BY created_at DESC
	LIMIT ? OFFSET ?;
	`, whereClause)

	args = append(args, limit, offset)

	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to list notifications: %w", err)
	}
	defer rows.Close()

	var result []*notify.Notification
	for rows.Next() {
		var n notify.Notification
		var accID, asmID, execID, baseExecID, classif, lastErr, leasedBy sql.NullString
		var fndIDsJSON, payloadJSON string
		var nextRetry, leaseExp sql.NullTime

		err := rows.Scan(
			&n.ID, &n.TenantID, &accID, &asmID, &execID, &baseExecID,
			&n.EventType, &n.Severity, &n.Title, &n.Message, &fndIDsJSON, &classif,
			&n.DedupKey, &n.DeliveryStatus, &n.AttemptCount, &n.MaxAttempts, &nextRetry,
			&lastErr, &leasedBy, &leaseExp, &payloadJSON, &n.CreatedAt, &n.UpdatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("failed scanning notification row: %w", err)
		}

		if accID.Valid {
			n.AccountID = accID.String
		}
		if asmID.Valid {
			n.AssessmentID = asmID.String
		}
		if execID.Valid {
			n.ExecutionID = execID.String
		}
		if baseExecID.Valid {
			n.BaselineExecutionID = baseExecID.String
		}
		if classif.Valid {
			n.Classification = classif.String
		}
		if lastErr.Valid {
			n.LastError = lastErr.String
		}
		if leasedBy.Valid {
			n.LeasedBy = leasedBy.String
		}
		if nextRetry.Valid {
			t := nextRetry.Time.UTC()
			n.NextRetryAt = &t
		}
		if leaseExp.Valid {
			t := leaseExp.Time.UTC()
			n.LeaseExpiresAt = &t
		}
		n.PayloadJSON = payloadJSON
		n.SetFindingIDsFromJSON(fndIDsJSON)

		result = append(result, &n)
	}

	return result, nil
}

// ClaimPendingNotifications atomically claims up to limit pending notifications for workerID with leaseDuration.
func (s *SQLiteStore) ClaimPendingNotifications(workerID string, limit int, leaseDuration time.Duration, now time.Time) ([]*notify.Notification, error) {
	if workerID == "" {
		return nil, errors.New("workerID cannot be empty")
	}
	if limit <= 0 {
		limit = 10
	}
	if leaseDuration <= 0 {
		leaseDuration = 60 * time.Second
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	// Query eligible pending notifications
	query := `
	SELECT id, tenant_id, account_id, assessment_id, execution_id, baseline_execution_id,
	       event_type, severity, title, message, finding_ids_json, classification,
	       dedup_key, delivery_status, attempt_count, max_attempts, next_retry_at,
	       last_error, leased_by, lease_expires_at, payload_json, created_at, updated_at
	FROM notification_outbox
	WHERE delivery_status = 'PENDING'
	  AND (next_retry_at IS NULL OR next_retry_at <= ?)
	  AND (leased_by IS NULL OR lease_expires_at IS NULL OR lease_expires_at <= ?)
	ORDER BY created_at ASC
	LIMIT ?;
	`

	rows, err := tx.Query(query, now, now, limit)
	if err != nil {
		return nil, fmt.Errorf("failed querying pending notifications: %w", err)
	}
	defer rows.Close()

	var claimed []*notify.Notification
	var idsToClaim []string

	for rows.Next() {
		var n notify.Notification
		var accID, asmID, execID, baseExecID, classif, lastErr, leasedBy sql.NullString
		var fndIDsJSON, payloadJSON string
		var nextRetry, leaseExp sql.NullTime

		err := rows.Scan(
			&n.ID, &n.TenantID, &accID, &asmID, &execID, &baseExecID,
			&n.EventType, &n.Severity, &n.Title, &n.Message, &fndIDsJSON, &classif,
			&n.DedupKey, &n.DeliveryStatus, &n.AttemptCount, &n.MaxAttempts, &nextRetry,
			&lastErr, &leasedBy, &leaseExp, &payloadJSON, &n.CreatedAt, &n.UpdatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("failed scanning claimable row: %w", err)
		}

		if accID.Valid {
			n.AccountID = accID.String
		}
		if asmID.Valid {
			n.AssessmentID = asmID.String
		}
		if execID.Valid {
			n.ExecutionID = execID.String
		}
		if baseExecID.Valid {
			n.BaselineExecutionID = baseExecID.String
		}
		if classif.Valid {
			n.Classification = classif.String
		}
		if lastErr.Valid {
			n.LastError = lastErr.String
		}
		if leasedBy.Valid {
			n.LeasedBy = leasedBy.String
		}
		if nextRetry.Valid {
			t := nextRetry.Time.UTC()
			n.NextRetryAt = &t
		}
		if leaseExp.Valid {
			t := leaseExp.Time.UTC()
			n.LeaseExpiresAt = &t
		}
		n.PayloadJSON = payloadJSON
		n.SetFindingIDsFromJSON(fndIDsJSON)

		claimed = append(claimed, &n)
		idsToClaim = append(idsToClaim, n.ID)
	}
	rows.Close()

	if len(idsToClaim) == 0 {
		return nil, nil
	}

	// Update lease fields for claimed notifications
	leaseExpiresAt := now.Add(leaseDuration)
	updateStmt := `
	UPDATE notification_outbox
	SET leased_by = ?, lease_expires_at = ?, updated_at = ?
	WHERE id = ?;
	`
	stmt, err := tx.Prepare(updateStmt)
	if err != nil {
		return nil, fmt.Errorf("failed preparing claim update: %w", err)
	}
	defer stmt.Close()

	for _, id := range idsToClaim {
		if _, err := stmt.Exec(workerID, leaseExpiresAt, now, id); err != nil {
			return nil, fmt.Errorf("failed updating claim lease for %s: %w", id, err)
		}
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("failed committing claim transaction: %w", err)
	}

	for _, n := range claimed {
		n.LeasedBy = workerID
		n.LeaseExpiresAt = &leaseExpiresAt
		n.UpdatedAt = now
	}

	return claimed, nil
}

// RenewNotificationLease extends an active delivery lease for a working notification worker.
func (s *SQLiteStore) RenewNotificationLease(id, workerID string, leaseDuration time.Duration) error {
	if id == "" || workerID == "" {
		return errors.New("id and workerID cannot be empty")
	}
	if leaseDuration <= 0 {
		leaseDuration = 60 * time.Second
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now().UTC()
	leaseExp := now.Add(leaseDuration)

	res, err := s.db.Exec(`
		UPDATE notification_outbox
		SET lease_expires_at = ?, updated_at = ?
		WHERE id = ? AND leased_by = ? AND (lease_expires_at IS NULL OR lease_expires_at >= ?) AND delivery_status = 'PENDING';
	`, leaseExp, now, id, workerID, now)
	if err != nil {
		return fmt.Errorf("failed renewing notification lease: %w", err)
	}

	rows, _ := res.RowsAffected()
	if rows == 0 {
		return ErrLeaseLost
	}

	return nil
}

// MarkNotificationDelivered transitions a notification to DELIVERED status.
// Fencing: Only the active lease holder can mark the notification delivered.
// Stale workers or workers whose lease has been reclaimed are safely prevented from corrupting state.
func (s *SQLiteStore) MarkNotificationDelivered(id, workerID string, deliveredAt time.Time) error {
	if id == "" {
		return errors.New("notification id cannot be empty")
	}
	if deliveredAt.IsZero() {
		deliveredAt = time.Now().UTC()
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	var query string
	var args []interface{}
	if workerID != "" {
		query = `
			UPDATE notification_outbox
			SET delivery_status = 'DELIVERED', leased_by = NULL, lease_expires_at = NULL, last_error = NULL, updated_at = ?
			WHERE id = ? AND leased_by = ? AND (lease_expires_at IS NULL OR lease_expires_at >= ?) AND delivery_status = 'PENDING';
		`
		args = []interface{}{deliveredAt, id, workerID, deliveredAt}
	} else {
		query = `
			UPDATE notification_outbox
			SET delivery_status = 'DELIVERED', leased_by = NULL, lease_expires_at = NULL, last_error = NULL, updated_at = ?
			WHERE id = ?;
		`
		args = []interface{}{deliveredAt, id}
	}

	res, err := s.db.Exec(query, args...)
	if err != nil {
		return fmt.Errorf("failed marking notification delivered: %w", err)
	}

	rows, _ := res.RowsAffected()
	if rows == 0 {
		var currentStatus string
		err := s.db.QueryRow("SELECT delivery_status FROM notification_outbox WHERE id = ?", id).Scan(&currentStatus)
		if err == sql.ErrNoRows {
			return ErrNotificationNotFound
		}
		if currentStatus == notify.DeliveryStatusDelivered {
			return nil // already delivered idempotently
		}
		return ErrLeaseLost
	}

	return nil
}

// MarkNotificationFailed records a failed delivery attempt, updating next retry or marking FAILED.
// Fencing: Stale workers whose lease has been lost or reclaimed cannot overwrite newer delivery state.
func (s *SQLiteStore) MarkNotificationFailed(id, workerID string, errStr string, nextRetryAt *time.Time, permanent bool) error {
	if id == "" {
		return errors.New("notification id cannot be empty")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now().UTC()
	redactedErr := secrets.RedactText(errStr)

	var query string
	var args []interface{}

	if permanent {
		if workerID != "" {
			query = `
				UPDATE notification_outbox
				SET delivery_status = 'FAILED', leased_by = NULL, lease_expires_at = NULL,
				    attempt_count = attempt_count + 1, last_error = ?, updated_at = ?
				WHERE id = ? AND leased_by = ? AND (lease_expires_at IS NULL OR lease_expires_at >= ?) AND delivery_status = 'PENDING';
			`
			args = []interface{}{redactedErr, now, id, workerID, now}
		} else {
			query = `
				UPDATE notification_outbox
				SET delivery_status = 'FAILED', leased_by = NULL, lease_expires_at = NULL,
				    attempt_count = attempt_count + 1, last_error = ?, updated_at = ?
				WHERE id = ?;
			`
			args = []interface{}{redactedErr, now, id}
		}
	} else {
		if workerID != "" {
			query = `
				UPDATE notification_outbox
				SET delivery_status = 'PENDING', leased_by = NULL, lease_expires_at = NULL,
				    attempt_count = attempt_count + 1, next_retry_at = ?, last_error = ?, updated_at = ?
				WHERE id = ? AND leased_by = ? AND (lease_expires_at IS NULL OR lease_expires_at >= ?) AND delivery_status = 'PENDING';
			`
			args = []interface{}{nextRetryAt, redactedErr, now, id, workerID, now}
		} else {
			query = `
				UPDATE notification_outbox
				SET delivery_status = 'PENDING', leased_by = NULL, lease_expires_at = NULL,
				    attempt_count = attempt_count + 1, next_retry_at = ?, last_error = ?, updated_at = ?
				WHERE id = ?;
			`
			args = []interface{}{nextRetryAt, redactedErr, now, id}
		}
	}

	res, err := s.db.Exec(query, args...)
	if err != nil {
		return fmt.Errorf("failed recording delivery failure: %w", err)
	}

	rows, _ := res.RowsAffected()
	if rows == 0 {
		var currentStatus string
		err := s.db.QueryRow("SELECT delivery_status FROM notification_outbox WHERE id = ?", id).Scan(&currentStatus)
		if err == sql.ErrNoRows {
			return ErrNotificationNotFound
		}
		if currentStatus == notify.DeliveryStatusDelivered {
			// Already delivered by another worker; stale failure write safely ignored
			return nil
		}
		return ErrLeaseLost
	}

	return nil
}

// RetryNotification resets a failed notification to PENDING so it can be re-dispatched.
func (s *SQLiteStore) RetryNotification(id string, auth TenantAuthContext) error {
	if id == "" {
		return errors.New("notification id cannot be empty")
	}

	// Check authorization
	notif, err := s.GetNotification(id, auth)
	if err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now().UTC()
	_, err = s.db.Exec(`
		UPDATE notification_outbox
		SET delivery_status = 'PENDING', leased_by = NULL, lease_expires_at = NULL,
		    next_retry_at = NULL, updated_at = ?
		WHERE id = ?;
	`, now, notif.ID)
	if err != nil {
		return fmt.Errorf("failed to reset notification for retry: %w", err)
	}

	return nil
}

// ReclaimExpiredNotificationLeases releases leases held by crashed or abandoned workers.
func (s *SQLiteStore) ReclaimExpiredNotificationLeases(now time.Time) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	res, err := s.db.Exec(`
		UPDATE notification_outbox
		SET leased_by = NULL, lease_expires_at = NULL, updated_at = ?
		WHERE delivery_status = 'PENDING'
		  AND lease_expires_at IS NOT NULL
		  AND lease_expires_at <= ?;
	`, now, now)
	if err != nil {
		return 0, fmt.Errorf("failed reclaiming expired notification leases: %w", err)
	}

	rows, _ := res.RowsAffected()
	return int(rows), nil
}

// GetNotificationStats aggregates health and counts for the outbox subsystem.
func (s *SQLiteStore) GetNotificationStats(auth TenantAuthContext) (*notify.SubsystemStats, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	whereClause := ""
	var args []interface{}
	if !auth.IsAdmin() {
		if auth.TenantID != "" {
			whereClause = "WHERE tenant_id = ?"
			args = append(args, auth.TenantID)
		} else {
			whereClause = "WHERE 1 = 0"
		}
	}

	stats := &notify.SubsystemStats{
		SubsystemHealthy: true,
	}

	query := fmt.Sprintf(`
	SELECT delivery_status, COUNT(*), MIN(created_at), MAX(updated_at)
	FROM notification_outbox
	%s
	GROUP BY delivery_status;
	`, whereClause)

	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed querying notification stats: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var status string
		var count int
		var minCreated, maxUpdated sql.NullTime

		if err := rows.Scan(&status, &count, &minCreated, &maxUpdated); err != nil {
			return nil, err
		}

		stats.TotalNotifications += count
		switch status {
		case "PENDING":
			stats.PendingCount = count
			if minCreated.Valid {
				t := minCreated.Time.UTC()
				stats.OldestPendingAt = &t
			}
		case "DELIVERED":
			stats.DeliveredCount = count
			if maxUpdated.Valid {
				t := maxUpdated.Time.UTC()
				stats.LastDeliveredAt = &t
			}
		case "FAILED":
			stats.FailedCount = count
			if maxUpdated.Valid {
				t := maxUpdated.Time.UTC()
				stats.LastFailedAt = &t
			}
		}
	}

	// Healthy if failed count is reasonable or subsystem is actively processing
	if stats.FailedCount > 50 && stats.FailedCount > stats.DeliveredCount {
		stats.SubsystemHealthy = false
	}

	return stats, nil
}


// ReconcileExecutionNotifications scans terminal executions that lack lifecycle notifications and enqueues them.
// Idempotency: Duplicate events are suppressed by ON CONFLICT(tenant_id, dedup_key) DO NOTHING.
func (s *SQLiteStore) ReconcileExecutionNotifications(auth TenantAuthContext, lookback time.Duration) (int, error) {
	s.mu.RLock()

	var args []interface{}
	timeClause := ""
	if lookback > 0 {
		cutoff := time.Now().UTC().Add(-lookback)
		timeClause = "AND COALESCE(ae.completed_at, ae.updated_at, ae.created_at) >= ?"
		args = append(args, cutoff)
	}

	tenantClause := ""
	if !auth.IsAdmin() {
		if auth.TenantID != "" {
			tenantClause = "AND ae.tenant_id = ?"
			args = append(args, auth.TenantID)
		} else {
			tenantClause = "AND 1=0"
		}
	}

	query := fmt.Sprintf(`
		SELECT ae.id, ae.assessment_id, ae.tenant_id, ae.account_id, ae.status,
		       ae.finding_count, ae.duration_ms, ae.error_message, ae.completed_at, a.ref
		FROM assessment_executions ae
		JOIN assessments a ON a.id = ae.assessment_id
		LEFT JOIN notification_outbox no ON no.execution_id = ae.id AND no.event_type = CASE ae.status
			WHEN 'COMPLETED' THEN 'assessment.completed'
			WHEN 'COMPLETED_WITH_ERRORS' THEN 'assessment.completed_with_errors'
			WHEN 'FAILED' THEN 'assessment.failed'
			WHEN 'CANCELLED' THEN 'assessment.cancelled'
			WHEN 'INTERRUPTED' THEN 'assessment.interrupted'
			ELSE ('assessment.' || LOWER(ae.status))
		END
		WHERE ae.status IN ('COMPLETED', 'COMPLETED_WITH_ERRORS', 'FAILED', 'CANCELLED', 'INTERRUPTED')
		  %s
		  %s
		  AND (no.id IS NULL OR no.payload_json IS NULL OR trim(no.payload_json) = '' OR no.payload_json = '{}')
		ORDER BY COALESCE(ae.completed_at, ae.updated_at, ae.created_at) ASC
		LIMIT 100;
	`, timeClause, tenantClause)

	rows, err := s.db.Query(query, args...)
	s.mu.RUnlock()
	if err != nil {
		return 0, fmt.Errorf("failed querying unreconciled executions: %w", err)
	}
	defer rows.Close()

	type unrecExec struct {
		id, asmID, tenantID, accountID, status, errMsg, ref string
		fndCount, durMs                                     int
		completedAt                                         time.Time
	}
	var toReconcile []unrecExec
	for rows.Next() {
		var u unrecExec
		var accID, errMsg sql.NullString
		var compAt sql.NullTime
		if err := rows.Scan(&u.id, &u.asmID, &u.tenantID, &accID, &u.status, &u.fndCount, &u.durMs, &errMsg, &compAt, &u.ref); err == nil {
			if accID.Valid {
				u.accountID = accID.String
			}
			if errMsg.Valid {
				u.errMsg = errMsg.String
			}
			if compAt.Valid {
				u.completedAt = compAt.Time.UTC()
			}
			toReconcile = append(toReconcile, u)
		}
	}
	rows.Close()

	enqueuedCount := 0
	for _, u := range toReconcile {
		notif := notify.BuildLifecycleNotification(
			u.tenantID, u.accountID, u.asmID, u.ref, u.id,
			u.status, u.fndCount, time.Duration(u.durMs)*time.Millisecond, u.errMsg, u.completedAt,
		)
		if err := s.EnqueueNotification(notif); err == nil {
			enqueuedCount++
		}
	}

	return enqueuedCount, nil
}
