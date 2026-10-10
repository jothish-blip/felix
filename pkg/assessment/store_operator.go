package assessment

import (
	"database/sql"
	"fmt"
	"time"

	"github.com/google/uuid"
)

// --- Finding Reviews ---

// SaveFindingReview creates or updates an operator review decision for a finding.
// Invariant: This is strictly an editorial decision for reporting and does NOT
// modify the underlying technical verification status or evidence.
func (s *SQLiteStore) SaveFindingReview(r *FindingReview) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if r.ID == "" {
		r.ID = "rev-" + uuid.New().String()
	}
	now := time.Now().UTC()
	if r.CreatedAt.IsZero() {
		r.CreatedAt = now
	}
	r.UpdatedAt = now
	if r.ReviewedAt.IsZero() {
		r.ReviewedAt = now
	}
	if !r.ReviewStatus.IsValid() {
		return fmt.Errorf("invalid review status: %s", r.ReviewStatus)
	}

	query := `
	INSERT INTO finding_reviews (
		id, assessment_id, finding_id, review_status, reviewed_by, reviewed_at, notes, created_at, updated_at
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
	ON CONFLICT(assessment_id, finding_id) DO UPDATE SET
		review_status = excluded.review_status,
		reviewed_by   = excluded.reviewed_by,
		reviewed_at   = excluded.reviewed_at,
		notes         = excluded.notes,
		updated_at    = excluded.updated_at;
	`

	_, err := s.db.Exec(query,
		r.ID,
		r.AssessmentID,
		r.FindingID,
		string(r.ReviewStatus),
		r.ReviewedBy,
		r.ReviewedAt,
		r.Notes,
		r.CreatedAt,
		r.UpdatedAt,
	)
	return err
}

// GetFindingReview retrieves the review decision for a finding in an assessment.
func (s *SQLiteStore) GetFindingReview(assessmentID string, findingID string) (*FindingReview, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	query := `
	SELECT id, assessment_id, finding_id, review_status, reviewed_by, reviewed_at, notes, created_at, updated_at
	FROM finding_reviews
	WHERE assessment_id = ? AND finding_id = ?;
	`

	var r FindingReview
	var statusStr string
	var notes sql.NullString

	err := s.db.QueryRow(query, assessmentID, findingID).Scan(
		&r.ID,
		&r.AssessmentID,
		&r.FindingID,
		&statusStr,
		&r.ReviewedBy,
		&r.ReviewedAt,
		&notes,
		&r.CreatedAt,
		&r.UpdatedAt,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	r.ReviewStatus = ReviewStatus(statusStr)
	if notes.Valid {
		r.Notes = notes.String
	}
	return &r, nil
}

// ListFindingReviews lists all finding reviews for an assessment.
func (s *SQLiteStore) ListFindingReviews(assessmentID string) ([]FindingReview, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	query := `
	SELECT id, assessment_id, finding_id, review_status, reviewed_by, reviewed_at, notes, created_at, updated_at
	FROM finding_reviews
	WHERE assessment_id = ?
	ORDER BY created_at ASC;
	`

	rows, err := s.db.Query(query, assessmentID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var reviews []FindingReview
	for rows.Next() {
		var r FindingReview
		var statusStr string
		var notes sql.NullString

		if err := rows.Scan(
			&r.ID,
			&r.AssessmentID,
			&r.FindingID,
			&statusStr,
			&r.ReviewedBy,
			&r.ReviewedAt,
			&notes,
			&r.CreatedAt,
			&r.UpdatedAt,
		); err != nil {
			return nil, err
		}
		r.ReviewStatus = ReviewStatus(statusStr)
		if notes.Valid {
			r.Notes = notes.String
		}
		reviews = append(reviews, r)
	}
	return reviews, rows.Err()
}

// --- Report Deliveries ---

// CreateReportDelivery records a new report delivery tracking entry.
func (s *SQLiteStore) CreateReportDelivery(d *ReportDelivery) error {
	if err := d.Validate(); err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if d.ID == "" {
		d.ID = "del-" + uuid.New().String()
	}
	now := time.Now().UTC()
	if d.CreatedAt.IsZero() {
		d.CreatedAt = now
	}
	d.UpdatedAt = now

	query := `
	INSERT INTO report_deliveries (
		id, assessment_id, report_id, delivery_status, recipient_name, recipient_email,
		delivery_method, tracking_reference, notes, dispatched_at, delivered_at, operator_id,
		created_at, updated_at
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
	`

	_, err := s.db.Exec(query,
		d.ID,
		d.AssessmentID,
		d.ReportID,
		string(d.DeliveryStatus),
		d.RecipientName,
		d.RecipientEmail,
		string(d.DeliveryMethod),
		d.TrackingReference,
		d.Notes,
		d.DispatchedAt,
		d.DeliveredAt,
		d.OperatorID,
		d.CreatedAt,
		d.UpdatedAt,
	)
	return err
}

// GetReportDelivery retrieves a delivery record by ID.
func (s *SQLiteStore) GetReportDelivery(id string) (*ReportDelivery, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	query := `
	SELECT id, assessment_id, report_id, delivery_status, recipient_name, recipient_email,
	       delivery_method, tracking_reference, notes, dispatched_at, delivered_at, operator_id,
	       created_at, updated_at
	FROM report_deliveries
	WHERE id = ?;
	`

	var d ReportDelivery
	var statusStr, methodStr string
	var trackingRef, notes sql.NullString
	var dispatchedAt, deliveredAt sql.NullTime

	err := s.db.QueryRow(query, id).Scan(
		&d.ID,
		&d.AssessmentID,
		&d.ReportID,
		&statusStr,
		&d.RecipientName,
		&d.RecipientEmail,
		&methodStr,
		&trackingRef,
		&notes,
		&dispatchedAt,
		&deliveredAt,
		&d.OperatorID,
		&d.CreatedAt,
		&d.UpdatedAt,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	d.DeliveryStatus = DeliveryStatus(statusStr)
	d.DeliveryMethod = DeliveryMethod(methodStr)
	if trackingRef.Valid {
		d.TrackingReference = trackingRef.String
	}
	if notes.Valid {
		d.Notes = notes.String
	}
	if dispatchedAt.Valid {
		t := dispatchedAt.Time
		d.DispatchedAt = &t
	}
	if deliveredAt.Valid {
		t := deliveredAt.Time
		d.DeliveredAt = &t
	}
	return &d, nil
}

// ListReportDeliveries lists all delivery records for an assessment.
func (s *SQLiteStore) ListReportDeliveries(assessmentID string) ([]ReportDelivery, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	query := `
	SELECT id, assessment_id, report_id, delivery_status, recipient_name, recipient_email,
	       delivery_method, tracking_reference, notes, dispatched_at, delivered_at, operator_id,
	       created_at, updated_at
	FROM report_deliveries
	WHERE assessment_id = ?
	ORDER BY created_at DESC;
	`

	rows, err := s.db.Query(query, assessmentID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var deliveries []ReportDelivery
	for rows.Next() {
		var d ReportDelivery
		var statusStr, methodStr string
		var trackingRef, notes sql.NullString
		var dispatchedAt, deliveredAt sql.NullTime

		if err := rows.Scan(
			&d.ID,
			&d.AssessmentID,
			&d.ReportID,
			&statusStr,
			&d.RecipientName,
			&d.RecipientEmail,
			&methodStr,
			&trackingRef,
			&notes,
			&dispatchedAt,
			&deliveredAt,
			&d.OperatorID,
			&d.CreatedAt,
			&d.UpdatedAt,
		); err != nil {
			return nil, err
		}

		d.DeliveryStatus = DeliveryStatus(statusStr)
		d.DeliveryMethod = DeliveryMethod(methodStr)
		if trackingRef.Valid {
			d.TrackingReference = trackingRef.String
		}
		if notes.Valid {
			d.Notes = notes.String
		}
		if dispatchedAt.Valid {
			t := dispatchedAt.Time
			d.DispatchedAt = &t
		}
		if deliveredAt.Valid {
			t := deliveredAt.Time
			d.DeliveredAt = &t
		}
		deliveries = append(deliveries, d)
	}
	return deliveries, rows.Err()
}

// UpdateReportDeliveryStatus updates the lifecycle state of a report delivery.
func (s *SQLiteStore) UpdateReportDeliveryStatus(id string, status DeliveryStatus, notes string, timestamp *time.Time) error {
	if !status.IsValid() {
		return fmt.Errorf("invalid delivery status: %s", status)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now().UTC()
	var query string
	var args []any

	switch status {
	case DeliveryStatusConfirmed:
		if timestamp == nil {
			timestamp = &now
		}
		query = `UPDATE report_deliveries SET delivery_status = ?, notes = COALESCE(NULLIF(?, ''), notes), delivered_at = ?, updated_at = ? WHERE id = ?`
		args = []any{string(status), notes, *timestamp, now, id}
	case DeliveryStatusDispatched:
		if timestamp == nil {
			timestamp = &now
		}
		query = `UPDATE report_deliveries SET delivery_status = ?, notes = COALESCE(NULLIF(?, ''), notes), dispatched_at = ?, updated_at = ? WHERE id = ?`
		args = []any{string(status), notes, *timestamp, now, id}
	default:
		query = `UPDATE report_deliveries SET delivery_status = ?, notes = COALESCE(NULLIF(?, ''), notes), updated_at = ? WHERE id = ?`
		args = []any{string(status), notes, now, id}
	}

	res, err := s.db.Exec(query, args...)
	if err != nil {
		return err
	}
	affected, _ := res.RowsAffected()
	if affected == 0 {
		return fmt.Errorf("delivery record %q not found", id)
	}
	return nil
}

// --- Audit Events ---

// RecordAuditEvent writes an append-only audit event log entry.
func (s *SQLiteStore) RecordAuditEvent(e *AuditEvent) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if e.ID == "" {
		e.ID = "aud-" + uuid.New().String()
	}
	if e.CreatedAt.IsZero() {
		e.CreatedAt = time.Now().UTC()
	}

	query := `
	INSERT INTO operator_audit_events (
		id, assessment_id, operator_id, action_type, entity_type, entity_id, details_json, created_at
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?);
	`

	_, err := s.db.Exec(query,
		e.ID,
		e.AssessmentID,
		e.OperatorID,
		e.ActionType,
		e.EntityType,
		e.EntityID,
		e.DetailsJSON,
		e.CreatedAt,
	)
	return err
}

// ListAuditEvents queries audit log records. If assessmentID is empty, retrieves recent global audit events.
func (s *SQLiteStore) ListAuditEvents(assessmentID string, limit int) ([]AuditEvent, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if limit <= 0 || limit > 1000 {
		limit = 100
	}

	var query string
	var args []any

	if assessmentID != "" {
		query = `
		SELECT id, assessment_id, operator_id, action_type, entity_type, entity_id, details_json, created_at
		FROM operator_audit_events
		WHERE assessment_id = ?
		ORDER BY created_at DESC
		LIMIT ?;
		`
		args = []any{assessmentID, limit}
	} else {
		query = `
		SELECT id, assessment_id, operator_id, action_type, entity_type, entity_id, details_json, created_at
		FROM operator_audit_events
		ORDER BY created_at DESC
		LIMIT ?;
		`
		args = []any{limit}
	}

	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var events []AuditEvent
	for rows.Next() {
		var e AuditEvent
		var asmID, details sql.NullString

		if err := rows.Scan(
			&e.ID,
			&asmID,
			&e.OperatorID,
			&e.ActionType,
			&e.EntityType,
			&e.EntityID,
			&details,
			&e.CreatedAt,
		); err != nil {
			return nil, err
		}
		if asmID.Valid {
			e.AssessmentID = asmID.String
		}
		if details.Valid {
			e.DetailsJSON = details.String
		}
		events = append(events, e)
	}
	return events, rows.Err()
}

// --- Scan Job Leases (Concurrency & Job Management) ---

// AcquireScanJobLease acquires an exclusive scan execution lease for an assessment.
func (s *SQLiteStore) AcquireScanJobLease(lease *ScanJobLease) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now().UTC()
	staleThreshold := now.Add(-3 * time.Minute)

	// Check if active unexpired lease exists
	var existingExecID, existingOp, existingStatus string
	var existingHeartbeat time.Time
	err := s.db.QueryRow(`
		SELECT execution_id, operator_id, status, heartbeat_at
		FROM scan_job_leases
		WHERE id = ? AND status IN ('QUEUED', 'RUNNING') AND heartbeat_at > ?;
	`, lease.ID, staleThreshold).Scan(&existingExecID, &existingOp, &existingStatus, &existingHeartbeat)

	if err == nil {
		return fmt.Errorf("active scan execution already in progress for assessment %s (exec: %s by %s, status: %s)",
			lease.ID, existingExecID, existingOp, existingStatus)
	}
	if err != sql.ErrNoRows {
		return fmt.Errorf("failed to check existing scan lease: %w", err)
	}

	lease.AcquiredAt = now
	lease.HeartbeatAt = now

	query := `
	INSERT INTO scan_job_leases (
		id, execution_id, operator_id, acquired_at, heartbeat_at, status, error_message, progress_message
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
	ON CONFLICT(id) DO UPDATE SET
		execution_id     = excluded.execution_id,
		operator_id      = excluded.operator_id,
		acquired_at      = excluded.acquired_at,
		heartbeat_at     = excluded.heartbeat_at,
		status           = excluded.status,
		error_message    = excluded.error_message,
		progress_message = excluded.progress_message;
	`

	_, err = s.db.Exec(query,
		lease.ID,
		lease.ExecutionID,
		lease.OperatorID,
		lease.AcquiredAt,
		lease.HeartbeatAt,
		lease.Status,
		lease.ErrorMessage,
		lease.ProgressMessage,
	)
	return err
}

// HeartbeatScanJobLease updates the heartbeat timestamp and progress text of an active lease.
func (s *SQLiteStore) HeartbeatScanJobLease(assessmentID string, progress string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	query := `
	UPDATE scan_job_leases
	SET heartbeat_at = ?, progress_message = ?
	WHERE id = ?;
	`
	_, err := s.db.Exec(query, time.Now().UTC(), progress, assessmentID)
	return err
}

// ReleaseScanJobLease updates the lease state upon completion, error, or cancellation.
func (s *SQLiteStore) ReleaseScanJobLease(assessmentID string, status string, errMsg string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	query := `
	UPDATE scan_job_leases
	SET status = ?, error_message = ?, heartbeat_at = ?
	WHERE id = ?;
	`
	_, err := s.db.Exec(query, status, errMsg, time.Now().UTC(), assessmentID)
	return err
}

// GetActiveScanJobLease retrieves the current lease state for an assessment.
func (s *SQLiteStore) GetActiveScanJobLease(assessmentID string) (*ScanJobLease, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	query := `
	SELECT id, execution_id, operator_id, acquired_at, heartbeat_at, status, error_message, progress_message
	FROM scan_job_leases
	WHERE id = ?;
	`

	var l ScanJobLease
	var errMsg, progMsg sql.NullString

	err := s.db.QueryRow(query, assessmentID).Scan(
		&l.ID,
		&l.ExecutionID,
		&l.OperatorID,
		&l.AcquiredAt,
		&l.HeartbeatAt,
		&l.Status,
		&errMsg,
		&progMsg,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if errMsg.Valid {
		l.ErrorMessage = errMsg.String
	}
	if progMsg.Valid {
		l.ProgressMessage = progMsg.String
	}
	return &l, nil
}

// RecoverStaleScanJobLeases detects and fails any scan job leases whose heartbeat has expired.
func (s *SQLiteStore) RecoverStaleScanJobLeases(staleDuration time.Duration) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if staleDuration <= 0 {
		staleDuration = 2 * time.Minute
	}
	staleThreshold := time.Now().UTC().Add(-staleDuration)

	query := `
	UPDATE scan_job_leases
	SET status = 'FAILED', error_message = 'Process terminated unexpectedly or lost heartbeat', heartbeat_at = ?
	WHERE status IN ('QUEUED', 'RUNNING') AND heartbeat_at < ?;
	`

	res, err := s.db.Exec(query, time.Now().UTC(), staleThreshold)
	if err != nil {
		return 0, err
	}
	affected, err := res.RowsAffected()
	return int(affected), err
}
