package compliance

import (
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
)

// PlatformSyncRecord captures durable tracking of an outbound compliance platform synchronization.
type PlatformSyncRecord struct {
	SyncID              string             `json:"sync_id"`
	Platform            CompliancePlatform `json:"platform"`
	AssessmentID        string             `json:"assessment_id"`
	ExecutionID         string             `json:"execution_id,omitempty"`
	AttestationLetterID string             `json:"attestation_letter_id,omitempty"`
	ExternalRecordID    string             `json:"external_record_id,omitempty"`
	ExternalURL         string             `json:"external_url,omitempty"`
	Status              SyncStatus         `json:"status"` // "SUCCESS", "PARTIAL", "FAILED", "REJECTED"
	IdempotencyKey      string             `json:"idempotency_key"`
	PayloadDigest       string             `json:"payload_digest"`
	RecordsSynced       int                `json:"records_synced"`
	RecordsFailed       int                `json:"records_failed"`
	ErrorMessage        string             `json:"error_message,omitempty"`
	SyncedAt            time.Time          `json:"synced_at"`
	CreatedAt           time.Time          `json:"created_at"`
}

// SavePlatformSyncRecord persists or updates a synchronization record in SQLite.
func (s *SQLiteComplianceStore) SavePlatformSyncRecord(rec *PlatformSyncRecord) error {
	if rec == nil {
		return errors.New("cannot save nil PlatformSyncRecord")
	}
	if strings.TrimSpace(rec.SyncID) == "" {
		return errors.New("sync_id cannot be empty")
	}
	if strings.TrimSpace(string(rec.Platform)) == "" {
		return errors.New("platform cannot be empty")
	}
	if strings.TrimSpace(rec.AssessmentID) == "" {
		return errors.New("assessment_id cannot be empty")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now().UTC()
	if rec.CreatedAt.IsZero() {
		rec.CreatedAt = now
	}
	if rec.SyncedAt.IsZero() {
		rec.SyncedAt = now
	}

	query := `
	INSERT INTO compliance_platform_sync_records (
		sync_id, platform, assessment_id, execution_id, attestation_letter_id,
		external_record_id, external_url, status, idempotency_key, payload_digest,
		records_synced, records_failed, error_message, synced_at, created_at
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	ON CONFLICT(sync_id) DO UPDATE SET
		status = excluded.status,
		external_record_id = excluded.external_record_id,
		external_url = excluded.external_url,
		records_synced = excluded.records_synced,
		records_failed = excluded.records_failed,
		error_message = excluded.error_message,
		synced_at = excluded.synced_at;
	`

	_, err := s.db.Exec(
		query,
		rec.SyncID,
		string(rec.Platform),
		rec.AssessmentID,
		rec.ExecutionID,
		rec.AttestationLetterID,
		rec.ExternalRecordID,
		rec.ExternalURL,
		string(rec.Status),
		rec.IdempotencyKey,
		rec.PayloadDigest,
		rec.RecordsSynced,
		rec.RecordsFailed,
		rec.ErrorMessage,
		rec.SyncedAt,
		rec.CreatedAt,
	)
	if err != nil {
		return fmt.Errorf("failed saving platform sync record %s: %w", rec.SyncID, err)
	}

	return nil
}

// GetPlatformSyncRecord retrieves a sync record by its unique sync_id.
func (s *SQLiteComplianceStore) GetPlatformSyncRecord(syncID string) (*PlatformSyncRecord, error) {
	if strings.TrimSpace(syncID) == "" {
		return nil, errors.New("sync_id cannot be empty")
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	query := `
	SELECT sync_id, platform, assessment_id, execution_id, attestation_letter_id,
	       external_record_id, external_url, status, idempotency_key, payload_digest,
	       records_synced, records_failed, error_message, synced_at, created_at
	FROM compliance_platform_sync_records
	WHERE sync_id = ?;
	`

	var rec PlatformSyncRecord
	var platformStr, statusStr string
	err := s.db.QueryRow(query, syncID).Scan(
		&rec.SyncID,
		&platformStr,
		&rec.AssessmentID,
		&rec.ExecutionID,
		&rec.AttestationLetterID,
		&rec.ExternalRecordID,
		&rec.ExternalURL,
		&statusStr,
		&rec.IdempotencyKey,
		&rec.PayloadDigest,
		&rec.RecordsSynced,
		&rec.RecordsFailed,
		&rec.ErrorMessage,
		&rec.SyncedAt,
		&rec.CreatedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("failed querying platform sync record %s: %w", syncID, err)
	}

	rec.Platform = CompliancePlatform(platformStr)
	rec.Status = SyncStatus(statusStr)
	return &rec, nil
}

// GetPlatformSyncRecordByIdempotencyKey retrieves an existing sync record matching the given idempotency key.
func (s *SQLiteComplianceStore) GetPlatformSyncRecordByIdempotencyKey(key string) (*PlatformSyncRecord, error) {
	if strings.TrimSpace(key) == "" {
		return nil, errors.New("idempotency key cannot be empty")
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	query := `
	SELECT sync_id, platform, assessment_id, execution_id, attestation_letter_id,
	       external_record_id, external_url, status, idempotency_key, payload_digest,
	       records_synced, records_failed, error_message, synced_at, created_at
	FROM compliance_platform_sync_records
	WHERE idempotency_key = ?
	ORDER BY created_at DESC
	LIMIT 1;
	`

	var rec PlatformSyncRecord
	var platformStr, statusStr string
	err := s.db.QueryRow(query, key).Scan(
		&rec.SyncID,
		&platformStr,
		&rec.AssessmentID,
		&rec.ExecutionID,
		&rec.AttestationLetterID,
		&rec.ExternalRecordID,
		&rec.ExternalURL,
		&statusStr,
		&rec.IdempotencyKey,
		&rec.PayloadDigest,
		&rec.RecordsSynced,
		&rec.RecordsFailed,
		&rec.ErrorMessage,
		&rec.SyncedAt,
		&rec.CreatedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("failed querying platform sync record by idempotency key: %w", err)
	}

	rec.Platform = CompliancePlatform(platformStr)
	rec.Status = SyncStatus(statusStr)
	return &rec, nil
}

// ListPlatformSyncRecords queries synchronization records filtered by platform and/or assessmentID.
func (s *SQLiteComplianceStore) ListPlatformSyncRecords(platform, assessmentID string) ([]PlatformSyncRecord, error) {
	return s.ListPlatformSyncRecordsPaged(platform, assessmentID, 0, 0)
}

// ListPlatformSyncRecordsPaged queries synchronization records filtered by platform and/or assessmentID with pagination support.
func (s *SQLiteComplianceStore) ListPlatformSyncRecordsPaged(platform, assessmentID string, limit, offset int) ([]PlatformSyncRecord, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var conditions []string
	var args []any

	if strings.TrimSpace(platform) != "" {
		conditions = append(conditions, "platform = ?")
		args = append(args, strings.TrimSpace(platform))
	}
	if strings.TrimSpace(assessmentID) != "" {
		conditions = append(conditions, "assessment_id = ?")
		args = append(args, strings.TrimSpace(assessmentID))
	}

	query := `
	SELECT sync_id, platform, assessment_id, execution_id, attestation_letter_id,
	       external_record_id, external_url, status, idempotency_key, payload_digest,
	       records_synced, records_failed, error_message, synced_at, created_at
	FROM compliance_platform_sync_records
	`
	if len(conditions) > 0 {
		query += " WHERE " + strings.Join(conditions, " AND ")
	}
	query += " ORDER BY synced_at DESC"
	if limit > 0 {
		query += fmt.Sprintf(" LIMIT %d", limit)
		if offset > 0 {
			query += fmt.Sprintf(" OFFSET %d", offset)
		}
	}
	query += ";"

	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed listing platform sync records: %w", err)
	}
	defer rows.Close()

	var records []PlatformSyncRecord
	for rows.Next() {
		var rec PlatformSyncRecord
		var platformStr, statusStr string
		if err := rows.Scan(
			&rec.SyncID,
			&platformStr,
			&rec.AssessmentID,
			&rec.ExecutionID,
			&rec.AttestationLetterID,
			&rec.ExternalRecordID,
			&rec.ExternalURL,
			&statusStr,
			&rec.IdempotencyKey,
			&rec.PayloadDigest,
			&rec.RecordsSynced,
			&rec.RecordsFailed,
			&rec.ErrorMessage,
			&rec.SyncedAt,
			&rec.CreatedAt,
		); err != nil {
			return nil, fmt.Errorf("failed scanning platform sync row: %w", err)
		}
		rec.Platform = CompliancePlatform(platformStr)
		rec.Status = SyncStatus(statusStr)
		records = append(records, rec)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error during platform sync rows iteration: %w", err)
	}

	return records, nil
}
