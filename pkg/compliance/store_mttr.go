package compliance

import (
	"database/sql"
	"fmt"
	"strings"
	"time"
)

// ListRemediationRecordsWithHistory retrieves remediation records and their full auditable history
// within an atomic, consistent read-lock snapshot, completely avoiding N+1 database queries.
func (s *SQLiteComplianceStore) ListRemediationRecordsWithHistory(filter RemediationFilter) ([]RemediationRecord, map[string][]RemediationHistoryEvent, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var (
		conditions []string
		args       []any
	)

	if filter.FindingID != "" {
		conditions = append(conditions, "finding_id = ?")
		args = append(args, strings.TrimSpace(filter.FindingID))
	}
	if filter.AssessmentID != "" {
		conditions = append(conditions, "assessment_id = ?")
		args = append(args, strings.TrimSpace(filter.AssessmentID))
	}
	if filter.ControlID != "" {
		conditions = append(conditions, "control_id = ?")
		args = append(args, strings.TrimSpace(filter.ControlID))
	}
	if filter.Severity != "" {
		conditions = append(conditions, "severity = ?")
		args = append(args, strings.ToUpper(strings.TrimSpace(filter.Severity)))
	}
	if filter.Status != "" {
		conditions = append(conditions, "status = ?")
		args = append(args, string(filter.Status))
	}
	if filter.PolicyID != "" {
		conditions = append(conditions, "policy_id = ?")
		args = append(args, strings.TrimSpace(filter.PolicyID))
	}
	if filter.OnlyOverdue {
		conditions = append(conditions, "status IN ('open', 'in_progress', 'reopened') AND deadline < ?")
		args = append(args, time.Now().UTC())
	}

	whereClause := ""
	if len(conditions) > 0 {
		whereClause = "WHERE " + strings.Join(conditions, " AND ")
	}

	limitClause := ""
	if filter.Limit > 0 {
		limitClause = fmt.Sprintf("LIMIT %d", filter.Limit)
		if filter.Offset > 0 {
			limitClause += fmt.Sprintf(" OFFSET %d", filter.Offset)
		}
	}

	query := fmt.Sprintf(`
	SELECT id, finding_id, finding_source, finding_title, finding_category,
	       assessment_id, catalog_id, control_id, evaluation_id, severity,
	       severity_source, policy_id, policy_version, policy_rule_matched,
	       assigned_at, sla_start_time, deadline, time_basis, status,
	       completed_at, risk_acceptance_json, reopen_count, reopened_at,
	       evidence_references_json, integrity_version, created_at, updated_at
	FROM compliance_remediation_records
	%s
	ORDER BY deadline ASC, created_at ASC
	%s;
	`, whereClause, limitClause)

	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, nil, fmt.Errorf("failed querying remediation records: %w", err)
	}
	defer rows.Close()

	var records []RemediationRecord
	var recordIDs []string
	idSet := make(map[string]bool)

	for rows.Next() {
		rec, err := scanRemediationRow(rows)
		if err != nil {
			return nil, nil, fmt.Errorf("failed scanning remediation row: %w", err)
		}
		records = append(records, *rec)
		if !idSet[rec.ID] {
			idSet[rec.ID] = true
			recordIDs = append(recordIDs, rec.ID)
		}
	}

	historyMap := make(map[string][]RemediationHistoryEvent, len(recordIDs))
	if len(recordIDs) == 0 {
		return records, historyMap, nil
	}

	// Batch query history events in chunks of up to 400 parameters to respect SQLite query parameter limits
	const batchSize = 400
	for i := 0; i < len(recordIDs); i += batchSize {
		end := i + batchSize
		if end > len(recordIDs) {
			end = len(recordIDs)
		}
		chunk := recordIDs[i:end]

		placeholders := make([]string, len(chunk))
		chunkArgs := make([]any, len(chunk))
		for j, id := range chunk {
			placeholders[j] = "?"
			chunkArgs[j] = id
		}

		histQuery := fmt.Sprintf(`
		SELECT id, remediation_id, event_type, from_status, to_status, actor, reason, details_json, timestamp
		FROM compliance_remediation_history
		WHERE remediation_id IN (%s)
		ORDER BY timestamp ASC, id ASC;
		`, strings.Join(placeholders, ","))

		hRows, err := s.db.Query(histQuery, chunkArgs...)
		if err != nil {
			return nil, nil, fmt.Errorf("failed querying batch remediation history: %w", err)
		}

		for hRows.Next() {
			var (
				e                      RemediationHistoryEvent
				eType, fromSt, toSt    string
				actor, reason, detJSON sql.NullString
			)
			if err := hRows.Scan(&e.ID, &e.RemediationID, &eType, &fromSt, &toSt, &actor, &reason, &detJSON, &e.Timestamp); err != nil {
				hRows.Close()
				return nil, nil, fmt.Errorf("failed scanning history row in batch: %w", err)
			}
			e.EventType = RemediationHistoryEventType(eType)
			e.FromStatus = RemediationLifecycleStatus(fromSt)
			e.ToStatus = RemediationLifecycleStatus(toSt)
			e.Actor = actor.String
			e.Reason = reason.String
			e.DetailsJSON = detJSON.String

			historyMap[e.RemediationID] = append(historyMap[e.RemediationID], e)
		}
		hRows.Close()
	}

	return records, historyMap, nil
}
