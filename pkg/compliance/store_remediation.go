package compliance

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// SaveRemediationPolicy stores or updates a versioned RemediationSLAPolicy in SQLite.
func (s *SQLiteComplianceStore) SaveRemediationPolicy(policy *RemediationSLAPolicy) error {
	if policy == nil {
		return errors.New("policy cannot be nil")
	}
	if err := ValidateRemediationPolicy(policy); err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now().UTC()
	if policy.CreatedAt.IsZero() {
		policy.CreatedAt = now
	}
	policy.UpdatedAt = now

	policyBytes, err := json.Marshal(policy)
	if err != nil {
		return fmt.Errorf("failed marshaling policy JSON: %w", err)
	}

	enabledInt := 0
	if policy.Enabled {
		enabledInt = 1
	}

	query := `
	INSERT INTO compliance_remediation_policies (
		id, version, enabled, description, priority, policy_json, created_at, updated_at
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
	ON CONFLICT(id) DO UPDATE SET
		version = excluded.version,
		enabled = excluded.enabled,
		description = excluded.description,
		priority = excluded.priority,
		policy_json = excluded.policy_json,
		updated_at = excluded.updated_at;
	`

	_, err = s.db.Exec(query,
		policy.ID, policy.Version, enabledInt, policy.Description, policy.Priority,
		string(policyBytes), policy.CreatedAt, policy.UpdatedAt,
	)
	if err != nil {
		return fmt.Errorf("failed persisting remediation policy %s: %w", policy.ID, err)
	}

	return nil
}

// GetRemediationPolicy retrieves a RemediationSLAPolicy by ID.
func (s *SQLiteComplianceStore) GetRemediationPolicy(policyID string) (*RemediationSLAPolicy, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	cleanID := strings.TrimSpace(policyID)
	var policyJSON string
	err := s.db.QueryRow("SELECT policy_json FROM compliance_remediation_policies WHERE id = ?", cleanID).Scan(&policyJSON)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("failed querying remediation policy: %w", err)
	}

	var policy RemediationSLAPolicy
	if err := json.Unmarshal([]byte(policyJSON), &policy); err != nil {
		return nil, fmt.Errorf("failed unmarshaling remediation policy: %w", err)
	}

	return &policy, nil
}

// ListRemediationPolicies returns all configured remediation policies sorted by priority DESC, id ASC.
func (s *SQLiteComplianceStore) ListRemediationPolicies() ([]RemediationSLAPolicy, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	rows, err := s.db.Query("SELECT policy_json FROM compliance_remediation_policies ORDER BY priority DESC, id ASC")
	if err != nil {
		return nil, fmt.Errorf("failed querying remediation policies: %w", err)
	}
	defer rows.Close()

	var policies []RemediationSLAPolicy
	for rows.Next() {
		var policyJSON string
		if err := rows.Scan(&policyJSON); err != nil {
			return nil, fmt.Errorf("failed scanning policy row: %w", err)
		}
		var p RemediationSLAPolicy
		if err := json.Unmarshal([]byte(policyJSON), &p); err == nil {
			policies = append(policies, p)
		}
	}

	return policies, nil
}

// SaveRemediationRecord atomically inserts or updates a RemediationRecord and its associated history event.
func (s *SQLiteComplianceStore) SaveRemediationRecord(rec *RemediationRecord, event *RemediationHistoryEvent) error {
	return s.SaveRemediationRecordWithKey(rec, event, nil)
}

func scanRemediationRow(scanner interface{ Scan(dest ...any) error }) (*RemediationRecord, error) {
	var (
		rec                                                   RemediationRecord
		statusStr                                             string
		riskJSON, evRefsJSON, integVer                        sql.NullString
		fTitle, fCat, assID, catID, ctrlID, evalID, ruleMatch sql.NullString
		compAt, reopAt                                        sql.NullTime
	)

	err := scanner.Scan(
		&rec.ID, &rec.FindingID, &rec.FindingSource, &fTitle, &fCat,
		&assID, &catID, &ctrlID, &evalID, &rec.Severity,
		&rec.SeveritySource, &rec.PolicyID, &rec.PolicyVersion, &ruleMatch,
		&rec.AssignedAt, &rec.SLAStartTime, &rec.Deadline, &rec.TimeBasis, &statusStr,
		&compAt, &riskJSON, &rec.ReopenCount, &reopAt,
		&evRefsJSON, &integVer, &rec.CreatedAt, &rec.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}

	rec.FindingTitle = fTitle.String
	rec.FindingCategory = fCat.String
	rec.AssessmentID = assID.String
	rec.CatalogID = catID.String
	rec.ControlID = ctrlID.String
	rec.EvaluationID = evalID.String
	rec.PolicyRuleMatched = ruleMatch.String
	rec.Status = RemediationLifecycleStatus(statusStr)
	rec.IntegrityVersion = integVer.String

	if compAt.Valid {
		rec.CompletedAt = &compAt.Time
	}
	if reopAt.Valid {
		rec.ReopenedAt = &reopAt.Time
	}

	if riskJSON.Valid && riskJSON.String != "" {
		var risk RiskAcceptanceRecord
		if err := json.Unmarshal([]byte(riskJSON.String), &risk); err == nil {
			rec.RiskAcceptance = &risk
		}
	}

	if evRefsJSON.Valid && evRefsJSON.String != "" {
		var refs []string
		_ = json.Unmarshal([]byte(evRefsJSON.String), &refs)
		rec.EvidenceReferences = refs
	}

	// Dynamically populate computed SLA fields based on current time
	svc := NewRemediationService(RealClock{}, DefaultWarningWindow)
	svc.PopulateComputedFields(&rec)

	return &rec, nil
}

// GetRemediationRecord retrieves a RemediationRecord by ID.
func (s *SQLiteComplianceStore) GetRemediationRecord(id string) (*RemediationRecord, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	query := `
	SELECT id, finding_id, finding_source, finding_title, finding_category,
	       assessment_id, catalog_id, control_id, evaluation_id, severity,
	       severity_source, policy_id, policy_version, policy_rule_matched,
	       assigned_at, sla_start_time, deadline, time_basis, status,
	       completed_at, risk_acceptance_json, reopen_count, reopened_at,
	       evidence_references_json, integrity_version, created_at, updated_at
	FROM compliance_remediation_records
	WHERE id = ?;
	`

	row := s.db.QueryRow(query, strings.TrimSpace(id))
	rec, err := scanRemediationRow(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("failed querying remediation record: %w", err)
	}

	return rec, nil
}

// GetRemediationRecordByFinding retrieves a RemediationRecord by FindingID.
func (s *SQLiteComplianceStore) GetRemediationRecordByFinding(findingID string) (*RemediationRecord, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	query := `
	SELECT id, finding_id, finding_source, finding_title, finding_category,
	       assessment_id, catalog_id, control_id, evaluation_id, severity,
	       severity_source, policy_id, policy_version, policy_rule_matched,
	       assigned_at, sla_start_time, deadline, time_basis, status,
	       completed_at, risk_acceptance_json, reopen_count, reopened_at,
	       evidence_references_json, integrity_version, created_at, updated_at
	FROM compliance_remediation_records
	WHERE finding_id = ?
	ORDER BY created_at DESC
	LIMIT 1;
	`

	row := s.db.QueryRow(query, strings.TrimSpace(findingID))
	rec, err := scanRemediationRow(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("failed querying remediation record by finding: %w", err)
	}

	return rec, nil
}

// ListRemediationRecords queries remediation records matching filter criteria.
func (s *SQLiteComplianceStore) ListRemediationRecords(filter RemediationFilter) ([]RemediationRecord, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var conditions []string
	var args []any

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
		// Overdue implies Open, InProgress, or Reopened, and deadline in past
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
		return nil, fmt.Errorf("failed querying remediation records: %w", err)
	}
	defer rows.Close()

	var records []RemediationRecord
	for rows.Next() {
		rec, err := scanRemediationRow(rows)
		if err != nil {
			return nil, fmt.Errorf("failed scanning remediation row: %w", err)
		}
		records = append(records, *rec)
	}

	return records, nil
}

// GetRemediationHistory retrieves the auditable history events for a remediation record.
func (s *SQLiteComplianceStore) GetRemediationHistory(remediationID string) ([]RemediationHistoryEvent, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	query := `
	SELECT id, remediation_id, event_type, from_status, to_status, actor, reason, details_json, timestamp
	FROM compliance_remediation_history
	WHERE remediation_id = ?
	ORDER BY timestamp ASC;
	`

	rows, err := s.db.Query(query, strings.TrimSpace(remediationID))
	if err != nil {
		return nil, fmt.Errorf("failed querying remediation history: %w", err)
	}
	defer rows.Close()

	var events []RemediationHistoryEvent
	for rows.Next() {
		var (
			e                      RemediationHistoryEvent
			eType, fromSt, toSt    string
			actor, reason, detJSON sql.NullString
		)
		err := rows.Scan(&e.ID, &e.RemediationID, &eType, &fromSt, &toSt, &actor, &reason, &detJSON, &e.Timestamp)
		if err != nil {
			return nil, fmt.Errorf("failed scanning history event: %w", err)
		}
		e.EventType = RemediationHistoryEventType(eType)
		e.FromStatus = RemediationLifecycleStatus(fromSt)
		e.ToStatus = RemediationLifecycleStatus(toSt)
		e.Actor = actor.String
		e.Reason = reason.String
		e.DetailsJSON = detJSON.String
		events = append(events, e)
	}

	return events, nil
}
