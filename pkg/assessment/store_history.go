package assessment

import (
	"database/sql"
	"fmt"

	"felix/pkg/correlation"
	"felix/pkg/report"
)

// ListAssessmentHistory retrieves deterministic, paginated assessment history with baseline eligibility indicators.
func (s *SQLiteStore) ListAssessmentHistory(clientID string, assessmentID string, auth TenantAuthContext, limit, offset int) ([]AssessmentHistoryItem, int, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if !auth.IsAdmin() {
		if clientID != "" && !auth.Authorizes(clientID, "", "") {
			return nil, 0, ErrExecutionUnauthorized
		}
		if clientID == "" {
			clientID = auth.ClientID
		}
	}

	if limit <= 0 {
		limit = 20
	}
	if limit > 100 {
		limit = 100
	}
	if offset < 0 {
		offset = 0
	}

	var targetClientID string
	if clientID != "" {
		targetClientID = s.resolveClientID(clientID)
	}

	if assessmentID != "" {
		assessmentID = s.resolveAssessmentID(assessmentID)
		var asmClientID string
		err := s.db.QueryRow(`SELECT client_id FROM assessments WHERE id = ?`, assessmentID).Scan(&asmClientID)
		if err != nil {
			if err == sql.ErrNoRows {
				return nil, 0, fmt.Errorf("assessment not found: %s", assessmentID)
			}
			return nil, 0, err
		}
		if !auth.Authorizes(asmClientID, "", "") {
			return nil, 0, ErrExecutionUnauthorized
		}
		targetClientID = asmClientID
	}

	whereClause := "WHERE 1=1"
	var countArgs []any
	var queryArgs []any

	if targetClientID != "" {
		whereClause += " AND client_id = ?"
		countArgs = append(countArgs, targetClientID)
		queryArgs = append(queryArgs, targetClientID)
	}

	countQuery := fmt.Sprintf(`SELECT COUNT(*) FROM assessments %s`, whereClause)
	var totalCount int
	if err := s.db.QueryRow(countQuery, countArgs...).Scan(&totalCount); err != nil {
		return nil, 0, fmt.Errorf("failed counting assessments for history: %w", err)
	}

	query := fmt.Sprintf(`
		SELECT id, ref, client_id, name, description, assessment_type, status,
		       created_at, started_at, completed_at, finding_count
		FROM assessments
		%s
		ORDER BY created_at DESC, id DESC
		LIMIT ? OFFSET ?
	`, whereClause)
	queryArgs = append(queryArgs, limit, offset)

	rows, err := s.db.Query(query, queryArgs...)
	if err != nil {
		return nil, 0, fmt.Errorf("failed querying assessment history: %w", err)
	}
	defer rows.Close()

	var items []AssessmentHistoryItem
	for rows.Next() {
		var item AssessmentHistoryItem
		var statusStr string
		var desc sql.NullString
		var startedAt, completedAt sql.NullTime

		err := rows.Scan(
			&item.ID, &item.Ref, &item.ClientID, &item.Name, &desc,
			&item.AssessmentType, &statusStr, &item.CreatedAt,
			&startedAt, &completedAt, &item.FindingCount,
		)
		if err != nil {
			return nil, 0, fmt.Errorf("failed scanning assessment history row: %w", err)
		}

		item.Status = AssessmentStatus(statusStr)
		if desc.Valid {
			item.Description = desc.String
		}
		if startedAt.Valid {
			item.StartedAt = &startedAt.Time
		}
		if completedAt.Valid {
			item.CompletedAt = &completedAt.Time
		}

		// Authorization boundary check
		if !auth.Authorizes(item.ClientID, "", "") {
			continue
		}

		// Retrieve targets for this assessment
		tgts, _ := s.GetTargets(item.ID)
		item.TargetCount = len(tgts)
		for _, t := range tgts {
			if t.ScopeStatus == "APPROVED" || t.ScopeStatus == "" {
				item.Targets = append(item.Targets, t.TargetURL)
			}
		}

		// Compute baseline eligibility
		asmCopy := Assessment{
			ID:     item.ID,
			Ref:    item.Ref,
			Status: item.Status,
		}
		eligible, reason := CheckBaselineEligibility(&asmCopy, tgts)
		item.IsEligibleBaseline = eligible
		item.IneligibilityReason = reason

		// Severity counts
		item.SeverityCounts = make(map[string]int)
		sRows, sErr := s.db.Query(`
			SELECT severity, COUNT(*) FROM assessment_findings
			WHERE assessment_id = ?
			GROUP BY severity
		`, item.ID)
		if sErr == nil {
			for sRows.Next() {
				var sev string
				var cnt int
				if sRows.Scan(&sev, &cnt) == nil {
					item.SeverityCounts[report.NormalizeSeverity(sev)] = cnt
				}
			}
			sRows.Close()
		}

		// Executions and reports counts
		var execCount int
		var latestExecID sql.NullString
		_ = s.db.QueryRow(`
			SELECT COUNT(*), COALESCE((SELECT id FROM assessment_executions WHERE assessment_id = ? ORDER BY started_at DESC, id DESC LIMIT 1), '')
			FROM assessment_executions WHERE assessment_id = ?
		`, item.ID, item.ID).Scan(&execCount, &latestExecID)
		item.ExecutionCount = execCount
		if latestExecID.Valid && latestExecID.String != "" {
			item.LatestExecutionID = latestExecID.String
		}

		var repCount int
		_ = s.db.QueryRow(`SELECT COUNT(*) FROM assessment_reports WHERE assessment_id = ?`, item.ID).Scan(&repCount)
		item.ReportCount = repCount

		items = append(items, item)
	}

	return items, totalCount, nil
}

// CompareAssessments compares two assessments by ID, enforcing tenant boundaries and baseline eligibility.
func (s *SQLiteStore) CompareAssessments(baselineAssessmentID, currentAssessmentID string, auth TenantAuthContext) (*AssessmentComparisonResult, error) {
	return s.CompareAssessmentsWithExecutions(baselineAssessmentID, "", currentAssessmentID, "", auth)
}

// CompareAssessmentsWithExecutions compares two assessments or specific executions, enforcing complete P10.8 rules.
func (s *SQLiteStore) CompareAssessmentsWithExecutions(
	baselineAssessmentID, baselineExecID,
	currentAssessmentID, currentExecID string,
	auth TenantAuthContext,
) (*AssessmentComparisonResult, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	baseID := s.resolveAssessmentID(baselineAssessmentID)
	curID := s.resolveAssessmentID(currentAssessmentID)

	baseAsm, err := s.GetAssessment(baseID)
	if err != nil {
		return nil, fmt.Errorf("baseline assessment %q not found: %w", baselineAssessmentID, err)
	}

	curAsm, err := s.GetAssessment(curID)
	if err != nil {
		return nil, fmt.Errorf("current assessment %q not found: %w", currentAssessmentID, err)
	}

	// 1. Strict Tenant Boundary Enforcement
	if !auth.Authorizes(baseAsm.ClientID, "", "") {
		return nil, fmt.Errorf("unauthorized access to baseline assessment %s: %w", baseAsm.ID, ErrExecutionUnauthorized)
	}
	if !auth.Authorizes(curAsm.ClientID, "", "") {
		return nil, fmt.Errorf("unauthorized access to current assessment %s: %w", curAsm.ID, ErrExecutionUnauthorized)
	}
	if baseAsm.ClientID != curAsm.ClientID {
		return nil, fmt.Errorf("cross-tenant comparison denied (baseline client %q != current client %q): %w",
			baseAsm.ClientID, curAsm.ClientID, ErrExecutionUnauthorized)
	}

	// 2. Prevent identical self-comparison
	if baseAsm.ID == curAsm.ID && (baselineExecID == "" || baselineExecID == currentExecID) {
		return nil, fmt.Errorf("cannot compare assessment %s against itself as a baseline", curAsm.Ref)
	}

	// 3. Targets and Scope Compatibility
	baseTargets, _ := s.GetTargets(baseAsm.ID)
	curTargets, _ := s.GetTargets(curAsm.ID)

	var baseTargetURLs []string
	for _, t := range baseTargets {
		if t.ScopeStatus == "APPROVED" || t.ScopeStatus == "" {
			baseTargetURLs = append(baseTargetURLs, t.TargetURL)
		}
	}

	var curTargetURLs []string
	for _, t := range curTargets {
		if t.ScopeStatus == "APPROVED" || t.ScopeStatus == "" {
			curTargetURLs = append(curTargetURLs, t.TargetURL)
		}
	}

	scopeCoverage, missingScope := ComputeScopeCoverage(baseTargetURLs, curTargetURLs)

	// 4. Baseline Eligibility Validation
	eligible, reason := CheckBaselineEligibility(baseAsm, baseTargets)
	if !eligible {
		// Ineligible baseline cannot produce reliable comparison
		emptyCmp := &correlation.AssessmentComparison{
			ComparisonStatus: "PARTIAL",
			ComparisonReason: reason,
		}
		res := BuildAssessmentComparisonResult(baseAsm, curAsm, baselineExecID, currentExecID, baseTargetURLs, curTargetURLs, emptyCmp, scopeCoverage, missingScope)
		res.ComparabilityStatus = ComparabilityStatusIneligibleBaseline
		res.ComparabilityReason = fmt.Sprintf("Ineligible baseline %s: %s", baseAsm.Ref, reason)
		res.IsReliable = false
		return res, nil
	}

	// 5. Incompatible Assessment Types
	if baseAsm.AssessmentType != "" && curAsm.AssessmentType != "" && !AreAssessmentTypesCompatible(baseAsm.AssessmentType, curAsm.AssessmentType) {
		emptyCmp := &correlation.AssessmentComparison{
			ComparisonStatus: "PARTIAL",
			ComparisonReason: fmt.Sprintf("Incompatible assessment types (%s vs %s)", baseAsm.AssessmentType, curAsm.AssessmentType),
		}
		res := BuildAssessmentComparisonResult(baseAsm, curAsm, baselineExecID, currentExecID, baseTargetURLs, curTargetURLs, emptyCmp, "DISJOINT", missingScope)
		res.ComparabilityStatus = ComparabilityStatusIncompatibleScope
		res.ComparabilityReason = fmt.Sprintf("Incompatible assessment types (%s vs %s)", baseAsm.AssessmentType, curAsm.AssessmentType)
		res.IsReliable = false
		return res, nil
	}

	// 6. Incompatible Disjoint Scopes
	if scopeCoverage == "DISJOINT" {
		emptyCmp := &correlation.AssessmentComparison{
			ComparisonStatus: "PARTIAL",
			ComparisonReason: "No target scope overlap between baseline and current assessments",
		}
		res := BuildAssessmentComparisonResult(baseAsm, curAsm, baselineExecID, currentExecID, baseTargetURLs, curTargetURLs, emptyCmp, scopeCoverage, missingScope)
		res.ComparabilityStatus = ComparabilityStatusIncompatibleScope
		res.ComparabilityReason = "No target scope overlap between baseline and current assessments; cannot establish resolution"
		res.IsReliable = false
		return res, nil
	}

	// 7. Execution Status & Completion Options
	isCurCompleted := (curAsm.Status == StatusCompleted || curAsm.Status == StatusCompletedWithErrors)
	isInconclusive := false

	if currentExecID != "" {
		curExec, err := s.GetExecutionHistory(currentExecID, auth)
		if err == nil && curExec != nil {
			if curExec.Status != StatusCompleted && curExec.Status != StatusCompletedWithErrors {
				isCurCompleted = false
			}
			if curExec.SnapshotID != "" {
				if snap, err := s.GetSnapshot(curExec.SnapshotID, auth); err == nil && snap != nil {
					if snap.IsInconclusive() || !snap.IsComplete {
						isCurCompleted = false
						isInconclusive = true
					}
				}
			}
		}
	}

	opts := correlation.ComparisonOptions{
		CurrentCompleted: isCurCompleted,
		Inconclusive:     isInconclusive,
		ScopedTargets:    curTargetURLs,
	}

	// 8. Retrieve Findings
	var baseFindings []AssessmentFinding
	if baselineExecID != "" {
		baseFindings, _ = s.GetFindings(baseAsm.ID, baselineExecID)
	} else {
		baseFindings, _ = s.GetFindings(baseAsm.ID, "")
	}

	var curFindings []AssessmentFinding
	if currentExecID != "" {
		curFindings, _ = s.GetFindings(curAsm.ID, currentExecID)
	} else {
		curFindings, _ = s.GetFindings(curAsm.ID, "")
	}

	baseReport := make([]report.Finding, len(baseFindings))
	for i, f := range baseFindings {
		baseReport[i] = ToReportFinding(f)
	}

	curReport := make([]report.Finding, len(curFindings))
	for i, f := range curFindings {
		curReport[i] = ToReportFinding(f)
	}

	// 9. Run Correlation Comparison Engine
	cmp := correlation.CompareFindingsWithOptions(baseReport, curReport, opts)

	// 10. Assemble Assessment Comparison Result
	res := BuildAssessmentComparisonResult(
		baseAsm, curAsm,
		baselineExecID, currentExecID,
		baseTargetURLs, curTargetURLs,
		&cmp,
		scopeCoverage, missingScope,
	)

	return res, nil
}
