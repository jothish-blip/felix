package assessment

import (
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"felix/pkg/correlation"
	"felix/pkg/report"
)

var (
	// ErrReconciliationFailed indicates a discrepancy between persisted data and a report.
	ErrReconciliationFailed = errors.New("report reconciliation failed: report does not match persisted assessment facts")
	// ErrUnexecutedAssessment indicates report generation was requested for an assessment with no execution records.
	ErrUnexecutedAssessment = errors.New("assessment has not been executed; cannot generate report from unexecuted assessment")
)

// AuthoritativeAssessmentSnapshot represents the immutable persisted facts of an assessment execution.
type AuthoritativeAssessmentSnapshot struct {
	AssessmentID         string                `json:"assessment_id"`
	AssessmentRef        string                `json:"assessment_ref"`
	ClientID             string                `json:"client_id"`
	TenantID             string                `json:"tenant_id"`
	ExecutionID          string                `json:"execution_id"`
	Name                 string                `json:"name"`
	AssessmentType       string                `json:"assessment_type"`
	Status               AssessmentStatus      `json:"status"`
	IsComplete           bool                  `json:"is_complete"`
	StartedAt            time.Time             `json:"started_at"`
	CompletedAt          *time.Time            `json:"completed_at,omitempty"`
	DurationMs           int64                 `json:"duration_ms"`
	RequestCount         int                   `json:"request_count"`
	ScopedTargets        []string              `json:"scoped_targets"`
	AssessedTargets      []string              `json:"assessed_targets,omitempty"`
	FailedTargets        []string              `json:"failed_targets,omitempty"`
	RawFindings          []AssessmentFinding   `json:"raw_findings"`
	DeduplicatedFindings []report.Finding      `json:"deduplicated_findings"`
	TotalPersistedCount  int                   `json:"total_persisted_count"`
	UniqueFindingsCount  int                   `json:"unique_findings_count"`
	SeverityCounts       map[string]int        `json:"severity_counts"`
	VerificationCounts   map[string]int        `json:"verification_counts"`
	ReviewCounts         map[string]int        `json:"review_counts"` // APPROVED, REJECTED, PENDING
	ApprovedFindings     []report.Finding      `json:"approved_findings"`
	ChangeSummary        *report.ChangeSummary `json:"change_summary,omitempty"`
	SnapshotTime         time.Time             `json:"snapshot_time"`
}

// ReconciliationResult records the outcome of comparing a report with authoritative persisted facts.
type ReconciliationResult struct {
	IsValid              bool             `json:"is_valid"`
	AssessmentID         string           `json:"assessment_id"`
	ExecutionID          string           `json:"execution_id"`
	PersistedStatus      AssessmentStatus `json:"persisted_status"`
	ReportStatus         string           `json:"report_status"`
	TotalPersistedCount  int              `json:"total_persisted_count"`
	UniquePersistedCount int              `json:"unique_persisted_count"`
	ApprovedCount        int              `json:"approved_count"`
	ReportedFindingCount int              `json:"reported_finding_count"`
	PersistedSeverities  map[string]int   `json:"persisted_severities"`
	ReportedSeverities   map[string]int   `json:"reported_severities"`
	Discrepancies        []string         `json:"discrepancies,omitempty"`
	ReconciledAt         time.Time        `json:"reconciled_at"`
}

// LoadAuthoritativeSnapshot loads authoritative assessment facts from the store, enforcing tenant isolation,
// deterministic ordering, count invariants, and completion status.
func LoadAuthoritativeSnapshot(
	store Store,
	assessmentID string,
	executionID string,
	auth TenantAuthContext,
) (*AuthoritativeAssessmentSnapshot, error) {
	if store == nil {
		return nil, errors.New("store is required")
	}
	assessmentID = strings.TrimSpace(assessmentID)
	if assessmentID == "" {
		return nil, errors.New("assessment ID is required")
	}

	// 1. Load Assessment Fact
	asm, err := store.GetAssessment(assessmentID)
	if err != nil {
		return nil, fmt.Errorf("assessment not found: %w", err)
	}

	// 2. Validate Tenant Authorization
	if !auth.IsAdmin() && !auth.Authorizes(asm.ClientID, "", "") {
		return nil, ErrSnapshotUnauthorized
	}

	// 3. Load Scope and Targets
	targets, _ := store.GetTargets(asm.ID)
	var scopedTargets []string
	for _, t := range targets {
		if t.ScopeStatus == "APPROVED" || t.ScopeStatus == "" {
			clean := strings.TrimSpace(t.TargetURL)
			if clean != "" {
				scopedTargets = append(scopedTargets, clean)
			}
		}
	}
	if len(scopedTargets) == 0 {
		for _, t := range asm.Targets {
			clean := strings.TrimSpace(t.TargetURL)
			if clean != "" {
				scopedTargets = append(scopedTargets, clean)
			}
		}
	}
	if len(scopedTargets) == 0 && asm.Name != "" {
		scopedTargets = []string{asm.Name}
	}
	sort.Strings(scopedTargets)

	// 4. Resolve Execution Fact
	var exec *AssessmentExecution
	if executionID != "" {
		e, err := store.GetExecution(executionID)
		if err != nil || e.AssessmentID != asm.ID {
			return nil, fmt.Errorf("execution %s not found for assessment %s: %w", executionID, asm.ID, err)
		}
		exec = e
	} else {
		execs, err := store.ListExecutions(asm.ID)
		if err != nil {
			return nil, fmt.Errorf("failed to list executions: %w", err)
		}
		if len(execs) == 0 {
			return nil, fmt.Errorf("%w (%s)", ErrUnexecutedAssessment, asm.ID)
		}
		// Pick newest finalized execution, fallback to latest execution
		for i := len(execs) - 1; i >= 0; i-- {
			if execs[i].Status == StatusCompleted || execs[i].Status == StatusCompletedWithErrors || execs[i].Status == StatusFailed {
				exec = &execs[i]
				break
			}
		}
		if exec == nil {
			exec = &execs[len(execs)-1]
		}
	}

	// 5. Load Persisted Findings
	rawFindings, err := store.GetFindings(asm.ID, exec.ID)
	if err != nil {
		return nil, fmt.Errorf("failed to load findings for execution %s: %w", exec.ID, err)
	}

	// Deterministic sort: SeverityRank desc, Fingerprint asc, ID asc
	sort.Slice(rawFindings, func(i, j int) bool {
		rI := report.SeverityRank(rawFindings[i].Severity)
		rJ := report.SeverityRank(rawFindings[j].Severity)
		if rI != rJ {
			return rI > rJ
		}
		if rawFindings[i].Fingerprint != rawFindings[j].Fingerprint {
			return rawFindings[i].Fingerprint < rawFindings[j].Fingerprint
		}
		return rawFindings[i].ID < rawFindings[j].ID
	})

	// Convert to report.Finding and deduplicate
	allReportFindings := make([]report.Finding, 0, len(rawFindings))
	for _, f := range rawFindings {
		rf := ToReportFinding(f)
		allReportFindings = append(allReportFindings, rf)
	}
	dedupedFindings := report.DeduplicateFindings(allReportFindings)

	// Calculate exact count invariants
	sevCounts := map[string]int{
		report.SeverityCritical: 0,
		report.SeverityHigh:     0,
		report.SeverityMedium:   0,
		report.SeverityLow:      0,
		report.SeverityInfo:     0,
	}
	verCounts := make(map[string]int)
	for _, f := range dedupedFindings {
		normSev := report.NormalizeSeverity(f.Severity)
		sevCounts[normSev]++
		normVer := string(report.NormalizeVerificationStatus(f.Verification.Status))
		verCounts[normVer]++
	}

	// 6. Review state invariants
	reviews, _ := store.ListFindingReviews(asm.ID)
	reviewMap := make(map[string]ReviewStatus, len(reviews))
	for _, r := range reviews {
		reviewMap[r.FindingID] = r.ReviewStatus
	}

	reviewCounts := map[string]int{"APPROVED": 0, "REJECTED": 0, "PENDING": 0}
	var approvedFindings []report.Finding
	for _, f := range rawFindings {
		status, exists := reviewMap[f.OriginalFindingID]
		if !exists {
			status, exists = reviewMap[f.ID]
		}
		if !exists {
			status = ReviewStatusPending
		}

		switch status {
		case ReviewStatusApproved:
			reviewCounts["APPROVED"]++
			approvedFindings = append(approvedFindings, ToReportFinding(f))
		case ReviewStatusRejected:
			reviewCounts["REJECTED"]++
		default:
			reviewCounts["PENDING"]++
		}
	}

	// 7. Status & Completeness Invariant
	finalStatus := exec.Status
	if finalStatus == "" {
		finalStatus = asm.Status
	}
	isComplete := finalStatus == StatusCompleted || finalStatus == StatusCompletedWithErrors

	// 8. Attach ChangeSummary if available
	var changeSummary *report.ChangeSummary
	if cs, err := store.GetAssessmentChangeSummary(asm.ID, "", exec.ID, auth); err == nil && cs != nil {
		changeSummary = cs
	}

	now := time.Now().UTC()
	return &AuthoritativeAssessmentSnapshot{
		AssessmentID:         asm.ID,
		AssessmentRef:        asm.Ref,
		ClientID:             asm.ClientID,
		TenantID:             asm.ClientID,
		ExecutionID:          exec.ID,
		Name:                 asm.Name,
		AssessmentType:       asm.AssessmentType,
		Status:               finalStatus,
		IsComplete:           isComplete,
		StartedAt:            exec.StartedAt,
		CompletedAt:          exec.CompletedAt,
		DurationMs:           exec.DurationMs,
		RequestCount:         exec.RequestCount,
		ScopedTargets:        scopedTargets,
		RawFindings:          rawFindings,
		DeduplicatedFindings: dedupedFindings,
		TotalPersistedCount:  len(rawFindings),
		UniqueFindingsCount:  len(dedupedFindings),
		SeverityCounts:       sevCounts,
		VerificationCounts:   verCounts,
		ReviewCounts:         reviewCounts,
		ApprovedFindings:     approvedFindings,
		ChangeSummary:        changeSummary,
		SnapshotTime:         now,
	}, nil
}

// BuildAuthoritativeReport constructs a canonical report.Report guaranteed to reflect the authoritative snapshot facts.
func BuildAuthoritativeReport(
	snapshot *AuthoritativeAssessmentSnapshot,
	isCurated bool,
	allowDraft bool,
) (*report.Report, error) {
	if snapshot == nil {
		return nil, errors.New("snapshot is required")
	}

	var findings []report.Finding
	if isCurated {
		if !allowDraft && snapshot.ReviewCounts["PENDING"] > 0 {
			return nil, fmt.Errorf(
				"report generation blocked: %d finding(s) remain pending review; explicit review approval required",
				snapshot.ReviewCounts["PENDING"],
			)
		}
		findings = snapshot.ApprovedFindings
	} else {
		findings = snapshot.DeduplicatedFindings
	}

	rep := report.BuildMultiTargetReport(snapshot.ScopedTargets, findings)
	rep.CompletionStatus = string(snapshot.Status)
	if snapshot.CompletedAt != nil && !snapshot.CompletedAt.IsZero() {
		rep.Timestamp = snapshot.CompletedAt.Format(time.RFC3339)
	}

	// Status and Risk Availability Invariants
	if snapshot.Status == StatusFailed || snapshot.Status == StatusCancelled || snapshot.Status == StatusInterrupted || snapshot.Status == StatusSkipped {
		rep.RiskScore = 0
		rep.RiskLevel = "UNAVAILABLE"
		rep.RiskScoreAvailable = false
		rep.Summary.ScoreAvailable = false
	}

	if rep.Metadata == nil {
		rep.Metadata = make(map[string]any)
	}
	rep.Metadata["assessment_id"] = snapshot.AssessmentID
	rep.Metadata["assessment_ref"] = snapshot.AssessmentRef
	rep.Metadata["execution_id"] = snapshot.ExecutionID
	rep.Metadata["client_id"] = snapshot.ClientID
	rep.Metadata["total_persisted_findings"] = snapshot.TotalPersistedCount
	rep.Metadata["unique_persisted_findings"] = snapshot.UniqueFindingsCount

	if isCurated && snapshot.ReviewCounts["PENDING"] > 0 {
		rep.Metadata["is_draft"] = true
		rep.Metadata["pending_review_count"] = snapshot.ReviewCounts["PENDING"]
		rep.Metadata["rejected_review_count"] = snapshot.ReviewCounts["REJECTED"]
	}

	if snapshot.ChangeSummary != nil {
		rep.ChangeSummary = snapshot.ChangeSummary
	}

	return &rep, nil
}

// ReconcileReport validates that a report accurately reconciles with authoritative persisted snapshot facts.
func ReconcileReport(
	snapshot *AuthoritativeAssessmentSnapshot,
	rep *report.Report,
	isCurated bool,
) (*ReconciliationResult, error) {
	if snapshot == nil {
		return nil, errors.New("snapshot is required for reconciliation")
	}
	if rep == nil {
		return nil, errors.New("report is required for reconciliation")
	}

	res := &ReconciliationResult{
		IsValid:              true,
		AssessmentID:         snapshot.AssessmentID,
		ExecutionID:          snapshot.ExecutionID,
		PersistedStatus:      snapshot.Status,
		ReportStatus:         rep.CompletionStatus,
		TotalPersistedCount:  snapshot.TotalPersistedCount,
		UniquePersistedCount: snapshot.UniqueFindingsCount,
		ApprovedCount:        snapshot.ReviewCounts["APPROVED"],
		ReportedFindingCount: len(rep.Findings),
		PersistedSeverities:  snapshot.SeverityCounts,
		ReportedSeverities:   make(map[string]int),
		ReconciledAt:         time.Now().UTC(),
	}

	for _, f := range rep.Findings {
		normSev := report.NormalizeSeverity(f.Severity)
		res.ReportedSeverities[normSev]++
	}

	// 1. Identity Check
	if rep.Metadata != nil {
		if asmID, ok := rep.Metadata["assessment_id"].(string); ok && asmID != "" && asmID != snapshot.AssessmentID {
			res.Discrepancies = append(res.Discrepancies, fmt.Sprintf("assessment ID mismatch: report=%s, persisted=%s", asmID, snapshot.AssessmentID))
		}
		if clientID, ok := rep.Metadata["client_id"].(string); ok && clientID != "" && clientID != snapshot.ClientID {
			res.Discrepancies = append(res.Discrepancies, fmt.Sprintf("client/tenant ID mismatch: report=%s, persisted=%s", clientID, snapshot.ClientID))
		}
	}

	// 2. Status Invariant Check
	reportStatus := strings.TrimSpace(rep.CompletionStatus)
	if reportStatus == "" {
		reportStatus = "COMPLETED"
	}

	// Incomplete or failed assessment must not be presented as complete
	if snapshot.Status == StatusFailed || snapshot.Status == StatusCancelled || snapshot.Status == StatusInterrupted || snapshot.Status == StatusSkipped {
		if reportStatus == "COMPLETED" {
			res.Discrepancies = append(res.Discrepancies, fmt.Sprintf("status conflict: persisted status is %s but report claims COMPLETED", snapshot.Status))
		}
		if rep.RiskScoreAvailable && rep.RiskScore > 0 {
			res.Discrepancies = append(res.Discrepancies, fmt.Sprintf("risk score conflict: persisted status %s requires unavailable risk score, but report claims %d/100", snapshot.Status, rep.RiskScore))
		}
	} else if snapshot.Status == StatusCompletedWithErrors && reportStatus == "COMPLETED" {
		res.Discrepancies = append(res.Discrepancies, "status conflict: assessment had execution errors but report claims clean COMPLETED")
	}

	// 3. Finding Count Invariant Check
	var expectedCount int
	if isCurated {
		expectedCount = len(snapshot.ApprovedFindings)
	} else {
		expectedCount = snapshot.UniqueFindingsCount
	}

	if len(rep.Findings) != expectedCount {
		res.Discrepancies = append(res.Discrepancies, fmt.Sprintf("finding count mismatch: report contains %d findings, expected %d", len(rep.Findings), expectedCount))
	}

	// 4. Severity Distribution Check
	var expectedSeverities map[string]int
	if isCurated {
		expectedSeverities = make(map[string]int)
		for _, f := range snapshot.ApprovedFindings {
			expectedSeverities[report.NormalizeSeverity(f.Severity)]++
		}
	} else {
		expectedSeverities = snapshot.SeverityCounts
	}

	for sev, count := range expectedSeverities {
		if res.ReportedSeverities[sev] != count {
			res.Discrepancies = append(res.Discrepancies, fmt.Sprintf("severity %s count mismatch: report=%d, persisted=%d", sev, res.ReportedSeverities[sev], count))
		}
	}

	// 5. Finding Provenance / No Fabricated Findings Check
	persistedIDs := make(map[string]bool, len(snapshot.RawFindings)*4)
	for _, f := range snapshot.RawFindings {
		if f.ID != "" {
			persistedIDs[f.ID] = true
		}
		if f.OriginalFindingID != "" {
			persistedIDs[f.OriginalFindingID] = true
		}
		if f.Fingerprint != "" {
			persistedIDs[f.Fingerprint] = true
		}
		// Also compute canonical stable fingerprint so both raw and canonical match
		cf := ToReportFinding(f)
		if cfp := correlation.ComputeStableFingerprint(cf); cfp != "" {
			persistedIDs[cfp] = true
		}
	}

	for _, f := range rep.Findings {
		found := false
		if f.ID != "" && persistedIDs[f.ID] {
			found = true
		} else if f.Fingerprint != "" && persistedIDs[f.Fingerprint] {
			found = true
		}
		if !found {
			res.Discrepancies = append(res.Discrepancies, fmt.Sprintf("unpersisted finding detected: ID=%s, fingerprint=%s (%s) not found in persisted records", f.ID, f.Fingerprint, f.Title))
			break
		}
	}

	if len(res.Discrepancies) > 0 {
		res.IsValid = false
		return res, fmt.Errorf("%w: %s", ErrReconciliationFailed, strings.Join(res.Discrepancies, "; "))
	}

	return res, nil
}
