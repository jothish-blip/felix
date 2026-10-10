package assessment

import (
	"fmt"
	"path/filepath"
	"time"

	"felix/pkg/report"
	"github.com/google/uuid"
)

// CuratedReportOptions configures curated report generation.
type CuratedReportOptions struct {
	AllowDraft     bool   // If true, permits compiling report even if some findings are PENDING review
	ExecutionID    string // Optional filter: restrict report to findings from a specific execution
	ExportHTMLPath string // Optional explicit destination path
	ExportJSONPath string // Optional explicit destination path
	FelixVersion   string // Reporter version stamp
}

// CuratedReportResult holds the generated report artifacts and metadata.
type CuratedReportResult struct {
	Report           *report.Report
	CommercialReport *report.CommercialReport
	IsDraft          bool
	TotalFindings    int
	ApprovedCount    int
	RejectedCount    int
	PendingCount     int
	HTMLPath         string
	JSONPath         string
	ReportRecordID   string
}

// GenerateCuratedCommercialReport compiles an authorized assessment's findings into a
// Commercial Report 2.0 deliverable, strictly enforcing finding review invariants:
//
// Invariants enforced:
// 1. Only findings explicitly reviewed and marked APPROVED_FOR_REPORT are included in a final report.
// 2. If any findings remain PENDING review, generation fails closed unless AllowDraft is true.
// 3. Rejected findings (REJECTED) are completely excluded from the commercial report.
// 4. Zero findings approved produces a valid empty report with a 0 risk score.
// 5. Technical verification status and evidence of source findings are never mutated.
func GenerateCuratedCommercialReport(
	store Store,
	assessmentID string,
	operatorID string,
	opts CuratedReportOptions,
) (*CuratedReportResult, error) {
	if operatorID == "" {
		operatorID = "local-operator"
	}

	// 1. Load Assessment
	asm, err := store.GetAssessment(assessmentID)
	if err != nil {
		return nil, fmt.Errorf("failed to load assessment: %w", err)
	}

	// 2. Fetch Findings
	rawFindings, err := store.GetFindings(asm.ID, opts.ExecutionID)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch assessment findings: %w", err)
	}

	// 3. Fetch Reviews
	reviews, err := store.ListFindingReviews(asm.ID)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch finding reviews: %w", err)
	}
	reviewMap := make(map[string]ReviewStatus, len(reviews))
	for _, r := range reviews {
		reviewMap[r.FindingID] = r.ReviewStatus
	}

	// 4. Classify findings into Approved, Rejected, and Pending
	var approvedFindings []report.Finding
	var pendingCount, rejectedCount int

	for _, f := range rawFindings {
		// Key by OriginalFindingID first, fallback to ID
		status, exists := reviewMap[f.OriginalFindingID]
		if !exists {
			status, exists = reviewMap[f.ID]
		}
		if !exists {
			status = ReviewStatusPending
		}

		switch status {
		case ReviewStatusApproved:
			// Map to report.Finding without mutating underlying assessment finding
			verRec := f.VerificationRecord
			if verRec.Status == "" && f.VerificationStatus != "" {
				verRec.Status = f.VerificationStatus
			}
			rf := report.Finding{
				ID:              f.OriginalFindingID,
				Title:           f.Title,
				Category:        f.Category,
				Severity:        f.Severity,
				Confidence:      f.Confidence,
				Target:          f.TargetURL,
				Endpoint:        f.Endpoint,
				Method:          f.Method,
				Evidence:        f.EvidenceDetails.Observation,
				EvidenceDetails: f.EvidenceDetails,
				Verification:    verRec,
				Score:           f.Score,
			}
			approvedFindings = append(approvedFindings, rf)
		case ReviewStatusRejected:
			rejectedCount++
		case ReviewStatusPending:
			pendingCount++
		default:
			pendingCount++
		}
	}

	// Invariant 2: A final report must not be generated while in-scope findings remain pending review
	isDraft := false
	if pendingCount > 0 {
		if !opts.AllowDraft {
			return nil, fmt.Errorf(
				"report generation blocked: %d finding(s) remain pending review. "+
					"All findings must be explicitly approved or rejected before generating a finalized commercial report, "+
					"or specify AllowDraft=true to generate a labeled draft report",
				pendingCount,
			)
		}
		isDraft = true
	}

	// 5. Targets list
	var targetsList []string
	for _, t := range asm.Targets {
		targetsList = append(targetsList, t.TargetURL)
	}
	if len(targetsList) == 0 {
		targetsList = []string{asm.Name}
	}

	// 6. Build MultiTargetReport strictly using APPROVED findings
	rep := report.BuildMultiTargetReport(targetsList, approvedFindings)
	if rep.Metadata == nil {
		rep.Metadata = make(map[string]any)
	}
	rep.Metadata["assessment_id"] = asm.ID
	rep.Metadata["assessment_ref"] = asm.Ref
	rep.Metadata["operator_id"] = operatorID
	rep.Metadata["is_draft"] = isDraft
	rep.Metadata["pending_review_count"] = pendingCount
	rep.Metadata["rejected_review_count"] = rejectedCount

	// Attach attack paths and stories if present
	paths, _ := store.GetAttackPaths(asm.ID, opts.ExecutionID, "", "")
	if len(paths) > 0 {
		var repStories []report.SecurityStory
		var repPaths []report.AttackPathSummary
		for _, p := range paths {
			// Check if all nodes in path belong to approved findings
			allNodesApproved := true
			for _, nid := range p.NodeIDs {
				st, ok := reviewMap[nid]
				if !ok || st != ReviewStatusApproved {
					allNodesApproved = false
					break
				}
			}
			if !allNodesApproved && !isDraft {
				// Do not include unapproved paths in final report
				continue
			}

			repStories = append(repStories, p.SecurityStory)
			var transitions []string
			for _, e := range p.Edges {
				transitions = append(transitions, fmt.Sprintf("[%s] %s -> %s: %s",
					e.ValidationStatus, e.SourceTitle, e.TargetTitle, e.Explanation))
			}
			repPaths = append(repPaths, report.AttackPathSummary{
				ID:                p.ID,
				Title:             p.Title,
				Status:            string(p.Status),
				Confidence:        p.Confidence,
				CombinedRiskLevel: p.CombinedRiskLevel,
				CombinedRiskScore: p.CombinedRiskScore,
				RiskRationale:     p.RiskRationale,
				EntryPoint:        p.EntryPoint,
				TargetAsset:       p.TargetAsset,
				PrimaryWeakness:   p.PrimaryWeakness,
				TerminalImpact:    p.TerminalImpact,
				Transitions:       transitions,
				Assumptions:       p.Assumptions,
				MissingEvidence:   p.MissingEvidence,
				Remediation:       p.Remediation,
				NodeIDs:           p.NodeIDs,
				SyntheticFixture:  p.SyntheticFixture,
			})
		}
		if len(repStories) > 0 {
			report.AttachSecurityStories(&rep, repStories)
		}
		if len(repPaths) > 0 {
			report.AttachAttackPaths(&rep, repPaths)
		}
	}

	// 7. Compile Commercial Report 2.0
	cr := report.BuildCommercialReport(rep)
	if isDraft {
		cr.ExecutiveSummary.CompletionStatus = "[DRAFT - PENDING OPERATOR REVIEW]"
		cr.ExecutiveSummary.PostureStatement = fmt.Sprintf(
			"[DRAFT REPORT] Contains %d approved findings; %d findings remain pending review; %d rejected.",
			len(approvedFindings), pendingCount, rejectedCount,
		)
	}

	// 8. Determine file paths & export
	reportsDir, _ := getReportsDir(asm.Ref)
	reportID := uuid.New().String()
	timestampStr := time.Now().UTC().Format("20060102_150405")

	// Resolve execution ID to ensure foreign key constraint in assessment_reports is satisfied
	reportExecID := opts.ExecutionID
	if reportExecID == "" {
		execs, _ := store.ListExecutions(asm.ID)
		if len(execs) > 0 {
			reportExecID = execs[len(execs)-1].ID
		} else {
			nowTime := time.Now().UTC()
			curExec := &AssessmentExecution{
				ID:           "exec-curated-" + uuid.New().String(),
				AssessmentID: asm.ID,
				Status:       StatusCompleted,
				StartedAt:    nowTime,
				CompletedAt:  &nowTime,
				ConfigSnapshot: ScanConfigSnapshot{
					TimeoutSeconds: 0,
					Concurrency:    1,
				},
			}
			_ = store.CreateExecution(curExec)
			reportExecID = curExec.ID
		}
	}

	htmlPath := opts.ExportHTMLPath
	if htmlPath == "" && reportsDir != "" {
		htmlPath = filepath.Join(reportsDir, fmt.Sprintf("%s_commercial_%s.html", asm.Ref, timestampStr))
	}

	jsonPath := opts.ExportJSONPath
	if jsonPath == "" && reportsDir != "" {
		jsonPath = filepath.Join(reportsDir, fmt.Sprintf("%s_commercial_%s.json", asm.Ref, timestampStr))
	}

	felixVer := opts.FelixVersion
	if felixVer == "" {
		felixVer = "2.0.0"
	}

	// Export HTML
	if htmlPath != "" {
		_ = report.WriteCommercialHTML(cr, htmlPath)
		_ = store.SaveReport(&ReportRecord{
			ID:           "rep-html-" + reportID,
			AssessmentID: asm.ID,
			ExecutionID:  reportExecID,
			Format:       "HTML",
			FilePath:     htmlPath,
			FelixVersion: felixVer,
			Status:       "GENERATED",
		})
	}

	// Export JSON
	if jsonPath != "" {
		_ = report.WriteCommercialJSON(cr, jsonPath)
		_ = store.SaveReport(&ReportRecord{
			ID:           "rep-json-" + reportID,
			AssessmentID: asm.ID,
			ExecutionID:  reportExecID,
			Format:       "JSON",
			FilePath:     jsonPath,
			FelixVersion: felixVer,
			Status:       "GENERATED",
		})
	}

	// Audit record
	_ = store.RecordAuditEvent(&AuditEvent{
		AssessmentID: asm.ID,
		OperatorID:   operatorID,
		ActionType:   "REPORT_GENERATED",
		EntityType:   "REPORT",
		EntityID:     reportID,
		DetailsJSON: fmt.Sprintf(
			`{"is_draft":%t,"approved_findings":%d,"pending_findings":%d,"rejected_findings":%d}`,
			isDraft, len(approvedFindings), pendingCount, rejectedCount,
		),
	})

	return &CuratedReportResult{
		Report:           &rep,
		CommercialReport: &cr,
		IsDraft:          isDraft,
		TotalFindings:    len(rawFindings),
		ApprovedCount:    len(approvedFindings),
		RejectedCount:    rejectedCount,
		PendingCount:     pendingCount,
		HTMLPath:         htmlPath,
		JSONPath:         jsonPath,
		ReportRecordID:   reportID,
	}, nil
}
