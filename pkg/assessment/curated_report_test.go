package assessment

import (
	"path/filepath"
	"strings"
	"testing"
	"time"

	"felix/pkg/report"
)

func TestCuratedReport_BlockedWhenFindingsPendingReview(t *testing.T) {
	store, cleanup := newTestOperatorStore(t)
	defer cleanup()

	client := &Client{ID: "cli-cr-1", Name: "Acme Corp"}
	_ = store.CreateClient(client)
	asm := &Assessment{
		ID:             "asm-cr-1",
		Ref:            "ASM-2026-CR1",
		ClientID:       client.ID,
		Name:           "Review Invariant Test",
		AssessmentType: "BLACK_BOX",
		Status:         StatusCompleted,
		ScopeMode:      "same-origin",
	}
	_ = store.CreateAssessment(asm)
	exec := &AssessmentExecution{
		ID:           "exec-cr-1",
		AssessmentID: asm.ID,
		Status:       StatusCompleted,
		StartedAt:    time.Now().UTC(),
		ConfigSnapshot: ScanConfigSnapshot{
			TimeoutSeconds: 30,
			Concurrency:    5,
		},
	}
	_ = store.CreateExecution(exec)
	target := &AssessmentTarget{
		ID:           "tgt-cr-1",
		AssessmentID: asm.ID,
		TargetURL:    "https://acme.example",
		TargetType:   TargetWebsite,
		ScopeStatus:  "APPROVED",
	}
	_ = store.AddTarget(target)

	// Add 2 findings
	f1 := AssessmentFinding{
		ID:                 "af-001",
		AssessmentID:       asm.ID,
		ExecutionID:        exec.ID,
		TargetID:           target.ID,
		OriginalFindingID:  "FND-AUTH-01",
		Title:              "BOLA in User Profile",
		Category:           "bola",
		Severity:           report.SeverityHigh,
		Confidence:         report.ConfidenceHigh,
		VerificationStatus: report.VerificationVerified,
		TargetURL:          "https://acme.example",
		Endpoint:           "https://acme.example/api/user/1",
	}
	f2 := AssessmentFinding{
		ID:                 "af-002",
		AssessmentID:       asm.ID,
		ExecutionID:        exec.ID,
		TargetID:           target.ID,
		OriginalFindingID:  "FND-SECRET-01",
		Title:              "Leaked API Key",
		Category:           "secrets",
		Severity:           report.SeverityCritical,
		Confidence:         report.ConfidenceHigh,
		VerificationStatus: report.VerificationVerified,
		TargetURL:          "https://acme.example",
		Endpoint:           "https://acme.example/app.js",
	}
	_ = store.SaveFindings([]AssessmentFinding{f1, f2})

	// Operator approves FND-AUTH-01, but leaves FND-SECRET-01 PENDING review
	_ = store.SaveFindingReview(&FindingReview{
		AssessmentID: asm.ID,
		FindingID:    "FND-AUTH-01",
		ReviewStatus: ReviewStatusApproved,
		ReviewedBy:   "alice",
	})

	// Attempting final report (AllowDraft=false) MUST FAIL CLOSED
	_, err := GenerateCuratedCommercialReport(store, asm.ID, "alice", CuratedReportOptions{
		AllowDraft: false,
	})
	if err == nil {
		t.Fatalf("expected error when generating final report with pending reviews, got nil")
	}
	if !strings.Contains(err.Error(), "report generation blocked") {
		t.Errorf("expected error message mentioning report generation blocked, got: %v", err)
	}

	// Generating draft report (AllowDraft=true) MUST SUCCEED with DRAFT labelling
	draftRes, err := GenerateCuratedCommercialReport(store, asm.ID, "alice", CuratedReportOptions{
		AllowDraft: true,
	})
	if err != nil {
		t.Fatalf("GenerateCuratedCommercialReport failed in draft mode: %v", err)
	}
	if !draftRes.IsDraft {
		t.Errorf("expected draft flag set to true")
	}
	if !strings.Contains(draftRes.CommercialReport.ExecutiveSummary.CompletionStatus, "DRAFT") {
		t.Errorf("expected DRAFT in executive completion status, got: %s",
			draftRes.CommercialReport.ExecutiveSummary.CompletionStatus)
	}
}

func TestCuratedReport_RejectedFindingsCompletelyExcluded(t *testing.T) {
	store, cleanup := newTestOperatorStore(t)
	defer cleanup()

	client := &Client{ID: "cli-cr-2", Name: "Delta Security"}
	_ = store.CreateClient(client)
	asm := &Assessment{
		ID:             "asm-cr-2",
		Ref:            "ASM-2026-CR2",
		ClientID:       client.ID,
		Name:           "Rejection Invariant Test",
		AssessmentType: "BLACK_BOX",
		Status:         StatusCompleted,
		ScopeMode:      "same-origin",
	}
	_ = store.CreateAssessment(asm)
	exec := &AssessmentExecution{
		ID:           "exec-cr-2",
		AssessmentID: asm.ID,
		Status:       StatusCompleted,
		StartedAt:    time.Now().UTC(),
	}
	_ = store.CreateExecution(exec)
	target := &AssessmentTarget{
		ID:           "tgt-cr-2",
		AssessmentID: asm.ID,
		TargetURL:    "https://delta.example",
		ScopeStatus:  "APPROVED",
	}
	_ = store.AddTarget(target)

	// Finding 1: Approved High Severity
	f1 := AssessmentFinding{
		ID:                 "af-101",
		AssessmentID:       asm.ID,
		ExecutionID:        exec.ID,
		TargetID:           target.ID,
		OriginalFindingID:  "FND-REAL-01",
		Title:              "Real CSRF Vulnerability",
		Category:           "csrf",
		Severity:           report.SeverityHigh,
		Confidence:         report.ConfidenceHigh,
		VerificationStatus: report.VerificationVerified,
		Score:              25,
		TargetURL:          "https://delta.example",
		Endpoint:           "https://delta.example/transfer",
	}
	// Finding 2: Rejected Critical Severity (e.g. false positive or out of report scope)
	f2 := AssessmentFinding{
		ID:                 "af-102",
		AssessmentID:       asm.ID,
		ExecutionID:        exec.ID,
		TargetID:           target.ID,
		OriginalFindingID:  "FND-FALSE-02",
		Title:              "Spurious SQL Injection Candidate",
		Category:           "sqli",
		Severity:           report.SeverityCritical,
		Confidence:         report.ConfidenceHigh,
		VerificationStatus: report.VerificationVerified,
		Score:              40,
		TargetURL:          "https://delta.example",
		Endpoint:           "https://delta.example/search",
	}
	_ = store.SaveFindings([]AssessmentFinding{f1, f2})

	// Operator explicitly reviews both: F1=Approved, F2=Rejected
	_ = store.SaveFindingReview(&FindingReview{
		AssessmentID: asm.ID,
		FindingID:    "FND-REAL-01",
		ReviewStatus: ReviewStatusApproved,
		ReviewedBy:   "alice",
		Notes:        "Valid CSRF confirmed.",
	})
	_ = store.SaveFindingReview(&FindingReview{
		AssessmentID: asm.ID,
		FindingID:    "FND-FALSE-02",
		ReviewStatus: ReviewStatusRejected,
		ReviewedBy:   "alice",
		Notes:        "WAF block false positive; rejected from client deliverable.",
	})

	// Generate Final Report
	tmpDir := t.TempDir()
	htmlDest := filepath.Join(tmpDir, "report.html")
	jsonDest := filepath.Join(tmpDir, "report.json")

	res, err := GenerateCuratedCommercialReport(store, asm.ID, "alice", CuratedReportOptions{
		AllowDraft:     false,
		ExportHTMLPath: htmlDest,
		ExportJSONPath: jsonDest,
	})
	if err != nil {
		t.Fatalf("GenerateCuratedCommercialReport failed: %v", err)
	}

	cr := res.CommercialReport
	if len(cr.VerifiedFindings) != 1 {
		t.Fatalf("expected exactly 1 verified finding in report, got %d", len(cr.VerifiedFindings))
	}
	if cr.VerifiedFindings[0].ID != "FND-REAL-01" {
		t.Errorf("expected approved finding FND-REAL-01, got %s", cr.VerifiedFindings[0].ID)
	}

	// Ensure rejected finding does NOT appear anywhere in verified, detected, or observations
	for _, df := range cr.DetectedFindings {
		if df.ID == "FND-FALSE-02" {
			t.Errorf("rejected finding leaked into DetectedFindings!")
		}
	}
	for _, obs := range cr.Observations {
		if strings.Contains(obs.Title, "Spurious SQL Injection") {
			t.Errorf("rejected finding leaked into Observations!")
		}
	}

	// Invariant: Risk score must NOT include the rejected critical finding (which would elevate to CRITICAL >= 80)!
	if cr.RiskOverview.RiskScore >= 80 || cr.RiskOverview.RiskLevel == "CRITICAL" {
		t.Errorf("risk score includes rejected critical finding! Got score %d, level %s", cr.RiskOverview.RiskScore, cr.RiskOverview.RiskLevel)
	}
	if cr.RiskOverview.RiskScore != 60 || cr.RiskOverview.RiskLevel != "HIGH" {
		t.Errorf("expected report risk score 60 (HIGH) for approved High finding, got score %d, level %s", cr.RiskOverview.RiskScore, cr.RiskOverview.RiskLevel)
	}

	// Invariant: Original finding in database remains completely unmodified!
	dbFindings, _ := store.GetFindings(asm.ID, "")
	for _, dbF := range dbFindings {
		if dbF.OriginalFindingID == "FND-FALSE-02" {
			if dbF.VerificationStatus != report.VerificationVerified {
				t.Errorf("operator rejection mutated underlying technical status in database!")
			}
			if dbF.Severity != report.SeverityCritical {
				t.Errorf("operator rejection mutated underlying severity in database!")
			}
		}
	}
}

func TestCuratedReport_ZeroFindingsApprovedProducesValidEmptyReport(t *testing.T) {
	store, cleanup := newTestOperatorStore(t)
	defer cleanup()

	client := &Client{ID: "cli-cr-3", Name: "Gamma Inc"}
	_ = store.CreateClient(client)
	asm := &Assessment{
		ID:             "asm-cr-3",
		Ref:            "ASM-2026-CR3",
		ClientID:       client.ID,
		Name:           "Zero Approved Test",
		AssessmentType: "BLACK_BOX",
		Status:         StatusCompleted,
		ScopeMode:      "same-origin",
	}
	_ = store.CreateAssessment(asm)
	exec := &AssessmentExecution{
		ID:           "exec-cr-3",
		AssessmentID: asm.ID,
		Status:       StatusCompleted,
		StartedAt:    time.Now().UTC(),
	}
	_ = store.CreateExecution(exec)
	target := &AssessmentTarget{
		ID:           "tgt-cr-3",
		AssessmentID: asm.ID,
		TargetURL:    "https://gamma.example",
		ScopeStatus:  "APPROVED",
	}
	_ = store.AddTarget(target)

	// Single finding rejected
	f := AssessmentFinding{
		ID:                 "af-201",
		AssessmentID:       asm.ID,
		ExecutionID:        exec.ID,
		TargetID:           target.ID,
		OriginalFindingID:  "FND-REJ-01",
		Title:              "Minor Config Flaw",
		Category:           "config",
		Severity:           report.SeverityLow,
		Confidence:         report.ConfidenceLow,
		VerificationStatus: report.VerificationDetected,
	}
	_ = store.SaveFindings([]AssessmentFinding{f})
	_ = store.SaveFindingReview(&FindingReview{
		AssessmentID: asm.ID,
		FindingID:    "FND-REJ-01",
		ReviewStatus: ReviewStatusRejected,
		ReviewedBy:   "bob",
	})

	// Generate Final Report: 0 approved findings
	res, err := GenerateCuratedCommercialReport(store, asm.ID, "bob", CuratedReportOptions{
		AllowDraft: false,
	})
	if err != nil {
		t.Fatalf("GenerateCuratedCommercialReport failed on zero approved: %v", err)
	}

	if len(res.CommercialReport.VerifiedFindings) != 0 {
		t.Errorf("expected 0 verified findings, got %d", len(res.CommercialReport.VerifiedFindings))
	}
	if res.CommercialReport.RiskOverview.RiskScore != 0 {
		t.Errorf("expected 0 risk score for zero approved findings, got %d", res.CommercialReport.RiskOverview.RiskScore)
	}
	// Does not claim target is secure
	if strings.Contains(strings.ToLower(res.CommercialReport.ExecutiveSummary.PostureStatement), "entirely secure") {
		t.Errorf("report falsely claimed target is secure")
	}
}
