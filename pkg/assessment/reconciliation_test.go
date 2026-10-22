package assessment

import (
	"strings"
	"testing"
	"time"

	"felix/pkg/report"
	"github.com/google/uuid"
)

func setupReconciliationTestStore(t *testing.T) (Store, *Client, TenantAuthContext) {
	t.Helper()
	store, err := NewSQLiteStore(":memory:")
	if err != nil {
		t.Fatalf("failed to create sqlite store: %v", err)
	}

	client := &Client{
		ID:        "client-reconcile-001",
		Name:      "Reconciliation Test Client",
		CreatedAt: time.Now().UTC(),
		UpdatedAt: time.Now().UTC(),
	}
	if err := store.CreateClient(client); err != nil {
		t.Fatalf("failed to create test client: %v", err)
	}

	authCtx := NewTenantAuthContext(client.ID, client.ID, "")
	return store, client, authCtx
}

// 1. Complete assessment with multiple findings reconciles with 100% accuracy
func TestReconciliation_CompleteAssessmentWithFindings(t *testing.T) {
	store, client, authCtx := setupReconciliationTestStore(t)
	now := time.Now().UTC()

	asm := &Assessment{
		ID:             "asm-rec-001",
		Ref:            "ASM-REC-001",
		ClientID:       client.ID,
		Name:           "Production Audit",
		AssessmentType: "BLACK_BOX_WEB",
		Status:         StatusCompleted,
		CreatedAt:      now,
		CompletedAt:    &now,
	}
	_ = store.CreateAssessment(asm)
	tgtID := uuid.New().String()
	_ = store.AddTarget(&AssessmentTarget{
		ID:           tgtID,
		AssessmentID: asm.ID,
		TargetURL:    "https://api.example.com",
		ScopeStatus:  "APPROVED",
	})
	execID := "exec-rec-001"
	_ = store.CreateExecution(&AssessmentExecution{
		ID:           execID,
		AssessmentID: asm.ID,
		ClientID:     client.ID,
		Status:       StatusCompleted,
		StartedAt:    now,
		CompletedAt:  &now,
	})

	f1 := AssessmentFinding{
		ID:                uuid.New().String(),
		AssessmentID:      asm.ID,
		ExecutionID:       execID,
		TargetID:          tgtID,
		OriginalFindingID: "REC-001",
		Title:             "SQLi in Login",
		Severity:          report.SeverityCritical,
		Category:          "sqli",
		TargetURL:         "https://api.example.com",
		Endpoint:          "/login",
		Fingerprint:       "fp-sqli-login",
	}
	f2 := AssessmentFinding{
		ID:                uuid.New().String(),
		AssessmentID:      asm.ID,
		ExecutionID:       execID,
		TargetID:          tgtID,
		OriginalFindingID: "REC-002",
		Title:             "Open Redirect",
		Severity:          report.SeverityMedium,
		Category:          "redirect",
		TargetURL:         "https://api.example.com",
		Endpoint:          "/oauth/callback",
		Fingerprint:       "fp-redirect",
	}
	if err := store.SaveFindings([]AssessmentFinding{f1, f2}); err != nil {
		t.Fatalf("failed to save findings: %v", err)
	}

	snap, err := LoadAuthoritativeSnapshot(store, asm.ID, execID, authCtx)
	if err != nil {
		t.Fatalf("LoadAuthoritativeSnapshot failed: %v", err)
	}

	if snap.TotalPersistedCount != 2 {
		t.Errorf("expected 2 persisted findings, got %d", snap.TotalPersistedCount)
	}
	if snap.UniqueFindingsCount != 2 {
		t.Errorf("expected 2 unique findings, got %d", snap.UniqueFindingsCount)
	}
	if snap.SeverityCounts[report.SeverityCritical] != 1 || snap.SeverityCounts[report.SeverityMedium] != 1 {
		t.Errorf("unexpected severity counts: %+v", snap.SeverityCounts)
	}

	// Build authoritative report and reconcile
	rep, err := BuildAuthoritativeReport(snap, false, false)
	if err != nil {
		t.Fatalf("BuildAuthoritativeReport failed: %v", err)
	}

	res, err := ReconcileReport(snap, rep, false)
	if err != nil || !res.IsValid {
		t.Fatalf("reconciliation failed unexpectedly: %v (discrepancies: %v)", err, res.Discrepancies)
	}
	if len(res.Discrepancies) != 0 {
		t.Errorf("expected 0 discrepancies, got: %v", res.Discrepancies)
	}
}

// 2. Complete assessment with genuinely zero findings reconciles cleanly
func TestReconciliation_CleanAssessmentGenuinelyZeroFindings(t *testing.T) {
	store, client, authCtx := setupReconciliationTestStore(t)
	now := time.Now().UTC()

	asm := &Assessment{
		ID:             "asm-rec-clean",
		Ref:            "ASM-REC-CLEAN",
		ClientID:       client.ID,
		Name:           "Clean Assessment",
		AssessmentType: "BLACK_BOX_WEB",
		Status:         StatusCompleted,
		CreatedAt:      now,
		CompletedAt:    &now,
	}
	_ = store.CreateAssessment(asm)
	tgtID := uuid.New().String()
	_ = store.AddTarget(&AssessmentTarget{
		ID:           tgtID,
		AssessmentID: asm.ID,
		TargetURL:    "https://clean.example.com",
		ScopeStatus:  "APPROVED",
	})
	execID := "exec-rec-clean"
	_ = store.CreateExecution(&AssessmentExecution{
		ID:           execID,
		AssessmentID: asm.ID,
		ClientID:     client.ID,
		Status:       StatusCompleted,
		StartedAt:    now,
		CompletedAt:  &now,
	})

	snap, err := LoadAuthoritativeSnapshot(store, asm.ID, execID, authCtx)
	if err != nil {
		t.Fatalf("LoadAuthoritativeSnapshot failed: %v", err)
	}
	if snap.TotalPersistedCount != 0 {
		t.Errorf("expected 0 persisted findings, got %d", snap.TotalPersistedCount)
	}

	rep, err := BuildAuthoritativeReport(snap, false, false)
	if err != nil {
		t.Fatalf("BuildAuthoritativeReport failed: %v", err)
	}

	res, err := ReconcileReport(snap, rep, false)
	if err != nil || !res.IsValid {
		t.Fatalf("clean zero-finding assessment failed reconciliation: %v", err)
	}
	if res.ReportedFindingCount != 0 {
		t.Errorf("expected 0 reported findings, got %d", res.ReportedFindingCount)
	}
}

// 3. Failed, Cancelled, and Incomplete assessments must never be presented as clean COMPLETED
func TestReconciliation_StatusIntegrityAndFailureShield(t *testing.T) {
	store, client, authCtx := setupReconciliationTestStore(t)
	now := time.Now().UTC()

	statusesToTest := []AssessmentStatus{
		StatusFailed,
		StatusCancelled,
		StatusInterrupted,
	}

	for _, st := range statusesToTest {
		t.Run(string(st), func(t *testing.T) {
			asmID := "asm-" + strings.ToLower(string(st))
			execID := "exec-" + strings.ToLower(string(st))

			asm := &Assessment{
				ID:             asmID,
				Ref:            "ASM-" + strings.ToUpper(string(st)),
				ClientID:       client.ID,
				Name:           "Failed or Incomplete Assessment",
				AssessmentType: "BLACK_BOX_WEB",
				Status:         st,
				CreatedAt:      now,
			}
			_ = store.CreateAssessment(asm)
			_ = store.CreateExecution(&AssessmentExecution{
				ID:           execID,
				AssessmentID: asm.ID,
				ClientID:     client.ID,
				Status:       st,
				StartedAt:    now,
				ErrorMessage: "execution halted with failure",
			})

			snap, err := LoadAuthoritativeSnapshot(store, asmID, execID, authCtx)
			if err != nil {
				t.Fatalf("failed loading snapshot for %s: %v", st, err)
			}
			if snap.IsComplete {
				t.Errorf("status %s must not be marked complete", st)
			}

			// Generate authoritative report: status must reflect persisted state and risk must be unavailable
			rep, err := BuildAuthoritativeReport(snap, false, false)
			if err != nil {
				t.Fatalf("BuildAuthoritativeReport failed: %v", err)
			}
			if rep.CompletionStatus != string(st) {
				t.Errorf("expected report completion status %s, got %s", st, rep.CompletionStatus)
			}
			if rep.RiskScoreAvailable || rep.RiskScore > 0 {
				t.Errorf("expected RiskScoreAvailable=false for %s, got available=%t score=%d", st, rep.RiskScoreAvailable, rep.RiskScore)
			}

			// Fabricate a fraudulent report claiming COMPLETED with 80 risk score: reconciliation must catch it
			fraudulentRep := *rep
			fraudulentRep.CompletionStatus = "COMPLETED"
			fraudulentRep.RiskScoreAvailable = true
			fraudulentRep.RiskScore = 80

			res, err := ReconcileReport(snap, &fraudulentRep, false)
			if err == nil || res.IsValid {
				t.Fatalf("reconciliation must reject fraudulent COMPLETED report on %s assessment", st)
			}
			if len(res.Discrepancies) == 0 {
				t.Errorf("expected discrepancies explaining status conflict")
			}
		})
	}
}

// 4. Duplicate findings and canonical deduplication reconciliation
func TestReconciliation_DeduplicationPreserved(t *testing.T) {
	store, client, authCtx := setupReconciliationTestStore(t)
	now := time.Now().UTC()

	asm := &Assessment{
		ID:             "asm-rec-dedup",
		Ref:            "ASM-REC-DEDUP",
		ClientID:       client.ID,
		Name:           "Dedup Audit",
		AssessmentType: "BLACK_BOX_WEB",
		Status:         StatusCompleted,
		CreatedAt:      now,
		CompletedAt:    &now,
	}
	_ = store.CreateAssessment(asm)
	tgtID := uuid.New().String()
	_ = store.AddTarget(&AssessmentTarget{
		ID:           tgtID,
		AssessmentID: asm.ID,
		TargetURL:    "https://api.example.com",
		ScopeStatus:  "APPROVED",
	})
	execID := "exec-rec-dedup"
	_ = store.CreateExecution(&AssessmentExecution{
		ID:           execID,
		AssessmentID: asm.ID,
		ClientID:     client.ID,
		Status:       StatusCompleted,
		StartedAt:    now,
		CompletedAt:  &now,
	})

	// 3 findings in database that share identical canonical fingerprint (e.g. repeated scans across paths)
	fpShared := "fp-shared-csrf-001"
	f1 := AssessmentFinding{
		ID:           uuid.New().String(),
		AssessmentID: asm.ID,
		ExecutionID:  execID,
		TargetID:     tgtID,
		Title:        "CSRF in Profile Update",
		Severity:     report.SeverityMedium,
		Category:     "CSRF",
		TargetURL:    "https://api.example.com",
		Endpoint:     "/api/user/profile",
		Fingerprint:  fpShared,
	}
	f2 := AssessmentFinding{
		ID:           uuid.New().String(),
		AssessmentID: asm.ID,
		ExecutionID:  execID,
		TargetID:     tgtID,
		Title:        "CSRF in Profile Update",
		Severity:     report.SeverityMedium,
		Category:     "CSRF",
		TargetURL:    "https://api.example.com",
		Endpoint:     "/api/user/profile",
		Fingerprint:  fpShared,
	}
	f3 := AssessmentFinding{
		ID:           uuid.New().String(),
		AssessmentID: asm.ID,
		ExecutionID:  execID,
		TargetID:     tgtID,
		Title:        "CSRF in Profile Update",
		Severity:     report.SeverityMedium,
		Category:     "CSRF",
		TargetURL:    "https://api.example.com",
		Endpoint:     "/api/user/profile",
		Fingerprint:  fpShared,
	}
	_ = store.SaveFindings([]AssessmentFinding{f1, f2, f3})

	snap, err := LoadAuthoritativeSnapshot(store, asm.ID, execID, authCtx)
	if err != nil {
		t.Fatalf("LoadAuthoritativeSnapshot failed: %v", err)
	}

	// Total persisted must be 3; unique deduplicated must be 1
	if snap.TotalPersistedCount != 3 {
		t.Errorf("expected 3 persisted findings, got %d", snap.TotalPersistedCount)
	}
	if snap.UniqueFindingsCount != 1 {
		t.Errorf("expected 1 unique deduplicated finding, got %d", snap.UniqueFindingsCount)
	}

	rep, err := BuildAuthoritativeReport(snap, false, false)
	if err != nil {
		t.Fatalf("BuildAuthoritativeReport failed: %v", err)
	}
	if len(rep.Findings) != 1 {
		t.Errorf("expected report to display 1 deduplicated finding, got %d", len(rep.Findings))
	}

	res, err := ReconcileReport(snap, rep, false)
	if err != nil || !res.IsValid {
		t.Fatalf("reconciliation failed for deduplicated finding: %v", err)
	}
}

// 5. Unexecuted assessment fails closed
func TestReconciliation_UnexecutedAssessmentFailsClosed(t *testing.T) {
	store, client, authCtx := setupReconciliationTestStore(t)
	now := time.Now().UTC()

	asm := &Assessment{
		ID:             "asm-unexecuted",
		Ref:            "ASM-UNEXECUTED",
		ClientID:       client.ID,
		Name:           "Draft Assessment",
		AssessmentType: "BLACK_BOX_WEB",
		Status:         StatusDraft,
		CreatedAt:      now,
	}
	_ = store.CreateAssessment(asm)

	_, err := LoadAuthoritativeSnapshot(store, asm.ID, "", authCtx)
	if err == nil {
		t.Fatalf("expected error loading snapshot for unexecuted assessment, got nil")
	}
	if !strings.Contains(err.Error(), "has not been executed") {
		t.Errorf("expected ErrUnexecutedAssessment error message, got %v", err)
	}
}

// 6. Cross-Tenant isolation: unauthorized client cannot load snapshot
func TestReconciliation_CrossTenantIsolation(t *testing.T) {
	store, clientA, authCtxA := setupReconciliationTestStore(t)
	now := time.Now().UTC()

	asmA := &Assessment{
		ID:             "asm-client-a",
		Ref:            "ASM-CLIENT-A",
		ClientID:       clientA.ID,
		Name:           "Client A Data",
		AssessmentType: "BLACK_BOX_WEB",
		Status:         StatusCompleted,
		CreatedAt:      now,
	}
	_ = store.CreateAssessment(asmA)
	_ = store.CreateExecution(&AssessmentExecution{
		ID:           "exec-client-a",
		AssessmentID: asmA.ID,
		ClientID:     clientA.ID,
		Status:       StatusCompleted,
		StartedAt:    now,
	})

	// Client B auth context
	authCtxB := NewTenantAuthContext("client-b-999", "client-b-999", "")

	// Client A succeeds
	_, err := LoadAuthoritativeSnapshot(store, asmA.ID, "", authCtxA)
	if err != nil {
		t.Errorf("Client A should successfully load own snapshot: %v", err)
	}

	// Client B fails
	_, err = LoadAuthoritativeSnapshot(store, asmA.ID, "", authCtxB)
	if err == nil {
		t.Fatalf("Client B must NOT be authorized to load Client A snapshot")
	}
}

// 7. Fabricated finding detection: reports containing unpersisted findings are rejected
func TestReconciliation_RejectsFabricatedFindings(t *testing.T) {
	store, client, authCtx := setupReconciliationTestStore(t)
	now := time.Now().UTC()

	asm := &Assessment{
		ID:             "asm-rec-fab",
		Ref:            "ASM-REC-FAB",
		ClientID:       client.ID,
		Name:           "Fabrication Test",
		AssessmentType: "BLACK_BOX_WEB",
		Status:         StatusCompleted,
		CreatedAt:      now,
	}
	_ = store.CreateAssessment(asm)
	tgtID := uuid.New().String()
	_ = store.AddTarget(&AssessmentTarget{
		ID:           tgtID,
		AssessmentID: asm.ID,
		TargetURL:    "https://api.example.com",
		ScopeStatus:  "APPROVED",
	})
	execID := "exec-rec-fab"
	_ = store.CreateExecution(&AssessmentExecution{
		ID:           execID,
		AssessmentID: asm.ID,
		ClientID:     client.ID,
		Status:       StatusCompleted,
		StartedAt:    now,
	})

	realFnd := AssessmentFinding{
		ID:           uuid.New().String(),
		AssessmentID: asm.ID,
		ExecutionID:  execID,
		TargetID:     tgtID,
		Title:        "Real Vulnerability",
		Severity:     report.SeverityLow,
		Fingerprint:  "fp-real-001",
	}
	_ = store.SaveFindings([]AssessmentFinding{realFnd})

	snap, err := LoadAuthoritativeSnapshot(store, asm.ID, execID, authCtx)
	if err != nil {
		t.Fatalf("LoadAuthoritativeSnapshot failed: %v", err)
	}

	// Create a report containing a fabricated finding not in the database
	rep, _ := BuildAuthoritativeReport(snap, false, false)
	fabricatedFnd := report.Finding{
		ID:          "fnd-fake-999",
		Title:       "Fabricated Critical RCE",
		Severity:    report.SeverityCritical,
		Fingerprint: "fp-fake-not-in-db-999",
	}
	rep.Findings = append(rep.Findings, fabricatedFnd)

	res, err := ReconcileReport(snap, rep, false)
	if err == nil || res.IsValid {
		t.Fatalf("reconciliation must reject reports with unpersisted fabricated findings")
	}
	if !strings.Contains(strings.Join(res.Discrepancies, "; "), "unpersisted finding detected") {
		t.Errorf("expected discrepancy mentioning unpersisted finding, got: %v", res.Discrepancies)
	}
}

// 8. Unexecuted assessment fails closed in curated commercial report generation
func TestCuratedCommercialReport_UnexecutedFailsClosed(t *testing.T) {
	store, client, _ := setupReconciliationTestStore(t)
	now := time.Now().UTC()

	asm := &Assessment{
		ID:             "asm-cr-unexecuted",
		Ref:            "ASM-CR-UNEXEC",
		ClientID:       client.ID,
		Name:           "Unexecuted Curated Assessment",
		AssessmentType: "BLACK_BOX_WEB",
		Status:         StatusDraft,
		CreatedAt:      now,
	}
	_ = store.CreateAssessment(asm)

	_, err := GenerateCuratedCommercialReport(store, asm.ID, "test-op", CuratedReportOptions{AllowDraft: false})
	if err == nil {
		t.Fatalf("expected error generating curated report for unexecuted assessment, got nil")
	}
	if !strings.Contains(err.Error(), "has never been executed") {
		t.Errorf("expected ErrUnexecutedAssessment message, got: %v", err)
	}
}

// 9. Cancelled and failed assessments in curated report generation produce UNAVAILABLE risk score
func TestCuratedCommercialReport_CancelledAndFailedRiskUnavailable(t *testing.T) {
	store, client, _ := setupReconciliationTestStore(t)
	now := time.Now().UTC()

	for _, st := range []AssessmentStatus{StatusCancelled, StatusFailed, StatusInterrupted} {
		t.Run(string(st), func(t *testing.T) {
			asm := &Assessment{
				ID:             "asm-cr-" + strings.ToLower(string(st)),
				Ref:            "ASM-CR-" + strings.ToUpper(string(st)),
				ClientID:       client.ID,
				Name:           "Status Shield Test",
				AssessmentType: "BLACK_BOX_WEB",
				Status:         st,
				CreatedAt:      now,
			}
			_ = store.CreateAssessment(asm)
			exec := &AssessmentExecution{
				ID:           "exec-cr-" + strings.ToLower(string(st)),
				AssessmentID: asm.ID,
				ClientID:     client.ID,
				Status:       st,
				StartedAt:    now,
			}
			_ = store.CreateExecution(exec)

			res, err := GenerateCuratedCommercialReport(store, asm.ID, "test-op", CuratedReportOptions{AllowDraft: true})
			if err != nil {
				t.Fatalf("unexpected error generating curated report for %s: %v", st, err)
			}
			if res.Report.RiskScoreAvailable || res.Report.RiskScore > 0 {
				t.Errorf("expected Report.RiskScoreAvailable=false, got score=%d available=%t", res.Report.RiskScore, res.Report.RiskScoreAvailable)
			}
			if res.Report.RiskLevel != "UNAVAILABLE" {
				t.Errorf("expected Report.RiskLevel=UNAVAILABLE, got %s", res.Report.RiskLevel)
			}
			if res.CommercialReport.RiskOverview.RiskScore != 0 {
				t.Errorf("expected CommercialReport.RiskScore=0, got %d", res.CommercialReport.RiskOverview.RiskScore)
			}
			if res.CommercialReport.RiskOverview.RiskLevel != "UNAVAILABLE" {
				t.Errorf("expected CommercialReport.RiskLevel=UNAVAILABLE, got %s", res.CommercialReport.RiskOverview.RiskLevel)
			}
			if res.CommercialReport.RiskOverview.RiskScoreAvailable {
				t.Errorf("expected CommercialReport.RiskScoreAvailable=false, got true")
			}
		})
	}
}
