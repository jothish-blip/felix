package operator

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"felix/pkg/assessment"
	"felix/pkg/report"
	"github.com/google/uuid"
)

func TestAPI_ReconcileReport(t *testing.T) {
	srv, store, cleanup := setupTestServer(t)
	defer cleanup()
	handler := srv.buildMiddlewareChain(srv.mux)

	// 1. Create Tenant A and Tenant B
	clientA := &assessment.Client{
		ID:   "tenant-reconcile-a",
		Name: "Client A",
	}
	_ = store.CreateClient(clientA)

	clientB := &assessment.Client{
		ID:   "tenant-reconcile-b",
		Name: "Client B",
	}
	_ = store.CreateClient(clientB)

	// Register Sessions
	tokenOpA := "tok-op-reconcile-a"
	_ = srv.RegisterSession(&UserSession{
		Token:      tokenOpA,
		OperatorID: "op-a",
		Role:       RoleOperator,
		ClientID:   clientA.ID,
	})

	tokenViewerA := "tok-view-reconcile-a"
	_ = srv.RegisterSession(&UserSession{
		Token:      tokenViewerA,
		OperatorID: "view-a",
		Role:       RoleViewer,
		ClientID:   clientA.ID,
	})

	tokenOpB := "tok-op-reconcile-b"
	_ = srv.RegisterSession(&UserSession{
		Token:      tokenOpB,
		OperatorID: "op-b",
		Role:       RoleOperator,
		ClientID:   clientB.ID,
	})

	// 2. Set up Completed Assessment for Client A
	now := time.Now().UTC()
	asmA := &assessment.Assessment{
		ID:             "asm-reconcile-a",
		Ref:            "ASM-REC-A-001",
		ClientID:       clientA.ID,
		Name:           "Reconciliation Assessment A",
		AssessmentType: "BLACK_BOX_WEB",
		Status:         assessment.StatusCompleted,
		CreatedAt:      now,
		CompletedAt:    &now,
	}
	_ = store.CreateAssessment(asmA)
	tgtID := uuid.New().String()
	_ = store.AddTarget(&assessment.AssessmentTarget{
		ID:           tgtID,
		AssessmentID: asmA.ID,
		TargetURL:    "https://api.alpha.com",
		ScopeStatus:  "APPROVED",
	})
	execID := "exec-reconcile-a"
	_ = store.CreateExecution(&assessment.AssessmentExecution{
		ID:           execID,
		AssessmentID: asmA.ID,
		ClientID:     clientA.ID,
		Status:       assessment.StatusCompleted,
		StartedAt:    now,
		CompletedAt:  &now,
	})

	fnd := assessment.AssessmentFinding{
		ID:                uuid.New().String(),
		AssessmentID:      asmA.ID,
		ExecutionID:       execID,
		TargetID:          tgtID,
		OriginalFindingID: "REC-A-01",
		Title:             "CORS Wildcard",
		Severity:          report.SeverityMedium,
		Category:          "CORS",
		TargetURL:         "https://api.alpha.com",
		Endpoint:          "/api/data",
		Fingerprint: "fp-rec-a-01",
		VerificationRecord: report.VerificationRecord{
			Status: report.VerificationVerified,
		},
	}
	_ = store.SaveFindings([]assessment.AssessmentFinding{fnd})

	// 3. Test reconcile BEFORE report is generated
	rec := doRequest(handler, "GET", "/api/v1/assessments/"+asmA.ID+"/reconcile", nil, tokenOpA, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 before report generation, got %d: %s", rec.Code, rec.Body.String())
	}
	var preResp struct {
		IsValid             bool `json:"is_valid"`
		TotalPersistedCount int  `json:"total_persisted_count"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &preResp)
	if !preResp.IsValid || preResp.TotalPersistedCount != 1 {
		t.Errorf("expected is_valid=true and total=1, got %+v", preResp)
	}

	// 4. Generate report
	_ = store.SaveFindingReview(&assessment.FindingReview{
		ID:           uuid.New().String(),
		AssessmentID: asmA.ID,
		FindingID:    fnd.OriginalFindingID,
		ReviewStatus: assessment.ReviewStatusApproved,
	})
	genRec := doRequest(handler, "POST", "/api/v1/assessments/"+asmA.ID+"/reports/generate", strings.NewReader(`{}`), tokenOpA, "")
	if genRec.Code != http.StatusCreated {
		t.Fatalf("expected 201 for report generation, got %d: %s", genRec.Code, genRec.Body.String())
	}

	// 5. Reconcile AFTER report is generated
	rec = doRequest(handler, "GET", "/api/v1/assessments/"+asmA.ID+"/reconcile", nil, tokenOpA, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 for reconcile, got %d: %s", rec.Code, rec.Body.String())
	}
	var reconResp assessment.ReconciliationResult
	if err := json.Unmarshal(rec.Body.Bytes(), &reconResp); err != nil {
		t.Fatalf("failed decoding reconciliation response: %v", err)
	}
	if !reconResp.IsValid {
		t.Errorf("expected report to reconcile cleanly, got discrepancies: %v", reconResp.Discrepancies)
	}
	if reconResp.ReportedFindingCount != 1 {
		t.Errorf("expected 1 reported finding, got %d", reconResp.ReportedFindingCount)
	}

	// 6. As Viewer A -> 200 OK (Viewers have read access to reconciliation facts)
	rec = doRequest(handler, "GET", "/api/v1/assessments/"+asmA.ID+"/reconcile", nil, tokenViewerA, "")
	if rec.Code != http.StatusOK {
		t.Errorf("expected 200 for Viewer A reconcile, got %d", rec.Code)
	}

	// 7. Cross-Tenant IDOR defense: Operator B -> 404 Not Found
	rec = doRequest(handler, "GET", "/api/v1/assessments/"+asmA.ID+"/reconcile", nil, tokenOpB, "")
	if rec.Code != http.StatusNotFound {
		t.Errorf("expected 404 for cross-tenant reconcile, got %d", rec.Code)
	}

	// 8. Unauthenticated -> 401 Unauthorized
	rec = doRequest(handler, "GET", "/api/v1/assessments/"+asmA.ID+"/reconcile", nil, "", "")
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 for unauthenticated reconcile, got %d", rec.Code)
	}

	// 9. Unexecuted assessment returns 409 Conflict
	asmUnexec := &assessment.Assessment{
		ID:             "asm-reconcile-unexec",
		Ref:            "ASM-REC-UNEXEC",
		ClientID:       clientA.ID,
		Name:           "Unexecuted Reconcile Test",
		AssessmentType: "BLACK_BOX_WEB",
		Status:         assessment.StatusDraft,
		CreatedAt:      now,
	}
	_ = store.CreateAssessment(asmUnexec)
	rec = doRequest(handler, "GET", "/api/v1/assessments/"+asmUnexec.ID+"/reconcile", nil, tokenOpA, "")
	if rec.Code != http.StatusConflict {
		t.Errorf("expected 409 Conflict for unexecuted assessment reconcile, got %d: %s", rec.Code, rec.Body.String())
	}
}
