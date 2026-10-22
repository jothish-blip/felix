package operator

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"felix/pkg/assessment"
	"felix/pkg/report"
	"github.com/google/uuid"
)

func TestAPI_AssessmentHistoryAndComparison(t *testing.T) {
	srv, store, cleanup := setupTestServer(t)
	defer cleanup()
	handler := srv.buildMiddlewareChain(srv.mux)

	// 1. Create two separate client organizations (Tenant A and Tenant B)
	clientA := &assessment.Client{
		ID:   "tenant-alpha",
		Name: "Alpha Corp",
	}
	_ = store.CreateClient(clientA)

	clientB := &assessment.Client{
		ID:   "tenant-beta",
		Name: "Beta Corp",
	}
	_ = store.CreateClient(clientB)

	// Register user sessions
	tokenAdmin := "admin-token-xyz"
	_ = srv.RegisterSession(&UserSession{
		Token:      tokenAdmin,
		OperatorID: "op-admin",
		Role:       RoleAdmin,
	})

	tokenOpA := "op-token-alpha"
	_ = srv.RegisterSession(&UserSession{
		Token:      tokenOpA,
		OperatorID: "op-alpha",
		Role:       RoleOperator,
		ClientID:   clientA.ID,
	})

	tokenViewerA := "viewer-token-alpha"
	_ = srv.RegisterSession(&UserSession{
		Token:      tokenViewerA,
		OperatorID: "viewer-alpha",
		Role:       RoleViewer,
		ClientID:   clientA.ID,
	})

	tokenOpB := "op-token-beta"
	_ = srv.RegisterSession(&UserSession{
		Token:      tokenOpB,
		OperatorID: "op-beta",
		Role:       RoleOperator,
		ClientID:   clientB.ID,
	})

	// 2. Set up Baseline Assessment for Client A
	past := time.Now().UTC().Add(-4 * time.Hour)
	baseAsm := &assessment.Assessment{
		ID:             "asm-alpha-base",
		Ref:            "ASM-ALPHA-001",
		ClientID:       clientA.ID,
		Name:           "Alpha Initial Assessment",
		AssessmentType: "BLACK_BOX_WEB",
		Status:         assessment.StatusCompleted,
		CreatedAt:      past,
		CompletedAt:    &past,
	}
	_ = store.CreateAssessment(baseAsm)
	baseTgtID := uuid.New().String()
	_ = store.AddTarget(&assessment.AssessmentTarget{
		ID:           baseTgtID,
		AssessmentID: baseAsm.ID,
		TargetURL:    "https://api.alpha.com",
		ScopeStatus:  "APPROVED",
	})
	baseExecID := "exec-alpha-001"
	_ = store.CreateExecution(&assessment.AssessmentExecution{
		ID:           baseExecID,
		AssessmentID: baseAsm.ID,
		ClientID:     clientA.ID,
		Status:       assessment.StatusCompleted,
		StartedAt:    past,
		CompletedAt:  &past,
	})

	// Findings for baseline
	baseFnd := assessment.AssessmentFinding{
		ID:                uuid.New().String(),
		AssessmentID:      baseAsm.ID,
		ExecutionID:       baseExecID,
		TargetID:          baseTgtID,
		OriginalFindingID: "ALPHA-001",
		Title:             "Vulnerable Cookie Setting",
		Severity:          report.SeverityHigh,
		Category:          "Configuration",
		TargetURL:         "https://api.alpha.com",
		Endpoint:          "/api/v1/auth",
		Fingerprint:       "fp-cookie-001",
	}
	_ = store.SaveFindings([]assessment.AssessmentFinding{baseFnd})

	// 3. Set up Current Assessment for Client A
	now := time.Now().UTC()
	curAsm := &assessment.Assessment{
		ID:             "asm-alpha-cur",
		Ref:            "ASM-ALPHA-002",
		ClientID:       clientA.ID,
		Name:           "Alpha Follow-up Assessment",
		AssessmentType: "BLACK_BOX_WEB",
		Status:         assessment.StatusCompleted,
		CreatedAt:      now,
		CompletedAt:    &now,
	}
	_ = store.CreateAssessment(curAsm)
	curTgtID := uuid.New().String()
	_ = store.AddTarget(&assessment.AssessmentTarget{
		ID:           curTgtID,
		AssessmentID: curAsm.ID,
		TargetURL:    "https://api.alpha.com",
		ScopeStatus:  "APPROVED",
	})
	curExecID := "exec-alpha-002"
	_ = store.CreateExecution(&assessment.AssessmentExecution{
		ID:           curExecID,
		AssessmentID: curAsm.ID,
		ClientID:     clientA.ID,
		Status:       assessment.StatusCompleted,
		StartedAt:    now,
		CompletedAt:  &now,
	})

	// Current assessment resolved the cookie finding and found a new CORS finding
	curFnd := assessment.AssessmentFinding{
		ID:                uuid.New().String(),
		AssessmentID:      curAsm.ID,
		ExecutionID:       curExecID,
		TargetID:          curTgtID,
		OriginalFindingID: "ALPHA-002",
		Title:             "Permissive CORS Wildcard",
		Severity:          report.SeverityMedium,
		Category:          "CORS",
		TargetURL:         "https://api.alpha.com",
		Endpoint:          "/api/v1/cors",
		Fingerprint:       "fp-cors-002",
	}
	_ = store.SaveFindings([]assessment.AssessmentFinding{curFnd})

	// 4. Test GET /api/v1/assessments/{id}/history
	// As Operator A -> 200 OK
	rec := doRequest(handler, "GET", "/api/v1/assessments/"+curAsm.ID+"/history?limit=10", nil, tokenOpA, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 for Operator A history, got %d: %s", rec.Code, rec.Body.String())
	}

	var histResp struct {
		AssessmentID string                             `json:"assessment_id"`
		History      []assessment.AssessmentHistoryItem `json:"history"`
		Total        int                                `json:"total"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &histResp); err != nil {
		t.Fatalf("failed decoding history JSON: %v", err)
	}
	if histResp.Total != 2 {
		t.Errorf("expected 2 assessments in history, got %d", histResp.Total)
	}
	if len(histResp.History) != 2 {
		t.Errorf("expected 2 items, got %d", len(histResp.History))
	}
	// Verify ordering: newest (curAsm) first
	if histResp.History[0].ID != curAsm.ID {
		t.Errorf("expected newest first (%s), got %s", curAsm.ID, histResp.History[0].ID)
	}
	// Verify baseline eligibility on past assessment
	if !histResp.History[1].IsEligibleBaseline {
		t.Errorf("completed baseline should be marked eligible")
	}

	// As Read-Only Viewer A -> 200 OK (Viewers have read access to history)
	rec = doRequest(handler, "GET", "/api/v1/assessments/"+curAsm.ID+"/history", nil, tokenViewerA, "")
	if rec.Code != http.StatusOK {
		t.Errorf("expected 200 for Viewer A history, got %d", rec.Code)
	}

	// 5. Test Cross-Tenant History Access: Operator B -> 404 (IDOR defense)
	rec = doRequest(handler, "GET", "/api/v1/assessments/"+curAsm.ID+"/history", nil, tokenOpB, "")
	if rec.Code != http.StatusNotFound {
		t.Errorf("expected 404 for cross-tenant history access, got %d", rec.Code)
	}

	// 6. Test GET /api/v1/assessments/{id}/compare (with explicit baseline_id)
	rec = doRequest(handler, "GET", "/api/v1/assessments/"+curAsm.ID+"/compare?baseline_id="+baseAsm.ID, nil, tokenOpA, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 for compare, got %d: %s", rec.Code, rec.Body.String())
	}

	var cmpRes assessment.AssessmentComparisonResult
	if err := json.Unmarshal(rec.Body.Bytes(), &cmpRes); err != nil {
		t.Fatalf("failed decoding comparison response: %v", err)
	}

	if cmpRes.ComparabilityStatus != assessment.ComparabilityStatusComparable {
		t.Errorf("expected COMPARABLE status, got %s", cmpRes.ComparabilityStatus)
	}
	if !cmpRes.IsReliable {
		t.Errorf("expected IsReliable=true")
	}
	if cmpRes.ResolvedCount != 1 {
		t.Errorf("expected 1 resolved finding, got %d", cmpRes.ResolvedCount)
	}
	if cmpRes.NewCount != 1 {
		t.Errorf("expected 1 new finding, got %d", cmpRes.NewCount)
	}
	if len(cmpRes.Items) != 2 {
		t.Errorf("expected 2 comparison items, got %d", len(cmpRes.Items))
	}

	// 7. Test Automatic Baseline Selection (omit baseline_id)
	rec = doRequest(handler, "GET", "/api/v1/assessments/"+curAsm.ID+"/compare", nil, tokenOpA, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 for auto baseline compare, got %d: %s", rec.Code, rec.Body.String())
	}
	var autoRes assessment.AssessmentComparisonResult
	_ = json.Unmarshal(rec.Body.Bytes(), &autoRes)
	if autoRes.BaselineAssessmentID != baseAsm.ID {
		t.Errorf("auto-baseline should have selected %s, got %s", baseAsm.ID, autoRes.BaselineAssessmentID)
	}

	// 8. Test Cross-Tenant Comparison Attempt: Operator B attempting to compare Client A assessments -> 404
	rec = doRequest(handler, "GET", "/api/v1/assessments/"+curAsm.ID+"/compare?baseline_id="+baseAsm.ID, nil, tokenOpB, "")
	if rec.Code != http.StatusNotFound {
		t.Errorf("expected 404 for cross-tenant compare attempt, got %d", rec.Code)
	}

	// 9. Test GET /api/v1/compare direct endpoint
	rec = doRequest(handler, "GET", "/api/v1/compare?baseline_id="+baseAsm.ID+"&current_id="+curAsm.ID, nil, tokenAdmin, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 for direct compare as Admin, got %d: %s", rec.Code, rec.Body.String())
	}

	// 10. Audit trail verification: verify ASSESSMENT_COMPARED event was recorded
	rec = doRequest(handler, "GET", "/api/v1/assessments/"+curAsm.ID+"/audit", nil, tokenOpA, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 for audit, got %d", rec.Code)
	}
	var auditResp struct {
		Events []assessment.AuditEvent `json:"events"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &auditResp)
	hasComparedEvent := false
	for _, ev := range auditResp.Events {
		if ev.ActionType == "ASSESSMENT_COMPARED" {
			hasComparedEvent = true
			break
		}
	}
	if !hasComparedEvent {
		t.Errorf("expected audit event ASSESSMENT_COMPARED to be recorded")
	}
}
