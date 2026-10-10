package operator

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"felix/pkg/assessment"
	"felix/pkg/report"
	"github.com/google/uuid"
)

// setupTestServer initializes an in-memory SQLite store and Operator Server.
func setupTestServer(t *testing.T) (*Server, assessment.Store, func()) {
	t.Helper()
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "felix_operator_test.db")

	store, err := assessment.NewSQLiteStore(dbPath)
	if err != nil {
		t.Fatalf("failed to init test sqlite store: %v", err)
	}

	cfg := Config{
		ListenHost: "127.0.0.1",
		ListenPort: 8383,
		OperatorID: "test-operator",
		Token:      "test-token-1234567890abcdef",
		Store:      store,
		Version:    "2.0.0-test",
	}

	srv, err := NewServer(cfg)
	if err != nil {
		store.Close()
		t.Fatalf("failed to init operator server: %v", err)
	}

	cleanup := func() {
		store.Close()
	}

	return srv, store, cleanup
}

func doRequest(handler http.Handler, method, target string, body any, token string, origin string) *httptest.ResponseRecorder {
	var bodyReader io.Reader
	if body != nil {
		switch v := body.(type) {
		case string:
			bodyReader = strings.NewReader(v)
		case []byte:
			bodyReader = bytes.NewReader(v)
		default:
			b, _ := json.Marshal(v)
			bodyReader = bytes.NewReader(b)
		}
	}

	req := httptest.NewRequest(method, target, bodyReader)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		req.Header.Set("X-Felix-Operator-Token", token)
	}
	if origin != "" {
		req.Header.Set("Origin", origin)
	}

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec
}

func TestServer_LoopbackBindingSecurityEnforcement(t *testing.T) {
	dir := t.TempDir()
	store, err := assessment.NewSQLiteStore(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	// Test 1: Binding to 0.0.0.0 must be rejected
	_, err = NewServer(Config{
		ListenHost: "0.0.0.0",
		Store:      store,
	})
	if err == nil {
		t.Errorf("expected error when binding to 0.0.0.0, got nil")
	}

	// Test 2: Binding to public/external IP must be rejected
	_, err = NewServer(Config{
		ListenHost: "192.168.1.50",
		Store:      store,
	})
	if err == nil {
		t.Errorf("expected error when binding to non-loopback IP, got nil")
	}

	// Test 3: Binding to 127.0.0.1 must succeed
	srv, err := NewServer(Config{
		ListenHost: "127.0.0.1",
		Store:      store,
	})
	if err != nil {
		t.Errorf("expected success binding to 127.0.0.1, got: %v", err)
	}
	if !strings.Contains(srv.URL(), "127.0.0.1") {
		t.Errorf("expected URL to contain 127.0.0.1, got: %s", srv.URL())
	}
}

func TestServer_AuthenticationAndOriginSecurity(t *testing.T) {
	srv, _, cleanup := setupTestServer(t)
	defer cleanup()

	handler := srv.buildMiddlewareChain(srv.mux)

	// Health check is public
	rec := doRequest(handler, "GET", "/api/v1/health", nil, "", "")
	if rec.Code != http.StatusOK {
		t.Errorf("expected 200 for health check, got %d", rec.Code)
	}

	// Unauthenticated request to protected route -> 401
	rec = doRequest(handler, "GET", "/api/v1/clients", nil, "", "")
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 for unauthenticated clients listing, got %d", rec.Code)
	}

	// Invalid token -> 401
	rec = doRequest(handler, "GET", "/api/v1/clients", nil, "wrong-token", "")
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 for wrong token, got %d", rec.Code)
	}

	// Valid header token -> 200
	rec = doRequest(handler, "GET", "/api/v1/clients", nil, srv.Token(), "")
	if rec.Code != http.StatusOK {
		t.Errorf("expected 200 for valid token, got %d", rec.Code)
	}

	// Valid query token -> 200
	rec = doRequest(handler, "GET", "/api/v1/clients?token="+srv.Token(), nil, "", "")
	if rec.Code != http.StatusOK {
		t.Errorf("expected 200 for query token, got %d", rec.Code)
	}

	// Untrusted Origin on mutating request -> 403 Forbidden
	clientPayload := map[string]string{"name": "Cross-Origin Client"}
	rec = doRequest(handler, "POST", "/api/v1/clients", clientPayload, srv.Token(), "http://malicious-site.com")
	if rec.Code != http.StatusForbidden {
		t.Errorf("expected 403 for untrusted Origin, got %d", rec.Code)
	}

	// Trusted loopback Origin on mutating request -> 201 Created
	rec = doRequest(handler, "POST", "/api/v1/clients", clientPayload, srv.Token(), "http://127.0.0.1:8383")
	if rec.Code != http.StatusCreated {
		t.Errorf("expected 201 for trusted loopback Origin, got %d (body: %s)", rec.Code, rec.Body.String())
	}
}

func TestServer_ClientLifecycle(t *testing.T) {
	srv, _, cleanup := setupTestServer(t)
	defer cleanup()

	handler := srv.buildMiddlewareChain(srv.mux)

	// 1. Create Client
	createPayload := map[string]string{
		"name":          "Initech Security",
		"organization":  "Initech Corporation",
		"contact_name":  "Peter Gibbons",
		"contact_email": "pgibbons@initech.com",
		"notes":         "High priority audit",
	}
	rec := doRequest(handler, "POST", "/api/v1/clients", createPayload, srv.Token(), "http://127.0.0.1:8383")
	if rec.Code != http.StatusCreated {
		t.Fatalf("failed to create client: %d %s", rec.Code, rec.Body.String())
	}

	var client assessment.Client
	if err := json.Unmarshal(rec.Body.Bytes(), &client); err != nil {
		t.Fatalf("failed to parse client response: %v", err)
	}
	if client.ID == "" || client.Name != "Initech Security" {
		t.Errorf("unexpected client created: %+v", client)
	}

	// 2. Get Client
	rec = doRequest(handler, "GET", "/api/v1/clients/"+client.ID, nil, srv.Token(), "")
	if rec.Code != http.StatusOK {
		t.Errorf("failed to get client: %d", rec.Code)
	}

	// 3. List Clients
	rec = doRequest(handler, "GET", "/api/v1/clients", nil, srv.Token(), "")
	if rec.Code != http.StatusOK {
		t.Errorf("failed to list clients: %d", rec.Code)
	}

	// 4. Archive Client
	rec = doRequest(handler, "POST", "/api/v1/clients/"+client.ID+"/archive", nil, srv.Token(), "http://127.0.0.1:8383")
	if rec.Code != http.StatusOK {
		t.Errorf("failed to archive client: %d", rec.Code)
	}
}

func TestServer_AssessmentTargetAndAuthorization(t *testing.T) {
	srv, store, cleanup := setupTestServer(t)
	defer cleanup()

	handler := srv.buildMiddlewareChain(srv.mux)

	// Setup client
	client := &assessment.Client{
		ID:        uuid.New().String(),
		Name:      "Target Corp",
		CreatedAt: time.Now().UTC(),
		UpdatedAt: time.Now().UTC(),
	}
	_ = store.CreateClient(client)

	// 1. Create Assessment
	asmPayload := map[string]string{
		"client_id":       client.ID,
		"name":            "Q4 Penetration Test",
		"assessment_type": "BLACK_BOX_WEB",
		"scope_mode":      "same-origin",
	}
	rec := doRequest(handler, "POST", "/api/v1/assessments", asmPayload, srv.Token(), "http://127.0.0.1:8383")
	if rec.Code != http.StatusCreated {
		t.Fatalf("failed to create assessment: %d %s", rec.Code, rec.Body.String())
	}

	var asm assessment.Assessment
	_ = json.Unmarshal(rec.Body.Bytes(), &asm)
	if !strings.HasPrefix(asm.Ref, "ASM-") {
		t.Errorf("expected ref starting with ASM-, got %s", asm.Ref)
	}

	// 2. Add Target
	targetPayload := map[string]string{
		"target_url":  "https://app.example.com",
		"target_type": "WEBSITE",
		"label":       "Staging App",
	}
	rec = doRequest(handler, "POST", "/api/v1/assessments/"+asm.ID+"/targets", targetPayload, srv.Token(), "http://127.0.0.1:8383")
	if rec.Code != http.StatusCreated {
		t.Fatalf("failed to add target: %d %s", rec.Code, rec.Body.String())
	}

	// 3. Record Authorization
	authPayload := map[string]any{
		"authorizing_party":    "John CISO",
		"authorization_method": "WRITTEN_CONTRACT",
		"valid_days":           30,
		"scope_doc_ref":        "DOCS/SOW-2026.pdf",
		"internal_notes":       "Approved testing window",
	}
	rec = doRequest(handler, "POST", "/api/v1/assessments/"+asm.ID+"/authorize", authPayload, srv.Token(), "http://127.0.0.1:8383")
	if rec.Code != http.StatusOK {
		t.Fatalf("failed to authorize: %d %s", rec.Code, rec.Body.String())
	}

	// Verify assessment status advanced to READY
	rec = doRequest(handler, "GET", "/api/v1/assessments/"+asm.ID, nil, srv.Token(), "")
	var getResp map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &getResp)
	asmMap := getResp["assessment"].(map[string]any)
	if asmMap["status"] != "READY" {
		t.Errorf("expected status READY after authorization, got %v", asmMap["status"])
	}
}

func TestServer_FindingReviewAndCuratedReportPipeline(t *testing.T) {
	srv, store, cleanup := setupTestServer(t)
	defer cleanup()

	handler := srv.buildMiddlewareChain(srv.mux)

	// 1. Create client & assessment
	client := &assessment.Client{
		ID:        uuid.New().String(),
		Name:      "Review Client",
		CreatedAt: time.Now().UTC(),
		UpdatedAt: time.Now().UTC(),
	}
	_ = store.CreateClient(client)

	asm := &assessment.Assessment{
		ID:             uuid.New().String(),
		Ref:            assessment.GenerateAssessmentRef(),
		ClientID:       client.ID,
		Name:           "Review Assessment",
		AssessmentType: "BLACK_BOX_WEB",
		Status:         assessment.StatusReady,
		CreatedAt:      time.Now().UTC(),
		UpdatedAt:      time.Now().UTC(),
	}
	_ = store.CreateAssessment(asm)
	target := &assessment.AssessmentTarget{
		ID:           uuid.New().String(),
		AssessmentID: asm.ID,
		TargetURL:    "https://portal.example.com",
		TargetType:   assessment.TargetWebsite,
		ScopeStatus:  "APPROVED",
		CreatedAt:    time.Now().UTC(),
	}
	_ = store.AddTarget(target)

	exec := &assessment.AssessmentExecution{
		ID:           "exec-" + uuid.New().String(),
		AssessmentID: asm.ID,
		Status:       assessment.StatusCompleted,
		StartedAt:    time.Now().UTC(),
	}
	_ = store.CreateExecution(exec)

	now := time.Now().UTC()
	future := now.Add(48 * time.Hour)
	_ = store.SetAuthorization(&assessment.AuthorizationRecord{
		ID:                  uuid.New().String(),
		AssessmentID:        asm.ID,
		AuthorizingParty:    "Security VP",
		AuthorizationMethod: "WRITTEN_CONTRACT",
		Status:              assessment.AuthApproved,
		DateReceived:        now,
		ValidFrom:           &now,
		ValidUntil:          &future,
		CreatedAt:           now,
		UpdatedAt:           now,
	})

	// 2. Insert test findings
	f1 := &assessment.AssessmentFinding{
		ID:                 uuid.New().String(),
		AssessmentID:       asm.ID,
		ExecutionID:        exec.ID,
		TargetID:           target.ID,
		OriginalFindingID:  "FND-REV-001",
		Title:              "Cross-Site Scripting in Search Form",
		Category:           "xss",
		Severity:           report.SeverityHigh,
		Confidence:         report.ConfidenceHigh,
		VerificationStatus: report.VerificationVerified,
		Score:              25,
		TargetURL:          "https://portal.example.com/search",
		CreatedAt:          now,
	}
	f2 := &assessment.AssessmentFinding{
		ID:                 uuid.New().String(),
		AssessmentID:       asm.ID,
		ExecutionID:        exec.ID,
		TargetID:           target.ID,
		OriginalFindingID:  "FND-REV-002",
		Title:              "False Positive Exposure",
		Category:           "info-leak",
		Severity:           report.SeverityMedium,
		Confidence:         report.ConfidenceLow,
		VerificationStatus: report.VerificationDetected,
		Score:              10,
		TargetURL:          "https://portal.example.com/debug",
		CreatedAt:          now,
	}
	if err := store.SaveFindings([]assessment.AssessmentFinding{*f1, *f2}); err != nil {
		t.Fatalf("failed to insert test findings: %v", err)
	}

	// 3. Verify unreviewed findings block final report generation
	genReq := map[string]any{"allow_draft": false}
	rec := doRequest(handler, "POST", "/api/v1/assessments/"+asm.ID+"/reports/generate", genReq, srv.Token(), "http://127.0.0.1:8383")
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 Bad Request when generating final report with unreviewed findings, got %d", rec.Code)
	}

	// 4. Draft generation succeeds
	genDraftReq := map[string]any{"allow_draft": true}
	rec = doRequest(handler, "POST", "/api/v1/assessments/"+asm.ID+"/reports/generate", genDraftReq, srv.Token(), "http://127.0.0.1:8383")
	if rec.Code != http.StatusCreated {
		t.Fatalf("expected 201 Created for draft report, got %d %s", rec.Code, rec.Body.String())
	}
	var draftRes map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &draftRes)
	if draftRes["is_draft"] != true {
		t.Errorf("expected is_draft=true for draft report, got %v", draftRes["is_draft"])
	}

	// 5. Review Findings: Approve FND-REV-001, Reject FND-REV-002
	reviewF1 := map[string]string{
		"status": "APPROVED_FOR_REPORT",
		"notes":  "Confirmed stored XSS with alert proof",
	}
	rec = doRequest(handler, "POST", "/api/v1/assessments/"+asm.ID+"/findings/"+f1.ID+"/review", reviewF1, srv.Token(), "http://127.0.0.1:8383")
	if rec.Code != http.StatusOK {
		t.Fatalf("failed to approve finding: %d %s", rec.Code, rec.Body.String())
	}

	reviewF2 := map[string]string{
		"status": "REJECTED",
		"notes":  "False positive debug endpoint; filtered behind gateway",
	}
	rec = doRequest(handler, "POST", "/api/v1/assessments/"+asm.ID+"/findings/"+f2.ID+"/review", reviewF2, srv.Token(), "http://127.0.0.1:8383")
	if rec.Code != http.StatusOK {
		t.Fatalf("failed to reject finding: %d %s", rec.Code, rec.Body.String())
	}

	// Invariant: underlying finding verification in database is untouched!
	dbFindings, _ := store.GetFindings(asm.ID, "")
	for _, dbF := range dbFindings {
		if dbF.ID == f2.ID || dbF.OriginalFindingID == f2.OriginalFindingID {
			if dbF.VerificationStatus != report.VerificationDetected {
				t.Errorf("operator rejection mutated underlying finding verification status!")
			}
		}
	}

	// 6. Final report generation now succeeds
	rec = doRequest(handler, "POST", "/api/v1/assessments/"+asm.ID+"/reports/generate", genReq, srv.Token(), "http://127.0.0.1:8383")
	if rec.Code != http.StatusCreated {
		t.Fatalf("expected 201 Created for finalized report, got %d %s", rec.Code, rec.Body.String())
	}
	var finalRes map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &finalRes)
	if finalRes["is_draft"] != false {
		t.Errorf("expected is_draft=false for final report")
	}

	// 7. Verify report listing and retrieval
	rec = doRequest(handler, "GET", "/api/v1/assessments/"+asm.ID+"/reports", nil, srv.Token(), "")
	if rec.Code != http.StatusOK {
		t.Errorf("failed to list reports: %d", rec.Code)
	}

	var reportsList map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &reportsList)
	reps := reportsList["reports"].([]any)
	if len(reps) == 0 {
		t.Fatalf("expected at least 1 report record")
	}
	firstRep := reps[0].(map[string]any)
	repID := firstRep["id"].(string)

	// 8. Record Delivery
	delivPayload := map[string]any{
		"recipient_name":  "Sarah Connor",
		"recipient_email": "sconnor@client.com",
		"delivery_method": "ENCRYPTED_EMAIL",
		"confirmed":       true,
		"notes":           "Handed over via PGP key 0xABCDEF",
	}
	rec = doRequest(handler, "POST", "/api/v1/assessments/"+asm.ID+"/reports/"+repID+"/deliver", delivPayload, srv.Token(), "http://127.0.0.1:8383")
	if rec.Code != http.StatusCreated {
		t.Fatalf("failed to record delivery: %d %s", rec.Code, rec.Body.String())
	}

	// 9. List Deliveries
	rec = doRequest(handler, "GET", "/api/v1/assessments/"+asm.ID+"/deliveries", nil, srv.Token(), "")
	if rec.Code != http.StatusOK {
		t.Errorf("failed to list deliveries: %d", rec.Code)
	}

	// 10. Audit trail verification
	rec = doRequest(handler, "GET", "/api/v1/audit", nil, srv.Token(), "")
	if rec.Code != http.StatusOK {
		t.Errorf("failed to list audit events: %d", rec.Code)
	}
	var auditResp map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &auditResp)
	events := auditResp["events"].([]any)
	if len(events) < 5 {
		t.Errorf("expected at least 5 audit events recorded, got %d", len(events))
	}
}

func TestServer_StaticWebAssetsServing(t *testing.T) {
	srv, _, cleanup := setupTestServer(t)
	defer cleanup()

	handler := srv.buildMiddlewareChain(srv.mux)

	// GET /
	rec := doRequest(handler, "GET", "/", nil, "", "")
	if rec.Code != http.StatusOK {
		t.Errorf("expected 200 for root index.html, got %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "FELIX OPERATOR") {
		t.Errorf("index.html missing FELIX OPERATOR title")
	}

	// GET /style.css
	rec = doRequest(handler, "GET", "/style.css", nil, "", "")
	if rec.Code != http.StatusOK {
		t.Errorf("expected 200 for style.css, got %d", rec.Code)
	}

	// GET /app.js
	rec = doRequest(handler, "GET", "/app.js", nil, "", "")
	if rec.Code != http.StatusOK {
		t.Errorf("expected 200 for app.js, got %d", rec.Code)
	}
}
