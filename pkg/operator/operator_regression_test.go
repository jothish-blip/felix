package operator

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"felix/pkg/assessment"
	"felix/pkg/report"
)

// setupOperatorTestServer initializes an in-memory SQLite store and Operator Server.
func setupOperatorRegressionServer(t *testing.T) (*Server, assessment.Store, string, func()) {
	t.Helper()
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "felix_operator_regression.db")
	reportsRoot := filepath.Join(dir, "reports")

	store, err := assessment.NewSQLiteStore(dbPath)
	if err != nil {
		t.Fatalf("failed to init test sqlite store: %v", err)
	}

	adminToken := "admin-secret-token-1234567890abcdef"
	cfg := Config{
		ListenHost:  "127.0.0.1",
		ListenPort:  8383,
		OperatorID:  "test-admin",
		Token:       adminToken,
		Store:       store,
		Version:     "2.0.0-test",
		ReportsRoot: reportsRoot,
	}

	srv, err := NewServer(cfg)
	if err != nil {
		store.Close()
		t.Fatalf("failed to init operator server: %v", err)
	}

	cleanup := func() {
		store.Close()
	}

	return srv, store, adminToken, cleanup
}

// TestOperator_AuthenticationAndAuthorizationEnforcement tests 401 and 403 boundaries and session lifecycle.
func TestOperator_AuthenticationAndAuthorizationEnforcement(t *testing.T) {
	srv, _, adminToken, cleanup := setupOperatorRegressionServer(t)
	defer cleanup()

	handler := srv.buildMiddlewareChain(srv.mux)

	// 1. Unauthenticated request returns 401 Unauthorized
	reqUnauth := httptest.NewRequest(http.MethodGet, "/api/v1/assessments", nil)
	rrUnauth := httptest.NewRecorder()
	handler.ServeHTTP(rrUnauth, reqUnauth)
	if rrUnauth.Code != http.StatusUnauthorized {
		t.Errorf("unauthenticated request status = %d, want 401", rrUnauth.Code)
	}

	// 2. Request with invalid bearer token returns 401 Unauthorized
	reqInvalid := httptest.NewRequest(http.MethodGet, "/api/v1/assessments", nil)
	reqInvalid.Header.Set("Authorization", "Bearer invalid-token-xyz")
	rrInvalid := httptest.NewRecorder()
	handler.ServeHTTP(rrInvalid, reqInvalid)
	if rrInvalid.Code != http.StatusUnauthorized {
		t.Errorf("invalid token request status = %d, want 401", rrInvalid.Code)
	}

	// 3. Request with valid admin token succeeds with 200 OK
	reqValid := httptest.NewRequest(http.MethodGet, "/api/v1/assessments", nil)
	reqValid.Header.Set("Authorization", "Bearer "+adminToken)
	rrValid := httptest.NewRecorder()
	handler.ServeHTTP(rrValid, reqValid)
	if rrValid.Code != http.StatusOK {
		t.Errorf("valid admin request status = %d, want 200", rrValid.Code)
	}

	// 4. Session revocation: register ephemeral session, verify access, revoke, verify 401
	ephemeralToken := "ephemeral-token-9876543210"
	sessErr := srv.RegisterSession(&UserSession{
		Token:      ephemeralToken,
		OperatorID: "operator-temp",
		Role:       RoleAdmin,
		ExpiresAt:  time.Now().Add(1 * time.Hour),
	})
	if sessErr != nil {
		t.Fatalf("RegisterSession failed: %v", sessErr)
	}

	reqSess := httptest.NewRequest(http.MethodGet, "/api/v1/assessments", nil)
	reqSess.Header.Set("Authorization", "Bearer "+ephemeralToken)
	rrSess := httptest.NewRecorder()
	handler.ServeHTTP(rrSess, reqSess)
	if rrSess.Code != http.StatusOK {
		t.Errorf("ephemeral session request status = %d, want 200", rrSess.Code)
	}

	// Revoke session
	revoked := srv.RevokeSession(ephemeralToken)
	if !revoked {
		t.Fatalf("RevokeSession returned false")
	}

	rrRevoked := httptest.NewRecorder()
	handler.ServeHTTP(rrRevoked, reqSess)
	if rrRevoked.Code != http.StatusUnauthorized {
		t.Errorf("revoked session request status = %d, want 401", rrRevoked.Code)
	}
}

// TestOperator_RoleBasedAccessControl verifies RBAC boundaries (Viewer cannot perform write/admin actions).
func TestOperator_RoleBasedAccessControl(t *testing.T) {
	srv, _, _, cleanup := setupOperatorRegressionServer(t)
	defer cleanup()

	handler := srv.buildMiddlewareChain(srv.mux)

	viewerToken := "viewer-token-1122334455"
	_ = srv.RegisterSession(&UserSession{
		Token:      viewerToken,
		OperatorID: "viewer-user",
		Role:       RoleViewer,
		ExpiresAt:  time.Now().Add(1 * time.Hour),
	})

	// Viewer can read assessment list (GET -> 200)
	reqRead := httptest.NewRequest(http.MethodGet, "/api/v1/assessments", nil)
	reqRead.Header.Set("Authorization", "Bearer "+viewerToken)
	rrRead := httptest.NewRecorder()
	handler.ServeHTTP(rrRead, reqRead)
	if rrRead.Code != http.StatusOK {
		t.Errorf("viewer read status = %d, want 200", rrRead.Code)
	}

	// Viewer cannot create assessment (POST -> 403 Forbidden)
	reqWrite := httptest.NewRequest(http.MethodPost, "/api/v1/assessments", strings.NewReader(`{"title":"Unauthorized"}`))
	reqWrite.Header.Set("Authorization", "Bearer "+viewerToken)
	reqWrite.Header.Set("Content-Type", "application/json")
	reqWrite.Header.Set("Origin", "http://127.0.0.1:8383")
	rrWrite := httptest.NewRecorder()
	handler.ServeHTTP(rrWrite, reqWrite)
	if rrWrite.Code != http.StatusForbidden {
		t.Errorf("viewer write status = %d, want 403 Forbidden", rrWrite.Code)
	}
}

// TestOperator_DownloadTokenScopingAndLifecycle verifies download token issuance, expiry, and revocation.
func TestOperator_DownloadTokenScopingAndLifecycle(t *testing.T) {
	srv, _, _, cleanup := setupOperatorRegressionServer(t)
	defer cleanup()

	// 1. Issue short-lived download token
	dt, err := srv.IssueDownloadToken("asmt-001", "rep-001", "HTML", "client-001", 5*time.Minute)
	if err != nil {
		t.Fatalf("IssueDownloadToken failed: %v", err)
	}
	if !strings.HasPrefix(dt.Token, "dlt_") {
		t.Errorf("token = %q, expected prefix 'dlt_'", dt.Token)
	}

	// 2. Validate token retrieval
	retrieved, ok := srv.GetDownloadToken(dt.Token)
	if !ok || retrieved == nil {
		t.Fatalf("GetDownloadToken failed to retrieve token")
	}
	if retrieved.AssessmentID != "asmt-001" || retrieved.ReportID != "rep-001" {
		t.Errorf("mismatched download token metadata: %#v", retrieved)
	}

	// 3. Revoke download token
	if !srv.RevokeDownloadToken(dt.Token) {
		t.Fatalf("RevokeDownloadToken returned false")
	}
	if _, ok := srv.GetDownloadToken(dt.Token); ok {
		t.Errorf("revoked download token was unexpectedly found")
	}

	// 4. Expired token validation
	expiredDT, err := srv.IssueDownloadToken("asmt-002", "rep-002", "JSON", "client-001", -1*time.Minute)
	if err != nil {
		t.Fatalf("IssueDownloadToken for expired token failed: %v", err)
	}
	if _, ok := srv.GetDownloadToken(expiredDT.Token); ok {
		t.Errorf("expired download token was unexpectedly valid")
	}
}

// TestOperator_PathContainmentDefense tests defense against filesystem escapes and directory traversal.
func TestOperator_PathContainmentDefense(t *testing.T) {
	srv, _, _, cleanup := setupOperatorRegressionServer(t)
	defer cleanup()

	cleanRoot := filepath.Clean(srv.cfg.ReportsRoot)

	// Valid path inside root
	safeFile := filepath.Join(cleanRoot, "report-2026.html")
	resolved, err := srv.validateReportPathContainment(safeFile)
	if err != nil {
		t.Fatalf("valid path rejected by containment check: %v", err)
	}
	if resolved != filepath.Clean(safeFile) {
		t.Errorf("resolved = %q, want %q", resolved, safeFile)
	}

	// Directory traversal attacks escaping root
	traversalAttempts := []string{
		"../../etc/passwd",
		filepath.Join(cleanRoot, "..", "secret.txt"),
		filepath.Join(cleanRoot, "..", "..", "windows", "system32", "calc.exe"),
		"/etc/shadow",
		"C:\\Windows\\System32\\cmd.exe",
		"",
		"   ",
	}

	for _, attempt := range traversalAttempts {
		t.Run("containment: "+attempt, func(t *testing.T) {
			_, err := srv.validateReportPathContainment(attempt)
			if err == nil {
				t.Errorf("path traversal attempt %q passed containment check unexpectedly", attempt)
			}
		})
	}
}

// TestOperator_EvidenceReview_FindingSerializationAndAuth tests that operator API finding routes
// require authorization and serialize findings without leaking raw synthetic secrets.
func TestOperator_EvidenceReview_FindingSerializationAndAuth(t *testing.T) {
	srv, store, adminToken, cleanup := setupOperatorRegressionServer(t)
	defer cleanup()

	handler := srv.buildMiddlewareChain(srv.mux)

	clientID := "client-op-rev"
	_ = store.CreateClient(&assessment.Client{
		ID:        clientID,
		Name:      "Operator Evidence Review Client",
		CreatedAt: time.Now().UTC(),
		UpdatedAt: time.Now().UTC(),
	})

	asmID := "asm-op-rev"
	execID := "exec-op-rev"
	targetID := "tgt-op-rev"

	_ = store.CreateAssessment(&assessment.Assessment{
		ID:             asmID,
		Ref:            "ASM-OP-REV",
		Name:           "Operator Evidence Review",
		ClientID:       clientID,
		AssessmentType: "WEB_API",
		Status:         assessment.StatusRunning,
		CreatedAt:      time.Now().UTC(),
		UpdatedAt:      time.Now().UTC(),
	})

	_ = store.AddTarget(&assessment.AssessmentTarget{
		ID:           targetID,
		AssessmentID: asmID,
		TargetURL:    "https://api.corp.local",
		TargetType:   assessment.TargetAPIBaseURL,
		ScopeStatus:  "APPROVED",
	})

	_ = store.CreateExecution(&assessment.AssessmentExecution{
		ID:           execID,
		AssessmentID: asmID,
		Status:       assessment.StatusRunning,
		StartedAt:    time.Now().UTC(),
	})

	secretPassword := "FELIX_TEST_SECRET_PASS_OPERATOR_12345"
	secretToken := "FELIX_TEST_SECRET_TOKEN_OPERATOR_67890"

	// Insert finding
	fnd := assessment.AssessmentFinding{
		ID:                 "op-find-001",
		AssessmentID:       asmID,
		ExecutionID:        execID,
		TargetID:           targetID,
		OriginalFindingID:  "op-find-001",
		Title:              "Credential exposure with password=" + secretPassword,
		Category:           "secrets",
		Severity:           "CRITICAL",
		Confidence:         "HIGH",
		VerificationStatus: "VERIFIED",
		TargetURL:          "https://admin:" + secretPassword + "@internal.corp.local/api",
		Endpoint:           "https://internal.corp.local/v1/auth?token=" + secretToken,
		Method:             "GET",
		EvidenceDetails: report.EvidenceDetails{
			Observation: "Exposed token: Bearer " + secretToken,
			Details: map[string]string{
				"Authorization": "Bearer " + secretToken,
				"db_password":   secretPassword,
				"context_id":    "audit_marker_123",
			},
		},
		CreatedAt: time.Now().UTC(),
	}

	if err := store.SaveFindings([]assessment.AssessmentFinding{fnd}); err != nil {
		t.Fatalf("failed to save finding: %v", err)
	}

	// 1. Unauthenticated request to /api/v1/assessments/{id}/findings must return 401 Unauthorized
	reqUnauth := httptest.NewRequest(http.MethodGet, "/api/v1/assessments/"+asmID+"/findings", nil)
	rrUnauth := httptest.NewRecorder()
	handler.ServeHTTP(rrUnauth, reqUnauth)
	if rrUnauth.Code != http.StatusUnauthorized {
		t.Errorf("unauthenticated findings request status = %d, want 401", rrUnauth.Code)
	}

	// 2. Authenticated request to /api/v1/assessments/{id}/findings returns 200 with zero secret leaks
	reqAuth := httptest.NewRequest(http.MethodGet, "/api/v1/assessments/"+asmID+"/findings", nil)
	reqAuth.Header.Set("Authorization", "Bearer "+adminToken)
	rrAuth := httptest.NewRecorder()
	handler.ServeHTTP(rrAuth, reqAuth)
	if rrAuth.Code != http.StatusOK {
		t.Fatalf("authenticated findings request status = %d, want 200", rrAuth.Code)
	}
	bodyFindings := rrAuth.Body.String()
	if strings.Contains(bodyFindings, secretPassword) || strings.Contains(bodyFindings, secretToken) {
		t.Fatalf("GET /findings leaked sensitive secrets! Body: %s", bodyFindings)
	}
	if !strings.Contains(bodyFindings, "op-find-001") {
		t.Errorf("Finding ID op-find-001 was missing from response: %s", bodyFindings)
	}
	if !strings.Contains(bodyFindings, "audit_marker_123") {
		t.Errorf("Safe metadata audit_marker_123 was missing from response: %s", bodyFindings)
	}

	// 3. Authenticated request to /api/v1/assessments/{id}/findings/{findingId} returns 200 with zero secret leaks
	reqSingle := httptest.NewRequest(http.MethodGet, "/api/v1/assessments/"+asmID+"/findings/op-find-001", nil)
	reqSingle.Header.Set("Authorization", "Bearer "+adminToken)
	rrSingle := httptest.NewRecorder()
	handler.ServeHTTP(rrSingle, reqSingle)
	if rrSingle.Code != http.StatusOK {
		t.Fatalf("authenticated single finding request status = %d, want 200", rrSingle.Code)
	}
	bodySingle := rrSingle.Body.String()
	if strings.Contains(bodySingle, secretPassword) || strings.Contains(bodySingle, secretToken) {
		t.Fatalf("GET /findings/op-find-001 leaked sensitive secrets! Body: %s", bodySingle)
	}
	if !strings.Contains(bodySingle, "op-find-001") {
		t.Errorf("Finding ID op-find-001 was missing from single finding response: %s", bodySingle)
	}
}
