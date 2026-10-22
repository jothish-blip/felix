package operator

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"felix/pkg/assessment"
	"felix/pkg/report"
)

// TestSecurity_AuthenticationAndTokenEnforcement tests all token validation mechanisms.
func TestSecurity_AuthenticationAndTokenEnforcement(t *testing.T) {
	srv, _, cleanup := setupTestServer(t)
	defer cleanup()
	handler := srv.buildMiddlewareChain(srv.mux)

	// 1. Missing token on protected endpoint -> 401
	rec := doRequest(handler, "GET", "/api/v1/clients", nil, "", "")
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for missing token, got %d", rec.Code)
	}

	// 2. Invalid token -> 401
	rec = doRequest(handler, "GET", "/api/v1/clients", nil, "invalid-non-existent-token", "")
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for invalid token, got %d", rec.Code)
	}

	// 3. Expired token -> 401
	expiredToken := "expired-token-123"
	_ = srv.RegisterSession(&UserSession{
		Token:      expiredToken,
		OperatorID: "op-expired",
		Role:       RoleAdmin,
		ExpiresAt:  time.Now().Add(-1 * time.Hour), // Expired 1 hour ago
	})
	rec = doRequest(handler, "GET", "/api/v1/clients", nil, expiredToken, "")
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for expired token, got %d", rec.Code)
	}

	// 4. Revoked token -> 401
	revokedToken := "revoked-token-456"
	_ = srv.RegisterSession(&UserSession{
		Token:      revokedToken,
		OperatorID: "op-revoked",
		Role:       RoleAdmin,
		Revoked:    true,
	})
	rec = doRequest(handler, "GET", "/api/v1/clients", nil, revokedToken, "")
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for revoked token, got %d", rec.Code)
	}

	// Also test explicit RevokeSession method
	activeToken := "active-then-revoked-token"
	_ = srv.RegisterSession(&UserSession{
		Token:      activeToken,
		OperatorID: "op-to-revoke",
		Role:       RoleAdmin,
	})
	rec = doRequest(handler, "GET", "/api/v1/clients", nil, activeToken, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 before revocation, got %d", rec.Code)
	}
	srv.RevokeSession(activeToken)
	rec = doRequest(handler, "GET", "/api/v1/clients", nil, activeToken, "")
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 after revocation, got %d", rec.Code)
	}

	// 5. Query parameter token:
	// Allowed for GET (safe requests like file downloads)
	rec = doRequest(handler, "GET", "/api/v1/clients?token="+srv.Token(), nil, "", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 for GET with query token, got %d", rec.Code)
	}

	// Strictly prohibited for state-changing mutations (POST, PUT, DELETE, PATCH)
	clientPayload := map[string]string{"name": "Query Param Mutation"}
	rec = doRequest(handler, "POST", "/api/v1/clients?token="+srv.Token(), clientPayload, "", "http://127.0.0.1:8383")
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 when attempting mutating POST with query parameter token, got %d", rec.Code)
	}

	// 6. Path-traversal authentication bypass prevention
	// An attacker attempts to exploit path normalization by prefixing with /api/v1/health/../
	rec = doRequest(handler, "GET", "/api/v1/health/../audit", nil, "", "")
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for path traversal attempt to audit trail without token, got %d", rec.Code)
	}
}

// TestSecurity_RoleBoundariesAndViewerRestrictions verifies that read-only viewers cannot execute mutations.
func TestSecurity_RoleBoundariesAndViewerRestrictions(t *testing.T) {
	srv, store, cleanup := setupTestServer(t)
	defer cleanup()
	handler := srv.buildMiddlewareChain(srv.mux)

	// Create test client and assessment
	client := &assessment.Client{
		ID:        "client-tenant-corp",
		Name:      "Tenant Corp",
		CreatedAt: time.Now().UTC(),
		UpdatedAt: time.Now().UTC(),
	}
	_ = store.CreateClient(client)

	asm := &assessment.Assessment{
		ID:             "asm-tenant-corp-01",
		Ref:            "ASM-TC-001",
		ClientID:       client.ID,
		Name:           "Core Assessment",
		AssessmentType: "BLACK_BOX_WEB",
		Status:         assessment.StatusDraft,
		CreatedAt:      time.Now().UTC(),
		UpdatedAt:      time.Now().UTC(),
	}
	_ = store.CreateAssessment(asm)

	// Register a read-only viewer session
	viewerToken := "token-viewer-restricted"
	_ = srv.RegisterSession(&UserSession{
		Token:      viewerToken,
		OperatorID: "viewer-alice",
		Role:       RoleViewer,
		ClientID:   client.ID,
	})

	// Viewer can read assessment data
	rec := doRequest(handler, "GET", "/api/v1/assessments/"+asm.ID, nil, viewerToken, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("expected viewer to read assessment, got %d", rec.Code)
	}

	// Viewer cannot access global audit trail (requires admin) -> 403 Forbidden
	rec = doRequest(handler, "GET", "/api/v1/audit", nil, viewerToken, "")
	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for viewer accessing global audit, got %d", rec.Code)
	}

	// Mutating operations that MUST be blocked with 403 Forbidden for Viewer:
	mutatingTests := []struct {
		name   string
		method string
		path   string
		body   any
	}{
		{
			name:   "Create Client",
			method: "POST",
			path:   "/api/v1/clients",
			body:   map[string]string{"name": "Unauthorized Client"},
		},
		{
			name:   "Archive Client",
			method: "POST",
			path:   "/api/v1/clients/" + client.ID + "/archive",
			body:   nil,
		},
		{
			name:   "Create Assessment",
			method: "POST",
			path:   "/api/v1/assessments",
			body:   map[string]string{"client_id": client.ID, "name": "Unauthorized Asm"},
		},
		{
			name:   "Add Target",
			method: "POST",
			path:   "/api/v1/assessments/" + asm.ID + "/targets",
			body:   map[string]string{"target_url": "https://example.com"},
		},
		{
			name:   "Authorize Assessment",
			method: "POST",
			path:   "/api/v1/assessments/" + asm.ID + "/authorize",
			body:   map[string]string{"authorizing_party": "Sarah", "authorization_method": "EMAIL"},
		},
		{
			name:   "Start Scan",
			method: "POST",
			path:   "/api/v1/assessments/" + asm.ID + "/scan",
			body:   map[string]any{"verbose": true},
		},
		{
			name:   "Cancel Scan",
			method: "POST",
			path:   "/api/v1/assessments/" + asm.ID + "/scan/cancel",
			body:   nil,
		},
		{
			name:   "Review Finding",
			method: "POST",
			path:   "/api/v1/assessments/" + asm.ID + "/findings/fnd-123/review",
			body:   map[string]string{"status": "APPROVED_FOR_REPORT"},
		},
		{
			name:   "Generate Report",
			method: "POST",
			path:   "/api/v1/assessments/" + asm.ID + "/reports/generate",
			body:   map[string]any{"allow_draft": true},
		},
		{
			name:   "Deliver Report",
			method: "POST",
			path:   "/api/v1/assessments/" + asm.ID + "/reports/rep-123/deliver",
			body:   map[string]any{"recipient_name": "Sarah Connor", "confirmed": true},
		},
	}

	for _, tc := range mutatingTests {
		t.Run(tc.name, func(t *testing.T) {
			rec := doRequest(handler, tc.method, tc.path, tc.body, viewerToken, "http://127.0.0.1:8383")
			if rec.Code != http.StatusForbidden {
				t.Errorf("[%s %s] expected 403 Forbidden for viewer, got %d (body: %s)", tc.method, tc.path, rec.Code, rec.Body.String())
			}
		})
	}
}

// TestSecurity_TenantIsolationAndIDORPrevention verifies that tenants cannot cross boundaries.
func TestSecurity_TenantIsolationAndIDORPrevention(t *testing.T) {
	srv, store, cleanup := setupTestServer(t)
	defer cleanup()
	handler := srv.buildMiddlewareChain(srv.mux)

	// Setup Tenant Alpha
	clientA := &assessment.Client{
		ID:        "client-alpha",
		Name:      "Alpha Corp",
		CreatedAt: time.Now().UTC(),
		UpdatedAt: time.Now().UTC(),
	}
	_ = store.CreateClient(clientA)

	asmA := &assessment.Assessment{
		ID:             "asm-alpha-1",
		Ref:            "ASM-ALPHA-01",
		ClientID:       clientA.ID,
		Name:           "Alpha Web Audit",
		AssessmentType: "BLACK_BOX_WEB",
		Status:         assessment.StatusDraft,
		CreatedAt:      time.Now().UTC(),
		UpdatedAt:      time.Now().UTC(),
	}
	_ = store.CreateAssessment(asmA)

	targetA := &assessment.AssessmentTarget{
		ID:           "target-alpha-1",
		AssessmentID: asmA.ID,
		TargetURL:    "https://alpha.example.com",
		TargetType:   assessment.TargetWebsite,
		ScopeStatus:  "APPROVED",
		CreatedAt:    time.Now().UTC(),
	}
	_ = store.AddTarget(targetA)

	findingA := assessment.AssessmentFinding{
		ID:                 "fnd-alpha-1",
		AssessmentID:       asmA.ID,
		OriginalFindingID:  "fnd-alpha-1",
		Title:              "Alpha Finding",
		Severity:           report.SeverityHigh,
		VerificationStatus: report.VerificationVerified,
		CreatedAt:          time.Now().UTC(),
	}
	_ = store.SaveFindings([]assessment.AssessmentFinding{findingA})

	// Setup Tenant Beta
	clientB := &assessment.Client{
		ID:        "client-beta",
		Name:      "Beta Industries",
		CreatedAt: time.Now().UTC(),
		UpdatedAt: time.Now().UTC(),
	}
	_ = store.CreateClient(clientB)

	asmB := &assessment.Assessment{
		ID:             "asm-beta-1",
		Ref:            "ASM-BETA-01",
		ClientID:       clientB.ID,
		Name:           "Beta API Audit",
		AssessmentType: "API_AUDIT",
		Status:         assessment.StatusDraft,
		CreatedAt:      time.Now().UTC(),
		UpdatedAt:      time.Now().UTC(),
	}
	_ = store.CreateAssessment(asmB)

	findingB := assessment.AssessmentFinding{
		ID:                 "fnd-beta-1",
		AssessmentID:       asmB.ID,
		OriginalFindingID:  "fnd-beta-1",
		Title:              "Beta Sensitive Finding",
		Severity:           report.SeverityCritical,
		VerificationStatus: report.VerificationVerified,
		CreatedAt:          time.Now().UTC(),
	}
	_ = store.SaveFindings([]assessment.AssessmentFinding{findingB})

	execB := &assessment.AssessmentExecution{
		ID:           "exec-beta-1",
		AssessmentID: asmB.ID,
		Status:       assessment.StatusCompleted,
		StartedAt:    time.Now().UTC(),
	}
	_ = store.CreateExecution(execB)

	// Create a dummy report file and ReportRecord for Tenant Beta
	tempDir := t.TempDir()
	srv.AddAllowedReportsRoot(tempDir)
	reportBFile := filepath.Join(tempDir, "beta_report.html")
	_ = os.WriteFile(reportBFile, []byte("<html><body>Beta Confidential Report</body></html>"), 0600)

	reportB := &assessment.ReportRecord{
		ID:           "rep-beta-confidential",
		AssessmentID: asmB.ID,
		ExecutionID:  execB.ID,
		Format:       "HTML",
		FilePath:     reportBFile,
		CreatedAt:    time.Now().UTC(),
	}
	if err := store.SaveReport(reportB); err != nil {
		t.Fatalf("failed to save reportB: %v", err)
	}

	// Register Operator A (scoped to Client Alpha)
	tokenOpA := "token-operator-alpha"
	_ = srv.RegisterSession(&UserSession{
		Token:      tokenOpA,
		OperatorID: "operator-alpha",
		Role:       RoleOperator,
		ClientID:   clientA.ID,
	})

	// Register Operator B (scoped to Client Beta)
	tokenOpB := "token-operator-beta"
	_ = srv.RegisterSession(&UserSession{
		Token:      tokenOpB,
		OperatorID: "operator-beta",
		Role:       RoleOperator,
		ClientID:   clientB.ID,
	})

	// 1. Client List Filtering: Operator A must NOT see Client B
	rec := doRequest(handler, "GET", "/api/v1/clients", nil, tokenOpA, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	var clientsResp map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &clientsResp)
	clientsList := clientsResp["clients"].([]any)
	if len(clientsList) != 1 {
		t.Fatalf("expected Operator A to only see 1 client, got %d", len(clientsList))
	}
	c0 := clientsList[0].(map[string]any)
	if c0["id"] != clientA.ID {
		t.Errorf("expected client A id %q, got %v", clientA.ID, c0["id"])
	}

	// 2. Direct Object Reference (BOLA/IDOR): Operator A cannot fetch Client B directly
	rec = doRequest(handler, "GET", "/api/v1/clients/"+clientB.ID, nil, tokenOpA, "")
	if rec.Code != http.StatusNotFound {
		t.Errorf("expected 404 Not Found when accessing another client's details, got %d", rec.Code)
	}

	// 3. Assessment List Filtering: Operator A must NOT see Tenant B's assessments
	rec = doRequest(handler, "GET", "/api/v1/assessments", nil, tokenOpA, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	var asmsResp map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &asmsResp)
	asmsList := asmsResp["assessments"].([]any)
	if len(asmsList) != 1 {
		t.Fatalf("expected Operator A to only see 1 assessment, got %d", len(asmsList))
	}
	a0 := asmsList[0].(map[string]any)
	if a0["id"] != asmA.ID {
		t.Errorf("expected assessment A id %q, got %v", asmA.ID, a0["id"])
	}

	// 4. Operator A cannot query assessments explicitly for Client B
	rec = doRequest(handler, "GET", "/api/v1/assessments?client_id="+clientB.ID, nil, tokenOpA, "")
	if rec.Code != http.StatusForbidden {
		t.Errorf("expected 403 Forbidden when Operator A requests Client B assessments, got %d", rec.Code)
	}

	// 5. Direct Assessment IDOR: Operator A cannot view Tenant B's assessment
	rec = doRequest(handler, "GET", "/api/v1/assessments/"+asmB.ID, nil, tokenOpA, "")
	if rec.Code != http.StatusNotFound {
		t.Errorf("expected 404 Not Found for cross-tenant assessment access, got %d", rec.Code)
	}

	// 6. Cross-Tenant Creation: Operator A cannot create assessment under Client B
	crossAsmReq := map[string]string{
		"client_id": clientB.ID,
		"name":      "Maliciously Injected Assessment",
	}
	rec = doRequest(handler, "POST", "/api/v1/assessments", crossAsmReq, tokenOpA, "http://127.0.0.1:8383")
	if rec.Code != http.StatusForbidden {
		t.Errorf("expected 403 Forbidden when creating assessment under different client, got %d", rec.Code)
	}

	// 7. Target Mutation IDOR: Operator A cannot add targets to Tenant B's assessment
	targetReq := map[string]string{"target_url": "https://attacker-target.com"}
	rec = doRequest(handler, "POST", "/api/v1/assessments/"+asmB.ID+"/targets", targetReq, tokenOpA, "http://127.0.0.1:8383")
	if rec.Code != http.StatusNotFound {
		t.Errorf("expected 404 Not Found for cross-tenant target add, got %d", rec.Code)
	}

	// 8. Finding IDOR: Operator A cannot view or review Tenant B's findings
	rec = doRequest(handler, "GET", "/api/v1/assessments/"+asmB.ID+"/findings", nil, tokenOpA, "")
	if rec.Code != http.StatusNotFound {
		t.Errorf("expected 404 Not Found for cross-tenant findings list, got %d", rec.Code)
	}

	reviewReq := map[string]string{"status": "APPROVED_FOR_REPORT"}
	rec = doRequest(handler, "POST", "/api/v1/assessments/"+asmB.ID+"/findings/"+findingB.ID+"/review", reviewReq, tokenOpA, "http://127.0.0.1:8383")
	if rec.Code != http.StatusNotFound {
		t.Errorf("expected 404 Not Found for cross-tenant finding review, got %d", rec.Code)
	}

	// 9. Report Download IDOR:
	// a) Operator A cannot download Tenant B's report via Tenant B's assessment URL
	rec = doRequest(handler, "GET", fmt.Sprintf("/api/v1/assessments/%s/reports/%s/html", asmB.ID, reportB.ID), nil, tokenOpA, "")
	if rec.Code != http.StatusNotFound {
		t.Errorf("expected 404 Not Found when downloading other tenant's report, got %d", rec.Code)
	}

	// b) Operator A cannot spoof assessment ID (using Assessment A's URL with Report B's ID)
	rec = doRequest(handler, "GET", fmt.Sprintf("/api/v1/assessments/%s/reports/%s/html", asmA.ID, reportB.ID), nil, tokenOpA, "")
	if rec.Code != http.StatusNotFound {
		t.Errorf("expected 404 Not Found when attempting report IDOR mismatch, got %d", rec.Code)
	}

	// c) Security Invariant: Passing long-lived session token in query string to download route is strictly REJECTED
	querySessionURL := fmt.Sprintf("/api/v1/assessments/%s/reports/%s/html?token=%s", asmB.ID, reportB.ID, tokenOpB)
	rec = doRequest(handler, "GET", querySessionURL, nil, "", "")
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 Unauthorized when attempting download with long-lived session token in query, got %d", rec.Code)
	}

	// d) Issuing scoped short-lived download token via POST /token succeeds
	rec = doRequest(handler, "POST", fmt.Sprintf("/api/v1/assessments/%s/reports/%s/token", asmB.ID, reportB.ID), nil, tokenOpB, "http://127.0.0.1:8383")
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK for issuing download token, got %d (body: %s)", rec.Code, rec.Body.String())
	}
	var tokenRes map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &tokenRes)
	downloadToken := tokenRes["download_token"].(string)

	// e) Downloading report using scoped download token succeeds
	scopedDownloadURL := fmt.Sprintf("/api/v1/assessments/%s/reports/%s/html?download_token=%s", asmB.ID, reportB.ID, downloadToken)
	rec = doRequest(handler, "GET", scopedDownloadURL, nil, "", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK for authorized report download with scoped download token, got %d (body: %s)", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "Beta Confidential Report") {
		t.Errorf("expected report body to contain 'Beta Confidential Report'")
	}

	// 10. Audit Trail Isolation: Operator A cannot read Tenant B's assessment audit events
	rec = doRequest(handler, "GET", "/api/v1/assessments/"+asmB.ID+"/audit", nil, tokenOpA, "")
	if rec.Code != http.StatusNotFound {
		t.Errorf("expected 404 Not Found for cross-tenant audit events, got %d", rec.Code)
	}

	// 11. Operator A cannot read global audit trail
	rec = doRequest(handler, "GET", "/api/v1/audit", nil, tokenOpA, "")
	if rec.Code != http.StatusForbidden {
		t.Errorf("expected 403 Forbidden for non-admin reading global audit trail, got %d", rec.Code)
	}
}

// TestSecurity_ReportPathRedaction verifies internal server filesystem paths are never leaked.
func TestSecurity_ReportPathRedaction(t *testing.T) {
	srv, store, cleanup := setupTestServer(t)
	defer cleanup()
	handler := srv.buildMiddlewareChain(srv.mux)

	client := &assessment.Client{
		ID:        "client-redact-test",
		Name:      "Path Redaction Test",
		CreatedAt: time.Now().UTC(),
		UpdatedAt: time.Now().UTC(),
	}
	_ = store.CreateClient(client)

	asm := &assessment.Assessment{
		ID:             "asm-redact-01",
		Ref:            "ASM-RED-001",
		ClientID:       client.ID,
		Name:           "Redaction Audit",
		AssessmentType: "BLACK_BOX_WEB",
		Status:         assessment.StatusDraft,
		CreatedAt:      time.Now().UTC(),
		UpdatedAt:      time.Now().UTC(),
	}
	_ = store.CreateAssessment(asm)

	// Generate draft report
	genReq := map[string]any{"allow_draft": true}
	rec := doRequest(handler, "POST", "/api/v1/assessments/"+asm.ID+"/reports/generate", genReq, srv.Token(), "http://127.0.0.1:8383")
	if rec.Code != http.StatusCreated {
		t.Fatalf("expected 201 Created, got %d %s", rec.Code, rec.Body.String())
	}

	var res map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &res)

	// Verify html_path and json_path are NOT present in the response
	if path, exists := res["html_path"]; exists && path != nil && path != "" {
		t.Errorf("security violation: raw internal html_path leaked in response: %v", path)
	}
	if path, exists := res["json_path"]; exists && path != nil && path != "" {
		t.Errorf("security violation: raw internal json_path leaked in response: %v", path)
	}

	// Verify safe download URLs ARE present
	htmlURL, ok := res["html_url"].(string)
	if !ok || !strings.HasPrefix(htmlURL, "/api/v1/assessments/") || !strings.HasSuffix(htmlURL, "/html") {
		t.Errorf("expected relative safe html_url, got: %v", res["html_url"])
	}
	jsonURL, ok := res["json_url"].(string)
	if !ok || !strings.HasPrefix(jsonURL, "/api/v1/assessments/") || !strings.HasSuffix(jsonURL, "/json") {
		t.Errorf("expected relative safe json_url, got: %v", res["json_url"])
	}
}

// TestSecurity_SecurityHeadersAndCORS checks defense-in-depth HTTP headers and origin checks.
func TestSecurity_SecurityHeadersAndCORS(t *testing.T) {
	srv, _, cleanup := setupTestServer(t)
	defer cleanup()
	handler := srv.buildMiddlewareChain(srv.mux)

	// Verify security headers on API responses
	rec := doRequest(handler, "GET", "/api/v1/health", nil, "", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("health check failed: %d", rec.Code)
	}

	expectedHeaders := map[string]string{
		"X-Content-Type-Options": "nosniff",
		"X-Frame-Options":        "DENY",
		"Referrer-Policy":        "same-origin",
		"Cache-Control":          "no-store, no-cache, must-revalidate",
	}

	for header, expectedVal := range expectedHeaders {
		actualVal := rec.Header().Get(header)
		if actualVal != expectedVal {
			t.Errorf("header %s: expected %q, got %q", header, expectedVal, actualVal)
		}
	}

	// Check CORS Preflight: untrusted origin -> 403 Forbidden
	req := httptest.NewRequest(http.MethodOptions, "/api/v1/clients", nil)
	req.Header.Set("Origin", "http://evil-attacker.com")
	preflightRec := httptest.NewRecorder()
	handler.ServeHTTP(preflightRec, req)
	if preflightRec.Code != http.StatusForbidden {
		t.Errorf("expected 403 Forbidden for untrusted CORS preflight origin, got %d", preflightRec.Code)
	}

	// Check CORS Preflight: loopback origin -> 204 No Content
	req = httptest.NewRequest(http.MethodOptions, "/api/v1/clients", nil)
	req.Header.Set("Origin", "http://127.0.0.1:8383")
	preflightRec = httptest.NewRecorder()
	handler.ServeHTTP(preflightRec, req)
	if preflightRec.Code != http.StatusNoContent {
		t.Errorf("expected 204 No Content for loopback CORS preflight, got %d", preflightRec.Code)
	}
}

// TestSecurity_DownloadTokenScopingAndLifecycle tests narrowly scoped download token issuance and validation.
func TestSecurity_DownloadTokenScopingAndLifecycle(t *testing.T) {
	srv, store, cleanup := setupTestServer(t)
	defer cleanup()
	handler := srv.buildMiddlewareChain(srv.mux)

	reportsDir := t.TempDir()
	srv.AddAllowedReportsRoot(reportsDir)

	clientA := &assessment.Client{
		ID:        "client-dt-a",
		Name:      "Client DT A",
		CreatedAt: time.Now().UTC(),
		UpdatedAt: time.Now().UTC(),
	}
	_ = store.CreateClient(clientA)

	asmA := &assessment.Assessment{
		ID:        "asm-dt-a",
		ClientID:  clientA.ID,
		Name:      "Assessment DT A",
		CreatedAt: time.Now().UTC(),
		UpdatedAt: time.Now().UTC(),
	}
	_ = store.CreateAssessment(asmA)

	execA := &assessment.AssessmentExecution{
		ID:           "exec-dt-a",
		AssessmentID: asmA.ID,
		Status:       assessment.StatusCompleted,
		StartedAt:    time.Now().UTC(),
	}
	_ = store.CreateExecution(execA)

	reportAFile := filepath.Join(reportsDir, "report_a.html")
	_ = os.WriteFile(reportAFile, []byte("<html><body>Report A Content</body></html>"), 0600)

	reportA := &assessment.ReportRecord{
		ID:           "rep-dt-a",
		AssessmentID: asmA.ID,
		ExecutionID:  execA.ID,
		Format:       "HTML",
		FilePath:     reportAFile,
		CreatedAt:    time.Now().UTC(),
	}
	_ = store.SaveReport(reportA)

	// Operator A
	tokenOpA := "token-op-dt-a"
	_ = srv.RegisterSession(&UserSession{
		Token:      tokenOpA,
		OperatorID: "op-a",
		Role:       RoleOperator,
		ClientID:   clientA.ID,
	})

	// 1. Issue scoped download token via POST /token
	rec := doRequest(handler, "POST", fmt.Sprintf("/api/v1/assessments/%s/reports/%s/token?format=HTML", asmA.ID, reportA.ID), nil, tokenOpA, "http://127.0.0.1:8383")
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK for token generation, got %d %s", rec.Code, rec.Body.String())
	}
	var tokenRes map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &tokenRes)
	dt := tokenRes["download_token"].(string)

	// 2. Download succeeds using valid download token
	downloadURL := fmt.Sprintf("/api/v1/assessments/%s/reports/%s/html?download_token=%s", asmA.ID, reportA.ID, dt)
	rec = doRequest(handler, "GET", downloadURL, nil, "", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK for download with valid scoped token, got %d", rec.Code)
	}
	// Check security headers on download response
	if rec.Header().Get("Cache-Control") != "no-store, no-cache, must-revalidate, private" {
		t.Errorf("expected strict Cache-Control on report download, got %q", rec.Header().Get("Cache-Control"))
	}
	if rec.Header().Get("Referrer-Policy") != "no-referrer" {
		t.Errorf("expected no-referrer on report download, got %q", rec.Header().Get("Referrer-Policy"))
	}

	// 3. Expired download token -> 401
	expiredDT, _ := srv.IssueDownloadToken(asmA.ID, reportA.ID, "HTML", clientA.ID, -1*time.Minute)
	rec = doRequest(handler, "GET", fmt.Sprintf("/api/v1/assessments/%s/reports/%s/html?download_token=%s", asmA.ID, reportA.ID, expiredDT.Token), nil, "", "")
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 for expired download token, got %d", rec.Code)
	}

	// 4. Revoked download token -> 401
	revokedDT, _ := srv.IssueDownloadToken(asmA.ID, reportA.ID, "HTML", clientA.ID, 5*time.Minute)
	srv.RevokeDownloadToken(revokedDT.Token)
	rec = doRequest(handler, "GET", fmt.Sprintf("/api/v1/assessments/%s/reports/%s/html?download_token=%s", asmA.ID, reportA.ID, revokedDT.Token), nil, "", "")
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 for revoked download token, got %d", rec.Code)
	}

	// 5. Cross-tenant download token rejection:
	clientB := &assessment.Client{ID: "client-dt-b", Name: "Client B", CreatedAt: time.Now().UTC(), UpdatedAt: time.Now().UTC()}
	_ = store.CreateClient(clientB)
	asmB := &assessment.Assessment{ID: "asm-dt-b", ClientID: clientB.ID, Name: "Asm B", CreatedAt: time.Now().UTC(), UpdatedAt: time.Now().UTC()}
	_ = store.CreateAssessment(asmB)
	execB := &assessment.AssessmentExecution{ID: "exec-dt-b", AssessmentID: asmB.ID, Status: assessment.StatusCompleted, StartedAt: time.Now().UTC()}
	_ = store.CreateExecution(execB)
	reportBFile := filepath.Join(reportsDir, "report_b.html")
	_ = os.WriteFile(reportBFile, []byte("<html><body>Report B Content</body></html>"), 0600)
	reportB := &assessment.ReportRecord{ID: "rep-dt-b", AssessmentID: asmB.ID, ExecutionID: execB.ID, Format: "HTML", FilePath: reportBFile, CreatedAt: time.Now().UTC()}
	_ = store.SaveReport(reportB)

	// Attempting to use dt (issued for Tenant A) to download Tenant B's report -> 403 Forbidden / 404 Not Found
	rec = doRequest(handler, "GET", fmt.Sprintf("/api/v1/assessments/%s/reports/%s/html?download_token=%s", asmB.ID, reportB.ID, dt), nil, "", "")
	if rec.Code != http.StatusForbidden && rec.Code != http.StatusNotFound {
		t.Errorf("expected 403/404 for cross-tenant download token usage, got %d", rec.Code)
	}

	// 6. Incorrectly scoped format: token issued for "HTML" used on "/json" route -> 403 Forbidden
	rec = doRequest(handler, "GET", fmt.Sprintf("/api/v1/assessments/%s/reports/%s/json?download_token=%s", asmA.ID, reportA.ID, dt), nil, "", "")
	if rec.Code != http.StatusForbidden {
		t.Errorf("expected 403 Forbidden when HTML download token is used on JSON route, got %d", rec.Code)
	}

	// 7. Download token attempted on general API route -> 403 Forbidden
	rec = doRequest(handler, "GET", "/api/v1/clients?download_token="+dt, nil, "", "")
	if rec.Code != http.StatusForbidden {
		t.Errorf("expected 403 Forbidden when download token is used for general API route, got %d", rec.Code)
	}

	// 8. Passing long-lived session token in query string to download route -> 401 Unauthorized
	rec = doRequest(handler, "GET", fmt.Sprintf("/api/v1/assessments/%s/reports/%s/html?token=%s", asmA.ID, reportA.ID, tokenOpA), nil, "", "")
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 Unauthorized when attempting download with long-lived session token in query, got %d", rec.Code)
	}
}

// TestSecurity_ReportFilesystemContainment tests that reports are strictly contained within allowed storage roots.
func TestSecurity_ReportFilesystemContainment(t *testing.T) {
	srv, store, cleanup := setupTestServer(t)
	defer cleanup()
	handler := srv.buildMiddlewareChain(srv.mux)

	// Isolated storage root for authorized reports
	reportsRoot := t.TempDir()
	srv.AddAllowedReportsRoot(reportsRoot)

	// Outside storage directory (unauthorized)
	outsideDir := t.TempDir()
	outsideFile := filepath.Join(outsideDir, "secret_data.txt")
	_ = os.WriteFile(outsideFile, []byte("CONFIDENTIAL_SYSTEM_DATA"), 0600)

	client := &assessment.Client{
		ID:        "client-containment",
		Name:      "Containment Test Client",
		CreatedAt: time.Now().UTC(),
		UpdatedAt: time.Now().UTC(),
	}
	_ = store.CreateClient(client)

	asm := &assessment.Assessment{
		ID:        "asm-containment",
		ClientID:  client.ID,
		Name:      "Containment Assessment",
		CreatedAt: time.Now().UTC(),
		UpdatedAt: time.Now().UTC(),
	}
	_ = store.CreateAssessment(asm)

	exec := &assessment.AssessmentExecution{
		ID:           "exec-containment",
		AssessmentID: asm.ID,
		Status:       assessment.StatusCompleted,
		StartedAt:    time.Now().UTC(),
	}
	_ = store.CreateExecution(exec)

	// 1. Legitimate file inside reportsRoot succeeds
	legitFile := filepath.Join(reportsRoot, "legit_report.html")
	_ = os.WriteFile(legitFile, []byte("<html><body>Legitimate Report</body></html>"), 0600)

	legitReport := &assessment.ReportRecord{
		ID:           "rep-legit",
		AssessmentID: asm.ID,
		ExecutionID:  exec.ID,
		Format:       "HTML",
		FilePath:     legitFile,
		CreatedAt:    time.Now().UTC(),
	}
	_ = store.SaveReport(legitReport)

	rec := doRequest(handler, "GET", fmt.Sprintf("/api/v1/assessments/%s/reports/%s/html", asm.ID, legitReport.ID), nil, srv.Token(), "")
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK for legitimate report download, got %d %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "Legitimate Report") {
		t.Errorf("expected report content, got %s", rec.Body.String())
	}

	// 2. Traversal attempt: FilePath with ".." navigating outside root
	traversalReport := &assessment.ReportRecord{
		ID:           "rep-traversal",
		AssessmentID: asm.ID,
		ExecutionID:  exec.ID,
		Format:       "HTML",
		FilePath:     filepath.Join(reportsRoot, "../outside_file.html"),
		CreatedAt:    time.Now().UTC(),
	}
	_ = store.SaveReport(traversalReport)

	rec = doRequest(handler, "GET", fmt.Sprintf("/api/v1/assessments/%s/reports/%s/html", asm.ID, traversalReport.ID), nil, srv.Token(), "")
	if rec.Code != http.StatusForbidden {
		t.Errorf("expected 403 Forbidden for traversal report path, got %d", rec.Code)
	}

	// 3. Absolute path to an external unauthorized directory
	outOfRootReport := &assessment.ReportRecord{
		ID:           "rep-outside",
		AssessmentID: asm.ID,
		ExecutionID:  exec.ID,
		Format:       "HTML",
		FilePath:     outsideFile,
		CreatedAt:    time.Now().UTC(),
	}
	_ = store.SaveReport(outOfRootReport)

	rec = doRequest(handler, "GET", fmt.Sprintf("/api/v1/assessments/%s/reports/%s/html", asm.ID, outOfRootReport.ID), nil, srv.Token(), "")
	if rec.Code != http.StatusForbidden {
		t.Errorf("expected 403 Forbidden for out-of-root report path, got %d", rec.Code)
	}

	// 4. Symlink escape: symlink inside reportsRoot pointing to outsideFile
	symlinkPath := filepath.Join(reportsRoot, "symlink_escape.html")
	if err := os.Symlink(outsideFile, symlinkPath); err == nil {
		symlinkReport := &assessment.ReportRecord{
			ID:           "rep-symlink",
			AssessmentID: asm.ID,
			ExecutionID:  exec.ID,
			Format:       "HTML",
			FilePath:     symlinkPath,
			CreatedAt:    time.Now().UTC(),
		}
		_ = store.SaveReport(symlinkReport)

		rec = doRequest(handler, "GET", fmt.Sprintf("/api/v1/assessments/%s/reports/%s/html", asm.ID, symlinkReport.ID), nil, srv.Token(), "")
		if rec.Code != http.StatusForbidden {
			t.Errorf("expected 403 Forbidden for symlink escape report path, got %d", rec.Code)
		}
	}
}

// TestSecurity_CompleteRouteAndRoleCoverage systematically audits all routes in routes.go
// across unauthenticated, admin, operator (own & foreign tenant), and viewer roles.
func TestSecurity_CompleteRouteAndRoleCoverage(t *testing.T) {
	srv, store, cleanup := setupTestServer(t)
	defer cleanup()
	handler := srv.buildMiddlewareChain(srv.mux)

	reportsDir := t.TempDir()
	srv.AddAllowedReportsRoot(reportsDir)

	// Setup Tenant 1 (Client Alpha)
	client1 := &assessment.Client{ID: "client-cov-1", Name: "Alpha Corp", CreatedAt: time.Now().UTC(), UpdatedAt: time.Now().UTC()}
	_ = store.CreateClient(client1)
	asm1 := &assessment.Assessment{ID: "asm-cov-1", ClientID: client1.ID, Name: "Alpha Audit", Status: assessment.StatusDraft, CreatedAt: time.Now().UTC(), UpdatedAt: time.Now().UTC()}
	_ = store.CreateAssessment(asm1)
	target1 := &assessment.AssessmentTarget{ID: "tgt-cov-1", AssessmentID: asm1.ID, TargetURL: "https://alpha.example.com", TargetType: assessment.TargetWebsite, ScopeStatus: "APPROVED", CreatedAt: time.Now().UTC()}
	_ = store.AddTarget(target1)
	exec1 := &assessment.AssessmentExecution{ID: "exec-cov-1", AssessmentID: asm1.ID, Status: assessment.StatusCompleted, StartedAt: time.Now().UTC()}
	_ = store.CreateExecution(exec1)
	fnd1 := assessment.AssessmentFinding{ID: "fnd-cov-1", AssessmentID: asm1.ID, OriginalFindingID: "fnd-cov-1", Title: "XSS", Severity: report.SeverityHigh, VerificationStatus: report.VerificationVerified, CreatedAt: time.Now().UTC()}
	_ = store.SaveFindings([]assessment.AssessmentFinding{fnd1})
	rep1File := filepath.Join(reportsDir, "cov_rep1.html")
	_ = os.WriteFile(rep1File, []byte("<html>report 1</html>"), 0600)
	rep1 := &assessment.ReportRecord{ID: "rep-cov-1", AssessmentID: asm1.ID, ExecutionID: exec1.ID, Format: "HTML", FilePath: rep1File, CreatedAt: time.Now().UTC()}
	_ = store.SaveReport(rep1)

	// Setup Tenant 2 (Client Beta)
	client2 := &assessment.Client{ID: "client-cov-2", Name: "Beta Corp", CreatedAt: time.Now().UTC(), UpdatedAt: time.Now().UTC()}
	_ = store.CreateClient(client2)
	asm2 := &assessment.Assessment{ID: "asm-cov-2", ClientID: client2.ID, Name: "Beta Audit", Status: assessment.StatusDraft, CreatedAt: time.Now().UTC(), UpdatedAt: time.Now().UTC()}
	_ = store.CreateAssessment(asm2)

	// Sessions
	tokenAdmin := srv.Token() // default admin
	tokenOp1 := "tok-op-1"
	_ = srv.RegisterSession(&UserSession{Token: tokenOp1, OperatorID: "op1", Role: RoleOperator, ClientID: client1.ID})
	tokenView1 := "tok-view-1"
	_ = srv.RegisterSession(&UserSession{Token: tokenView1, OperatorID: "view1", Role: RoleViewer, ClientID: client1.ID})
	tokenOp2 := "tok-op-2"
	_ = srv.RegisterSession(&UserSession{Token: tokenOp2, OperatorID: "op2", Role: RoleOperator, ClientID: client2.ID})

	// 1. Unauthenticated requests to protected endpoints return 401
	protectedPaths := []string{
		"/api/v1/clients",
		"/api/v1/assessments",
		"/api/v1/audit",
		"/api/v1/assessments/" + asm1.ID,
		"/api/v1/assessments/" + asm1.ID + "/findings",
		"/api/v1/assessments/" + asm1.ID + "/reports",
		"/api/v1/assessments/" + asm1.ID + "/deliveries",
		"/api/v1/assessments/" + asm1.ID + "/audit",
	}
	for _, p := range protectedPaths {
		rec := doRequest(handler, "GET", p, nil, "", "")
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("[Unauth] expected 401 for GET %s, got %d", p, rec.Code)
		}
	}

	// 2. Global Audit Route: Admin -> 200, Operator -> 403, Viewer -> 403
	rec := doRequest(handler, "GET", "/api/v1/audit", nil, tokenAdmin, "")
	if rec.Code != http.StatusOK {
		t.Errorf("[Global Audit Admin] expected 200, got %d", rec.Code)
	}
	rec = doRequest(handler, "GET", "/api/v1/audit", nil, tokenOp1, "")
	if rec.Code != http.StatusForbidden {
		t.Errorf("[Global Audit Operator] expected 403, got %d", rec.Code)
	}
	rec = doRequest(handler, "GET", "/api/v1/audit", nil, tokenView1, "")
	if rec.Code != http.StatusForbidden {
		t.Errorf("[Global Audit Viewer] expected 403, got %d", rec.Code)
	}

	// 3. Client Creation & Archival: Admin -> permitted, Operator/Viewer -> 403
	rec = doRequest(handler, "POST", "/api/v1/clients", map[string]string{"name": "New Org"}, tokenOp1, "http://127.0.0.1:8383")
	if rec.Code != http.StatusForbidden {
		t.Errorf("[Create Client Operator] expected 403, got %d", rec.Code)
	}
	rec = doRequest(handler, "POST", "/api/v1/clients", map[string]string{"name": "New Org"}, tokenView1, "http://127.0.0.1:8383")
	if rec.Code != http.StatusForbidden {
		t.Errorf("[Create Client Viewer] expected 403, got %d", rec.Code)
	}
	rec = doRequest(handler, "POST", "/api/v1/clients/"+client1.ID+"/archive", nil, tokenOp1, "http://127.0.0.1:8383")
	if rec.Code != http.StatusForbidden {
		t.Errorf("[Archive Client Operator] expected 403, got %d", rec.Code)
	}
	rec = doRequest(handler, "POST", "/api/v1/clients/"+client1.ID+"/archive", nil, tokenView1, "http://127.0.0.1:8383")
	if rec.Code != http.StatusForbidden {
		t.Errorf("[Archive Client Viewer] expected 403, got %d", rec.Code)
	}

	// 4. Cross-tenant reads and mutations (Operator 2 against Tenant 1 resources):
	// All must return 404 Not Found (or 403 for cross-client creation)
	crossTenantTests := []struct {
		method string
		path   string
		body   any
	}{
		{"GET", "/api/v1/clients/" + client1.ID, nil},
		{"GET", "/api/v1/assessments/" + asm1.ID, nil},
		{"POST", "/api/v1/assessments/" + asm1.ID + "/targets", map[string]string{"target_url": "https://hack.com"}},
		{"POST", "/api/v1/assessments/" + asm1.ID + "/authorize", map[string]string{"authorizing_party": "Eve"}},
		{"POST", "/api/v1/assessments/" + asm1.ID + "/scan", nil},
		{"GET", "/api/v1/assessments/" + asm1.ID + "/scan/status", nil},
		{"POST", "/api/v1/assessments/" + asm1.ID + "/scan/cancel", nil},
		{"GET", "/api/v1/assessments/" + asm1.ID + "/findings", nil},
		{"GET", "/api/v1/assessments/" + asm1.ID + "/findings/" + fnd1.ID, nil},
		{"POST", "/api/v1/assessments/" + asm1.ID + "/findings/" + fnd1.ID + "/review", map[string]string{"status": "APPROVED_FOR_REPORT"}},
		{"POST", "/api/v1/assessments/" + asm1.ID + "/reports/generate", map[string]any{"allow_draft": true}},
		{"GET", "/api/v1/assessments/" + asm1.ID + "/reports", nil},
		{"GET", "/api/v1/assessments/" + asm1.ID + "/reports/" + rep1.ID, nil},
		{"GET", "/api/v1/assessments/" + asm1.ID + "/reports/" + rep1.ID + "/html", nil},
		{"GET", "/api/v1/assessments/" + asm1.ID + "/reports/" + rep1.ID + "/json", nil},
		{"POST", "/api/v1/assessments/" + asm1.ID + "/reports/" + rep1.ID + "/token", nil},
		{"POST", "/api/v1/assessments/" + asm1.ID + "/reports/" + rep1.ID + "/deliver", map[string]any{"recipient_name": "Eve"}},
		{"GET", "/api/v1/assessments/" + asm1.ID + "/deliveries", nil},
		{"GET", "/api/v1/assessments/" + asm1.ID + "/audit", nil},
	}
	for _, tc := range crossTenantTests {
		rec := doRequest(handler, tc.method, tc.path, tc.body, tokenOp2, "http://127.0.0.1:8383")
		if rec.Code != http.StatusNotFound && rec.Code != http.StatusForbidden {
			t.Errorf("[Cross-Tenant %s %s] expected 404/403, got %d", tc.method, tc.path, rec.Code)
		}
	}
}

// TestSecurity_InvalidOrUnknownRoleDenied verifies default-deny access for unknown or invalid roles.
func TestSecurity_InvalidOrUnknownRoleDenied(t *testing.T) {
	srv, _, cleanup := setupTestServer(t)
	defer cleanup()
	handler := srv.buildMiddlewareChain(srv.mux)

	invalidRoles := []string{"guest", "attacker", "unknown", "", "   ", "audit", "superadmin"}
	for _, role := range invalidRoles {
		token := "tok-invalid-" + strings.ReplaceAll(role, " ", "_")
		sess := &UserSession{
			Token:      token,
			OperatorID: "op-test",
			Role:       role,
			ClientID:   "client-1",
		}
		_ = srv.RegisterSession(sess)

		// 1. AuthContext must fail closed (zero authorized scope)
		authCtx := sess.AuthContext()
		if authCtx.IsAdmin() {
			t.Errorf("role %q auth context unexpectedly reports IsAdmin() = true", role)
		}
		if authCtx.Authorizes("client-1", "", "") {
			t.Errorf("role %q auth context unexpectedly authorized client-1", role)
		}

		// 2. Request through API must be rejected with 403 Forbidden
		rec := doRequest(handler, "GET", "/api/v1/assessments", nil, token, "")
		if rec.Code != http.StatusForbidden {
			t.Errorf("role %q got status %d, expected 403 Forbidden", role, rec.Code)
		}
	}

	// Recognized valid roles must pass role validation
	validRoles := []string{RoleAdmin, RoleOperator, RoleViewer, "ADMIN", "Operator", "VIEWER"}
	for _, role := range validRoles {
		if !IsValidRole(role) {
			t.Errorf("expected role %q to be recognized as valid", role)
		}
	}
}

// TestSecurity_IssueDownloadTokenRoleEnforcement verifies download token generation requires valid roles.
func TestSecurity_IssueDownloadTokenRoleEnforcement(t *testing.T) {
	srv, store, cleanup := setupTestServer(t)
	defer cleanup()
	handler := srv.buildMiddlewareChain(srv.mux)

	client := &assessment.Client{ID: "client-dlt-1", Name: "DLT Test Client", CreatedAt: time.Now().UTC(), UpdatedAt: time.Now().UTC()}
	_ = store.CreateClient(client)

	asm := &assessment.Assessment{ID: "asm-dlt-1", ClientID: client.ID, Name: "DLT Asm", Status: assessment.StatusCompleted, CreatedAt: time.Now().UTC(), UpdatedAt: time.Now().UTC()}
	_ = store.CreateAssessment(asm)

	exec := &assessment.AssessmentExecution{
		ID:           "exec-dlt-1",
		AssessmentID: asm.ID,
		Status:       assessment.StatusCompleted,
		StartedAt:    time.Now().UTC(),
	}
	_ = store.CreateExecution(exec)

	reportsRoot := t.TempDir()
	srv.AddAllowedReportsRoot(reportsRoot)
	repFile := filepath.Join(reportsRoot, "rep-dlt-1.html")
	_ = os.WriteFile(repFile, []byte("<html>report</html>"), 0600)
	rep := &assessment.ReportRecord{
		ID:           "rep-dlt-1",
		AssessmentID: asm.ID,
		ExecutionID:  exec.ID,
		Format:       "HTML",
		FilePath:     repFile,
		CreatedAt:    time.Now().UTC(),
	}
	if err := store.SaveReport(rep); err != nil {
		t.Fatalf("failed to save report record: %v", err)
	}

	// Valid roles can issue download tokens
	for _, role := range []string{RoleAdmin, RoleOperator, RoleViewer} {
		token := "tok-valid-" + role
		_ = srv.RegisterSession(&UserSession{
			Token:      token,
			OperatorID: "op-" + role,
			Role:       role,
			ClientID:   client.ID,
		})

		rec := doRequest(handler, "POST", "/api/v1/assessments/"+asm.ID+"/reports/"+rep.ID+"/token", nil, token, "http://127.0.0.1:8383")
		if rec.Code != http.StatusOK {
			t.Errorf("role %s failed to issue download token, got status %d", role, rec.Code)
		}
	}

	// Invalid role receives 403 Forbidden
	invalidToken := "tok-invalid-role-dlt"
	_ = srv.RegisterSession(&UserSession{
		Token:      invalidToken,
		OperatorID: "op-invalid",
		Role:       "contractor",
		ClientID:   client.ID,
	})
	rec := doRequest(handler, "POST", "/api/v1/assessments/"+asm.ID+"/reports/"+rep.ID+"/token", nil, invalidToken, "http://127.0.0.1:8383")
	if rec.Code != http.StatusForbidden {
		t.Errorf("invalid role received status %d, expected 403 Forbidden", rec.Code)
	}
}

// TestSecurity_ReportDownloadPathErrorSanitization verifies that file read errors do not leak internal filesystem paths.
func TestSecurity_ReportDownloadPathErrorSanitization(t *testing.T) {
	srv, store, cleanup := setupTestServer(t)
	defer cleanup()
	handler := srv.buildMiddlewareChain(srv.mux)

	client := &assessment.Client{ID: "client-leak-test", Name: "Leak Test", CreatedAt: time.Now().UTC(), UpdatedAt: time.Now().UTC()}
	_ = store.CreateClient(client)

	asm := &assessment.Assessment{ID: "asm-leak-test", ClientID: client.ID, Name: "Leak Asm", Status: assessment.StatusCompleted, CreatedAt: time.Now().UTC(), UpdatedAt: time.Now().UTC()}
	_ = store.CreateAssessment(asm)

	exec := &assessment.AssessmentExecution{
		ID:           "exec-leak-test",
		AssessmentID: asm.ID,
		Status:       assessment.StatusCompleted,
		StartedAt:    time.Now().UTC(),
	}
	_ = store.CreateExecution(exec)

	reportsRoot := t.TempDir()
	srv.AddAllowedReportsRoot(reportsRoot)

	// File deliberately does not exist on disk, but is located inside authorized reports directory
	missingPath := filepath.Join(reportsRoot, "secret_internal_report.html")
	rep := &assessment.ReportRecord{
		ID:           "rep-missing-file",
		AssessmentID: asm.ID,
		ExecutionID:  exec.ID,
		Format:       "HTML",
		FilePath:     missingPath,
		CreatedAt:    time.Now().UTC(),
	}
	if err := store.SaveReport(rep); err != nil {
		t.Fatalf("failed to save missing path report record: %v", err)
	}

	rec := doRequest(handler, "GET", "/api/v1/assessments/"+asm.ID+"/reports/"+rep.ID+"/html", nil, srv.Token(), "")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404 for missing report file, got %d", rec.Code)
	}

	body := rec.Body.String()
	// Must not leak the missingPath or internal directory names
	if strings.Contains(body, "subdir_never_created") || strings.Contains(body, "secret_internal_report") || strings.Contains(body, "C:\\") || strings.Contains(body, "/Users/") {
		t.Fatalf("response leaked internal filesystem path in error message: %s", body)
	}

	var jsonErr map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &jsonErr); err != nil {
		t.Fatalf("response is not valid JSON: %s", body)
	}
	if jsonErr["error"] != "report file could not be read" {
		t.Errorf("error message = %q, want exactly 'report file could not be read'", jsonErr["error"])
	}
}

// TestSecurity_ReportFilePermissions verifies that exported reports have restricted 0600 permissions.
func TestSecurity_ReportFilePermissions(t *testing.T) {
	tempDir := t.TempDir()

	sampleFindings := []report.Finding{
		{
			ID:          "FND-001",
			Title:       "Sensitive finding",
			Severity:    "HIGH",
			Category:    "sqli",
			Target:      "https://target.local",
			Endpoint:    "/api/query",
			Description: "Confidential security vulnerability",
		},
	}
	rep := report.Report{
		Target:           "https://target.local",
		CompletionStatus: "COMPLETED",
		Findings:         sampleFindings,
		Summary:          report.Summarize(sampleFindings),
	}
	cr := report.BuildCommercialReport(rep)

	htmlPath := filepath.Join(tempDir, "report.html")
	jsonPath := filepath.Join(tempDir, "report.json")
	sarifPath := filepath.Join(tempDir, "report.sarif")
	commHTMLPath := filepath.Join(tempDir, "comm_report.html")
	commJSONPath := filepath.Join(tempDir, "comm_report.json")

	if err := report.WriteHTML(rep, htmlPath); err != nil {
		t.Fatalf("WriteHTML failed: %v", err)
	}
	if err := report.WriteJSON(rep, jsonPath); err != nil {
		t.Fatalf("WriteJSON failed: %v", err)
	}
	if err := report.WriteSARIF(rep, sarifPath); err != nil {
		t.Fatalf("WriteSARIF failed: %v", err)
	}
	if err := report.WriteCommercialHTML(cr, commHTMLPath); err != nil {
		t.Fatalf("WriteCommercialHTML failed: %v", err)
	}
	if err := report.WriteCommercialJSON(cr, commJSONPath); err != nil {
		t.Fatalf("WriteCommercialJSON failed: %v", err)
	}

	files := []string{htmlPath, jsonPath, sarifPath, commHTMLPath, commJSONPath}
	for _, f := range files {
		info, err := os.Stat(f)
		if err != nil {
			t.Fatalf("os.Stat(%s) failed: %v", f, err)
		}
		// On POSIX systems, verify strictly owner read/write (0600)
		if runtime.GOOS != "windows" {
			perm := info.Mode().Perm()
			if perm != 0600 {
				t.Errorf("file %s has permissions %04o, want 0600", f, perm)
			}
		} else {
			// On Windows, verify file was created successfully and is non-empty
			if info.Size() == 0 {
				t.Errorf("file %s is unexpectedly empty", f)
			}
		}
	}
}

// TestSecurity_ValidateReportPathContainmentRootEdgeCase verifies that targeting the reports directory root itself is rejected.
func TestSecurity_ValidateReportPathContainmentRootEdgeCase(t *testing.T) {
	srv, _, cleanup := setupTestServer(t)
	defer cleanup()

	// Containment must reject targeting the directory root itself
	_, err := srv.validateReportPathContainment(srv.cfg.ReportsRoot)
	if err == nil {
		t.Errorf("expected containment validation to reject report root directory itself, but it passed")
	}
}
