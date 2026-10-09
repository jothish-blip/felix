package assessment

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestController_AuthorizationRefusal(t *testing.T) {
	store, cleanup := newTestStore(t)
	defer cleanup()

	ctrl := NewController(store)
	ctx := context.Background()

	// 1. Setup client and assessment without authorization
	clientID := uuid.New().String()
	_ = store.CreateClient(&Client{ID: clientID, Name: "Acme"})
	asmID := uuid.New().String()
	asmRef := GenerateAssessmentRef()
	_ = store.CreateAssessment(&Assessment{
		ID:        asmID,
		Ref:       asmRef,
		ClientID:  clientID,
		Name:      "Unauthorized Assessment",
		Status:    StatusDraft,
		ScopeMode: "same-origin",
	})
	_ = store.AddTarget(&AssessmentTarget{
		ID:           uuid.New().String(),
		AssessmentID: asmID,
		TargetURL:    "https://example.com",
		ScopeStatus:  "APPROVED",
	})

	// Execute without authorization: must fail closed
	_, err := ctrl.RunAssessment(ctx, asmID, ExecutionOptions{})
	if err == nil || !strings.Contains(err.Error(), "security refusal: no authorization record found") {
		t.Fatalf("expected security refusal for missing auth, got: %v", err)
	}

	// 2. Setup expired authorization
	past := time.Now().UTC().Add(-48 * time.Hour)
	yesterday := time.Now().UTC().Add(-24 * time.Hour)
	_ = store.SetAuthorization(&AuthorizationRecord{
		ID:                  uuid.New().String(),
		AssessmentID:        asmID,
		AuthorizingParty:    "Security Team",
		AuthorizationMethod: "EMAIL",
		DateReceived:        past,
		ValidFrom:           &past,
		ValidUntil:          &yesterday,
		Status:              AuthApproved,
	})

	// Execute with expired authorization: must fail closed
	_, err = ctrl.RunAssessment(ctx, asmID, ExecutionOptions{})
	if err == nil || !strings.Contains(err.Error(), "security refusal: invalid authorization: authorization expired") {
		t.Fatalf("expected security refusal for expired auth, got: %v", err)
	}

	// 3. Setup pending authorization: must fail closed
	_ = store.SetAuthorization(&AuthorizationRecord{
		ID:                  uuid.New().String(),
		AssessmentID:        asmID,
		AuthorizingParty:    "Security Team",
		AuthorizationMethod: "EMAIL",
		DateReceived:        time.Now().UTC(),
		Status:              AuthPending,
	})
	_, err = ctrl.RunAssessment(ctx, asmID, ExecutionOptions{})
	if err == nil || !strings.Contains(err.Error(), "security refusal: invalid authorization: authorization status is PENDING") {
		t.Fatalf("expected security refusal for pending auth, got: %v", err)
	}

	// 4. Setup not yet valid authorization (future ValidFrom): must fail closed
	tomorrow := time.Now().UTC().Add(24 * time.Hour)
	nextWeek := time.Now().UTC().Add(7 * 24 * time.Hour)
	_ = store.SetAuthorization(&AuthorizationRecord{
		ID:                  uuid.New().String(),
		AssessmentID:        asmID,
		AuthorizingParty:    "Security Team",
		AuthorizationMethod: "EMAIL",
		DateReceived:        time.Now().UTC(),
		ValidFrom:           &tomorrow,
		ValidUntil:          &nextWeek,
		Status:              AuthApproved,
	})
	_, err = ctrl.RunAssessment(ctx, asmID, ExecutionOptions{})
	if err == nil || !strings.Contains(err.Error(), "security refusal: invalid authorization: authorization not yet active") {
		t.Fatalf("expected security refusal for not yet active auth, got: %v", err)
	}

	// 5. Setup revoked authorization: must fail closed
	_ = store.SetAuthorization(&AuthorizationRecord{
		ID:                  uuid.New().String(),
		AssessmentID:        asmID,
		AuthorizingParty:    "Security Team",
		AuthorizationMethod: "EMAIL",
		DateReceived:        time.Now().UTC(),
		Status:              AuthRevoked,
	})
	_, err = ctrl.RunAssessment(ctx, asmID, ExecutionOptions{})
	if err == nil || !strings.Contains(err.Error(), "security refusal: invalid authorization: authorization status is REVOKED") {
		t.Fatalf("expected security refusal for revoked auth, got: %v", err)
	}
}

func TestController_ExclusionRefusal(t *testing.T) {
	store, cleanup := newTestStore(t)
	defer cleanup()

	ctrl := NewController(store)
	ctx := context.Background()

	clientID := uuid.New().String()
	_ = store.CreateClient(&Client{ID: clientID, Name: "Acme"})
	asmID := uuid.New().String()
	_ = store.CreateAssessment(&Assessment{
		ID:        asmID,
		Ref:       "ASM-2026-EXCL",
		ClientID:  clientID,
		Name:      "Exclusion Test",
		Status:    StatusReady,
		ScopeMode: "same-origin",
	})
	_ = store.AddTarget(&AssessmentTarget{
		ID:           uuid.New().String(),
		AssessmentID: asmID,
		TargetURL:    "https://excluded.example.com",
		ScopeStatus:  "APPROVED",
	})
	_ = store.SetAuthorization(&AuthorizationRecord{
		ID:                  uuid.New().String(),
		AssessmentID:        asmID,
		AuthorizingParty:    "Security Team",
		AuthorizationMethod: "CONTRACT",
		DateReceived:        time.Now().UTC(),
		Status:              AuthApproved,
	})
	_ = store.AddExclusion(&Exclusion{
		ID:            uuid.New().String(),
		AssessmentID:  asmID,
		ExclusionType: ExclusionHostname,
		Pattern:       "excluded.example.com",
		Reason:        "Strict boundary",
	})

	// Execute: must fail closed because target itself is excluded
	_, err := ctrl.RunAssessment(ctx, asmID, ExecutionOptions{})
	if err == nil || !strings.Contains(err.Error(), "security refusal: all approved targets are excluded") {
		t.Fatalf("expected security refusal when targets are excluded, got: %v", err)
	}
}

func TestController_SyntheticExecutionAndTraceability(t *testing.T) {
	// 1. Start synthetic HTTP test server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			w.Header().Set("Content-Type", "text/html")
			// Provide links and a secret exposure in page
			fmt.Fprint(w, `
				<html>
				<head><title>Test App</title></head>
				<body>
					<a href="/dashboard">Dashboard</a>
					<a href="/api/v1/users">API Users</a>
					<script>
						const aws_key = "AKIAIOSFODNN7EXAMPLE";
					</script>
				</body>
				</html>
			`)
		case "/dashboard":
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprint(w, "<html><body>Welcome to Dashboard</body></html>")
		case "/api/v1/users":
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `{"users": [{"id": 1, "name": "Alice"}]}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	store, cleanup := newTestStore(t)
	defer cleanup()

	// 2. Setup Client
	clientID := uuid.New().String()
	_ = store.CreateClient(&Client{ID: clientID, Name: "Synthetic Corp"})

	// 3. Setup Assessment
	asmID := uuid.New().String()
	asmRef := GenerateAssessmentRef()
	_ = store.CreateAssessment(&Assessment{
		ID:        asmID,
		Ref:       asmRef,
		ClientID:  clientID,
		Name:      "Synthetic Security Run",
		Status:    StatusDraft,
		ScopeMode: "same-origin",
	})

	// 4. Setup Target
	targetID := uuid.New().String()
	_ = store.AddTarget(&AssessmentTarget{
		ID:           targetID,
		AssessmentID: asmID,
		TargetURL:    server.URL,
		TargetType:   TargetWebsite,
		ScopeStatus:  "APPROVED",
	})

	// 5. Setup Valid Authorization
	now := time.Now().UTC()
	future := now.Add(24 * time.Hour)
	_ = store.SetAuthorization(&AuthorizationRecord{
		ID:                  uuid.New().String(),
		AssessmentID:        asmID,
		AuthorizingParty:    "Security Director",
		AuthorizationMethod: "TICKET",
		DateReceived:        now,
		ValidUntil:          &future,
		Status:              AuthApproved,
	})

	// Transition to READY
	_ = store.UpdateAssessmentStatus(asmID, StatusReady)

	// 6. Setup custom export paths in temp directory
	tmpDir, err := os.MkdirTemp("", "felix_ctrl_test_*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	htmlPath := filepath.Join(tmpDir, "assessment_report.html")
	jsonPath := filepath.Join(tmpDir, "assessment_report.json")

	ctrl := NewController(store)
	opts := ExecutionOptions{
		TimeoutDuration: 5 * time.Second,
		Concurrency:     2,
		MaxAssets:       50,
		ExportHTMLPath:  htmlPath,
		ExportJSONPath:  jsonPath,
		FelixVersion:    "2.0.0",
		BuildID:         "test",
	}

	// 7. Execute Assessment
	res, err := ctrl.RunAssessment(context.Background(), asmID, opts)
	if err != nil {
		t.Fatalf("RunAssessment failed unexpectedly: %v", err)
	}

	if res.Execution.Status != StatusCompleted {
		t.Errorf("expected execution status COMPLETED, got %s", res.Execution.Status)
	}

	// Verify Assessment updated to COMPLETED
	asm, err := store.GetAssessment(asmID)
	if err != nil || asm.Status != StatusCompleted {
		t.Errorf("expected assessment status COMPLETED, got %s (err: %v)", asm.Status, err)
	}

	// 8. Verify Report Files Created
	if _, err := os.Stat(htmlPath); os.IsNotExist(err) {
		t.Errorf("expected HTML report file to be written to %s", htmlPath)
	}
	if _, err := os.Stat(jsonPath); os.IsNotExist(err) {
		t.Errorf("expected JSON report file to be written to %s", jsonPath)
	}

	// 9. Verify Findings Traceability in SQLite
	findings, err := store.GetFindings(asmID, res.Execution.ID)
	if err != nil {
		t.Fatalf("failed to get findings: %v", err)
	}

	// Should have discovered at least the AWS key or assets
	for _, f := range findings {
		if f.AssessmentID != asmID {
			t.Errorf("finding AssessmentID mismatch: expected %s, got %s", asmID, f.AssessmentID)
		}
		if f.ExecutionID != res.Execution.ID {
			t.Errorf("finding ExecutionID mismatch: expected %s, got %s", res.Execution.ID, f.ExecutionID)
		}
		if f.TargetID != targetID {
			t.Errorf("finding TargetID mismatch: expected %s, got %s", targetID, f.TargetID)
		}
	}

	// 10. Verify Reports recorded in SQLite
	reports, err := store.GetReports(asmID)
	if err != nil || len(reports) < 2 {
		t.Errorf("expected at least 2 report records (HTML & JSON), got %d (err: %v)", len(reports), err)
	}

	// 11. Verify Attack-Surface Inventory recorded in SQLite
	invAssets, invRelations, err := store.GetInventory(asmID, res.Execution.ID, "", false)
	if err != nil {
		t.Fatalf("failed to retrieve attack-surface inventory: %v", err)
	}
	if len(invAssets) == 0 {
		t.Errorf("expected discovered inventory assets to be recorded in SQLite")
	}
	if len(invRelations) == 0 {
		t.Errorf("expected inventory relationships to be recorded in SQLite")
	}
	if res.InventorySummary == nil || res.InventorySummary.TotalAssets == 0 {
		t.Errorf("expected non-nil InventorySummary on ExecutionResult")
	}
}

func TestController_NetworkRedirectAndExclusionEnforcement(t *testing.T) {
	// Setup test HTTP server with redirection
	var forbiddenHit bool

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/redirect-to-external":
			http.Redirect(w, r, "https://example.org/forbidden", http.StatusFound)
		case "/redirect-to-excluded":
			http.Redirect(w, r, "/admin/secret", http.StatusFound)
		case "/admin/secret":
			forbiddenHit = true
			w.Header().Set("Content-Type", "application/javascript")
			_, _ = w.Write([]byte(`var key = "AKIAIOSFODNN7EXAMPLE";`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer ts.Close()

	store, cleanup := newTestStore(t)
	defer cleanup()

	ctrl := NewController(store)
	ctx := context.Background()

	clientID := uuid.New().String()
	_ = store.CreateClient(&Client{ID: clientID, Name: "Redirect & Scope Test"})

	asmID := uuid.New().String()
	_ = store.CreateAssessment(&Assessment{
		ID:        asmID,
		Ref:       "ASM-2026-REDIR",
		ClientID:  clientID,
		Name:      "Redirect Scope Test",
		Status:    StatusReady,
		ScopeMode: "same-origin",
	})

	_ = store.SetAuthorization(&AuthorizationRecord{
		ID:                  uuid.New().String(),
		AssessmentID:        asmID,
		AuthorizingParty:    "Security Lead",
		AuthorizationMethod: "CONTRACT",
		DateReceived:        time.Now().UTC(),
		Status:              AuthApproved,
	})

	// Add excluded path /admin
	_ = store.AddExclusion(&Exclusion{
		ID:            uuid.New().String(),
		AssessmentID:  asmID,
		ExclusionType: ExclusionPathPrefix,
		Pattern:       "/admin",
		Reason:        "Strict admin exclusion",
	})

	// Case 1: Target redirects to excluded path /admin/secret
	targetExcludedID := uuid.New().String()
	_ = store.AddTarget(&AssessmentTarget{
		ID:           targetExcludedID,
		AssessmentID: asmID,
		TargetURL:    ts.URL + "/redirect-to-excluded",
		ScopeStatus:  "APPROVED",
	})

	// Case 2: Target redirects to external domain
	targetExternalID := uuid.New().String()
	_ = store.AddTarget(&AssessmentTarget{
		ID:           targetExternalID,
		AssessmentID: asmID,
		TargetURL:    ts.URL + "/redirect-to-external",
		ScopeStatus:  "APPROVED",
	})

	opts := ExecutionOptions{
		TimeoutDuration: 3 * time.Second,
		Concurrency:     2,
		FelixVersion:    "2.0.0",
		BuildID:         "test",
	}

	res, err := ctrl.RunAssessment(ctx, asmID, opts)
	if err != nil {
		t.Fatalf("RunAssessment failed unexpectedly: %v", err)
	}

	if forbiddenHit {
		t.Fatalf("CRITICAL SECURITY FAILURE: crawler followed redirect to excluded path /admin/secret over the network!")
	}

	// Verify that zero findings were created from forbidden path
	findings, err := store.GetFindings(asmID, res.Execution.ID)
	if err != nil {
		t.Fatalf("failed to retrieve findings: %v", err)
	}
	for _, f := range findings {
		if strings.Contains(f.Endpoint, "/admin") || strings.Contains(f.TargetURL, "example.org") || strings.Contains(f.Endpoint, "example.org") {
			t.Fatalf("CRITICAL: found unexpected finding from excluded/external target: %v", f)
		}
	}
}

