package assessment

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"felix/pkg/correlation"
	"felix/pkg/report"

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
			w.Header().Set("Set-Cookie", "auth_sess=xyz123; Path=/; HttpOnly; SameSite=Lax")
			// Provide links and a secret exposure in page
			fmt.Fprint(w, `
				<html>
				<head><title>Test App</title></head>
				<body>
					<a href="/dashboard">Dashboard</a>
					<a href="/api/v1/users">API Users</a>
					<form action="/login" method="POST">
						<input type="text" name="username"/>
						<input type="password" name="password"/>
					</form>
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

	// 12. Verify Authentication Intelligence recorded in SQLite
	authInv, err := store.GetAuthInventory(asmID, res.Execution.ID, "")
	if err != nil {
		t.Fatalf("failed to retrieve auth inventory: %v", err)
	}
	if len(authInv.Surfaces) == 0 {
		t.Errorf("expected discovered auth surfaces to be recorded in SQLite")
	}
	if len(authInv.Cookies) == 0 {
		t.Errorf("expected cookies to be recorded in SQLite")
	}
	if res.AuthSummary == nil || res.AuthSummary.TotalSurfaces == 0 {
		t.Errorf("expected non-nil AuthSummary with discovered surfaces on ExecutionResult")
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

func TestController_CorrelationAndReportIntegration(t *testing.T) {
	// 1. Setup store
	store, cleanup := newTestStore(t)
	defer cleanup()

	clientID := uuid.New().String()
	_ = store.CreateClient(&Client{ID: clientID, Name: "Attack Path Integration Corp"})

	asmID := uuid.New().String()
	asmRef := "ASM-2026-CORR"
	_ = store.CreateAssessment(&Assessment{
		ID:        asmID,
		Ref:       asmRef,
		ClientID:  clientID,
		Name:      "Correlated Assessment",
		Status:    StatusReady,
		ScopeMode: "same-origin",
	})

	targetID := uuid.New().String()
	targetURL := "https://api.example.com"
	_ = store.AddTarget(&AssessmentTarget{
		ID:           targetID,
		AssessmentID: asmID,
		TargetURL:    targetURL,
		TargetType:   TargetAPIBaseURL,
		ScopeStatus:  "APPROVED",
	})

	now := time.Now().UTC()
	future := now.Add(24 * time.Hour)
	_ = store.SetAuthorization(&AuthorizationRecord{
		ID:                  uuid.New().String(),
		AssessmentID:        asmID,
		AuthorizingParty:    "Security Team",
		AuthorizationMethod: "TICKET",
		DateReceived:        now,
		ValidUntil:          &future,
		Status:              AuthApproved,
	})

	// 2. Prepare findings that correlate into an attack path:
	// Finding 1: Entry Point (COR-01)
	// Finding 2: Vulnerable API resource with BOLA (COR-03)
	// Finding 3: Sensitive data exposed in response
	f1 := report.Finding{
		ID:          "fnd-entrypoint",
		Title:       "Public API Endpoint Discovered",
		Category:    "RECON",
		Severity:    report.SeverityInfo,
		Confidence:  report.ConfidenceHigh,
		Target:      targetURL,
		Endpoint:    targetURL + "/api/v1/users/123",
		Method:      "GET",
		Description: "Public API entry point",
		EvidenceDetails: report.EvidenceDetails{
			Observation: "Discovered active endpoint",
			Details: map[string]string{
				"status": "200",
			},
		},
		Verification: report.VerificationRecord{
			Status: report.VerificationVerified,
		},
	}
	f2 := report.Finding{
		ID:          "fnd-bola",
		Title:       "Broken Object Level Authorization (BOLA)",
		Category:    "BOLA",
		Severity:    report.SeverityHigh,
		Confidence:  report.ConfidenceHigh,
		Target:      targetURL,
		Endpoint:    targetURL + "/api/v1/users/123",
		Method:      "GET",
		Description: "BOLA allows accessing another tenant record",
		EvidenceDetails: report.EvidenceDetails{
			Observation: "Unauthorized record access",
			Details: map[string]string{
				"resource_id": "user-123",
			},
		},
		Verification: report.VerificationRecord{
			Status: report.VerificationVerified,
		},
	}
	f3 := report.Finding{
		ID:          "fnd-pii",
		Title:       "Customer PII Exposed in Response",
		Category:    "DATA_EXPOSURE",
		Severity:    report.SeverityCritical,
		Confidence:  report.ConfidenceHigh,
		Target:      targetURL,
		Endpoint:    targetURL + "/api/v1/users/123",
		Method:      "GET",
		Description: "Response body contains plaintext PII",
		EvidenceDetails: report.EvidenceDetails{
			Observation: "Exposed customer credentials and PII",
			Details: map[string]string{
				"resource_id": "user-123",
			},
		},
		Verification: report.VerificationRecord{
			Status: report.VerificationVerified,
		},
	}

	reportFindings := []report.Finding{f1, f2, f3}

	// 3. Test correlation engine directly with findings
	cfg := correlation.DefaultConfig()
	eng := correlation.NewEngine(cfg)
	summary, paths, _, err := eng.Correlate(context.Background(), reportFindings)
	if err != nil {
		t.Fatalf("correlation failed: %v", err)
	}
	if len(paths) == 0 {
		t.Fatalf("expected at least 1 correlated attack path, got 0")
	}

	// 4. Verify persistence of attack paths and correlation run in store
	execID := "exec-test-corr"
	exec := &AssessmentExecution{
		ID:           execID,
		AssessmentID: asmID,
		Status:       "RUNNING",
		StartedAt:    time.Now().UTC(),
	}
	if err := store.CreateExecution(exec); err != nil {
		t.Fatalf("CreateExecution failed: %v", err)
	}

	runRec := &correlation.RunRecord{
		ID:                     uuid.New().String(),
		AssessmentID:           asmID,
		ExecutionID:            execID,
		TotalFindings:          summary.TotalFindings,
		CandidateRelationships: summary.CandidateRelationships,
		CandidatePaths:         summary.CandidatePaths,
		VerifiedPaths:          summary.VerifiedPaths,
		HighestRisk:            summary.HighestRiskLevel,
		CoverageJSON:           "{}",
		SyntheticFixture:       summary.SyntheticFixture,
		CreatedAt:              time.Now().UTC(),
	}
	if err := store.SaveCorrelationRun(runRec); err != nil {
		t.Fatalf("SaveCorrelationRun failed: %v", err)
	}
	if err := store.SaveAttackPaths(asmID, execID, paths); err != nil {
		t.Fatalf("SaveAttackPaths failed: %v", err)
	}

	loadedRun, err := store.GetCorrelationRun(asmID, execID)
	if err != nil {
		t.Fatalf("GetCorrelationRun failed: %v", err)
	}
	if loadedRun == nil || loadedRun.AssessmentID != asmID {
		t.Fatalf("loaded correlation run mismatch: %+v", loadedRun)
	}

	loadedPaths, err := store.GetAttackPaths(asmID, execID, "", "")
	if err != nil {
		t.Fatalf("GetAttackPaths failed: %v", err)
	}
	if len(loadedPaths) != len(paths) {
		t.Fatalf("expected %d loaded paths, got %d", len(paths), len(loadedPaths))
	}

	// 5. Test report integration: build report, attach attack paths & security stories, export HTML & JSON
	rep := report.BuildMultiTargetReport([]string{targetURL}, reportFindings)
	var corrSummaries []report.AttackPathSummary
	var stories []report.SecurityStory
	for _, p := range paths {
		stories = append(stories, p.SecurityStory)
		var transitions []string
		for _, e := range p.Edges {
			transitions = append(transitions, fmt.Sprintf("[%s] %s -> %s: %s",
				e.ValidationStatus, e.SourceTitle, e.TargetTitle, e.Explanation))
		}
		corrSummaries = append(corrSummaries, report.AttackPathSummary{
			ID:                p.ID,
			Title:             p.Title,
			Status:            string(p.Status),
			CombinedRiskLevel: p.CombinedRiskLevel,
			CombinedRiskScore: p.CombinedRiskScore,
			Confidence:        p.Confidence,
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
	report.AttachAttackPaths(&rep, corrSummaries)
	report.AttachSecurityStories(&rep, stories)

	if len(rep.AttackPaths) == 0 {
		t.Fatalf("expected rep.AttackPaths to be populated")
	}
	if len(rep.SecurityStories) == 0 {
		t.Fatalf("expected rep.SecurityStories to be populated")
	}

	tmpDir, err := os.MkdirTemp("", "felix_corr_report_test_*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	htmlPath := filepath.Join(tmpDir, "report.html")
	jsonPath := filepath.Join(tmpDir, "report.json")

	if err := report.WriteHTML(rep, htmlPath); err != nil {
		t.Fatalf("WriteHTML failed: %v", err)
	}
	if err := report.WriteJSON(rep, jsonPath); err != nil {
		t.Fatalf("WriteJSON failed: %v", err)
	}

	// Verify HTML file contains Correlated Attack Paths section and badge
	htmlBytes, err := os.ReadFile(htmlPath)
	if err != nil {
		t.Fatalf("failed to read generated HTML: %v", err)
	}
	htmlContent := string(htmlBytes)
	if !strings.Contains(htmlContent, "Correlated Attack Paths") {
		t.Errorf("HTML report missing 'Correlated Attack Paths' section")
	}
	if !strings.Contains(htmlContent, "badge-") {
		t.Errorf("HTML report missing path status badge")
	}

	// Verify JSON file contains attack_paths array and security_stories array
	jsonBytes, err := os.ReadFile(jsonPath)
	if err != nil {
		t.Fatalf("failed to read generated JSON: %v", err)
	}
	var deserialized report.Report
	if err := json.Unmarshal(jsonBytes, &deserialized); err != nil {
		t.Fatalf("failed to unmarshal JSON report: %v", err)
	}
	if len(deserialized.AttackPaths) != len(paths) {
		t.Fatalf("expected %d deserialized attack paths, got %d", len(paths), len(deserialized.AttackPaths))
	}
	if deserialized.AttackPaths[0].Title != paths[0].Title {
		t.Errorf("deserialized attack path title mismatch: %s vs %s", deserialized.AttackPaths[0].Title, paths[0].Title)
	}
	if len(deserialized.SecurityStories) == 0 {
		t.Errorf("expected security stories in deserialized report")
	}
}
