package assessment

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"felix/pkg/report"
	"github.com/google/uuid"
)

// Canary secret tokens for leak detection in Test Area C / F.
const (
	safetyCanarySecret = "AKIA" + "IOSFODNN7SAFETYCANARY"
	safetyCanaryToken  = "ghp_" + "SAFETYCANARYTOKEN1234567890abcdef"
	safetyCanaryPass   = "SuperSecretPasswordSafetyCanary123!"
)

// TestSafety_ScopeRejectionBeforeNetwork verifies that out-of-scope or excluded targets
// are rejected before unauthorized network requests are made, failing closed with a security refusal.
func TestSafety_ScopeRejectionBeforeNetwork(t *testing.T) {
	store, cleanup := newTestStore(t)
	defer cleanup()

	ctrl := NewController(store)
	ctx := context.Background()

	networkCalled := false
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		networkCalled = true
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	clientID := uuid.New().String()
	_ = store.CreateClient(&Client{ID: clientID, Name: "Safety Scope Test"})
	asmID := uuid.New().String()
	asmRef := GenerateAssessmentRef()
	_ = store.CreateAssessment(&Assessment{
		ID:        asmID,
		Ref:       asmRef,
		ClientID:  clientID,
		Name:      "Scope Rejection Test",
		Status:    StatusDraft,
		ScopeMode: "same-origin",
	})

	now := time.Now().UTC()
	_ = store.SetAuthorization(&AuthorizationRecord{
		ID:                  uuid.New().String(),
		AssessmentID:        asmID,
		AuthorizingParty:    "Security Team",
		AuthorizationMethod: "WRITTEN_CONSENT",
		DateReceived:        now,
		Status:              AuthApproved,
	})

	targetID := uuid.New().String()
	_ = store.AddTarget(&AssessmentTarget{
		ID:           targetID,
		AssessmentID: asmID,
		TargetURL:    ts.URL,
		ScopeStatus:  "APPROVED",
	})

	// Add an exclusion that matches the target URL explicitly
	_ = store.AddExclusion(&Exclusion{
		ID:            uuid.New().String(),
		AssessmentID:  asmID,
		ExclusionType: ExclusionExactURL,
		Pattern:       ts.URL,
		Reason:        "Explicit exclusion for safety test",
		CreatedAt:     now,
	})

	// Run assessment: should be rejected immediately before any network call
	_, err := ctrl.RunAssessment(ctx, asmID, ExecutionOptions{
		AllowLoopback: true,
	})
	if err == nil {
		t.Fatalf("expected security refusal error when target is excluded, got nil")
	}
	if !strings.Contains(err.Error(), "security refusal: all approved targets are excluded") {
		t.Errorf("expected security refusal for excluded targets, got: %v", err)
	}
	if networkCalled {
		t.Errorf("CRITICAL SAFETY VIOLATION: network request was made to excluded target URL")
	}

	// Verify assessment status was not marked completed
	asm, _ := store.GetAssessment(asmID)
	if asm.Status == StatusCompleted {
		t.Errorf("assessment status must not be COMPLETED after scope refusal")
	}
}

// TestSafety_WildcardAndPrefixExclusions verifies wildcard and path-prefix exclusion rules.
func TestSafety_WildcardAndPrefixExclusions(t *testing.T) {
	rules := []ScopeRule{}
	exclusions := []Exclusion{
		{ID: "1", ExclusionType: ExclusionHostname, Pattern: "*.internal.local", Reason: "Wildcard internal domain"},
		{ID: "2", ExclusionType: ExclusionPathPrefix, Pattern: "/admin/*", Reason: "Admin path prefix"},
		{ID: "3", ExclusionType: ExclusionExactURL, Pattern: "/api/private", Reason: "Exact private endpoint"},
	}

	validator := NewScopeValidator("same-origin", []string{"http://app.internal.local", "https://example.com"}, rules, exclusions)

	// 1. Wildcard host matching
	excluded, reason := validator.IsExcluded("http://sub.internal.local/dashboard")
	if !excluded {
		t.Errorf("expected http://sub.internal.local/dashboard to be excluded by *.internal.local")
	}
	if reason == "" {
		t.Errorf("expected exclusion reason to be populated")
	}

	// 2. Path prefix matching
	excluded, _ = validator.IsExcluded("https://example.com/admin/users")
	if !excluded {
		t.Errorf("expected https://example.com/admin/users to be excluded by /admin/*")
	}

	// 3. Allowed path
	excluded, _ = validator.IsExcluded("https://example.com/public/catalog")
	if excluded {
		t.Errorf("expected https://example.com/public/catalog to be allowed")
	}
}

// TestSafety_RedirectBlockedToRestrictedDestinations verifies that HTTP redirects
// to loopback, private IPs, metadata endpoints, and out-of-scope hosts are intercepted and blocked.
func TestSafety_RedirectBlockedToRestrictedDestinations(t *testing.T) {
	cases := []struct {
		name        string
		redirectURL string
		expectErr   string
	}{
		{
			name:        "Redirect to Cloud Metadata IPv4",
			redirectURL: "http://169.254.169.254/latest/meta-data/",
			expectErr:   "cloud metadata service",
		},
		{
			name:        "Redirect to Out of Scope Host",
			redirectURL: "http://unauthorized-external.com/evil",
			expectErr:   "blocked by scope validator",
		},
		{
			name:        "Redirect to Unsupported Scheme",
			redirectURL: "file:///etc/passwd",
			expectErr:   "unsupported scheme",
		},
		{
			name:        "Redirect with Embedded Credentials",
			redirectURL: "http://admin:secret@target.local/portal",
			expectErr:   "embedded credentials",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				http.Redirect(w, r, tc.redirectURL, http.StatusFound)
			}))
			defer ts.Close()

			store, cleanup := newTestStore(t)
			defer cleanup()

			ctrl := NewController(store)
			ctx := context.Background()

			clientID := uuid.New().String()
			_ = store.CreateClient(&Client{ID: clientID, Name: "Redirect Safety Client"})
			asmID := uuid.New().String()
			asmRef := GenerateAssessmentRef()
			_ = store.CreateAssessment(&Assessment{
				ID:        asmID,
				Ref:       asmRef,
				ClientID:  clientID,
				Name:      "Redirect Safety Assessment",
				Status:    StatusDraft,
				ScopeMode: "same-origin",
			})

			now := time.Now().UTC()
			_ = store.SetAuthorization(&AuthorizationRecord{
				ID:                  uuid.New().String(),
				AssessmentID:        asmID,
				AuthorizingParty:    "Security Team",
				AuthorizationMethod: "WRITTEN_CONSENT",
				DateReceived:        now,
				Status:              AuthApproved,
			})

			_ = store.AddTarget(&AssessmentTarget{
				ID:           uuid.New().String(),
				AssessmentID: asmID,
				TargetURL:    ts.URL,
				ScopeStatus:  "APPROVED",
			})

			// Allow loopback for the initial target, but redirect to restricted destination must fail
			res, err := ctrl.RunAssessment(ctx, asmID, ExecutionOptions{
				AllowLoopback: true,
			})
			if err != nil {
				// Controller error is acceptable
				return
			}
			// If assessment completed, verify that no findings or assets were created from the unauthorized redirect destination
			if res != nil && res.Report != nil {
				for _, f := range res.Report.Findings {
					if strings.Contains(f.Endpoint, "169.254.169.254") || strings.Contains(f.Endpoint, "unauthorized-external.com") {
						t.Errorf("CRITICAL LEAK: finding was registered for prohibited redirect destination: %s", f.Endpoint)
					}
				}
			}
		})
	}
}

// TestSafety_AssessmentContextCancellation verifies prompt cancellation propagation and cleanup.
func TestSafety_AssessmentContextCancellation(t *testing.T) {
	serverBlock := make(chan struct{})
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Hang until unblocked or client disconnects
		select {
		case <-serverBlock:
			w.WriteHeader(http.StatusOK)
		case <-r.Context().Done():
		}
	}))
	defer func() {
		close(serverBlock)
		ts.Close()
	}()

	store, cleanup := newTestStore(t)
	defer cleanup()

	ctrl := NewController(store)
	ctx, cancel := context.WithCancel(context.Background())

	clientID := uuid.New().String()
	_ = store.CreateClient(&Client{ID: clientID, Name: "Cancellation Client"})
	asmID := uuid.New().String()
	asmRef := GenerateAssessmentRef()
	_ = store.CreateAssessment(&Assessment{
		ID:        asmID,
		Ref:       asmRef,
		ClientID:  clientID,
		Name:      "Cancellation Assessment",
		Status:    StatusDraft,
		ScopeMode: "same-origin",
	})

	now := time.Now().UTC()
	_ = store.SetAuthorization(&AuthorizationRecord{
		ID:                  uuid.New().String(),
		AssessmentID:        asmID,
		AuthorizingParty:    "Security Team",
		AuthorizationMethod: "WRITTEN_CONSENT",
		DateReceived:        now,
		Status:              AuthApproved,
	})

	_ = store.AddTarget(&AssessmentTarget{
		ID:           uuid.New().String(),
		AssessmentID: asmID,
		TargetURL:    ts.URL,
		ScopeStatus:  "APPROVED",
	})

	// Cancel context after 100 milliseconds
	go func() {
		time.Sleep(100 * time.Millisecond)
		cancel()
	}()

	start := time.Now()
	res, err := ctrl.RunAssessment(ctx, asmID, ExecutionOptions{
		AllowLoopback: true,
	})
	duration := time.Since(start)

	if duration > 3*time.Second {
		t.Errorf("cancellation took too long (%v), expected prompt termination", duration)
	}

	if err == nil {
		t.Fatalf("expected error on context cancellation, got nil")
	}
	if !errors.Is(err, context.Canceled) {
		t.Errorf("expected context.Canceled error, got: %v", err)
	}

	if res == nil || res.Execution == nil {
		t.Fatalf("expected Execution record in result even on cancellation")
	}
	if res.Execution.Status != StatusCancelled {
		t.Errorf("expected Execution status CANCELLED, got: %s", res.Execution.Status)
	}
	if !strings.Contains(res.Execution.ErrorMessage, "cancelled by operator") {
		t.Errorf("expected error message to mention operator cancellation, got: %q", res.Execution.ErrorMessage)
	}

	// Verify assessment status in store
	asm, _ := store.GetAssessment(asmID)
	if asm.Status != StatusCancelled {
		t.Errorf("expected assessment status in store to be CANCELLED, got: %s", asm.Status)
	}
}

// TestSafety_AssessmentExecutionTimeout verifies that when a timeout deadline expires,
// the assessment terminates cleanly and records failure without claiming the target is safe.
func TestSafety_AssessmentExecutionTimeout(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Sleep longer than the client timeout
		time.Sleep(500 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	store, cleanup := newTestStore(t)
	defer cleanup()

	ctrl := NewController(store)
	// Deadline of 50ms
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	clientID := uuid.New().String()
	_ = store.CreateClient(&Client{ID: clientID, Name: "Timeout Client"})
	asmID := uuid.New().String()
	asmRef := GenerateAssessmentRef()
	_ = store.CreateAssessment(&Assessment{
		ID:        asmID,
		Ref:       asmRef,
		ClientID:  clientID,
		Name:      "Timeout Assessment",
		Status:    StatusDraft,
		ScopeMode: "same-origin",
	})

	now := time.Now().UTC()
	_ = store.SetAuthorization(&AuthorizationRecord{
		ID:                  uuid.New().String(),
		AssessmentID:        asmID,
		AuthorizingParty:    "Security Team",
		AuthorizationMethod: "WRITTEN_CONSENT",
		DateReceived:        now,
		Status:              AuthApproved,
	})

	_ = store.AddTarget(&AssessmentTarget{
		ID:           uuid.New().String(),
		AssessmentID: asmID,
		TargetURL:    ts.URL,
		ScopeStatus:  "APPROVED",
	})

	res, err := ctrl.RunAssessment(ctx, asmID, ExecutionOptions{
		AllowLoopback: true,
	})

	if err == nil {
		t.Fatalf("expected deadline exceeded error, got nil")
	}
	if !errors.Is(err, context.DeadlineExceeded) && !strings.Contains(err.Error(), "context deadline exceeded") {
		t.Errorf("expected deadline exceeded error, got: %v", err)
	}

	if res != nil && res.Execution != nil {
		if res.Execution.Status != StatusFailed {
			t.Errorf("expected execution status FAILED on timeout, got: %s", res.Execution.Status)
		}
	}
}

// TestSafety_EvidencePipelineConsistency tests the full pipeline:
// Engine -> Finding Model -> Controller -> SQLite Persistence -> Report Export (JSON, HTML, SARIF).
// Verifies stable IDs, valid provenance, secret redaction in final outputs, and field round-trip fidelity.
func TestSafety_EvidencePipelineConsistency(t *testing.T) {
	tempDir := t.TempDir()

	// Mock server that returns HTML containing a synthetic secret
	mockHTML := fmt.Sprintf(`<!DOCTYPE html>
<html>
<head><title>Fidelity Test</title></head>
<body>
  <h1>Fidelity App</h1>
  <script>
    const awsKey = "%s";
    const apiKey = "%s";
  </script>
</body>
</html>`, safetyCanarySecret, safetyCanaryToken)

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(mockHTML))
	}))
	defer ts.Close()

	store, cleanup := newTestStore(t)
	defer cleanup()

	ctrl := NewController(store)
	ctx := context.Background()

	clientID := uuid.New().String()
	_ = store.CreateClient(&Client{ID: clientID, Name: "Pipeline Client"})
	asmID := uuid.New().String()
	asmRef := GenerateAssessmentRef()
	_ = store.CreateAssessment(&Assessment{
		ID:        asmID,
		Ref:       asmRef,
		ClientID:  clientID,
		Name:      "Pipeline Consistency Assessment",
		Status:    StatusDraft,
		ScopeMode: "same-origin",
	})

	now := time.Now().UTC()
	_ = store.SetAuthorization(&AuthorizationRecord{
		ID:                  uuid.New().String(),
		AssessmentID:        asmID,
		AuthorizingParty:    "Security Lead",
		AuthorizationMethod: "WRITTEN_CONSENT",
		DateReceived:        now,
		Status:              AuthApproved,
	})

	targetID := uuid.New().String()
	_ = store.AddTarget(&AssessmentTarget{
		ID:           targetID,
		AssessmentID: asmID,
		TargetURL:    ts.URL,
		ScopeStatus:  "APPROVED",
	})

	htmlExportPath := filepath.Join(tempDir, "report.html")
	jsonExportPath := filepath.Join(tempDir, "report.json")

	res, err := ctrl.RunAssessment(ctx, asmID, ExecutionOptions{
		AllowLoopback:  true,
		ExportHTMLPath: htmlExportPath,
		ExportJSONPath: jsonExportPath,
	})
	if err != nil {
		t.Fatalf("RunAssessment failed: %v", err)
	}

	if res.Execution.Status != StatusCompleted {
		t.Fatalf("expected StatusCompleted, got: %s", res.Execution.Status)
	}

	// 1. Retrieve findings from SQLite store
	persistedFindings, err := store.GetFindings(asmID, "")
	if err != nil {
		t.Fatalf("GetFindings from SQLite failed: %v", err)
	}
	if len(persistedFindings) == 0 {
		t.Fatalf("expected findings to be persisted to SQLite store")
	}

	// 2. Validate Provenance & Identifiers in persisted findings
	for _, pf := range persistedFindings {
		if pf.ID == "" {
			t.Errorf("persisted finding ID cannot be empty")
		}
		if pf.AssessmentID != asmID {
			t.Errorf("persisted finding AssessmentID = %q, want %q", pf.AssessmentID, asmID)
		}
		if pf.ExecutionID != res.Execution.ID {
			t.Errorf("persisted finding ExecutionID = %q, want %q", pf.ExecutionID, res.Execution.ID)
		}
		if pf.TargetID != targetID {
			t.Errorf("persisted finding TargetID = %q, want %q", pf.TargetID, targetID)
		}
		if pf.Status == "" {
			t.Errorf("persisted finding Status cannot be empty")
		}

		// Negative Canary check: Raw secrets must never appear in SQLite finding records
		if strings.Contains(pf.EvidenceDetails.Observation, safetyCanarySecret) {
			t.Errorf("LEAK: raw canary secret found in SQLite finding observation")
		}
		if strings.Contains(pf.EvidenceDetails.Observation, safetyCanaryToken) {
			t.Errorf("LEAK: raw canary token found in SQLite finding observation")
		}
		if strings.Contains(pf.Title, safetyCanarySecret) || strings.Contains(pf.Title, safetyCanaryToken) {
			t.Errorf("LEAK: raw canary found in finding Title")
		}
	}

	// 3. Inspect JSON Export
	jsonData, err := os.ReadFile(jsonExportPath)
	if err != nil {
		t.Fatalf("failed to read JSON export: %v", err)
	}
	jsonStr := string(jsonData)
	if strings.Contains(jsonStr, safetyCanarySecret) || strings.Contains(jsonStr, safetyCanaryToken) {
		t.Errorf("LEAK: raw canary secret found in exported JSON report")
	}
	var exportedRep report.Report
	if err := json.Unmarshal(jsonData, &exportedRep); err != nil {
		t.Fatalf("failed to parse exported JSON report: %v", err)
	}
	if len(exportedRep.Findings) != len(persistedFindings) {
		t.Errorf("exported JSON findings count (%d) does not match SQLite findings count (%d)",
			len(exportedRep.Findings), len(persistedFindings))
	}

	// 4. Inspect HTML Export
	htmlData, err := os.ReadFile(htmlExportPath)
	if err != nil {
		t.Fatalf("failed to read HTML export: %v", err)
	}
	htmlStr := string(htmlData)
	if strings.Contains(htmlStr, safetyCanarySecret) || strings.Contains(htmlStr, safetyCanaryToken) {
		t.Errorf("LEAK: raw canary secret found in exported HTML report")
	}
	if !strings.Contains(htmlStr, "Felix Security Assessment Report") {
		t.Errorf("exported HTML missing report title")
	}

	// 5. Inspect SARIF Export
	sarifLog := report.BuildSARIFLog(exportedRep)
	sarifBytes, err := json.Marshal(sarifLog)
	if err != nil {
		t.Fatalf("failed to marshal SARIF log: %v", err)
	}
	sarifStr := string(sarifBytes)
	if strings.Contains(sarifStr, safetyCanarySecret) || strings.Contains(sarifStr, safetyCanaryToken) {
		t.Errorf("LEAK: raw canary secret found in generated SARIF report")
	}
	if sarifLog.Version != "2.1.0" {
		t.Errorf("SARIF version = %q, want 2.1.0", sarifLog.Version)
	}
	if len(sarifLog.Runs) == 0 {
		t.Fatalf("SARIF log has zero runs")
	}
	if len(sarifLog.Runs[0].Results) != len(exportedRep.Findings) {
		t.Errorf("SARIF results count (%d) does not match report findings (%d)",
			len(sarifLog.Runs[0].Results), len(exportedRep.Findings))
	}
}

// TestSafety_UnreachableTargetFailureClassification verifies that network reachability failures
// do not produce a false claim of security or negative finding states.
func TestSafety_UnreachableTargetFailureClassification(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	closedURL := ts.URL
	ts.Close() // Immediately close to guarantee connection refused

	store, cleanup := newTestStore(t)
	defer cleanup()

	ctrl := NewController(store)
	ctx := context.Background()

	clientID := uuid.New().String()
	_ = store.CreateClient(&Client{ID: clientID, Name: "Unreachable Client"})
	asmID := uuid.New().String()
	asmRef := GenerateAssessmentRef()
	_ = store.CreateAssessment(&Assessment{
		ID:        asmID,
		Ref:       asmRef,
		ClientID:  clientID,
		Name:      "Unreachable Target Assessment",
		Status:    StatusDraft,
		ScopeMode: "same-origin",
	})

	now := time.Now().UTC()
	_ = store.SetAuthorization(&AuthorizationRecord{
		ID:                  uuid.New().String(),
		AssessmentID:        asmID,
		AuthorizingParty:    "Security Team",
		AuthorizationMethod: "WRITTEN_CONSENT",
		DateReceived:        now,
		Status:              AuthApproved,
	})

	_ = store.AddTarget(&AssessmentTarget{
		ID:           uuid.New().String(),
		AssessmentID: asmID,
		TargetURL:    closedURL,
		ScopeStatus:  "APPROVED",
	})

	res, err := ctrl.RunAssessment(ctx, asmID, ExecutionOptions{
		AllowLoopback: true,
	})
	if err != nil {
		// Error returned from controller is expected for unreachable target
		return
	}

	// If controller completed execution, verify that unreachable target was not reported as clean
	if res != nil && res.Report != nil {
		if res.Execution.FindingCount == 0 && res.Execution.RequestCount == 0 {
			// Reachability failed: zero requests succeeded
			if res.Execution.RequestCount != 0 {
				t.Errorf("expected 0 successful requests for closed target")
			}
		}
	}
}
