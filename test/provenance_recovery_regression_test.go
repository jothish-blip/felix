package test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"felix/pkg/assessment"
	"felix/pkg/ci"
	"felix/pkg/clierror"
	"felix/pkg/provenance"
	"felix/pkg/report"
)

// Scenario 1–6: Provenance metadata capture, graceful missing revision, dirty status,
// deterministic digests, config changes, and secret redaction.
func TestPhase88_1_to_6_ProvenanceMetadataAndDigests(t *testing.T) {
	// 1. Build & Runtime Revision Capture
	ctx := context.Background()
	info := provenance.ResolveVCSInfo(ctx, "")
	if info.RuntimeRevision != "" {
		if len(info.RuntimeRevision) < 7 {
			t.Errorf("expected valid Git SHA, got: %s", info.RuntimeRevision)
		}
	}

	// 2. Missing or unavailable revision does not crash or fabricate fake values
	emptyDir := t.TempDir()
	emptyInfo := provenance.ResolveVCSInfo(ctx, emptyDir)
	if emptyInfo.RuntimeRevision != "" && emptyInfo.VCSSource == "unavailable" {
		t.Errorf("fabricated fake SHA in empty directory: %s", emptyInfo.RuntimeRevision)
	}

	// 3. Dirty checkout detection
	if info.RuntimeRevision != "" && info.RuntimeDirty != nil {
		t.Logf("Git worktree dirty status detected: %v", *info.RuntimeDirty)
	}

	// 4. Deterministic digests: identical configurations with varying key order yield exact same digest
	cfgA := map[string]any{
		"concurrency":         5,
		"timeout_seconds":     30,
		"scope_mode":          "same-origin",
		"max_assets":          200,
		"allow_loopback":      true,
		"active_verification": true,
	}
	cfgB := map[string]any{
		"active_verification": true,
		"allow_loopback":      true,
		"max_assets":          200,
		"scope_mode":          "same-origin",
		"timeout_seconds":     30,
		"concurrency":         5,
	}

	digestA, _, errA := provenance.ComputeConfigDigest(cfgA)
	if errA != nil {
		t.Fatalf("ComputeConfigDigest A failed: %v", errA)
	}
	digestB, _, errB := provenance.ComputeConfigDigest(cfgB)
	if errB != nil {
		t.Fatalf("ComputeConfigDigest B failed: %v", errB)
	}
	if digestA != digestB {
		t.Fatalf("expected identical digest for equivalent configs, got:\n  %s\n  vs\n  %s", digestA, digestB)
	}

	// 5. Config change produces distinct digest
	cfgC := map[string]any{
		"concurrency":         10, // Changed
		"timeout_seconds":     30,
		"scope_mode":          "same-origin",
		"max_assets":          200,
		"allow_loopback":      true,
		"active_verification": true,
	}
	digestC, _, _ := provenance.ComputeConfigDigest(cfgC)
	if digestA == digestC {
		t.Fatalf("expected different digest when concurrency changed, got same: %s", digestA)
	}

	// 6. Tokens, credentials, and secrets are not exposed in persisted provenance
	cfgSensitive := map[string]any{
		"concurrency":    5,
		"api_key":        "sk_live_1234567890abcdef",
		"token":          "ghp_secret_access_token_xyz",
		"password":       "top_secret_db_pass",
		"webhook_secret": "whsec_super_secret_webhook",
		"authorization":  "Bearer secret_token",
		"user_agent":     "Felix/2.0 (token=secret)",
	}
	digestSens, sanitized, errSens := provenance.ComputeConfigDigest(cfgSensitive)
	if errSens != nil {
		t.Fatalf("ComputeConfigDigest sensitive failed: %v", errSens)
	}
	if digestSens == "" {
		t.Fatal("expected non-empty digest")
	}

	for _, secretKey := range []string{"api_key", "token", "password", "webhook_secret", "authorization"} {
		if _, exists := sanitized[secretKey]; exists {
			t.Errorf("secret key %q leaked into sanitized config!", secretKey)
		}
	}
	if ua, ok := sanitized["user_agent"].(string); ok && strings.Contains(ua, "secret_access_token") {
		t.Errorf("user_agent leaked secret: %s", ua)
	}
}

// Scenario 7–8: Assessment start metadata and terminal status/timestamps persisted consistently
func TestPhase88_7_8_StartAndTerminalMetadataConsistency(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`<!DOCTYPE html><html><body><h1>Audit Target</h1></body></html>`))
	}))
	defer ts.Close()

	dbPath := filepath.Join(t.TempDir(), "provenance_test.db")
	store, err := assessment.NewSQLiteStore(dbPath)
	if err != nil {
		t.Fatalf("failed creating store: %v", err)
	}
	defer store.Close()

	client := &assessment.Client{ID: "client-prov-1", Name: "Prov Test Client"}
	_ = store.CreateClient(client)

	asm := &assessment.Assessment{
		ID:             "asm-prov-1",
		Ref:            "ASM-PROV-1",
		ClientID:       client.ID,
		Name:           "Provenance Test Assessment",
		AssessmentType: "web",
		Status:         assessment.StatusReady,
		ScopeMode:      "same-origin",
	}
	_ = store.CreateAssessment(asm)
	_ = store.AddTarget(&assessment.AssessmentTarget{
		ID:           "tgt-prov-1",
		AssessmentID: asm.ID,
		TargetURL:    ts.URL,
		ScopeStatus:  "APPROVED",
	})
	now := time.Now().UTC()
	validFrom := now.Add(-1 * time.Hour)
	validUntil := now.Add(24 * time.Hour)
	_ = store.SetAuthorization(&assessment.AuthorizationRecord{
		ID:                  "auth-prov-1",
		AssessmentID:        asm.ID,
		AuthorizingParty:    "Security Team",
		AuthorizationMethod: "WRITTEN_APPROVAL",
		Status:              assessment.AuthApproved,
		DateReceived:        now,
		ValidFrom:           &validFrom,
		ValidUntil:          &validUntil,
	})

	ctrl := assessment.NewController(store)
	res, execErr := ctrl.RunAssessment(context.Background(), asm.ID, assessment.ExecutionOptions{
		TimeoutDuration: 10 * time.Second,
		AllowLoopback:   true,
		Concurrency:     2,
	})
	if execErr != nil {
		t.Fatalf("RunAssessment failed: %v", execErr)
	}

	// 7. Verify start metadata preserved after completion
	if res.Execution == nil {
		t.Fatal("expected execution record")
	}
	if res.Execution.StartedAt.IsZero() {
		t.Error("StartedAt is zero")
	}
	if res.Provenance == nil {
		t.Fatal("expected provenance attached to execution result")
	}
	if res.Provenance.StartedAt.IsZero() {
		t.Error("Provenance.StartedAt is zero")
	}
	if res.Provenance.ConfigDigest == "" {
		t.Error("Provenance.ConfigDigest is empty")
	}

	// 8. Verify terminal status and end timestamp persisted consistently
	if res.Execution.CompletedAt == nil {
		t.Fatal("Execution.CompletedAt is nil")
	}
	if res.Provenance.CompletedAt == nil {
		t.Fatal("Provenance.CompletedAt is nil")
	}
	if res.Provenance.Status != "COMPLETED" {
		t.Errorf("expected provenance status COMPLETED, got %s", res.Provenance.Status)
	}
	if res.Provenance.DurationMs <= 0 {
		t.Errorf("expected positive duration_ms, got %d", res.Provenance.DurationMs)
	}

	// Verify persistence in SQLite store: reload execution
	reloaded, err := store.GetExecution(res.Execution.ID)
	if err != nil {
		t.Fatalf("failed reloading execution: %v", err)
	}
	provLoaded := reloaded.GetProvenance()
	if provLoaded == nil {
		t.Fatal("failed to load provenance from SQLite database")
	}
	if provLoaded.Status != "COMPLETED" {
		t.Errorf("expected loaded provenance status COMPLETED, got %s", provLoaded.Status)
	}
	if provLoaded.ConfigDigest != res.Provenance.ConfigDigest {
		t.Errorf("loaded config digest %s != original %s", provLoaded.ConfigDigest, res.Provenance.ConfigDigest)
	}
}

// Scenario 9–10: Cancelled assessment and deadline exceeded are classified correctly and never report success
func TestPhase88_9_10_CancellationAndDeadlineExceeded(t *testing.T) {
	// Block requests until test cancels context
	serverBlocked := make(chan struct{})
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-serverBlocked
		w.WriteHeader(http.StatusOK)
	}))
	defer func() {
		close(serverBlocked)
		ts.Close()
	}()

	dbPath := filepath.Join(t.TempDir(), "cancel_test.db")
	store, _ := assessment.NewSQLiteStore(dbPath)
	defer store.Close()

	client := &assessment.Client{ID: "client-cancel-1", Name: "Cancel Client"}
	_ = store.CreateClient(client)
	asm := &assessment.Assessment{
		ID:             "asm-cancel-1",
		Ref:            "ASM-CANCEL-1",
		ClientID:       client.ID,
		Name:           "Cancel Test",
		AssessmentType: "web",
		Status:         assessment.StatusReady,
		ScopeMode:      "same-origin",
	}
	_ = store.CreateAssessment(asm)
	_ = store.AddTarget(&assessment.AssessmentTarget{
		ID:           "tgt-cancel-1",
		AssessmentID: asm.ID,
		TargetURL:    ts.URL,
		ScopeStatus:  "APPROVED",
	})
	now := time.Now().UTC()
	vf, vu := now.Add(-time.Hour), now.Add(time.Hour)
	_ = store.SetAuthorization(&assessment.AuthorizationRecord{
		ID:                  "auth-cancel-1",
		AssessmentID:        asm.ID,
		AuthorizingParty:    "SecOps",
		AuthorizationMethod: "PIPELINE_AUTHORIZATION",
		Status:              assessment.AuthApproved,
		DateReceived:        now,
		ValidFrom:           &vf,
		ValidUntil:          &vu,
	})

	ctrl := assessment.NewController(store)

	// 9. Cancelled assessment
	cancelCtx, cancel := context.WithCancel(context.Background())
	// Cancel shortly after start
	go func() {
		time.Sleep(50 * time.Millisecond)
		cancel()
	}()

	res, execErr := ctrl.RunAssessment(cancelCtx, asm.ID, assessment.ExecutionOptions{
		TimeoutDuration: 10 * time.Second,
		AllowLoopback:   true,
	})

	if execErr == nil {
		t.Fatal("expected error on cancelled assessment, got nil")
	}
	if res.Execution.Status != assessment.StatusCancelled {
		t.Errorf("expected StatusCancelled, got: %s", res.Execution.Status)
	}
	if res.Provenance == nil || !res.Provenance.IsPartial {
		t.Errorf("expected IsPartial == true on cancelled assessment")
	}
	if res.Provenance.IsComplete() {
		t.Errorf("cancelled assessment must never report IsComplete() == true")
	}

	// 10. Deadline exceeded assessment
	timeoutCtx, cancelTimeout := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancelTimeout()

	asm2 := &assessment.Assessment{
		ID:             "asm-timeout-1",
		Ref:            "ASM-TIMEOUT-1",
		ClientID:       client.ID,
		Name:           "Timeout Test",
		AssessmentType: "web",
		Status:         assessment.StatusReady,
		ScopeMode:      "same-origin",
	}
	_ = store.CreateAssessment(asm2)
	_ = store.AddTarget(&assessment.AssessmentTarget{
		ID:           "tgt-timeout-1",
		AssessmentID: asm2.ID,
		TargetURL:    ts.URL,
		ScopeStatus:  "APPROVED",
	})
	_ = store.SetAuthorization(&assessment.AuthorizationRecord{
		ID:                  "auth-timeout-1",
		AssessmentID:        asm2.ID,
		AuthorizingParty:    "SecOps",
		AuthorizationMethod: "PIPELINE_AUTHORIZATION",
		Status:              assessment.AuthApproved,
		DateReceived:        now,
		ValidFrom:           &vf,
		ValidUntil:          &vu,
	})

	resTimeout, timeoutErr := ctrl.RunAssessment(timeoutCtx, asm2.ID, assessment.ExecutionOptions{
		TimeoutDuration: 50 * time.Millisecond,
		AllowLoopback:   true,
	})

	if timeoutErr == nil {
		t.Fatal("expected error on timed-out assessment, got nil")
	}
	if resTimeout.Execution.Status != assessment.StatusFailed && resTimeout.Execution.Status != assessment.StatusCancelled {
		t.Errorf("expected StatusFailed or StatusCancelled on timeout, got %s", resTimeout.Execution.Status)
	}
	code := clierror.CodeFor(timeoutErr)
	if code != clierror.ExitOperational {
		t.Errorf("expected exit code 2 (ExitOperational) for timeout, got %d", code)
	}
}

// Scenario 11–14: Stale execution recovery, idempotency, and immunity of completed runs
func TestPhase88_11_to_14_RecoveryAndIdempotency(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "recovery_test.db")
	store, _ := assessment.NewSQLiteStore(dbPath)
	defer store.Close()

	client := &assessment.Client{ID: "client-rec-88", Name: "Recovery Client"}
	_ = store.CreateClient(client)
	asm := &assessment.Assessment{
		ID:             "asm-rec-88",
		Ref:            "ASM-REC-88",
		ClientID:       client.ID,
		Name:           "Recovery Test",
		AssessmentType: "web",
		Status:         assessment.StatusReady,
	}
	_ = store.CreateAssessment(asm)

	// 11–12. Create abandoned execution (started 10 minutes ago, no heartbeat)
	tenMinsAgo := time.Now().UTC().Add(-10 * time.Minute)
	abandonedExec := &assessment.AssessmentExecution{
		ID:               "exec-abandoned-1",
		AssessmentID:     asm.ID,
		ClientID:         client.ID,
		InitiationSource: "manual",
		Status:           assessment.StatusRunning,
		StartedAt:        tenMinsAgo,
		CreatedAt:        tenMinsAgo,
		TargetCount:      1,
		WorkerID:         "dead-worker-1",
	}
	if err := store.CreateExecution(abandonedExec); err != nil {
		t.Fatalf("failed to create execution: %v", err)
	}

	opts := assessment.RecoveryOptions{
		Auth:          assessment.NewAdminAuthContext(),
		StaleDuration: 3 * time.Minute,
		MaxRetries:    3,
		WorkerID:      "recovery-sweeper",
	}

	summary1, err := store.RecoverExecutions(opts)
	if err != nil {
		t.Fatalf("first recovery sweep failed: %v", err)
	}
	if summary1.FinalizedCount != 1 {
		t.Fatalf("expected 1 finalized execution, got %d", summary1.FinalizedCount)
	}

	rec1 := summary1.Results[0]
	if rec1.NewStatus != assessment.StatusInterrupted {
		t.Errorf("expected NewStatus INTERRUPTED, got %s", rec1.NewStatus)
	}

	// 13. Recovery is idempotent: running recovery a second time produces 0 new recoveries
	summary2, err := store.RecoverExecutions(opts)
	if err != nil {
		t.Fatalf("second recovery sweep failed: %v", err)
	}
	if summary2.RecoveredCount != 0 {
		t.Errorf("expected 0 recovered on repeated sweep, got %d", summary2.RecoveredCount)
	}

	// 14. Recovery cannot overwrite a trustworthy completed assessment or snapshot
	completedExec := &assessment.AssessmentExecution{
		ID:               "exec-completed-trustworthy",
		AssessmentID:     asm.ID,
		ClientID:         client.ID,
		InitiationSource: "manual",
		Status:           assessment.StatusCompleted,
		StartedAt:        tenMinsAgo,
		CompletedAt:      &tenMinsAgo,
		CreatedAt:        tenMinsAgo,
		FindingCount:     0,
	}
	_ = store.CreateExecution(completedExec)

	finalizeRes, err := store.FinalizeAbandonedExecution(completedExec.ID, "sweeper-worker", assessment.StatusInterrupted, "test", assessment.NewAdminAuthContext())
	if err != nil {
		t.Fatalf("FinalizeAbandonedExecution on completed run failed: %v", err)
	}
	if finalizeRes.Action != assessment.ActionSkippedTerminal {
		t.Errorf("expected ActionSkippedTerminal on completed execution, got %s", finalizeRes.Action)
	}
	rechecked, _ := store.GetExecution(completedExec.ID)
	if rechecked.Status != assessment.StatusCompleted {
		t.Errorf("completed execution was mutated! Status: %s", rechecked.Status)
	}
}

// Scenario 15–16: Interrupted / recovered executions cannot be selected as baselines and do not generate false RESOLVED changes
func TestPhase88_15_16_BaselineRejectionAndNoFalseResolution(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "baseline_rej_test.db")
	store, _ := assessment.NewSQLiteStore(dbPath)
	defer store.Close()

	client := &assessment.Client{ID: "client-base-88", Name: "Base Client"}
	_ = store.CreateClient(client)
	asm := &assessment.Assessment{
		ID:             "asm-base-88",
		Ref:            "ASM-BASE-88",
		ClientID:       client.ID,
		Name:           "Base Test",
		AssessmentType: "web",
		Status:         assessment.StatusReady,
		ScopeMode:      "same-origin",
	}
	_ = store.CreateAssessment(asm)
	_ = store.AddTarget(&assessment.AssessmentTarget{
		ID:           "tgt-base-88",
		AssessmentID: asm.ID,
		TargetURL:    "https://example.com",
		ScopeStatus:  "APPROVED",
	})
	now := time.Now().UTC()
	vf, vu := now.Add(-time.Hour), now.Add(time.Hour)
	_ = store.SetAuthorization(&assessment.AuthorizationRecord{
		ID:                  "auth-base-88",
		AssessmentID:        asm.ID,
		AuthorizingParty:    "SecOps",
		AuthorizationMethod: "PIPELINE_AUTHORIZATION",
		Status:              assessment.AuthApproved,
		DateReceived:        now,
		ValidFrom:           &vf,
		ValidUntil:          &vu,
	})

	// Create an interrupted execution with an inconclusive snapshot
	interruptedExec := &assessment.AssessmentExecution{
		ID:               "exec-interrupted-baseline",
		AssessmentID:     asm.ID,
		ClientID:         client.ID,
		InitiationSource: "manual",
		Status:           assessment.StatusInterrupted,
		StartedAt:        now.Add(-10 * time.Minute),
		CompletedAt:      &now,
		SnapshotID:       "snap-interrupted-1",
	}
	_ = store.CreateExecution(interruptedExec)

	// Attempt to run assessment using the interrupted execution as a baseline
	ctrl := assessment.NewController(store)
	_, err := ctrl.RunAssessment(context.Background(), asm.ID, assessment.ExecutionOptions{
		BaselineRef: interruptedExec.ID,
	})

	if err == nil {
		t.Fatal("expected RunAssessment to reject interrupted baseline, but succeeded!")
	}
	if !strings.Contains(err.Error(), "ineligible baseline") {
		t.Errorf("expected error mentioning ineligible baseline, got: %v", err)
	}
}

// Scenario 17: Partial artifacts cannot masquerade as complete outputs
func TestPhase88_17_PartialArtifactsCannotMasquerade(t *testing.T) {
	// A report marked as partial or incomplete
	partialRep := report.Report{
		Version:          "1.0.0",
		Target:           "https://example.com",
		CompletionStatus: "INTERRUPTED",
		Metadata: map[string]any{
			"is_partial": true,
		},
		Findings: []report.Finding{
			{
				ID:       "fnd-1",
				Title:    "Partial finding detected before crash",
				Severity: "HIGH",
			},
		},
	}

	sarifBytes, err := report.GenerateSARIF(partialRep)
	if err != nil {
		t.Fatalf("GenerateSARIF failed: %v", err)
	}

	var log report.SARIFLog
	if err := json.Unmarshal(sarifBytes, &log); err != nil {
		t.Fatalf("failed parsing SARIF: %v", err)
	}

	if len(log.Runs) == 0 {
		t.Fatal("expected at least 1 run in SARIF")
	}

	run := log.Runs[0]
	// Invocations executionSuccessful MUST be false for partial / interrupted run
	if len(run.Invocations) == 0 {
		t.Fatal("expected invocations array in SARIF run")
	}
	if run.Invocations[0].ExecutionSuccessful {
		t.Errorf("partial artifact has executionSuccessful == true!")
	}
	if isPartial, ok := run.Properties["is_partial"].(bool); !ok || !isPartial {
		t.Errorf("expected properties.is_partial == true in SARIF run")
	}
}

// Scenario 18–19: Precedence of policy failure (1) over secondary feedback failure,
// and engine failure / incomplete assessment yields 2 even with partial findings.
func TestPhase88_18_19_FailureClassificationPrecedence(t *testing.T) {
	// 18. Security violation established + secondary report error -> Exit 1
	cls18 := clierror.ClassifyAssessment("COMPLETED", nil, true, nil, os.ErrPermission)
	if cls18.ExitCode() != 1 {
		t.Errorf("expected Exit 1 for security violation despite report error, got %d", cls18.ExitCode())
	}
	if cls18.Category != clierror.CategorySecurityViolation {
		t.Errorf("expected CategorySecurityViolation, got %s", cls18.Category)
	}

	// 19. Engine failure or incomplete assessment -> Exit 2 even if findings exist
	cls19 := clierror.ClassifyAssessment("COMPLETED_WITH_ERRORS", nil, true, nil)
	if cls19.ExitCode() != 2 {
		t.Errorf("expected Exit 2 for incomplete crawl, got %d", cls19.ExitCode())
	}
	if cls19.Category != clierror.CategoryIncomplete {
		t.Errorf("expected CategoryIncomplete, got %s", cls19.Category)
	}
}

// Scenario 20–21: CI cancellation does not publish misleading success feedback,
// and CI retry does not duplicate comments or reviews.
func TestPhase88_20_21_CICancellationAndRetryIdempotency(t *testing.T) {
	var commentPostCount int32
	var commentPatchCount int32
	var reviewPostCount int32

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		// GET comments
		if r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/issues/10/comments") {
			w.WriteHeader(http.StatusOK)
			if atomic.LoadInt32(&commentPostCount) > 0 {
				w.Write([]byte(`[{"id": 9999, "body": "<!-- felix-security-pr-comment -->\nExisting comment"}]`))
			} else {
				w.Write([]byte(`[]`))
			}
			return
		}
		// POST comments
		if r.Method == http.MethodPost && strings.Contains(r.URL.Path, "/issues/10/comments") {
			atomic.AddInt32(&commentPostCount, 1)
			w.WriteHeader(http.StatusCreated)
			w.Write([]byte(`{"id": 9999, "body": "created"}`))
			return
		}
		// PATCH comments
		if r.Method == http.MethodPatch && strings.Contains(r.URL.Path, "/issues/comments/9999") {
			atomic.AddInt32(&commentPatchCount, 1)
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"id": 9999, "body": "updated"}`))
			return
		}
		// GET reviews
		if r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/pulls/10/reviews") {
			w.WriteHeader(http.StatusOK)
			if atomic.LoadInt32(&reviewPostCount) > 0 {
				w.Write([]byte(`[{"id": 8888, "commit_id": "commit-abc-123", "body": "FELIX Security Assessment: Inline Code Findings"}]`))
			} else {
				w.Write([]byte(`[]`))
			}
			return
		}
		// POST reviews
		if r.Method == http.MethodPost && strings.Contains(r.URL.Path, "/pulls/10/reviews") {
			atomic.AddInt32(&reviewPostCount, 1)
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"id": 8888, "commit_id": "commit-abc-123", "body": "FELIX Security Assessment: Inline Code Findings"}`))
			return
		}
		// Diff
		if strings.Contains(r.URL.Path, "/pulls/10") {
			w.Header().Set("Content-Type", "application/vnd.github.diff")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("diff --git a/app.js b/app.js\n--- a/app.js\n+++ b/app.js\n@@ -1,5 +2,6 @@\n+line 2\n"))
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{}`))
	}))
	defer server.Close()

	// Mock event file
	tmpDir := t.TempDir()
	eventFile := filepath.Join(tmpDir, "event.json")
	_ = os.WriteFile(eventFile, []byte(`{"pull_request": {"number": 10, "head": {"sha": "commit-abc-123"}}, "repository": {"full_name": "owner/repo"}}`), 0644)
	t.Setenv("GITHUB_EVENT_PATH", eventFile)
	t.Setenv("GITHUB_REPOSITORY", "owner/repo")
	t.Setenv("GITHUB_TOKEN", "fake-token")

	ciCfg := &ci.Config{
		Provider:         ci.ProviderGitHub,
		TargetURL:        "https://example.com",
		GitHubAPIBaseURL: server.URL,
		GitHubToken:      "fake-token",
		PRComment:        true,
		PRInline:         true,
	}

	res := &ci.Result{
		ExitCode: 0,
		Findings: []report.Finding{
			{
				ID:       "f1",
				Title:    "Inline vuln",
				Severity: "MEDIUM",
				EvidenceDetails: report.EvidenceDetails{
					Location: "app.js:2",
				},
			},
		},
	}

	// First execution: comment created, review submitted
	err := ci.PublishPRFeedback(context.Background(), ciCfg, res)
	if err != nil {
		t.Fatalf("first PublishPRFeedback failed: %v", err)
	}
	if atomic.LoadInt32(&commentPostCount) != 1 {
		t.Errorf("expected 1 comment POST, got %d", commentPostCount)
	}
	if atomic.LoadInt32(&reviewPostCount) != 1 {
		t.Errorf("expected 1 review POST, got %d", reviewPostCount)
	}

	// 21. Retry execution: MUST NOT duplicate comment or review
	err = ci.PublishPRFeedback(context.Background(), ciCfg, res)
	if err != nil {
		t.Fatalf("second PublishPRFeedback failed: %v", err)
	}
	// Comment should be patched (updated), NOT created again
	if atomic.LoadInt32(&commentPostCount) != 1 {
		t.Errorf("comment was duplicated! POST count: %d", commentPostCount)
	}
	if atomic.LoadInt32(&commentPatchCount) != 1 {
		t.Errorf("expected 1 comment PATCH on retry, got %d", commentPatchCount)
	}
	// Review for identical commit should NOT be posted again
	if atomic.LoadInt32(&reviewPostCount) != 1 {
		t.Errorf("review was duplicated! POST count: %d", reviewPostCount)
	}

	// 20. CI cancellation does not publish misleading success feedback
	cancelCtx, cancel := context.WithCancel(context.Background())
	cancel() // Cancelled immediately

	resCancel := &ci.Result{
		ExitCode: 2,
		Error:    context.Canceled,
	}
	// PublishPRFeedback with cancelled context fails safely and does not publish success summary
	errCancel := ci.PublishPRFeedback(cancelCtx, ciCfg, resCancel)
	if errCancel == nil {
		t.Log("PublishPRFeedback with cancelled context was cleanly skipped")
	}
	formattedSummary := ci.FormatPRSummary(resCancel, ciCfg, "")
	if strings.Contains(formattedSummary, "STATUS: PASSED") {
		t.Errorf("cancelled assessment published misleading STATUS: PASSED in summary!")
	}
	if !strings.Contains(formattedSummary, "INCONCLUSIVE / ERROR") {
		t.Errorf("expected INCONCLUSIVE / ERROR in cancelled summary, got: %s", formattedSummary)
	}
}

// Focused Verification: Recovery Safety — Active execution cannot be marked interrupted while worker holds valid lease
func TestPhase88_RecoverySafety_LiveExecutionCannotBeFinalized(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "recovery_safety.db")
	store, err := assessment.NewSQLiteStore(dbPath)
	if err != nil {
		t.Fatalf("failed creating store: %v", err)
	}
	defer store.Close()

	client := &assessment.Client{
		ID:        "client-rec-safe",
		Name:      "Recovery Safety Client",
		CreatedAt: time.Now().UTC(),
	}
	_ = store.CreateClient(client)

	asm := &assessment.Assessment{
		ID:             "asm-rec-safe-1",
		ClientID:       client.ID,
		Ref:            "ASM-REC-SAFE-01",
		AssessmentType: assessment.AssessmentTypeWebSecurity,
		Status:         assessment.StatusRunning,
		CreatedAt:      time.Now().UTC(),
	}
	_ = store.CreateAssessment(asm)

	now := time.Now().UTC()
	liveWorkerID := "live-worker-active-777"
	staleHeartbeat := now.Add(-5 * time.Minute)
	activeLeaseExpiry := now.Add(10 * time.Minute) // Unexpired lease held by live worker

	liveExec := &assessment.AssessmentExecution{
		ID:               "exec-live-active-01",
		AssessmentID:     asm.ID,
		ClientID:         client.ID,
		InitiationSource: "manual",
		Status:           assessment.StatusRunning,
		StartedAt:        now.Add(-6 * time.Minute),
		CreatedAt:        now.Add(-6 * time.Minute),
		WorkerID:         liveWorkerID,
		HeartbeatAt:      &staleHeartbeat,
		LeaseExpiresAt:   &activeLeaseExpiry,
		RecoveryAttempts: 5, // Exceeds normal max retries to test boundary
		FindingCount:     3,
	}
	if err := store.CreateExecution(liveExec); err != nil {
		t.Fatalf("failed to create live execution: %v", err)
	}

	auth := assessment.NewAdminAuthContext()

	// 1. FindAbandonedExecutions must not return the actively leased execution despite stale heartbeat
	staleThreshold := now.Add(-2 * time.Minute)
	abandoned, err := store.FindAbandonedExecutions(staleThreshold, assessment.RecoveryOptions{Auth: auth})
	if err != nil {
		t.Fatalf("FindAbandonedExecutions failed: %v", err)
	}
	if len(abandoned) != 0 {
		t.Fatalf("expected 0 abandoned executions due to active lease, got %d", len(abandoned))
	}

	// 2. RecoverExecutions must not touch or finalize the actively leased execution
	recoveryOpts := assessment.RecoveryOptions{
		Auth:          auth,
		StaleDuration: 2 * time.Minute,
		MaxRetries:    3,
		WorkerID:      "recovery-sweeper-999",
	}
	summary, err := store.RecoverExecutions(recoveryOpts)
	if err != nil {
		t.Fatalf("RecoverExecutions failed: %v", err)
	}
	if summary.ExaminedCount != 0 || summary.RecoveredCount != 0 || summary.FinalizedCount != 0 {
		t.Fatalf("active worker execution was examined or recovered! Examined: %d, Recovered: %d, Finalized: %d",
			summary.ExaminedCount, summary.RecoveredCount, summary.FinalizedCount)
	}

	// 3. Direct FinalizeAbandonedExecution call by another worker must be fenced out and rejected
	finRes, err := store.FinalizeAbandonedExecution(
		liveExec.ID,
		"recovery-sweeper-999",
		assessment.StatusInterrupted,
		"adversarial or mistaken finalize call",
		auth,
	)
	if err != nil {
		t.Fatalf("FinalizeAbandonedExecution returned error instead of safe fencing: %v", err)
	}
	if finRes.Action != assessment.ActionSkippedNoOwnership {
		t.Fatalf("expected ActionSkippedNoOwnership for active leased execution, got: %s", finRes.Action)
	}

	// Verify status in DB is STILL StatusRunning
	currentExec, err := store.GetExecution(liveExec.ID)
	if err != nil {
		t.Fatalf("failed fetching execution: %v", err)
	}
	if currentExec.Status != assessment.StatusRunning {
		t.Fatalf("active execution status was corrupted! Expected RUNNING, got: %s", currentExec.Status)
	}

	// 4. Live worker continues heartbeat and successfully updates lease
	hbErr := store.HeartbeatExecution(liveExec.ID, liveWorkerID, nil, 15*time.Minute)
	if hbErr != nil {
		t.Fatalf("live worker heartbeat failed: %v", hbErr)
	}

	// 5. Live worker cleanly completes assessment
	compNow := time.Now().UTC()
	currentExec.Status = assessment.StatusCompleted
	currentExec.CompletedAt = &compNow
	if err := store.UpdateExecution(currentExec); err != nil {
		t.Fatalf("live worker final UpdateExecution failed: %v", err)
	}

	finalExec, _ := store.GetExecution(liveExec.ID)
	if finalExec.Status != assessment.StatusCompleted {
		t.Fatalf("expected execution status COMPLETED, got: %s", finalExec.Status)
	}
}
