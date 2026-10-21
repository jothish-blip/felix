package test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"felix/pkg/assessment"
	"felix/pkg/notify"
	"felix/pkg/report"
	"github.com/google/uuid"
	_ "modernc.org/sqlite"
)

// =============================================================================
// PHASE 7.8: CROSS-ENGINE MONITORING REGRESSION TEST SUITE
// Validates end-to-end execution, scheduling, recovery, duplicate prevention,
// change summaries, finding fingerprinting, and notifications across ALL
// supported assessment engines.
// =============================================================================

func helperNewCrossEngineStore(t *testing.T) (assessment.Store, func()) {
	t.Helper()
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, fmt.Sprintf("test_cross_engine_%d.db", time.Now().UnixNano()))
	store, err := assessment.NewSQLiteStore(dbPath)
	if err != nil {
		t.Fatalf("failed to create sqlite store: %v", err)
	}
	cleanup := func() {
		_ = store.Close()
	}
	return store, cleanup
}

func helperSetupAuthorizedAssessment(
	t *testing.T,
	store assessment.Store,
	asmType string,
	targetURL string,
	tenantID string,
) (*assessment.Client, *assessment.Assessment, *assessment.AssessmentTarget) {
	t.Helper()

	clientID := "client-" + uuid.New().String()[:8]
	if tenantID != "" {
		clientID = tenantID
	}
	client, _ := store.GetClient(clientID)
	if client == nil {
		client = &assessment.Client{
			ID:   clientID,
			Name: "Cross Engine Corp",
		}
		if err := store.CreateClient(client); err != nil {
			t.Fatalf("failed to create client: %v", err)
		}
	}

	asmID := "asm-" + uuid.New().String()[:8]
	asmRef := assessment.GenerateAssessmentRef()
	asm := &assessment.Assessment{
		ID:             asmID,
		Ref:            asmRef,
		ClientID:       client.ID,
		Name:           fmt.Sprintf("Assessment %s", asmType),
		AssessmentType: asmType,
		Status:         assessment.StatusReady,
		ScopeMode:      "same-origin",
	}
	if err := store.CreateAssessment(asm); err != nil {
		t.Fatalf("failed to create assessment: %v", err)
	}

	now := time.Now().UTC()
	yesterday := now.Add(-24 * time.Hour)
	tomorrow := now.Add(24 * time.Hour)
	authRec := &assessment.AuthorizationRecord{
		ID:                  "auth-" + uuid.New().String()[:8],
		AssessmentID:        asm.ID,
		AuthorizingParty:    "Security Team",
		AuthorizationMethod: "WRITTEN_CONSENT",
		DateReceived:        yesterday,
		ValidFrom:           &yesterday,
		ValidUntil:          &tomorrow,
		Status:              assessment.AuthApproved,
	}
	if err := store.SetAuthorization(authRec); err != nil {
		t.Fatalf("failed to set authorization: %v", err)
	}

	tgt := &assessment.AssessmentTarget{
		ID:           "tgt-" + uuid.New().String()[:8],
		AssessmentID: asm.ID,
		TargetURL:    targetURL,
		ScopeStatus:  "APPROVED",
	}
	if err := store.AddTarget(tgt); err != nil {
		t.Fatalf("failed to add target: %v", err)
	}

	return client, asm, tgt
}

// -----------------------------------------------------------------------------
// 1. Engine Resolution & Invocation
// -----------------------------------------------------------------------------

func TestCrossEngine_1_ResolutionAndInvocation(t *testing.T) {
	store, cleanup := helperNewCrossEngineStore(t)
	defer cleanup()

	ctrl := assessment.NewController(store)
	reg := ctrl.GetEngineRegistry()

	standardTypes := []string{
		assessment.AssessmentTypeWebSecurity,
		assessment.AssessmentTypeAPISecurity,
		assessment.AssessmentTypeWebVulnerability,
		assessment.AssessmentTypeSessionSecurity,
		assessment.AssessmentTypeCloudSecurity,
		assessment.AssessmentTypeBusinessLogic,
		assessment.AssessmentTypeBOLA,
		assessment.AssessmentTypeBFLA,
		assessment.AssessmentTypeBOPLA,
		assessment.AssessmentTypeWorkflow,
		assessment.AssessmentTypeFull,
	}

	for _, engType := range standardTypes {
		runner, err := reg.Get(engType)
		if err != nil {
			t.Errorf("failed to resolve standard engine %q: %v", engType, err)
			continue
		}
		if runner == nil {
			t.Errorf("runner for %q was nil", engType)
		}
		caps := runner.Capabilities()
		if assessment.NormalizeAssessmentType(caps.AssessmentType) != engType {
			t.Errorf("expected engine capability type %q, got %q", engType, caps.AssessmentType)
		}
		if len(caps.CoverageCategories) == 0 {
			t.Errorf("engine %q declared zero coverage categories", engType)
		}
	}

	aliasMap := map[string]string{
		"BLACK_BOX": assessment.AssessmentTypeWebSecurity,
		"WEB":       assessment.AssessmentTypeWebSecurity,
		"APISEC":    assessment.AssessmentTypeAPISecurity,
		"API_AUDIT": assessment.AssessmentTypeAPISecurity,
		"VULN":      assessment.AssessmentTypeWebVulnerability,
		"SESSION":   assessment.AssessmentTypeSessionSecurity,
		"CLOUD":     assessment.AssessmentTypeCloudSecurity,
		"BIZLOGIC":  assessment.AssessmentTypeBusinessLogic,
		"IDOR":      assessment.AssessmentTypeBOLA,
		"WORKFLOWS": assessment.AssessmentTypeWorkflow,
		"HYBRID":    assessment.AssessmentTypeFull,
	}

	for alias, expectedCanon := range aliasMap {
		runner, err := reg.Get(alias)
		if err != nil {
			t.Errorf("failed to resolve engine by alias %q: %v", alias, err)
			continue
		}
		if assessment.NormalizeAssessmentType(runner.Capabilities().AssessmentType) != expectedCanon {
			t.Errorf("alias %q resolved to %q, expected %q", alias, runner.Capabilities().AssessmentType, expectedCanon)
		}
	}

	// Register custom runner (e.g. mobile runner)
	customRunner := &mockCustomMobileRunner{}
	if err := ctrl.RegisterEngine(customRunner); err != nil {
		t.Fatalf("failed to register custom mobile runner: %v", err)
	}

	resolvedCustom, err := reg.Get("APK_MOBILE")
	if err != nil {
		t.Fatalf("failed to resolve custom mobile runner: %v", err)
	}
	if resolvedCustom.Capabilities().DisplayName != "Android Mobile APK Analyzer" {
		t.Errorf("unexpected display name: %s", resolvedCustom.Capabilities().DisplayName)
	}
}

type mockCustomMobileRunner struct{}

func (m *mockCustomMobileRunner) Capabilities() assessment.EngineCapabilities {
	return assessment.EngineCapabilities{
		AssessmentType:     assessment.AssessmentTypeAPKMobile,
		DisplayName:        "Android Mobile APK Analyzer",
		Aliases:            []string{"APK", "MOBILE"},
		CoverageCategories: []string{"apk_manifest", "apk_secrets", "apk_network"},
		SupportsCancellation: true,
	}
}

func (m *mockCustomMobileRunner) Execute(ctx context.Context, execCtx *assessment.EngineExecutionContext) (*assessment.EngineExecutionOutput, error) {
	out := &assessment.EngineExecutionOutput{
		AssessedTargets: execCtx.RunnableTargets,
		RequestCount:    5,
		ReportFindings: []report.Finding{
			{
				ID:       "apk-finding-1",
				RuleID:   "APK_DEBUGGABLE",
				Title:    "APK is configured as debuggable",
				Category: "apk_manifest",
				Severity: "HIGH",
			},
		},
	}
	if len(execCtx.RunnableTargets) > 0 {
		tgt := execCtx.TargetMap[execCtx.RunnableTargets[0]]
		for _, rf := range out.ReportFindings {
			out.AssessmentFindings = append(out.AssessmentFindings, assessment.ToAssessmentFinding(execCtx.Assessment.ID, execCtx.Execution.ID, tgt.ID, rf))
		}
	}
	return out, nil
}

// -----------------------------------------------------------------------------
// 2. Manual Execution Across Engines
// -----------------------------------------------------------------------------

func TestCrossEngine_2_ManualExecutionPersistence(t *testing.T) {
	store, cleanup := helperNewCrossEngineStore(t)
	defer cleanup()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ok","version":"1.0"}`))
	}))
	defer server.Close()

	ctrl := assessment.NewController(store)

	testEngines := []string{
		assessment.AssessmentTypeWebSecurity,
		assessment.AssessmentTypeAPISecurity,
		assessment.AssessmentTypeWebVulnerability,
		assessment.AssessmentTypeSessionSecurity,
		assessment.AssessmentTypeCloudSecurity,
	}

	for _, engType := range testEngines {
		_, asm, _ := helperSetupAuthorizedAssessment(t, store, engType, server.URL, "")

		opts := assessment.ExecutionOptions{
			AllowLoopback: true,
		}

		res, err := ctrl.RunAssessment(context.Background(), asm.ID, opts)
		if err != nil {
			t.Fatalf("[%s] RunAssessment failed: %v", engType, err)
		}

		if res.Execution == nil {
			t.Fatalf("[%s] expected non-nil execution", engType)
		}
		if res.Execution.Status != assessment.StatusCompleted {
			t.Errorf("[%s] expected status COMPLETED, got %s", engType, res.Execution.Status)
		}
		if res.Execution.AssessmentType != engType {
			t.Errorf("[%s] expected execution assessment type %s, got %s", engType, engType, res.Execution.AssessmentType)
		}
		if res.Execution.SnapshotID == "" {
			t.Errorf("[%s] expected non-empty SnapshotID", engType)
		}

		// Verify snapshot in store has honest coverage categories
		snap, err := store.GetSnapshot(res.Execution.SnapshotID, assessment.NewAdminAuthContext())
		if err != nil {
			t.Fatalf("[%s] failed to load snapshot: %v", engType, err)
		}
		cov := snap.GetCoveredCategories()
		if len(cov) == 0 {
			t.Errorf("[%s] expected non-empty covered categories in snapshot", engType)
		}

		// Verify assessment status was updated
		loadedAsm, err := store.GetAssessment(asm.ID)
		if err != nil {
			t.Fatalf("[%s] failed to load assessment: %v", engType, err)
		}
		if loadedAsm.Status != assessment.StatusCompleted {
			t.Errorf("[%s] expected assessment status COMPLETED, got %s", engType, loadedAsm.Status)
		}
	}
}

// -----------------------------------------------------------------------------
// 3. Scheduled Execution Across Engines
// -----------------------------------------------------------------------------

func TestCrossEngine_3_ScheduledExecutionAcrossEngines(t *testing.T) {
	store, cleanup := helperNewCrossEngineStore(t)
	defer cleanup()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"items":[]}`))
	}))
	defer server.Close()

	ctrl := assessment.NewController(store)
	scheduler := assessment.NewScheduler(store, ctrl, assessment.DefaultSchedulerConfig())

	enginesToSchedule := []string{
		assessment.AssessmentTypeAPISecurity,
		assessment.AssessmentTypeWebVulnerability,
		assessment.AssessmentTypeBusinessLogic,
	}

	now := time.Now().UTC()
	for _, engType := range enginesToSchedule {
		_, asm, _ := helperSetupAuthorizedAssessment(t, store, engType, server.URL, "")

		past := now.Add(-10 * time.Minute)
		sch := &assessment.AssessmentSchedule{
			ID:              "sch-" + uuid.New().String()[:8],
			Name:            "Scheduled " + engType,
			AssessmentID:    asm.ID,
			ClientID:        asm.ClientID,
			RecurrenceType:  assessment.RecurrenceInterval,
			RecurrenceExpr:  "@every 1h",
			IntervalSeconds: 3600,
			Timezone:        "UTC",
			IsEnabled:       true,
			NextDueAt:       past,
		}
		if err := store.CreateSchedule(sch, assessment.NewAdminAuthContext()); err != nil {
			t.Fatalf("[%s] failed to create schedule: %v", engType, err)
		}
	}

	// Trigger due schedules
	count, err := scheduler.RunDueSchedulesSync(context.Background(), now)
	if err != nil {
		t.Fatalf("RunDueSchedulesSync failed: %v", err)
	}

	if count != len(enginesToSchedule) {
		t.Fatalf("expected %d scheduled runs, got %d", len(enginesToSchedule), count)
	}

	// Verify dispatches and executions recorded in persistent history
	for _, engType := range enginesToSchedule {
		asmList, _ := store.ListAssessments("")
		for _, asm := range asmList {
			if asm.AssessmentType == engType {
				execs, err := store.ListExecutions(asm.ID)
				if err != nil || len(execs) == 0 {
					t.Fatalf("[%s] expected execution for scheduled assessment, got err=%v, count=%d", engType, err, len(execs))
				}
				exec := execs[0]
				if exec.InitiationSource != "scheduled" {
					t.Errorf("[%s] expected initiation source 'scheduled', got %s", engType, exec.InitiationSource)
				}
				if exec.Status != assessment.StatusCompleted {
					t.Errorf("[%s] expected status COMPLETED, got %s", engType, exec.Status)
				}
				if exec.AssessmentType != engType {
					t.Errorf("[%s] expected execution assessment type %s, got %s", engType, engType, exec.AssessmentType)
				}
			}
		}
	}
}

// -----------------------------------------------------------------------------
// 4. Duplicate Prevention Across Engines
// -----------------------------------------------------------------------------

func TestCrossEngine_4_DuplicatePreventionAcrossEngines(t *testing.T) {
	store, cleanup := helperNewCrossEngineStore(t)
	defer cleanup()

	ctrl := assessment.NewController(store)

	_, asm, _ := helperSetupAuthorizedAssessment(t, store, assessment.AssessmentTypeAPISecurity, "http://127.0.0.1:8080", "")

	// 1. Create an active running execution
	now := time.Now().UTC()
	leaseExp := now.Add(5 * time.Minute)
	runningExec := &assessment.AssessmentExecution{
		ID:             "exec-active-overlap-test",
		AssessmentID:   asm.ID,
		ClientID:       asm.ClientID,
		AssessmentType: asm.AssessmentType,
		Status:         assessment.StatusRunning,
		StartedAt:      now,
		CreatedAt:      now,
		WorkerID:       "worker-active-1",
		LeaseExpiresAt: &leaseExp,
	}
	if err := store.CreateExecution(runningExec); err != nil {
		t.Fatalf("failed to create running execution: %v", err)
	}

	// 2. Attempt duplicate execution
	_, err := ctrl.RunAssessment(context.Background(), asm.ID, assessment.ExecutionOptions{})
	if err == nil || !errors.Is(err, assessment.ErrExecutionOverlap) {
		t.Fatalf("expected ErrExecutionOverlap for concurrent run, got: %v", err)
	}

	// 3. Request Idempotency Key test
	idempKey := "idemp-key-test-123"
	completedExec := &assessment.AssessmentExecution{
		ID:             "exec-idemp-completed",
		AssessmentID:   asm.ID,
		ClientID:       asm.ClientID,
		AssessmentType: asm.AssessmentType,
		Status:         assessment.StatusCompleted,
		StartedAt:      now,
		CreatedAt:      now,
		IdempotencyKey: idempKey,
	}
	if err := store.CreateExecution(completedExec); err != nil {
		t.Fatalf("failed to create completed execution: %v", err)
	}

	// Invoking with same idempotency key must safely return existing execution
	res, err := ctrl.RunAssessment(context.Background(), asm.ID, assessment.ExecutionOptions{
		IdempotencyKey: idempKey,
	})
	if err != nil {
		t.Fatalf("idempotent RunAssessment failed: %v", err)
	}
	if res.Execution.ID != completedExec.ID {
		t.Errorf("expected idempotent execution %s, got %s", completedExec.ID, res.Execution.ID)
	}
}

// -----------------------------------------------------------------------------
// 5. Engine Failure Isolation
// -----------------------------------------------------------------------------

func TestCrossEngine_5_EngineFailureIsolation(t *testing.T) {
	store, cleanup := helperNewCrossEngineStore(t)
	defer cleanup()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{}`))
	}))
	defer server.Close()

	ctrl := assessment.NewController(store)

	// Register a failing engine
	failingRunner := &mockFailingRunner{err: errors.New("simulated fatal engine crash")}
	if err := ctrl.RegisterEngine(failingRunner); err != nil {
		t.Fatalf("failed to register failing runner: %v", err)
	}

	// Assessment 1: Uses failing runner
	_, asmA, _ := helperSetupAuthorizedAssessment(t, store, "FAILING_ENGINE", "http://127.0.0.1:9999", "")
	resA, errA := ctrl.RunAssessment(context.Background(), asmA.ID, assessment.ExecutionOptions{})
	if errA == nil {
		t.Fatalf("expected failure from failing engine, got nil")
	}
	if resA != nil && resA.Execution != nil && resA.Execution.Status != assessment.StatusFailed {
		t.Errorf("expected execution A status FAILED, got %s", resA.Execution.Status)
	}

	// Assessment 2: Uses standard API Security engine against healthy server
	_, asmB, _ := helperSetupAuthorizedAssessment(t, store, assessment.AssessmentTypeAPISecurity, server.URL, "")
	resB, errB := ctrl.RunAssessment(context.Background(), asmB.ID, assessment.ExecutionOptions{AllowLoopback: true})
	if errB != nil {
		t.Fatalf("healthy assessment B failed due to engine failure bleed: %v", errB)
	}
	if resB.Execution.Status != assessment.StatusCompleted {
		t.Errorf("expected execution B status COMPLETED, got %s", resB.Execution.Status)
	}
}

type mockFailingRunner struct {
	err error
}

func (m *mockFailingRunner) Capabilities() assessment.EngineCapabilities {
	return assessment.EngineCapabilities{
		AssessmentType:     "FAILING_ENGINE",
		DisplayName:        "Simulated Failing Engine",
		CoverageCategories: []string{"failure_test"},
	}
}

func (m *mockFailingRunner) Execute(ctx context.Context, execCtx *assessment.EngineExecutionContext) (*assessment.EngineExecutionOutput, error) {
	return nil, m.err
}

// -----------------------------------------------------------------------------
// 6. Truthful Failure / Partial-Success Reporting
// -----------------------------------------------------------------------------

func TestCrossEngine_6_HonestStatusReporting(t *testing.T) {
	store, cleanup := helperNewCrossEngineStore(t)
	defer cleanup()

	ctrl := assessment.NewController(store)

	// Mock runner that fails target-2 but passes target-1
	partialRunner := &mockPartialTargetRunner{}
	_ = ctrl.RegisterEngine(partialRunner)

	_, asm, _ := helperSetupAuthorizedAssessment(t, store, "PARTIAL_ENGINE", "http://target1.local", "")
	// Add second target
	_ = store.AddTarget(&assessment.AssessmentTarget{
		ID:           "tgt-2",
		AssessmentID: asm.ID,
		TargetURL:    "http://target2.local",
		ScopeStatus:  "APPROVED",
	})

	res, err := ctrl.RunAssessment(context.Background(), asm.ID, assessment.ExecutionOptions{})
	if err != nil {
		t.Fatalf("unexpected RunAssessment error: %v", err)
	}

	// When 1 of 2 targets fails: status must be COMPLETED_WITH_ERRORS
	if res.Execution.Status != assessment.StatusCompletedWithErrors {
		t.Errorf("expected status COMPLETED_WITH_ERRORS, got %s", res.Execution.Status)
	}

	snap, err := store.GetSnapshot(res.Execution.SnapshotID, assessment.NewAdminAuthContext())
	if err != nil {
		t.Fatalf("failed to load snapshot: %v", err)
	}
	if len(snap.GetAssessedTargets()) != 1 || len(snap.GetFailedTargets()) != 1 {
		t.Errorf("expected 1 assessed and 1 failed target, got %d assessed, %d failed",
			len(snap.GetAssessedTargets()), len(snap.GetFailedTargets()))
	}
}

type mockPartialTargetRunner struct{}

func (m *mockPartialTargetRunner) Capabilities() assessment.EngineCapabilities {
	return assessment.EngineCapabilities{
		AssessmentType:     "PARTIAL_ENGINE",
		DisplayName:        "Mock Partial Target Runner",
		CoverageCategories: []string{"partial_test"},
	}
}

func (m *mockPartialTargetRunner) Execute(ctx context.Context, execCtx *assessment.EngineExecutionContext) (*assessment.EngineExecutionOutput, error) {
	out := &assessment.EngineExecutionOutput{
		TargetErrors: make(map[string]string),
	}
	for i, t := range execCtx.RunnableTargets {
		if i == 0 {
			out.AssessedTargets = append(out.AssessedTargets, t)
			out.ReportFindings = append(out.ReportFindings, report.Finding{
				ID:       "fnd-1",
				RuleID:   "PARTIAL_RULE",
				Category: "partial_test",
				Severity: "LOW",
				Target:   t,
			})
			tgt := execCtx.TargetMap[t]
			out.AssessmentFindings = append(out.AssessmentFindings, assessment.ToAssessmentFinding(execCtx.Assessment.ID, execCtx.Execution.ID, tgt.ID, out.ReportFindings[0]))
		} else {
			out.FailedTargets = append(out.FailedTargets, t)
			out.TargetErrors[t] = "connection refused on target"
		}
	}
	return out, nil
}

// -----------------------------------------------------------------------------
// 7. Cancellation & Timeout
// -----------------------------------------------------------------------------

func TestCrossEngine_7_CancellationAndTimeout(t *testing.T) {
	store, cleanup := helperNewCrossEngineStore(t)
	defer cleanup()

	ctrl := assessment.NewController(store)

	slowRunner := &mockSlowEngineRunner{delay: 500 * time.Millisecond}
	_ = ctrl.RegisterEngine(slowRunner)

	_, asmCancel, _ := helperSetupAuthorizedAssessment(t, store, "SLOW_ENGINE", "http://slow1.local", "")
	_, asmTimeout, _ := helperSetupAuthorizedAssessment(t, store, "SLOW_ENGINE", "http://slow2.local", "")

	// 1. Context Cancellation
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(50 * time.Millisecond)
		cancel()
	}()

	res, err := ctrl.RunAssessment(ctx, asmCancel.ID, assessment.ExecutionOptions{})
	if err == nil || !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled error, got: %v", err)
	}
	if res.Execution.Status != assessment.StatusCancelled {
		t.Errorf("expected execution status CANCELLED, got %s", res.Execution.Status)
	}

	// 2. Timeout / DeadlineExceeded
	timeoutCtx, timeoutCancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer timeoutCancel()

	resTimeout, errTimeout := ctrl.RunAssessment(timeoutCtx, asmTimeout.ID, assessment.ExecutionOptions{})
	if errTimeout == nil || !errors.Is(errTimeout, context.DeadlineExceeded) {
		t.Fatalf("expected context.DeadlineExceeded error, got: %v", errTimeout)
	}
	if resTimeout.Execution.Status != assessment.StatusFailed {
		t.Errorf("expected execution status FAILED for deadline exceeded, got %s", resTimeout.Execution.Status)
	}
	if !strings.Contains(resTimeout.Execution.ErrorMessage, "deadline exceeded") {
		t.Errorf("expected timeout message in execution, got: %s", resTimeout.Execution.ErrorMessage)
	}
}

type mockSlowEngineRunner struct {
	delay time.Duration
}

func (m *mockSlowEngineRunner) Capabilities() assessment.EngineCapabilities {
	return assessment.EngineCapabilities{
		AssessmentType:       "SLOW_ENGINE",
		DisplayName:          "Mock Slow Engine Runner",
		CoverageCategories:   []string{"slow_test"},
		SupportsCancellation: true,
	}
}

func (m *mockSlowEngineRunner) Execute(ctx context.Context, execCtx *assessment.EngineExecutionContext) (*assessment.EngineExecutionOutput, error) {
	select {
	case <-time.After(m.delay):
		return &assessment.EngineExecutionOutput{
			AssessedTargets: execCtx.RunnableTargets,
		}, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// -----------------------------------------------------------------------------
// 8. Recovery Respects Checkpoint Capabilities
// -----------------------------------------------------------------------------

func TestCrossEngine_8_RecoveryRespectsCheckpointCapabilities(t *testing.T) {
	store, cleanup := helperNewCrossEngineStore(t)
	defer cleanup()

	now := time.Now().UTC()
	tenMinsAgo := now.Add(-10 * time.Minute)

	// Case A: WebSecurity (supports checkpoint resume)
	_, asmWeb, _ := helperSetupAuthorizedAssessment(t, store, assessment.AssessmentTypeWebSecurity, "http://target1.local", "")
	chk := assessment.ScanCheckpoint{
		Stage:            "CRAWL_PARTIAL",
		CompletedTargets: []string{"http://target1.local"},
		RemainingTargets: []string{"http://target2.local"},
		FindingsCount:    2,
	}
	chkJ, _ := json.Marshal(chk)
	webExec := &assessment.AssessmentExecution{
		ID:               "exec-abandoned-web",
		AssessmentID:     asmWeb.ID,
		ClientID:         asmWeb.ClientID,
		AssessmentType:   assessment.AssessmentTypeWebSecurity,
		Status:           assessment.StatusRunning,
		StartedAt:        tenMinsAgo,
		CreatedAt:        tenMinsAgo,
		WorkerID:         "worker-died-web",
		CheckpointJSON:   string(chkJ),
	}
	_ = store.CreateExecution(webExec)

	// Case B: APISecurity (does NOT support checkpoint resume)
	_, asmAPI, _ := helperSetupAuthorizedAssessment(t, store, assessment.AssessmentTypeAPISecurity, "http://api.local", "")
	apiExec := &assessment.AssessmentExecution{
		ID:               "exec-abandoned-api",
		AssessmentID:     asmAPI.ID,
		ClientID:         asmAPI.ClientID,
		AssessmentType:   assessment.AssessmentTypeAPISecurity,
		Status:           assessment.StatusRunning,
		StartedAt:        tenMinsAgo,
		CreatedAt:        tenMinsAgo,
		WorkerID:         "worker-died-api",
		CheckpointJSON:   string(chkJ), // Has checkpoint JSON, but engine does NOT support checkpoint resume!
	}
	_ = store.CreateExecution(apiExec)

	mockRunnerCalled := false
	mockRunner := func(ctx context.Context, assessmentID string, opts assessment.ExecutionOptions) (*assessment.ExecutionResult, error) {
		mockRunnerCalled = true
		exec, _ := store.GetExecution(opts.ExecutionID)
		if exec != nil {
			exec.Status = assessment.StatusCompleted
			_ = store.UpdateExecution(exec)
		}
		return &assessment.ExecutionResult{
			Execution: &assessment.AssessmentExecution{
				ID:           opts.ExecutionID,
				AssessmentID: assessmentID,
				Status:       assessment.StatusCompleted,
			},
		}, nil
	}

	opts := assessment.RecoveryOptions{
		Auth:          assessment.NewAdminAuthContext(),
		WorkerID:      "recovery-worker-1",
		AllowResume:   true,
		Runner:        mockRunner,
		StaleDuration: 5 * time.Minute,
	}

	summary, err := store.RecoverExecutions(opts)
	if err != nil {
		t.Fatalf("RecoverExecutions failed: %v", err)
	}

	if summary.RecoveredCount < 2 {
		t.Fatalf("expected at least 2 recovered executions, got %d", summary.RecoveredCount)
	}

	// Verify WebSecurity was safely resumed
	webRec, _ := store.GetExecution(webExec.ID)
	if webRec.Status != assessment.StatusCompleted {
		t.Errorf("expected resumed web execution status COMPLETED, got %s", webRec.Status)
	}
	if !mockRunnerCalled {
		t.Errorf("expected runner to be called for web execution resumption")
	}

	// Verify APISecurity was safely finalized as INTERRUPTED (not resumed!)
	apiRec, _ := store.GetExecution(apiExec.ID)
	if apiRec.Status != assessment.StatusInterrupted {
		t.Errorf("expected non-resumable API execution status INTERRUPTED, got %s", apiRec.Status)
	}
	if !strings.Contains(apiRec.RecoveryReason, "does not support checkpoint resumption") {
		t.Errorf("expected reason explaining checkpoint incompatibility, got: %s", apiRec.RecoveryReason)
	}
}

// -----------------------------------------------------------------------------
// 9. Stale Worker Lease Fencing
// -----------------------------------------------------------------------------

func TestCrossEngine_9_StaleWorkerLeaseFencing(t *testing.T) {
	store, cleanup := helperNewCrossEngineStore(t)
	defer cleanup()

	ctrl := assessment.NewController(store)

	_, asm, _ := helperSetupAuthorizedAssessment(t, store, assessment.AssessmentTypeSessionSecurity, "http://127.0.0.1:8080", "")

	now := time.Now().UTC()
	leaseExp := now.Add(1 * time.Minute)
	exec := &assessment.AssessmentExecution{
		ID:             "exec-fencing-test",
		AssessmentID:   asm.ID,
		ClientID:       asm.ClientID,
		AssessmentType: asm.AssessmentType,
		Status:         assessment.StatusRunning,
		StartedAt:      now,
		CreatedAt:      now,
		WorkerID:       "worker-original",
		LeaseExpiresAt: &leaseExp,
	}
	if err := store.CreateExecution(exec); err != nil {
		t.Fatalf("failed to create execution: %v", err)
	}

	// Recovery claims ownership
	won, err := store.ClaimAbandonedExecutionForRecovery(exec.ID, "worker-recovery", now.Add(2*time.Minute), 5*time.Minute)
	if err != nil || !won {
		t.Fatalf("recovery claim failed: won=%v, err=%v", won, err)
	}

	// Original worker attempts heartbeat -> must be rejected with ErrLeaseLost
	hbErr := store.HeartbeatExecution(exec.ID, "worker-original", nil, 5*time.Minute)
	if hbErr == nil || !errors.Is(hbErr, assessment.ErrLeaseLost) {
		t.Fatalf("expected ErrLeaseLost for stale worker, got: %v", hbErr)
	}

	_ = ctrl // Controller utilizes store.HeartbeatExecution
}

// -----------------------------------------------------------------------------
// 10. Finding Fingerprint Stability
// -----------------------------------------------------------------------------

func TestCrossEngine_10_FindingFingerprintStability(t *testing.T) {
	rawFindings := []report.Finding{
		{
			RuleID:   "API1_BOLA",
			Title:    "Unauthorized access to user profile endpoint",
			Category: "api1_bola",
			Severity: "HIGH",
			Target:   "https://api.example.com",
			Endpoint: "/api/v1/users/{id}",
			Method:   "GET",
		},
		{
			RuleID:   "SEC_AWS_KEY",
			Title:    "AWS Access Key Identified in Source",
			Category: "secrets",
			Severity: "CRITICAL",
			Target:   "https://web.example.com",
			Endpoint: "/app.js",
			Method:   "GET",
		},
		{
			RuleID:   "CLOUD_S3_OPEN",
			Title:    "Publicly Readable S3 Storage Bucket",
			Category: "cloud",
			Severity: "HIGH",
			Target:   "https://bucket.s3.amazonaws.com",
			Endpoint: "/",
			Method:   "GET",
		},
	}

	for _, rf := range rawFindings {
		af1 := assessment.ToAssessmentFinding("asm-1", "exec-1", "tgt-1", rf)
		af2 := assessment.ToAssessmentFinding("asm-1", "exec-2", "tgt-1", rf)

		if af1.Fingerprint == "" {
			t.Fatalf("[%s] expected non-empty fingerprint", rf.RuleID)
		}
		if af1.Fingerprint != af2.Fingerprint {
			t.Errorf("[%s] fingerprint changed across executions: %s != %s", rf.RuleID, af1.Fingerprint, af2.Fingerprint)
		}
	}

	// Collision freedom check
	fpSet := make(map[string]string)
	for _, rf := range rawFindings {
		af := assessment.ToAssessmentFinding("asm-1", "exec-1", "tgt-1", rf)
		if existingRule, exists := fpSet[af.Fingerprint]; exists {
			t.Errorf("fingerprint collision between %s and %s: %s", rf.RuleID, existingRule, af.Fingerprint)
		}
		fpSet[af.Fingerprint] = rf.RuleID
	}
}

// -----------------------------------------------------------------------------
// 11. Incompatible Engine Comparison Rejection
// -----------------------------------------------------------------------------

func TestCrossEngine_11_IncompatibleEngineComparisonRejection(t *testing.T) {
	store, cleanup := helperNewCrossEngineStore(t)
	defer cleanup()

	auth := assessment.NewAdminAuthContext()

	// 1. Setup baseline execution: CLOUD_SECURITY
	_, asmCloud, tgtCloud := helperSetupAuthorizedAssessment(t, store, assessment.AssessmentTypeCloudSecurity, "https://cloud.example.com", "tenant-alpha")
	now := time.Now().UTC()
	execCloud := &assessment.AssessmentExecution{
		ID:             "exec-base-cloud",
		AssessmentID:   asmCloud.ID,
		ClientID:       asmCloud.ClientID,
		TenantID:       "tenant-alpha",
		AssessmentType: assessment.AssessmentTypeCloudSecurity,
		Status:         assessment.StatusCompleted,
		StartedAt:      now.Add(-2 * time.Hour),
		CreatedAt:      now.Add(-2 * time.Hour),
	}
	_ = store.CreateExecution(execCloud)

	cloudFinding := assessment.ToAssessmentFinding(asmCloud.ID, execCloud.ID, tgtCloud.ID, report.Finding{
		ID:       "cloud-fnd-1",
		RuleID:   "CLOUD_BUCKET_OPEN",
		Category: "cloud",
		Title:    "Unrestricted Cloud Bucket",
		Severity: "HIGH",
	})
	_ = store.SaveFindings([]assessment.AssessmentFinding{cloudFinding})

	snapCloud := assessment.BuildAssessmentSnapshot(asmCloud, execCloud, []string{tgtCloud.TargetURL}, []assessment.AssessmentFinding{cloudFinding}, true)
	snapCloud.SetCoveredCategories([]string{"aws", "azure", "gcp", "cloud"})
	_ = store.CreateSnapshot(snapCloud, []assessment.AssessmentFinding{cloudFinding}, nil)
	execCloud.SnapshotID = snapCloud.ID
	_ = store.UpdateExecution(execCloud)

	// 2. Setup comparison execution: API_SECURITY on same tenant
	_, asmAPI, tgtAPI := helperSetupAuthorizedAssessment(t, store, assessment.AssessmentTypeAPISecurity, "https://api.example.com", "tenant-alpha")
	execAPI := &assessment.AssessmentExecution{
		ID:             "exec-curr-api",
		AssessmentID:   asmAPI.ID,
		ClientID:       asmAPI.ClientID,
		TenantID:       "tenant-alpha",
		AssessmentType: assessment.AssessmentTypeAPISecurity,
		Status:         assessment.StatusCompleted,
		StartedAt:      now.Add(-1 * time.Hour),
		CreatedAt:      now.Add(-1 * time.Hour),
	}
	_ = store.CreateExecution(execAPI)

	apiFinding := assessment.ToAssessmentFinding(asmAPI.ID, execAPI.ID, tgtAPI.ID, report.Finding{
		ID:       "api-fnd-1",
		RuleID:   "API_AUTH_BYPASS",
		Category: "api1_bola",
		Title:    "API Auth Bypass",
		Severity: "HIGH",
	})
	_ = store.SaveFindings([]assessment.AssessmentFinding{apiFinding})

	snapAPI := assessment.BuildAssessmentSnapshot(asmAPI, execAPI, []string{tgtAPI.TargetURL}, []assessment.AssessmentFinding{apiFinding}, true)
	snapAPI.SetCoveredCategories([]string{"api1_bola", "api2_broken_auth"})
	_ = store.CreateSnapshot(snapAPI, []assessment.AssessmentFinding{apiFinding}, nil)
	execAPI.SnapshotID = snapAPI.ID
	_ = store.UpdateExecution(execAPI)

	// Explicit comparison must fail closed with ErrIncompatibleAssessmentScope
	_, err := store.CompareExecutionHistory(execCloud.ID, execAPI.ID, auth)
	if err == nil || !errors.Is(err, assessment.ErrIncompatibleAssessmentScope) {
		t.Fatalf("expected ErrIncompatibleAssessmentScope for cross-engine comparison, got: %v", err)
	}

	// ChangeSummary explicit comparison must fail closed
	_, csErr := store.GetAssessmentChangeSummary(asmAPI.ID, execCloud.ID, execAPI.ID, auth)
	if csErr == nil || !errors.Is(csErr, assessment.ErrIncompatibleAssessmentScope) {
		t.Fatalf("expected ErrIncompatibleAssessmentScope in ChangeSummary, got: %v", csErr)
	}

	// Automatic baseline selection check:
	// If an assessment has prior executions of incompatible type, automatic baseline selection must skip them
	// and produce an initial execution summary (zero false resolutions).
	autoCS, autoErr := store.GetAssessmentChangeSummary(asmAPI.ID, "", execAPI.ID, auth)
	if autoErr != nil {
		t.Fatalf("automatic baseline summary failed: %v", autoErr)
	}
	if autoCS.BaselineExecutionID != "" {
		t.Errorf("expected no baseline selected for initial API execution, got: %s", autoCS.BaselineExecutionID)
	}
	if autoCS.Counts.Resolved > 0 {
		t.Errorf("false resolution detected: resolved count=%d", autoCS.Counts.Resolved)
	}

	// 3. Verify FULL composite scope cannot be compared with single-engine baseline
	execFull := &assessment.AssessmentExecution{
		ID:             "exec-full-comp",
		AssessmentID:   asmAPI.ID,
		ClientID:       asmAPI.ClientID,
		TenantID:       "tenant-alpha",
		AssessmentType: assessment.AssessmentTypeFull,
		Status:         assessment.StatusCompleted,
		StartedAt:      now.Add(-30 * time.Minute),
		CreatedAt:      now.Add(-30 * time.Minute),
	}
	_ = store.CreateExecution(execFull)

	_, fullCmpErr := store.CompareExecutionHistory(execAPI.ID, execFull.ID, auth)
	if fullCmpErr == nil || !errors.Is(fullCmpErr, assessment.ErrIncompatibleAssessmentScope) {
		t.Errorf("expected ErrIncompatibleAssessmentScope when comparing API vs FULL, got: %v", fullCmpErr)
	}

	_, fullSummaryErr := store.GetAssessmentChangeSummary(asmAPI.ID, execAPI.ID, execFull.ID, auth)
	if fullSummaryErr == nil || !errors.Is(fullSummaryErr, assessment.ErrIncompatibleAssessmentScope) {
		t.Errorf("expected ErrIncompatibleAssessmentScope when summarizing API vs FULL, got: %v", fullSummaryErr)
	}

	// Verify Snapshot Coverage check
	cov := snapAPI.Coverage()
	canResolve, reason := cov.CanResolveFinding(tgtCloud.TargetURL, nil, "cloud")
	if canResolve {
		t.Errorf("API coverage falsely permitted resolving a cloud category finding! Reason: %s", reason)
	}
}

// -----------------------------------------------------------------------------
// 12. Change Summary Agreement
// -----------------------------------------------------------------------------

func TestCrossEngine_12_ChangeSummaryAgreement(t *testing.T) {
	store, cleanup := helperNewCrossEngineStore(t)
	defer cleanup()

	auth := assessment.NewAdminAuthContext()

	_, asm, tgt := helperSetupAuthorizedAssessment(t, store, assessment.AssessmentTypeAPISecurity, "https://api.example.com", "tenant-cs")

	now := time.Now().UTC()
	comp1 := now.Add(-110 * time.Minute)
	exec1 := &assessment.AssessmentExecution{
		ID:             "exec-api-1",
		AssessmentID:   asm.ID,
		ClientID:       asm.ClientID,
		AssessmentType: asm.AssessmentType,
		Status:         assessment.StatusCompleted,
		StartedAt:      now.Add(-2 * time.Hour),
		CompletedAt:    &comp1,
		CreatedAt:      now.Add(-2 * time.Hour),
	}
	_ = store.CreateExecution(exec1)

	f1 := assessment.ToAssessmentFinding(asm.ID, exec1.ID, tgt.ID, report.Finding{
		ID:       "fnd-1",
		RuleID:   "API_1",
		Category: "api1_bola",
		Title:    "Persistent finding",
		Severity: "HIGH",
		Target:   tgt.TargetURL,
		Endpoint: "/api/v1/resource",
	})
	f2 := assessment.ToAssessmentFinding(asm.ID, exec1.ID, tgt.ID, report.Finding{
		ID:       "fnd-2",
		RuleID:   "API_2",
		Category: "api2_broken_auth",
		Title:    "Resolved finding",
		Severity: "MEDIUM",
		Target:   tgt.TargetURL,
		Endpoint: "/api/v1/auth",
	})
	_ = store.SaveFindings([]assessment.AssessmentFinding{f1, f2})

	snap1 := assessment.BuildAssessmentSnapshot(asm, exec1, []string{tgt.TargetURL}, []assessment.AssessmentFinding{f1, f2}, true)
	snap1.SetCoveredCategories([]string{"api1_bola", "api2_broken_auth"})
	_ = store.CreateSnapshot(snap1, []assessment.AssessmentFinding{f1, f2}, nil)
	exec1.SnapshotID = snap1.ID
	_ = store.UpdateExecution(exec1)

	// Second execution: f1 persists, f2 resolved, f3 is new
	comp2 := now.Add(-50 * time.Minute)
	exec2 := &assessment.AssessmentExecution{
		ID:             "exec-api-2",
		AssessmentID:   asm.ID,
		ClientID:       asm.ClientID,
		AssessmentType: asm.AssessmentType,
		Status:         assessment.StatusCompleted,
		StartedAt:      now.Add(-1 * time.Hour),
		CompletedAt:    &comp2,
		CreatedAt:      now.Add(-1 * time.Hour),
	}
	_ = store.CreateExecution(exec2)

	f1_exec2 := assessment.ToAssessmentFinding(asm.ID, exec2.ID, tgt.ID, report.Finding{
		ID:       "fnd-1",
		RuleID:   "API_1",
		Category: "api1_bola",
		Title:    "Persistent finding",
		Severity: "HIGH",
		Target:   tgt.TargetURL,
		Endpoint: "/api/v1/resource",
	})
	f3 := assessment.ToAssessmentFinding(asm.ID, exec2.ID, tgt.ID, report.Finding{
		ID:       "fnd-3",
		RuleID:   "API_3",
		Category: "api3_bopla",
		Title:    "New finding",
		Severity: "LOW",
		Target:   tgt.TargetURL,
		Endpoint: "/api/v1/property",
	})
	_ = store.SaveFindings([]assessment.AssessmentFinding{f1_exec2, f3})

	snap2 := assessment.BuildAssessmentSnapshot(asm, exec2, []string{tgt.TargetURL}, []assessment.AssessmentFinding{f1_exec2, f3}, true)
	snap2.SetCoveredCategories([]string{"api1_bola", "api2_broken_auth", "api3_bopla"})
	_ = store.CreateSnapshot(snap2, []assessment.AssessmentFinding{f1_exec2, f3}, nil)
	exec2.SnapshotID = snap2.ID
	_ = store.UpdateExecution(exec2)

	cs, err := store.GetAssessmentChangeSummary(asm.ID, exec1.ID, exec2.ID, auth)
	if err != nil {
		t.Fatalf("GetAssessmentChangeSummary failed: %v", err)
	}

	if cs.Counts.New != 1 {
		t.Errorf("expected 1 new finding, got %d", cs.Counts.New)
	}
	if cs.Counts.Resolved != 1 {
		t.Errorf("expected 1 resolved finding, got %d", cs.Counts.Resolved)
	}
	if cs.Counts.Persistent != 1 {
		t.Errorf("expected 1 persistent finding, got %d", cs.Counts.Persistent)
	}
}

// -----------------------------------------------------------------------------
// 13. Notification Outbox Generation Exactly Once
// -----------------------------------------------------------------------------

func TestCrossEngine_13_NotificationOutboxGeneration(t *testing.T) {
	store, cleanup := helperNewCrossEngineStore(t)
	defer cleanup()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{}`))
	}))
	defer server.Close()

	t.Setenv("FELIX_NOTIFY_ENABLED", "true")
	t.Setenv("FELIX_NOTIFY_LIFECYCLE", "completed,failed,completed_with_errors")
	t.Setenv("FELIX_NOTIFY_MIN_SEVERITY", "INFO")
	t.Setenv("FELIX_NOTIFY_WEBHOOK_URL", server.URL+"/webhook")
	t.Setenv("FELIX_NOTIFY_ALLOW_INSECURE_HTTP", "true")

	ctrl := assessment.NewController(store)

	testEngines := []string{
		assessment.AssessmentTypeAPISecurity,
		assessment.AssessmentTypeSessionSecurity,
		assessment.AssessmentTypeCloudSecurity,
	}

	for _, engType := range testEngines {
		_, asm, _ := helperSetupAuthorizedAssessment(t, store, engType, server.URL, "")

		res, err := ctrl.RunAssessment(context.Background(), asm.ID, assessment.ExecutionOptions{AllowLoopback: true})
		if err != nil {
			t.Fatalf("[%s] RunAssessment failed: %v", engType, err)
		}

		deliveries, err := store.ListNotifications(notify.NotificationFilter{
			AssessmentID: asm.ID,
			ExecutionID:  res.Execution.ID,
		}, assessment.NewAdminAuthContext())
		if err != nil {
			t.Fatalf("[%s] failed to list notifications: %v", engType, err)
		}
		if len(deliveries) != 1 {
			t.Errorf("[%s] expected exactly 1 notification outbox record, got %d", engType, len(deliveries))
		}
	}
}

// -----------------------------------------------------------------------------
// 14. Notification Failure Independence
// -----------------------------------------------------------------------------

func TestCrossEngine_14_NotificationFailureIndependence(t *testing.T) {
	store, cleanup := helperNewCrossEngineStore(t)
	defer cleanup()

	t.Setenv("FELIX_NOTIFY_ENABLED", "true")
	t.Setenv("FELIX_NOTIFY_LIFECYCLE", "completed,failed")
	t.Setenv("FELIX_NOTIFY_WEBHOOK_URL", "http://127.0.0.1:65530/dead-endpoint")
	t.Setenv("FELIX_NOTIFY_ALLOW_INSECURE_HTTP", "true")

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{}`))
	}))
	defer server.Close()

	ctrl := assessment.NewController(store)

	_, asm, _ := helperSetupAuthorizedAssessment(t, store, assessment.AssessmentTypeAPISecurity, server.URL, "")

	res, err := ctrl.RunAssessment(context.Background(), asm.ID, assessment.ExecutionOptions{AllowLoopback: true})
	if err != nil {
		t.Fatalf("RunAssessment failed despite notification failure independence: %v", err)
	}

	// Execution record and snapshot must be safely COMPLETED
	if res.Execution.Status != assessment.StatusCompleted {
		t.Errorf("expected execution status COMPLETED, got %s", res.Execution.Status)
	}
	if res.Snapshot == nil {
		t.Errorf("expected non-nil snapshot despite notification failure")
	}
}

// -----------------------------------------------------------------------------
// 15. Tenant Isolation Across All Engines
// -----------------------------------------------------------------------------

func TestCrossEngine_15_TenantIsolationAcrossEngines(t *testing.T) {
	store, cleanup := helperNewCrossEngineStore(t)
	defer cleanup()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{}`))
	}))
	defer server.Close()

	ctrl := assessment.NewController(store)

	// Tenant A: runs API security
	_, asmA, _ := helperSetupAuthorizedAssessment(t, store, assessment.AssessmentTypeAPISecurity, server.URL, "tenant-a")
	resA, _ := ctrl.RunAssessment(context.Background(), asmA.ID, assessment.ExecutionOptions{AllowLoopback: true, TenantID: "tenant-a"})

	// Tenant B: runs Cloud security
	_, asmB, _ := helperSetupAuthorizedAssessment(t, store, assessment.AssessmentTypeCloudSecurity, server.URL, "tenant-b")
	resB, _ := ctrl.RunAssessment(context.Background(), asmB.ID, assessment.ExecutionOptions{AllowLoopback: true, TenantID: "tenant-b"})

	authTenantB := assessment.NewTenantAuthContext("tenant-b", "tenant-b", "")

	// Tenant B attempting to read Tenant A's execution history -> denied
	_, err := store.GetExecutionHistory(resA.Execution.ID, authTenantB)
	if err == nil || !errors.Is(err, assessment.ErrExecutionUnauthorized) {
		t.Fatalf("expected ErrExecutionUnauthorized for cross-tenant execution read, got: %v", err)
	}

	// Tenant B attempting to compare against Tenant A's execution -> denied
	_, diffErr := store.CompareExecutionHistory(resA.Execution.ID, resB.Execution.ID, authTenantB)
	if diffErr == nil || !errors.Is(diffErr, assessment.ErrExecutionUnauthorized) {
		t.Fatalf("expected ErrExecutionUnauthorized for cross-tenant comparison, got: %v", diffErr)
	}
}

// -----------------------------------------------------------------------------
// 16. Unregistered / Unknown Assessment Type Fails
// -----------------------------------------------------------------------------

func TestCrossEngine_16_UnsupportedAssessmentTypeFails(t *testing.T) {
	store, cleanup := helperNewCrossEngineStore(t)
	defer cleanup()

	ctrl := assessment.NewController(store)

	_, asm, _ := helperSetupAuthorizedAssessment(t, store, "NONEXISTENT_AI_ENGINE_XYZ", "http://127.0.0.1:8080", "")

	res, err := ctrl.RunAssessment(context.Background(), asm.ID, assessment.ExecutionOptions{})
	if err == nil || !errors.Is(err, assessment.ErrUnsupportedAssessmentType) {
		t.Fatalf("expected ErrUnsupportedAssessmentType for unregistered engine, got: %v", err)
	}

	if res == nil || res.Execution == nil || res.Execution.Status != assessment.StatusFailed {
		t.Errorf("expected failed execution state recorded in database")
	}
}

// -----------------------------------------------------------------------------
// 17. Surfaced Engine Registration Errors
// -----------------------------------------------------------------------------

func TestCrossEngine_17_RegistrationErrorsSurfaced(t *testing.T) {
	reg := assessment.NewEngineRegistry()

	// 1. Nil runner
	if err := reg.Register(nil); err == nil {
		t.Errorf("expected error registering nil runner")
	}

	// 2. Empty AssessmentType
	emptyRunner := &mockInvalidRunner{emptyType: true}
	if err := reg.Register(emptyRunner); err == nil {
		t.Errorf("expected error registering runner with empty AssessmentType")
	}
}

type mockInvalidRunner struct {
	emptyType bool
}

func (m *mockInvalidRunner) Capabilities() assessment.EngineCapabilities {
	return assessment.EngineCapabilities{
		AssessmentType: "",
	}
}

func (m *mockInvalidRunner) Execute(ctx context.Context, execCtx *assessment.EngineExecutionContext) (*assessment.EngineExecutionOutput, error) {
	return nil, nil
}

// -----------------------------------------------------------------------------
// 18. Multi-Engine Comprehensive Workflow
// -----------------------------------------------------------------------------

func TestCrossEngine_18_MultiEngineEndToEndWorkflow(t *testing.T) {
	store, cleanup := helperNewCrossEngineStore(t)
	defer cleanup()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"online"}`))
	}))
	defer server.Close()

	ctrl := assessment.NewController(store)

	engines := []string{
		assessment.AssessmentTypeWebSecurity,
		assessment.AssessmentTypeAPISecurity,
		assessment.AssessmentTypeFull,
	}

	for _, engType := range engines {
		_, asm, _ := helperSetupAuthorizedAssessment(t, store, engType, server.URL, "")
		res, err := ctrl.RunAssessment(context.Background(), asm.ID, assessment.ExecutionOptions{AllowLoopback: true})
		if err != nil {
			t.Fatalf("[%s] end-to-end run failed: %v", engType, err)
		}
		if res.Execution.Status != assessment.StatusCompleted {
			t.Errorf("[%s] expected status COMPLETED, got %s", engType, res.Execution.Status)
		}
	}
}
