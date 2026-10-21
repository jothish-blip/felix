package test

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"felix/pkg/assessment"
	"felix/pkg/correlation"
	"felix/pkg/notify"
	"felix/pkg/report"
	"github.com/google/uuid"
	_ "modernc.org/sqlite"
)

// =============================================================================
// PHASE 7: CONTINUOUS MONITORING INTEGRATED VERIFICATION SUITE
// Validates the complete monitoring lifecycle, critical invariants, scheduling,
// recovery, duplicate prevention, finding deltas, change summaries, and alerts.
// =============================================================================

func helperNewPhase7Store(t *testing.T) (assessment.Store, func()) {
	t.Helper()
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, fmt.Sprintf("test_phase7_%d.db", time.Now().UnixNano()))
	store, err := assessment.NewSQLiteStore(dbPath)
	if err != nil {
		t.Fatalf("failed to create sqlite store: %v", err)
	}
	cleanup := func() {
		_ = store.Close()
	}
	return store, cleanup
}

func helperSetupPhase7Assessment(
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
			Name: "Phase 7 Monitoring Corp",
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
	future := now.Add(30 * 24 * time.Hour)
	authRec := &assessment.AuthorizationRecord{
		ID:                  "auth-" + uuid.New().String()[:8],
		AssessmentID:        asm.ID,
		AuthorizingParty:    "Security Team",
		AuthorizationMethod: "WRITTEN_CONSENT",
		DateReceived:        yesterday,
		ValidFrom:           &yesterday,
		ValidUntil:          &future,
		Status:              assessment.AuthApproved,
	}
	if err := store.SetAuthorization(authRec); err != nil {
		t.Fatalf("failed to set authorization: %v", err)
	}

	tgt := &assessment.AssessmentTarget{
		ID:           "tgt-" + uuid.New().String()[:8],
		AssessmentID: asm.ID,
		TargetURL:    targetURL,
		TargetType:   assessment.TargetWebsite,
		ScopeStatus:  "APPROVED",
		CreatedAt:    now,
	}
	if err := store.AddTarget(tgt); err != nil {
		t.Fatalf("failed to add target: %v", err)
	}

	return client, asm, tgt
}

// -----------------------------------------------------------------------------
// Scenario A: Healthy recurring monitoring
// -----------------------------------------------------------------------------

func TestPhase7_ScenarioA_HealthyRecurringMonitoring(t *testing.T) {
	store, cleanup := helperNewPhase7Store(t)
	defer cleanup()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"healthy","users":[{"id":1,"role":"admin"}]}`))
	}))
	defer server.Close()

	t.Setenv("FELIX_NOTIFY_ENABLED", "true")
	t.Setenv("FELIX_NOTIFY_LIFECYCLE", "completed,failed")
	t.Setenv("FELIX_NOTIFY_MIN_SEVERITY", "INFO")
	t.Setenv("FELIX_NOTIFY_WEBHOOK_URL", server.URL+"/webhook")
	t.Setenv("FELIX_NOTIFY_ALLOW_INSECURE_HTTP", "true")

	_, asm, _ := helperSetupPhase7Assessment(t, store, assessment.AssessmentTypeAPISecurity, server.URL, "tenant-a")
	authCtx := assessment.NewAdminAuthContext()

	// 1. Schedule the assessment
	now := time.Now().UTC()
	sch := &assessment.AssessmentSchedule{
		ID:             "sched-" + uuid.New().String()[:8],
		AssessmentID:   asm.ID,
		ClientID:       asm.ClientID,
		TenantID:       "tenant-a",
		Name:           "Daily API Security Audit",
		RecurrenceType: assessment.RecurrenceDaily,
		RecurrenceExpr: "00:00",
		Timezone:       "UTC",
		IsEnabled:      true,
		NextDueAt:      now,
		ExecutionOptions: assessment.ScheduleExecutionOptions{
			AllowLoopback: true,
		},
	}
	if err := store.CreateSchedule(sch, authCtx); err != nil {
		t.Fatalf("CreateSchedule failed: %v", err)
	}

	ctrl := assessment.NewController(store)
	sched := assessment.NewScheduler(store, ctrl, assessment.DefaultSchedulerConfig())

	// 2. Dispatch first scheduled occurrence
	dispatched1, err := sched.RunDueSchedulesSync(context.Background(), now)
	if err != nil {
		t.Fatalf("RunDueSchedulesSync occurrence 1 failed: %v", err)
	}
	if dispatched1 != 1 {
		t.Fatalf("expected 1 schedule dispatched, got %d", dispatched1)
	}

	// 3. Inspect first execution record, snapshot, and findings
	execs, err := store.ListExecutions(asm.ID)
	if err != nil || len(execs) != 1 {
		t.Fatalf("expected 1 execution record, got %d (err: %v)", len(execs), err)
	}
	exec1 := execs[0]
	if exec1.Status != assessment.StatusCompleted {
		t.Fatalf("expected execution status COMPLETED, got %s", exec1.Status)
	}
	if exec1.SnapshotID == "" {
		t.Fatalf("expected non-empty snapshot ID on first execution")
	}

	// Check notification outbox for occurrence 1
	notifs1, err := store.ListNotifications(notify.NotificationFilter{AssessmentID: asm.ID, ExecutionID: exec1.ID}, authCtx)
	if err != nil {
		t.Fatalf("failed listing notifications for exec 1: %v", err)
	}
	if len(notifs1) != 1 {
		t.Errorf("expected 1 notification outbox record for exec 1, got %d", len(notifs1))
	}

	// 4. Dispatch second occurrence 24 hours later
	tomorrow := now.Add(24 * time.Hour)
	dispatched2, err := sched.RunDueSchedulesSync(context.Background(), tomorrow)
	if err != nil {
		t.Fatalf("RunDueSchedulesSync occurrence 2 failed: %v", err)
	}
	if dispatched2 != 1 {
		t.Fatalf("expected 1 schedule dispatched for occurrence 2, got %d", dispatched2)
	}

	execsAfter, err := store.ListExecutions(asm.ID)
	if err != nil || len(execsAfter) != 2 {
		t.Fatalf("expected 2 execution records, got %d (err: %v)", len(execsAfter), err)
	}
	exec2 := execsAfter[0] // Latest first

	// 5. Generate Change Summary between the two consecutive executions
	cs, err := store.GetAssessmentChangeSummary(asm.ID, exec1.ID, exec2.ID, authCtx)
	if err != nil {
		t.Fatalf("GetAssessmentChangeSummary failed: %v", err)
	}
	if !cs.IsReliable {
		t.Errorf("expected reliable change summary, got false: %s", cs.ReliabilityReason)
	}
	if cs.Counts.TotalBaseline != cs.Counts.TotalComparison {
		t.Errorf("expected equal finding count across identical runs, got baseline=%d current=%d", cs.Counts.TotalBaseline, cs.Counts.TotalComparison)
	}
	if cs.Counts.Resolved > 0 {
		t.Errorf("expected 0 resolved findings on persistent healthy run, got %d", cs.Counts.Resolved)
	}

	// 6. Check notification outbox for occurrence 2
	notifs2, err := store.ListNotifications(notify.NotificationFilter{AssessmentID: asm.ID, ExecutionID: exec2.ID}, authCtx)
	if err != nil || len(notifs2) != 1 {
		t.Errorf("expected 1 notification outbox record for exec 2, got %d", len(notifs2))
	}
}

// -----------------------------------------------------------------------------
// Scenario B: Operational failure must not resolve findings
// -----------------------------------------------------------------------------

func TestPhase7_ScenarioB_OperationalFailureDoesNotResolveFindings(t *testing.T) {
	store, cleanup := helperNewPhase7Store(t)
	defer cleanup()

	auth := assessment.NewAdminAuthContext()
	_, asm, tgt := helperSetupPhase7Assessment(t, store, assessment.AssessmentTypeAPISecurity, "https://api.example.com", "tenant-b")

	now := time.Now().UTC()
	comp1 := now.Add(-110 * time.Minute)

	// Baseline execution: healthy, discovers fnd-1
	execBase := &assessment.AssessmentExecution{
		ID:             "exec-scen-b-base",
		AssessmentID:   asm.ID,
		ClientID:       asm.ClientID,
		TenantID:       "tenant-b",
		AssessmentType: assessment.AssessmentTypeAPISecurity,
		Status:         assessment.StatusCompleted,
		StartedAt:      now.Add(-2 * time.Hour),
		CompletedAt:    &comp1,
		CreatedAt:      now.Add(-2 * time.Hour),
	}
	_ = store.CreateExecution(execBase)

	fndBase := assessment.ToAssessmentFinding(asm.ID, execBase.ID, tgt.ID, report.Finding{
		ID:       "fnd-b-1",
		RuleID:   "API_BOLA_1",
		Category: "api1_bola",
		Title:    "Unauthorized Object Access",
		Severity: report.SeverityHigh,
		Target:   tgt.TargetURL,
		Endpoint: "/api/v1/accounts/123",
	})
	_ = store.SaveFindings([]assessment.AssessmentFinding{fndBase})

	snapBase := assessment.BuildAssessmentSnapshot(asm, execBase, []string{tgt.TargetURL}, []assessment.AssessmentFinding{fndBase}, true)
	snapBase.SetCoveredCategories([]string{"api1_bola", "api2_broken_auth"})
	_ = store.CreateSnapshot(snapBase, []assessment.AssessmentFinding{fndBase}, nil)
	execBase.SnapshotID = snapBase.ID
	_ = store.UpdateExecution(execBase)

	// Test 4 failure conditions: FAILED, CANCELLED, INTERRUPTED, and TARGET_UNREACHABLE
	testCases := []struct {
		name         string
		status       assessment.AssessmentStatus
		failedTarget string
		isIncomplete bool
	}{
		{name: "Execution Failed", status: assessment.StatusFailed},
		{name: "Execution Cancelled", status: assessment.StatusCancelled},
		{name: "Execution Interrupted", status: assessment.StatusInterrupted},
		{name: "Completed With Failed Target", status: assessment.StatusCompletedWithErrors, failedTarget: tgt.TargetURL, isIncomplete: true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			compFail := now.Add(-20 * time.Minute)
			execFail := &assessment.AssessmentExecution{
				ID:             "exec-scen-b-" + uuid.New().String()[:8],
				AssessmentID:   asm.ID,
				ClientID:       asm.ClientID,
				TenantID:       "tenant-b",
				AssessmentType: assessment.AssessmentTypeAPISecurity,
				Status:         tc.status,
				StartedAt:      now.Add(-30 * time.Minute),
				CompletedAt:    &compFail,
				ErrorMessage:   "operational failure simulated",
				CreatedAt:      now.Add(-30 * time.Minute),
			}
			_ = store.CreateExecution(execFail)

			snapFail := assessment.BuildAssessmentSnapshot(asm, execFail, []string{tgt.TargetURL}, nil, !tc.isIncomplete)
			snapFail.SetCoveredCategories([]string{"api1_bola", "api2_broken_auth"})
			if tc.failedTarget != "" {
				snapFail.SetFailedTargets([]string{tc.failedTarget})
			}
			_ = store.CreateSnapshot(snapFail, nil, nil)
			execFail.SnapshotID = snapFail.ID
			_ = store.UpdateExecution(execFail)

			// Generate change summary
			cs, err := store.GetAssessmentChangeSummary(asm.ID, execBase.ID, execFail.ID, auth)
			if err != nil {
				t.Fatalf("[%s] GetAssessmentChangeSummary failed: %v", tc.name, err)
			}

			// Invariant Check: Never resolve absent findings during operational failures
			if cs.Counts.Resolved > 0 {
				t.Fatalf("[%s] CRITICAL INVARIANT VIOLATED: finding falsely marked RESOLVED during failure! (Resolved=%d)", tc.name, cs.Counts.Resolved)
			}
			if cs.IsReliable {
				t.Errorf("[%s] expected summary to be marked UNRELIABLE due to failure, got is_reliable=true", tc.name)
			}
			if cs.Counts.Unverified == 0 {
				t.Errorf("[%s] expected finding to be classified as UNVERIFIED, got 0", tc.name)
			}
		})
	}
}

// -----------------------------------------------------------------------------
// Scenario C: Recovery and duplicate prevention
// -----------------------------------------------------------------------------

func TestPhase7_ScenarioC_RecoveryAndDuplicatePrevention(t *testing.T) {
	store, cleanup := helperNewPhase7Store(t)
	defer cleanup()

	_, asm, _ := helperSetupPhase7Assessment(t, store, assessment.AssessmentTypeWebSecurity, "https://example.com", "tenant-c")

	now := time.Now().UTC()
	staleHeartbeat := now.Add(-10 * time.Minute)
	staleLease := now.Add(-5 * time.Minute)

	// Create abandoned execution
	exec := &assessment.AssessmentExecution{
		ID:             "exec-scen-c-abandoned",
		AssessmentID:   asm.ID,
		ClientID:       asm.ClientID,
		TenantID:       "tenant-c",
		AssessmentType: assessment.AssessmentTypeWebSecurity,
		Status:         assessment.StatusRunning,
		WorkerID:       "dead-worker-1",
		StartedAt:      now.Add(-20 * time.Minute),
		HeartbeatAt:    &staleHeartbeat,
		LeaseExpiresAt: &staleLease,
		CreatedAt:      now.Add(-20 * time.Minute),
	}
	if err := store.CreateExecution(exec); err != nil {
		t.Fatalf("CreateExecution failed: %v", err)
	}

	// Competing recovery workers race to claim lease
	var (
		wg      sync.WaitGroup
		winner  string
		winsMu  sync.Mutex
		winCnt  int32
	)

	workers := []string{"recovery-worker-alpha", "recovery-worker-beta"}
	for _, wID := range workers {
		wg.Add(1)
		go func(w string) {
			defer wg.Done()
			claimed, err := store.ClaimAbandonedExecutionForRecovery(exec.ID, w, now, 5*time.Minute)
			if err == nil && claimed {
				atomic.AddInt32(&winCnt, 1)
				winsMu.Lock()
				winner = w
				winsMu.Unlock()
			}
		}(wID)
	}
	wg.Wait()

	if winCnt != 1 {
		t.Fatalf("expected exactly 1 recovery worker to win claim, got %d", winCnt)
	}

	// Verify database record reflects the winning worker
	updatedExec, err := store.GetExecution(exec.ID)
	if err != nil {
		t.Fatalf("GetExecution failed: %v", err)
	}
	if updatedExec.WorkerID != winner {
		t.Errorf("expected WorkerID %s, got %s", winner, updatedExec.WorkerID)
	}

	// Stale worker tries to write progress / heartbeat -> MUST be rejected with ErrLeaseLost
	loser := "recovery-worker-alpha"
	if winner == loser {
		loser = "recovery-worker-beta"
	}
	staleErr := store.HeartbeatExecution(exec.ID, loser, nil, 5*time.Minute)
	if staleErr == nil || !errors.Is(staleErr, assessment.ErrLeaseLost) {
		t.Errorf("expected ErrLeaseLost for stale worker heartbeat, got: %v", staleErr)
	}

	// Winning worker safely finalizes the execution as interrupted
	authCtx := assessment.NewAdminAuthContext()
	res, err := store.FinalizeAbandonedExecution(exec.ID, winner, assessment.StatusInterrupted, "recovered by test", authCtx)
	if err != nil {
		t.Fatalf("FinalizeAbandonedExecution failed: %v", err)
	}
	if res.NewStatus != assessment.StatusInterrupted {
		t.Errorf("expected status INTERRUPTED, got %s", res.NewStatus)
	}

	// Late attempt by stale worker to claim terminal execution -> rejected
	lateClaim, err := store.ClaimExecutionOwnership(exec.ID, "late-rogue-worker", 5*time.Minute)
	if err != nil || lateClaim {
		t.Errorf("expected late claim on terminal execution to be rejected (claimed=%t, err=%v)", lateClaim, err)
	}
}

// -----------------------------------------------------------------------------
// Scenario D: Genuine finding resolution and regression
// -----------------------------------------------------------------------------

func TestPhase7_ScenarioD_GenuineFindingResolutionAndRegression(t *testing.T) {
	store, cleanup := helperNewPhase7Store(t)
	defer cleanup()

	auth := assessment.NewAdminAuthContext()
	client, asm, tgt := helperSetupPhase7Assessment(t, store, assessment.AssessmentTypeAPISecurity, "https://api.example.com", "tenant-d")

	now := time.Now().UTC()

	// 1. Baseline Execution: finds fnd-1
	t1 := now.Add(-3 * time.Hour)
	comp1 := t1.Add(10 * time.Minute)
	exec1 := &assessment.AssessmentExecution{
		ID:             "exec-scen-d-1",
		AssessmentID:   asm.ID,
		ClientID:       asm.ClientID,
		TenantID:       client.ID,
		AssessmentType: assessment.AssessmentTypeAPISecurity,
		Status:         assessment.StatusCompleted,
		StartedAt:      t1,
		CompletedAt:    &comp1,
		CreatedAt:      t1,
	}
	_ = store.CreateExecution(exec1)

	rf1 := report.Finding{
		ID:       "fnd-vuln-1",
		RuleID:   "API_BOLA_RESOURCE",
		Category: "api1_bola",
		Title:    "BOLA Resource Leaking",
		Severity: report.SeverityHigh,
		Target:   tgt.TargetURL,
		Endpoint: "/api/v1/orders/100",
	}
	correlation.EnsureFindingFingerprint(&rf1, correlation.TrustPolicyForceRecompute)

	af1 := assessment.ToAssessmentFinding(asm.ID, exec1.ID, tgt.ID, rf1)
	_ = store.SaveFindings([]assessment.AssessmentFinding{af1})

	snap1 := &assessment.AssessmentSnapshot{
		ID:            "snap-scen-d-1",
		AssessmentID:  asm.ID,
		ExecutionID:   exec1.ID,
		ClientID:      client.ID,
		TenantID:      client.ID,
		Status:        assessment.StatusCompleted,
		IsComplete:    true,
		StartedAt:     t1,
		CompletedAt:   &comp1,
		ScopedTargets: []string{tgt.TargetURL},
	}
	snap1.SetCoveredCategories([]string{"api1_bola", "api2_broken_auth"})
	_ = store.CreateSnapshot(snap1, []assessment.AssessmentFinding{af1}, nil)
	exec1.SnapshotID = snap1.ID
	_ = store.UpdateExecution(exec1)

	// 2. Second Execution: successfully completed, fully covers api1_bola, fnd-1 is absent -> RESOLVED
	t2 := now.Add(-2 * time.Hour)
	comp2 := t2.Add(10 * time.Minute)
	exec2 := &assessment.AssessmentExecution{
		ID:             "exec-scen-d-2",
		AssessmentID:   asm.ID,
		ClientID:       asm.ClientID,
		TenantID:       client.ID,
		AssessmentType: assessment.AssessmentTypeAPISecurity,
		Status:         assessment.StatusCompleted,
		StartedAt:      t2,
		CompletedAt:    &comp2,
		CreatedAt:      t2,
	}
	_ = store.CreateExecution(exec2)

	snap2 := &assessment.AssessmentSnapshot{
		ID:            "snap-scen-d-2",
		AssessmentID:  asm.ID,
		ExecutionID:   exec2.ID,
		ClientID:      client.ID,
		TenantID:      client.ID,
		Status:        assessment.StatusCompleted,
		IsComplete:    true,
		StartedAt:     t2,
		CompletedAt:   &comp2,
		ScopedTargets: []string{tgt.TargetURL},
	}
	snap2.SetCoveredCategories([]string{"api1_bola", "api2_broken_auth"})
	_ = store.CreateSnapshot(snap2, []assessment.AssessmentFinding{}, nil)
	exec2.SnapshotID = snap2.ID
	_ = store.UpdateExecution(exec2)

	cs1, err := store.GetAssessmentChangeSummary(asm.ID, exec1.ID, exec2.ID, auth)
	if err != nil {
		t.Fatalf("GetAssessmentChangeSummary (exec1 -> exec2) failed: %v", err)
	}
	if cs1.Counts.Resolved != 1 {
		t.Fatalf("expected 1 RESOLVED finding, got %d", cs1.Counts.Resolved)
	}

	// 3. Third Execution: fnd-1 reappears! -> REGRESSED (reappeared)
	t3 := now.Add(-1 * time.Hour)
	comp3 := t3.Add(10 * time.Minute)
	exec3 := &assessment.AssessmentExecution{
		ID:             "exec-scen-d-3",
		AssessmentID:   asm.ID,
		ClientID:       asm.ClientID,
		TenantID:       client.ID,
		AssessmentType: assessment.AssessmentTypeAPISecurity,
		Status:         assessment.StatusCompleted,
		StartedAt:      t3,
		CompletedAt:    &comp3,
		CreatedAt:      t3,
	}
	_ = store.CreateExecution(exec3)

	af1_reappeared := assessment.ToAssessmentFinding(asm.ID, exec3.ID, tgt.ID, rf1)
	_ = store.SaveFindings([]assessment.AssessmentFinding{af1_reappeared})

	snap3 := &assessment.AssessmentSnapshot{
		ID:            "snap-scen-d-3",
		AssessmentID:  asm.ID,
		ExecutionID:   exec3.ID,
		ClientID:      client.ID,
		TenantID:      client.ID,
		Status:        assessment.StatusCompleted,
		IsComplete:    true,
		StartedAt:     t3,
		CompletedAt:   &comp3,
		ScopedTargets: []string{tgt.TargetURL},
	}
	snap3.SetCoveredCategories([]string{"api1_bola", "api2_broken_auth"})
	_ = store.CreateSnapshot(snap3, []assessment.AssessmentFinding{af1_reappeared}, nil)
	exec3.SnapshotID = snap3.ID
	_ = store.UpdateExecution(exec3)

	cs2, err := store.GetAssessmentChangeSummary(asm.ID, exec2.ID, exec3.ID, auth)
	if err != nil {
		t.Fatalf("GetAssessmentChangeSummary (exec2 -> exec3) failed: %v", err)
	}
	if cs2.Counts.Regressed != 1 {
		t.Fatalf("expected 1 REGRESSED finding upon reappearance, got %d (New=%d)", cs2.Counts.Regressed, cs2.Counts.New)
	}
}

// -----------------------------------------------------------------------------
// Scenario E: Cross-engine incompatibility
// -----------------------------------------------------------------------------

func TestPhase7_ScenarioE_CrossEngineIncompatibility(t *testing.T) {
	store, cleanup := helperNewPhase7Store(t)
	defer cleanup()

	auth := assessment.NewAdminAuthContext()

	// 1. Cloud Security assessment
	_, asmCloud, tgtCloud := helperSetupPhase7Assessment(t, store, assessment.AssessmentTypeCloudSecurity, "https://cloud.example.com", "tenant-e")
	now := time.Now().UTC()
	comp1 := now.Add(-110 * time.Minute)
	execCloud := &assessment.AssessmentExecution{
		ID:             "exec-scen-e-cloud",
		AssessmentID:   asmCloud.ID,
		ClientID:       asmCloud.ClientID,
		TenantID:       "tenant-e",
		AssessmentType: assessment.AssessmentTypeCloudSecurity,
		Status:         assessment.StatusCompleted,
		StartedAt:      now.Add(-2 * time.Hour),
		CompletedAt:    &comp1,
		CreatedAt:      now.Add(-2 * time.Hour),
	}
	_ = store.CreateExecution(execCloud)

	fndCloud := assessment.ToAssessmentFinding(asmCloud.ID, execCloud.ID, tgtCloud.ID, report.Finding{
		ID:       "fnd-cloud-1",
		RuleID:   "S3_PUBLIC_BUCKET",
		Category: "storage_buckets",
		Title:    "Public S3 Bucket",
		Severity: report.SeverityCritical,
		Target:   tgtCloud.TargetURL,
	})
	_ = store.SaveFindings([]assessment.AssessmentFinding{fndCloud})

	snapCloud := assessment.BuildAssessmentSnapshot(asmCloud, execCloud, []string{tgtCloud.TargetURL}, []assessment.AssessmentFinding{fndCloud}, true)
	snapCloud.SetCoveredCategories([]string{"aws", "azure", "storage_buckets"})
	_ = store.CreateSnapshot(snapCloud, []assessment.AssessmentFinding{fndCloud}, nil)
	execCloud.SnapshotID = snapCloud.ID
	_ = store.UpdateExecution(execCloud)

	// 2. API Security assessment
	_, asmAPI, tgtAPI := helperSetupPhase7Assessment(t, store, assessment.AssessmentTypeAPISecurity, "https://api.example.com", "tenant-e")
	comp2 := now.Add(-50 * time.Minute)
	execAPI := &assessment.AssessmentExecution{
		ID:             "exec-scen-e-api",
		AssessmentID:   asmAPI.ID,
		ClientID:       asmAPI.ClientID,
		TenantID:       "tenant-e",
		AssessmentType: assessment.AssessmentTypeAPISecurity,
		Status:         assessment.StatusCompleted,
		StartedAt:      now.Add(-1 * time.Hour),
		CompletedAt:    &comp2,
		CreatedAt:      now.Add(-1 * time.Hour),
	}
	_ = store.CreateExecution(execAPI)

	fndAPI := assessment.ToAssessmentFinding(asmAPI.ID, execAPI.ID, tgtAPI.ID, report.Finding{
		ID:       "fnd-api-1",
		RuleID:   "API_AUTH_BYPASS",
		Category: "api2_broken_auth",
		Title:    "Broken Auth Endpoint",
		Severity: report.SeverityHigh,
		Target:   tgtAPI.TargetURL,
		Endpoint: "/api/v1/auth",
	})
	_ = store.SaveFindings([]assessment.AssessmentFinding{fndAPI})

	snapAPI := assessment.BuildAssessmentSnapshot(asmAPI, execAPI, []string{tgtAPI.TargetURL}, []assessment.AssessmentFinding{fndAPI}, true)
	snapAPI.SetCoveredCategories([]string{"api1_bola", "api2_broken_auth"})
	_ = store.CreateSnapshot(snapAPI, []assessment.AssessmentFinding{fndAPI}, nil)
	execAPI.SnapshotID = snapAPI.ID
	_ = store.UpdateExecution(execAPI)

	// 3. Explicit cross-engine comparison must fail closed
	_, cmpErr := store.CompareExecutionHistory(execCloud.ID, execAPI.ID, auth)
	if cmpErr == nil || !errors.Is(cmpErr, assessment.ErrIncompatibleAssessmentScope) {
		t.Fatalf("expected ErrIncompatibleAssessmentScope for cross-engine comparison, got: %v", cmpErr)
	}

	_, csErr := store.GetAssessmentChangeSummary(asmAPI.ID, execCloud.ID, execAPI.ID, auth)
	if csErr == nil || !errors.Is(csErr, assessment.ErrIncompatibleAssessmentScope) {
		t.Fatalf("expected ErrIncompatibleAssessmentScope in ChangeSummary, got: %v", csErr)
	}

	// 4. Comparison between FULL composite and single-engine must fail closed
	execFull := &assessment.AssessmentExecution{
		ID:             "exec-scen-e-full",
		AssessmentID:   asmAPI.ID,
		ClientID:       asmAPI.ClientID,
		TenantID:       "tenant-e",
		AssessmentType: assessment.AssessmentTypeFull,
		Status:         assessment.StatusCompleted,
		StartedAt:      now.Add(-20 * time.Minute),
		CompletedAt:    &now,
		CreatedAt:      now.Add(-20 * time.Minute),
	}
	_ = store.CreateExecution(execFull)

	_, fullErr := store.CompareExecutionHistory(execAPI.ID, execFull.ID, auth)
	if fullErr == nil || !errors.Is(fullErr, assessment.ErrIncompatibleAssessmentScope) {
		t.Fatalf("expected ErrIncompatibleAssessmentScope for API vs FULL, got: %v", fullErr)
	}

	// 5. Automatic baseline selection ignores incompatible executions
	autoCS, autoErr := store.GetAssessmentChangeSummary(asmAPI.ID, "", execAPI.ID, auth)
	if autoErr != nil {
		t.Fatalf("automatic baseline summary failed: %v", autoErr)
	}
	if autoCS.BaselineExecutionID != "" {
		t.Errorf("expected no baseline for single API execution, got: %s", autoCS.BaselineExecutionID)
	}
	if autoCS.Counts.Resolved > 0 {
		t.Errorf("false resolution detected across engines: resolved=%d", autoCS.Counts.Resolved)
	}
}

// -----------------------------------------------------------------------------
// Scenario F: Notification outage
// -----------------------------------------------------------------------------

func TestPhase7_ScenarioF_NotificationOutage(t *testing.T) {
	store, cleanup := helperNewPhase7Store(t)
	defer cleanup()

	// Failing test server (500 internal error)
	var failAttempts int32
	failServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&failAttempts, 1)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer failServer.Close()

	t.Setenv("FELIX_NOTIFY_ENABLED", "true")
	t.Setenv("FELIX_NOTIFY_LIFECYCLE", "completed,failed")
	t.Setenv("FELIX_NOTIFY_MIN_SEVERITY", "INFO")
	t.Setenv("FELIX_NOTIFY_WEBHOOK_URL", failServer.URL+"/failing-webhook")
	t.Setenv("FELIX_NOTIFY_ALLOW_INSECURE_HTTP", "true")

	targetServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{}`))
	}))
	defer targetServer.Close()

	ctrl := assessment.NewController(store)
	_, asm, _ := helperSetupPhase7Assessment(t, store, assessment.AssessmentTypeAPISecurity, targetServer.URL, "tenant-f")

	// 1. Run assessment with failing notification endpoint
	res, err := ctrl.RunAssessment(context.Background(), asm.ID, assessment.ExecutionOptions{AllowLoopback: true})
	if err != nil {
		t.Fatalf("RunAssessment failed: %v", err)
	}

	// Invariant: Assessment outcome, snapshot, and findings are completely independent of notification success
	if res.Execution.Status != assessment.StatusCompleted {
		t.Errorf("expected execution COMPLETED despite webhook failure, got: %s", res.Execution.Status)
	}
	if res.Snapshot == nil {
		t.Errorf("expected non-nil snapshot despite webhook failure")
	}

	// 2. Outbox record exists in pending / failed state
	authCtx := assessment.NewAdminAuthContext()
	deliveries, err := store.ListNotifications(notify.NotificationFilter{AssessmentID: asm.ID, ExecutionID: res.Execution.ID}, authCtx)
	if err != nil || len(deliveries) != 1 {
		t.Fatalf("expected 1 outbox record, got %d (err: %v)", len(deliveries), err)
	}
	initialNotif := deliveries[0]

	// 3. Recover notification delivery via healthy webhook endpoint
	healthyServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"received"}`))
	}))
	defer healthyServer.Close()

	webhookCfg := notify.WebhookConfig{
		URL:               healthyServer.URL + "/healthy-webhook",
		AllowInsecureHTTP: true,
		AllowPrivateIPs:   true,
		AllowLoopback:     true,
		Timeout:           5 * time.Second,
	}
	provider, err := notify.NewWebhookProvider(webhookCfg)
	if err != nil {
		t.Fatalf("NewWebhookProvider failed: %v", err)
	}

	dispatcher := notify.NewOutboxDispatcher(store, provider, notify.DispatcherConfig{Concurrency: 1})
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	deliveredCount, err := dispatcher.DispatchBatch(ctx, 1)
	if err != nil {
		t.Fatalf("DispatchBatch failed: %v", err)
	}
	if deliveredCount != 1 {
		t.Errorf("expected 1 notification delivered, got %d", deliveredCount)
	}

	// 4. Verify stable delivery identity and terminal DELIVERED status
	deliveriesAfter, _ := store.ListNotifications(notify.NotificationFilter{AssessmentID: asm.ID, ExecutionID: res.Execution.ID}, authCtx)
	if len(deliveriesAfter) != 1 {
		t.Fatalf("expected outbox deduplication (exactly 1 record), got %d", len(deliveriesAfter))
	}
	deliveredNotif := deliveriesAfter[0]
	if deliveredNotif.ID != initialNotif.ID {
		t.Errorf("expected delivery ID %s to remain stable, got %s", initialNotif.ID, deliveredNotif.ID)
	}
	if deliveredNotif.DeliveryStatus != notify.DeliveryStatusDelivered {
		t.Errorf("expected status DELIVERED, got %s", deliveredNotif.DeliveryStatus)
	}
}

// -----------------------------------------------------------------------------
// Critical Invariant: 12-Case Matrix on Resolution, Failure, and Regressions
// -----------------------------------------------------------------------------

func TestPhase7_CriticalInvariant_All12Cases(t *testing.T) {
	store, cleanup := helperNewPhase7Store(t)
	defer cleanup()

	auth := assessment.NewAdminAuthContext()
	client, asm, tgt := helperSetupPhase7Assessment(t, store, assessment.AssessmentTypeAPISecurity, "https://api.example.com", "tenant-inv")

	now := time.Now().UTC()
	t0 := now.Add(-5 * time.Hour)
	comp0 := t0.Add(10 * time.Minute)

	// Baseline finding (Case 1: successfully discovered)
	rfBase := report.Finding{
		ID:       "fnd-base-main",
		RuleID:   "API_BOLA_TEST",
		Category: "api1_bola",
		Title:    "BOLA Test Endpoint",
		Severity: report.SeverityHigh,
		Target:   tgt.TargetURL,
		Endpoint: "/api/v1/users/profile",
	}
	correlation.EnsureFindingFingerprint(&rfBase, correlation.TrustPolicyForceRecompute)

	execBase := &assessment.AssessmentExecution{
		ID:             "exec-inv-base",
		AssessmentID:   asm.ID,
		ClientID:       client.ID,
		TenantID:       client.ID,
		AssessmentType: assessment.AssessmentTypeAPISecurity,
		Status:         assessment.StatusCompleted,
		StartedAt:      t0,
		CompletedAt:    &comp0,
		CreatedAt:      t0,
	}
	_ = store.CreateExecution(execBase)
	afBase := assessment.ToAssessmentFinding(asm.ID, execBase.ID, tgt.ID, rfBase)
	_ = store.SaveFindings([]assessment.AssessmentFinding{afBase})

	snapBase := &assessment.AssessmentSnapshot{
		ID:            "snap-inv-base",
		AssessmentID:  asm.ID,
		ExecutionID:   execBase.ID,
		ClientID:      client.ID,
		TenantID:      client.ID,
		Status:        assessment.StatusCompleted,
		IsComplete:    true,
		StartedAt:     t0,
		CompletedAt:   &comp0,
		ScopedTargets: []string{tgt.TargetURL},
	}
	snapBase.SetCoveredCategories([]string{"api1_bola", "api2_broken_auth"})
	_ = store.CreateSnapshot(snapBase, []assessment.AssessmentFinding{afBase}, nil)
	execBase.SnapshotID = snapBase.ID
	_ = store.UpdateExecution(execBase)

	// Case 2: Subsequent successful compatible assessment no longer discovers it -> RESOLVED
	t2 := now.Add(-4 * time.Hour)
	comp2 := t2.Add(10 * time.Minute)
	exec2 := &assessment.AssessmentExecution{
		ID:             "exec-inv-case2",
		AssessmentID:   asm.ID,
		ClientID:       client.ID,
		TenantID:       client.ID,
		AssessmentType: assessment.AssessmentTypeAPISecurity,
		Status:         assessment.StatusCompleted,
		StartedAt:      t2,
		CompletedAt:    &comp2,
		CreatedAt:      t2,
	}
	_ = store.CreateExecution(exec2)
	snap2 := &assessment.AssessmentSnapshot{
		ID:            "snap-inv-case2",
		AssessmentID:  asm.ID,
		ExecutionID:   exec2.ID,
		ClientID:      client.ID,
		TenantID:      client.ID,
		Status:        assessment.StatusCompleted,
		IsComplete:    true,
		StartedAt:     t2,
		CompletedAt:   &comp2,
		ScopedTargets: []string{tgt.TargetURL},
	}
	snap2.SetCoveredCategories([]string{"api1_bola", "api2_broken_auth"})
	_ = store.CreateSnapshot(snap2, []assessment.AssessmentFinding{}, nil)
	exec2.SnapshotID = snap2.ID
	_ = store.UpdateExecution(exec2)

	cs2, err := store.GetAssessmentChangeSummary(asm.ID, execBase.ID, exec2.ID, auth)
	if err != nil || cs2.Counts.Resolved != 1 {
		t.Fatalf("Case 2: expected 1 RESOLVED finding, got %d (err: %v)", cs2.Counts.Resolved, err)
	}

	// Case 3: Subsequent assessment fails before scanning relevant target -> UNVERIFIED
	cmp3 := correlation.CompareFindingsWithOptions([]report.Finding{rfBase}, nil, correlation.ComparisonOptions{
		CurrentCompleted: false,
		FailedTargets:    []string{tgt.TargetURL},
		ScopedTargets:    []string{tgt.TargetURL},
		ScopedCategories: []string{"api1_bola"},
	})
	if cmp3.ResolvedCount != 0 || cmp3.UnverifiedCount != 1 {
		t.Errorf("Case 3: expected 0 resolved and 1 unverified for failed target, got resolved=%d unverified=%d", cmp3.ResolvedCount, cmp3.UnverifiedCount)
	}

	// Case 4: Assessment is cancelled partway through execution -> UNVERIFIED
	cmp4 := correlation.CompareFindingsWithOptions([]report.Finding{rfBase}, nil, correlation.ComparisonOptions{
		CurrentCompleted: false,
		ScopedTargets:    []string{tgt.TargetURL},
		ScopedCategories: []string{"api1_bola"},
	})
	if cmp4.ResolvedCount != 0 || cmp4.UnverifiedCount != 1 {
		t.Errorf("Case 4: expected 0 resolved and 1 unverified for cancelled run, got resolved=%d unverified=%d", cmp4.ResolvedCount, cmp4.UnverifiedCount)
	}

	// Case 5: Assessment interrupted by worker loss -> UNVERIFIED
	cmp5 := correlation.CompareFindingsWithOptions([]report.Finding{rfBase}, nil, correlation.ComparisonOptions{
		CurrentCompleted: false,
		Inconclusive:     true,
		ScopedTargets:    []string{tgt.TargetURL},
		ScopedCategories: []string{"api1_bola"},
	})
	if cmp5.ResolvedCount != 0 || cmp5.UnverifiedCount != 1 {
		t.Errorf("Case 5: expected 0 resolved and 1 unverified for interrupted run, got resolved=%d unverified=%d", cmp5.ResolvedCount, cmp5.UnverifiedCount)
	}

	// Case 6: Assessment completes with errors -> UNVERIFIED if target failed
	cmp6 := correlation.CompareFindingsWithOptions([]report.Finding{rfBase}, nil, correlation.ComparisonOptions{
		CurrentCompleted: true,
		FailedTargets:    []string{tgt.TargetURL},
		ScopedTargets:    []string{tgt.TargetURL},
		ScopedCategories: []string{"api1_bola"},
	})
	if cmp6.ResolvedCount != 0 || cmp6.UnverifiedCount != 1 {
		t.Errorf("Case 6: expected 0 resolved for run with target failure, got resolved=%d unverified=%d", cmp6.ResolvedCount, cmp6.UnverifiedCount)
	}

	// Case 7: Target is unreachable / skipped -> UNVERIFIED
	cmp7 := correlation.CompareFindingsWithOptions([]report.Finding{rfBase}, nil, correlation.ComparisonOptions{
		CurrentCompleted: true,
		SkippedTargets:   []string{tgt.TargetURL},
		ScopedTargets:    []string{tgt.TargetURL},
		ScopedCategories: []string{"api1_bola"},
	})
	if cmp7.ResolvedCount != 0 || cmp7.UnverifiedCount != 1 {
		t.Errorf("Case 7: expected 0 resolved for skipped target, got resolved=%d unverified=%d", cmp7.ResolvedCount, cmp7.UnverifiedCount)
	}

	// Case 8: Relevant category is not covered by newer engine -> UNVERIFIED
	cmp8 := correlation.CompareFindingsWithOptions([]report.Finding{rfBase}, nil, correlation.ComparisonOptions{
		CurrentCompleted: true,
		ScopedTargets:    []string{tgt.TargetURL},
		ScopedCategories: []string{"api2_broken_auth", "api3_bopla"}, // api1_bola not scoped!
	})
	if cmp8.ResolvedCount != 0 || cmp8.UnverifiedCount != 1 {
		t.Errorf("Case 8: expected 0 resolved when category not covered, got resolved=%d unverified=%d", cmp8.ResolvedCount, cmp8.UnverifiedCount)
	}

	// Case 9: Incompatible engine scope -> rejected
	if assessment.AreAssessmentTypesCompatible(assessment.AssessmentTypeCloudSecurity, assessment.AssessmentTypeAPISecurity) {
		t.Errorf("Case 9: expected incompatible engine scopes to be rejected")
	}

	// Case 10: Newer assessment produces partial snapshot -> UNVERIFIED
	cmp10 := correlation.CompareFindingsWithOptions([]report.Finding{rfBase}, nil, correlation.ComparisonOptions{
		CurrentCompleted: true,
		Inconclusive:     true,
		ScopedTargets:    []string{tgt.TargetURL},
		ScopedCategories: []string{"api1_bola"},
	})
	if cmp10.ResolvedCount != 0 || cmp10.UnverifiedCount != 1 {
		t.Errorf("Case 10: expected 0 resolved for inconclusive snapshot, got resolved=%d unverified=%d", cmp10.ResolvedCount, cmp10.UnverifiedCount)
	}

	// Case 11: Finding reappears after previously verified resolution -> REGRESSED
	resOpts := correlation.ComparisonOptions{
		CurrentCompleted:     true,
		ResolvedFingerprints: map[string]bool{rfBase.Fingerprint: true},
		ScopedTargets:        []string{tgt.TargetURL},
		ScopedCategories:     []string{"api1_bola"},
	}
	cmp11 := correlation.CompareFindingsWithOptions(nil, []report.Finding{rfBase}, resOpts)
	if cmp11.RegressedCount != 1 || len(cmp11.Items) == 0 || cmp11.Items[0].RegressionReason != correlation.RegressionReappeared {
		t.Errorf("Case 11: expected 1 REGRESSED (reappeared) finding, got regressed=%d items=%+v", cmp11.RegressedCount, cmp11.Items)
	}

	// Case 12: Finding changes attribute:
	// A: Severity worsened (HIGH -> CRITICAL) -> REGRESSED (RegressionSeverityWorsened)
	rfWorsened := rfBase
	rfWorsened.Severity = report.SeverityCritical
	cmp12A := correlation.CompareFindingsWithOptions([]report.Finding{rfBase}, []report.Finding{rfWorsened}, correlation.ComparisonOptions{CurrentCompleted: true})
	if cmp12A.RegressedCount != 1 || cmp12A.Items[0].RegressionReason != correlation.RegressionSeverityWorsened {
		t.Errorf("Case 12A: expected REGRESSED (worsened), got %+v", cmp12A.Items)
	}

	// B: Severity decreased (HIGH -> MEDIUM) -> CHANGED (ChangeSeverityDecreased)
	rfDecreased := rfBase
	rfDecreased.Severity = report.SeverityMedium
	cmp12B := correlation.CompareFindingsWithOptions([]report.Finding{rfBase}, []report.Finding{rfDecreased}, correlation.ComparisonOptions{CurrentCompleted: true})
	if cmp12B.ChangedCount != 1 || cmp12B.Items[0].ChangeReason != correlation.ChangeSeverityDecreased {
		t.Errorf("Case 12B: expected CHANGED (decreased), got %+v", cmp12B.Items)
	}
}
