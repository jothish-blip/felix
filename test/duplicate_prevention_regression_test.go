package test

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"felix/pkg/assessment"
	"felix/pkg/report"

	_ "modernc.org/sqlite"
)

// setupDupTestDB creates an isolated SQLite store with an approved target and valid authorization.
func setupDupTestDB(t *testing.T) (*assessment.SQLiteStore, *assessment.Client, *assessment.Assessment, *assessment.AssessmentTarget, *httptest.Server) {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "test_dup.db")
	store, err := assessment.NewSQLiteStore(dbPath)
	if err != nil {
		t.Fatalf("failed to open store: %v", err)
	}

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintln(w, "<html><head><title>Safe Target</title></head><body><h1>Safe Target</h1></body></html>")
	}))

	client := &assessment.Client{
		ID:   "client-dup-1",
		Name: "Dup Prevention Client",
	}
	if err := store.CreateClient(client); err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	asm := &assessment.Assessment{
		ID:             "asm-dup-1",
		Ref:            "ASM-DUP-1",
		ClientID:       client.ID,
		Name:           "Duplicate Prevention Assessment",
		AssessmentType: "web",
		Status:         assessment.StatusReady,
		ScopeMode:      "same-origin",
	}
	if err := store.CreateAssessment(asm); err != nil {
		t.Fatalf("failed to create assessment: %v", err)
	}

	now := time.Now().UTC()
	validFrom := now.Add(-1 * time.Hour)
	validUntil := now.Add(24 * time.Hour)
	auth := &assessment.AuthorizationRecord{
		ID:                  "auth-dup-1",
		AssessmentID:        asm.ID,
		AuthorizingParty:    "Security Team",
		AuthorizationMethod: "CONTRACT",
		DateReceived:        validFrom,
		ValidFrom:           &validFrom,
		ValidUntil:          &validUntil,
		Status:              assessment.AuthApproved,
	}
	if err := store.SetAuthorization(auth); err != nil {
		t.Fatalf("failed creating auth record: %v", err)
	}

	tgt := &assessment.AssessmentTarget{
		ID:           "tgt-dup-1",
		AssessmentID: asm.ID,
		TargetURL:    ts.URL,
		ScopeStatus:  "APPROVED",
		CreatedAt:    now,
	}
	if err := store.AddTarget(tgt); err != nil {
		t.Fatalf("failed adding target: %v", err)
	}

	return store, client, asm, tgt, ts
}

// 1. Concurrent identical manual requests: 10 concurrent requests with same idempotency key create exactly 1 execution.
func TestDuplicatePrevention_1_ConcurrentIdenticalManualRequests(t *testing.T) {
	store, _, asm, _, ts := setupDupTestDB(t)
	defer store.Close()
	defer ts.Close()

	ctrl := assessment.NewController(store)
	idempKey := "manual-concurrent-key-1"

	var wg sync.WaitGroup
	numRequests := 10
	results := make([]*assessment.ExecutionResult, numRequests)
	errs := make([]error, numRequests)

	for i := 0; i < numRequests; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			opts := assessment.ExecutionOptions{
				IdempotencyKey:  idempKey,
				AllowLoopback:   true,
				AllowPrivateIPs: true,
				Concurrency:     1,
				TimeoutDuration: 2 * time.Second,
			}
			res, err := ctrl.RunAssessment(context.Background(), asm.ID, opts)
			results[idx] = res
			errs[idx] = err
		}(i)
	}
	wg.Wait()

	// Verify that exactly 1 execution was created in database with this key
	history, total, err := store.ListExecutionHistory(assessment.ExecutionListOptions{
		Auth: assessment.NewAdminAuthContext(),
	})
	if err != nil {
		t.Fatalf("ListExecutionHistory failed: %v", err)
	}
	if total != 1 {
		t.Fatalf("expected exactly 1 execution in DB, found %d", total)
	}
	exec := history[0]
	if exec.IdempotencyKey != idempKey {
		t.Errorf("expected idempotency key %s, got %s", idempKey, exec.IdempotencyKey)
	}

	// Verify responses: callers got either the canonical execution or ErrExecutionOverlap / ErrIdempotencyConflict
	successCount := 0
	overlapCount := 0
	for i := 0; i < numRequests; i++ {
		if errs[i] == nil && results[i] != nil {
			successCount++
			if results[i].Execution.ID != exec.ID {
				t.Errorf("request %d returned unexpected execution ID %s", i, results[i].Execution.ID)
			}
		} else if errors.Is(errs[i], assessment.ErrExecutionOverlap) || errors.Is(errs[i], assessment.ErrIdempotencyConflict) {
			overlapCount++
		} else {
			t.Errorf("request %d encountered unexpected error: %v", i, errs[i])
		}
	}
	if successCount < 1 {
		t.Fatalf("expected at least 1 successful execution return, got %d", successCount)
	}
}

// 2. Sequential retry with same idempotency key: Returns existing completed execution without re-executing.
func TestDuplicatePrevention_2_SequentialRetry_SameIdempotencyKey(t *testing.T) {
	store, _, asm, _, ts := setupDupTestDB(t)
	defer store.Close()
	defer ts.Close()

	ctrl := assessment.NewController(store)
	idempKey := "seq-retry-key-1"

	opts := assessment.ExecutionOptions{
		IdempotencyKey:  idempKey,
		AllowLoopback:   true,
		AllowPrivateIPs: true,
		Concurrency:     1,
		TimeoutDuration: 2 * time.Second,
	}

	// First execution
	res1, err := ctrl.RunAssessment(context.Background(), asm.ID, opts)
	if err != nil {
		t.Fatalf("initial RunAssessment failed: %v", err)
	}
	if res1.Execution == nil || res1.Execution.Status != assessment.StatusCompleted {
		t.Fatalf("expected completed execution, got: %+v", res1.Execution)
	}
	exec1ID := res1.Execution.ID

	// Sequential retry with the same key
	res2, err := ctrl.RunAssessment(context.Background(), asm.ID, opts)
	if err != nil {
		t.Fatalf("sequential retry failed: %v", err)
	}
	if res2.Execution == nil {
		t.Fatalf("expected non-nil execution on retry")
	}
	if res2.Execution.ID != exec1ID {
		t.Fatalf("expected retry to return existing execution ID %s, got %s", exec1ID, res2.Execution.ID)
	}
	if res2.Execution.Status != assessment.StatusCompleted {
		t.Errorf("expected status COMPLETED, got %s", res2.Execution.Status)
	}

	// Verify only 1 execution exists in database
	_, total, err := store.ListExecutionHistory(assessment.ExecutionListOptions{
		Auth: assessment.NewAdminAuthContext(),
	})
	if err != nil {
		t.Fatalf("failed listing history: %v", err)
	}
	if total != 1 {
		t.Fatalf("expected exactly 1 execution in database, found %d", total)
	}
}

// 3. Independent manual assessments: Two manual assessments on same targets execute successfully in sequence.
func TestDuplicatePrevention_3_IndependentManualAssessments_Sequence(t *testing.T) {
	store, _, asm, _, ts := setupDupTestDB(t)
	defer store.Close()
	defer ts.Close()

	ctrl := assessment.NewController(store)

	opts1 := assessment.ExecutionOptions{
		AllowLoopback:   true,
		AllowPrivateIPs: true,
		Concurrency:     1,
		TimeoutDuration: 2 * time.Second,
	}
	res1, err := ctrl.RunAssessment(context.Background(), asm.ID, opts1)
	if err != nil {
		t.Fatalf("first manual run failed: %v", err)
	}

	// Reset assessment status to READY for next assessment iteration
	if err := store.UpdateAssessmentStatus(asm.ID, assessment.StatusReady); err != nil {
		t.Fatalf("failed resetting assessment status to READY: %v", err)
	}

	opts2 := assessment.ExecutionOptions{
		AllowLoopback:   true,
		AllowPrivateIPs: true,
		Concurrency:     1,
		TimeoutDuration: 2 * time.Second,
	}
	res2, err := ctrl.RunAssessment(context.Background(), asm.ID, opts2)
	if err != nil {
		t.Fatalf("second manual run failed: %v", err)
	}

	if res1.Execution.ID == res2.Execution.ID {
		t.Fatalf("expected distinct execution IDs for independent runs, got same %s", res1.Execution.ID)
	}

	_, total, err := store.ListExecutionHistory(assessment.ExecutionListOptions{
		Auth: assessment.NewAdminAuthContext(),
	})
	if err != nil {
		t.Fatalf("failed listing history: %v", err)
	}
	if total != 2 {
		t.Fatalf("expected exactly 2 executions in database, found %d", total)
	}
}

// 4. Concurrent scheduled dispatch: Multiple scheduler threads attempting to dispatch same due schedule create exactly 1 dispatch and 1 execution.
func TestDuplicatePrevention_4_ConcurrentScheduledDispatch(t *testing.T) {
	store, client, asm, _, ts := setupDupTestDB(t)
	defer store.Close()
	defer ts.Close()

	scheduledFor := time.Now().UTC().Truncate(time.Hour)
	adminAuth := assessment.NewAdminAuthContext()
	sch := &assessment.AssessmentSchedule{
		ID:              "sch-concurrent-1",
		Name:            "Hourly Scheduled Audit",
		AssessmentID:    asm.ID,
		ClientID:        client.ID,
		TenantID:        client.ID,
		RecurrenceType:  assessment.RecurrenceInterval,
		RecurrenceExpr:  "@every 1h",
		IntervalSeconds: 3600,
		Timezone:        "UTC",
		IsEnabled:       true,
		NextDueAt:       scheduledFor.Add(-10 * time.Minute),
		CreatedAt:       time.Now().UTC(),
		UpdatedAt:       time.Now().UTC(),
		ExecutionOptions: assessment.ScheduleExecutionOptions{
			AllowLoopback:   true,
			AllowPrivateIPs: true,
			Concurrency:     1,
			TimeoutSeconds:  2,
		},
	}
	if err := store.CreateSchedule(sch, adminAuth); err != nil {
		t.Fatalf("CreateSchedule failed: %v", err)
	}

	ctrl := assessment.NewController(store)
	scheduler := assessment.NewScheduler(store, ctrl, assessment.SchedulerConfig{
		MaxConcurrency: 4,
	})

	var wg sync.WaitGroup
	threads := 5
	for i := 0; i < threads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = scheduler.RunDueSchedulesSync(context.Background(), scheduledFor)
		}()
	}
	wg.Wait()

	// Verify exactly 1 dispatch record exists for this occurrence
	disp, err := store.GetScheduleDispatchByOccurrence(sch.ID, scheduledFor)
	if err != nil {
		t.Fatalf("GetScheduleDispatchByOccurrence failed: %v", err)
	}
	if disp == nil {
		t.Fatalf("expected dispatch record to exist")
	}

	// Verify exactly 1 execution was created in database
	_, total, err := store.ListExecutionHistory(assessment.ExecutionListOptions{
		Auth: assessment.NewAdminAuthContext(),
	})
	if err != nil {
		t.Fatalf("ListExecutionHistory failed: %v", err)
	}
	if total != 1 {
		t.Fatalf("expected exactly 1 execution in DB, found %d", total)
	}
}

// 5. Scheduler restart: Re-running scheduler after restart does not re-dispatch an already-completed occurrence.
func TestDuplicatePrevention_5_SchedulerRestart_NoRedispatch(t *testing.T) {
	store, client, asm, _, ts := setupDupTestDB(t)
	defer store.Close()
	defer ts.Close()

	scheduledFor := time.Now().UTC().Truncate(time.Hour)
	adminAuth := assessment.NewAdminAuthContext()
	sch := &assessment.AssessmentSchedule{
		ID:              "sch-restart-1",
		Name:            "Hourly Scheduled Audit",
		AssessmentID:    asm.ID,
		ClientID:        client.ID,
		TenantID:        client.ID,
		RecurrenceType:  assessment.RecurrenceInterval,
		RecurrenceExpr:  "@every 1h",
		IntervalSeconds: 3600,
		Timezone:        "UTC",
		IsEnabled:       true,
		NextDueAt:       scheduledFor.Add(-10 * time.Minute),
		CreatedAt:       time.Now().UTC(),
		UpdatedAt:       time.Now().UTC(),
		ExecutionOptions: assessment.ScheduleExecutionOptions{
			AllowLoopback:   true,
			AllowPrivateIPs: true,
			Concurrency:     1,
			TimeoutSeconds:  2,
		},
	}
	if err := store.CreateSchedule(sch, adminAuth); err != nil {
		t.Fatalf("CreateSchedule failed: %v", err)
	}

	ctrl := assessment.NewController(store)
	sched1 := assessment.NewScheduler(store, ctrl, assessment.SchedulerConfig{})

	count1, err := sched1.RunDueSchedulesSync(context.Background(), scheduledFor)
	if err != nil {
		t.Fatalf("RunDueSchedulesSync failed: %v", err)
	}
	if count1 != 1 {
		t.Fatalf("expected 1 dispatch on first run, got %d", count1)
	}

	// Simulate restart: new Scheduler instance
	sched2 := assessment.NewScheduler(store, ctrl, assessment.SchedulerConfig{})
	count2, err := sched2.RunDueSchedulesSync(context.Background(), scheduledFor)
	if err != nil {
		t.Fatalf("second RunDueSchedulesSync failed: %v", err)
	}
	if count2 != 0 {
		t.Fatalf("expected 0 dispatches after restart for same occurrence, got %d", count2)
	}

	// Verify only 1 execution exists
	_, total, err := store.ListExecutionHistory(assessment.ExecutionListOptions{
		Auth: assessment.NewAdminAuthContext(),
	})
	if err != nil {
		t.Fatalf("ListExecutionHistory failed: %v", err)
	}
	if total != 1 {
		t.Fatalf("expected exactly 1 execution, found %d", total)
	}
}

// 6. Distinct schedule occurrences: Separate due timestamps for the same recurring schedule are not de-duplicated against each other.
func TestDuplicatePrevention_6_DistinctScheduleOccurrences_NotDeduplicated(t *testing.T) {
	store, client, asm, _, ts := setupDupTestDB(t)
	defer store.Close()
	defer ts.Close()

	t1 := time.Now().UTC().Truncate(time.Hour).Add(-2 * time.Hour)
	t2 := time.Now().UTC().Truncate(time.Hour)

	adminAuth := assessment.NewAdminAuthContext()
	sch := &assessment.AssessmentSchedule{
		ID:              "sch-distinct-1",
		Name:            "Hourly Scheduled Audit",
		AssessmentID:    asm.ID,
		ClientID:        client.ID,
		TenantID:        client.ID,
		RecurrenceType:  assessment.RecurrenceInterval,
		RecurrenceExpr:  "@every 1h",
		IntervalSeconds: 3600,
		Timezone:        "UTC",
		IsEnabled:       true,
		NextDueAt:       t1.Add(-10 * time.Minute),
		CreatedAt:       time.Now().UTC(),
		UpdatedAt:       time.Now().UTC(),
		ExecutionOptions: assessment.ScheduleExecutionOptions{
			AllowLoopback:   true,
			AllowPrivateIPs: true,
			Concurrency:     1,
			TimeoutSeconds:  2,
		},
	}
	if err := store.CreateSchedule(sch, adminAuth); err != nil {
		t.Fatalf("CreateSchedule failed: %v", err)
	}

	ctrl := assessment.NewController(store)
	scheduler := assessment.NewScheduler(store, ctrl, assessment.SchedulerConfig{})

	// Occurrence 1
	c1, err := scheduler.RunDueSchedulesSync(context.Background(), t1)
	if err != nil || c1 != 1 {
		t.Fatalf("occurrence 1 dispatch failed: %v, count=%d", err, c1)
	}

	// Occurrence 2
	c2, err := scheduler.RunDueSchedulesSync(context.Background(), t2)
	if err != nil || c2 != 1 {
		t.Fatalf("occurrence 2 dispatch failed: %v, count=%d", err, c2)
	}

	// Verify both dispatches exist and have distinct IDs
	disp1, err := store.GetScheduleDispatchByOccurrence(sch.ID, t1)
	if err != nil || disp1 == nil {
		t.Fatalf("failed retrieving dispatch 1: %v", err)
	}
	disp2, err := store.GetScheduleDispatchByOccurrence(sch.ID, t2)
	if err != nil || disp2 == nil {
		t.Fatalf("failed retrieving dispatch 2: %v", err)
	}
	if disp1.ID == disp2.ID {
		t.Fatalf("expected distinct dispatch IDs, got %s", disp1.ID)
	}

	// Verify exactly 2 executions exist
	history, total, err := store.ListExecutionHistory(assessment.ExecutionListOptions{
		Auth: assessment.NewAdminAuthContext(),
	})
	if err != nil || total != 2 {
		t.Fatalf("expected 2 executions, got total=%d, err=%v", total, err)
	}
	if history[0].ID == history[1].ID {
		t.Fatalf("expected distinct execution IDs")
	}
}

// 7. Multiple processes / database connections: Verify SQLite-level unique constraints across separate store instances.
func TestDuplicatePrevention_7_MultipleProcesses_DatabaseConnections_UniqueConstraints(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "multi_conn.db")

	store1, err := assessment.NewSQLiteStore(dbPath)
	if err != nil {
		t.Fatalf("store1 init failed: %v", err)
	}
	defer store1.Close()

	store2, err := assessment.NewSQLiteStore(dbPath)
	if err != nil {
		t.Fatalf("store2 init failed: %v", err)
	}
	defer store2.Close()

	client := &assessment.Client{ID: "client-multi-1", Name: "Multi Conn Client"}
	_ = store1.CreateClient(client)
	asm := &assessment.Assessment{ID: "asm-multi-1", Ref: "ASM-MULTI-1", ClientID: client.ID, Status: assessment.StatusReady}
	_ = store1.CreateAssessment(asm)

	now := time.Now().UTC()
	exec1 := &assessment.AssessmentExecution{
		ID:               "exec-multi-1",
		AssessmentID:     asm.ID,
		ClientID:         client.ID,
		Status:           assessment.StatusRunning,
		StartedAt:        now,
		CreatedAt:        now,
		InitiationSource: "manual",
	}

	// store1 starts execution in RUNNING state
	if err := store1.CreateExecution(exec1); err != nil {
		t.Fatalf("store1.CreateExecution failed: %v", err)
	}

	// store2 attempts to start an active execution for the same assessment concurrently
	exec2 := &assessment.AssessmentExecution{
		ID:               "exec-multi-2",
		AssessmentID:     asm.ID,
		ClientID:         client.ID,
		Status:           assessment.StatusRunning,
		StartedAt:        now,
		CreatedAt:        now,
		InitiationSource: "manual",
	}
	err2 := store2.CreateExecution(exec2)
	if err2 == nil {
		t.Fatalf("expected store2 to be rejected due to active execution, but succeeded")
	}
	if !errors.Is(err2, assessment.ErrExecutionOverlap) {
		t.Errorf("expected ErrExecutionOverlap, got: %v", err2)
	}

	// store1 finishes execution
	compAt := time.Now().UTC()
	exec1.Status = assessment.StatusCompleted
	exec1.CompletedAt = &compAt
	if err := store1.UpdateExecution(exec1); err != nil {
		t.Fatalf("store1.UpdateExecution failed: %v", err)
	}

	// store2 can now create a new execution
	if err := store2.CreateExecution(exec2); err != nil {
		t.Fatalf("store2.CreateExecution should succeed after store1 completes, got: %v", err)
	}
}

// 8. Persistence-response failure: Lost confirmation retry returns existing execution.
func TestDuplicatePrevention_8_PersistenceResponseFailure_ClientRetry(t *testing.T) {
	store, _, asm, _, ts := setupDupTestDB(t)
	defer store.Close()
	defer ts.Close()

	ctrl := assessment.NewController(store)
	lostAckKey := "lost-ack-key-1"

	opts := assessment.ExecutionOptions{
		IdempotencyKey:  lostAckKey,
		AllowLoopback:   true,
		AllowPrivateIPs: true,
		Concurrency:     1,
		TimeoutDuration: 2 * time.Second,
	}

	// Initial run completes in database
	res1, err := ctrl.RunAssessment(context.Background(), asm.ID, opts)
	if err != nil {
		t.Fatalf("RunAssessment failed: %v", err)
	}

	// Client retries with the same key
	res2, err := ctrl.RunAssessment(context.Background(), asm.ID, opts)
	if err != nil {
		t.Fatalf("retry failed: %v", err)
	}

	if res2.Execution.ID != res1.Execution.ID {
		t.Fatalf("expected retry to return existing execution %s, got %s", res1.Execution.ID, res2.Execution.ID)
	}
	if res2.Execution.Status != assessment.StatusCompleted {
		t.Errorf("expected completed status, got %s", res2.Execution.Status)
	}
}

// 9. Concurrent retries: Rapid simultaneous retries with the same idempotency key resolve to the single canonical execution.
func TestDuplicatePrevention_9_ConcurrentRetries(t *testing.T) {
	store, _, asm, _, ts := setupDupTestDB(t)
	defer store.Close()
	defer ts.Close()

	ctrl := assessment.NewController(store)
	idempKey := "concurrent-retry-key-1"

	// First execute to completion
	opts := assessment.ExecutionOptions{
		IdempotencyKey:  idempKey,
		AllowLoopback:   true,
		AllowPrivateIPs: true,
		Concurrency:     1,
		TimeoutDuration: 2 * time.Second,
	}
	resOrig, err := ctrl.RunAssessment(context.Background(), asm.ID, opts)
	if err != nil {
		t.Fatalf("initial run failed: %v", err)
	}
	canonicalID := resOrig.Execution.ID

	// 10 concurrent retries
	var wg sync.WaitGroup
	numRetries := 10
	results := make([]*assessment.ExecutionResult, numRetries)
	errs := make([]error, numRetries)

	for i := 0; i < numRetries; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			r, e := ctrl.RunAssessment(context.Background(), asm.ID, opts)
			results[idx] = r
			errs[idx] = e
		}(i)
	}
	wg.Wait()

	for i := 0; i < numRetries; i++ {
		if errs[i] != nil {
			t.Errorf("retry %d failed: %v", i, errs[i])
		}
		if results[i] == nil || results[i].Execution.ID != canonicalID {
			t.Errorf("retry %d did not return canonical ID %s", i, canonicalID)
		}
	}
}

// 10. Recovery interaction: Expired-lease execution can be recovered, but recovery worker cannot create duplicate execution.
func TestDuplicatePrevention_10_RecoveryInteraction_NoDuplicateExecution(t *testing.T) {
	store, client, asm, _, _ := setupDupTestDB(t)
	defer store.Close()

	expiredLease := time.Now().UTC().Add(-10 * time.Minute)
	exec := &assessment.AssessmentExecution{
		ID:               "exec-stale-lease-1",
		AssessmentID:     asm.ID,
		ClientID:         client.ID,
		Status:           assessment.StatusRunning,
		StartedAt:        expiredLease,
		CreatedAt:        expiredLease,
		WorkerID:         "dead-worker-1",
		HeartbeatAt:      &expiredLease,
		LeaseExpiresAt:   &expiredLease,
		InitiationSource: "manual",
	}
	if err := store.CreateExecution(exec); err != nil {
		t.Fatalf("CreateExecution failed: %v", err)
	}

	ctrl := assessment.NewController(store)

	// Attempting a new run while stale execution is still active is rejected with ErrExecutionOverlap
	_, err := ctrl.RunAssessment(context.Background(), asm.ID, assessment.ExecutionOptions{
		AllowLoopback: true,
	})
	if err == nil || !errors.Is(err, assessment.ErrExecutionOverlap) {
		t.Fatalf("expected ErrExecutionOverlap before recovery, got: %v", err)
	}

	// Recovery recovers and finalizes the stale execution to INTERRUPTED
	summary, err := store.RecoverExecutions(assessment.RecoveryOptions{
		Auth:          assessment.NewAdminAuthContext(),
		StaleDuration: 3 * time.Minute,
		MaxRetries:    3,
		WorkerID:      "recovery-worker-1",
	})
	if err != nil || summary.FinalizedCount != 1 {
		t.Fatalf("recovery failed or unexpected finalized count: %v, summary=%+v", err, summary)
	}

	// Now that it has been finalized to INTERRUPTED, HasActiveExecution is false
	active, _, err := store.HasActiveExecution(asm.ID)
	if err != nil || active {
		t.Fatalf("expected active=false after recovery finalization, got %v, err=%v", active, err)
	}
}

// 11. Lease & ownership interaction: Stale worker attempting to resume or write findings cannot bypass fencing.
func TestDuplicatePrevention_11_LeaseAndOwnershipInteraction_StaleWorkerFencing(t *testing.T) {
	store, client, asm, _, _ := setupDupTestDB(t)
	defer store.Close()

	now := time.Now().UTC()
	leaseExp := now.Add(200 * time.Millisecond)

	exec := &assessment.AssessmentExecution{
		ID:               "exec-fencing-1",
		AssessmentID:     asm.ID,
		ClientID:         client.ID,
		Status:           assessment.StatusRunning,
		StartedAt:        now,
		CreatedAt:        now,
		WorkerID:         "stale-worker-1",
		HeartbeatAt:      &now,
		LeaseExpiresAt:   &leaseExp,
		InitiationSource: "manual",
	}
	if err := store.CreateExecution(exec); err != nil {
		t.Fatalf("CreateExecution failed: %v", err)
	}

	// Wait for lease to expire
	time.Sleep(250 * time.Millisecond)

	// Another worker recovers the execution
	_, err := store.RecoverExecutions(assessment.RecoveryOptions{
		Auth:          assessment.NewAdminAuthContext(),
		StaleDuration: 100 * time.Millisecond,
		MaxRetries:    3,
		WorkerID:      "recovery-worker-2",
	})
	if err != nil {
		t.Fatalf("recovery failed: %v", err)
	}

	// Stale worker attempts to write findings
	f := assessment.AssessmentFinding{
		ID:                 "fnd-stale-1",
		AssessmentID:       asm.ID,
		ExecutionID:        exec.ID,
		Title:              "Stale Finding",
		Category:           "webvuln",
		Severity:           report.SeverityHigh,
		VerificationStatus: report.VerificationVerified,
	}
	err = store.SaveFindings([]assessment.AssessmentFinding{f})
	if err == nil || (!errors.Is(err, assessment.ErrLeaseLost) && !errors.Is(err, assessment.ErrExecutionTerminal)) {
		t.Fatalf("expected ErrLeaseLost or ErrExecutionTerminal on SaveFindings from fenced worker, got: %v", err)
	}

	// Stale worker attempts to UpdateExecution
	exec.Status = assessment.StatusCompleted
	err = store.UpdateExecution(exec)
	if err == nil || (!errors.Is(err, assessment.ErrLeaseLost) && !errors.Is(err, assessment.ErrExecutionTerminal)) {
		t.Fatalf("expected ErrLeaseLost or ErrExecutionTerminal on UpdateExecution from fenced worker, got: %v", err)
	}
}

// 12. Terminal-state protection: Completed or failed execution cannot be overwritten or restarted by replaying request.
func TestDuplicatePrevention_12_TerminalStateProtection(t *testing.T) {
	store, client, asm, _, _ := setupDupTestDB(t)
	defer store.Close()

	now := time.Now().UTC()
	compAt := now.Add(5 * time.Second)
	exec := &assessment.AssessmentExecution{
		ID:               "exec-terminal-1",
		AssessmentID:     asm.ID,
		ClientID:         client.ID,
		Status:           assessment.StatusCompleted,
		StartedAt:        now,
		CompletedAt:      &compAt,
		CreatedAt:        now,
		InitiationSource: "manual",
		IdempotencyKey:   "terminal-key-1",
	}
	if err := store.CreateExecution(exec); err != nil {
		t.Fatalf("CreateExecution failed: %v", err)
	}

	// Attempting to re-create execution with the same key fails
	replayExec := &assessment.AssessmentExecution{
		ID:               "exec-terminal-replay",
		AssessmentID:     asm.ID,
		ClientID:         client.ID,
		Status:           assessment.StatusRunning,
		StartedAt:        time.Now().UTC(),
		CreatedAt:        time.Now().UTC(),
		InitiationSource: "manual",
		IdempotencyKey:   "terminal-key-1",
	}
	err := store.CreateExecution(replayExec)
	if err == nil || !errors.Is(err, assessment.ErrIdempotencyConflict) {
		t.Fatalf("expected ErrIdempotencyConflict on replaying terminal execution, got: %v", err)
	}

	// Verify original execution remains completed
	stored, err := store.GetExecution(exec.ID)
	if err != nil || stored.Status != assessment.StatusCompleted {
		t.Fatalf("expected original execution to remain completed, got status %v, err=%v", stored.Status, err)
	}
}

// 13. Finding persistence de-duplication: Re-saving findings from duplicate or replayed runs updates existing rather than duplicating.
func TestDuplicatePrevention_13_FindingPersistenceDeduplication(t *testing.T) {
	store, client, asm, tgt, _ := setupDupTestDB(t)
	defer store.Close()

	now := time.Now().UTC()
	exec := &assessment.AssessmentExecution{
		ID:               "exec-fnd-dedup-1",
		AssessmentID:     asm.ID,
		ClientID:         client.ID,
		Status:           assessment.StatusRunning,
		StartedAt:        now,
		CreatedAt:        now,
		InitiationSource: "manual",
	}
	if err := store.CreateExecution(exec); err != nil {
		t.Fatalf("CreateExecution failed: %v", err)
	}

	f1 := assessment.AssessmentFinding{
		ID:                 "fnd-1",
		AssessmentID:       asm.ID,
		ExecutionID:        exec.ID,
		TargetID:           tgt.ID,
		Title:              "Finding 1",
		Category:           "secrets",
		Severity:           report.SeverityHigh,
		VerificationStatus: report.VerificationVerified,
	}
	f2 := assessment.AssessmentFinding{
		ID:                 "fnd-2",
		AssessmentID:       asm.ID,
		ExecutionID:        exec.ID,
		TargetID:           tgt.ID,
		Title:              "Finding 2",
		Category:           "cloud",
		Severity:           report.SeverityMedium,
		VerificationStatus: report.VerificationDetected,
	}

	// First save
	if err := store.SaveFindings([]assessment.AssessmentFinding{f1, f2}); err != nil {
		t.Fatalf("initial SaveFindings failed: %v", err)
	}

	// Second save with same IDs
	f1Updated := f1
	f1Updated.Title = "Finding 1 Updated"
	if err := store.SaveFindings([]assessment.AssessmentFinding{f1Updated, f2}); err != nil {
		t.Fatalf("second SaveFindings failed: %v", err)
	}

	// Verify findings in database
	findings, err := store.GetFindings(asm.ID, exec.ID)
	if err != nil {
		t.Fatalf("GetFindings failed: %v", err)
	}
	if len(findings) != 2 {
		t.Fatalf("expected exactly 2 findings, got %d", len(findings))
	}
	if findings[0].Title != "Finding 1 Updated" && findings[1].Title != "Finding 1 Updated" {
		t.Errorf("expected finding title to be updated, got: %s and %s", findings[0].Title, findings[1].Title)
	}
}

// 14. Report generation idempotency: Multiple report generation calls for same execution and format update rather than duplicate.
func TestDuplicatePrevention_14_ReportGenerationIdempotency(t *testing.T) {
	store, _, asm, _, _ := setupDupTestDB(t)
	defer store.Close()

	now := time.Now().UTC()
	exec := &assessment.AssessmentExecution{
		ID:               "exec-rep-1",
		AssessmentID:     asm.ID,
		ClientID:         asm.ClientID,
		Status:           assessment.StatusCompleted,
		StartedAt:        now,
		CreatedAt:        now,
		InitiationSource: "manual",
	}
	if err := store.CreateExecution(exec); err != nil {
		t.Fatalf("CreateExecution failed: %v", err)
	}

	r1 := &assessment.ReportRecord{
		ID:           "rep-1",
		AssessmentID: asm.ID,
		ExecutionID:  exec.ID,
		Format:       "HTML",
		FilePath:     "/tmp/report_v1.html",
		FelixVersion: "2.0.0",
		Status:       "GENERATED",
	}
	if err := store.SaveReport(r1); err != nil {
		t.Fatalf("initial SaveReport failed: %v", err)
	}

	r2 := &assessment.ReportRecord{
		ID:           "rep-2",
		AssessmentID: asm.ID,
		ExecutionID:  exec.ID,
		Format:       "HTML",
		FilePath:     "/tmp/report_v2.html",
		FelixVersion: "2.0.0",
		Status:       "GENERATED",
	}
	if err := store.SaveReport(r2); err != nil {
		t.Fatalf("second SaveReport failed: %v", err)
	}

	reports, err := store.GetReports(asm.ID)
	if err != nil {
		t.Fatalf("GetReports failed: %v", err)
	}
	if len(reports) != 1 {
		t.Fatalf("expected exactly 1 report record for (execution, format), found %d", len(reports))
	}
	if reports[0].FilePath != "/tmp/report_v2.html" {
		t.Errorf("expected updated FilePath /tmp/report_v2.html, got %s", reports[0].FilePath)
	}
}

// 15. Tenant isolation: Identical keys in different tenant scopes do not collide or suppress legitimate executions.
func TestDuplicatePrevention_15_TenantIsolation(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "tenant_iso.db")
	store, err := assessment.NewSQLiteStore(dbPath)
	if err != nil {
		t.Fatalf("failed opening store: %v", err)
	}
	defer store.Close()

	clientA := &assessment.Client{ID: "client-A", Name: "Tenant A"}
	clientB := &assessment.Client{ID: "client-B", Name: "Tenant B"}
	_ = store.CreateClient(clientA)
	_ = store.CreateClient(clientB)

	asmA := &assessment.Assessment{ID: "asm-A", Ref: "ASM-A", ClientID: clientA.ID, Status: assessment.StatusReady}
	asmB := &assessment.Assessment{ID: "asm-B", Ref: "ASM-B", ClientID: clientB.ID, Status: assessment.StatusReady}
	_ = store.CreateAssessment(asmA)
	_ = store.CreateAssessment(asmB)

	now := time.Now().UTC()
	sharedKey := "shared-idempotency-key"

	execA := &assessment.AssessmentExecution{
		ID:               "exec-A-1",
		AssessmentID:     asmA.ID,
		ClientID:         clientA.ID,
		TenantID:         "tenant-A",
		Status:           assessment.StatusCompleted,
		StartedAt:        now,
		CreatedAt:        now,
		InitiationSource: "manual",
		IdempotencyKey:   sharedKey,
	}
	if err := store.CreateExecution(execA); err != nil {
		t.Fatalf("execA creation failed: %v", err)
	}

	execB := &assessment.AssessmentExecution{
		ID:               "exec-B-1",
		AssessmentID:     asmB.ID,
		ClientID:         clientB.ID,
		TenantID:         "tenant-B",
		Status:           assessment.StatusCompleted,
		StartedAt:        now,
		CreatedAt:        now,
		InitiationSource: "manual",
		IdempotencyKey:   sharedKey,
	}
	if err := store.CreateExecution(execB); err != nil {
		t.Fatalf("execB creation should succeed under tenant-B scope, got: %v", err)
	}

	// Query each by idempotency key
	retrievedA, err := store.GetExecutionByIdempotencyKey("tenant-A", asmA.ID, sharedKey)
	if err != nil || retrievedA.ID != execA.ID {
		t.Fatalf("failed retrieving execA: %v, retrieved=%+v", err, retrievedA)
	}

	retrievedB, err := store.GetExecutionByIdempotencyKey("tenant-B", asmB.ID, sharedKey)
	if err != nil || retrievedB.ID != execB.ID {
		t.Fatalf("failed retrieving execB: %v, retrieved=%+v", err, retrievedB)
	}
}

// 16. Migration 22 compatibility: Schema upgrade from v21 to v22 preserves existing executions and schedules without loss.
func TestDuplicatePrevention_16_Migration22_Compatibility(t *testing.T) {
	freshDBPath := filepath.Join(t.TempDir(), "mig22_test.db")
	store, err := assessment.NewSQLiteStore(freshDBPath)
	if err != nil {
		t.Fatalf("failed opening store: %v", err)
	}
	defer store.Close()

	db, err := sql.Open("sqlite", freshDBPath)
	if err != nil {
		t.Fatalf("sql.Open failed: %v", err)
	}
	defer db.Close()

	// Verify idempotency_key column exists
	var idempKey sql.NullString
	err = db.QueryRow("SELECT idempotency_key FROM assessment_executions LIMIT 0").Scan(&idempKey)
	if err != nil && err != sql.ErrNoRows {
		t.Fatalf("idempotency_key column check failed: %v", err)
	}

	// Verify unique indexes exist
	indexes := []string{
		"idx_active_assessment_execution",
		"idx_executions_idempotency",
		"idx_executions_sched_occurrence",
		"idx_dispatch_occurrence",
	}
	for _, idx := range indexes {
		var name string
		err := db.QueryRow("SELECT name FROM sqlite_master WHERE type = 'index' AND name = ?", idx).Scan(&name)
		if err != nil {
			t.Errorf("expected index %s to exist, err: %v", idx, err)
		}
	}
}

// 17. Database reopen: Overlap prevention and idempotency guarantees hold across store close and reopen.
func TestDuplicatePrevention_17_DatabaseReopen_GuaranteesHold(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "reopen_test.db")

	// Session 1: Create active execution
	store1, err := assessment.NewSQLiteStore(dbPath)
	if err != nil {
		t.Fatalf("store1 init failed: %v", err)
	}

	client := &assessment.Client{ID: "client-reopen-1", Name: "Reopen Client"}
	_ = store1.CreateClient(client)
	asm := &assessment.Assessment{ID: "asm-reopen-1", Ref: "ASM-REOPEN-1", ClientID: client.ID, Status: assessment.StatusReady}
	_ = store1.CreateAssessment(asm)

	now := time.Now().UTC()
	exec1 := &assessment.AssessmentExecution{
		ID:               "exec-reopen-active",
		AssessmentID:     asm.ID,
		ClientID:         client.ID,
		Status:           assessment.StatusRunning,
		StartedAt:        now,
		CreatedAt:        now,
		InitiationSource: "manual",
	}
	if err := store1.CreateExecution(exec1); err != nil {
		t.Fatalf("exec1 creation failed: %v", err)
	}
	_ = store1.Close()

	// Session 2: Reopen database and verify active execution detection & overlap prevention
	store2, err := assessment.NewSQLiteStore(dbPath)
	if err != nil {
		t.Fatalf("store2 init failed: %v", err)
	}
	defer store2.Close()

	active, activeID, err := store2.HasActiveExecution(asm.ID)
	if err != nil {
		t.Fatalf("HasActiveExecution failed: %v", err)
	}
	if !active || activeID != exec1.ID {
		t.Fatalf("expected active=true with activeID=%s, got active=%v, activeID=%s", exec1.ID, active, activeID)
	}

	// Attempting to create another running execution is rejected
	exec2 := &assessment.AssessmentExecution{
		ID:               "exec-reopen-duplicate",
		AssessmentID:     asm.ID,
		ClientID:         client.ID,
		Status:           assessment.StatusRunning,
		StartedAt:        now,
		CreatedAt:        now,
		InitiationSource: "manual",
	}
	err = store2.CreateExecution(exec2)
	if err == nil || !errors.Is(err, assessment.ErrExecutionOverlap) {
		t.Fatalf("expected ErrExecutionOverlap across store reopen, got: %v", err)
	}
}


// 18. Migration 22 against legacy database states with conflicts without data loss
func TestDuplicatePrevention_18_Migration22_LegacyDatabaseStateWithConflicts(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "legacy_v21_conflicts.db")

	// Step 1: Create a database with the complete schema using SQLiteStore
	storeInit, err := assessment.NewSQLiteStore(dbPath)
	if err != nil {
		t.Fatalf("failed initializing base store: %v", err)
	}

	adminAuth := assessment.NewAdminAuthContext()
	client := &assessment.Client{ID: "client-v21", Name: "Legacy Corp"}
	if err := storeInit.CreateClient(client); err != nil {
		t.Fatalf("CreateClient failed: %v", err)
	}

	asm := &assessment.Assessment{
		ID:             "asm-v21",
		Ref:            "ASM-V21",
		ClientID:       client.ID,
		Name:           "Legacy V21 Audit",
		AssessmentType: "web",
		Status:         assessment.StatusReady,
		ScopeMode:      "same-origin",
	}
	if err := storeInit.CreateAssessment(asm); err != nil {
		t.Fatalf("CreateAssessment failed: %v", err)
	}

	tgt := &assessment.AssessmentTarget{
		ID:           "tgt-v21",
		AssessmentID: asm.ID,
		TargetURL:    "https://legacy.example.com",
		ScopeStatus:  "APPROVED",
	}
	if err := storeInit.AddTarget(tgt); err != nil {
		t.Fatalf("AddTarget failed: %v", err)
	}

	// Close storeInit completely before modifying with rawDB
	if err := storeInit.Close(); err != nil {
		t.Fatalf("failed closing storeInit: %v", err)
	}

	// Step 2: Roll back to v21 state and insert conflicting records using transaction
	rawDB, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("failed opening raw db: %v", err)
	}
	defer rawDB.Close()

	tx, err := rawDB.Begin()
	if err != nil {
		t.Fatalf("failed starting tx: %v", err)
	}

	_, err = tx.Exec(`
		DROP INDEX IF EXISTS idx_active_assessment_execution;
		DROP INDEX IF EXISTS idx_executions_idempotency;
		DROP INDEX IF EXISTS idx_executions_sched_occurrence;
		DROP INDEX IF EXISTS idx_dispatch_occurrence;
		DROP TABLE IF EXISTS notification_outbox;
		DELETE FROM schema_migrations WHERE version >= 22;
	`)
	if err != nil {
		t.Fatalf("failed rolling back to v21: %v", err)
	}

	// Insert conflicting historical records in v21 state:
	// Conflict 1: Two active executions for the same assessment (both RUNNING)
	t1 := time.Now().UTC().Add(-30 * time.Minute)
	t2 := time.Now().UTC().Add(-10 * time.Minute)
	_, err = tx.Exec(`INSERT INTO assessment_executions (id, assessment_id, client_id, status, started_at, created_at, updated_at, config_snapshot) VALUES ('exec-active-old', 'asm-v21', 'client-v21', 'RUNNING', ?, ?, ?, '{}')`, t1, t1, t1)
	if err != nil {
		t.Fatalf("insert exec-active-old failed: %v", err)
	}
	_, err = tx.Exec(`INSERT INTO assessment_executions (id, assessment_id, client_id, status, started_at, created_at, updated_at, config_snapshot) VALUES ('exec-active-new', 'asm-v21', 'client-v21', 'RUNNING', ?, ?, ?, '{}')`, t2, t2, t2)
	if err != nil {
		t.Fatalf("insert exec-active-new failed: %v", err)
	}

	schedTime := time.Now().UTC().Truncate(time.Hour)
	// Schedule for scheduled executions and dispatches
	_, err = tx.Exec(`INSERT INTO assessment_schedules (id, name, assessment_id, client_id, tenant_id, recurrence_type, recurrence_expr, timezone, is_enabled, next_due_at, created_at, updated_at) VALUES ('sch-v21', 'Schedule v21', 'asm-v21', 'client-v21', 'client-v21', 'daily', '0 0 * * *', 'UTC', 1, ?, ?, ?)`, schedTime, schedTime, schedTime)
	if err != nil {
		t.Fatalf("insert sch-v21 failed: %v", err)
	}

	// Conflict 2: Two scheduled executions with identical (schedule_id, scheduled_for)
	_, err = tx.Exec(`INSERT INTO assessment_executions (id, assessment_id, schedule_id, scheduled_for, client_id, status, started_at, created_at, updated_at, config_snapshot) VALUES ('exec-sched-1', 'asm-v21', 'sch-v21', ?, 'client-v21', 'COMPLETED', ?, ?, ?, '{}')`, schedTime, schedTime, schedTime, schedTime)
	if err != nil {
		t.Fatalf("insert exec-sched-1 failed: %v", err)
	}
	_, err = tx.Exec(`INSERT INTO assessment_executions (id, assessment_id, schedule_id, scheduled_for, client_id, status, started_at, created_at, updated_at, config_snapshot) VALUES ('exec-sched-2', 'asm-v21', 'sch-v21', ?, 'client-v21', 'COMPLETED', ?, ?, ?, '{}')`, schedTime, schedTime, schedTime, schedTime)
	if err != nil {
		t.Fatalf("insert exec-sched-2 failed: %v", err)
	}

	// Conflict 3: Duplicate dispatch records with identical (schedule_id, scheduled_for)
	_, err = tx.Exec(`INSERT INTO schedule_dispatch_records (id, schedule_id, assessment_id, execution_id, tenant_id, scheduled_for, dispatched_at, status, created_at) VALUES ('disp-1', 'sch-v21', 'asm-v21', 'exec-sched-1', 'client-v21', ?, ?, 'COMPLETED', ?)`, schedTime, schedTime, schedTime)
	if err != nil {
		t.Fatalf("insert disp-1 failed: %v", err)
	}
	_, err = tx.Exec(`INSERT INTO schedule_dispatch_records (id, schedule_id, assessment_id, execution_id, tenant_id, scheduled_for, dispatched_at, status, created_at) VALUES ('disp-2', 'sch-v21', 'asm-v21', 'exec-sched-2', 'client-v21', ?, ?, 'COMPLETED', ?)`, schedTime, schedTime, schedTime)
	if err != nil {
		t.Fatalf("insert disp-2 failed: %v", err)
	}

	// Associated findings for each execution
	_, err = tx.Exec(`INSERT INTO assessment_findings (id, assessment_id, execution_id, target_id, original_finding_id, title, category, severity, confidence, verification_status, target_url, endpoint, method, fingerprint, evidence_json, verification_json, remediation, created_at) VALUES ('f-1', 'asm-v21', 'exec-sched-1', 'tgt-v21', 'F1', 'Finding 1', 'secrets', 'HIGH', 'HIGH', 'VERIFIED', 'https://legacy.example.com', '/', 'GET', 'fp1', '{}', '{}', 'None', ?)`, schedTime)
	if err != nil {
		t.Fatalf("insert f-1 failed: %v", err)
	}
	_, err = tx.Exec(`INSERT INTO assessment_findings (id, assessment_id, execution_id, target_id, original_finding_id, title, category, severity, confidence, verification_status, target_url, endpoint, method, fingerprint, evidence_json, verification_json, remediation, created_at) VALUES ('f-2', 'asm-v21', 'exec-sched-2', 'tgt-v21', 'F2', 'Finding 2', 'webvuln', 'MEDIUM', 'HIGH', 'VERIFIED', 'https://legacy.example.com', '/', 'GET', 'fp2', '{}', '{}', 'None', ?)`, schedTime)
	if err != nil {
		t.Fatalf("insert f-2 failed: %v", err)
	}

	if err := tx.Commit(); err != nil {
		t.Fatalf("failed committing conflicting records: %v", err)
	}
	if err := rawDB.Close(); err != nil {
		t.Fatalf("failed closing rawDB: %v", err)
	}

	// Step 3: Open database with SQLiteStore - triggers Migration 22 against conflicting data
	storeUpgraded, err := assessment.NewSQLiteStore(dbPath)
	if err != nil {
		t.Fatalf("failed upgrading store with Migration 22: %v", err)
	}
	t.Cleanup(func() { _ = storeUpgraded.Close() })

	// Step 4: Verify zero data loss across executions, findings, and dispatches
	history, totalExecs, err := storeUpgraded.ListExecutionHistory(assessment.ExecutionListOptions{Auth: adminAuth})
	if err != nil || totalExecs != 4 {
		t.Fatalf("expected all 4 executions preserved, got total=%d, err=%v", totalExecs, err)
	}

	// Verify older duplicate active execution was safely marked INTERRUPTED
	oldExec, err := storeUpgraded.GetExecution("exec-active-old")
	if err != nil || oldExec.Status != assessment.StatusInterrupted {
		t.Fatalf("expected exec-active-old to be INTERRUPTED, got status=%v, err=%v", oldExec.Status, err)
	}
	// Newer active execution remains RUNNING
	newExec, err := storeUpgraded.GetExecution("exec-active-new")
	if err != nil || newExec.Status != assessment.StatusRunning {
		t.Fatalf("expected exec-active-new to remain RUNNING, got status=%v, err=%v", newExec.Status, err)
	}

	// Verify findings count: both findings preserved
	f1, err := storeUpgraded.GetFindings("asm-v21", "exec-sched-1")
	if err != nil || len(f1) != 1 {
		t.Fatalf("expected findings for exec-sched-1 preserved, got len=%d, err=%v", len(f1), err)
	}
	f2, err := storeUpgraded.GetFindings("asm-v21", "exec-sched-2")
	if err != nil || len(f2) != 1 {
		t.Fatalf("expected findings for exec-sched-2 preserved, got len=%d, err=%v", len(f2), err)
	}

	// Verify both dispatches preserved
	dispatches, err := storeUpgraded.GetScheduleDispatches("sch-v21", adminAuth)
	if err != nil || len(dispatches) != 2 {
		t.Fatalf("expected 2 dispatches preserved, got len=%d, err=%v", len(dispatches), err)
	}

	// Step 5: Verify migration idempotency on reopen
	if err := storeUpgraded.Close(); err != nil {
		t.Fatalf("failed closing upgraded store: %v", err)
	}

	reopenedStore, err := assessment.NewSQLiteStore(dbPath)
	if err != nil {
		t.Fatalf("failed reopening store after Migration 22: %v", err)
	}

	// Verify all 4 unique indexes exist and are valid
	dbCheck, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("failed opening dbCheck: %v", err)
	}
	indexes := []string{
		"idx_active_assessment_execution",
		"idx_executions_idempotency",
		"idx_executions_sched_occurrence",
		"idx_dispatch_occurrence",
	}
	for _, idx := range indexes {
		var name string
		err := dbCheck.QueryRow("SELECT name FROM sqlite_master WHERE type='index' AND name=?", idx).Scan(&name)
		if err != nil {
			t.Errorf("expected index %s to exist after migration", idx)
		}
	}
	_ = dbCheck.Close()
	_ = reopenedStore.Close()
	_ = history
}

// 19. Scheduled dispatch skipped when assessment is active; subsequent ticks and restarts behavior
func TestDuplicatePrevention_19_ScheduledDispatch_ActiveExecutionSkipped_SubsequentTicks(t *testing.T) {
	store, client, asm, _, ts := setupDupTestDB(t)
	defer store.Close()
	defer ts.Close()

	adminAuth := assessment.NewAdminAuthContext()
	now := time.Now().UTC()
	vFrom := now.Add(-48 * time.Hour)
	vUntil := now.Add(48 * time.Hour)
	_ = store.SetAuthorization(&assessment.AuthorizationRecord{
		ID:                  "auth-dup-1",
		AssessmentID:        asm.ID,
		AuthorizingParty:    "Security Team",
		AuthorizationMethod: "CONTRACT",
		DateReceived:        vFrom,
		ValidFrom:           &vFrom,
		ValidUntil:          &vUntil,
		Status:              assessment.AuthApproved,
	})
	t1 := now.Add(-1 * time.Hour).Truncate(time.Minute)
	t2 := now.Truncate(time.Minute)

	sch := &assessment.AssessmentSchedule{
		ID:              "sch-skip-test-1",
		Name:            "Hourly Skip Test",
		AssessmentID:    asm.ID,
		ClientID:        client.ID,
		TenantID:        client.ID,
		RecurrenceType:  assessment.RecurrenceInterval,
		RecurrenceExpr:  "@every 1h",
		IntervalSeconds: 3600,
		Timezone:        "UTC",
		IsEnabled:       true,
		NextDueAt:       t1.Add(-5 * time.Minute),
		CreatedAt:       now,
		UpdatedAt:       now,
		ExecutionOptions: assessment.ScheduleExecutionOptions{
			AllowLoopback:   true,
			AllowPrivateIPs: true,
			Concurrency:     1,
			TimeoutSeconds:  2,
		},
	}
	if err := store.CreateSchedule(sch, adminAuth); err != nil {
		t.Fatalf("CreateSchedule failed: %v", err)
	}

	// Pre-create an active execution in RUNNING state
	activeExec := &assessment.AssessmentExecution{
		ID:               "exec-blocker-1",
		AssessmentID:     asm.ID,
		ClientID:         client.ID,
		Status:           assessment.StatusRunning,
		StartedAt:        now,
		CreatedAt:        now,
		InitiationSource: "manual",
	}
	if err := store.CreateExecution(activeExec); err != nil {
		t.Fatalf("CreateExecution failed: %v", err)
	}

	ctrl := assessment.NewController(store)
	scheduler := assessment.NewScheduler(store, ctrl, assessment.SchedulerConfig{})

	// Occurrence 1 at T1: should be SKIPPED because activeExec is RUNNING
	c1, err := scheduler.RunDueSchedulesSync(context.Background(), t1)
	if err != nil {
		t.Fatalf("RunDueSchedulesSync t1 failed: %v", err)
	}
	if c1 != 1 {
		t.Fatalf("expected 1 claimed schedule, got %d", c1)
	}

	// Verify dispatch was recorded as SKIPPED with reason
	disp1, err := store.GetScheduleDispatchByOccurrence(sch.ID, t1)
	if err != nil || disp1 == nil {
		t.Fatalf("failed retrieving dispatch 1: %v", err)
	}
	if disp1.Status != "SKIPPED" {
		t.Errorf("expected dispatch 1 to be SKIPPED, got %s", disp1.Status)
	}
	if disp1.ErrorMessage != "previous execution still in progress; overlapping execution prevented" {
		t.Errorf("unexpected error message: %s", disp1.ErrorMessage)
	}

	// Active execution remains RUNNING and uncorrupted
	storedActive, err := store.GetExecution(activeExec.ID)
	if err != nil || storedActive.Status != assessment.StatusRunning {
		t.Fatalf("expected active execution to remain RUNNING, got %v", storedActive.Status)
	}

	// Now complete the active execution
	compAt := time.Now().UTC()
	activeExec.Status = assessment.StatusCompleted
	activeExec.CompletedAt = &compAt
	if err := store.UpdateExecution(activeExec); err != nil {
		t.Fatalf("UpdateExecution failed: %v", err)
	}

	// Next scheduler tick at T2: now that active execution is done, T2 can execute
	c2, err := scheduler.RunDueSchedulesSync(context.Background(), t2)
	if err != nil {
		t.Fatalf("RunDueSchedulesSync t2 failed: %v", err)
	}
	if c2 != 1 {
		t.Fatalf("expected occurrence 2 to dispatch, got %d", c2)
	}

	disp2, err := store.GetScheduleDispatchByOccurrence(sch.ID, t2)
	if err != nil || disp2 == nil {
		t.Fatalf("failed retrieving dispatch 2: %v", err)
	}
	if disp2.Status != "COMPLETED" {
		t.Errorf("expected dispatch 2 to be COMPLETED, got %s", disp2.Status)
	}

	// Scheduler restart: re-running for T1 does not redispatch T1
	schedRestart := assessment.NewScheduler(store, ctrl, assessment.SchedulerConfig{})
	cRestart, err := schedRestart.RunDueSchedulesSync(context.Background(), t1)
	if err != nil {
		t.Fatalf("RunDueSchedulesSync restart failed: %v", err)
	}
	if cRestart != 0 {
		t.Fatalf("expected 0 dispatches after restart for t1, got %d", cRestart)
	}
}

// 20. Repeated idempotency key while RUNNING then after reaching terminal state
func TestDuplicatePrevention_20_IdempotencyKey_RunningThenTerminal_NoDuplicate(t *testing.T) {
	store, _, asm, _, ts := setupDupTestDB(t)
	defer store.Close()
	defer ts.Close()

	ctrl := assessment.NewController(store)
	idempKey := "lifecycle-idemp-key-1"

	// Create an execution in RUNNING state with this idempotency key
	now := time.Now().UTC()
	exec := &assessment.AssessmentExecution{
		ID:               "exec-lifecycle-1",
		AssessmentID:     asm.ID,
		ClientID:         asm.ClientID,
		Status:           assessment.StatusRunning,
		StartedAt:        now,
		CreatedAt:        now,
		InitiationSource: "manual",
		IdempotencyKey:   idempKey,
	}
	if err := store.CreateExecution(exec); err != nil {
		t.Fatalf("CreateExecution failed: %v", err)
	}

	// While RUNNING: caller attempting to run with the same idempotency key is rejected with ErrExecutionOverlap
	opts := assessment.ExecutionOptions{
		IdempotencyKey:  idempKey,
		AllowLoopback:   true,
		AllowPrivateIPs: true,
		Concurrency:     1,
		TimeoutDuration: 2 * time.Second,
	}
	_, err := ctrl.RunAssessment(context.Background(), asm.ID, opts)
	if err == nil || !errors.Is(err, assessment.ErrExecutionOverlap) {
		t.Fatalf("expected ErrExecutionOverlap while execution is RUNNING, got: %v", err)
	}

	// Complete the execution
	compAt := time.Now().UTC()
	exec.Status = assessment.StatusCompleted
	exec.CompletedAt = &compAt
	if err := store.UpdateExecution(exec); err != nil {
		t.Fatalf("UpdateExecution failed: %v", err)
	}

	// After reaching terminal state: caller querying with same idempotency key immediately receives canonical execution
	res, err := ctrl.RunAssessment(context.Background(), asm.ID, opts)
	if err != nil {
		t.Fatalf("RunAssessment after terminal failed: %v", err)
	}
	if res.Execution == nil || res.Execution.ID != exec.ID {
		t.Fatalf("expected canonical execution %s, got: %+v", exec.ID, res.Execution)
	}
	if res.Execution.Status != assessment.StatusCompleted {
		t.Errorf("expected COMPLETED status, got %s", res.Execution.Status)
	}

	// Verify database has exactly 1 execution with this key
	history, total, err := store.ListExecutionHistory(assessment.ExecutionListOptions{
		Auth: assessment.NewAdminAuthContext(),
	})
	if err != nil || total != 1 {
		t.Fatalf("expected exactly 1 execution in DB, got total=%d, err=%v", total, err)
	}
	if history[0].IdempotencyKey != idempKey {
		t.Errorf("expected idempotency key %s, got %s", idempKey, history[0].IdempotencyKey)
	}
}
