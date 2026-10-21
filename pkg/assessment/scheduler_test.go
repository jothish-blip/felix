package assessment

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"
)

type mockRunner struct {
	runCount   int32
	activeRuns int32
	maxSeen    int32
	runDelay   time.Duration
	failWith   error
}

func (m *mockRunner) RunAssessment(ctx context.Context, assessmentID string, opts ExecutionOptions) (*ExecutionResult, error) {
	atomic.AddInt32(&m.runCount, 1)
	current := atomic.AddInt32(&m.activeRuns, 1)
	defer atomic.AddInt32(&m.activeRuns, -1)

	for {
		seen := atomic.LoadInt32(&m.maxSeen)
		if current <= seen {
			break
		}
		if atomic.CompareAndSwapInt32(&m.maxSeen, seen, current) {
			break
		}
	}

	if m.runDelay > 0 {
		time.Sleep(m.runDelay)
	}

	if m.failWith != nil {
		return nil, m.failWith
	}

	return &ExecutionResult{
		Execution: &AssessmentExecution{
			ID:           "exec-" + assessmentID,
			AssessmentID: assessmentID,
			Status:       StatusCompleted,
		},
	}, nil
}

func setupAuthorizedAssessment(t *testing.T, store *SQLiteStore, asmID string) {
	t.Helper()
	setupTestAssessment(t, store, "client-1", asmID)

	now := time.Now().UTC()
	validFrom := now.Add(-24 * time.Hour)
	validUntil := now.Add(24 * time.Hour)

	auth := &AuthorizationRecord{
		ID:                  "auth-" + asmID,
		AssessmentID:        asmID,
		AuthorizingParty:    "Security Team",
		AuthorizationMethod: "WRITTEN_CONTRACT",
		DateReceived:        validFrom,
		ValidFrom:           &validFrom,
		ValidUntil:          &validUntil,
		Status:              AuthApproved,
	}
	if err := store.SetAuthorization(auth); err != nil {
		t.Fatalf("SetAuthorization failed: %v", err)
	}

	target := &AssessmentTarget{
		ID:           "tgt-" + asmID,
		AssessmentID: asmID,
		TargetURL:    "https://api.example.com",
		TargetType:   TargetAPIBaseURL,
		ScopeStatus:  "APPROVED",
	}
	if err := store.AddTarget(target); err != nil {
		t.Fatalf("AddTarget failed: %v", err)
	}
}

func TestScheduler_StartStop(t *testing.T) {
	store, cleanup := newTestScheduleStore(t)
	defer cleanup()

	runner := &mockRunner{}
	cfg := SchedulerConfig{
		PollInterval:    50 * time.Millisecond,
		MaxConcurrency:  2,
		ShutdownTimeout: 1 * time.Second,
	}

	sched := NewScheduler(store, runner, cfg)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := sched.Start(ctx); err != nil {
		t.Fatalf("Start failed: %v", err)
	}
	if !sched.IsRunning() {
		t.Errorf("expected scheduler to be running")
	}

	// Double start should fail
	if err := sched.Start(ctx); err == nil {
		t.Errorf("expected error on double start")
	}

	if err := sched.Stop(); err != nil {
		t.Fatalf("Stop failed: %v", err)
	}
	if sched.IsRunning() {
		t.Errorf("expected scheduler to not be running after Stop")
	}
}

func TestScheduler_ExecutionSuccess(t *testing.T) {
	store, cleanup := newTestScheduleStore(t)
	defer cleanup()

	setupAuthorizedAssessment(t, store, "asm-exec-1")
	adminAuth := NewAdminAuthContext()

	now := time.Now().UTC()
	pastDue := now.Add(-5 * time.Minute)

	s := &AssessmentSchedule{
		ID:             "sched-success",
		Name:           "Success Schedule",
		AssessmentID:   "asm-exec-1",
		ClientID:       "client-1",
		RecurrenceType: RecurrenceInterval,
		RecurrenceExpr: "@every 1h",
		IntervalSeconds: 3600,
		Timezone:       "UTC",
		IsEnabled:      true,
		NextDueAt:      pastDue,
	}
	if err := store.CreateSchedule(s, adminAuth); err != nil {
		t.Fatalf("CreateSchedule failed: %v", err)
	}

	runner := &mockRunner{}
	scheduler := NewScheduler(store, runner, DefaultSchedulerConfig())

	count, err := scheduler.RunDueSchedulesSync(context.Background(), now)
	if err != nil {
		t.Fatalf("RunDueSchedulesSync failed: %v", err)
	}
	if count != 1 {
		t.Fatalf("expected 1 dispatched, got %d", count)
	}
	if atomic.LoadInt32(&runner.runCount) != 1 {
		t.Fatalf("expected runner to be called once, got %d", runner.runCount)
	}

	// Verify dispatch telemetry recorded
	dispatches, err := store.GetScheduleDispatches(s.ID, adminAuth)
	if err != nil || len(dispatches) != 1 {
		t.Fatalf("expected 1 dispatch record, got %v (err=%v)", dispatches, err)
	}
	if dispatches[0].Status != "COMPLETED" || dispatches[0].ExecutionID != "exec-asm-exec-1" {
		t.Errorf("unexpected dispatch record: %+v", dispatches[0])
	}

	// Verify schedule record updated
	updated, _ := store.GetSchedule(s.ID, adminAuth)
	if updated.LastCompletedAt == nil || updated.LastExecutionID != "exec-asm-exec-1" {
		t.Errorf("expected schedule last completion to be updated: %+v", updated)
	}
}

func TestScheduler_RefuseWhenNotAuthorized(t *testing.T) {
	store, cleanup := newTestScheduleStore(t)
	defer cleanup()

	// Setup assessment with EXPIRED authorization
	setupTestAssessment(t, store, "client-1", "asm-expired")
	adminAuth := NewAdminAuthContext()

	expiredFrom := time.Now().UTC().Add(-48 * time.Hour)
	expiredUntil := time.Now().UTC().Add(-24 * time.Hour)

	auth := &AuthorizationRecord{
		ID:                  "auth-exp",
		AssessmentID:        "asm-expired",
		AuthorizingParty:    "Security Team",
		AuthorizationMethod: "WRITTEN_CONTRACT",
		DateReceived:        expiredFrom,
		ValidFrom:           &expiredFrom,
		ValidUntil:          &expiredUntil,
		Status:              AuthApproved,
	}
	_ = store.SetAuthorization(auth)
	_ = store.AddTarget(&AssessmentTarget{
		ID:           "tgt-exp",
		AssessmentID: "asm-expired",
		TargetURL:    "https://api.example.com",
		ScopeStatus:  "APPROVED",
	})

	now := time.Now().UTC()
	s := &AssessmentSchedule{
		ID:             "sched-exp",
		Name:           "Expired Auth Schedule",
		AssessmentID:   "asm-expired",
		ClientID:       "client-1",
		RecurrenceType: RecurrenceInterval,
		RecurrenceExpr: "@every 1h",
		IntervalSeconds: 3600,
		Timezone:       "UTC",
		IsEnabled:      true,
		NextDueAt:      now.Add(-10 * time.Minute),
	}
	if err := store.CreateSchedule(s, adminAuth); err != nil {
		t.Fatalf("CreateSchedule failed: %v", err)
	}

	runner := &mockRunner{}
	scheduler := NewScheduler(store, runner, DefaultSchedulerConfig())

	count, err := scheduler.RunDueSchedulesSync(context.Background(), now)
	if err != nil {
		t.Fatalf("RunDueSchedulesSync failed: %v", err)
	}
	if count != 1 {
		t.Fatalf("expected 1 schedule claimed, got %d", count)
	}

	// Runner must NOT have been called
	if atomic.LoadInt32(&runner.runCount) != 0 {
		t.Fatalf("runner should not be called for expired auth, got %d calls", runner.runCount)
	}

	// Telemetry must record SKIPPED with reason
	dispatches, err := store.GetScheduleDispatches(s.ID, adminAuth)
	if err != nil || len(dispatches) != 1 {
		t.Fatalf("expected 1 dispatch record: %v", dispatches)
	}
	if dispatches[0].Status != "SKIPPED" {
		t.Errorf("expected SKIPPED status, got %s", dispatches[0].Status)
	}
}

func TestScheduler_RefuseWhenZeroApprovedTargets(t *testing.T) {
	store, cleanup := newTestScheduleStore(t)
	defer cleanup()

	// Setup assessment with targets having ScopeStatus == "PENDING"
	setupTestAssessment(t, store, "client-1", "asm-notargets")
	adminAuth := NewAdminAuthContext()

	now := time.Now().UTC()
	validFrom := now.Add(-24 * time.Hour)
	validUntil := now.Add(24 * time.Hour)

	auth := &AuthorizationRecord{
		ID:                  "auth-valid",
		AssessmentID:        "asm-notargets",
		AuthorizingParty:    "Security Team",
		AuthorizationMethod: "WRITTEN_CONTRACT",
		DateReceived:        validFrom,
		ValidFrom:           &validFrom,
		ValidUntil:          &validUntil,
		Status:              AuthApproved,
	}
	_ = store.SetAuthorization(auth)
	_ = store.AddTarget(&AssessmentTarget{
		ID:           "tgt-pending",
		AssessmentID: "asm-notargets",
		TargetURL:    "https://api.example.com",
		ScopeStatus:  "PENDING", // Not approved!
	})

	s := &AssessmentSchedule{
		ID:             "sched-pending",
		Name:           "Pending Target Schedule",
		AssessmentID:   "asm-notargets",
		ClientID:       "client-1",
		RecurrenceType: RecurrenceInterval,
		RecurrenceExpr: "@every 1h",
		IntervalSeconds: 3600,
		Timezone:       "UTC",
		IsEnabled:      true,
		NextDueAt:      now.Add(-10 * time.Minute),
	}
	if err := store.CreateSchedule(s, adminAuth); err != nil {
		t.Fatalf("CreateSchedule failed: %v", err)
	}

	runner := &mockRunner{}
	scheduler := NewScheduler(store, runner, DefaultSchedulerConfig())

	count, err := scheduler.RunDueSchedulesSync(context.Background(), now)
	if err != nil {
		t.Fatalf("RunDueSchedulesSync failed: %v", err)
	}
	if count != 1 {
		t.Fatalf("expected 1 schedule claimed, got %d", count)
	}

	// Runner must NOT have been called
	if atomic.LoadInt32(&runner.runCount) != 0 {
		t.Fatalf("runner should not be called for zero approved targets, got %d calls", runner.runCount)
	}

	dispatches, err := store.GetScheduleDispatches(s.ID, adminAuth)
	if err != nil || len(dispatches) != 1 {
		t.Fatalf("expected 1 dispatch record: %v", dispatches)
	}
	if dispatches[0].Status != "SKIPPED" {
		t.Errorf("expected SKIPPED status, got %s", dispatches[0].Status)
	}
}

func TestScheduler_ExecutionFailureRecorded(t *testing.T) {
	store, cleanup := newTestScheduleStore(t)
	defer cleanup()

	setupAuthorizedAssessment(t, store, "asm-fail-1")
	adminAuth := NewAdminAuthContext()

	now := time.Now().UTC()
	s := &AssessmentSchedule{
		ID:             "sched-fail",
		Name:           "Failing Schedule",
		AssessmentID:   "asm-fail-1",
		ClientID:       "client-1",
		RecurrenceType: RecurrenceInterval,
		RecurrenceExpr: "@every 1h",
		IntervalSeconds: 3600,
		Timezone:       "UTC",
		IsEnabled:      true,
		NextDueAt:      now.Add(-5 * time.Minute),
	}
	if err := store.CreateSchedule(s, adminAuth); err != nil {
		t.Fatalf("CreateSchedule failed: %v", err)
	}

	runner := &mockRunner{
		failWith: errors.New("network target unreachable"),
	}
	scheduler := NewScheduler(store, runner, DefaultSchedulerConfig())

	_, _ = scheduler.RunDueSchedulesSync(context.Background(), now)

	// Verify dispatch telemetry recorded FAILED
	dispatches, _ := store.GetScheduleDispatches(s.ID, adminAuth)
	if len(dispatches) != 1 || dispatches[0].Status != "FAILED" {
		t.Fatalf("expected 1 FAILED dispatch, got %+v", dispatches)
	}

	// Verify schedule telemetry incremented failure count
	updated, _ := store.GetSchedule(s.ID, adminAuth)
	if updated.FailureCount != 1 || updated.ConsecutiveFailures != 1 {
		t.Errorf("expected failure counts 1, got %+v", updated)
	}
	if updated.LastError != "network target unreachable" {
		t.Errorf("expected last error recorded, got %s", updated.LastError)
	}
}
