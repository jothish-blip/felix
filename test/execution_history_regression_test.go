package test

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"felix/pkg/assessment"
	_ "modernc.org/sqlite"
)

func helperNewExecutionTestStore(t *testing.T) (*assessment.SQLiteStore, string, func()) {
	t.Helper()
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, fmt.Sprintf("test_exec_%d.db", time.Now().UnixNano()))
	store, err := assessment.NewSQLiteStore(dbPath)
	if err != nil {
		t.Fatalf("failed to create sqlite store: %v", err)
	}
	cleanup := func() {
		_ = store.Close()
	}
	return store, dbPath, cleanup
}

func helperSeedAssessmentWithAuth(t *testing.T, store *assessment.SQLiteStore, clientID, asmID, tenantID, accountID string) *assessment.Assessment {
	t.Helper()
	_ = store.CreateClient(&assessment.Client{
		ID:        clientID,
		Name:      "Client " + clientID,
		CreatedAt: time.Now().UTC(),
		UpdatedAt: time.Now().UTC(),
	})

	asm := &assessment.Assessment{
		ID:             asmID,
		Ref:            "ASM-" + asmID,
		ClientID:       clientID,
		Name:           "Assessment " + asmID,
		AssessmentType: "BLACK_BOX_WEB",
		Status:         assessment.StatusReady,
		ScopeMode:      "same-origin",
		CreatedAt:      time.Now().UTC(),
		UpdatedAt:      time.Now().UTC(),
	}
	if err := store.CreateAssessment(asm); err != nil {
		t.Fatalf("CreateAssessment failed: %v", err)
	}

	now := time.Now().UTC()
	validFrom := now.Add(-24 * time.Hour)
	validUntil := now.Add(24 * time.Hour)
	authRec := &assessment.AuthorizationRecord{
		ID:                  "auth-" + asmID,
		AssessmentID:        asmID,
		AuthorizingParty:    "Security Team",
		AuthorizationMethod: "WRITTEN_CONTRACT",
		DateReceived:        validFrom,
		ValidFrom:           &validFrom,
		ValidUntil:          &validUntil,
		Status:              assessment.AuthApproved,
	}
	if err := store.SetAuthorization(authRec); err != nil {
		t.Fatalf("SetAuthorization failed: %v", err)
	}

	target := &assessment.AssessmentTarget{
		ID:           "tgt-" + asmID,
		AssessmentID: asmID,
		TargetURL:    "https://example.com/api",
		TargetType:   assessment.TargetAPIBaseURL,
		ScopeStatus:  "APPROVED",
	}
	if err := store.AddTarget(target); err != nil {
		t.Fatalf("AddTarget failed: %v", err)
	}

	return asm
}

// -----------------------------------------------------------------------------
// Category A: Assessment Record Lifecycle & Terminal State Transitions
// -----------------------------------------------------------------------------

func TestExecutionHistory_RecordLifecycle_QueuedRunningCompleted(t *testing.T) {
	store, _, cleanup := helperNewExecutionTestStore(t)
	defer cleanup()

	helperSeedAssessmentWithAuth(t, store, "client-1", "asm-1", "tenant-1", "acc-1")
	authCtx := assessment.NewAdminAuthContext()

	now := time.Now().UTC()
	execID := "exec-lifecycle-1"

	// 1. Initial creation in QUEUED state
	queuedExec := &assessment.AssessmentExecution{
		ID:               execID,
		AssessmentID:     "asm-1",
		ClientID:         "client-1",
		TenantID:         "tenant-1",
		AccountID:        "acc-1",
		Status:           assessment.StatusQueued,
		InitiationSource: "manual",
		AssessmentType:   "BLACK_BOX_WEB",
		StartedAt:        now,
		CreatedAt:        now,
		UpdatedAt:        now,
	}

	if err := store.CreateExecution(queuedExec); err != nil {
		t.Fatalf("CreateExecution(QUEUED) failed: %v", err)
	}

	// Read back and verify QUEUED
	got, err := store.GetExecutionHistory(execID, authCtx)
	if err != nil {
		t.Fatalf("GetExecutionHistory failed: %v", err)
	}
	if got.Status != assessment.StatusQueued {
		t.Fatalf("expected status %s, got %s", assessment.StatusQueued, got.Status)
	}
	if got.InitiationSource != "manual" {
		t.Fatalf("expected source 'manual', got %s", got.InitiationSource)
	}

	// 2. Transition QUEUED -> RUNNING
	got.Status = assessment.StatusRunning
	got.TargetCount = 3
	if err := store.UpdateExecution(got); err != nil {
		t.Fatalf("UpdateExecution(RUNNING) failed: %v", err)
	}

	gotRunning, err := store.GetExecutionHistory(execID, authCtx)
	if err != nil {
		t.Fatalf("GetExecutionHistory(RUNNING) failed: %v", err)
	}
	if gotRunning.Status != assessment.StatusRunning {
		t.Fatalf("expected status %s, got %s", assessment.StatusRunning, gotRunning.Status)
	}
	if gotRunning.TargetCount != 3 {
		t.Fatalf("expected TargetCount 3, got %d", gotRunning.TargetCount)
	}

	// 3. Transition RUNNING -> COMPLETED
	completedAt := now.Add(45 * time.Second)
	gotRunning.Status = assessment.StatusCompleted
	gotRunning.CompletedAt = &completedAt
	gotRunning.DurationMs = 45000
	gotRunning.FindingCount = 5
	gotRunning.SnapshotID = "snap-exec-1"

	if err := store.UpdateExecution(gotRunning); err != nil {
		t.Fatalf("UpdateExecution(COMPLETED) failed: %v", err)
	}

	gotCompleted, err := store.GetExecutionHistory(execID, authCtx)
	if err != nil {
		t.Fatalf("GetExecutionHistory(COMPLETED) failed: %v", err)
	}
	if gotCompleted.Status != assessment.StatusCompleted {
		t.Fatalf("expected status %s, got %s", assessment.StatusCompleted, gotCompleted.Status)
	}
	if gotCompleted.FindingCount != 5 {
		t.Fatalf("expected FindingCount 5, got %d", gotCompleted.FindingCount)
	}
	if gotCompleted.SnapshotID != "snap-exec-1" {
		t.Fatalf("expected SnapshotID snap-exec-1, got %s", gotCompleted.SnapshotID)
	}
	if gotCompleted.DurationMs != 45000 {
		t.Fatalf("expected DurationMs 45000, got %d", gotCompleted.DurationMs)
	}
	if gotCompleted.CompletedAt == nil {
		t.Fatalf("expected CompletedAt to be set")
	}
}

func TestExecutionHistory_TerminalStates(t *testing.T) {
	store, _, cleanup := helperNewExecutionTestStore(t)
	defer cleanup()

	helperSeedAssessmentWithAuth(t, store, "client-1", "asm-1", "tenant-1", "acc-1")
	authCtx := assessment.NewAdminAuthContext()
	now := time.Now().UTC()

	terminalStatuses := []assessment.AssessmentStatus{
		assessment.StatusCompletedWithErrors,
		assessment.StatusFailed,
		assessment.StatusCancelled,
		assessment.StatusSkipped,
		assessment.StatusInterrupted,
	}

	for i, termStatus := range terminalStatuses {
		execID := fmt.Sprintf("exec-term-%d", i)
		exec := &assessment.AssessmentExecution{
			ID:               execID,
			AssessmentID:     "asm-1",
			ClientID:         "client-1",
			TenantID:         "tenant-1",
			AccountID:        "acc-1",
			Status:           assessment.StatusRunning,
			InitiationSource: "manual",
			StartedAt:        now,
			CreatedAt:        now,
			UpdatedAt:        now,
		}
		if termStatus == assessment.StatusSkipped {
			exec.Status = assessment.StatusQueued
		}

		if err := store.CreateExecution(exec); err != nil {
			t.Fatalf("CreateExecution for %s failed: %v", termStatus, err)
		}

		completedAt := now.Add(10 * time.Second)
		exec.Status = termStatus
		exec.CompletedAt = &completedAt
		exec.DurationMs = 10000
		exec.ErrorMessage = fmt.Sprintf("execution reached terminal %s", termStatus)

		if err := store.UpdateExecution(exec); err != nil {
			t.Fatalf("UpdateExecution to terminal %s failed: %v", termStatus, err)
		}

		got, err := store.GetExecutionHistory(execID, authCtx)
		if err != nil {
			t.Fatalf("GetExecutionHistory for %s failed: %v", termStatus, err)
		}
		if got.Status != termStatus {
			t.Fatalf("expected status %s, got %s", termStatus, got.Status)
		}
		if got.ErrorMessage != exec.ErrorMessage {
			t.Fatalf("expected error message %q, got %q", exec.ErrorMessage, got.ErrorMessage)
		}
		if got.CompletedAt == nil {
			t.Fatalf("expected completedAt to be set for %s", termStatus)
		}
	}
}

func TestExecutionHistory_StateMachineIntegrityAndImmutability(t *testing.T) {
	store, _, cleanup := helperNewExecutionTestStore(t)
	defer cleanup()

	helperSeedAssessmentWithAuth(t, store, "client-1", "asm-1", "tenant-1", "acc-1")
	authCtx := assessment.NewAdminAuthContext()
	now := time.Now().UTC()

	execID := "exec-immut-1"
	exec := &assessment.AssessmentExecution{
		ID:               execID,
		AssessmentID:     "asm-1",
		ClientID:         "client-1",
		TenantID:         "tenant-1",
		AccountID:        "acc-1",
		Status:           assessment.StatusRunning,
		InitiationSource: "manual",
		StartedAt:        now,
		CreatedAt:        now,
		UpdatedAt:        now,
	}
	if err := store.CreateExecution(exec); err != nil {
		t.Fatalf("CreateExecution failed: %v", err)
	}

	// Complete the execution
	completedAt := now.Add(20 * time.Second)
	exec.Status = assessment.StatusCompleted
	exec.CompletedAt = &completedAt
	exec.DurationMs = 20000
	exec.FindingCount = 4
	if err := store.UpdateExecution(exec); err != nil {
		t.Fatalf("UpdateExecution to COMPLETED failed: %v", err)
	}

	// 1. Attempt invalid transition COMPLETED -> RUNNING (must fail)
	invalidUpdate := *exec
	invalidUpdate.Status = assessment.StatusRunning
	err := store.UpdateExecution(&invalidUpdate)
	if err == nil {
		t.Fatalf("expected error transitioning COMPLETED -> RUNNING, got nil")
	}
	if !errors.Is(err, assessment.ErrInvalidStateTransition) {
		t.Fatalf("expected ErrInvalidStateTransition, got: %v", err)
	}

	// 2. Attempt invalid transition COMPLETED -> FAILED (must fail)
	invalidUpdate.Status = assessment.StatusFailed
	err = store.UpdateExecution(&invalidUpdate)
	if err == nil {
		t.Fatalf("expected error transitioning COMPLETED -> FAILED, got nil")
	}
	if !errors.Is(err, assessment.ErrInvalidStateTransition) {
		t.Fatalf("expected ErrInvalidStateTransition, got: %v", err)
	}

	// 3. Idempotent finalization: updating with same COMPLETED status succeeds idempotently
	idempotentUpdate := *exec
	idempotentUpdate.Status = assessment.StatusCompleted
	if err := store.UpdateExecution(&idempotentUpdate); err != nil {
		t.Fatalf("expected idempotent terminal update to succeed, got: %v", err)
	}

	// Verify data remains uncorrupted
	got, err := store.GetExecutionHistory(execID, authCtx)
	if err != nil {
		t.Fatalf("GetExecutionHistory failed: %v", err)
	}
	if got.Status != assessment.StatusCompleted {
		t.Fatalf("expected status COMPLETED, got %s", got.Status)
	}
	if got.FindingCount != 4 {
		t.Fatalf("expected FindingCount 4, got %d", got.FindingCount)
	}
}

// -----------------------------------------------------------------------------
// Category B: Persistence Across DB Close and Reopen
// -----------------------------------------------------------------------------

func TestExecutionHistory_PersistenceAcrossStoreCloseReopen(t *testing.T) {
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "exec_persistence_test.db")

	now := time.Now().UTC().Truncate(time.Millisecond)

	// Phase 1: Open store, seed assessment and multiple execution records
	{
		store, err := assessment.NewSQLiteStore(dbPath)
		if err != nil {
			t.Fatalf("failed to create store: %v", err)
		}

		helperSeedAssessmentWithAuth(t, store, "client-persist", "asm-persist", "tenant-p", "acc-p")

		// Create record 1: COMPLETED
		cAt1 := now.Add(30 * time.Second)
		e1 := &assessment.AssessmentExecution{
			ID:               "exec-p-1",
			AssessmentID:     "asm-persist",
			ClientID:         "client-persist",
			TenantID:         "tenant-p",
			AccountID:        "acc-p",
			ScheduleID:       "sched-ref-1",
			Status:           assessment.StatusCompleted,
			InitiationSource: "scheduled",
			AssessmentType:   "BLACK_BOX_WEB",
			TargetCount:      2,
			FindingCount:     7,
			SnapshotID:       "snap-p-1",
			StartedAt:        now,
			CompletedAt:      &cAt1,
			DurationMs:       30000,
			CreatedAt:        now,
			UpdatedAt:        now,
		}
		if err := store.CreateExecution(e1); err != nil {
			t.Fatalf("CreateExecution e1 failed: %v", err)
		}

		// Create record 2: SKIPPED
		cAt2 := now.Add(1 * time.Second)
		e2 := &assessment.AssessmentExecution{
			ID:               "exec-p-2",
			AssessmentID:     "asm-persist",
			ClientID:         "client-persist",
			TenantID:         "tenant-p",
			AccountID:        "acc-p",
			ScheduleID:       "sched-ref-1",
			Status:           assessment.StatusSkipped,
			InitiationSource: "scheduled",
			AssessmentType:   "BLACK_BOX_WEB",
			TargetCount:      0,
			FindingCount:     0,
			ErrorMessage:     "authorization expired before start",
			StartedAt:        now.Add(1 * time.Minute),
			CompletedAt:      &cAt2,
			DurationMs:       1000,
			CreatedAt:        now.Add(1 * time.Minute),
			UpdatedAt:        now.Add(1 * time.Minute),
		}
		if err := store.CreateExecution(e2); err != nil {
			t.Fatalf("CreateExecution e2 failed: %v", err)
		}

		if err := store.Close(); err != nil {
			t.Fatalf("failed to close store: %v", err)
		}
	}

	// Phase 2: Reopen store from disk and verify byte-for-byte fidelity
	{
		store, err := assessment.NewSQLiteStore(dbPath)
		if err != nil {
			t.Fatalf("failed to reopen store: %v", err)
		}
		defer store.Close()

		authCtx := assessment.NewAdminAuthContext()

		e1, err := store.GetExecutionHistory("exec-p-1", authCtx)
		if err != nil {
			t.Fatalf("GetExecutionHistory(exec-p-1) failed after reopen: %v", err)
		}
		if e1.Status != assessment.StatusCompleted {
			t.Errorf("e1: expected COMPLETED, got %s", e1.Status)
		}
		if e1.ScheduleID != "sched-ref-1" {
			t.Errorf("e1: expected ScheduleID 'sched-ref-1', got %s", e1.ScheduleID)
		}
		if e1.InitiationSource != "scheduled" {
			t.Errorf("e1: expected source 'scheduled', got %s", e1.InitiationSource)
		}
		if e1.TargetCount != 2 || e1.FindingCount != 7 {
			t.Errorf("e1: expected targets=2, findings=7, got targets=%d, findings=%d", e1.TargetCount, e1.FindingCount)
		}
		if e1.SnapshotID != "snap-p-1" {
			t.Errorf("e1: expected snapshot 'snap-p-1', got %s", e1.SnapshotID)
		}
		if e1.DurationMs != 30000 {
			t.Errorf("e1: expected duration 30000, got %d", e1.DurationMs)
		}

		e2, err := store.GetExecutionHistory("exec-p-2", authCtx)
		if err != nil {
			t.Fatalf("GetExecutionHistory(exec-p-2) failed after reopen: %v", err)
		}
		if e2.Status != assessment.StatusSkipped {
			t.Errorf("e2: expected SKIPPED, got %s", e2.Status)
		}
		if e2.ErrorMessage != "authorization expired before start" {
			t.Errorf("e2: expected error message 'authorization expired before start', got %q", e2.ErrorMessage)
		}
		if e2.TargetCount != 0 {
			t.Errorf("e2: expected target count 0, got %d", e2.TargetCount)
		}
	}
}

// -----------------------------------------------------------------------------
// Category C: Database Migration v20 Verification
// -----------------------------------------------------------------------------

func TestExecutionHistory_MigrationV20SchemaVerification(t *testing.T) {
	_, dbPath, cleanup := helperNewExecutionTestStore(t)
	defer cleanup()

	rawDB, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("failed to open raw db: %v", err)
	}
	defer rawDB.Close()

	// Verify migration v20 is recorded in schema_migrations
	var count int
	err = rawDB.QueryRow("SELECT COUNT(*) FROM schema_migrations WHERE version >= 20").Scan(&count)
	if err != nil {
		t.Fatalf("failed querying schema_migrations: %v", err)
	}
	if count < 1 {
		t.Fatalf("expected migration v20 to be recorded, found %d", count)
	}

	// Verify columns exist on assessment_executions
	columnsToCheck := []string{
		"schedule_id",
		"scheduled_for",
		"client_id",
		"tenant_id",
		"account_id",
		"initiation_source",
		"assessment_type",
		"target_count",
		"finding_count",
		"snapshot_id",
		"created_at",
		"updated_at",
	}

	rows, err := rawDB.Query("PRAGMA table_info(assessment_executions)")
	if err != nil {
		t.Fatalf("PRAGMA table_info failed: %v", err)
	}
	defer rows.Close()

	foundCols := make(map[string]bool)
	for rows.Next() {
		var cid int
		var name, ctype string
		var notnull, pk int
		var dfltValue interface{}
		if err := rows.Scan(&cid, &name, &ctype, &notnull, &dfltValue, &pk); err != nil {
			t.Fatalf("scanning pragma row failed: %v", err)
		}
		foundCols[name] = true
	}

	for _, col := range columnsToCheck {
		if !foundCols[col] {
			t.Errorf("expected column %q to exist in assessment_executions", col)
		}
	}

	// Verify multi-column indexes exist
	indexRows, err := rawDB.Query("PRAGMA index_list(assessment_executions)")
	if err != nil {
		t.Fatalf("PRAGMA index_list failed: %v", err)
	}
	defer indexRows.Close()

	foundIdx := make(map[string]bool)
	for indexRows.Next() {
		var seq int
		var name string
		var unique int
		var origin, partial interface{}
		if err := indexRows.Scan(&seq, &name, &unique, &origin, &partial); err != nil {
			t.Fatalf("scanning index row failed: %v", err)
		}
		foundIdx[name] = true
	}

	expectedIndices := []string{"idx_executions_schedule_id", "idx_executions_tenant_acc", "idx_executions_assessment_id"}
	for _, idx := range expectedIndices {
		if !foundIdx[idx] {
			t.Errorf("expected index %q on assessment_executions", idx)
		}
	}
}

// -----------------------------------------------------------------------------
// Category D: Manual Assessment Execution Integration
// -----------------------------------------------------------------------------

func TestExecutionHistory_ManualAssessmentExecutionIntegration(t *testing.T) {
	store, _, cleanup := helperNewExecutionTestStore(t)
	defer cleanup()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("<html><head><title>Test Target</title></head><body><h1>Felix Security Scan Target</h1></body></html>"))
	}))
	defer server.Close()

	_ = store.CreateClient(&assessment.Client{
		ID:        "client-ctrl",
		Name:      "Client ctrl",
		CreatedAt: time.Now().UTC(),
		UpdatedAt: time.Now().UTC(),
	})
	asm := &assessment.Assessment{
		ID:             "asm-ctrl",
		Ref:            "ASM-ctrl",
		ClientID:       "client-ctrl",
		Name:           "Assessment ctrl",
		AssessmentType: "BLACK_BOX_WEB",
		Status:         assessment.StatusReady,
		ScopeMode:      "same-origin",
	}
	if err := store.CreateAssessment(asm); err != nil {
		t.Fatalf("CreateAssessment failed: %v", err)
	}

	now := time.Now().UTC()
	validFrom := now.Add(-24 * time.Hour)
	validUntil := now.Add(24 * time.Hour)
	if err := store.SetAuthorization(&assessment.AuthorizationRecord{
		ID:                  "auth-ctrl",
		AssessmentID:        asm.ID,
		AuthorizingParty:    "Security Team",
		AuthorizationMethod: "WRITTEN_CONTRACT",
		DateReceived:        validFrom,
		ValidFrom:           &validFrom,
		ValidUntil:          &validUntil,
		Status:              assessment.AuthApproved,
	}); err != nil {
		t.Fatalf("SetAuthorization failed: %v", err)
	}

	if err := store.AddTarget(&assessment.AssessmentTarget{
		ID:           "tgt-ctrl",
		AssessmentID: asm.ID,
		TargetURL:    server.URL,
		TargetType:   assessment.TargetWebsite,
		ScopeStatus:  "APPROVED",
	}); err != nil {
		t.Fatalf("AddTarget failed: %v", err)
	}

	ctrl := assessment.NewController(store)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	runOpts := assessment.ExecutionOptions{
		TimeoutDuration: 10 * time.Second,
		Concurrency:     2,
		AllowLoopback:   true,
	}

	// Run assessment through the actual controller
	res, err := ctrl.RunAssessment(ctx, asm.ID, runOpts)
	if err != nil {
		t.Fatalf("RunAssessment failed: %v", err)
	}

	if res.Execution == nil || res.Execution.ID == "" {
		t.Fatalf("expected non-empty Execution in ExecutionResult")
	}

	authCtx := assessment.NewAdminAuthContext()
	execRec, err := store.GetExecutionHistory(res.Execution.ID, authCtx)
	if err != nil {
		t.Fatalf("GetExecutionHistory(%s) failed: %v", res.Execution.ID, err)
	}

	// Verify record contents
	if execRec.AssessmentID != asm.ID {
		t.Errorf("expected AssessmentID %s, got %s", asm.ID, execRec.AssessmentID)
	}
	if execRec.ClientID != asm.ClientID {
		t.Errorf("expected ClientID %s, got %s", asm.ClientID, execRec.ClientID)
	}
	if execRec.InitiationSource != "manual" {
		t.Errorf("expected InitiationSource 'manual', got %s", execRec.InitiationSource)
	}
	if execRec.Status != assessment.StatusCompleted {
		t.Errorf("expected status COMPLETED, got %s (err: %s)", execRec.Status, execRec.ErrorMessage)
	}
	if execRec.CompletedAt == nil {
		t.Errorf("expected non-nil CompletedAt")
	}
	if execRec.DurationMs <= 0 {
		t.Errorf("expected positive DurationMs, got %d", execRec.DurationMs)
	}
	if execRec.SnapshotID == "" {
		t.Errorf("expected non-empty SnapshotID linking execution to assessment snapshot")
	}
}

// -----------------------------------------------------------------------------
// Category E: Scheduled Assessment Execution & Bidirectional Linkage
// -----------------------------------------------------------------------------

func TestExecutionHistory_ScheduledAssessmentIntegrationAndDispatchLink(t *testing.T) {
	store, _, cleanup := helperNewExecutionTestStore(t)
	defer cleanup()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("<html><head><title>Scheduled Scan Target</title></head><body><h1>Scheduled</h1></body></html>"))
	}))
	defer server.Close()

	_ = store.CreateClient(&assessment.Client{
		ID:        "client-sch",
		Name:      "Client sch",
		CreatedAt: time.Now().UTC(),
		UpdatedAt: time.Now().UTC(),
	})
	asm := &assessment.Assessment{
		ID:             "asm-sch",
		Ref:            "ASM-sch",
		ClientID:       "client-sch",
		Name:           "Assessment sch",
		AssessmentType: "BLACK_BOX_WEB",
		Status:         assessment.StatusReady,
		ScopeMode:      "same-origin",
	}
	if err := store.CreateAssessment(asm); err != nil {
		t.Fatalf("CreateAssessment failed: %v", err)
	}

	now := time.Now().UTC()
	validFrom := now.Add(-24 * time.Hour)
	validUntil := now.Add(24 * time.Hour)
	if err := store.SetAuthorization(&assessment.AuthorizationRecord{
		ID:                  "auth-sch",
		AssessmentID:        asm.ID,
		AuthorizingParty:    "Security Team",
		AuthorizationMethod: "WRITTEN_CONTRACT",
		DateReceived:        validFrom,
		ValidFrom:           &validFrom,
		ValidUntil:          &validUntil,
		Status:              assessment.AuthApproved,
	}); err != nil {
		t.Fatalf("SetAuthorization failed: %v", err)
	}

	if err := store.AddTarget(&assessment.AssessmentTarget{
		ID:           "tgt-sch",
		AssessmentID: asm.ID,
		TargetURL:    server.URL,
		TargetType:   assessment.TargetWebsite,
		ScopeStatus:  "APPROVED",
	}); err != nil {
		t.Fatalf("AddTarget failed: %v", err)
	}
	adminAuth := assessment.NewAdminAuthContext()

	// 1. Create a schedule with AllowLoopback true
	sched := &assessment.AssessmentSchedule{
		ID:             "sched-link-1",
		Name:           "Hourly Scan",
		AssessmentID:   asm.ID,
		AssessmentRef:  asm.Ref,
		ClientID:       asm.ClientID,
		TenantID:       "tenant-sch",
		AccountID:      "acc-sch",
		RecurrenceType: assessment.RecurrenceInterval,
		RecurrenceExpr: "@every 1h",
		Timezone:       "UTC",
		IsEnabled:      true,
		CatchUpPolicy:  "once",
		NextDueAt:      time.Now().UTC().Add(-1 * time.Minute),
		ExecutionOptions: assessment.ScheduleExecutionOptions{
			AllowLoopback: true,
		},
	}
	if err := store.CreateSchedule(sched, adminAuth); err != nil {
		t.Fatalf("CreateSchedule failed: %v", err)
	}

	// 2. Dispatch via scheduler synchronously
	ctrl := assessment.NewController(store)
	scheduler := assessment.NewScheduler(store, ctrl, assessment.DefaultSchedulerConfig())

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	dispatched, err := scheduler.RunDueSchedulesSync(ctx, time.Now().UTC())
	if err != nil {
		t.Fatalf("RunDueSchedulesSync failed: %v", err)
	}
	if dispatched != 1 {
		t.Fatalf("expected 1 dispatched schedule, got %d", dispatched)
	}

	// 3. Verify dispatch record
	dispatches, err := store.GetScheduleDispatches(sched.ID, adminAuth)
	if err != nil {
		t.Fatalf("GetScheduleDispatches failed: %v", err)
	}
	if len(dispatches) != 1 {
		t.Fatalf("expected 1 dispatch record, got %d", len(dispatches))
	}

	disp := dispatches[0]
	if disp.ExecutionID == "" {
		t.Fatalf("expected dispatch record to have non-empty ExecutionID")
	}

	// 4. Verify canonical AssessmentExecution record matches dispatch record
	execRec, err := store.GetExecutionHistory(disp.ExecutionID, adminAuth)
	if err != nil {
		t.Fatalf("GetExecutionHistory(%s) failed: %v", disp.ExecutionID, err)
	}

	if execRec.ScheduleID != sched.ID {
		t.Errorf("expected exec.ScheduleID %s, got %s", sched.ID, execRec.ScheduleID)
	}
	if execRec.InitiationSource != "scheduled" {
		t.Errorf("expected exec.InitiationSource 'scheduled', got %s", execRec.InitiationSource)
	}
	if execRec.Status != assessment.StatusCompleted {
		t.Errorf("expected exec.Status COMPLETED, got %s (err: %s)", execRec.Status, execRec.ErrorMessage)
	}
	if execRec.SnapshotID == "" {
		t.Errorf("expected exec.SnapshotID to be linked")
	}
}

// -----------------------------------------------------------------------------
// Category F: Schedule Deletion Safety — Execution History Preserved
// -----------------------------------------------------------------------------

func TestExecutionHistory_ScheduleDeletionPreservesHistory(t *testing.T) {
	store, _, cleanup := helperNewExecutionTestStore(t)
	defer cleanup()

	asm := helperSeedAssessmentWithAuth(t, store, "client-del", "asm-del", "tenant-del", "acc-del")
	adminAuth := assessment.NewAdminAuthContext()

	sched := &assessment.AssessmentSchedule{
		ID:             "sched-to-delete",
		Name:           "Temporary Schedule",
		AssessmentID:   asm.ID,
		AssessmentRef:  asm.Ref,
		ClientID:       asm.ClientID,
		TenantID:       "tenant-del",
		AccountID:      "acc-del",
		RecurrenceType: assessment.RecurrenceInterval,
		RecurrenceExpr: "@every 24h",
		Timezone:       "UTC",
		IsEnabled:      true,
		NextDueAt:      time.Now().UTC(),
	}
	if err := store.CreateSchedule(sched, adminAuth); err != nil {
		t.Fatalf("CreateSchedule failed: %v", err)
	}

	// Create an execution record linked to this schedule
	now := time.Now().UTC()
	execID := "exec-survive-sched-del"
	exec := &assessment.AssessmentExecution{
		ID:               execID,
		AssessmentID:     asm.ID,
		ClientID:         asm.ClientID,
		TenantID:         "tenant-del",
		AccountID:        "acc-del",
		ScheduleID:       sched.ID,
		Status:           assessment.StatusCompleted,
		InitiationSource: "scheduled",
		AssessmentType:   "BLACK_BOX_WEB",
		StartedAt:        now,
		CreatedAt:        now,
		UpdatedAt:        now,
	}
	if err := store.CreateExecution(exec); err != nil {
		t.Fatalf("CreateExecution failed: %v", err)
	}

	// Delete the schedule
	if err := store.DeleteSchedule(sched.ID, adminAuth); err != nil {
		t.Fatalf("DeleteSchedule failed: %v", err)
	}

	// Verify the execution history record still exists and retains schedule linkage
	got, err := store.GetExecutionHistory(execID, adminAuth)
	if err != nil {
		t.Fatalf("GetExecutionHistory failed after schedule deletion: %v", err)
	}
	if got.ID != execID {
		t.Fatalf("expected execution %s, got %s", execID, got.ID)
	}
	if got.ScheduleID != sched.ID {
		t.Fatalf("expected preserved schedule ID %s, got %s", sched.ID, got.ScheduleID)
	}
}

// -----------------------------------------------------------------------------
// Category G: Querying, Filtering, & Pagination
// -----------------------------------------------------------------------------

func TestExecutionHistory_QueryingFilteringPagination(t *testing.T) {
	store, _, cleanup := helperNewExecutionTestStore(t)
	defer cleanup()

	adminAuth := assessment.NewAdminAuthContext()
	baseTime := time.Date(2026, 10, 20, 10, 0, 0, 0, time.UTC)

	// Seed parent client and assessments
	_ = store.CreateClient(&assessment.Client{
		ID:        "client-filter",
		Name:      "Client Filter",
		CreatedAt: baseTime,
		UpdatedAt: baseTime,
	})

	for _, asmID := range []string{"asm-A", "asm-B", "asm-C"} {
		_ = store.CreateAssessment(&assessment.Assessment{
			ID:             asmID,
			Ref:            "ASM-" + asmID,
			ClientID:       "client-filter",
			Name:           "Assessment " + asmID,
			AssessmentType: "BLACK_BOX_WEB",
			Status:         assessment.StatusReady,
			ScopeMode:      "same-origin",
			CreatedAt:      baseTime,
			UpdatedAt:      baseTime,
		})
	}

	// Seed 8 records with different dimensions
	records := []*assessment.AssessmentExecution{
		{
			ID: "rec-1", AssessmentID: "asm-A", ScheduleID: "sch-1", Status: assessment.StatusCompleted,
			InitiationSource: "scheduled", TenantID: "tenant-T", AccountID: "acc-1", StartedAt: baseTime.Add(1 * time.Hour),
		},
		{
			ID: "rec-2", AssessmentID: "asm-A", ScheduleID: "sch-1", Status: assessment.StatusFailed,
			InitiationSource: "scheduled", TenantID: "tenant-T", AccountID: "acc-1", StartedAt: baseTime.Add(2 * time.Hour),
		},
		{
			ID: "rec-3", AssessmentID: "asm-A", ScheduleID: "", Status: assessment.StatusCompleted,
			InitiationSource: "manual", TenantID: "tenant-T", AccountID: "acc-1", StartedAt: baseTime.Add(3 * time.Hour),
		},
		{
			ID: "rec-4", AssessmentID: "asm-B", ScheduleID: "sch-2", Status: assessment.StatusSkipped,
			InitiationSource: "scheduled", TenantID: "tenant-T", AccountID: "acc-2", StartedAt: baseTime.Add(4 * time.Hour),
		},
		{
			ID: "rec-5", AssessmentID: "asm-B", ScheduleID: "", Status: assessment.StatusCompleted,
			InitiationSource: "manual", TenantID: "tenant-T", AccountID: "acc-2", StartedAt: baseTime.Add(5 * time.Hour),
		},
		{
			ID: "rec-6", AssessmentID: "asm-B", ScheduleID: "sch-2", Status: assessment.StatusCompleted,
			InitiationSource: "scheduled", TenantID: "tenant-T", AccountID: "acc-2", StartedAt: baseTime.Add(6 * time.Hour),
		},
		{
			ID: "rec-7", AssessmentID: "asm-C", ScheduleID: "", Status: assessment.StatusCancelled,
			InitiationSource: "api", TenantID: "tenant-T", AccountID: "acc-3", StartedAt: baseTime.Add(7 * time.Hour),
		},
		{
			ID: "rec-8", AssessmentID: "asm-C", ScheduleID: "sch-3", Status: assessment.StatusCompletedWithErrors,
			InitiationSource: "scheduled", TenantID: "tenant-T", AccountID: "acc-3", StartedAt: baseTime.Add(8 * time.Hour),
		},
	}

	for _, r := range records {
		r.ClientID = "client-filter"
		r.AssessmentType = "BLACK_BOX_WEB"
		r.CreatedAt = r.StartedAt
		r.UpdatedAt = r.StartedAt
		if err := store.CreateExecution(r); err != nil {
			t.Fatalf("CreateExecution(%s) failed: %v", r.ID, err)
		}
	}

	// 1. Filter by AssessmentID
	listAsmA, _, err := store.ListExecutionHistory(assessment.ExecutionListOptions{
		Auth:         adminAuth,
		AssessmentID: "asm-A",
	})
	if err != nil {
		t.Fatalf("ListExecutionHistory(asm-A) failed: %v", err)
	}
	if len(listAsmA) != 3 {
		t.Fatalf("expected 3 records for asm-A, got %d", len(listAsmA))
	}

	// 2. Filter by ScheduleID
	listSch2, _, err := store.ListExecutionHistory(assessment.ExecutionListOptions{
		Auth:       adminAuth,
		ScheduleID: "sch-2",
	})
	if err != nil {
		t.Fatalf("ListExecutionHistory(sch-2) failed: %v", err)
	}
	if len(listSch2) != 2 {
		t.Fatalf("expected 2 records for sch-2, got %d", len(listSch2))
	}

	// 3. Filter by Status
	listSkipped, _, err := store.ListExecutionHistory(assessment.ExecutionListOptions{
		Auth:   adminAuth,
		Status: assessment.StatusSkipped,
	})
	if err != nil {
		t.Fatalf("ListExecutionHistory(SKIPPED) failed: %v", err)
	}
	if len(listSkipped) != 1 || listSkipped[0].ID != "rec-4" {
		t.Fatalf("expected 1 SKIPPED record (rec-4), got %d", len(listSkipped))
	}

	// 4. Filter by Source
	listManual, _, err := store.ListExecutionHistory(assessment.ExecutionListOptions{
		Auth:             adminAuth,
		InitiationSource: "manual",
	})
	if err != nil {
		t.Fatalf("ListExecutionHistory(manual) failed: %v", err)
	}
	if len(listManual) != 2 {
		t.Fatalf("expected 2 manual records, got %d", len(listManual))
	}

	// 5. Filter by Time Window: Since and Until
	since := baseTime.Add(2 * time.Hour)
	until := baseTime.Add(6 * time.Hour)
	listWindow, _, err := store.ListExecutionHistory(assessment.ExecutionListOptions{
		Auth:  adminAuth,
		Since: &since,
		Until: &until,
	})
	if err != nil {
		t.Fatalf("ListExecutionHistory(window) failed: %v", err)
	}
	// Records with StartedAt >= since (2h) and <= until (6h): rec-2, rec-3, rec-4, rec-5, rec-6 -> 5 records
	if len(listWindow) != 5 {
		t.Fatalf("expected 5 records in window [2h, 6h], got %d", len(listWindow))
	}

	// 6. Pagination & Ordering (Newest First)
	page1, _, err := store.ListExecutionHistory(assessment.ExecutionListOptions{
		Auth:   adminAuth,
		Limit:  3,
		Offset: 0,
	})
	if err != nil {
		t.Fatalf("ListExecutionHistory(page1) failed: %v", err)
	}
	if len(page1) != 3 {
		t.Fatalf("expected 3 records in page 1, got %d", len(page1))
	}
	if page1[0].ID != "rec-8" || page1[1].ID != "rec-7" || page1[2].ID != "rec-6" {
		t.Fatalf("expected order [rec-8, rec-7, rec-6], got [%s, %s, %s]", page1[0].ID, page1[1].ID, page1[2].ID)
	}

	page2, _, err := store.ListExecutionHistory(assessment.ExecutionListOptions{
		Auth:   adminAuth,
		Limit:  3,
		Offset: 3,
	})
	if err != nil {
		t.Fatalf("ListExecutionHistory(page2) failed: %v", err)
	}
	if len(page2) != 3 {
		t.Fatalf("expected 3 records in page 2, got %d", len(page2))
	}
	if page2[0].ID != "rec-5" || page2[1].ID != "rec-4" || page2[2].ID != "rec-3" {
		t.Fatalf("expected order [rec-5, rec-4, rec-3], got [%s, %s, %s]", page2[0].ID, page2[1].ID, page2[2].ID)
	}
}

// -----------------------------------------------------------------------------
// Category H: Tenant Authorization & Cross-Tenant Boundary Enforcement
// -----------------------------------------------------------------------------

func TestExecutionHistory_TenantIsolation(t *testing.T) {
	store, _, cleanup := helperNewExecutionTestStore(t)
	defer cleanup()

	now := time.Now().UTC()

	// Seed client and assessments
	_ = store.CreateClient(&assessment.Client{
		ID:        "client-a",
		Name:      "Client A",
		CreatedAt: now,
		UpdatedAt: now,
	})
	_ = store.CreateClient(&assessment.Client{
		ID:        "client-b",
		Name:      "Client B",
		CreatedAt: now,
		UpdatedAt: now,
	})
	_ = store.CreateAssessment(&assessment.Assessment{
		ID:             "asm-a",
		Ref:            "ASM-A",
		ClientID:       "client-a",
		Name:           "Assessment A",
		AssessmentType: "BLACK_BOX_WEB",
		Status:         assessment.StatusReady,
		ScopeMode:      "same-origin",
	})
	_ = store.CreateAssessment(&assessment.Assessment{
		ID:             "asm-b",
		Ref:            "ASM-B",
		ClientID:       "client-b",
		Name:           "Assessment B",
		AssessmentType: "BLACK_BOX_WEB",
		Status:         assessment.StatusReady,
		ScopeMode:      "same-origin",
	})

	// Seed execution for Tenant A
	execA := &assessment.AssessmentExecution{
		ID:               "exec-tenant-a",
		AssessmentID:     "asm-a",
		ClientID:         "client-a",
		TenantID:         "tenant-alpha",
		AccountID:        "acc-a",
		Status:           assessment.StatusCompleted,
		InitiationSource: "manual",
		AssessmentType:   "BLACK_BOX_WEB",
		StartedAt:        now,
		CreatedAt:        now,
		UpdatedAt:        now,
	}
	if err := store.CreateExecution(execA); err != nil {
		t.Fatalf("CreateExecution A failed: %v", err)
	}

	// Seed execution for Tenant B
	execB := &assessment.AssessmentExecution{
		ID:               "exec-tenant-b",
		AssessmentID:     "asm-b",
		ClientID:         "client-b",
		TenantID:         "tenant-beta",
		AccountID:        "acc-b",
		Status:           assessment.StatusCompleted,
		InitiationSource: "manual",
		AssessmentType:   "BLACK_BOX_WEB",
		StartedAt:        now.Add(5 * time.Minute),
		CreatedAt:        now.Add(5 * time.Minute),
		UpdatedAt:        now.Add(5 * time.Minute),
	}
	if err := store.CreateExecution(execB); err != nil {
		t.Fatalf("CreateExecution B failed: %v", err)
	}

	// Tenant A auth context
	authAlpha := assessment.NewTenantAuthContext("client-a", "tenant-alpha", "acc-a")

	// Tenant B auth context
	authBeta := assessment.NewTenantAuthContext("client-b", "tenant-beta", "acc-b")

	// Admin auth context
	adminAuth := assessment.NewAdminAuthContext()

	// 1. Tenant Alpha can get their own record
	recA, err := store.GetExecutionHistory("exec-tenant-a", authAlpha)
	if err != nil {
		t.Fatalf("Tenant Alpha could not retrieve own execution: %v", err)
	}
	if recA.ID != "exec-tenant-a" {
		t.Fatalf("expected exec-tenant-a, got %s", recA.ID)
	}

	// 2. Tenant Alpha CANNOT get Tenant Beta's record
	_, err = store.GetExecutionHistory("exec-tenant-b", authAlpha)
	if err == nil {
		t.Fatalf("expected Tenant Alpha to be denied access to Tenant Beta's record, but succeeded")
	}
	if !errors.Is(err, assessment.ErrExecutionUnauthorized) && !errors.Is(err, assessment.ErrExecutionNotFound) {
		t.Fatalf("expected ErrExecutionUnauthorized or ErrExecutionNotFound, got: %v", err)
	}

	// 3. Tenant Beta CANNOT get Tenant Alpha's record
	_, err = store.GetExecutionHistory("exec-tenant-a", authBeta)
	if err == nil {
		t.Fatalf("expected Tenant Beta to be denied access to Tenant Alpha's record, but succeeded")
	}
	if !errors.Is(err, assessment.ErrExecutionUnauthorized) && !errors.Is(err, assessment.ErrExecutionNotFound) {
		t.Fatalf("expected ErrExecutionUnauthorized or ErrExecutionNotFound, got: %v", err)
	}

	// 4. Tenant Alpha list only returns Tenant Alpha's executions
	listA, _, err := store.ListExecutionHistory(assessment.ExecutionListOptions{
		Auth: authAlpha,
	})
	if err != nil {
		t.Fatalf("ListExecutionHistory(authAlpha) failed: %v", err)
	}
	if len(listA) != 1 || listA[0].ID != "exec-tenant-a" {
		t.Fatalf("expected only exec-tenant-a for Tenant Alpha, got %d items", len(listA))
	}

	// 5. Tenant Beta list only returns Tenant Beta's executions
	listB, _, err := store.ListExecutionHistory(assessment.ExecutionListOptions{
		Auth: authBeta,
	})
	if err != nil {
		t.Fatalf("ListExecutionHistory(authBeta) failed: %v", err)
	}
	if len(listB) != 1 || listB[0].ID != "exec-tenant-b" {
		t.Fatalf("expected only exec-tenant-b for Tenant Beta, got %d items", len(listB))
	}

	// 6. Admin can see both
	listAdmin, _, err := store.ListExecutionHistory(assessment.ExecutionListOptions{
		Auth: adminAuth,
	})
	if err != nil {
		t.Fatalf("ListExecutionHistory(adminAuth) failed: %v", err)
	}
	if len(listAdmin) != 2 {
		t.Fatalf("expected Admin to see all 2 records, got %d", len(listAdmin))
	}
}

// -----------------------------------------------------------------------------
// Category I: Refusal and Pre-Execution Failure Recording
// -----------------------------------------------------------------------------

func TestExecutionHistory_PreExecutionRefusalRecording(t *testing.T) {
	store, _, cleanup := helperNewExecutionTestStore(t)
	defer cleanup()

	adminAuth := assessment.NewAdminAuthContext()

	// Create assessment without approved targets and with expired authorization
	_ = store.CreateClient(&assessment.Client{
		ID:   "client-unauth",
		Name: "Client Unauth",
	})
	asm := &assessment.Assessment{
		ID:             "asm-unauth",
		Ref:            "ASM-UNAUTH",
		ClientID:       "client-unauth",
		Name:           "Unapproved Assessment",
		AssessmentType: "BLACK_BOX_WEB",
		Status:         assessment.StatusDraft, // not ready!
	}
	if err := store.CreateAssessment(asm); err != nil {
		t.Fatalf("CreateAssessment failed: %v", err)
	}

	sched := &assessment.AssessmentSchedule{
		ID:             "sched-refused",
		Name:           "Refused Schedule",
		AssessmentID:   asm.ID,
		AssessmentRef:  asm.Ref,
		ClientID:       asm.ClientID,
		TenantID:       "tenant-refused",
		AccountID:      "acc-refused",
		RecurrenceType: assessment.RecurrenceInterval,
		RecurrenceExpr: "@every 1h",
		Timezone:       "UTC",
		IsEnabled:      true,
		NextDueAt:      time.Now().UTC().Add(-1 * time.Minute),
	}
	if err := store.CreateSchedule(sched, adminAuth); err != nil {
		t.Fatalf("CreateSchedule failed: %v", err)
	}

	ctrl := assessment.NewController(store)
	scheduler := assessment.NewScheduler(store, ctrl, assessment.DefaultSchedulerConfig())

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Scheduler runs due schedule synchronously
	dispatched, err := scheduler.RunDueSchedulesSync(ctx, time.Now().UTC())
	if err != nil {
		t.Fatalf("RunDueSchedulesSync failed: %v", err)
	}
	if dispatched != 1 {
		t.Fatalf("expected 1 schedule dispatched, got %d", dispatched)
	}

	// Verify dispatch was recorded as FAILED or SKIPPED
	dispatches, err := store.GetScheduleDispatches(sched.ID, adminAuth)
	if err != nil {
		t.Fatalf("GetScheduleDispatches failed: %v", err)
	}
	if len(dispatches) == 0 {
		t.Fatalf("expected a dispatch record to be generated for the refusal")
	}

	disp := dispatches[0]
	if disp.ExecutionID == "" {
		t.Fatalf("expected refusal dispatch to have ExecutionID")
	}

	// Canonical Execution Record must be in SKIPPED or FAILED status
	execRec, err := store.GetExecutionHistory(disp.ExecutionID, adminAuth)
	if err != nil {
		t.Fatalf("GetExecutionHistory(%s) failed: %v", disp.ExecutionID, err)
	}

	if execRec.Status != assessment.StatusSkipped && execRec.Status != assessment.StatusFailed {
		t.Fatalf("expected status SKIPPED or FAILED, got %s", execRec.Status)
	}
	if execRec.TargetCount != 0 {
		t.Fatalf("expected 0 targets scanned on pre-execution refusal, got %d", execRec.TargetCount)
	}
	if execRec.ErrorMessage == "" {
		t.Fatalf("expected refusal error message to explain reason")
	}
}
