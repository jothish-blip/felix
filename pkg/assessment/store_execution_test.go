package assessment

import (
	"errors"
	"path/filepath"
	"testing"
	"time"
)

func newTestExecutionStore(t *testing.T) (*SQLiteStore, func()) {
	t.Helper()
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "execution_test.db")

	store, err := NewSQLiteStore(dbPath)
	if err != nil {
		t.Fatalf("failed to create SQLite store: %v", err)
	}

	cleanup := func() {
		_ = store.Close()
	}
	return store, cleanup
}

func TestMigration20_ExecutionHistorySchemaApplied(t *testing.T) {
	store, cleanup := newTestExecutionStore(t)
	defer cleanup()

	var version int
	err := store.db.QueryRow("SELECT MAX(version) FROM schema_migrations").Scan(&version)
	if err != nil {
		t.Fatalf("failed querying schema version: %v", err)
	}
	if version < 20 {
		t.Errorf("expected schema version >= 20, got %d", version)
	}
}

func TestStoreExecution_LifecycleAndStateMachine(t *testing.T) {
	store, cleanup := newTestExecutionStore(t)
	defer cleanup()

	setupTestAssessment(t, store, "client-exec", "asm-exec")
	now := time.Now().UTC()

	exec := &AssessmentExecution{
		ID:               "exec-sm-1",
		AssessmentID:     "asm-exec",
		ClientID:         "client-exec",
		TenantID:         "tenant-exec",
		AccountID:        "acc-exec",
		InitiationSource: "manual",
		AssessmentType:   "BLACK_BOX_WEB",
		Status:           StatusRunning,
		StartedAt:        now,
		CreatedAt:        now,
		TargetCount:      2,
	}

	// 1. Create Execution
	if err := store.CreateExecution(exec); err != nil {
		t.Fatalf("CreateExecution failed: %v", err)
	}

	// 2. Fetch created execution
	fetched, err := store.GetExecution(exec.ID)
	if err != nil {
		t.Fatalf("GetExecution failed: %v", err)
	}
	if fetched.Status != StatusRunning || fetched.InitiationSource != "manual" || fetched.TargetCount != 2 {
		t.Errorf("unexpected fetched execution: %+v", fetched)
	}

	// 3. Transition to terminal state: COMPLETED
	completedAt := now.Add(5 * time.Second)
	fetched.Status = StatusCompleted
	fetched.CompletedAt = &completedAt
	fetched.FindingCount = 3
	fetched.DurationMs = 5000
	fetched.SnapshotID = "snap-12345"

	if err := store.UpdateExecution(fetched); err != nil {
		t.Fatalf("UpdateExecution to COMPLETED failed: %v", err)
	}

	afterComplete, err := store.GetExecution(exec.ID)
	if err != nil {
		t.Fatalf("GetExecution after completion failed: %v", err)
	}
	if afterComplete.Status != StatusCompleted || afterComplete.FindingCount != 3 || afterComplete.SnapshotID != "snap-12345" {
		t.Errorf("expected completed execution with snapshot, got: %+v", afterComplete)
	}

	// 4. Idempotent finalization: Updating with identical terminal status succeeds
	if err := store.UpdateExecution(afterComplete); err != nil {
		t.Errorf("expected idempotent update on identical terminal status, got error: %v", err)
	}

	// 5. State Machine Invariant: Transition from terminal state to RUNNING or FAILED must be rejected
	afterComplete.Status = StatusRunning
	if err := store.UpdateExecution(afterComplete); !errors.Is(err, ErrInvalidStateTransition) {
		t.Errorf("expected ErrInvalidStateTransition when reopening terminal execution, got: %v", err)
	}

	afterComplete.Status = StatusFailed
	if err := store.UpdateExecution(afterComplete); !errors.Is(err, ErrInvalidStateTransition) {
		t.Errorf("expected ErrInvalidStateTransition when mutating terminal execution, got: %v", err)
	}
}

func TestStoreExecution_TenantIsolationAndListing(t *testing.T) {
	store, cleanup := newTestExecutionStore(t)
	defer cleanup()

	setupTestAssessment(t, store, "client-a", "asm-a")
	setupTestAssessment(t, store, "client-b", "asm-b")

	authA := NewTenantAuthContext("client-a", "tenant-a", "acc-a")
	authB := NewTenantAuthContext("client-b", "tenant-b", "acc-b")
	authAdmin := NewAdminAuthContext()

	now := time.Now().UTC()
	execA := &AssessmentExecution{
		ID:               "exec-tenant-a",
		AssessmentID:     "asm-a",
		ClientID:         "client-a",
		TenantID:         "tenant-a",
		AccountID:        "acc-a",
		InitiationSource: "manual",
		Status:           StatusCompleted,
		StartedAt:        now.Add(-10 * time.Minute),
		CompletedAt:      &now,
		TargetCount:      1,
		FindingCount:     2,
	}
	execB := &AssessmentExecution{
		ID:               "exec-tenant-b",
		AssessmentID:     "asm-b",
		ClientID:         "client-b",
		TenantID:         "tenant-b",
		AccountID:        "acc-b",
		ScheduleID:       "sched-b",
		InitiationSource: "scheduled",
		Status:           StatusCompleted,
		StartedAt:        now.Add(-5 * time.Minute),
		CompletedAt:      &now,
		TargetCount:      1,
		FindingCount:     0,
	}

	if err := store.CreateExecution(execA); err != nil {
		t.Fatalf("CreateExecution A failed: %v", err)
	}
	if err := store.CreateExecution(execB); err != nil {
		t.Fatalf("CreateExecution B failed: %v", err)
	}

	// 1. Tenant B cannot access Tenant A's execution by ID
	_, err := store.GetExecutionHistory(execA.ID, authB)
	if err != ErrExecutionUnauthorized {
		t.Fatalf("expected ErrExecutionUnauthorized for Tenant B accessing Tenant A execution, got: %v", err)
	}

	// 2. Tenant A can access its own execution
	gotA, err := store.GetExecutionHistory(execA.ID, authA)
	if err != nil || gotA.ID != execA.ID {
		t.Fatalf("GetExecutionHistory for Tenant A failed: %v", err)
	}

	// 3. Admin can access any tenant's execution
	gotAdmin, err := store.GetExecutionHistory(execA.ID, authAdmin)
	if err != nil || gotAdmin.ID != execA.ID {
		t.Fatalf("GetExecutionHistory for Admin failed: %v", err)
	}

	// 4. List execution history with tenant scoping
	listA, countA, err := store.ListExecutionHistory(ExecutionListOptions{Auth: authA})
	if err != nil || countA != 1 || len(listA) != 1 || listA[0].ID != execA.ID {
		t.Fatalf("ListExecutionHistory for Tenant A should have 1 record, got count=%d, err=%v", countA, err)
	}

	listB, countB, err := store.ListExecutionHistory(ExecutionListOptions{Auth: authB})
	if err != nil || countB != 1 || len(listB) != 1 || listB[0].ID != execB.ID {
		t.Fatalf("ListExecutionHistory for Tenant B should have 1 record, got count=%d, err=%v", countB, err)
	}

	listAdmin, countAdmin, err := store.ListExecutionHistory(ExecutionListOptions{Auth: authAdmin})
	if err != nil || countAdmin != 2 || len(listAdmin) != 2 {
		t.Fatalf("ListExecutionHistory for Admin should see 2 records, got count=%d, err=%v", countAdmin, err)
	}

	// 5. Filter by InitiationSource
	listScheduled, countSched, err := store.ListExecutionHistory(ExecutionListOptions{
		Auth:             authAdmin,
		InitiationSource: "scheduled",
	})
	if err != nil || countSched != 1 || len(listScheduled) != 1 || listScheduled[0].ID != execB.ID {
		t.Fatalf("Filter by scheduled should yield execB, got count=%d, err=%v", countSched, err)
	}

	// 6. Filter by ScheduleID
	listBySched, countBySched, err := store.ListExecutionHistory(ExecutionListOptions{
		Auth:       authAdmin,
		ScheduleID: "sched-b",
	})
	if err != nil || countBySched != 1 || len(listBySched) != 1 || listBySched[0].ID != execB.ID {
		t.Fatalf("Filter by schedule ID should yield execB, got count=%d, err=%v", countBySched, err)
	}
}

func TestStoreExecution_PersistenceAcrossCloseReopen(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "persist_exec_test.db")

	store, err := NewSQLiteStore(dbPath)
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}

	setupTestAssessment(t, store, "client-p", "asm-p")
	adminAuth := NewAdminAuthContext()

	now := time.Now().UTC()
	exec := &AssessmentExecution{
		ID:               "exec-persist-100",
		AssessmentID:     "asm-p",
		ClientID:         "client-p",
		TenantID:         "tenant-corp",
		AccountID:        "acc-corp",
		ScheduleID:       "sched-persist",
		ScheduledFor:     &now,
		InitiationSource: "scheduled",
		AssessmentType:   "BLACK_BOX_WEB",
		Status:           StatusCompleted,
		StartedAt:        now.Add(-2 * time.Minute),
		CompletedAt:      &now,
		DurationMs:       120000,
		RequestCount:     150,
		TargetCount:      4,
		FindingCount:     7,
		SnapshotID:       "snap-persist-999",
	}

	if err := store.CreateExecution(exec); err != nil {
		t.Fatalf("CreateExecution failed: %v", err)
	}

	// Close store
	if err := store.Close(); err != nil {
		t.Fatalf("Close failed: %v", err)
	}

	// Reopen store
	reopened, err := NewSQLiteStore(dbPath)
	if err != nil {
		t.Fatalf("Reopen failed: %v", err)
	}
	defer reopened.Close()

	fetched, err := reopened.GetExecutionHistory(exec.ID, adminAuth)
	if err != nil {
		t.Fatalf("GetExecutionHistory after reopen failed: %v", err)
	}

	if fetched.ID != exec.ID || fetched.ScheduleID != "sched-persist" ||
		fetched.InitiationSource != "scheduled" || fetched.TargetCount != 4 ||
		fetched.FindingCount != 7 || fetched.SnapshotID != "snap-persist-999" {
		t.Errorf("reopened execution data mismatch: %+v", fetched)
	}
}
