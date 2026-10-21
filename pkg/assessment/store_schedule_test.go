package assessment

import (
	"path/filepath"
	"testing"
	"time"
)

func newTestScheduleStore(t *testing.T) (*SQLiteStore, func()) {
	t.Helper()
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "schedule_test.db")

	store, err := NewSQLiteStore(dbPath)
	if err != nil {
		t.Fatalf("failed to create SQLite store: %v", err)
	}

	cleanup := func() {
		_ = store.Close()
	}
	return store, cleanup
}

func setupTestAssessment(t *testing.T, store *SQLiteStore, clientID, asmID string) {
	t.Helper()
	client := &Client{ID: clientID, Name: "Test Client"}
	if err := store.CreateClient(client); err != nil {
		t.Fatalf("CreateClient failed: %v", err)
	}
	asm := &Assessment{
		ID:             asmID,
		Ref:            "ASM-" + asmID,
		ClientID:       clientID,
		Name:           "Security Scan",
		AssessmentType: "BLACK_BOX_WEB",
		Status:         StatusReady,
		ScopeMode:      "same-origin",
	}
	if err := store.CreateAssessment(asm); err != nil {
		t.Fatalf("CreateAssessment failed: %v", err)
	}
}

func TestMigration19_ScheduleSchemaApplied(t *testing.T) {
	store, cleanup := newTestScheduleStore(t)
	defer cleanup()

	var version int
	err := store.db.QueryRow("SELECT MAX(version) FROM schema_migrations").Scan(&version)
	if err != nil {
		t.Fatalf("failed querying schema version: %v", err)
	}
	if version < 19 {
		t.Errorf("expected schema version >= 19, got %d", version)
	}
}

func TestStoreSchedule_CRUDAndAuthorization(t *testing.T) {
	store, cleanup := newTestScheduleStore(t)
	defer cleanup()

	setupTestAssessment(t, store, "client-a", "asm-1")

	adminAuth := NewAdminAuthContext()
	tenantAAuth := NewTenantAuthContext("client-a", "tenant-a", "account-a")
	tenantBAuth := NewTenantAuthContext("client-b", "tenant-b", "account-b")

	sched := &AssessmentSchedule{
		ID:             "sched-1",
		Name:           "Daily Scan",
		Description:    "Daily web assessment",
		AssessmentID:   "asm-1",
		ClientID:       "client-a",
		TenantID:       "tenant-a",
		AccountID:      "account-a",
		RecurrenceType: RecurrenceDaily,
		RecurrenceExpr: "03:00",
		Timezone:       "UTC",
		IsEnabled:      true,
		CatchUpPolicy:  "once",
	}

	// 1. Tenant B cannot create schedule for Tenant A's assessment
	err := store.CreateSchedule(sched, tenantBAuth)
	if err != ErrScheduleUnauthorized {
		t.Fatalf("expected ErrScheduleUnauthorized, got %v", err)
	}

	// 2. Tenant A can create schedule
	err = store.CreateSchedule(sched, tenantAAuth)
	if err != nil {
		t.Fatalf("CreateSchedule failed: %v", err)
	}

	// 3. Get schedule: Tenant B cannot access
	_, err = store.GetSchedule(sched.ID, tenantBAuth)
	if err != ErrScheduleUnauthorized {
		t.Fatalf("expected ErrScheduleUnauthorized for tenant B, got %v", err)
	}

	// 4. Get schedule: Tenant A can access
	fetched, err := store.GetSchedule(sched.ID, tenantAAuth)
	if err != nil {
		t.Fatalf("GetSchedule failed: %v", err)
	}
	if fetched.Name != "Daily Scan" || fetched.RecurrenceType != RecurrenceDaily {
		t.Errorf("unexpected fetched schedule: %+v", fetched)
	}
	if fetched.NextDueAt.IsZero() {
		t.Errorf("expected NextDueAt to be computed and set")
	}

	// 5. List schedules
	listA, countA, err := store.ListSchedules(ScheduleListOptions{Auth: tenantAAuth})
	if err != nil || countA != 1 || len(listA) != 1 {
		t.Fatalf("ListSchedules for tenant A failed: count=%d, err=%v", countA, err)
	}

	listB, countB, err := store.ListSchedules(ScheduleListOptions{Auth: tenantBAuth})
	if err != nil || countB != 0 || len(listB) != 0 {
		t.Fatalf("ListSchedules for tenant B should be empty, got count=%d, err=%v", countB, err)
	}

	listAdmin, countAdmin, err := store.ListSchedules(ScheduleListOptions{Auth: adminAuth})
	if err != nil || countAdmin != 1 || len(listAdmin) != 1 {
		t.Fatalf("ListSchedules for admin failed: count=%d, err=%v", countAdmin, err)
	}

	// 6. Update schedule: Tenant B cannot update
	fetched.Description = "Updated description"
	err = store.UpdateSchedule(fetched, tenantBAuth)
	if err != ErrScheduleUnauthorized {
		t.Fatalf("expected ErrScheduleUnauthorized on update by tenant B, got %v", err)
	}

	// Tenant A can update
	err = store.UpdateSchedule(fetched, tenantAAuth)
	if err != nil {
		t.Fatalf("UpdateSchedule failed: %v", err)
	}
	updated, _ := store.GetSchedule(sched.ID, tenantAAuth)
	if updated.Description != "Updated description" {
		t.Errorf("expected updated description, got %s", updated.Description)
	}

	// 7. Delete schedule: Tenant B cannot delete
	err = store.DeleteSchedule(sched.ID, tenantBAuth)
	if err != ErrScheduleUnauthorized {
		t.Fatalf("expected ErrScheduleUnauthorized on delete by tenant B, got %v", err)
	}

	// Tenant A can delete
	err = store.DeleteSchedule(sched.ID, tenantAAuth)
	if err != nil {
		t.Fatalf("DeleteSchedule failed: %v", err)
	}

	// Verify gone
	_, err = store.GetSchedule(sched.ID, tenantAAuth)
	if err != ErrScheduleNotFound {
		t.Fatalf("expected ErrScheduleNotFound after delete, got %v", err)
	}
}

func TestStoreSchedule_ClaimDueAndCatchUp(t *testing.T) {
	store, cleanup := newTestScheduleStore(t)
	defer cleanup()

	setupTestAssessment(t, store, "client-x", "asm-x")
	adminAuth := NewAdminAuthContext()

	now := time.Date(2026, 10, 20, 10, 0, 0, 0, time.UTC)
	pastDue := now.Add(-1 * time.Hour)

	sched := &AssessmentSchedule{
		ID:             "sched-interval",
		Name:           "Hourly Scan",
		AssessmentID:   "asm-x",
		ClientID:       "client-x",
		TenantID:       "tenant-x",
		RecurrenceType: RecurrenceInterval,
		RecurrenceExpr: "@every 1h",
		IntervalSeconds: 3600,
		Timezone:       "UTC",
		IsEnabled:      true,
		CatchUpPolicy:  "once",
		NextDueAt:      pastDue,
	}

	if err := store.CreateSchedule(sched, adminAuth); err != nil {
		t.Fatalf("CreateSchedule failed: %v", err)
	}

	// 1. Claim due schedules at 'now'
	claimed, err := store.ClaimDueSchedules(now, 10)
	if err != nil {
		t.Fatalf("ClaimDueSchedules failed: %v", err)
	}
	if len(claimed) != 1 {
		t.Fatalf("expected 1 claimed schedule, got %d", len(claimed))
	}
	if claimed[0].ID != sched.ID {
		t.Errorf("claimed ID mismatch: %s", claimed[0].ID)
	}
	if claimed[0].DispatchCount != 1 {
		t.Errorf("expected dispatch count 1, got %d", claimed[0].DispatchCount)
	}

	// 2. Second claim immediately must return empty (prevent duplicate dispatch)
	claimed2, err := store.ClaimDueSchedules(now, 10)
	if err != nil {
		t.Fatalf("ClaimDueSchedules second attempt failed: %v", err)
	}
	if len(claimed2) != 0 {
		t.Fatalf("expected 0 claimed schedules on immediate retry, got %d", len(claimed2))
	}

	// 3. Verify schedule next_due_at has advanced into future
	afterClaim, err := store.GetSchedule(sched.ID, adminAuth)
	if err != nil {
		t.Fatalf("GetSchedule failed: %v", err)
	}
	if !afterClaim.NextDueAt.After(now) {
		t.Errorf("expected NextDueAt to advance past now (%v), got %v", now, afterClaim.NextDueAt)
	}
}

func TestStoreSchedule_RecordDispatchTelemetry(t *testing.T) {
	store, cleanup := newTestScheduleStore(t)
	defer cleanup()

	setupTestAssessment(t, store, "client-y", "asm-y")
	adminAuth := NewAdminAuthContext()

	sched := &AssessmentSchedule{
		ID:             "sched-y",
		Name:           "Audit Scan",
		AssessmentID:   "asm-y",
		ClientID:       "client-y",
		RecurrenceType: RecurrenceInterval,
		RecurrenceExpr: "@every 30m",
		IntervalSeconds: 1800,
		Timezone:       "UTC",
		IsEnabled:      true,
	}
	if err := store.CreateSchedule(sched, adminAuth); err != nil {
		t.Fatalf("CreateSchedule failed: %v", err)
	}

	now := time.Now().UTC()
	dispRecord := &ScheduleDispatchRecord{
		ID:           "disp-1",
		ScheduleID:   sched.ID,
		AssessmentID: sched.AssessmentID,
		ExecutionID:  "exec-100",
		TenantID:     sched.TenantID,
		ScheduledFor: now.Add(-5 * time.Minute),
		DispatchedAt: now.Add(-5 * time.Minute),
		CompletedAt:  &now,
		Status:       "COMPLETED",
	}

	if err := store.RecordScheduleDispatch(dispRecord); err != nil {
		t.Fatalf("RecordScheduleDispatch failed: %v", err)
	}

	// Verify telemetry updated on schedule
	updated, err := store.GetSchedule(sched.ID, adminAuth)
	if err != nil {
		t.Fatalf("GetSchedule failed: %v", err)
	}
	if updated.LastExecutionID != "exec-100" {
		t.Errorf("expected last execution ID exec-100, got %s", updated.LastExecutionID)
	}
	if updated.LastCompletedAt == nil {
		t.Errorf("expected LastCompletedAt to be set")
	}

	// Verify dispatch history retrieval
	dispatches, err := store.GetScheduleDispatches(sched.ID, adminAuth)
	if err != nil {
		t.Fatalf("GetScheduleDispatches failed: %v", err)
	}
	if len(dispatches) != 1 || dispatches[0].ExecutionID != "exec-100" {
		t.Errorf("unexpected dispatches: %+v", dispatches)
	}
}
