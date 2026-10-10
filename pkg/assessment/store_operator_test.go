package assessment

import (
	"path/filepath"
	"testing"
	"time"
)

func newTestOperatorStore(t *testing.T) (*SQLiteStore, func()) {
	t.Helper()
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "operator_test.db")

	store, err := NewSQLiteStore(dbPath)
	if err != nil {
		t.Fatalf("failed to create SQLite store: %v", err)
	}

	cleanup := func() {
		_ = store.Close()
	}
	return store, cleanup
}

func TestMigration12_OperatorSchemaApplied(t *testing.T) {
	store, cleanup := newTestOperatorStore(t)
	defer cleanup()

	// Verify schema_migrations has version 12
	var version int
	err := store.db.QueryRow("SELECT MAX(version) FROM schema_migrations").Scan(&version)
	if err != nil {
		t.Fatalf("failed to query schema version: %v", err)
	}
	if version < 12 {
		t.Errorf("expected schema version >= 12, got %d", version)
	}
}

func TestFindingReview_PersistenceAndInvariants(t *testing.T) {
	store, cleanup := newTestOperatorStore(t)
	defer cleanup()

	// Create test client and assessment
	client := &Client{ID: "cli-1", Name: "Acme"}
	if err := store.CreateClient(client); err != nil {
		t.Fatalf("CreateClient failed: %v", err)
	}
	asm := &Assessment{
		ID:             "asm-1",
		Ref:            "ASM-2026-TEST",
		ClientID:       client.ID,
		Name:           "Web Audit",
		AssessmentType: "BLACK_BOX",
		Status:         StatusReady,
		ScopeMode:      "same-origin",
	}
	if err := store.CreateAssessment(asm); err != nil {
		t.Fatalf("CreateAssessment failed: %v", err)
	}

	// 1. Initial review: Approved
	rev1 := &FindingReview{
		AssessmentID: asm.ID,
		FindingID:    "FND-001",
		ReviewStatus: ReviewStatusApproved,
		ReviewedBy:   "sec-operator-alice",
		Notes:        "Confirmed reproducible in staging; approved for final report.",
	}
	if err := store.SaveFindingReview(rev1); err != nil {
		t.Fatalf("SaveFindingReview failed: %v", err)
	}

	// 2. Query review
	fetched, err := store.GetFindingReview(asm.ID, "FND-001")
	if err != nil {
		t.Fatalf("GetFindingReview failed: %v", err)
	}
	if fetched == nil {
		t.Fatalf("expected finding review to exist")
	}
	if fetched.ReviewStatus != ReviewStatusApproved {
		t.Errorf("expected status %s, got %s", ReviewStatusApproved, fetched.ReviewStatus)
	}
	if fetched.ReviewedBy != "sec-operator-alice" {
		t.Errorf("expected reviewer %s, got %s", "sec-operator-alice", fetched.ReviewedBy)
	}

	// 3. Update review to Rejected (re-review)
	rev1Update := &FindingReview{
		AssessmentID: asm.ID,
		FindingID:    "FND-001",
		ReviewStatus: ReviewStatusRejected,
		ReviewedBy:   "lead-operator-bob",
		Notes:        "Duplicate of FND-002; rejected from client report.",
	}
	if err := store.SaveFindingReview(rev1Update); err != nil {
		t.Fatalf("SaveFindingReview update failed: %v", err)
	}

	updated, err := store.GetFindingReview(asm.ID, "FND-001")
	if err != nil {
		t.Fatalf("GetFindingReview failed: %v", err)
	}
	if updated.ReviewStatus != ReviewStatusRejected {
		t.Errorf("expected status %s, got %s", ReviewStatusRejected, updated.ReviewStatus)
	}
	if updated.ReviewedBy != "lead-operator-bob" {
		t.Errorf("expected updated reviewer lead-operator-bob, got %s", updated.ReviewedBy)
	}

	// 4. List reviews
	rev2 := &FindingReview{
		AssessmentID: asm.ID,
		FindingID:    "FND-002",
		ReviewStatus: ReviewStatusApproved,
		ReviewedBy:   "lead-operator-bob",
	}
	_ = store.SaveFindingReview(rev2)

	list, err := store.ListFindingReviews(asm.ID)
	if err != nil {
		t.Fatalf("ListFindingReviews failed: %v", err)
	}
	if len(list) != 2 {
		t.Errorf("expected 2 reviews, got %d", len(list))
	}
}

func TestReportDelivery_LifecycleAndTracking(t *testing.T) {
	store, cleanup := newTestOperatorStore(t)
	defer cleanup()

	// Create test client, assessment, and report record
	client := &Client{ID: "cli-2", Name: "Beta Corp"}
	_ = store.CreateClient(client)
	asm := &Assessment{
		ID:             "asm-2",
		Ref:            "ASM-2026-BETA",
		ClientID:       client.ID,
		Name:           "Beta Audit",
		AssessmentType: "BLACK_BOX",
		Status:         StatusCompleted,
		ScopeMode:      "same-origin",
	}
	_ = store.CreateAssessment(asm)
	exec := &AssessmentExecution{
		ID:           "exec-001",
		AssessmentID: asm.ID,
		Status:       StatusCompleted,
		StartedAt:    time.Now().UTC(),
		ConfigSnapshot: ScanConfigSnapshot{
			TimeoutSeconds: 30,
			Concurrency:    5,
			ScopeMode:      "same-origin",
		},
	}
	if err := store.CreateExecution(exec); err != nil {
		t.Fatalf("CreateExecution failed: %v", err)
	}
	rep := &ReportRecord{
		ID:           "rep-001",
		AssessmentID: asm.ID,
		ExecutionID:  "exec-001",
		Format:       "HTML",
		FilePath:     "/reports/beta.html",
		FelixVersion: "2.0.0",
		Status:       "GENERATED",
	}
	if err := store.SaveReport(rep); err != nil {
		t.Fatalf("SaveReport failed: %v", err)
	}

	// 1. Validation error: confirmed status without delivered_at timestamp
	invalidDel := &ReportDelivery{
		AssessmentID:   asm.ID,
		ReportID:       rep.ID,
		DeliveryStatus: DeliveryStatusConfirmed,
		RecipientName:  "Jane Doe",
		RecipientEmail: "jane@beta.example",
		DeliveryMethod: DeliveryMethodSecureDownload,
		OperatorID:     "op-1",
	}
	if err := store.CreateReportDelivery(invalidDel); err == nil {
		t.Errorf("expected error when creating confirmed delivery without delivered_at timestamp")
	}

	// 2. Valid initial delivery: Prepared
	del := &ReportDelivery{
		ID:             "del-001",
		AssessmentID:   asm.ID,
		ReportID:       rep.ID,
		DeliveryStatus: DeliveryStatusPrepared,
		RecipientName:  "Jane Doe",
		RecipientEmail: "jane@beta.example",
		DeliveryMethod: DeliveryMethodSecureDownload,
		OperatorID:     "op-1",
		Notes:          "Generated and staged for secure link transmission.",
	}
	if err := store.CreateReportDelivery(del); err != nil {
		t.Fatalf("CreateReportDelivery failed: %v", err)
	}

	// 3. Update to Dispatched
	dispatchTime := time.Now().UTC()
	err := store.UpdateReportDeliveryStatus(del.ID, DeliveryStatusDispatched, "Secure download link emailed", &dispatchTime)
	if err != nil {
		t.Fatalf("UpdateReportDeliveryStatus to DISPATCHED failed: %v", err)
	}

	dFetched, err := store.GetReportDelivery(del.ID)
	if err != nil {
		t.Fatalf("GetReportDelivery failed: %v", err)
	}
	if dFetched.DeliveryStatus != DeliveryStatusDispatched {
		t.Errorf("expected status %s, got %s", DeliveryStatusDispatched, dFetched.DeliveryStatus)
	}
	if dFetched.DispatchedAt == nil {
		t.Errorf("expected dispatched_at timestamp set")
	}

	// 4. Update to DeliveryConfirmed
	deliveredTime := time.Now().UTC().Add(time.Hour)
	err = store.UpdateReportDeliveryStatus(del.ID, DeliveryStatusConfirmed, "Client confirmed successful receipt", &deliveredTime)
	if err != nil {
		t.Fatalf("UpdateReportDeliveryStatus to DELIVERY_CONFIRMED failed: %v", err)
	}

	dFinal, _ := store.GetReportDelivery(del.ID)
	if dFinal.DeliveryStatus != DeliveryStatusConfirmed {
		t.Errorf("expected status %s, got %s", DeliveryStatusConfirmed, dFinal.DeliveryStatus)
	}
	if dFinal.DeliveredAt == nil {
		t.Errorf("expected delivered_at timestamp set")
	}

	// 5. List deliveries
	dList, err := store.ListReportDeliveries(asm.ID)
	if err != nil || len(dList) != 1 {
		t.Errorf("expected 1 delivery record in list, got %d", len(dList))
	}
}

func TestOperatorAuditEvents_AppendOnlyLog(t *testing.T) {
	store, cleanup := newTestOperatorStore(t)
	defer cleanup()

	// Record several audit events
	e1 := &AuditEvent{
		AssessmentID: "asm-10",
		OperatorID:   "op-alice",
		ActionType:   "ASSESSMENT_CREATED",
		EntityType:   "ASSESSMENT",
		EntityID:     "asm-10",
		DetailsJSON:  `{"name":"Q1 Audit"}`,
	}
	e2 := &AuditEvent{
		AssessmentID: "asm-10",
		OperatorID:   "op-alice",
		ActionType:   "FINDING_APPROVED",
		EntityType:   "FINDING",
		EntityID:     "FND-100",
		DetailsJSON:  `{"status":"APPROVED_FOR_REPORT"}`,
	}
	e3 := &AuditEvent{
		AssessmentID: "asm-20",
		OperatorID:   "op-bob",
		ActionType:   "CLIENT_CREATED",
		EntityType:   "CLIENT",
		EntityID:     "cli-99",
	}

	if err := store.RecordAuditEvent(e1); err != nil {
		t.Fatalf("RecordAuditEvent e1 failed: %v", err)
	}
	if err := store.RecordAuditEvent(e2); err != nil {
		t.Fatalf("RecordAuditEvent e2 failed: %v", err)
	}
	if err := store.RecordAuditEvent(e3); err != nil {
		t.Fatalf("RecordAuditEvent e3 failed: %v", err)
	}

	// Filter by assessment
	asmEvents, err := store.ListAuditEvents("asm-10", 50)
	if err != nil {
		t.Fatalf("ListAuditEvents failed: %v", err)
	}
	if len(asmEvents) != 2 {
		t.Errorf("expected 2 audit events for asm-10, got %d", len(asmEvents))
	}

	// Global audit log
	allEvents, err := store.ListAuditEvents("", 50)
	if err != nil {
		t.Fatalf("ListAuditEvents global failed: %v", err)
	}
	if len(allEvents) != 3 {
		t.Errorf("expected 3 total audit events, got %d", len(allEvents))
	}
}

func TestScanJobLease_ConcurrencyAndRecovery(t *testing.T) {
	store, cleanup := newTestOperatorStore(t)
	defer cleanup()

	asmID := "asm-lease-1"

	// 1. Acquire initial lease
	lease1 := &ScanJobLease{
		ID:          asmID,
		ExecutionID: "exec-001",
		OperatorID:  "op-alice",
		Status:      "RUNNING",
	}
	if err := store.AcquireScanJobLease(lease1); err != nil {
		t.Fatalf("AcquireScanJobLease failed: %v", err)
	}

	// 2. Attempt duplicate concurrent lease for same assessment -> MUST FAIL
	lease2 := &ScanJobLease{
		ID:          asmID,
		ExecutionID: "exec-002",
		OperatorID:  "op-bob",
		Status:      "RUNNING",
	}
	err := store.AcquireScanJobLease(lease2)
	if err == nil {
		t.Errorf("expected error when acquiring duplicate active lease for same assessment, got nil")
	}

	// 3. Heartbeat
	if err := store.HeartbeatScanJobLease(asmID, "Audited 15/20 endpoints"); err != nil {
		t.Fatalf("HeartbeatScanJobLease failed: %v", err)
	}
	active, err := store.GetActiveScanJobLease(asmID)
	if err != nil || active == nil {
		t.Fatalf("GetActiveScanJobLease failed: %v", err)
	}
	if active.ProgressMessage != "Audited 15/20 endpoints" {
		t.Errorf("expected progress message updated, got %s", active.ProgressMessage)
	}

	// 4. Release lease
	if err := store.ReleaseScanJobLease(asmID, "COMPLETED", ""); err != nil {
		t.Fatalf("ReleaseScanJobLease failed: %v", err)
	}

	// 5. After release, new lease can be acquired
	lease3 := &ScanJobLease{
		ID:          asmID,
		ExecutionID: "exec-003",
		OperatorID:  "op-bob",
		Status:      "RUNNING",
	}
	if err := store.AcquireScanJobLease(lease3); err != nil {
		t.Fatalf("expected to acquire lease after previous completed, got: %v", err)
	}

	// 6. Test stale recovery: manually age the heartbeat
	_, err = store.db.Exec(`UPDATE scan_job_leases SET heartbeat_at = ? WHERE id = ?`,
		time.Now().UTC().Add(-10*time.Minute), asmID)
	if err != nil {
		t.Fatalf("failed to age heartbeat: %v", err)
	}

	recovered, err := store.RecoverStaleScanJobLeases(5 * time.Minute)
	if err != nil {
		t.Fatalf("RecoverStaleScanJobLeases failed: %v", err)
	}
	if recovered != 1 {
		t.Errorf("expected 1 stale lease recovered, got %d", recovered)
	}

	stale, _ := store.GetActiveScanJobLease(asmID)
	if stale.Status != "FAILED" {
		t.Errorf("expected recovered lease status FAILED, got %s", stale.Status)
	}
}
