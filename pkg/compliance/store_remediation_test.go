package compliance

import (
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func TestStoreRemediation_1_FreshCreationAndMigration(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "rem_migration_test.db")

	store, err := NewSQLiteComplianceStore(dbPath)
	if err != nil {
		t.Fatalf("failed creating store: %v", err)
	}
	defer store.Close()

	// Verify schema version is at least 4
	var version int
	err = store.db.QueryRow("SELECT MAX(version) FROM compliance_schema_migrations").Scan(&version)
	if err != nil {
		t.Fatalf("failed reading schema migration version: %v", err)
	}
	if version < 4 {
		t.Errorf("expected migration version >= 4, got %d", version)
	}
}

func TestStoreRemediation_2_PolicyPersistenceRoundTrip(t *testing.T) {
	store := newTestStore(t)

	policy := &RemediationSLAPolicy{
		ID:                   "pci-dss-sla",
		Version:              "4.0.0",
		Enabled:              true,
		Description:          "PCI-DSS v4.0 Remediation Deadlines",
		Priority:             50,
		ApplicableCategories: []string{"cardholder-data", "auth"},
		ApplicableSources:    []string{"api", "webvuln"},
		Rules: map[string]string{
			"CRITICAL": "24h",
			"HIGH":     "30d",
			"MEDIUM":   "90d",
		},
		DefaultRule: "90d",
	}

	if err := store.SaveRemediationPolicy(policy); err != nil {
		t.Fatalf("SaveRemediationPolicy failed: %v", err)
	}

	retrieved, err := store.GetRemediationPolicy("pci-dss-sla")
	if err != nil {
		t.Fatalf("GetRemediationPolicy failed: %v", err)
	}

	if retrieved.ID != "pci-dss-sla" || retrieved.Version != "4.0.0" {
		t.Errorf("unexpected retrieved policy ID/Version: %s:%s", retrieved.ID, retrieved.Version)
	}
	if retrieved.Priority != 50 {
		t.Errorf("expected priority 50, got %d", retrieved.Priority)
	}
	if retrieved.Rules["CRITICAL"] != "24h" {
		t.Errorf("expected CRITICAL=24h, got %s", retrieved.Rules["CRITICAL"])
	}

	// List policies
	policies, err := store.ListRemediationPolicies()
	if err != nil {
		t.Fatalf("ListRemediationPolicies failed: %v", err)
	}
	if len(policies) == 0 {
		t.Errorf("expected at least 1 policy in list")
	}
}

func TestStoreRemediation_3_RecordAndHistoryPersistence(t *testing.T) {
	store := newTestStore(t)
	now := time.Now().UTC()

	rec := &RemediationRecord{
		ID:                 "rem:ASM-01:FINDING-123",
		FindingID:          "FINDING-123",
		FindingSource:      "apisec",
		FindingTitle:       "Broken Object Level Authorization",
		FindingCategory:    "authz",
		AssessmentID:       "ASM-01",
		ControlID:          "AC-3",
		Severity:           "HIGH",
		SeveritySource:     "finding",
		PolicyID:           "felix-default-sla",
		PolicyVersion:      "1.0.0",
		PolicyRuleMatched:  "rule:HIGH=7d",
		AssignedAt:         now,
		SLAStartTime:       now,
		Deadline:           now.Add(7 * 24 * time.Hour),
		TimeBasis:          "ELAPSED_TIME",
		Status:             RemediationStatusOpen,
		EvidenceReferences: []string{"EV-BOLA-01", "EV-BOLA-02"},
	}

	event := &RemediationHistoryEvent{
		ID:            "evthist:1",
		RemediationID: rec.ID,
		EventType:     HistoryEventAssigned,
		ToStatus:      RemediationStatusOpen,
		Actor:         "operator",
		Reason:        "Initial assignment",
		Timestamp:     now,
	}

	if err := store.SaveRemediationRecord(rec, event); err != nil {
		t.Fatalf("SaveRemediationRecord failed: %v", err)
	}

	// Retrieve by ID
	retrieved, err := store.GetRemediationRecord("rem:ASM-01:FINDING-123")
	if err != nil {
		t.Fatalf("GetRemediationRecord failed: %v", err)
	}
	if retrieved.FindingID != "FINDING-123" {
		t.Errorf("expected FindingID FINDING-123, got %s", retrieved.FindingID)
	}
	if retrieved.Severity != "HIGH" {
		t.Errorf("expected Severity HIGH, got %s", retrieved.Severity)
	}
	if len(retrieved.EvidenceReferences) != 2 {
		t.Errorf("expected 2 evidence references, got %d", len(retrieved.EvidenceReferences))
	}

	// Retrieve by Finding ID
	retrievedByFinding, err := store.GetRemediationRecordByFinding("FINDING-123")
	if err != nil {
		t.Fatalf("GetRemediationRecordByFinding failed: %v", err)
	}
	if retrievedByFinding.ID != rec.ID {
		t.Errorf("expected ID %s, got %s", rec.ID, retrievedByFinding.ID)
	}

	// Check history
	history, err := store.GetRemediationHistory(rec.ID)
	if err != nil {
		t.Fatalf("GetRemediationHistory failed: %v", err)
	}
	if len(history) != 1 {
		t.Fatalf("expected 1 history event, got %d", len(history))
	}
	if history[0].EventType != HistoryEventAssigned {
		t.Errorf("expected event ASSIGNED, got %s", history[0].EventType)
	}
}

func TestStoreRemediation_4_QueryFiltering(t *testing.T) {
	store := newTestStore(t)
	now := time.Now().UTC()

	// 1. Open record, not overdue
	r1 := &RemediationRecord{
		ID:            "rem:r1",
		FindingID:     "F1",
		Severity:      "CRITICAL",
		AssessmentID:  "ASM-A",
		ControlID:     "AC-1",
		Status:        RemediationStatusOpen,
		AssignedAt:    now,
		SLAStartTime:  now,
		Deadline:      now.Add(24 * time.Hour), // Future
		TimeBasis:     "ELAPSED_TIME",
		PolicyID:      "pol-1",
		PolicyVersion: "1.0",
	}
	_ = store.SaveRemediationRecord(r1, nil)

	// 2. Open record, OVERDUE (deadline in past)
	r2 := &RemediationRecord{
		ID:            "rem:r2",
		FindingID:     "F2",
		Severity:      "HIGH",
		AssessmentID:  "ASM-A",
		ControlID:     "AC-2",
		Status:        RemediationStatusOpen,
		AssignedAt:    now.Add(-48 * time.Hour),
		SLAStartTime:  now.Add(-48 * time.Hour),
		Deadline:      now.Add(-24 * time.Hour), // Past
		TimeBasis:     "ELAPSED_TIME",
		PolicyID:      "pol-1",
		PolicyVersion: "1.0",
	}
	_ = store.SaveRemediationRecord(r2, nil)

	// 3. Remediated record, assessment B
	r3 := &RemediationRecord{
		ID:            "rem:r3",
		FindingID:     "F3",
		Severity:      "LOW",
		AssessmentID:  "ASM-B",
		ControlID:     "AC-1",
		Status:        RemediationStatusRemediated,
		AssignedAt:    now.Add(-72 * time.Hour),
		SLAStartTime:  now.Add(-72 * time.Hour),
		Deadline:      now.Add(24 * time.Hour),
		TimeBasis:     "ELAPSED_TIME",
		PolicyID:      "pol-2",
		PolicyVersion: "1.0",
	}
	_ = store.SaveRemediationRecord(r3, nil)

	// Filter by Assessment
	recordsA, err := store.ListRemediationRecords(RemediationFilter{AssessmentID: "ASM-A"})
	if err != nil {
		t.Fatalf("ListRemediationRecords Assessment failed: %v", err)
	}
	if len(recordsA) != 2 {
		t.Errorf("expected 2 records for ASM-A, got %d", len(recordsA))
	}

	// Filter by Severity
	recordsCrit, err := store.ListRemediationRecords(RemediationFilter{Severity: "CRITICAL"})
	if err != nil {
		t.Fatalf("ListRemediationRecords Severity failed: %v", err)
	}
	if len(recordsCrit) != 1 || recordsCrit[0].ID != "rem:r1" {
		t.Errorf("expected 1 critical record r1, got %+v", recordsCrit)
	}

	// Filter Only Overdue
	recordsOverdue, err := store.ListRemediationRecords(RemediationFilter{OnlyOverdue: true})
	if err != nil {
		t.Fatalf("ListRemediationRecords OnlyOverdue failed: %v", err)
	}
	if len(recordsOverdue) != 1 || recordsOverdue[0].ID != "rem:r2" {
		t.Errorf("expected exactly 1 overdue record (r2), got %d records", len(recordsOverdue))
	}
}

func TestStoreRemediation_5_ReopeningPreservesRecordsAndHistoricalEvaluations(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "compliance_rem_persist.db")

	// 1. Open store, save evaluation result AND remediation record
	store1, err := NewSQLiteComplianceStore(dbPath)
	if err != nil {
		t.Fatalf("NewSQLiteComplianceStore failed: %v", err)
	}

	evalRes := sampleValidEvaluationResult("ASM-PERSIST-EVAL")
	if err := store1.SaveEvaluationResult(evalRes); err != nil {
		t.Fatalf("SaveEvaluationResult failed: %v", err)
	}
	origDigest := evalRes.Digest()

	now := time.Now().UTC()
	remRec := &RemediationRecord{
		ID:            "rem:persisted",
		FindingID:     "FINDING-P",
		AssessmentID:  "ASM-PERSIST-EVAL",
		Severity:      "HIGH",
		Status:        RemediationStatusOpen,
		AssignedAt:    now,
		SLAStartTime:  now,
		Deadline:      now.Add(7 * 24 * time.Hour),
		TimeBasis:     "ELAPSED_TIME",
		PolicyID:      "felix-default-sla",
		PolicyVersion: "1.0.0",
	}
	if err := store1.SaveRemediationRecord(remRec, nil); err != nil {
		t.Fatalf("SaveRemediationRecord failed: %v", err)
	}

	// Update remediation status to Remediated
	remRec.Status = RemediationStatusRemediated
	compTime := now.Add(2 * time.Hour)
	remRec.CompletedAt = &compTime
	if err := store1.SaveRemediationRecord(remRec, nil); err != nil {
		t.Fatalf("updating remediation record failed: %v", err)
	}

	if err := store1.Close(); err != nil {
		t.Fatalf("store1.Close failed: %v", err)
	}

	// 2. Reopen store in new instance
	store2, err := NewSQLiteComplianceStore(dbPath)
	if err != nil {
		t.Fatalf("NewSQLiteComplianceStore reopen failed: %v", err)
	}
	defer store2.Close()

	// Verify remediation record survived
	reopenedRem, err := store2.GetRemediationRecord("rem:persisted")
	if err != nil {
		t.Fatalf("reopened GetRemediationRecord failed: %v", err)
	}
	if reopenedRem.Status != RemediationStatusRemediated {
		t.Errorf("expected status Remediated, got %s", reopenedRem.Status)
	}

	// Invariant: Historical compliance evaluation result must NOT be mutated!
	reopenedEval, err := store2.GetEvaluationResult("ASM-PERSIST-EVAL", "nist-sp800-53-sample")
	if err != nil {
		t.Fatalf("GetEvaluationResult failed: %v", err)
	}
	if reopenedEval.Digest() != origDigest {
		t.Errorf("Historical evaluation digest mutated by remediation update! Expected %s, got %s", origDigest, reopenedEval.Digest())
	}
}

func TestStoreRemediation_6_ConcurrentRemediationUpdates(t *testing.T) {
	store := newTestStore(t)
	now := time.Now().UTC()

	baseRec := &RemediationRecord{
		ID:            "rem:concurrent",
		FindingID:     "F-CONCURRENT",
		Severity:      "MEDIUM",
		Status:        RemediationStatusOpen,
		AssignedAt:    now,
		SLAStartTime:  now,
		Deadline:      now.Add(30 * 24 * time.Hour),
		TimeBasis:     "ELAPSED_TIME",
		PolicyID:      "p1",
		PolicyVersion: "1.0",
	}
	_ = store.SaveRemediationRecord(baseRec, nil)

	var wg sync.WaitGroup
	workers := 10
	errChan := make(chan error, workers)

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			event := &RemediationHistoryEvent{
				ID:            "", // Auto-assigned
				RemediationID: "rem:concurrent",
				EventType:     HistoryEventStatusChanged,
				FromStatus:    RemediationStatusOpen,
				ToStatus:      RemediationStatusInProgress,
				Actor:         "worker",
				Reason:        "concurrent probe",
				Timestamp:     time.Now().UTC(),
			}
			err := store.SaveRemediationRecord(baseRec, event)
			if err != nil {
				errChan <- err
			}
		}(i)
	}

	wg.Wait()
	close(errChan)

	for err := range errChan {
		t.Errorf("concurrent update failure: %v", err)
	}

	history, err := store.GetRemediationHistory("rem:concurrent")
	if err != nil {
		t.Fatalf("GetRemediationHistory failed: %v", err)
	}
	if len(history) != workers {
		t.Errorf("expected %d history records, got %d", workers, len(history))
	}
}
