package assessment

import (
	"database/sql"
	"fmt"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"felix/pkg/report"
	"github.com/google/uuid"
	_ "modernc.org/sqlite"
)

// TestDatabaseIntegrity_ForeignKeysPool verifies that foreign keys and busy timeout
// are enforced across all connections in the database/sql connection pool.
func TestDatabaseIntegrity_ForeignKeysPool(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "fk_integrity.db")
	store, err := NewSQLiteStore(dbPath)
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}
	defer store.Close()

	// 1. Verify PRAGMA foreign_keys is ON directly via store.db
	var fkStatus int
	if err := store.db.QueryRow("PRAGMA foreign_keys;").Scan(&fkStatus); err != nil {
		t.Fatalf("failed to query foreign_keys pragma: %v", err)
	}
	if fkStatus != 1 {
		t.Fatalf("expected foreign_keys = 1, got %d", fkStatus)
	}

	// 2. Attempt to insert assessment referencing non-existent client -> must fail FK check
	orphanAssessment := &Assessment{
		ID:             uuid.New().String(),
		Ref:            "ASM-FK-001",
		ClientID:       "non-existent-client-id",
		Name:           "Orphan Assessment",
		AssessmentType: "WEB",
		Status:         StatusDraft,
	}
	err = store.CreateAssessment(orphanAssessment)
	if err == nil {
		t.Fatalf("expected foreign key violation error when creating assessment with invalid client_id, got nil")
	}

	// 3. Insert valid client, then retry assessment -> must succeed
	validClient := &Client{
		ID:   "client-" + uuid.New().String(),
		Name: "Integrity Client",
	}
	if err := store.CreateClient(validClient); err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	orphanAssessment.ClientID = validClient.ID
	if err := store.CreateAssessment(orphanAssessment); err != nil {
		t.Fatalf("expected assessment creation to succeed after valid client inserted, got: %v", err)
	}

	// 4. Concurrently execute multiple queries to ensure pool connections maintain foreign_keys = 1
	var wg sync.WaitGroup
	errCh := make(chan error, 20)
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			var fk int
			if qErr := store.db.QueryRow("PRAGMA foreign_keys;").Scan(&fk); qErr != nil {
				errCh <- fmt.Errorf("goroutine %d pragma query failed: %w", idx, qErr)
				return
			}
			if fk != 1 {
				errCh <- fmt.Errorf("goroutine %d saw foreign_keys=%d, expected 1", idx, fk)
				return
			}

			// Try to insert orphan target referencing non-existent assessment
			badTarget := &AssessmentTarget{
				ID:           uuid.New().String(),
				AssessmentID: "non-existent-asm-" + uuid.New().String(),
				TargetURL:    "https://example.com",
			}
			if addErr := store.AddTarget(badTarget); addErr == nil {
				errCh <- fmt.Errorf("goroutine %d: orphan target insert should have failed FK check", idx)
			}
		}(i)
	}
	wg.Wait()
	close(errCh)

	for e := range errCh {
		t.Errorf("Pool FK check failed: %v", e)
	}
}

// TestDatabaseIntegrity_MigrationHealing reproduces the critical defect where
// Migration 18 was out-of-order, leaving version set to 18 while migrations 2..17 were unapplied.
// It verifies that store.migrate() heals such databases by applying missing migrations.
func TestDatabaseIntegrity_MigrationHealing(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "healing.db")

	// Pre-create the database simulating the historical bug:
	// Migration 1 applied, then out-of-order Migration 18 applied prematurely.
	rawDB, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("failed to open raw DB: %v", err)
	}

	initSQL := `
	CREATE TABLE schema_migrations (version INTEGER PRIMARY KEY, applied_at TIMESTAMP NOT NULL);
	INSERT INTO schema_migrations (version, applied_at) VALUES (1, CURRENT_TIMESTAMP);
	INSERT INTO schema_migrations (version, applied_at) VALUES (18, CURRENT_TIMESTAMP);

	CREATE TABLE clients (id TEXT PRIMARY KEY, name TEXT NOT NULL, organization TEXT, contact_name TEXT, contact_email TEXT, notes TEXT, created_at TIMESTAMP NOT NULL, updated_at TIMESTAMP NOT NULL, archived INTEGER NOT NULL DEFAULT 0);
	CREATE TABLE assessments (id TEXT PRIMARY KEY, ref TEXT UNIQUE NOT NULL, client_id TEXT NOT NULL, name TEXT NOT NULL, description TEXT, assessment_type TEXT NOT NULL, status TEXT NOT NULL, created_at TIMESTAMP NOT NULL, updated_at TIMESTAMP NOT NULL, started_at TIMESTAMP, completed_at TIMESTAMP, scope_mode TEXT NOT NULL DEFAULT 'same-origin', config_snapshot_json TEXT, finding_count INTEGER NOT NULL DEFAULT 0);
	CREATE TABLE assessment_executions (id TEXT PRIMARY KEY, assessment_id TEXT NOT NULL, status TEXT NOT NULL, started_at TIMESTAMP NOT NULL, completed_at TIMESTAMP, duration_ms INTEGER, request_count INTEGER, error_message TEXT, config_snapshot TEXT NOT NULL);
	CREATE TABLE assessment_targets (id TEXT PRIMARY KEY, assessment_id TEXT NOT NULL, target_url TEXT NOT NULL, target_type TEXT NOT NULL, scope_status TEXT NOT NULL DEFAULT 'APPROVED', label TEXT, created_at TIMESTAMP NOT NULL);
	CREATE TABLE assessment_findings (id TEXT PRIMARY KEY, assessment_id TEXT NOT NULL, execution_id TEXT NOT NULL, target_id TEXT NOT NULL, original_finding_id TEXT NOT NULL, title TEXT NOT NULL, category TEXT NOT NULL, severity TEXT NOT NULL, confidence TEXT NOT NULL, verification_status TEXT NOT NULL, target_url TEXT NOT NULL, endpoint TEXT NOT NULL, method TEXT NOT NULL, fingerprint TEXT NOT NULL, score INTEGER NOT NULL DEFAULT 0, evidence_json TEXT NOT NULL, verification_json TEXT NOT NULL, remediation TEXT, created_at TIMESTAMP NOT NULL);
	CREATE TABLE finding_lifecycles (id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, account_id TEXT NOT NULL, client_id TEXT NOT NULL, fingerprint TEXT NOT NULL, fingerprint_version TEXT NOT NULL DEFAULT 'v1', current_state TEXT NOT NULL, previous_state TEXT, target_id TEXT, target_url TEXT NOT NULL, title TEXT NOT NULL, category TEXT NOT NULL, severity TEXT NOT NULL, score INTEGER NOT NULL DEFAULT 0, last_assessment_id TEXT NOT NULL, last_execution_id TEXT NOT NULL, last_snapshot_id TEXT, first_observed_at TIMESTAMP NOT NULL, last_observed_at TIMESTAMP NOT NULL, resolved_at TIMESTAMP, regression_count INTEGER NOT NULL DEFAULT 0, metadata_json TEXT NOT NULL DEFAULT '{}', created_at TIMESTAMP NOT NULL, updated_at TIMESTAMP NOT NULL, UNIQUE(tenant_id, account_id, fingerprint));
	CREATE TABLE finding_lifecycle_events (id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, account_id TEXT NOT NULL, client_id TEXT NOT NULL, assessment_id TEXT NOT NULL, execution_id TEXT NOT NULL, snapshot_id TEXT, finding_id TEXT NOT NULL, fingerprint TEXT NOT NULL, fingerprint_version TEXT NOT NULL DEFAULT 'v1', target_id TEXT, target_url TEXT NOT NULL, previous_state TEXT NOT NULL, current_state TEXT NOT NULL, transition_reason TEXT NOT NULL, qualifying_assessment INTEGER NOT NULL DEFAULT 1, historical_finding_id TEXT, historical_evidence_id TEXT, metadata_json TEXT NOT NULL DEFAULT '{}', created_at TIMESTAMP NOT NULL);
	`
	if _, err := rawDB.Exec(initSQL); err != nil {
		t.Fatalf("failed to initialize bug-state DB: %v", err)
	}
	rawDB.Close()

	// Now open the database via NewSQLiteStore.
	// It must run migrate() and successfully apply migrations 2..17 and 19..24!
	store, err := NewSQLiteStore(dbPath)
	if err != nil {
		t.Fatalf("NewSQLiteStore failed to heal out-of-order migrations: %v", err)
	}
	defer store.Close()

	// Verify that tables from skipped migrations now exist
	expectedTables := []string{
		"assessment_inventory_assets",    // Migration 2
		"assessment_apisec_runs",         // Migration 5
		"assessment_webvuln_runs",        // Migration 6
		"assessment_sessionsec_runs",     // Migration 7
		"assessment_businesslogic_runs",  // Migration 9
		"assessment_attack_paths",        // Migration 10
		"assessment_verification_runs",   // Migration 11
		"finding_reviews",                // Migration 12
		"assessment_snapshots",           // Migration 17
		"assessment_schedules",           // Migration 19
		"notification_outbox",            // Migration 23
	}

	for _, tbl := range expectedTables {
		var exists int
		err := store.db.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?`, tbl).Scan(&exists)
		if err != nil || exists == 0 {
			t.Errorf("expected table %s to exist after migration healing, but was not found (err: %v)", tbl, err)
		}
	}

	// Verify Migration 24 index exists
	var idxCount int
	err = store.db.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE type='index' AND name='idx_findings_target_id'`).Scan(&idxCount)
	if err != nil || idxCount == 0 {
		t.Errorf("expected index idx_findings_target_id from migration 24 to exist, err: %v", err)
	}
}

// TestDatabaseIntegrity_AtomicRollbackOnBatchFailure verifies that SaveFindings
// operates atomically in a transaction: if any finding fails (e.g. FK violation),
// NONE of the findings in the batch are persisted.
func TestDatabaseIntegrity_AtomicRollbackOnBatchFailure(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "atomic_batch.db")
	store, err := NewSQLiteStore(dbPath)
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}
	defer store.Close()

	// Setup valid client, assessment, target, and running execution
	client := &Client{ID: "cli-" + uuid.New().String(), Name: "Batch Client"}
	if err := store.CreateClient(client); err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	asm := &Assessment{
		ID:             uuid.New().String(),
		Ref:            "ASM-BATCH-001",
		ClientID:       client.ID,
		Name:           "Batch Assessment",
		AssessmentType: "WEB",
		Status:         StatusRunning,
	}
	if err := store.CreateAssessment(asm); err != nil {
		t.Fatalf("failed to create assessment: %v", err)
	}

	target := &AssessmentTarget{
		ID:           uuid.New().String(),
		AssessmentID: asm.ID,
		TargetURL:    "https://api.example.com",
	}
	if err := store.AddTarget(target); err != nil {
		t.Fatalf("failed to add target: %v", err)
	}

	exec := &AssessmentExecution{
		ID:           uuid.New().String(),
		AssessmentID: asm.ID,
		Status:       StatusRunning,
		StartedAt:    time.Now().UTC(),
	}
	if err := store.CreateExecution(exec); err != nil {
		t.Fatalf("failed to create execution: %v", err)
	}

	// Create batch of 5 findings: 4 valid, 1 with invalid TargetID (FK violation)
	batch := make([]AssessmentFinding, 5)
	for i := 0; i < 4; i++ {
		batch[i] = AssessmentFinding{
			ID:                 fmt.Sprintf("find-valid-%d-%s", i, uuid.New().String()),
			AssessmentID:       asm.ID,
			ExecutionID:        exec.ID,
			TargetID:           target.ID,
			OriginalFindingID:  fmt.Sprintf("orig-%d", i),
			Title:              fmt.Sprintf("Valid Finding %d", i),
			Category:           "injection",
			Severity:           "HIGH",
			Confidence:         "CERTAIN",
			VerificationStatus: report.VerificationVerified,
			TargetURL:          target.TargetURL,
			Endpoint:           "/test",
			Method:             "GET",
			Fingerprint:        fmt.Sprintf("fp-%d", i),
		}
	}
	// The 5th finding points to non-existent target ID
	batch[4] = AssessmentFinding{
		ID:                 "find-invalid-" + uuid.New().String(),
		AssessmentID:       asm.ID,
		ExecutionID:        exec.ID,
		TargetID:           "non-existent-target-id",
		OriginalFindingID:  "orig-invalid",
		Title:              "Invalid Finding",
		Category:           "injection",
		Severity:           "HIGH",
		Confidence:         "CERTAIN",
		VerificationStatus: report.VerificationVerified,
		TargetURL:          target.TargetURL,
		Endpoint:           "/test",
		Method:             "GET",
		Fingerprint:        "fp-invalid",
	}

	// SaveFindings should fail due to FK violation on finding 4
	err = store.SaveFindings(batch)
	if err == nil {
		t.Fatalf("expected SaveFindings to fail on FK violation, but got nil")
	}

	// Verify atomic rollback: exactly 0 findings must exist in the database
	findings, err := store.GetFindings(asm.ID, exec.ID)
	if err != nil {
		t.Fatalf("failed to get findings: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings after transaction rollback, but found %d", len(findings))
	}

	// Verify assessment finding_count remains 0
	asmRefreshed, err := store.GetAssessment(asm.ID)
	if err != nil {
		t.Fatalf("failed to get assessment: %v", err)
	}
	if asmRefreshed.FindingCount != 0 {
		t.Fatalf("expected assessment finding_count to be 0, got %d", asmRefreshed.FindingCount)
	}
}

// TestDatabaseIntegrity_TerminalExecutionAndSnapshotImmutability verifies that
// SaveFindings rejects writes to terminal executions (COMPLETED, FAILED, CANCELLED, INTERRUPTED)
// and immutable snapshots (is_complete = 1).
func TestDatabaseIntegrity_TerminalExecutionAndSnapshotImmutability(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "immutability.db")
	store, err := NewSQLiteStore(dbPath)
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}
	defer store.Close()

	client := &Client{ID: "cli-" + uuid.New().String(), Name: "Imm Client"}
	if err := store.CreateClient(client); err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	asm := &Assessment{
		ID:             uuid.New().String(),
		Ref:            "ASM-IMM-001",
		ClientID:       client.ID,
		Name:           "Immutability Test Assessment",
		AssessmentType: "WEB",
		Status:         StatusRunning,
	}
	if err := store.CreateAssessment(asm); err != nil {
		t.Fatalf("failed to create assessment: %v", err)
	}

	target := &AssessmentTarget{
		ID:           uuid.New().String(),
		AssessmentID: asm.ID,
		TargetURL:    "https://api.example.com",
	}
	if err := store.AddTarget(target); err != nil {
		t.Fatalf("failed to add target: %v", err)
	}

	terminalStatuses := []AssessmentStatus{
		StatusCancelled,
		StatusInterrupted,
	}

	for _, status := range terminalStatuses {
		exec := &AssessmentExecution{
			ID:           uuid.New().String(),
			AssessmentID: asm.ID,
			Status:       status,
			StartedAt:    time.Now().UTC().Add(-1 * time.Hour),
		}
		if err := store.CreateExecution(exec); err != nil {
			t.Fatalf("failed to create execution with status %s: %v", status, err)
		}

		finding := AssessmentFinding{
			ID:                 "find-" + uuid.New().String(),
			AssessmentID:       asm.ID,
			ExecutionID:        exec.ID,
			TargetID:           target.ID,
			Title:              "Finding on Terminal Execution",
			Category:           "auth",
			Severity:           "MEDIUM",
			Confidence:         "CERTAIN",
			VerificationStatus: report.VerificationVerified,
			TargetURL:          target.TargetURL,
			Endpoint:           "/login",
			Method:             "POST",
			Fingerprint:        "fp-" + uuid.New().String(),
		}

		err = store.SaveFindings([]AssessmentFinding{finding})
		if err == nil {
			t.Errorf("expected SaveFindings to reject write to terminal execution %s (%s), but got nil", exec.ID, status)
		}
	}

	// Test snapshot immutability: active execution with an immutable snapshot
	activeExec := &AssessmentExecution{
		ID:           uuid.New().String(),
		AssessmentID: asm.ID,
		Status:       StatusRunning,
		StartedAt:    time.Now().UTC(),
	}
	if err := store.CreateExecution(activeExec); err != nil {
		t.Fatalf("failed to create active execution: %v", err)
	}

	// Create a completed snapshot referencing activeExec.ID
	snap := BuildAssessmentSnapshot(asm, activeExec, []string{target.TargetURL}, nil, false)
	snap.IsComplete = true
	if err := store.CreateSnapshot(snap, nil, nil); err != nil {
		t.Fatalf("failed to create snapshot: %v", err)
	}

	findingForSnap := AssessmentFinding{
		ID:                 "find-snap-" + uuid.New().String(),
		AssessmentID:       asm.ID,
		ExecutionID:        activeExec.ID,
		TargetID:           target.ID,
		Title:              "Finding on Completed Snapshot",
		Category:           "auth",
		Severity:           "HIGH",
		Confidence:         "CERTAIN",
		VerificationStatus: report.VerificationVerified,
		TargetURL:          target.TargetURL,
		Endpoint:           "/snap",
		Method:             "GET",
		Fingerprint:        "fp-snap",
	}

	err = store.SaveFindings([]AssessmentFinding{findingForSnap})
	if err == nil {
		t.Fatalf("expected SaveFindings to reject write for execution with is_complete=1 snapshot, got nil")
	}
}

// TestDatabaseIntegrity_ConcurrencyStress verifies that multiple goroutines concurrently
// performing reads, writes, and status checks operate without database locks, crashes, or data corruption.
func TestDatabaseIntegrity_ConcurrencyStress(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "concurrency_stress.db")
	store, err := NewSQLiteStore(dbPath)
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}
	defer store.Close()

	client := &Client{ID: "cli-" + uuid.New().String(), Name: "Stress Client"}
	if err := store.CreateClient(client); err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	asm := &Assessment{
		ID:             uuid.New().String(),
		Ref:            "ASM-STRESS-001",
		ClientID:       client.ID,
		Name:           "Stress Assessment",
		AssessmentType: "WEB",
		Status:         StatusRunning,
	}
	if err := store.CreateAssessment(asm); err != nil {
		t.Fatalf("failed to create assessment: %v", err)
	}

	target := &AssessmentTarget{
		ID:           uuid.New().String(),
		AssessmentID: asm.ID,
		TargetURL:    "https://stress.example.com",
	}
	if err := store.AddTarget(target); err != nil {
		t.Fatalf("failed to add target: %v", err)
	}

	exec := &AssessmentExecution{
		ID:           uuid.New().String(),
		AssessmentID: asm.ID,
		Status:       StatusRunning,
		StartedAt:    time.Now().UTC(),
	}
	if err := store.CreateExecution(exec); err != nil {
		t.Fatalf("failed to create execution: %v", err)
	}

	const numWriters = 10
	const findingsPerWriter = 15
	const numReaders = 10

	var wg sync.WaitGroup
	errCh := make(chan error, numWriters+numReaders)

	// Launch writers
	for w := 0; w < numWriters; w++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			var batch []AssessmentFinding
			for i := 0; i < findingsPerWriter; i++ {
				batch = append(batch, AssessmentFinding{
					ID:                 fmt.Sprintf("stress-f-w%d-i%d-%s", workerID, i, uuid.New().String()),
					AssessmentID:       asm.ID,
					ExecutionID:        exec.ID,
					TargetID:           target.ID,
					OriginalFindingID:  fmt.Sprintf("orig-w%d-i%d", workerID, i),
					Title:              fmt.Sprintf("Stress Finding %d-%d", workerID, i),
					Category:           "xss",
					Severity:           "MEDIUM",
					Confidence:         "CERTAIN",
					VerificationStatus: report.VerificationVerified,
					TargetURL:          target.TargetURL,
					Endpoint:           fmt.Sprintf("/item/%d", i),
					Method:             "GET",
					Fingerprint:        fmt.Sprintf("fp-w%d-i%d", workerID, i),
				})
			}
			if saveErr := store.SaveFindings(batch); saveErr != nil {
				errCh <- fmt.Errorf("writer %d failed: %w", workerID, saveErr)
			}
		}(w)
	}

	// Launch concurrent readers
	for r := 0; r < numReaders; r++ {
		wg.Add(1)
		go func(readerID int) {
			defer wg.Done()
			for loop := 0; loop < 5; loop++ {
				_, getErr := store.GetFindings(asm.ID, exec.ID)
				if getErr != nil {
					errCh <- fmt.Errorf("reader %d failed: %w", readerID, getErr)
					return
				}
				_, asmErr := store.GetAssessment(asm.ID)
				if asmErr != nil {
					errCh <- fmt.Errorf("reader %d asm query failed: %w", readerID, asmErr)
					return
				}
				time.Sleep(5 * time.Millisecond)
			}
		}(r)
	}

	wg.Wait()
	close(errCh)

	for e := range errCh {
		t.Errorf("Concurrency stress error: %v", e)
	}

	// Verify all findings were written accurately without data loss
	expectedTotal := numWriters * findingsPerWriter
	findings, err := store.GetFindings(asm.ID, exec.ID)
	if err != nil {
		t.Fatalf("failed to retrieve findings after stress test: %v", err)
	}
	if len(findings) != expectedTotal {
		t.Fatalf("expected %d total findings persisted, got %d", expectedTotal, len(findings))
	}

	// Verify assessment finding_count matches
	refreshedAsm, err := store.GetAssessment(asm.ID)
	if err != nil {
		t.Fatalf("failed to retrieve assessment: %v", err)
	}
	if refreshedAsm.FindingCount != expectedTotal {
		t.Fatalf("expected assessment finding_count to be %d, got %d", expectedTotal, refreshedAsm.FindingCount)
	}
}

// TestDatabaseIntegrity_ReopenAndRecoveryIdempotency verifies that store state
// survives closing and reopening the SQLite database, and that abandoned execution
// recovery is fully idempotent across multiple reopens.
func TestDatabaseIntegrity_ReopenAndRecoveryIdempotency(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "reopen_recovery.db")

	client := &Client{ID: "cli-reopen", Name: "Reopen Client"}
	asm := &Assessment{
		ID:             "asm-reopen",
		Ref:            "ASM-REOPEN-001",
		ClientID:       client.ID,
		Name:           "Reopen Recovery Assessment",
		AssessmentType: "WEB",
		Status:         StatusRunning,
	}
	exec := &AssessmentExecution{
		ID:           "exec-reopen",
		AssessmentID: asm.ID,
		Status:       StatusRunning,
		StartedAt:    time.Now().UTC().Add(-10 * time.Minute),
	}

	// 1. First session: open store, create records, simulate crash / ungraceful exit
	{
		store1, err := NewSQLiteStore(dbPath)
		if err != nil {
			t.Fatalf("session 1: failed to create store: %v", err)
		}
		if err := store1.CreateClient(client); err != nil {
			t.Fatalf("session 1: failed to create client: %v", err)
		}
		if err := store1.CreateAssessment(asm); err != nil {
			t.Fatalf("session 1: failed to create assessment: %v", err)
		}
		if err := store1.CreateExecution(exec); err != nil {
			t.Fatalf("session 1: failed to create execution: %v", err)
		}
		if err := store1.Close(); err != nil {
			t.Fatalf("session 1: failed to close store: %v", err)
		}
	}

	// 2. Second session: reopen store, execute FinalizeAbandonedExecution
	{
		store2, err := NewSQLiteStore(dbPath)
		if err != nil {
			t.Fatalf("session 2: failed to reopen store: %v", err)
		}

		auth := NewAdminAuthContext()
		recResult, err := store2.FinalizeAbandonedExecution(exec.ID, "worker-recovery-1", StatusInterrupted, "Recovered after crash", auth)
		if err != nil {
			t.Fatalf("session 2: FinalizeAbandonedExecution failed: %v", err)
		}
		if recResult.Action != ActionFinalizedInterrupted {
			t.Fatalf("expected action ActionFinalizedInterrupted, got %s", recResult.Action)
		}
		if recResult.NewStatus != StatusInterrupted {
			t.Fatalf("expected status StatusInterrupted, got %s", recResult.NewStatus)
		}

		// Verify both execution and parent assessment statuses updated atomically
		refreshedExec, err := store2.GetExecution(exec.ID)
		if err != nil {
			t.Fatalf("session 2: failed to get execution: %v", err)
		}
		if refreshedExec.Status != StatusInterrupted {
			t.Fatalf("expected execution status StatusInterrupted, got %s", refreshedExec.Status)
		}

		refreshedAsm, err := store2.GetAssessment(asm.ID)
		if err != nil {
			t.Fatalf("session 2: failed to get assessment: %v", err)
		}
		if refreshedAsm.Status != StatusInterrupted {
			t.Fatalf("expected assessment status StatusInterrupted, got %s", refreshedAsm.Status)
		}

		if err := store2.Close(); err != nil {
			t.Fatalf("session 2: failed to close store: %v", err)
		}
	}

	// 3. Third session: reopen again and re-run recovery -> must be idempotent (ActionSkippedTerminal)
	{
		store3, err := NewSQLiteStore(dbPath)
		if err != nil {
			t.Fatalf("session 3: failed to reopen store: %v", err)
		}
		defer store3.Close()

		auth := NewAdminAuthContext()
		recResult2, err := store3.FinalizeAbandonedExecution(exec.ID, "worker-recovery-2", StatusInterrupted, "Second recovery attempt", auth)
		if err != nil {
			t.Fatalf("session 3: second FinalizeAbandonedExecution failed: %v", err)
		}
		if recResult2.Action != ActionSkippedTerminal {
			t.Fatalf("expected action ActionSkippedTerminal on second recovery, got %s", recResult2.Action)
		}
	}
}

// TestDatabaseIntegrity_AssessmentIDResolution verifies that passing human-readable
// assessment references (e.g. ASM-2026-0001) resolves cleanly to the primary UUID key
// across SaveFindings, Reviews, and Delivery operations without FK violations.
func TestDatabaseIntegrity_AssessmentIDResolution(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "ref_resolution.db")
	store, err := NewSQLiteStore(dbPath)
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}
	defer store.Close()

	client := &Client{ID: "cli-res", Name: "Resolution Client"}
	if err := store.CreateClient(client); err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	asmUUID := uuid.New().String()
	asmRef := "ASM-2026-9999"
	asm := &Assessment{
		ID:             asmUUID,
		Ref:            asmRef,
		ClientID:       client.ID,
		Name:           "Ref Resolution Assessment",
		AssessmentType: "WEB",
		Status:         StatusRunning,
	}
	if err := store.CreateAssessment(asm); err != nil {
		t.Fatalf("failed to create assessment: %v", err)
	}

	target := &AssessmentTarget{
		ID:           uuid.New().String(),
		AssessmentID: asmRef, // Passed as human ref!
		TargetURL:    "https://resolution.example.com",
	}
	if err := store.AddTarget(target); err != nil {
		t.Fatalf("failed to add target using ref: %v", err)
	}

	exec := &AssessmentExecution{
		ID:           uuid.New().String(),
		AssessmentID: asmUUID,
		Status:       StatusRunning,
		StartedAt:    time.Now().UTC(),
	}
	if err := store.CreateExecution(exec); err != nil {
		t.Fatalf("failed to create execution: %v", err)
	}

	// 1. Save finding passing asmRef as AssessmentID
	finding := AssessmentFinding{
		ID:                 "find-res-1",
		AssessmentID:       asmRef, // Passed as human ref!
		ExecutionID:        exec.ID,
		TargetID:           target.ID,
		Title:              "Ref Resolution Finding",
		Category:           "auth",
		Severity:           "HIGH",
		Confidence:         "CERTAIN",
		VerificationStatus: report.VerificationVerified,
		TargetURL:          target.TargetURL,
		Endpoint:           "/auth",
		Method:             "POST",
		Fingerprint:        "fp-res-1",
	}

	if err := store.SaveFindings([]AssessmentFinding{finding}); err != nil {
		t.Fatalf("SaveFindings failed when using assessment Ref: %v", err)
	}

	// Retrieve using asmRef
	retrievedFindings, err := store.GetFindings(asmRef, exec.ID)
	if err != nil {
		t.Fatalf("GetFindings failed using asmRef: %v", err)
	}
	if len(retrievedFindings) != 1 {
		t.Fatalf("expected 1 finding retrieved using asmRef, got %d", len(retrievedFindings))
	}
	if retrievedFindings[0].AssessmentID != asmUUID {
		t.Fatalf("expected stored finding AssessmentID to be resolved to UUID %s, got %s", asmUUID, retrievedFindings[0].AssessmentID)
	}

	// 2. Save finding review using asmRef
	review := &FindingReview{
		AssessmentID: asmRef, // Human ref
		FindingID:    finding.ID,
		ReviewStatus: ReviewStatusApproved,
		ReviewedBy:   "operator-1",
	}
	if err := store.SaveFindingReview(review); err != nil {
		t.Fatalf("SaveFindingReview failed using asmRef: %v", err)
	}

	retrievedReview, err := store.GetFindingReview(asmRef, finding.ID)
	if err != nil || retrievedReview == nil {
		t.Fatalf("GetFindingReview failed using asmRef: %v", err)
	}
	if retrievedReview.ReviewStatus != ReviewStatusApproved {
		t.Fatalf("expected review status ReviewStatusApproved, got %s", retrievedReview.ReviewStatus)
	}

	// 3. Save report and report delivery using asmRef
	reportRec := &ReportRecord{
		ID:           "rep-" + uuid.New().String(),
		AssessmentID: asmUUID,
		ExecutionID:  exec.ID,
		Format:       "json",
		FilePath:     "/tmp/report.json",
		FelixVersion: "v1.0",
		Status:       "GENERATED",
	}
	if err := store.SaveReport(reportRec); err != nil {
		t.Fatalf("failed to save report: %v", err)
	}

	delivery := &ReportDelivery{
		AssessmentID:   asmRef, // Human ref
		ReportID:       reportRec.ID,
		DeliveryStatus: DeliveryStatusPrepared,
		RecipientName:  "Security Team",
		RecipientEmail: "sec@example.com",
		DeliveryMethod: DeliveryMethodEmail,
		OperatorID:     "operator-1",
	}
	if err := store.CreateReportDelivery(delivery); err != nil {
		t.Fatalf("CreateReportDelivery failed using asmRef: %v", err)
	}

	deliveries, err := store.ListReportDeliveries(asmRef)
	if err != nil {
		t.Fatalf("ListReportDeliveries failed using asmRef: %v", err)
	}
	if len(deliveries) != 1 {
		t.Fatalf("expected 1 delivery retrieved using asmRef, got %d", len(deliveries))
	}
}

// TestDatabaseIntegrity_Migration24_DuplicateReportPreservation verifies that Migration 24:
// 1. Disambiguates duplicate (execution_id, format) report records without deleting either row.
// 2. Creates the unique index idx_reports_exec_format so subsequent duplicates are rejected.
func TestDatabaseIntegrity_Migration24_DuplicateReportPreservation(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "dup_reports_m24.db")

	// Pre-create database up to migration 23 with duplicate report rows for (e1, "json")
	rawDB, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("failed to open raw DB: %v", err)
	}

	preSQL := `
	CREATE TABLE schema_migrations (version INTEGER PRIMARY KEY, applied_at TIMESTAMP NOT NULL);
	INSERT INTO schema_migrations (version, applied_at) VALUES (1, CURRENT_TIMESTAMP);
	INSERT INTO schema_migrations (version, applied_at) VALUES (23, CURRENT_TIMESTAMP);

	CREATE TABLE clients (id TEXT PRIMARY KEY, name TEXT NOT NULL, created_at TIMESTAMP NOT NULL, updated_at TIMESTAMP NOT NULL, archived INTEGER NOT NULL DEFAULT 0);
	CREATE TABLE assessments (id TEXT PRIMARY KEY, ref TEXT UNIQUE NOT NULL, client_id TEXT NOT NULL, name TEXT NOT NULL, assessment_type TEXT NOT NULL, status TEXT NOT NULL, created_at TIMESTAMP NOT NULL, updated_at TIMESTAMP NOT NULL, scope_mode TEXT NOT NULL DEFAULT 'same-origin', finding_count INTEGER NOT NULL DEFAULT 0);
	CREATE TABLE assessment_executions (id TEXT PRIMARY KEY, assessment_id TEXT NOT NULL, status TEXT NOT NULL, started_at TIMESTAMP NOT NULL, config_snapshot TEXT NOT NULL);
	CREATE TABLE assessment_targets (id TEXT PRIMARY KEY, assessment_id TEXT NOT NULL, target_url TEXT NOT NULL, target_type TEXT NOT NULL, scope_status TEXT NOT NULL DEFAULT 'APPROVED', label TEXT, created_at TIMESTAMP NOT NULL);
	CREATE TABLE assessment_findings (id TEXT PRIMARY KEY, assessment_id TEXT NOT NULL, execution_id TEXT NOT NULL, target_id TEXT NOT NULL, original_finding_id TEXT NOT NULL, title TEXT NOT NULL, category TEXT NOT NULL, severity TEXT NOT NULL, confidence TEXT NOT NULL, verification_status TEXT NOT NULL, target_url TEXT NOT NULL, endpoint TEXT NOT NULL, method TEXT NOT NULL, fingerprint TEXT NOT NULL, score INTEGER NOT NULL DEFAULT 0, evidence_json TEXT NOT NULL, verification_json TEXT NOT NULL, remediation TEXT, created_at TIMESTAMP NOT NULL);
	CREATE TABLE assessment_reports (id TEXT PRIMARY KEY, assessment_id TEXT NOT NULL, execution_id TEXT NOT NULL, format TEXT NOT NULL, file_path TEXT NOT NULL, felix_version TEXT NOT NULL, status TEXT NOT NULL, created_at TIMESTAMP NOT NULL);

	INSERT INTO clients VALUES ('c1', 'Client 1', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, 0);
	INSERT INTO assessments VALUES ('a1', 'ASM-1', 'c1', 'Asm 1', 'WEB', 'COMPLETED', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, 'same-origin', 0);
	INSERT INTO assessment_executions VALUES ('e1', 'a1', 'COMPLETED', CURRENT_TIMESTAMP, '{}');
	INSERT INTO assessment_targets VALUES ('t1', 'a1', 'https://example.com', 'website', 'APPROVED', '', CURRENT_TIMESTAMP);

	-- Insert two conflicting report records for the same execution_id and format
	INSERT INTO assessment_reports VALUES ('rep-orig-1', 'a1', 'e1', 'json', '/reports/r1.json', 'v1.0', 'GENERATED', CURRENT_TIMESTAMP);
	INSERT INTO assessment_reports VALUES ('rep-dup-2', 'a1', 'e1', 'json', '/reports/r2.json', 'v1.0', 'GENERATED', CURRENT_TIMESTAMP);
	`
	if _, err := rawDB.Exec(preSQL); err != nil {
		t.Fatalf("failed inserting pre-m24 fixture: %v", err)
	}
	rawDB.Close()

	// Open with NewSQLiteStore which will run Migration 24
	store, err := NewSQLiteStore(dbPath)
	if err != nil {
		t.Fatalf("NewSQLiteStore failed to run migration 24: %v", err)
	}
	defer store.Close()

	// 1. Verify ZERO rows were deleted: both rep-orig-1 and rep-dup-2 must exist
	var r1Count, r2Count int
	_ = store.db.QueryRow(`SELECT COUNT(*) FROM assessment_reports WHERE id = 'rep-orig-1'`).Scan(&r1Count)
	_ = store.db.QueryRow(`SELECT COUNT(*) FROM assessment_reports WHERE id = 'rep-dup-2'`).Scan(&r2Count)
	if r1Count != 1 || r2Count != 1 {
		t.Fatalf("Migration 24 unexpectedly deleted report data: r1=%d, r2=%d", r1Count, r2Count)
	}

	// 2. Check the formats of the reconciled records
	var f1, f2 string
	_ = store.db.QueryRow(`SELECT format FROM assessment_reports WHERE id = 'rep-orig-1'`).Scan(&f1)
	_ = store.db.QueryRow(`SELECT format FROM assessment_reports WHERE id = 'rep-dup-2'`).Scan(&f2)

	// One should be canonical 'json' and the other disambiguated with '-dup-'
	if f1 != "json" && f2 != "json" {
		t.Errorf("expected one report to retain canonical format 'json', got f1=%q, f2=%q", f1, f2)
	}
	if f1 != "json" && f1[:8] != "json-dup" {
		t.Errorf("expected disambiguated format for f1, got %q", f1)
	}
	if f2 != "json" && f2[:8] != "json-dup" {
		t.Errorf("expected disambiguated format for f2, got %q", f2)
	}

	// 3. Verify unique index prevents new conflicting (execution_id, format) entries
	_, err = store.db.Exec(`
		INSERT INTO assessment_reports (id, assessment_id, execution_id, format, file_path, felix_version, status, created_at)
		VALUES ('rep-new-conflict', 'a1', 'e1', 'json', '/reports/r3.json', 'v1.0', 'GENERATED', CURRENT_TIMESTAMP)
	`)
	if err == nil {
		t.Fatalf("expected unique index idx_reports_exec_format to reject duplicate insertion, but it succeeded")
	}
}

// TestDatabaseIntegrity_FailedAssessmentCreationRollback verifies that if a child
// target or authorization insert fails within CreateAssessment, the parent assessment
// row is completely rolled back from the database.
func TestDatabaseIntegrity_FailedAssessmentCreationRollback(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "asm_rollback.db")
	store, err := NewSQLiteStore(dbPath)
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}
	defer store.Close()

	client := &Client{ID: "cli-roll", Name: "Rollback Client"}
	if err := store.CreateClient(client); err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	asmID := "asm-to-rollback-" + uuid.New().String()
	duplicateTargetID := "target-duplicate-id"

	asm := &Assessment{
		ID:             asmID,
		Ref:            "ASM-ROLLBACK-001",
		ClientID:       client.ID,
		Name:           "Assessment Rollback Test",
		AssessmentType: "WEB",
		Status:         StatusDraft,
		Targets: []AssessmentTarget{
			{ID: duplicateTargetID, TargetURL: "https://site1.example.com"},
			{ID: duplicateTargetID, TargetURL: "https://site2.example.com"}, // duplicate primary key!
		},
	}

	err = store.CreateAssessment(asm)
	if err == nil {
		t.Fatalf("expected CreateAssessment to fail on duplicate target ID, but got nil")
	}

	// Verify the assessment row was NOT created (transaction rolled back)
	var asmCount int
	_ = store.db.QueryRow(`SELECT COUNT(*) FROM assessments WHERE id = ?`, asmID).Scan(&asmCount)
	if asmCount != 0 {
		t.Fatalf("expected 0 assessments with id %s after rollback, got %d", asmID, asmCount)
	}
}

// TestDatabaseIntegrity_MultiAssessmentBatchRollback verifies that SaveFindings
// with findings spanning multiple assessments rolls back entirely across all assessments
// if a single finding in the batch fails constraint validation.
func TestDatabaseIntegrity_MultiAssessmentBatchRollback(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "multi_asm_rollback.db")
	store, err := NewSQLiteStore(dbPath)
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}
	defer store.Close()

	client := &Client{ID: "cli-multi", Name: "Multi Client"}
	if err := store.CreateClient(client); err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	asm1 := &Assessment{
		ID:             uuid.New().String(),
		Ref:            "ASM-MULTI-001",
		ClientID:       client.ID,
		Name:           "Assessment 1",
		AssessmentType: "WEB",
		Status:         StatusRunning,
	}
	if err := store.CreateAssessment(asm1); err != nil {
		t.Fatalf("failed to create asm1: %v", err)
	}
	target1 := &AssessmentTarget{ID: uuid.New().String(), AssessmentID: asm1.ID, TargetURL: "https://asm1.example.com"}
	_ = store.AddTarget(target1)
	exec1 := &AssessmentExecution{ID: uuid.New().String(), AssessmentID: asm1.ID, Status: StatusRunning, StartedAt: time.Now().UTC()}
	_ = store.CreateExecution(exec1)

	asm2 := &Assessment{
		ID:             uuid.New().String(),
		Ref:            "ASM-MULTI-002",
		ClientID:       client.ID,
		Name:           "Assessment 2",
		AssessmentType: "WEB",
		Status:         StatusRunning,
	}
	if err := store.CreateAssessment(asm2); err != nil {
		t.Fatalf("failed to create asm2: %v", err)
	}
	target2 := &AssessmentTarget{ID: uuid.New().String(), AssessmentID: asm2.ID, TargetURL: "https://asm2.example.com"}
	_ = store.AddTarget(target2)
	exec2 := &AssessmentExecution{ID: uuid.New().String(), AssessmentID: asm2.ID, Status: StatusRunning, StartedAt: time.Now().UTC()}
	_ = store.CreateExecution(exec2)

	// Batch: 1 valid for asm1, 1 valid for asm2, 1 invalid for asm1 (non-existent target)
	batch := []AssessmentFinding{
		{
			ID:                 "find-asm1-ok",
			AssessmentID:       asm1.ID,
			ExecutionID:        exec1.ID,
			TargetID:           target1.ID,
			Title:              "Finding Asm 1",
			Category:           "auth",
			Severity:           "HIGH",
			Confidence:         "CERTAIN",
			VerificationStatus: report.VerificationVerified,
			TargetURL:          target1.TargetURL,
			Endpoint:           "/login",
			Method:             "POST",
			Fingerprint:        "fp-1",
		},
		{
			ID:                 "find-asm2-ok",
			AssessmentID:       asm2.ID,
			ExecutionID:        exec2.ID,
			TargetID:           target2.ID,
			Title:              "Finding Asm 2",
			Category:           "xss",
			Severity:           "MEDIUM",
			Confidence:         "CERTAIN",
			VerificationStatus: report.VerificationVerified,
			TargetURL:          target2.TargetURL,
			Endpoint:           "/search",
			Method:             "GET",
			Fingerprint:        "fp-2",
		},
		{
			ID:                 "find-asm1-bad",
			AssessmentID:       asm1.ID,
			ExecutionID:        exec1.ID,
			TargetID:           "non-existent-target-violates-fk",
			Title:              "Bad Finding",
			Category:           "sqli",
			Severity:           "CRITICAL",
			Confidence:         "CERTAIN",
			VerificationStatus: report.VerificationVerified,
			TargetURL:          target1.TargetURL,
			Endpoint:           "/bad",
			Method:             "POST",
			Fingerprint:        "fp-bad",
		},
	}

	err = store.SaveFindings(batch)
	if err == nil {
		t.Fatalf("expected SaveFindings to fail on FK violation, got nil")
	}

	// Verify rollback on BOTH assessments
	f1, _ := store.GetFindings(asm1.ID, exec1.ID)
	f2, _ := store.GetFindings(asm2.ID, exec2.ID)
	if len(f1) != 0 || len(f2) != 0 {
		t.Fatalf("expected 0 findings for both assessments after rollback, got asm1=%d, asm2=%d", len(f1), len(f2))
	}

	refreshedAsm1, _ := store.GetAssessment(asm1.ID)
	refreshedAsm2, _ := store.GetAssessment(asm2.ID)
	if refreshedAsm1.FindingCount != 0 || refreshedAsm2.FindingCount != 0 {
		t.Fatalf("expected finding_count 0 for both assessments, got asm1=%d, asm2=%d", refreshedAsm1.FindingCount, refreshedAsm2.FindingCount)
	}
}

// TestDatabaseIntegrity_RepeatedMigrationSafety verifies that executing store.migrate()
// multiple times sequentially against an active database with data is completely idempotent,
// causes zero data loss, and creates no duplicate schema_migrations entries.
func TestDatabaseIntegrity_RepeatedMigrationSafety(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "repeated_migration.db")
	store, err := NewSQLiteStore(dbPath)
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}
	defer store.Close()

	client := &Client{ID: "cli-rep-mig", Name: "Repeated Migration Client"}
	_ = store.CreateClient(client)

	asm := &Assessment{
		ID:             "asm-rep-mig",
		Ref:            "ASM-REP-MIG",
		ClientID:       client.ID,
		Name:           "Repeated Migration Assessment",
		AssessmentType: "WEB",
		Status:         StatusDraft,
	}
	_ = store.CreateAssessment(asm)

	// Run migrate() 5 additional times
	for i := 0; i < 5; i++ {
		if err := store.migrate(); err != nil {
			t.Fatalf("repeated migration iteration %d failed: %v", i+1, err)
		}
	}

	// Verify existing client and assessment are unharmed
	c, err := store.GetClient(client.ID)
	if err != nil || c.Name != client.Name {
		t.Fatalf("client record corrupted after repeated migrations: %+v, err: %v", c, err)
	}

	a, err := store.GetAssessment(asm.ID)
	if err != nil || a.Name != asm.Name {
		t.Fatalf("assessment record corrupted after repeated migrations: %+v, err: %v", a, err)
	}

	// Verify no duplicate versions in schema_migrations
	var dupCount int
	err = store.db.QueryRow(`
		SELECT COUNT(*) FROM (
			SELECT version FROM schema_migrations GROUP BY version HAVING COUNT(*) > 1
		)
	`).Scan(&dupCount)
	if err != nil {
		t.Fatalf("failed querying schema_migrations duplicates: %v", err)
	}
	if dupCount != 0 {
		t.Fatalf("found %d duplicate version entries in schema_migrations", dupCount)
	}
}
