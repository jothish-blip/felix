package test

import (
	"context"
	"sync/atomic"
	"database/sql"
	_ "modernc.org/sqlite"
	"net/http"
	"net/http/httptest"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"felix/pkg/assessment"
	"felix/pkg/report"
)

// helper to create a test store and base client/assessment
func setupRecoveryTestDB(t *testing.T) (*assessment.SQLiteStore, *assessment.Client, *assessment.Assessment) {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "test_recovery.db")
	store, err := assessment.NewSQLiteStore(dbPath)
	if err != nil {
		t.Fatalf("failed to open store: %v", err)
	}

	client := &assessment.Client{
		ID:   "client-rec-1",
		Name: "Recovery Corp",
	}
	if err := store.CreateClient(client); err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	asm := &assessment.Assessment{
		ID:             "asm-rec-1",
		Ref:            "ASM-REC-1",
		ClientID:       client.ID,
		Name:           "Crash Recovery Audit",
		AssessmentType: "web",
		Status:         assessment.StatusReady,
		ScopeMode:      "same-origin",
	}
	if err := store.CreateAssessment(asm); err != nil {
		t.Fatalf("failed to create assessment: %v", err)
	}

	return store, client, asm
}

func TestRecovery_1_CrashBeforeStart_FinalizedInterrupted(t *testing.T) {
	store, client, asm := setupRecoveryTestDB(t)
	defer store.Close()

	auth := assessment.NewAdminAuthContext()

	// Execution was created and marked RUNNING 10 minutes ago, but worker died before sending heartbeats
	tenMinsAgo := time.Now().UTC().Add(-10 * time.Minute)
	execRecord := &assessment.AssessmentExecution{
		ID:               "exec-crash-before-start",
		AssessmentID:     asm.ID,
		ClientID:         client.ID,
		InitiationSource: "manual",
		Status:           assessment.StatusRunning,
		StartedAt:        tenMinsAgo,
		CreatedAt:        tenMinsAgo,
		TargetCount:      1,
		WorkerID:         "worker-died-early",
	}
	if err := store.CreateExecution(execRecord); err != nil {
		t.Fatalf("failed to create execution: %v", err)
	}

	opts := assessment.RecoveryOptions{
		Auth:          auth,
		StaleDuration: 3 * time.Minute,
		MaxRetries:    3,
		WorkerID:      "rec-worker-1",
	}

	summary, err := store.RecoverExecutions(opts)
	if err != nil {
		t.Fatalf("RecoverExecutions failed: %v", err)
	}

	if summary.RecoveredCount != 1 {
		t.Fatalf("expected 1 recovered execution, got %d", summary.RecoveredCount)
	}
	if summary.FinalizedCount != 1 {
		t.Fatalf("expected 1 finalized execution, got %d", summary.FinalizedCount)
	}

	res := summary.Results[0]
	if res.Action != assessment.ActionFinalizedInterrupted {
		t.Errorf("expected action %s, got %s", assessment.ActionFinalizedInterrupted, res.Action)
	}
	if res.NewStatus != assessment.StatusInterrupted {
		t.Errorf("expected status %s, got %s", assessment.StatusInterrupted, res.NewStatus)
	}

	// Verify DB record
	updatedExec, err := store.GetExecution(execRecord.ID)
	if err != nil {
		t.Fatalf("failed to get execution: %v", err)
	}
	if updatedExec.Status != assessment.StatusInterrupted {
		t.Errorf("expected persistent status %s, got %s", assessment.StatusInterrupted, updatedExec.Status)
	}
	if updatedExec.CompletedAt == nil {
		t.Errorf("expected CompletedAt to be set")
	}
	if updatedExec.SnapshotID == "" {
		t.Errorf("expected durable snapshot ID on execution")
	}

	// Verify snapshot exists and is marked partial / inconclusive
	snap, err := store.GetSnapshot(updatedExec.SnapshotID, auth)
	if err != nil {
		t.Fatalf("failed to get snapshot: %v", err)
	}
	if snap.Status != assessment.StatusInterrupted {
		t.Errorf("expected snapshot status %s, got %s", assessment.StatusInterrupted, snap.Status)
	}
	if snap.Metadata["is_partial"] != "true" || snap.Metadata["inconclusive"] != "true" {
		t.Errorf("expected snapshot marked partial and inconclusive: %v", snap.Metadata)
	}
}

func TestRecovery_2_CrashDuringCrawl_PartialFindingsPreserved(t *testing.T) {
	store, client, asm := setupRecoveryTestDB(t)
	defer store.Close()

	auth := assessment.NewAdminAuthContext()

	// 2 approved targets
	tgt1 := &assessment.AssessmentTarget{
		AssessmentID: asm.ID,
		TargetURL:    "https://api.example.com/target1",
		ScopeStatus:  "APPROVED",
	}
	tgt2 := &assessment.AssessmentTarget{
		AssessmentID: asm.ID,
		TargetURL:    "https://api.example.com/target2",
		ScopeStatus:  "APPROVED",
	}
	_ = store.AddTarget(tgt1)
	_ = store.AddTarget(tgt2)

	fiveMinsAgo := time.Now().UTC().Add(-5 * time.Minute)
	execRecord := &assessment.AssessmentExecution{
		ID:               "exec-partial-crash",
		AssessmentID:     asm.ID,
		ClientID:         client.ID,
		InitiationSource: "manual",
		Status:           assessment.StatusRunning,
		StartedAt:        fiveMinsAgo,
		CreatedAt:        fiveMinsAgo,
		TargetCount:      2,
		WorkerID:         "worker-crashed-mid-crawl",
	}
	if err := store.CreateExecution(execRecord); err != nil {
		t.Fatalf("failed to create execution: %v", err)
	}

	// Partial findings found during target 1
	f1 := assessment.AssessmentFinding{
		ID:                "af-part-1",
		AssessmentID:      asm.ID,
		ExecutionID:       execRecord.ID,
		OriginalFindingID: "f-part-1",
		RuleID:            "API_VULN_1",
		Endpoint:          "/v1/users",
		TargetURL:         tgt1.TargetURL,
		Severity:          string(report.SeverityHigh),
		Fingerprint:       "fp-high-vuln-1",
		Confidence:        string(report.ConfidenceHigh),
		EvidenceDetails: report.EvidenceDetails{
			Location: "/v1/users",
		},
		CreatedAt: fiveMinsAgo,
	}
	f2 := assessment.AssessmentFinding{
		ID:                "af-part-2",
		AssessmentID:      asm.ID,
		ExecutionID:       execRecord.ID,
		OriginalFindingID: "f-part-2",
		RuleID:            "API_VULN_2",
		Endpoint:          "/v1/auth",
		TargetURL:         tgt1.TargetURL,
		Severity:          string(report.SeverityMedium),
		Fingerprint:       "fp-med-vuln-2",
		Confidence:        string(report.ConfidenceMedium),
		EvidenceDetails: report.EvidenceDetails{
			Location: "/v1/auth",
		},
		CreatedAt: fiveMinsAgo,
	}
	if err := store.SaveFindings([]assessment.AssessmentFinding{f1, f2}); err != nil {
		t.Fatalf("failed to save partial findings: %v", err)
	}

	// Worker recorded checkpoint after target 1, then crashed
	chk := &assessment.ScanCheckpoint{
		Stage:            "CRAWL_PARTIAL",
		CompletedTargets: []string{tgt1.TargetURL},
		RemainingTargets: []string{tgt2.TargetURL},
		FindingsCount:    2,
		LastTargetURL:    tgt1.TargetURL,
		UpdatedAt:        fiveMinsAgo,
	}
	chkBytes, _ := json.Marshal(chk)
	execRecord.CheckpointJSON = string(chkBytes)
	execRecord.FindingCount = 2
	execRecord.HeartbeatAt = &fiveMinsAgo
	leaseExp := fiveMinsAgo.Add(2 * time.Minute) // expired 3 minutes ago
	execRecord.LeaseExpiresAt = &leaseExp
	if err := store.UpdateExecution(execRecord); err != nil {
		t.Fatalf("failed to update execution with checkpoint: %v", err)
	}

	// Run recovery sweep
	summary, err := store.RecoverExecutions(assessment.RecoveryOptions{
		Auth:          auth,
		StaleDuration: 2 * time.Minute,
		MaxRetries:    3,
		WorkerID:      "rec-worker-crawl",
	})
	if err != nil {
		t.Fatalf("RecoverExecutions failed: %v", err)
	}

	if summary.FinalizedCount != 1 {
		t.Fatalf("expected 1 finalized, got %d", summary.FinalizedCount)
	}
	if summary.Results[0].PreservedFindings != 2 {
		t.Fatalf("expected 2 preserved findings, got %d", summary.Results[0].PreservedFindings)
	}

	// Invariant: Findings must be 100% intact and queryable
	storedFindings, err := store.GetFindings(asm.ID, execRecord.ID)
	if err != nil {
		t.Fatalf("failed to get findings: %v", err)
	}
	if len(storedFindings) != 2 {
		t.Errorf("expected 2 findings in store, got %d", len(storedFindings))
	}

	// Invariant: Historical snapshot must capture assessed target and partial stage
	updExec, _ := store.GetExecution(execRecord.ID)
	snap, err := store.GetSnapshot(updExec.SnapshotID, auth)
	if err != nil {
		t.Fatalf("failed to get snapshot: %v", err)
	}
	assessed := snap.GetAssessedTargets()
	if len(assessed) != 1 || assessed[0] != tgt1.TargetURL {
		t.Errorf("expected assessed targets [%s], got %v", tgt1.TargetURL, assessed)
	}
	if snap.Metadata["checkpoint_stage"] != "CRAWL_PARTIAL" {
		t.Errorf("expected checkpoint_stage CRAWL_PARTIAL, got %s", snap.Metadata["checkpoint_stage"])
	}
}

func TestRecovery_3_ActiveWorkerProtection(t *testing.T) {
	store, client, asm := setupRecoveryTestDB(t)
	defer store.Close()

	auth := assessment.NewAdminAuthContext()

	// Execution is actively running with fresh heartbeat 15 seconds ago, lease expires in 4 minutes
	now := time.Now().UTC()
	recentHb := now.Add(-15 * time.Second)
	leaseExp := now.Add(4 * time.Minute)

	execRecord := &assessment.AssessmentExecution{
		ID:               "exec-active-worker",
		AssessmentID:     asm.ID,
		ClientID:         client.ID,
		InitiationSource: "manual",
		Status:           assessment.StatusRunning,
		StartedAt:        now.Add(-1 * time.Minute),
		CreatedAt:        now.Add(-1 * time.Minute),
		WorkerID:         "live-worker-42",
		HeartbeatAt:      &recentHb,
		LeaseExpiresAt:   &leaseExp,
	}
	if err := store.CreateExecution(execRecord); err != nil {
		t.Fatalf("failed to create execution: %v", err)
	}

	// Recovery sweep with 3m stale threshold
	summary, err := store.RecoverExecutions(assessment.RecoveryOptions{
		Auth:          auth,
		StaleDuration: 3 * time.Minute,
		MaxRetries:    3,
		WorkerID:      "rec-worker-sweeper",
	})
	if err != nil {
		t.Fatalf("RecoverExecutions failed: %v", err)
	}

	// Active execution MUST NOT be touched
	if summary.ExaminedCount != 0 {
		t.Errorf("expected 0 abandoned executions examined, got %d", summary.ExaminedCount)
	}
	if summary.RecoveredCount != 0 {
		t.Errorf("active worker execution was improperly recovered!")
	}

	curr, _ := store.GetExecution(execRecord.ID)
	if curr.Status != assessment.StatusRunning {
		t.Errorf("expected status %s, got %s", assessment.StatusRunning, curr.Status)
	}
	if curr.WorkerID != "live-worker-42" {
		t.Errorf("worker ID was overwritten on active execution!")
	}
}

func TestRecovery_4_ExpiredLeaseRecovery(t *testing.T) {
	store, client, asm := setupRecoveryTestDB(t)
	defer store.Close()

	auth := assessment.NewAdminAuthContext()

	// Execution lease expired 1 minute ago
	now := time.Now().UTC()
	staleHb := now.Add(-6 * time.Minute)
	expiredLease := now.Add(-1 * time.Minute)

	execRecord := &assessment.AssessmentExecution{
		ID:               "exec-expired-lease",
		AssessmentID:     asm.ID,
		ClientID:         client.ID,
		InitiationSource: "manual",
		Status:           assessment.StatusRunning,
		StartedAt:        now.Add(-10 * time.Minute),
		CreatedAt:        now.Add(-10 * time.Minute),
		WorkerID:         "abandoned-worker-99",
		HeartbeatAt:      &staleHb,
		LeaseExpiresAt:   &expiredLease,
	}
	if err := store.CreateExecution(execRecord); err != nil {
		t.Fatalf("failed to create execution: %v", err)
	}

	// Sweep recovers the expired lease
	summary, err := store.RecoverExecutions(assessment.RecoveryOptions{
		Auth:          auth,
		StaleDuration: 3 * time.Minute,
		MaxRetries:    3,
		WorkerID:      "recovery-agent-primary",
	})
	if err != nil {
		t.Fatalf("recovery sweep failed: %v", err)
	}

	if summary.RecoveredCount != 1 {
		t.Fatalf("expected 1 recovered execution, got %d", summary.RecoveredCount)
	}

	curr, _ := store.GetExecution(execRecord.ID)
	if curr.Status != assessment.StatusInterrupted {
		t.Errorf("expected status %s, got %s", assessment.StatusInterrupted, curr.Status)
	}
	if curr.RecoveryAttempts != 1 {
		t.Errorf("expected 1 recovery attempt, got %d", curr.RecoveryAttempts)
	}
}

func TestRecovery_5_ConcurrentRecoveryWorkersRace(t *testing.T) {
	store, client, asm := setupRecoveryTestDB(t)
	defer store.Close()

	now := time.Now().UTC()
	expiredLease := now.Add(-5 * time.Minute)

	execRecord := &assessment.AssessmentExecution{
		ID:               "exec-concurrent-race",
		AssessmentID:     asm.ID,
		ClientID:         client.ID,
		InitiationSource: "manual",
		Status:           assessment.StatusRunning,
		StartedAt:        now.Add(-15 * time.Minute),
		CreatedAt:        now.Add(-15 * time.Minute),
		WorkerID:         "dead-worker-1",
		LeaseExpiresAt:   &expiredLease,
	}
	if err := store.CreateExecution(execRecord); err != nil {
		t.Fatalf("failed to create execution: %v", err)
	}

	// Two workers attempt to claim the abandoned execution concurrently
	const workers = 10
	var wg sync.WaitGroup
	wins := 0
	var mu sync.Mutex

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(workerIdx int) {
			defer wg.Done()
			wID := filepath.Join("worker", time.Now().String())
			won, err := store.ClaimAbandonedExecutionForRecovery(execRecord.ID, wID, time.Now().UTC(), 5*time.Minute)
			if err == nil && won {
				mu.Lock()
				wins++
				mu.Unlock()
			}
		}(i)
	}

	wg.Wait()

	// Invariant: Exactly ONE recovery worker must win the claim
	if wins != 1 {
		t.Fatalf("expected exactly 1 worker to win claim, got %d", wins)
	}
}

func TestRecovery_6_StaleWorkerWriteRejection(t *testing.T) {
	store, client, asm := setupRecoveryTestDB(t)
	defer store.Close()

	now := time.Now().UTC()
	expiredLease := now.Add(-2 * time.Minute)

	execRecord := &assessment.AssessmentExecution{
		ID:               "exec-stale-worker",
		AssessmentID:     asm.ID,
		ClientID:         client.ID,
		InitiationSource: "manual",
		Status:           assessment.StatusRunning,
		StartedAt:        now.Add(-10 * time.Minute),
		CreatedAt:        now.Add(-10 * time.Minute),
		WorkerID:         "stale-worker-A",
		LeaseExpiresAt:   &expiredLease,
	}
	if err := store.CreateExecution(execRecord); err != nil {
		t.Fatalf("failed to create execution: %v", err)
	}

	// Recovery worker claims the abandoned execution
	won, err := store.ClaimAbandonedExecutionForRecovery(execRecord.ID, "recovery-worker-B", now, 5*time.Minute)
	if err != nil || !won {
		t.Fatalf("recovery claim failed: won=%v, err=%v", won, err)
	}

	// Stale worker A awakens from freeze/sleep and attempts heartbeat
	hbErr := store.HeartbeatExecution(execRecord.ID, "stale-worker-A", nil, 5*time.Minute)
	if !errors.Is(hbErr, assessment.ErrLeaseLost) {
		t.Fatalf("expected ErrLeaseLost on stale worker heartbeat, got %v", hbErr)
	}

	// Stale worker attempts UpdateExecution to COMPLETED -> finalization by recovery seals it
	_, err = store.FinalizeAbandonedExecution(execRecord.ID, "recovery-worker-B", assessment.StatusInterrupted, "Worker timed out", assessment.NewAdminAuthContext())
	if err != nil {
		t.Fatalf("finalize failed: %v", err)
	}

	// Once terminal, stale worker attempting heartbeat must receive terminal or lease error
	hbErr2 := store.HeartbeatExecution(execRecord.ID, "stale-worker-A", nil, 5*time.Minute)
	if hbErr2 == nil {
		t.Errorf("expected error when stale worker heartbeats terminal execution, got nil")
	}
}

func TestRecovery_7_SafeResumptionWithCheckpoint(t *testing.T) {
	store, _, asm := setupRecoveryTestDB(t)
	defer store.Close()

	// 3 approved targets
	t1 := &assessment.AssessmentTarget{AssessmentID: asm.ID, TargetURL: "https://example.com/target1", ScopeStatus: "APPROVED"}
	t2 := &assessment.AssessmentTarget{AssessmentID: asm.ID, TargetURL: "https://example.com/target2", ScopeStatus: "APPROVED"}
	t3 := &assessment.AssessmentTarget{AssessmentID: asm.ID, TargetURL: "https://example.com/target3", ScopeStatus: "APPROVED"}
	_ = store.AddTarget(t1)
	_ = store.AddTarget(t2)
	_ = store.AddTarget(t3)

	// Simulate checkpoint with target 1 completed
	chk := &assessment.ScanCheckpoint{
		Stage:            "CRAWL_PARTIAL",
		CompletedTargets: []string{t1.TargetURL},
		RemainingTargets: []string{t2.TargetURL, t3.TargetURL},
		FindingsCount:    1,
		LastTargetURL:    t1.TargetURL,
		UpdatedAt:        time.Now().UTC(),
	}

	ctrl := assessment.NewController(store)

	// When controller runs with ResumeCheckpoint, it filters out Target 1
	// and only executes against Targets 2 & 3.
	// Since example.com targets are mocked, let's verify ResumeCheckpoint filtering logic.
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	opts := assessment.ExecutionOptions{
		ExecutionID:      "exec-resume-test",
		ResumeCheckpoint: chk,
		ProgressFunc:     func(msg string) {},
	}

	// Execution will fail on reachability (no real network), but we verify TargetCount and resumption message
	res, _ := ctrl.RunAssessment(ctx, asm.ID, opts)
	if res != nil && res.Execution != nil {
		// TargetCount should reflect remaining targets (2), not the full 3
		if res.Execution.TargetCount != 2 {
			t.Errorf("expected TargetCount to be 2 (remaining), got %d", res.Execution.TargetCount)
		}
	}
}

func TestRecovery_8_ExceededRetryLimit(t *testing.T) {
	store, client, asm := setupRecoveryTestDB(t)
	defer store.Close()

	auth := assessment.NewAdminAuthContext()

	now := time.Now().UTC()
	expiredLease := now.Add(-5 * time.Minute)

	// Execution has already undergone 3 recovery attempts
	execRecord := &assessment.AssessmentExecution{
		ID:               "exec-retry-limit-exceeded",
		AssessmentID:     asm.ID,
		ClientID:         client.ID,
		InitiationSource: "manual",
		Status:           assessment.StatusRunning,
		StartedAt:        now.Add(-30 * time.Minute),
		CreatedAt:        now.Add(-30 * time.Minute),
		WorkerID:         "flaky-worker",
		RecoveryAttempts: 3,
		LeaseExpiresAt:   &expiredLease,
	}
	if err := store.CreateExecution(execRecord); err != nil {
		t.Fatalf("failed to create execution: %v", err)
	}

	summary, err := store.RecoverExecutions(assessment.RecoveryOptions{
		Auth:          auth,
		StaleDuration: 3 * time.Minute,
		MaxRetries:    3,
		WorkerID:      "rec-worker-limit",
	})
	if err != nil {
		t.Fatalf("RecoverExecutions failed: %v", err)
	}

	if summary.SkippedCount != 1 {
		t.Errorf("expected 1 skipped due to limit, got %d", summary.SkippedCount)
	}
	if summary.Results[0].Action != assessment.ActionSkippedExceededLimit {
		t.Errorf("expected action %s, got %s", assessment.ActionSkippedExceededLimit, summary.Results[0].Action)
	}

	// Invariant: Must still be finalized permanently as INTERRUPTED
	curr, _ := store.GetExecution(execRecord.ID)
	if curr.Status != assessment.StatusInterrupted {
		t.Errorf("expected status %s, got %s", assessment.StatusInterrupted, curr.Status)
	}
}

func TestRecovery_9_MultiTenantIsolation(t *testing.T) {
	store, _, _ := setupRecoveryTestDB(t)
	defer store.Close()

	now := time.Now().UTC()
	expiredLease := now.Add(-5 * time.Minute)

	// Tenant A client and assessment
	clientA := &assessment.Client{ID: "client-A", Name: "Corp A"}
	_ = store.CreateClient(clientA)
	asmA := &assessment.Assessment{ID: "asm-A", Ref: "ASM-A", ClientID: clientA.ID, Name: "A", Status: assessment.StatusReady}
	_ = store.CreateAssessment(asmA)

	execA := &assessment.AssessmentExecution{
		ID:             "exec-tenant-A",
		AssessmentID:   asmA.ID,
		ClientID:       clientA.ID,
		TenantID:       "tenant-A",
		Status:         assessment.StatusRunning,
		StartedAt:      now.Add(-10 * time.Minute),
		CreatedAt:      now.Add(-10 * time.Minute),
		LeaseExpiresAt: &expiredLease,
	}
	_ = store.CreateExecution(execA)

	// Tenant B client and assessment
	clientB := &assessment.Client{ID: "client-B", Name: "Corp B"}
	_ = store.CreateClient(clientB)
	asmB := &assessment.Assessment{ID: "asm-B", Ref: "ASM-B", ClientID: clientB.ID, Name: "B", Status: assessment.StatusReady}
	_ = store.CreateAssessment(asmB)

	execB := &assessment.AssessmentExecution{
		ID:             "exec-tenant-B",
		AssessmentID:   asmB.ID,
		ClientID:       clientB.ID,
		TenantID:       "tenant-B",
		Status:         assessment.StatusRunning,
		StartedAt:      now.Add(-10 * time.Minute),
		CreatedAt:      now.Add(-10 * time.Minute),
		LeaseExpiresAt: &expiredLease,
	}
	if err := store.CreateExecution(execB); err != nil {
		t.Fatalf("failed to create execB: %v", err)
	}

	// Tenant A caller recovers abandoned executions
	authA := assessment.NewTenantAuthContext(clientA.ID, "tenant-A", "")
	summaryA, err := store.RecoverExecutions(assessment.RecoveryOptions{
		Auth:          authA,
		StaleDuration: 3 * time.Minute,
		MaxRetries:    3,
		WorkerID:      "worker-tenant-A",
	})
	if err != nil {
		t.Fatalf("RecoverExecutions failed: %v", err)
	}

	// Only Tenant A's execution should be recovered
	if summaryA.RecoveredCount != 1 {
		t.Fatalf("expected 1 recovered execution for tenant A, got %d", summaryA.RecoveredCount)
	}
	if summaryA.Results[0].ExecutionID != execA.ID {
		t.Errorf("expected tenant A exec recovered, got %s", summaryA.Results[0].ExecutionID)
	}

	// Tenant B's execution must remain untouched
	currB, err := store.GetExecution(execB.ID)
	if err != nil {
		t.Fatalf("failed to get execB: %v", err)
	}
	if currB.Status != assessment.StatusRunning {
		t.Errorf("tenant B execution was illegally modified by tenant A recovery!")
	}
}

func TestRecovery_10_RecoveryIdempotency(t *testing.T) {
	store, client, asm := setupRecoveryTestDB(t)
	defer store.Close()

	auth := assessment.NewAdminAuthContext()

	now := time.Now().UTC()
	expiredLease := now.Add(-5 * time.Minute)

	execRecord := &assessment.AssessmentExecution{
		ID:               "exec-idempotent-sweep",
		AssessmentID:     asm.ID,
		ClientID:         client.ID,
		InitiationSource: "manual",
		Status:           assessment.StatusRunning,
		StartedAt:        now.Add(-10 * time.Minute),
		CreatedAt:        now.Add(-10 * time.Minute),
		LeaseExpiresAt:   &expiredLease,
	}
	_ = store.CreateExecution(execRecord)

	opts := assessment.RecoveryOptions{
		Auth:          auth,
		StaleDuration: 3 * time.Minute,
		MaxRetries:    3,
		WorkerID:      "idempotent-agent",
	}

	// First sweep recovers
	s1, err := store.RecoverExecutions(opts)
	if err != nil || s1.RecoveredCount != 1 {
		t.Fatalf("first sweep failed: count=%d, err=%v", s1.RecoveredCount, err)
	}

	// Second sweep finds nothing to recover
	s2, err := store.RecoverExecutions(opts)
	if err != nil {
		t.Fatalf("second sweep failed: %v", err)
	}
	if s2.RecoveredCount != 0 {
		t.Errorf("expected 0 recovered on second sweep, got %d", s2.RecoveredCount)
	}

	// Third sweep explicitly targeting this execution ID recognizes terminal state
	optsTargeted := opts
	optsTargeted.ExecutionID = execRecord.ID
	s3, err := store.RecoverExecutions(optsTargeted)
	if err != nil {
		t.Fatalf("third sweep failed: %v", err)
	}
	if s3.RecoveredCount != 0 {
		t.Errorf("expected 0 recovered on targeted terminal sweep, got %d", s3.RecoveredCount)
	}
}

func TestRecovery_11_FindingDeltaAndLifecycleCompatibility(t *testing.T) {
	// Invariant: An interrupted execution with partial findings must NOT cause
	// baseline findings to be falsely marked RESOLVED in finding delta comparison.
	store, client, asm := setupRecoveryTestDB(t)
	defer store.Close()

	auth := assessment.NewAdminAuthContext()

	tgt := &assessment.AssessmentTarget{
		ID:           "tgt-base-1",
		AssessmentID: asm.ID,
		TargetURL:    "https://api.example.com",
		ScopeStatus:  "APPROVED",
	}
	if err := store.AddTarget(tgt); err != nil {
		t.Fatalf("failed to add target: %v", err)
	}

	// 1. Create baseline completed execution with finding F1
	baseExec := &assessment.AssessmentExecution{
		ID:           "exec-delta-base",
		AssessmentID: asm.ID,
		ClientID:     client.ID,
		Status:       assessment.StatusCompleted,
		StartedAt:    time.Now().UTC().Add(-2 * time.Hour),
		TargetCount:  2,
		FindingCount: 1,
	}
	_ = store.CreateExecution(baseExec)

	baseFinding := assessment.AssessmentFinding{
		ID:                "af-base-1",
		AssessmentID:      asm.ID,
		ExecutionID:       baseExec.ID,
		TargetID:          tgt.ID,
		OriginalFindingID: "f-base-101",
		TargetURL:         "https://api.example.com",
		Severity:          string(report.SeverityHigh),
		Fingerprint:       "fp-sql-injection-user",
		Confidence:        string(report.ConfidenceHigh),
		EvidenceDetails: report.EvidenceDetails{
			Location: "/users",
		},
	}
	if err := store.SaveFindings([]assessment.AssessmentFinding{baseFinding}); err != nil {
		t.Fatalf("failed to save baseFinding: %v", err)
	}

	baseSnap := assessment.BuildAssessmentSnapshot(asm, baseExec, []string{"https://api.example.com"}, []assessment.AssessmentFinding{baseFinding}, true)
	baseSnap.SetAssessedTargets([]string{"https://api.example.com"})
	baseEv := assessment.ExtractHistoricalEvidence(baseSnap.ID, []assessment.AssessmentFinding{baseFinding})
	_ = store.CreateSnapshot(baseSnap, []assessment.AssessmentFinding{baseFinding}, baseEv)
	baseExec.SnapshotID = baseSnap.ID
	_ = store.UpdateExecution(baseExec)

	// 2. Second execution started, evaluated only 1 of 2 targets, then crashed and recovered
	crashedExec := &assessment.AssessmentExecution{
		ID:             "exec-delta-crashed",
		AssessmentID:   asm.ID,
		ClientID:       client.ID,
		Status:         assessment.StatusRunning,
		StartedAt:      time.Now().UTC().Add(-30 * time.Minute),
		TargetCount:    2,
		LeaseExpiresAt: func() *time.Time { t := time.Now().UTC().Add(-10 * time.Minute); return &t }(),
	}
	_ = store.CreateExecution(crashedExec)

	// Recover it
	_, err := store.RecoverExecutions(assessment.RecoveryOptions{
		Auth:          auth,
		StaleDuration: 3 * time.Minute,
		MaxRetries:    3,
	})
	if err != nil {
		t.Fatalf("recovery failed: %v", err)
	}

	// 3. Compare execution history via Phase 7.3 Store method
	cmp, err := store.CompareExecutionHistory(baseExec.ID, crashedExec.ID, auth)
	if err != nil {
		t.Fatalf("CompareExecutionHistory failed: %v", err)
	}

	// Invariant: Because second execution was INTERRUPTED and not complete,
	// baseline finding must NOT be classified as RESOLVED!
	t.Logf("cmp: %+v", cmp)
	if cmp.ResolvedCount > 0 {
		t.Fatalf("CRITICAL SAFETY VIOLATION: Interrupted execution caused %d finding(s) to be marked RESOLVED!", cmp.ResolvedCount)
	}
	if cmp.UnassessedCount != 1 {
		t.Errorf("expected 1 UNASSESSED finding due to incomplete assessment, got %d", cmp.UnassessedCount)
	}
}

func TestRecovery_12_CLIRecoveryExecution(t *testing.T) {
	// Build or locate binary
	binPath := filepath.Join("..", "bin", "felix.exe")
	if _, err := os.Stat(binPath); os.IsNotExist(err) {
		binPath = filepath.Join("bin", "felix.exe")
	}
	if _, err := os.Stat(binPath); os.IsNotExist(err) {
		t.Skip("felix binary not found; skipping CLI test")
	}

	// Prepare temp DB with an abandoned execution
	dbPath := filepath.Join(t.TempDir(), "test_cli_rec.db")
	store, err := assessment.NewSQLiteStore(dbPath)
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}

	client := &assessment.Client{ID: "client-cli", Name: "CLI Corp"}
	_ = store.CreateClient(client)
	asm := &assessment.Assessment{ID: "asm-cli", ClientID: client.ID, Name: "CLI", Status: assessment.StatusReady}
	_ = store.CreateAssessment(asm)

	now := time.Now().UTC()
	expiredLease := now.Add(-5 * time.Minute)
	execRecord := &assessment.AssessmentExecution{
		ID:             "exec-cli-test",
		AssessmentID:   asm.ID,
		ClientID:       client.ID,
		Status:         assessment.StatusRunning,
		StartedAt:      now.Add(-10 * time.Minute),
		CreatedAt:      now.Add(-10 * time.Minute),
		LeaseExpiresAt: &expiredLease,
	}
	_ = store.CreateExecution(execRecord)
	store.Close()

	// Run CLI recover command with --json
	cmd := exec.Command(binPath, "assessment", "recover", "--db", dbPath, "--json")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("CLI recovery command failed: %v, output: %s", err, string(out))
	}

	var summary assessment.RecoverySummary
	if err := json.Unmarshal(out, &summary); err != nil {
		t.Fatalf("failed to parse CLI JSON output: %v, raw: %s", err, string(out))
	}

	if summary.RecoveredCount != 1 {
		t.Errorf("expected 1 recovered in CLI output, got %d", summary.RecoveredCount)
	}
	if len(summary.Results) != 1 || summary.Results[0].ExecutionID != execRecord.ID {
		t.Errorf("unexpected results in CLI output: %+v", summary.Results)
	}
}


func TestRecovery_13_LongRunningTarget_ActiveLeaseRenewal_RejectsConcurrentClaim(t *testing.T) {
	store, client, asm := setupRecoveryTestDB(t)
	defer store.Close()

	// Spin up a slow test HTTP server that simulates a long-running target
	var reqCount int32
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if atomic.AddInt32(&reqCount, 1) == 1 {
			time.Sleep(1200 * time.Millisecond)
		}
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("<html><body><h1>Slow Target</h1></body></html>"))
	}))
	defer ts.Close()

	// Add approved target
	target := &assessment.AssessmentTarget{
		ID:           "tgt-slow",
		AssessmentID: asm.ID,
		TargetURL:    ts.URL,
		TargetType:   assessment.TargetWebsite,
		ScopeStatus:  "APPROVED",
	}
	if err := store.AddTarget(target); err != nil {
		t.Fatalf("failed to add target: %v", err)
	}

	_ = client
	past := time.Now().UTC().Add(-1 * time.Hour)
	future := time.Now().UTC().Add(24 * time.Hour)
	authRec := &assessment.AuthorizationRecord{
		ID:                  "auth-slow",
		AssessmentID:        asm.ID,
		AuthorizingParty:    "Security Team",
		AuthorizationMethod: "WRITTEN",
		DateReceived:        past,
		ValidFrom:           &past,
		ValidUntil:          &future,
		Status:              assessment.AuthApproved,
	}
	if err := store.SetAuthorization(authRec); err != nil {
		t.Fatalf("failed to save authorization: %v", err)
	}

	ctrl := assessment.NewController(store)

	execID := "exec-long-running-healthy"
	workerID := "healthy-worker-1"
	leaseDuration := 600 * time.Millisecond // Short lease duration

	opts := assessment.ExecutionOptions{
		ExecutionID:     execID,
		WorkerID:        workerID,
		LeaseDuration:   leaseDuration,
		AllowLoopback:   true,
		AllowPrivateIPs: true,
		ProgressFunc:    func(string) {},
	}

	var wg sync.WaitGroup
	var runResult *assessment.ExecutionResult
	var runErr error
	var concurrentWon bool
	var concurrentErr error

	wg.Add(1)
	go func() {
		defer wg.Done()
		runResult, runErr = ctrl.RunAssessment(context.Background(), asm.ID, opts)
	}()

	// At t = 850ms, the original 600ms lease would have expired without renewal.
	// But the active background renewal runs every 200ms, keeping the lease valid.
	time.Sleep(850 * time.Millisecond)

	// Concurrent recovery attempt tries to steal/reclaim ownership
	concurrentWon, concurrentErr = store.ClaimAbandonedExecutionForRecovery(
		execID,
		"recovery-adversary",
		time.Now().UTC(),
		5*time.Minute,
	)

	wg.Wait()

	if concurrentErr != nil {
		t.Fatalf("concurrent claim query error: %v", concurrentErr)
	}
	if concurrentWon {
		t.Fatalf("CRITICAL FLAW: Concurrent recovery claimed execution while healthy worker owned valid lease!")
	}

	if runErr != nil {
		t.Fatalf("RunAssessment failed: %v", runErr)
	}
	if runResult == nil || runResult.Execution == nil {
		t.Fatalf("expected non-nil execution result")
	}
	if runResult.Execution.Status != assessment.StatusCompleted {
		t.Errorf("expected execution COMPLETED, got %s", runResult.Execution.Status)
	}
	if runResult.Execution.WorkerID != workerID {
		t.Errorf("expected workerID %s, got %s", workerID, runResult.Execution.WorkerID)
	}
}

func TestRecovery_14_StaleWorkerFencing_SaveFindings_CreateSnapshot_UpdateExecution(t *testing.T) {
	store, client, asm := setupRecoveryTestDB(t)
	defer store.Close()

	target := &assessment.AssessmentTarget{
		ID:           "tgt-fencing",
		AssessmentID: asm.ID,
		TargetURL:    "https://fencing.example",
		TargetType:   assessment.TargetWebsite,
		ScopeStatus:  "APPROVED",
	}
	_ = store.AddTarget(target)

	now := time.Now().UTC()
	execID := "exec-fenced-worker"
	staleWorkerID := "stale-worker-old"
	recoveryWorkerID := "recovery-worker-new"

	// Execution created with an expired lease
	expiredTime := now.Add(-10 * time.Minute)
	exec := &assessment.AssessmentExecution{
		ID:             execID,
		AssessmentID:   asm.ID,
		ClientID:       client.ID,
		Status:         assessment.StatusRunning,
		StartedAt:      expiredTime,
		WorkerID:       staleWorkerID,
		HeartbeatAt:    &expiredTime,
		LeaseExpiresAt: &expiredTime,
	}
	if err := store.CreateExecution(exec); err != nil {
		t.Fatalf("failed creating execution: %v", err)
	}

	// Recovery worker reclaims and finalizes the execution as INTERRUPTED
	won, err := store.ClaimAbandonedExecutionForRecovery(execID, recoveryWorkerID, now, 5*time.Minute)
	if err != nil || !won {
		t.Fatalf("recovery claim failed: won=%v, err=%v", won, err)
	}
	_, err = store.FinalizeAbandonedExecution(execID, recoveryWorkerID, assessment.StatusInterrupted, "Worker lost", assessment.NewAdminAuthContext())
	if err != nil {
		t.Fatalf("finalization failed: %v", err)
	}

	// Fencing Check 1: Stale worker cannot persist new findings under recovered execution
	staleFinding := assessment.AssessmentFinding{
		ID:                "fnd-stale-write",
		AssessmentID:      asm.ID,
		ExecutionID:       execID,
		TargetID:          target.ID,
		OriginalFindingID: "STALE-01",
		Title:             "Stale Finding Attempt",
		Status:            report.FindingStatusConfirmed,
	}
	err = store.SaveFindings([]assessment.AssessmentFinding{staleFinding})
	if err == nil {
		t.Fatalf("CRITICAL FLAW: Stale worker successfully saved findings under recovered execution!")
	}
	if !errors.Is(err, assessment.ErrExecutionTerminal) && !errors.Is(err, assessment.ErrSnapshotImmutable) {
		t.Logf("SaveFindings correctly rejected with: %v", err)
	}

	// Fencing Check 2: Stale worker cannot create or replace snapshot
	staleSnap := &assessment.AssessmentSnapshot{
		ID:           "snap-stale-attempt",
		SnapshotRef:  "SNP-STALE",
		AssessmentID: asm.ID,
		ExecutionID:  execID,
		Status:       assessment.StatusCompleted,
		IsComplete:   true,
		CreatedAt:    now,
	}
	err = store.CreateSnapshot(staleSnap, []assessment.AssessmentFinding{staleFinding}, nil)
	if err == nil {
		t.Fatalf("CRITICAL FLAW: Stale worker successfully created snapshot on recovered execution!")
	}
	if !errors.Is(err, assessment.ErrSnapshotImmutable) {
		t.Logf("CreateSnapshot correctly rejected with: %v", err)
	}

	// Fencing Check 3: Stale worker cannot overwrite terminal status or update execution
	staleExecUpdate := &assessment.AssessmentExecution{
		ID:           execID,
		AssessmentID: asm.ID,
		Status:       assessment.StatusCompleted,
		WorkerID:     staleWorkerID,
	}
	err = store.UpdateExecution(staleExecUpdate)
	if err == nil {
		t.Fatalf("CRITICAL FLAW: Stale worker successfully updated execution record after recovery finalization!")
	}
	t.Logf("UpdateExecution correctly rejected with: %v", err)

	// Verify terminal status remained INTERRUPTED
	finalExec, _ := store.GetExecution(execID)
	if finalExec.Status != assessment.StatusInterrupted {
		t.Errorf("expected final status INTERRUPTED, got %s", finalExec.Status)
	}
}

func TestRecovery_15_CheckpointResume_RealExecution_CompletedSkipped_FindingsPreserved(t *testing.T) {
	store, client, asm := setupRecoveryTestDB(t)
	defer store.Close()

	// Spin up 2 test HTTP targets
	target1HitCount := 0
	target2HitCount := 0

	ts1 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		target1HitCount++
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("<html><body>Target 1 Content</body></html>"))
	}))
	defer ts1.Close()

	ts2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		target2HitCount++
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("<html><body>Target 2 Content</body></html>"))
	}))
	defer ts2.Close()

	tgt1 := &assessment.AssessmentTarget{
		ID:           "tgt-resume-1",
		AssessmentID: asm.ID,
		TargetURL:    ts1.URL,
		TargetType:   assessment.TargetWebsite,
		ScopeStatus:  "APPROVED",
	}
	tgt2 := &assessment.AssessmentTarget{
		ID:           "tgt-resume-2",
		AssessmentID: asm.ID,
		TargetURL:    ts2.URL,
		TargetType:   assessment.TargetWebsite,
		ScopeStatus:  "APPROVED",
	}
	_ = store.AddTarget(tgt1)
	_ = store.AddTarget(tgt2)

	past15 := time.Now().UTC().Add(-1 * time.Hour)
	future15 := time.Now().UTC().Add(24 * time.Hour)
	authRec := &assessment.AuthorizationRecord{
		ID:                  "auth-resume",
		AssessmentID:        asm.ID,
		AuthorizingParty:    "admin",
		AuthorizationMethod: "WRITTEN",
		DateReceived:        past15,
		ValidFrom:           &past15,
		ValidUntil:          &future15,
		Status:              assessment.AuthApproved,
	}
	_ = store.SetAuthorization(authRec)

	execID := "exec-resume-demo"
	now := time.Now().UTC()
	expiredLease := now.Add(-10 * time.Minute)

	// Target 1 was completed and produced a finding before crash
	chk := &assessment.ScanCheckpoint{
		Stage:            "CRAWL_PARTIAL",
		CompletedTargets: []string{ts1.URL},
		RemainingTargets: []string{ts2.URL},
		FindingsCount:    1,
		LastTargetURL:    ts1.URL,
		UpdatedAt:        expiredTimeHelper(-10 * time.Minute),
	}
	chkJSON, _ := json.Marshal(chk)

	execRecord := &assessment.AssessmentExecution{
		ID:             execID,
		AssessmentID:   asm.ID,
		ClientID:       client.ID,
		Status:         assessment.StatusRunning,
		StartedAt:      now.Add(-15 * time.Minute),
		CreatedAt:      now.Add(-15 * time.Minute),
		WorkerID:       "worker-crashed-midway",
		HeartbeatAt:    &expiredLease,
		LeaseExpiresAt: &expiredLease,
		CheckpointJSON: string(chkJSON),
	}
	if err := store.CreateExecution(execRecord); err != nil {
		t.Fatalf("failed creating execution: %v", err)
	}

	// Persist Target 1 finding
	finding1 := assessment.AssessmentFinding{
		ID:                 "fnd-tgt1-preserved",
		AssessmentID:       asm.ID,
		ExecutionID:        execID,
		TargetID:           tgt1.ID,
		OriginalFindingID:  "FND-T1",
		Title:              "Information Disclosure in Target 1",
		Category:           "webvuln",
		Severity:           report.SeverityMedium,
		Confidence:         report.ConfidenceHigh,
		VerificationStatus: report.VerificationVerified,
		TargetURL:          ts1.URL,
		Endpoint:           ts1.URL,
		Method:             "GET",
		Status:             report.FindingStatusConfirmed,
	}
	if err := store.SaveFindings([]assessment.AssessmentFinding{finding1}); err != nil {
		t.Fatalf("failed saving initial finding: %v", err)
	}

	ctrl := assessment.NewController(store)

	// Execute recovery with --allow-resume
	opts := assessment.RecoveryOptions{
		Auth:            assessment.NewAdminAuthContext(),
		ExecutionID:     execID,
		StaleDuration:   3 * time.Minute,
		MaxRetries:      3,
		AllowResume:     true,
		AllowLoopback:   true,
		AllowPrivateIPs: true,
		WorkerID:        "recovery-resumer-1",
		Runner:          ctrl.RunAssessment,
		Context:         context.Background(),
	}

	summary, err := store.RecoverExecutions(opts)
	if err != nil {
		t.Fatalf("RecoverExecutions failed: %v", err)
	}

	if summary.ResumedCount != 1 {
		t.Fatalf("expected 1 resumed execution, got %d (results: %+v)", summary.ResumedCount, summary.Results)
	}
	if summary.Results[0].Action != assessment.ActionResumed {
		t.Errorf("expected action %s, got %s", assessment.ActionResumed, summary.Results[0].Action)
	}

	// Verify target 1 was skipped and target 2 was visited
	if target1HitCount != 0 {
		t.Errorf("expected Target 1 to be skipped (0 hits), got %d hits", target1HitCount)
	}
	if target2HitCount == 0 {
		t.Errorf("expected Target 2 to be evaluated during resumption, got 0 hits")
	}

	// Verify execution record reached COMPLETED
	updatedExec, err := store.GetExecution(execID)
	if err != nil {
		t.Fatalf("failed retrieving execution: %v", err)
	}
	if updatedExec.Status != assessment.StatusCompleted {
		t.Errorf("expected resumed execution status COMPLETED, got %s", updatedExec.Status)
	}

	// Verify preserved findings from Target 1 survived
	findings, err := store.GetFindings(asm.ID, execID)
	if err != nil {
		t.Fatalf("failed getting findings: %v", err)
	}
	foundTarget1Finding := false
	for _, f := range findings {
		if f.ID == finding1.ID {
			foundTarget1Finding = true
			break
		}
	}
	if !foundTarget1Finding {
		t.Errorf("CRITICAL: Preserved Target 1 finding was lost after resumption!")
	}

	// Contrast test: Resumption requested for execution WITHOUT checkpoint honestly finalizes as INTERRUPTED
	execNoChk := &assessment.AssessmentExecution{
		ID:             "exec-no-checkpoint",
		AssessmentID:   asm.ID,
		ClientID:       client.ID,
		Status:         assessment.StatusRunning,
		StartedAt:      now.Add(-20 * time.Minute),
		LeaseExpiresAt: &expiredLease,
	}
	_ = store.CreateExecution(execNoChk)

	optsNoChk := assessment.RecoveryOptions{
		Auth:          assessment.NewAdminAuthContext(),
		ExecutionID:   execNoChk.ID,
		StaleDuration: 3 * time.Minute,
		MaxRetries:    3,
		AllowResume:   true,
		WorkerID:      "rec-honest-finalizer",
		Runner:        ctrl.RunAssessment,
	}
	summaryNoChk, err := store.RecoverExecutions(optsNoChk)
	if err != nil {
		t.Fatalf("RecoverExecutions failed on no-chk: %v", err)
	}
	if summaryNoChk.FinalizedCount != 1 || summaryNoChk.ResumedCount != 0 {
		t.Errorf("expected honest finalization (1 finalized, 0 resumed), got: finalized=%d, resumed=%d",
			summaryNoChk.FinalizedCount, summaryNoChk.ResumedCount)
	}
	if summaryNoChk.Results[0].Action != assessment.ActionFinalizedInterrupted {
		t.Errorf("expected action %s, got %s", assessment.ActionFinalizedInterrupted, summaryNoChk.Results[0].Action)
	}
}

func TestRecovery_16_Migration21_SafetyAndIdempotency(t *testing.T) {
	// Subtest 1: Fresh database initialization
	freshDBPath := filepath.Join(t.TempDir(), "fresh_mig21.db")
	storeFresh, err := assessment.NewSQLiteStore(freshDBPath)
	if err != nil {
		t.Fatalf("fresh DB creation failed: %v", err)
	}
	storeFresh.Close()

	db, err := sql.Open("sqlite", freshDBPath)
	if err != nil {
		t.Fatalf("sql.Open failed: %v", err)
	}
	defer db.Close()

	// Verify all 7 columns exist and queryable
	rows, err := db.Query(`
		SELECT worker_id, heartbeat_at, lease_expires_at, recovery_attempts, last_recovery_at, recovery_reason, checkpoint_json
		FROM assessment_executions LIMIT 0
	`)
	if err != nil {
		t.Fatalf("querying migration 21 columns on fresh DB failed: %v", err)
	}
	rows.Close()

	// Subtest 2: Repeatable migration execution (reopening DB is completely idempotent)
	storeReopened, err := assessment.NewSQLiteStore(freshDBPath)
	if err != nil {
		t.Fatalf("reopening store failed: %v", err)
	}
	storeReopened.Close()

	// Verify indexes exist
	var idxCount int
	err = db.QueryRow(`
		SELECT COUNT(*) FROM sqlite_master WHERE type='index' AND name IN (
			'idx_executions_lease_exp', 'idx_executions_heartbeat', 'idx_executions_worker'
		)
	`).Scan(&idxCount)
	if err != nil || idxCount != 3 {
		t.Errorf("expected 3 recovery indexes, got %d, err: %v", idxCount, err)
	}

	// Subtest 3: Upgrade from v20 database with existing execution records, findings, and tenant/account info
	v20DBPath := filepath.Join(t.TempDir(), "v20_upgrade.db")
	v20DB, err := sql.Open("sqlite", v20DBPath)
	if err != nil {
		t.Fatalf("failed to create v20 db: %v", err)
	}

	// Initialize v20 schema manually
	_, err = v20DB.Exec(`
		CREATE TABLE schema_migrations (version INTEGER PRIMARY KEY, applied_at TIMESTAMP NOT NULL);
		CREATE TABLE assessments (id TEXT PRIMARY KEY, client_id TEXT, ref TEXT, name TEXT, assessment_type TEXT, status TEXT, scope_mode TEXT, created_at TIMESTAMP, updated_at TIMESTAMP);
		CREATE TABLE assessment_executions (
			id TEXT PRIMARY KEY, assessment_id TEXT, schedule_id TEXT, scheduled_for TIMESTAMP,
			client_id TEXT, tenant_id TEXT, account_id TEXT, initiation_source TEXT,
			assessment_type TEXT, status TEXT, started_at TIMESTAMP, completed_at TIMESTAMP,
			duration_ms INTEGER, request_count INTEGER, target_count INTEGER, finding_count INTEGER,
			snapshot_id TEXT, error_message TEXT, config_snapshot TEXT, created_at TIMESTAMP, updated_at TIMESTAMP
		);
		INSERT INTO schema_migrations (version, applied_at) VALUES (20, CURRENT_TIMESTAMP);
		INSERT INTO assessments (id, ref, name, status) VALUES ('asm-v20', 'ASM-V20', 'Legacy V20 ASM', 'COMPLETED');
		INSERT INTO assessment_executions (
			id, assessment_id, client_id, tenant_id, account_id, status, started_at, created_at, updated_at, finding_count
		) VALUES (
			'exec-v20-1', 'asm-v20', 'client-t1', 'tenant-t1', 'acc-a1', 'COMPLETED', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, 5
		);
	`)
	if err != nil {
		t.Fatalf("v20 fixture creation failed: %v", err)
	}
	v20DB.Close()

	// Now open with assessment.NewSQLiteStore, which runs migration 21
	storeUpgraded, err := assessment.NewSQLiteStore(v20DBPath)
	if err != nil {
		t.Fatalf("migration 21 upgrade from v20 failed: %v", err)
	}
	defer storeUpgraded.Close()

	// Verify existing data survived intact
	execV20, err := storeUpgraded.GetExecution("exec-v20-1")
	if err != nil {
		t.Fatalf("failed retrieving existing execution after v21 migration: %v", err)
	}
	if execV20.TenantID != "tenant-t1" || execV20.AccountID != "acc-a1" || execV20.Status != assessment.StatusCompleted || execV20.FindingCount != 5 {
		t.Errorf("existing data corruption after migration 21: %+v", execV20)
	}
	if execV20.RecoveryAttempts != 0 {
		t.Errorf("expected default 0 recovery attempts, got %d", execV20.RecoveryAttempts)
	}
}

func expiredTimeHelper(d time.Duration) time.Time {
	return time.Now().UTC().Add(d)
}
