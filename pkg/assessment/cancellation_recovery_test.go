package assessment

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
)

// Helper to create an assessment with authorized client and target
func setupCancellationTestAssessment(t *testing.T, store *SQLiteStore, targetURL string) (string, string, string) {
	t.Helper()

	clientID := uuid.New().String()
	_ = store.CreateClient(&Client{ID: clientID, Name: "Cancellation & Recovery Client"})

	asmID := uuid.New().String()
	asmRef := GenerateAssessmentRef()
	_ = store.CreateAssessment(&Assessment{
		ID:        asmID,
		Ref:       asmRef,
		ClientID:  clientID,
		Name:      "Cancellation & Recovery Target Assessment",
		Status:    StatusDraft,
		ScopeMode: "same-origin",
	})

	validFrom := time.Now().Add(-1 * time.Hour)
	validUntil := time.Now().Add(24 * time.Hour)
	_ = store.SetAuthorization(&AuthorizationRecord{
		ID:                  uuid.New().String(),
		AssessmentID:        asmID,
		AuthorizingParty:    "Security Team Lead",
		AuthorizationMethod: "TICKET",
		DateReceived:        time.Now().Add(-2 * time.Hour),
		ValidFrom:           &validFrom,
		ValidUntil:          &validUntil,
		Status:              AuthApproved,
	})

	targetID := uuid.New().String()
	_ = store.AddTarget(&AssessmentTarget{
		ID:           targetID,
		AssessmentID: asmID,
		TargetURL:    targetURL,
		TargetType:   "web",
		ScopeStatus:  "APPROVED",
	})

	return clientID, asmID, targetID
}

// =========================================================================
// Group 1: Cancellation Lifecycle & Boundary Propagation
// =========================================================================

// TestCancellation_ImmediatelyAfterStart verifies that cancelling context immediately
// halts execution, marks execution as CANCELLED, and produces an inconclusive snapshot.
func TestCancellation_ImmediatelyAfterStart(t *testing.T) {
	store, cleanup := newTestStore(t)
	defer cleanup()

	ctrl := NewController(store)

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(200 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	clientID, asmID, _ := setupCancellationTestAssessment(t, store, ts.URL)

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel before execution begins

	res, err := ctrl.RunAssessment(ctx, asmID, ExecutionOptions{
		AllowLoopback: true,
	})

	if err == nil {
		t.Fatal("expected non-nil error on pre-cancelled execution, got nil")
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled error, got: %v", err)
	}

	if res == nil || res.Execution == nil {
		t.Fatal("expected non-nil execution result")
	}
	if res.Execution.Status != StatusCancelled {
		t.Fatalf("expected status StatusCancelled, got %q", res.Execution.Status)
	}

	// Verify authoritative snapshot reflects cancellation
	authCtx := TenantAuthContext{ClientID: clientID, isAdmin: true}
	snap, snapErr := LoadAuthoritativeSnapshot(store, asmID, res.Execution.ID, authCtx)
	if snapErr != nil {
		t.Fatalf("LoadAuthoritativeSnapshot failed: %v", snapErr)
	}
	if snap.IsComplete {
		t.Fatal("expected snapshot.IsComplete to be false for cancelled execution")
	}
	if snap.Status != StatusCancelled {
		t.Fatalf("expected snapshot.Status to be StatusCancelled, got %q", snap.Status)
	}

	canonicalRep, repErr := BuildAuthoritativeReport(snap, false, true)
	if repErr != nil {
		t.Fatalf("BuildAuthoritativeReport failed: %v", repErr)
	}
	if canonicalRep.RiskLevel != "UNAVAILABLE" || canonicalRep.RiskScoreAvailable {
		t.Fatalf("expected RiskLevel UNAVAILABLE for cancelled assessment, got %q", canonicalRep.RiskLevel)
	}
	if canonicalRep.CompletionStatus != string(StatusCancelled) {
		t.Fatalf("expected CompletionStatus %q, got %q", StatusCancelled, canonicalRep.CompletionStatus)
	}
}

// TestCancellation_DuringCrawlAndInFlightRequests verifies that in-flight network requests
// and crawler goroutines are interrupted promptly upon cancellation.
func TestCancellation_DuringCrawlAndInFlightRequests(t *testing.T) {
	store, cleanup := newTestStore(t)
	defer cleanup()

	ctrl := NewController(store)

	requestReceived := make(chan struct{})
	serverHold := make(chan struct{})

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case requestReceived <- struct{}{}:
		default:
		}
		select {
		case <-serverHold:
			w.WriteHeader(http.StatusOK)
		case <-r.Context().Done():
		}
	}))
	defer func() {
		close(serverHold)
		ts.Close()
	}()

	clientID, asmID, _ := setupCancellationTestAssessment(t, store, ts.URL)

	ctx, cancel := context.WithCancel(context.Background())
	doneCh := make(chan *ExecutionResult, 1)

	go func() {
		res, _ := ctrl.RunAssessment(ctx, asmID, ExecutionOptions{
			AllowLoopback: true,
			Concurrency:   2,
		})
		doneCh <- res
	}()

	// Wait until server sees the request, then cancel
	select {
	case <-requestReceived:
		cancel()
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for server request")
	}

	select {
	case res := <-doneCh:
		if res == nil || res.Execution == nil {
			t.Fatal("expected non-nil execution result")
		}
		if res.Execution.Status != StatusCancelled {
			t.Fatalf("expected status StatusCancelled, got %q", res.Execution.Status)
		}
		if res.Execution.ErrorMessage != "Execution was cancelled by operator" {
			t.Fatalf("expected operator cancellation message, got: %q", res.Execution.ErrorMessage)
		}

		// Ensure store record matches
		execInStore, err := store.GetExecution(res.Execution.ID)
		if err != nil {
			t.Fatalf("failed to fetch execution from store: %v", err)
		}
		if execInStore.Status != StatusCancelled {
			t.Fatalf("expected store status StatusCancelled, got %q", execInStore.Status)
		}
		_ = clientID
	case <-time.After(4 * time.Second):
		t.Fatal("cancellation did not complete within timeout")
	}
}

// TestCancellation_AfterFindingsGenerated verifies that partial findings generated
// before cancellation are preserved in the store and referenced by the partial snapshot.
func TestCancellation_AfterFindingsGenerated(t *testing.T) {
	store, cleanup := newTestStore(t)
	defer cleanup()

	ctrl := NewController(store)

	// Custom engine runner that produces findings then blocks until cancellation
	customRunner := &mockEngineRunner{
		capabilities: EngineCapabilities{
			AssessmentType:     "MOCK_CANCELLATION",
			CoverageCategories: []string{"sqli", "xss"},
		},
		executeFunc: func(ctx context.Context, execCtx *EngineExecutionContext) (*EngineExecutionOutput, error) {
			targetID := ""
			if tRec, ok := execCtx.TargetMap["https://example.com/target"]; ok {
				targetID = tRec.ID
			}
			output := &EngineExecutionOutput{
				AssessmentFindings: []AssessmentFinding{
					{
						ID:                uuid.New().String(),
						AssessmentID:      execCtx.Assessment.ID,
						ExecutionID:       execCtx.Execution.ID,
						TargetID:          targetID,
						OriginalFindingID: "part-1",
						Title:             "Partial Finding 1",
						Severity:          "HIGH",
						Endpoint:          "/api/partial-1",
						Fingerprint:       "fp-part-1",
					},
					{
						ID:                uuid.New().String(),
						AssessmentID:      execCtx.Assessment.ID,
						ExecutionID:       execCtx.Execution.ID,
						TargetID:          targetID,
						OriginalFindingID: "part-2",
						Title:             "Partial Finding 2",
						Severity:          "MEDIUM",
						Endpoint:          "/api/partial-2",
						Fingerprint:       "fp-part-2",
					},
				},
				AssessedTargets: []string{"https://example.com/target"},
			}
			// Wait on context cancellation
			<-ctx.Done()
			return output, ctx.Err()
		},
	}
	_ = ctrl.RegisterEngine(customRunner)

	clientID := uuid.New().String()
	_ = store.CreateClient(&Client{ID: clientID, Name: "Custom Runner Client"})

	asmID := uuid.New().String()
	_ = store.CreateAssessment(&Assessment{
		ID:             asmID,
		Ref:            GenerateAssessmentRef(),
		ClientID:       clientID,
		Name:           "Partial Findings Test",
		AssessmentType: "MOCK_CANCELLATION",
		Status:         StatusDraft,
	})

	validFrom := time.Now().Add(-1 * time.Hour)
	validUntil := time.Now().Add(24 * time.Hour)
	_ = store.SetAuthorization(&AuthorizationRecord{
		ID:                  uuid.New().String(),
		AssessmentID:        asmID,
		AuthorizingParty:    "Lead Auditor",
		AuthorizationMethod: "STATEMENT_OF_WORK",
		DateReceived:        time.Now().Add(-1 * time.Hour),
		ValidFrom:           &validFrom,
		ValidUntil:          &validUntil,
		Status:              AuthApproved,
	})

	_ = store.AddTarget(&AssessmentTarget{
		ID:           uuid.New().String(),
		AssessmentID: asmID,
		TargetURL:    "https://example.com/target",
		TargetType:   "web",
		ScopeStatus:  "APPROVED",
	})

	ctx, cancel := context.WithCancel(context.Background())
	doneCh := make(chan *ExecutionResult, 1)

	go func() {
		res, _ := ctrl.RunAssessment(ctx, asmID, ExecutionOptions{
			AllowLoopback: true,
		})
		doneCh <- res
	}()

	time.Sleep(100 * time.Millisecond)
	cancel()

	select {
	case res := <-doneCh:
		if res == nil || res.Execution == nil {
			t.Fatal("expected non-nil execution result")
		}
		if res.Execution.Status != StatusCancelled {
			t.Fatalf("expected status StatusCancelled, got %q", res.Execution.Status)
		}
		if res.Execution.FindingCount != 2 {
			t.Fatalf("expected 2 partial findings preserved, got %d", res.Execution.FindingCount)
		}

		// Verify partial findings are in the store
		persisted, err := store.GetFindings(asmID, res.Execution.ID)
		if err != nil {
			t.Fatalf("failed fetching persisted findings: %v", err)
		}
		if len(persisted) != 2 {
			t.Fatalf("expected 2 persisted partial findings in store, got %d", len(persisted))
		}

		// Verify snapshot metadata marks is_partial and inconclusive
		if res.Snapshot == nil {
			t.Fatal("expected partial snapshot to be created, got nil")
		}
		if res.Snapshot.Metadata["is_partial"] != "true" {
			t.Fatalf("expected is_partial=true, got %q", res.Snapshot.Metadata["is_partial"])
		}
		if res.Snapshot.Metadata["inconclusive"] != "true" {
			t.Fatalf("expected inconclusive=true, got %q", res.Snapshot.Metadata["inconclusive"])
		}
	case <-time.After(3 * time.Second):
		t.Fatal("cancellation did not complete within timeout")
	}
}

// mockEngineRunner allows deterministic mocking of engine execution stages
type mockEngineRunner struct {
	capabilities EngineCapabilities
	executeFunc  func(ctx context.Context, execCtx *EngineExecutionContext) (*EngineExecutionOutput, error)
}

func (m *mockEngineRunner) Capabilities() EngineCapabilities {
	return m.capabilities
}

func (m *mockEngineRunner) Execute(ctx context.Context, execCtx *EngineExecutionContext) (*EngineExecutionOutput, error) {
	if m.executeFunc != nil {
		return m.executeFunc(ctx, execCtx)
	}
	return &EngineExecutionOutput{}, nil
}

// =========================================================================
// Group 2: Failure Injection & State Invariants
// =========================================================================

// TestFailureInjection_InvalidStateTransitions verifies that terminal states
// (COMPLETED, CANCELLED, INTERRUPTED, FAILED) cannot be overwritten or transitioned
// to any other state.
func TestFailureInjection_InvalidStateTransitions(t *testing.T) {
	store, cleanup := newTestStore(t)
	defer cleanup()

	terminalStatuses := []AssessmentStatus{
		StatusCompleted,
		StatusCompletedWithErrors,
		StatusCancelled,
		StatusInterrupted,
		StatusFailed,
	}

	for _, fromStatus := range terminalStatuses {
		for _, toStatus := range []AssessmentStatus{StatusRunning, StatusQueued, StatusCompleted, StatusCancelled} {
			if fromStatus == toStatus {
				continue // Idempotent same-state is permitted
			}
			valid := IsValidExecutionTransition(fromStatus, toStatus)
			if valid {
				t.Errorf("transition from %s to %s should be rejected by state machine", fromStatus, toStatus)
			}
		}
	}

	// Verify store enforcement
	clientID := uuid.New().String()
	_ = store.CreateClient(&Client{ID: clientID, Name: "State Machine Client"})
	asmID := uuid.New().String()
	_ = store.CreateAssessment(&Assessment{
		ID:        asmID,
		Ref:       GenerateAssessmentRef(),
		ClientID:  clientID,
		Name:      "State Machine Test",
		Status:    StatusDraft,
	})

	execID := uuid.New().String()
	_ = store.CreateExecution(&AssessmentExecution{
		ID:           execID,
		AssessmentID: asmID,
		ClientID:     clientID,
		Status:       StatusCancelled,
	})

	// Attempting to reopen as RUNNING or COMPLETED must fail
	err := store.UpdateExecution(&AssessmentExecution{
		ID:           execID,
		AssessmentID: asmID,
		ClientID:     clientID,
		Status:       StatusCompleted,
	})
	if err == nil {
		t.Fatal("expected UpdateExecution to reject transition from CANCELLED to COMPLETED, got nil")
	}
	if !errors.Is(err, ErrInvalidStateTransition) {
		t.Fatalf("expected ErrInvalidStateTransition, got: %v", err)
	}
}

// TestFailureInjection_TerminalExecutionFindingProtection verifies that calling SaveFindings
// against an execution that has already entered a terminal status (INTERRUPTED or CANCELLED)
// is rejected with ErrExecutionTerminal.
func TestFailureInjection_TerminalExecutionFindingProtection(t *testing.T) {
	store, cleanup := newTestStore(t)
	defer cleanup()

	clientID := uuid.New().String()
	_ = store.CreateClient(&Client{ID: clientID, Name: "Terminal Finding Protection Client"})
	asmID := uuid.New().String()
	_ = store.CreateAssessment(&Assessment{
		ID:       asmID,
		Ref:      GenerateAssessmentRef(),
		ClientID: clientID,
		Name:     "Terminal Finding Protection Test",
		Status:   StatusDraft,
	})

	// 1. Test against CANCELLED execution
	execCancelledID := uuid.New().String()
	_ = store.CreateExecution(&AssessmentExecution{
		ID:           execCancelledID,
		AssessmentID: asmID,
		ClientID:     clientID,
		Status:       StatusCancelled,
	})

	f1 := AssessmentFinding{
		ID:           uuid.New().String(),
		AssessmentID: asmID,
		ExecutionID:  execCancelledID,
		Title:        "Late Finding Into Cancelled",
		Severity:     "HIGH",
	}
	err := store.SaveFindings([]AssessmentFinding{f1})
	if err == nil {
		t.Fatal("expected SaveFindings to reject findings into CANCELLED execution, got nil")
	}
	if !errors.Is(err, ErrExecutionTerminal) {
		t.Fatalf("expected ErrExecutionTerminal, got: %v", err)
	}

	// 2. Test against INTERRUPTED execution
	execInterruptedID := uuid.New().String()
	_ = store.CreateExecution(&AssessmentExecution{
		ID:           execInterruptedID,
		AssessmentID: asmID,
		ClientID:     clientID,
		Status:       StatusInterrupted,
	})

	f2 := AssessmentFinding{
		ID:           uuid.New().String(),
		AssessmentID: asmID,
		ExecutionID:  execInterruptedID,
		Title:        "Late Finding Into Interrupted",
		Severity:     "HIGH",
	}
	err = store.SaveFindings([]AssessmentFinding{f2})
	if err == nil {
		t.Fatal("expected SaveFindings to reject findings into INTERRUPTED execution, got nil")
	}
	if !errors.Is(err, ErrExecutionTerminal) {
		t.Fatalf("expected ErrExecutionTerminal, got: %v", err)
	}
}

// TestFailureInjection_ContradictorySnapshotRejection verifies that attempting to create
// a COMPLETED snapshot for an execution finalized as CANCELLED or INTERRUPTED is rejected
// with ErrSnapshotImmutable.
func TestFailureInjection_ContradictorySnapshotRejection(t *testing.T) {
	store, cleanup := newTestStore(t)
	defer cleanup()

	clientID := uuid.New().String()
	_ = store.CreateClient(&Client{ID: clientID, Name: "Contradictory Snapshot Client"})
	asmID := uuid.New().String()
	_ = store.CreateAssessment(&Assessment{
		ID:       asmID,
		Ref:      GenerateAssessmentRef(),
		ClientID: clientID,
		Name:     "Contradictory Snapshot Test",
		Status:   StatusDraft,
	})

	execID := uuid.New().String()
	_ = store.CreateExecution(&AssessmentExecution{
		ID:           execID,
		AssessmentID: asmID,
		ClientID:     clientID,
		Status:       StatusCancelled,
	})

	// Attempt to create a COMPLETED snapshot for the CANCELLED execution
	snap := &AssessmentSnapshot{
		ID:             uuid.New().String(),
		SnapshotRef:    "SNP-CONTRADICTORY",
		AssessmentID:   asmID,
		ExecutionID:    execID,
		ClientID:       clientID,
		Status:         StatusCompleted,
		IsComplete:     true,
		ScopedTargets:  []string{"https://example.com"},
		Metadata:       make(map[string]string),
	}

	err := store.CreateSnapshot(snap, nil, nil)
	if err == nil {
		t.Fatal("expected CreateSnapshot to reject COMPLETED snapshot for CANCELLED execution, got nil")
	}
	if !errors.Is(err, ErrSnapshotImmutable) {
		t.Fatalf("expected ErrSnapshotImmutable, got: %v", err)
	}
}

// =========================================================================
// Group 3: Recovery After Interruption
// =========================================================================

// TestRecovery_FinalizeAbandonedExecution verifies that an execution abandoned
// during execution is safely identified and finalized as INTERRUPTED.
func TestRecovery_FinalizeAbandonedExecution(t *testing.T) {
	store, cleanup := newTestStore(t)
	defer cleanup()

	clientID := uuid.New().String()
	_ = store.CreateClient(&Client{ID: clientID, Name: "Recovery Client"})
	asmID := uuid.New().String()
	asmRef := GenerateAssessmentRef()
	_ = store.CreateAssessment(&Assessment{
		ID:       asmID,
		Ref:      asmRef,
		ClientID: clientID,
		Name:     "Recovery Test",
		Status:   StatusRunning,
	})

	// Create an abandoned execution whose lease expired 10 minutes ago
	staleHeartbeat := time.Now().UTC().Add(-15 * time.Minute)
	staleLease := time.Now().UTC().Add(-10 * time.Minute)
	execID := uuid.New().String()
	_ = store.CreateExecution(&AssessmentExecution{
		ID:              execID,
		AssessmentID:    asmID,
		ClientID:        clientID,
		Status:          StatusRunning,
		StartedAt:       staleHeartbeat,
		HeartbeatAt:     &staleHeartbeat,
		LeaseExpiresAt:  &staleLease,
		WorkerID:        "lost-worker-1",
		FindingCount:    1,
	})

	targetID := uuid.New().String()
	_ = store.AddTarget(&AssessmentTarget{
		ID:           targetID,
		AssessmentID: asmID,
		TargetURL:    "https://example.com",
		TargetType:   "web",
		ScopeStatus:  "APPROVED",
	})

	f := AssessmentFinding{
		ID:                uuid.New().String(),
		AssessmentID:      asmID,
		ExecutionID:       execID,
		TargetID:          targetID,
		OriginalFindingID: "orphaned-1",
		Title:             "Orphaned Finding",
		Severity:          "HIGH",
		Endpoint:          "/orphaned",
		Fingerprint:       "fp-orphaned",
	}
	if err := store.SaveFindings([]AssessmentFinding{f}); err != nil {
		t.Fatalf("failed to save orphaned finding: %v", err)
	}

	// Run recovery sweep
	authCtx := TenantAuthContext{ClientID: clientID, isAdmin: true}
	recoverySummary, err := store.RecoverExecutions(RecoveryOptions{
		Auth:          authCtx,
		StaleDuration: 3 * time.Minute,
		WorkerID:      "recovery-sweeper",
	})
	if err != nil {
		t.Fatalf("RecoverExecutions failed: %v", err)
	}

	if recoverySummary.RecoveredCount != 1 {
		t.Fatalf("expected 1 recovered execution, got %d", recoverySummary.RecoveredCount)
	}
	if recoverySummary.FinalizedCount != 1 {
		t.Fatalf("expected 1 finalized execution, got %d", recoverySummary.FinalizedCount)
	}

	res := recoverySummary.Results[0]
	if res.Action != ActionFinalizedInterrupted {
		t.Fatalf("expected ActionFinalizedInterrupted, got %q", res.Action)
	}
	if res.NewStatus != StatusInterrupted {
		t.Fatalf("expected NewStatus StatusInterrupted, got %q", res.NewStatus)
	}
	if res.PreservedFindings != 1 {
		t.Fatalf("expected 1 preserved finding, got %d", res.PreservedFindings)
	}

	// Verify store records reflect INTERRUPTED status and inconclusive snapshot
	updatedExec, _ := store.GetExecution(execID)
	if updatedExec.Status != StatusInterrupted {
		t.Fatalf("expected execution status StatusInterrupted, got %q", updatedExec.Status)
	}

	updatedAsm, _ := store.GetAssessment(asmID)
	if updatedAsm.Status != StatusInterrupted {
		t.Fatalf("expected assessment status StatusInterrupted, got %q", updatedAsm.Status)
	}

	snap, err := LoadAuthoritativeSnapshot(store, asmID, execID, authCtx)
	if err != nil {
		t.Fatalf("LoadAuthoritativeSnapshot failed: %v", err)
	}
	if snap.IsComplete {
		t.Fatal("expected recovered snapshot to be incomplete")
	}
	if snap.Status != StatusInterrupted {
		t.Fatalf("expected snapshot status StatusInterrupted, got %q", snap.Status)
	}
}

// TestRecovery_Idempotency verifies that repeating recovery sweeps on already-recovered
// executions is safely idempotent and does not modify persistent data.
func TestRecovery_Idempotency(t *testing.T) {
	store, cleanup := newTestStore(t)
	defer cleanup()

	clientID := uuid.New().String()
	_ = store.CreateClient(&Client{ID: clientID, Name: "Idempotency Client"})
	asmID := uuid.New().String()
	_ = store.CreateAssessment(&Assessment{
		ID:       asmID,
		Ref:      GenerateAssessmentRef(),
		ClientID: clientID,
		Name:     "Idempotency Test",
		Status:   StatusRunning,
	})

	staleLease := time.Now().UTC().Add(-10 * time.Minute)
	execID := uuid.New().String()
	_ = store.CreateExecution(&AssessmentExecution{
		ID:             execID,
		AssessmentID:   asmID,
		ClientID:       clientID,
		Status:         StatusRunning,
		StartedAt:      staleLease,
		LeaseExpiresAt: &staleLease,
		WorkerID:       "dead-worker",
	})

	authCtx := TenantAuthContext{ClientID: clientID, isAdmin: true}
	opts := RecoveryOptions{
		Auth:          authCtx,
		StaleDuration: 3 * time.Minute,
		WorkerID:      "idempotent-sweeper",
	}

	// First pass recovers
	s1, err := store.RecoverExecutions(opts)
	if err != nil || s1.RecoveredCount != 1 {
		t.Fatalf("first recovery pass failed: count=%d, err=%v", s1.RecoveredCount, err)
	}

	// Second pass should find 0 abandoned executions and perform 0 mutations
	s2, err := store.RecoverExecutions(opts)
	if err != nil {
		t.Fatalf("second recovery pass failed: %v", err)
	}
	if s2.RecoveredCount != 0 || s2.ExaminedCount != 0 {
		t.Fatalf("second recovery pass should be idempotent: examined=%d, recovered=%d", s2.ExaminedCount, s2.RecoveredCount)
	}

	// Direct call to FinalizeAbandonedExecution on terminal execution returns ActionSkippedTerminal
	res, err := store.FinalizeAbandonedExecution(execID, "late-worker", StatusInterrupted, "reason", authCtx)
	if err != nil {
		t.Fatalf("FinalizeAbandonedExecution failed: %v", err)
	}
	if res.Action != ActionSkippedTerminal {
		t.Fatalf("expected ActionSkippedTerminal on already finalized execution, got %q", res.Action)
	}
}

// TestRecovery_DryRun_DoesNotMutateState verifies that dry-run recovery evaluates
// abandoned executions without modifying database state.
func TestRecovery_DryRun_DoesNotMutateState(t *testing.T) {
	store, cleanup := newTestStore(t)
	defer cleanup()

	clientID := uuid.New().String()
	_ = store.CreateClient(&Client{ID: clientID, Name: "DryRun Client"})
	asmID := uuid.New().String()
	_ = store.CreateAssessment(&Assessment{
		ID:       asmID,
		Ref:      GenerateAssessmentRef(),
		ClientID: clientID,
		Name:     "DryRun Test",
		Status:   StatusRunning,
	})

	staleLease := time.Now().UTC().Add(-10 * time.Minute)
	execID := uuid.New().String()
	_ = store.CreateExecution(&AssessmentExecution{
		ID:             execID,
		AssessmentID:   asmID,
		ClientID:       clientID,
		Status:         StatusRunning,
		StartedAt:      staleLease,
		LeaseExpiresAt: &staleLease,
		WorkerID:       "dead-worker",
	})

	authCtx := TenantAuthContext{ClientID: clientID, isAdmin: true}
	opts := RecoveryOptions{
		Auth:          authCtx,
		StaleDuration: 3 * time.Minute,
		DryRun:        true,
	}

	s, err := store.RecoverExecutions(opts)
	if err != nil {
		t.Fatalf("dry-run recovery failed: %v", err)
	}
	if s.RecoveredCount != 1 || !s.Results[0].WasDryRun {
		t.Fatalf("expected dry-run evaluation of 1 execution, got count=%d, dryRun=%v", s.RecoveredCount, s.Results[0].WasDryRun)
	}

	// Verify database record remains in RUNNING
	exec, _ := store.GetExecution(execID)
	if exec.Status != StatusRunning {
		t.Fatalf("expected database status to remain StatusRunning during dry-run, got %q", exec.Status)
	}
}

// =========================================================================
// Group 4: Concurrency, Lease Ownership & Fencing
// =========================================================================

// TestConcurrency_LeaseLostPreventsOverwritingRecovery verifies that if a worker's
// lease expires and is claimed by another worker, the original worker detects ErrLeaseLost
// and is fenced from updating the execution record.
func TestConcurrency_LeaseLostPreventsOverwritingRecovery(t *testing.T) {
	store, cleanup := newTestStore(t)
	defer cleanup()

	clientID := uuid.New().String()
	_ = store.CreateClient(&Client{ID: clientID, Name: "Lease Fencing Client"})
	asmID := uuid.New().String()
	_ = store.CreateAssessment(&Assessment{
		ID:       asmID,
		Ref:      GenerateAssessmentRef(),
		ClientID: clientID,
		Name:     "Lease Fencing Test",
		Status:   StatusRunning,
	})

	originalWorker := "worker-alpha"
	recoveryWorker := "worker-bravo"

	execID := uuid.New().String()
	now := time.Now().UTC()
	leaseExp := now.Add(5 * time.Minute)
	_ = store.CreateExecution(&AssessmentExecution{
		ID:             execID,
		AssessmentID:   asmID,
		ClientID:       clientID,
		Status:         StatusRunning,
		WorkerID:       originalWorker,
		StartedAt:      now,
		HeartbeatAt:    &now,
		LeaseExpiresAt: &leaseExp,
	})

	// Recovery worker claims ownership by updating worker_id
	_, _ = store.db.Exec(`UPDATE assessment_executions SET worker_id = ?, heartbeat_at = ? WHERE id = ?`,
		recoveryWorker, now, execID)

	// Original worker attempts heartbeat
	hbErr := store.HeartbeatExecution(execID, originalWorker, nil, 5*time.Minute)
	if hbErr == nil {
		t.Fatal("expected original worker heartbeat to fail with ErrLeaseLost, got nil")
	}
	if !errors.Is(hbErr, ErrLeaseLost) {
		t.Fatalf("expected ErrLeaseLost, got: %v", hbErr)
	}

	// Original worker attempts UpdateExecution
	updateErr := store.UpdateExecution(&AssessmentExecution{
		ID:           execID,
		AssessmentID: asmID,
		ClientID:     clientID,
		WorkerID:     originalWorker,
		Status:       StatusCompleted,
	})
	if updateErr == nil {
		t.Fatal("expected original worker UpdateExecution to fail with ErrLeaseLost, got nil")
	}
	if !errors.Is(updateErr, ErrLeaseLost) {
		t.Fatalf("expected ErrLeaseLost on update, got: %v", updateErr)
	}
}

// TestConcurrency_DualRecoveryWorkersRace verifies that when two workers attempt
// to claim the same abandoned execution simultaneously, exactly one wins ownership.
func TestConcurrency_DualRecoveryWorkersRace(t *testing.T) {
	store, cleanup := newTestStore(t)
	defer cleanup()

	clientID := uuid.New().String()
	_ = store.CreateClient(&Client{ID: clientID, Name: "Race Client"})
	asmID := uuid.New().String()
	_ = store.CreateAssessment(&Assessment{
		ID:       asmID,
		Ref:      GenerateAssessmentRef(),
		ClientID: clientID,
		Name:     "Race Test",
		Status:   StatusRunning,
	})

	staleLease := time.Now().UTC().Add(-10 * time.Minute)
	execID := uuid.New().String()
	_ = store.CreateExecution(&AssessmentExecution{
		ID:             execID,
		AssessmentID:   asmID,
		ClientID:       clientID,
		Status:         StatusRunning,
		StartedAt:      staleLease,
		LeaseExpiresAt: &staleLease,
		WorkerID:       "dead-worker",
	})

	var wg sync.WaitGroup
	winners := 0
	var mu sync.Mutex

	now := time.Now().UTC()
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func(workerNum int) {
			defer wg.Done()
			wID := fmt.Sprintf("competitor-worker-%d", workerNum)
			won, err := store.ClaimAbandonedExecutionForRecovery(execID, wID, now, 5*time.Minute)
			if err == nil && won {
				mu.Lock()
				winners++
				mu.Unlock()
			}
		}(i)
	}
	wg.Wait()

	if winners != 1 {
		t.Fatalf("expected exactly 1 worker to win claim, got %d winners", winners)
	}
}

// TestConcurrency_ReopenStoreAfterInterruption verifies that after a forced process
// termination (reopening the database file with a new connection), unfinalized records
// are recovered cleanly without locked database errors.
func TestConcurrency_ReopenStoreAfterInterruption(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "interrupted_process.db")

	clientID := uuid.New().String()
	asmID := uuid.New().String()
	execID := uuid.New().String()

	// Session 1: Start assessment and exit uncleanly
	{
		s1, err := NewSQLiteStore(dbPath)
		if err != nil {
			t.Fatalf("failed to open session 1 store: %v", err)
		}
		_ = s1.CreateClient(&Client{ID: clientID, Name: "Crash Recovery Client"})
		_ = s1.CreateAssessment(&Assessment{
			ID:       asmID,
			Ref:      GenerateAssessmentRef(),
			ClientID: clientID,
			Name:     "Crash Recovery Assessment",
			Status:   StatusRunning,
		})
		_ = s1.CreateExecution(&AssessmentExecution{
			ID:           execID,
			AssessmentID: asmID,
			ClientID:     clientID,
			Status:       StatusRunning,
			StartedAt:    time.Now().UTC(),
		})
		_ = s1.Close()
	}

	// Session 2: Startup recovery sweep
	{
		s2, err := NewSQLiteStore(dbPath)
		if err != nil {
			t.Fatalf("failed to open session 2 store: %v", err)
		}
		defer s2.Close()

		recovered, err := s2.DetectAndRecoverInterruptedRuns()
		if err != nil {
			t.Fatalf("DetectAndRecoverInterruptedRuns failed: %v", err)
		}
		if recovered != 1 {
			t.Fatalf("expected 1 recovered execution on startup, got %d", recovered)
		}

		exec, err := s2.GetExecution(execID)
		if err != nil {
			t.Fatalf("failed fetching recovered execution: %v", err)
		}
		if exec.Status != StatusFailed {
			t.Fatalf("expected recovered execution to be FAILED, got %q", exec.Status)
		}

		asm, err := s2.GetAssessment(asmID)
		if err != nil {
			t.Fatalf("failed fetching recovered assessment: %v", err)
		}
		if asm.Status != StatusFailed {
			t.Fatalf("expected recovered assessment to be FAILED, got %q", asm.Status)
		}
	}
}
