package assessment

import (
	"context"
	"testing"
	"time"
)

func TestJobManager_LifecycleAndConcurrency(t *testing.T) {
	store, cleanup := newTestOperatorStore(t)
	defer cleanup()

	client := &Client{ID: "cli-jm-1", Name: "Job Test Client"}
	_ = store.CreateClient(client)
	asm := &Assessment{
		ID:             "asm-jm-1",
		Ref:            "ASM-2026-JOB1",
		ClientID:       client.ID,
		Name:           "Job Manager Test",
		AssessmentType: "BLACK_BOX",
		Status:         StatusReady,
		ScopeMode:      "same-origin",
	}
	_ = store.CreateAssessment(asm)

	// Authorization
	authRec := &AuthorizationRecord{
		ID:                  "auth-jm-1",
		AssessmentID:        asm.ID,
		AuthorizingParty:    "Alice CISO",
		AuthorizationMethod: "WRITTEN_CONTRACT",
		DateReceived:        time.Now().UTC().Add(-time.Hour),
		Status:              AuthApproved,
	}
	_ = store.SetAuthorization(authRec)

	// Target
	target := &AssessmentTarget{
		ID:           "tgt-jm-1",
		AssessmentID: asm.ID,
		TargetURL:    "https://example.com",
		ScopeStatus:  "APPROVED",
	}
	_ = store.AddTarget(target)

	controller := NewController(store)
	jm := NewJobManager(store, controller)

	// 1. Get status before any run
	st, err := jm.GetJobStatus(asm.ID)
	if err != nil {
		t.Fatalf("GetJobStatus failed: %v", err)
	}
	if st != nil {
		t.Errorf("expected nil status before any scan, got %+v", st)
	}

	// 2. Cancellation of non-running scan returns clean error
	err = jm.CancelAssessmentScan(asm.ID, "alice")
	if err == nil {
		t.Errorf("expected error when cancelling non-running scan")
	}

	// 3. Test active lease concurrency rejection
	// Manually acquire a lease to simulate another running worker/process
	lease := &ScanJobLease{
		ID:          asm.ID,
		ExecutionID: "exec-external-1",
		OperatorID:  "other-process",
		Status:      "RUNNING",
	}
	if err := store.AcquireScanJobLease(lease); err != nil {
		t.Fatalf("AcquireScanJobLease failed: %v", err)
	}

	// Attempting StartAssessmentScan while lease active MUST FAIL
	_, err = jm.StartAssessmentScan(context.Background(), asm.ID, "alice", ExecutionOptions{})
	if err == nil {
		t.Fatalf("expected StartAssessmentScan to fail when active lease exists, got nil")
	}

	// Release lease and test recovery
	_ = store.ReleaseScanJobLease(asm.ID, "COMPLETED", "")
	stRecovered, err := jm.GetJobStatus(asm.ID)
	if err != nil {
		t.Fatalf("GetJobStatus after release failed: %v", err)
	}
	if stRecovered.State != JobStateCompleted {
		t.Errorf("expected state COMPLETED, got %s", stRecovered.State)
	}
}
