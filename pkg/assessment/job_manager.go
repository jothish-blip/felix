package assessment

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"
)

// JobState represents the operational execution state of an assessment scan job.
type JobState string

const (
	JobStateQueued    JobState = "QUEUED"
	JobStateRunning   JobState = "RUNNING"
	JobStateCompleted JobState = "COMPLETED"
	JobStateFailed    JobState = "FAILED"
	JobStateCancelled JobState = "CANCELLED"
)

// JobStatus contains real-time status and telemetry for an assessment scan job.
type JobStatus struct {
	AssessmentID    string           `json:"assessment_id"`
	ExecutionID     string           `json:"execution_id"`
	OperatorID      string           `json:"operator_id"`
	State           JobState         `json:"state"`
	StartedAt       time.Time        `json:"started_at"`
	CompletedAt     *time.Time       `json:"completed_at,omitempty"`
	DurationMs      int64            `json:"duration_ms,omitempty"`
	ProgressMessage string           `json:"progress_message,omitempty"`
	ErrorMessage    string           `json:"error_message,omitempty"`
	Result          *ExecutionResult `json:"result,omitempty"`
}

// JobManager coordinates background assessment scan executions, enforcing
// SQLite-backed single-instance leases, progress heartbeats, and graceful cancellation.
type JobManager struct {
	store      Store
	controller *Controller
	mu         sync.Mutex
	activeJobs map[string]*activeJobEntry
}

type activeJobEntry struct {
	cancel context.CancelFunc
	status JobStatus
}

// NewJobManager initializes a scan job manager.
func NewJobManager(store Store, controller *Controller) *JobManager {
	if controller == nil {
		controller = NewController(store)
	}
	jm := &JobManager{
		store:      store,
		controller: controller,
		activeJobs: make(map[string]*activeJobEntry),
	}
	// On startup, recover any stale leases
	_, _ = store.RecoverStaleScanJobLeases(3 * time.Minute)
	return jm
}

// StartAssessmentScan launches an asynchronous authorized assessment run.
func (jm *JobManager) StartAssessmentScan(
	ctx context.Context,
	assessmentID string,
	operatorID string,
	opts ExecutionOptions,
) (*JobStatus, error) {
	jm.mu.Lock()
	defer jm.mu.Unlock()

	if operatorID == "" {
		operatorID = "local-operator"
	}

	// 1. Check in-memory active jobs
	if existing, ok := jm.activeJobs[assessmentID]; ok {
		if existing.status.State == JobStateRunning || existing.status.State == JobStateQueued {
			return nil, fmt.Errorf("scan execution already active for assessment %s (job: %s)",
				assessmentID, existing.status.ExecutionID)
		}
	}

	// 2. Acquire SQLite database lease (cross-process mutual exclusion)
	execID := "exec-" + uuid.New().String()
	lease := &ScanJobLease{
		ID:              assessmentID,
		ExecutionID:     execID,
		OperatorID:      operatorID,
		Status:          string(JobStateRunning),
		ProgressMessage: "Initializing assessment execution...",
	}
	if err := jm.store.AcquireScanJobLease(lease); err != nil {
		return nil, fmt.Errorf("unable to acquire scan lease: %w", err)
	}

	// 3. Create cancellable execution context
	jobCtx, cancel := context.WithCancel(context.Background())

	status := JobStatus{
		AssessmentID:    assessmentID,
		ExecutionID:     execID,
		OperatorID:      operatorID,
		State:           JobStateRunning,
		StartedAt:       time.Now().UTC(),
		ProgressMessage: "Execution queued and starting...",
	}

	jm.activeJobs[assessmentID] = &activeJobEntry{
		cancel: cancel,
		status: status,
	}

	// Record audit event
	_ = jm.store.RecordAuditEvent(&AuditEvent{
		AssessmentID: assessmentID,
		OperatorID:   operatorID,
		ActionType:   "SCAN_STARTED",
		EntityType:   "SCAN",
		EntityID:     execID,
		DetailsJSON:  fmt.Sprintf(`{"concurrency":%d,"timeout":"%s"}`, opts.Concurrency, opts.TimeoutDuration),
	})

	// 4. Wrap progress func to update lease and in-memory status
	originalProgress := opts.ProgressFunc
	opts.ProgressFunc = func(msg string) {
		jm.mu.Lock()
		if entry, ok := jm.activeJobs[assessmentID]; ok {
			entry.status.ProgressMessage = msg
		}
		jm.mu.Unlock()

		_ = jm.store.HeartbeatScanJobLease(assessmentID, msg)
		if originalProgress != nil {
			originalProgress(msg)
		}
	}

	// 5. Execute in background goroutine
	go func() {
		defer cancel()

		res, err := jm.controller.RunAssessment(jobCtx, assessmentID, opts)

		jm.mu.Lock()
		defer jm.mu.Unlock()

		now := time.Now().UTC()
		entry, ok := jm.activeJobs[assessmentID]
		if !ok {
			return
		}

		entry.status.CompletedAt = &now
		entry.status.DurationMs = now.Sub(entry.status.StartedAt).Milliseconds()
		entry.status.Result = res

		if err != nil {
			if jobCtx.Err() == context.Canceled {
				entry.status.State = JobStateCancelled
				entry.status.ErrorMessage = "Execution was cancelled by operator"
				_ = jm.store.ReleaseScanJobLease(assessmentID, string(JobStateCancelled), "Cancelled by operator")
				_ = jm.store.RecordAuditEvent(&AuditEvent{
					AssessmentID: assessmentID,
					OperatorID:   operatorID,
					ActionType:   "SCAN_CANCELLED",
					EntityType:   "SCAN",
					EntityID:     execID,
				})
			} else {
				entry.status.State = JobStateFailed
				entry.status.ErrorMessage = err.Error()
				_ = jm.store.ReleaseScanJobLease(assessmentID, string(JobStateFailed), err.Error())
				_ = jm.store.RecordAuditEvent(&AuditEvent{
					AssessmentID: assessmentID,
					OperatorID:   operatorID,
					ActionType:   "SCAN_FAILED",
					EntityType:   "SCAN",
					EntityID:     execID,
					DetailsJSON:  fmt.Sprintf(`{"error":%q}`, err.Error()),
				})
			}
		} else {
			entry.status.State = JobStateCompleted
			entry.status.ProgressMessage = "Assessment completed successfully"
			_ = jm.store.ReleaseScanJobLease(assessmentID, string(JobStateCompleted), "")
			_ = jm.store.RecordAuditEvent(&AuditEvent{
				AssessmentID: assessmentID,
				OperatorID:   operatorID,
				ActionType:   "SCAN_COMPLETED",
				EntityType:   "SCAN",
				EntityID:     execID,
				DetailsJSON:  fmt.Sprintf(`{"duration_ms":%d}`, entry.status.DurationMs),
			})
		}
	}()

	return &status, nil
}

// CancelAssessmentScan requests graceful cancellation of an active assessment scan.
func (jm *JobManager) CancelAssessmentScan(assessmentID string, operatorID string) error {
	jm.mu.Lock()
	defer jm.mu.Unlock()

	entry, ok := jm.activeJobs[assessmentID]
	if !ok || (entry.status.State != JobStateRunning && entry.status.State != JobStateQueued) {
		// Fallback check SQLite lease
		lease, err := jm.store.GetActiveScanJobLease(assessmentID)
		if err == nil && lease != nil && lease.Status == "RUNNING" {
			_ = jm.store.ReleaseScanJobLease(assessmentID, string(JobStateCancelled), "Cancelled by operator")
			return nil
		}
		return fmt.Errorf("no active running scan found for assessment %s", assessmentID)
	}

	entry.cancel()
	entry.status.ProgressMessage = "Cancellation requested; terminating worker threads..."
	_ = jm.store.HeartbeatScanJobLease(assessmentID, "Cancelling...")
	return nil
}

// GetJobStatus retrieves the current scan status for an assessment.
func (jm *JobManager) GetJobStatus(assessmentID string) (*JobStatus, error) {
	jm.mu.Lock()
	defer jm.mu.Unlock()

	if entry, ok := jm.activeJobs[assessmentID]; ok {
		cp := entry.status
		return &cp, nil
	}

	// Query SQLite lease state if not in memory (e.g. after server restart)
	lease, err := jm.store.GetActiveScanJobLease(assessmentID)
	if err != nil {
		return nil, err
	}
	if lease == nil {
		return nil, nil
	}

	return &JobStatus{
		AssessmentID:    lease.ID,
		ExecutionID:     lease.ExecutionID,
		OperatorID:      lease.OperatorID,
		State:           JobState(lease.Status),
		StartedAt:       lease.AcquiredAt,
		ProgressMessage: lease.ProgressMessage,
		ErrorMessage:    lease.ErrorMessage,
	}, nil
}
