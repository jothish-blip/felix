package swarm

import (
	"errors"
	"time"

	"felix/pkg/report"
)

// Common errors in swarm operations.
var (
	ErrQueueFull          = errors.New("finding channel capacity exceeded (backpressure active)")
	ErrWorkerNotFound     = errors.New("worker not registered with coordinator")
	ErrTaskNotFound       = errors.New("task not found in queue")
	ErrTaskAlreadyClaimed = errors.New("task is already claimed by another active worker")
	ErrUnauthorized       = errors.New("unauthorized swarm worker credentials")
	ErrScopeViolation     = errors.New("target URL violates configured assessment scope")
	ErrInvalidPayload     = errors.New("malformed or invalid swarm request payload")
	ErrCoordinatorClosed  = errors.New("swarm coordinator is shutting down")
)

// WorkerStatus represents the operational lifecycle state of a swarm worker node.
type WorkerStatus string

const (
	WorkerStatusOnline       WorkerStatus = "ONLINE"
	WorkerStatusBusy         WorkerStatus = "BUSY"
	WorkerStatusUnresponsive WorkerStatus = "UNRESPONSIVE"
	WorkerStatusDead         WorkerStatus = "DEAD"
)

// TaskStatus represents the lifecycle state of a distributed scanning task.
type TaskStatus string

const (
	TaskStatusPending    TaskStatus = "PENDING"
	TaskStatusAssigned   TaskStatus = "ASSIGNED"
	TaskStatusInProgress TaskStatus = "IN_PROGRESS"
	TaskStatusCompleted  TaskStatus = "COMPLETED"
	TaskStatusFailed     TaskStatus = "FAILED"
)

// ScanTask defines a unit of vulnerability scanning work dispatched by the master coordinator.
type ScanTask struct {
	ID               string            `json:"id"`
	AssessmentID     string            `json:"assessment_id"`
	ExecutionID      string            `json:"execution_id"`
	TargetID         string            `json:"target_id"`
	TargetURL        string            `json:"target_url"`
	AssetType        string            `json:"asset_type"`
	Priority         int               `json:"priority"`
	Status           TaskStatus        `json:"status"`
	AssignedWorkerID string            `json:"assigned_worker_id,omitempty"`
	AssignedAt       time.Time         `json:"assigned_at,omitempty"`
	CompletedAt      time.Time         `json:"completed_at,omitempty"`
	RetryCount       int               `json:"retry_count"`
	MaxRetries       int               `json:"max_retries"`
	TargetScope      []string          `json:"target_scope,omitempty"`
	AllowedMethods   []string          `json:"allowed_methods,omitempty"`
	Parameters       map[string]string `json:"parameters,omitempty"`
}

// WorkerNode represents a registered loopback or remote worker node in the cluster.
type WorkerNode struct {
	ID             string            `json:"id"`
	Address        string            `json:"address"` // e.g. "http://127.0.0.1:54321"
	Status         WorkerStatus      `json:"status"`
	LastHeartbeat  time.Time         `json:"last_heartbeat"`
	RegisteredAt   time.Time         `json:"registered_at"`
	ActiveTaskID   string            `json:"active_task_id,omitempty"`
	CompletedTasks int               `json:"completed_tasks"`
	FailedTasks    int               `json:"failed_tasks"`
	Labels         map[string]string `json:"labels,omitempty"`
}

// RegisterRequest is submitted by a worker during initial cluster handshake.
type RegisterRequest struct {
	WorkerID      string            `json:"worker_id"`
	WorkerAddress string            `json:"worker_address"`
	AuthToken     string            `json:"auth_token"`
	Labels        map[string]string `json:"labels,omitempty"`
}

// RegisterResponse returns registration status and cluster configuration parameters.
type RegisterResponse struct {
	Accepted          bool          `json:"accepted"`
	HeartbeatInterval time.Duration `json:"heartbeat_interval"`
	Message           string        `json:"message,omitempty"`
}

// HeartbeatRequest is submitted periodically by workers to attest vitality.
type HeartbeatRequest struct {
	WorkerID     string    `json:"worker_id"`
	AuthToken    string    `json:"auth_token"`
	Timestamp    time.Time `json:"timestamp"`
	ActiveTaskID string    `json:"active_task_id,omitempty"`
}

// HeartbeatResponse is returned by master after recording vitality.
type HeartbeatResponse struct {
	Acknowledged bool   `json:"acknowledged"`
	DirectAction string `json:"direct_action,omitempty"` // e.g. "RECONNECT", "ABORT"
}

// TaskPollRequest is sent by an idle worker requesting the next scan assignment.
type TaskPollRequest struct {
	WorkerID  string `json:"worker_id"`
	AuthToken string `json:"auth_token"`
}

// TaskPollResponse delivers a pending task or indicates no work is available.
type TaskPollResponse struct {
	HasTask bool      `json:"has_task"`
	Task    *ScanTask `json:"task,omitempty"`
}

// TaskCompleteRequest is submitted by a worker upon completing a scan task.
type TaskCompleteRequest struct {
	WorkerID       string    `json:"worker_id"`
	AuthToken      string    `json:"auth_token"`
	TaskID         string    `json:"task_id"`
	Success        bool      `json:"success"`
	ErrorMessage   string    `json:"error_message,omitempty"`
	ScanDurationMs float64   `json:"scan_duration_ms"`
	FindingsCount  int       `json:"findings_count"`
	CompletedAt    time.Time `json:"completed_at"`
}

// TaskCompleteResponse acknowledges receipt of task outcome.
type TaskCompleteResponse struct {
	Acknowledged bool `json:"acknowledged"`
}

// FindingSubmission contains findings streamed from a worker to the master writer.
type FindingSubmission struct {
	WorkerID     string           `json:"worker_id"`
	AuthToken    string           `json:"auth_token"`
	TaskID       string           `json:"task_id"`
	SubmissionID string           `json:"submission_id"` // Idempotency key for deduplication
	Findings     []report.Finding `json:"findings"`
}

// FindingSubmissionResponse acknowledges queued findings.
type FindingSubmissionResponse struct {
	AcceptedCount int    `json:"accepted_count"`
	DroppedCount  int    `json:"dropped_count"`
	Status        string `json:"status"`
}

// SwarmMetrics tracks performance, concurrency, and fault tolerance stats.
type SwarmMetrics struct {
	TotalTasksDistributed       int64   `json:"total_tasks_distributed"`
	TasksCompletedSuccessfully  int64   `json:"tasks_completed_successfully"`
	TasksFailed                 int64   `json:"tasks_failed"`
	TasksReassigned             int64   `json:"tasks_reassigned"`
	WorkerFailuresDetected      int64   `json:"worker_failures_detected"`
	ActiveWorkers               int     `json:"active_workers"`
	TotalRegisteredWorkers      int     `json:"total_registered_workers"`
	TotalFindingsReceived       int64   `json:"total_findings_received"`
	TotalFindingsPersisted      int64   `json:"total_findings_persisted"`
	DuplicateFindingsDropped    int64   `json:"duplicate_findings_dropped"`
	BatchesCommitted            int64   `json:"batches_committed"`
	SQLiteBusyErrors            int64   `json:"sqlite_busy_errors"`
	TotalBatchDurationMs        float64 `json:"total_batch_duration_ms"`
	ThroughputFindingsPerSecond float64 `json:"throughput_findings_per_second"`
}

// CoordinatorConfig configures the master swarm coordinator.
type CoordinatorConfig struct {
	ListenAddr        string        `json:"listen_addr"`
	AuthToken         string        `json:"auth_token"`
	HeartbeatInterval time.Duration `json:"heartbeat_interval"`
	HeartbeatTimeout  time.Duration `json:"heartbeat_timeout"`
	ReaperInterval    time.Duration `json:"reaper_interval"`
	CommitInterval    time.Duration `json:"commit_interval"`
	BatchSize         int           `json:"batch_size"`
	ChannelCapacity   int           `json:"channel_capacity"`
	MaxTaskRetries    int           `json:"max_task_retries"`
	ScopeTargets      []string      `json:"scope_targets"`
	AssessmentID      string        `json:"assessment_id"`
	ExecutionID       string        `json:"execution_id"`
	TargetID          string        `json:"target_id"`
}

// DefaultCoordinatorConfig returns production-calibrated swarm defaults.
func DefaultCoordinatorConfig() CoordinatorConfig {
	return CoordinatorConfig{
		ListenAddr:        "127.0.0.1:0", // Dynamic local loopback port
		AuthToken:         "felix-swarm-loopback-secret",
		HeartbeatInterval: 250 * time.Millisecond,
		HeartbeatTimeout:  1000 * time.Millisecond,
		ReaperInterval:    200 * time.Millisecond,
		CommitInterval:    250 * time.Millisecond,
		BatchSize:         500,
		ChannelCapacity:   5000,
		MaxTaskRetries:    3,
		AssessmentID:      "ASM-SWARM-DEFAULT",
		ExecutionID:       "EXEC-SWARM-DEFAULT",
		TargetID:          "TGT-SWARM-DEFAULT",
	}
}
