package assessment

import (
	"context"
	"time"
)

// ExecutionRunner defines a function capable of executing or resuming an assessment.
type ExecutionRunner func(ctx context.Context, assessmentID string, opts ExecutionOptions) (*ExecutionResult, error)

// ScanCheckpoint captures incremental progress state allowing safe resumption of interrupted assessments.
type ScanCheckpoint struct {
	Stage            string    `json:"stage"` // "INITIALIZED", "CRAWL_PARTIAL", "CRAWL_COMPLETE", "DETECTION_COMPLETE", "FINALIZING"
	CompletedTargets []string  `json:"completed_targets"`
	RemainingTargets []string  `json:"remaining_targets"`
	FindingsCount    int       `json:"findings_count"`
	LastTargetURL    string    `json:"last_target_url,omitempty"`
	UpdatedAt        time.Time `json:"updated_at"`
}

// RecoveryAction describes the operational decision made during assessment recovery.
type RecoveryAction string

const (
	ActionFinalizedInterrupted RecoveryAction = "FINALIZED_INTERRUPTED"
	ActionFinalizedFailed      RecoveryAction = "FINALIZED_FAILED"
	ActionResumed              RecoveryAction = "RESUMED"
	ActionRetried              RecoveryAction = "RETRIED"
	ActionSkippedActive        RecoveryAction = "SKIPPED_ACTIVE"
	ActionSkippedTerminal      RecoveryAction = "SKIPPED_TERMINAL"
	ActionSkippedNoOwnership   RecoveryAction = "SKIPPED_NO_OWNERSHIP"
	ActionSkippedExceededLimit RecoveryAction = "SKIPPED_EXCEEDED_LIMIT"
)

// ExecutionRecoveryResult details the outcome of recovering an individual assessment execution.
type ExecutionRecoveryResult struct {
	ExecutionID       string           `json:"execution_id"`
	AssessmentID      string           `json:"assessment_id"`
	PreviousStatus    AssessmentStatus `json:"previous_status"`
	NewStatus         AssessmentStatus `json:"new_status"`
	Action            RecoveryAction   `json:"action"`
	Reason            string           `json:"reason"`
	RecoveredAt       time.Time        `json:"recovered_at"`
	WasDryRun         bool             `json:"was_dry_run"`
	HasSnapshot       bool             `json:"has_snapshot"`
	PreservedFindings int              `json:"preserved_findings"`
}

// RecoverySummary provides aggregated metrics across an entire recovery sweep.
type RecoverySummary struct {
	ExaminedCount  int                       `json:"examined_count"`
	RecoveredCount int                       `json:"recovered_count"`
	FinalizedCount int                       `json:"finalized_count"`
	ResumedCount   int                       `json:"resumed_count"`
	RetriedCount   int                       `json:"retried_count"`
	SkippedCount   int                       `json:"skipped_count"`
	FailedCount    int                       `json:"failed_count"`
	Results        []ExecutionRecoveryResult `json:"results"`
}

// RecoveryOptions configures the scope and policy of an assessment recovery operation.
type RecoveryOptions struct {
	Auth          TenantAuthContext
	ExecutionID   string        // If set, target a specific execution
	AssessmentID  string        // If set, filter by assessment
	DryRun        bool          // If true, evaluate without mutating persistent state
	StaleDuration time.Duration // Time since last heartbeat or start before execution is deemed abandoned
	MaxRetries    int           // Maximum recovery attempts allowed before permanent finalization
	WorkerID      string          // Unique identifier of the recovering worker
	AllowResume   bool            // If true and a verified checkpoint exists, attempt safe resume
	Runner        ExecutionRunner // Optional execution engine used for real resumption
	Context       context.Context // Optional context for resumption execution
	AllowLoopback bool            // Permits loopback endpoints during test resumption
	AllowPrivateIPs bool          // Permits private IP endpoints during test resumption
}

// DefaultRecoveryOptions returns production-safe recovery parameters.
func DefaultRecoveryOptions() RecoveryOptions {
	return RecoveryOptions{
		StaleDuration: 3 * time.Minute,
		MaxRetries:    3,
		AllowResume:   true,
	}
}
