package assessment

import (
	"errors"
	"time"
)

// RecurrenceType defines the scheduling recurrence pattern.
type RecurrenceType string

const (
	RecurrenceOnce     RecurrenceType = "once"
	RecurrenceInterval RecurrenceType = "interval"
	RecurrenceDaily    RecurrenceType = "daily"
	RecurrenceWeekly   RecurrenceType = "weekly"
	RecurrenceCron     RecurrenceType = "cron"
)

var (
	// ErrScheduleNotFound indicates the requested schedule record does not exist.
	ErrScheduleNotFound = errors.New("schedule not found")

	// ErrScheduleInvalid indicates an invalid or malformed schedule configuration.
	ErrScheduleInvalid = errors.New("invalid schedule configuration")

	// ErrScheduleUnauthorized indicates the caller lacks authorization to access the schedule.
	ErrScheduleUnauthorized = errors.New("unauthorized access to schedule")

	// ErrScheduleNotAuthorized indicates the underlying assessment lacks approved execution authorization.
	ErrScheduleNotAuthorized = errors.New("assessment lacks approved execution authorization")
)

// ScheduleExecutionOptions encapsulates persisted runtime options for scheduled execution.
type ScheduleExecutionOptions struct {
	TimeoutSeconds     int    `json:"timeout_seconds,omitempty"`
	Concurrency        int    `json:"concurrency,omitempty"`
	MaxAssets          int    `json:"max_assets,omitempty"`
	MaxSizeBytes       int64  `json:"max_size_bytes,omitempty"`
	UserAgent          string `json:"user_agent,omitempty"`
	Verbose            bool   `json:"verbose,omitempty"`
	AllowLoopback      bool   `json:"allow_loopback,omitempty"`
	AllowPrivateIPs    bool   `json:"allow_private_ips,omitempty"`
	InsecureSkipVerify bool   `json:"insecure_skip_verify,omitempty"`
	ActiveVerification bool   `json:"active_verification,omitempty"`
	MaxRedirects       int    `json:"max_redirects,omitempty"`
	MaxRetries         int    `json:"max_retries,omitempty"`
	RetryDelayMs       int    `json:"retry_delay_ms,omitempty"`
}

// ToExecutionOptions converts scheduled options into controller ExecutionOptions.
func (s ScheduleExecutionOptions) ToExecutionOptions() ExecutionOptions {
	var timeout time.Duration
	if s.TimeoutSeconds > 0 {
		timeout = time.Duration(s.TimeoutSeconds) * time.Second
	}
	return ExecutionOptions{
		TimeoutDuration:    timeout,
		Concurrency:        s.Concurrency,
		MaxAssets:          s.MaxAssets,
		MaxSizeBytes:       s.MaxSizeBytes,
		UserAgent:          s.UserAgent,
		Verbose:            s.Verbose,
		AllowLoopback:      s.AllowLoopback,
		AllowPrivateIPs:    s.AllowPrivateIPs,
		InsecureSkipVerify: s.InsecureSkipVerify,
		ActiveVerification: s.ActiveVerification,
		MaxRedirects:       s.MaxRedirects,
		MaxRetries:         s.MaxRetries,
		RetryDelayMs:       s.RetryDelayMs,
	}
}

// AssessmentSchedule represents a persistent scheduled assessment configuration.
type AssessmentSchedule struct {
	ID                  string                   `json:"id"`
	Name                string                   `json:"name"`
	Description         string                   `json:"description,omitempty"`
	AssessmentID        string                   `json:"assessment_id"` // Assessment Ref or UUID
	AssessmentRef       string                   `json:"assessment_ref,omitempty"`
	ClientID            string                   `json:"client_id"`
	TenantID            string                   `json:"tenant_id"`
	AccountID           string                   `json:"account_id,omitempty"`
	RecurrenceType      RecurrenceType           `json:"recurrence_type"`
	RecurrenceExpr      string                   `json:"recurrence_expr"` // e.g. "@every 1h", "02:30", "Mon 09:00", "0 2 * * *"
	IntervalSeconds     int64                    `json:"interval_seconds,omitempty"`
	Timezone            string                   `json:"timezone"` // IANA timezone, e.g. "UTC", "America/New_York"
	IsEnabled           bool                     `json:"is_enabled"`
	CatchUpPolicy       string                   `json:"catch_up_policy,omitempty"` // "once" (default), "skip"
	ExecutionOptions    ScheduleExecutionOptions `json:"execution_options"`
	NextDueAt           time.Time                `json:"next_due_at"`
	LastDispatchedAt    *time.Time               `json:"last_dispatched_at,omitempty"`
	LastCompletedAt     *time.Time               `json:"last_completed_at,omitempty"`
	LastExecutionID     string                   `json:"last_execution_id,omitempty"`
	DispatchCount       int                      `json:"dispatch_count"`
	FailureCount        int                      `json:"failure_count"`
	ConsecutiveFailures int                      `json:"consecutive_failures"`
	LastError           string                   `json:"last_error,omitempty"`
	CreatedAt           time.Time                `json:"created_at"`
	UpdatedAt           time.Time                `json:"updated_at"`
}

// ScheduleListOptions provides tenant-scoped filtering and pagination for listing schedules.
type ScheduleListOptions struct {
	Auth         TenantAuthContext
	ClientID     string
	TenantID     string
	AccountID    string
	AssessmentID string
	IsEnabled    *bool
	Limit        int
	Offset       int
}

// ScheduleDispatchRecord records a single scheduled occurrence dispatch event.
type ScheduleDispatchRecord struct {
	ID           string     `json:"id"`
	ScheduleID   string     `json:"schedule_id"`
	AssessmentID string     `json:"assessment_id"`
	ExecutionID  string     `json:"execution_id,omitempty"`
	TenantID     string     `json:"tenant_id"`
	AccountID    string     `json:"account_id,omitempty"`
	ScheduledFor time.Time  `json:"scheduled_for"`
	DispatchedAt time.Time  `json:"dispatched_at"`
	CompletedAt  *time.Time `json:"completed_at,omitempty"`
	Status       string     `json:"status"` // "CLAIMED", "RUNNING", "COMPLETED", "FAILED", "SKIPPED"
	ErrorMessage string     `json:"error_message,omitempty"`
	CreatedAt    time.Time  `json:"created_at"`
}
