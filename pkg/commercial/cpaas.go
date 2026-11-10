package commercial

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"felix/pkg/assessment"
	"felix/pkg/secrets"
)

// ScheduleType identifies the trigger mechanism for a continuous assessment schedule.
type ScheduleType string

const (
	ScheduleTypeMonthly ScheduleType = "MONTHLY"
	ScheduleTypeCron    ScheduleType = "CRON"
	ScheduleTypeWebhook ScheduleType = "WEBHOOK"
)

// ExecutionStatus captures the lifecycle state of a scheduled assessment.
type ExecutionStatus string

const (
	ExecutionStatusPending   ExecutionStatus = "PENDING"
	ExecutionStatusRunning   ExecutionStatus = "RUNNING"
	ExecutionStatusCompleted ExecutionStatus = "COMPLETED"
	ExecutionStatusFailed    ExecutionStatus = "FAILED"
	ExecutionStatusCancelled ExecutionStatus = "CANCELLED"
)

// NotificationTarget configures an external webhook or incident management integration.
type NotificationTarget struct {
	Provider    string `json:"provider"`     // "slack", "teams", "pagerduty", "webhook"
	EndpointURL string `json:"endpoint_url"` // Webhook destination URL
	RoutingKey  string `json:"routing_key,omitempty"`
	Token       string `json:"token,omitempty"`
	Secret      string `json:"secret,omitempty"` // For HMAC-SHA256 signature verification
	Enabled     bool   `json:"enabled"`
}

// ScheduleOptions captures serializable pentest execution parameters.
type ScheduleOptions struct {
	ActiveVerification bool              `json:"active_verification,omitempty"`
	AllowLoopback      bool              `json:"allow_loopback,omitempty"`
	AllowPrivateIPs    bool              `json:"allow_private_ips,omitempty"`
	InsecureSkipVerify bool              `json:"insecure_skip_verify,omitempty"`
	Timeout            time.Duration     `json:"timeout,omitempty"`
	ScopeManifestPath  string            `json:"scope_manifest_path,omitempty"`
	CustomParameters   map[string]string `json:"custom_parameters,omitempty"`
}

// ScheduleConfig represents an enterprise CPaaS recurring penetration test policy.
type ScheduleConfig struct {
	ID                  string               `json:"id"`
	ClientID            string               `json:"client_id"`
	Name                string               `json:"name"`
	ScheduleType        ScheduleType         `json:"schedule_type"`
	CronExpr            string               `json:"cron_expr"`
	TargetURLs          []string             `json:"target_urls"`
	Profile             string               `json:"profile"`
	Enabled             bool                 `json:"enabled"`
	Options             ScheduleOptions      `json:"options,omitempty"`
	NotificationTargets []NotificationTarget `json:"notification_targets,omitempty"`
	WebhookSecret       string               `json:"webhook_secret,omitempty"`
	CreatedAt           time.Time            `json:"created_at"`
	UpdatedAt           time.Time            `json:"updated_at"`
	LastRunAt           *time.Time           `json:"last_run_at,omitempty"`
	NextRunAt           *time.Time           `json:"next_run_at,omitempty"`
}

// BuildExecutionOptions converts persistent ScheduleOptions into executable assessment.ExecutionOptions.
func (s *ScheduleConfig) BuildExecutionOptions() assessment.ExecutionOptions {
	return assessment.ExecutionOptions{
		ActiveVerification: s.Options.ActiveVerification,
		AllowLoopback:      s.Options.AllowLoopback,
		AllowPrivateIPs:    s.Options.AllowPrivateIPs,
		InsecureSkipVerify: s.Options.InsecureSkipVerify,
		TimeoutDuration:    s.Options.Timeout,
		ScopeManifestPath:  s.Options.ScopeManifestPath,
	}
}

// ScheduledExecution records an individual assessment execution triggered by schedule or webhook.
type ScheduledExecution struct {
	ID                   string          `json:"id"`
	ScheduleID           string          `json:"schedule_id"`
	ClientID             string          `json:"client_id"`
	TriggerType          string          `json:"trigger_type"` // "SCHEDULED", "WEBHOOK", "MANUAL"
	Status               ExecutionStatus `json:"status"`
	IdempotencyKey       string          `json:"idempotency_key"`
	ScheduledFor         time.Time       `json:"scheduled_for"`
	StartedAt            *time.Time      `json:"started_at,omitempty"`
	CompletedAt          *time.Time      `json:"completed_at,omitempty"`
	AssessmentID         string          `json:"assessment_id,omitempty"`
	ExecutionID          string          `json:"execution_id,omitempty"`
	DriftReportID        string          `json:"drift_report_id,omitempty"`
	FindingsCount        int             `json:"findings_count"`
	VerifiedDefectsCount int             `json:"verified_defects_count"`
	AlertsDispatched     int             `json:"alerts_dispatched"`
	ErrorMessage         string          `json:"error_message,omitempty"`
}

// WebhookTriggerRequest encapsulates a CI/CD deployment or external pipeline trigger.
type WebhookTriggerRequest struct {
	ScheduleID     string   `json:"schedule_id"`
	ClientID       string   `json:"client_id"`
	TargetURLs     []string `json:"target_urls,omitempty"`
	Profile        string   `json:"profile,omitempty"`
	CommitHash     string   `json:"commit_hash,omitempty"`
	Branch         string   `json:"branch,omitempty"`
	TriggeredBy    string   `json:"triggered_by,omitempty"`
	WebhookSecret  string   `json:"webhook_secret,omitempty"`
	HMACSignature  string   `json:"hmac_signature,omitempty"`
	Timestamp      string   `json:"timestamp,omitempty"`
	IdempotencyKey string   `json:"idempotency_key,omitempty"`
}

// WebhookTriggerResponse provides the immediate synchronous response to a CI/CD trigger.
type WebhookTriggerResponse struct {
	Accepted       bool      `json:"accepted"`
	ExecutionID    string    `json:"execution_id"`
	ScheduleID     string    `json:"schedule_id"`
	Message        string    `json:"message"`
	ScheduledAt    time.Time `json:"scheduled_at"`
	IdempotencyKey string    `json:"idempotency_key"`
}

// AssessmentRunner defines the execution boundary for running automated assessments.
type AssessmentRunner interface {
	RunAssessment(ctx context.Context, sched *ScheduleConfig) (*AttackSurfaceSnapshot, error)
}

// CPaaSScheduler manages recurring penetration test schedules, execution queues, and drift analysis.
type CPaaSScheduler struct {
	store          *CPaaSStore
	driftEngine    *DriftEngine
	notifier       *SmartAlertNotifier
	runner         AssessmentRunner
	maxConcurrency int
	semaphore      chan struct{}

	clock     func() time.Time
	sleepFunc func(ctx context.Context, d time.Duration) error

	mu          sync.Mutex
	running     bool
	stopCh      chan struct{}
	wg          sync.WaitGroup
	activeTasks map[string]*ScheduledExecution

	// Snapshots cache for baseline tracking (AssessmentID -> Snapshot)
	snapshotCache   map[string]*AttackSurfaceSnapshot
	lastSnapshot    map[string]*AttackSurfaceSnapshot // ScheduleID -> latest snapshot
	snapshotCacheMu sync.RWMutex
}

// CPaaSSchedulerOptions configures scheduler behavior.
type CPaaSSchedulerOptions struct {
	MaxConcurrency int
	Clock          func() time.Time
	SleepFunc      func(ctx context.Context, d time.Duration) error
}

// NewCPaaSScheduler constructs an initialized CPaaS scheduler.
func NewCPaaSScheduler(
	store *CPaaSStore,
	driftEngine *DriftEngine,
	notifier *SmartAlertNotifier,
	runner AssessmentRunner,
	opts CPaaSSchedulerOptions,
) *CPaaSScheduler {
	concurrency := opts.MaxConcurrency
	if concurrency <= 0 {
		concurrency = 2
	}

	clock := opts.Clock
	if clock == nil {
		clock = time.Now
	}

	sleepFunc := opts.SleepFunc
	if sleepFunc == nil {
		sleepFunc = func(ctx context.Context, d time.Duration) error {
			if d <= 0 {
				return nil
			}
			t := time.NewTimer(d)
			defer t.Stop()
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-t.C:
				return nil
			}
		}
	}

	return &CPaaSScheduler{
		store:           store,
		driftEngine:     driftEngine,
		notifier:        notifier,
		runner:          runner,
		maxConcurrency:  concurrency,
		semaphore:       make(chan struct{}, concurrency),
		clock:           clock,
		sleepFunc:       sleepFunc,
		stopCh:          make(chan struct{}),
		activeTasks:     make(map[string]*ScheduledExecution),
		snapshotCache:   make(map[string]*AttackSurfaceSnapshot),
		lastSnapshot:    make(map[string]*AttackSurfaceSnapshot),
	}
}

// Start launches the background scheduler loop.
func (s *CPaaSScheduler) Start(ctx context.Context) error {
	s.mu.Lock()
	if s.running {
		s.mu.Unlock()
		return errors.New("cpaas: scheduler already running")
	}
	s.running = true
	s.stopCh = make(chan struct{})
	s.mu.Unlock()

	// Initial recovery of pending / missed executions
	_, _ = s.RecoverPending(ctx)

	s.wg.Add(1)
	go s.schedulerLoop(ctx)
	return nil
}

// Stop gracefully shuts down the scheduler, waiting for active executions to complete.
func (s *CPaaSScheduler) Stop(ctx context.Context) error {
	s.mu.Lock()
	if !s.running {
		s.mu.Unlock()
		return nil
	}
	s.running = false
	close(s.stopCh)
	s.mu.Unlock()

	done := make(chan struct{})
	go func() {
		s.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (s *CPaaSScheduler) schedulerLoop(ctx context.Context) {
	defer s.wg.Done()

	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-s.stopCh:
			return
		case <-ctx.Done():
			return
		case <-ticker.C:
			_ = s.RunCycle(ctx)
		}
	}
}

// RunCycle evaluates all enabled schedules, queuing any whose NextRunAt has arrived.
func (s *CPaaSScheduler) RunCycle(ctx context.Context) error {
	if s.store == nil {
		return nil
	}

	now := s.clock().UTC()
	schedules, err := s.store.ListSchedules(ctx, "", true)
	if err != nil {
		return err
	}

	for _, sched := range schedules {
		if sched.ScheduleType == ScheduleTypeWebhook {
			continue // Webhooks are triggered externally
		}

		if sched.NextRunAt == nil {
			// Compute next run if unset
			next, err := CalculateNextRun(sched.ScheduleType, sched.CronExpr, now)
			if err == nil {
				_ = s.store.UpdateScheduleNextRun(ctx, sched.ID, sched.LastRunAt, &next)
			}
			continue
		}

		if now.After(*sched.NextRunAt) || now.Equal(*sched.NextRunAt) {
			// Trigger scheduled assessment
			schedTime := *sched.NextRunAt
			idempotencyKey := fmt.Sprintf("%s:%s", sched.ID, schedTime.Format(time.RFC3339))

			exec := &ScheduledExecution{
				ID:             fmt.Sprintf("cpaas_exec_%s_%d", sched.ID, now.UnixNano()),
				ScheduleID:     sched.ID,
				ClientID:       sched.ClientID,
				TriggerType:    "SCHEDULED",
				Status:         ExecutionStatusPending,
				IdempotencyKey: idempotencyKey,
				ScheduledFor:   schedTime,
			}

			err := s.store.CreateExecution(ctx, exec)
			if err != nil && !errors.Is(err, ErrDuplicateExecution) {
				continue
			}

			// Advance schedule's next run
			next, err := CalculateNextRun(sched.ScheduleType, sched.CronExpr, schedTime.Add(time.Second))
			if err == nil {
				_ = s.store.UpdateScheduleNextRun(ctx, sched.ID, &schedTime, &next)
			}

			// Dispatch to worker pool if newly created
			if err == nil || !errors.Is(err, ErrDuplicateExecution) {
				s.enqueueExecution(ctx, &sched, exec)
			}
		}
	}

	return nil
}

// TriggerWebhook processes an authenticated incoming CI/CD deployment webhook.
func (s *CPaaSScheduler) TriggerWebhook(ctx context.Context, req WebhookTriggerRequest) (*WebhookTriggerResponse, error) {
	if req.ScheduleID == "" {
		return nil, errors.New("cpaas: schedule_id is required")
	}

	sched, err := s.store.GetSchedule(ctx, req.ScheduleID)
	if err != nil {
		return nil, fmt.Errorf("cpaas: invalid schedule: %w", err)
	}

	if !sched.Enabled {
		return nil, errors.New("cpaas: schedule is disabled")
	}

	// 1. Webhook Authentication
	if sched.WebhookSecret != "" {
		authed := false
		// Plain secret comparison
		if req.WebhookSecret != "" && subtleConstantTimeCompare(req.WebhookSecret, sched.WebhookSecret) {
			authed = true
		}
		// HMAC-SHA256 signature verification (X-Felix-Signature)
		if !authed && req.HMACSignature != "" && req.Timestamp != "" {
			expectedSig := computeHMACSHA256(sched.WebhookSecret, fmt.Sprintf("%s:%s:%s", req.ScheduleID, req.Timestamp, req.CommitHash))
			if subtleConstantTimeCompare(req.HMACSignature, expectedSig) {
				authed = true
			}
		}
		if !authed {
			return nil, errors.New("cpaas: unauthorized webhook trigger (invalid secret or signature)")
		}
	}

	// 2. Target URL Validation (SSRF / Scheme safety)
	targets := sched.TargetURLs
	if len(req.TargetURLs) > 0 {
		for _, u := range req.TargetURLs {
			parsed, err := url.Parse(u)
			if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") {
				return nil, fmt.Errorf("cpaas: invalid target URL %q", secrets.RedactText(u))
			}
		}
		targets = req.TargetURLs
	}

	// 3. Replay Defense & Idempotency Key
	now := s.clock().UTC()
	idempKey := req.IdempotencyKey
	if idempKey == "" {
		if req.CommitHash != "" {
			idempKey = fmt.Sprintf("wh_%s_%s", req.ScheduleID, req.CommitHash)
		} else {
			idempKey = fmt.Sprintf("wh_%s_%d", req.ScheduleID, now.Unix())
		}
	}

	exec := &ScheduledExecution{
		ID:             fmt.Sprintf("cpaas_exec_wh_%d", now.UnixNano()),
		ScheduleID:     sched.ID,
		ClientID:       sched.ClientID,
		TriggerType:    "WEBHOOK",
		Status:         ExecutionStatusPending,
		IdempotencyKey: idempKey,
		ScheduledFor:   now,
	}

	if err := s.store.CreateExecution(ctx, exec); err != nil {
		if errors.Is(err, ErrDuplicateExecution) {
			return nil, fmt.Errorf("cpaas: duplicate webhook delivery (idempotency key %q already processed)", idempKey)
		}
		return nil, fmt.Errorf("cpaas: failed creating execution: %w", err)
	}

	// Dynamic override of targets if supplied
	schedCopy := *sched
	schedCopy.TargetURLs = targets
	if req.Profile != "" {
		schedCopy.Profile = req.Profile
	}

	s.enqueueExecution(ctx, &schedCopy, exec)

	return &WebhookTriggerResponse{
		Accepted:       true,
		ExecutionID:    exec.ID,
		ScheduleID:     sched.ID,
		Message:        "CI/CD assessment successfully queued",
		ScheduledAt:    now,
		IdempotencyKey: idempKey,
	}, nil
}

// TriggerScheduleNow immediately schedules an execution for an existing schedule.
func (s *CPaaSScheduler) TriggerScheduleNow(ctx context.Context, scheduleID string) (*ScheduledExecution, error) {
	sched, err := s.store.GetSchedule(ctx, scheduleID)
	if err != nil {
		return nil, err
	}

	now := s.clock().UTC()
	idempKey := fmt.Sprintf("manual_%s_%d", scheduleID, now.UnixNano())

	exec := &ScheduledExecution{
		ID:             fmt.Sprintf("cpaas_exec_man_%d", now.UnixNano()),
		ScheduleID:     sched.ID,
		ClientID:       sched.ClientID,
		TriggerType:    "MANUAL",
		Status:         ExecutionStatusPending,
		IdempotencyKey: idempKey,
		ScheduledFor:   now,
	}

	if err := s.store.CreateExecution(ctx, exec); err != nil {
		return nil, err
	}

	s.enqueueExecution(ctx, sched, exec)
	return exec, nil
}

// RecoverPending inspects SQLite for pending executions and restarts them.
func (s *CPaaSScheduler) RecoverPending(ctx context.Context) (int, error) {
	if s.store == nil {
		return 0, nil
	}

	pending, err := s.store.ListPendingExecutions(ctx)
	if err != nil {
		return 0, err
	}

	count := 0
	for _, exec := range pending {
		sched, err := s.store.GetSchedule(ctx, exec.ScheduleID)
		if err != nil || !sched.Enabled {
			continue
		}
		execCopy := exec
		s.enqueueExecution(ctx, sched, &execCopy)
		count++
	}

	return count, nil
}

func (s *CPaaSScheduler) enqueueExecution(ctx context.Context, sched *ScheduleConfig, exec *ScheduledExecution) {
	s.mu.Lock()
	s.activeTasks[exec.ID] = exec
	s.mu.Unlock()

	s.wg.Add(1)
	go func() {
		defer s.wg.Done()

		// Acquire worker pool semaphore
		select {
		case s.semaphore <- struct{}{}:
			defer func() { <-s.semaphore }()
		case <-s.stopCh:
			return
		case <-ctx.Done():
			return
		}

		s.executeTask(ctx, sched, exec)

		s.mu.Lock()
		delete(s.activeTasks, exec.ID)
		s.mu.Unlock()
	}()
}

func (s *CPaaSScheduler) executeTask(ctx context.Context, sched *ScheduleConfig, exec *ScheduledExecution) {
	startTime := s.clock().UTC()
	exec.Status = ExecutionStatusRunning
	exec.StartedAt = &startTime
	_ = s.store.UpdateExecution(ctx, exec)

	// Licensing feature entitlement check (Phase 10.3)
	if !IsDevTestMode() {
		mgr := GetGlobalLicenseManager()
		if mgr != nil {
			if err := mgr.CheckFeature(FeatureCommercialCPaaS); err != nil {
				exec.Status = ExecutionStatusFailed
				exec.ErrorMessage = fmt.Sprintf("licensing refusal: %v", err)
				now := s.clock().UTC()
				exec.CompletedAt = &now
				_ = s.store.UpdateExecution(ctx, exec)
				return
			}
		}
	}

	if s.runner == nil {
		exec.Status = ExecutionStatusFailed
		exec.ErrorMessage = "no assessment runner configured"
		now := s.clock().UTC()
		exec.CompletedAt = &now
		_ = s.store.UpdateExecution(ctx, exec)
		return
	}

	// 1. Execute assessment
	curSnapshot, err := s.runner.RunAssessment(ctx, sched)
	if err != nil {
		exec.Status = ExecutionStatusFailed
		exec.ErrorMessage = err.Error()
		now := s.clock().UTC()
		exec.CompletedAt = &now
		_ = s.store.UpdateExecution(ctx, exec)
		return
	}

	exec.AssessmentID = curSnapshot.AssessmentID
	exec.FindingsCount = len(curSnapshot.Findings)

	// 2. Fetch baseline snapshot
	s.snapshotCacheMu.Lock()
	baseSnapshot := s.lastSnapshot[sched.ID]
	s.snapshotCache[curSnapshot.AssessmentID] = curSnapshot
	s.lastSnapshot[sched.ID] = curSnapshot
	s.snapshotCacheMu.Unlock()

	// 3. Compute Attack Surface Drift
	var driftReport *DriftReport
	if s.driftEngine != nil {
		driftReport, err = s.driftEngine.Compare(sched.ID, baseSnapshot, curSnapshot)
		if err == nil && driftReport != nil {
			exec.DriftReportID = driftReport.ID
			exec.VerifiedDefectsCount = driftReport.NewlyVerifiedDefectsCount
			_ = s.store.SaveDriftReport(ctx, driftReport)

			// 4. Dispatch smart notifications (strictly gated to VERIFIED_DEFECT)
			if s.notifier != nil {
				alertResults, _ := s.notifier.DispatchAlerts(ctx, sched, driftReport, curSnapshot)
				deliveredCount := 0
				for _, ar := range alertResults {
					if ar.Delivered {
						deliveredCount++
					}
				}
				exec.AlertsDispatched = deliveredCount
			}
		}
	}

	// 5. Finalize execution status
	completeTime := s.clock().UTC()
	exec.Status = ExecutionStatusCompleted
	exec.CompletedAt = &completeTime
	_ = s.store.UpdateExecution(ctx, exec)
}

// SetSnapshot stores an explicit baseline snapshot for tests.
func (s *CPaaSScheduler) SetSnapshot(scheduleID string, snap *AttackSurfaceSnapshot) {
	s.snapshotCacheMu.Lock()
	defer s.snapshotCacheMu.Unlock()
	s.snapshotCache[snap.AssessmentID] = snap
	s.lastSnapshot[scheduleID] = snap
}

// -----------------------------------------------------------------------------
// Cron and Schedule Math Engine
// -----------------------------------------------------------------------------

// CalculateNextRun determines the next trigger timestamp based on schedule type and expression.
func CalculateNextRun(schedType ScheduleType, expr string, referenceTime time.Time) (time.Time, error) {
	ref := referenceTime.UTC()

	switch schedType {
	case ScheduleTypeMonthly:
		// Monthly runs on the 1st day of the next month at 00:00:00 UTC
		year, month, _ := ref.Date()
		firstOfCurrentMonth := time.Date(year, month, 1, 0, 0, 0, 0, time.UTC)
		if ref.Before(firstOfCurrentMonth) {
			return firstOfCurrentMonth, nil
		}
		// Next month
		nextMonth := month + 1
		nextYear := year
		if nextMonth > 12 {
			nextMonth = 1
			nextYear++
		}
		return time.Date(nextYear, nextMonth, 1, 0, 0, 0, 0, time.UTC), nil

	case ScheduleTypeCron:
		return parseCronNext(expr, ref)

	case ScheduleTypeWebhook:
		return time.Time{}, nil // Webhooks do not possess a fixed scheduled next run

	default:
		return time.Time{}, fmt.Errorf("cpaas: unsupported schedule type %q", schedType)
	}
}

func parseCronNext(expr string, ref time.Time) (time.Time, error) {
	clean := strings.TrimSpace(strings.ToLower(expr))

	switch clean {
	case "@monthly", "0 0 1 * *":
		year, month, _ := ref.Date()
		nextMonth := month + 1
		nextYear := year
		if nextMonth > 12 {
			nextMonth = 1
			nextYear++
		}
		return time.Date(nextYear, nextMonth, 1, 0, 0, 0, 0, time.UTC), nil

	case "@weekly":
		// Next Sunday at 00:00:00 UTC
		daysUntilSunday := (7 - int(ref.Weekday())) % 7
		if daysUntilSunday == 0 {
			daysUntilSunday = 7
		}
		target := ref.AddDate(0, 0, daysUntilSunday)
		return time.Date(target.Year(), target.Month(), target.Day(), 0, 0, 0, 0, time.UTC), nil

	case "@daily", "@midnight", "0 0 * * *":
		nextDay := ref.AddDate(0, 0, 1)
		return time.Date(nextDay.Year(), nextDay.Month(), nextDay.Day(), 0, 0, 0, 0, time.UTC), nil

	case "@hourly", "0 * * * *":
		nextHour := ref.Truncate(time.Hour).Add(time.Hour)
		return nextHour, nil
	}

	// Standard 5-field cron: minute hour dom month dow
	fields := strings.Fields(clean)
	if len(fields) == 5 {
		// Interval minute syntax: */N * * * *
		if strings.HasPrefix(fields[0], "*/") && fields[1] == "*" && fields[2] == "*" && fields[3] == "*" && fields[4] == "*" {
			stepStr := strings.TrimPrefix(fields[0], "*/")
			step, err := strconv.Atoi(stepStr)
			if err == nil && step > 0 && step <= 60 {
				dur := time.Duration(step) * time.Minute
				next := ref.Truncate(dur).Add(dur)
				return next, nil
			}
		}

		// Fixed minute/hour syntax: M H * * *
		min, errM := strconv.Atoi(fields[0])
		hr, errH := strconv.Atoi(fields[1])
		if errM == nil && errH == nil && fields[2] == "*" && fields[3] == "*" && fields[4] == "*" {
			candidate := time.Date(ref.Year(), ref.Month(), ref.Day(), hr, min, 0, 0, time.UTC)
			if !candidate.After(ref) {
				candidate = candidate.AddDate(0, 0, 1)
			}
			return candidate, nil
		}
	}

	return time.Time{}, fmt.Errorf("cpaas: unsupported or invalid cron expression %q", expr)
}

func computeHMACSHA256(secret, message string) string {
	h := hmac.New(sha256.New, []byte(secret))
	h.Write([]byte(message))
	return hex.EncodeToString(h.Sum(nil))
}

func subtleConstantTimeCompare(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	var res byte
	for i := 0; i < len(a); i++ {
		res |= a[i] ^ b[i]
	}
	return res == 0
}
