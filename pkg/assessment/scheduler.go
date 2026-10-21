package assessment

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
)

// AssessmentRunner defines the execution engine capable of running assessments.
// Both *Controller and mock runners in tests satisfy this interface.
type AssessmentRunner interface {
	RunAssessment(ctx context.Context, assessmentID string, opts ExecutionOptions) (*ExecutionResult, error)
}

// SchedulerConfig holds runtime configuration for the assessment scheduler.
type SchedulerConfig struct {
	PollInterval    time.Duration // How often to check for due schedules (default: 10s)
	MaxConcurrency  int           // Maximum concurrent assessment executions (default: 4)
	ClaimBatchSize  int           // Maximum schedules to claim per tick (default: 10)
	ShutdownTimeout time.Duration // Graceful shutdown wait time (default: 30s)
	Logger          func(format string, args ...any)
}

// DefaultSchedulerConfig provides safe production defaults.
func DefaultSchedulerConfig() SchedulerConfig {
	return SchedulerConfig{
		PollInterval:    10 * time.Second,
		MaxConcurrency:  4,
		ClaimBatchSize:  10,
		ShutdownTimeout: 30 * time.Second,
		Logger:          nil,
	}
}

// Scheduler coordinates the periodic execution of assessment schedules.
type Scheduler struct {
	store    Store
	runner   AssessmentRunner
	cfg      SchedulerConfig
	mu       sync.Mutex
	running  bool
	cancel   context.CancelFunc
	wg       sync.WaitGroup
	activeWg sync.WaitGroup
	workerCh chan struct{}
}

// NewScheduler creates a new assessment scheduler instance.
func NewScheduler(store Store, runner AssessmentRunner, cfg SchedulerConfig) *Scheduler {
	if cfg.PollInterval <= 0 {
		cfg.PollInterval = 10 * time.Second
	}
	if cfg.MaxConcurrency <= 0 {
		cfg.MaxConcurrency = 4
	}
	if cfg.ClaimBatchSize <= 0 {
		cfg.ClaimBatchSize = 10
	}
	if cfg.ShutdownTimeout <= 0 {
		cfg.ShutdownTimeout = 30 * time.Second
	}

	return &Scheduler{
		store:    store,
		runner:   runner,
		cfg:      cfg,
		workerCh: make(chan struct{}, cfg.MaxConcurrency),
	}
}

// Start begins background polling for due schedules.
func (s *Scheduler) Start(ctx context.Context) error {
	s.mu.Lock()
	if s.running {
		s.mu.Unlock()
		return fmt.Errorf("scheduler already running")
	}
	schedCtx, cancel := context.WithCancel(ctx)
	s.cancel = cancel
	s.running = true
	s.mu.Unlock()

	s.wg.Add(1)
	go s.runLoop(schedCtx)

	return nil
}

// Stop initiates graceful shutdown, waiting for active dispatches up to ShutdownTimeout.
func (s *Scheduler) Stop() error {
	s.mu.Lock()
	if !s.running {
		s.mu.Unlock()
		return nil
	}
	s.running = false
	if s.cancel != nil {
		s.cancel()
	}
	s.mu.Unlock()

	done := make(chan struct{})
	go func() {
		s.wg.Wait()
		s.activeWg.Wait()
		close(done)
	}()

	select {
	case <-done:
		return nil
	case <-time.After(s.cfg.ShutdownTimeout):
		return fmt.Errorf("scheduler shutdown timed out after %v", s.cfg.ShutdownTimeout)
	}
}

// IsRunning reports whether the background scheduler loop is active.
func (s *Scheduler) IsRunning() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.running
}

// RunDueSchedules queries, claims, and asynchronously dispatches all due schedules at the given time.
func (s *Scheduler) RunDueSchedules(ctx context.Context, now time.Time) (int, error) {
	claimed, err := s.store.ClaimDueSchedules(now, s.cfg.ClaimBatchSize)
	if err != nil {
		return 0, fmt.Errorf("failed claiming due schedules: %w", err)
	}
	if len(claimed) == 0 {
		return 0, nil
	}

	dispatched := 0
	for _, sched := range claimed {
		select {
		case s.workerCh <- struct{}{}:
		case <-ctx.Done():
			return dispatched, ctx.Err()
		}

		s.activeWg.Add(1)
		go func(sch *AssessmentSchedule) {
			defer func() {
				<-s.workerCh
				s.activeWg.Done()
			}()
			s.executeSchedule(ctx, sch, now)
		}(sched)

		dispatched++
	}

	return dispatched, nil
}

// RunDueSchedulesSync claims and executes all due schedules, waiting for completion before returning.
// Suitable for CLI manual invocation and deterministic unit/regression tests.
func (s *Scheduler) RunDueSchedulesSync(ctx context.Context, now time.Time) (int, error) {
	dispatched, err := s.RunDueSchedules(ctx, now)
	if err != nil {
		return dispatched, err
	}
	s.activeWg.Wait()
	return dispatched, nil
}

// executeSchedule conducts pre-execution authorization/scope verification and executes the assessment.
func (s *Scheduler) executeSchedule(ctx context.Context, sch *AssessmentSchedule, scheduledFor time.Time) {
	occurrenceKey := fmt.Sprintf("sched:%s:%s", sch.ID, scheduledFor.UTC().Format(time.RFC3339))

	existingDisp, err := s.store.GetScheduleDispatchByOccurrence(sch.ID, scheduledFor)
	if err == nil && existingDisp != nil {
		if existingDisp.Status == "COMPLETED" || existingDisp.Status == "RUNNING" {
			return
		}
	}

	dispID := fmt.Sprintf("disp:%s:%s", sch.ID, scheduledFor.UTC().Format(time.RFC3339))
	disp := &ScheduleDispatchRecord{
		ID:           dispID,
		ScheduleID:   sch.ID,
		AssessmentID: sch.AssessmentID,
		TenantID:     sch.TenantID,
		AccountID:    sch.AccountID,
		ScheduledFor: scheduledFor,
		DispatchedAt: time.Now().UTC(),
		Status:       "RUNNING",
	}

	if err := s.store.RecordScheduleDispatch(disp); err != nil {
		return
	}

	// Pre-execution Verification 1: Assessment status & existence
	asm, err := s.store.GetAssessment(sch.AssessmentID)
	if err != nil || asm == nil {
		comp := time.Now().UTC()
		reason := fmt.Sprintf("underlying assessment not found: %v", err)
		disp.Status = "FAILED"
		disp.ErrorMessage = reason
		disp.CompletedAt = &comp

		execID := "exec-" + uuid.New().String()
		_ = s.store.CreateExecution(&AssessmentExecution{
			ID:               execID,
			AssessmentID:     sch.AssessmentID,
			ScheduleID:       sch.ID,
			ScheduledFor:     &scheduledFor,
			ClientID:         sch.ClientID,
			TenantID:         sch.TenantID,
			AccountID:        sch.AccountID,
			InitiationSource: "scheduled",
			Status:           StatusFailed,
			StartedAt:        comp,
			CompletedAt:      &comp,
			ErrorMessage:     reason,
			CreatedAt:        comp,
			UpdatedAt:        comp,
		})
		disp.ExecutionID = execID
		_ = s.store.RecordScheduleDispatch(disp)
		return
	}

	if asm.Status != StatusReady && asm.Status != StatusDraft && asm.Status != StatusCompleted && asm.Status != StatusCompletedWithErrors && asm.Status != StatusFailed {
		comp := time.Now().UTC()
		reason := fmt.Sprintf("assessment is in %s state (cannot execute)", asm.Status)
		disp.Status = "SKIPPED"
		disp.ErrorMessage = reason
		disp.CompletedAt = &comp

		execID := "exec-" + uuid.New().String()
		_ = s.store.CreateExecution(&AssessmentExecution{
			ID:               execID,
			AssessmentID:     sch.AssessmentID,
			ScheduleID:       sch.ID,
			ScheduledFor:     &scheduledFor,
			ClientID:         sch.ClientID,
			TenantID:         sch.TenantID,
			AccountID:        sch.AccountID,
			InitiationSource: "scheduled",
			Status:           StatusSkipped,
			StartedAt:        comp,
			CompletedAt:      &comp,
			ErrorMessage:     reason,
			CreatedAt:        comp,
			UpdatedAt:        comp,
		})
		disp.ExecutionID = execID
		_ = s.store.RecordScheduleDispatch(disp)
		return
	}

	// Pre-execution Verification 2: Authorization validity
	authRecord, err := s.store.GetAuthorization(sch.AssessmentID)
	if err != nil || authRecord == nil {
		comp := time.Now().UTC()
		reason := "assessment lacks execution authorization record"
		disp.Status = "FAILED"
		disp.ErrorMessage = reason
		disp.CompletedAt = &comp

		execID := "exec-" + uuid.New().String()
		_ = s.store.CreateExecution(&AssessmentExecution{
			ID:               execID,
			AssessmentID:     sch.AssessmentID,
			ScheduleID:       sch.ID,
			ScheduledFor:     &scheduledFor,
			ClientID:         sch.ClientID,
			TenantID:         sch.TenantID,
			AccountID:        sch.AccountID,
			InitiationSource: "scheduled",
			Status:           StatusFailed,
			StartedAt:        comp,
			CompletedAt:      &comp,
			ErrorMessage:     reason,
			CreatedAt:        comp,
			UpdatedAt:        comp,
		})
		disp.ExecutionID = execID
		_ = s.store.RecordScheduleDispatch(disp)
		return
	}
	if valid, reason := authRecord.IsCurrentlyValid(scheduledFor); !valid {
		comp := time.Now().UTC()
		refusalReason := fmt.Sprintf("assessment authorization invalid: %s", reason)
		disp.Status = "SKIPPED"
		disp.ErrorMessage = refusalReason
		disp.CompletedAt = &comp

		execID := "exec-" + uuid.New().String()
		_ = s.store.CreateExecution(&AssessmentExecution{
			ID:               execID,
			AssessmentID:     sch.AssessmentID,
			ScheduleID:       sch.ID,
			ScheduledFor:     &scheduledFor,
			ClientID:         sch.ClientID,
			TenantID:         sch.TenantID,
			AccountID:        sch.AccountID,
			InitiationSource: "scheduled",
			Status:           StatusSkipped,
			StartedAt:        comp,
			CompletedAt:      &comp,
			ErrorMessage:     refusalReason,
			CreatedAt:        comp,
			UpdatedAt:        comp,
		})
		disp.ExecutionID = execID
		_ = s.store.RecordScheduleDispatch(disp)
		return
	}

	// Pre-execution Verification 3: Target scope check
	targets, err := s.store.GetTargets(sch.AssessmentID)
	if err != nil || len(targets) == 0 {
		comp := time.Now().UTC()
		reason := "assessment has no configured targets"
		disp.Status = "FAILED"
		disp.ErrorMessage = reason
		disp.CompletedAt = &comp

		execID := "exec-" + uuid.New().String()
		_ = s.store.CreateExecution(&AssessmentExecution{
			ID:               execID,
			AssessmentID:     sch.AssessmentID,
			ScheduleID:       sch.ID,
			ScheduledFor:     &scheduledFor,
			ClientID:         sch.ClientID,
			TenantID:         sch.TenantID,
			AccountID:        sch.AccountID,
			InitiationSource: "scheduled",
			Status:           StatusFailed,
			StartedAt:        comp,
			CompletedAt:      &comp,
			ErrorMessage:     reason,
			CreatedAt:        comp,
			UpdatedAt:        comp,
		})
		disp.ExecutionID = execID
		_ = s.store.RecordScheduleDispatch(disp)
		return
	}
	hasApproved := false
	for _, t := range targets {
		if t.ScopeStatus == "APPROVED" {
			hasApproved = true
			break
		}
	}
	if !hasApproved {
		comp := time.Now().UTC()
		reason := "assessment has no approved targets in scope"
		disp.Status = "SKIPPED"
		disp.ErrorMessage = reason
		disp.CompletedAt = &comp

		execID := "exec-" + uuid.New().String()
		_ = s.store.CreateExecution(&AssessmentExecution{
			ID:               execID,
			AssessmentID:     sch.AssessmentID,
			ScheduleID:       sch.ID,
			ScheduledFor:     &scheduledFor,
			ClientID:         sch.ClientID,
			TenantID:         sch.TenantID,
			AccountID:        sch.AccountID,
			InitiationSource: "scheduled",
			Status:           StatusSkipped,
			StartedAt:        comp,
			CompletedAt:      &comp,
			ErrorMessage:     reason,
			CreatedAt:        comp,
			UpdatedAt:        comp,
		})
		disp.ExecutionID = execID
		_ = s.store.RecordScheduleDispatch(disp)
		return
	}

	// Execution
	execOpts := sch.ExecutionOptions.ToExecutionOptions()
	execOpts.ScheduleID = sch.ID
	execOpts.ScheduledFor = &scheduledFor
	execOpts.InitiationSource = "scheduled"
	execOpts.TenantID = sch.TenantID
	execOpts.AccountID = sch.AccountID
	execOpts.IdempotencyKey = occurrenceKey
	res, execErr := s.runner.RunAssessment(ctx, sch.AssessmentID, execOpts)

	completedAt := time.Now().UTC()
	disp.CompletedAt = &completedAt

	if execErr != nil {
		if errors.Is(execErr, ErrExecutionOverlap) || strings.Contains(execErr.Error(), "already has active execution") || strings.Contains(execErr.Error(), "already running") {
			disp.Status = "SKIPPED"
			disp.ErrorMessage = "previous execution still in progress; overlapping execution prevented"
			_ = s.store.RecordScheduleDispatch(disp)
			return
		}
		if strings.Contains(execErr.Error(), "security refusal") {
			disp.Status = "SKIPPED"
		} else {
			disp.Status = "FAILED"
		}
		disp.ErrorMessage = execErr.Error()
		_ = s.store.RecordScheduleDispatch(disp)
		return
	}

	disp.Status = "COMPLETED"
	if res != nil && res.Execution != nil {
		disp.ExecutionID = res.Execution.ID
	}
	_ = s.store.RecordScheduleDispatch(disp)
}

// ReconcileAbandonedExecutions performs a safe recovery sweep across abandoned executions and dispatches.
func (s *Scheduler) ReconcileAbandonedExecutions(ctx context.Context, now time.Time) (*RecoverySummary, error) {
	opts := RecoveryOptions{
		Auth:          NewAdminAuthContext(),
		StaleDuration: 3 * time.Minute,
		MaxRetries:    3,
		WorkerID:      "scheduler-reconciler",
		AllowResume:   false,
	}
	summary, err := s.store.RecoverExecutions(opts)
	if err != nil && s.cfg.Logger != nil {
		s.cfg.Logger("[-] Scheduler recovery sweep error: %v", err)
	}
	// Reconcile any terminal executions that crashed before lifecycle notification enqueue (unbounded lookback so offline gaps never lose alerts)
	_, _ = s.store.ReconcileExecutionNotifications(opts.Auth, 0)
	return summary, err
}

// runLoop executes the polling ticker.
func (s *Scheduler) runLoop(ctx context.Context) {
	defer s.wg.Done()

	ticker := time.NewTicker(s.cfg.PollInterval)
	defer ticker.Stop()

	// Initial check and recovery sweep on start
	nowInit := time.Now().UTC()
	_, _ = s.ReconcileAbandonedExecutions(ctx, nowInit)
	_, _ = s.RunDueSchedules(ctx, nowInit)

	recoveryTickCounter := 0

	for {
		select {
		case <-ctx.Done():
			return
		case now := <-ticker.C:
			recoveryTickCounter++
			if recoveryTickCounter >= 6 {
				recoveryTickCounter = 0
				_, _ = s.ReconcileAbandonedExecutions(ctx, now.UTC())
			}
			_, _ = s.RunDueSchedules(ctx, now.UTC())
		}
	}
}
