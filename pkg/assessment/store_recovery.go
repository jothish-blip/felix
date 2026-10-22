package assessment

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"strings"

	"felix/pkg/config"
	"felix/pkg/notify"
	"felix/pkg/provenance"
	"github.com/google/uuid"
)

// ClaimExecutionOwnership establishes or refreshes an active worker lease on an execution.
func (s *SQLiteStore) ClaimExecutionOwnership(execID, workerID string, leaseDuration time.Duration) (bool, error) {
	if execID == "" || workerID == "" {
		return false, fmt.Errorf("execution ID and worker ID required")
	}
	if leaseDuration <= 0 {
		leaseDuration = 5 * time.Minute
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now().UTC()
	leaseExp := now.Add(leaseDuration)

	res, err := s.db.Exec(`
		UPDATE assessment_executions
		SET worker_id = ?, heartbeat_at = ?, lease_expires_at = ?, updated_at = ?
		WHERE id = ?
		  AND status NOT IN ('COMPLETED', 'COMPLETED_WITH_ERRORS', 'FAILED', 'CANCELLED', 'SKIPPED', 'INTERRUPTED')
		  AND (worker_id IS NULL OR worker_id = '' OR worker_id = ? OR lease_expires_at IS NULL OR lease_expires_at < ?)
	`, workerID, now, leaseExp, now, execID, workerID, now)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return n > 0, err
}

// HeartbeatExecution updates the worker heartbeat, lease expiry, and checkpoint progress.
// If the worker no longer holds ownership or lease expired and was claimed, ErrLeaseLost is returned.
func (s *SQLiteStore) HeartbeatExecution(execID, workerID string, checkpoint *ScanCheckpoint, leaseDuration time.Duration) error {
	if execID == "" || workerID == "" {
		return fmt.Errorf("execution ID and worker ID required")
	}
	if leaseDuration <= 0 {
		leaseDuration = 5 * time.Minute
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now().UTC()
	leaseExp := now.Add(leaseDuration)

	// Verify current ownership
	var curWorker sql.NullString
	var curStatus string
	var curLeaseExp sql.NullTime
	err := s.db.QueryRow(`
		SELECT worker_id, status, lease_expires_at FROM assessment_executions WHERE id = ?
	`, execID).Scan(&curWorker, &curStatus, &curLeaseExp)
	if err == sql.ErrNoRows {
		return fmt.Errorf("%w: execution %s", ErrExecutionNotFound, execID)
	}
	if err != nil {
		return err
	}

	if IsTerminalExecutionStatus(AssessmentStatus(curStatus)) {
		return ErrExecutionTerminal
	}

	// If ownership was usurped by another worker or nullified
	if !curWorker.Valid || curWorker.String != workerID {
		return ErrLeaseLost
	}

	// If lease expired in the past and another process could claim it
	if curLeaseExp.Valid && curLeaseExp.Time.Before(now) {
		// Stale worker tried to heartbeat after its lease expired
		return ErrLeaseLost
	}

	var chkJSON any
	if checkpoint != nil {
		checkpoint.UpdatedAt = now
		b, err := json.Marshal(checkpoint)
		if err != nil {
			return fmt.Errorf("failed marshaling checkpoint: %w", err)
		}
		chkJSON = string(b)
	}

	if chkJSON != nil {
		_, err = s.db.Exec(`
			UPDATE assessment_executions
			SET heartbeat_at = ?, lease_expires_at = ?, checkpoint_json = ?, updated_at = ?
			WHERE id = ? AND worker_id = ?
		`, now, leaseExp, chkJSON, now, execID, workerID)
	} else {
		_, err = s.db.Exec(`
			UPDATE assessment_executions
			SET heartbeat_at = ?, lease_expires_at = ?, updated_at = ?
			WHERE id = ? AND worker_id = ?
		`, now, leaseExp, now, execID, workerID)
	}
	return err
}

// ClaimAbandonedExecutionForRecovery atomically transfers lease ownership of an abandoned execution to recoveryWorkerID.
func (s *SQLiteStore) ClaimAbandonedExecutionForRecovery(execID, recoveryWorkerID string, now time.Time, leaseDuration time.Duration) (bool, error) {
	if execID == "" || recoveryWorkerID == "" {
		return false, fmt.Errorf("execution ID and recovery worker ID required")
	}
	if leaseDuration <= 0 {
		leaseDuration = 5 * time.Minute
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	leaseExp := now.Add(leaseDuration)

	s.mu.Lock()
	defer s.mu.Unlock()

	res, err := s.db.Exec(`
		UPDATE assessment_executions
		SET worker_id = ?, heartbeat_at = ?, lease_expires_at = ?,
		    recovery_attempts = recovery_attempts + 1, last_recovery_at = ?, updated_at = ?
		WHERE id = ?
		  AND status NOT IN ('COMPLETED', 'COMPLETED_WITH_ERRORS', 'FAILED', 'CANCELLED', 'SKIPPED', 'INTERRUPTED')
		  AND (lease_expires_at IS NULL OR lease_expires_at <= ?)
	`, recoveryWorkerID, now, leaseExp, now, now, execID, now)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return n > 0, err
}

// FindAbandonedExecutions queries for non-terminal executions whose heartbeat or lease has expired.
func (s *SQLiteStore) FindAbandonedExecutions(staleThreshold time.Time, opts RecoveryOptions) ([]AssessmentExecution, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if staleThreshold.IsZero() {
		staleThreshold = time.Now().UTC().Add(-3 * time.Minute)
	}

	query := `
		SELECT id, assessment_id, schedule_id, scheduled_for, client_id, tenant_id, account_id,
		       initiation_source, assessment_type, status, started_at, completed_at, duration_ms,
		       request_count, target_count, finding_count, snapshot_id, error_message, config_snapshot,
		       worker_id, heartbeat_at, lease_expires_at, recovery_attempts, last_recovery_at,
		       recovery_reason, checkpoint_json, idempotency_key, created_at, updated_at
		FROM assessment_executions
		WHERE status NOT IN ('COMPLETED', 'COMPLETED_WITH_ERRORS', 'FAILED', 'CANCELLED', 'SKIPPED', 'INTERRUPTED')
		  AND completed_at IS NULL
		  AND (lease_expires_at IS NULL OR lease_expires_at <= ?)
		  AND (
		      (lease_expires_at IS NOT NULL)
		      OR (heartbeat_at IS NOT NULL AND heartbeat_at <= ?)
		      OR (heartbeat_at IS NULL AND COALESCE(started_at, created_at) <= ?)
		  )
	`
	nowUTC := time.Now().UTC()
	args := []any{nowUTC, staleThreshold, staleThreshold}

	if opts.ExecutionID != "" {
		query += ` AND id = ?`
		args = append(args, opts.ExecutionID)
	}
	if opts.AssessmentID != "" {
		query += ` AND assessment_id = ?`
		args = append(args, s.resolveAssessmentID(opts.AssessmentID))
	}

	query += ` ORDER BY COALESCE(started_at, created_at) ASC`

	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed querying abandoned executions: %w", err)
	}
	defer rows.Close()

	var execs []AssessmentExecution
	for rows.Next() {
		exec, err := scanExecutionRows(rows)
		if err != nil {
			return nil, fmt.Errorf("failed scanning execution row: %w", err)
		}
		if opts.Auth.Authorizes(exec.ClientID, exec.TenantID, exec.AccountID) {
			execs = append(execs, *exec)
		}
	}
	return execs, rows.Err()
}

// FinalizeAbandonedExecution safely seals an abandoned execution, preserving all findings and creating a partial snapshot.
func (s *SQLiteStore) FinalizeAbandonedExecution(execID, recoveryWorkerID string, finalStatus AssessmentStatus, reason string, auth TenantAuthContext) (*ExecutionRecoveryResult, error) {
	if execID == "" {
		return nil, fmt.Errorf("execution ID required")
	}
	if finalStatus == "" {
		finalStatus = StatusInterrupted
	}
	if reason == "" {
		reason = "Assessment execution abandoned and recovered safely as interrupted"
	}

	exec, err := s.GetExecution(execID)
	if err != nil {
		return nil, err
	}
	if !auth.Authorizes(exec.ClientID, exec.TenantID, exec.AccountID) {
		return nil, ErrExecutionUnauthorized
	}
	if IsTerminalExecutionStatus(exec.Status) {
		return &ExecutionRecoveryResult{
			ExecutionID:       exec.ID,
			AssessmentID:      exec.AssessmentID,
			PreviousStatus:    exec.Status,
			NewStatus:         exec.Status,
			Action:            ActionSkippedTerminal,
			Reason:            "execution already in terminal state",
			RecoveredAt:       time.Now().UTC(),
			PreservedFindings: exec.FindingCount,
		}, nil
	}

	// Retrieve partial findings already saved
	findings, _ := s.GetFindings(exec.AssessmentID, exec.ID)
	dedupedFindings := DeduplicateAssessmentFindings(findings)

	// Fetch parent assessment
	asm, err := s.GetAssessment(exec.AssessmentID)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch assessment %s: %w", exec.AssessmentID, err)
	}

	targets, _ := s.GetTargets(exec.AssessmentID)
	var targetURLs []string
	for _, t := range targets {
		if t.ScopeStatus == "APPROVED" {
			targetURLs = append(targetURLs, t.TargetURL)
		}
	}

	now := time.Now().UTC()
	durMs := exec.DurationMs
	if durMs <= 0 && !exec.StartedAt.IsZero() {
		durMs = now.Sub(exec.StartedAt).Milliseconds()
		if durMs < 0 {
			durMs = 0
		}
	}

	prov := exec.GetProvenance()
	if prov != nil {
		prov.Finalize(provenance.FinalizeOptions{
			Status:          string(finalStatus),
			FailureCategory: "INCOMPLETE",
			ExitCode:        2,
			DurationMs:      durMs,
			IsPartial:       true,
			RecoveryAction:  string(ActionFinalizedInterrupted),
			RecoveryReason:  reason,
			RecoveredAt:     &now,
		})
		exec.Provenance = prov
		exec.ConfigSnapshot.Provenance = prov
	}

	// Create durable historical snapshot for partial / interrupted assessment
	snap := BuildAssessmentSnapshot(asm, exec, targetURLs, dedupedFindings, false)
	snap.Status = finalStatus
	snap.Metadata["is_partial"] = "true"
	snap.Metadata["inconclusive"] = "true"
	snap.Metadata["recovery_action"] = string(ActionFinalizedInterrupted)
	snap.Metadata["recovery_reason"] = reason
	snap.Metadata["recovered_by"] = recoveryWorkerID
	snap.Metadata["recovered_at"] = now.Format(time.RFC3339)
	if prov != nil {
		if b, err := json.Marshal(prov); err == nil {
			snap.Metadata["provenance"] = string(b)
		}
	}

	if exec.CheckpointJSON != "" {
		var chk ScanCheckpoint
		if err := json.Unmarshal([]byte(exec.CheckpointJSON), &chk); err == nil {
			snap.SetAssessedTargets(chk.CompletedTargets)
			snap.Metadata["checkpoint_stage"] = chk.Stage
		}
	}

	histEvidence := ExtractHistoricalEvidence(snap.ID, dedupedFindings)
	hasSnap := false
	if err := s.CreateSnapshot(snap, dedupedFindings, histEvidence); err != nil {
		snap = nil
	} else {
		hasSnap = true
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	snapIDVal := ""
	if snap != nil {
		snapIDVal = snap.ID
	}

	cfgJSON, _ := json.Marshal(exec.ConfigSnapshot)

	tx, err := s.db.Begin()
	if err != nil {
		return nil, fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback()

	res, err := tx.Exec(`
		UPDATE assessment_executions
		SET status = ?, completed_at = ?, duration_ms = ?, finding_count = ?,
		    snapshot_id = CASE WHEN snapshot_id IS NOT NULL AND snapshot_id != '' THEN snapshot_id ELSE ? END,
		    error_message = ?, recovery_reason = ?, config_snapshot = ?, updated_at = ?
		WHERE id = ?
		  AND status NOT IN ('COMPLETED', 'COMPLETED_WITH_ERRORS', 'FAILED', 'CANCELLED', 'SKIPPED', 'INTERRUPTED')
		  AND (worker_id = ? OR worker_id IS NULL OR worker_id = '' OR lease_expires_at IS NULL OR lease_expires_at <= ?)
	`, string(finalStatus), now, durMs, len(dedupedFindings), snapIDVal, reason, reason, string(cfgJSON), now, exec.ID, recoveryWorkerID, now)
	if err != nil {
		return nil, fmt.Errorf("failed finalizing execution record: %w", err)
	}

	rows, err := res.RowsAffected()
	if err != nil {
		return nil, err
	}
	if rows == 0 {
		var curStatus string
		var curWorker sql.NullString
		var curLeaseExp sql.NullTime
		_ = tx.QueryRow(`SELECT status, worker_id, lease_expires_at FROM assessment_executions WHERE id = ?`, exec.ID).Scan(&curStatus, &curWorker, &curLeaseExp)
		if IsTerminalExecutionStatus(AssessmentStatus(curStatus)) {
			return &ExecutionRecoveryResult{
				ExecutionID:       exec.ID,
				AssessmentID:      exec.AssessmentID,
				PreviousStatus:    AssessmentStatus(curStatus),
				NewStatus:         AssessmentStatus(curStatus),
				Action:            ActionSkippedTerminal,
				Reason:            "execution already in terminal state",
				RecoveredAt:       now,
				PreservedFindings: exec.FindingCount,
			}, nil
		}
		return &ExecutionRecoveryResult{
			ExecutionID:       exec.ID,
			AssessmentID:      exec.AssessmentID,
			PreviousStatus:    AssessmentStatus(curStatus),
			NewStatus:         AssessmentStatus(curStatus),
			Action:            ActionSkippedNoOwnership,
			Reason:            fmt.Sprintf("cannot finalize execution: actively leased by worker %q until %v", curWorker.String, curLeaseExp.Time),
			RecoveredAt:       now,
			PreservedFindings: exec.FindingCount,
		}, nil
	}

	if _, err := tx.Exec(`UPDATE assessments SET status = ?, updated_at = ? WHERE id = ?`,
		string(finalStatus), now, exec.AssessmentID); err != nil {
		return nil, fmt.Errorf("failed updating parent assessment status: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("failed committing execution finalization: %w", err)
	}

	// Emit recovery interruption notification if configured
	go func() {
		cfg, err := config.LoadWithEnv("")
		if err != nil || !cfg.Notification.Enabled {
			return
		}
		notifyInterrupted := false
		for _, evt := range cfg.Notification.NotifyOnLifecycle {
			if strings.ToLower(strings.TrimSpace(evt)) == "interrupted" {
				notifyInterrupted = true
				break
			}
		}
		if notifyInterrupted {
			notif := notify.BuildLifecycleNotification(
				exec.TenantID, exec.AccountID, exec.AssessmentID, asm.Ref, exec.ID,
				string(finalStatus), len(dedupedFindings), time.Duration(durMs)*time.Millisecond, reason, now,
			)
			if notify.MeetsSeverityThreshold(notif.Severity, cfg.Notification.MinSeverity) {
				if s.EnqueueNotification(notif) == nil && cfg.Notification.WebhookURL != "" {
					webhookCfg := notify.WebhookConfig{
						URL:               cfg.Notification.WebhookURL,
						Secret:            cfg.Notification.WebhookSecret,
						PreviousSecret:    cfg.Notification.WebhookPreviousSecret,
						RequireSigning:    cfg.Notification.RequireSigning,
						Timeout:           time.Duration(cfg.Notification.TimeoutSeconds) * time.Second,
						AllowInsecureHTTP: cfg.Notification.AllowInsecureHTTP,
						AllowPrivateIPs:   cfg.Notification.AllowPrivateIPs,
						AllowLoopback:     cfg.Notification.AllowLoopback,
					}
					if provider, pErr := notify.NewProvider(webhookCfg, cfg.Notification.Provider); pErr == nil {
						dispatcher := notify.NewOutboxDispatcher(s, provider, notify.DispatcherConfig{Concurrency: cfg.Notification.Concurrency})
						dispatchCtx, cancel := context.WithTimeout(context.Background(), time.Duration(cfg.Notification.TimeoutSeconds*3)*time.Second)
						defer cancel()
						_, _ = dispatcher.DispatchBatch(dispatchCtx, cfg.Notification.Concurrency)
					}
				}
			}
		}
	}()

	return &ExecutionRecoveryResult{
		ExecutionID:       exec.ID,
		AssessmentID:      exec.AssessmentID,
		PreviousStatus:    exec.Status,
		NewStatus:         finalStatus,
		Action:            ActionFinalizedInterrupted,
		Reason:            reason,
		RecoveredAt:       now,
		HasSnapshot:       hasSnap,
		PreservedFindings: len(dedupedFindings),
	}, nil
}

// RecoverExecutions sweeps for and handles abandoned executions according to RecoveryOptions.
func (s *SQLiteStore) RecoverExecutions(opts RecoveryOptions) (*RecoverySummary, error) {
	if opts.StaleDuration <= 0 {
		opts.StaleDuration = 3 * time.Minute
	}
	if opts.MaxRetries <= 0 {
		opts.MaxRetries = 3
	}
	if opts.WorkerID == "" {
		opts.WorkerID = "recovery-worker-" + uuid.New().String()
	}

	threshold := time.Now().UTC().Add(-opts.StaleDuration)
	abandoned, err := s.FindAbandonedExecutions(threshold, opts)
	if err != nil {
		return nil, fmt.Errorf("failed querying abandoned executions: %w", err)
	}

	summary := &RecoverySummary{
		ExaminedCount: len(abandoned),
		Results:       make([]ExecutionRecoveryResult, 0, len(abandoned)),
	}

	now := time.Now().UTC()

	for _, exec := range abandoned {
		if opts.DryRun {
			summary.RecoveredCount++
			summary.FinalizedCount++
			summary.Results = append(summary.Results, ExecutionRecoveryResult{
				ExecutionID:       exec.ID,
				AssessmentID:      exec.AssessmentID,
				PreviousStatus:    exec.Status,
				NewStatus:         StatusInterrupted,
				Action:            ActionFinalizedInterrupted,
				Reason:            "dry-run: execution abandoned; would finalize as interrupted",
				RecoveredAt:       now,
				WasDryRun:         true,
				PreservedFindings: exec.FindingCount,
			})
			continue
		}

		// Check if recovery attempt limit exceeded
		if exec.RecoveryAttempts >= opts.MaxRetries {
			// Atomically claim ownership before permanently finalizing
			won, claimErr := s.ClaimAbandonedExecutionForRecovery(exec.ID, opts.WorkerID, now, 5*time.Minute)
			if claimErr != nil {
				summary.FailedCount++
				continue
			}
			if !won {
				summary.SkippedCount++
				summary.Results = append(summary.Results, ExecutionRecoveryResult{
					ExecutionID:    exec.ID,
					AssessmentID:   exec.AssessmentID,
					PreviousStatus: exec.Status,
					NewStatus:      exec.Status,
					Action:         ActionSkippedNoOwnership,
					Reason:         "could not acquire ownership: execution actively leased by another worker",
					RecoveredAt:    now,
				})
				continue
			}

			res, finalizeErr := s.FinalizeAbandonedExecution(
				exec.ID,
				opts.WorkerID,
				StatusInterrupted,
				fmt.Sprintf("Recovery attempts exceeded limit (%d/%d): permanently marked interrupted", exec.RecoveryAttempts, opts.MaxRetries),
				opts.Auth,
			)
			if finalizeErr != nil {
				summary.FailedCount++
				continue
			}
			res.Action = ActionSkippedExceededLimit
			summary.SkippedCount++
			summary.Results = append(summary.Results, *res)
			continue
		}

		// Atomically claim ownership
		won, claimErr := s.ClaimAbandonedExecutionForRecovery(exec.ID, opts.WorkerID, now, 5*time.Minute)
		if claimErr != nil {
			summary.FailedCount++
			continue
		}
		if !won {
			summary.SkippedCount++
			summary.Results = append(summary.Results, ExecutionRecoveryResult{
				ExecutionID:    exec.ID,
				AssessmentID:   exec.AssessmentID,
				PreviousStatus: exec.Status,
				NewStatus:      exec.Status,
				Action:         ActionSkippedNoOwnership,
				Reason:         "could not acquire ownership: execution claimed or state changed",
				RecoveredAt:    now,
			})
			continue
		}

		// Attempt safe checkpoint resumption only if requested, runner provided, engine supports checkpointing, and valid checkpoint exists
		supportsResume := NormalizeAssessmentType(exec.AssessmentType) == AssessmentTypeWebSecurity || exec.AssessmentType == ""
		if opts.AllowResume && opts.Runner != nil && exec.CheckpointJSON != "" && supportsResume {
			var chk ScanCheckpoint
			if jsonErr := json.Unmarshal([]byte(exec.CheckpointJSON), &chk); jsonErr == nil && len(chk.CompletedTargets) > 0 && len(chk.RemainingTargets) > 0 {
				runnerOpts := ExecutionOptions{
					ExecutionID:      exec.ID,
					WorkerID:         opts.WorkerID,
					ResumeCheckpoint: &chk,
					LeaseDuration:    5 * time.Minute,
					AllowLoopback:    opts.AllowLoopback,
					AllowPrivateIPs:  opts.AllowPrivateIPs,
					ProgressFunc:     func(string) {},
				}
				ctx := opts.Context
				if ctx == nil {
					ctx = context.Background()
				}
				res, runErr := opts.Runner(ctx, exec.AssessmentID, runnerOpts)
				if runErr == nil && res != nil && res.Execution != nil {
					summary.RecoveredCount++
					summary.ResumedCount++
					summary.Results = append(summary.Results, ExecutionRecoveryResult{
						ExecutionID:       exec.ID,
						AssessmentID:      exec.AssessmentID,
						PreviousStatus:    exec.Status,
						NewStatus:         res.Execution.Status,
						Action:            ActionResumed,
						Reason:            fmt.Sprintf("Safely resumed from checkpoint (%d completed, %d remaining)", len(chk.CompletedTargets), len(chk.RemainingTargets)),
						RecoveredAt:       time.Now().UTC(),
						HasSnapshot:       res.Snapshot != nil,
						PreservedFindings: res.Execution.FindingCount,
					})
					continue
				}
			}
		}

		// Safe finalization as INTERRUPTED, preserving partial findings and evidence
		reason := fmt.Sprintf("Assessment abandoned: worker %s lost; safely finalized", exec.WorkerID)
		if opts.AllowResume {
			if !supportsResume {
				reason = fmt.Sprintf("Assessment engine %s does not support checkpoint resumption; safely finalized as interrupted", exec.AssessmentType)
			} else if exec.CheckpointJSON == "" {
				reason = "Resumption requested but no valid checkpoint exists; safely finalized as interrupted"
			} else if opts.Runner == nil {
				reason = "Resumption requested but no execution runner provided; safely finalized as interrupted"
			}
		}
		res, finalizeErr := s.FinalizeAbandonedExecution(
			exec.ID,
			opts.WorkerID,
			StatusInterrupted,
			reason,
			opts.Auth,
		)
		if finalizeErr != nil {
			summary.FailedCount++
			continue
		}

		summary.RecoveredCount++
		summary.FinalizedCount++
		summary.Results = append(summary.Results, *res)
	}

	return summary, nil
}
