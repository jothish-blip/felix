package test

import (
	"context"
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"felix/pkg/assessment"
)

func newTestDB(t *testing.T) (*assessment.SQLiteStore, string, func()) {
	t.Helper()
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "felix_test.db")

	store, err := assessment.NewSQLiteStore(dbPath)
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}

	cleanup := func() {
		_ = store.Close()
	}
	return store, dbPath, cleanup
}

func createTestAssessmentWithScope(t *testing.T, store *assessment.SQLiteStore, clientID, asmID string, authValid bool, targetApproved bool) *assessment.Assessment {
	t.Helper()
	_ = store.CreateClient(&assessment.Client{
		ID:   clientID,
		Name: "Client " + clientID,
	})

	asm := &assessment.Assessment{
		ID:             asmID,
		Ref:            "ASM-" + asmID,
		ClientID:       clientID,
		Name:           "Assessment " + asmID,
		AssessmentType: "BLACK_BOX_WEB",
		Status:         assessment.StatusReady,
		ScopeMode:      "same-origin",
	}
	if err := store.CreateAssessment(asm); err != nil {
		t.Fatalf("CreateAssessment failed: %v", err)
	}

	now := time.Now().UTC()
	var validFrom, validUntil time.Time
	if authValid {
		validFrom = now.Add(-24 * time.Hour)
		validUntil = now.Add(24 * time.Hour)
	} else {
		validFrom = now.Add(-48 * time.Hour)
		validUntil = now.Add(-24 * time.Hour)
	}

	authRec := &assessment.AuthorizationRecord{
		ID:                  "auth-" + asmID,
		AssessmentID:        asmID,
		AuthorizingParty:    "Security Officer",
		AuthorizationMethod: "WRITTEN_CONTRACT",
		DateReceived:        validFrom,
		ValidFrom:           &validFrom,
		ValidUntil:          &validUntil,
		Status:              assessment.AuthApproved,
	}
	if err := store.SetAuthorization(authRec); err != nil {
		t.Fatalf("SetAuthorization failed: %v", err)
	}

	targetScope := "APPROVED"
	if !targetApproved {
		targetScope = "PENDING"
	}
	target := &assessment.AssessmentTarget{
		ID:           "tgt-" + asmID,
		AssessmentID: asmID,
		TargetURL:    "https://api.example.com/v1",
		TargetType:   assessment.TargetAPIBaseURL,
		ScopeStatus:  targetScope,
	}
	if err := store.AddTarget(target); err != nil {
		t.Fatalf("AddTarget failed: %v", err)
	}

	return asm
}

// 1. Persistence across DB close/reopen
func TestSchedule_PersistenceAcrossCloseReopen(t *testing.T) {
	store, dbPath, cleanup := newTestDB(t)
	defer cleanup()

	createTestAssessmentWithScope(t, store, "client-p", "asm-p", true, true)
	adminAuth := assessment.NewAdminAuthContext()

	s := &assessment.AssessmentSchedule{
		ID:              "sched-persist-1",
		Name:            "Nightly Assessment",
		Description:     "Scans production web endpoints every night",
		AssessmentID:    "asm-p",
		ClientID:        "client-p",
		TenantID:        "tenant-corp",
		AccountID:       "acc-corp",
		RecurrenceType:  assessment.RecurrenceDaily,
		RecurrenceExpr:  "02:30",
		Timezone:        "America/New_York",
		IsEnabled:       true,
		CatchUpPolicy:   "skip",
		ExecutionOptions: assessment.ScheduleExecutionOptions{
			TimeoutSeconds: 1800,
			Concurrency:    8,
			MaxAssets:      500,
		},
	}

	if err := store.CreateSchedule(s, adminAuth); err != nil {
		t.Fatalf("CreateSchedule failed: %v", err)
	}

	originalNextDue := s.NextDueAt

	// Close store
	if err := store.Close(); err != nil {
		t.Fatalf("Close failed: %v", err)
	}

	// Reopen store from disk
	reopened, err := assessment.NewSQLiteStore(dbPath)
	if err != nil {
		t.Fatalf("NewSQLiteStore reopen failed: %v", err)
	}
	defer reopened.Close()

	fetched, err := reopened.GetSchedule("sched-persist-1", adminAuth)
	if err != nil {
		t.Fatalf("GetSchedule after reopen failed: %v", err)
	}

	if fetched.Name != s.Name {
		t.Errorf("expected Name %s, got %s", s.Name, fetched.Name)
	}
	if fetched.RecurrenceType != assessment.RecurrenceDaily {
		t.Errorf("expected RecurrenceDaily, got %s", fetched.RecurrenceType)
	}
	if fetched.RecurrenceExpr != "02:30" {
		t.Errorf("expected 02:30, got %s", fetched.RecurrenceExpr)
	}
	if fetched.Timezone != "America/New_York" {
		t.Errorf("expected America/New_York, got %s", fetched.Timezone)
	}
	if fetched.CatchUpPolicy != "skip" {
		t.Errorf("expected skip, got %s", fetched.CatchUpPolicy)
	}
	if fetched.ExecutionOptions.TimeoutSeconds != 1800 || fetched.ExecutionOptions.Concurrency != 8 {
		t.Errorf("execution options mismatch: %+v", fetched.ExecutionOptions)
	}
	if !fetched.NextDueAt.Equal(originalNextDue) {
		t.Errorf("expected NextDueAt %v, got %v", originalNextDue, fetched.NextDueAt)
	}
}

// 2. Concurrency Safety: Atomic claim prevents double-dispatch under concurrent workers
func TestSchedule_AtomicClaimConcurrency(t *testing.T) {
	store, _, cleanup := newTestDB(t)
	defer cleanup()

	createTestAssessmentWithScope(t, store, "client-c", "asm-c", true, true)
	adminAuth := assessment.NewAdminAuthContext()

	now := time.Now().UTC()
	pastDue := now.Add(-10 * time.Minute)

	// Create 5 due schedules
	for i := 1; i <= 5; i++ {
		schedID := fmt.Sprintf("sched-race-%d", i)
		s := &assessment.AssessmentSchedule{
			ID:              schedID,
			Name:            "Race Test Schedule " + schedID,
			AssessmentID:    "asm-c",
			ClientID:        "client-c",
			RecurrenceType:  assessment.RecurrenceInterval,
			RecurrenceExpr:  "@every 1h",
			IntervalSeconds: 3600,
			Timezone:        "UTC",
			IsEnabled:       true,
			NextDueAt:       pastDue,
		}
		if err := store.CreateSchedule(s, adminAuth); err != nil {
			t.Fatalf("CreateSchedule failed: %v", err)
		}
	}

	// Launch 10 concurrent claim workers simultaneously
	const numWorkers = 10
	var wg sync.WaitGroup
	var totalClaimedCount int64
	claimedMap := sync.Map{} // scheduleID -> claim count

	wg.Add(numWorkers)
	for w := 0; w < numWorkers; w++ {
		go func() {
			defer wg.Done()
			claimed, err := store.ClaimDueSchedules(now, 10)
			if err != nil {
				t.Errorf("ClaimDueSchedules worker error: %v", err)
				return
			}
			for _, sch := range claimed {
				atomic.AddInt64(&totalClaimedCount, 1)
				val, _ := claimedMap.LoadOrStore(sch.ID, new(int64))
				atomic.AddInt64(val.(*int64), 1)
			}
		}()
	}
	wg.Wait()

	// Exactly 5 schedules must be claimed across all 10 workers
	if totalClaimedCount != 5 {
		t.Errorf("expected exactly 5 total claims across concurrent workers, got %d", totalClaimedCount)
	}

	claimedMap.Range(func(key, value any) bool {
		id := key.(string)
		count := atomic.LoadInt64(value.(*int64))
		if count != 1 {
			t.Errorf("schedule %s claimed %d times (MUST BE EXACTLY 1, NO DOUBLE DISPATCH)", id, count)
		}
		return true
	})
}

// 3. Restart Duplicate Prevention
func TestSchedule_RestartDuplicatePrevention(t *testing.T) {
	store, _, cleanup := newTestDB(t)
	defer cleanup()

	createTestAssessmentWithScope(t, store, "client-r", "asm-r", true, true)
	adminAuth := assessment.NewAdminAuthContext()

	now := time.Now().UTC()
	pastDue := now.Add(-5 * time.Minute)

	s := &assessment.AssessmentSchedule{
		ID:              "sched-restart-1",
		Name:            "Hourly Scan",
		AssessmentID:    "asm-r",
		ClientID:        "client-r",
		RecurrenceType:  assessment.RecurrenceInterval,
		RecurrenceExpr:  "@every 1h",
		IntervalSeconds: 3600,
		Timezone:        "UTC",
		IsEnabled:       true,
		NextDueAt:       pastDue,
	}
	if err := store.CreateSchedule(s, adminAuth); err != nil {
		t.Fatalf("CreateSchedule failed: %v", err)
	}

	// First scheduler run claims and dispatches
	claimed, err := store.ClaimDueSchedules(now, 10)
	if err != nil || len(claimed) != 1 {
		t.Fatalf("expected 1 claimed schedule, got %d (err=%v)", len(claimed), err)
	}

	// Simulate service restart 1 minute later
	restartNow := now.Add(1 * time.Minute)
	restartClaimed, err := store.ClaimDueSchedules(restartNow, 10)
	if err != nil {
		t.Fatalf("ClaimDueSchedules after restart failed: %v", err)
	}
	if len(restartClaimed) != 0 {
		t.Fatalf("expected 0 claims after restart (no premature re-dispatch), got %d", len(restartClaimed))
	}
}

// 4. Pre-execution Safety: Refuse execution if authorization or scope invalid
func TestSchedule_PreExecutionSafetyEnforcement(t *testing.T) {
	store, _, cleanup := newTestDB(t)
	defer cleanup()

	// 4a. Assessment with expired authorization
	createTestAssessmentWithScope(t, store, "client-s", "asm-expired-auth", false, true)
	// 4b. Assessment with unapproved targets
	createTestAssessmentWithScope(t, store, "client-s", "asm-unapproved-scope", true, false)

	adminAuth := assessment.NewAdminAuthContext()
	now := time.Now().UTC()

	s1 := &assessment.AssessmentSchedule{
		ID:             "sched-bad-auth",
		Name:           "Expired Auth",
		AssessmentID:   "asm-expired-auth",
		ClientID:       "client-s",
		RecurrenceType: assessment.RecurrenceInterval,
		RecurrenceExpr: "@every 1h",
		IntervalSeconds: 3600,
		IsEnabled:      true,
		NextDueAt:      now.Add(-10 * time.Minute),
	}
	s2 := &assessment.AssessmentSchedule{
		ID:             "sched-bad-scope",
		Name:           "Unapproved Scope",
		AssessmentID:   "asm-unapproved-scope",
		ClientID:       "client-s",
		RecurrenceType: assessment.RecurrenceInterval,
		RecurrenceExpr: "@every 1h",
		IntervalSeconds: 3600,
		IsEnabled:      true,
		NextDueAt:      now.Add(-10 * time.Minute),
	}

	if err := store.CreateSchedule(s1, adminAuth); err != nil {
		t.Fatalf("CreateSchedule s1 failed: %v", err)
	}
	if err := store.CreateSchedule(s2, adminAuth); err != nil {
		t.Fatalf("CreateSchedule s2 failed: %v", err)
	}

	var runCount int32
	runner := &mockRunnerCallback{
		onRun: func() {
			atomic.AddInt32(&runCount, 1)
		},
	}

	scheduler := assessment.NewScheduler(store, runner, assessment.DefaultSchedulerConfig())
	dispatched, err := scheduler.RunDueSchedulesSync(context.Background(), now)
	if err != nil {
		t.Fatalf("RunDueSchedulesSync failed: %v", err)
	}
	if dispatched != 2 {
		t.Fatalf("expected 2 schedules claimed for evaluation, got %d", dispatched)
	}

	// Execution engine must NEVER be invoked for invalid auth or invalid targets
	if atomic.LoadInt32(&runCount) != 0 {
		t.Fatalf("runner must not be invoked for invalid auth or targets, got %d calls", runCount)
	}

	// Verify telemetry recorded SKIPPED status
	disp1, err := store.GetScheduleDispatches(s1.ID, adminAuth)
	if err != nil || len(disp1) != 1 || disp1[0].Status != "SKIPPED" {
		t.Errorf("expected s1 dispatch SKIPPED, got %+v", disp1)
	}

	disp2, err := store.GetScheduleDispatches(s2.ID, adminAuth)
	if err != nil || len(disp2) != 1 || disp2[0].Status != "SKIPPED" {
		t.Errorf("expected s2 dispatch SKIPPED, got %+v", disp2)
	}
}

// 5. Multi-Tenant Authorization Isolation
func TestSchedule_TenantIsolation(t *testing.T) {
	store, _, cleanup := newTestDB(t)
	defer cleanup()

	createTestAssessmentWithScope(t, store, "client-alpha", "asm-alpha", true, true)
	createTestAssessmentWithScope(t, store, "client-beta", "asm-beta", true, true)

	authAlpha := assessment.NewTenantAuthContext("client-alpha", "tenant-alpha", "acc-1")
	authBeta := assessment.NewTenantAuthContext("client-beta", "tenant-beta", "acc-2")
	authAdmin := assessment.NewAdminAuthContext()

	schedAlpha := &assessment.AssessmentSchedule{
		ID:             "sched-alpha-1",
		Name:           "Alpha Scan",
		AssessmentID:   "asm-alpha",
		ClientID:       "client-alpha",
		TenantID:       "tenant-alpha",
		RecurrenceType: assessment.RecurrenceInterval,
		RecurrenceExpr: "@every 2h",
		IntervalSeconds: 7200,
		IsEnabled:      true,
	}

	// Alpha creates schedule
	if err := store.CreateSchedule(schedAlpha, authAlpha); err != nil {
		t.Fatalf("CreateSchedule Alpha failed: %v", err)
	}

	// Beta cannot get Alpha's schedule
	_, err := store.GetSchedule(schedAlpha.ID, authBeta)
	if err != assessment.ErrScheduleUnauthorized {
		t.Errorf("expected ErrScheduleUnauthorized for Beta getting Alpha's schedule, got %v", err)
	}

	// Beta cannot update Alpha's schedule
	schedAlpha.Name = "Hijacked Name"
	err = store.UpdateSchedule(schedAlpha, authBeta)
	if err != assessment.ErrScheduleUnauthorized {
		t.Errorf("expected ErrScheduleUnauthorized for Beta updating Alpha's schedule, got %v", err)
	}

	// Beta cannot delete Alpha's schedule
	err = store.DeleteSchedule(schedAlpha.ID, authBeta)
	if err != assessment.ErrScheduleUnauthorized {
		t.Errorf("expected ErrScheduleUnauthorized for Beta deleting Alpha's schedule, got %v", err)
	}

	// Beta cannot list Alpha's schedule
	listBeta, countBeta, err := store.ListSchedules(assessment.ScheduleListOptions{Auth: authBeta})
	if err != nil || countBeta != 0 || len(listBeta) != 0 {
		t.Errorf("expected 0 schedules for Beta, got %d", countBeta)
	}

	// Admin can see Alpha's schedule
	listAdmin, countAdmin, err := store.ListSchedules(assessment.ScheduleListOptions{Auth: authAdmin})
	if err != nil || countAdmin != 1 || len(listAdmin) != 1 {
		t.Errorf("expected 1 schedule for Admin, got %d", countAdmin)
	}
}

// 6. CLI End-to-End Execution
func TestSchedule_CLIEndToEnd(t *testing.T) {
	store, dbPath, cleanup := newTestDB(t)
	defer cleanup()

	createTestAssessmentWithScope(t, store, "client-cli", "asm-cli", true, true)
	_ = store.Close() // Close store so CLI can open SQLite db without locking conflicts

	felixBin := filepath.Join("..", "bin", "felix.exe")

	// 1. Create schedule via CLI
	createCmd := exec.Command(felixBin, "assessment", "schedule", "create",
		"--name", "CLI Scheduled Scan",
		"--assessment", "asm-cli",
		"--type", "interval",
		"--expr", "@every 1h",
		"--interval", "3600",
		"--db", dbPath,
		"--json",
	)
	out, err := createCmd.CombinedOutput()
	if err != nil {
		t.Fatalf("CLI schedule create failed: %v\nOutput: %s", err, string(out))
	}
	if !strings.Contains(string(out), "CLI Scheduled Scan") {
		t.Errorf("expected JSON output containing schedule name, got: %s", string(out))
	}

	// 2. List schedules via CLI
	listCmd := exec.Command(felixBin, "assessment", "schedule", "list",
		"--db", dbPath,
	)
	listOut, err := listCmd.CombinedOutput()
	if err != nil {
		t.Fatalf("CLI schedule list failed: %v\nOutput: %s", err, string(listOut))
	}
	if !strings.Contains(string(listOut), "CLI Scheduled Scan") {
		t.Errorf("expected list to show schedule, got: %s", string(listOut))
	}

	// 3. Run due schedules via CLI
	runDueCmd := exec.Command(felixBin, "assessment", "schedule", "run-due",
		"--db", dbPath,
	)
	runDueOut, err := runDueCmd.CombinedOutput()
	if err != nil {
		t.Fatalf("CLI run-due failed: %v\nOutput: %s", err, string(runDueOut))
	}
	if !strings.Contains(string(runDueOut), "Checked and dispatched") {
		t.Errorf("expected run-due success message, got: %s", string(runDueOut))
	}

	// 4. Daemon help CLI command
	daemonHelpCmd := exec.Command(felixBin, "schedule", "daemon", "--help")
	daemonHelpOut, err := daemonHelpCmd.CombinedOutput()
	if err != nil {
		t.Fatalf("CLI daemon help failed: %v\nOutput: %s", err, string(daemonHelpOut))
	}
	if !strings.Contains(string(daemonHelpOut), "Continuous background scheduler daemon") &&
		!strings.Contains(string(daemonHelpOut), "scheduler daemon") {
		t.Errorf("expected daemon help output, got: %s", string(daemonHelpOut))
	}
}

// 7. Target Scope: Mixed approved, pending, and excluded targets
func TestSchedule_TargetScope_MixedApprovedAndUnapproved(t *testing.T) {
	store, _, cleanup := newTestDB(t)
	defer cleanup()

	asmID := "asm-mixed-scope"
	createTestAssessmentWithScope(t, store, "client-mixed", asmID, true, true)
	// tgt-asm-mixed-scope was added as APPROVED: https://api.example.com/v1

	// Add second target with PENDING status (unapproved)
	_ = store.AddTarget(&assessment.AssessmentTarget{
		ID:           "tgt-pending",
		AssessmentID: asmID,
		TargetURL:    "https://unauthorized-internal.corp/secret",
		TargetType:   assessment.TargetAPIBaseURL,
		ScopeStatus:  "PENDING",
	})

	// Add third target with EXCLUDED status
	_ = store.AddTarget(&assessment.AssessmentTarget{
		ID:           "tgt-excluded",
		AssessmentID: asmID,
		TargetURL:    "https://external-forbidden.com",
		TargetType:   assessment.TargetWebsite,
		ScopeStatus:  "EXCLUDED",
	})

	adminAuth := assessment.NewAdminAuthContext()
	sched := &assessment.AssessmentSchedule{
		ID:              "sched-mixed",
		Name:            "Mixed Targets Test",
		AssessmentID:    asmID,
		ClientID:        "client-mixed",
		RecurrenceType:  assessment.RecurrenceInterval,
		RecurrenceExpr:  "@every 1h",
		IntervalSeconds: 3600,
		IsEnabled:       true,
		NextDueAt:       time.Now().UTC().Add(-10 * time.Minute),
	}
	if err := store.CreateSchedule(sched, adminAuth); err != nil {
		t.Fatalf("CreateSchedule failed: %v", err)
	}

	// Use canonical Controller to execute and verify exactly what targets are runnable
	ctrl := assessment.NewController(store)
	scheduler := assessment.NewScheduler(store, ctrl, assessment.DefaultSchedulerConfig())

	dispatched, err := scheduler.RunDueSchedulesSync(context.Background(), time.Now().UTC())
	if err != nil {
		t.Fatalf("RunDueSchedulesSync failed: %v", err)
	}
	if dispatched != 1 {
		t.Fatalf("expected 1 dispatched schedule, got %d", dispatched)
	}

	// Inspect execution record created by the canonical controller
	dispatches, err := store.GetScheduleDispatches(sched.ID, adminAuth)
	if err != nil || len(dispatches) != 1 {
		t.Fatalf("failed fetching dispatches: %v", err)
	}
	if dispatches[0].Status != "COMPLETED" {
		t.Fatalf("expected COMPLETED dispatch for approved target, got %s (error: %s)",
			dispatches[0].Status, dispatches[0].ErrorMessage)
	}

	exec, err := store.GetExecution(dispatches[0].ExecutionID)
	if err != nil || exec == nil {
		t.Fatalf("failed fetching execution %s: %v", dispatches[0].ExecutionID, err)
	}

	// Verify all findings or targets in execution only touch https://api.example.com/v1
	// and never touch unauthorized-internal.corp or external-forbidden.com
	findings, _ := store.GetFindings(asmID, exec.ID)
	targets, _ := store.GetTargets(asmID)
	for _, f := range findings {
		for _, target := range targets {
			if target.ID == f.TargetID {
				if strings.Contains(target.TargetURL, "unauthorized-internal.corp") ||
					strings.Contains(target.TargetURL, "external-forbidden.com") {
					t.Fatalf("CRITICAL SECURITY DEFECT: Unapproved target was scanned: %s", target.TargetURL)
				}
			}
		}
	}
}

// 8. Target Scope: Authorization revoked after schedule creation
func TestSchedule_TargetScope_AuthRevokedAfterScheduleCreation(t *testing.T) {
	store, _, cleanup := newTestDB(t)
	defer cleanup()

	asmID := "asm-revoke-test"
	createTestAssessmentWithScope(t, store, "client-rev", asmID, true, true)
	adminAuth := assessment.NewAdminAuthContext()

	sched := &assessment.AssessmentSchedule{
		ID:              "sched-revoked",
		Name:            "Revocation Test",
		AssessmentID:    asmID,
		ClientID:        "client-rev",
		RecurrenceType:  assessment.RecurrenceInterval,
		RecurrenceExpr:  "@every 1h",
		IntervalSeconds: 3600,
		IsEnabled:       true,
		NextDueAt:       time.Now().UTC().Add(-5 * time.Minute),
	}
	if err := store.CreateSchedule(sched, adminAuth); err != nil {
		t.Fatalf("CreateSchedule failed: %v", err)
	}

	// Revoke authorization after schedule was successfully created
	authRec, err := store.GetAuthorization(asmID)
	if err != nil || authRec == nil {
		t.Fatalf("failed getting auth record: %v", err)
	}
	if err := store.UpdateAuthorizationStatus(authRec.ID, assessment.AuthRevoked); err != nil {
		t.Fatalf("UpdateAuthorizationStatus failed: %v", err)
	}

	var runCount int32
	runner := &mockRunnerCallback{
		onRun: func() {
			atomic.AddInt32(&runCount, 1)
		},
	}

	scheduler := assessment.NewScheduler(store, runner, assessment.DefaultSchedulerConfig())
	dispatched, err := scheduler.RunDueSchedulesSync(context.Background(), time.Now().UTC())
	if err != nil {
		t.Fatalf("RunDueSchedulesSync failed: %v", err)
	}
	if dispatched != 1 {
		t.Fatalf("expected 1 schedule evaluated, got %d", dispatched)
	}

	// Runner must NOT have been called
	if atomic.LoadInt32(&runCount) != 0 {
		t.Fatalf("CRITICAL: Runner invoked despite revoked authorization!")
	}

	// Dispatch must be recorded as SKIPPED
	dispatches, err := store.GetScheduleDispatches(sched.ID, adminAuth)
	if err != nil || len(dispatches) != 1 {
		t.Fatalf("expected 1 dispatch record, got %v", dispatches)
	}
	if dispatches[0].Status != "SKIPPED" {
		t.Errorf("expected SKIPPED status for revoked authorization, got %s", dispatches[0].Status)
	}
	if !strings.Contains(dispatches[0].ErrorMessage, "REVOKED") &&
		!strings.Contains(dispatches[0].ErrorMessage, "invalid") {
		t.Errorf("expected rejection reason in dispatch record, got: %s", dispatches[0].ErrorMessage)
	}
}

// 9. Target Scope: All approved targets excluded by exclusion rules added after schedule creation
func TestSchedule_TargetScope_AllApprovedTargetsExcluded(t *testing.T) {
	store, _, cleanup := newTestDB(t)
	defer cleanup()

	asmID := "asm-exclude-all"
	createTestAssessmentWithScope(t, store, "client-ex", asmID, true, true)
	// Target is https://api.example.com/v1

	adminAuth := assessment.NewAdminAuthContext()
	sched := &assessment.AssessmentSchedule{
		ID:              "sched-exclude-all",
		Name:            "Exclusion Test",
		AssessmentID:    asmID,
		ClientID:        "client-ex",
		RecurrenceType:  assessment.RecurrenceInterval,
		RecurrenceExpr:  "@every 1h",
		IntervalSeconds: 3600,
		IsEnabled:       true,
		NextDueAt:       time.Now().UTC().Add(-5 * time.Minute),
	}
	if err := store.CreateSchedule(sched, adminAuth); err != nil {
		t.Fatalf("CreateSchedule failed: %v", err)
	}

	// Add an exclusion rule matching the approved target after schedule creation
	exclusion := &assessment.Exclusion{
		ID:           "excl-1",
		AssessmentID: asmID,
		Pattern:      "*.example.com",
		Reason:       "Maintenance window active",
		ExclusionType: assessment.ExclusionHostname,
	}
	if err := store.AddExclusion(exclusion); err != nil {
		t.Fatalf("AddExclusion failed: %v", err)
	}

	ctrl := assessment.NewController(store)
	scheduler := assessment.NewScheduler(store, ctrl, assessment.DefaultSchedulerConfig())

	dispatched, err := scheduler.RunDueSchedulesSync(context.Background(), time.Now().UTC())
	if err != nil {
		t.Fatalf("RunDueSchedulesSync failed: %v", err)
	}
	if dispatched != 1 {
		t.Fatalf("expected 1 schedule evaluated, got %d", dispatched)
	}

	// Dispatch must be recorded as SKIPPED due to canonical exclusion refusal
	dispatches, err := store.GetScheduleDispatches(sched.ID, adminAuth)
	if err != nil || len(dispatches) != 1 {
		t.Fatalf("expected 1 dispatch record, got %v", dispatches)
	}
	if dispatches[0].Status != "SKIPPED" {
		t.Errorf("expected SKIPPED status for excluded targets, got %s", dispatches[0].Status)
	}
	if !strings.Contains(dispatches[0].ErrorMessage, "excluded by active exclusion rules") {
		t.Errorf("expected exclusion refusal in error message, got: %s", dispatches[0].ErrorMessage)
	}
}

// 10. Automatic Scheduler Runtime: Continuous background daemon polling, dispatch, and clean shutdown
func TestScheduleDaemon_LifecycleAndAutomaticDispatch(t *testing.T) {
	store, _, cleanup := newTestDB(t)
	defer cleanup()

	asmID := "asm-daemon-test"
	createTestAssessmentWithScope(t, store, "client-d", asmID, true, true)
	adminAuth := assessment.NewAdminAuthContext()

	var runCount int32
	runner := &mockRunnerCallback{
		onRun: func() {
			atomic.AddInt32(&runCount, 1)
		},
	}

	// Fast 20ms poll ticker for deterministic automated testing
	cfg := assessment.SchedulerConfig{
		PollInterval:    20 * time.Millisecond,
		MaxConcurrency:  2,
		ClaimBatchSize:  5,
		ShutdownTimeout: 2 * time.Second,
	}

	scheduler := assessment.NewScheduler(store, runner, cfg)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start daemon in background
	if err := scheduler.Start(ctx); err != nil {
		t.Fatalf("Start daemon failed: %v", err)
	}
	if !scheduler.IsRunning() {
		t.Fatalf("expected scheduler daemon to be running")
	}

	// Create a schedule that is due immediately
	now := time.Now().UTC()
	sched := &assessment.AssessmentSchedule{
		ID:              "sched-daemon-1",
		Name:            "Daemon Auto Dispatch",
		AssessmentID:    asmID,
		ClientID:        "client-d",
		RecurrenceType:  assessment.RecurrenceInterval,
		RecurrenceExpr:  "@every 1h",
		IntervalSeconds: 3600,
		IsEnabled:       true,
		NextDueAt:       now.Add(-100 * time.Millisecond), // Due right now
	}
	if err := store.CreateSchedule(sched, adminAuth); err != nil {
		t.Fatalf("CreateSchedule failed: %v", err)
	}

	// Wait for background daemon ticker to automatically discover, claim, and dispatch
	timeout := time.After(2 * time.Second)
	dispatched := false
	for !dispatched {
		select {
		case <-timeout:
			t.Fatalf("Timed out waiting for scheduler daemon to automatically dispatch due schedule")
		default:
			if atomic.LoadInt32(&runCount) >= 1 {
				dispatched = true
				break
			}
			time.Sleep(10 * time.Millisecond)
		}
	}

	// Verify schedule was updated by the background daemon
	afterRun, err := store.GetSchedule(sched.ID, adminAuth)
	if err != nil {
		t.Fatalf("GetSchedule failed: %v", err)
	}
	if afterRun.DispatchCount < 1 {
		t.Errorf("expected DispatchCount >= 1, got %d", afterRun.DispatchCount)
	}
	if !afterRun.NextDueAt.After(now) {
		t.Errorf("expected NextDueAt to advance into future, got %v", afterRun.NextDueAt)
	}

	// Stop daemon and verify clean shutdown
	if err := scheduler.Stop(); err != nil {
		t.Fatalf("Stop daemon failed: %v", err)
	}
	if scheduler.IsRunning() {
		t.Errorf("expected scheduler to report not running after Stop")
	}
}

type mockRunnerCallback struct {
	onRun func()
}

func (m *mockRunnerCallback) RunAssessment(ctx context.Context, assessmentID string, opts assessment.ExecutionOptions) (*assessment.ExecutionResult, error) {
	if m.onRun != nil {
		m.onRun()
	}
	return &assessment.ExecutionResult{
		Execution: &assessment.AssessmentExecution{
			ID:           "exec-" + assessmentID,
			AssessmentID: assessmentID,
			Status:       assessment.StatusCompleted,
		},
	}, nil
}
