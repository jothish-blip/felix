package commercial

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"felix/pkg/assessment"
)

func createTestSignerAndRegistry(t *testing.T) (assessment.AttestationSigner, assessment.MapKeyRegistry) {
	t.Helper()
	signer, tk, err := assessment.NewEvidenceSignerAuthority("KEY-FELIX-TEST-001", "FELIX Authority", "Test Key")
	if err != nil {
		t.Fatalf("failed generating test signer: %v", err)
	}
	reg := assessment.MapKeyRegistry{
		tk.KeyID: tk,
	}
	return signer, reg
}

func signTestFindingEvidence(t *testing.T, signer assessment.AttestationSigner, findingID, targetURL string) *assessment.SignedEvidenceRecord {
	t.Helper()
	payload := assessment.EvidencePayload{
		EvidenceID:         fmt.Sprintf("ev_%s", findingID),
		EvidenceType:       assessment.EvidenceTypeSQLiControlledBehavioral,
		IssuerID:           "FELIX Authority",
		TargetURL:          targetURL,
		FindingID:          findingID,
		OriginalFindingRef: findingID,
		IssuedAt:           time.Now().UTC(),
		ExpiresAt:          time.Now().UTC().Add(24 * time.Hour),
		Outcome:            assessment.EvidenceOutcomeDefectReproduced,
		Details: map[string]any{
			"positive_control_reproduced": true,
			"verified":                    true,
		},
	}
	rec, err := assessment.SignEvidenceRecord(payload, signer)
	if err != nil {
		t.Fatalf("failed signing test evidence: %v", err)
	}
	return rec
}

func createTestAttestationLetter(t *testing.T, signer assessment.AttestationSigner, findingID, title, targetURL string) *assessment.AttestationLetter {
	t.Helper()
	snap := assessment.AttestationSnapshot{
		AssessmentID:   "asm-test-attestation-001",
		ClientName:     "Test Enterprise",
		StartedAt:      time.Now().UTC().Add(-1 * time.Hour).Format(time.RFC3339),
		CompletedAt:    time.Now().UTC().Format(time.RFC3339),
		SigningKeyID:   signer.KeyID(),
		Targets: []assessment.TargetSnapshot{
			{TargetURL: targetURL, TargetType: "URL", ScopeStatus: "APPROVED"},
		},
		SignificantExposures: []assessment.SignificantExposure{
			{
				FindingID:          findingID,
				Title:              title,
				Severity:           "HIGH",
				Status:             "VERIFIED_DEFECT",
				VerificationStatus: "VERIFIED",
				TargetEndpoint:     targetURL,
			},
		},
		TotalFindingsCount: 1,
		ConfirmedFindings:  1,
	}
	letter, err := assessment.GenerateAttestationLetter(snap, signer, assessment.DefaultAttestationOptions())
	if err != nil {
		t.Fatalf("failed generating attestation letter: %v", err)
	}
	return letter
}

// mockAssessmentRunner provides controllable snapshot responses for testing.
type mockAssessmentRunner struct {
	mu        sync.Mutex
	snapshots []*AttackSurfaceSnapshot
	index     int
	runFunc   func(ctx context.Context, sched *ScheduleConfig) (*AttackSurfaceSnapshot, error)
}

func (m *mockAssessmentRunner) RunAssessment(ctx context.Context, sched *ScheduleConfig) (*AttackSurfaceSnapshot, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.runFunc != nil {
		return m.runFunc(ctx, sched)
	}
	if len(m.snapshots) == 0 {
		return NewAttackSurfaceSnapshot("asm_default", sched.ClientID, time.Now().UTC()), nil
	}
	snap := m.snapshots[m.index%len(m.snapshots)]
	m.index++
	return snap, nil
}

// -----------------------------------------------------------------------------
// Test 1: Monthly Schedule Creation and Execution
// -----------------------------------------------------------------------------
func TestCPaaS_01_MonthlyScheduleCreationAndExecution(t *testing.T) {
	store, err := NewCPaaSStore(":memory:")
	if err != nil {
		t.Fatalf("failed creating store: %v", err)
	}
	defer store.Close()

	now := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	sched := &ScheduleConfig{
		ID:           "sched_monthly_01",
		ClientID:     "client_enterprise_01",
		Name:         "Enterprise Monthly Pentest",
		ScheduleType: ScheduleTypeMonthly,
		CronExpr:     "@monthly",
		TargetURLs:   []string{"https://api.enterprise.com"},
		Profile:      "standard",
		Enabled:      true,
		CreatedAt:    now,
		UpdatedAt:    now,
	}

	next, err := CalculateNextRun(sched.ScheduleType, sched.CronExpr, now)
	if err != nil {
		t.Fatalf("failed calculating next run: %v", err)
	}
	expectedNext := time.Date(2026, 12, 1, 0, 0, 0, 0, time.UTC)
	if !next.Equal(expectedNext) {
		t.Errorf("expected next monthly run %v, got %v", expectedNext, next)
	}
	sched.NextRunAt = &next

	if err := store.SaveSchedule(context.Background(), sched); err != nil {
		t.Fatalf("failed saving schedule: %v", err)
	}

	runner := &mockAssessmentRunner{}
	scheduler := NewCPaaSScheduler(store, NewDriftEngine(), nil, runner, CPaaSSchedulerOptions{
		Clock: func() time.Time { return next.Add(time.Second) },
	})

	if err := scheduler.RunCycle(context.Background()); err != nil {
		t.Fatalf("RunCycle failed: %v", err)
	}

	time.Sleep(50 * time.Millisecond)

	schedules, err := store.ListSchedules(context.Background(), sched.ClientID, true)
	if err != nil || len(schedules) != 1 {
		t.Fatalf("failed listing schedules: %v", err)
	}
	if schedules[0].LastRunAt == nil {
		t.Errorf("expected LastRunAt to be updated after cycle")
	}
}

// -----------------------------------------------------------------------------
// Test 2: Cron Schedule Math & Execution
// -----------------------------------------------------------------------------
func TestCPaaS_02_CronScheduleExecution(t *testing.T) {
	ref := time.Date(2026, 11, 10, 14, 0, 0, 0, time.UTC)

	cases := []struct {
		expr     string
		expected time.Time
	}{
		{"@hourly", time.Date(2026, 11, 10, 15, 0, 0, 0, time.UTC)},
		{"@daily", time.Date(2026, 11, 11, 0, 0, 0, 0, time.UTC)},
		{"@weekly", time.Date(2026, 11, 15, 0, 0, 0, 0, time.UTC)}, // next Sunday
		{"*/15 * * * *", time.Date(2026, 11, 10, 14, 15, 0, 0, time.UTC)},
		{"30 16 * * *", time.Date(2026, 11, 10, 16, 30, 0, 0, time.UTC)},
	}

	for _, tc := range cases {
		next, err := CalculateNextRun(ScheduleTypeCron, tc.expr, ref)
		if err != nil {
			t.Errorf("expr %q failed: %v", tc.expr, err)
			continue
		}
		if !next.Equal(tc.expected) {
			t.Errorf("expr %q expected %v, got %v", tc.expr, tc.expected, next)
		}
	}
}

// -----------------------------------------------------------------------------
// Test 3: CI/CD Webhook-Triggered Assessments
// -----------------------------------------------------------------------------
func TestCPaaS_03_CICDWebhookTriggeredAssessment(t *testing.T) {
	store, _ := NewCPaaSStore(":memory:")
	defer store.Close()

	sched := &ScheduleConfig{
		ID:            "sched_wh_01",
		ClientID:      "client_devops",
		Name:          "CI/CD Pipeline Scan",
		ScheduleType:  ScheduleTypeWebhook,
		TargetURLs:    []string{"https://staging.internal.com"},
		Enabled:       true,
		WebhookSecret: "super-secret-wh-token",
		CreatedAt:     time.Now().UTC(),
		UpdatedAt:     time.Now().UTC(),
	}
	_ = store.SaveSchedule(context.Background(), sched)

	var runInvoked atomic.Bool
	runner := &mockAssessmentRunner{
		runFunc: func(ctx context.Context, s *ScheduleConfig) (*AttackSurfaceSnapshot, error) {
			runInvoked.Store(true)
			return NewAttackSurfaceSnapshot("asm_wh_01", s.ClientID, time.Now().UTC()), nil
		},
	}

	scheduler := NewCPaaSScheduler(store, NewDriftEngine(), nil, runner, CPaaSSchedulerOptions{})

	req := WebhookTriggerRequest{
		ScheduleID:    sched.ID,
		ClientID:      sched.ClientID,
		CommitHash:    "a1b2c3d4e5f6",
		Branch:        "release/v3.0",
		WebhookSecret: "super-secret-wh-token",
	}

	resp, err := scheduler.TriggerWebhook(context.Background(), req)
	if err != nil {
		t.Fatalf("TriggerWebhook failed: %v", err)
	}
	if !resp.Accepted || resp.ExecutionID == "" {
		t.Fatalf("expected accepted response, got: %+v", resp)
	}

	time.Sleep(50 * time.Millisecond)
	if !runInvoked.Load() {
		t.Errorf("expected assessment runner to be executed from webhook trigger")
	}
}

// -----------------------------------------------------------------------------
// Test 4: Invalid and Unauthorized Webhook Requests
// -----------------------------------------------------------------------------
func TestCPaaS_04_InvalidAndUnauthorizedWebhookRequests(t *testing.T) {
	store, _ := NewCPaaSStore(":memory:")
	defer store.Close()

	sched := &ScheduleConfig{
		ID:            "sched_wh_auth",
		ClientID:      "client_sec",
		ScheduleType:  ScheduleTypeWebhook,
		Enabled:       true,
		WebhookSecret: "valid-secret-12345",
	}
	_ = store.SaveSchedule(context.Background(), sched)

	scheduler := NewCPaaSScheduler(store, nil, nil, nil, CPaaSSchedulerOptions{})

	// 1. Wrong secret
	_, errBadSecret := scheduler.TriggerWebhook(context.Background(), WebhookTriggerRequest{
		ScheduleID:    sched.ID,
		WebhookSecret: "wrong-secret",
	})
	if errBadSecret == nil || !strings.Contains(errBadSecret.Error(), "unauthorized") {
		t.Errorf("expected unauthorized error for bad secret, got: %v", errBadSecret)
	}

	// 2. Nonexistent schedule
	_, errMissingSched := scheduler.TriggerWebhook(context.Background(), WebhookTriggerRequest{
		ScheduleID: "sched_does_not_exist",
	})
	if errMissingSched == nil {
		t.Errorf("expected error for nonexistent schedule")
	}
}

// -----------------------------------------------------------------------------
// Test 5: Duplicate Webhook and Replay Rejection
// -----------------------------------------------------------------------------
func TestCPaaS_05_DuplicateWebhookAndReplayRejection(t *testing.T) {
	store, _ := NewCPaaSStore(":memory:")
	defer store.Close()

	sched := &ScheduleConfig{
		ID:            "sched_wh_replay",
		ClientID:      "client_corp",
		ScheduleType:  ScheduleTypeWebhook,
		Enabled:       true,
		WebhookSecret: "secret",
	}
	_ = store.SaveSchedule(context.Background(), sched)

	scheduler := NewCPaaSScheduler(store, nil, nil, &mockAssessmentRunner{}, CPaaSSchedulerOptions{})

	req := WebhookTriggerRequest{
		ScheduleID:     sched.ID,
		WebhookSecret:  "secret",
		IdempotencyKey: "delivery_unique_12345",
	}

	// First delivery: succeeds
	resp1, err1 := scheduler.TriggerWebhook(context.Background(), req)
	if err1 != nil || !resp1.Accepted {
		t.Fatalf("first delivery failed: %v", err1)
	}

	// Replay delivery: must be rejected
	_, err2 := scheduler.TriggerWebhook(context.Background(), req)
	if err2 == nil || !strings.Contains(err2.Error(), "duplicate webhook delivery") {
		t.Fatalf("expected duplicate rejection on replay, got: %v", err2)
	}
}

// -----------------------------------------------------------------------------
// Test 6: Scheduler Restart and Recovery
// -----------------------------------------------------------------------------
func TestCPaaS_06_SchedulerRestartAndRecovery(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "cpaas_recovery.db")

	store1, err := NewCPaaSStore(dbPath)
	if err != nil {
		t.Fatalf("failed creating store1: %v", err)
	}

	sched := &ScheduleConfig{
		ID:           "sched_recover_01",
		ClientID:     "client_rec",
		Name:         "Recovery Test Schedule",
		ScheduleType: ScheduleTypeCron,
		CronExpr:     "@daily",
		Enabled:      true,
		CreatedAt:    time.Now().UTC(),
		UpdatedAt:    time.Now().UTC(),
	}
	_ = store1.SaveSchedule(context.Background(), sched)

	// Simulate an execution stuck in PENDING from an aborted process
	pendingExec := &ScheduledExecution{
		ID:             "exec_pending_crashed",
		ScheduleID:     sched.ID,
		ClientID:       sched.ClientID,
		TriggerType:    "SCHEDULED",
		Status:         ExecutionStatusPending,
		IdempotencyKey: "sched_recover_01:2026-11-10T00:00:00Z",
		ScheduledFor:   time.Now().UTC(),
	}
	_ = store1.CreateExecution(context.Background(), pendingExec)
	_ = store1.Close()

	// Restart scheduler with new store instance connected to same database
	store2, err := NewCPaaSStore(dbPath)
	if err != nil {
		t.Fatalf("failed opening store2: %v", err)
	}
	defer store2.Close()

	var recoveredRun atomic.Bool
	runner := &mockAssessmentRunner{
		runFunc: func(ctx context.Context, s *ScheduleConfig) (*AttackSurfaceSnapshot, error) {
			recoveredRun.Store(true)
			return NewAttackSurfaceSnapshot("asm_rec", s.ClientID, time.Now().UTC()), nil
		},
	}

	scheduler := NewCPaaSScheduler(store2, NewDriftEngine(), nil, runner, CPaaSSchedulerOptions{})
	recoveredCount, err := scheduler.RecoverPending(context.Background())
	if err != nil {
		t.Fatalf("RecoverPending failed: %v", err)
	}
	if recoveredCount != 1 {
		t.Errorf("expected 1 recovered execution, got %d", recoveredCount)
	}

	time.Sleep(50 * time.Millisecond)
	if !recoveredRun.Load() {
		t.Errorf("expected recovered execution to be processed by runner")
	}
}

// -----------------------------------------------------------------------------
// Test 7: Duplicate Scheduled Execution Prevention
// -----------------------------------------------------------------------------
func TestCPaaS_07_DuplicateScheduledExecutionPrevention(t *testing.T) {
	store, _ := NewCPaaSStore(":memory:")
	defer store.Close()

	schedTime := time.Date(2026, 11, 10, 12, 0, 0, 0, time.UTC)
	sched := &ScheduleConfig{
		ID:           "sched_dup_prevent",
		ClientID:     "client_dup",
		ScheduleType: ScheduleTypeCron,
		CronExpr:     "@hourly",
		Enabled:      true,
		NextRunAt:    &schedTime,
	}
	_ = store.SaveSchedule(context.Background(), sched)

	var runCount atomic.Int32
	runner := &mockAssessmentRunner{
		runFunc: func(ctx context.Context, s *ScheduleConfig) (*AttackSurfaceSnapshot, error) {
			runCount.Add(1)
			return NewAttackSurfaceSnapshot("asm_dup", s.ClientID, time.Now().UTC()), nil
		},
	}

	scheduler := NewCPaaSScheduler(store, NewDriftEngine(), nil, runner, CPaaSSchedulerOptions{
		Clock: func() time.Time { return schedTime.Add(time.Second) },
	})

	// Run two consecutive cycles
	_ = scheduler.RunCycle(context.Background())
	_ = scheduler.RunCycle(context.Background())

	time.Sleep(50 * time.Millisecond)

	if count := runCount.Load(); count != 1 {
		t.Errorf("expected exactly 1 execution dispatched, got %d", count)
	}
}

// -----------------------------------------------------------------------------
// Test 8: Concurrent Scheduler Execution Limits (Bounded Concurrency)
// -----------------------------------------------------------------------------
func TestCPaaS_08_ConcurrentSchedulerExecutionLimits(t *testing.T) {
	store, _ := NewCPaaSStore(":memory:")
	defer store.Close()

	var activeConcurrent atomic.Int32
	var maxObserved atomic.Int32
	maxAllowed := 2

	runner := &mockAssessmentRunner{
		runFunc: func(ctx context.Context, s *ScheduleConfig) (*AttackSurfaceSnapshot, error) {
			curr := activeConcurrent.Add(1)
			for {
				peak := maxObserved.Load()
				if curr <= peak || maxObserved.CompareAndSwap(peak, curr) {
					break
				}
			}
			time.Sleep(20 * time.Millisecond)
			activeConcurrent.Add(-1)
			return NewAttackSurfaceSnapshot("asm_concurr", s.ClientID, time.Now().UTC()), nil
		},
	}

	scheduler := NewCPaaSScheduler(store, NewDriftEngine(), nil, runner, CPaaSSchedulerOptions{
		MaxConcurrency: maxAllowed,
	})

	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		schedID := fmt.Sprintf("sched_c_%d", i)
		_ = store.SaveSchedule(context.Background(), &ScheduleConfig{
			ID:           schedID,
			ClientID:     "client_c",
			ScheduleType: ScheduleTypeWebhook,
			Enabled:      true,
		})
		go func(id string) {
			defer wg.Done()
			_, _ = scheduler.TriggerScheduleNow(context.Background(), id)
		}(schedID)
	}

	wg.Wait()
	time.Sleep(100 * time.Millisecond)

	if peak := maxObserved.Load(); peak > int32(maxAllowed) {
		t.Errorf("concurrency violation: expected peak <= %d, observed %d", maxAllowed, peak)
	}
}

// -----------------------------------------------------------------------------
// Test 9: New Route Detection
// -----------------------------------------------------------------------------
func TestCPaaS_09_NewRouteDetection(t *testing.T) {
	engine := NewDriftEngine()

	base := NewAttackSurfaceSnapshot("asm_base", "c1", time.Now().UTC())
	base.Routes["GET:/api/v1/users"] = RouteDetail{Method: "GET", Path: "/api/v1/users"}

	curr := NewAttackSurfaceSnapshot("asm_curr", "c1", time.Now().UTC())
	curr.Routes["GET:/api/v1/users"] = RouteDetail{Method: "GET", Path: "/api/v1/users"}
	curr.Routes["POST:/api/v1/checkout"] = RouteDetail{Method: "POST", Path: "/api/v1/checkout"}

	report, err := engine.Compare("sched_1", base, curr)
	if err != nil {
		t.Fatalf("Compare failed: %v", err)
	}

	if report.NewRoutesCount != 1 {
		t.Errorf("expected 1 new route, got %d", report.NewRoutesCount)
	}
	found := false
	for _, evt := range report.DriftEvents {
		if evt.Type == DriftTypeNewRoute && evt.Entity == "POST /api/v1/checkout" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected event for POST /api/v1/checkout, got: %+v", report.DriftEvents)
	}
}

// -----------------------------------------------------------------------------
// Test 10: Query Parameter Drift
// -----------------------------------------------------------------------------
func TestCPaaS_10_QueryParameterDrift(t *testing.T) {
	engine := NewDriftEngine()

	base := NewAttackSurfaceSnapshot("asm_base", "c1", time.Now().UTC())
	base.QueryParams["GET:/api/v1/search"] = []string{"q", "page"}

	curr := NewAttackSurfaceSnapshot("asm_curr", "c1", time.Now().UTC())
	curr.QueryParams["GET:/api/v1/search"] = []string{"q", "page", "debug", "admin_mode"}

	report, err := engine.Compare("sched_1", base, curr)
	if err != nil {
		t.Fatalf("Compare failed: %v", err)
	}

	if report.NewQueryParamsCount != 2 {
		t.Errorf("expected 2 new query params, got %d", report.NewQueryParamsCount)
	}
}

// -----------------------------------------------------------------------------
// Test 11: Cookie Configuration Drift
// -----------------------------------------------------------------------------
func TestCPaaS_11_CookieConfigurationDrift(t *testing.T) {
	engine := NewDriftEngine()

	base := NewAttackSurfaceSnapshot("asm_base", "c1", time.Now().UTC())
	base.Cookies["session_id"] = CookieDetail{Name: "session_id", HttpOnly: true, Secure: true}

	curr := NewAttackSurfaceSnapshot("asm_curr", "c1", time.Now().UTC())
	// Security degradation: HttpOnly flag removed
	curr.Cookies["session_id"] = CookieDetail{Name: "session_id", HttpOnly: false, Secure: true}

	report, err := engine.Compare("sched_1", base, curr)
	if err != nil {
		t.Fatalf("Compare failed: %v", err)
	}

	if report.CookieDriftCount != 1 {
		t.Errorf("expected 1 cookie drift, got %d", report.CookieDriftCount)
	}
	if report.DriftEvents[0].Severity != "MEDIUM" {
		t.Errorf("expected MEDIUM severity for cookie security degradation, got: %s", report.DriftEvents[0].Severity)
	}
}

// -----------------------------------------------------------------------------
// Test 12: Authorization Boundary Changes
// -----------------------------------------------------------------------------
func TestCPaaS_12_AuthorizationBoundaryChanges(t *testing.T) {
	engine := NewDriftEngine()

	base := NewAttackSurfaceSnapshot("asm_base", "c1", time.Now().UTC())
	base.AuthBoundaries["GET:/admin/metrics"] = AuthBoundaryDetail{Route: "GET:/admin/metrics", RequiresAuth: true}

	curr := NewAttackSurfaceSnapshot("asm_curr", "c1", time.Now().UTC())
	// Endpoint dropped authentication requirement!
	curr.AuthBoundaries["GET:/admin/metrics"] = AuthBoundaryDetail{Route: "GET:/admin/metrics", RequiresAuth: false}

	report, err := engine.Compare("sched_1", base, curr)
	if err != nil {
		t.Fatalf("Compare failed: %v", err)
	}

	if report.AuthBoundaryDriftCount != 1 {
		t.Errorf("expected 1 auth boundary shift, got %d", report.AuthBoundaryDriftCount)
	}
	if report.DriftEvents[0].Severity != "HIGH" {
		t.Errorf("expected HIGH severity for dropped auth requirement, got: %s", report.DriftEvents[0].Severity)
	}
}

// -----------------------------------------------------------------------------
// Test 13: BOLA / IDOR Boundary Changes
// -----------------------------------------------------------------------------
func TestCPaaS_13_BOLABoundaryChanges(t *testing.T) {
	engine := NewDriftEngine()

	base := NewAttackSurfaceSnapshot("asm_base", "c1", time.Now().UTC())
	base.BOLABoundaries["GET:/api/v1/invoices"] = BOLABoundaryDetail{Route: "GET:/api/v1/invoices", IDParameters: nil}

	curr := NewAttackSurfaceSnapshot("asm_curr", "c1", time.Now().UTC())
	curr.BOLABoundaries["GET:/api/v1/invoices"] = BOLABoundaryDetail{Route: "GET:/api/v1/invoices", IDParameters: []string{"account_id", "invoice_id"}}

	report, err := engine.Compare("sched_1", base, curr)
	if err != nil {
		t.Fatalf("Compare failed: %v", err)
	}

	if report.BOLABoundaryDriftCount != 2 {
		t.Errorf("expected 2 BOLA boundary changes, got %d", report.BOLABoundaryDriftCount)
	}
}

// -----------------------------------------------------------------------------
// Test 14: Newly Discovered Findings
// -----------------------------------------------------------------------------
func TestCPaaS_14_NewlyDiscoveredFindings(t *testing.T) {
	engine := NewDriftEngine()

	base := NewAttackSurfaceSnapshot("asm_base", "c1", time.Now().UTC())

	curr := NewAttackSurfaceSnapshot("asm_curr", "c1", time.Now().UTC())
	curr.Findings["fp_sqli_01"] = FindingSnapshot{
		ID:          "fnd_1",
		Fingerprint: "fp_sqli_01",
		Title:       "SQL Injection in /api/v1/search",
		Severity:    "CRITICAL",
		Status:      "VERIFIED_DEFECT",
	}

	report, err := engine.Compare("sched_1", base, curr)
	if err != nil {
		t.Fatalf("Compare failed: %v", err)
	}

	if report.NewFindingsCount != 1 || report.NewlyVerifiedDefectsCount != 1 {
		t.Errorf("expected 1 new verified finding, got %d (verified=%d)", report.NewFindingsCount, report.NewlyVerifiedDefectsCount)
	}
}

// -----------------------------------------------------------------------------
// Test 15: Existing Finding Deduplication
// -----------------------------------------------------------------------------
func TestCPaaS_15_ExistingFindingDeduplication(t *testing.T) {
	engine := NewDriftEngine()

	fnd := FindingSnapshot{
		ID:          "fnd_1",
		Fingerprint: "fp_pers_01",
		Title:       "Persistent XSS",
		Severity:    "HIGH",
		Status:      "VERIFIED_DEFECT",
	}

	base := NewAttackSurfaceSnapshot("asm_base", "c1", time.Now().UTC())
	base.Findings["fp_pers_01"] = fnd

	curr := NewAttackSurfaceSnapshot("asm_curr", "c1", time.Now().UTC())
	curr.Findings["fp_pers_01"] = fnd

	report, err := engine.Compare("sched_1", base, curr)
	if err != nil {
		t.Fatalf("Compare failed: %v", err)
	}

	if report.NewFindingsCount != 0 || report.NewlyVerifiedDefectsCount != 0 {
		t.Errorf("expected 0 new findings for existing identical finding, got %d", report.NewFindingsCount)
	}
}

// -----------------------------------------------------------------------------
// Test 16: Finding Verification Status Transitions
// -----------------------------------------------------------------------------
func TestCPaaS_16_FindingVerificationStatusTransitions(t *testing.T) {
	engine := NewDriftEngine()

	base := NewAttackSurfaceSnapshot("asm_base", "c1", time.Now().UTC())
	base.Findings["fp_trans_01"] = FindingSnapshot{
		Fingerprint: "fp_trans_01",
		Title:       "Suspected IDOR",
		Severity:    "MEDIUM",
		Status:      "POTENTIAL", // initially unverified
	}

	curr := NewAttackSurfaceSnapshot("asm_curr", "c1", time.Now().UTC())
	curr.Findings["fp_trans_01"] = FindingSnapshot{
		Fingerprint: "fp_trans_01",
		Title:       "Suspected IDOR",
		Severity:    "HIGH",
		Status:      "VERIFIED_DEFECT", // now affirmative verified defect!
	}

	report, err := engine.Compare("sched_1", base, curr)
	if err != nil {
		t.Fatalf("Compare failed: %v", err)
	}

	if report.NewlyVerifiedDefectsCount != 1 {
		t.Errorf("expected 1 newly verified defect from status transition, got %d", report.NewlyVerifiedDefectsCount)
	}
}

// -----------------------------------------------------------------------------
// Test 17: Missing and Insufficient Historical Evidence
// -----------------------------------------------------------------------------
func TestCPaaS_17_MissingAndInsufficientHistoricalEvidence(t *testing.T) {
	engine := NewDriftEngine()

	curr := NewAttackSurfaceSnapshot("asm_curr", "c1", time.Now().UTC())
	curr.Routes["GET:/api/v1/status"] = RouteDetail{Method: "GET", Path: "/api/v1/status"}

	// Comparing with nil baseline must safely establish baseline without error or panic
	report, err := engine.Compare("sched_1", nil, curr)
	if err != nil {
		t.Fatalf("Compare with nil baseline failed: %v", err)
	}
	if report.NewRoutesCount != 1 {
		t.Errorf("expected 1 initial route, got %d", report.NewRoutesCount)
	}
}

// -----------------------------------------------------------------------------
// Test 18: Deterministic Comparison Results
// -----------------------------------------------------------------------------
func TestCPaaS_18_DeterministicComparisonResults(t *testing.T) {
	engine := NewDriftEngine()

	base := NewAttackSurfaceSnapshot("asm_base", "c1", time.Now().UTC())
	curr := NewAttackSurfaceSnapshot("asm_curr", "c1", time.Now().UTC())

	// Insert in non-sorted order
	curr.Routes["POST:/z"] = RouteDetail{Method: "POST", Path: "/z"}
	curr.Routes["GET:/a"] = RouteDetail{Method: "GET", Path: "/a"}
	curr.Routes["PUT:/m"] = RouteDetail{Method: "PUT", Path: "/m"}

	rep1, _ := engine.Compare("sched_1", base, curr)
	rep2, _ := engine.Compare("sched_1", base, curr)

	b1, _ := json.Marshal(rep1.DriftEvents)
	b2, _ := json.Marshal(rep2.DriftEvents)

	if string(b1) != string(b2) {
		t.Errorf("non-deterministic drift comparison output!")
	}
}

// -----------------------------------------------------------------------------
// Test 19: SQLite Persistence Across Restart
// -----------------------------------------------------------------------------
func TestCPaaS_19_SQLitePersistenceAcrossRestart(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "cpaas_persist.db")

	store1, _ := NewCPaaSStore(dbPath)
	sched := &ScheduleConfig{
		ID:           "sched_p_01",
		ClientID:     "client_p",
		Name:         "Persistent Schedule",
		ScheduleType: ScheduleTypeCron,
		CronExpr:     "@daily",
		TargetURLs:   []string{"https://api.persist.com"},
		Enabled:      true,
		CreatedAt:    time.Now().UTC(),
		UpdatedAt:    time.Now().UTC(),
	}
	_ = store1.SaveSchedule(context.Background(), sched)
	_ = store1.Close()

	store2, _ := NewCPaaSStore(dbPath)
	defer store2.Close()

	loaded, err := store2.GetSchedule(context.Background(), sched.ID)
	if err != nil {
		t.Fatalf("failed loading schedule after restart: %v", err)
	}
	if loaded.Name != sched.Name || loaded.TargetURLs[0] != sched.TargetURLs[0] {
		t.Errorf("corrupted data after restart: %+v", loaded)
	}
}

// -----------------------------------------------------------------------------
// Test 20: Slack, Teams, and PagerDuty Mock Integrations
// -----------------------------------------------------------------------------
func TestCPaaS_20_SlackTeamsPagerDutyMockIntegrations(t *testing.T) {
	var slackCalls, teamsCalls, pagerDutyCalls atomic.Int32

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		switch r.URL.Path {
		case "/slack":
			slackCalls.Add(1)
			if !strings.Contains(string(body), "blocks") {
				t.Errorf("invalid Slack payload: %s", string(body))
			}
			w.WriteHeader(http.StatusOK)
		case "/teams":
			teamsCalls.Add(1)
			if !strings.Contains(string(body), "MessageCard") {
				t.Errorf("invalid Teams payload: %s", string(body))
			}
			w.WriteHeader(http.StatusOK)
		case "/pagerduty":
			pagerDutyCalls.Add(1)
			if !strings.Contains(string(body), "routing_key") {
				t.Errorf("invalid PagerDuty payload: %s", string(body))
			}
			w.WriteHeader(http.StatusAccepted)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	store, _ := NewCPaaSStore(":memory:")
	defer store.Close()

	signer, reg := createTestSignerAndRegistry(t)
	notifier := NewSmartAlertNotifier(store, true, true)
	notifier.SetKeyRegistry(reg)

	sched := &ScheduleConfig{
		ID:   "sched_notify_all",
		Name: "Multi-Channel Alert Test",
		NotificationTargets: []NotificationTarget{
			{Provider: "slack", EndpointURL: server.URL + "/slack", Enabled: true},
			{Provider: "teams", EndpointURL: server.URL + "/teams", Enabled: true},
			{Provider: "pagerduty", EndpointURL: server.URL + "/pagerduty", RoutingKey: "pd-key-123", Enabled: true},
		},
	}

	ev := signTestFindingEvidence(t, signer, "fp_critical_rce", "http://example.com/app")
	driftReport := &DriftReport{
		DriftEvents: []DriftEvent{
			{
				Type:              DriftTypeNewFinding,
				AfterState:        "VERIFIED_DEFECT",
				EvidenceReference: "fp_critical_rce",
			},
		},
	}
	currSnapshot := &AttackSurfaceSnapshot{
		AssessmentID: "asm_rce",
		Findings: map[string]FindingSnapshot{
			"fp_critical_rce": {
				Fingerprint:    "fp_critical_rce",
				Title:          "Remote Code Execution via SSTI",
				Severity:       "CRITICAL",
				Status:         "VERIFIED_DEFECT",
				TargetURL:      "http://example.com/app",
				SignedEvidence: ev,
			},
		},
	}

	results, err := notifier.DispatchAlerts(context.Background(), sched, driftReport, currSnapshot)
	if err != nil {
		t.Fatalf("DispatchAlerts failed: %v", err)
	}

	if len(results) != 3 {
		t.Errorf("expected 3 delivery results, got %d", len(results))
	}
	if slackCalls.Load() != 1 || teamsCalls.Load() != 1 || pagerDutyCalls.Load() != 1 {
		t.Errorf("expected 1 call per provider: slack=%d, teams=%d, pd=%d",
			slackCalls.Load(), teamsCalls.Load(), pagerDutyCalls.Load())
	}
}

// -----------------------------------------------------------------------------
// Test 21: Notification Delivery Retries and Failures
// -----------------------------------------------------------------------------
func TestCPaaS_21_NotificationDeliveryRetriesAndFailures(t *testing.T) {
	var attempts atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		att := attempts.Add(1)
		if att < 2 {
			w.WriteHeader(http.StatusServiceUnavailable) // 503 retryable
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	store, _ := NewCPaaSStore(":memory:")
	defer store.Close()

	signer, reg := createTestSignerAndRegistry(t)
	notifier := NewSmartAlertNotifier(store, true, true)
	notifier.SetKeyRegistry(reg)
	notifier.initialBackoff = 1 * time.Millisecond // fast retry for test

	sched := &ScheduleConfig{
		ID: "sched_retry",
		NotificationTargets: []NotificationTarget{
			{Provider: "webhook", EndpointURL: server.URL + "/alert", Enabled: true},
		},
	}

	ev := signTestFindingEvidence(t, signer, "fp_retry", "http://example.com/app")
	driftReport := &DriftReport{
		DriftEvents: []DriftEvent{
			{Type: DriftTypeNewFinding, AfterState: "VERIFIED_DEFECT", EvidenceReference: "fp_retry"},
		},
	}
	currSnapshot := &AttackSurfaceSnapshot{
		Findings: map[string]FindingSnapshot{
			"fp_retry": {Fingerprint: "fp_retry", Title: "Flaw", Severity: "HIGH", Status: "VERIFIED_DEFECT", TargetURL: "http://example.com/app", SignedEvidence: ev},
		},
	}

	results, err := notifier.DispatchAlerts(context.Background(), sched, driftReport, currSnapshot)
	if err != nil || len(results) != 1 || !results[0].Delivered {
		t.Fatalf("expected successful retry delivery, got: %+v (err=%v)", results, err)
	}
	if attempts.Load() != 2 {
		t.Errorf("expected 2 attempts, got %d", attempts.Load())
	}
}

// -----------------------------------------------------------------------------
// Test 22: Notification Idempotency (Deduplication)
// -----------------------------------------------------------------------------
func TestCPaaS_22_NotificationIdempotency(t *testing.T) {
	var callCount atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	store, _ := NewCPaaSStore(":memory:")
	defer store.Close()

	signer, reg := createTestSignerAndRegistry(t)
	notifier := NewSmartAlertNotifier(store, true, true)
	notifier.SetKeyRegistry(reg)

	sched := &ScheduleConfig{
		ID: "sched_idemp",
		NotificationTargets: []NotificationTarget{
			{Provider: "slack", EndpointURL: server.URL + "/slack", Enabled: true},
		},
	}

	ev := signTestFindingEvidence(t, signer, "fp_idemp", "http://example.com/app")
	driftReport := &DriftReport{
		DriftEvents: []DriftEvent{
			{Type: DriftTypeNewFinding, AfterState: "VERIFIED_DEFECT", EvidenceReference: "fp_idemp"},
		},
	}
	currSnapshot := &AttackSurfaceSnapshot{
		Findings: map[string]FindingSnapshot{
			"fp_idemp": {Fingerprint: "fp_idemp", Title: "SQLi", Severity: "CRITICAL", Status: "VERIFIED_DEFECT", TargetURL: "http://example.com/app", SignedEvidence: ev},
		},
	}

	// Dispatch 1
	res1, _ := notifier.DispatchAlerts(context.Background(), sched, driftReport, currSnapshot)
	if len(res1) != 1 || !res1[0].Delivered {
		t.Fatalf("expected dispatch 1 to succeed")
	}

	// Dispatch 2 (Identical verified finding on same schedule)
	res2, _ := notifier.DispatchAlerts(context.Background(), sched, driftReport, currSnapshot)
	if len(res2) != 0 {
		t.Errorf("expected duplicate alert to be suppressed, got: %+v", res2)
	}
	if callCount.Load() != 1 {
		t.Errorf("expected server to be called exactly once, got %d", callCount.Load())
	}
}

// -----------------------------------------------------------------------------
// Test 23: CRITICAL GATE: Only VERIFIED_DEFECT Triggers Alerts
// -----------------------------------------------------------------------------
func TestCPaaS_23_VerificationOnlyVerifiedDefectsTriggerAlerts(t *testing.T) {
	var alertCalls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		alertCalls.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	store, _ := NewCPaaSStore(":memory:")
	defer store.Close()

	signer, reg := createTestSignerAndRegistry(t)
	notifier := NewSmartAlertNotifier(store, true, true)
	notifier.SetKeyRegistry(reg)

	sched := &ScheduleConfig{
		ID: "sched_strict_gate",
		NotificationTargets: []NotificationTarget{
			{Provider: "webhook", EndpointURL: server.URL + "/alert", Enabled: true},
		},
	}

	// Case A: Ordinary route and query drift (0 findings) -> MUST DISPATCH ZERO ALERTS
	repA := &DriftReport{
		DriftEvents: []DriftEvent{
			{Type: DriftTypeNewRoute, Entity: "GET /api/v2/items"},
			{Type: DriftTypeNewQueryParam, Entity: "GET /api/v2/items?filter"},
		},
	}
	snapA := &AttackSurfaceSnapshot{Findings: make(map[string]FindingSnapshot)}
	resA, _ := notifier.DispatchAlerts(context.Background(), sched, repA, snapA)
	if len(resA) != 0 || alertCalls.Load() != 0 {
		t.Fatalf("VIOLATION: route/query drift improperly triggered alert!")
	}

	// Case B: POTENTIAL and UNVERIFIED findings -> MUST DISPATCH ZERO ALERTS
	repB := &DriftReport{
		DriftEvents: []DriftEvent{
			{Type: DriftTypeNewFinding, AfterState: "POTENTIAL", EvidenceReference: "fp_potential"},
			{Type: DriftTypeNewFinding, AfterState: "UNVERIFIED", EvidenceReference: "fp_unverified"},
		},
	}
	snapB := &AttackSurfaceSnapshot{
		Findings: map[string]FindingSnapshot{
			"fp_potential":  {Fingerprint: "fp_potential", Status: "POTENTIAL"},
			"fp_unverified": {Fingerprint: "fp_unverified", Status: "UNVERIFIED"},
		},
	}
	resB, _ := notifier.DispatchAlerts(context.Background(), sched, repB, snapB)
	if len(resB) != 0 || alertCalls.Load() != 0 {
		t.Fatalf("VIOLATION: potential/unverified findings improperly triggered alert!")
	}

	// Case C: AFFIRMATIVE VERIFIED_DEFECT with authentic signed evidence -> MUST DISPATCH ALERT
	ev := signTestFindingEvidence(t, signer, "fp_verified", "http://example.com/app")
	repC := &DriftReport{
		DriftEvents: []DriftEvent{
			{Type: DriftTypeNewFinding, AfterState: "VERIFIED_DEFECT", EvidenceReference: "fp_verified"},
		},
	}
	snapC := &AttackSurfaceSnapshot{
		Findings: map[string]FindingSnapshot{
			"fp_verified": {Fingerprint: "fp_verified", Title: "Verified RCE", Status: "VERIFIED_DEFECT", TargetURL: "http://example.com/app", SignedEvidence: ev},
		},
	}
	resC, _ := notifier.DispatchAlerts(context.Background(), sched, repC, snapC)
	if len(resC) != 1 || alertCalls.Load() != 1 {
		t.Fatalf("expected verified defect to trigger exactly 1 alert, got: %d calls", alertCalls.Load())
	}
}

// -----------------------------------------------------------------------------
// Test 24: SSRF, Redirect, and Malformed URL Defense
// -----------------------------------------------------------------------------
func TestCPaaS_24_SSRFRedirectAndMalformedURLDefense(t *testing.T) {
	store, _ := NewCPaaSStore(":memory:")
	defer store.Close()

	signer, reg := createTestSignerAndRegistry(t)
	// Disallow loopback and private IPs to test SSRF refusal
	notifier := NewSmartAlertNotifier(store, false, false)
	notifier.SetKeyRegistry(reg)

	sched := &ScheduleConfig{
		ID: "sched_ssrf",
		NotificationTargets: []NotificationTarget{
			{Provider: "webhook", EndpointURL: "http://169.254.169.254/meta-data", Enabled: true}, // Cloud Metadata SSRF
			{Provider: "webhook", EndpointURL: "http://127.0.0.1:9999/internal", Enabled: true},    // Loopback SSRF
			{Provider: "webhook", EndpointURL: "file:///etc/passwd", Enabled: true},                 // Invalid scheme
		},
	}

	ev := signTestFindingEvidence(t, signer, "fp_ssrf_test", "http://example.com/target")
	driftReport := &DriftReport{
		DriftEvents: []DriftEvent{
			{Type: DriftTypeNewFinding, AfterState: "VERIFIED_DEFECT", EvidenceReference: "fp_ssrf_test"},
		},
	}
	currSnapshot := &AttackSurfaceSnapshot{
		Findings: map[string]FindingSnapshot{
			"fp_ssrf_test": {Fingerprint: "fp_ssrf_test", Status: "VERIFIED_DEFECT", TargetURL: "http://example.com/target", SignedEvidence: ev},
		},
	}

	results, _ := notifier.DispatchAlerts(context.Background(), sched, driftReport, currSnapshot)
	for _, res := range results {
		if res.Delivered {
			t.Errorf("CRITICAL SECURITY VIOLATION: alert was delivered to prohibited destination: %s", res.TargetURL)
		}
	}
}

// -----------------------------------------------------------------------------
// Test 25: Concurrency and Race Safety
// -----------------------------------------------------------------------------
func TestCPaaS_25_ConcurrencyAndRaceSafety(t *testing.T) {
	store, _ := NewCPaaSStore(":memory:")
	defer store.Close()

	sched := &ScheduleConfig{
		ID:           "sched_race",
		ClientID:     "client_race",
		ScheduleType: ScheduleTypeWebhook,
		Enabled:      true,
	}
	_ = store.SaveSchedule(context.Background(), sched)

	scheduler := NewCPaaSScheduler(store, NewDriftEngine(), nil, &mockAssessmentRunner{}, CPaaSSchedulerOptions{
		MaxConcurrency: 4,
	})

	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			_, _ = scheduler.TriggerWebhook(context.Background(), WebhookTriggerRequest{
				ScheduleID:     sched.ID,
				IdempotencyKey: fmt.Sprintf("race_%d", idx),
			})
		}(i)
	}

	wg.Wait()
	time.Sleep(50 * time.Millisecond)
}

// -----------------------------------------------------------------------------
// Test 26: Secret Redaction in Alerts and Errors
// -----------------------------------------------------------------------------
func TestCPaaS_26_SecretRedactionInAlertsAndLogs(t *testing.T) {
	store, _ := NewCPaaSStore(":memory:")
	defer store.Close()

	signer, reg := createTestSignerAndRegistry(t)
	notifier := NewSmartAlertNotifier(store, true, true)
	notifier.SetKeyRegistry(reg)

	sched := &ScheduleConfig{
		ID: "sched_redact",
		NotificationTargets: []NotificationTarget{
			{Provider: "webhook", EndpointURL: "http://invalid-destination-domain-99999.xyz/alert?api_key=SECRET_TOKEN_12345", Enabled: true},
		},
	}

	ev := signTestFindingEvidence(t, signer, "fp_redact", "http://example.com/app")
	driftReport := &DriftReport{
		DriftEvents: []DriftEvent{
			{Type: DriftTypeNewFinding, AfterState: "VERIFIED_DEFECT", EvidenceReference: "fp_redact"},
		},
	}
	currSnapshot := &AttackSurfaceSnapshot{
		Findings: map[string]FindingSnapshot{
			"fp_redact": {Fingerprint: "fp_redact", Title: "Secret Leak", Status: "VERIFIED_DEFECT", TargetURL: "http://example.com/app", SignedEvidence: ev},
		},
	}

	results, _ := notifier.DispatchAlerts(context.Background(), sched, driftReport, currSnapshot)
	if len(results) == 1 {
		if strings.Contains(results[0].TargetURL, "SECRET_TOKEN_12345") {
			t.Errorf("secret credential leaked in alert target URL: %s", results[0].TargetURL)
		}
	}
}

// -----------------------------------------------------------------------------
// Test 27: Continuous Drift Simulation (50 Cycles with Resource Verification)
// -----------------------------------------------------------------------------
func TestCPaaS_27_ContinuousDriftSimulation_50Cycles(t *testing.T) {
	store, err := NewCPaaSStore(":memory:")
	if err != nil {
		t.Fatalf("failed creating store: %v", err)
	}
	defer store.Close()

	engine := NewDriftEngine()
	signer, reg := createTestSignerAndRegistry(t)

	// Capture initial runtime metrics
	runtime.GC()
	var memBefore runtime.MemStats
	runtime.ReadMemStats(&memBefore)
	initialGoroutines := runtime.NumGoroutine()

	var alertsReceived atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		alertsReceived.Add(1)
		w.WriteHeader(http.StatusOK)
	}))

	notifier := NewSmartAlertNotifier(store, true, true)
	notifier.SetKeyRegistry(reg)

	sched := &ScheduleConfig{
		ID:           "sched_sim_50",
		ClientID:     "client_enterprise_sim",
		Name:         "50-Cycle Continuous Simulation",
		ScheduleType: ScheduleTypeCron,
		CronExpr:     "@hourly",
		Enabled:      true,
		NotificationTargets: []NotificationTarget{
			{Provider: "webhook", EndpointURL: server.URL + "/alert", Enabled: true},
		},
	}
	_ = store.SaveSchedule(context.Background(), sched)

	var lastSnap *AttackSurfaceSnapshot
	var totalDriftEventsObserved int
	var newlyVerifiedObserved int

	// Execute 50 simulated continuous cycles against rotating application versions
	for cycle := 1; cycle <= 50; cycle++ {
		snap := NewAttackSurfaceSnapshot(fmt.Sprintf("asm_v%d", cycle), sched.ClientID, time.Now().UTC())

		// Rotate endpoints
		snap.Routes[fmt.Sprintf("GET:/api/v%d/items", cycle)] = RouteDetail{
			Method: "GET",
			Path:   fmt.Sprintf("/api/v%d/items", cycle),
		}

		// Inject a genuine cryptographically verified defect only on cycles 10 and 30
		if cycle == 10 || cycle == 30 {
			fp := fmt.Sprintf("fp_defect_cycle_%d", cycle)
			targetURL := fmt.Sprintf("http://example.com/api/v%d", cycle)
			ev := signTestFindingEvidence(t, signer, fp, targetURL)
			snap.Findings[fp] = FindingSnapshot{
				Fingerprint:    fp,
				Title:          fmt.Sprintf("SQL Injection Introduced in v%d", cycle),
				Severity:       "HIGH",
				Status:         "VERIFIED_DEFECT",
				TargetURL:      targetURL,
				SignedEvidence: ev,
			}
		}

		// Calculate drift
		rep, err := engine.Compare(sched.ID, lastSnap, snap)
		if err != nil {
			t.Fatalf("cycle %d compare error: %v", cycle, err)
		}

		totalDriftEventsObserved += rep.TotalDriftEvents
		newlyVerifiedObserved += rep.NewlyVerifiedDefectsCount

		// Save drift report
		_ = store.SaveDriftReport(context.Background(), rep)

		// Dispatch alerts
		_, _ = notifier.DispatchAlerts(context.Background(), sched, rep, snap)

		lastSnap = snap
	}

	// Verify alert gating: exactly 2 alerts dispatched across 50 cycles!
	if alerts := alertsReceived.Load(); alerts != 2 {
		t.Errorf("expected exactly 2 alerts across 50 cycles (cycles 10 and 30), got %d", alerts)
	}

	if newlyVerifiedObserved != 2 {
		t.Errorf("expected 2 newly verified defects, got %d", newlyVerifiedObserved)
	}

	// Resource stabilization: explicitly close server, transport connections, and wait for cleanup
	server.Close()
	notifier.Close()

	time.Sleep(30 * time.Millisecond)
	runtime.GC()
	runtime.GC()

	var memAfter runtime.MemStats
	runtime.ReadMemStats(&memAfter)
	finalGoroutines := runtime.NumGoroutine()

	// Memory usage growth should be well bounded (< 50 MB for 50 cycles)
	heapAllocGrowth := int64(memAfter.HeapAlloc) - int64(memBefore.HeapAlloc)
	if heapAllocGrowth > 50*1024*1024 {
		t.Errorf("potential memory leak: heap allocation grew by %d bytes across 50 cycles", heapAllocGrowth)
	}

	// Log residual goroutines if any
	goroutineDelta := finalGoroutines - initialGoroutines
	if goroutineDelta > 0 {
		buf := make([]byte, 4096)
		n := runtime.Stack(buf, false)
		t.Logf("Goroutine measurement: initial=%d, final=%d (delta=%d). Stack:\n%s",
			initialGoroutines, finalGoroutines, goroutineDelta, string(buf[:n]))
	}

	t.Logf("50-Cycle Simulation Succeeded: Total Drift Events=%d, Verified Alerts=%d, Heap Growth=%d KB, Goroutine Delta=%d",
		totalDriftEventsObserved, alertsReceived.Load(), heapAllocGrowth/1024, goroutineDelta)
}

// -----------------------------------------------------------------------------
// Test 28: Adversarial Security - Forged VERIFIED_DEFECT Status Rejected
// -----------------------------------------------------------------------------
func TestCPaaS_28_ForgedVerifiedDefectStatusRejected(t *testing.T) {
	var alertCalls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		alertCalls.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	store, _ := NewCPaaSStore(":memory:")
	defer store.Close()

	_, reg := createTestSignerAndRegistry(t)
	notifier := NewSmartAlertNotifier(store, true, true)
	notifier.SetKeyRegistry(reg)

	sched := &ScheduleConfig{
		ID: "sched_forged",
		NotificationTargets: []NotificationTarget{
			{Provider: "webhook", EndpointURL: server.URL + "/alert", Enabled: true},
		},
	}

	// Forged: Caller supplies "VERIFIED_DEFECT" string but NO cryptographic attestation or signed evidence!
	driftReport := &DriftReport{
		DriftEvents: []DriftEvent{
			{Type: DriftTypeNewFinding, AfterState: "VERIFIED_DEFECT", EvidenceReference: "fp_forged"},
		},
	}
	currSnapshot := &AttackSurfaceSnapshot{
		Findings: map[string]FindingSnapshot{
			"fp_forged": {
				Fingerprint: "fp_forged",
				Title:       "Forged SQL Injection",
				Severity:    "HIGH",
				Status:      "VERIFIED_DEFECT", // Caller string assertion only
				// SignedEvidence: nil
				// AttestationLetter: nil
			},
		},
	}

	results, err := notifier.DispatchAlerts(context.Background(), sched, driftReport, currSnapshot)
	if err != nil {
		t.Fatalf("unexpected DispatchAlerts error: %v", err)
	}
	if len(results) != 0 || alertCalls.Load() != 0 {
		t.Fatalf("FAIL-CLOSED VIOLATION: Forged VERIFIED_DEFECT status without signed evidence triggered alert!")
	}
}

// -----------------------------------------------------------------------------
// Test 29: Adversarial Security - Untrusted Signing Key Rejected
// -----------------------------------------------------------------------------
func TestCPaaS_29_UntrustedSigningKeyRejected(t *testing.T) {
	var alertCalls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		alertCalls.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	store, _ := NewCPaaSStore(":memory:")
	defer store.Close()

	// Legitimate registry contains KEY-FELIX-TEST-001
	_, reg := createTestSignerAndRegistry(t)
	notifier := NewSmartAlertNotifier(store, true, true)
	notifier.SetKeyRegistry(reg)

	// Rogue/attacker signer with an untrusted key NOT in the registry
	rogueSigner, _, err := assessment.NewEvidenceSignerAuthority("KEY-ROGUE-ATTACKER", "Rogue Authority", "Untrusted")
	if err != nil {
		t.Fatalf("failed creating rogue signer: %v", err)
	}

	sched := &ScheduleConfig{
		ID: "sched_untrusted_key",
		NotificationTargets: []NotificationTarget{
			{Provider: "webhook", EndpointURL: server.URL + "/alert", Enabled: true},
		},
	}

	// Evidence signed by the untrusted key
	ev := signTestFindingEvidence(t, rogueSigner, "fp_untrusted", "http://example.com/app")
	driftReport := &DriftReport{
		DriftEvents: []DriftEvent{
			{Type: DriftTypeNewFinding, AfterState: "VERIFIED_DEFECT", EvidenceReference: "fp_untrusted"},
		},
	}
	currSnapshot := &AttackSurfaceSnapshot{
		Findings: map[string]FindingSnapshot{
			"fp_untrusted": {
				Fingerprint:    "fp_untrusted",
				Title:          "Defect Signed by Untrusted Key",
				Severity:       "HIGH",
				Status:         "VERIFIED_DEFECT",
				TargetURL:      "http://example.com/app",
				SignedEvidence: ev,
			},
		},
	}

	results, _ := notifier.DispatchAlerts(context.Background(), sched, driftReport, currSnapshot)
	if len(results) != 0 || alertCalls.Load() != 0 {
		t.Fatalf("SECURITY VIOLATION: Finding signed by untrusted key triggered alert!")
	}
}

// -----------------------------------------------------------------------------
// Test 30: Adversarial Security - Missing Attestation Rejected
// -----------------------------------------------------------------------------
func TestCPaaS_30_MissingAttestationRejected(t *testing.T) {
	store, _ := NewCPaaSStore(":memory:")
	defer store.Close()

	_, reg := createTestSignerAndRegistry(t)
	notifier := NewSmartAlertNotifier(store, true, true)
	notifier.SetKeyRegistry(reg)

	sched := &ScheduleConfig{
		ID: "sched_missing_att",
		NotificationTargets: []NotificationTarget{
			{Provider: "webhook", EndpointURL: "http://example.com/alert", Enabled: true},
		},
	}

	driftReport := &DriftReport{
		DriftEvents: []DriftEvent{
			{Type: DriftTypeFindingStatusChange, BeforeState: "POTENTIAL", AfterState: "VERIFIED_DEFECT", EvidenceReference: "fp_missing"},
		},
	}
	currSnapshot := &AttackSurfaceSnapshot{
		Findings: map[string]FindingSnapshot{
			"fp_missing": {
				Fingerprint:       "fp_missing",
				Title:             "Unattested Transition",
				Status:            "VERIFIED_DEFECT",
				SignedEvidence:    nil,
				AttestationLetter: nil,
			},
		},
	}

	results, _ := notifier.DispatchAlerts(context.Background(), sched, driftReport, currSnapshot)
	if len(results) != 0 {
		t.Fatalf("expected 0 alerts for missing attestation, got %d", len(results))
	}
}

// -----------------------------------------------------------------------------
// Test 31: Adversarial Security - Invalid / Corrupted Signature Rejected
// -----------------------------------------------------------------------------
func TestCPaaS_31_InvalidSignatureRejected(t *testing.T) {
	var alertCalls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		alertCalls.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	store, _ := NewCPaaSStore(":memory:")
	defer store.Close()

	signer, reg := createTestSignerAndRegistry(t)
	notifier := NewSmartAlertNotifier(store, true, true)
	notifier.SetKeyRegistry(reg)

	sched := &ScheduleConfig{
		ID: "sched_bad_sig",
		NotificationTargets: []NotificationTarget{
			{Provider: "webhook", EndpointURL: server.URL + "/alert", Enabled: true},
		},
	}

	ev := signTestFindingEvidence(t, signer, "fp_bad_sig", "http://example.com/app")
	// Corrupt the signature hex
	ev.Signature.SignatureHex = "0000000000000000" + ev.Signature.SignatureHex[16:]

	driftReport := &DriftReport{
		DriftEvents: []DriftEvent{
			{Type: DriftTypeNewFinding, AfterState: "VERIFIED_DEFECT", EvidenceReference: "fp_bad_sig"},
		},
	}
	currSnapshot := &AttackSurfaceSnapshot{
		Findings: map[string]FindingSnapshot{
			"fp_bad_sig": {
				Fingerprint:    "fp_bad_sig",
				Title:          "Corrupted Signature Defect",
				Severity:       "HIGH",
				Status:         "VERIFIED_DEFECT",
				TargetURL:      "http://example.com/app",
				SignedEvidence: ev,
			},
		},
	}

	results, _ := notifier.DispatchAlerts(context.Background(), sched, driftReport, currSnapshot)
	if len(results) != 0 || alertCalls.Load() != 0 {
		t.Fatalf("SECURITY VIOLATION: Finding with invalid digital signature triggered alert!")
	}
}

// -----------------------------------------------------------------------------
// Test 32: Adversarial Security - Modified Finding After Attestation Rejected
// -----------------------------------------------------------------------------
func TestCPaaS_32_ModifiedFindingAfterAttestationRejected(t *testing.T) {
	var alertCalls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		alertCalls.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	store, _ := NewCPaaSStore(":memory:")
	defer store.Close()

	signer, reg := createTestSignerAndRegistry(t)
	notifier := NewSmartAlertNotifier(store, true, true)
	notifier.SetKeyRegistry(reg)

	sched := &ScheduleConfig{
		ID: "sched_tampered_finding",
		NotificationTargets: []NotificationTarget{
			{Provider: "webhook", EndpointURL: server.URL + "/alert", Enabled: true},
		},
	}

	// Attestation letter generated for finding "fp_orig" with title "Original SQLi"
	letter := createTestAttestationLetter(t, signer, "fp_orig", "Original SQLi", "http://example.com/app")

	driftReport := &DriftReport{
		DriftEvents: []DriftEvent{
			{Type: DriftTypeNewFinding, AfterState: "VERIFIED_DEFECT", EvidenceReference: "fp_orig"},
		},
	}

	// Post-attestation tampering: The finding title has been modified after attestation was signed!
	currSnapshot := &AttackSurfaceSnapshot{
		Findings: map[string]FindingSnapshot{
			"fp_orig": {
				Fingerprint:       "fp_orig",
				Title:             "Tampered Finding Title Post-Signing", // Title modified!
				Severity:          "HIGH",
				Status:            "VERIFIED_DEFECT",
				TargetURL:         "http://example.com/app",
				AttestationLetter: letter,
			},
		},
	}

	results, _ := notifier.DispatchAlerts(context.Background(), sched, driftReport, currSnapshot)
	if len(results) != 0 || alertCalls.Load() != 0 {
		t.Fatalf("SECURITY VIOLATION: Finding modified after attestation triggered alert!")
	}
}

// -----------------------------------------------------------------------------
// Test 33: Legitimately Verified Finding Successfully Triggers Alert
// -----------------------------------------------------------------------------
func TestCPaaS_33_LegitimatelyVerifiedFindingAccepted(t *testing.T) {
	var alertCalls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		alertCalls.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	store, _ := NewCPaaSStore(":memory:")
	defer store.Close()

	signer, reg := createTestSignerAndRegistry(t)
	notifier := NewSmartAlertNotifier(store, true, true)
	notifier.SetKeyRegistry(reg)

	sched := &ScheduleConfig{
		ID: "sched_legit_verified",
		NotificationTargets: []NotificationTarget{
			{Provider: "webhook", EndpointURL: server.URL + "/alert", Enabled: true},
		},
	}

	ev := signTestFindingEvidence(t, signer, "fp_legit_verified", "http://example.com/app")
	letter := createTestAttestationLetter(t, signer, "fp_legit_verified", "Verified Command Injection", "http://example.com/app")

	driftReport := &DriftReport{
		DriftEvents: []DriftEvent{
			{Type: DriftTypeNewFinding, AfterState: "VERIFIED_DEFECT", EvidenceReference: "fp_legit_verified"},
		},
	}
	currSnapshot := &AttackSurfaceSnapshot{
		Findings: map[string]FindingSnapshot{
			"fp_legit_verified": {
				Fingerprint:       "fp_legit_verified",
				Title:             "Verified Command Injection",
				Severity:          "CRITICAL",
				Status:            "VERIFIED_DEFECT",
				TargetURL:         "http://example.com/app",
				SignedEvidence:    ev,
				AttestationLetter: letter,
			},
		},
	}

	results, err := notifier.DispatchAlerts(context.Background(), sched, driftReport, currSnapshot)
	if err != nil {
		t.Fatalf("DispatchAlerts failed: %v", err)
	}
	if len(results) != 1 || !results[0].Delivered {
		t.Fatalf("expected legitimately verified finding to deliver alert, got: %+v", results)
	}
	if alertCalls.Load() != 1 {
		t.Errorf("expected exactly 1 alert call, got %d", alertCalls.Load())
	}
}

// -----------------------------------------------------------------------------
// Test 34: Newly Verified Alert Semantics & Cross-Assessment Deduplication
// -----------------------------------------------------------------------------
func TestCPaaS_34_NewlyVerifiedAlertSemantics_CrossAssessmentDeduplication(t *testing.T) {
	var alertCalls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		alertCalls.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	store, _ := NewCPaaSStore(":memory:")
	defer store.Close()

	signer, reg := createTestSignerAndRegistry(t)
	notifier := NewSmartAlertNotifier(store, true, true)
	notifier.SetKeyRegistry(reg)

	sched := &ScheduleConfig{
		ID: "sched_transition_dedup",
		NotificationTargets: []NotificationTarget{
			{Provider: "slack", EndpointURL: server.URL + "/slack", Enabled: true},
			{Provider: "teams", EndpointURL: server.URL + "/teams", Enabled: true},
		},
	}
	_ = store.SaveSchedule(context.Background(), sched)

	engine := NewDriftEngine()

	// Run 1: Assessment 1 contains POTENTIAL finding (fp_auth) and UNVERIFIED finding (fp_ssrf)
	// REQ 1 & 2: Potential and unverified findings produce zero alerts!
	snap1 := NewAttackSurfaceSnapshot("asm_001", sched.ClientID, time.Now().UTC())
	snap1.Findings["fp_auth"] = FindingSnapshot{Fingerprint: "fp_auth", Title: "Broken Auth", Status: "POTENTIAL"}
	snap1.Findings["fp_ssrf"] = FindingSnapshot{Fingerprint: "fp_ssrf", Title: "SSRF Candidate", Status: "UNVERIFIED"}

	rep1, _ := engine.Compare(sched.ID, nil, snap1)
	res1, _ := notifier.DispatchAlerts(context.Background(), sched, rep1, snap1)
	if len(res1) != 0 || alertCalls.Load() != 0 {
		t.Fatalf("VIOLATION (REQ 1 & 2): Potential or unverified finding dispatched alert in Assessment 1")
	}

	// Run 2: Assessment 2 — fp_auth newly transitions from POTENTIAL -> VERIFIED_DEFECT!
	// REQ 3: A newly and independently verified defect produces one alert per configured provider!
	snap2 := NewAttackSurfaceSnapshot("asm_002", sched.ClientID, time.Now().UTC())
	evAuth := signTestFindingEvidence(t, signer, "fp_auth", "http://example.com/login")
	snap2.Findings["fp_auth"] = FindingSnapshot{
		Fingerprint:    "fp_auth",
		Title:          "Broken Auth",
		Severity:       "HIGH",
		Status:         "VERIFIED_DEFECT",
		TargetURL:      "http://example.com/login",
		SignedEvidence: evAuth,
	}
	snap2.Findings["fp_ssrf"] = snap1.Findings["fp_ssrf"]

	rep2, _ := engine.Compare(sched.ID, snap1, snap2)
	res2, _ := notifier.DispatchAlerts(context.Background(), sched, rep2, snap2)
	// 2 configured providers (slack, teams) -> exactly 2 alert calls!
	if len(res2) != 2 || alertCalls.Load() != 2 {
		t.Fatalf("VIOLATION (REQ 3): Expected 2 alerts for newly verified defect (1 per provider), got %d (alertCalls=%d)",
			len(res2), alertCalls.Load())
	}

	// Run 3: Assessment 3 — fp_auth remains VERIFIED_DEFECT.
	// REQ 4: The same verified finding in a subsequent assessment produces no repeated alert!
	snap3 := NewAttackSurfaceSnapshot("asm_003", sched.ClientID, time.Now().UTC())
	snap3.Findings["fp_auth"] = snap2.Findings["fp_auth"]
	snap3.Findings["fp_ssrf"] = snap2.Findings["fp_ssrf"]

	rep3, _ := engine.Compare(sched.ID, snap2, snap3)
	res3, _ := notifier.DispatchAlerts(context.Background(), sched, rep3, snap3)
	if len(res3) != 0 || alertCalls.Load() != 2 {
		t.Fatalf("VIOLATION (REQ 4): Persistent verified finding in subsequent assessment caused repeated alert!")
	}

	// Run 4: Assessment 4 — A different finding fp_rce is newly discovered and verified!
	// REQ 5: A different newly verified finding produces a new alert!
	snap4 := NewAttackSurfaceSnapshot("asm_004", sched.ClientID, time.Now().UTC())
	snap4.Findings["fp_auth"] = snap3.Findings["fp_auth"]
	evRCE := signTestFindingEvidence(t, signer, "fp_rce", "http://example.com/exec")
	snap4.Findings["fp_rce"] = FindingSnapshot{
		Fingerprint:    "fp_rce",
		Title:          "Remote Code Execution",
		Severity:       "CRITICAL",
		Status:         "VERIFIED_DEFECT",
		TargetURL:      "http://example.com/exec",
		SignedEvidence: evRCE,
	}

	rep4, _ := engine.Compare(sched.ID, snap3, snap4)
	res4, _ := notifier.DispatchAlerts(context.Background(), sched, rep4, snap4)
	// 2 alerts for fp_rce across the 2 providers, fp_auth suppressed!
	if len(res4) != 2 || alertCalls.Load() != 4 {
		t.Fatalf("VIOLATION (REQ 5): Different newly verified defect failed to trigger alert (got %d alerts, total calls=%d)",
			len(res4), alertCalls.Load())
	}

	// Run 5: REQ 6: Repeated execution and webhook delivery do not duplicate notifications!
	res5, _ := notifier.DispatchAlerts(context.Background(), sched, rep4, snap4)
	if len(res5) != 0 || alertCalls.Load() != 4 {
		t.Fatalf("VIOLATION (REQ 6): Repeated webhook delivery duplicated notifications! len=%d, alertCalls=%d, res5=%+v", len(res5), alertCalls.Load(), res5)
	}
}

// -----------------------------------------------------------------------------
// Test 35: SSRF and Deterministic DNS Rebinding Defense
// -----------------------------------------------------------------------------
type mockRebindingResolver struct {
	rebindToIP net.IP
}

func (m *mockRebindingResolver) LookupIPAddr(ctx context.Context, host string) ([]net.IPAddr, error) {
	// Simulates an adversarial DNS server resolving a public hostname to a prohibited IP
	return []net.IPAddr{{IP: m.rebindToIP}}, nil
}

func TestCPaaS_35_SSRFAndDeterministicDNSRebindingDefense(t *testing.T) {
	var destinationHits atomic.Int32
	// Target server simulating a protected internal service (e.g., cloud metadata or private endpoint)
	destServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		destinationHits.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer destServer.Close()

	destURL, _ := url.Parse(destServer.URL)
	destPort := destURL.Port()

	store, _ := NewCPaaSStore(":memory:")
	defer store.Close()

	signer, reg := createTestSignerAndRegistry(t)

	// Injectable resolver simulating DNS rebinding to loopback 127.0.0.1
	rebindingResolver := &mockRebindingResolver{
		rebindToIP: net.ParseIP("127.0.0.1"),
	}

	// Safe notifier strictly disallows loopback and private IPs
	notifier := NewSmartAlertNotifierWithOptions(store, SmartAlertOptions{
		AllowLoopback:   false,
		AllowPrivateIPs: false,
		Resolver:        rebindingResolver,
		KeyRegistry:     reg,
		Timeout:         2 * time.Second,
	})
	defer notifier.Close()

	sched := &ScheduleConfig{
		ID: "sched_dns_rebind",
		NotificationTargets: []NotificationTarget{
			{
				Provider:    "webhook",
				EndpointURL: fmt.Sprintf("http://rebind-attacker.external:%s/alert", destPort),
				Enabled:     true,
			},
		},
	}

	ev := signTestFindingEvidence(t, signer, "fp_rebind", "http://example.com/vuln")
	driftReport := &DriftReport{
		DriftEvents: []DriftEvent{
			{Type: DriftTypeNewFinding, AfterState: "VERIFIED_DEFECT", EvidenceReference: "fp_rebind"},
		},
	}
	currSnapshot := &AttackSurfaceSnapshot{
		Findings: map[string]FindingSnapshot{
			"fp_rebind": {
				Fingerprint:    "fp_rebind",
				Title:          "DNS Rebinding Test Finding",
				Severity:       "HIGH",
				Status:         "VERIFIED_DEFECT",
				TargetURL:      "http://example.com/vuln",
				SignedEvidence: ev,
			},
		},
	}

	results, _ := notifier.DispatchAlerts(context.Background(), sched, driftReport, currSnapshot)

	// EMPIRICAL INVARIANT: Zero requests must reach the prohibited destination!
	if hits := destinationHits.Load(); hits != 0 {
		t.Fatalf("CRITICAL SSRF / DNS REBINDING BREACH: Destination received %d requests despite SSRF refusal!", hits)
	}

	if len(results) != 1 || results[0].Delivered {
		t.Fatalf("expected alert delivery to fail closed against DNS rebinding, got: %+v", results)
	}

	if !strings.Contains(results[0].ErrorMessage, "SSRF") && !strings.Contains(results[0].ErrorMessage, "prohibited") {
		t.Errorf("expected SSRF refusal error message, got: %s", results[0].ErrorMessage)
	}
}

// -----------------------------------------------------------------------------
// Test 36: Shared SQLite Store Architecture Integration
// -----------------------------------------------------------------------------
func TestCPaaS_36_SharedSQLiteStoreIntegration(t *testing.T) {
	// Test integration with existing FELIX SQLite database using NewCPaaSStoreWithDB
	store, err := NewCPaaSStore(":memory:")
	if err != nil {
		t.Fatalf("failed initializing CPaaSStore: %v", err)
	}
	defer store.Close()

	// Verify NewCPaaSStoreWithDB initializes on the same shared DB connection
	sharedStore, err := NewCPaaSStoreWithDB(store.db)
	if err != nil {
		t.Fatalf("failed initializing CPaaSStoreWithDB: %v", err)
	}

	ctx := context.Background()
	sched := &ScheduleConfig{
		ID:           "sched_shared_db",
		ClientID:     "client_enterprise",
		Name:         "Shared DB Architecture Test",
		ScheduleType: ScheduleTypeMonthly,
		CronExpr:     "@monthly",
		Enabled:      true,
		TargetURLs:   []string{"http://example.com"},
		Profile:      "enterprise_standard",
		CreatedAt:    time.Now().UTC(),
		UpdatedAt:    time.Now().UTC(),
	}

	if err := sharedStore.SaveSchedule(ctx, sched); err != nil {
		t.Fatalf("failed saving schedule to shared store: %v", err)
	}

	// Verify reading through original store handle
	loaded, err := store.GetSchedule(ctx, sched.ID)
	if err != nil {
		t.Fatalf("failed retrieving schedule across shared handles: %v", err)
	}
	if loaded.Name != sched.Name {
		t.Errorf("expected schedule name %q, got %q", sched.Name, loaded.Name)
	}
}
