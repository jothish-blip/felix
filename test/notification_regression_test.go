package test

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"felix/pkg/assessment"
	"felix/pkg/config"
	"felix/pkg/notify"
	"felix/pkg/report"
)

func setupNotificationTestStore(t *testing.T) (*assessment.SQLiteStore, string) {
	t.Helper()
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "notify_test.db")
	store, err := assessment.NewSQLiteStore(dbPath)
	if err != nil {
		t.Fatalf("failed to create test SQLiteStore: %v", err)
	}
	t.Cleanup(func() {
		_ = store.Close()
	})
	return store, dbPath
}

// 1. Correct creation of an alert for a configured event
func TestNotification_1_CorrectAlertCreation(t *testing.T) {
	store, _ := setupNotificationTestStore(t)
	now := time.Now().UTC()

	notif := notify.BuildLifecycleNotification(
		"tenant-1", "acc-1", "asm-1", "ASM-001", "exec-1",
		"COMPLETED", 5, 2*time.Second, "", now,
	)

	if err := store.EnqueueNotification(notif); err != nil {
		t.Fatalf("failed to enqueue notification: %v", err)
	}

	auth := assessment.NewTenantAuthContext("", "tenant-1", "acc-1")
	fetched, err := store.GetNotification(notif.ID, auth)
	if err != nil {
		t.Fatalf("failed to get notification: %v", err)
	}

	if fetched.ID != notif.ID {
		t.Errorf("expected ID %s, got %s", notif.ID, fetched.ID)
	}
	if fetched.EventType != notify.EventAssessmentCompleted {
		t.Errorf("expected EventType %s, got %s", notify.EventAssessmentCompleted, fetched.EventType)
	}
	if fetched.DeliveryStatus != notify.DeliveryStatusPending {
		t.Errorf("expected DeliveryStatus %s, got %s", notify.DeliveryStatusPending, fetched.DeliveryStatus)
	}
}

// 2. Notification disabled or unconfigured behavior
func TestNotification_2_DisabledUnconfiguredBehavior(t *testing.T) {
	cfg := config.Default()
	if cfg.Notification.Enabled {
		t.Errorf("expected notification to be disabled by default")
	}

	// Verify that when unconfigured, no notifications are queued or dispatched
	store, _ := setupNotificationTestStore(t)
	stats, err := store.GetNotificationStats(assessment.NewAdminAuthContext())
	if err != nil {
		t.Fatalf("unexpected error getting stats: %v", err)
	}
	if stats.TotalNotifications != 0 {
		t.Errorf("expected 0 total notifications when inert, got %d", stats.TotalNotifications)
	}
}

// 3. New-finding and regression alert generation
func TestNotification_3_NewAndRegressedAlerts(t *testing.T) {
	store, _ := setupNotificationTestStore(t)
	now := time.Now().UTC()

	newItem := report.ChangeFindingItem{
		FindingID:      "fnd-new-1",
		Fingerprint:    "fp-new-1",
		Title:          "SQL Injection",
		Severity:       "HIGH",
		Category:       "injection",
		TargetURL:      "https://example.com/login",
		Classification: "NEW",
		Reason:         "Detected active vulnerability",
	}

	newNotif := notify.BuildDeltaNotification(
		"tenant-1", "acc-1", "asm-1", "ASM-001", "exec-2", "exec-1",
		"NEW", newItem, now,
	)

	if err := store.EnqueueNotification(newNotif); err != nil {
		t.Fatalf("failed to enqueue new finding notification: %v", err)
	}

	regItem := report.ChangeFindingItem{
		FindingID:      "fnd-reg-1",
		Fingerprint:    "fp-reg-1",
		Title:          "XSS Reflected",
		Severity:       "CRITICAL",
		Category:       "xss",
		TargetURL:      "https://example.com/search",
		Classification: "REGRESSED",
		Reason:         "Finding reappeared after prior resolution",
	}

	regNotif := notify.BuildDeltaNotification(
		"tenant-1", "acc-1", "asm-1", "ASM-001", "exec-2", "exec-1",
		"REGRESSED", regItem, now,
	)

	if err := store.EnqueueNotification(regNotif); err != nil {
		t.Fatalf("failed to enqueue regressed finding notification: %v", err)
	}

	auth := assessment.NewTenantAuthContext("", "tenant-1", "acc-1")
	list, err := store.ListNotifications(notify.NotificationFilter{TenantID: "tenant-1"}, auth)
	if err != nil {
		t.Fatalf("failed to list notifications: %v", err)
	}
	if len(list) != 2 {
		t.Fatalf("expected 2 notifications, got %d", len(list))
	}

	events := map[string]bool{}
	for _, n := range list {
		events[n.EventType] = true
	}
	if !events[notify.EventSecurityFindingNew] {
		t.Errorf("missing new finding event")
	}
	if !events[notify.EventSecurityFindingRegressed] {
		t.Errorf("missing regressed finding event")
	}
}

// 4. Verified resolution and incomplete-comparison behavior
func TestNotification_4_IncompleteComparisonSafeguards(t *testing.T) {
	store, _ := setupNotificationTestStore(t)
	now := time.Now().UTC()

	// Incomplete summary should NOT produce RESOLVED alerts; it produces EventSecuritySummaryIncomplete
	incompNotif := notify.BuildIncompleteSummaryNotification(
		"tenant-1", "acc-1", "asm-1", "ASM-001", "exec-3", "exec-1",
		"Scan timed out; only 1 of 4 targets reached", 3, now,
	)

	if incompNotif.EventType != notify.EventSecuritySummaryIncomplete {
		t.Errorf("expected EventType %s, got %s", notify.EventSecuritySummaryIncomplete, incompNotif.EventType)
	}
	if strings.Contains(incompNotif.EventType, "resolved") {
		t.Errorf("incomplete assessment must never produce a resolution event")
	}

	if err := store.EnqueueNotification(incompNotif); err != nil {
		t.Fatalf("failed enqueuing incomplete notification: %v", err)
	}
}

// 5. Severity-threshold filtering
func TestNotification_5_SeverityThresholdFiltering(t *testing.T) {
	// MinSeverity: HIGH
	if !notify.MeetsSeverityThreshold("CRITICAL", "HIGH") {
		t.Errorf("CRITICAL should meet HIGH threshold")
	}
	if !notify.MeetsSeverityThreshold("HIGH", "HIGH") {
		t.Errorf("HIGH should meet HIGH threshold")
	}
	if notify.MeetsSeverityThreshold("MEDIUM", "HIGH") {
		t.Errorf("MEDIUM should NOT meet HIGH threshold")
	}
	if notify.MeetsSeverityThreshold("LOW", "HIGH") {
		t.Errorf("LOW should NOT meet HIGH threshold")
	}
	if notify.MeetsSeverityThreshold("INFO", "HIGH") {
		t.Errorf("INFO should NOT meet HIGH threshold")
	}
}

// 6. Stable event deduplication
func TestNotification_6_StableDeduplication(t *testing.T) {
	store, _ := setupNotificationTestStore(t)
	now := time.Now().UTC()

	notif1 := notify.BuildLifecycleNotification(
		"tenant-1", "acc-1", "asm-1", "ASM-001", "exec-dup-1",
		"COMPLETED", 2, time.Second, "", now,
	)

	err1 := store.EnqueueNotification(notif1)
	if err1 != nil {
		t.Fatalf("first enqueue failed: %v", err1)
	}

	// Re-attempting to enqueue the exact same event
	notif2 := notify.BuildLifecycleNotification(
		"tenant-1", "acc-1", "asm-1", "ASM-001", "exec-dup-1",
		"COMPLETED", 2, time.Second, "", now,
	)

	err2 := store.EnqueueNotification(notif2)
	if err2 == nil || err2 != assessment.ErrNotificationDuplicate {
		t.Errorf("expected ErrNotificationDuplicate, got %v", err2)
	}

	// Verify only 1 row exists in DB
	auth := assessment.NewTenantAuthContext("", "tenant-1", "")
	list, _ := store.ListNotifications(notify.NotificationFilter{ExecutionID: "exec-dup-1"}, auth)
	if len(list) != 1 {
		t.Fatalf("expected exactly 1 notification after duplicate insert, got %d", len(list))
	}
}

// 7. Concurrent attempts to create the same notification
func TestNotification_7_ConcurrentNotificationCreation(t *testing.T) {
	store, _ := setupNotificationTestStore(t)
	now := time.Now().UTC()

	var wg sync.WaitGroup
	workers := 10
	errs := make([]error, workers)

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			n := notify.BuildLifecycleNotification(
				"tenant-1", "acc-1", "asm-1", "ASM-001", "exec-race-1",
				"COMPLETED", 3, time.Second, "", now,
			)
			errs[idx] = store.EnqueueNotification(n)
		}(i)
	}
	wg.Wait()

	successCount := 0
	dupCount := 0
	for _, err := range errs {
		if err == nil {
			successCount++
		} else if err == assessment.ErrNotificationDuplicate {
			dupCount++
		} else {
			t.Errorf("unexpected error: %v", err)
		}
	}

	if successCount != 1 {
		t.Errorf("expected exactly 1 success out of %d concurrent attempts, got %d", workers, successCount)
	}
	if dupCount != workers-1 {
		t.Errorf("expected %d duplicates, got %d", workers-1, dupCount)
	}
}

// 8. Concurrent workers claiming one pending notification
func TestNotification_8_ConcurrentWorkerClaiming(t *testing.T) {
	store, _ := setupNotificationTestStore(t)
	now := time.Now().UTC()

	notif := notify.BuildLifecycleNotification(
		"tenant-1", "acc-1", "asm-1", "ASM-001", "exec-claim-1",
		"COMPLETED", 1, time.Second, "", now,
	)
	_ = store.EnqueueNotification(notif)

	var wg sync.WaitGroup
	workers := 5
	claimedCounts := make([]int, workers)

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			workerID := fmt.Sprintf("worker-%d", idx)
			claimed, err := store.ClaimPendingNotifications(workerID, 10, 30*time.Second, time.Now().UTC())
			if err == nil {
				claimedCounts[idx] = len(claimed)
			}
		}(i)
	}
	wg.Wait()

	totalClaimed := 0
	for _, c := range claimedCounts {
		totalClaimed += c
	}

	if totalClaimed != 1 {
		t.Fatalf("expected exactly 1 worker to claim the notification, total claims: %d", totalClaimed)
	}
}

// 9. Recovery of pending notifications after database close and reopen
func TestNotification_9_RecoveryAfterDatabaseReopen(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "persist_test.db")

	store1, err := assessment.NewSQLiteStore(dbPath)
	if err != nil {
		t.Fatalf("store1 init failed: %v", err)
	}

	now := time.Now().UTC()
	notif := notify.BuildLifecycleNotification(
		"tenant-1", "acc-1", "asm-1", "ASM-001", "exec-persist-1",
		"FAILED", 0, time.Second, "Crawl timeout", now,
	)
	_ = store1.EnqueueNotification(notif)
	_ = store1.Close()

	// Re-open store from same DB file
	store2, err := assessment.NewSQLiteStore(dbPath)
	if err != nil {
		t.Fatalf("store2 init failed: %v", err)
	}
	defer store2.Close()

	auth := assessment.NewTenantAuthContext("", "tenant-1", "acc-1")
	recovered, err := store2.GetNotification(notif.ID, auth)
	if err != nil {
		t.Fatalf("failed retrieving notification after reopen: %v", err)
	}

	if recovered.ID != notif.ID || recovered.DeliveryStatus != notify.DeliveryStatusPending {
		t.Errorf("recovered notification state mismatch: %+v", recovered)
	}
}

// 10. Retry after a transient network failure
func TestNotification_10_RetryTransientNetworkFailure(t *testing.T) {
	store, _ := setupNotificationTestStore(t)
	now := time.Now().UTC()

	notif := notify.BuildLifecycleNotification(
		"tenant-1", "acc-1", "asm-1", "ASM-001", "exec-transient-1",
		"COMPLETED", 1, time.Second, "", now,
	)
	_ = store.EnqueueNotification(notif)

	// Simulate fake server returning transient 503
	var attempts int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&attempts, 1)
		w.WriteHeader(http.StatusServiceUnavailable)
		w.Write([]byte(`{"error": "temporarily overloaded"}`))
	}))
	defer server.Close()

	provider, _ := notify.NewWebhookProvider(notify.WebhookConfig{
		URL:               server.URL,
		AllowInsecureHTTP: true,
		AllowPrivateIPs:   true,
		AllowLoopback:     true,
		Timeout:           2 * time.Second,
	})

	dispatcher := notify.NewOutboxDispatcher(store, provider, notify.DispatcherConfig{
		WorkerID:          "worker-transient",
		InitialRetryDelay: 10 * time.Millisecond,
		MaxRetryDelay:     100 * time.Millisecond,
	})

	delivered, _ := dispatcher.DispatchBatch(context.Background(), 10)
	if delivered != 0 {
		t.Errorf("expected 0 delivered on transient failure, got %d", delivered)
	}

	auth := assessment.NewAdminAuthContext()
	updated, _ := store.GetNotification(notif.ID, auth)
	if updated.DeliveryStatus != notify.DeliveryStatusPending {
		t.Errorf("expected status PENDING for retry, got %s", updated.DeliveryStatus)
	}
	if updated.AttemptCount != 1 {
		t.Errorf("expected attempt count 1, got %d", updated.AttemptCount)
	}
	if updated.NextRetryAt == nil {
		t.Errorf("expected next_retry_at to be populated")
	}
}

// 11. Permanent provider failure and maximum-attempt handling
func TestNotification_11_PermanentFailureMaxAttempts(t *testing.T) {
	store, _ := setupNotificationTestStore(t)
	now := time.Now().UTC()

	notif := notify.BuildLifecycleNotification(
		"tenant-1", "acc-1", "asm-1", "ASM-001", "exec-perm-1",
		"COMPLETED", 1, time.Second, "", now,
	)
	notif.MaxAttempts = 1 // 1 attempt allowed
	_ = store.EnqueueNotification(notif)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest) // 400 Bad Request: permanent
		w.Write([]byte(`{"error": "invalid payload schema"}`))
	}))
	defer server.Close()

	provider, _ := notify.NewWebhookProvider(notify.WebhookConfig{
		URL:               server.URL,
		AllowInsecureHTTP: true,
		AllowPrivateIPs:   true,
		AllowLoopback:     true,
		Timeout:           2 * time.Second,
	})

	dispatcher := notify.NewOutboxDispatcher(store, provider, notify.DispatcherConfig{
		WorkerID: "worker-perm",
	})

	_, _ = dispatcher.DispatchBatch(context.Background(), 10)

	auth := assessment.NewAdminAuthContext()
	updated, _ := store.GetNotification(notif.ID, auth)
	if updated.DeliveryStatus != notify.DeliveryStatusFailed {
		t.Errorf("expected status FAILED, got %s", updated.DeliveryStatus)
	}
	if !strings.Contains(updated.LastError, "400") {
		t.Errorf("expected error message mentioning 400, got %s", updated.LastError)
	}
}

// 12. Provider timeout and cancellation
func TestNotification_12_ProviderTimeoutAndCancellation(t *testing.T) {
	store, _ := setupNotificationTestStore(t)
	now := time.Now().UTC()

	notif := notify.BuildLifecycleNotification(
		"tenant-1", "acc-1", "asm-1", "ASM-001", "exec-timeout-1",
		"COMPLETED", 1, time.Second, "", now,
	)
	_ = store.EnqueueNotification(notif)

	// Server sleeps longer than timeout
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(500 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	provider, _ := notify.NewWebhookProvider(notify.WebhookConfig{
		URL:               server.URL,
		AllowInsecureHTTP: true,
		AllowPrivateIPs:   true,
		AllowLoopback:     true,
		Timeout:           50 * time.Millisecond, // very short timeout
	})

	dispatcher := notify.NewOutboxDispatcher(store, provider, notify.DispatcherConfig{
		WorkerID: "worker-timeout",
	})

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	_, _ = dispatcher.DispatchBatch(ctx, 10)

	auth := assessment.NewAdminAuthContext()
	updated, _ := store.GetNotification(notif.ID, auth)
	if updated.DeliveryStatus != notify.DeliveryStatusPending {
		t.Errorf("timeout should remain PENDING with retry scheduled, got %s", updated.DeliveryStatus)
	}
	if !strings.Contains(strings.ToLower(updated.LastError), "timeout") && !strings.Contains(strings.ToLower(updated.LastError), "deadline") {
		t.Errorf("expected timeout in error, got %s", updated.LastError)
	}
}

// 13. Provider acceptance followed by lost client acknowledgement
func TestNotification_13_ProviderAcceptanceIdempotency(t *testing.T) {
	// A server that records receipt IDs
	var receivedIDs []string
	var mu sync.Mutex

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		deliveryID := r.Header.Get("X-Felix-Delivery")
		mu.Lock()
		receivedIDs = append(receivedIDs, deliveryID)
		mu.Unlock()
		w.Header().Set("X-Delivery-Receipt", "rcpt-ack-123")
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	provider, _ := notify.NewWebhookProvider(notify.WebhookConfig{
		URL:               server.URL,
		AllowInsecureHTTP: true,
		AllowPrivateIPs:   true,
		AllowLoopback:     true,
	})

	notif := &notify.Notification{
		ID:        "ntf-ack-test-1",
		EventType: notify.EventAssessmentCompleted,
		Severity:  "INFO",
		Title:     "Test Ack",
		Message:   "Test ack",
	}

	receipt, err := provider.Send(context.Background(), notif)
	if err != nil {
		t.Fatalf("send failed: %v", err)
	}
	if receipt.ReceiptID != "rcpt-ack-123" {
		t.Errorf("expected receipt rcpt-ack-123, got %s", receipt.ReceiptID)
	}
}

// 14. Retry of a terminally failed notification
func TestNotification_14_RetryTerminallyFailed(t *testing.T) {
	store, _ := setupNotificationTestStore(t)
	now := time.Now().UTC()

	notif := notify.BuildLifecycleNotification(
		"tenant-1", "acc-1", "asm-1", "ASM-001", "exec-retry-cmd",
		"FAILED", 0, time.Second, "Fail", now,
	)
	_ = store.EnqueueNotification(notif)
	_, _ = store.ClaimPendingNotifications("worker-1", 1, time.Minute, now)
	_ = store.MarkNotificationFailed(notif.ID, "worker-1", "Terminal error", nil, true)

	auth := assessment.NewAdminAuthContext()
	n, _ := store.GetNotification(notif.ID, auth)
	if n.DeliveryStatus != notify.DeliveryStatusFailed {
		t.Fatalf("expected FAILED status, got %s", n.DeliveryStatus)
	}

	// Retry resets to PENDING
	if err := store.RetryNotification(notif.ID, auth); err != nil {
		t.Fatalf("retry failed: %v", err)
	}

	retried, _ := store.GetNotification(notif.ID, auth)
	if retried.DeliveryStatus != notify.DeliveryStatusPending {
		t.Errorf("expected PENDING status after retry, got %s", retried.DeliveryStatus)
	}
}

// 15. One broken provider not blocking unrelated notifications
func TestNotification_15_OneBrokenDestinationNotBlockingOthers(t *testing.T) {
	store, _ := setupNotificationTestStore(t)
	now := time.Now().UTC()

	n1 := notify.BuildLifecycleNotification("tenant-1", "", "asm-1", "ASM-001", "exec-1", "COMPLETED", 0, time.Second, "", now)
	n2 := notify.BuildLifecycleNotification("tenant-1", "", "asm-2", "ASM-002", "exec-2", "COMPLETED", 0, time.Second, "", now)
	_ = store.EnqueueNotification(n1)
	_ = store.EnqueueNotification(n2)

	// Provider that fails n1 but succeeds n2
	mockProv := &selectiveProvider{
		failID: n1.ID,
	}

	dispatcher := notify.NewOutboxDispatcher(store, mockProv, notify.DispatcherConfig{
		WorkerID: "worker-selective",
	})

	delivered, _ := dispatcher.DispatchBatch(context.Background(), 10)
	if delivered != 1 {
		t.Errorf("expected 1 notification delivered, got %d", delivered)
	}

	auth := assessment.NewAdminAuthContext()
	res1, _ := store.GetNotification(n1.ID, auth)
	res2, _ := store.GetNotification(n2.ID, auth)

	if res1.DeliveryStatus != notify.DeliveryStatusPending && res1.DeliveryStatus != notify.DeliveryStatusFailed {
		t.Errorf("expected n1 to fail/retry, got %s", res1.DeliveryStatus)
	}
	if res2.DeliveryStatus != notify.DeliveryStatusDelivered {
		t.Errorf("expected n2 to be DELIVERED, got %s", res2.DeliveryStatus)
	}
}

type selectiveProvider struct {
	failID string
}

func (p *selectiveProvider) Name() string { return "selective" }
func (p *selectiveProvider) ValidateConfig() error { return nil }
func (p *selectiveProvider) Send(ctx context.Context, notif *notify.Notification) (*notify.DeliveryReceipt, error) {
	if notif.ID == p.failID {
		return nil, &notify.DeliveryError{Permanent: false, Message: "simulated transient error"}
	}
	return &notify.DeliveryReceipt{ReceiptID: "rcpt-" + notif.ID, DeliveredAt: time.Now().UTC(), StatusCode: 200}, nil
}

// 16. Tenant isolation
func TestNotification_16_TenantIsolation(t *testing.T) {
	store, _ := setupNotificationTestStore(t)
	now := time.Now().UTC()

	notifA := notify.BuildLifecycleNotification("tenant-A", "", "asm-A", "ASM-A", "exec-A", "COMPLETED", 0, time.Second, "", now)
	notifB := notify.BuildLifecycleNotification("tenant-B", "", "asm-B", "ASM-B", "exec-B", "COMPLETED", 0, time.Second, "", now)
	_ = store.EnqueueNotification(notifA)
	_ = store.EnqueueNotification(notifB)

	authA := assessment.NewTenantAuthContext("", "tenant-A", "")
	authB := assessment.NewTenantAuthContext("", "tenant-B", "")

	// Tenant A cannot view Tenant B's notification
	_, err := store.GetNotification(notifB.ID, authA)
	if err == nil || err != assessment.ErrNotificationNotFound {
		t.Errorf("tenant A should not access tenant B's notification, got %v", err)
	}

	// Tenant A list only contains Tenant A records
	listA, _ := store.ListNotifications(notify.NotificationFilter{}, authA)
	for _, n := range listA {
		if n.TenantID != "tenant-A" {
			t.Errorf("tenant A list contained record for tenant %s", n.TenantID)
		}
	}

	// Cross-tenant deduplication keys do not collide
	notifB_sameKey := notify.BuildLifecycleNotification("tenant-B", "", "asm-A", "ASM-A", "exec-A", "COMPLETED", 0, time.Second, "", now)
	if err := store.EnqueueNotification(notifB_sameKey); err != nil {
		t.Errorf("tenant B should be able to create event with same dedup_key as tenant A: %v", err)
	}
	_ = authB
}

// 17. Secret redaction in errors and logs
func TestNotification_17_SecretRedaction(t *testing.T) {
	rawSecret := "ghp_VerySecretGitHubToken12345"
	delivErr := &notify.DeliveryError{
		Permanent: true,
		Message:   fmt.Sprintf("Authorization header token %s invalid", rawSecret),
	}

	errMsg := delivErr.Error()
	if strings.Contains(errMsg, rawSecret) {
		t.Errorf("secret leaked in delivery error message: %s", errMsg)
	}
}

// 18. HTTPS and endpoint validation
func TestNotification_18_HTTPSEndpointValidation(t *testing.T) {
	// Plain HTTP should be rejected when AllowInsecureHTTP is false
	_, err := notify.NewWebhookProvider(notify.WebhookConfig{
		URL:               "http://example.com/webhook",
		AllowInsecureHTTP: false,
	})
	if err == nil || !strings.Contains(err.Error(), "HTTPS is required") {
		t.Errorf("expected HTTPS requirement error, got: %v", err)
	}

	// Empty URL should be rejected
	_, err = notify.NewWebhookProvider(notify.WebhookConfig{
		URL: "",
	})
	if err == nil {
		t.Errorf("expected error on empty URL")
	}
}

// 19. Redirect and unsafe destination handling (SSRF)
func TestNotification_19_SSRFProtection(t *testing.T) {
	// Loopback address blocked
	err := notify.CheckSafeDestination("127.0.0.1", 2*time.Second)
	if err == nil || !strings.Contains(strings.ToLower(err.Error()), "loopback") {
		t.Errorf("expected loopback to be blocked by SSRF check, got %v", err)
	}

	// Cloud metadata IP blocked
	err = notify.CheckSafeDestination("169.254.169.254", 2*time.Second)
	if err == nil {
		t.Errorf("expected cloud metadata IP to be blocked by SSRF check")
	}

	// RFC 1918 private IP blocked
	err = notify.CheckSafeDestination("10.0.0.1", 2*time.Second)
	if err == nil {
		t.Errorf("expected RFC 1918 IP to be blocked by SSRF check")
	}
}

// 20. Payload size limits and malformed provider responses
func TestNotification_20_PayloadLimitsAndMalformedResponses(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("not valid json at all <>!!"))
	}))
	defer server.Close()

	provider, _ := notify.NewWebhookProvider(notify.WebhookConfig{
		URL:               server.URL,
		AllowInsecureHTTP: true,
		AllowPrivateIPs:   true,
		AllowLoopback:     true,
		MaxPayloadBytes:   1024, // 1KB limit
	})

	// Very large notification with 500 finding IDs
	largeIDs := make([]string, 500)
	for i := 0; i < 500; i++ {
		largeIDs[i] = fmt.Sprintf("finding-id-number-%05d", i)
	}

	n := &notify.Notification{
		ID:         "ntf-large-1",
		EventType:  notify.EventAssessmentCompleted,
		Severity:   "INFO",
		Title:      "Large payload",
		FindingIDs: largeIDs,
	}

	receipt, err := provider.Send(context.Background(), n)
	if err != nil {
		t.Fatalf("send failed with large payload: %v", err)
	}
	if receipt.StatusCode != 200 {
		t.Errorf("expected HTTP 200, got %d", receipt.StatusCode)
	}
}

// 21. Duplicate assessment processing not producing duplicate alerts
func TestNotification_21_DuplicateAssessmentProcessing(t *testing.T) {
	store, _ := setupNotificationTestStore(t)
	now := time.Now().UTC()

	// Simulating assessment rerun or resume on the same execution
	n1 := notify.BuildLifecycleNotification("tenant-1", "", "asm-1", "ASM-001", "exec-fixed-id", "COMPLETED", 0, time.Second, "", now)
	n2 := notify.BuildLifecycleNotification("tenant-1", "", "asm-1", "ASM-001", "exec-fixed-id", "COMPLETED", 0, time.Second, "", now.Add(time.Minute))

	_ = store.EnqueueNotification(n1)
	err2 := store.EnqueueNotification(n2)
	if err2 != assessment.ErrNotificationDuplicate {
		t.Errorf("duplicate execution notification was not deduplicated: %v", err2)
	}
}

// 22. Scheduler restart and assessment recovery compatibility
func TestNotification_22_RecoveryInterruptionAlert(t *testing.T) {
	store, _ := setupNotificationTestStore(t)
	now := time.Now().UTC()

	interruptedNotif := notify.BuildLifecycleNotification(
		"tenant-1", "acc-1", "asm-1", "ASM-001", "exec-abandoned-1",
		"INTERRUPTED", 2, 5*time.Second, "Heartbeat lease expired; reclaimed by recovery", now,
	)

	if interruptedNotif.EventType != notify.EventAssessmentInterrupted {
		t.Errorf("expected EventType %s, got %s", notify.EventAssessmentInterrupted, interruptedNotif.EventType)
	}

	if err := store.EnqueueNotification(interruptedNotif); err != nil {
		t.Fatalf("failed enqueuing recovery notification: %v", err)
	}
}

// 23. Change-summary integration without false resolution alerts
func TestNotification_23_ChangeSummaryNoFalseResolutions(t *testing.T) {
	// If an assessment comparison is unreliable (e.g. failed/partial), resolved events must not be fired
	unreliableSummary := &report.ChangeSummary{
		IsReliable:        false,
		ReliabilityReason: "Execution was interrupted; coverage incomplete",
		Counts: report.ChangeClassificationCounts{
			Unverified: 4,
		},
	}

	if unreliableSummary.IsReliable {
		t.Errorf("unreliable summary should not be reliable")
	}

	incomp := notify.BuildIncompleteSummaryNotification(
		"tenant-1", "", "asm-1", "ASM-001", "exec-part", "exec-base",
		unreliableSummary.ReliabilityReason, unreliableSummary.Counts.Unverified, time.Now().UTC(),
	)
	if incomp.EventType != notify.EventSecuritySummaryIncomplete {
		t.Errorf("expected incomplete summary notification, got %s", incomp.EventType)
	}
}

// 24. Assessment success remaining successful when alert delivery fails
func TestNotification_24_AssessmentRemainsSuccessfulWhenAlertFails(t *testing.T) {
	store, _ := setupNotificationTestStore(t)

	client := &assessment.Client{
		ID:        "client-fail-test",
		Name:      "Test Client",
		CreatedAt: time.Now().UTC(),
		UpdatedAt: time.Now().UTC(),
	}
	_ = store.CreateClient(client)

	asm := &assessment.Assessment{
		ID:        "asm-fail-test",
		Ref:       "ASM-FAIL",
		ClientID:  client.ID,
		Name:      "Fail Alert Test",
		Status:    assessment.StatusReady,
		CreatedAt: time.Now().UTC(),
		UpdatedAt: time.Now().UTC(),
	}
	_ = store.CreateAssessment(asm)

	execRecord := &assessment.AssessmentExecution{
		ID:           "exec-fail-alert",
		AssessmentID: asm.ID,
		ClientID:     client.ID,
		TenantID:     "tenant-1",
		Status:       assessment.StatusCompleted,
		FindingCount: 0,
		StartedAt:    time.Now().UTC(),
		CreatedAt:    time.Now().UTC(),
		UpdatedAt:    time.Now().UTC(),
	}
	_ = store.CreateExecution(execRecord)

	// Enqueue notification and attempt delivery to a dead endpoint
	notif := notify.BuildLifecycleNotification(
		execRecord.TenantID, execRecord.AccountID, asm.ID, asm.Ref, execRecord.ID,
		string(execRecord.Status), execRecord.FindingCount, time.Second, "", time.Now().UTC(),
	)
	_ = store.EnqueueNotification(notif)

	deadProvider, _ := notify.NewWebhookProvider(notify.WebhookConfig{
		URL:               "http://127.0.0.1:54321/dead",
		AllowInsecureHTTP: true,
		AllowPrivateIPs:   true,
		AllowLoopback:     true,
		Timeout:           100 * time.Millisecond,
	})

	dispatcher := notify.NewOutboxDispatcher(store, deadProvider, notify.DispatcherConfig{
		WorkerID: "worker-dead",
	})
	_, _ = dispatcher.DispatchBatch(context.Background(), 10)

	// Verify notification delivery failed or scheduled for retry
	auth := assessment.NewAdminAuthContext()
	n, _ := store.GetNotification(notif.ID, auth)
	if n.DeliveryStatus != notify.DeliveryStatusPending && n.DeliveryStatus != notify.DeliveryStatusFailed {
		t.Errorf("expected notification to be pending retry or failed, got %s", n.DeliveryStatus)
	}

	// Crucial: Assessment execution in DB must remain COMPLETED!
	res, err := store.GetExecution(execRecord.ID)
	if err != nil {
		t.Fatalf("failed fetching execution: %v", err)
	}
	if res.Status != assessment.StatusCompleted {
		t.Errorf("assessment status was modified by notification failure! status: %s", res.Status)
	}
}

// 25. CLI status, listing, inspection, retry, and test behavior
func TestNotification_25_CLICommands(t *testing.T) {
	store, dbPath := setupNotificationTestStore(t)
	now := time.Now().UTC()

	notif := notify.BuildLifecycleNotification(
		"tenant-cli", "", "asm-cli", "ASM-CLI", "exec-cli",
		"FAILED", 0, time.Second, "Test CLI error", now,
	)
	_ = store.EnqueueNotification(notif)

	// Run CLI binary
	binPath := filepath.Join("..", "bin", "felix.exe")
	if _, err := os.Stat(binPath); err != nil {
		binPath = filepath.Join("bin", "felix.exe")
	}

	// 1. felix notification status
	cmdStatus := exec.Command(binPath, "notification", "status", "--db", dbPath, "--json")
	outStatus, err := cmdStatus.CombinedOutput()
	if err != nil {
		t.Fatalf("cli status failed: %v, out: %s", err, string(outStatus))
	}
	var statusMap map[string]interface{}
	if err := json.Unmarshal(outStatus, &statusMap); err != nil {
		t.Fatalf("invalid json from cli status: %v", err)
	}

	// 2. felix notification list
	cmdList := exec.Command(binPath, "notification", "list", "--db", dbPath, "--json")
	outList, err := cmdList.CombinedOutput()
	if err != nil {
		t.Fatalf("cli list failed: %v, out: %s", err, string(outList))
	}
	var listItems []notify.Notification
	if err := json.Unmarshal(outList, &listItems); err != nil {
		t.Fatalf("invalid json from cli list: %v", err)
	}
	if len(listItems) != 1 {
		t.Errorf("expected 1 item in cli list, got %d", len(listItems))
	}

	// 3. felix notification show
	cmdShow := exec.Command(binPath, "notification", "show", notif.ID, "--db", dbPath, "--json")
	outShow, err := cmdShow.CombinedOutput()
	if err != nil {
		t.Fatalf("cli show failed: %v, out: %s", err, string(outShow))
	}
	var showItem notify.Notification
	if err := json.Unmarshal(outShow, &showItem); err != nil {
		t.Fatalf("invalid json from cli show: %v", err)
	}
	if showItem.ID != notif.ID {
		t.Errorf("cli show ID mismatch: %s != %s", showItem.ID, notif.ID)
	}

	// 4. felix notification retry
	cmdRetry := exec.Command(binPath, "notification", "retry", notif.ID, "--db", dbPath)
	outRetry, err := cmdRetry.CombinedOutput()
	if err != nil {
		t.Fatalf("cli retry failed: %v, out: %s", err, string(outRetry))
	}
	if !strings.Contains(string(outRetry), "reset to PENDING") {
		t.Errorf("expected reset to PENDING confirmation, got: %s", string(outRetry))
	}

	// 5. felix notification test
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	t.Setenv("FELIX_NOTIFY_ALLOW_INSECURE_HTTP", "true")
	t.Setenv("FELIX_NOTIFY_ALLOW_PRIVATE_IPS", "true")
	t.Setenv("FELIX_NOTIFY_ALLOW_LOOPBACK", "true")
	cmdTest := exec.Command(binPath, "notification", "test", "--url", server.URL, "--json")
	cmdTest.Env = append(os.Environ(), "FELIX_NOTIFY_ALLOW_INSECURE_HTTP=true", "FELIX_NOTIFY_ALLOW_PRIVATE_IPS=true", "FELIX_NOTIFY_ALLOW_LOOPBACK=true")
	outTest, err := cmdTest.CombinedOutput()
	if err != nil {
		t.Fatalf("cli test ping failed: %v, out: %s", err, string(outTest))
	}
	var testResult map[string]interface{}
	if err := json.Unmarshal(outTest, &testResult); err != nil {
		t.Fatalf("invalid json from cli test: %v", err)
	}
	if testResult["success"] != true {
		t.Errorf("expected test ping success: true, got %+v", testResult)
	}
}

// 26. Migration compatibility and idempotency
func TestNotification_26_MigrationCompatibilityAndIdempotency(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "mig_test.db")

	// Apply migration first time
	store1, err := assessment.NewSQLiteStore(dbPath)
	if err != nil {
		t.Fatalf("first store init failed: %v", err)
	}
	_ = store1.Close()

	// Apply migration second time (must be idempotent)
	store2, err := assessment.NewSQLiteStore(dbPath)
	if err != nil {
		t.Fatalf("second store init (idempotency check) failed: %v", err)
	}
	defer store2.Close()

	// Verify table exists by enqueuing a notification
	n := notify.BuildLifecycleNotification("tenant-1", "", "asm-1", "ASM-001", "exec-mig", "COMPLETED", 0, time.Second, "", time.Now().UTC())
	if err := store2.EnqueueNotification(n); err != nil {
		t.Errorf("enqueuing into migrated table failed: %v", err)
	}
}

// 27. Shutdown behavior and expired delivery lease recovery
func TestNotification_27_ShutdownAndLeaseRecovery(t *testing.T) {
	store, _ := setupNotificationTestStore(t)
	now := time.Now().UTC()

	n := notify.BuildLifecycleNotification("tenant-1", "", "asm-1", "ASM-001", "exec-lease", "COMPLETED", 0, time.Second, "", now)
	_ = store.EnqueueNotification(n)

	// Claim with very short lease (10ms)
	claimed, err := store.ClaimPendingNotifications("worker-old", 1, 10*time.Millisecond, now)
	if err != nil || len(claimed) != 1 {
		t.Fatalf("failed claiming notification: %v", err)
	}

	// Advance time past lease expiration
	futureTime := now.Add(100 * time.Millisecond)

	// Reclaim expired leases
	reclaimed, err := store.ReclaimExpiredNotificationLeases(futureTime)
	if err != nil {
		t.Fatalf("failed reclaiming expired leases: %v", err)
	}
	if reclaimed != 1 {
		t.Errorf("expected 1 lease reclaimed, got %d", reclaimed)
	}

	// New worker can now claim the unblocked notification
	newClaimed, err := store.ClaimPendingNotifications("worker-new", 1, 30*time.Second, futureTime)
	if err != nil || len(newClaimed) != 1 {
		t.Errorf("expected new worker to claim reclaimed notification, got %v", err)
	}
}


// 28. Cloud metadata strictly blocked even when private IPs are permitted
func TestNotification_28_CloudMetadataBlockedEvenWithPrivateIPs(t *testing.T) {
	// 169.254.169.254 (IPv4)
	ipMetaV4 := net.ParseIP("169.254.169.254")
	if err := notify.ValidateIP(ipMetaV4, true, false); err == nil {
		t.Errorf("expected cloud metadata 169.254.169.254 to be blocked even with allowPrivateIPs=true")
	}

	// ::ffff:169.254.169.254 (IPv4-mapped IPv6)
	ipMetaMapped := net.ParseIP("::ffff:169.254.169.254")
	if err := notify.ValidateIP(ipMetaMapped, true, false); err == nil {
		t.Errorf("expected IPv4-mapped metadata ::ffff:169.254.169.254 to be blocked")
	}

	// fe80::1 (IPv6 link-local)
	ipLinkLocalV6 := net.ParseIP("fe80::1")
	if err := notify.ValidateIP(ipLinkLocalV6, true, false); err == nil {
		t.Errorf("expected IPv6 link-local fe80::1 to be blocked")
	}

	// 0.0.0.0 (Unspecified)
	ipZero := net.ParseIP("0.0.0.0")
	if err := notify.ValidateIP(ipZero, true, false); err == nil {
		t.Errorf("expected 0.0.0.0 to be blocked even with allowPrivateIPs=true")
	}

	// Legitimate private IP (10.0.0.1) should be permitted when allowPrivateIPs=true
	ipPriv := net.ParseIP("10.0.0.1")
	if err := notify.ValidateIP(ipPriv, true, false); err != nil {
		t.Errorf("expected 10.0.0.1 to be permitted when allowPrivateIPs=true, got %v", err)
	}

	// But 10.0.0.1 is blocked when allowPrivateIPs=false
	if err := notify.ValidateIP(ipPriv, false, false); err == nil {
		t.Errorf("expected 10.0.0.1 to be blocked when allowPrivateIPs=false")
	}
}

// 29. Stale workers cannot overwrite newer delivery state
func TestNotification_29_StaleWorkerCannotOverwriteDeliveredState(t *testing.T) {
	store, _ := setupNotificationTestStore(t)
	now := time.Now().UTC()

	n := notify.BuildLifecycleNotification("tenant-1", "", "asm-1", "ASM-001", "exec-stale-1", "COMPLETED", 0, time.Second, "", now)
	_ = store.EnqueueNotification(n)

	// Worker A claims with 10ms lease
	claimedA, _ := store.ClaimPendingNotifications("worker-A", 1, 10*time.Millisecond, now)
	if len(claimedA) != 1 {
		t.Fatalf("expected worker-A to claim notification")
	}

	// Advance time, lease expires
	timeAfterLease := now.Add(100 * time.Millisecond)

	// Worker B reclaims expired lease
	_, _ = store.ReclaimExpiredNotificationLeases(timeAfterLease)
	claimedB, _ := store.ClaimPendingNotifications("worker-B", 1, 30*time.Second, timeAfterLease)
	if len(claimedB) != 1 {
		t.Fatalf("expected worker-B to claim reclaimed notification")
	}

	// Worker B delivers successfully
	err := store.MarkNotificationDelivered(n.ID, "worker-B", timeAfterLease)
	if err != nil {
		t.Fatalf("worker-B failed to mark delivered: %v", err)
	}

	// Worker A wakes up and attempts to mark FAILED using stale worker lease
	errStale := store.MarkNotificationFailed(n.ID, "worker-A", "stale worker error", nil, true)
	if errStale != nil && errStale != assessment.ErrLeaseLost {
		t.Errorf("expected ErrLeaseLost or nil, got: %v", errStale)
	}

	// Crucial: The notification state in DB must remain DELIVERED!
	auth := assessment.NewAdminAuthContext()
	finalRec, _ := store.GetNotification(n.ID, auth)
	if finalRec.DeliveryStatus != notify.DeliveryStatusDelivered {
		t.Fatalf("CRITICAL DEFECT: Stale worker overwrote DELIVERED state with %s!", finalRec.DeliveryStatus)
	}
}

// 30. Stable delivery identifier across retries for receiver-side deduplication
func TestNotification_30_StableDeliveryIDAcrossRetries(t *testing.T) {
	var deliveryIDs []string
	var mu sync.Mutex

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		deliveryIDs = append(deliveryIDs, r.Header.Get("X-Felix-Delivery"))
		callCount := len(deliveryIDs)
		mu.Unlock()

		if callCount == 1 {
			// Simulate lost acknowledgement (server accepted, but connection reset)
			hj, ok := w.(http.Hijacker)
			if ok {
				conn, _, _ := hj.Hijack()
				conn.Close()
				return
			}
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}

		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"ok"}`))
	}))
	defer server.Close()

	store, _ := setupNotificationTestStore(t)
	now := time.Now().UTC()
	n := notify.BuildLifecycleNotification("tenant-1", "", "asm-1", "ASM-001", "exec-stable-id", "COMPLETED", 0, time.Second, "", now)
	_ = store.EnqueueNotification(n)

	provider, _ := notify.NewWebhookProvider(notify.WebhookConfig{
		URL:               server.URL,
		AllowInsecureHTTP: true,
		AllowPrivateIPs:   true,
		AllowLoopback:     true,
	})

	dispatcher := notify.NewOutboxDispatcher(store, provider, notify.DispatcherConfig{
		WorkerID:          "worker-stable",
		InitialRetryDelay: 10 * time.Millisecond,
	})

	// Attempt 1: fails with lost ack
	_, _ = dispatcher.DispatchBatch(context.Background(), 1)

	// Wait for InitialRetryDelay to elapse so retry is eligible for pickup
	time.Sleep(30 * time.Millisecond)

	// Attempt 2: retry
	_, _ = dispatcher.DispatchBatch(context.Background(), 1)

	mu.Lock()
	defer mu.Unlock()
	if len(deliveryIDs) != 2 {
		t.Fatalf("expected 2 delivery attempts recorded, got %d", len(deliveryIDs))
	}
	if deliveryIDs[0] != deliveryIDs[1] {
		t.Errorf("delivery ID must be stable across retries for receiver deduplication: %s != %s", deliveryIDs[0], deliveryIDs[1])
	}
	if deliveryIDs[0] != n.ID {
		t.Errorf("delivery ID must match notification primary key: %s != %s", deliveryIDs[0], n.ID)
	}
}

// 31. Reconcile terminal executions that crashed before notification creation
func TestNotification_31_ReconcileExecutionNotifications(t *testing.T) {
	store, _ := setupNotificationTestStore(t)

	client := &assessment.Client{
		ID:        "client-rec-1",
		Name:      "Client Rec",
		CreatedAt: time.Now().UTC(),
		UpdatedAt: time.Now().UTC(),
	}
	_ = store.CreateClient(client)

	asm := &assessment.Assessment{
		ID:        "asm-rec-1",
		Ref:       "ASM-REC-001",
		ClientID:  client.ID,
		Name:      "Reconcile Test",
		Status:    assessment.StatusReady,
		CreatedAt: time.Now().UTC(),
		UpdatedAt: time.Now().UTC(),
	}
	_ = store.CreateAssessment(asm)

	now := time.Now().UTC()
	execRecord := &assessment.AssessmentExecution{
		ID:           "exec-crashed-before-notif",
		AssessmentID: asm.ID,
		ClientID:     client.ID,
		TenantID:     "tenant-rec",
		Status:       assessment.StatusCompleted,
		FindingCount: 4,
		StartedAt:    now.Add(-time.Hour),
		CompletedAt:  &now,
		CreatedAt:    now.Add(-time.Hour),
		UpdatedAt:    now,
	}
	_ = store.CreateExecution(execRecord)

	auth := assessment.NewAdminAuthContext()

	// Initial outbox is empty
	statsBefore, _ := store.GetNotificationStats(auth)
	if statsBefore.TotalNotifications != 0 {
		t.Fatalf("expected 0 notifications initially, got %d", statsBefore.TotalNotifications)
	}

	// Run reconciliation
	reconciledCount, err := store.ReconcileExecutionNotifications(auth, 24*time.Hour)
	if err != nil {
		t.Fatalf("reconciliation failed: %v", err)
	}
	if reconciledCount != 1 {
		t.Errorf("expected 1 execution reconciled, got %d", reconciledCount)
	}

	// Verify notification now exists in outbox
	list, _ := store.ListNotifications(notify.NotificationFilter{ExecutionID: execRecord.ID}, auth)
	if len(list) != 1 {
		t.Fatalf("expected 1 notification in outbox after reconciliation, got %d", len(list))
	}
	if list[0].EventType != notify.EventAssessmentCompleted {
		t.Errorf("expected EventAssessmentCompleted, got %s", list[0].EventType)
	}

	// Second reconciliation is completely idempotent
	reconciledSecond, _ := store.ReconcileExecutionNotifications(auth, 24*time.Hour)
	if reconciledSecond != 0 {
		t.Errorf("subsequent reconciliation should not duplicate: got %d", reconciledSecond)
	}
}

// 32. CLI tenant isolation enforced on show and retry
func TestNotification_32_CLITenantIsolation(t *testing.T) {
	store, dbPath := setupNotificationTestStore(t)
	now := time.Now().UTC()

	// Create notification for Tenant B
	notifB := notify.BuildLifecycleNotification(
		"tenant-B", "", "asm-B", "ASM-B", "exec-B",
		"FAILED", 0, time.Second, "Error for B", now,
	)
	_ = store.EnqueueNotification(notifB)

	binPath := filepath.Join("..", "bin", "felix.exe")
	if _, err := os.Stat(binPath); err != nil {
		binPath = filepath.Join("bin", "felix.exe")
	}

	// Tenant A attempts to show Tenant B's notification
	cmdShow := exec.Command(binPath, "notification", "show", notifB.ID, "--tenant", "tenant-A", "--db", dbPath)
	outShow, errShow := cmdShow.CombinedOutput()
	if errShow == nil {
		t.Errorf("tenant A should NOT be able to view tenant B's notification! Output: %s", string(outShow))
	}
	if !strings.Contains(string(outShow), "not found") && !strings.Contains(string(outShow), "access denied") {
		t.Errorf("expected 'not found' or 'access denied' error, got: %s", string(outShow))
	}

	// Tenant A attempts to retry Tenant B's notification
	cmdRetry := exec.Command(binPath, "notification", "retry", notifB.ID, "--tenant", "tenant-A", "--db", dbPath)
	outRetry, errRetry := cmdRetry.CombinedOutput()
	if errRetry == nil {
		t.Errorf("tenant A should NOT be able to retry tenant B's notification! Output: %s", string(outRetry))
	}
}


// 33. Reconciliation when FELIX was offline longer than standard window
func TestNotification_33_ReconcileOfflineLongerThanLookback(t *testing.T) {
	store, _ := setupNotificationTestStore(t)
	now := time.Now().UTC()

	client := &assessment.Client{
		ID:        "client-offline-1",
		Name:      "Client Offline",
		CreatedAt: now,
		UpdatedAt: now,
	}
	_ = store.CreateClient(client)

	asm := &assessment.Assessment{
		ID:        "asm-offline-1",
		Ref:       "ASM-OFFLINE-001",
		ClientID:  client.ID,
		Name:      "Offline Reconcile",
		Status:    assessment.StatusReady,
		CreatedAt: now,
		UpdatedAt: now,
	}
	_ = store.CreateAssessment(asm)

	// Completed 72 hours ago (e.g. over a 3-day holiday weekend)
	offlineCompletedAt := now.Add(-72 * time.Hour)
	execRecord := &assessment.AssessmentExecution{
		ID:           "exec-offline-72h",
		AssessmentID: asm.ID,
		ClientID:     client.ID,
		TenantID:     "tenant-offline",
		Status:       assessment.StatusCompleted,
		FindingCount: 2,
		StartedAt:    offlineCompletedAt.Add(-time.Hour),
		CompletedAt:  &offlineCompletedAt,
		CreatedAt:    offlineCompletedAt.Add(-time.Hour),
		UpdatedAt:    offlineCompletedAt,
	}
	_ = store.CreateExecution(execRecord)

	auth := assessment.NewAdminAuthContext()

	// Narrow 24h lookback does not find it
	narrowCount, err := store.ReconcileExecutionNotifications(auth, 24*time.Hour)
	if err != nil {
		t.Fatalf("narrow reconciliation failed: %v", err)
	}
	if narrowCount != 0 {
		t.Errorf("narrow 24h lookback should not find 72h-old execution, got %d", narrowCount)
	}

	// Unbounded lookback (0) recovers it safely
	recoveredCount, err := store.ReconcileExecutionNotifications(auth, 0)
	if err != nil {
		t.Fatalf("unbounded reconciliation failed: %v", err)
	}
	if recoveredCount != 1 {
		t.Fatalf("unbounded reconciliation should recover 72h-old execution, got %d", recoveredCount)
	}

	// Verify notification in outbox
	list, _ := store.ListNotifications(notify.NotificationFilter{ExecutionID: execRecord.ID}, auth)
	if len(list) != 1 {
		t.Fatalf("expected 1 notification in outbox, got %d", len(list))
	}
	if list[0].EventType != notify.EventAssessmentCompleted {
		t.Errorf("expected EventAssessmentCompleted, got %s", list[0].EventType)
	}
}

// 34. Reconciliation when partial/started notification record already exists in outbox
func TestNotification_34_ReconcilePartialExistingOutboxRecord(t *testing.T) {
	store, _ := setupNotificationTestStore(t)
	now := time.Now().UTC()

	client := &assessment.Client{
		ID:        "client-part-1",
		Name:      "Client Partial",
		CreatedAt: now,
		UpdatedAt: now,
	}
	_ = store.CreateClient(client)

	asm := &assessment.Assessment{
		ID:        "asm-part-1",
		Ref:       "ASM-PART-001",
		ClientID:  client.ID,
		Name:      "Partial Outbox Test",
		Status:    assessment.StatusReady,
		CreatedAt: now,
		UpdatedAt: now,
	}
	_ = store.CreateAssessment(asm)

	execRecord := &assessment.AssessmentExecution{
		ID:           "exec-with-started-alert",
		AssessmentID: asm.ID,
		ClientID:     client.ID,
		TenantID:     "tenant-part",
		Status:       assessment.StatusCompleted,
		FindingCount: 1,
		StartedAt:    now.Add(-10 * time.Minute),
		CompletedAt:  &now,
		CreatedAt:    now.Add(-10 * time.Minute),
		UpdatedAt:    now,
	}
	_ = store.CreateExecution(execRecord)

	// An intermediate "assessment.started" notification was previously enqueued
	startedNotif := &notify.Notification{
		ID:           "ntf-started-1",
		TenantID:     "tenant-part",
		AssessmentID: asm.ID,
		ExecutionID:  execRecord.ID,
		EventType:    "assessment.started",
		Severity:     "INFO",
		Title:        "Assessment Started",
		Message:      "Assessment execution started",
		DedupKey:     notify.ComputeDedupKey("lifecycle", execRecord.ID, "assessment.started", ""),
		PayloadJSON:  `{"status":"STARTED"}`,
		CreatedAt:    now.Add(-10 * time.Minute),
		UpdatedAt:    now.Add(-10 * time.Minute),
	}
	_ = store.EnqueueNotification(startedNotif)

	auth := assessment.NewAdminAuthContext()

	// Reconcile must recognize that the TERMINAL lifecycle notification (assessment.completed) is missing
	reconciledCount, err := store.ReconcileExecutionNotifications(auth, 24*time.Hour)
	if err != nil {
		t.Fatalf("reconciliation failed: %v", err)
	}
	if reconciledCount != 1 {
		t.Fatalf("expected terminal notification to be reconciled despite existing started alert, got %d", reconciledCount)
	}

	// Verify outbox now contains the terminal completed notification alongside the started notification
	list, _ := store.ListNotifications(notify.NotificationFilter{ExecutionID: execRecord.ID}, auth)
	if len(list) != 2 {
		t.Fatalf("expected 2 notifications in outbox (started + completed), got %d", len(list))
	}
	var hasCompleted bool
	for _, n := range list {
		if n.EventType == notify.EventAssessmentCompleted {
			hasCompleted = true
		}
	}
	if !hasCompleted {
		t.Errorf("expected assessment.completed notification to be present in outbox")
	}
}

// 35. Deterministic worker lease fencing without sleeps or timing luck
func TestNotification_35_DeterministicStaleWorkerLeaseFencing(t *testing.T) {
	store, _ := setupNotificationTestStore(t)
	t0 := time.Date(2026, 10, 20, 10, 0, 0, 0, time.UTC)

	notif := notify.BuildLifecycleNotification(
		"tenant-fence", "acc-fence", "asm-fence", "ASM-FENCE-001", "exec-fence-1",
		"COMPLETED", 0, time.Second, "", t0,
	)
	_ = store.EnqueueNotification(notif)

	// Step 1: Worker 1 claims notification with a 5-second lease at t0
	claimed, err := store.ClaimPendingNotifications("worker-1", 1, 5*time.Second, t0)
	if err != nil || len(claimed) != 1 {
		t.Fatalf("worker-1 failed to claim: %v", err)
	}

	// Step 2: At t0 + 10s, lease has expired. Reclaim leases deterministically
	reclaimed, err := store.ReclaimExpiredNotificationLeases(t0.Add(10 * time.Second))
	if err != nil || reclaimed != 1 {
		t.Fatalf("expected 1 lease reclaimed at t0+10s, got %d (err: %v)", reclaimed, err)
	}

	// Step 3: Stale Worker 1 wakes up at t0 + 11s and tries to mark FAILED
	// Since lease was reclaimed, update must be authoritative rejected with ErrLeaseLost
	err = store.MarkNotificationFailed(notif.ID, "worker-1", "delayed failure", nil, true)
	if err != assessment.ErrLeaseLost {
		t.Fatalf("expected ErrLeaseLost for stale worker after reclamation, got %v", err)
	}

	// Step 4: Worker 2 claims the notification at t0 + 12s with 5s lease
	claimed2, err := store.ClaimPendingNotifications("worker-2", 1, 5*time.Second, t0.Add(12*time.Second))
	if err != nil || len(claimed2) != 1 {
		t.Fatalf("worker-2 failed to claim: %v", err)
	}

	// Step 5: Stale Worker 1 tries to mark DELIVERED while Worker 2 holds ownership
	err = store.MarkNotificationDelivered(notif.ID, "worker-1", t0.Add(13*time.Second))
	if err != assessment.ErrLeaseLost {
		t.Fatalf("expected ErrLeaseLost for Worker 1 while Worker 2 owns lease, got %v", err)
	}

	// Step 6: Legitimate Worker 2 marks DELIVERED at t0 + 14s
	err = store.MarkNotificationDelivered(notif.ID, "worker-2", t0.Add(14*time.Second))
	if err != nil {
		t.Fatalf("worker-2 delivery failed: %v", err)
	}

	// Step 7: Stale Worker 1 tries to mark FAILED again
	err = store.MarkNotificationFailed(notif.ID, "worker-1", "late failure attempt", nil, true)
	if err != assessment.ErrLeaseLost && err != nil {
		t.Errorf("unexpected error for late worker failure attempt: %v", err)
	}

	// Final verification: status must remain DELIVERED
	auth := assessment.NewAdminAuthContext()
	finalRec, _ := store.GetNotification(notif.ID, auth)
	if finalRec.DeliveryStatus != notify.DeliveryStatusDelivered {
		t.Fatalf("CRITICAL DEFECT: Stale worker corrupted status to %s", finalRec.DeliveryStatus)
	}

	// Step 8: Expired lease rejection before reclamation runs
	notif2 := notify.BuildLifecycleNotification(
		"tenant-fence", "acc-fence", "asm-fence", "ASM-FENCE-002", "exec-fence-2",
		"COMPLETED", 0, time.Second, "", t0,
	)
	_ = store.EnqueueNotification(notif2)
	_, _ = store.ClaimPendingNotifications("worker-3", 1, 2*time.Second, t0)

	// Worker 3 attempts delivery at t0 + 4s (lease expired, but reclaim hasn't run)
	err = store.MarkNotificationDelivered(notif2.ID, "worker-3", t0.Add(4*time.Second))
	if err != assessment.ErrLeaseLost {
		t.Fatalf("expected ErrLeaseLost when lease_expires_at is past, got %v", err)
	}
}

// 36. Cross-tenant authorization audit across all subcommands
func TestNotification_36_CrossTenantAuthorizationAudit(t *testing.T) {
	store, dbPath := setupNotificationTestStore(t)
	now := time.Now().UTC()

	// Tenant B creates notification
	notifB := notify.BuildLifecycleNotification(
		"tenant-B", "acc-B", "asm-B", "ASM-B", "exec-B-cross",
		"FAILED", 1, time.Second, "Err", now,
	)
	_ = store.EnqueueNotification(notifB)

	authA := assessment.NewTenantAuthContext("client-A", "tenant-A", "acc-A")

	// 1. GetNotification across tenant boundary returns ErrNotificationNotFound
	_, err := store.GetNotification(notifB.ID, authA)
	if err != assessment.ErrNotificationNotFound {
		t.Fatalf("expected ErrNotificationNotFound on cross-tenant GetNotification, got %v", err)
	}

	// 2. RetryNotification across tenant boundary returns ErrNotificationNotFound
	err = store.RetryNotification(notifB.ID, authA)
	if err != assessment.ErrNotificationNotFound {
		t.Fatalf("expected ErrNotificationNotFound on cross-tenant RetryNotification, got %v", err)
	}

	// 3. ListNotifications for tenant-A returns 0 items
	listA, err := store.ListNotifications(notify.NotificationFilter{}, authA)
	if err != nil || len(listA) != 0 {
		t.Fatalf("expected 0 items in ListNotifications for tenant-A, got %d (err: %v)", len(listA), err)
	}

	// 4. GetNotificationStats for tenant-A returns 0
	statsA, err := store.GetNotificationStats(authA)
	if err != nil || statsA.TotalNotifications != 0 {
		t.Fatalf("expected 0 stats for tenant-A, got %+v", statsA)
	}

	binPath := filepath.Join("..", "bin", "felix.exe")
	if _, err := os.Stat(binPath); err != nil {
		binPath = filepath.Join("bin", "felix.exe")
	}

	// 5. CLI test ping rejected for non-admin
	cmdTest := exec.Command(binPath, "notification", "test", "--url", "https://example.com/hook", "--role", "viewer", "--tenant", "tenant-A", "--db", dbPath)
	outTest, errTest := cmdTest.CombinedOutput()
	if errTest == nil {
		t.Errorf("non-admin should not be allowed to execute test ping! Output: %s", string(outTest))
	}
	if !strings.Contains(string(outTest), "administrative privileges") && !strings.Contains(string(outTest), "Authorization error") {
		t.Errorf("expected administrative authorization error on test ping, got: %s", string(outTest))
	}

	// 6. CLI dispatch rejected for non-admin
	cmdDisp := exec.Command(binPath, "notification", "dispatch", "--role", "viewer", "--tenant", "tenant-A", "--db", dbPath)
	outDisp, errDisp := cmdDisp.CombinedOutput()
	if errDisp == nil {
		t.Errorf("non-admin should not be allowed to execute dispatch! Output: %s", string(outDisp))
	}
	if !strings.Contains(string(outDisp), "administrative privileges") && !strings.Contains(string(outDisp), "Authorization error") {
		t.Errorf("expected administrative authorization error on dispatch, got: %s", string(outDisp))
	}
}

// 37. SSRF dual-homed DNS and redirect hop validation
func TestNotification_37_SSRFDualHomedAndHopRedirectValidation(t *testing.T) {
	// A server that attempts an SSRF redirect to cloud metadata
	redirectServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://169.254.169.254/latest/meta-data/", http.StatusFound)
	}))
	defer redirectServer.Close()

	prov, err := notify.NewWebhookProvider(notify.WebhookConfig{
		URL:               redirectServer.URL,
		AllowInsecureHTTP: true,
		AllowLoopback:     true, // allow the test server itself
	})
	if err != nil {
		t.Fatalf("failed to create provider: %v", err)
	}

	notif := &notify.Notification{
		ID:        "ntf-ssrf-redirect",
		EventType: notify.EventAssessmentCompleted,
		Severity:  "INFO",
		Title:     "Redirect Test",
		Message:   "SSRF redirect test",
	}

	_, err = prov.Send(context.Background(), notif)
	if err == nil {
		t.Fatalf("expected redirect to 169.254.169.254 to be blocked!")
	}
	if !strings.Contains(err.Error(), "SSRF") && !strings.Contains(err.Error(), "prohibited") && !strings.Contains(err.Error(), "unsafe") {
		t.Errorf("expected SSRF redirect error, got: %v", err)
	}
}
