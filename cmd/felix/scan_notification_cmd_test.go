package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"felix/pkg/assessment"
	"felix/pkg/config"
	"felix/pkg/notify"
	"felix/pkg/report"
)

func TestScanNotificationSuccess(t *testing.T) {
	// Target HTTP server
	targetSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`<!DOCTYPE html><html><body><h1>Safe Page</h1></body></html>`))
	}))
	defer targetSrv.Close()

	// Webhook receiver
	var webhookReceived int32
	var lastPayload []byte
	webhookSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&webhookReceived, 1)
		b, _ := io.ReadAll(r.Body)
		lastPayload = b
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok": true}`))
	}))
	defer webhookSrv.Close()

	args := []string{
		targetSrv.URL,
		"--allow-loopback",
		"--notify",
		"--webhook=" + webhookSrv.URL,
		"--notify-provider=webhook",
		"--timeout=5s",
	}

	exitCode, stdout, stderr := captureStdoutStderr(func() int {
		return runScan(args)
	})

	// When findings are discovered without a relaxed policy, exit code is 1 (ExitSecurityFail)
	if exitCode != 1 && exitCode != 0 {
		t.Fatalf("expected assessment exit code 0 or 1, got %d. stderr: %s", exitCode, stderr)
	}

	if atomic.LoadInt32(&webhookReceived) == 0 {
		t.Fatalf("expected webhook delivery to be received, got 0 deliveries. stdout: %s, stderr: %s", stdout, stderr)
	}

	payloadStr := string(lastPayload)
	if !strings.Contains(payloadStr, targetSrv.URL) && !strings.Contains(payloadStr, "127.0.0.1") {
		t.Errorf("webhook payload did not contain target: %s", payloadStr)
	}
}

func TestScanNotificationFailurePreservesExitCode(t *testing.T) {
	// Target server
	targetSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`<html><body>Hello</body></html>`))
	}))
	defer targetSrv.Close()

	// 1. First run: Webhook succeeds
	successWebhook := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok": true}`))
	}))
	defer successWebhook.Close()

	argsSuccess := []string{
		targetSrv.URL,
		"--allow-loopback",
		"--notify",
		"--webhook=" + successWebhook.URL,
		"--notify-provider=webhook",
		"--timeout=5s",
	}

	expectedCode, _, _ := captureStdoutStderr(func() int {
		return runScan(argsSuccess)
	})

	// 2. Second run: Webhook returns 500 (transient delivery failure)
	failWebhook := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`internal webhook error`))
	}))
	defer failWebhook.Close()

	argsFail := []string{
		targetSrv.URL,
		"--allow-loopback",
		"--notify",
		"--webhook=" + failWebhook.URL,
		"--notify-provider=webhook",
		"--timeout=5s",
	}

	failCode, _, stderr := captureStdoutStderr(func() int {
		return runScan(argsFail)
	})

	// CRITICAL REQUIREMENT: Notification failure must NEVER change scan outcome or exit code!
	if failCode != expectedCode {
		t.Fatalf("expected exit code %d (same as baseline scan), but got %d when webhook failed. stderr: %s", expectedCode, failCode, stderr)
	}

	// Warning should be logged to stderr
	if !strings.Contains(stderr, "Notification delivery failed") {
		t.Errorf("expected warning in stderr about notification delivery failure, got: %s", stderr)
	}
}

func TestNotificationTestSubcommandProviders(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok": true}`))
	}))
	defer srv.Close()

	providers := []string{"webhook", "slack", "discord", "teams"}
	for _, p := range providers {
		args := []string{
			"test",
			"--url=" + srv.URL,
			"--provider=" + p,
			"--role=admin",
		}
		code, stdout, stderr := captureStdoutStderr(func() int {
			return runNotification(args)
		})
		if code != 0 {
			t.Errorf("expected exit code 0 for notification test with provider %s, got %d. stderr: %s", p, code, stderr)
		}
		if !strings.Contains(stdout, "delivered successfully") {
			t.Errorf("expected success message in stdout for provider %s, got: %s", p, stdout)
		}
	}
}

func TestNotificationStatusSubcommandOutput(t *testing.T) {
	args := []string{"status"}
	code, stdout, stderr := captureStdoutStderr(func() int {
		return runNotification(args)
	})
	if code != 0 {
		t.Fatalf("expected exit code 0 for notification status, got %d. stderr: %s", code, stderr)
	}
	if !strings.Contains(stdout, "Supported:         webhook, slack, discord, teams") {
		t.Errorf("expected supported providers list in status output, got: %s", stdout)
	}

	// Also verify JSON output format
	argsJSON := []string{"status", "--json"}
	codeJSON, stdoutJSON, _ := captureStdoutStderr(func() int {
		return runNotification(argsJSON)
	})
	if codeJSON != 0 {
		t.Fatalf("expected exit code 0 for notification status --json, got %d", codeJSON)
	}
	if !strings.Contains(stdoutJSON, `"supported_providers"`) || !strings.Contains(stdoutJSON, `"slack"`) {
		t.Errorf("expected JSON output to list supported_providers, got: %s", stdoutJSON)
	}
}

func TestAPKNotificationDispatch(t *testing.T) {
	// Create valid test APK with AndroidManifest.xml and classes.dex
	apkPath := createCLIValidAPK(t)

	var webhookCalled int32
	webhookSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&webhookCalled, 1)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status": "ok"}`))
	}))
	defer webhookSrv.Close()

	args := []string{
		apkPath,
		"--allow-loopback",
		"--notify",
		"--webhook=" + webhookSrv.URL,
		"--notify-provider=webhook",
	}

	exitCode, stdout, stderr := captureStdoutStderr(func() int {
		return runAPK(args)
	})

	if exitCode != 0 {
		t.Fatalf("expected exit code 0 for apk intake, got %d. stderr: %s", exitCode, stderr)
	}

	if atomic.LoadInt32(&webhookCalled) == 0 {
		t.Errorf("expected webhook notification from apk run, but none received. stdout: %s, stderr: %s", stdout, stderr)
	}
}

func TestScanNotificationMinSeverityFiltering(t *testing.T) {
	apkPath := createCLIValidAPK(t)

	var webhookCalled int32
	webhookSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&webhookCalled, 1)
		w.WriteHeader(http.StatusOK)
	}))
	defer webhookSrv.Close()

	// Clean APK intake produces SeverityInfo notification. Setting threshold to HIGH should filter it out.
	argsHigh := []string{
		apkPath,
		"--allow-loopback",
		"--notify",
		"--webhook=" + webhookSrv.URL,
		"--notify-min-severity=HIGH",
	}

	exitCode, _, _ := captureStdoutStderr(func() int {
		return runAPK(argsHigh)
	})
	if exitCode != 0 {
		t.Fatalf("expected exit code 0, got %d", exitCode)
	}
	if atomic.LoadInt32(&webhookCalled) != 0 {
		t.Errorf("expected notification to be filtered out by HIGH threshold, but was called %d times", atomic.LoadInt32(&webhookCalled))
	}

	// Now set threshold to INFO: should be dispatched
	atomic.StoreInt32(&webhookCalled, 0)
	argsInfo := []string{
		apkPath,
		"--allow-loopback",
		"--notify",
		"--webhook=" + webhookSrv.URL,
		"--notify-min-severity=INFO",
	}
	exitCode, _, _ = captureStdoutStderr(func() int {
		return runAPK(argsInfo)
	})
	if exitCode != 0 {
		t.Fatalf("expected exit code 0, got %d", exitCode)
	}
	if atomic.LoadInt32(&webhookCalled) != 1 {
		t.Errorf("expected notification to be dispatched with INFO threshold, but got %d", atomic.LoadInt32(&webhookCalled))
	}
}

func TestScanNotificationSSRFProtection(t *testing.T) {
	apkPath := createCLIValidAPK(t)

	// Attempt to notify cloud metadata endpoint (169.254.169.254)
	args := []string{
		apkPath,
		"--allow-loopback",
		"--notify",
		"--webhook=https://169.254.169.254/latest/meta-data",
	}

	exitCode, _, stderr := captureStdoutStderr(func() int {
		return runAPK(args)
	})

	// Scan must still complete with exit code 0, but SSRF error must be logged safely
	if exitCode != 0 {
		t.Fatalf("expected exit code 0 despite SSRF block on webhook, got %d", exitCode)
	}
	if !strings.Contains(stderr, "Notification error") && !strings.Contains(stderr, "Notification delivery failed") {
		t.Errorf("expected SSRF error logged in stderr, got: %s", stderr)
	}
}

func TestScanNotificationSecretResolutionViaEnv(t *testing.T) {
	apkPath := createCLIValidAPK(t)
	rawSecret := "super-secret-canary-hmac-key-998877"
	t.Setenv("FELIX_CUSTOM_TEST_SECRET", rawSecret)

	var lastSig string
	var lastTimestamp string
	var lastBody []byte
	webhookSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		lastSig = r.Header.Get("X-Felix-Signature")
		lastTimestamp = r.Header.Get("X-Felix-Timestamp")
		lastBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok": true}`))
	}))
	defer webhookSrv.Close()

	// 1. Pass --notify-secret env:FELIX_CUSTOM_TEST_SECRET
	args := []string{
		apkPath,
		"--allow-loopback",
		"--notify",
		"--webhook=" + webhookSrv.URL,
		"--notify-secret=env:FELIX_CUSTOM_TEST_SECRET",
	}

	exitCode, stdout, stderr := captureStdoutStderr(func() int {
		return runAPK(args)
	})

	if exitCode != 0 {
		t.Fatalf("expected exit code 0, got %d. stderr: %s", exitCode, stderr)
	}

	if lastSig == "" {
		t.Fatal("expected X-Felix-Signature header generated from env secret, but none found")
	}

	// Verify the signature matches HMAC-SHA256 (formatted as v1=<hex>)
	if err := notify.VerifyWebhookSignature(rawSecret, lastTimestamp, lastBody, lastSig, 5*time.Minute, time.Time{}); err != nil {
		t.Errorf("expected valid signature, got verification error: %v (sig: %s, ts: %s)", err, lastSig, lastTimestamp)
	}

	// Verify plaintext secret was never leaked to stdout or stderr
	if strings.Contains(stdout, rawSecret) {
		t.Errorf("stdout leaked raw secret: %s", stdout)
	}
	if strings.Contains(stderr, rawSecret) {
		t.Errorf("stderr leaked raw secret: %s", stderr)
	}
}

func computeExpectedSignature(secret string, payload []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(payload)
	return hex.EncodeToString(mac.Sum(nil))
}

func TestCriticalFindingAlertAndCompletionCoexistence(t *testing.T) {
	var receivedPayloads [][]byte
	webhookSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		receivedPayloads = append(receivedPayloads, b)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok": true}`))
	}))
	defer webhookSrv.Close()

	// Report with 1 critical finding
	rep := report.Report{
		Target:           "https://target.example.com",
		CompletionStatus: "COMPLETED",
		Duration:         "2.1s",
		RiskScore:        90,
		RiskLevel:        "CRITICAL",
		Summary: report.Summary{
			CriticalCount: 1,
		},
		Findings: []report.Finding{
			{
				ID:       "flx-sqli-01",
				RuleID:   "SQLI-CRIT",
				Title:    "SQL Injection in /api/data",
				Severity: report.SeverityCritical,
				Endpoint: "https://target.example.com/api/data",
			},
		},
	}

	cfgStore := config.Default()
	opts := scanNotifyOptions{
		enabled:       true,
		explicit:      true,
		webhookURL:    webhookSrv.URL,
		provider:      "webhook",
		allowLoopback: true,
	}

	dispatchReportNotification(rep, cfgStore, opts)

	if len(receivedPayloads) < 2 {
		t.Fatalf("expected at least 2 notifications (terminal completion AND critical finding alert), got %d", len(receivedPayloads))
	}

	var hasTerminalEvent bool
	var hasCriticalFindingAlert bool

	for _, p := range receivedPayloads {
		var payload map[string]interface{}
		_ = json.Unmarshal(p, &payload)
		evt, _ := payload["event_type"].(string)
		if evt == notify.EventAssessmentCompletedWithErrors || evt == notify.EventAssessmentCompleted {
			hasTerminalEvent = true
		}
		if evt == notify.EventSecurityFindingCritical {
			hasCriticalFindingAlert = true
		}
	}

	if !hasTerminalEvent {
		t.Errorf("critical finding alert suppressed the terminal completion event")
	}
	if !hasCriticalFindingAlert {
		t.Errorf("critical finding failed to trigger EventSecurityFindingCritical alert")
	}
}

func TestOutboxDeduplicationSemantics(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "notifications.db")
	store, err := assessment.NewSQLiteStore(dbPath)
	if err != nil {
		t.Fatalf("failed creating store: %v", err)
	}
	defer store.Close()

	now := time.Now().UTC()
	notif1 := &notify.Notification{
		ID:             "notif-dedup-1",
		TenantID:       "tenant-1",
		EventType:      notify.EventAssessmentCompleted,
		Severity:       notify.SeverityInfo,
		Title:          "Completed Run",
		Message:        "Scan completed",
		DedupKey:       "dedup-exec-100",
		DeliveryStatus: notify.DeliveryStatusPending,
		CreatedAt:      now,
		UpdatedAt:      now,
	}

	// 1. First insert must succeed
	err = store.EnqueueNotification(notif1)
	if err != nil {
		t.Fatalf("expected first enqueue to succeed, got %v", err)
	}

	// 2. Second insert with identical tenant_id and dedup_key must return ErrNotificationDuplicate
	notif2 := &notify.Notification{
		ID:             "notif-dedup-2",
		TenantID:       "tenant-1",
		EventType:      notify.EventAssessmentCompleted,
		Severity:       notify.SeverityInfo,
		Title:          "Completed Run (Duplicate)",
		Message:        "Duplicate event",
		DedupKey:       "dedup-exec-100",
		DeliveryStatus: notify.DeliveryStatusPending,
		CreatedAt:      now,
		UpdatedAt:      now,
	}

	err = store.EnqueueNotification(notif2)
	if err != assessment.ErrNotificationDuplicate {
		t.Fatalf("expected ErrNotificationDuplicate on duplicate dedup_key, got: %v", err)
	}

	// 3. Verify total outbox count is still 1
	stats, err := store.GetNotificationStats(assessment.NewAdminAuthContext())
	if err != nil {
		t.Fatalf("failed getting stats: %v", err)
	}
	if stats.TotalNotifications != 1 {
		t.Errorf("expected exactly 1 notification in outbox, got %d", stats.TotalNotifications)
	}
}
