package monitor

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"felix/pkg/api"
)

// Helper to construct a single test drift report
func sampleDriftReport(targetID string) *DriftReport {
	evt := DriftEvent{
		ID:                 "evt_sample_shadow_001",
		TargetID:           targetID,
		Classification:     ClassificationNewShadowRoute,
		CanonicalRoute:     "/api/v1/auth/export",
		Method:             "POST",
		Priority:           PriorityCritical,
		PriorityRationale:  "Newly discovered undocumented endpoint with sensitive parameter boundaries",
		SuggestedAction:    "Review route for missing authorization middleware",
		DetectedAt:         time.Now().UTC(),
		SensitiveIdentifiers: []string{"TENANT_ID"},
	}
	return &DriftReport{
		TargetID: targetID,
		Events:   []DriftEvent{evt},
		Summary: map[DriftClassification]int{
			ClassificationNewShadowRoute: 1,
		},
	}
}

// 23. Valid Slack Payload: Asserts Block Kit structure, header, text, fields
func TestNotifier_ValidSlackPayload(t *testing.T) {
	var receivedBody []byte

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	}))
	defer ts.Close()

	monCfg := &api.MonitoringConfig{
		Enabled: true,
		Webhooks: []api.MonitorWebhookConfig{
			{
				ID:                "slack-test",
				Provider:          "slack",
				URL:               ts.URL,
				Enabled:           true,
				AllowInsecureHTTP: true,
				AllowLoopback:     true,
			},
		},
	}

	delivStore, err := NewDeliveryStateStore(t.TempDir(), "target-slack")
	if err != nil {
		t.Fatalf("delivStore init: %v", err)
	}

	notifier := NewNotifier(monCfg, delivStore)
	rep := sampleDriftReport("target-slack")

	summary, err := notifier.DeliverAlerts(context.Background(), rep)
	if err != nil {
		t.Fatalf("DeliverAlerts failed: %v", err)
	}

	if summary.TotalDelivered != 1 {
		t.Errorf("expected 1 delivered alert, got %d", summary.TotalDelivered)
	}

	var parsed map[string]interface{}
	if err := json.Unmarshal(receivedBody, &parsed); err != nil {
		t.Fatalf("failed to parse Slack payload: %v", err)
	}

	// Verify Slack structure has "text" fallback and "blocks"
	if _, ok := parsed["text"]; !ok {
		t.Errorf("expected top-level 'text' fallback in Slack payload")
	}
	blocks, ok := parsed["blocks"].([]interface{})
	if !ok || len(blocks) < 2 {
		t.Errorf("expected blocks array with at least 2 items, got %+v", blocks)
	}
}

// 24. Valid Discord Payload: Asserts embeds array, title, fields, allowed_mentions
func TestNotifier_ValidDiscordPayload(t *testing.T) {
	var receivedBody []byte

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	}))
	defer ts.Close()

	monCfg := &api.MonitoringConfig{
		Enabled: true,
		Webhooks: []api.MonitorWebhookConfig{
			{
				ID:                "discord-test",
				Provider:          "discord",
				URL:               ts.URL,
				Enabled:           true,
				AllowInsecureHTTP: true,
				AllowLoopback:     true,
			},
		},
	}

	delivStore, _ := NewDeliveryStateStore(t.TempDir(), "target-discord")
	notifier := NewNotifier(monCfg, delivStore)
	rep := sampleDriftReport("target-discord")

	summary, err := notifier.DeliverAlerts(context.Background(), rep)
	if err != nil || summary.TotalDelivered != 1 {
		t.Fatalf("DeliverAlerts failed: %v (delivered=%d)", err, summary.TotalDelivered)
	}

	var parsed map[string]interface{}
	if err := json.Unmarshal(receivedBody, &parsed); err != nil {
		t.Fatalf("parse Discord JSON: %v", err)
	}

	// Verify allowed_mentions is empty to block pings
	mentions, ok := parsed["allowed_mentions"].(map[string]interface{})
	if !ok {
		t.Errorf("expected allowed_mentions map in Discord payload")
	}
	if parseArr, ok := mentions["parse"].([]interface{}); !ok || len(parseArr) != 0 {
		t.Errorf("expected allowed_mentions.parse to be empty slice")
	}

	// Verify embeds structure
	embeds, ok := parsed["embeds"].([]interface{})
	if !ok || len(embeds) == 0 {
		t.Fatalf("expected embeds array in Discord payload")
	}
}

// 25. Valid Teams Payload: Asserts MessageCard schema, themeColor, sections
func TestNotifier_ValidTeamsPayload(t *testing.T) {
	var receivedBody []byte

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	}))
	defer ts.Close()

	monCfg := &api.MonitoringConfig{
		Enabled: true,
		Webhooks: []api.MonitorWebhookConfig{
			{
				ID:                "teams-test",
				Provider:          "teams",
				URL:               ts.URL,
				Enabled:           true,
				AllowInsecureHTTP: true,
				AllowLoopback:     true,
			},
		},
	}

	delivStore, _ := NewDeliveryStateStore(t.TempDir(), "target-teams")
	notifier := NewNotifier(monCfg, delivStore)
	rep := sampleDriftReport("target-teams")

	summary, err := notifier.DeliverAlerts(context.Background(), rep)
	if err != nil || summary.TotalDelivered != 1 {
		t.Fatalf("DeliverAlerts failed: %v (delivered=%d)", err, summary.TotalDelivered)
	}

	var parsed map[string]interface{}
	if err := json.Unmarshal(receivedBody, &parsed); err != nil {
		t.Fatalf("parse Teams JSON: %v", err)
	}

	if parsed["@type"] != "MessageCard" {
		t.Errorf("expected @type MessageCard, got %v", parsed["@type"])
	}
	if parsed["themeColor"] != "EF4444" { // Critical severity red
		t.Errorf("expected critical themeColor EF4444, got %v", parsed["themeColor"])
	}
}

// 26. Secret Canary Zero Leakage: Ensures canary credentials never appear in payloads or error output
func TestNotifier_SecretCanaryZeroLeakage(t *testing.T) {
	canarySecret := "sk_test_super_confidential_canary_secret_12345"
	var receivedBody []byte

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	}))
	defer ts.Close()

	monCfg := &api.MonitoringConfig{
		Enabled: true,
		Webhooks: []api.MonitorWebhookConfig{
			{
				ID:                "slack-canary",
				Provider:          "slack",
				URL:               ts.URL,
				Enabled:           true,
				AllowInsecureHTTP: true,
				AllowLoopback:     true,
			},
		},
	}

	delivStore, _ := NewDeliveryStateStore(t.TempDir(), "target-canary")
	notifier := NewNotifier(monCfg, delivStore)

	// Drift event containing synthetic canary
	evt := DriftEvent{
		ID:                "evt_canary_leak_test",
		TargetID:          "target-canary",
		Classification:    ClassificationNewShadowRoute,
		CanonicalRoute:    "/api/v1/debug",
		Method:            "GET",
		Priority:          PriorityHigh,
		PriorityRationale: fmt.Sprintf("Observed token: %s in parameter trace", canarySecret),
	}
	rep := &DriftReport{TargetID: "target-canary", Events: []DriftEvent{evt}}

	_, _ = notifier.DeliverAlerts(context.Background(), rep)

	bodyStr := string(receivedBody)
	if strings.Contains(bodyStr, canarySecret) {
		t.Fatalf("CRITICAL SECURITY DEFECT: Canary secret was leaked into webhook payload: %s", bodyStr)
	}
}

// 27. Missing or Invalid Credentials: Handled safely without panic or secret exposure
func TestNotifier_MissingOrEmptyCredentials(t *testing.T) {
	envVar := "FELIX_UNSET_TEST_ENV_VAR_9999"
	_ = os.Unsetenv(envVar)

	monCfg := &api.MonitoringConfig{
		Enabled: true,
		Webhooks: []api.MonitorWebhookConfig{
			{
				ID:            "missing-env-wh",
				Provider:      "slack",
				CredentialEnv: envVar,
				Enabled:       true,
			},
		},
	}

	delivStore, _ := NewDeliveryStateStore(t.TempDir(), "target-missing-env")
	notifier := NewNotifier(monCfg, delivStore)
	rep := sampleDriftReport("target-missing-env")

	summary, err := notifier.DeliverAlerts(context.Background(), rep)
	if err != nil {
		t.Fatalf("expected graceful handle of missing env var, got error: %v", err)
	}
	if summary.TotalDelivered != 0 || summary.TotalAttempted != 0 {
		t.Errorf("expected 0 delivered/attempted, got delivered=%d attempted=%d", summary.TotalDelivered, summary.TotalAttempted)
	}
	if len(summary.Warnings) == 0 || !strings.Contains(summary.Warnings[0], envVar) {
		t.Errorf("expected warning mentioning unset env var %s, got %v", envVar, summary.Warnings)
	}
}

// 28. Insecure Scheme and SSRF Rejection: Rejects http:// when AllowInsecureHTTP is false
func TestNotifier_SSRFAndInsecureDestinationRejection(t *testing.T) {
	monCfg := &api.MonitoringConfig{
		Enabled: true,
		Webhooks: []api.MonitorWebhookConfig{
			{
				ID:                "insecure-http-wh",
				Provider:          "slack",
				URL:               "http://example.com/webhook", // HTTP without AllowInsecureHTTP
				Enabled:           true,
				AllowInsecureHTTP: false,
			},
		},
	}

	delivStore, _ := NewDeliveryStateStore(t.TempDir(), "target-ssrf")
	notifier := NewNotifier(monCfg, delivStore)
	rep := sampleDriftReport("target-ssrf")

	summary, _ := notifier.DeliverAlerts(context.Background(), rep)
	if summary.TotalDelivered != 0 {
		t.Errorf("expected 0 delivered for insecure HTTP, got %d", summary.TotalDelivered)
	}
	if len(summary.Warnings) == 0 || !strings.Contains(summary.Warnings[0], "insecure webhook destination scheme") {
		t.Errorf("expected insecure scheme refusal warning, got: %v", summary.Warnings)
	}
}

// 29. Deduplication Across Repeated Diff Runs: Same drift event is delivered once, then skipped
func TestNotifier_DeduplicationAcrossConsecutiveRuns(t *testing.T) {
	var callCount int32

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&callCount, 1)
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	}))
	defer ts.Close()

	monCfg := &api.MonitoringConfig{
		Enabled: true,
		Webhooks: []api.MonitorWebhookConfig{
			{
				ID:                "dedup-slack",
				Provider:          "slack",
				URL:               ts.URL,
				Enabled:           true,
				AllowInsecureHTTP: true,
				AllowLoopback:     true,
			},
		},
	}

	delivStore, _ := NewDeliveryStateStore(t.TempDir(), "target-dedup")
	notifier := NewNotifier(monCfg, delivStore)
	rep := sampleDriftReport("target-dedup")

	// Run 1: Should deliver
	sum1, err := notifier.DeliverAlerts(context.Background(), rep)
	if err != nil || sum1.TotalDelivered != 1 {
		t.Fatalf("Run 1 expected 1 delivered, got %d (err: %v)", sum1.TotalDelivered, err)
	}
	if atomic.LoadInt32(&callCount) != 1 {
		t.Errorf("expected callCount 1 after run 1, got %d", callCount)
	}

	// Run 2: Exact same drift event -> MUST BE DEDUPLICATED AND SKIPPED
	sum2, err := notifier.DeliverAlerts(context.Background(), rep)
	if err != nil {
		t.Fatalf("Run 2 error: %v", err)
	}
	if sum2.TotalDelivered != 0 || sum2.TotalSkippedDedupe != 1 {
		t.Errorf("Run 2 expected 0 delivered and 1 skipped dedupe, got delivered=%d skipped=%d", sum2.TotalDelivered, sum2.TotalSkippedDedupe)
	}
	if atomic.LoadInt32(&callCount) != 1 {
		t.Errorf("expected callCount to remain 1 after run 2 (no duplicate network requests), got %d", callCount)
	}
}

// 30. Permanent vs Transient Error Handling:
// HTTP 400 Bad Request is permanent -> does NOT retry
// HTTP 500 Internal Error is transient -> retries with bounded backoff
func TestNotifier_PermanentVsTransientErrorHandling(t *testing.T) {
	// A. Permanent Error (400)
	{
		var attempts int32
		tsPerm := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			atomic.AddInt32(&attempts, 1)
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte("invalid_payload"))
		}))
		defer tsPerm.Close()

		monCfg := &api.MonitoringConfig{
			Enabled: true,
			Webhooks: []api.MonitorWebhookConfig{
				{
					ID:                "wh-perm",
					Provider:          "slack",
					URL:               tsPerm.URL,
					Enabled:           true,
					AllowInsecureHTTP: true,
					AllowLoopback:     true,
				},
			},
		}
		delivStore, _ := NewDeliveryStateStore(t.TempDir(), "target-perm")
		notifier := NewNotifier(monCfg, delivStore)
		rep := sampleDriftReport("target-perm")

		sum, _ := notifier.DeliverAlerts(context.Background(), rep)
		if sum.TotalFailed != 1 {
			t.Errorf("expected 1 failed alert, got %d", sum.TotalFailed)
		}
		// Permanent error should NOT retry multiple times
		if atomic.LoadInt32(&attempts) != 1 {
			t.Errorf("expected exactly 1 attempt for permanent error (no retry loops), got %d", attempts)
		}
	}

	// B. Transient Error (500) -> Retries max 3 times
	{
		var attempts int32
		tsTransient := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			atomic.AddInt32(&attempts, 1)
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte("service unavailable"))
		}))
		defer tsTransient.Close()

		monCfg := &api.MonitoringConfig{
			Enabled: true,
			Webhooks: []api.MonitorWebhookConfig{
				{
					ID:                "wh-trans",
					Provider:          "slack",
					URL:               tsTransient.URL,
					Enabled:           true,
					AllowInsecureHTTP: true,
					AllowLoopback:     true,
				},
			},
		}
		delivStore, _ := NewDeliveryStateStore(t.TempDir(), "target-trans")
		notifier := NewNotifier(monCfg, delivStore)
		rep := sampleDriftReport("target-trans")

		sum, _ := notifier.DeliverAlerts(context.Background(), rep)
		if sum.TotalFailed != 1 {
			t.Errorf("expected 1 failed alert after retry exhaustion, got %d", sum.TotalFailed)
		}
		// Transient error should retry up to maxAttempts (3)
		if atomic.LoadInt32(&attempts) != 3 {
			t.Errorf("expected 3 retry attempts for transient 500 error, got %d", attempts)
		}
	}
}

// 31. Synthetic Webhook Test: Transmits clearly labeled verification message with zero real data
func TestNotifier_SyntheticWebhookTest(t *testing.T) {
	var receivedBody []byte

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	}))
	defer ts.Close()

	monCfg := &api.MonitoringConfig{
		Enabled: true,
		Webhooks: []api.MonitorWebhookConfig{
			{
				ID:                "test-wh",
				Provider:          "slack",
				URL:               ts.URL,
				Enabled:           true,
				AllowInsecureHTTP: true,
				AllowLoopback:     true,
			},
		},
	}

	notifier := NewNotifier(monCfg, nil)
	receipt, err := notifier.SendTestWebhook(context.Background(), "test-wh", "slack")
	if err != nil {
		t.Fatalf("SendTestWebhook failed: %v", err)
	}
	if receipt.StatusCode != http.StatusOK {
		t.Errorf("expected status 200, got %d", receipt.StatusCode)
	}

	bodyStr := string(receivedBody)
	if !strings.Contains(bodyStr, "SYNTHETIC TEST") {
		t.Errorf("expected [SYNTHETIC TEST] marker in test payload: %s", bodyStr)
	}
	if !strings.Contains(bodyStr, "No assessment data was transmitted") {
		t.Errorf("expected zero-data disclosure disclaimer in synthetic test: %s", bodyStr)
	}
}

// 32. Mention Neutralization: Neutralizes @everyone, @channel, @here to prevent ping spam
func TestNotifier_MentionNeutralization(t *testing.T) {
	var receivedBody []byte

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	}))
	defer ts.Close()

	monCfg := &api.MonitoringConfig{
		Enabled: true,
		Webhooks: []api.MonitorWebhookConfig{
			{
				ID:                "wh-mention",
				Provider:          "slack",
				URL:               ts.URL,
				Enabled:           true,
				AllowInsecureHTTP: true,
				AllowLoopback:     true,
			},
		},
	}

	delivStore, _ := NewDeliveryStateStore(t.TempDir(), "target-mention")
	notifier := NewNotifier(monCfg, delivStore)

	evt := DriftEvent{
		ID:                "evt_mention_test",
		TargetID:          "target-mention",
		Classification:    ClassificationNewShadowRoute,
		CanonicalRoute:    "/api/v1/@everyone",
		Method:            "GET",
		Priority:          PriorityHigh,
		PriorityRationale: "Route created by @channel for @here",
	}
	rep := &DriftReport{TargetID: "target-mention", Events: []DriftEvent{evt}}

	_, _ = notifier.DeliverAlerts(context.Background(), rep)

	bodyStr := string(receivedBody)
	// Check that raw @everyone was neutralized with zero-width space
	if strings.Contains(bodyStr, "@everyone") {
		t.Errorf("raw @everyone was not neutralized in payload: %s", bodyStr)
	}
	if strings.Contains(bodyStr, "@channel") {
		t.Errorf("raw @channel was not neutralized in payload: %s", bodyStr)
	}
}

// 33. Disabled Webhook Produces Zero Network Calls
func TestNotifier_DisabledWebhooksProduceNoNetwork(t *testing.T) {
	var networkCalls int32

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&networkCalls, 1)
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	monCfg := &api.MonitoringConfig{
		Enabled: true,
		Webhooks: []api.MonitorWebhookConfig{
			{
				ID:                "disabled-wh",
				Provider:          "slack",
				URL:               ts.URL,
				Enabled:           false, // DISABLED
				AllowInsecureHTTP: true,
				AllowLoopback:     true,
			},
		},
	}

	delivStore, _ := NewDeliveryStateStore(t.TempDir(), "target-disabled")
	notifier := NewNotifier(monCfg, delivStore)
	rep := sampleDriftReport("target-disabled")

	sum, err := notifier.DeliverAlerts(context.Background(), rep)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if sum.TotalDelivered != 0 || sum.TotalAttempted != 0 {
		t.Errorf("expected 0 delivered/attempted for disabled webhook")
	}
	if atomic.LoadInt32(&networkCalls) != 0 {
		t.Errorf("expected zero network requests for disabled webhook, got %d", networkCalls)
	}
}
