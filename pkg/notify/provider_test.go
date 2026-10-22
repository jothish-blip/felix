package notify

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"felix/pkg/report"
)

func TestProviderSelection(t *testing.T) {
	cfg := WebhookConfig{
		URL:               "http://127.0.0.1:8080/hook",
		AllowLoopback:     true,
		AllowInsecureHTTP: true,
	}

	types := []string{"webhook", "slack", "discord", "teams", "WEBHOOK", "Slack", "DISCORD", "Teams"}
	for _, pt := range types {
		p, err := NewProvider(cfg, pt)
		if err != nil {
			t.Fatalf("NewProvider failed for %s: %v", pt, err)
		}
		if p == nil {
			t.Fatalf("expected non-nil provider for %s", pt)
		}
		if p.Name() != strings.ToLower(pt) {
			t.Errorf("expected name %s, got %s", strings.ToLower(pt), p.Name())
		}
	}

	_, err := NewProvider(cfg, "unsupported_unknown")
	if err == nil {
		t.Fatal("expected error for unsupported provider, got nil")
	}
}

func TestSlackProviderPayloadAndSanitization(t *testing.T) {
	var receivedBody []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
			t.Errorf("expected application/json, got %s", r.Header.Get("Content-Type"))
		}
		if r.Header.Get("X-Felix-Delivery") == "" {
			t.Error("missing X-Felix-Delivery header")
		}
		body, _ := io.ReadAll(r.Body)
		receivedBody = body
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok": true}`))
	}))
	defer srv.Close()

	prov, err := NewProvider(WebhookConfig{
		URL:               srv.URL,
		AllowLoopback:     true,
		AllowInsecureHTTP: true,
	}, "slack")
	if err != nil {
		t.Fatalf("failed creating slack provider: %v", err)
	}

	notif := &Notification{
		ID:          "notif-1",
		EventType:   EventSecurityFindingCritical,
		Severity:    SeverityCritical,
		Title:       "Critical Alert: @everyone @channel check this <script>alert(1)</script>",
		Message:     "Found vulnerability; notify @here immediately & report <bad>",
		CreatedAt:   time.Now().UTC(),
		PayloadJSON: `{"finding_count": 1}`,
	}

	receipt, err := prov.Send(context.Background(), notif)
	if err != nil {
		t.Fatalf("Slack send failed: %v", err)
	}
	if receipt == nil || receipt.StatusCode != http.StatusOK {
		t.Fatalf("unexpected receipt: %+v", receipt)
	}

	var slackPayload map[string]interface{}
	if err := json.Unmarshal(receivedBody, &slackPayload); err != nil {
		t.Fatalf("failed parsing slack JSON payload: %v", err)
	}

	bodyStr := string(receivedBody)
	// Verify mention sanitization
	if strings.Contains(bodyStr, "@everyone") {
		t.Errorf("payload contains unsanitized @everyone: %s", bodyStr)
	}
	if strings.Contains(bodyStr, "@channel") {
		t.Errorf("payload contains unsanitized @channel: %s", bodyStr)
	}
	if strings.Contains(bodyStr, "@here") {
		t.Errorf("payload contains unsanitized @here: %s", bodyStr)
	}
	if !strings.Contains(bodyStr, "@\u200beveryone") {
		t.Errorf("payload missing zero-width spaced @everyone: %s", bodyStr)
	}

	// Verify Block Kit structure
	blocks, ok := slackPayload["blocks"].([]interface{})
	if !ok || len(blocks) == 0 {
		t.Fatalf("slack payload missing blocks: %s", bodyStr)
	}
}

func TestDiscordProviderPayloadAndSanitization(t *testing.T) {
	var receivedBody []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		receivedBody = body
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	prov, err := NewProvider(WebhookConfig{
		URL:               srv.URL,
		AllowLoopback:     true,
		AllowInsecureHTTP: true,
	}, "discord")
	if err != nil {
		t.Fatalf("failed creating discord provider: %v", err)
	}

	notif := &Notification{
		ID:          "notif-2",
		EventType:   EventSecurityFindingCritical,
		Severity:    SeverityCritical,
		Title:       "Discord Alert @everyone",
		Message:     "Testing discord delivery",
		CreatedAt:   time.Now().UTC(),
		PayloadJSON: `{"target": "https://example.com", "finding_count": 5}`,
	}

	receipt, err := prov.Send(context.Background(), notif)
	if err != nil {
		t.Fatalf("Discord send failed: %v", err)
	}
	if receipt.StatusCode != http.StatusNoContent {
		t.Errorf("expected 204, got %d", receipt.StatusCode)
	}

	var discordPayload map[string]interface{}
	if err := json.Unmarshal(receivedBody, &discordPayload); err != nil {
		t.Fatalf("failed unmarshaling discord payload: %v", err)
	}

	// Verify allowed_mentions is empty to block mass pinging
	allowedMentions, ok := discordPayload["allowed_mentions"].(map[string]interface{})
	if !ok {
		t.Fatalf("missing allowed_mentions in discord payload: %s", string(receivedBody))
	}
	parseList, ok := allowedMentions["parse"].([]interface{})
	if !ok || len(parseList) != 0 {
		t.Errorf("expected empty allowed_mentions parse list, got: %v", parseList)
	}

	// Verify embeds exist with color
	embeds, ok := discordPayload["embeds"].([]interface{})
	if !ok || len(embeds) == 0 {
		t.Fatalf("missing embeds in discord payload: %s", string(receivedBody))
	}
	firstEmbed := embeds[0].(map[string]interface{})
	if firstEmbed["color"] == nil {
		t.Error("missing color in discord embed")
	}
}

func TestTeamsProviderPayload(t *testing.T) {
	var receivedBody []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		receivedBody = body
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`1`))
	}))
	defer srv.Close()

	prov, err := NewProvider(WebhookConfig{
		URL:               srv.URL,
		AllowLoopback:     true,
		AllowInsecureHTTP: true,
	}, "teams")
	if err != nil {
		t.Fatalf("failed creating teams provider: %v", err)
	}

	notif := &Notification{
		ID:          "notif-3",
		EventType:   EventAssessmentCompleted,
		Severity:    SeverityInfo,
		Title:       "Teams Assessment Completed",
		Message:     "Assessment completed without issues",
		CreatedAt:   time.Now().UTC(),
		PayloadJSON: `{"target": "https://example.com", "finding_count": 0}`,
	}

	receipt, err := prov.Send(context.Background(), notif)
	if err != nil {
		t.Fatalf("Teams send failed: %v", err)
	}
	if receipt.StatusCode != http.StatusOK {
		t.Errorf("expected 200, got %d", receipt.StatusCode)
	}

	var teamsPayload map[string]interface{}
	if err := json.Unmarshal(receivedBody, &teamsPayload); err != nil {
		t.Fatalf("failed unmarshaling teams payload: %v", err)
	}

	if teamsPayload["@type"] != "MessageCard" {
		t.Errorf("expected MessageCard @type, got %v", teamsPayload["@type"])
	}
	if teamsPayload["title"] != "Teams Assessment Completed" {
		t.Errorf("unexpected title: %v", teamsPayload["title"])
	}
}

func TestBuildReportNotificationCaveatOnZeroFindings(t *testing.T) {
	now := time.Now().UTC()

	// 1. Zero finding clean report
	repClean := report.Report{
		Target:           "https://api.example.com",
		CompletionStatus: "COMPLETED",
		Duration:         "1.23s",
		RiskScore:        0,
		RiskLevel:        "NONE",
		Findings:         nil,
	}

	notifClean := BuildReportNotification(repClean, "asm-clean", "exec-1", now)
	if !strings.Contains(notifClean.Title, "(0 Findings)") {
		t.Errorf("expected title to indicate 0 findings, got: %s", notifClean.Title)
	}
	if !strings.Contains(notifClean.Message, "Zero findings does not guarantee that the target is completely secure") {
		t.Errorf("expected honesty caveat on 0 findings in message, got: %s", notifClean.Message)
	}
	if notifClean.Severity != SeverityInfo {
		t.Errorf("expected SeverityInfo for clean run, got: %s", notifClean.Severity)
	}

	// 2. Critical findings report
	repCrit := report.Report{
		Target:           "https://api.example.com",
		CompletionStatus: "COMPLETED",
		Duration:         "3.45s",
		RiskScore:        85,
		RiskLevel:        "CRITICAL",
		Summary: report.Summary{
			CriticalCount: 2,
			HighCount:     1,
		},
		Findings: []report.Finding{
			{
				ID:       "felix-sqli",
				Title:    "SQL Injection in /api/v1/user",
				Severity: report.SeverityCritical,
				Endpoint: "https://api.example.com/api/v1/user",
				Status:   report.FindingStatusConfirmed,
				Verification: report.VerificationRecord{
					Status: report.VerificationVerified,
				},
			},
		},
	}

	notifCrit := BuildReportNotification(repCrit, "asm-crit", "exec-2", now)
	if notifCrit.Severity != SeverityCritical {
		t.Errorf("expected SeverityCritical, got: %s", notifCrit.Severity)
	}
	if !strings.Contains(notifCrit.Title, "2 Findings") && !strings.Contains(notifCrit.Title, "1 Findings") {
		t.Errorf("unexpected title for findings report: %s", notifCrit.Title)
	}
	if len(notifCrit.FindingIDs) == 0 || notifCrit.FindingIDs[0] != "felix-sqli" {
		t.Errorf("expected finding IDs to contain felix-sqli, got: %v", notifCrit.FindingIDs)
	}

	// 3. Blocked and Partial terminal states
	repBlocked := report.Report{
		Target:           "https://waf.example.com",
		CompletionStatus: "BLOCKED",
	}
	notifBlocked := BuildReportNotification(repBlocked, "asm-blocked", "exec-3", now)
	if notifBlocked.EventType != EventAssessmentBlocked {
		t.Errorf("expected EventAssessmentBlocked, got: %s", notifBlocked.EventType)
	}
	if !strings.Contains(notifBlocked.Message, "HTTP 403 Forbidden") {
		t.Errorf("expected blocked explanation in message, got: %s", notifBlocked.Message)
	}

	repPartial := report.Report{
		Target:           "https://partial.example.com",
		CompletionStatus: "PARTIAL",
	}
	notifPartial := BuildReportNotification(repPartial, "asm-partial", "exec-4", now)
	if notifPartial.EventType != EventAssessmentPartial {
		t.Errorf("expected EventAssessmentPartial, got: %s", notifPartial.EventType)
	}
}

func TestSendWithRetriesTransientRecovery(t *testing.T) {
	var attempts int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		count := atomic.AddInt32(&attempts, 1)
		if count < 3 {
			// First two attempts fail transiently with 503
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte(`service temporarily unavailable`))
			return
		}
		// Third attempt succeeds
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status": "ok"}`))
	}))
	defer srv.Close()

	prov, err := NewWebhookProvider(WebhookConfig{
		URL:               srv.URL,
		AllowLoopback:     true,
		AllowInsecureHTTP: true,
	})
	if err != nil {
		t.Fatalf("failed creating provider: %v", err)
	}

	notif := &Notification{
		ID:        "notif-retry",
		EventType: EventAssessmentCompleted,
		Severity:  SeverityInfo,
		Title:     "Retry Test",
		Message:   "Checking retry recovery",
	}

	ctx := context.Background()
	receipt, err := SendWithRetries(ctx, prov, notif, 3, 20*time.Millisecond)
	if err != nil {
		t.Fatalf("expected successful delivery on attempt 3, got error: %v", err)
	}
	if receipt == nil || receipt.StatusCode != http.StatusOK {
		t.Fatalf("unexpected receipt: %+v", receipt)
	}
	if atomic.LoadInt32(&attempts) != 3 {
		t.Errorf("expected exactly 3 attempts, got %d", atomic.LoadInt32(&attempts))
	}
	if notif.DeliveryStatus != DeliveryStatusDelivered {
		t.Errorf("expected DeliveryStatusDelivered, got %s", notif.DeliveryStatus)
	}
}

func TestSendWithRetriesPermanentFailFast(t *testing.T) {
	var attempts int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&attempts, 1)
		// Permanent 400 Bad Request
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`client bad request`))
	}))
	defer srv.Close()

	prov, err := NewWebhookProvider(WebhookConfig{
		URL:               srv.URL,
		AllowLoopback:     true,
		AllowInsecureHTTP: true,
	})
	if err != nil {
		t.Fatalf("failed creating provider: %v", err)
	}

	notif := &Notification{
		ID:        "notif-permanent",
		EventType: EventAssessmentCompleted,
		Severity:  SeverityInfo,
		Title:     "Permanent Error Test",
		Message:   "Should not retry on 400",
	}

	ctx := context.Background()
	receipt, err := SendWithRetries(ctx, prov, notif, 5, 20*time.Millisecond)
	if err == nil {
		t.Fatal("expected error on permanent 400, got nil")
	}
	if receipt != nil {
		t.Fatalf("expected nil receipt on failure, got %+v", receipt)
	}
	// Must have failed immediately after attempt 1 without exhausting all 5 retries!
	if atomic.LoadInt32(&attempts) != 1 {
		t.Errorf("expected fail-fast with 1 attempt, but got %d attempts", atomic.LoadInt32(&attempts))
	}
	if notif.DeliveryStatus != DeliveryStatusFailed {
		t.Errorf("expected DeliveryStatusFailed, got %s", notif.DeliveryStatus)
	}
}

func TestSendWithRetriesContextCancellation(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Hang until context times out
		time.Sleep(100 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	prov, _ := NewWebhookProvider(WebhookConfig{
		URL:               srv.URL,
		AllowLoopback:     true,
		AllowInsecureHTTP: true,
		Timeout:           500 * time.Millisecond,
	})

	notif := &Notification{
		ID:        "notif-cancel",
		EventType: EventAssessmentCompleted,
		Title:     "Cancel test",
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()

	_, err := SendWithRetries(ctx, prov, notif, 3, 20*time.Millisecond)
	if err == nil {
		t.Fatal("expected context deadline error, got nil")
	}
}

func TestHostilePayloadInjectionAllProviders(t *testing.T) {
	hostileTitle := "<!subteam^S12345> Hostile Title <@U99999> with @everyone and <script>alert(1)</script>"
	hostileMsg := "Evidence: <at>user@corp</at> injection with @channel & @here plus <!date^123456> and <https://evil.com|click>"

	// 1. Slack
	var slackBody []byte
	slackSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		slackBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok": true}`))
	}))
	defer slackSrv.Close()

	slackProv, _ := NewProvider(WebhookConfig{
		URL:               slackSrv.URL,
		AllowLoopback:     true,
		AllowInsecureHTTP: true,
	}, "slack")
	_, err := slackProv.Send(context.Background(), &Notification{
		ID:        "slack-hostile",
		EventType: EventSecurityFindingCritical,
		Severity:  SeverityCritical,
		Title:     hostileTitle,
		Message:   hostileMsg,
	})
	if err != nil {
		t.Fatalf("Slack send failed: %v", err)
	}
	slackStr := string(slackBody)
	if strings.Contains(slackStr, "<!subteam^") {
		t.Errorf("Slack payload contains unescaped subteam mention: %s", slackStr)
	}
	if strings.Contains(slackStr, "<@U") {
		t.Errorf("Slack payload contains unescaped user mention: %s", slackStr)
	}
	if strings.Contains(slackStr, "@everyone") || strings.Contains(slackStr, "@channel") || strings.Contains(slackStr, "@here") {
		t.Errorf("Slack payload contains un-neutralized broadcast mention: %s", slackStr)
	}

	// 2. Discord
	var discordBody []byte
	discordSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		discordBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer discordSrv.Close()

	discordProv, _ := NewProvider(WebhookConfig{
		URL:               discordSrv.URL,
		AllowLoopback:     true,
		AllowInsecureHTTP: true,
	}, "discord")
	_, err = discordProv.Send(context.Background(), &Notification{
		ID:        "discord-hostile",
		EventType: EventSecurityFindingCritical,
		Severity:  SeverityCritical,
		Title:     hostileTitle,
		Message:   hostileMsg,
	})
	if err != nil {
		t.Fatalf("Discord send failed: %v", err)
	}
	discordStr := string(discordBody)
	if strings.Contains(discordStr, "@everyone") || strings.Contains(discordStr, "@here") {
		t.Errorf("Discord payload contains un-neutralized mention: %s", discordStr)
	}
	var discJSON map[string]interface{}
	_ = json.Unmarshal(discordBody, &discJSON)
	am, _ := discJSON["allowed_mentions"].(map[string]interface{})
	parseArr, _ := am["parse"].([]interface{})
	if len(parseArr) != 0 {
		t.Errorf("expected empty parse array in allowed_mentions, got: %v", parseArr)
	}

	// 3. Teams
	var teamsBody []byte
	teamsSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		teamsBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`1`))
	}))
	defer teamsSrv.Close()

	teamsProv, _ := NewProvider(WebhookConfig{
		URL:               teamsSrv.URL,
		AllowLoopback:     true,
		AllowInsecureHTTP: true,
	}, "teams")
	_, err = teamsProv.Send(context.Background(), &Notification{
		ID:        "teams-hostile",
		EventType: EventSecurityFindingCritical,
		Severity:  SeverityCritical,
		Title:     hostileTitle,
		Message:   hostileMsg,
	})
	if err != nil {
		t.Fatalf("Teams send failed: %v", err)
	}
	teamsStr := string(teamsBody)
	if strings.Contains(teamsStr, "<at>") || strings.Contains(teamsStr, "</at>") {
		t.Errorf("Teams payload contains unescaped <at> tags: %s", teamsStr)
	}
	if strings.Contains(teamsStr, "<script>") || strings.Contains(teamsStr, "</script>") {
		t.Errorf("Teams payload contains raw <script> tags: %s", teamsStr)
	}
}

func TestSSRFTransportImmunity(t *testing.T) {
	// 1. Cloud metadata IP 169.254.169.254 must be blocked unconditionally
	metaConfig := WebhookConfig{
		URL:             "https://169.254.169.254/latest/meta-data",
		AllowPrivateIPs: true,
		AllowLoopback:   true,
	}
	_, err := NewWebhookProvider(metaConfig)
	if err == nil {
		t.Fatal("expected error creating provider for cloud metadata IP, got nil")
	}

	// 2. IPv6 link-local metadata (fe80::1) must be blocked unconditionally
	fe80Config := WebhookConfig{
		URL:             "https://[fe80::1]/hook",
		AllowPrivateIPs: true,
		AllowLoopback:   true,
	}
	_, err = NewWebhookProvider(fe80Config)
	if err == nil {
		t.Fatal("expected error creating provider for fe80 link-local, got nil")
	}

	// 3. Private IP 10.0.0.1 must be blocked unless AllowPrivateIPs is explicitly true
	privateConfig := WebhookConfig{
		URL:             "https://10.0.0.1:8443/hook",
		AllowPrivateIPs: false,
	}
	_, err = NewWebhookProvider(privateConfig)
	if err == nil {
		t.Fatal("expected error creating provider for private IP without opt-in, got nil")
	}

	// 4. DialContext direct IP check
	client := newHardenedHTTPClient(WebhookConfig{
		AllowPrivateIPs: false,
		AllowLoopback:   false,
		Timeout:         500 * time.Millisecond,
	})
	req, _ := http.NewRequestWithContext(context.Background(), "POST", "https://127.0.0.1:9999/hook", nil)
	_, err = client.Do(req)
	if err == nil {
		t.Fatal("expected dial error when connecting to loopback without opt-in, got nil")
	}
}

func TestCriticalFindingAlertGeneration(t *testing.T) {
	now := time.Now().UTC()

	// 1. Direct Critical Finding Notification
	f := report.Finding{
		ID:          "felix-rce-01",
		RuleID:      "FLX-RCE",
		Title:       "Remote Code Execution in Admin Upload",
		Severity:    report.SeverityCritical,
		Endpoint:    "https://api.example.com/admin/upload",
		Description: "Unrestricted file upload leads to code execution",
		Confidence:  "CERTAIN",
		Fingerprint: "rce-fp-998877",
		Verification: report.VerificationRecord{
			Status: report.VerificationVerified,
		},
		Remediation: "Validate file extensions and store files outside web root",
	}

	notif := BuildCriticalFindingNotification("tenant-a", "acc-b", "asm-c", "asm-ref", "exec-d", f, now)
	if notif.EventType != EventSecurityFindingCritical {
		t.Errorf("expected EventSecurityFindingCritical, got %s", notif.EventType)
	}
	if notif.Severity != SeverityCritical {
		t.Errorf("expected SeverityCritical, got %s", notif.Severity)
	}
	if !strings.Contains(notif.Title, "[CRITICAL]") || !strings.Contains(notif.Title, "FLX-RCE") {
		t.Errorf("unexpected title: %s", notif.Title)
	}
	if len(notif.FindingIDs) != 1 || notif.FindingIDs[0] != "felix-rce-01" {
		t.Errorf("unexpected finding IDs: %v", notif.FindingIDs)
	}

	// 2. Report Notification with Critical findings
	rep := report.Report{
		Target:           "https://target.example.com",
		CompletionStatus: "COMPLETED",
		Duration:         "4.2s",
		RiskScore:        92,
		RiskLevel:        "CRITICAL",
		Summary: report.Summary{
			CriticalCount: 1,
			HighCount:     2,
		},
		Findings: []report.Finding{f},
	}

	repNotif := BuildReportNotification(rep, "asm-report", "exec-rep", now)
	if repNotif.EventType != EventAssessmentCompletedWithErrors {
		t.Errorf("expected EventAssessmentCompletedWithErrors for completed report with critical findings, got %s", repNotif.EventType)
	}
	if repNotif.Severity != SeverityCritical {
		t.Errorf("expected SeverityCritical, got %s", repNotif.Severity)
	}
}
