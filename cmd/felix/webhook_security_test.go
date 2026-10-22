package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"felix/pkg/config"
	"felix/pkg/notify"
	"felix/pkg/report"
)

func TestRedirectHeaderStripping_CrossOrigin(t *testing.T) {
	// Attacker-controlled destination server
	var attackerReceivedSig string
	var attackerReceivedAuth string
	var attackerReceivedDelivery string

	attackerServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attackerReceivedSig = r.Header.Get(notify.HeaderFelixSignature)
		attackerReceivedAuth = r.Header.Get("Authorization")
		attackerReceivedDelivery = r.Header.Get(notify.HeaderFelixDelivery)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok": true}`))
	}))
	defer attackerServer.Close()

	// Legitimate original server that issues a redirect to the attacker server
	originServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, attackerServer.URL+"/capture", http.StatusFound)
	}))
	defer originServer.Close()

	secret := "sensitive-signing-key-12345"
	prov, err := notify.NewWebhookProvider(notify.WebhookConfig{
		URL:               originServer.URL,
		Secret:            secret,
		AllowInsecureHTTP: true,
		AllowPrivateIPs:   true,
		AllowLoopback:     true,
	})
	if err != nil {
		t.Fatalf("failed to create provider: %v", err)
	}

	notif := notify.BuildTestNotification("test-tenant", originServer.URL, time.Now().UTC())
	// Send notification (will follow redirect to attackerServer)
	_, _ = prov.Send(context.Background(), notif)

	// Verify sensitive headers were stripped and not leaked to attacker server
	if attackerReceivedSig != "" {
		t.Fatalf("security violation: signature header leaked to cross-origin redirect destination: %s", attackerReceivedSig)
	}
	if attackerReceivedAuth != "" {
		t.Fatalf("security violation: authorization header leaked to cross-origin redirect destination: %s", attackerReceivedAuth)
	}
	if attackerReceivedDelivery != "" {
		t.Fatalf("security violation: delivery header leaked to cross-origin redirect destination: %s", attackerReceivedDelivery)
	}
}

func TestScanCommand_RequireSigningFailsClosed(t *testing.T) {
	var endpointReceived bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		endpointReceived = true
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	// Clear any environment secrets
	t.Setenv("FELIX_NOTIFY_SECRET", "")
	t.Setenv("FELIX_NOTIFY_WEBHOOK_SECRET", "")

	// Create dummy test report
	rep := report.Report{
		Target:           server.URL,
		CompletionStatus: "COMPLETED",
		Summary:          report.Summary{TotalFindings: 0},
	}
	cfg := config.Default()

	// Dispatch with requireSigning: true and no secret
	opts := scanNotifyOptions{
		enabled:        true,
		explicit:       true,
		webhookURL:     server.URL,
		provider:       "webhook",
		secret:         "", // empty
		requireSigning: true,
		allowLoopback:  true,
		insecure:       true,
		quiet:          true,
	}

	dispatchReportNotification(rep, cfg, opts)

	if endpointReceived {
		t.Fatal("endpoint received request despite missing secret in requireSigning mode")
	}
}

func TestScanCommand_KeyRotationDualSignature(t *testing.T) {
	primaryKey := "primary-secret-key-2026"
	previousKey := "previous-secret-key-2025"

	var receivedSig string
	var receivedTS string
	var receivedBody []byte

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedSig = r.Header.Get(notify.HeaderFelixSignature)
		receivedTS = r.Header.Get(notify.HeaderFelixTimestamp)
		receivedBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	rep := report.Report{
		Target:           server.URL,
		CompletionStatus: "COMPLETED",
		Summary:          report.Summary{TotalFindings: 0},
	}
	cfg := config.Default()

	opts := scanNotifyOptions{
		enabled:        true,
		explicit:       true,
		webhookURL:     server.URL,
		provider:       "webhook",
		secret:         primaryKey,
		previousSecret: previousKey,
		allowLoopback:  true,
		insecure:       true,
		quiet:          true,
	}

	dispatchReportNotification(rep, cfg, opts)

	if receivedSig == "" {
		t.Fatal("expected X-Felix-Signature header, got empty")
	}

	// Verify that header contains both primary and previous signatures (e.g. v1=<sig1>,v1=<sig2>)
	sigParts := strings.Split(receivedSig, ",")
	if len(sigParts) != 2 {
		t.Fatalf("expected 2 signatures in rotation header, got %d: %s", len(sigParts), receivedSig)
	}

	// Verify receiver can authenticate using primaryKey
	if err := notify.VerifyWebhookSignature(primaryKey, receivedTS, receivedBody, receivedSig, 300*time.Second, time.Time{}); err != nil {
		t.Fatalf("receiver failed to verify with primary key: %v", err)
	}

	// Verify receiver can also authenticate using previousKey during rotation window
	if err := notify.VerifyWebhookSignature(previousKey, receivedTS, receivedBody, receivedSig, 300*time.Second, time.Time{}); err != nil {
		t.Fatalf("receiver failed to verify with previous key: %v", err)
	}
}

func TestScanCommand_SecretResolutionEnvPrecedence(t *testing.T) {
	t.Setenv("PRIMARY_CANARY_SECRET", "canary-secret-val-77")
	t.Setenv("PREV_CANARY_SECRET", "canary-prev-val-88")

	s1 := resolveNotifySecret("env:PRIMARY_CANARY_SECRET", "cfg-fallback")
	if s1 != "canary-secret-val-77" {
		t.Fatalf("expected canary secret from env, got: %s", s1)
	}

	s2 := resolvePreviousSecret("env:PREV_CANARY_SECRET", "cfg-prev-fallback")
	if s2 != "canary-prev-val-88" {
		t.Fatalf("expected canary prev secret from env, got: %s", s2)
	}
}

func TestChatProvidersCompatibility_NoHMACHeaders(t *testing.T) {
	// Verify that Slack, Discord, and Teams do not include X-Felix-Signature headers
	// which could cause third-party webhook receivers to reject unexpected headers.
	var receivedHeaders http.Header
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedHeaders = r.Header.Clone()
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`ok`))
	}))
	defer srv.Close()

	providers := []string{"slack", "discord", "teams"}
	for _, pType := range providers {
		t.Run(pType, func(t *testing.T) {
			p, err := notify.NewProvider(notify.WebhookConfig{
				URL:               srv.URL,
				Secret:            "secret-should-not-be-used-for-chat",
				AllowInsecureHTTP: true,
				AllowPrivateIPs:   true,
				AllowLoopback:     true,
			}, pType)
			if err != nil {
				t.Fatalf("failed to create %s provider: %v", pType, err)
			}

			notif := notify.BuildTestNotification("tenant-1", srv.URL, time.Now().UTC())
			receipt, err := p.Send(context.Background(), notif)
			if err != nil {
				t.Fatalf("failed to send via %s: %v", pType, err)
			}
			if receipt.StatusCode != http.StatusOK {
				t.Fatalf("expected status 200, got %d", receipt.StatusCode)
			}

			if sig := receivedHeaders.Get(notify.HeaderFelixSignature); sig != "" {
				t.Fatalf("unexpected X-Felix-Signature on %s provider: %s", pType, sig)
			}
		})
	}
}

func TestNotificationStatusAndTestFlags(t *testing.T) {
	// Test notification status displays require_signing and previous_secret
	statusExit, statusOut, _ := captureStdoutStderr(func() int {
		return runNotification([]string{"status", "--role", "admin"})
	})
	if statusExit != 0 {
		t.Fatalf("expected status exit code 0, got %d", statusExit)
	}
	if !strings.Contains(statusOut, "Require Signing:") {
		t.Errorf("expected status output to include 'Require Signing:', got: %s", statusOut)
	}
	if !strings.Contains(statusOut, "Previous Secret:") {
		t.Errorf("expected status output to include 'Previous Secret:', got: %s", statusOut)
	}

	// Test notification test subcommand with --require-signing and --previous-secret
	var receivedSig string
	var receivedTS string
	var receivedBody []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedSig = r.Header.Get(notify.HeaderFelixSignature)
		receivedTS = r.Header.Get(notify.HeaderFelixTimestamp)
		receivedBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status": "ok"}`))
	}))
	defer srv.Close()

	primaryKey := "test-primary-secret-key"
	previousKey := "test-previous-secret-key"

	testExit, testOut, testErr := captureStdoutStderr(func() int {
		return runNotification([]string{
			"test",
			"--url", srv.URL,
			"--secret", primaryKey,
			"--previous-secret", previousKey,
			"--require-signing",
			"--role", "admin",
		})
	})

	if testExit != 0 {
		t.Fatalf("expected notification test exit code 0, got %d. stderr: %s, stdout: %s", testExit, testErr, testOut)
	}

	// Check dual signatures in test notification
	if err := notify.VerifyWebhookSignature(primaryKey, receivedTS, receivedBody, receivedSig, 300*time.Second, time.Time{}); err != nil {
		t.Fatalf("failed to verify test notification with primary key: %v", err)
	}
	if err := notify.VerifyWebhookSignature(previousKey, receivedTS, receivedBody, receivedSig, 300*time.Second, time.Time{}); err != nil {
		t.Fatalf("failed to verify test notification with previous key: %v", err)
	}
}

func TestLegacySignatureDowngradeRejection(t *testing.T) {
	secret := "strict-verification-key"
	now := time.Now().UTC()
	tsStr := fmt.Sprintf("%d", now.Unix())
	body := []byte(`{"finding":"critical-rce","action":"alert"}`)

	// An attacker or legacy client sends a body-only sha256 HMAC (without timestamp binding)
	legacyUnboundSig := "sha256=" + notify.ComputeWebhookSignature(secret, body)

	// Under default VerifyWebhookSignature, this downgrade attempt MUST be rejected!
	err := notify.VerifyWebhookSignature(secret, tsStr, body, legacyUnboundSig, 300*time.Second, now)
	if err == nil {
		t.Fatal("security violation: VerifyWebhookSignature accepted legacy unbound sha256 signature without timestamp binding")
	}
	if !errors.Is(err, notify.ErrLegacyDowngradeRejected) {
		t.Fatalf("expected ErrLegacyDowngradeRejected, got: %v", err)
	}

	// Under explicit permissive policy, it is permitted
	errPermissive := notify.VerifyWebhookSignaturePermissive(secret, tsStr, body, legacyUnboundSig, 300*time.Second, now)
	if errPermissive != nil {
		t.Fatalf("expected permissive policy to accept legacy signature: %v", errPermissive)
	}
}

func TestSigningEnforcementPrecedence(t *testing.T) {
	// Precedence test:
	// 1. Config says RequireSigning: true
	cfg := config.Default()
	cfg.Notification.Enabled = true
	cfg.Notification.RequireSigning = true
	cfg.Notification.WebhookSecret = "" // Empty secret

	// Config validation fails closed immediately
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected cfg.Validate() to fail closed when RequireSigning is true and WebhookSecret is empty")
	}

	// 2. CLI options requireSigning override
	var endpointReceived bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		endpointReceived = true
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	// Config has RequireSigning: false, but CLI option has requireSigning: true
	cfgSafe := config.Default()
	cfgSafe.Notification.RequireSigning = false

	opts := scanNotifyOptions{
		enabled:        true,
		explicit:       true,
		webhookURL:     srv.URL,
		provider:       "webhook",
		secret:         "",   // empty
		requireSigning: true, // CLI override
		allowLoopback:  true,
		insecure:       true,
		quiet:          true,
	}

	rep := report.Report{
		Target:           srv.URL,
		CompletionStatus: "COMPLETED",
		Summary:          report.Summary{TotalFindings: 0},
	}
	dispatchReportNotification(rep, cfgSafe, opts)

	if endpointReceived {
		t.Fatal("request was sent despite CLI --notify-require-signing override with missing secret")
	}
}
