package notify

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestComputeSignatureV1_Determinism(t *testing.T) {
	secret := "secret-test-key-12345"
	ts := "1700000000"
	payload := []byte(`{"event":"test","status":"ok"}`)

	sig1 := ComputeSignatureV1(secret, ts, payload)
	sig2 := ComputeSignatureV1(secret, ts, payload)

	if sig1 == "" {
		t.Fatal("expected non-empty signature")
	}
	if sig1 != sig2 {
		t.Fatalf("expected deterministic signature: %s != %s", sig1, sig2)
	}

	// Verify manual calculation
	expectedMsg := "1700000000.{\"event\":\"test\",\"status\":\"ok\"}"
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(expectedMsg))
	expectedSig := hex.EncodeToString(mac.Sum(nil))

	if sig1 != expectedSig {
		t.Fatalf("signature mismatch: got %s, want %s", sig1, expectedSig)
	}
}

func TestVerifyWebhookSignature_CryptographicIntegrity(t *testing.T) {
	secret := "top-secret-signing-key"
	now := time.Unix(1700000000, 0).UTC()
	tsStr := "1700000000"
	payload := []byte(`{"target":"https://example.com","findings":[{"id":"vuln-1","severity":"HIGH"}]}`)
	sig := ComputeSignatureV1(secret, tsStr, payload)
	header := "v1=" + sig

	// 1. Valid signature
	if err := VerifyWebhookSignature(secret, tsStr, payload, header, 300*time.Second, now); err != nil {
		t.Fatalf("expected valid signature, got: %v", err)
	}

	// 2. Single byte alteration in payload invalidates
	tamperedPayload := bytes.Clone(payload)
	tamperedPayload[len(tamperedPayload)-2] = 'X'
	if err := VerifyWebhookSignature(secret, tsStr, tamperedPayload, header, 300*time.Second, now); !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("expected ErrInvalidSignature on tampered payload, got: %v", err)
	}

	// 3. Timestamp alteration invalidates
	tamperedTS := "1700000001"
	if err := VerifyWebhookSignature(secret, tamperedTS, payload, header, 300*time.Second, now); !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("expected ErrInvalidSignature on tampered timestamp, got: %v", err)
	}

	// 4. Whitespace or JSON reordering invalidates
	whitespacePayload := []byte(`{ "target": "https://example.com", "findings": [{"id":"vuln-1","severity":"HIGH"}] }`)
	if err := VerifyWebhookSignature(secret, tsStr, whitespacePayload, header, 300*time.Second, now); !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("expected ErrInvalidSignature on whitespace change, got: %v", err)
	}

	// 5. Wrong key invalidates
	wrongSecret := "attacker-different-secret-key"
	if err := VerifyWebhookSignature(wrongSecret, tsStr, payload, header, 300*time.Second, now); !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("expected ErrInvalidSignature on wrong key, got: %v", err)
	}
}

func TestVerifyWebhookSignature_PayloadEdgeCases(t *testing.T) {
	secret := "edge-case-secret-key"
	now := time.Unix(1710000000, 0).UTC()
	tsStr := "1710000000"

	testCases := []struct {
		name    string
		payload []byte
	}{
		{"empty payload", []byte{}},
		{"unicode and emoji", []byte(`{"msg":"安全检查 completed 🎉! 日本語 / 한국어 / 🔐"}`)},
		{"escaped characters and tabs", []byte("{\n\t\"data\": \"line1\\nline2\\t\\\"quoted\\\"\"\n}")},
		{"large payload (256 KB)", bytes.Repeat([]byte("A"), 256*1024)},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			sig := ComputeSignatureV1(secret, tsStr, tc.payload)
			header := "v1=" + sig

			if err := VerifyWebhookSignature(secret, tsStr, tc.payload, header, 300*time.Second, now); err != nil {
				t.Fatalf("verification failed for %s: %v", tc.name, err)
			}
		})
	}
}

func TestVerifyWebhookSignature_ReplayAndTolerance(t *testing.T) {
	secret := "replay-tolerance-test-key"
	fixedNow := time.Unix(1700000500, 0).UTC() // now = 1700000500
	payload := []byte(`{"ping":"pong"}`)
	tolerance := 300 * time.Second // window: [1700000200, 1700000800]

	// 1. Exact boundary - exactly at now
	tsNow := "1700000500"
	sigNow := "v1=" + ComputeSignatureV1(secret, tsNow, payload)
	if err := VerifyWebhookSignature(secret, tsNow, payload, sigNow, tolerance, fixedNow); err != nil {
		t.Errorf("expected valid for current timestamp: %v", err)
	}

	// 2. Exactly within past tolerance (1700000500 - 299s = 1700000201)
	tsPastValid := "1700000201"
	sigPastValid := "v1=" + ComputeSignatureV1(secret, tsPastValid, payload)
	if err := VerifyWebhookSignature(secret, tsPastValid, payload, sigPastValid, tolerance, fixedNow); err != nil {
		t.Errorf("expected valid for within past tolerance: %v", err)
	}

	// 3. Expired past tolerance (1700000500 - 301s = 1700000199)
	tsExpired := "1700000199"
	sigExpired := "v1=" + ComputeSignatureV1(secret, tsExpired, payload)
	if err := VerifyWebhookSignature(secret, tsExpired, payload, sigExpired, tolerance, fixedNow); !errors.Is(err, ErrTimestampExpired) {
		t.Errorf("expected ErrTimestampExpired for expired timestamp, got: %v", err)
	}

	// 4. Exactly within future tolerance (1700000500 + 299s = 1700000799)
	tsFutureValid := "1700000799"
	sigFutureValid := "v1=" + ComputeSignatureV1(secret, tsFutureValid, payload)
	if err := VerifyWebhookSignature(secret, tsFutureValid, payload, sigFutureValid, tolerance, fixedNow); err != nil {
		t.Errorf("expected valid for within future tolerance: %v", err)
	}

	// 5. Excessive future timestamp (1700000500 + 301s = 1700000801)
	tsFutureInvalid := "1700000801"
	sigFutureInvalid := "v1=" + ComputeSignatureV1(secret, tsFutureInvalid, payload)
	if err := VerifyWebhookSignature(secret, tsFutureInvalid, payload, sigFutureInvalid, tolerance, fixedNow); !errors.Is(err, ErrTimestampFuture) {
		t.Errorf("expected ErrTimestampFuture for excessive future timestamp, got: %v", err)
	}

	// 6. RFC3339 timestamp format fallback
	rfc3339TS := fixedNow.Format(time.RFC3339)
	sigRFC := "v1=" + ComputeSignatureV1(secret, rfc3339TS, payload)
	if err := VerifyWebhookSignature(secret, rfc3339TS, payload, sigRFC, tolerance, fixedNow); err != nil {
		t.Errorf("expected valid for RFC3339 timestamp: %v", err)
	}

	// 7. Malformed timestamp format
	if err := VerifyWebhookSignature(secret, "not-a-timestamp", payload, sigNow, tolerance, fixedNow); !errors.Is(err, ErrInvalidTimestamp) {
		t.Errorf("expected ErrInvalidTimestamp for invalid format, got: %v", err)
	}

	// 8. Missing timestamp
	if err := VerifyWebhookSignature(secret, "", payload, sigNow, tolerance, fixedNow); !errors.Is(err, ErrMissingTimestamp) {
		t.Errorf("expected ErrMissingTimestamp for empty timestamp, got: %v", err)
	}
}

func TestVerifyWebhookSignature_HeaderParsingAndVersions(t *testing.T) {
	secret := "version-test-secret"
	now := time.Unix(1700000000, 0).UTC()
	tsStr := "1700000000"
	payload := []byte(`{"status":"healthy"}`)
	validSig := ComputeSignatureV1(secret, tsStr, payload)

	// 1. Missing signature header
	if err := VerifyWebhookSignature(secret, tsStr, payload, "", 300*time.Second, now); !errors.Is(err, ErrMissingSignature) {
		t.Errorf("expected ErrMissingSignature, got: %v", err)
	}

	// 2. Unsupported signature scheme (e.g. v2=...)
	if err := VerifyWebhookSignature(secret, tsStr, payload, "v2=abcdef123456", 300*time.Second, now); !errors.Is(err, ErrUnsupportedVersion) {
		t.Errorf("expected ErrUnsupportedVersion, got: %v", err)
	}

	// 3. Malformed header without =
	if err := VerifyWebhookSignature(secret, tsStr, payload, "malformed-no-equal", 300*time.Second, now); !errors.Is(err, ErrInvalidSignature) {
		t.Errorf("expected ErrInvalidSignature, got: %v", err)
	}

	// 4. Multiple comma-separated signatures (e.g. invalid then valid)
	multiHeader := fmt.Sprintf("v1=0000000000000000000000000000000000000000000000000000000000000000, v1=%s", validSig)
	if err := VerifyWebhookSignature(secret, tsStr, payload, multiHeader, 300*time.Second, now); err != nil {
		t.Errorf("expected multi-header with valid signature to succeed, got: %v", err)
	}

	// 5. Legacy body-only sha256= signature is rejected under strict policy (downgrade prevention)
	legacySig := ComputeWebhookSignature(secret, payload)
	legacyHeader := "sha256=" + legacySig
	if err := VerifyWebhookSignature(secret, tsStr, payload, legacyHeader, 300*time.Second, now); !errors.Is(err, ErrLegacyDowngradeRejected) {
		t.Errorf("expected ErrLegacyDowngradeRejected under strict verification, got: %v", err)
	}

	// 6. Legacy body-only sha256= signature succeeds under explicit permissive policy
	if err := VerifyWebhookSignaturePermissive(secret, tsStr, payload, legacyHeader, 300*time.Second, now); err != nil {
		t.Errorf("expected legacy sha256 header to succeed under permissive policy, got: %v", err)
	}

	// 7. Legacy sha256= header that binds timestamp and payload succeeds under strict policy
	legacyBoundSig := "sha256=" + ComputeSignatureV1(secret, tsStr, payload)
	if err := VerifyWebhookSignature(secret, tsStr, payload, legacyBoundSig, 300*time.Second, now); err != nil {
		t.Errorf("expected timestamp-bound sha256 header to succeed, got: %v", err)
	}
}

func TestVerifyWebhookSignatureWithKeys_Rotation(t *testing.T) {
	primarySecret := "new-primary-key-2026"
	previousSecret := "old-previous-key-2025"
	now := time.Unix(1700000000, 0).UTC()
	tsStr := "1700000000"
	payload := []byte(`{"event":"key_rotation_test"}`)

	sigPrimary := ComputeSignatureV1(primarySecret, tsStr, payload)
	sigPrevious := ComputeSignatureV1(previousSecret, tsStr, payload)

	// Case 1: Request signed with primary key -> verifies against primary
	if err := VerifyWebhookSignatureWithKeys(primarySecret, previousSecret, tsStr, payload, "v1="+sigPrimary, 300*time.Second, now); err != nil {
		t.Errorf("expected primary key to verify: %v", err)
	}

	// Case 2: Request signed with previous key -> verifies against previous during rotation window
	if err := VerifyWebhookSignatureWithKeys(primarySecret, previousSecret, tsStr, payload, "v1="+sigPrevious, 300*time.Second, now); err != nil {
		t.Errorf("expected previous key to verify during rotation: %v", err)
	}

	// Case 3: Dual signature header (contains both primary and previous signatures)
	dualHeader := fmt.Sprintf("v1=%s,v1=%s", sigPrimary, sigPrevious)
	if err := VerifyWebhookSignatureWithKeys(primarySecret, previousSecret, tsStr, payload, dualHeader, 300*time.Second, now); err != nil {
		t.Errorf("expected dual signature header to verify: %v", err)
	}

	// Case 4: Neither key matches -> fails with ErrInvalidSignature
	badSig := "v1=1111111111111111111111111111111111111111111111111111111111111111"
	if err := VerifyWebhookSignatureWithKeys(primarySecret, previousSecret, tsStr, payload, badSig, 300*time.Second, now); !errors.Is(err, ErrInvalidSignature) {
		t.Errorf("expected ErrInvalidSignature when neither key matches, got: %v", err)
	}

	// Case 5: Expired timestamp fails even if key matches
	expiredNow := now.Add(1000 * time.Second)
	if err := VerifyWebhookSignatureWithKeys(primarySecret, previousSecret, tsStr, payload, "v1="+sigPrimary, 300*time.Second, expiredNow); !errors.Is(err, ErrTimestampExpired) {
		t.Errorf("expected ErrTimestampExpired on expired token even during rotation, got: %v", err)
	}
}

func TestMemoryReplayDetector(t *testing.T) {
	detector := NewMemoryReplayDetector(60 * time.Second)
	now := time.Now().UTC()

	// 1. First arrival of delivery ID succeeds
	if err := detector.CheckAndRecord("deliv-100", now); err != nil {
		t.Fatalf("expected first arrival to succeed: %v", err)
	}

	// 2. Replay of same delivery ID within window fails
	if err := detector.CheckAndRecord("deliv-100", now.Add(5*time.Second)); !errors.Is(err, ErrReplayDetected) {
		t.Fatalf("expected ErrReplayDetected on replay, got: %v", err)
	}

	// 3. Different delivery ID succeeds
	if err := detector.CheckAndRecord("deliv-200", now.Add(10*time.Second)); err != nil {
		t.Fatalf("expected new delivery ID to succeed: %v", err)
	}

	// 4. Empty delivery ID returns error
	if err := detector.CheckAndRecord("", now); err == nil {
		t.Fatal("expected error on empty delivery ID")
	}

	// 5. Expiration / pruning: after retention period, stale delivery ID is purged and accepted as new
	futureNow := now.Add(70 * time.Second)
	if err := detector.CheckAndRecord("deliv-100", futureNow); err != nil {
		t.Fatalf("expected delivery ID to succeed after eviction: %v", err)
	}

	// 6. Concurrency safety test
	concurDetector := NewMemoryReplayDetector(60 * time.Second)
	var wg sync.WaitGroup
	var errCount int
	var mu sync.Mutex

	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			err := concurDetector.CheckAndRecord("shared-deliv-concurrent", now)
			if err != nil {
				mu.Lock()
				errCount++
				mu.Unlock()
			}
		}(i)
	}
	wg.Wait()

	// Exactly 49 should be rejected as replays, exactly 1 should succeed
	if errCount != 49 {
		t.Errorf("expected exactly 49 replays rejected, got %d", errCount)
	}
}

func TestGenerateWebhookSecret(t *testing.T) {
	s1, err := GenerateWebhookSecret()
	if err != nil {
		t.Fatalf("failed to generate secret: %v", err)
	}
	if len(s1) != 64 {
		t.Fatalf("expected 64 hex characters (32 bytes), got length %d", len(s1))
	}

	s2, err := GenerateWebhookSecret()
	if err != nil {
		t.Fatalf("failed to generate second secret: %v", err)
	}
	if s1 == s2 {
		t.Fatalf("expected distinct random secrets, got duplicate: %s", s1)
	}
}

func TestVerifyWebhookRequestHelper(t *testing.T) {
	secret := "request-helper-secret"
	now := time.Now().UTC()
	tsStr := fmt.Sprintf("%d", now.Unix())
	body := []byte(`{"assessment_id":"asm-123","event":"completed"}`)
	sig := ComputeSignatureV1(secret, tsStr, body)

	req := httptest.NewRequest(http.MethodPost, "/webhook", bytes.NewReader(body))
	req.Header.Set(HeaderFelixSignature, "v1="+sig)
	req.Header.Set(HeaderFelixTimestamp, tsStr)

	// Valid request verification
	readBody, err := VerifyWebhookRequest(req, secret, 300*time.Second, now)
	if err != nil {
		t.Fatalf("expected VerifyWebhookRequest to succeed: %v", err)
	}
	if !bytes.Equal(readBody, body) {
		t.Fatalf("read body does not match original body")
	}

	// Verify req.Body was restored and can be read again
	downstreamBody, err := io.ReadAll(req.Body)
	if err != nil {
		t.Fatalf("failed to read downstream body: %v", err)
	}
	if !bytes.Equal(downstreamBody, body) {
		t.Fatalf("downstream body does not match original body")
	}

	// Tampered body fails verification
	tamperedReq := httptest.NewRequest(http.MethodPost, "/webhook", bytes.NewReader([]byte(`{"tampered":true}`)))
	tamperedReq.Header.Set(HeaderFelixSignature, "v1="+sig)
	tamperedReq.Header.Set(HeaderFelixTimestamp, tsStr)

	if _, err := VerifyWebhookRequest(tamperedReq, secret, 300*time.Second, now); !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("expected ErrInvalidSignature on tampered request body, got: %v", err)
	}
}

func TestWebhookProvider_RequireSigningEnforcement(t *testing.T) {
	// Server should never receive a request when signing is required but secret is missing
	var received bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received = true
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	cfg := WebhookConfig{
		URL:               srv.URL,
		Secret:            "",
		RequireSigning:    true,
		AllowInsecureHTTP: true,
		AllowPrivateIPs:   true,
		AllowLoopback:     true,
	}

	// 1. NewWebhookProvider must refuse invalid configuration at construction time
	_, err := NewWebhookProvider(cfg)
	if err == nil {
		t.Fatal("expected NewWebhookProvider constructor to reject missing secret when RequireSigning is true")
	}
	if !errors.Is(err, ErrSigningKeyRequired) {
		t.Fatalf("expected ErrSigningKeyRequired, got: %v", err)
	}

	// 2. Direct Send() must also fail closed immediately and never transmit
	prov := &WebhookProvider{
		cfg:    cfg,
		client: newHardenedHTTPClient(cfg),
	}

	notif := BuildTestNotification("tenant-1", srv.URL, time.Now().UTC())
	receipt, err := prov.Send(context.Background(), notif)

	if err == nil {
		t.Fatal("expected delivery to fail closed when RequireSigning is true and Secret is empty")
	}
	if receipt != nil {
		t.Fatal("expected nil receipt on signing failure")
	}
	if received {
		t.Fatal("endpoint received request despite missing signing key in RequireSigning mode")
	}

	var delivErr *DeliveryError
	if !errors.As(err, &delivErr) || !delivErr.IsPermanent() {
		t.Fatalf("expected permanent DeliveryError, got: %v", err)
	}
}

func TestWebhookProvider_ExactTransmittedBytes(t *testing.T) {
	secret := "transmitted-bytes-canary-key-42"
	var receivedBody []byte
	var receivedSig string
	var receivedTS string
	var receivedDelivery string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedBody, _ = io.ReadAll(r.Body)
		receivedSig = r.Header.Get(HeaderFelixSignature)
		receivedTS = r.Header.Get(HeaderFelixTimestamp)
		receivedDelivery = r.Header.Get(HeaderFelixDelivery)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	prov, err := NewWebhookProvider(WebhookConfig{
		URL:               srv.URL,
		Secret:            secret,
		RequireSigning:    true,
		AllowInsecureHTTP: true,
		AllowPrivateIPs:   true,
		AllowLoopback:     true,
	})
	if err != nil {
		t.Fatalf("failed to create provider: %v", err)
	}

	notif := BuildTestNotification("tenant-bytes-test", srv.URL, time.Now().UTC())
	receipt, err := prov.Send(context.Background(), notif)
	if err != nil {
		t.Fatalf("expected send to succeed: %v", err)
	}
	if receipt.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 OK, got: %d", receipt.StatusCode)
	}

	// Verify headers were set
	if receivedSig == "" || !strings.HasPrefix(receivedSig, "v1=") {
		t.Fatalf("expected valid v1= signature header, got: %s", receivedSig)
	}
	if receivedTS == "" {
		t.Fatal("expected X-Felix-Timestamp header")
	}
	if receivedDelivery != notif.ID {
		t.Fatalf("expected delivery ID %s, got: %s", notif.ID, receivedDelivery)
	}

	// Verify exact transmitted bytes match the signature
	if err := VerifyWebhookSignature(secret, receivedTS, receivedBody, receivedSig, 300*time.Second, time.Time{}); err != nil {
		t.Fatalf("receiver signature verification failed over exact transmitted bytes: %v", err)
	}
}

func TestWebhookProvider_ConstructorRequireSigningValidation(t *testing.T) {
	// Constructor NewWebhookProvider must fail immediately if RequireSigning is true and Secret is empty
	_, err := NewWebhookProvider(WebhookConfig{
		URL:               "https://example.com/webhook",
		Secret:            "",
		RequireSigning:    true,
		AllowInsecureHTTP: false,
	})
	if err == nil {
		t.Fatal("expected NewWebhookProvider to fail when RequireSigning is true and Secret is empty")
	}
	if !errors.Is(err, ErrSigningKeyRequired) {
		t.Fatalf("expected ErrSigningKeyRequired, got: %v", err)
	}

	// NewProvider must also fail
	_, err = NewProvider(WebhookConfig{
		URL:            "https://example.com/webhook",
		Secret:         "",
		RequireSigning: true,
	}, "webhook")
	if err == nil || !errors.Is(err, ErrSigningKeyRequired) {
		t.Fatalf("expected NewProvider to fail closed with ErrSigningKeyRequired, got: %v", err)
	}
}

func TestWebhookProvider_RetryDeliverySemantics(t *testing.T) {
	// Verify that across delivery retries:
	// 1. Delivery ID (X-Felix-Delivery) remains stable and unchanged
	// 2. Serialized body bytes remain stable and unchanged
	// 3. Timestamp is refreshed per attempt and signature authenticates that attempt's timestamp
	var attemptCount int
	var capturedDeliveries []string
	var capturedSignatures []string
	var capturedTimestamps []string
	var capturedBodies [][]byte

	secret := "retry-semantics-test-secret"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attemptCount++
		capturedDeliveries = append(capturedDeliveries, r.Header.Get(HeaderFelixDelivery))
		capturedSignatures = append(capturedSignatures, r.Header.Get(HeaderFelixSignature))
		capturedTimestamps = append(capturedTimestamps, r.Header.Get(HeaderFelixTimestamp))
		b, _ := io.ReadAll(r.Body)
		capturedBodies = append(capturedBodies, b)

		if attemptCount == 1 {
			// Fail first attempt with transient 500 error
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		// Succeed second attempt
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	prov, err := NewWebhookProvider(WebhookConfig{
		URL:               srv.URL,
		Secret:            secret,
		RequireSigning:    true,
		AllowInsecureHTTP: true,
		AllowPrivateIPs:   true,
		AllowLoopback:     true,
	})
	if err != nil {
		t.Fatalf("failed to create provider: %v", err)
	}

	notif := BuildTestNotification("retry-tenant", srv.URL, time.Now().UTC())
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	receipt, err := SendWithRetries(ctx, prov, notif, 2, 50*time.Millisecond)
	if err != nil {
		t.Fatalf("expected delivery to succeed on retry: %v", err)
	}
	if receipt == nil || receipt.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 OK receipt, got: %+v", receipt)
	}
	if attemptCount != 2 {
		t.Fatalf("expected 2 attempts, got: %d", attemptCount)
	}

	// 1. Delivery ID must be identical across retries
	if capturedDeliveries[0] != notif.ID || capturedDeliveries[1] != notif.ID {
		t.Errorf("delivery ID changed across retries: %s vs %s (expected %s)", capturedDeliveries[0], capturedDeliveries[1], notif.ID)
	}

	// 2. Body must be identical across retries
	if !bytes.Equal(capturedBodies[0], capturedBodies[1]) {
		t.Errorf("body mutated across retries")
	}

	// 3. Both attempts must be cryptographically verifiable
	for i := 0; i < 2; i++ {
		if err := VerifyWebhookSignature(secret, capturedTimestamps[i], capturedBodies[i], capturedSignatures[i], 300*time.Second, time.Time{}); err != nil {
			t.Errorf("attempt %d failed signature verification: %v", i+1, err)
		}
	}
}
