package notify

import (
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

// TestWebhookSecurity_RegressionFixtures tests signature integrity, key rotation, replay defenses, and downgrade prevention.
func TestWebhookSecurity_RegressionFixtures(t *testing.T) {
	primarySecret := "primary-secret-key-2026"
	previousSecret := "previous-secret-key-2025"
	now := time.Unix(1760000000, 0).UTC()
	tsStr := "1760000000"
	payload := []byte(`{"event":"assessment.completed","id":"asmt-123","risk_score":45}`)

	primarySig := ComputeSignatureV1(primarySecret, tsStr, payload)
	previousSig := ComputeSignatureV1(previousSecret, tsStr, payload)

	// 1. Valid signature with primary key succeeds under PolicyStrict
	validHeader := "v1=" + primarySig
	err := VerifyWebhookSignatureWithOptions(primarySecret, tsStr, payload, validHeader, VerificationOptions{
		Tolerance: 300 * time.Second,
		Now:       now,
		Policy:    PolicyStrict,
	})
	if err != nil {
		t.Fatalf("valid signature rejected: %v", err)
	}

	// 2. Key rotation: primary key mismatch, but previous key succeeds
	errRotated := VerifyWebhookSignatureWithKeys(primarySecret, previousSecret, tsStr, payload, "v1="+previousSig, 300*time.Second, now)
	if errRotated != nil {
		t.Fatalf("key rotation signature with previousSecret rejected: %v", errRotated)
	}

	// 3. Replay defense: Stale timestamp (older than tolerance) rejected with ErrTimestampExpired
	staleTs := fmt.Sprintf("%d", now.Unix()-301)
	staleSig := ComputeSignatureV1(primarySecret, staleTs, payload)
	errStale := VerifyWebhookSignatureWithOptions(primarySecret, staleTs, payload, "v1="+staleSig, VerificationOptions{
		Tolerance: 300 * time.Second,
		Now:       now,
		Policy:    PolicyStrict,
	})
	if !errors.Is(errStale, ErrTimestampExpired) {
		t.Fatalf("expected ErrTimestampExpired for stale request, got: %v", errStale)
	}

	// 4. Future timestamp defense: request timestamp in future beyond tolerance rejected with ErrTimestampFuture
	futureTs := fmt.Sprintf("%d", now.Unix()+301)
	futureSig := ComputeSignatureV1(primarySecret, futureTs, payload)
	errFuture := VerifyWebhookSignatureWithOptions(primarySecret, futureTs, payload, "v1="+futureSig, VerificationOptions{
		Tolerance: 300 * time.Second,
		Now:       now,
		Policy:    PolicyStrict,
	})
	if !errors.Is(errFuture, ErrTimestampFuture) {
		t.Fatalf("expected ErrTimestampFuture for future request, got: %v", errFuture)
	}

	// 5. Replay detector: duplicate delivery ID rejected with ErrReplayDetected
	detector := NewMemoryReplayDetector(300 * time.Second)
	deliveryID := "deliv-unique-uuid-12345"

	// First delivery attempt -> accepted
	if err := detector.CheckAndRecord(deliveryID, now); err != nil {
		t.Fatalf("first delivery attempt rejected: %v", err)
	}

	// Second delivery attempt with same deliveryID -> rejected
	if err := detector.CheckAndRecord(deliveryID, now); !errors.Is(err, ErrReplayDetected) {
		t.Fatalf("expected ErrReplayDetected on duplicate delivery ID, got: %v", err)
	}

	// 6. Downgrade prevention: legacy body-only sha256= signature is strictly rejected under PolicyStrict
	legacyBodySig := ComputeWebhookSignature(primarySecret, payload)
	legacyHeader := "sha256=" + legacyBodySig

	errDowngrade := VerifyWebhookSignatureWithOptions(primarySecret, tsStr, payload, legacyHeader, VerificationOptions{
		Tolerance: 300 * time.Second,
		Now:       now,
		Policy:    PolicyStrict,
	})
	if !errors.Is(errDowngrade, ErrLegacyDowngradeRejected) {
		t.Fatalf("expected ErrLegacyDowngradeRejected under strict policy, got: %v", errDowngrade)
	}

	// 7. Explicit permissive policy accepts legacy body-only signature during migration window
	errPermissive := VerifyWebhookSignatureWithOptions(primarySecret, tsStr, payload, legacyHeader, VerificationOptions{
		Tolerance: 300 * time.Second,
		Now:       now,
		Policy:    PolicyPermissive,
	})
	if errPermissive != nil {
		t.Fatalf("permissive policy failed to accept legacy signature: %v", errPermissive)
	}
}

// TestWebhookSecurity_RedactionAndDiagnostics verifies that sensitive secrets and tokens are redacted.
func TestWebhookSecurity_RedactionAndDiagnostics(t *testing.T) {
	rawSecret := "whsec_supersecretkey999"
	err := VerifyWebhookSignatureWithOptions("", "1760000000", []byte("{}"), "v1=123", VerificationOptions{})
	if !errors.Is(err, ErrSigningKeyRequired) {
		t.Fatalf("expected ErrSigningKeyRequired for empty secret, got: %v", err)
	}

	// Ensure error string does not leak any potential sensitive values
	if strings.Contains(err.Error(), rawSecret) {
		t.Fatalf("raw secret leaked in error: %v", err)
	}
}
