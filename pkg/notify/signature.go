package notify

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	// HeaderFelixSignature is the HTTP header containing webhook HMAC signatures.
	HeaderFelixSignature = "X-Felix-Signature"
	// HeaderFelixTimestamp is the HTTP header containing the Unix timestamp of the request.
	HeaderFelixTimestamp = "X-Felix-Timestamp"
	// HeaderFelixDelivery is the HTTP header containing the stable outbox delivery ID.
	HeaderFelixDelivery = "X-Felix-Delivery"

	// SignatureVersionV1 is the current signature scheme version prefix.
	SignatureVersionV1 = "v1"
	// LegacySignaturePrefix is the legacy prefix supported for backward compatibility.
	LegacySignaturePrefix = "sha256"

	// DefaultSignatureTolerance is the default maximum allowable clock skew / timestamp age (5 minutes).
	DefaultSignatureTolerance = 300 * time.Second
)

// Common webhook signature and authentication errors.
var (
	ErrMissingSignature        = errors.New("missing webhook signature header")
	ErrMissingTimestamp        = errors.New("missing webhook timestamp header")
	ErrInvalidTimestamp        = errors.New("invalid webhook timestamp format")
	ErrTimestampExpired        = errors.New("webhook timestamp expired (replay tolerance exceeded)")
	ErrTimestampFuture         = errors.New("webhook timestamp is in the future beyond tolerance window")
	ErrInvalidSignature        = errors.New("webhook signature verification failed")
	ErrUnsupportedVersion      = errors.New("unsupported signature scheme version")
	ErrSigningKeyRequired      = errors.New("signing is required by configuration, but no webhook secret is configured")
	ErrReplayDetected          = errors.New("webhook delivery replay detected")
	ErrLegacyDowngradeRejected = errors.New("legacy body-only sha256 signature rejected: timestamp-bound v1 signature required")
)

// SignaturePolicy defines the policy for accepting legacy or modern signature schemes.
type SignaturePolicy string

const (
	// PolicyStrict requires timestamp-bound signatures (v1=). Legacy body-only signatures are rejected as downgrade attempts.
	PolicyStrict SignaturePolicy = "strict"
	// PolicyPermissive accepts both timestamp-bound and legacy body-only signatures during explicit migration windows.
	PolicyPermissive SignaturePolicy = "permissive"
)

// VerificationOptions provides configuration for receiver signature validation.
type VerificationOptions struct {
	Tolerance time.Duration
	Now       time.Time
	Policy    SignaturePolicy // Default: PolicyStrict
}

// ComputeSignatureMessage constructs the unambiguous canonical message: "<timestamp>.<raw-payload-bytes>".
func ComputeSignatureMessage(timestampStr string, payload []byte) []byte {
	tsBytes := []byte(strings.TrimSpace(timestampStr))
	msg := make([]byte, len(tsBytes)+1+len(payload))
	copy(msg, tsBytes)
	msg[len(tsBytes)] = '.'
	copy(msg[len(tsBytes)+1:], payload)
	return msg
}

// ComputeSignatureV1 generates an HMAC-SHA-256 hex digest for "<timestamp>.<raw-payload-bytes>".
func ComputeSignatureV1(secret string, timestampStr string, payload []byte) string {
	msg := ComputeSignatureMessage(timestampStr, payload)
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(msg)
	return hex.EncodeToString(mac.Sum(nil))
}

// FormatSignatureHeader builds a comma-separated signature header string.
func FormatSignatureHeader(signatures ...string) string {
	return strings.Join(signatures, ",")
}

// ParseSignatureHeader extracts versioned signatures from the signature header.
// Supports comma-separated entries, e.g. "v1=abc,v1=def" or legacy "sha256=xyz".
func ParseSignatureHeader(header string) map[string][]string {
	result := make(map[string][]string)
	entries := strings.Split(header, ",")
	for _, entry := range entries {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		parts := strings.SplitN(entry, "=", 2)
		if len(parts) == 2 {
			ver := strings.TrimSpace(parts[0])
			sig := strings.TrimSpace(parts[1])
			if ver != "" && sig != "" {
				result[ver] = append(result[ver], sig)
			}
		}
	}
	return result
}

// ParseWebhookTimestamp parses a Unix timestamp string (or RFC3339 fallback).
func ParseWebhookTimestamp(timestampStr string) (time.Time, error) {
	trimmed := strings.TrimSpace(timestampStr)
	if trimmed == "" {
		return time.Time{}, ErrMissingTimestamp
	}

	// 1. Try Unix epoch seconds (standard)
	if sec, err := strconv.ParseInt(trimmed, 10, 64); err == nil {
		return time.Unix(sec, 0).UTC(), nil
	}

	// 2. Fallback to RFC3339 for backward compatibility
	if t, err := time.Parse(time.RFC3339, trimmed); err == nil {
		return t.UTC(), nil
	}

	return time.Time{}, fmt.Errorf("%w: %s", ErrInvalidTimestamp, trimmed)
}

// VerifyWebhookSignature verifies that an incoming payload, timestamp, and signature header
// match the expected HMAC-SHA-256 signature using constant-time comparison under PolicyStrict.
// Legacy body-only signatures without timestamp binding are strictly rejected as downgrade attempts.
func VerifyWebhookSignature(
	secret string,
	timestampStr string,
	payload []byte,
	sigHeader string,
	tolerance time.Duration,
	now time.Time,
) error {
	return VerifyWebhookSignatureWithOptions(secret, timestampStr, payload, sigHeader, VerificationOptions{
		Tolerance: tolerance,
		Now:       now,
		Policy:    PolicyStrict,
	})
}

// VerifyWebhookSignaturePermissive verifies signatures allowing legacy body-only sha256= signatures
// during explicit migration windows.
func VerifyWebhookSignaturePermissive(
	secret string,
	timestampStr string,
	payload []byte,
	sigHeader string,
	tolerance time.Duration,
	now time.Time,
) error {
	return VerifyWebhookSignatureWithOptions(secret, timestampStr, payload, sigHeader, VerificationOptions{
		Tolerance: tolerance,
		Now:       now,
		Policy:    PolicyPermissive,
	})
}

// VerifyWebhookSignatureWithOptions validates a webhook signature according to explicit VerificationOptions.
func VerifyWebhookSignatureWithOptions(
	secret string,
	timestampStr string,
	payload []byte,
	sigHeader string,
	opts VerificationOptions,
) error {
	if strings.TrimSpace(secret) == "" {
		return ErrSigningKeyRequired
	}

	trimmedSig := strings.TrimSpace(sigHeader)
	if trimmedSig == "" {
		return ErrMissingSignature
	}

	ts, err := ParseWebhookTimestamp(timestampStr)
	if err != nil {
		return err
	}

	tolerance := opts.Tolerance
	if tolerance <= 0 {
		tolerance = DefaultSignatureTolerance
	}
	now := opts.Now
	if now.IsZero() {
		now = time.Now().UTC()
	} else {
		now = now.UTC()
	}

	// Replay mitigation: check timestamp freshness against tolerance window
	if now.Sub(ts) > tolerance {
		return fmt.Errorf("%w: timestamp %s is older than tolerance %v", ErrTimestampExpired, timestampStr, tolerance)
	}
	if ts.Sub(now) > tolerance {
		return fmt.Errorf("%w: timestamp %s is in the future beyond tolerance %v", ErrTimestampFuture, timestampStr, tolerance)
	}

	policy := opts.Policy
	if policy == "" {
		policy = PolicyStrict
	}

	parsedSigs := ParseSignatureHeader(trimmedSig)
	if len(parsedSigs) == 0 {
		return fmt.Errorf("%w: no valid scheme=signature pairs in header %q", ErrInvalidSignature, trimmedSig)
	}

	// 1. Check v1 signatures (bound to timestamp and payload)
	if v1Sigs, ok := parsedSigs[SignatureVersionV1]; ok {
		expectedSig := ComputeSignatureV1(secret, timestampStr, payload)
		expectedBytes := []byte(expectedSig)

		for _, sig := range v1Sigs {
			if hmac.Equal([]byte(sig), expectedBytes) {
				return nil
			}
		}
	}

	// 2. Check legacy sha256 signatures with explicit downgrade protection
	if legacySigs, ok := parsedSigs[LegacySignaturePrefix]; ok {
		// First check if legacy header was actually generated over "<timestamp>.<payload>" (timestamp-bound)
		expectedV1 := ComputeSignatureV1(secret, timestampStr, payload)
		for _, sig := range legacySigs {
			if hmac.Equal([]byte(sig), []byte(expectedV1)) {
				return nil
			}
		}

		// Check if it matches the legacy body-only HMAC
		expectedLegacy := ComputeWebhookSignature(secret, payload)
		for _, sig := range legacySigs {
			if hmac.Equal([]byte(sig), []byte(expectedLegacy)) {
				if policy != PolicyPermissive {
					return fmt.Errorf("%w: payload signed with body-only sha256 without timestamp binding", ErrLegacyDowngradeRejected)
				}
				// Explicitly allowed only under PolicyPermissive
				return nil
			}
		}
	}

	// If no supported version matched
	if _, hasV1 := parsedSigs[SignatureVersionV1]; !hasV1 {
		if _, hasLegacy := parsedSigs[LegacySignaturePrefix]; !hasLegacy {
			return ErrUnsupportedVersion
		}
	}

	return ErrInvalidSignature
}

// VerifyWebhookSignatureWithKeys checks the signature against primarySecret, and falls back to
// previousSecret during a key rotation window.
func VerifyWebhookSignatureWithKeys(
	primarySecret string,
	previousSecret string,
	timestampStr string,
	payload []byte,
	sigHeader string,
	tolerance time.Duration,
	now time.Time,
) error {
	return VerifyWebhookSignatureWithKeysAndOptions(primarySecret, previousSecret, timestampStr, payload, sigHeader, VerificationOptions{
		Tolerance: tolerance,
		Now:       now,
		Policy:    PolicyStrict,
	})
}

// VerifyWebhookSignatureWithKeysAndOptions checks the signature against keys under custom VerificationOptions.
func VerifyWebhookSignatureWithKeysAndOptions(
	primarySecret string,
	previousSecret string,
	timestampStr string,
	payload []byte,
	sigHeader string,
	opts VerificationOptions,
) error {
	var primaryErr error
	if strings.TrimSpace(primarySecret) != "" {
		primaryErr = VerifyWebhookSignatureWithOptions(primarySecret, timestampStr, payload, sigHeader, opts)
		if primaryErr == nil {
			return nil
		}
		// If verification failed due to timestamp / format / downgrade issues, don't fallback to previous key
		if errors.Is(primaryErr, ErrTimestampExpired) ||
			errors.Is(primaryErr, ErrTimestampFuture) ||
			errors.Is(primaryErr, ErrInvalidTimestamp) ||
			errors.Is(primaryErr, ErrMissingTimestamp) ||
			errors.Is(primaryErr, ErrMissingSignature) ||
			errors.Is(primaryErr, ErrLegacyDowngradeRejected) {
			return primaryErr
		}
	}

	if strings.TrimSpace(previousSecret) != "" {
		prevErr := VerifyWebhookSignatureWithOptions(previousSecret, timestampStr, payload, sigHeader, opts)
		if prevErr == nil {
			return nil
		}
	}

	if primaryErr != nil {
		return primaryErr
	}
	return ErrSigningKeyRequired
}

// VerifyWebhookRequest inspects and validates an incoming HTTP webhook request on the receiver side.
// The request body is restored so downstream handlers can process the payload normally.
func VerifyWebhookRequest(req *http.Request, secret string, tolerance time.Duration, now time.Time) ([]byte, error) {
	if req == nil {
		return nil, errors.New("request cannot be nil")
	}
	if req.Body == nil {
		return nil, errors.New("request body is nil")
	}

	bodyBytes, err := io.ReadAll(io.LimitReader(req.Body, int64(DefaultMaxPayloadBytes)+1024))
	if err != nil {
		return nil, fmt.Errorf("failed to read request body: %w", err)
	}
	_ = req.Body.Close()
	req.Body = io.NopCloser(bytes.NewReader(bodyBytes))

	sigHeader := req.Header.Get(HeaderFelixSignature)
	timestampStr := req.Header.Get(HeaderFelixTimestamp)

	if err := VerifyWebhookSignature(secret, timestampStr, bodyBytes, sigHeader, tolerance, now); err != nil {
		return nil, err
	}

	return bodyBytes, nil
}

// VerifyWebhookRequestWithKeys validates an incoming HTTP webhook request supporting key rotation.
func VerifyWebhookRequestWithKeys(req *http.Request, primarySecret, previousSecret string, tolerance time.Duration, now time.Time) ([]byte, error) {
	if req == nil {
		return nil, errors.New("request cannot be nil")
	}
	if req.Body == nil {
		return nil, errors.New("request body is nil")
	}

	bodyBytes, err := io.ReadAll(io.LimitReader(req.Body, int64(DefaultMaxPayloadBytes)+1024))
	if err != nil {
		return nil, fmt.Errorf("failed to read request body: %w", err)
	}
	_ = req.Body.Close()
	req.Body = io.NopCloser(bytes.NewReader(bodyBytes))

	sigHeader := req.Header.Get(HeaderFelixSignature)
	timestampStr := req.Header.Get(HeaderFelixTimestamp)

	if err := VerifyWebhookSignatureWithKeys(primarySecret, previousSecret, timestampStr, bodyBytes, sigHeader, tolerance, now); err != nil {
		return nil, err
	}

	return bodyBytes, nil
}

// GenerateWebhookSecret generates a cryptographically secure 32-byte (64 hex characters) secret.
func GenerateWebhookSecret() (string, error) {
	buf := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, buf); err != nil {
		return "", fmt.Errorf("failed to read secure random bytes: %w", err)
	}
	return hex.EncodeToString(buf), nil
}

// ReplayDetector defines the interface for receiver-side replay detection.
// While timestamp verification restricts replay to a bounded window, complete replay
// prevention requires the receiver to track unique delivery IDs or signatures.
type ReplayDetector interface {
	CheckAndRecord(deliveryID string, now time.Time) error
}

// MemoryReplayDetector implements an in-memory sliding-window replay detector for receivers.
// It tracks seen delivery IDs within a bounded retention window and evicts stale records.
type MemoryReplayDetector struct {
	mu        sync.Mutex
	seen      map[string]time.Time
	retention time.Duration
}

// NewMemoryReplayDetector creates a MemoryReplayDetector with the specified retention window.
func NewMemoryReplayDetector(retention time.Duration) *MemoryReplayDetector {
	if retention <= 0 {
		retention = DefaultSignatureTolerance
	}
	return &MemoryReplayDetector{
		seen:      make(map[string]time.Time),
		retention: retention,
	}
}

// CheckAndRecord verifies that deliveryID has not been seen within the retention window,
// records it if new, and prunes expired records.
func (d *MemoryReplayDetector) CheckAndRecord(deliveryID string, now time.Time) error {
	trimmedID := strings.TrimSpace(deliveryID)
	if trimmedID == "" {
		return errors.New("delivery ID cannot be empty")
	}
	if now.IsZero() {
		now = time.Now().UTC()
	} else {
		now = now.UTC()
	}

	d.mu.Lock()
	defer d.mu.Unlock()

	// Prune expired records
	cutoff := now.Add(-d.retention)
	for id, seenAt := range d.seen {
		if seenAt.Before(cutoff) {
			delete(d.seen, id)
		}
	}

	// Check if already seen
	if seenAt, exists := d.seen[trimmedID]; exists {
		if seenAt.After(cutoff) {
			return fmt.Errorf("%w: delivery ID %q already processed at %s", ErrReplayDetected, trimmedID, seenAt.Format(time.RFC3339))
		}
	}

	d.seen[trimmedID] = now
	return nil
}
