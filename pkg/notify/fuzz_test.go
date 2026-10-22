package notify

import (
	"strings"
	"testing"
	"time"
)

func FuzzParseSignatureHeader(f *testing.F) {
	// Seed corpus
	f.Add("v1=5d41402abc4b2a76b9719d911017c592")
	f.Add("v1=abc123,v1=def456")
	f.Add("sha256=legacy123")
	f.Add("v1=new123,sha256=old123")
	f.Add("")
	f.Add("   ")
	f.Add("invalid_without_equals")
	f.Add("=missing_key")
	f.Add("missing_val=")
	f.Add(",,,,")
	f.Add("v1=a=b=c")
	f.Add(strings.Repeat("v1=abc,", 100))

	f.Fuzz(func(t *testing.T, header string) {
		res := ParseSignatureHeader(header)
		if res == nil {
			t.Fatalf("ParseSignatureHeader returned nil map")
		}

		for k, list := range res {
			if strings.TrimSpace(k) == "" {
				t.Fatalf("ParseSignatureHeader produced empty key")
			}
			for _, sig := range list {
				if strings.TrimSpace(sig) == "" {
					t.Fatalf("ParseSignatureHeader produced empty signature value for key %q", k)
				}
			}
		}
	})
}

func FuzzParseWebhookTimestamp(f *testing.F) {
	// Seed corpus
	f.Add("1760000000")
	f.Add("0")
	f.Add("-1")
	f.Add("9999999999999")
	f.Add("2026-10-22T10:00:00Z")
	f.Add("2026-10-22T10:00:00.000Z")
	f.Add("2026-10-22T15:30:00+05:30")
	f.Add("")
	f.Add("   ")
	f.Add("not-a-timestamp")
	f.Add("1760000000\x00extra")

	f.Fuzz(func(t *testing.T, timestampStr string) {
		ts, err := ParseWebhookTimestamp(timestampStr)
		if err != nil {
			return
		}

		// Invariant: Parsed timestamp must be normalized to UTC
		if ts.Location() != time.UTC {
			t.Fatalf("ParseWebhookTimestamp did not normalize to UTC: %v", ts.Location())
		}
	})
}

func FuzzVerifyWebhookSignature(f *testing.F) {
	now := time.Unix(1760000000, 0).UTC()
	validSecret := "supersecretkey"
	validTs := "1760000000"
	validPayload := []byte(`{"event":"test","id":"123"}`)
	validSig := ComputeSignatureV1(validSecret, validTs, validPayload)
	validHeader := "v1=" + validSig

	f.Add(validSecret, validTs, validPayload, validHeader, "strict")
	f.Add(validSecret, validTs, validPayload, "sha256=deadbeef", "strict")
	f.Add(validSecret, validTs, validPayload, "sha256=deadbeef", "permissive")
	f.Add("", validTs, validPayload, validHeader, "strict")
	f.Add(validSecret, "", validPayload, validHeader, "strict")
	f.Add(validSecret, "invalid-ts", validPayload, validHeader, "strict")
	f.Add(validSecret, validTs, []byte(""), validHeader, "strict")
	f.Add(validSecret, validTs, validPayload, "", "strict")
	f.Add("short", "100", []byte{0x00, 0xff}, "unsupported=foo", "strict")

	f.Fuzz(func(t *testing.T, secret, tsStr string, payload []byte, sigHeader, policyStr string) {
		policy := PolicyStrict
		if policyStr == "permissive" {
			policy = PolicyPermissive
		}

		opts := VerificationOptions{
			Tolerance: 300 * time.Second,
			Now:       now,
			Policy:    policy,
		}

		err := VerifyWebhookSignatureWithOptions(secret, tsStr, payload, sigHeader, opts)

		// Invariant 1: If secret is empty or whitespace, it must fail with ErrSigningKeyRequired
		if strings.TrimSpace(secret) == "" {
			if err != ErrSigningKeyRequired {
				t.Fatalf("expected ErrSigningKeyRequired for empty secret, got: %v", err)
			}
		}

		// Invariant 2: Under PolicyStrict, a header containing only legacy sha256= must be rejected
		if policy == PolicyStrict && strings.HasPrefix(sigHeader, "sha256=") && !strings.Contains(sigHeader, "v1=") {
			if err == nil {
				t.Fatalf("strict policy accepted legacy sha256 signature without v1")
			}
		}
	})
}
