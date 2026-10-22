package apk

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// TestAPK_TextualManifest_XXEDefense verifies strict rejection of XML entity expansion
// and DOCTYPE declarations (both upper and lower case).
func TestAPK_TextualManifest_XXEDefense(t *testing.T) {
	xxePayloads := []struct {
		name    string
		payload string
	}{
		{
			name:    "uppercase DOCTYPE with file entity",
			payload: `<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><manifest>&test;</manifest>`,
		},
		{
			name:    "lowercase doctype with external entity",
			payload: `<!doctype manifest [<!entity evil "evil">]><manifest>&evil;</manifest>`,
		},
		{
			name:    "mixed case DocType with parameter entity",
			payload: `<!DocType manifest SYSTEM "http://evil.com/dtd"><manifest/>`,
		},
		{
			name:    "billion laughs entity expansion attempt",
			payload: `<!DOCTYPE lolz [<!ENTITY lol "lol"><!ENTITY lol2 "&lol;&lol;">]><manifest>&lol2;</manifest>`,
		},
	}

	limits := DefaultLimits()

	for _, tt := range xxePayloads {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParseTextualManifest([]byte(tt.payload), limits)
			if err == nil {
				t.Fatalf("ParseTextualManifest accepted prohibited entity expansion payload")
			}
			if !errors.Is(err, ErrSecurityViolation) {
				t.Errorf("expected ErrSecurityViolation, got: %v", err)
			}
			if !strings.Contains(err.Error(), "prohibited DOCTYPE or ENTITY declaration") {
				t.Errorf("error %q does not explain entity expansion defense", err.Error())
			}
		})
	}
}

// TestAPK_AXML_BoundsAndChunkValidation verifies parser resilience on malformed chunk headers and sizes.
func TestAPK_AXML_BoundsAndChunkValidation(t *testing.T) {
	tests := []struct {
		name        string
		data        []byte
		errContains string
	}{
		{
			name:        "truncated header less than 8 bytes",
			data:        []byte{0x03, 0x00, 0x08, 0x00},
			errContains: "AXML data too short",
		},
		{
			name:        "invalid root chunk type",
			data:        []byte{0x99, 0x99, 0x08, 0x00, 0x08, 0x00, 0x00, 0x00},
			errContains: "invalid AXML root chunk type",
		},
		{
			name:        "declared chunk size smaller than header size",
			data:        []byte{0x03, 0x00, 0x08, 0x00, 0x04, 0x00, 0x00, 0x00},
			errContains: "declared AXML chunk size",
		},
		{
			name:        "declared chunk size exceeds actual data buffer",
			data:        []byte{0x03, 0x00, 0x08, 0x00, 0xFF, 0x00, 0x00, 0x00},
			errContains: "declared AXML chunk size",
		},
	}

	limits := DefaultLimits()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParseAXML(tt.data, limits)
			if err == nil {
				t.Fatalf("ParseAXML succeeded unexpectedly on malformed AXML data")
			}
			if !strings.Contains(err.Error(), tt.errContains) {
				t.Errorf("error %q does not contain expected %q", err.Error(), tt.errContains)
			}
		})
	}
}

// TestAPK_DEX_HeaderValidation tests DEX header validation and bounds.
func TestAPK_DEX_HeaderValidation(t *testing.T) {
	ctx := context.Background()
	limits := DefaultLimits()

	// 1. Truncated buffer (< 112 bytes)
	_, errTruncated := ParseDEX(ctx, "classes.dex", []byte("dex\n035\x00"), limits)
	if errTruncated == nil {
		t.Fatalf("expected error for truncated DEX buffer, got nil")
	}

	// 2. Invalid magic bytes
	fakeDEX := append([]byte("not_a_dex_file!!"), make([]byte, 100)...)
	_, errMagic := ParseDEX(ctx, "classes.dex", fakeDEX, limits)
	if errMagic == nil {
		t.Fatalf("expected error for invalid DEX magic, got nil")
	}
	if !strings.Contains(errMagic.Error(), "invalid DEX magic") {
		t.Errorf("error %q does not mention invalid DEX magic", errMagic.Error())
	}

	// 3. Valid DEX 035 and 039 headers with minimal zero-filled structures
	valid035 := make([]byte, 112)
	copy(valid035, []byte("dex\n035\x00"))
	valid035[32] = 112 // fileSize = 112
	valid035[36] = 112 // headerSize = 112
	valid035[40] = 0x78
	valid035[41] = 0x56
	valid035[42] = 0x34
	valid035[43] = 0x12 // endian_tag = ENDIAN_CONSTANT (0x12345678)

	dex035, err035 := ParseDEX(ctx, "classes.dex", valid035, limits)
	if err035 != nil {
		t.Fatalf("ParseDEX failed on valid 035 header: %v", err035)
	}
	if dex035 == nil || dex035.Version != "035" {
		t.Errorf("unexpected DEXFile version: %#v", dex035)
	}
}
