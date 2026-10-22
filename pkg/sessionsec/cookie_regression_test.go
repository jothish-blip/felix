package sessionsec

import (
	"net/http"
	"strings"
	"testing"
)

// TestSplitSetCookieHeader_P11_1_DefectRegression verifies the concrete defect unmasked by P11.1 fuzzing:
// A header with leading commas (e.g. ",0=" or ",a=b") or consecutive commas (",,,") must not append
// empty string elements to the returned slice.
func TestSplitSetCookieHeader_P11_1_DefectRegression(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected []string
	}{
		{
			name:     "P11.1 fuzz failure corpus: leading comma with 0=",
			input:    ",0=",
			expected: []string{"0="},
		},
		{
			name:     "leading comma before valid cookie",
			input:    ",session_id=abc123",
			expected: []string{"session_id=abc123"},
		},
		{
			name:     "multiple leading commas",
			input:    ",,,token=xyz456",
			expected: []string{"token=xyz456"},
		},
		{
			name:     "consecutive commas between cookies",
			input:    "sess=123,,,pref=dark",
			expected: []string{"sess=123", "pref=dark"},
		},
		{
			name:     "trailing commas",
			input:    "sess=123,,",
			expected: []string{"sess=123"},
		},
		{
			name:     "only commas and whitespace",
			input:    " , , , ",
			expected: nil,
		},
		{
			name:     "empty header string",
			input:    "",
			expected: nil,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := SplitSetCookieHeader(tc.input)

			if len(result) != len(tc.expected) {
				t.Fatalf("SplitSetCookieHeader(%q) length mismatch: got %d (%#v), want %d (%#v)",
					tc.input, len(result), result, len(tc.expected), tc.expected)
			}

			for i := range result {
				if result[i] != tc.expected[i] {
					t.Errorf("[%d] got %q, want %q", i, result[i], tc.expected[i])
				}
				if strings.TrimSpace(result[i]) == "" {
					t.Errorf("[%d] result element is unexpectedly empty or whitespace", i)
				}
			}
		})
	}
}

// TestSplitSetCookieHeader_ComplexDelimitersAndExpires verifies that RFC-compliant
// Expires dates containing commas are not incorrectly split.
func TestSplitSetCookieHeader_ComplexDelimitersAndExpires(t *testing.T) {
	header := "session=abc; Expires=Wed, 21 Oct 2026 07:28:00 GMT; Path=/, theme=dark; Path=/; Secure, lang=en; Max-Age=3600"
	cookies := SplitSetCookieHeader(header)

	if len(cookies) != 3 {
		t.Fatalf("expected 3 cookies split, got %d: %#v", len(cookies), cookies)
	}

	if !strings.HasPrefix(cookies[0], "session=abc;") || !strings.Contains(cookies[0], "Expires=Wed, 21 Oct 2026") {
		t.Errorf("cookie 0 malformed or incorrectly split on date comma: %s", cookies[0])
	}
	if cookies[1] != "theme=dark; Path=/; Secure" {
		t.Errorf("cookie 1 incorrect: %s", cookies[1])
	}
	if cookies[2] != "lang=en; Max-Age=3600" {
		t.Errorf("cookie 2 incorrect: %s", cookies[2])
	}
}

// TestParseSetCookie_ComprehensiveAttributes verifies parsing of all standard and modern security attributes.
func TestParseSetCookie_ComprehensiveAttributes(t *testing.T) {
	tests := []struct {
		name            string
		raw             string
		wantName        string
		wantValue       string
		wantSecure      bool
		wantHttpOnly    bool
		wantSameSite    http.SameSite
		wantPartitioned bool
		wantMaxAge      int
		wantType        CookieType
	}{
		{
			name:            "fully hardened session cookie",
			raw:             "__Host-sess=supersecret123; Path=/; Secure; HttpOnly; SameSite=Strict; Partitioned; Max-Age=1800",
			wantName:        "__Host-sess",
			wantValue:       "supersecret123",
			wantSecure:      true,
			wantHttpOnly:    true,
			wantSameSite:    http.SameSiteStrictMode,
			wantPartitioned: true,
			wantMaxAge:      1800,
			wantType:        CookieTypeSession,
		},
		{
			name:            "lax csrf token cookie",
			raw:             "csrf_token=csrf_val_abc; Path=/; Secure; SameSite=Lax",
			wantName:        "csrf_token",
			wantValue:       "csrf_val_abc",
			wantSecure:      true,
			wantHttpOnly:    false,
			wantSameSite:    http.SameSiteLaxMode,
			wantPartitioned: false,
			wantMaxAge:      0,
			wantType:        CookieTypeCSRF,
		},
		{
			name:            "samesite none requiring secure",
			raw:             "third_party_id=xyz; SameSite=None; Secure",
			wantName:        "third_party_id",
			wantValue:       "xyz",
			wantSecure:      true,
			wantHttpOnly:    false,
			wantSameSite:    http.SameSiteNoneMode,
			wantPartitioned: false,
			wantMaxAge:      0,
			wantType:        CookieTypeUnknown,
		},
		{
			name:            "analytics cookie with domain and negative max-age (deletion)",
			raw:             "_ga=GA1.2.123456; Domain=.example.com; Path=/; Max-Age=-1",
			wantName:        "_ga",
			wantValue:       "GA1.2.123456",
			wantSecure:      false,
			wantHttpOnly:    false,
			wantSameSite:    0,
			wantPartitioned: false,
			wantMaxAge:      -1,
			wantType:        CookieTypeAnalytics,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, err := ParseSetCookie(tt.raw)
			if err != nil {
				t.Fatalf("ParseSetCookie(%q) failed: %v", tt.raw, err)
			}
			if c.Name != tt.wantName {
				t.Errorf("Name = %q, want %q", c.Name, tt.wantName)
			}
			if c.Value != tt.wantValue {
				t.Errorf("Value = %q, want %q", c.Value, tt.wantValue)
			}
			if c.Secure != tt.wantSecure {
				t.Errorf("Secure = %v, want %v", c.Secure, tt.wantSecure)
			}
			if c.HttpOnly != tt.wantHttpOnly {
				t.Errorf("HttpOnly = %v, want %v", c.HttpOnly, tt.wantHttpOnly)
			}
			if c.SameSite != tt.wantSameSite {
				t.Errorf("SameSite = %v, want %v", c.SameSite, tt.wantSameSite)
			}
			if c.Partitioned != tt.wantPartitioned {
				t.Errorf("Partitioned = %v, want %v", c.Partitioned, tt.wantPartitioned)
			}
			if c.MaxAge != tt.wantMaxAge {
				t.Errorf("MaxAge = %d, want %d", c.MaxAge, tt.wantMaxAge)
			}
			if cType := ClassifyCookie(c.Name); cType != tt.wantType {
				t.Errorf("ClassifyCookie(%q) = %q, want %q", c.Name, cType, tt.wantType)
			}
		})
	}
}

// TestParseSetCookie_NegativeAndMalformedInputs verifies error handling on invalid or hostile cookie headers.
func TestParseSetCookie_NegativeAndMalformedInputs(t *testing.T) {
	malformed := []string{
		"",
		"   ",
		"; ; ;",
		"=",
		"=only_value_without_name",
		"only_name_without_equal",
	}

	for _, raw := range malformed {
		t.Run("malformed: "+raw, func(t *testing.T) {
			c, err := ParseSetCookie(raw)
			if err == nil {
				t.Errorf("ParseSetCookie(%q) succeeded unexpectedly, returned: %#v", raw, c)
			}
		})
	}
}
