package crawler

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestReachability_SanitizeURLString(t *testing.T) {
	canaryPass := "FELIX_REACH_PASS_CANARY_01"
	canaryToken := "FELIX_REACH_TOKEN_CANARY_02"

	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "UserPassInURL",
			input:    "https://admin:" + canaryPass + "@corp.internal/dashboard",
			expected: "https://admin:[REDACTED]@corp.internal/dashboard",
		},
		{
			name:     "UserOnlyTokenInURL",
			input:    "https://" + canaryToken + "@corp.internal/v1/api",
			expected: "https://[REDACTED]@corp.internal/v1/api",
		},
		{
			name:     "SensitiveQueryParams",
			input:    "https://api.example.com/data?token=" + canaryToken + "&page=2&secret=" + canaryPass,
			expected: "https://api.example.com/data?page=2&secret=[REDACTED]&token=[REDACTED]",
		},
		{
			name:     "SafeQueryParamsPreserved",
			input:    "https://example.com/search?q=test&page=1&sort=asc",
			expected: "https://example.com/search?q=test&page=1&sort=asc",
		},
		{
			name:     "MalformedURLWithCredentials",
			input:    "https://admin:" + canaryPass + "@bad url:8080/path?token=" + canaryToken,
			expected: "https://admin:[REDACTED]@bad url:8080/path?token=[REDACTED]",
		},
		{
			name:     "EmptyInput",
			input:    "",
			expected: "",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			out := SanitizeURLString(tc.input)
			if strings.Contains(out, canaryPass) || strings.Contains(out, canaryToken) {
				t.Fatalf("[%s] LEAK: output contains sensitive canary: %s", tc.name, out)
			}
			if out != tc.expected {
				t.Errorf("[%s] Expected %q, got %q", tc.name, tc.expected, out)
			}
		})
	}
}

func TestReachability_SanitizeErrorString(t *testing.T) {
	canaryPass := "FELIX_REACH_PASS_CANARY_03"
	canaryToken := "FELIX_REACH_TOKEN_CANARY_04"

	// 1. URL credentials in error
	errWithURL := fmt.Errorf("dial tcp: failed to connect to https://admin:%s@10.0.0.1:8443?token=%s: connection refused", canaryPass, canaryToken)
	sanitizedErr := SanitizeErrorString(errWithURL)
	if strings.Contains(sanitizedErr, canaryPass) || strings.Contains(sanitizedErr, canaryToken) {
		t.Fatalf("LEAK: SanitizeErrorString leaked canary: %s", sanitizedErr)
	}
	if !strings.Contains(sanitizedErr, "admin:[REDACTED]@") || !strings.Contains(sanitizedErr, "token=[REDACTED]") {
		t.Errorf("SanitizeErrorString did not redact credentials: %s", sanitizedErr)
	}

	// 2. Bearer token in error
	errWithBearer := fmt.Errorf("http request failed: 401 Unauthorized with header Authorization: Bearer %s", canaryToken)
	sanitizedBearer := SanitizeErrorString(errWithBearer)
	if strings.Contains(sanitizedBearer, canaryToken) {
		t.Fatalf("LEAK: SanitizeErrorString leaked bearer token: %s", sanitizedBearer)
	}
	if !strings.Contains(sanitizedBearer, "Bearer [REDACTED]") {
		t.Errorf("expected Bearer [REDACTED], got: %s", sanitizedBearer)
	}

	// 3. Length bounding (>256 characters)
	longMsg := "network timeout while communicating with target server: " + strings.Repeat("detail_", 50) + " ending"
	errLong := errors.New(longMsg)
	sanitizedLong := SanitizeErrorString(errLong)
	if len([]rune(sanitizedLong)) > 256 {
		t.Errorf("SanitizeErrorString exceeded 256 rune bound: got %d", len([]rune(sanitizedLong)))
	}
	if !strings.HasSuffix(sanitizedLong, "...") {
		t.Errorf("expected ellipsis suffix on truncated error: %s", sanitizedLong)
	}

	// 4. Nil error
	if out := SanitizeErrorString(nil); out != "" {
		t.Errorf("expected empty string for nil error, got %q", out)
	}
}

func TestReachability_ClassifyNetworkError_Sanitization(t *testing.T) {
	canaryPass := "FELIX_REACH_PASS_CANARY_05"
	targetURL := "https://admin:" + canaryPass + "@target.internal/api"

	diag := ClassifyNetworkError(errors.New("i/o timeout"), targetURL)
	if diag == nil {
		t.Fatalf("expected diagnostic, got nil")
	}
	if strings.Contains(diag.SafeSummary, canaryPass) {
		t.Fatalf("LEAK: ClassifyNetworkError leaked canary in SafeSummary: %s", diag.SafeSummary)
	}
	if !strings.Contains(diag.SafeSummary, "admin:[REDACTED]@target.internal/api") {
		t.Errorf("expected redacted target in SafeSummary, got: %s", diag.SafeSummary)
	}
}
