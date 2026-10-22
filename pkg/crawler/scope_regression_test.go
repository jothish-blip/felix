package crawler

import (
	"strings"
	"testing"
)

// TestValidateTargetURL_RegressionFixtures tests boundary and security validation on raw target strings.
func TestValidateTargetURL_RegressionFixtures(t *testing.T) {
	tests := []struct {
		name        string
		raw         string
		wantErr     bool
		errContains string
	}{
		// Valid targets
		{"valid standard http", "http://example.com", false, ""},
		{"valid standard https", "https://example.com/", false, ""},
		{"valid with port and path", "https://sub.domain.co.uk:8443/api/v1", false, ""},
		{"valid IPv4 host", "http://192.168.1.1:8080", false, ""},
		{"valid bracketed IPv6", "https://[2001:db8::1]:8443/status", false, ""},
		{"valid bracketed IPv6 loopback", "http://[::1]:8080", false, ""},

		// Prohibited schemes
		{"javascript scheme rejected", "javascript:alert(1)", true, "only http and https are permitted"},
		{"file scheme rejected", "file:///etc/passwd", true, "only http and https are permitted"},
		{"data scheme rejected", "data:text/html,<script>alert(1)</script>", true, "only http and https are permitted"},
		{"ftp scheme rejected", "ftp://ftp.example.com", true, "only http and https are permitted"},
		{"missing scheme rejected", "example.com", true, "only http and https are permitted"},
		{"schemeless double-slash rejected", "//example.com", true, "only http and https are permitted"},

		// Embedded credentials (defense against credential leakage and parser confusion)
		{"user and pass embedded", "http://admin:secret123@example.com", true, "embedded credentials in target URL are prohibited"},
		{"user only embedded", "http://admin:@example.com", true, "embedded credentials in target URL are prohibited"},
		{"pass only embedded", "http://:secret@example.com", true, "embedded credentials in target URL are prohibited"},

		// Malformed hostnames and syntax
		{"empty string", "", true, "target URL cannot be empty"},
		{"whitespace string", "   ", true, "target URL cannot be empty"},
		{"spaces in hostname", "http://host with spaces.com", true, "invalid character"},
		{"missing host", "http:///no-host", true, "target URL must contain a valid hostname"},
		{"unbracketed IPv6", "http://2001:db8::1:8080", true, "invalid URL syntax"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ValidateTargetURL(tt.raw)
			if (err != nil) != tt.wantErr {
				t.Fatalf("ValidateTargetURL(%q) error = %v, wantErr %v", tt.raw, err, tt.wantErr)
			}
			if tt.wantErr && tt.errContains != "" {
				if !strings.Contains(err.Error(), tt.errContains) {
					t.Errorf("error %q does not contain %q", err.Error(), tt.errContains)
				}
			}
		})
	}
}

// TestNormalizeTargetURL_RegressionFixtures tests canonicalization, port stripping, and idempotency.
func TestNormalizeTargetURL_RegressionFixtures(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "http default port 80 stripped",
			input:    "http://example.com:80/index.html",
			expected: "http://example.com/index.html",
		},
		{
			name:     "https default port 443 stripped",
			input:    "https://example.com:443/login",
			expected: "https://example.com/login",
		},
		{
			name:     "non-default port preserved",
			input:    "https://example.com:8443/api",
			expected: "https://example.com:8443/api",
		},
		{
			name:     "root trailing slash normalized",
			input:    "https://example.com/",
			expected: "https://example.com",
		},
		{
			name:     "subpath trailing slash normalized",
			input:    "https://example.com/api/v1/",
			expected: "https://example.com/api/v1",
		},
		{
			name:     "query string preserved",
			input:    "https://example.com/search?q=test&lang=en",
			expected: "https://example.com/search?q=test&lang=en",
		},
		{
			name:     "uppercase scheme and host lowercased",
			input:    "HTTPS://EXAMPLE.COM/PATH",
			expected: "https://example.com/PATH",
		},
		{
			name:     "bracketed IPv6 normalized",
			input:    "http://[2001:db8::1]:80/status",
			expected: "http://[2001:db8::1]/status",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			norm, err := NormalizeTargetURL(tt.input)
			if err != nil {
				t.Fatalf("NormalizeTargetURL(%q) failed: %v", tt.input, err)
			}
			if norm != tt.expected {
				t.Errorf("NormalizeTargetURL(%q) = %q, want %q", tt.input, norm, tt.expected)
			}

			// Idempotency check: Normalize(Normalize(u)) must strictly equal Normalize(u)
			norm2, err2 := NormalizeTargetURL(norm)
			if err2 != nil {
				t.Fatalf("idempotency failed on second pass for %q: %v", norm, err2)
			}
			if norm2 != norm {
				t.Errorf("NormalizeTargetURL is not idempotent: first=%q, second=%q", norm, norm2)
			}
		})
	}
}

// TestScope_PathContainment_RegressionFixtures tests defense against traversal, URL-encoding bypasses,
// boundary confusion, and cross-host escapes.
func TestScope_PathContainment_RegressionFixtures(t *testing.T) {
	scope, err := NewScope("https://example.com/app/v1", ScopeSameOrigin)
	if err != nil {
		t.Fatalf("NewScope failed: %v", err)
	}

	tests := []struct {
		name      string
		candidate string
		wantIn    bool
	}{
		// Valid in-scope paths
		{"exact subpath", "/app/v1", true},
		{"subpath with trailing slash", "/app/v1/", true},
		{"nested child route", "/app/v1/users", true},
		{"deeply nested child route", "/app/v1/users/42/details", true},
		{"in-scope absolute URL", "https://example.com/app/v1/profile", true},

		// Boundary confusion attacks (critical prefix mismatch)
		{"similar prefix dash", "/app/v1-admin", false},
		{"similar prefix underscore", "/app/v1_evil", false},
		{"similar prefix suffix", "/app/v10", false},

		// Path traversal attacks (dot-dot escapes)
		{"dot-dot escape to parent", "/app/v1/../v2", false},
		{"dot-dot escape to root admin", "/app/v1/../../admin", false},
		{"dot-dot escape to etc passwd", "/app/v1/../../../etc/passwd", false},
		{"backslash traversal", "/app/v1\\..\\admin", false},

		// URL-encoded traversal attacks
		{"encoded dot-dot %2e%2e", "/app/v1/%2e%2e/admin", false},
		{"double encoded traversal", "/app/v1/%252e%252e/admin", false},
		{"encoded slash %2f", "/app/v1%2f..%2fadmin", false},

		// Hostile control characters and null bytes
		{"null byte in path", "/app/v1\x00/admin", false},
		{"encoded null byte %00", "/app/v1%00/bypass", false},

		// Cross-host absolute URLs
		{"different host", "https://evil.com/app/v1/users", false},
		{"subdomain host under same-origin", "https://sub.example.com/app/v1/users", false},
		{"scheme downgrade to http", "http://example.com/app/v1/users", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := scope.IsPathInScope(tt.candidate)
			if got != tt.wantIn {
				t.Errorf("IsPathInScope(%q) = %v, want %v", tt.candidate, got, tt.wantIn)
			}
		})
	}
}
