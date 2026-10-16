package crawler

import (
	"strings"
	"testing"
)

func TestValidateTargetURL(t *testing.T) {
	tests := []struct {
		name        string
		rawURL      string
		expectError bool
		errContains string
	}{
		{
			name:        "Valid HTTP target",
			rawURL:      "http://example.com",
			expectError: false,
		},
		{
			name:        "Valid HTTPS target with port and path",
			rawURL:      "https://target.local:8443/app/dashboard",
			expectError: false,
		},
		{
			name:        "Empty target",
			rawURL:      "",
			expectError: true,
			errContains: "empty",
		},
		{
			name:        "Whitespace-only target",
			rawURL:      "   \t\n  ",
			expectError: true,
			errContains: "empty",
		},
		{
			name:        "File scheme rejected",
			rawURL:      "file:///etc/passwd",
			expectError: true,
			errContains: "unsupported URL scheme",
		},
		{
			name:        "FTP scheme rejected",
			rawURL:      "ftp://ftp.example.com/pub",
			expectError: true,
			errContains: "unsupported URL scheme",
		},
		{
			name:        "JavaScript pseudo-scheme rejected",
			rawURL:      "javascript:alert(1)",
			expectError: true,
			errContains: "unsupported URL scheme",
		},
		{
			name:        "Embedded credentials rejected (user:pass)",
			rawURL:      "http://admin:secret123@target.internal/api",
			expectError: true,
			errContains: "embedded credentials",
		},
		{
			name:        "Embedded credentials rejected (user only)",
			rawURL:      "https://root@target.org",
			expectError: true,
			errContains: "embedded credentials",
		},
		{
			name:        "Missing hostname",
			rawURL:      "http:///api/v1",
			expectError: true,
			errContains: "valid hostname",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			parsed, err := ValidateTargetURL(tc.rawURL)
			if tc.expectError {
				if err == nil {
					t.Fatalf("expected error containing %q, got nil", tc.errContains)
				}
				if tc.errContains != "" && !strings.Contains(err.Error(), tc.errContains) {
					t.Errorf("expected error to contain %q, got %v", tc.errContains, err)
				}
			} else {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				if parsed == nil {
					t.Fatalf("expected parsed URL, got nil")
				}
			}
		})
	}
}

func TestNormalizeTargetURL(t *testing.T) {
	tests := []struct {
		name       string
		rawURL     string
		expected   string
		shouldFail bool
	}{
		{
			name:     "Strip default HTTP port 80",
			rawURL:   "http://Example.com:80/",
			expected: "http://example.com",
		},
		{
			name:     "Strip default HTTPS port 443",
			rawURL:   "HTTPS://TARGET.ORG:443/app/",
			expected: "https://target.org/app",
		},
		{
			name:     "Retain non-default port",
			rawURL:   "http://service.local:8080/api",
			expected: "http://service.local:8080/api",
		},
		{
			name:     "Retain non-default HTTPS port",
			rawURL:   "https://secure.local:8443/console",
			expected: "https://secure.local:8443/console",
		},
		{
			name:     "Retain query parameters",
			rawURL:   "https://example.com/search?q=test&page=1",
			expected: "https://example.com/search?q=test&page=1",
		},
		{
			name:       "Fail on invalid target",
			rawURL:     "ftp://invalid.com",
			shouldFail: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			normalized, err := NormalizeTargetURL(tc.rawURL)
			if tc.shouldFail {
				if err == nil {
					t.Fatalf("expected normalization error, got %q", normalized)
				}
			} else {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				if normalized != tc.expected {
					t.Errorf("expected normalized %q, got %q", tc.expected, normalized)
				}
			}
		})
	}
}

func TestNewScope(t *testing.T) {
	// Rejects invalid target
	_, err := NewScope("not-a-valid-url", ScopeSameOrigin)
	if err == nil {
		t.Fatal("expected NewScope to fail on invalid target")
	}

	// Rejects embedded credentials
	_, err = NewScope("http://admin:pass@example.com", ScopeSameOrigin)
	if err == nil {
		t.Fatal("expected NewScope to fail on target with embedded credentials")
	}

	// Defaults empty ScopeMode to ScopeSameOrigin
	s, err := NewScope("https://example.com", "", "api.example.com", "CDN.EXAMPLE.COM")
	if err != nil {
		t.Fatalf("unexpected error creating scope: %v", err)
	}
	if s.Mode != ScopeSameOrigin {
		t.Errorf("expected default mode %s, got %s", ScopeSameOrigin, s.Mode)
	}

	// Target host automatically in allowedHosts
	if _, ok := s.allowedHosts["example.com"]; !ok {
		t.Error("expected example.com to be in allowedHosts")
	}
	// Case-normalized extra allowed hosts
	if _, ok := s.allowedHosts["cdn.example.com"]; !ok {
		t.Error("expected cdn.example.com to be in allowedHosts")
	}
}

func TestScope_IsAllowed_Modes(t *testing.T) {
	t.Run("ScopeSameOrigin", func(t *testing.T) {
		s, err := NewScope("https://example.com:8443", ScopeSameOrigin)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if !s.IsAllowed("https://example.com:8443/page") {
			t.Error("expected same origin to be allowed")
		}
		if !s.IsAllowed("/relative/path") {
			t.Error("expected relative path to be allowed")
		}
		// Different port -> rejected
		if s.IsAllowed("https://example.com:9443/page") {
			t.Error("expected different port to be rejected in same-origin mode")
		}
		// Different scheme -> rejected
		if s.IsAllowed("http://example.com:8443/page") {
			t.Error("expected different scheme to be rejected in same-origin mode")
		}
		// Different host -> rejected
		if s.IsAllowed("https://sub.example.com:8443/page") {
			t.Error("expected subdomain to be rejected in same-origin mode")
		}
	})

	t.Run("ScopeSubdomains", func(t *testing.T) {
		s, err := NewScope("https://example.com", ScopeSubdomains)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if !s.IsAllowed("https://example.com/path") {
			t.Error("expected apex domain to be allowed")
		}
		if !s.IsAllowed("https://sub.example.com/api") {
			t.Error("expected direct subdomain to be allowed")
		}
		if !s.IsAllowed("https://deep.nested.sub.example.com/test") {
			t.Error("expected deep subdomain to be allowed")
		}
		if s.IsAllowed("https://notexample.com") {
			t.Error("expected sibling domain to be rejected")
		}
		if s.IsAllowed("https://fakeexample.com") {
			t.Error("expected deceptive suffix to be rejected")
		}
	})

	t.Run("ScopeExplicit", func(t *testing.T) {
		s, err := NewScope("https://example.com", ScopeExplicit, "api.example.com", "cdn.example.org")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if !s.IsAllowed("https://example.com/home") {
			t.Error("expected target domain to be allowed")
		}
		if !s.IsAllowed("https://api.example.com/v1") {
			t.Error("expected declared explicit host to be allowed")
		}
		if !s.IsAllowed("https://cdn.example.org/bundle.js") {
			t.Error("expected declared explicit host to be allowed")
		}
		if s.IsAllowed("https://unknown.example.com") {
			t.Error("expected unlisted host to be rejected in explicit mode")
		}
	})

	t.Run("SchemeValidation", func(t *testing.T) {
		s, err := NewScope("https://example.com", ScopeSubdomains)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		dangerousSchemes := []string{
			"javascript:alert(1)",
			"data:text/html,<script>alert(1)</script>",
			"file:///etc/hosts",
			"mailto:security@example.com",
			"gopher://evil.com",
		}
		for _, ds := range dangerousSchemes {
			if s.IsAllowed(ds) {
				t.Errorf("expected scheme %q to be rejected by IsAllowed", ds)
			}
		}
	})
}

func TestScope_Exclusions(t *testing.T) {
	s, err := NewScope("https://example.com", ScopeSubdomains, "api.example.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Add host exclusions
	s.ExcludeHost("billing.example.com")
	s.ExcludeHost("*.internal.example.com")

	// Add path prefix exclusions
	s.ExcludePathPrefix("/admin")
	s.ExcludePathPrefix("/api/v1/auth/logout")

	// 1. Normal allowed URL
	if !s.IsAllowed("https://example.com/home") {
		t.Error("expected standard URL to be allowed")
	}

	// 2. Exact excluded host
	if excluded, reason := s.IsExcluded("https://billing.example.com/checkout"); !excluded {
		t.Error("expected billing.example.com to be excluded")
	} else if !strings.Contains(reason, "excluded by scope rule") {
		t.Errorf("unexpected exclusion reason: %s", reason)
	}
	if s.IsAllowed("https://billing.example.com/checkout") {
		t.Error("expected IsAllowed to be false for excluded host")
	}

	// 3. Wildcard excluded host
	if excluded, reason := s.IsExcluded("https://db.internal.example.com/metrics"); !excluded {
		t.Error("expected wildcard internal host to be excluded")
	} else if !strings.Contains(reason, "wildcard exclusion") {
		t.Errorf("unexpected exclusion reason: %s", reason)
	}
	if s.IsAllowed("https://db.internal.example.com/metrics") {
		t.Error("expected IsAllowed to be false for wildcard excluded host")
	}

	// 4. Excluded path prefix
	if excluded, reason := s.IsExcluded("https://example.com/admin/settings"); !excluded {
		t.Error("expected /admin path to be excluded")
	} else if !strings.Contains(reason, "matches excluded prefix") {
		t.Errorf("unexpected exclusion reason: %s", reason)
	}
	if s.IsAllowed("https://example.com/admin/settings") {
		t.Error("expected IsAllowed to be false for excluded path prefix")
	}

	// 5. Another excluded path prefix
	if s.IsAllowed("https://example.com/api/v1/auth/logout") {
		t.Error("expected logout endpoint to be excluded")
	}
}

func TestEffectivePort(t *testing.T) {
	tests := []struct {
		urlStr       string
		expectedPort string
	}{
		{"http://example.com", ""},
		{"http://example.com:80", ""},
		{"https://example.com", ""},
		{"https://example.com:443", ""},
		{"http://example.com:8080", "8080"},
		{"https://example.com:8443", "8443"},
		{"http://[2001:db8::1]:80", ""},
		{"http://[2001:db8::1]:8080", "8080"},
	}

	for _, tc := range tests {
		u, err := ValidateTargetURL(tc.urlStr)
		if err != nil {
			t.Fatalf("unexpected validation error for %s: %v", tc.urlStr, err)
		}
		got := EffectivePort(u)
		if got != tc.expectedPort {
			t.Errorf("EffectivePort(%s) = %q; want %q", tc.urlStr, got, tc.expectedPort)
		}
	}
}

func TestScope_SameOrigin_DefaultPorts(t *testing.T) {
	// Target without port should match candidate with default port 80
	s1, err := NewScope("http://example.com", ScopeSameOrigin)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !s1.IsAllowed("http://example.com:80/app.js") {
		t.Error("expected http://example.com:80/app.js to match http://example.com in same-origin mode")
	}

	// Target with default port 443 should match candidate without port
	s2, err := NewScope("https://example.com:443", ScopeSameOrigin)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !s2.IsAllowed("https://example.com/main.js") {
		t.Error("expected https://example.com/main.js to match https://example.com:443 in same-origin mode")
	}

	// Different port must still be rejected
	if s2.IsAllowed("https://example.com:8443/main.js") {
		t.Error("expected non-default port 8443 to be rejected for target on port 443")
	}
}

func TestScope_PathPrefix_BoundaryMatching(t *testing.T) {
	s, err := NewScope("https://example.com", ScopeSameOrigin)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	s.ExcludePathPrefix("/admin")

	excludedCases := []string{
		"https://example.com/admin",
		"https://example.com/admin/",
		"https://example.com/admin/users",
		"https://example.com/admin?tab=security",
	}
	for _, u := range excludedCases {
		if excluded, reason := s.IsExcluded(u); !excluded {
			t.Errorf("expected %s to be excluded, reason: %s", u, reason)
		}
		if s.IsAllowed(u) {
			t.Errorf("expected IsAllowed(%s) to be false", u)
		}
	}

	// Boundary integrity: /administrator or /admin-tools must NOT be excluded by prefix /admin
	allowedCases := []string{
		"https://example.com/administrator",
		"https://example.com/administrator/login",
		"https://example.com/admin-tools",
	}
	for _, u := range allowedCases {
		if excluded, reason := s.IsExcluded(u); excluded {
			t.Errorf("expected %s NOT to be excluded, but was excluded: %s", u, reason)
		}
		if !s.IsAllowed(u) {
			t.Errorf("expected IsAllowed(%s) to be true", u)
		}
	}
}

func TestScope_EmbeddedCredentialsRejection(t *testing.T) {
	s, err := NewScope("https://example.com", ScopeSameOrigin)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	credURLs := []string{
		"https://user:password@example.com/api",
		"https://admin@example.com/dashboard",
		"https://:secret@example.com/key",
	}
	for _, u := range credURLs {
		if s.IsAllowed(u) {
			t.Errorf("expected candidate URL with embedded credentials %q to be rejected by IsAllowed", u)
		}
	}
}

func TestNormalizeTargetURL_IPv6(t *testing.T) {
	tests := []struct {
		name     string
		rawURL   string
		expected string
	}{
		{
			name:     "IPv6 literal with default HTTP port",
			rawURL:   "http://[2001:db8::1]:80/test",
			expected: "http://[2001:db8::1]/test",
		},
		{
			name:     "IPv6 literal with custom port",
			rawURL:   "http://[2001:db8::1]:8080/test/",
			expected: "http://[2001:db8::1]:8080/test",
		},
		{
			name:     "IPv6 literal without port",
			rawURL:   "https://[2001:db8::2]/app",
			expected: "https://[2001:db8::2]/app",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			normalized, err := NormalizeTargetURL(tc.rawURL)
			if err != nil {
				t.Fatalf("unexpected normalization error: %v", err)
			}
			if normalized != tc.expected {
				t.Errorf("NormalizeTargetURL(%s) = %q; want %q", tc.rawURL, normalized, tc.expected)
			}
		})
	}
}

func TestScope_IsPathInScope(t *testing.T) {
	// Subpath target
	sSubpath, err := NewScope("https://example.com/hithaone", ScopeSameOrigin)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	validSubpathCases := []string{
		"/hithaone",
		"/hithaone/",
		"/hithaone/dashboard",
		"/hithaone/api/v1/users",
		"/hithaone?query=1",
		"https://example.com/hithaone",
		"https://example.com/hithaone/",
		"https://example.com/hithaone/reports",
	}
	for _, u := range validSubpathCases {
		if !sSubpath.IsPathInScope(u) {
			t.Errorf("expected %q to be in path scope for /hithaone target", u)
		}
	}

	invalidSubpathCases := []string{
		"/hithaone-admin",
		"/hithaone_evil",
		"/hithaone-settings",
		"/admin",
		"/.env",
		"/api/v1/users",
		"https://example.com/hithaone-admin",
		"https://example.com/dashboard",
		"https://attacker.com/hithaone/dashboard",
		"/hithaone/../admin",
		"/hithaone/..",
		"/hithaone/%2e%2e/admin",
		"/hithaone/%2E%2E/admin",
		"/hithaone/%252e%252e/admin",
		"/hithaone/%252E%252E/admin",
		"/hithaone/%25252e%25252e/admin",
		"/hithaone/%2525252e%2525252e/admin",
		"/hithaone/../hithaone/admin",
		"/hithaone/app/../../hithaone/admin",
		"/hithaone/%",
		"/hithaone/%2",
		"/hithaone/%zz/admin",
		"/hithaone/%2e%2e%/admin",
		"/hithaone/%00/admin",
		"/hithaone/\x00/admin",
		"/hithaone/%2500/admin",
		"/hithaone/\x01/admin",
		"/hithaone/\x1f/admin",
		"/hithaone/%252f%252e%252e%252fadmin",
		"/hithaone/%255c%252e%252e%255cadmin",
		"/hithaone\\..\\admin",
		"/hithaone\\admin",
		"/hithaone%5c%2e%2e%5cadmin",
		"/hithaone%2dadmin",
		"https://example.com/hithaone/../admin",
		"https://example.com/hithaone/%2e%2e/admin",
		"https://example.com/hithaone/%252e%252e/admin",
		"https://example.com/hithaone/%25252e%25252e/admin",
		"https://example.com/hithaone/../hithaone/admin",
		"https://example.com/hithaone\\..\\admin",
	}
	for _, u := range invalidSubpathCases {
		if sSubpath.IsPathInScope(u) {
			t.Errorf("expected %q to be OUT of path scope for /hithaone target", u)
		}
	}

	validNormalizedCases := []string{
		"/hithaone/./admin",
		"/hithaone/sub/../admin",
		"/hithaone/%2fadmin",
	}
	for _, u := range validNormalizedCases {
		if !sSubpath.IsPathInScope(u) {
			t.Errorf("expected %q to be IN path scope for /hithaone target", u)
		}
	}

	// Nested subpath target
	sNested, err := NewScope("https://example.com/app/v1", ScopeSameOrigin)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	validNestedCases := []string{
		"/app/v1",
		"/app/v1/",
		"/app/v1/users",
		"https://example.com/app/v1/dashboard",
	}
	for _, u := range validNestedCases {
		if !sNested.IsPathInScope(u) {
			t.Errorf("expected %q to be IN path scope for /app/v1 target", u)
		}
	}

	invalidNestedCases := []string{
		"/app/v1-admin",
		"/app/v2",
		"/app",
		"/app/v1/../v2",
		"/app/v1/%2e%2e/v2",
		"/app/v1/%252e%252e/v2",
		"/app/v1\\..\\v2",
	}
	for _, u := range invalidNestedCases {
		if sNested.IsPathInScope(u) {
			t.Errorf("expected %q to be OUT of path scope for /app/v1 target", u)
		}
	}

	// Root target
	sRoot, err := NewScope("https://example.com", ScopeSameOrigin)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	rootCases := []string{
		"/",
		"/admin",
		"/hithaone",
		"/api/v1/users",
		"https://example.com/reports",
	}
	for _, u := range rootCases {
		if !sRoot.IsPathInScope(u) {
			t.Errorf("expected %q to be in path scope for root target", u)
		}
	}

	if sRoot.IsPathInScope("https://attacker.com/reports") {
		t.Errorf("expected attacker.com to be OUT of path scope for root target")
	}
}
