package crawler

import (
	"net/url"
	"strings"
	"testing"
)

func FuzzNormalizeTargetURL(f *testing.F) {
	// Seed corpus: valid URLs
	f.Add("https://example.com")
	f.Add("http://example.com")
	f.Add("https://example.com/")
	f.Add("http://example.com:8080/api/v1?query=test#frag")
	f.Add("https://sub.domain.example.co.uk:443/path/to/resource")
	f.Add("http://127.0.0.1:80/index.html")
	f.Add("http://[::1]:8080/test")
	f.Add("https://[2001:db8::1]/service")
	f.Add("https://example.com/a/b/../c/./d")

	// Seed corpus: boundary, hostile and malformed inputs
	f.Add("")
	f.Add("   ")
	f.Add("http://")
	f.Add("https://")
	f.Add("://missing-scheme")
	f.Add("//schemeless.example.com")
	f.Add("javascript:alert(1)")
	f.Add("data:text/html,<script>alert(1)</script>")
	f.Add("file:///etc/passwd")
	f.Add("ftp://ftp.example.com/pub")
	f.Add("http://user:pass@example.com/protected")
	f.Add("http://admin:@example.com")
	f.Add("http://:pass@example.com")
	f.Add("http://host with spaces.com")
	f.Add("http://example.com:notaport")
	f.Add("http://example.com:99999999")
	f.Add("http://example.com:-80")
	f.Add("http:///no-host")
	f.Add("http://example.com/%00/nullbyte")
	f.Add("http://[invalid-ipv6")
	f.Add("http://example.com:80/default-port")
	f.Add("https://example.com:443/default-tls-port")
	f.Add(strings.Repeat("https://example.com/", 50))
	f.Add("https://\x00\x01\x02evil.com")
	f.Add("https://xn--e1afmkfd.xn--p1ai") // IDN punycode

	f.Fuzz(func(t *testing.T, raw string) {
		norm, err := NormalizeTargetURL(raw)
		if err != nil {
			// Expected outcome for malformed, non-http, credentialed, or hostile URLs
			return
		}

		// Invariant 1: Normalized target must not be empty
		if strings.TrimSpace(norm) == "" {
			t.Fatalf("invariant violation: successful normalization returned empty string for input %q", raw)
		}

		// Invariant 2: Scheme must be lowercase http or https
		if !strings.HasPrefix(norm, "http://") && !strings.HasPrefix(norm, "https://") {
			t.Fatalf("invariant violation: normalized URL %q does not start with http:// or https://", norm)
		}

		// Invariant 3: Normalized URL must parse with standard net/url without error
		parsed, parseErr := url.Parse(norm)
		if parseErr != nil {
			t.Fatalf("invariant violation: normalized URL %q failed net/url.Parse: %v", norm, parseErr)
		}

		// Invariant 4: Must never contain user credentials
		if parsed.User != nil || strings.Contains(parsed.Host, "@") {
			t.Fatalf("invariant violation: normalized URL %q contains user credentials", norm)
		}

		// Invariant 5: Idempotency property: NormalizeTargetURL(norm) MUST equal norm
		norm2, err2 := NormalizeTargetURL(norm)
		if err2 != nil {
			t.Fatalf("invariant violation: NormalizeTargetURL is not idempotent for %q: second pass failed: %v", norm, err2)
		}
		if norm2 != norm {
			t.Fatalf("invariant violation: NormalizeTargetURL is not idempotent: first=%q second=%q", norm, norm2)
		}
	})
}

func FuzzScopeIsAllowed(f *testing.F) {
	// Seed corpus: (baseTarget, candidateURL, mode)
	f.Add("https://example.com", "https://example.com/page", "same-origin")
	f.Add("https://example.com", "https://sub.example.com/api", "subdomains")
	f.Add("https://example.com", "https://external.com/path", "same-origin")
	f.Add("https://example.com", "javascript:void(0)", "same-origin")
	f.Add("https://example.com", "file:///local/file", "subdomains")
	f.Add("https://example.com", "data:text/plain;base64,SGVsbG8=", "same-origin")
	f.Add("https://example.com", "http://user:pass@example.com/leak", "same-origin")
	f.Add("https://example.com", "", "same-origin")
	f.Add("https://example.com", "https://example.com:8443/alt", "same-origin")
	f.Add("https://example.com", "https://example.com/admin/secrets", "same-origin")
	f.Add("https://example.com", "http://127.0.0.1/status", "explicit")
	f.Add("https://example.com", "https://example.com/logout", "same-origin")
	f.Add("https://example.com", "https://blocked.example.com/test", "subdomains")
	f.Add("https://example.com", "https://api.example.com/v1", "explicit")

	f.Fuzz(func(t *testing.T, baseTarget, candidateURL, modeStr string) {
		mode := ScopeSameOrigin
		switch modeStr {
		case "subdomains":
			mode = ScopeSubdomains
		case "explicit":
			mode = ScopeExplicit
		}

		scope, err := NewScope(baseTarget, mode, "api.example.com")
		if err != nil {
			// If baseTarget was invalid, scope creation fails cleanly
			return
		}

		scope.ExcludeHost("blocked.example.com")
		scope.ExcludeHost("*.internal.net")
		scope.ExcludePathPrefix("/logout")
		scope.ExcludePathPrefix("/admin")

		allowed := scope.IsAllowed(candidateURL)

		// Invariant 1: Empty or whitespace-only candidate URLs must NEVER be allowed
		if strings.TrimSpace(candidateURL) == "" && allowed {
			t.Fatalf("invariant violation: empty candidate URL was allowed")
		}

		// Invariant 2: Non-http/https schemes must NEVER be allowed
		if strings.HasPrefix(candidateURL, "javascript:") || strings.HasPrefix(candidateURL, "file:") || strings.HasPrefix(candidateURL, "data:") {
			if allowed {
				t.Fatalf("invariant violation: non-HTTP URL %q was allowed by scope", candidateURL)
			}
		}

		// Invariant 3: Embedded credentials must NEVER be allowed
		if strings.Contains(candidateURL, "@") {
			if parsed, pErr := url.Parse(candidateURL); pErr == nil && parsed.User != nil {
				if allowed {
					t.Fatalf("invariant violation: credentialed URL %q was allowed by scope", candidateURL)
				}
			}
		}

		// Invariant 4: Excluded paths (/logout, /admin) must NEVER be allowed
		if parsed, pErr := url.Parse(candidateURL); pErr == nil && parsed != nil {
			p := parsed.Path
			if p == "/logout" || strings.HasPrefix(p, "/logout/") || p == "/admin" || strings.HasPrefix(p, "/admin/") {
				if allowed {
					t.Fatalf("invariant violation: excluded path %q was allowed by scope", candidateURL)
				}
			}
		}
	})
}

func FuzzScopeIsPathInScope(f *testing.F) {
	// Seed corpus: (baseTargetWithSubpath, candidatePathOrURL)
	f.Add("https://example.com/app/v1", "/app/v1/users")
	f.Add("https://example.com/app/v1", "/app/v1/../admin")
	f.Add("https://example.com/app/v1", "/app/v1%2e%2e/evil")
	f.Add("https://example.com/app/v1", "/app/v1-admin")
	f.Add("https://example.com/app/v1", "/app/v1_evil")
	f.Add("https://example.com/app/v1", "/app/v1/sub/deep/path")
	f.Add("https://example.com/app/v1", "https://example.com/app/v1/items")
	f.Add("https://example.com/app/v1", "https://other.com/app/v1/items")
	f.Add("https://example.com/", "/any/path")
	f.Add("https://example.com", "/login")
	f.Add("https://example.com/tenantA", "/tenantB/data")
	f.Add("https://example.com/sec", "/sec%00/bypass")

	f.Fuzz(func(t *testing.T, baseTarget, candidate string) {
		scope, err := NewScope(baseTarget, ScopeSameOrigin)
		if err != nil {
			return
		}

		inScope := scope.IsPathInScope(candidate)

		// Invariant 1: Empty or whitespace string is never in path scope
		if strings.TrimSpace(candidate) == "" && inScope {
			t.Fatalf("invariant violation: empty candidate was in path scope")
		}

		// Invariant 2: If candidate has a different host, it must not be in path scope
		if parsed, pErr := url.Parse(candidate); pErr == nil && parsed.Hostname() != "" {
			if strings.ToLower(parsed.Hostname()) != strings.ToLower(scope.TargetURL.Hostname()) {
				if inScope {
					t.Fatalf("invariant violation: candidate with cross-host %q was in path scope", candidate)
				}
			}
		}

		// Invariant 3: Suspicious null bytes or raw control characters must never be in path scope
		if strings.ContainsRune(candidate, 0) && inScope {
			t.Fatalf("invariant violation: candidate with null byte was in path scope")
		}
	})
}
