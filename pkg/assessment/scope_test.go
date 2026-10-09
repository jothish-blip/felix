package assessment

import (
	"testing"
)

func TestValidateTargetURL(t *testing.T) {
	validCases := []string{
		"https://example.com",
		"http://example.com/app",
		"https://sub.domain.org:8443/api/v1",
		"http://192.168.1.100:8080/test",
	}

	for _, tc := range validCases {
		u, err := ValidateTargetURL(tc)
		if err != nil || u == nil {
			t.Errorf("expected valid URL for %q, got error: %v", tc, err)
		}
	}

	invalidCases := []struct {
		url string
		err string
	}{
		{"", "cannot be empty"},
		{"   ", "cannot be empty"},
		{"ftp://example.com/files", "unsupported URL scheme"},
		{"file:///etc/passwd", "unsupported URL scheme"},
		{"https://user:password@example.com", "embedded credentials"},
		{"https://", "valid hostname"},
		{"https://host with spaces.com", "invalid characters"},
	}

	for _, tc := range invalidCases {
		_, err := ValidateTargetURL(tc.url)
		if err == nil {
			t.Errorf("expected error for URL %q, got nil", tc.url)
		}
	}
}

func TestNormalizeTargetURL(t *testing.T) {
	cases := []struct {
		input    string
		expected string
	}{
		{"https://EXAMPLE.COM", "https://example.com"},
		{"https://example.com:443/app", "https://example.com/app"},
		{"http://example.com:80/app", "http://example.com/app"},
		{"http://example.com:8080/app/", "http://example.com:8080/app"},
	}

	for _, tc := range cases {
		norm, err := NormalizeTargetURL(tc.input)
		if err != nil {
			t.Errorf("unexpected error normalizing %q: %v", tc.input, err)
			continue
		}
		if norm != tc.expected {
			t.Errorf("normalize %q: expected %q, got %q", tc.input, tc.expected, norm)
		}
	}
}

func TestScopeValidator_ExclusionPrecedence(t *testing.T) {
	approvedTargets := []string{
		"https://example.com",
		"https://api.example.com",
	}

	scopeRules := []ScopeRule{
		{RuleType: "subdomains", Pattern: "example.com"},
	}

	exclusions := []Exclusion{
		{ExclusionType: ExclusionHostname, Pattern: "billing.example.com", Reason: "PCI boundary"},
		{ExclusionType: ExclusionHostname, Pattern: "*.internal.example.com", Reason: "Internal networks"},
		{ExclusionType: ExclusionPathPrefix, Pattern: "/admin", Reason: "Admin exclusion"},
		{ExclusionType: ExclusionExactURL, Pattern: "https://example.com/logout", Reason: "Session invalidation"},
	}

	validator := NewScopeValidator("subdomains", approvedTargets, scopeRules, exclusions)

	// 1. Regular subdomains in scope and not excluded
	if !validator.IsAllowed("https://api.example.com/users") {
		t.Errorf("expected api.example.com/users to be allowed")
	}
	if !validator.IsAllowed("https://portal.example.com/") {
		t.Errorf("expected portal.example.com to be allowed")
	}

	// 2. Out of scope entirely
	if validator.IsAllowed("https://evil.com/app") {
		t.Errorf("expected evil.com to be disallowed")
	}

	// 3. EXCLUSION PRECEDENCE: Hostname exclusion overrides subdomains scope
	if validator.IsAllowed("https://billing.example.com/invoice") {
		t.Errorf("expected billing.example.com to be blocked by exclusion, got allowed")
	}
	if excluded, reason := validator.IsExcluded("https://billing.example.com/invoice"); !excluded || reason == "" {
		t.Errorf("expected IsExcluded to return true with reason for billing.example.com")
	}

	// 4. EXCLUSION PRECEDENCE: Wildcard hostname exclusion
	if validator.IsAllowed("https://db.internal.example.com/metrics") {
		t.Errorf("expected *.internal.example.com to be blocked by exclusion")
	}

	// 5. EXCLUSION PRECEDENCE: Path prefix exclusion
	if validator.IsAllowed("https://example.com/admin/settings") {
		t.Errorf("expected /admin to be blocked by exclusion")
	}
	if validator.IsAllowed("https://api.example.com/admin") {
		t.Errorf("expected /admin on api.example.com to be blocked by exclusion")
	}

	// 6. EXCLUSION PRECEDENCE: Exact URL exclusion
	if validator.IsAllowed("https://example.com/logout") {
		t.Errorf("expected exact URL https://example.com/logout to be blocked by exclusion")
	}
	// Non-exact URL on same path should be allowed
	if !validator.IsAllowed("https://example.com/logout-preview") {
		t.Errorf("expected https://example.com/logout-preview to be allowed")
	}
}

func TestScopeValidator_RedirectValidation(t *testing.T) {
	approvedTargets := []string{"https://example.com"}
	exclusions := []Exclusion{
		{ExclusionType: ExclusionPathPrefix, Pattern: "/restricted"},
	}
	validator := NewScopeValidator("same-origin", approvedTargets, nil, exclusions)

	// 1. In-scope redirect allowed
	if err := validator.ValidateRedirect("https://example.com/start", "https://example.com/next"); err != nil {
		t.Errorf("expected in-scope redirect to be allowed, got: %v", err)
	}

	// 2. Relative redirect resolved and allowed
	if err := validator.ValidateRedirect("https://example.com/start", "https://example.com/dashboard"); err != nil {
		t.Errorf("expected in-scope redirect to dashboard to be allowed, got: %v", err)
	}

	// 3. Out-of-scope redirect blocked (fails closed)
	if err := validator.ValidateRedirect("https://example.com/start", "https://thirdparty.com/login"); err == nil {
		t.Errorf("expected redirect to thirdparty.com to be blocked")
	}

	// 4. Redirect into excluded path blocked
	if err := validator.ValidateRedirect("https://example.com/start", "https://example.com/restricted/area"); err == nil {
		t.Errorf("expected redirect into excluded path /restricted/area to be blocked")
	}
}
