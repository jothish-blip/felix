package crawler

import (
	"fmt"
	"testing"
)

// -----------------------------------------------------------------------------
// Stage A & B: Target & Scope Normalization Benchmarks
// -----------------------------------------------------------------------------

func BenchmarkNormalizeTargetURL(b *testing.B) {
	testURLs := []string{
		"https://example.com",
		"http://sub.domain.example.com:8080/path/to/resource?query=1&b=2#frag",
		"HTTPS://UPPERCASE.EXAMPLE.COM/PATH/",
		"http://example.com:80/standard-port",
		"https://example.com:443/standard-ssl-port",
		"https://user:pass@example.com/creds",
	}

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, _ = NormalizeTargetURL(testURLs[i%len(testURLs)])
	}
}

// -----------------------------------------------------------------------------
// Stage B: Scope Policy Evaluation Benchmarks
// -----------------------------------------------------------------------------

func BenchmarkScopeEvaluation_SameOrigin(b *testing.B) {
	scope, err := NewScope("https://app.example.com", ScopeSameOrigin)
	if err != nil {
		b.Fatalf("failed to create scope: %v", err)
	}
	scope.ExcludePathPrefix("/logout")
	scope.ExcludePathPrefix("/static")

	testCandidates := []string{
		"https://app.example.com/dashboard",
		"https://app.example.com/api/v1/users",
		"https://app.example.com/logout",
		"https://app.example.com/static/css/main.css",
		"https://other.example.com/dashboard",
		"http://app.example.com/insecure",
	}

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		candidate := testCandidates[i%len(testCandidates)]
		_ = scope.IsAllowed(candidate)
	}
}

func BenchmarkScopeEvaluation_Subdomains(b *testing.B) {
	scope, err := NewScope("https://example.com", ScopeSubdomains)
	if err != nil {
		b.Fatalf("failed to create scope: %v", err)
	}
	scope.ExcludePathPrefix("/admin")

	testCandidates := []string{
		"https://api.example.com/v1",
		"https://auth.example.com/oauth/token",
		"https://app.example.com/dashboard",
		"https://example.com/admin/settings",
		"https://attacker.com/payload",
	}

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		candidate := testCandidates[i%len(testCandidates)]
		_ = scope.IsAllowed(candidate)
	}
}

func BenchmarkScopeEvaluation_BatchTargets(b *testing.B) {
	scales := []struct {
		name    string
		targets int
	}{
		{"Small_10", 10},
		{"Medium_100", 100},
		{"Large_1000", 1000},
	}

	for _, sc := range scales {
		b.Run(sc.name, func(b *testing.B) {
			scope, _ := NewScope("https://example.com", ScopeSubdomains)
			candidates := make([]string, sc.targets)
			for i := 0; i < sc.targets; i++ {
				candidates[i] = fmt.Sprintf("https://target-%d.example.com/resource/%d", i%10, i)
			}

			b.ReportAllocs()
			b.ResetTimer()

			for i := 0; i < b.N; i++ {
				for _, candidate := range candidates {
					_ = scope.IsAllowed(candidate)
				}
			}
		})
	}
}
