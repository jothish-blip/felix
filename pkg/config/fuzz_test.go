package config

import (
	"strings"
	"testing"
)

func FuzzConfigParser(f *testing.F) {
	// Seed corpus: valid baseline configs
	f.Add([]byte(`{}`))
	f.Add([]byte(`{"timeout": 30, "concurrency": 5, "scope": "same-origin"}`))
	f.Add([]byte(`{"timeout": 1, "concurrency": 1, "max_size_mb": 1, "user_agent": "FuzzBot/1.0", "max_assets": 10}`))
	f.Add([]byte(`{"timeout": 3600, "concurrency": 1000, "max_size_mb": 1024, "scope": "subdomains", "max_assets": 10000, "max_depth": 20}`))
	f.Add([]byte(`{"notification": {"enabled": true, "webhook_url": "https://hooks.slack.com/services/T00/B00/X00", "timeout_seconds": 15, "min_severity": "HIGH"}}`))
	f.Add([]byte(`{"policy_path": "policy.json", "insecure_skip_verify": false, "active_verification": true}`))

	// Seed corpus: boundary and malformed inputs
	f.Add([]byte(``))
	f.Add([]byte(`   `))
	f.Add([]byte(`null`))
	f.Add([]byte(`true`))
	f.Add([]byte(`"plain string"`))
	f.Add([]byte(`[1, 2, 3]`))
	f.Add([]byte(`{"timeout": 0}`))
	f.Add([]byte(`{"timeout": -10}`))
	f.Add([]byte(`{"timeout": 3601}`))
	f.Add([]byte(`{"concurrency": 0}`))
	f.Add([]byte(`{"concurrency": 1001}`))
	f.Add([]byte(`{"scope": "invalid-scope"}`))
	f.Add([]byte(`{"scope": "  "}`))
	f.Add([]byte(`{"user_agent": ""}`))
	f.Add([]byte(`{"user_agent": "evil\r\nagent"}`))
	f.Add([]byte(`{"max_size_mb": 0}`))
	f.Add([]byte(`{"max_size_mb": 1025}`))
	f.Add([]byte(`{"max_assets": 0}`))
	f.Add([]byte(`{"max_assets": 10001}`))
	f.Add([]byte(`{"max_depth": 0}`))
	f.Add([]byte(`{"max_depth": 21}`))
	f.Add([]byte(`{"max_retries": -1}`))
	f.Add([]byte(`{"max_retries": 11}`))
	f.Add([]byte(`{"retry_delay_ms": -1}`))
	f.Add([]byte(`{"retry_delay_ms": 5001}`))
	f.Add([]byte(`{"notification": {"enabled": true, "webhook_url": "http://insecure.internal", "allow_insecure_http": false}}`))
	f.Add([]byte(`{"notification": {"timeout_seconds": 0}}`))
	f.Add([]byte(`{"notification": {"timeout_seconds": 301}}`))
	f.Add([]byte(`{"notification": {"min_severity": "ULTRA"}}`))
	f.Add([]byte(`{"notification": {"concurrency": 0}}`))
	f.Add([]byte(`{"notification": {"concurrency": 51}}`))
	f.Add([]byte(`{"unclosed_json": `))
	f.Add([]byte(`{"nested": {"nested": {"nested": 1}}}`))

	f.Fuzz(func(t *testing.T, data []byte) {
		cfg, err := ParseConfig(data)
		if err != nil {
			// Expected outcome for malformed JSON or invalid configuration values
			return
		}

		// Invariant 1: If parsing succeeded, Validate() MUST succeed
		if valErr := cfg.Validate(); valErr != nil {
			t.Fatalf("invariant violation: ParseConfig returned non-nil error from Validate(): %v", valErr)
		}

		// Invariant 2: Operational bounds check
		if cfg.Timeout < 1 || cfg.Timeout > 3600 {
			t.Fatalf("invariant violation: timeout %d out of bounds (1..3600)", cfg.Timeout)
		}
		if cfg.Concurrency < 1 || cfg.Concurrency > 1000 {
			t.Fatalf("invariant violation: concurrency %d out of bounds (1..1000)", cfg.Concurrency)
		}
		if cfg.MaxSizeMB < 1 || cfg.MaxSizeMB > 1024 {
			t.Fatalf("invariant violation: max_size_mb %d out of bounds (1..1024)", cfg.MaxSizeMB)
		}
		if cfg.Scope != "same-origin" && cfg.Scope != "subdomains" && cfg.Scope != "explicit" {
			t.Fatalf("invariant violation: invalid scope %q accepted", cfg.Scope)
		}
		if strings.TrimSpace(cfg.UserAgent) == "" || strings.ContainsAny(cfg.UserAgent, "\r\n") {
			t.Fatalf("invariant violation: invalid user_agent %q accepted", cfg.UserAgent)
		}
		if cfg.MaxAssets < 1 || cfg.MaxAssets > 10000 {
			t.Fatalf("invariant violation: max_assets %d out of bounds (1..10000)", cfg.MaxAssets)
		}
		if cfg.MaxDepth < 1 || cfg.MaxDepth > 20 {
			t.Fatalf("invariant violation: max_depth %d out of bounds (1..20)", cfg.MaxDepth)
		}
		if cfg.MaxRetries < 0 || cfg.MaxRetries > 10 {
			t.Fatalf("invariant violation: max_retries %d out of bounds (0..10)", cfg.MaxRetries)
		}
		if cfg.RetryDelayMs < 0 || cfg.RetryDelayMs > 5000 {
			t.Fatalf("invariant violation: retry_delay_ms %d out of bounds (0..5000)", cfg.RetryDelayMs)
		}
		if cfg.MaxRedirects < 0 || cfg.MaxRedirects > 20 {
			t.Fatalf("invariant violation: max_redirects %d out of bounds (0..20)", cfg.MaxRedirects)
		}

		// Invariant 3: Notification constraints
		if cfg.Notification.Enabled {
			if cfg.Notification.TimeoutSeconds < 1 || cfg.Notification.TimeoutSeconds > 300 {
				t.Fatalf("invariant violation: notification timeout %d out of bounds (1..300)", cfg.Notification.TimeoutSeconds)
			}
			if cfg.Notification.MaxRetries < 0 || cfg.Notification.MaxRetries > 10 {
				t.Fatalf("invariant violation: notification max_retries %d out of bounds (0..10)", cfg.Notification.MaxRetries)
			}
			if cfg.Notification.Concurrency < 1 || cfg.Notification.Concurrency > 50 {
				t.Fatalf("invariant violation: notification concurrency %d out of bounds (1..50)", cfg.Notification.Concurrency)
			}
		}
	})
}
