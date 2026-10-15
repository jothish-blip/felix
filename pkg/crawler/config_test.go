package crawler

import (
	"testing"
	"time"
)

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()

	if cfg.Concurrency != DefaultConcurrency {
		t.Errorf("expected Concurrency %d, got %d", DefaultConcurrency, cfg.Concurrency)
	}
	if cfg.Timeout != DefaultTimeout {
		t.Errorf("expected Timeout %v, got %v", DefaultTimeout, cfg.Timeout)
	}
	if cfg.MaxAssetSize != DefaultMaxAssetSize {
		t.Errorf("expected MaxAssetSize %d, got %d", DefaultMaxAssetSize, cfg.MaxAssetSize)
	}
	if cfg.UserAgent != DefaultUserAgent {
		t.Errorf("expected UserAgent %q, got %q", DefaultUserAgent, cfg.UserAgent)
	}
	if cfg.ScopeMode != ScopeSameOrigin {
		t.Errorf("expected ScopeMode %q, got %q", ScopeSameOrigin, cfg.ScopeMode)
	}
	if cfg.AllowLoopback {
		t.Errorf("expected AllowLoopback to be false by default")
	}
	if cfg.AllowPrivateIPs {
		t.Errorf("expected AllowPrivateIPs to be false by default")
	}
}

func TestCrawlerNew_DefaultsAndFallbacks(t *testing.T) {
	tests := []struct {
		name       string
		input      Config
		checkField func(t *testing.T, c *Crawler)
	}{
		{
			name:  "zero config falls back to all defaults",
			input: Config{},
			checkField: func(t *testing.T, c *Crawler) {
				if c.config.Concurrency != DefaultConcurrency {
					t.Errorf("Concurrency: expected %d, got %d", DefaultConcurrency, c.config.Concurrency)
				}
				if c.config.Timeout != DefaultTimeout {
					t.Errorf("Timeout: expected %v, got %v", DefaultTimeout, c.config.Timeout)
				}
				if c.config.MaxAssetSize != DefaultMaxAssetSize {
					t.Errorf("MaxAssetSize: expected %d, got %d", DefaultMaxAssetSize, c.config.MaxAssetSize)
				}
				if c.config.UserAgent != DefaultUserAgent {
					t.Errorf("UserAgent: expected %q, got %q", DefaultUserAgent, c.config.UserAgent)
				}
				if c.config.ScopeMode != ScopeSameOrigin {
					t.Errorf("ScopeMode: expected %q, got %q", ScopeSameOrigin, c.config.ScopeMode)
				}
				if c.client == nil {
					t.Fatalf("expected non-nil http.Client")
				}
				if c.client.Timeout != DefaultTimeout {
					t.Errorf("client Timeout: expected %v, got %v", DefaultTimeout, c.client.Timeout)
				}
			},
		},
		{
			name: "negative numbers fall back to defaults",
			input: Config{
				Concurrency:  -5,
				Timeout:      -10 * time.Second,
				MaxAssetSize: -1024,
			},
			checkField: func(t *testing.T, c *Crawler) {
				if c.config.Concurrency != DefaultConcurrency {
					t.Errorf("Concurrency: expected %d, got %d", DefaultConcurrency, c.config.Concurrency)
				}
				if c.config.Timeout != DefaultTimeout {
					t.Errorf("Timeout: expected %v, got %v", DefaultTimeout, c.config.Timeout)
				}
				if c.config.MaxAssetSize != DefaultMaxAssetSize {
					t.Errorf("MaxAssetSize: expected %d, got %d", DefaultMaxAssetSize, c.config.MaxAssetSize)
				}
			},
		},
		{
			name: "custom valid options are preserved",
			input: Config{
				Concurrency:  35,
				Timeout:      45 * time.Second,
				MaxAssetSize: 50 * 1024 * 1024,
				UserAgent:    "CustomAuditor/1.0",
				ScopeMode:    ScopeSubdomains,
			},
			checkField: func(t *testing.T, c *Crawler) {
				if c.config.Concurrency != 35 {
					t.Errorf("Concurrency: expected 35, got %d", c.config.Concurrency)
				}
				if c.config.Timeout != 45*time.Second {
					t.Errorf("Timeout: expected 45s, got %v", c.config.Timeout)
				}
				if c.config.MaxAssetSize != 50*1024*1024 {
					t.Errorf("MaxAssetSize: expected 50MB, got %d", c.config.MaxAssetSize)
				}
				if c.config.UserAgent != "CustomAuditor/1.0" {
					t.Errorf("UserAgent: expected CustomAuditor/1.0, got %s", c.config.UserAgent)
				}
				if c.config.ScopeMode != ScopeSubdomains {
					t.Errorf("ScopeMode: expected %q, got %q", ScopeSubdomains, c.config.ScopeMode)
				}
				if c.client.Timeout != 45*time.Second {
					t.Errorf("client Timeout: expected 45s, got %v", c.client.Timeout)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := New(tt.input)
			tt.checkField(t, c)
		})
	}
}
