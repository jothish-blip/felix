package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDefault(t *testing.T) {
	cfg := Default()

	if cfg.Timeout != DefaultTimeoutSeconds {
		t.Errorf("expected Timeout %d, got %d", DefaultTimeoutSeconds, cfg.Timeout)
	}
	if cfg.Concurrency != DefaultConcurrency {
		t.Errorf("expected Concurrency %d, got %d", DefaultConcurrency, cfg.Concurrency)
	}
	if cfg.Scope != DefaultScope {
		t.Errorf("expected Scope %q, got %q", DefaultScope, cfg.Scope)
	}
	if cfg.MaxSizeMB != DefaultMaxSizeMB {
		t.Errorf("expected MaxSizeMB %d, got %d", DefaultMaxSizeMB, cfg.MaxSizeMB)
	}
	if cfg.UserAgent != DefaultUserAgent {
		t.Errorf("expected UserAgent %q, got %q", DefaultUserAgent, cfg.UserAgent)
	}
	if cfg.MaxAssets != DefaultMaxAssets {
		t.Errorf("expected MaxAssets %d, got %d", DefaultMaxAssets, cfg.MaxAssets)
	}
	if cfg.MaxDepth != DefaultMaxDepth {
		t.Errorf("expected MaxDepth %d, got %d", DefaultMaxDepth, cfg.MaxDepth)
	}
	if cfg.MaxRetries != DefaultMaxRetries {
		t.Errorf("expected MaxRetries %d, got %d", DefaultMaxRetries, cfg.MaxRetries)
	}
	if cfg.RetryDelayMs != DefaultRetryDelayMs {
		t.Errorf("expected RetryDelayMs %d, got %d", DefaultRetryDelayMs, cfg.RetryDelayMs)
	}
	if cfg.MaxRedirects != DefaultMaxRedirects {
		t.Errorf("expected MaxRedirects %d, got %d", DefaultMaxRedirects, cfg.MaxRedirects)
	}
	if cfg.InsecureSkipVerify != DefaultInsecureSkipVerify {
		t.Errorf("expected InsecureSkipVerify to be false by default")
	}
	if cfg.AllowPrivateIPs != DefaultAllowPrivateIPs {
		t.Errorf("expected AllowPrivateIPs to be false by default")
	}
	if cfg.AllowLoopback != DefaultAllowLoopback {
		t.Errorf("expected AllowLoopback to be false by default")
	}
	if cfg.ActiveVerification != DefaultActiveVerification {
		t.Errorf("expected ActiveVerification to be false by default")
	}
	if !cfg.Updates.Check {
		t.Errorf("expected Updates.Check to be true by default")
	}
	if cfg.Updates.AutoInstall {
		t.Errorf("expected Updates.AutoInstall to be false by default")
	}

	if err := cfg.Validate(); err != nil {
		t.Fatalf("Default() failed validation: %v", err)
	}
}

func TestValidate(t *testing.T) {
	tests := []struct {
		name      string
		modify    func(c *Config)
		wantError bool
		errMsg    string
	}{
		{
			name:      "valid default",
			modify:    func(c *Config) {},
			wantError: false,
		},
		{
			name: "timeout zero",
			modify: func(c *Config) {
				c.Timeout = 0
			},
			wantError: true,
			errMsg:    "timeout must be greater than 0",
		},
		{
			name: "timeout negative",
			modify: func(c *Config) {
				c.Timeout = -5
			},
			wantError: true,
			errMsg:    "timeout must be greater than 0",
		},
		{
			name: "timeout excessive",
			modify: func(c *Config) {
				c.Timeout = 3601
			},
			wantError: true,
			errMsg:    "timeout cannot exceed 3600",
		},
		{
			name: "concurrency zero",
			modify: func(c *Config) {
				c.Concurrency = 0
			},
			wantError: true,
			errMsg:    "concurrency must be greater than 0",
		},
		{
			name: "concurrency excessive",
			modify: func(c *Config) {
				c.Concurrency = 1001
			},
			wantError: true,
			errMsg:    "concurrency cannot exceed 1000",
		},
		{
			name: "scope invalid",
			modify: func(c *Config) {
				c.Scope = "all-domains"
			},
			wantError: true,
			errMsg:    "invalid scope",
		},
		{
			name: "scope subdomains",
			modify: func(c *Config) {
				c.Scope = "subdomains"
			},
			wantError: false,
		},
		{
			name: "scope explicit",
			modify: func(c *Config) {
				c.Scope = "explicit"
			},
			wantError: false,
		},
		{
			name: "max size mb zero",
			modify: func(c *Config) {
				c.MaxSizeMB = 0
			},
			wantError: true,
			errMsg:    "max_size_mb must be greater than 0",
		},
		{
			name: "max size mb excessive",
			modify: func(c *Config) {
				c.MaxSizeMB = 1025
			},
			wantError: true,
			errMsg:    "max_size_mb cannot exceed 1024",
		},
		{
			name: "user agent empty",
			modify: func(c *Config) {
				c.UserAgent = ""
			},
			wantError: true,
			errMsg:    "user_agent cannot be empty",
		},
		{
			name: "user agent whitespace only",
			modify: func(c *Config) {
				c.UserAgent = "   "
			},
			wantError: true,
			errMsg:    "user_agent cannot be empty",
		},
		{
			name: "user agent with newline injection",
			modify: func(c *Config) {
				c.UserAgent = "Felix/1.0\r\nX-Injected-Header: evil"
			},
			wantError: true,
			errMsg:    "user_agent cannot contain newline",
		},
		{
			name: "max assets zero",
			modify: func(c *Config) {
				c.MaxAssets = 0
			},
			wantError: true,
			errMsg:    "max_assets must be greater than 0",
		},
		{
			name: "max assets excessive",
			modify: func(c *Config) {
				c.MaxAssets = 10001
			},
			wantError: true,
			errMsg:    "max_assets cannot exceed 10000",
		},
		{
			name: "max depth zero",
			modify: func(c *Config) {
				c.MaxDepth = 0
			},
			wantError: true,
			errMsg:    "max_depth must be greater than 0",
		},
		{
			name: "max depth excessive",
			modify: func(c *Config) {
				c.MaxDepth = 21
			},
			wantError: true,
			errMsg:    "max_depth cannot exceed 20",
		},
		{
			name: "max retries negative",
			modify: func(c *Config) {
				c.MaxRetries = -1
			},
			wantError: true,
			errMsg:    "max_retries cannot be negative",
		},
		{
			name: "max retries excessive",
			modify: func(c *Config) {
				c.MaxRetries = 11
			},
			wantError: true,
			errMsg:    "max_retries cannot exceed 10",
		},
		{
			name: "retry delay ms negative",
			modify: func(c *Config) {
				c.RetryDelayMs = -1
			},
			wantError: true,
			errMsg:    "retry_delay_ms cannot be negative",
		},
		{
			name: "retry delay ms excessive",
			modify: func(c *Config) {
				c.RetryDelayMs = 5001
			},
			wantError: true,
			errMsg:    "retry_delay_ms cannot exceed 5000",
		},
		{
			name: "max redirects negative",
			modify: func(c *Config) {
				c.MaxRedirects = -1
			},
			wantError: true,
			errMsg:    "max_redirects cannot be negative",
		},
		{
			name: "max redirects excessive",
			modify: func(c *Config) {
				c.MaxRedirects = 21
			},
			wantError: true,
			errMsg:    "max_redirects cannot exceed 20",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := Default()
			tt.modify(&cfg)
			err := cfg.Validate()
			if tt.wantError {
				if err == nil {
					t.Fatalf("expected error, got nil")
				}
				if !strings.Contains(err.Error(), tt.errMsg) {
					t.Fatalf("expected error containing %q, got %q", tt.errMsg, err.Error())
				}
			} else {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
			}
		})
	}
}

func TestGetAndSet(t *testing.T) {
	cfg := Default()

	// Test Get defaults
	getChecks := []struct {
		key     string
		wantVal string
	}{
		{"timeout", "10"},
		{"concurrency", "10"},
		{"scope", "same-origin"},
		{"max_size_mb", "10"},
		{"user_agent", DefaultUserAgent},
		{"max_assets", "200"},
		{"max_depth", "3"},
		{"max_retries", "2"},
		{"retry_delay_ms", "200"},
		{"max_redirects", "5"},
		{"insecure_skip_verify", "false"},
		{"allow_private_ips", "false"},
		{"allow_loopback", "false"},
		{"active_verification", "false"},
		{"update_check", "true"},
		{"auto_install", "false"},
	}

	for _, gc := range getChecks {
		val, err := cfg.Get(gc.key)
		if err != nil || val != gc.wantVal {
			t.Errorf("Get(%q) = %q (err: %v), want %q", gc.key, val, err, gc.wantVal)
		}
	}

	// Test Set valid values
	setTests := []struct {
		key      string
		val      string
		checkKey string
		wantVal  string
	}{
		{"timeout", "25", "timeout", "25"},
		{"concurrency", "50", "concurrency", "50"},
		{"scope", "subdomains", "scope", "subdomains"},
		{"scope", "explicit", "scope", "explicit"},
		{"max-size-mb", "32", "max_size_mb", "32"},
		{"maxsize", "64", "max_size_mb", "64"},
		{"user-agent", "CustomScanner/2.0", "user_agent", "CustomScanner/2.0"},
		{"max_assets", "500", "max_assets", "500"},
		{"max-assets", "1000", "max_assets", "1000"},
		{"max_depth", "5", "max_depth", "5"},
		{"max_retries", "4", "max_retries", "4"},
		{"retry_delay_ms", "350", "retry_delay_ms", "350"},
		{"max_redirects", "8", "max_redirects", "8"},
		{"insecure_skip_verify", "true", "insecure_skip_verify", "true"},
		{"allow_private_ips", "true", "allow_private_ips", "true"},
		{"allow_loopback", "true", "allow_loopback", "true"},
		{"active_verification", "true", "active_verification", "true"},
		{"update-check", "false", "update_check", "false"},
		{"updates.check", "true", "update_check", "true"},
		{"auto-install", "true", "auto_install", "true"},
		{"updates.auto_install", "false", "auto_install", "false"},
	}

	for _, st := range setTests {
		if err := cfg.Set(st.key, st.val); err != nil {
			t.Errorf("Set(%q, %q) returned error: %v", st.key, st.val, err)
		}
		got, err := cfg.Get(st.checkKey)
		if err != nil || got != st.wantVal {
			t.Errorf("Get(%q) after Set(%q, %q) = %q (err: %v), want %q", st.checkKey, st.key, st.val, got, err, st.wantVal)
		}
	}

	// Test Set invalid values
	invalidSetTests := []struct {
		name string
		key  string
		val  string
	}{
		{"timeout not integer", "timeout", "abc"},
		{"timeout zero", "timeout", "0"},
		{"timeout negative", "timeout", "-1"},
		{"timeout excessive", "timeout", "5000"},
		{"concurrency not integer", "concurrency", "xyz"},
		{"concurrency zero", "concurrency", "0"},
		{"concurrency excessive", "concurrency", "2000"},
		{"scope invalid", "scope", "open-wildcard"},
		{"max_size_mb not integer", "max_size_mb", "big"},
		{"max_size_mb zero", "max_size_mb", "0"},
		{"max_size_mb excessive", "max_size_mb", "2048"},
		{"user_agent empty", "user_agent", ""},
		{"user_agent newline", "user_agent", "BadAgent\nEvil: true"},
		{"max_assets zero", "max_assets", "0"},
		{"max_assets excessive", "max_assets", "20000"},
		{"max_depth zero", "max_depth", "0"},
		{"max_depth excessive", "max_depth", "50"},
		{"max_retries negative", "max_retries", "-1"},
		{"max_retries excessive", "max_retries", "15"},
		{"retry_delay_ms negative", "retry_delay_ms", "-1"},
		{"retry_delay_ms excessive", "retry_delay_ms", "6000"},
		{"max_redirects negative", "max_redirects", "-1"},
		{"max_redirects excessive", "max_redirects", "30"},
		{"insecure not bool", "insecure_skip_verify", "maybe"},
		{"allow_private not bool", "allow_private_ips", "yes"},
		{"allow_loopback not bool", "allow_loopback", "no"},
		{"active not bool", "active_verification", "sure"},
		{"update_check not bool", "update_check", "maybe"},
		{"auto_install not bool", "auto_install", "1234"},
	}

	for _, it := range invalidSetTests {
		t.Run(it.name, func(t *testing.T) {
			if err := cfg.Set(it.key, it.val); err == nil {
				t.Fatalf("Set(%q, %q) expected error, got nil", it.key, it.val)
			}
		})
	}

	// Test Unknown Keys and Secret Redaction
	t.Run("unknown key error", func(t *testing.T) {
		_, err := cfg.Get("nonexistent_key")
		if err == nil {
			t.Fatalf("expected error for nonexistent key")
		}
		if !strings.Contains(err.Error(), "unknown configuration key") {
			t.Fatalf("unexpected error message: %v", err)
		}

		err = cfg.Set("nonexistent_key", "value")
		if err == nil {
			t.Fatalf("expected error for nonexistent key")
		}
		if !strings.Contains(err.Error(), "unknown configuration key") {
			t.Fatalf("unexpected error message: %v", err)
		}
	})

	t.Run("secret redaction in unknown key error", func(t *testing.T) {
		rawSecret := "AKIAIOSFODNN7EXAMPLE"
		_, err := cfg.Get(rawSecret)
		if err == nil {
			t.Fatalf("expected error")
		}
		if strings.Contains(err.Error(), rawSecret) {
			t.Fatalf("raw secret leaked in Get() error: %v", err)
		}
		if !strings.Contains(err.Error(), "[REDACTED") {
			t.Fatalf("expected redacted token in Get() error, got: %v", err)
		}

		err = cfg.Set(rawSecret, "val")
		if err == nil {
			t.Fatalf("expected error")
		}
		if strings.Contains(err.Error(), rawSecret) {
			t.Fatalf("raw secret leaked in Set() error: %v", err)
		}
		if !strings.Contains(err.Error(), "[REDACTED") {
			t.Fatalf("expected redacted token in Set() error, got: %v", err)
		}
	})
}

func TestPrecedence_DefaultToFileToEnv(t *testing.T) {
	tempDir := t.TempDir()
	t.Setenv("FELIX_DIR", tempDir)

	// Step 1: Default configuration
	cfg, err := LoadWithEnv("")
	if err != nil {
		t.Fatalf("LoadWithEnv default failed: %v", err)
	}
	if cfg.Timeout != DefaultTimeoutSeconds {
		t.Errorf("expected default timeout %d, got %d", DefaultTimeoutSeconds, cfg.Timeout)
	}
	if cfg.Concurrency != DefaultConcurrency {
		t.Errorf("expected default concurrency %d, got %d", DefaultConcurrency, cfg.Concurrency)
	}

	// Step 2: Config file overrides defaults
	diskCfg := Default()
	diskCfg.Timeout = 25
	diskCfg.Concurrency = 30
	diskCfg.MaxAssets = 450
	if err := Save(diskCfg); err != nil {
		t.Fatalf("Save failed: %v", err)
	}

	cfg, err = LoadWithEnv("")
	if err != nil {
		t.Fatalf("LoadWithEnv after save failed: %v", err)
	}
	if cfg.Timeout != 25 {
		t.Errorf("expected file timeout 25, got %d", cfg.Timeout)
	}
	if cfg.Concurrency != 30 {
		t.Errorf("expected file concurrency 30, got %d", cfg.Concurrency)
	}
	if cfg.MaxAssets != 450 {
		t.Errorf("expected file max assets 450, got %d", cfg.MaxAssets)
	}

	// Step 3: Environment variables override config file
	t.Setenv("FELIX_TIMEOUT", "45s")
	t.Setenv("FELIX_CONCURRENCY", "60")
	t.Setenv("FELIX_MAX_ASSETS", "800")
	t.Setenv("FELIX_ALLOW_PRIVATE_IPS", "true")

	cfg, err = LoadWithEnv("")
	if err != nil {
		t.Fatalf("LoadWithEnv with env vars failed: %v", err)
	}
	if cfg.Timeout != 45 {
		t.Errorf("expected env timeout 45, got %d", cfg.Timeout)
	}
	if cfg.Concurrency != 60 {
		t.Errorf("expected env concurrency 60, got %d", cfg.Concurrency)
	}
	if cfg.MaxAssets != 800 {
		t.Errorf("expected env max assets 800, got %d", cfg.MaxAssets)
	}
	if !cfg.AllowPrivateIPs {
		t.Errorf("expected env allow_private_ips true, got false")
	}
}

func TestLoadWithEnv_InvalidEnvErrorsOut(t *testing.T) {
	tempDir := t.TempDir()
	t.Setenv("FELIX_DIR", tempDir)

	// 1. Invalid duration in FELIX_TIMEOUT
	t.Run("invalid FELIX_TIMEOUT", func(t *testing.T) {
		t.Setenv("FELIX_TIMEOUT", "not-a-duration")
		_, err := LoadWithEnv("")
		if err == nil {
			t.Fatalf("expected error for invalid FELIX_TIMEOUT, got nil")
		}
		if !strings.Contains(err.Error(), "invalid FELIX_TIMEOUT") {
			t.Errorf("unexpected error message: %v", err)
		}
	})

	// 2. Negative FELIX_CONCURRENCY
	t.Run("negative FELIX_CONCURRENCY", func(t *testing.T) {
		t.Setenv("FELIX_CONCURRENCY", "-5")
		_, err := LoadWithEnv("")
		if err == nil {
			t.Fatalf("expected error for negative FELIX_CONCURRENCY, got nil")
		}
		if !strings.Contains(err.Error(), "invalid FELIX_CONCURRENCY") {
			t.Errorf("unexpected error message: %v", err)
		}
	})

	// 3. Invalid FELIX_SCOPE
	t.Run("invalid FELIX_SCOPE", func(t *testing.T) {
		t.Setenv("FELIX_SCOPE", "open-wildcard")
		_, err := LoadWithEnv("")
		if err == nil {
			t.Fatalf("expected error for invalid FELIX_SCOPE, got nil")
		}
		if !strings.Contains(err.Error(), "invalid FELIX_SCOPE") {
			t.Errorf("unexpected error message: %v", err)
		}
	})

	// 4. Secret redaction in invalid env var error
	t.Run("secret redaction in invalid env var", func(t *testing.T) {
		rawSecret := "AKIAIOSFODNN7EXAMPLE"
		t.Setenv("FELIX_SCOPE", rawSecret)
		_, err := LoadWithEnv("")
		if err == nil {
			t.Fatalf("expected error")
		}
		if strings.Contains(err.Error(), rawSecret) {
			t.Fatalf("raw secret leaked in LoadWithEnv error: %v", err)
		}
		if !strings.Contains(err.Error(), "[REDACTED") {
			t.Fatalf("expected redacted token in LoadWithEnv error, got: %v", err)
		}
	})
}

func TestDirAndPath(t *testing.T) {
	tempDir := t.TempDir()
	t.Setenv("FELIX_DIR", tempDir)

	d, err := Dir()
	if err != nil {
		t.Fatalf("Dir() error: %v", err)
	}
	if d != tempDir {
		t.Fatalf("expected Dir %q, got %q", tempDir, d)
	}

	p, err := Path()
	if err != nil {
		t.Fatalf("Path() error: %v", err)
	}
	expectedPath := filepath.Join(tempDir, "config.json")
	if p != expectedPath {
		t.Fatalf("expected Path %q, got %q", expectedPath, p)
	}

	// Test FELIX_CONFIG override
	explicitPath := filepath.Join(tempDir, "custom-cfg.json")
	t.Setenv("FELIX_CONFIG", explicitPath)
	p, err = Path()
	if err != nil {
		t.Fatalf("Path() error: %v", err)
	}
	if p != explicitPath {
		t.Fatalf("expected explicit Path %q, got %q", explicitPath, p)
	}
}

func TestLoad_NoFileReturnsDefault(t *testing.T) {
	tempDir := t.TempDir()
	t.Setenv("FELIX_DIR", tempDir)

	cfg, err := Load()
	if err != nil {
		t.Fatalf("expected no error when config file does not exist, got: %v", err)
	}
	defaultCfg := Default()

	if cfg.Timeout != defaultCfg.Timeout ||
		cfg.Concurrency != defaultCfg.Concurrency ||
		cfg.Scope != defaultCfg.Scope ||
		cfg.MaxSizeMB != defaultCfg.MaxSizeMB ||
		cfg.UserAgent != defaultCfg.UserAgent ||
		cfg.MaxAssets != defaultCfg.MaxAssets ||
		cfg.MaxDepth != defaultCfg.MaxDepth ||
		cfg.MaxRetries != defaultCfg.MaxRetries ||
		cfg.RetryDelayMs != defaultCfg.RetryDelayMs ||
		cfg.MaxRedirects != defaultCfg.MaxRedirects ||
		cfg.InsecureSkipVerify != defaultCfg.InsecureSkipVerify ||
		cfg.AllowPrivateIPs != defaultCfg.AllowPrivateIPs ||
		cfg.AllowLoopback != defaultCfg.AllowLoopback ||
		cfg.ActiveVerification != defaultCfg.ActiveVerification ||
		cfg.Updates != defaultCfg.Updates {
		t.Fatalf("expected Load() without file to return default, got %+v", cfg)
	}
}

func TestSaveAndLoad_RoundTrip(t *testing.T) {
	tempDir := t.TempDir()
	t.Setenv("FELIX_DIR", tempDir)

	cfg := Config{
		Timeout:            42,
		Concurrency:        15,
		Scope:              "subdomains",
		MaxSizeMB:          100,
		UserAgent:          "FelixIntegration/1.0",
		MaxAssets:          350,
		MaxDepth:           4,
		MaxRetries:         3,
		RetryDelayMs:       150,
		MaxRedirects:       7,
		InsecureSkipVerify: true,
		AllowPrivateIPs:    true,
		AllowLoopback:      true,
		ActiveVerification: true,
		Updates: UpdateConfig{
			Check:       false,
			AutoInstall: true,
		},
	}

	if err := Save(cfg); err != nil {
		t.Fatalf("Save() failed: %v", err)
	}

	loaded, err := Load()
	if err != nil {
		t.Fatalf("Load() failed: %v", err)
	}

	if loaded.Timeout != 42 {
		t.Errorf("Timeout: expected 42, got %d", loaded.Timeout)
	}
	if loaded.Concurrency != 15 {
		t.Errorf("Concurrency: expected 15, got %d", loaded.Concurrency)
	}
	if loaded.Scope != "subdomains" {
		t.Errorf("Scope: expected subdomains, got %s", loaded.Scope)
	}
	if loaded.MaxSizeMB != 100 {
		t.Errorf("MaxSizeMB: expected 100, got %d", loaded.MaxSizeMB)
	}
	if loaded.UserAgent != "FelixIntegration/1.0" {
		t.Errorf("UserAgent: expected FelixIntegration/1.0, got %s", loaded.UserAgent)
	}
	if loaded.MaxAssets != 350 {
		t.Errorf("MaxAssets: expected 350, got %d", loaded.MaxAssets)
	}
	if loaded.MaxDepth != 4 {
		t.Errorf("MaxDepth: expected 4, got %d", loaded.MaxDepth)
	}
	if loaded.MaxRetries != 3 {
		t.Errorf("MaxRetries: expected 3, got %d", loaded.MaxRetries)
	}
	if loaded.RetryDelayMs != 150 {
		t.Errorf("RetryDelayMs: expected 150, got %d", loaded.RetryDelayMs)
	}
	if loaded.MaxRedirects != 7 {
		t.Errorf("MaxRedirects: expected 7, got %d", loaded.MaxRedirects)
	}
	if !loaded.InsecureSkipVerify {
		t.Errorf("InsecureSkipVerify: expected true, got false")
	}
	if !loaded.AllowPrivateIPs {
		t.Errorf("AllowPrivateIPs: expected true, got false")
	}
	if !loaded.AllowLoopback {
		t.Errorf("AllowLoopback: expected true, got false")
	}
	if !loaded.ActiveVerification {
		t.Errorf("ActiveVerification: expected true, got false")
	}
	if loaded.Updates.Check != false {
		t.Errorf("Updates.Check: expected false, got %v", loaded.Updates.Check)
	}
	if loaded.Updates.AutoInstall != true {
		t.Errorf("Updates.AutoInstall: expected true, got %v", loaded.Updates.AutoInstall)
	}
}

func TestSave_ValidationFailure(t *testing.T) {
	tempDir := t.TempDir()
	t.Setenv("FELIX_DIR", tempDir)

	cfg := Default()
	cfg.Timeout = -10 // Invalid

	err := Save(cfg)
	if err == nil {
		t.Fatalf("expected Save() with invalid config to fail, but it succeeded")
	}

	p, _ := Path()
	if _, err := os.Stat(p); !os.IsNotExist(err) {
		t.Fatalf("expected config file to not exist after failed Save()")
	}
}

func TestLoad_MalformedJSONReturnsError(t *testing.T) {
	tempDir := t.TempDir()
	t.Setenv("FELIX_DIR", tempDir)

	p, err := Path()
	if err != nil {
		t.Fatalf("Path() error: %v", err)
	}

	if err := os.WriteFile(p, []byte(`{invalid-json`), 0644); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	_, err = Load()
	if err == nil {
		t.Fatalf("expected Load() to return error on malformed JSON, got nil")
	}
	if !strings.Contains(err.Error(), "malformed configuration file") {
		t.Errorf("expected error containing 'malformed configuration file', got: %v", err)
	}
}

func TestLoad_CorruptedScopeReturnsError(t *testing.T) {
	tempDir := t.TempDir()
	t.Setenv("FELIX_DIR", tempDir)

	p, err := Path()
	if err != nil {
		t.Fatalf("Path() error: %v", err)
	}

	// Corrupted scope on disk
	jsonContent := `{"timeout": 22, "scope": "arbitrary-internet"}`
	if err := os.WriteFile(p, []byte(jsonContent), 0644); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	_, err = Load()
	if err == nil {
		t.Fatalf("expected Load() to return error on corrupted scope, got nil")
	}
	if !strings.Contains(err.Error(), "invalid scope") {
		t.Errorf("expected error containing 'invalid scope', got: %v", err)
	}
}

func TestLoad_CorruptedNumericReturnsError(t *testing.T) {
	tempDir := t.TempDir()
	t.Setenv("FELIX_DIR", tempDir)

	p, err := Path()
	if err != nil {
		t.Fatalf("Path() error: %v", err)
	}

	// Corrupted numeric field on disk
	jsonContent := `{"timeout": -10}`
	if err := os.WriteFile(p, []byte(jsonContent), 0644); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	_, err = Load()
	if err == nil {
		t.Fatalf("expected Load() to return error on corrupted timeout, got nil")
	}
	if !strings.Contains(err.Error(), "timeout must be greater than 0") {
		t.Errorf("expected error containing 'timeout must be greater than 0', got: %v", err)
	}
}

func TestLoad_OmittedUpdatesRetainsDefault(t *testing.T) {
	tempDir := t.TempDir()
	t.Setenv("FELIX_DIR", tempDir)

	p, err := Path()
	if err != nil {
		t.Fatalf("Path() error: %v", err)
	}

	// updates field completely omitted
	jsonContent := `{"timeout": 18, "concurrency": 8}`
	if err := os.WriteFile(p, []byte(jsonContent), 0644); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() failed: %v", err)
	}

	if cfg.Timeout != 18 {
		t.Errorf("expected Timeout 18, got %d", cfg.Timeout)
	}
	if cfg.Concurrency != 8 {
		t.Errorf("expected Concurrency 8, got %d", cfg.Concurrency)
	}
	if !cfg.Updates.Check {
		t.Errorf("expected Updates.Check to retain default true when omitted")
	}
	if cfg.Updates.AutoInstall {
		t.Errorf("expected Updates.AutoInstall to retain default false when omitted")
	}
}

func TestReset(t *testing.T) {
	tempDir := t.TempDir()
	t.Setenv("FELIX_DIR", tempDir)

	p, err := Path()
	if err != nil {
		t.Fatalf("Path() error: %v", err)
	}

	// Reset when file doesn't exist should succeed
	if err := Reset(); err != nil {
		t.Fatalf("Reset() when no file exists returned error: %v", err)
	}

	// Save a config
	if err := Save(Default()); err != nil {
		t.Fatalf("Save() error: %v", err)
	}
	if _, err := os.Stat(p); err != nil {
		t.Fatalf("expected config file to exist: %v", err)
	}

	// Reset should remove the file
	if err := Reset(); err != nil {
		t.Fatalf("Reset() failed: %v", err)
	}
	if _, err := os.Stat(p); !os.IsNotExist(err) {
		t.Fatalf("expected config file to be removed by Reset()")
	}
}

func TestParseConfig(t *testing.T) {
	// 1. Empty bytes return default configuration
	cfgDefault, err := ParseConfig(nil)
	if err != nil {
		t.Fatalf("ParseConfig(nil) failed: %v", err)
	}
	if cfgDefault.Timeout != DefaultTimeoutSeconds {
		t.Errorf("expected default timeout %d, got %d", DefaultTimeoutSeconds, cfgDefault.Timeout)
	}

	cfgEmpty, err := ParseConfig([]byte("   "))
	if err != nil {
		t.Fatalf("ParseConfig(whitespace) failed: %v", err)
	}
	if cfgEmpty.Concurrency != DefaultConcurrency {
		t.Errorf("expected default concurrency %d, got %d", DefaultConcurrency, cfgEmpty.Concurrency)
	}

	// 2. Custom values override defaults, omitted fields get defaults
	customJSON := []byte(`{"timeout": 45, "concurrency": 20, "scope": "subdomains"}`)
	cfgCustom, err := ParseConfig(customJSON)
	if err != nil {
		t.Fatalf("ParseConfig(customJSON) failed: %v", err)
	}
	if cfgCustom.Timeout != 45 {
		t.Errorf("expected timeout 45, got %d", cfgCustom.Timeout)
	}
	if cfgCustom.Concurrency != 20 {
		t.Errorf("expected concurrency 20, got %d", cfgCustom.Concurrency)
	}
	if cfgCustom.Scope != "subdomains" {
		t.Errorf("expected scope subdomains, got %s", cfgCustom.Scope)
	}
	if cfgCustom.MaxAssets != DefaultMaxAssets {
		t.Errorf("expected omitted field MaxAssets to have default %d, got %d", DefaultMaxAssets, cfgCustom.MaxAssets)
	}

	// 3. Malformed JSON returns an error containing "malformed configuration"
	_, errMalformed := ParseConfig([]byte(`{not valid json`))
	if errMalformed == nil {
		t.Fatalf("expected error for malformed JSON, got nil")
	}
	if !strings.Contains(errMalformed.Error(), "malformed configuration") {
		t.Errorf("expected 'malformed configuration' in error, got: %v", errMalformed)
	}

	// 4. Invalid configuration values fail validation
	_, errInvalid := ParseConfig([]byte(`{"concurrency": -1}`))
	if errInvalid == nil {
		t.Fatalf("expected error for negative concurrency, got nil")
	}
	if !strings.Contains(errInvalid.Error(), "configuration validation failed") {
		t.Errorf("expected 'configuration validation failed' in error, got: %v", errInvalid)
	}
}

func TestLoadWithEnv_FileErrorFormatting(t *testing.T) {
	tempDir := t.TempDir()
	t.Setenv("FELIX_DIR", tempDir)

	badFile := filepath.Join(tempDir, "config.json")

	// Test malformed JSON formatting
	if err := os.WriteFile(badFile, []byte(`{broken json`), 0600); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}
	_, err := LoadWithEnv(badFile)
	if err == nil {
		t.Fatalf("expected error for malformed file, got nil")
	}
	if !strings.HasPrefix(err.Error(), fmt.Sprintf("malformed configuration file %q:", badFile)) {
		t.Errorf("unexpected error format for malformed file: %v", err)
	}

	// Test validation failure formatting
	if err := os.WriteFile(badFile, []byte(`{"concurrency": -10}`), 0600); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}
	_, err = LoadWithEnv(badFile)
	if err == nil {
		t.Fatalf("expected error for invalid config file, got nil")
	}
	if !strings.HasPrefix(err.Error(), "configuration file validation failed:") {
		t.Errorf("unexpected error format for validation failure: %v", err)
	}
}
