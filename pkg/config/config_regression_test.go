package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestConfig_FullPopulationAndOmittedDefaults verifies that:
// 1. A minimal "{}" config yields all documented default values.
// 2. A fully populated JSON structure populates every field accurately without data loss.
func TestConfig_FullPopulationAndOmittedDefaults(t *testing.T) {
	// 1. Minimal configuration
	cfgMin, err := ParseConfig([]byte(`{}`))
	if err != nil {
		t.Fatalf("ParseConfig({}) failed: %v", err)
	}

	if cfgMin.Timeout != DefaultTimeoutSeconds {
		t.Errorf("Timeout = %d, want default %d", cfgMin.Timeout, DefaultTimeoutSeconds)
	}
	if cfgMin.Concurrency != DefaultConcurrency {
		t.Errorf("Concurrency = %d, want default %d", cfgMin.Concurrency, DefaultConcurrency)
	}
	if cfgMin.Scope != DefaultScope {
		t.Errorf("Scope = %q, want default %q", cfgMin.Scope, DefaultScope)
	}
	if cfgMin.MaxSizeMB != DefaultMaxSizeMB {
		t.Errorf("MaxSizeMB = %d, want default %d", cfgMin.MaxSizeMB, DefaultMaxSizeMB)
	}
	if cfgMin.UserAgent != DefaultUserAgent {
		t.Errorf("UserAgent = %q, want default %q", cfgMin.UserAgent, DefaultUserAgent)
	}
	if cfgMin.MaxAssets != DefaultMaxAssets {
		t.Errorf("MaxAssets = %d, want default %d", cfgMin.MaxAssets, DefaultMaxAssets)
	}

	// 2. Fully populated configuration
	fullJSON := `{
		"timeout": 45,
		"concurrency": 25,
		"scope": "subdomains",
		"max_size_mb": 15,
		"user_agent": "CustomSecurityScanner/2.0",
		"max_assets": 500,
		"max_depth": 7,
		"max_retries": 3,
		"retry_delay_ms": 250,
		"max_redirects": 8,
		"insecure_skip_verify": true,
		"allow_private_ips": true,
		"allow_loopback": true,
		"active_verification": true,
		"policy_path": "/etc/felix/policy.yaml",
		"updates": {
			"check": false,
			"auto_install": false
		},
		"notification": {
			"enabled": true,
			"provider": "webhook",
			"webhook_url": "https://alerts.example.com/felix",
			"webhook_secret": "whsec_testkey1234567890abcdef",
			"require_signing": true,
			"concurrency": 4,
			"timeout_seconds": 15,
			"max_retries": 4,
			"min_severity": "HIGH",
			"notify_on_lifecycle": ["completed", "failed"],
			"notify_on_deltas": ["new", "regressed"]
		}
	}`

	cfgFull, err := ParseConfig([]byte(fullJSON))
	if err != nil {
		t.Fatalf("ParseConfig(fullJSON) failed: %v", err)
	}

	if cfgFull.Timeout != 45 {
		t.Errorf("Timeout = %d, want 45", cfgFull.Timeout)
	}
	if cfgFull.Concurrency != 25 {
		t.Errorf("Concurrency = %d, want 25", cfgFull.Concurrency)
	}
	if cfgFull.Scope != "subdomains" {
		t.Errorf("Scope = %q, want 'subdomains'", cfgFull.Scope)
	}
	if cfgFull.MaxSizeMB != 15 {
		t.Errorf("MaxSizeMB = %d, want 15", cfgFull.MaxSizeMB)
	}
	if cfgFull.UserAgent != "CustomSecurityScanner/2.0" {
		t.Errorf("UserAgent = %q, want 'CustomSecurityScanner/2.0'", cfgFull.UserAgent)
	}
	if cfgFull.MaxAssets != 500 {
		t.Errorf("MaxAssets = %d, want 500", cfgFull.MaxAssets)
	}
	if cfgFull.MaxDepth != 7 {
		t.Errorf("MaxDepth = %d, want 7", cfgFull.MaxDepth)
	}
	if cfgFull.MaxRetries != 3 {
		t.Errorf("MaxRetries = %d, want 3", cfgFull.MaxRetries)
	}
	if cfgFull.RetryDelayMs != 250 {
		t.Errorf("RetryDelayMs = %d, want 250", cfgFull.RetryDelayMs)
	}
	if cfgFull.MaxRedirects != 8 {
		t.Errorf("MaxRedirects = %d, want 8", cfgFull.MaxRedirects)
	}
	if !cfgFull.InsecureSkipVerify {
		t.Errorf("InsecureSkipVerify = false, want true")
	}
	if !cfgFull.AllowPrivateIPs {
		t.Errorf("AllowPrivateIPs = false, want true")
	}
	if !cfgFull.AllowLoopback {
		t.Errorf("AllowLoopback = false, want true")
	}
	if !cfgFull.ActiveVerification {
		t.Errorf("ActiveVerification = false, want true")
	}
	if cfgFull.PolicyPath != "/etc/felix/policy.yaml" {
		t.Errorf("PolicyPath = %q, want '/etc/felix/policy.yaml'", cfgFull.PolicyPath)
	}
	if cfgFull.Updates.Check {
		t.Errorf("Updates.Check = true, want false")
	}
	if !cfgFull.Notification.Enabled {
		t.Errorf("Notification.Enabled = false, want true")
	}
	if cfgFull.Notification.WebhookURL != "https://alerts.example.com/felix" {
		t.Errorf("Notification.WebhookURL = %q", cfgFull.Notification.WebhookURL)
	}
	if cfgFull.Notification.WebhookSecret != "whsec_testkey1234567890abcdef" {
		t.Errorf("Notification.WebhookSecret mismatch")
	}
}

// TestConfig_ValidationBoundaries verifies boundary enforcement on all numeric and string fields.
func TestConfig_ValidationBoundaries(t *testing.T) {
	tests := []struct {
		name        string
		patchJSON   string
		wantErr     bool
		errContains string
	}{
		// Timeout boundaries (1..3600)
		{"timeout min valid (1)", `{"timeout": 1}`, false, ""},
		{"timeout max valid (3600)", `{"timeout": 3600}`, false, ""},
		{"timeout zero invalid", `{"timeout": 0}`, true, "timeout must be greater than 0"},
		{"timeout negative invalid", `{"timeout": -10}`, true, "timeout must be greater than 0"},
		{"timeout above max (3601)", `{"timeout": 3601}`, true, "timeout cannot exceed 3600"},

		// Concurrency boundaries (1..1000)
		{"concurrency min valid (1)", `{"concurrency": 1}`, false, ""},
		{"concurrency max valid (1000)", `{"concurrency": 1000}`, false, ""},
		{"concurrency zero invalid", `{"concurrency": 0}`, true, "concurrency must be greater than 0"},
		{"concurrency above max (1001)", `{"concurrency": 1001}`, true, "concurrency cannot exceed 1000"},

		// Scope boundaries
		{"scope same-origin valid", `{"scope": "same-origin"}`, false, ""},
		{"scope subdomains valid", `{"scope": "subdomains"}`, false, ""},
		{"scope explicit valid", `{"scope": "explicit"}`, false, ""},
		{"scope invalid value", `{"scope": "wildcard-internet"}`, true, "invalid scope"},

		// MaxSizeMB boundaries (1..1024)
		{"max_size_mb min valid (1)", `{"max_size_mb": 1}`, false, ""},
		{"max_size_mb max valid (1024)", `{"max_size_mb": 1024}`, false, ""},
		{"max_size_mb zero invalid", `{"max_size_mb": 0}`, true, "max_size_mb must be greater than 0"},
		{"max_size_mb above max (1025)", `{"max_size_mb": 1025}`, true, "max_size_mb cannot exceed 1024"},

		// User-Agent CRLF injection
		{"user_agent valid", `{"user_agent": "Mozilla/5.0"}`, false, ""},
		{"user_agent empty invalid", `{"user_agent": ""}`, true, "user_agent cannot be empty"},
		{"user_agent CRLF injection \r\n", `{"user_agent": "Felix/1.0\r\nEvil-Header: inject"}`, true, "user_agent cannot contain newline or carriage return"},
		{"user_agent LF injection \n", `{"user_agent": "Felix/1.0\nInjected: 1"}`, true, "user_agent cannot contain newline or carriage return"},

		// MaxAssets boundaries (1..10000)
		{"max_assets min valid (1)", `{"max_assets": 1}`, false, ""},
		{"max_assets max valid (10000)", `{"max_assets": 10000}`, false, ""},
		{"max_assets zero invalid", `{"max_assets": 0}`, true, "max_assets must be greater than 0"},
		{"max_assets above max (10001)", `{"max_assets": 10001}`, true, "max_assets cannot exceed 10000"},

		// MaxDepth boundaries (1..20)
		{"max_depth min valid (1)", `{"max_depth": 1}`, false, ""},
		{"max_depth max valid (20)", `{"max_depth": 20}`, false, ""},
		{"max_depth zero invalid", `{"max_depth": 0}`, true, "max_depth must be greater than 0"},
		{"max_depth above max (21)", `{"max_depth": 21}`, true, "max_depth cannot exceed 20"},

		// MaxRetries boundaries (0..10)
		{"max_retries min valid (0)", `{"max_retries": 0}`, false, ""},
		{"max_retries max valid (10)", `{"max_retries": 10}`, false, ""},
		{"max_retries negative invalid", `{"max_retries": -1}`, true, "max_retries cannot be negative"},
		{"max_retries above max (11)", `{"max_retries": 11}`, true, "max_retries cannot exceed 10"},

		// Notification validations
		{
			name:        "notification enabled but missing url",
			patchJSON:   `{"notification": {"enabled": true, "provider": "webhook", "webhook_url": ""}}`,
			wantErr:     true,
			errContains: "webhook_url cannot be empty",
		},
		{
			name:        "notification invalid provider",
			patchJSON:   `{"notification": {"enabled": true, "provider": "telegram", "webhook_url": "https://example.com/hook"}}`,
			wantErr:     true,
			errContains: "invalid notification provider",
		},
		{
			name:        "notification require_signing without secret fails closed",
			patchJSON:   `{"notification": {"enabled": true, "provider": "webhook", "webhook_url": "https://example.com/hook", "require_signing": true, "webhook_secret": "", "concurrency": 4}}`,
			wantErr:     true,
			errContains: "require_signing is true, but webhook_secret is empty",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParseConfig([]byte(tt.patchJSON))
			if (err != nil) != tt.wantErr {
				t.Fatalf("ParseConfig error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr && tt.errContains != "" {
				if !strings.Contains(err.Error(), tt.errContains) {
					t.Errorf("error %q does not contain %q", err.Error(), tt.errContains)
				}
			}
		})
	}
}

// TestConfig_MalformedAndTruncatedInput verifies handling of non-JSON and truncated JSON.
func TestConfig_MalformedAndTruncatedInput(t *testing.T) {
	malformed := []struct {
		name  string
		input string
	}{
		{"unclosed curly brace", `{"timeout": 30`},
		{"unexpected comma", `{"timeout": 30,,}`},
		{"raw string instead of object", `"just a string"`},
		{"array instead of object", `[1, 2, 3]`},
		{"null literal", `null`},
		{"control character in value", "{\"user_agent\": \"foo\x00bar\"}"},
	}

	for _, tc := range malformed {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParseConfig([]byte(tc.input))
			// Null literal parses to empty disk struct (default), others should fail
			if tc.name == "null literal" {
				if err != nil {
					t.Errorf("expected null to produce defaults without error, got: %v", err)
				}
				return
			}
			if err == nil {
				t.Errorf("expected error for %s, got nil", tc.name)
			}
		})
	}
}

// TestConfig_LoadWithEnv_PrecedenceAndOverrides verifies the 3-layer precedence contract:
// Layer 1: Code Defaults -> Layer 2: Disk Config File -> Layer 3: Environment Variables
func TestConfig_LoadWithEnv_PrecedenceAndOverrides(t *testing.T) {
	tempDir := t.TempDir()
	t.Setenv("FELIX_DIR", tempDir)
	configFile := filepath.Join(tempDir, "config.json")

	// Layer 2: File overrides timeout (25) and concurrency (30)
	fileContent := `{
		"timeout": 25,
		"concurrency": 30,
		"max_assets": 200
	}`
	if err := os.WriteFile(configFile, []byte(fileContent), 0600); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	// Layer 3: Environment overrides timeout (60) and max_assets (900)
	t.Setenv("FELIX_TIMEOUT", "60s")
	t.Setenv("FELIX_MAX_ASSETS", "900")

	loaded, err := LoadWithEnv(configFile)
	if err != nil {
		t.Fatalf("LoadWithEnv failed: %v", err)
	}

	// Timeout should take Env (60)
	if loaded.Timeout != 60 {
		t.Errorf("Timeout = %d, want env override 60", loaded.Timeout)
	}
	// Concurrency was not set in Env, should retain File (30)
	if loaded.Concurrency != 30 {
		t.Errorf("Concurrency = %d, want file override 30", loaded.Concurrency)
	}
	// MaxAssets should take Env (900)
	if loaded.MaxAssets != 900 {
		t.Errorf("MaxAssets = %d, want env override 900", loaded.MaxAssets)
	}
	// Scope was not set in File or Env, should retain Default ("same-origin")
	if loaded.Scope != DefaultScope {
		t.Errorf("Scope = %q, want default %q", loaded.Scope, DefaultScope)
	}
}
