package config

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"felix/pkg/secrets"
)

// Default settings for Felix auditor.
const (
	DefaultTimeoutSeconds     = 10
	DefaultConcurrency        = 10
	DefaultScope              = "same-origin"
	DefaultMaxSizeMB          = 10
	DefaultUserAgent          = "Mozilla/5.0 (compatible; Felix/1.0; +https://github.com/jothish-blip/felix)"
	DefaultMaxAssets          = 200
	DefaultMaxDepth           = 3
	DefaultMaxRetries         = 2
	DefaultRetryDelayMs       = 200
	DefaultMaxRedirects       = 5
	DefaultInsecureSkipVerify = false
	DefaultAllowPrivateIPs    = false
	DefaultAllowLoopback      = false
	DefaultActiveVerification = false
)

// UpdateConfig holds optional preferences for Felix release checks.
type UpdateConfig struct {
	Check       bool `json:"check"`        // Check for updates on appropriate triggers
	AutoInstall bool `json:"auto_install"` // Automatic installation (always false by default)
}

// NotificationConfig holds settings for assessment alerting and webhook dispatching.
type NotificationConfig struct {
	Enabled                   bool     `json:"enabled"`                               // Master switch for notification generation
	Provider                  string   `json:"provider"`                              // Notification provider (default "webhook")
	WebhookURL                string   `json:"webhook_url"`                           // Destination HTTPS webhook URL
	WebhookSecret             string   `json:"webhook_secret,omitempty"`              // Optional HMAC-SHA256 signature secret
	WebhookPreviousSecret     string   `json:"webhook_previous_secret,omitempty"`     // Optional previous HMAC secret for key rotation
	RequireSigning            bool     `json:"require_signing"`                       // Fail closed if webhook deliveries cannot be signed
	SignatureToleranceSeconds int      `json:"signature_tolerance_seconds,omitempty"` // Timestamp tolerance window for replay defense (1..3600)
	TimeoutSeconds            int      `json:"timeout_seconds"`                       // Request timeout in seconds (1..300)
	MaxRetries                int      `json:"max_retries"`                           // Maximum retry attempts for transient delivery failures (0..10)
	MinSeverity               string   `json:"min_severity"`                          // Minimum severity threshold (CRITICAL, HIGH, MEDIUM, LOW, INFO)
	NotifyOnLifecycle         []string `json:"notify_on_lifecycle"`                   // Lifecycle events to alert on (completed, failed, interrupted, etc.)
	NotifyOnDeltas            []string `json:"notify_on_deltas"`                      // Security delta classifications to alert on (new, regressed, changed, resolved)
	AllowInsecureHTTP         bool     `json:"allow_insecure_http"`                   // Allow unencrypted HTTP webhooks (default false)
	AllowPrivateIPs           bool     `json:"allow_private_ips"`                     // Allow webhooks to private/internal IPs (default false)
	AllowLoopback             bool     `json:"allow_loopback"`                        // Allow webhooks to loopback/127.0.0.1 (default false)
	Concurrency               int      `json:"concurrency"`                           // Concurrency for background outbox workers (1..50)
}

// Config holds operational settings for Felix CLI and scanning pipelines.
type Config struct {
	Timeout            int                `json:"timeout"`               // Request timeout in seconds (1..3600)
	Concurrency        int                `json:"concurrency"`           // Concurrent worker threads (1..1000)
	Scope              string             `json:"scope"`                 // same-origin, subdomains, explicit
	MaxSizeMB          int                `json:"max_size_mb"`           // Max asset size in MB (1..1024)
	UserAgent          string             `json:"user_agent"`            // User-Agent string
	MaxAssets          int                `json:"max_assets"`            // Maximum assets discovered/budgeted (1..10000)
	MaxDepth           int                `json:"max_depth"`             // Maximum crawl depth (1..20)
	MaxRetries         int                `json:"max_retries"`           // Maximum network retries (0..10)
	RetryDelayMs       int                `json:"retry_delay_ms"`        // Retry delay in milliseconds (0..5000)
	MaxRedirects       int                `json:"max_redirects"`         // Maximum HTTP redirects to follow (0..20)
	InsecureSkipVerify bool               `json:"insecure_skip_verify"`  // Skip TLS certificate verification (default false)
	AllowPrivateIPs    bool               `json:"allow_private_ips"`     // Allow RFC 1918 private subnets (default false)
	AllowLoopback      bool               `json:"allow_loopback"`        // Allow 127.0.0.0/8 loopback (default false)
	ActiveVerification bool               `json:"active_verification"`   // Permit active verification probes (default false)
	PolicyPath         string             `json:"policy_path,omitempty"` // Default path to security threshold policy file
	Updates            UpdateConfig       `json:"updates"`               // Update configuration
	Notification       NotificationConfig `json:"notification"`          // Alerting and notification settings
}

// diskConfigWire is used during disk unmarshaling to accurately distinguish explicitly present JSON fields.
type diskConfigWire struct {
	Timeout            *int                `json:"timeout"`
	Concurrency        *int                `json:"concurrency"`
	Scope              *string             `json:"scope"`
	MaxSizeMB          *int                `json:"max_size_mb"`
	UserAgent          *string             `json:"user_agent"`
	MaxAssets          *int                `json:"max_assets"`
	MaxDepth           *int                `json:"max_depth"`
	MaxRetries         *int                `json:"max_retries"`
	RetryDelayMs       *int                `json:"retry_delay_ms"`
	MaxRedirects       *int                `json:"max_redirects"`
	InsecureSkipVerify *bool               `json:"insecure_skip_verify"`
	AllowPrivateIPs    *bool               `json:"allow_private_ips"`
	AllowLoopback      *bool               `json:"allow_loopback"`
	ActiveVerification *bool               `json:"active_verification"`
	PolicyPath         *string             `json:"policy_path,omitempty"`
	Updates            *UpdateConfig       `json:"updates"`
	Notification       *NotificationConfig `json:"notification"`
}

// Default returns standard, defensive configuration defaults.
func Default() Config {
	return Config{
		Timeout:            DefaultTimeoutSeconds,
		Concurrency:        DefaultConcurrency,
		Scope:              DefaultScope,
		MaxSizeMB:          DefaultMaxSizeMB,
		UserAgent:          DefaultUserAgent,
		MaxAssets:          DefaultMaxAssets,
		MaxDepth:           DefaultMaxDepth,
		MaxRetries:         DefaultMaxRetries,
		RetryDelayMs:       DefaultRetryDelayMs,
		MaxRedirects:       DefaultMaxRedirects,
		InsecureSkipVerify: DefaultInsecureSkipVerify,
		AllowPrivateIPs:    DefaultAllowPrivateIPs,
		AllowLoopback:      DefaultAllowLoopback,
		ActiveVerification: DefaultActiveVerification,
		Updates: UpdateConfig{
			Check:       true,
			AutoInstall: false,
		},
		Notification: NotificationConfig{
			Enabled:                   false,
			Provider:                  "webhook",
			WebhookURL:                "",
			WebhookSecret:             "",
			WebhookPreviousSecret:     "",
			RequireSigning:            false,
			SignatureToleranceSeconds: 300,
			TimeoutSeconds:            10,
			MaxRetries:                3,
			MinSeverity:               "LOW",
			NotifyOnLifecycle:         []string{"completed", "completed_with_errors", "failed", "interrupted"},
			NotifyOnDeltas:            []string{"new", "regressed", "changed"},
			AllowInsecureHTTP:         false,
			AllowPrivateIPs:           false,
			AllowLoopback:             false,
			Concurrency:               5,
		},
	}
}

// Validate checks that the configuration values are within safe and functional operational bounds.
func (c Config) Validate() error {
	if c.Timeout <= 0 {
		return fmt.Errorf("timeout must be greater than 0 seconds (got %d)", c.Timeout)
	}
	if c.Timeout > 3600 {
		return fmt.Errorf("timeout cannot exceed 3600 seconds (got %d)", c.Timeout)
	}
	if c.Concurrency <= 0 {
		return fmt.Errorf("concurrency must be greater than 0 (got %d)", c.Concurrency)
	}
	if c.Concurrency > 1000 {
		return fmt.Errorf("concurrency cannot exceed 1000 workers (got %d)", c.Concurrency)
	}
	scopeLower := strings.ToLower(strings.TrimSpace(c.Scope))
	if scopeLower != "same-origin" && scopeLower != "subdomains" && scopeLower != "explicit" {
		return fmt.Errorf("invalid scope %q: must be one of: same-origin, subdomains, explicit", secrets.RedactText(c.Scope))
	}
	if c.MaxSizeMB <= 0 {
		return fmt.Errorf("max_size_mb must be greater than 0 MB (got %d)", c.MaxSizeMB)
	}
	if c.MaxSizeMB > 1024 {
		return fmt.Errorf("max_size_mb cannot exceed 1024 MB (got %d)", c.MaxSizeMB)
	}
	if strings.TrimSpace(c.UserAgent) == "" {
		return fmt.Errorf("user_agent cannot be empty")
	}
	if strings.ContainsAny(c.UserAgent, "\r\n") {
		return fmt.Errorf("user_agent cannot contain newline or carriage return characters")
	}
	if c.MaxAssets <= 0 {
		return fmt.Errorf("max_assets must be greater than 0 (got %d)", c.MaxAssets)
	}
	if c.MaxAssets > 10000 {
		return fmt.Errorf("max_assets cannot exceed 10000 (got %d)", c.MaxAssets)
	}
	if c.MaxDepth <= 0 {
		return fmt.Errorf("max_depth must be greater than 0 (got %d)", c.MaxDepth)
	}
	if c.MaxDepth > 20 {
		return fmt.Errorf("max_depth cannot exceed 20 (got %d)", c.MaxDepth)
	}
	if c.MaxRetries < 0 {
		return fmt.Errorf("max_retries cannot be negative (got %d)", c.MaxRetries)
	}
	if c.MaxRetries > 10 {
		return fmt.Errorf("max_retries cannot exceed 10 (got %d)", c.MaxRetries)
	}
	if c.RetryDelayMs < 0 {
		return fmt.Errorf("retry_delay_ms cannot be negative (got %d)", c.RetryDelayMs)
	}
	if c.RetryDelayMs > 5000 {
		return fmt.Errorf("retry_delay_ms cannot exceed 5000 ms (got %d)", c.RetryDelayMs)
	}
	if c.MaxRedirects < 0 {
		return fmt.Errorf("max_redirects cannot be negative (got %d)", c.MaxRedirects)
	}
	if c.MaxRedirects > 20 {
		return fmt.Errorf("max_redirects cannot exceed 20 (got %d)", c.MaxRedirects)
	}

	// Notification validation
	if c.Notification.Enabled {
		prov := strings.ToLower(strings.TrimSpace(c.Notification.Provider))
		switch prov {
		case "webhook", "slack", "discord", "teams":
			// supported
		default:
			return fmt.Errorf("invalid notification provider %q: currently supported: webhook, slack, discord, teams", secrets.RedactText(c.Notification.Provider))
		}
		rawURL := strings.TrimSpace(c.Notification.WebhookURL)
		if rawURL == "" {
			return fmt.Errorf("webhook_url cannot be empty when notifications are enabled")
		}
		parsedURL, err := url.Parse(rawURL)
		if err != nil || parsedURL.Host == "" {
			return fmt.Errorf("invalid webhook_url %q: must be a valid URL", secrets.RedactText(rawURL))
		}
		scheme := strings.ToLower(parsedURL.Scheme)
		if scheme != "https" {
			if scheme == "http" {
				if !c.Notification.AllowInsecureHTTP {
					return fmt.Errorf("insecure HTTP webhook_url %q prohibited; HTTPS is required unless allow_insecure_http is true", secrets.RedactText(rawURL))
				}
			} else {
				return fmt.Errorf("unsupported webhook_url scheme %q: must be https (or http if allow_insecure_http is set)", scheme)
			}
		}
		if c.Notification.RequireSigning && strings.TrimSpace(c.Notification.WebhookSecret) == "" {
			return fmt.Errorf("notification require_signing is true, but webhook_secret is empty")
		}
		if c.Notification.SignatureToleranceSeconds < 0 || c.Notification.SignatureToleranceSeconds > 3600 {
			return fmt.Errorf("notification signature_tolerance_seconds must be between 1 and 3600 (got %d)", c.Notification.SignatureToleranceSeconds)
		}
		if c.Notification.TimeoutSeconds <= 0 || c.Notification.TimeoutSeconds > 300 {
			return fmt.Errorf("notification timeout_seconds must be between 1 and 300 (got %d)", c.Notification.TimeoutSeconds)
		}
		if c.Notification.MaxRetries < 0 || c.Notification.MaxRetries > 10 {
			return fmt.Errorf("notification max_retries must be between 0 and 10 (got %d)", c.Notification.MaxRetries)
		}
		if c.Notification.Concurrency <= 0 || c.Notification.Concurrency > 50 {
			return fmt.Errorf("notification concurrency must be between 1 and 50 (got %d)", c.Notification.Concurrency)
		}
		if sev := strings.ToUpper(strings.TrimSpace(c.Notification.MinSeverity)); sev != "" {
			switch sev {
			case "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO":
			default:
				return fmt.Errorf("invalid notification min_severity %q: must be one of CRITICAL, HIGH, MEDIUM, LOW, INFO", secrets.RedactText(c.Notification.MinSeverity))
			}
		}
	}

	return nil
}

// Dir returns the path to the Felix configuration directory (~/.felix or $FELIX_DIR).
func Dir() (string, error) {
	if d := os.Getenv("FELIX_DIR"); d != "" {
		return d, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".felix"), nil
}

// Path returns the path to the configuration file (~/.felix/config.json or $FELIX_CONFIG).
func Path() (string, error) {
	if p := os.Getenv("FELIX_CONFIG"); p != "" {
		return p, nil
	}
	dir, err := Dir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "config.json"), nil
}

// applyEnv reads environment variables (FELIX_*) and applies them over cfg.
// Returns an actionable error if any environment variable has an invalid value.
func applyEnv(cfg *Config) error {
	// 1. FELIX_TIMEOUT
	if v, ok := os.LookupEnv("FELIX_TIMEOUT"); ok {
		v = strings.TrimSpace(v)
		if v == "" {
			return fmt.Errorf("FELIX_TIMEOUT cannot be empty")
		}
		if d, err := time.ParseDuration(v); err == nil {
			sec := int(d.Seconds())
			if d > 0 && sec == 0 {
				sec = 1
			}
			if sec <= 0 || sec > 3600 {
				return fmt.Errorf("FELIX_TIMEOUT duration %q out of bounds: must be between 1s and 3600s", secrets.RedactText(v))
			}
			cfg.Timeout = sec
		} else {
			n, err := strconv.Atoi(v)
			if err != nil || n <= 0 || n > 3600 {
				return fmt.Errorf("invalid FELIX_TIMEOUT %q: must be a positive integer between 1 and 3600 seconds", secrets.RedactText(v))
			}
			cfg.Timeout = n
		}
	}

	// 2. FELIX_CONCURRENCY
	if v, ok := os.LookupEnv("FELIX_CONCURRENCY"); ok {
		v = strings.TrimSpace(v)
		n, err := strconv.Atoi(v)
		if err != nil || n <= 0 || n > 1000 {
			return fmt.Errorf("invalid FELIX_CONCURRENCY %q: must be a positive integer between 1 and 1000", secrets.RedactText(v))
		}
		cfg.Concurrency = n
	}

	// 3. FELIX_SCOPE
	if v, ok := os.LookupEnv("FELIX_SCOPE"); ok {
		vLower := strings.ToLower(strings.TrimSpace(v))
		if vLower != "same-origin" && vLower != "subdomains" && vLower != "explicit" {
			return fmt.Errorf("invalid FELIX_SCOPE %q: must be one of: same-origin, subdomains, explicit", secrets.RedactText(v))
		}
		cfg.Scope = vLower
	}

	// 4. FELIX_MAX_SIZE_MB
	if v, ok := os.LookupEnv("FELIX_MAX_SIZE_MB"); ok {
		v = strings.TrimSpace(v)
		n, err := strconv.Atoi(v)
		if err != nil || n <= 0 || n > 1024 {
			return fmt.Errorf("invalid FELIX_MAX_SIZE_MB %q: must be a positive integer between 1 and 1024", secrets.RedactText(v))
		}
		cfg.MaxSizeMB = n
	}

	// 5. FELIX_USER_AGENT
	if v, ok := os.LookupEnv("FELIX_USER_AGENT"); ok {
		v = strings.TrimSpace(v)
		if v == "" {
			return fmt.Errorf("FELIX_USER_AGENT cannot be empty")
		}
		if strings.ContainsAny(v, "\r\n") {
			return fmt.Errorf("FELIX_USER_AGENT cannot contain newline characters")
		}
		cfg.UserAgent = v
	}

	// 6. FELIX_MAX_ASSETS
	if v, ok := os.LookupEnv("FELIX_MAX_ASSETS"); ok {
		v = strings.TrimSpace(v)
		n, err := strconv.Atoi(v)
		if err != nil || n <= 0 || n > 10000 {
			return fmt.Errorf("invalid FELIX_MAX_ASSETS %q: must be a positive integer between 1 and 10000", secrets.RedactText(v))
		}
		cfg.MaxAssets = n
	}

	// 7. FELIX_MAX_DEPTH
	if v, ok := os.LookupEnv("FELIX_MAX_DEPTH"); ok {
		v = strings.TrimSpace(v)
		n, err := strconv.Atoi(v)
		if err != nil || n <= 0 || n > 20 {
			return fmt.Errorf("invalid FELIX_MAX_DEPTH %q: must be a positive integer between 1 and 20", secrets.RedactText(v))
		}
		cfg.MaxDepth = n
	}

	// 8. FELIX_MAX_RETRIES
	if v, ok := os.LookupEnv("FELIX_MAX_RETRIES"); ok {
		v = strings.TrimSpace(v)
		n, err := strconv.Atoi(v)
		if err != nil || n < 0 || n > 10 {
			return fmt.Errorf("invalid FELIX_MAX_RETRIES %q: must be an integer between 0 and 10", secrets.RedactText(v))
		}
		cfg.MaxRetries = n
	}

	// 9. FELIX_RETRY_DELAY_MS
	if v, ok := os.LookupEnv("FELIX_RETRY_DELAY_MS"); ok {
		v = strings.TrimSpace(v)
		n, err := strconv.Atoi(v)
		if err != nil || n < 0 || n > 5000 {
			return fmt.Errorf("invalid FELIX_RETRY_DELAY_MS %q: must be an integer between 0 and 5000", secrets.RedactText(v))
		}
		cfg.RetryDelayMs = n
	}

	// 10. FELIX_MAX_REDIRECTS
	if v, ok := os.LookupEnv("FELIX_MAX_REDIRECTS"); ok {
		v = strings.TrimSpace(v)
		n, err := strconv.Atoi(v)
		if err != nil || n < 0 || n > 20 {
			return fmt.Errorf("invalid FELIX_MAX_REDIRECTS %q: must be an integer between 0 and 20", secrets.RedactText(v))
		}
		cfg.MaxRedirects = n
	}

	// 11. FELIX_INSECURE_SKIP_VERIFY
	if v, ok := os.LookupEnv("FELIX_INSECURE_SKIP_VERIFY"); ok {
		b, err := strconv.ParseBool(strings.TrimSpace(v))
		if err != nil {
			return fmt.Errorf("invalid FELIX_INSECURE_SKIP_VERIFY %q: must be true or false", secrets.RedactText(v))
		}
		cfg.InsecureSkipVerify = b
	}

	// 12. FELIX_ALLOW_PRIVATE_IPS
	if v, ok := os.LookupEnv("FELIX_ALLOW_PRIVATE_IPS"); ok {
		b, err := strconv.ParseBool(strings.TrimSpace(v))
		if err != nil {
			return fmt.Errorf("invalid FELIX_ALLOW_PRIVATE_IPS %q: must be true or false", secrets.RedactText(v))
		}
		cfg.AllowPrivateIPs = b
	}

	// 13. FELIX_ALLOW_LOOPBACK
	if v, ok := os.LookupEnv("FELIX_ALLOW_LOOPBACK"); ok {
		b, err := strconv.ParseBool(strings.TrimSpace(v))
		if err != nil {
			return fmt.Errorf("invalid FELIX_ALLOW_LOOPBACK %q: must be true or false", secrets.RedactText(v))
		}
		cfg.AllowLoopback = b
	}

	// 14. FELIX_ACTIVE_VERIFICATION
	if v, ok := os.LookupEnv("FELIX_ACTIVE_VERIFICATION"); ok {
		b, err := strconv.ParseBool(strings.TrimSpace(v))
		if err != nil {
			return fmt.Errorf("invalid FELIX_ACTIVE_VERIFICATION %q: must be true or false", secrets.RedactText(v))
		}
		cfg.ActiveVerification = b
	}

	// 15. FELIX_UPDATE_CHECK
	if v, ok := os.LookupEnv("FELIX_UPDATE_CHECK"); ok {
		b, err := strconv.ParseBool(strings.TrimSpace(v))
		if err != nil {
			return fmt.Errorf("invalid FELIX_UPDATE_CHECK %q: must be true or false", secrets.RedactText(v))
		}
		cfg.Updates.Check = b
	}

	// 16. FELIX_AUTO_INSTALL
	if v, ok := os.LookupEnv("FELIX_AUTO_INSTALL"); ok {
		b, err := strconv.ParseBool(strings.TrimSpace(v))
		if err != nil {
			return fmt.Errorf("invalid FELIX_AUTO_INSTALL %q: must be true or false", secrets.RedactText(v))
		}
		cfg.Updates.AutoInstall = b
	}

	// 17. FELIX_NOTIFY_ENABLED
	if v, ok := os.LookupEnv("FELIX_NOTIFY_ENABLED"); ok {
		b, err := strconv.ParseBool(strings.TrimSpace(v))
		if err != nil {
			return fmt.Errorf("invalid FELIX_NOTIFY_ENABLED %q: must be true or false", secrets.RedactText(v))
		}
		cfg.Notification.Enabled = b
	}

	// 18. FELIX_NOTIFY_PROVIDER
	if v, ok := os.LookupEnv("FELIX_NOTIFY_PROVIDER"); ok {
		v = strings.TrimSpace(v)
		if v == "" {
			return fmt.Errorf("FELIX_NOTIFY_PROVIDER cannot be empty")
		}
		cfg.Notification.Provider = v
	}

	// 19. FELIX_NOTIFY_WEBHOOK_URL
	if v, ok := os.LookupEnv("FELIX_NOTIFY_WEBHOOK_URL"); ok {
		v = strings.TrimSpace(v)
		cfg.Notification.WebhookURL = v
	}

	// 20. FELIX_NOTIFY_WEBHOOK_SECRET
	if v, ok := os.LookupEnv("FELIX_NOTIFY_WEBHOOK_SECRET"); ok {
		cfg.Notification.WebhookSecret = strings.TrimSpace(v)
	}

	// 20a. FELIX_NOTIFY_PREVIOUS_SECRET
	if v, ok := os.LookupEnv("FELIX_NOTIFY_PREVIOUS_SECRET"); ok {
		cfg.Notification.WebhookPreviousSecret = strings.TrimSpace(v)
	}

	// 20b. FELIX_NOTIFY_REQUIRE_SIGNING
	if v, ok := os.LookupEnv("FELIX_NOTIFY_REQUIRE_SIGNING"); ok {
		b, err := strconv.ParseBool(strings.TrimSpace(v))
		if err != nil {
			return fmt.Errorf("invalid FELIX_NOTIFY_REQUIRE_SIGNING %q: must be true or false", secrets.RedactText(v))
		}
		cfg.Notification.RequireSigning = b
	}

	// 20c. FELIX_NOTIFY_SIG_TOLERANCE
	if v, ok := os.LookupEnv("FELIX_NOTIFY_SIG_TOLERANCE"); ok {
		v = strings.TrimSpace(v)
		n, err := strconv.Atoi(v)
		if err != nil || n <= 0 || n > 3600 {
			return fmt.Errorf("invalid FELIX_NOTIFY_SIG_TOLERANCE %q: must be an integer between 1 and 3600 seconds", secrets.RedactText(v))
		}
		cfg.Notification.SignatureToleranceSeconds = n
	}

	// 21. FELIX_NOTIFY_TIMEOUT
	if v, ok := os.LookupEnv("FELIX_NOTIFY_TIMEOUT"); ok {
		v = strings.TrimSpace(v)
		n, err := strconv.Atoi(v)
		if err != nil || n <= 0 || n > 300 {
			return fmt.Errorf("invalid FELIX_NOTIFY_TIMEOUT %q: must be a positive integer between 1 and 300 seconds", secrets.RedactText(v))
		}
		cfg.Notification.TimeoutSeconds = n
	}

	// 22. FELIX_NOTIFY_MAX_RETRIES
	if v, ok := os.LookupEnv("FELIX_NOTIFY_MAX_RETRIES"); ok {
		v = strings.TrimSpace(v)
		n, err := strconv.Atoi(v)
		if err != nil || n < 0 || n > 10 {
			return fmt.Errorf("invalid FELIX_NOTIFY_MAX_RETRIES %q: must be an integer between 0 and 10", secrets.RedactText(v))
		}
		cfg.Notification.MaxRetries = n
	}

	// 23. FELIX_NOTIFY_MIN_SEVERITY
	if v, ok := os.LookupEnv("FELIX_NOTIFY_MIN_SEVERITY"); ok {
		v = strings.ToUpper(strings.TrimSpace(v))
		switch v {
		case "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO":
			cfg.Notification.MinSeverity = v
		default:
			return fmt.Errorf("invalid FELIX_NOTIFY_MIN_SEVERITY %q: must be one of CRITICAL, HIGH, MEDIUM, LOW, INFO", secrets.RedactText(v))
		}
	}

	// 24. FELIX_NOTIFY_ALLOW_INSECURE_HTTP
	if v, ok := os.LookupEnv("FELIX_NOTIFY_ALLOW_INSECURE_HTTP"); ok {
		b, err := strconv.ParseBool(strings.TrimSpace(v))
		if err != nil {
			return fmt.Errorf("invalid FELIX_NOTIFY_ALLOW_INSECURE_HTTP %q: must be true or false", secrets.RedactText(v))
		}
		cfg.Notification.AllowInsecureHTTP = b
	}

	// 25. FELIX_NOTIFY_ALLOW_PRIVATE_IPS
	if v, ok := os.LookupEnv("FELIX_NOTIFY_ALLOW_PRIVATE_IPS"); ok {
		b, err := strconv.ParseBool(strings.TrimSpace(v))
		if err != nil {
			return fmt.Errorf("invalid FELIX_NOTIFY_ALLOW_PRIVATE_IPS %q: must be true or false", secrets.RedactText(v))
		}
		cfg.Notification.AllowPrivateIPs = b
	}

	// 26. FELIX_NOTIFY_ALLOW_LOOPBACK
	if v, ok := os.LookupEnv("FELIX_NOTIFY_ALLOW_LOOPBACK"); ok {
		b, err := strconv.ParseBool(strings.TrimSpace(v))
		if err != nil {
			return fmt.Errorf("invalid FELIX_NOTIFY_ALLOW_LOOPBACK %q: must be true or false", secrets.RedactText(v))
		}
		cfg.Notification.AllowLoopback = b
	}
	if cfg.AllowLoopback {
		cfg.Notification.AllowLoopback = true
	}

	// 27. FELIX_NOTIFY_CONCURRENCY
	if v, ok := os.LookupEnv("FELIX_NOTIFY_CONCURRENCY"); ok {
		v = strings.TrimSpace(v)
		n, err := strconv.Atoi(v)
		if err != nil || n <= 0 || n > 50 {
			return fmt.Errorf("invalid FELIX_NOTIFY_CONCURRENCY %q: must be an integer between 1 and 50", secrets.RedactText(v))
		}
		cfg.Notification.Concurrency = n
	}

	// 28. FELIX_POLICY_PATH / FELIX_POLICY
	if v, ok := os.LookupEnv("FELIX_POLICY_PATH"); ok {
		cfg.PolicyPath = strings.TrimSpace(v)
	} else if v, ok := os.LookupEnv("FELIX_POLICY"); ok {
		cfg.PolicyPath = strings.TrimSpace(v)
	}

	return nil
}

// LoadWithEnv loads configuration enforcing strict precedence:
// 1. Built-in defaults
// 2. Configuration file (p, or default Path() if p is empty)
// 3. Environment variables (FELIX_*)
// Any invalid value from higher-precedence sources produces an actionable validation error.
// ParseConfig parses and validates raw JSON configuration bytes, populating defaults for omitted fields.
// MaxConfigFileSize defines the maximum permitted size (10 MB) for configuration files and payloads.
const MaxConfigFileSize int64 = 10 * 1024 * 1024

// ParseConfig deserializes configuration JSON bytes into a validated Config struct with defaults.
func ParseConfig(data []byte) (Config, error) {
	if int64(len(data)) > MaxConfigFileSize {
		return Config{}, fmt.Errorf("configuration payload size (%d bytes) exceeds maximum permitted limit (%d bytes)", len(data), MaxConfigFileSize)
	}
	cfg := Default()
	if len(strings.TrimSpace(string(data))) == 0 {
		return cfg, nil
	}
	var diskCfg diskConfigWire
	if err := json.Unmarshal(data, &diskCfg); err != nil {
		return cfg, fmt.Errorf("malformed configuration: %w", err)
	}
	if diskCfg.Timeout != nil {
		cfg.Timeout = *diskCfg.Timeout
	}
	if diskCfg.Concurrency != nil {
		cfg.Concurrency = *diskCfg.Concurrency
	}
	if diskCfg.Scope != nil {
		cfg.Scope = strings.ToLower(strings.TrimSpace(*diskCfg.Scope))
	}
	if diskCfg.MaxSizeMB != nil {
		cfg.MaxSizeMB = *diskCfg.MaxSizeMB
	}
	if diskCfg.UserAgent != nil {
		cfg.UserAgent = *diskCfg.UserAgent
	}
	if diskCfg.MaxAssets != nil {
		cfg.MaxAssets = *diskCfg.MaxAssets
	}
	if diskCfg.MaxDepth != nil {
		cfg.MaxDepth = *diskCfg.MaxDepth
	}
	if diskCfg.MaxRetries != nil {
		cfg.MaxRetries = *diskCfg.MaxRetries
	}
	if diskCfg.RetryDelayMs != nil {
		cfg.RetryDelayMs = *diskCfg.RetryDelayMs
	}
	if diskCfg.MaxRedirects != nil {
		cfg.MaxRedirects = *diskCfg.MaxRedirects
	}
	if diskCfg.InsecureSkipVerify != nil {
		cfg.InsecureSkipVerify = *diskCfg.InsecureSkipVerify
	}
	if diskCfg.AllowPrivateIPs != nil {
		cfg.AllowPrivateIPs = *diskCfg.AllowPrivateIPs
	}
	if diskCfg.AllowLoopback != nil {
		cfg.AllowLoopback = *diskCfg.AllowLoopback
	}
	if diskCfg.ActiveVerification != nil {
		cfg.ActiveVerification = *diskCfg.ActiveVerification
	}
	if diskCfg.PolicyPath != nil {
		cfg.PolicyPath = *diskCfg.PolicyPath
	}
	if diskCfg.Updates != nil {
		cfg.Updates.Check = diskCfg.Updates.Check
		cfg.Updates.AutoInstall = diskCfg.Updates.AutoInstall
	}
	if diskCfg.Notification != nil {
		n := *diskCfg.Notification
		cfg.Notification = n
	}

	if err := cfg.Validate(); err != nil {
		return cfg, fmt.Errorf("configuration validation failed: %w", err)
	}
	return cfg, nil
}

func LoadWithEnv(p string) (Config, error) {
	cfg := Default()
	if p == "" {
		var err error
		p, err = Path()
		if err != nil {
			return cfg, fmt.Errorf("failed to determine configuration path: %w", err)
		}
	}

	fi, statErr := os.Stat(p)
	if statErr == nil {
		if fi.Size() > MaxConfigFileSize {
			return cfg, fmt.Errorf("configuration file %q size (%d bytes) exceeds maximum permitted limit (%d bytes)", p, fi.Size(), MaxConfigFileSize)
		}
		data, err := os.ReadFile(p)
		if err != nil {
			return cfg, fmt.Errorf("failed to read configuration file %q: %w", p, err)
		}
		c, err := ParseConfig(data)
		if err != nil {
			if strings.Contains(err.Error(), "malformed configuration") {
				return cfg, fmt.Errorf("malformed configuration file %q: %w", p, err)
			}
			return cfg, fmt.Errorf("configuration file validation failed: %w", err)
		}
		cfg = c
	} else if !os.IsNotExist(statErr) {
		return cfg, fmt.Errorf("failed to read configuration file %q: %w", p, statErr)
	}

	// Merge environment variables
	if err := applyEnv(&cfg); err != nil {
		return cfg, err
	}

	// Validate final merged configuration
	if err := cfg.Validate(); err != nil {
		return cfg, fmt.Errorf("effective configuration validation failed: %w", err)
	}

	return cfg, nil
}

// Load loads configuration from the default path (~/.felix/config.json or $FELIX_CONFIG)
// merged with environment variables (FELIX_*).
// A genuinely absent optional configuration file returns defaults without error.
// An existing but unreadable, malformed, or invalid configuration file, or invalid
// environment variables, returns an actionable error to prevent silent unsafe fallbacks.
func Load() (Config, error) {
	return LoadWithEnv("")
}

// Save writes the configuration to disk after validation.
func Save(cfg Config) error {
	if err := cfg.Validate(); err != nil {
		return fmt.Errorf("cannot save invalid configuration: %w", err)
	}

	p, err := Path()
	if err != nil {
		return err
	}

	dir := filepath.Dir(p)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}

	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(p, data, 0644)
}

// Reset restores default configuration and removes the config file if present.
func Reset() error {
	p, err := Path()
	if err != nil {
		return err
	}
	if err := os.Remove(p); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

// Get returns the string value of a named configuration key.
func (c Config) Get(key string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(key)) {
	case "timeout":
		return strconv.Itoa(c.Timeout), nil
	case "concurrency":
		return strconv.Itoa(c.Concurrency), nil
	case "scope":
		return c.Scope, nil
	case "max_size_mb", "max-size-mb", "maxsize":
		return strconv.Itoa(c.MaxSizeMB), nil
	case "user_agent", "user-agent", "useragent":
		return c.UserAgent, nil
	case "max_assets", "max-assets", "maxassets":
		return strconv.Itoa(c.MaxAssets), nil
	case "max_depth", "max-depth", "maxdepth":
		return strconv.Itoa(c.MaxDepth), nil
	case "max_retries", "max-retries", "maxretries":
		return strconv.Itoa(c.MaxRetries), nil
	case "retry_delay_ms", "retry-delay-ms", "retrydelay":
		return strconv.Itoa(c.RetryDelayMs), nil
	case "max_redirects", "max-redirects", "maxredirects":
		return strconv.Itoa(c.MaxRedirects), nil
	case "insecure_skip_verify", "insecure-skip-verify", "insecure":
		return strconv.FormatBool(c.InsecureSkipVerify), nil
	case "allow_private_ips", "allow-private-ips", "allow_private", "allow-private":
		return strconv.FormatBool(c.AllowPrivateIPs), nil
	case "allow_loopback", "allow-loopback":
		return strconv.FormatBool(c.AllowLoopback), nil
	case "active_verification", "active-verification", "active":
		return strconv.FormatBool(c.ActiveVerification), nil
	case "update_check", "update-check", "updates.check":
		return strconv.FormatBool(c.Updates.Check), nil
	case "auto_install", "auto-install", "updates.auto_install":
		return strconv.FormatBool(c.Updates.AutoInstall), nil
	case "policy_path", "policy-path", "policy":
		return c.PolicyPath, nil
	default:
		safeKey := secrets.RedactText(key)
		return "", fmt.Errorf("unknown configuration key %q (available: timeout, concurrency, scope, max_size_mb, user_agent, max_assets, max_depth, max_retries, retry_delay_ms, max_redirects, insecure_skip_verify, allow_private_ips, allow_loopback, active_verification, update_check, auto_install, policy_path)", safeKey)
	}
}

// Set updates the value of a named configuration key.
func (c *Config) Set(key, val string) error {
	k := strings.ToLower(strings.TrimSpace(key))
	v := strings.TrimSpace(val)

	switch k {
	case "timeout":
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > 3600 {
			return fmt.Errorf("timeout must be a positive integer between 1 and 3600 seconds")
		}
		c.Timeout = n
	case "concurrency":
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > 1000 {
			return fmt.Errorf("concurrency must be a positive integer between 1 and 1000")
		}
		c.Concurrency = n
	case "scope":
		vLower := strings.ToLower(v)
		if vLower != "same-origin" && vLower != "subdomains" && vLower != "explicit" {
			return fmt.Errorf("scope must be one of: same-origin, subdomains, explicit")
		}
		c.Scope = vLower
	case "max_size_mb", "max-size-mb", "maxsize":
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > 1024 {
			return fmt.Errorf("max_size_mb must be a positive integer between 1 and 1024 MB")
		}
		c.MaxSizeMB = n
	case "user_agent", "user-agent", "useragent":
		if v == "" {
			return fmt.Errorf("user_agent cannot be empty")
		}
		if strings.ContainsAny(v, "\r\n") {
			return fmt.Errorf("user_agent cannot contain newline or carriage return characters")
		}
		c.UserAgent = v
	case "max_assets", "max-assets", "maxassets":
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > 10000 {
			return fmt.Errorf("max_assets must be a positive integer between 1 and 10000")
		}
		c.MaxAssets = n
	case "max_depth", "max-depth", "maxdepth":
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > 20 {
			return fmt.Errorf("max_depth must be a positive integer between 1 and 20")
		}
		c.MaxDepth = n
	case "max_retries", "max-retries", "maxretries":
		n, err := strconv.Atoi(v)
		if err != nil || n < 0 || n > 10 {
			return fmt.Errorf("max_retries must be an integer between 0 and 10")
		}
		c.MaxRetries = n
	case "retry_delay_ms", "retry-delay-ms", "retrydelay":
		n, err := strconv.Atoi(v)
		if err != nil || n < 0 || n > 5000 {
			return fmt.Errorf("retry_delay_ms must be an integer between 0 and 5000")
		}
		c.RetryDelayMs = n
	case "max_redirects", "max-redirects", "maxredirects":
		n, err := strconv.Atoi(v)
		if err != nil || n < 0 || n > 20 {
			return fmt.Errorf("max_redirects must be an integer between 0 and 20")
		}
		c.MaxRedirects = n
	case "insecure_skip_verify", "insecure-skip-verify", "insecure":
		b, err := strconv.ParseBool(v)
		if err != nil {
			return fmt.Errorf("insecure_skip_verify must be true or false")
		}
		c.InsecureSkipVerify = b
	case "allow_private_ips", "allow-private-ips", "allow_private", "allow-private":
		b, err := strconv.ParseBool(v)
		if err != nil {
			return fmt.Errorf("allow_private_ips must be true or false")
		}
		c.AllowPrivateIPs = b
	case "allow_loopback", "allow-loopback":
		b, err := strconv.ParseBool(v)
		if err != nil {
			return fmt.Errorf("allow_loopback must be true or false")
		}
		c.AllowLoopback = b
	case "active_verification", "active-verification", "active":
		b, err := strconv.ParseBool(v)
		if err != nil {
			return fmt.Errorf("active_verification must be true or false")
		}
		c.ActiveVerification = b
	case "update_check", "update-check", "updates.check":
		b, err := strconv.ParseBool(v)
		if err != nil {
			return fmt.Errorf("update_check must be true or false")
		}
		c.Updates.Check = b
	case "auto_install", "auto-install", "updates.auto_install":
		b, err := strconv.ParseBool(v)
		if err != nil {
			return fmt.Errorf("auto_install must be true or false")
		}
		c.Updates.AutoInstall = b
	case "policy_path", "policy-path", "policy":
		c.PolicyPath = v
	default:
		safeKey := secrets.RedactText(key)
		return fmt.Errorf("unknown configuration key %q (available: timeout, concurrency, scope, max_size_mb, user_agent, max_assets, max_depth, max_retries, retry_delay_ms, max_redirects, insecure_skip_verify, allow_private_ips, allow_loopback, active_verification, update_check, auto_install, policy_path)", safeKey)
	}

	return nil
}
