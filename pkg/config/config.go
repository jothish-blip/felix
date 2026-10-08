package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// Default settings for Felix auditor.
const (
	DefaultTimeoutSeconds = 10
	DefaultConcurrency    = 10
	DefaultScope          = "same-origin"
	DefaultMaxSizeMB      = 10
	DefaultUserAgent      = "Mozilla/5.0 (compatible; Felix/1.0; +https://github.com/jothish-blip/felix)"
)

// Config holds operational settings for Felix CLI and scanning pipelines.
type Config struct {
	Timeout     int    `json:"timeout"`       // Request timeout in seconds
	Concurrency int    `json:"concurrency"`   // Concurrent worker threads
	Scope       string `json:"scope"`         // same-origin, subdomains, explicit
	MaxSizeMB   int    `json:"max_size_mb"`   // Max asset size in MB
	UserAgent   string `json:"user_agent"`    // User-Agent string
}

// Default returns standard, defensive configuration defaults.
func Default() Config {
	return Config{
		Timeout:     DefaultTimeoutSeconds,
		Concurrency: DefaultConcurrency,
		Scope:       DefaultScope,
		MaxSizeMB:   DefaultMaxSizeMB,
		UserAgent:   DefaultUserAgent,
	}
}

// Dir returns the path to the Felix configuration directory (~/.felix).
func Dir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".felix"), nil
}

// Path returns the path to the configuration file (~/.felix/config.json).
func Path() (string, error) {
	dir, err := Dir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "config.json"), nil
}

// Load loads configuration from disk. If the file does not exist, defaults are returned.
func Load() Config {
	cfg := Default()
	p, err := Path()
	if err != nil {
		return cfg
	}

	data, err := os.ReadFile(p)
	if err != nil {
		return cfg
	}

	var diskCfg Config
	if err := json.Unmarshal(data, &diskCfg); err != nil {
		return cfg
	}

	if diskCfg.Timeout > 0 {
		cfg.Timeout = diskCfg.Timeout
	}
	if diskCfg.Concurrency > 0 {
		cfg.Concurrency = diskCfg.Concurrency
	}
	if diskCfg.Scope != "" {
		cfg.Scope = diskCfg.Scope
	}
	if diskCfg.MaxSizeMB > 0 {
		cfg.MaxSizeMB = diskCfg.MaxSizeMB
	}
	if diskCfg.UserAgent != "" {
		cfg.UserAgent = diskCfg.UserAgent
	}

	return cfg
}

// Save writes the configuration to disk.
func Save(cfg Config) error {
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
	default:
		return "", fmt.Errorf("unknown configuration key %q (available: timeout, concurrency, scope, max_size_mb, user_agent)", key)
	}
}

// Set updates the value of a named configuration key.
func (c *Config) Set(key, val string) error {
	k := strings.ToLower(strings.TrimSpace(key))
	v := strings.TrimSpace(val)

	switch k {
	case "timeout":
		n, err := strconv.Atoi(v)
		if err != nil || n <= 0 {
			return fmt.Errorf("timeout must be a positive integer in seconds")
		}
		c.Timeout = n
	case "concurrency":
		n, err := strconv.Atoi(v)
		if err != nil || n <= 0 {
			return fmt.Errorf("concurrency must be a positive integer")
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
		if err != nil || n <= 0 {
			return fmt.Errorf("max_size_mb must be a positive integer")
		}
		c.MaxSizeMB = n
	case "user_agent", "user-agent", "useragent":
		if v == "" {
			return fmt.Errorf("user_agent cannot be empty")
		}
		c.UserAgent = v
	default:
		return fmt.Errorf("unknown configuration key %q (available: timeout, concurrency, scope, max_size_mb, user_agent)", key)
	}

	return nil
}
