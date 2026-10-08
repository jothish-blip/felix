package crawler

import (
	"net/http"
	"time"
)

const (
	DefaultConcurrency  = 10
	DefaultTimeout      = 10 * time.Second
	DefaultMaxAssetSize = 10 * 1024 * 1024 // 10 MB default limit
	DefaultUserAgent    = "Felix/0.1"
)

// Config defines crawler runtime options.
type Config struct {
	Concurrency  int           `json:"concurrency"`
	Timeout      time.Duration `json:"timeout"`
	MaxAssetSize int64         `json:"max_asset_size"`
	MaxAssets    int           `json:"max_assets,omitempty"`
	UserAgent    string        `json:"user_agent"`
	ScopeMode          ScopeMode     `json:"scope_mode"`
	AllowedHosts       []string      `json:"allowed_hosts"`
	InsecureSkipVerify bool          `json:"insecure_skip_verify"`
	Client             *http.Client  `json:"-"`
}

// DefaultConfig provides sensible defaults for web auditing.
func DefaultConfig() Config {
	return Config{
		Concurrency:  DefaultConcurrency,
		Timeout:      DefaultTimeout,
		MaxAssetSize: DefaultMaxAssetSize,
		UserAgent:    DefaultUserAgent,
		ScopeMode:    ScopeSameOrigin,
	}
}
