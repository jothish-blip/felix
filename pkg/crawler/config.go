package crawler

import (
	"context"
	"net"
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
	Concurrency        int                     `json:"concurrency"`
	Timeout            time.Duration           `json:"timeout"`
	MaxAssetSize       int64                   `json:"max_asset_size"`
	MaxAssets          int                     `json:"max_assets,omitempty"`
	MaxDepth           int                     `json:"max_depth,omitempty"`
	MaxRetries         int                     `json:"max_retries,omitempty"`
	RetryDelay         time.Duration           `json:"retry_delay,omitempty"`
	MaxRedirects       int                     `json:"max_redirects,omitempty"`
	UserAgent          string                  `json:"user_agent"`
	ScopeMode          ScopeMode               `json:"scope_mode"`
	AllowedHosts       []string                `json:"allowed_hosts"`
	InsecureSkipVerify bool                    `json:"insecure_skip_verify"`
	RateLimit          float64                 `json:"rate_limit,omitempty"`
	Client             *http.Client            `json:"-"`
	IsAllowed          func(string) bool       `json:"-"`
	IsExcluded         func(string) bool       `json:"-"`
	BrowserDiscovery   BrowserDiscoveryOptions `json:"browser_discovery,omitempty"`
	Progress           func(string)            `json:"-"`

	// AllowLoopback permits loopback IP addresses (127.0.0.0/8, ::1).
	// Default is false (strictly blocked for SSRF protection).
	AllowLoopback bool `json:"allow_loopback,omitempty"`

	// AllowPrivateIPs permits RFC 1918 private subnets and IPv6 ULA.
	// Default is false (strictly blocked for SSRF protection).
	AllowPrivateIPs bool `json:"allow_private_ips,omitempty"`

	// Resolver allows injecting a custom DNS resolver for testing or enterprise resolution.
	Resolver Resolver `json:"-"`

	// DialFunc allows injecting a mock network dialer for offline testing.
	DialFunc func(ctx context.Context, network, addr string) (net.Conn, error) `json:"-"`
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
