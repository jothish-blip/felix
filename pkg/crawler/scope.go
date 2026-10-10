package crawler

import (
	"fmt"
	"net/url"
	"strings"
)

// ScopeMode defines the domain restriction strategy for asset fetching.
type ScopeMode string

const (
	ScopeSameOrigin ScopeMode = "same-origin"
	ScopeSubdomains ScopeMode = "subdomains"
	ScopeExplicit   ScopeMode = "explicit"
)

// Scope controls which assets the crawler is permitted to fetch.
type Scope struct {
	Mode         ScopeMode
	TargetURL    *url.URL
	allowedHosts map[string]struct{}
}

// NewScope initializes scope boundaries based on the target URL and mode.
func NewScope(rawTarget string, mode ScopeMode, allowedHosts ...string) (*Scope, error) {
	if mode == "" {
		mode = ScopeSameOrigin
	}

	parsed, err := url.Parse(rawTarget)
	if err != nil {
		return nil, fmt.Errorf("invalid target URL for scope: %w", err)
	}

	hosts := make(map[string]struct{})
	if parsed.Hostname() != "" {
		hosts[strings.ToLower(parsed.Hostname())] = struct{}{}
	}
	for _, h := range allowedHosts {
		h = strings.ToLower(strings.TrimSpace(h))
		if h != "" {
			hosts[h] = struct{}{}
		}
	}

	return &Scope{
		Mode:         mode,
		TargetURL:    parsed,
		allowedHosts: hosts,
	}, nil
}

// IsAllowed returns true if an asset URL is within the authorized scope.
func (s *Scope) IsAllowed(rawURL string) bool {
	if s == nil || s.TargetURL == nil {
		return true
	}

	if strings.TrimSpace(rawURL) == "" {
		return false
	}

	parsed, err := url.Parse(rawURL)
	if err != nil {
		return false
	}

	// Reject non-http(s) schemes explicitly (e.g. javascript:, data:, file:, mailto:)
	if parsed.Scheme != "" && !strings.EqualFold(parsed.Scheme, "http") && !strings.EqualFold(parsed.Scheme, "https") {
		return false
	}

	assetHost := strings.ToLower(parsed.Hostname())
	targetHost := strings.ToLower(s.TargetURL.Hostname())

	// Relative URLs without a hostname inherit the target origin.
	if assetHost == "" {
		return true
	}

	switch s.Mode {
	case ScopeSameOrigin:
		if assetHost != targetHost {
			return false
		}
		if parsed.Port() != s.TargetURL.Port() {
			return false
		}
		if parsed.Scheme != "" && s.TargetURL.Scheme != "" && !strings.EqualFold(parsed.Scheme, s.TargetURL.Scheme) {
			return false
		}
		return true

	case ScopeSubdomains:
		if assetHost == targetHost {
			return true
		}
		return strings.HasSuffix(assetHost, "."+targetHost)

	case ScopeExplicit:
		if assetHost == targetHost {
			return true
		}
		_, ok := s.allowedHosts[assetHost]
		return ok

	default:
		return assetHost == targetHost
	}
}
