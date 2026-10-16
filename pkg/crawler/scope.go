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

// ValidateTargetURL validates an assessment target URL according to strict security rules:
// - Must be HTTP or HTTPS
// - Must have a valid, non-empty host
// - Must NOT contain embedded credentials (user:pass@host)
// - Must NOT be empty or purely whitespace
func ValidateTargetURL(raw string) (*url.URL, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return nil, fmt.Errorf("target URL cannot be empty")
	}

	parsed, err := url.Parse(trimmed)
	if err != nil {
		return nil, fmt.Errorf("invalid URL syntax: %w", err)
	}

	scheme := strings.ToLower(parsed.Scheme)
	if scheme != "http" && scheme != "https" {
		return nil, fmt.Errorf("unsupported URL scheme %q: only http and https are permitted", parsed.Scheme)
	}

	if parsed.User != nil {
		return nil, fmt.Errorf("embedded credentials in target URL are prohibited")
	}

	host := strings.TrimSpace(parsed.Hostname())
	if host == "" {
		return nil, fmt.Errorf("target URL must contain a valid hostname")
	}

	if strings.Contains(host, " ") {
		return nil, fmt.Errorf("invalid characters in target hostname")
	}

	return parsed, nil
}

// NormalizeTargetURL returns a canonical representation of a target URL.
func NormalizeTargetURL(raw string) (string, error) {
	u, err := ValidateTargetURL(raw)
	if err != nil {
		return "", err
	}

	scheme := strings.ToLower(u.Scheme)
	host := strings.ToLower(u.Hostname())
	port := u.Port()

	hostPort := host
	if strings.Contains(host, ":") && !strings.HasPrefix(host, "[") {
		hostPort = "[" + host + "]"
	}
	if port != "" {
		if !(scheme == "http" && port == "80") && !(scheme == "https" && port == "443") {
			hostPort = fmt.Sprintf("%s:%s", hostPort, port)
		}
	}

	path := u.EscapedPath()
	path = strings.TrimRight(path, "/")
	if path != "" && !strings.HasPrefix(path, "/") {
		path = "/" + path
	}

	normalized := fmt.Sprintf("%s://%s%s", scheme, hostPort, path)
	if u.RawQuery != "" {
		normalized = fmt.Sprintf("%s?%s", normalized, u.RawQuery)
	}

	return normalized, nil
}

// EffectivePort returns the normalized port string, treating default HTTP (80) and HTTPS (443) ports as empty.
func EffectivePort(u *url.URL) string {
	if u == nil {
		return ""
	}
	port := u.Port()
	if port == "" {
		return ""
	}
	scheme := strings.ToLower(u.Scheme)
	if (scheme == "http" && port == "80") || (scheme == "https" && port == "443") {
		return ""
	}
	return port
}

// Scope controls which assets the crawler is permitted to fetch.
type Scope struct {
	Mode             ScopeMode
	TargetURL        *url.URL
	allowedHosts     map[string]struct{}
	excludedHosts    map[string]struct{}
	excludedPrefixes []string
}

// NewScope initializes scope boundaries based on the target URL and mode.
func NewScope(rawTarget string, mode ScopeMode, allowedHosts ...string) (*Scope, error) {
	if mode == "" {
		mode = ScopeSameOrigin
	}

	parsed, err := ValidateTargetURL(rawTarget)
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
		Mode:             mode,
		TargetURL:        parsed,
		allowedHosts:     hosts,
		excludedHosts:    make(map[string]struct{}),
		excludedPrefixes: nil,
	}, nil
}

// ExcludeHost adds a hostname to the exclusion list.
func (s *Scope) ExcludeHost(host string) {
	if s == nil {
		return
	}
	h := strings.ToLower(strings.TrimSpace(host))
	if h != "" {
		if s.excludedHosts == nil {
			s.excludedHosts = make(map[string]struct{})
		}
		s.excludedHosts[h] = struct{}{}
	}
}

// ExcludePathPrefix adds a URL path prefix to the exclusion list.
func (s *Scope) ExcludePathPrefix(prefix string) {
	if s == nil {
		return
	}
	p := strings.TrimSpace(prefix)
	if p != "" {
		if !strings.HasPrefix(p, "/") {
			p = "/" + p
		}
		s.excludedPrefixes = append(s.excludedPrefixes, p)
	}
}

// IsExcluded checks if an asset URL matches any defined exclusion rules.
func (s *Scope) IsExcluded(rawURL string) (bool, string) {
	if s == nil {
		return false, ""
	}

	trimmed := strings.TrimSpace(rawURL)
	if trimmed == "" {
		return true, "empty URL is excluded"
	}

	parsed, err := url.Parse(trimmed)
	if err != nil {
		return true, "malformed URL is excluded"
	}

	host := strings.ToLower(parsed.Hostname())
	if host != "" {
		if _, excluded := s.excludedHosts[host]; excluded {
			return true, fmt.Sprintf("hostname %s is excluded by scope rule", host)
		}
		// Wildcard match for *.domain.com
		for eh := range s.excludedHosts {
			if strings.HasPrefix(eh, "*.") {
				suffix := eh[1:]
				if strings.HasSuffix(host, suffix) {
					return true, fmt.Sprintf("hostname %s matches wildcard exclusion %s", host, eh)
				}
			}
		}
	}

	path := parsed.Path
	if path == "" {
		path = "/"
	}
	for _, prefix := range s.excludedPrefixes {
		cleanPrefix := strings.TrimRight(prefix, "/")
		if path == cleanPrefix || strings.HasPrefix(path, cleanPrefix+"/") {
			return true, fmt.Sprintf("path %s matches excluded prefix %s", path, prefix)
		}
	}

	return false, ""
}

// IsAllowed returns true if an asset URL is within the authorized scope AND not excluded.
func (s *Scope) IsAllowed(rawURL string) bool {
	if s == nil || s.TargetURL == nil {
		return false
	}

	if strings.TrimSpace(rawURL) == "" {
		return false
	}

	// Exclusions always take precedence over broader scope rules
	if excluded, _ := s.IsExcluded(rawURL); excluded {
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

	// Reject embedded credentials in candidate URLs
	if parsed.User != nil {
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
		if EffectivePort(parsed) != EffectivePort(s.TargetURL) {
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

// IsPathInScope checks if a URL or path is strictly within the target's authorized path boundary.
// If the target has a root path ("" or "/"), any path on the authorized origin is in path scope.
// If the target has a subpath (e.g. "/hithaone" or "/app/v1"), the URL/path must equal the subpath
// or have the subpath followed immediately by a path separator ("/" or end of string).
// Similar-looking prefixes (e.g. "/hithaone-admin" or "/hithaone_evil") are STRICTLY REJECTED.
func (s *Scope) IsPathInScope(rawURL string) bool {
	if s == nil || s.TargetURL == nil {
		return false
	}

	trimmed := strings.TrimSpace(rawURL)
	if trimmed == "" {
		return false
	}

	parsed, err := url.Parse(trimmed)
	if err != nil {
		return false
	}

	// If an absolute URL is given, check host/origin first
	if parsed.Hostname() != "" {
		if !s.IsAllowed(trimmed) {
			return false
		}
	}

	targetPath := strings.TrimRight(s.TargetURL.Path, "/")
	if targetPath == "" || targetPath == "/" {
		return true
	}

	reqPath := parsed.Path
	if reqPath == "" {
		reqPath = "/"
	}
	cleanReqPath := strings.TrimRight(reqPath, "/")

	// Exact match: e.g. "/hithaone" == "/hithaone"
	if cleanReqPath == targetPath {
		return true
	}

	// Subpath match: must start with targetPath + "/"
	if strings.HasPrefix(cleanReqPath, targetPath+"/") {
		return true
	}

	return false
}
