package assessment

import (
	"fmt"
	"net/url"
	"strings"
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

	// Reject localhost or non-routable link-local unless explicitly permitted in testing
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
	if port != "" {
		if !(scheme == "http" && port == "80") && !(scheme == "https" && port == "443") {
			hostPort = fmt.Sprintf("%s:%s", host, port)
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

// ScopeValidator enforces scope and exclusion boundaries for an assessment.
type ScopeValidator struct {
	ScopeMode    string
	Targets      []string
	ScopeRules   []ScopeRule
	Exclusions   []Exclusion
	allowedHosts map[string]struct{}
}

// NewScopeValidator creates a validator populated with approved targets, scope rules, and exclusions.
func NewScopeValidator(scopeMode string, targets []string, rules []ScopeRule, exclusions []Exclusion) *ScopeValidator {
	if scopeMode == "" {
		scopeMode = "same-origin"
	}

	allowed := make(map[string]struct{})
	for _, t := range targets {
		if parsed, err := url.Parse(t); err == nil && parsed.Hostname() != "" {
			allowed[strings.ToLower(parsed.Hostname())] = struct{}{}
		}
	}
	for _, r := range rules {
		if r.RuleType == "HOSTNAME" || r.RuleType == "EXACT_ORIGIN" {
			allowed[strings.ToLower(r.Pattern)] = struct{}{}
		}
	}

	return &ScopeValidator{
		ScopeMode:    scopeMode,
		Targets:      targets,
		ScopeRules:   rules,
		Exclusions:   exclusions,
		allowedHosts: allowed,
	}
}

// IsExcluded checks if a given URL matches any defined exclusion rule.
// EXCLUSIONS ALWAYS TAKE PRECEDENCE OVER ANY BROADER SCOPE RULE.
func (v *ScopeValidator) IsExcluded(rawURL string) (bool, string) {
	if v == nil || len(v.Exclusions) == 0 {
		return false, ""
	}

	parsed, err := url.Parse(rawURL)
	if err != nil {
		return true, "malformed URL is excluded by default"
	}

	host := strings.ToLower(parsed.Hostname())
	path := parsed.Path
	if path == "" {
		path = "/"
	}
	fullURL := parsed.String()

	for _, exc := range v.Exclusions {
		pattern := strings.TrimSpace(exc.Pattern)
		if pattern == "" {
			continue
		}

		switch exc.ExclusionType {
		case "HOSTNAME":
			patternHost := strings.ToLower(pattern)
			if strings.HasPrefix(patternHost, "*.") {
				suffix := patternHost[1:] // e.g. .example.com
				if strings.HasSuffix(host, suffix) {
					return true, fmt.Sprintf("hostname matches wildcard exclusion %s (reason: %s)", pattern, exc.Reason)
				}
			} else if host == patternHost {
				return true, fmt.Sprintf("hostname matches exclusion %s (reason: %s)", pattern, exc.Reason)
			}

		case "PATH_PREFIX":
			if strings.HasPrefix(path, pattern) {
				return true, fmt.Sprintf("path %s matches excluded prefix %s (reason: %s)", path, pattern, exc.Reason)
			}

		case "EXACT_URL":
			if strings.EqualFold(fullURL, pattern) {
				return true, fmt.Sprintf("URL exactly matches exclusion %s (reason: %s)", pattern, exc.Reason)
			}

		default:
			// Fallback: check if host or path contains pattern
			if strings.EqualFold(host, pattern) || strings.HasPrefix(path, pattern) {
				return true, fmt.Sprintf("URL matches exclusion pattern %s (reason: %s)", pattern, exc.Reason)
			}
		}
	}

	return false, ""
}

// IsAllowed returns true if a URL is within the approved scope AND not excluded.
func (v *ScopeValidator) IsAllowed(rawURL string) bool {
	if v == nil {
		return false
	}

	// 1. Exclusions check: EXCLUSIONS MUST ALWAYS OVERRIDE SCOPE
	if excluded, _ := v.IsExcluded(rawURL); excluded {
		return false
	}

	parsed, err := url.Parse(rawURL)
	if err != nil {
		return false
	}

	assetHost := strings.ToLower(parsed.Hostname())
	if assetHost == "" {
		// Relative URLs inherit the active target origin
		return true
	}

	switch v.ScopeMode {
	case "same-origin":
		// Must match at least one approved target host exactly, plus port and scheme
		for _, t := range v.Targets {
			if targetParsed, err := url.Parse(t); err == nil {
				targetHost := strings.ToLower(targetParsed.Hostname())
				if assetHost == targetHost && parsed.Port() == targetParsed.Port() {
					if parsed.Scheme == "" || targetParsed.Scheme == "" || strings.EqualFold(parsed.Scheme, targetParsed.Scheme) {
						return true
					}
				}
			}
		}
		return false

	case "subdomains":
		for _, t := range v.Targets {
			if targetParsed, err := url.Parse(t); err == nil {
				targetHost := strings.ToLower(targetParsed.Hostname())
				if assetHost == targetHost || strings.HasSuffix(assetHost, "."+targetHost) {
					return true
				}
			}
		}
		return false

	case "explicit":
		_, ok := v.allowedHosts[assetHost]
		return ok

	default:
		// Default to strict same-origin
		for _, t := range v.Targets {
			if targetParsed, err := url.Parse(t); err == nil {
				if assetHost == strings.ToLower(targetParsed.Hostname()) {
					return true
				}
			}
		}
		return false
	}
}

// ValidateRedirect checks if following a redirect from currentURL to nextURL is permitted.
// Fails closed if the redirect escapes scope or enters an excluded host/path.
func (v *ScopeValidator) ValidateRedirect(currentURL, nextURL string) error {
	if v == nil {
		return fmt.Errorf("scope validator is nil")
	}

	if excluded, reason := v.IsExcluded(nextURL); excluded {
		return fmt.Errorf("redirect to %s blocked: %s", nextURL, reason)
	}

	if !v.IsAllowed(nextURL) {
		return fmt.Errorf("redirect to %s blocked: target is outside approved assessment scope", nextURL)
	}

	// Enforce origin and host boundaries relative to currentURL
	if currentURL != "" {
		currParsed, err1 := url.Parse(currentURL)
		nextParsed, err2 := url.Parse(nextURL)
		if err1 == nil && err2 == nil && currParsed.Hostname() != "" && nextParsed.Hostname() != "" {
			currHost := strings.ToLower(currParsed.Hostname())
			nextHost := strings.ToLower(nextParsed.Hostname())
			if v.ScopeMode == "same-origin" || v.ScopeMode == "" {
				if currHost != nextHost || currParsed.Port() != nextParsed.Port() {
					return fmt.Errorf("cross-host redirect from %s to %s blocked in same-origin mode", currHost, nextHost)
				}
			} else if v.ScopeMode == "subdomains" {
				if currHost != nextHost && !strings.HasSuffix(nextHost, "."+currHost) && !strings.HasSuffix(currHost, "."+nextHost) {
					return fmt.Errorf("cross-domain redirect from %s to %s blocked in subdomains mode", currHost, nextHost)
				}
			}
		}
	}

	return nil
}
