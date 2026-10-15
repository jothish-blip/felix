package assessment

import (
	"fmt"
	"net/url"
	"strings"

	"felix/pkg/crawler"
)

// ValidateTargetURL validates an assessment target URL according to strict security rules.
// Delegates to crawler.ValidateTargetURL for unified validation logic.
func ValidateTargetURL(raw string) (*url.URL, error) {
	return crawler.ValidateTargetURL(raw)
}

// NormalizeTargetURL returns a canonical representation of a target URL.
// Delegates to crawler.NormalizeTargetURL for unified normalization logic.
func NormalizeTargetURL(raw string) (string, error) {
	return crawler.NormalizeTargetURL(raw)
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
			cleanPattern := strings.TrimSpace(pattern)
			if !strings.HasPrefix(cleanPattern, "/") {
				cleanPattern = "/" + cleanPattern
			}
			cleanPrefix := strings.TrimRight(strings.TrimRight(cleanPattern, "*"), "/")
			if cleanPrefix == "" {
				return true, fmt.Sprintf("path %s matches excluded prefix %s (reason: %s)", path, pattern, exc.Reason)
			}
			if path == cleanPrefix || strings.HasPrefix(path, cleanPrefix+"/") {
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

	if strings.TrimSpace(rawURL) == "" {
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

	// Reject non-http(s) schemes explicitly (e.g. javascript:, data:, file:, mailto:)
	if parsed.Scheme != "" && !strings.EqualFold(parsed.Scheme, "http") && !strings.EqualFold(parsed.Scheme, "https") {
		return false
	}

	// Reject embedded credentials in candidate URLs
	if parsed.User != nil {
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
				if assetHost == targetHost && crawler.EffectivePort(parsed) == crawler.EffectivePort(targetParsed) {
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

	nextParsed, err := url.Parse(nextURL)
	if err != nil {
		return fmt.Errorf("invalid redirect URL %q: %w", nextURL, err)
	}

	scheme := strings.ToLower(nextParsed.Scheme)
	if scheme != "http" && scheme != "https" {
		return fmt.Errorf("redirect to unsupported scheme %q blocked", nextParsed.Scheme)
	}

	if nextParsed.User != nil {
		return fmt.Errorf("redirect with embedded credentials blocked")
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
		if err1 == nil && currParsed.Hostname() != "" && nextParsed.Hostname() != "" {
			currHost := strings.ToLower(currParsed.Hostname())
			nextHost := strings.ToLower(nextParsed.Hostname())
			if v.ScopeMode == "same-origin" || v.ScopeMode == "" {
				if currHost != nextHost || crawler.EffectivePort(currParsed) != crawler.EffectivePort(nextParsed) || (currParsed.Scheme != "" && nextParsed.Scheme != "" && !strings.EqualFold(currParsed.Scheme, nextParsed.Scheme)) {
					return fmt.Errorf("cross-origin redirect from %s to %s blocked in same-origin mode", currHost, nextHost)
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
