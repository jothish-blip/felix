package crawler

import (
	"fmt"
	"net/url"
	"regexp"
	"strings"
)

var (
	// Dynamic segment patterns
	rxDynamicTemplateParam = regexp.MustCompile(`\$\{[^}]+\}`)
	rxDynamicColonParam    = regexp.MustCompile(`/:([a-zA-Z0-9_]+)`)
	rxDynamicBracketParam  = regexp.MustCompile(`/\[([a-zA-Z0-9_\.]+)\]`)

	// Sensitive query parameter names whose values should be redacted
	sensitiveQueryParamKeys = map[string]bool{
		"token":         true,
		"access_token":  true,
		"auth_token":    true,
		"refresh_token": true,
		"key":           true,
		"api_key":       true,
		"apikey":        true,
		"secret":        true,
		"password":      true,
		"passwd":        true,
		"auth":          true,
		"bearer":        true,
		"signature":     true,
		"sig":           true,
	}

	// Secret-looking token pattern in query string
	rxSecretTokenInQuery = regexp.MustCompile(`(?i)(?:token|key|secret|password|bearer|auth|sig)=([^&#\s]+)`)
)

// RouteNormalizationResult stores the outcome of normalizing a candidate route string.
type RouteNormalizationResult struct {
	NormalizedPath     string
	RawPath            string
	IsAbsolute         bool
	IsInScope          bool
	TargetHost         string
	StaticallyResolved bool
	Warnings           []string
}

// NormalizeRouteCandidate sanitizes, collapses dynamic parameters, redacts query secrets,
// and enforces target scope on a candidate route string.
func NormalizeRouteCandidate(rawPath string, scopeHost string) RouteNormalizationResult {
	res := RouteNormalizationResult{
		RawPath:            rawPath,
		StaticallyResolved: true,
		IsInScope:          true,
	}

	trimmed := strings.TrimSpace(rawPath)
	if trimmed == "" {
		res.Warnings = append(res.Warnings, "Empty route string")
		return res
	}

	// Reject dangerous non-HTTP pseudo-schemes
	lower := strings.ToLower(trimmed)
	if strings.HasPrefix(lower, "javascript:") || strings.HasPrefix(lower, "data:") ||
		strings.HasPrefix(lower, "mailto:") || strings.HasPrefix(lower, "blob:") ||
		strings.HasPrefix(lower, "file:") {
		res.Warnings = append(res.Warnings, fmt.Sprintf("Ignored non-HTTP pseudo-scheme: %s", trimmed))
		res.IsInScope = false
		return res
	}

	// Check if absolute URL
	if strings.HasPrefix(trimmed, "http://") || strings.HasPrefix(trimmed, "https://") {
		res.IsAbsolute = true
		parsed, err := url.Parse(trimmed)
		if err != nil {
			res.Warnings = append(res.Warnings, fmt.Sprintf("Malformed absolute URL: %v", err))
			res.IsInScope = false
			return res
		}

		res.TargetHost = strings.ToLower(parsed.Hostname())
		if scopeHost != "" && !strings.EqualFold(res.TargetHost, strings.ToLower(scopeHost)) {
			// Out of scope absolute URL
			res.IsInScope = false
			res.NormalizedPath = sanitizeQuerySecrets(trimmed)
			return res
		}

		trimmed = parsed.Path
		if parsed.RawQuery != "" {
			trimmed += "?" + parsed.RawQuery
		}
	}

	// Must start with slash for relative API routes
	if !strings.HasPrefix(trimmed, "/") {
		res.Warnings = append(res.Warnings, "Non-slash-prefixed route ignored")
		return res
	}

	// Separate path from query string / fragment
	pathPart := trimmed
	queryPart := ""
	if idx := strings.IndexAny(trimmed, "?#"); idx != -1 {
		pathPart = trimmed[:idx]
		queryPart = trimmed[idx:]
	}

	// Collapse dynamic template parameter: ${id} -> {param}
	if rxDynamicTemplateParam.MatchString(pathPart) {
		pathPart = rxDynamicTemplateParam.ReplaceAllString(pathPart, "{param}")
		res.StaticallyResolved = false
	}

	// Collapse Express / Next colon parameter: /:id -> /{param}
	if rxDynamicColonParam.MatchString(pathPart) {
		pathPart = rxDynamicColonParam.ReplaceAllString(pathPart, "/{param}")
		res.StaticallyResolved = false
	}

	// Collapse Next.js bracket parameter: /[id] -> /{param}
	if rxDynamicBracketParam.MatchString(pathPart) {
		pathPart = rxDynamicBracketParam.ReplaceAllString(pathPart, "/{param}")
		res.StaticallyResolved = false
	}

	// Collapse duplicate consecutive slashes: //api//users -> /api/users
	for strings.Contains(pathPart, "//") {
		pathPart = strings.ReplaceAll(pathPart, "//", "/")
	}

	// Normalize trailing slash for non-root paths: /api/users/ -> /api/users
	if len(pathPart) > 1 && strings.HasSuffix(pathPart, "/") {
		pathPart = strings.TrimSuffix(pathPart, "/")
	}

	// Redact sensitive query parameters if present
	if queryPart != "" {
		sanitizedQuery := sanitizeQuerySecrets(queryPart)
		res.NormalizedPath = pathPart + sanitizedQuery
	} else {
		res.NormalizedPath = pathPart
	}

	return res
}

// sanitizeQuerySecrets redacts API keys and auth tokens from URL query strings.
func sanitizeQuerySecrets(rawQuery string) string {
	if !strings.Contains(rawQuery, "?") && !strings.Contains(rawQuery, "&") && !strings.Contains(rawQuery, "=") {
		return rawQuery
	}

	return rxSecretTokenInQuery.ReplaceAllStringFunc(rawQuery, func(match string) string {
		parts := strings.SplitN(match, "=", 2)
		if len(parts) == 2 {
			key := strings.ToLower(parts[0])
			if sensitiveQueryParamKeys[key] || strings.Contains(key, "token") || strings.Contains(key, "secret") || strings.Contains(key, "key") {
				return parts[0] + "=[REDACTED]"
			}
		}
		return match
	})
}
