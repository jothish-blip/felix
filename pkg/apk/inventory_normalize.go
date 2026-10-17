package apk

import (
	"fmt"
	"net"
	"net/url"
	"path"
	"sort"
	"strconv"
	"strings"

	"felix/pkg/secrets"
)

// RFC 3986 unreserved characters table: ALPHA / DIGIT / "-" / "." / "_" / "~"
var unreservedTable = [256]bool{
	'A': true, 'B': true, 'C': true, 'D': true, 'E': true, 'F': true, 'G': true,
	'H': true, 'I': true, 'J': true, 'K': true, 'L': true, 'M': true, 'N': true,
	'O': true, 'P': true, 'Q': true, 'R': true, 'S': true, 'T': true, 'U': true,
	'V': true, 'W': true, 'X': true, 'Y': true, 'Z': true,
	'a': true, 'b': true, 'c': true, 'd': true, 'e': true, 'f': true, 'g': true,
	'h': true, 'i': true, 'j': true, 'k': true, 'l': true, 'm': true, 'n': true,
	'o': true, 'p': true, 'q': true, 'r': true, 's': true, 't': true, 'u': true,
	'v': true, 'w': true, 'x': true, 'y': true, 'z': true,
	'0': true, '1': true, '2': true, '3': true, '4': true, '5': true, '6': true,
	'7': true, '8': true, '9': true,
	'-': true, '_': true, '.': true, '~': true,
}

// NormalizedEndpoint holds the parsed and sanitized components of an endpoint reference.
type NormalizedEndpoint struct {
	NormalizedURL string
	RawURL        string
	Scheme        string
	Host          string
	Port          int
	Path          string
	RawQuery      string
	HostIdentity  string
	IsRelative    bool
}

// DefaultPortForScheme returns the canonical IANA default port for recognized URI schemes.
func DefaultPortForScheme(scheme string) int {
	switch strings.ToLower(scheme) {
	case "http", "ws":
		return 80
	case "https", "wss":
		return 443
	case "redis":
		return 6379
	case "rediss":
		return 6380
	case "mongodb", "mongodb+srv":
		return 27017
	case "postgres", "postgresql":
		return 5432
	case "mysql":
		return 3306
	default:
		return 0
	}
}

// NormalizeEndpoint parses, sanitizes, and deterministically normalizes an endpoint string.
// It returns nil if the string is empty, not an endpoint, or malformed beyond safe parsing.
func NormalizeEndpoint(raw string) (*NormalizedEndpoint, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return nil, nil
	}

	// Reject obvious non-URL strings (e.g. Java package names, boolean literals, hex colors, integers)
	if isNonEndpointString(trimmed) {
		return nil, nil
	}

	// 1. Detect relative routes (e.g. /api/v1/users or /graphql)
	if strings.HasPrefix(trimmed, "/") {
		return normalizeRelativeRoute(trimmed)
	}

	// 2. Absolute URI parsing
	// Strip userinfo credentials from URL before url.Parse so credentials never cause syntax errors or leak
	cleanURL := trimmed
	if schemeIdx := strings.Index(cleanURL, "://"); schemeIdx != -1 {
		afterScheme := cleanURL[schemeIdx+3:]
		slashIdx := strings.IndexAny(afterScheme, "/?#")
		hostPart := afterScheme
		restPart := ""
		if slashIdx != -1 {
			hostPart = afterScheme[:slashIdx]
			restPart = afterScheme[slashIdx:]
		}
		if atIdx := strings.LastIndex(hostPart, "@"); atIdx != -1 {
			cleanURL = cleanURL[:schemeIdx+3] + hostPart[atIdx+1:] + restPart
		}
	}

	sanitizedRaw := secrets.SanitizeURL(trimmed)

	parsed, err := url.Parse(cleanURL)
	if err != nil {
		return nil, fmt.Errorf("malformed URL: %w", err)
	}

	// If no scheme is present, do not invent one
	if parsed.Scheme == "" {
		// If it's a versioned route without leading slash (e.g. "api/v1/users"), normalize as relative route
		if strings.HasPrefix(parsed.Path, "api/") || strings.HasPrefix(parsed.Path, "v1/") || strings.HasPrefix(parsed.Path, "v2/") {
			return normalizeRelativeRoute("/" + parsed.Path)
		}
		return nil, nil
	}

	scheme := strings.ToLower(parsed.Scheme)

	// Clean and normalize percent-encoding in path (prefer RawPath to preserve percent escapes)
	rawPath := parsed.RawPath
	if rawPath == "" {
		rawPath = parsed.Path
	}
	normPath := normalizePercentEncoding(rawPath)
	cleanedPath := cleanURLPath(normPath)

	// Parse and normalize host and port
	hostname, port, hostIdentity := parseHostAndPort(parsed.Host, scheme)
	if hostname == "" {
		// Malformed host
		return nil, nil
	}

	// Normalize query string (scrub sensitive parameters and sort keys)
	normQuery := normalizeQueryString(parsed.RawQuery)

	// Build the canonical NormalizedURL
	var sb strings.Builder
	sb.WriteString(scheme)
	sb.WriteString("://")

	// Host representation in URL (bracket IPv6 if needed)
	if strings.Contains(hostname, ":") && !strings.HasPrefix(hostname, "[") {
		sb.WriteString("[")
		sb.WriteString(hostname)
		sb.WriteString("]")
	} else {
		sb.WriteString(hostname)
	}

	defaultPort := DefaultPortForScheme(scheme)
	if port > 0 && port != defaultPort {
		sb.WriteString(":")
		sb.WriteString(strconv.Itoa(port))
	}

	sb.WriteString(cleanedPath)

	if normQuery != "" {
		sb.WriteString("?")
		sb.WriteString(normQuery)
	}

	canonicalURL := sb.String()

	return &NormalizedEndpoint{
		NormalizedURL: canonicalURL,
		RawURL:        sanitizedRaw,
		Scheme:        scheme,
		Host:          hostname,
		Port:          port,
		Path:          cleanedPath,
		RawQuery:      normQuery,
		HostIdentity:  hostIdentity,
		IsRelative:    false,
	}, nil
}

// normalizeRelativeRoute normalizes a relative route path.
func normalizeRelativeRoute(rawPath string) (*NormalizedEndpoint, error) {
	// Strip fragment if present
	clean := rawPath
	if idx := strings.Index(clean, "#"); idx != -1 {
		clean = clean[:idx]
	}

	rawQuery := ""
	if qIdx := strings.Index(clean, "?"); qIdx != -1 {
		rawQuery = clean[qIdx+1:]
		clean = clean[:qIdx]
	}

	normPath := normalizePercentEncoding(clean)
	cleanedPath := cleanURLPath(normPath)
	normQuery := normalizeQueryString(rawQuery)

	normURL := cleanedPath
	if normQuery != "" {
		normURL += "?" + normQuery
	}

	return &NormalizedEndpoint{
		NormalizedURL: normURL,
		RawURL:        rawPath,
		Scheme:        "",
		Host:          "",
		Port:          0,
		Path:          cleanedPath,
		RawQuery:      normQuery,
		HostIdentity:  "(unresolved)",
		IsRelative:    true,
	}, nil
}

// parseHostAndPort extracts normalized hostname, effective port, and host identity.
func parseHostAndPort(rawHost, scheme string) (hostname string, port int, hostIdentity string) {
	defaultPort := DefaultPortForScheme(scheme)

	if rawHost == "" {
		return "", 0, ""
	}

	// Handle IPv6 enclosed in brackets: e.g. [2001:db8::1]:8080 or [::1]
	if strings.HasPrefix(rawHost, "[") {
		endBracket := strings.Index(rawHost, "]")
		if endBracket != -1 {
			ip := strings.ToLower(rawHost[1:endBracket])
			rest := rawHost[endBracket+1:]
			if strings.HasPrefix(rest, ":") {
				p, err := strconv.Atoi(rest[1:])
				if err == nil && p > 0 && p <= 65535 {
					port = p
				}
			}
			if port == 0 {
				port = defaultPort
			}

			if port > 0 && port != defaultPort {
				hostIdentity = fmt.Sprintf("[%s]:%d", ip, port)
			} else {
				hostIdentity = fmt.Sprintf("[%s]", ip)
			}
			return ip, port, hostIdentity
		}
	}

	// Handle standard host or host:port
	h, pStr, err := net.SplitHostPort(rawHost)
	if err == nil {
		hLower := strings.ToLower(h)
		p, pErr := strconv.Atoi(pStr)
		if pErr == nil && p > 0 && p <= 65535 {
			port = p
		} else {
			port = defaultPort
		}
		if port > 0 && port != defaultPort {
			hostIdentity = fmt.Sprintf("%s:%d", hLower, port)
		} else {
			hostIdentity = hLower
		}
		return hLower, port, hostIdentity
	}

	// No port specified
	hLower := strings.ToLower(rawHost)
	port = defaultPort
	hostIdentity = hLower
	return hLower, port, hostIdentity
}

// cleanURLPath safely resolves dot segments and collapses duplicate slashes while preserving meaningful trailing slashes.
func cleanURLPath(p string) string {
	if p == "" || p == "/" {
		return "/"
	}

	hasTrailingSlash := strings.HasSuffix(p, "/")

	// Collapse duplicate slashes
	for strings.Contains(p, "//") {
		p = strings.ReplaceAll(p, "//", "/")
	}

	cleaned := path.Clean(p)
	if cleaned == "." || cleaned == "" {
		return "/"
	}
	if !strings.HasPrefix(cleaned, "/") {
		cleaned = "/" + cleaned
	}

	if hasTrailingSlash && cleaned != "/" && !strings.HasSuffix(cleaned, "/") {
		cleaned += "/"
	}
	return cleaned
}

// normalizePercentEncoding normalizes percent escapes by decoding unreserved characters and uppercasing hex bytes.
func normalizePercentEncoding(s string) string {
	if !strings.Contains(s, "%") {
		return s
	}

	var sb strings.Builder
	sb.Grow(len(s))

	for i := 0; i < len(s); {
		if s[i] == '%' && i+2 < len(s) && isHex(s[i+1]) && isHex(s[i+2]) {
			b := (hexVal(s[i+1]) << 4) | hexVal(s[i+2])
			if unreservedTable[b] {
				// Unreserved RFC 3986 character: decode safely
				sb.WriteByte(b)
			} else {
				// Reserved character: uppercase hex digits
				sb.WriteByte('%')
				sb.WriteByte(toUpperHex(s[i+1]))
				sb.WriteByte(toUpperHex(s[i+2]))
			}
			i += 3
		} else {
			sb.WriteByte(s[i])
			i++
		}
	}

	return sb.String()
}

// normalizeQueryString scrubs sensitive values, sorts query parameters deterministically, and re-encodes.
func normalizeQueryString(rawQuery string) string {
	if rawQuery == "" {
		return ""
	}

	params, err := url.ParseQuery(rawQuery)
	if err != nil {
		// Fallback for malformed query strings
		return secrets.RedactText(rawQuery)
	}

	keys := make([]string, 0, len(params))
	for k := range params {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var pairs []string
	for _, k := range keys {
		vals := params[k]
		// Retain original value ordering for repeated keys to preserve parameter semantics
		isSens := secrets.IsSensitiveQueryParam(k) || secrets.IsSensitiveKey(k)
		for _, v := range vals {
			cleanVal := v
			if isSens {
				cleanVal = "[REDACTED]"
			} else {
				cleanVal = secrets.RedactText(v)
			}
			pairs = append(pairs, url.QueryEscape(k)+"="+url.QueryEscape(cleanVal))
		}
	}

	res := strings.Join(pairs, "&")
	res = strings.ReplaceAll(res, "%5BREDACTED%5D", "[REDACTED]")
	return res
}

func isHex(c byte) bool {
	return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
}

func hexVal(c byte) byte {
	switch {
	case c >= '0' && c <= '9':
		return c - '0'
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10
	}
	return 0
}

func toUpperHex(c byte) byte {
	if c >= 'a' && c <= 'f' {
		return c - 'a' + 'A'
	}
	return c
}

// isNonEndpointString rejects identifier strings that should not be normalized into endpoints.
func isNonEndpointString(s string) bool {
	sLower := strings.ToLower(s)

	// Java package names or classes without scheme/path structure
	if strings.HasPrefix(sLower, "com.android.") ||
		strings.HasPrefix(sLower, "android.permission.") ||
		strings.HasPrefix(sLower, "androidx.") ||
		strings.HasPrefix(sLower, "java.lang.") {
		return true
	}

	// Hex colors
	if strings.HasPrefix(s, "#") && (len(s) == 7 || len(s) == 9) {
		return true
	}

	// Common programming constants
	if sLower == "true" || sLower == "false" || sLower == "null" || sLower == "undefined" {
		return true
	}

	// Strings starting with letter but without scheme or slashes
	if !strings.Contains(s, "/") && !strings.Contains(s, ":") {
		return true
	}

	return false
}
