package sessionsec

import (
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"felix/pkg/report"
)

// CookieType classifies cookies to distinguish session from non-session cookies.
type CookieType string

const (
	CookieTypeSession    CookieType = "SESSION"
	CookieTypeCSRF       CookieType = "CSRF"
	CookieTypeAnalytics  CookieType = "ANALYTICS"
	CookieTypePreference CookieType = "PREFERENCE"
	CookieTypeUnknown    CookieType = "UNKNOWN"
)

// ParsedCookie models a parsed HTTP cookie with explicit tracking of defined attributes.
type ParsedCookie struct {
	Name        string
	Value       string
	Path        string
	Domain      string
	Expires     time.Time
	RawExpires  string
	MaxAge      int
	Secure      bool
	HttpOnly    bool
	SameSite    http.SameSite
	RawSameSite string
	Partitioned bool

	HasDomain   bool
	HasPath     bool
	HasExpires  bool
	HasMaxAge   bool
	HasSecure   bool
	HasHttpOnly bool
	HasSameSite bool

	Raw string
}

// ClassifyCookie determines the role of a cookie based on common naming patterns.
func ClassifyCookie(name string) CookieType {
	lower := strings.ToLower(name)

	// Explicit prefixes
	if strings.HasPrefix(lower, "__host-") || strings.HasPrefix(lower, "__secure-") {
		return CookieTypeSession
	}

	// Anti-CSRF tokens
	if strings.Contains(lower, "csrf") || strings.Contains(lower, "xsrf") || strings.Contains(lower, "antiforgery") {
		return CookieTypeCSRF
	}

	// Analytics and tracking
	if strings.HasPrefix(lower, "_ga") || strings.HasPrefix(lower, "_gid") || strings.HasPrefix(lower, "_gat") ||
		strings.Contains(lower, "analytics") || strings.Contains(lower, "utm_") || strings.HasPrefix(lower, "mp_") ||
		strings.Contains(lower, "segment") || strings.Contains(lower, "optimizely") {
		return CookieTypeAnalytics
	}

	// Preferences and display
	if strings.Contains(lower, "theme") || strings.Contains(lower, "lang") || strings.Contains(lower, "locale") ||
		strings.Contains(lower, "consent") || strings.Contains(lower, "notice") || strings.Contains(lower, "layout") ||
		strings.Contains(lower, "dark_mode") || strings.Contains(lower, "ui_") {
		return CookieTypePreference
	}

	// Session identifiers
	if strings.Contains(lower, "sess") || strings.Contains(lower, "token") || strings.Contains(lower, "auth") ||
		strings.Contains(lower, "jwt") || strings.Contains(lower, "sid") || strings.Contains(lower, "connect.sid") ||
		strings.Contains(lower, "phpsessid") || strings.Contains(lower, "jsessionid") || strings.Contains(lower, "asp.net_sessionid") {
		return CookieTypeSession
	}

	return CookieTypeUnknown
}

// SplitSetCookieHeader splits comma-separated Set-Cookie header lines
// without incorrectly splitting on commas within Expires date strings (e.g. "Wed, 21 Oct 2026 07:28:00 GMT").
func SplitSetCookieHeader(header string) []string {
	var cookies []string
	var current strings.Builder

	inExpires := false

	for i := 0; i < len(header); i++ {
		ch := header[i]

		// Check if entering or inside an Expires attribute
		if ch == ';' || ch == ',' {
			remaining := strings.ToLower(strings.TrimSpace(header[i+1:]))
			if strings.HasPrefix(remaining, "expires=") {
				inExpires = true
			}
		}

		if ch == ',' {
			if inExpires {
				// Check if this comma is inside a date, e.g. "Wed, 21 Oct"
				// Standard HTTP date has a day-of-week followed by comma and space then day of month (digit)
				rest := strings.TrimSpace(header[i+1:])
				isDateComma := false
				if len(rest) > 0 && rest[0] >= '0' && rest[0] <= '9' {
					isDateComma = true
				}
				if isDateComma {
					current.WriteByte(ch)
					continue
				}
				// Otherwise, this comma might end the expires or separate cookies
				inExpires = false
			}

			// If next part looks like another cookie "name=value", split here
			rest := strings.TrimSpace(header[i+1:])
			if looksLikeCookieStart(rest) {
				cookies = append(cookies, strings.TrimSpace(current.String()))
				current.Reset()
				continue
			}
		}

		current.WriteByte(ch)
	}

	if current.Len() > 0 {
		trimmed := strings.TrimSpace(current.String())
		if trimmed != "" {
			cookies = append(cookies, trimmed)
		}
	}

	return cookies
}

// looksLikeCookieStart checks if a string begins with "<token>=" where token does not match an attribute name.
func looksLikeCookieStart(s string) bool {
	idx := strings.IndexByte(s, '=')
	if idx <= 0 {
		return false
	}
	token := strings.ToLower(strings.TrimSpace(s[:idx]))
	knownAttrs := []string{"expires", "path", "domain", "samesite", "max-age", "secure", "httponly", "partitioned"}
	for _, attr := range knownAttrs {
		if token == attr {
			return false
		}
	}
	return true
}

// ParseSetCookie parses a single Set-Cookie header string case-insensitively and returns a ParsedCookie.
func ParseSetCookie(raw string) (*ParsedCookie, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, fmt.Errorf("empty cookie header")
	}

	parts := strings.Split(raw, ";")
	if len(parts) == 0 {
		return nil, fmt.Errorf("malformed cookie header")
	}

	nameVal := strings.TrimSpace(parts[0])
	eqIdx := strings.IndexByte(nameVal, '=')
	if eqIdx < 0 {
		return nil, fmt.Errorf("missing '=' in cookie name/value pair")
	}

	cookie := &ParsedCookie{
		Name:  strings.TrimSpace(nameVal[:eqIdx]),
		Value: strings.TrimSpace(nameVal[eqIdx+1:]),
		Raw:   raw,
	}
	if cookie.Name == "" {
		return nil, fmt.Errorf("empty cookie name")
	}

	// Parse subsequent attributes case-insensitively
	for i := 1; i < len(parts); i++ {
		attr := strings.TrimSpace(parts[i])
		if attr == "" {
			continue
		}

		var attrName, attrVal string
		if idx := strings.IndexByte(attr, '='); idx >= 0 {
			attrName = strings.ToLower(strings.TrimSpace(attr[:idx]))
			attrVal = strings.TrimSpace(attr[idx+1:])
		} else {
			attrName = strings.ToLower(attr)
		}

		switch attrName {
		case "secure":
			cookie.Secure = true
			cookie.HasSecure = true
		case "httponly":
			cookie.HttpOnly = true
			cookie.HasHttpOnly = true
		case "domain":
			cookie.Domain = attrVal
			cookie.HasDomain = true
		case "path":
			cookie.Path = attrVal
			cookie.HasPath = true
		case "max-age":
			if val, err := strconv.Atoi(attrVal); err == nil {
				cookie.MaxAge = val
				cookie.HasMaxAge = true
			}
		case "expires":
			cookie.RawExpires = attrVal
			cookie.HasExpires = true
			cookie.Expires = parseCookieExpires(attrVal)
		case "samesite":
			cookie.HasSameSite = true
			cookie.RawSameSite = attrVal
			switch strings.ToLower(attrVal) {
			case "strict":
				cookie.SameSite = http.SameSiteStrictMode
			case "lax":
				cookie.SameSite = http.SameSiteLaxMode
			case "none":
				cookie.SameSite = http.SameSiteNoneMode
			default:
				cookie.SameSite = http.SameSiteDefaultMode
			}
		case "partitioned":
			cookie.Partitioned = true
		}
	}

	return cookie, nil
}

// parseCookieExpires attempts parsing expiration date across known HTTP cookie date formats.
func parseCookieExpires(raw string) time.Time {
	formats := []string{
		time.RFC1123,
		"Mon, 02-Jan-2006 15:04:05 MST",
		"Mon, 02 Jan 2006 15:04:05 -0700",
		time.RFC850,
		time.ANSIC,
	}
	for _, f := range formats {
		if t, err := time.Parse(f, raw); err == nil {
			return t
		}
	}
	return time.Time{}
}

// ParseSetCookieHeaders parses a collection of Set-Cookie header lines into ParsedCookies.
func ParseSetCookieHeaders(headers []string) []*ParsedCookie {
	var result []*ParsedCookie
	for _, h := range headers {
		split := SplitSetCookieHeader(h)
		for _, s := range split {
			if pc, err := ParseSetCookie(s); err == nil {
				result = append(result, pc)
			}
		}
	}
	return result
}

// CookieDefect describes a specific weakness or violation identified on a cookie.
type CookieDefect struct {
	Code        string
	Description string
	Severity    string
	Confidence  string
}

// EvaluateCookieAttributes analyzes a parsed cookie against security standards and RFC 6265bis prefix rules.
func EvaluateCookieAttributes(cookie *ParsedCookie, targetURL string) (defects []CookieDefect, isSession bool) {
	cType := ClassifyCookie(cookie.Name)
	isSession = cType == CookieTypeSession

	parsedURL, _ := url.Parse(targetURL)
	isHTTPS := parsedURL != nil && strings.EqualFold(parsedURL.Scheme, "https")
	isLoopback := false
	if parsedURL != nil {
		host := parsedURL.Hostname()
		isLoopback = host == "localhost" || host == "127.0.0.1" || host == "::1"
	}

	// 1. __Host- Cookie Prefix Rules (RFC 6265bis):
	// - Must declare Secure flag
	// - Must specify Path=/
	// - Must NOT specify Domain attribute
	if strings.HasPrefix(cookie.Name, "__Host-") {
		if !cookie.Secure {
			defects = append(defects, CookieDefect{
				Code:        "SS-COOKIE-PREFIX-HOST-NO-SECURE",
				Description: fmt.Sprintf("__Host- prefix violation: Cookie '%s' must declare the Secure attribute", cookie.Name),
				Severity:    report.SeverityHigh,
				Confidence:  report.ConfidenceHigh,
			})
		}
		if cookie.Path != "/" {
			defects = append(defects, CookieDefect{
				Code:        "SS-COOKIE-PREFIX-HOST-PATH",
				Description: fmt.Sprintf("__Host- prefix violation: Cookie '%s' must specify Path=/ (found '%s')", cookie.Name, cookie.Path),
				Severity:    report.SeverityMedium,
				Confidence:  report.ConfidenceHigh,
			})
		}
		if cookie.HasDomain {
			defects = append(defects, CookieDefect{
				Code:        "SS-COOKIE-PREFIX-HOST-DOMAIN",
				Description: fmt.Sprintf("__Host- prefix violation: Cookie '%s' must not declare a Domain attribute (found '%s')", cookie.Name, cookie.Domain),
				Severity:    report.SeverityMedium,
				Confidence:  report.ConfidenceHigh,
			})
		}
	}

	// 2. __Secure- Cookie Prefix Rules (RFC 6265bis):
	// - Must declare Secure flag
	if strings.HasPrefix(cookie.Name, "__Secure-") {
		if !cookie.Secure {
			defects = append(defects, CookieDefect{
				Code:        "SS-COOKIE-PREFIX-SECURE-NO-SECURE",
				Description: fmt.Sprintf("__Secure- prefix violation: Cookie '%s' must declare the Secure attribute", cookie.Name),
				Severity:    report.SeverityHigh,
				Confidence:  report.ConfidenceHigh,
			})
		}
	}

	// 3. Insecure Transport Exposure (Cleartext remote HTTP)
	if !isHTTPS && !isLoopback && isSession {
		defects = append(defects, CookieDefect{
			Code:        "SS-COOKIE-CLEARTEXT",
			Description: fmt.Sprintf("Session cookie '%s' transmitted over unencrypted remote HTTP transport", cookie.Name),
			Severity:    report.SeverityHigh,
			Confidence:  report.ConfidenceHigh,
		})
	}

	// 4. Missing Secure flag for HTTPS
	if isHTTPS && !cookie.Secure && isSession {
		defects = append(defects, CookieDefect{
			Code:        "SS-COOKIE-NO-SECURE",
			Description: fmt.Sprintf("Session cookie '%s' missing Secure flag on HTTPS transport", cookie.Name),
			Severity:    report.SeverityMedium,
			Confidence:  report.ConfidenceHigh,
		})
	}

	// 5. Missing HttpOnly flag for session cookies
	if !cookie.HttpOnly && isSession {
		defects = append(defects, CookieDefect{
			Code:        "SS-COOKIE-NO-HTTPONLY",
			Description: fmt.Sprintf("Session cookie '%s' missing HttpOnly flag (accessible to JavaScript DOM)", cookie.Name),
			Severity:    report.SeverityMedium,
			Confidence:  report.ConfidenceHigh,
		})
	}

	// 6. SameSite evaluations
	if isSession {
		if !cookie.HasSameSite || cookie.SameSite == http.SameSiteDefaultMode {
			defects = append(defects, CookieDefect{
				Code:        "SS-COOKIE-SAMESITE-UNSET",
				Description: fmt.Sprintf("Session cookie '%s' SameSite attribute unset (relies on browser default)", cookie.Name),
				Severity:    report.SeverityLow,
				Confidence:  report.ConfidenceMedium,
			})
		} else if cookie.SameSite == http.SameSiteNoneMode && !cookie.Secure {
			defects = append(defects, CookieDefect{
				Code:        "SS-COOKIE-SAMESITE-NONE-INSECURE",
				Description: fmt.Sprintf("Cookie '%s' specifies SameSite=None without the Secure flag (rejected by modern browsers)", cookie.Name),
				Severity:    report.SeverityHigh,
				Confidence:  report.ConfidenceHigh,
			})
		}
	}

	// 7. Overly broad domain scope (e.g. domain is a public suffix or leading dot with single label)
	if cookie.HasDomain && (cookie.Domain == "." || cookie.Domain == ".com" || cookie.Domain == ".net" || cookie.Domain == ".org" || cookie.Domain == ".co.uk") {
		defects = append(defects, CookieDefect{
			Code:        "SS-COOKIE-BROAD-DOMAIN",
			Description: fmt.Sprintf("Cookie '%s' declares overly broad public suffix domain '%s'", cookie.Name, cookie.Domain),
			Severity:    report.SeverityHigh,
			Confidence:  report.ConfidenceHigh,
		})
	}

	return defects, isSession
}
