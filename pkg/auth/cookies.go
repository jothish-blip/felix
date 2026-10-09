package auth

import (
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
)

var (
	sessionCookieNames = map[string]struct{}{
		"session": {}, "sessionid": {}, "session_id": {}, "sess": {}, "sid": {},
		"connect.sid": {}, "phpsessid": {}, "jsessionid": {}, "aspsessionid": {},
		"asp.net_sessionid": {}, "auth_token": {}, "access_token": {}, "jwt": {},
		"token": {}, "auth": {}, "user_session": {}, "logged_in": {},
		"sb-access-token": {}, "sb-refresh-token": {}, "supabase-auth-token": {},
		"next-auth.session-token": {}, "__session": {}, "clerk_session": {},
	}

	csrfCookieNames = map[string]struct{}{
		"csrf": {}, "csrftoken": {}, "csrf_token": {}, "xsrf": {}, "xsrftoken": {},
		"xsrf-token": {}, "_csrf": {}, "_csrf_token": {}, "anti-forgery": {},
		"authenticity_token": {}, "__host-csrf": {},
	}
)

// ParseAndAnalyzeCookies extracts cookie security metadata from HTTP response headers.
// Mandatory safety guarantee: Raw cookie values and secret payloads are NEVER persisted.
func ParseAndAnalyzeCookies(headers http.Header, sourceURL, asmID, execID, targetID string) []CookieMetadata {
	var results []CookieMetadata
	if headers == nil {
		return results
	}

	rawSetCookies := headers.Values("Set-Cookie")
	if len(rawSetCookies) == 0 {
		return results
	}

	seen := make(map[string]struct{})
	sanitizedSource := SanitizeURL(sourceURL)
	isHTTPS := strings.HasPrefix(strings.ToLower(sourceURL), "https://")

	for _, raw := range rawSetCookies {
		// Use Go's standard http.Header reader to parse Set-Cookie safely
		fakeHeader := http.Header{"Set-Cookie": []string{raw}}
		fakeResp := http.Response{Header: fakeHeader}
		cookies := fakeResp.Cookies()

		for _, c := range cookies {
			if c == nil || c.Name == "" {
				continue
			}

			cookieKey := strings.ToLower(c.Name)
			if _, exists := seen[cookieKey]; exists {
				continue
			}
			seen[cookieKey] = struct{}{}

			sameSiteStr := "Unset"
			switch c.SameSite {
			case http.SameSiteStrictMode:
				sameSiteStr = "Strict"
			case http.SameSiteLaxMode:
				sameSiteStr = "Lax"
			case http.SameSiteNoneMode:
				sameSiteStr = "None"
			}

			purpose, isSession := classifyCookie(c.Name)
			var defects []string

			// Evaluate security flags on session and authentication cookies
			if isSession {
				if !c.HttpOnly {
					defects = append(defects, "Missing HttpOnly flag (accessible to client JavaScript)")
				}
				if isHTTPS && !c.Secure {
					defects = append(defects, "Missing Secure flag (transmissible over unencrypted HTTP)")
				} else if !isHTTPS && !c.Secure {
					defects = append(defects, "Missing Secure flag (target served over unencrypted HTTP)")
				}
				if c.SameSite == http.SameSiteDefaultMode {
					defects = append(defects, "SameSite attribute unset (relies on browser default)")
				} else if c.SameSite == http.SameSiteNoneMode && !c.Secure {
					defects = append(defects, "SameSite=None without Secure flag")
				}
			}

			meta := CookieMetadata{
				ID:               uuid.New().String(),
				AssessmentID:     asmID,
				ExecutionID:      execID,
				TargetID:         targetID,
				Name:             c.Name,
				Domain:           c.Domain,
				Path:             c.Path,
				IsSecure:         c.Secure,
				IsHTTPOnly:       c.HttpOnly,
				SameSite:         sameSiteStr,
				MaxAge:           c.MaxAge,
				Expires:          c.Expires.Format(time.RFC3339),
				Purpose:          purpose,
				IsSession:        isSession,
				HasSecurityIssue: len(defects) > 0,
				SecurityDefects:  defects,
				SourceURL:        sanitizedSource,
				CreatedAt:        time.Now().UTC(),
			}

			results = append(results, meta)
		}
	}

	return results
}

func classifyCookie(name string) (CookiePurpose, bool) {
	lower := strings.ToLower(name)

	// Check exact known session names
	if _, ok := sessionCookieNames[lower]; ok {
		return CookiePurposeSession, true
	}

	// Check exact known CSRF names
	if _, ok := csrfCookieNames[lower]; ok {
		return CookiePurposeCSRF, false
	}

	// Avoid false positive on author/authenticity cookies
	if strings.Contains(lower, "author") || strings.Contains(lower, "authenticity") {
		if strings.Contains(lower, "authenticity") {
			return CookiePurposeCSRF, false
		}
		return CookiePurposeUnknown, false
	}

	// Check CSRF substrings before generic auth/token substrings
	if strings.Contains(lower, "csrf") || strings.Contains(lower, "xsrf") {
		return CookiePurposeCSRF, false
	}

	// Check pattern substrings
	if strings.Contains(lower, "sess") || strings.Contains(lower, "auth") ||
		strings.Contains(lower, "token") || strings.Contains(lower, "jwt") ||
		strings.Contains(lower, "login") {
		return CookiePurposeSession, true
	}

	if strings.Contains(lower, "lang") || strings.Contains(lower, "theme") ||
		strings.Contains(lower, "pref") || strings.Contains(lower, "locale") {
		return CookiePurposePreference, false
	}

	if strings.Contains(lower, "ga") || strings.Contains(lower, "gid") ||
		strings.Contains(lower, "utm_") || strings.Contains(lower, "track") {
		return CookiePurposeTracking, false
	}

	return CookiePurposeUnknown, false
}
