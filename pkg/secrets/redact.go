package secrets

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
)

var (
	// pemPrivateKeyPattern matches complete multiline PEM private key blocks.
	pemPrivateKeyPattern = regexp.MustCompile(`(?s)-----BEGIN [A-Z0-9_\- ]*(?:PRIVATE KEY|PGP PRIVATE KEY BLOCK)-----.*?-----END [A-Z0-9_\- ]*(?:PRIVATE KEY|PGP PRIVATE KEY BLOCK)-----`)

	// pemTruncatedPattern matches unclosed or truncated PEM private key blocks to prevent raw leakage.
	pemTruncatedPattern = regexp.MustCompile(`(?s)-----BEGIN [A-Z0-9_\- ]*(?:PRIVATE KEY|PGP PRIVATE KEY BLOCK)-----[A-Za-z0-9+/=_\-\s\r\n]+$`)

	// jwtPattern matches JSON Web Tokens with standard three-part base64url structure.
	jwtPattern = regexp.MustCompile(`\bey[A-Za-z0-9_-]{8,}\.ey[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]+\b`)

	// bearerTokenPattern matches Authorization Bearer tokens.
	bearerTokenPattern = regexp.MustCompile(`(?i)\b(Bearer\s+)(?:\[REDACTED\]|[A-Za-z0-9_\-\.~+/]+=*)`)

	// Well-known API token and credential formats.
	stripeKeyPattern    = regexp.MustCompile(`(?:\b|_)(?:sk|rk)_(?:live|test)_[0-9a-zA-Z_]{16,}\b`)
	githubTokenPattern  = regexp.MustCompile(`(?:\b|_)(?:ghp|gho|ghu|ghs|ghr|github_pat)_[0-9a-zA-Z_]{20,}\b`)
	slackTokenPattern   = regexp.MustCompile(`(?:\b|_)(?:xox[baprs]-[0-9a-zA-Z_]{10,}(?:-[0-9a-zA-Z_]{10,})*)\b`)
	openaiKeyPattern      = regexp.MustCompile(`(?:\b|_)(?:sk-(?:proj-)?[0-9a-zA-Z_-]{20,})\b`)
	awsAccessKeyPattern   = regexp.MustCompile(`(?:\b|_)(AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16,28}\b`)
	supabaseSecretPattern = regexp.MustCompile(`(?:\b|_)(?:sb_secret_[0-9a-zA-Z_-]{20,})\b`)

	// Payment card numbers (Visa, Mastercard, Amex, Discover, formatted or unformatted).
	creditCardPattern = regexp.MustCompile(`\b(?:\d{4}[-\s]?){3}\d{4}\b|\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b`)

	// ssnPattern matches US Social Security Numbers formatted as XXX-XX-XXXX.
	ssnPattern = regexp.MustCompile(`\b\d{3}-\d{2}-\d{4}\b`)

	// sensitiveAssignPattern matches key-value assignments for sensitive credentials in config, code, headers, JSON, or logs.
	// Matches: key (=, :, :=, =>) value, with optional quotes around keys and values, unclosed values at EOF, and whitespace variations.
	sensitiveAssignPattern = regexp.MustCompile(`(?i)(?:["'\x60]|\b)((?:[a-zA-Z0-9_.-]+[\s_-]+)?(?:password|passwd|pass|pwd|secret|secret_key|secretkey|client_secret|clientsecret|client\s+secret|api_key|apikey|api\s+key|api_token|apitoken|api\s+token|access_token|accesstoken|access\s+token|refresh_token|refreshtoken|refresh\s+token|auth_token|authtoken|auth\s+token|private_key|privatekey|private\s+key|credential|credentials|db_password|database_url|aws_secret_access_key|token|auth|key)(?:[\s_-]+(?:leaked|exposed|found|compromised|value))?)(["'\x60]?)\s*(:=|=>|=|:)\s*(?:(")(?:[^"\r\n]*"|[^"\r\n]*$)|(')(?:[^'\r\n]*'|[^'\r\n]*$)|(\x60)(?:[^\x60\r\n]*\x60|[^\x60\r\n]*$)|([^&\s,;'"<>\x60\)\}\]]+))`)

	// cookiePattern matches common session identifiers in Cookie/Set-Cookie headers or log text.
	cookiePattern = regexp.MustCompile(`(?i)\b(connect\.sid|phpsessid|jsessionid|sessionid|session_id|session|sid|remember_me|remember_token|auth_token)\s*=\s*([^;\s\r\n]+)`)

	// HTML password and token form inputs.
	htmlPasswordPattern1 = regexp.MustCompile(`(?i)(<input[^>]+type=["']?password["']?[^>]*value=["'])([^"']*)(["'])`)
	htmlPasswordPattern2 = regexp.MustCompile(`(?i)(<input[^>]+value=["'])([^"']*)(["'][^>]*type=["']?password["']?)`)
	htmlTokenPattern1    = regexp.MustCompile(`(?i)(<input[^>]+name=["'][^"']*(?:token|secret|key|csrf|xsrf|auth)[^"']*["'][^>]*value=["'])([^"']*)(["'])`)
	htmlTokenPattern2    = regexp.MustCompile(`(?i)(<input[^>]+value=["'])([^"']*)(["'][^>]*name=["'][^"']*(?:token|secret|key|csrf|xsrf|auth)[^"']*["'])`)

	// querySensitiveFallbackPattern matches credential query parameters in raw text or malformed URLs.
	querySensitiveFallbackPattern = regexp.MustCompile(`(?i)([?&](?:[a-zA-Z0-9_\-\.]*(?:token|access_token|refresh_token|auth_token|id_token|key|api_key|apikey|secret|secret_key|client_secret|password|passwd|pwd|pass|auth|credential|credentials|session|session_id|sessionid|sid|sig|signature)|ssn|social_security|socialsecurity|pin|cvv|cvc)=)(?:\[REDACTED\]|[^&\s"'<>` + "`" + `]+)`)

	// userPassURLPattern matches user:password or :password credentials in raw URL strings, including percent-encoded credentials.
	userPassURLPattern = regexp.MustCompile(`(?i)([a-zA-Z0-9+.-]+://)([^:/\s?#]*):([^/\s?#]*)@`)

	// redisTokenURLPattern matches standalone tokens in Redis URIs: redis://token@host:port
	redisTokenURLPattern = regexp.MustCompile(`(?i)(rediss?://)([^:/\s?#@]+)@`)
)

// RedactText sanitizes arbitrary text by redacting all recognized credentials, tokens,
// connection strings, private keys, session cookies, and key-value secret assignments.
// It is strictly idempotent: repeatedly redacting already sanitized text produces identical output.
func RedactText(input string) string {
	if input == "" {
		return ""
	}

	// 1. Redact multiline PEM private key blocks (complete and truncated)
	s := pemPrivateKeyPattern.ReplaceAllString(input, "[REDACTED_PRIVATE_KEY]")
	s = pemTruncatedPattern.ReplaceAllString(s, "[REDACTED_PRIVATE_KEY]")

	// 2. Redact Bearer authorization tokens
	s = bearerTokenPattern.ReplaceAllStringFunc(s, func(m string) string {
		if strings.Contains(m, "[REDACTED") {
			return m
		}
		idx := strings.Index(m, " ")
		if idx != -1 {
			return m[:idx+1] + "[REDACTED]"
		}
		return "Bearer [REDACTED]"
	})

	// 3. Redact JWT tokens
	s = jwtPattern.ReplaceAllString(s, "[REDACTED_JWT]")

	// 4. Redact well-known vendor API keys and tokens
	s = stripeKeyPattern.ReplaceAllStringFunc(s, func(m string) string {
		if strings.HasPrefix(m, "_") {
			return "_[REDACTED]"
		}
		return "[REDACTED]"
	})
	s = githubTokenPattern.ReplaceAllStringFunc(s, func(m string) string {
		if strings.HasPrefix(m, "_") {
			return "_[REDACTED]"
		}
		return "[REDACTED]"
	})
	s = slackTokenPattern.ReplaceAllStringFunc(s, func(m string) string {
		if strings.HasPrefix(m, "_") {
			return "_[REDACTED]"
		}
		return "[REDACTED]"
	})
	s = openaiKeyPattern.ReplaceAllStringFunc(s, func(m string) string {
		if strings.HasPrefix(m, "_") {
			return "_[REDACTED]"
		}
		return "[REDACTED]"
	})
	s = awsAccessKeyPattern.ReplaceAllStringFunc(s, func(m string) string {
		prefix := ""
		if strings.HasPrefix(m, "_") {
			prefix = "_"
			m = m[1:]
		}
		if len(m) >= 4 {
			return prefix + m[:4] + "[REDACTED]"
		}
		return prefix + "[REDACTED]"
	})
	s = supabaseSecretPattern.ReplaceAllStringFunc(s, func(m string) string {
		if strings.HasPrefix(m, "_") {
			return "_[REDACTED]"
		}
		return "[REDACTED]"
	})

	// 5. Redact credit card numbers and personal identity numbers (SSN)
	s = creditCardPattern.ReplaceAllString(s, "[REDACTED_CARD_NUMBER]")
	s = ssnPattern.ReplaceAllString(s, "[REDACTED_SSN]")

	// 6. Redact HTML form password and sensitive token inputs
	s = htmlPasswordPattern1.ReplaceAllString(s, "${1}[REDACTED]${3}")
	s = htmlPasswordPattern2.ReplaceAllString(s, "${1}[REDACTED]${3}")
	s = htmlTokenPattern1.ReplaceAllString(s, "${1}[REDACTED]${3}")
	s = htmlTokenPattern2.ReplaceAllString(s, "${1}[REDACTED]${3}")

	// 7. Redact session cookies
	s = cookiePattern.ReplaceAllStringFunc(s, func(m string) string {
		if strings.Contains(m, "[REDACTED") {
			return m
		}
		parts := strings.SplitN(m, "=", 2)
		if len(parts) == 2 {
			return parts[0] + "=[REDACTED]"
		}
		return m
	})

	// 8. Redact URL embedded user:password credentials in text
	s = userPassURLPattern.ReplaceAllString(s, "${1}${2}:[REDACTED]@")
	s = redisTokenURLPattern.ReplaceAllString(s, "${1}[REDACTED]@")

	// 9. Redact query parameter secrets in embedded URLs
	s = querySensitiveFallbackPattern.ReplaceAllString(s, "${1}[REDACTED]")

	// 10. Redact sensitive key-value assignments
	s = sensitiveAssignPattern.ReplaceAllStringFunc(s, func(m string) string {
		if strings.Contains(m, "[REDACTED") {
			return m
		}
		// Find assignment separator
		sepIdx := -1
		sepLen := 1
		for _, sep := range []string{":=", "=>", "=", ":"} {
			if idx := strings.Index(m, sep); idx != -1 {
				if sepIdx == -1 || idx < sepIdx {
					sepIdx = idx
					sepLen = len(sep)
				}
			}
		}
		if sepIdx == -1 {
			return m
		}

		key := m[:sepIdx]
		sep := m[sepIdx : sepIdx+sepLen]

		// Verify key sensitivity against canonical IsSensitiveKey
		cleanKey := strings.Trim(key, "\"'` \t\r\n")
		if !IsSensitiveKey(cleanKey) {
			return m
		}

		afterSep := m[sepIdx+sepLen:]
		valPart := strings.TrimSpace(afterSep)

		// Determine leading whitespace after separator
		leadingSpace := ""
		for _, r := range afterSep {
			if r == ' ' || r == '\t' {
				leadingSpace += string(r)
			} else {
				break
			}
		}
		if leadingSpace == "" && (sep == ":" || sep == ":=" || sep == "=>") {
			leadingSpace = " "
		}

		// Preserve quotes around the redacted placeholder if quotes were present
		if strings.HasPrefix(valPart, "\"") {
			return fmt.Sprintf("%s%s%s\"[REDACTED]\"", key, sep, leadingSpace)
		}
		if strings.HasPrefix(valPart, "'") {
			return fmt.Sprintf("%s%s%s'[REDACTED]'", key, sep, leadingSpace)
		}
		if strings.HasPrefix(valPart, "`") {
			return fmt.Sprintf("%s%s%s`[REDACTED]`", key, sep, leadingSpace)
		}

		return fmt.Sprintf("%s%s%s[REDACTED]", key, sep, leadingSpace)
	})

	return s
}

// SanitizeURL scrubs credentials (user info and sensitive query parameters) from URLs and connection strings
// while preserving non-sensitive components (scheme, host, port, path, safe query parameters).
func SanitizeURL(rawURL string) string {
	clean := strings.TrimSpace(rawURL)
	if clean == "" {
		return ""
	}

	// Handle JDBC prefix (e.g. jdbc:postgresql://user:pass@host:5432/db)
	prefix := ""
	if strings.HasPrefix(strings.ToLower(clean), "jdbc:") {
		prefix = clean[:5]
		clean = clean[5:]
	}

	u, err := url.Parse(clean)
	if err != nil {
		// Fallback for malformed URLs: scrub user:pass and query secrets via regex
		scrubbed := userPassURLPattern.ReplaceAllString(clean, "${1}${2}:[REDACTED]@")
		scrubbed = querySensitiveFallbackPattern.ReplaceAllString(scrubbed, "${1}[REDACTED]")
		scrubbed = ssnPattern.ReplaceAllString(scrubbed, "[REDACTED_SSN]")
		scrubbed = creditCardPattern.ReplaceAllString(scrubbed, "[REDACTED_CARD_NUMBER]")
		return prefix + scrubbed
	}

	// 1. Scrub UserInfo credentials
	if u.User != nil {
		username := u.User.Username()
		_, hasPassword := u.User.Password()
		if hasPassword {
			u.User = url.UserPassword(username, "[REDACTED]")
		} else if IsSensitiveKey(username) || strings.EqualFold(u.Scheme, "redis") || strings.EqualFold(u.Scheme, "rediss") {
			// Token passed in username position (e.g. redis://:secret@host or redis://secret@host or http://token@host)
			u.User = url.User("[REDACTED]")
		}
	}

	// 2. Scrub sensitive query parameters
	if u.RawQuery != "" {
		q := u.Query()
		modified := false
		for k, vv := range q {
			if IsSensitiveQueryParam(k) {
				q.Set(k, "[REDACTED]")
				modified = true
			} else {
				for i, v := range vv {
					if red := RedactText(v); red != v {
						vv[i] = red
						modified = true
					}
				}
				if modified {
					q[k] = vv
				}
			}
		}
		if modified {
			// Encode and decode %5BREDACTED%5D back to [REDACTED] for human readability in reports
			encoded := q.Encode()
			encoded = strings.ReplaceAll(encoded, "%5BREDACTED%5D", "[REDACTED]")
			u.RawQuery = encoded
		}
	}

	res := prefix + u.String()
	res = strings.ReplaceAll(res, "%5BREDACTED%5D", "[REDACTED]")
	res = RedactText(res)
	res = ssnPattern.ReplaceAllString(res, "[REDACTED_SSN]")
	res = creditCardPattern.ReplaceAllString(res, "[REDACTED_CARD_NUMBER]")
	return res
}

// SanitizeHeaders strips sensitive authentication, token, and session headers from an http.Header collection.
// It returns a safe map[string]string suitable for logging, persistence, or report inclusion.
func SanitizeHeaders(headers http.Header) map[string]string {
	out := make(map[string]string)
	if headers == nil {
		return out
	}

	for k, vv := range headers {
		if IsSensitiveHeader(k) {
			out[k] = "[REDACTED]"
		} else {
			out[k] = strings.Join(vv, ", ")
		}
	}
	return out
}

// RedactCookieHeader redacts sensitive cookie values from a Cookie or Set-Cookie header string
// while preserving security attributes (Secure, HttpOnly, SameSite, Path, Domain).
func RedactCookieHeader(raw string) string {
	if raw == "" {
		return ""
	}
	parts := strings.Split(raw, ";")
	if len(parts) == 0 {
		return ""
	}

	for i := range parts {
		parts[i] = strings.TrimSpace(parts[i])
	}

	firstPart := parts[0]
	eqIdx := strings.Index(firstPart, "=")
	if eqIdx != -1 {
		name := firstPart[:eqIdx]
		parts[0] = fmt.Sprintf("%s=[REDACTED]", name)
	}

	return strings.Join(parts, "; ")
}

// RedactBody sanitizes an HTTP request or response body. If the body is valid JSON,
// it performs structured key-based redaction before falling back to comprehensive text redaction.
// If maxLen > 0 and the resulting output exceeds maxLen, it is safely truncated.
func RedactBody(body []byte, maxLen int) string {
	if len(body) == 0 {
		return ""
	}

	// Attempt structured JSON redaction first
	var js any
	if err := json.Unmarshal(body, &js); err == nil {
		redactedVal := RedactAny(js)
		b, err := json.Marshal(redactedVal)
		if err == nil {
			s := RedactText(string(b))
			if maxLen > 0 && len(s) > maxLen {
				return s[:maxLen] + " ... [TRUNCATED]"
			}
			return s
		}
	}

	// Unstructured or non-JSON content: comprehensive text redaction
	s := RedactText(string(body))
	if maxLen > 0 && len(s) > maxLen {
		return s[:maxLen] + " ... [TRUNCATED]"
	}
	return s
}

// RedactJSON parses JSON bytes, recursively redacts sensitive fields and values,
// and returns the sanitized JSON bytes. If input is not valid JSON, it fails safely
// by applying RedactText to the raw string.
func RedactJSON(body []byte) []byte {
	if len(body) == 0 {
		return body
	}

	var js any
	if err := json.Unmarshal(body, &js); err != nil {
		// Fail closed: return text-redacted bytes rather than unredacted invalid JSON
		return []byte(RedactText(string(body)))
	}

	redacted := RedactAny(js)
	b, err := json.Marshal(redacted)
	if err != nil {
		return []byte(RedactText(string(body)))
	}
	return []byte(RedactText(string(b)))
}

// RedactMap recursively sanitizes a map[string]any data structure without mutating the input map.
func RedactMap(m map[string]any) map[string]any {
	if m == nil {
		return nil
	}
	out := make(map[string]any, len(m))
	for k, v := range m {
		if IsSensitiveKey(k) {
			out[k] = "[REDACTED]"
		} else {
			out[k] = RedactAny(v)
		}
	}
	return out
}

// RedactAny recursively sanitizes any Go data structure (maps, slices, strings, byte slices, errors).
func RedactAny(v any) any {
	switch val := v.(type) {
	case map[string]any:
		return RedactMap(val)
	case map[string]string:
		out := make(map[string]string, len(val))
		for k, item := range val {
			if IsSensitiveKey(k) || IsSensitiveHeader(k) {
				out[k] = "[REDACTED]"
			} else {
				out[k] = RedactText(item)
			}
		}
		return out
	case []any:
		out := make([]any, len(val))
		for i, item := range val {
			out[i] = RedactAny(item)
		}
		return out
	case []string:
		out := make([]string, len(val))
		for i, item := range val {
			out[i] = RedactText(item)
		}
		return out
	case []byte:
		return []byte(RedactText(string(val)))
	case string:
		return RedactText(val)
	case error:
		if val == nil {
			return nil
		}
		return WrapSanitizedError(val)
	default:
		return val
	}
}

// RedactStructuredEvidence recursively sanitizes an evidence map.
func RedactStructuredEvidence(evidence map[string]any) map[string]any {
	return RedactMap(evidence)
}

// RedactValue is an alias to RedactText for single sensitive values.
func RedactValue(val string) string {
	return RedactText(val)
}

// RedactRequestSummary creates a sanitized representation of an HTTP request for audit logs and results.
func RedactRequestSummary(method, endpoint string, headers map[string]string, payload string) string {
	sanitizedEndpoint := SanitizeURL(endpoint)
	var parts []string
	parts = append(parts, fmt.Sprintf("%s %s", method, sanitizedEndpoint))

	for k, v := range headers {
		if IsSensitiveHeader(k) {
			parts = append(parts, fmt.Sprintf("%s: [REDACTED]", k))
		} else {
			parts = append(parts, fmt.Sprintf("%s: %s", k, RedactText(v)))
		}
	}

	if payload != "" {
		redactedPayload := RedactBody([]byte(payload), 256)
		parts = append(parts, fmt.Sprintf("\n%s", redactedPayload))
	}

	return strings.Join(parts, "\n")
}

// SanitizeError strips sensitive parameters, credentials, and URLs from an error message,
// and bounds the error string length to prevent unbounded log pollution.
func SanitizeError(err error) string {
	if err == nil {
		return ""
	}
	msg := err.Error()
	msg = RedactText(msg)
	if len(msg) > 256 {
		msg = msg[:253] + "..."
	}
	return msg
}

// WrapSanitizedError wraps an error ensuring the message is completely sanitized and bounded in length.
func WrapSanitizedError(err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("%s", SanitizeError(err))
}

// IsSensitiveHeader returns true if the header name represents sensitive credential or authorization material.
func IsSensitiveHeader(h string) bool {
	lower := strings.ToLower(strings.TrimSpace(h))

	// Harmless headers containing "key" or "token" that must not be redacted
	if lower == "sec-websocket-key" || lower == "public-key-pins" || lower == "public-key-pins-report-only" || lower == "idempotency-key" {
		return false
	}

	// Exact sensitive header names
	sensitiveExact := map[string]struct{}{
		"authorization":       {},
		"proxy-authorization": {},
		"cookie":              {},
		"set-cookie":          {},
		"x-api-key":           {},
		"api-key":             {},
		"x-auth-token":        {},
		"x-session-id":        {},
		"x-session-token":     {},
		"x-csrf-token":        {},
		"x-xsrf-token":        {},
		"x-access-token":      {},
		"x-refresh-token":     {},
		"x-secret-key":        {},
		"x-client-secret":     {},
		"x-token":             {},
		"token":               {},
		"secret":              {},
		"private-key":         {},
		"authentication":      {},
	}
	if _, ok := sensitiveExact[lower]; ok {
		return true
	}

	// Substring / Prefix / Suffix rules
	if strings.Contains(lower, "password") || strings.Contains(lower, "passwd") {
		return true
	}
	if strings.HasPrefix(lower, "x-auth-") {
		return true
	}
	if strings.HasSuffix(lower, "-token") || strings.HasSuffix(lower, "_token") {
		return true
	}
	if strings.HasSuffix(lower, "-secret") || strings.HasSuffix(lower, "_secret") {
		return true
	}
	if strings.HasSuffix(lower, "-key") || strings.HasSuffix(lower, "_key") {
		return true
	}

	return false
}

// IsSensitiveKey returns true if a map or JSON object field name corresponds to a credential or secret.
func IsSensitiveKey(k string) bool {
	lower := strings.ToLower(strings.TrimSpace(k))
	clean := strings.ReplaceAll(strings.ReplaceAll(lower, "_", ""), "-", "")

	// Public keys and non-sensitive identifiers are explicitly exempt
	if strings.Contains(clean, "public") {
		return false
	}
	if clean == "category" || clean == "keyboard" || clean == "monkey" || clean == "status" || clean == "type" || clean == "credentialvalidity" {
		return false
	}

	sensitiveExact := map[string]struct{}{
		"password":      {},
		"passwd":        {},
		"pass":          {},
		"pwd":           {},
		"userpassword":  {},
		"dbpassword":    {},
		"secret":        {},
		"secretkey":     {},
		"clientsecret":  {},
		"appsecret":     {},
		"sharedsecret":  {},
		"token":         {},
		"accesstoken":   {},
		"refreshtoken":  {},
		"authtoken":     {},
		"idtoken":       {},
		"bearertoken":   {},
		"apikey":        {},
		"apitoken":      {},
		"privatekey":    {},
		"privkey":       {},
		"authorization": {},
		"auth":          {},
		"cookie":        {},
		"cookies":       {},
		"setcookie":     {},
		"session":       {},
		"sessionid":     {},
		"sid":           {},
		"credential":    {},
		"credentials":   {},
		"creditcard":    {},
		"cardnumber":    {},
		"cvv":           {},
		"cvc":                  {},
		"ssn":                  {},
		"socialsecuritynumber": {},
		"socialsecurity":       {},
		"dob":                  {},
		"dateofbirth":          {},
		"pin":                  {},
		"dsn":                  {},
		"connectionstring":     {},
		"databaseurl":          {},
		"dburl":                {},
	}
	if _, ok := sensitiveExact[clean]; ok {
		return true
	}

	// Suffix / Substring matches
	if strings.Contains(clean, "password") || strings.Contains(clean, "passwd") ||
		strings.Contains(clean, "secret") || strings.Contains(clean, "apikey") ||
		strings.Contains(clean, "privatekey") || strings.Contains(clean, "credential") ||
		strings.HasSuffix(clean, "token") || strings.HasSuffix(clean, "tokens") ||
		strings.HasSuffix(clean, "key") || strings.HasSuffix(clean, "keys") ||
		strings.HasSuffix(clean, "auth") || strings.HasSuffix(clean, "session") ||
		strings.HasSuffix(clean, "cookie") || strings.HasSuffix(clean, "cookies") {
		return true
	}

	return false
}

// IsSensitiveQueryParam returns true if a URL query parameter name corresponds to a secret.
func IsSensitiveQueryParam(k string) bool {
	lower := strings.ToLower(strings.TrimSpace(k))

	// Harmless query parameters that must never be redacted
	harmless := map[string]struct{}{
		"page": {}, "limit": {}, "offset": {}, "sort": {}, "order": {},
		"search": {}, "query": {}, "q": {}, "filter": {}, "category": {},
		"format": {}, "view": {}, "type": {}, "mode": {}, "status": {},
		"id": {}, "name": {}, "title": {}, "lang": {}, "locale": {},
	}
	if _, ok := harmless[lower]; ok {
		return false
	}

	// Exact matches
	sensitiveExact := map[string]struct{}{
		"token":         {},
		"access_token":  {},
		"refresh_token": {},
		"id_token":      {},
		"auth_token":    {},
		"auth":          {},
		"authorization": {},
		"key":           {},
		"api_key":       {},
		"apikey":        {},
		"secret_key":    {},
		"secret":        {},
		"client_secret": {},
		"password":      {},
		"passwd":        {},
		"pass":          {},
		"pwd":           {},
		"session":       {},
		"session_id":    {},
		"sessionid":     {},
		"sid":           {},
		"signature":     {},
		"sig":           {},
		"credential":    {},
		"credentials":            {},
		"private_key":            {},
		"code":                   {},
		"ssn":                    {},
		"social_security":        {},
		"socialsecurity":         {},
		"social_security_number": {},
		"socialsecuritynumber":   {},
		"pin":                    {},
		"dob":                    {},
		"date_of_birth":          {},
		"cvv":                    {},
		"cvc":                    {},
		"credit_card":            {},
		"card_number":            {},
	}
	if _, ok := sensitiveExact[lower]; ok {
		return true
	}

	// Prefix and Suffix checks
	if strings.HasSuffix(lower, "_key") || strings.HasSuffix(lower, "-key") || strings.HasPrefix(lower, "key_") {
		return true
	}
	if strings.HasSuffix(lower, "_token") || strings.HasSuffix(lower, "-token") || strings.HasPrefix(lower, "token_") {
		return true
	}
	if strings.HasSuffix(lower, "_secret") || strings.HasSuffix(lower, "-secret") || strings.HasPrefix(lower, "secret_") {
		return true
	}
	if strings.HasSuffix(lower, "_auth") || strings.HasSuffix(lower, "-auth") || strings.HasPrefix(lower, "auth_") {
		return true
	}
	if strings.HasSuffix(lower, "_pass") || strings.HasSuffix(lower, "-pass") || strings.HasSuffix(lower, "_password") {
		return true
	}
	if strings.HasSuffix(lower, "_session") || strings.HasSuffix(lower, "-session") || strings.HasSuffix(lower, "_sig") {
		return true
	}

	// Substring checks
	if strings.Contains(lower, "apikey") || strings.Contains(lower, "api_key") ||
		strings.Contains(lower, "secret") || strings.Contains(lower, "password") ||
		strings.Contains(lower, "passwd") || strings.Contains(lower, "credential") ||
		strings.Contains(lower, "private_key") || strings.Contains(lower, "signature") ||
		strings.HasPrefix(lower, "x-amz-") {
		return true
	}

	return false
}
