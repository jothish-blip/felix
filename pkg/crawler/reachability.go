package crawler

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"syscall"
)

// ReachabilityCategory defines structured classification of network and HTTP reachability outcomes.
type ReachabilityCategory string

const (
	ReachabilitySuccess           ReachabilityCategory = "SUCCESS"
	ReachabilityDNSFailure        ReachabilityCategory = "DNS_FAILURE"
	ReachabilityConnectionRefused ReachabilityCategory = "CONNECTION_REFUSED"
	ReachabilityTLSFailure        ReachabilityCategory = "TLS_FAILURE"
	ReachabilityTimeout           ReachabilityCategory = "TIMEOUT"
	ReachabilityHTTP403Challenge  ReachabilityCategory = "HTTP_403_CHALLENGE"
	ReachabilityHTTP403Forbidden  ReachabilityCategory = "HTTP_403_FORBIDDEN"
	ReachabilityHTTP404NotFound   ReachabilityCategory = "HTTP_404_NOT_FOUND"
	ReachabilityHTTP429RateLimit  ReachabilityCategory = "HTTP_429_RATE_LIMITED"
	ReachabilityHTTP5xxServer     ReachabilityCategory = "HTTP_5XX_SERVER_ERROR"
	ReachabilityRedirectError     ReachabilityCategory = "REDIRECT_ERROR"
	ReachabilityHTTPClientError   ReachabilityCategory = "HTTP_CLIENT_ERROR"
	ReachabilityGenericError      ReachabilityCategory = "GENERIC_ERROR"
)

// ReachabilityDiagnostic encapsulates safe, structured metadata and classification for target reachability.
type ReachabilityDiagnostic struct {
	Category    ReachabilityCategory `json:"category"`
	StatusCode  int                  `json:"status_code,omitempty"`
	StatusText  string               `json:"status_text,omitempty"`
	Server      string               `json:"server,omitempty"`
	CfMitigated string               `json:"cf_mitigated,omitempty"`
	CfRay       string               `json:"cf_ray,omitempty"`
	RetryAfter  string               `json:"retry_after,omitempty"`
	SafeSummary string               `json:"safe_summary"`
	RawError    string               `json:"raw_error,omitempty"`
}

// Error implements the standard error interface.
func (d *ReachabilityDiagnostic) Error() string {
	if d == nil {
		return ""
	}
	return d.SafeSummary
}

// IsBlocked returns true if access was halted due to access control or challenge barriers.
func (d *ReachabilityDiagnostic) IsBlocked() bool {
	if d == nil {
		return false
	}
	return d.Category == ReachabilityHTTP403Challenge || d.Category == ReachabilityHTTP403Forbidden
}

// IsFailed returns true if reachability failed due to network, transport, or server errors.
func (d *ReachabilityDiagnostic) IsFailed() bool {
	if d == nil {
		return false
	}
	return d.Category != ReachabilitySuccess && !d.IsBlocked()
}

var rayIDPattern = regexp.MustCompile(`^[a-zA-Z0-9\-]{1,64}$`)

// SanitizeRayID safely extracts and bounds a Cloudflare Ray ID to safe alphanumeric characters and dashes.
func SanitizeRayID(raw string) string {
	raw = strings.TrimSpace(raw)
	if rayIDPattern.MatchString(raw) {
		return raw
	}
	// Fallback filter
	var b strings.Builder
	for _, r := range raw {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' {
			b.WriteRune(r)
		}
		if b.Len() >= 64 {
			break
		}
	}
	return b.String()
}

var sensitiveParamPattern = regexp.MustCompile(`(?i)(token|key|secret|auth|api_key|session|password|pwd|credential)=([^&#\s]+)`)

// SanitizeURLString strips sensitive query parameter values while preserving URL structure.
func SanitizeURLString(raw string) string {
	if raw == "" {
		return ""
	}
	u, err := url.Parse(raw)
	if err != nil {
		return sensitiveParamPattern.ReplaceAllString(raw, "$1=[REDACTED]")
	}
	if u.RawQuery != "" {
		q := u.Query()
		modified := false
		for k := range q {
			lowerK := strings.ToLower(k)
			if strings.Contains(lowerK, "token") || strings.Contains(lowerK, "key") ||
				strings.Contains(lowerK, "secret") || strings.Contains(lowerK, "auth") ||
				strings.Contains(lowerK, "pass") || strings.Contains(lowerK, "credential") ||
				strings.Contains(lowerK, "session") {
				q.Set(k, "[REDACTED]")
				modified = true
			}
		}
		if modified {
			u.RawQuery = q.Encode()
		}
	}
	return u.String()
}

// SanitizeErrorString strips sensitive parameters, cookies, and bounds error length.
func SanitizeErrorString(err error) string {
	if err == nil {
		return ""
	}
	msg := err.Error()
	msg = sensitiveParamPattern.ReplaceAllString(msg, "$1=[REDACTED]")
	if len(msg) > 256 {
		msg = msg[:253] + "..."
	}
	return msg
}

// ClassifyNetworkError analyzes a transport or network-level error without an HTTP response.
func ClassifyNetworkError(err error, rawTarget string) *ReachabilityDiagnostic {
	if err == nil {
		return nil
	}

	sanitizedTarget := SanitizeURLString(rawTarget)
	sanitizedErr := SanitizeErrorString(err)
	errLower := strings.ToLower(err.Error())

	// 1. DNS resolution failure
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		host := dnsErr.Name
		if host == "" {
			host = sanitizedTarget
		}
		return &ReachabilityDiagnostic{
			Category:    ReachabilityDNSFailure,
			SafeSummary: fmt.Sprintf("DNS resolution failed for %s (%s)", host, dnsErr.Err),
			RawError:    sanitizedErr,
		}
	}

	// 2. TLS handshake / certificate failure
	var certErr x509.CertificateInvalidError
	var unknownAuthErr x509.UnknownAuthorityError
	var hostnameErr x509.HostnameError
	var recordErr tls.RecordHeaderError
	if errors.As(err, &certErr) || errors.As(err, &unknownAuthErr) || errors.As(err, &hostnameErr) || errors.As(err, &recordErr) ||
		strings.Contains(errLower, "tls:") || strings.Contains(errLower, "x509:") || strings.Contains(errLower, "certificate") {
		return &ReachabilityDiagnostic{
			Category:    ReachabilityTLSFailure,
			SafeSummary: fmt.Sprintf("TLS negotiation or certificate verification failed for %s", sanitizedTarget),
			RawError:    sanitizedErr,
		}
	}

	// 3. Timeout / deadline exceeded
	var netErr net.Error
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, os.ErrDeadlineExceeded) ||
		(errors.As(err, &netErr) && netErr.Timeout()) || strings.Contains(errLower, "timeout") ||
		strings.Contains(errLower, "deadline exceeded") {
		return &ReachabilityDiagnostic{
			Category:    ReachabilityTimeout,
			SafeSummary: fmt.Sprintf("connection timed out while reaching %s", sanitizedTarget),
			RawError:    sanitizedErr,
		}
	}

	// 4. TCP Connection Refused
	if errors.Is(err, syscall.ECONNREFUSED) || strings.Contains(errLower, "connection refused") ||
		strings.Contains(errLower, "actively refused") || strings.Contains(errLower, "connect: connectex") ||
		strings.Contains(errLower, "no route to host") || strings.Contains(errLower, "network is unreachable") {
		return &ReachabilityDiagnostic{
			Category:    ReachabilityConnectionRefused,
			SafeSummary: fmt.Sprintf("TCP connection refused by target host %s", sanitizedTarget),
			RawError:    sanitizedErr,
		}
	}

	// 5. Redirect error
	if strings.Contains(errLower, "stopped after 10 redirects") || strings.Contains(errLower, "redirect loop") ||
		strings.Contains(errLower, "redirect to") {
		return &ReachabilityDiagnostic{
			Category:    ReachabilityRedirectError,
			SafeSummary: fmt.Sprintf("redirect policy prevented reachability for %s: %s", sanitizedTarget, sanitizedErr),
			RawError:    sanitizedErr,
		}
	}

	// 6. Generic network failure fallback
	return &ReachabilityDiagnostic{
		Category:    ReachabilityGenericError,
		SafeSummary: fmt.Sprintf("network failure while connecting to %s: %s", sanitizedTarget, sanitizedErr),
		RawError:    sanitizedErr,
	}
}

// ClassifyHTTPResponse analyzes an HTTP response and classifies status codes, bot challenges, and safe diagnostics.
func ClassifyHTTPResponse(resp *http.Response, rawTarget string) *ReachabilityDiagnostic {
	if resp == nil {
		return nil
	}

	sanitizedTarget := SanitizeURLString(rawTarget)
	code := resp.StatusCode
	text := http.StatusText(code)
	if text == "" {
		text = fmt.Sprintf("Status %d", code)
	}

	// Extract strictly allowlisted safe diagnostic headers
	server := strings.TrimSpace(resp.Header.Get("Server"))
	if len(server) > 64 {
		server = server[:64]
	}

	cfMitigated := strings.TrimSpace(resp.Header.Get("Cf-Mitigated"))
	if len(cfMitigated) > 32 {
		cfMitigated = cfMitigated[:32]
	}

	cfRay := SanitizeRayID(resp.Header.Get("CF-RAY"))
	retryAfter := strings.TrimSpace(resp.Header.Get("Retry-After"))
	if len(retryAfter) > 32 {
		retryAfter = retryAfter[:32]
	}

	diag := &ReachabilityDiagnostic{
		StatusCode:  code,
		StatusText:  text,
		Server:      server,
		CfMitigated: cfMitigated,
		CfRay:       cfRay,
		RetryAfter:  retryAfter,
	}

	// 1. Success (2xx, 3xx)
	if code >= 200 && code < 400 {
		diag.Category = ReachabilitySuccess
		diag.SafeSummary = fmt.Sprintf("target %s reached successfully (HTTP %d %s)", sanitizedTarget, code, text)
		return diag
	}

	// 2. HTTP 403: Forbidden vs Challenge
	if code == http.StatusForbidden {
		serverLower := strings.ToLower(server)
		isChallenge := strings.EqualFold(cfMitigated, "challenge") ||
			resp.Header.Get("cf-chl-bypass") != "" ||
			(strings.Contains(serverLower, "cloudflare") && (cfMitigated != "" || cfRay != ""))

		if isChallenge {
			diag.Category = ReachabilityHTTP403Challenge
			summary := fmt.Sprintf("target %s presented an automated challenge barrier (HTTP 403 Forbidden)", sanitizedTarget)
			if cfMitigated != "" {
				summary += fmt.Sprintf(" [mitigation: %s]", cfMitigated)
			}
			if server != "" {
				summary += fmt.Sprintf(" [server: %s]", server)
			}
			diag.SafeSummary = summary
			return diag
		}

		diag.Category = ReachabilityHTTP403Forbidden
		summary := fmt.Sprintf("access denied by target server for %s (HTTP 403 Forbidden)", sanitizedTarget)
		if server != "" {
			summary += fmt.Sprintf(" [server: %s]", server)
		}
		diag.SafeSummary = summary
		return diag
	}

	// 3. HTTP 404: Not Found
	if code == http.StatusNotFound {
		diag.Category = ReachabilityHTTP404NotFound
		diag.SafeSummary = fmt.Sprintf("target resource was not found for %s (HTTP 404 Not Found)", sanitizedTarget)
		return diag
	}

	// 4. HTTP 429: Rate Limited
	if code == http.StatusTooManyRequests {
		diag.Category = ReachabilityHTTP429RateLimit
		summary := fmt.Sprintf("request rate limited by target server for %s (HTTP 429 Too Many Requests)", sanitizedTarget)
		if retryAfter != "" {
			summary += fmt.Sprintf(" [retry-after: %s]", retryAfter)
		}
		diag.SafeSummary = summary
		return diag
	}

	// 5. HTTP 5xx: Server Error
	if code >= 500 && code <= 599 {
		diag.Category = ReachabilityHTTP5xxServer
		diag.SafeSummary = fmt.Sprintf("target %s returned server error (HTTP %d %s)", sanitizedTarget, code, text)
		return diag
	}

	// 6. Other 4xx Client Error
	diag.Category = ReachabilityHTTPClientError
	diag.SafeSummary = fmt.Sprintf("target %s returned HTTP client error (HTTP %d %s)", sanitizedTarget, code, text)
	return diag
}
