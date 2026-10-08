package api

import (
	"context"
	"fmt"
	"net/http"
	"strings"
)

// AuditSecurityHeaders inspects HTTP response headers on a target URL for recommended defense-in-depth protections.
func AuditSecurityHeaders(ctx context.Context, client *Client, targetURL string) []APIFinding {
	var findings []APIFinding

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, targetURL, nil)
	if err != nil {
		return findings
	}

	resp, err := client.Do(ctx, req)
	if err != nil {
		return findings
	}

	isHTTPS := strings.HasPrefix(strings.ToLower(targetURL), "https://")
	headers := resp.Header

	// 1. Content-Security-Policy
	if headers.Get("Content-Security-Policy") == "" {
		findings = append(findings, APIFinding{
			Category:    CategoryMissingCSP,
			Endpoint:    targetURL,
			Method:      http.MethodGet,
			Description: "Missing Content-Security-Policy (CSP) defense-in-depth header",
			Evidence:    "Response headers do not include Content-Security-Policy.",
			Severity:    SeverityLow,
			Confidence:  ConfidenceHigh,
			Fingerprint: GenerateFingerprint(CategoryMissingCSP, targetURL, http.MethodGet),
		})
	}

	// 2. Strict-Transport-Security (HSTS)
	// IMPORTANT: Only evaluate HSTS meaningfully when target is HTTPS
	if isHTTPS && headers.Get("Strict-Transport-Security") == "" {
		findings = append(findings, APIFinding{
			Category:    CategoryMissingHSTS,
			Endpoint:    targetURL,
			Method:      http.MethodGet,
			Description: "Missing HTTP Strict-Transport-Security (HSTS) header on HTTPS endpoint",
			Evidence:    "HTTPS response headers do not include Strict-Transport-Security.",
			Severity:    SeverityLow,
			Confidence:  ConfidenceHigh,
			Fingerprint: GenerateFingerprint(CategoryMissingHSTS, targetURL, http.MethodGet),
		})
	}

	// 3. X-Frame-Options
	if headers.Get("X-Frame-Options") == "" && !strings.Contains(headers.Get("Content-Security-Policy"), "frame-ancestors") {
		findings = append(findings, APIFinding{
			Category:    CategoryMissingXFrameOptions,
			Endpoint:    targetURL,
			Method:      http.MethodGet,
			Description: "Missing X-Frame-Options header (clickjacking protection)",
			Evidence:    "Response headers do not include X-Frame-Options or CSP frame-ancestors directive.",
			Severity:    SeverityLow,
			Confidence:  ConfidenceHigh,
			Fingerprint: GenerateFingerprint(CategoryMissingXFrameOptions, targetURL, http.MethodGet),
		})
	}

	// 4. X-Content-Type-Options
	if !strings.EqualFold(strings.TrimSpace(headers.Get("X-Content-Type-Options")), "nosniff") {
		findings = append(findings, APIFinding{
			Category:    CategoryMissingXContentType,
			Endpoint:    targetURL,
			Method:      http.MethodGet,
			Description: "Missing or incomplete X-Content-Type-Options: nosniff header",
			Evidence:    fmt.Sprintf("X-Content-Type-Options observed: %q (expected 'nosniff').", headers.Get("X-Content-Type-Options")),
			Severity:    SeverityInfo,
			Confidence:  ConfidenceHigh,
			Fingerprint: GenerateFingerprint(CategoryMissingXContentType, targetURL, http.MethodGet),
		})
	}

	// 5. Permissions-Policy
	if headers.Get("Permissions-Policy") == "" {
		findings = append(findings, APIFinding{
			Category:    CategoryMissingPermissions,
			Endpoint:    targetURL,
			Method:      http.MethodGet,
			Description: "Missing Permissions-Policy header (browser feature gating)",
			Evidence:    "Response headers do not include Permissions-Policy.",
			Severity:    SeverityInfo,
			Confidence:  ConfidenceHigh,
			Fingerprint: GenerateFingerprint(CategoryMissingPermissions, targetURL, http.MethodGet),
		})
	}

	return findings
}
