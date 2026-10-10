package api

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"strings"
)

// parseCSPDirectives splits a CSP header string into directive names and token values.
func parseCSPDirectives(csp string) map[string][]string {
	directives := make(map[string][]string)
	parts := strings.Split(csp, ";")
	for _, part := range parts {
		fields := strings.Fields(strings.TrimSpace(part))
		if len(fields) > 0 {
			dirName := strings.ToLower(fields[0])
			directives[dirName] = fields[1:]
		}
	}
	return directives
}

// containsToken checks if a slice of tokens contains a target string (case-insensitive).
func containsToken(tokens []string, target string) bool {
	for _, t := range tokens {
		if strings.EqualFold(strings.Trim(t, `"'`), target) {
			return true
		}
	}
	return false
}

// parseHSTSMaxAge extracts the max-age value from a Strict-Transport-Security header.
func parseHSTSMaxAge(hsts string) int {
	for _, part := range strings.Split(hsts, ";") {
		part = strings.TrimSpace(part)
		if strings.HasPrefix(strings.ToLower(part), "max-age=") {
			valStr := strings.TrimPrefix(part, "max-age=")
			valStr = strings.TrimPrefix(valStr, "MAX-AGE=")
			if val, err := strconv.Atoi(strings.TrimSpace(valStr)); err == nil {
				return val
			}
		}
	}
	return -1
}

// getHeaderValues returns all non-empty trimmed values for a header, case-insensitively.
func getHeaderValues(h http.Header, name string) []string {
	var results []string
	for k, vals := range h {
		if strings.EqualFold(k, name) {
			for _, v := range vals {
				v = strings.TrimSpace(v)
				if v != "" {
					results = append(results, v)
				}
			}
		}
	}
	return results
}

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
	statusCode := resp.StatusCode

	// 1. Content-Security-Policy Analysis
	cspValues := getHeaderValues(headers, "Content-Security-Policy")
	cspReportOnlyValues := getHeaderValues(headers, "Content-Security-Policy-Report-Only")

	var cspHeader string
	if len(cspValues) > 0 {
		cspHeader = strings.Join(cspValues, "; ")
	}

	if len(cspValues) == 0 {
		if len(cspReportOnlyValues) > 0 {
			// Case B: Report-Only CSP present without enforcing CSP
			reportOnlyStr := strings.Join(cspReportOnlyValues, "; ")
			findings = append(findings, APIFinding{
				Category:         CategoryMissingCSP,
				Endpoint:         targetURL,
				Method:           http.MethodGet,
				Description:      "Missing enforcing Content-Security-Policy (CSP) header (Report-Only CSP detected)",
				Evidence:         fmt.Sprintf("Content-Security-Policy-Report-Only observed (%q), but enforcing Content-Security-Policy header is absent.", reportOnlyStr),
				Severity:         SeverityLow,
				Confidence:       ConfidenceHigh,
				HTTPStatus:       statusCode,
				NegativeEvidence: "Target web server evaluates CSP in report-only mode; policy restrictions are not enforced by the browser.",
				Details: map[string]string{
					"header":               "Content-Security-Policy",
					"observed":             "absent",
					"enforcing":            "absent",
					"report_only":          "present",
					"report_only_observed": reportOnlyStr,
				},
				Fingerprint: GenerateFingerprint(CategoryMissingCSP, targetURL, http.MethodGet),
			})
		} else {
			// Case D: Neither enforcing nor report-only CSP present
			findings = append(findings, APIFinding{
				Category:         CategoryMissingCSP,
				Endpoint:         targetURL,
				Method:           http.MethodGet,
				Description:      "Missing Content-Security-Policy (CSP) defense-in-depth header",
				Evidence:         "Response headers do not include Content-Security-Policy.",
				Severity:         SeverityLow,
				Confidence:       ConfidenceHigh,
				HTTPStatus:       statusCode,
				NegativeEvidence: "Informational hardening observation; does not constitute an exploitable vulnerability by itself.",
				Details: map[string]string{
					"header":      "Content-Security-Policy",
					"observed":    "absent",
					"enforcing":   "absent",
					"report_only": "absent",
				},
				Fingerprint: GenerateFingerprint(CategoryMissingCSP, targetURL, http.MethodGet),
			})
		}
	} else {
		// Case A & C: Enforcing CSP present - evaluate directives
		directives := parseCSPDirectives(cspHeader)
		var weakDirectives []string

		scriptTokens, hasScriptSrc := directives["script-src"]
		if !hasScriptSrc {
			scriptTokens = directives["default-src"]
		}

		if containsToken(scriptTokens, "'unsafe-inline'") || containsToken(scriptTokens, "unsafe-inline") {
			weakDirectives = append(weakDirectives, "script-src contains 'unsafe-inline'")
		}
		if containsToken(scriptTokens, "'unsafe-eval'") || containsToken(scriptTokens, "unsafe-eval") {
			weakDirectives = append(weakDirectives, "script-src contains 'unsafe-eval'")
		}

		objectTokens, hasObjectSrc := directives["object-src"]
		if hasObjectSrc && containsToken(objectTokens, "*") {
			weakDirectives = append(weakDirectives, "object-src permits wildcard (*)")
		}

		if len(weakDirectives) > 0 {
			det := map[string]string{
				"header":    "Content-Security-Policy",
				"observed":  cspHeader,
				"issues":    strings.Join(weakDirectives, "; "),
				"enforcing": "present",
			}
			if len(cspReportOnlyValues) > 0 {
				det["report_only"] = "present"
				det["report_only_observed"] = strings.Join(cspReportOnlyValues, "; ")
			}
			findings = append(findings, APIFinding{
				Category:         CategoryWeakCSP,
				Endpoint:         targetURL,
				Method:           http.MethodGet,
				Description:      "Content-Security-Policy contains weak or permissive directives",
				Evidence:         fmt.Sprintf("CSP observed: %s. Identified permissive directives: [%s].", cspHeader, strings.Join(weakDirectives, "; ")),
				Severity:         SeverityLow,
				Confidence:       ConfidenceHigh,
				HTTPStatus:       statusCode,
				NegativeEvidence: "Defense-in-depth posture observation; exploitability requires an independent injection vector.",
				Details:          det,
				Fingerprint:      GenerateFingerprint(CategoryWeakCSP, targetURL, http.MethodGet),
			})
		}
	}

	// 2. Strict-Transport-Security (HSTS)
	// IMPORTANT: Only evaluate HSTS meaningfully when target is HTTPS
	if isHTTPS {
		hstsValues := getHeaderValues(headers, "Strict-Transport-Security")
		if len(hstsValues) == 0 {
			findings = append(findings, APIFinding{
				Category:         CategoryMissingHSTS,
				Endpoint:         targetURL,
				Method:           http.MethodGet,
				Description:      "Missing HTTP Strict-Transport-Security (HSTS) header on HTTPS endpoint",
				Evidence:         "HTTPS response headers do not include Strict-Transport-Security.",
				Severity:         SeverityLow,
				Confidence:       ConfidenceHigh,
				HTTPStatus:       statusCode,
				NegativeEvidence: "Endpoint is served over HTTPS but does not mandate persistent transport security.",
				Details: map[string]string{
					"header":   "Strict-Transport-Security",
					"observed": "absent",
				},
				Fingerprint: GenerateFingerprint(CategoryMissingHSTS, targetURL, http.MethodGet),
			})
		} else {
			hstsHeader := strings.Join(hstsValues, "; ")
			maxAge := parseHSTSMaxAge(hstsHeader)
			if maxAge >= 0 && maxAge < 10368000 {
				findings = append(findings, APIFinding{
					Category:         CategoryWeakHSTS,
					Endpoint:         targetURL,
					Method:           http.MethodGet,
					Description:      "Strict-Transport-Security max-age is set to a short duration",
					Evidence:         fmt.Sprintf("Observed HSTS header: %q. max-age=%d is below recommended 1-year threshold (31536000).", hstsHeader, maxAge),
					Severity:         SeverityInfo,
					Confidence:       ConfidenceHigh,
					HTTPStatus:       statusCode,
					NegativeEvidence: "HSTS is present, but duration is shorter than standard recommendations.",
					Details: map[string]string{
						"header":   "Strict-Transport-Security",
						"observed": hstsHeader,
						"max_age":  strconv.Itoa(maxAge),
					},
					Fingerprint: GenerateFingerprint(CategoryWeakHSTS, targetURL, http.MethodGet),
				})
			}
		}
	}

	// 3. X-Frame-Options & Modern frame-ancestors Equivalence
	xfoValues := getHeaderValues(headers, "X-Frame-Options")
	hasFrameAncestors := strings.Contains(strings.ToLower(cspHeader), "frame-ancestors")
	if len(xfoValues) == 0 && !hasFrameAncestors {
		findings = append(findings, APIFinding{
			Category:         CategoryMissingXFrameOptions,
			Endpoint:         targetURL,
			Method:           http.MethodGet,
			Description:      "Missing X-Frame-Options header (clickjacking protection)",
			Evidence:         "Response headers do not include X-Frame-Options or CSP frame-ancestors directive.",
			Severity:         SeverityLow,
			Confidence:       ConfidenceHigh,
			HTTPStatus:       statusCode,
			NegativeEvidence: "No clickjacking defense-in-depth header was returned by the web server.",
			Details: map[string]string{
				"header":   "X-Frame-Options",
				"observed": "absent",
			},
			Fingerprint: GenerateFingerprint(CategoryMissingXFrameOptions, targetURL, http.MethodGet),
		})
	}

	// 4. X-Content-Type-Options
	xctoValues := getHeaderValues(headers, "X-Content-Type-Options")
	hasNosniff := false
	for _, v := range xctoValues {
		for _, part := range strings.Split(v, ",") {
			if strings.EqualFold(strings.TrimSpace(part), "nosniff") {
				hasNosniff = true
				break
			}
		}
	}
	if !hasNosniff {
		observed := "absent"
		if len(xctoValues) > 0 {
			observed = strings.Join(xctoValues, ", ")
		}
		findings = append(findings, APIFinding{
			Category:         CategoryMissingXContentType,
			Endpoint:         targetURL,
			Method:           http.MethodGet,
			Description:      "Missing or incomplete X-Content-Type-Options: nosniff header",
			Evidence:         fmt.Sprintf("X-Content-Type-Options observed: %q (expected 'nosniff').", observed),
			Severity:         SeverityInfo,
			Confidence:       ConfidenceHigh,
			HTTPStatus:       statusCode,
			NegativeEvidence: "MIME sniffing protection not explicitly declared.",
			Details: map[string]string{
				"header":   "X-Content-Type-Options",
				"observed": observed,
			},
			Fingerprint: GenerateFingerprint(CategoryMissingXContentType, targetURL, http.MethodGet),
		})
	}

	// 5. Permissions-Policy
	permValues := getHeaderValues(headers, "Permissions-Policy")
	if len(permValues) == 0 {
		findings = append(findings, APIFinding{
			Category:         CategoryMissingPermissions,
			Endpoint:         targetURL,
			Method:           http.MethodGet,
			Description:      "Missing Permissions-Policy header (browser feature gating)",
			Evidence:         "Response headers do not include Permissions-Policy.",
			Severity:         SeverityInfo,
			Confidence:       ConfidenceHigh,
			HTTPStatus:       statusCode,
			NegativeEvidence: "Browser feature delegation policy not explicitly configured.",
			Details: map[string]string{
				"header":   "Permissions-Policy",
				"observed": "absent",
			},
			Fingerprint: GenerateFingerprint(CategoryMissingPermissions, targetURL, http.MethodGet),
		})
	}

	// 6. Referrer-Policy Analysis
	refValues := getHeaderValues(headers, "Referrer-Policy")
	if len(refValues) == 0 {
		findings = append(findings, APIFinding{
			Category:         CategoryMissingReferrerPolicy,
			Endpoint:         targetURL,
			Method:           http.MethodGet,
			Description:      "Missing Referrer-Policy defense-in-depth header",
			Evidence:         "Response headers do not include Referrer-Policy (browser default applies).",
			Severity:         SeverityInfo,
			Confidence:       ConfidenceHigh,
			HTTPStatus:       statusCode,
			NegativeEvidence: "Referrer policy is not explicitly declared; browser fallback applies.",
			Details: map[string]string{
				"header":   "Referrer-Policy",
				"observed": "absent",
			},
			Fingerprint: GenerateFingerprint(CategoryMissingReferrerPolicy, targetURL, http.MethodGet),
		})
	} else {
		hasUnsafe := false
		for _, v := range refValues {
			for _, part := range strings.Split(v, ",") {
				if strings.EqualFold(strings.TrimSpace(part), "unsafe-url") {
					hasUnsafe = true
					break
				}
			}
		}
		if hasUnsafe {
			findings = append(findings, APIFinding{
				Category:         CategoryWeakReferrerPolicy,
				Endpoint:         targetURL,
				Method:           http.MethodGet,
				Description:      "Weak Referrer-Policy header allows full URL leakage",
				Evidence:         "Referrer-Policy is configured as 'unsafe-url', transmitting full request URLs with paths and query parameters cross-origin.",
				Severity:         SeverityLow,
				Confidence:       ConfidenceHigh,
				HTTPStatus:       statusCode,
				NegativeEvidence: "Weak referrer policy configured; sensitive parameters in URLs may be leaked cross-origin.",
				Details: map[string]string{
					"header":   "Referrer-Policy",
					"observed": strings.Join(refValues, ", "),
				},
				Fingerprint: GenerateFingerprint(CategoryWeakReferrerPolicy, targetURL, http.MethodGet),
			})
		}
	}

	return findings
}
