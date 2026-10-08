package api

import (
	"context"
	"fmt"
	"net/http"
	"regexp"
	"sort"
	"strings"
)

// DefaultSensitivePaths lists common paths checked for sensitive exposures.
var DefaultSensitivePaths = []string{
	"/.env",
	"/.env.local",
	"/.env.example",
	"/.git/HEAD",
	"/swagger.json",
	"/openapi.json",
	"/api-docs",
	"/api/debug",
	"/actuator/health",
	"/metrics",
}

var (
	envLineRegex     = regexp.MustCompile(`(?m)^([A-Za-z0-9_]{3,})\s*=\s*(.+)$`)
	gitRefRegex      = regexp.MustCompile(`^(?:ref:\s*refs/heads/[A-Za-z0-9_\-\./]+|[0-9a-fA-F]{40})\s*$`)
	promMetricsRegex = regexp.MustCompile(`(?m)^(?:#\s*HELP|#\s*TYPE|[a-zA-Z_:][a-zA-Z0-9_:]*\{)`)
)

// AuditSensitiveEndpoints scans a target for unauthenticated sensitive configuration or operational exposures.
func AuditSensitiveEndpoints(ctx context.Context, client *Client, targetBaseURL string, customPaths []string) []APIFinding {
	var findings []APIFinding
	baseURL := strings.TrimRight(targetBaseURL, "/")

	pathsToCheck := DefaultSensitivePaths
	if len(customPaths) > 0 {
		seen := make(map[string]struct{})
		for _, p := range append(DefaultSensitivePaths, customPaths...) {
			cleanP := strings.TrimSpace(p)
			if cleanP == "" {
				continue
			}
			if !strings.HasPrefix(cleanP, "/") {
				cleanP = "/" + cleanP
			}
			if _, exists := seen[cleanP]; !exists {
				seen[cleanP] = struct{}{}
			}
		}
		var merged []string
		for p := range seen {
			merged = append(merged, p)
		}
		pathsToCheck = merged
	}

	for _, p := range pathsToCheck {
		endpointURL := baseURL + p
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpointURL, nil)
		if err != nil {
			continue
		}
		req.Header.Set("Accept", "*/*")

		resp, err := client.Do(ctx, req)
		if err != nil {
			if err == ErrRateLimited {
				break
			}
			continue
		}

		// 404, 403, 401: Properly protected or non-existent
		if resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusUnauthorized {
			continue
		}

		if resp.StatusCode != http.StatusOK {
			continue
		}

		bodyStr := string(resp.Body)
		lowerBody := strings.ToLower(bodyStr)
		isHTML := strings.Contains(lowerBody, "<html") || strings.Contains(lowerBody, "<!doctype")

		// 1. .env and .env.local file exposure
		if (p == "/.env" || p == "/.env.local") && !isHTML {
			matches := envLineRegex.FindAllStringSubmatch(bodyStr, -1)
			if len(matches) > 0 {
				var varNames []string
				for _, m := range matches {
					varNames = append(varNames, m[1])
				}
				sort.Strings(varNames)
				if len(varNames) > 6 {
					varNames = append(varNames[:6], fmt.Sprintf("... +%d more", len(varNames)-6))
				}

				findings = append(findings, APIFinding{
					Category:    CategoryEnvExposure,
					Endpoint:    endpointURL,
					Method:      http.MethodGet,
					Description: fmt.Sprintf("Public exposure of sensitive %s configuration file", p),
					Evidence: fmt.Sprintf("HTTP 200 OK. Observed variable declarations: [%s] (secret values redacted).",
						strings.Join(varNames, ", ")),
					Severity:    SeverityCritical,
					Confidence:  ConfidenceHigh,
					Fingerprint: GenerateFingerprint(CategoryEnvExposure, endpointURL, http.MethodGet),
				})
				continue
			}
		}

		// 2. .env.example exposure
		if p == "/.env.example" && !isHTML {
			matches := envLineRegex.FindAllStringSubmatch(bodyStr, -1)
			if len(matches) > 0 {
				findings = append(findings, APIFinding{
					Category:    CategoryEnvExposure,
					Endpoint:    endpointURL,
					Method:      http.MethodGet,
					Description: "Public exposure of .env.example configuration template",
					Evidence:    fmt.Sprintf("HTTP 200 OK. %d configuration variables observed.", len(matches)),
					Severity:    SeverityMedium,
					Confidence:  ConfidenceHigh,
					Fingerprint: GenerateFingerprint(CategoryEnvExposure, endpointURL, http.MethodGet),
				})
				continue
			}
		}

		// 3. .git/HEAD metadata exposure
		if p == "/.git/HEAD" && !isHTML {
			cleanHead := strings.TrimSpace(bodyStr)
			if gitRefRegex.MatchString(cleanHead) {
				findings = append(findings, APIFinding{
					Category:    CategoryGitExposure,
					Endpoint:    endpointURL,
					Method:      http.MethodGet,
					Description: "Public Git repository metadata exposed via .git/HEAD",
					Evidence:    fmt.Sprintf("HTTP 200 OK. Valid Git HEAD reference observed: %s", cleanHead),
					Severity:    SeverityHigh,
					Confidence:  ConfidenceHigh,
					Fingerprint: GenerateFingerprint(CategoryGitExposure, endpointURL, http.MethodGet),
				})
				continue
			}
		}

		// 4. Swagger / OpenAPI documentation
		if (p == "/swagger.json" || p == "/openapi.json" || p == "/api-docs") {
			isSwaggerDoc := strings.Contains(lowerBody, `"swagger":`) ||
				strings.Contains(lowerBody, `"openapi":`) ||
				strings.Contains(lowerBody, `swagger-ui`) ||
				strings.Contains(lowerBody, `openapi`)
			if isSwaggerDoc {
				findings = append(findings, APIFinding{
					Category:    CategoryAPIDocsExposure,
					Endpoint:    endpointURL,
					Method:      http.MethodGet,
					Description: "Publicly accessible API documentation / OpenAPI specification",
					Evidence:    fmt.Sprintf("HTTP 200 OK. Public API documentation discovered at %s.", p),
					Severity:    SeverityLow,
					Confidence:  ConfidenceHigh,
					Fingerprint: GenerateFingerprint(CategoryAPIDocsExposure, endpointURL, http.MethodGet),
				})
				continue
			}
		}

		// 5. Spring Boot Actuator health
		if p == "/actuator/health" {
			if strings.Contains(lowerBody, `"status"`) && (strings.Contains(lowerBody, `"up"`) || strings.Contains(lowerBody, `"down"`)) {
				findings = append(findings, APIFinding{
					Category:    CategoryHealthExposure,
					Endpoint:    endpointURL,
					Method:      http.MethodGet,
					Description: "Public application health monitoring endpoint",
					Evidence:    "HTTP 200 OK. Standard operational health status observed.",
					Severity:    SeverityInfo,
					Confidence:  ConfidenceHigh,
					Fingerprint: GenerateFingerprint(CategoryHealthExposure, endpointURL, http.MethodGet),
				})
				continue
			}
		}

		// 6. Prometheus / OpenMetrics
		if p == "/metrics" && !isHTML {
			if promMetricsRegex.MatchString(bodyStr) {
				lineCount := len(strings.Split(bodyStr, "\n"))
				findings = append(findings, APIFinding{
					Category:    CategoryMetricsExposure,
					Endpoint:    endpointURL,
					Method:      http.MethodGet,
					Description: "Public application telemetry and operational metrics endpoint",
					Evidence: fmt.Sprintf("HTTP 200 OK. Metrics endpoint observed (%d metric lines). Metric values redacted.",
						lineCount),
					Severity:    SeverityLow,
					Confidence:  ConfidenceHigh,
					Fingerprint: GenerateFingerprint(CategoryMetricsExposure, endpointURL, http.MethodGet),
				})
				continue
			}
		}
	}

	return findings
}
