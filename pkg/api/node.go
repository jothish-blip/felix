package api

import (
	"context"
	"fmt"
	"net/http"
	"regexp"
	"sort"
	"strings"

	"felix/pkg/secrets"
)

const (
	// MaxNodeResponseSize enforces a strict 512 KiB wire-read limit for Node.js diagnostic inspection.
	MaxNodeResponseSize = 512 * 1024
)

// DefaultNodeCandidatePaths lists standard diagnostic and discovery probe relative paths for Node.js.
var DefaultNodeCandidatePaths = []string{
	"/_felix_node_probe",
}

var (
	// nodeStackTraceFrameRegex matches standard V8/Node.js stack trace lines, e.g. "    at /app/routes/api.js:45:12" or "    at Object.run (/app/index.js:10:5)"
	nodeStackTraceFrameRegex = regexp.MustCompile(`(?m)^\s*at\s+(?:(?:async\s+)?([a-zA-Z0-9_\.\<\>\[\]\$]+)\s+\()?([A-Za-z0-9_\-\.\/\\:]+\.(?:js|ts|mjs|cjs|jsx|tsx)):(\d+):(\d+)\)?`)
	// nodeInternalFrameRegex matches Node.js core library and node_modules internal call frames
	nodeInternalFrameRegex = regexp.MustCompile(`(?m)^\s*at\s+.*(?:\((?:node:)?internal\/|node_modules\/)`)
	// nodeErrorHeaderRegex matches standard Node.js and database error class prefixes
	nodeErrorHeaderRegex = regexp.MustCompile(`(?m)^(?:Error|TypeError|ReferenceError|SyntaxError|RangeError|URIError|EvalError|MongoServerError|Sequelize\w+Error|PrismaClient\w+Error):\s*(.+)$`)
	// nodeFilePathRegex matches internal absolute filesystem paths for Node.js applications
	nodeFilePathRegex = regexp.MustCompile(`(?:^|[\s\("'])(/(?:var/www|usr/src|app|home|opt|workspace|srv|root)/[a-zA-Z0-9_\-\./\\]+\.(?:js|ts|mjs|cjs|jsx|tsx)|[A-Za-z]:\\[a-zA-Z0-9_\-\.\\]+\.(?:js|ts|mjs|cjs|jsx|tsx))`)
	// nodeVersionRegex matches explicit Node.js version disclosure strings
	nodeVersionRegex = regexp.MustCompile(`(?i)(?:Node\.js|node)[/\s]v?(\d+\.\d+\.\d+)`)
)

// AuditNodeDiagnostics coordinates safe, bounded assessment of Node.js and Express diagnostic behavior.
func AuditNodeDiagnostics(ctx context.Context, client *Client, targetBaseURL string, candidatePaths []string) []APIFinding {
	var findings []APIFinding
	resolvedCandidates := ResolveNodeCandidateURLs(targetBaseURL, candidatePaths)

	seenFP := make(map[string]struct{})
	for _, targetURL := range resolvedCandidates {
		if client.isExcluded != nil && client.isExcluded(targetURL) {
			continue
		}
		if client.isAllowed != nil && !client.isAllowed(targetURL) {
			continue
		}

		endpointFindings := ProbeNodeEndpoint(ctx, client, targetURL)
		for _, f := range endpointFindings {
			if _, exists := seenFP[f.Fingerprint]; !exists {
				seenFP[f.Fingerprint] = struct{}{}
				findings = append(findings, f)
			}
		}
	}

	return findings
}

// ResolveNodeCandidateURLs resolves candidate Node.js diagnostic URLs for a target base URL,
// supporting nested application paths, root origin endpoints, and crawled asset hints.
func ResolveNodeCandidateURLs(targetBaseURL string, customCandidates []string) []string {
	baseURL := strings.TrimRight(targetBaseURL, "/")
	if baseURL == "" {
		return nil
	}

	seen := make(map[string]struct{})
	var candidates []string

	addURL := func(u string) {
		clean := strings.TrimSpace(u)
		if clean == "" {
			return
		}
		if _, exists := seen[clean]; !exists {
			seen[clean] = struct{}{}
			candidates = append(candidates, clean)
		}
	}

	// 1. Default probe path (harmless non-existent route to check for verbose error handlers)
	for _, p := range DefaultNodeCandidatePaths {
		addURL(baseURL + p)
	}

	// 2. Custom or discovered candidate paths from crawled assets
	for _, cp := range customCandidates {
		clean := strings.TrimSpace(cp)
		if clean == "" {
			continue
		}
		lower := strings.ToLower(clean)
		if strings.Contains(lower, "node") || strings.Contains(lower, "express") ||
			strings.Contains(lower, "debug") || strings.Contains(lower, "error") ||
			strings.Contains(lower, "api") {
			if strings.HasPrefix(clean, "http://") || strings.HasPrefix(clean, "https://") {
				addURL(clean)
			} else {
				if !strings.HasPrefix(clean, "/") {
					clean = "/" + clean
				}
				addURL(baseURL + clean)
			}
		}
	}

	return candidates
}

// ProbeNodeEndpoint dispatches a bounded, safe HTTP GET probe to assess Node.js diagnostic disclosure.
func ProbeNodeEndpoint(ctx context.Context, client *Client, targetURL string) []APIFinding {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, targetURL, nil)
	if err != nil {
		return nil
	}
	req.Header.Set("Accept", "text/html,application/json,*/*")

	resp, err := client.DoBounded(ctx, req, MaxNodeResponseSize)
	if err != nil {
		return nil
	}

	// Properly protected endpoints (401/403 or redirect to login) are NOT findings
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return nil
	}
	if resp.StatusCode == http.StatusFound || resp.StatusCode == http.StatusSeeOther || resp.StatusCode == http.StatusTemporaryRedirect {
		loc := resp.Header.Get("Location")
		if strings.Contains(strings.ToLower(loc), "login") || strings.Contains(strings.ToLower(loc), "auth") {
			return nil
		}
	}

	return InspectNodeResponse(resp, targetURL)
}

// InspectNodeResponse evaluates HTTP response headers and body for Node.js runtime and stack trace indicators.
func InspectNodeResponse(resp *ProbeResponse, endpointURL string) []APIFinding {
	if resp == nil {
		return nil
	}

	var findings []APIFinding
	bodyStr := string(resp.Body)
	lowerBody := strings.ToLower(bodyStr)

	// 1. Check for runtime identifying headers (e.g. X-Powered-By: Express)
	poweredBy := strings.TrimSpace(resp.Header.Get("X-Powered-By"))
	lowerPowered := strings.ToLower(poweredBy)
	hasExpressHeader := strings.Contains(lowerPowered, "express")
	hasNextHeader := strings.Contains(lowerPowered, "next.js") || strings.Contains(lowerPowered, "nextjs")

	// 2. Extract and evaluate Node.js stack trace frames and file paths
	stackFrames := nodeStackTraceFrameRegex.FindAllString(bodyStr, -1)
	internalFrames := nodeInternalFrameRegex.FindAllString(bodyStr, -1)
	errorMatches := nodeErrorHeaderRegex.FindAllStringSubmatch(bodyStr, -1)
	filePaths := nodeFilePathRegex.FindAllStringSubmatch(bodyStr, -1)

	// De-duplicate extracted filesystem paths
	seenPaths := make(map[string]struct{})
	var uniquePaths []string
	for _, m := range filePaths {
		if len(m) > 1 {
			p := strings.TrimSpace(m[1])
			if _, exists := seenPaths[p]; !exists {
				seenPaths[p] = struct{}{}
				uniquePaths = append(uniquePaths, p)
			}
		}
	}
	sort.Strings(uniquePaths)

	hasGenuineStackTrace := len(stackFrames) >= 2 || (len(errorMatches) > 0 && len(stackFrames) >= 1) || len(internalFrames) >= 2
	hasExpressHTMLTemplate := strings.Contains(lowerBody, "<pre>cannot get ") ||
		strings.Contains(lowerBody, "title>error</title>") && hasGenuineStackTrace

	// Check for candidate unmasked secrets in error body
	hasUnmaskedSecret := false
	var observedSecretKeys []string
	for _, line := range strings.Split(bodyStr, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		// Check key-value assignments e.g. "DB_PASS=...", "password: '...'"
		if strings.Contains(trimmed, "=") || strings.Contains(trimmed, ":") {
			parts := strings.SplitN(trimmed, "=", 2)
			if len(parts) < 2 {
				parts = strings.SplitN(trimmed, ":", 2)
			}
			if len(parts) == 2 {
				k := strings.Trim(strings.TrimSpace(parts[0]), `"'`)
				v := strings.Trim(strings.TrimSpace(parts[1]), `"',;`)
				if isGenuineUnmaskedSecret(k, v) {
					hasUnmaskedSecret = true
					observedSecretKeys = append(observedSecretKeys, k)
				}
			}
		}
		// Also direct synthetic canary check
		if strings.Contains(trimmed, "felix_test_canary_secret") {
			hasUnmaskedSecret = true
			observedSecretKeys = append(observedSecretKeys, "canary_secret")
		}
	}

	// 3. Evaluate Verbose Stack Trace / Development Error Disclosure
	if hasGenuineStackTrace {
		severity := SeverityMedium
		desc := "Node.js verbose stack trace disclosed via HTTP error response"
		confidence := ConfidenceHigh

		if hasUnmaskedSecret {
			severity = SeverityCritical
			desc = "Node.js diagnostic error response exposes candidate secret material (validity unverified)"
		} else if isNodeSensitiveError(bodyStr) {
			severity = SeverityHigh
			desc = "Node.js diagnostic error response exposes sensitive database or internal application details"
		} else if len(uniquePaths) > 0 {
			severity = SeverityMedium
			desc = "Node.js verbose stack trace exposes internal filesystem paths and application structure"
		}

		evPrefix := fmt.Sprintf("HTTP %d error response on %s disclosed Node.js call frames.", resp.StatusCode, endpointURL)
		if len(uniquePaths) > 0 {
			sample := uniquePaths
			if len(sample) > 3 {
				sample = sample[:3]
			}
			evPrefix += fmt.Sprintf(" Disclosed %d internal path(s): [%s].", len(uniquePaths), strings.Join(sample, ", "))
		}
		if hasUnmaskedSecret {
			evPrefix += fmt.Sprintf(" Candidate secret material observed: [%s] (active validity was not verified; values redacted).",
				strings.Join(observedSecretKeys, ", "))
		}

		negEv := "Detected candidate diagnostic stack trace. Active credential validity was not tested or confirmed; all sensitive paths and values were bounded and redacted."

		details := map[string]string{
			"framework":                "Node.js",
			"component":                "ErrorHandler",
			"endpoint":                 endpointURL,
			"http_status":              fmt.Sprintf("%d", resp.StatusCode),
			"stack_frames_count":       fmt.Sprintf("%d", len(stackFrames)),
			"validity_status":          "unverified_active_probe_omitted",
			"active_auth_tested":       "false",
			"verification_limitations": "Passive read-only inspection; backend state was not altered",
		}
		if len(uniquePaths) > 0 {
			details["disclosed_paths_count"] = fmt.Sprintf("%d", len(uniquePaths))
			details["sample_path"] = uniquePaths[0]
		}
		if hasUnmaskedSecret {
			details["unmasked_secrets_count"] = fmt.Sprintf("%d", len(observedSecretKeys))
			details["candidate_material_status"] = "unverified_candidate_material"
		}
		if resp.Truncated {
			details["limitations"] = "Response exceeded 512 KiB and was bounded to preserve system resources"
		}

		// Recursively redact all detail values
		for k, v := range details {
			if secrets.IsSensitiveKey(k) || secrets.IsSensitiveHeader(k) {
				details[k] = "[REDACTED]"
			} else {
				details[k] = secrets.RedactText(v)
			}
		}

		findings = append(findings, APIFinding{
			Category:         CategoryNodeStackTrace,
			Endpoint:         endpointURL,
			Method:           http.MethodGet,
			Description:      secrets.RedactText(desc),
			Evidence:         secrets.RedactText(evPrefix),
			NegativeEvidence: secrets.RedactText(negEv),
			Severity:         severity,
			Confidence:       confidence,
			Fingerprint:      GenerateFingerprint(CategoryNodeStackTrace, endpointURL, http.MethodGet),
			Classification:   ClassHealth,
			Details:          details,
			HTTPStatus:       resp.StatusCode,
		})
		return findings
	}

	// 4. Evaluate Filesystem Path Disclosed Without Full Stack Trace
	if len(uniquePaths) > 0 && (resp.StatusCode >= 400 || len(errorMatches) > 0) {
		desc := "Node.js diagnostic error response exposes internal filesystem path"
		evPrefix := fmt.Sprintf("HTTP %d on %s disclosed internal filesystem path(s): [%s] without a full call stack.",
			resp.StatusCode, endpointURL, strings.Join(uniquePaths, ", "))
		negEv := "Internal application path observed in error response without complete stack trace; active credential validity was not tested."

		severity := SeverityLow
		if hasUnmaskedSecret {
			severity = SeverityCritical
			desc = "Node.js error response exposes candidate secret material (validity unverified)"
		} else if isNodeSensitiveError(bodyStr) {
			severity = SeverityMedium
		}

		details := map[string]string{
			"framework":                "Node.js",
			"component":                "ErrorHandler",
			"endpoint":                 endpointURL,
			"http_status":              fmt.Sprintf("%d", resp.StatusCode),
			"disclosed_paths_count":    fmt.Sprintf("%d", len(uniquePaths)),
			"sample_path":              uniquePaths[0],
			"has_stack_trace":          "false",
			"validity_status":          "unverified_active_probe_omitted",
			"active_auth_tested":       "false",
			"verification_limitations": "Passive read-only inspection; backend state was not altered",
		}
		if hasUnmaskedSecret {
			details["unmasked_secrets_count"] = fmt.Sprintf("%d", len(observedSecretKeys))
			details["candidate_material_status"] = "unverified_candidate_material"
		}
		if resp.Truncated {
			details["limitations"] = "Response exceeded 512 KiB and was bounded to preserve system resources"
		}

		for k, v := range details {
			if secrets.IsSensitiveKey(k) || secrets.IsSensitiveHeader(k) {
				details[k] = "[REDACTED]"
			} else {
				details[k] = secrets.RedactText(v)
			}
		}

		findings = append(findings, APIFinding{
			Category:         CategoryNodeDebugError,
			Endpoint:         endpointURL,
			Method:           http.MethodGet,
			Description:      secrets.RedactText(desc),
			Evidence:         secrets.RedactText(evPrefix),
			NegativeEvidence: secrets.RedactText(negEv),
			Severity:         severity,
			Confidence:       ConfidenceHigh,
			Fingerprint:      GenerateFingerprint(CategoryNodeDebugError, endpointURL, http.MethodGet),
			Classification:   ClassHealth,
			Details:          details,
			HTTPStatus:       resp.StatusCode,
		})
		return findings
	}

	// 5. Evaluate Express / Next.js Runtime Header Identification (Informational only)
	if hasExpressHeader || hasNextHeader {
		techName := "Express"
		if hasNextHeader {
			techName = "Next.js"
		}

		// Framework header alone is NOT a vulnerability -> SeverityInfo
		findings = append(findings, APIFinding{
			Category:         CategoryNodeRuntimeExposure,
			Endpoint:         endpointURL,
			Method:           http.MethodGet,
			Description:      fmt.Sprintf("Node.js %s framework identified via HTTP response header", techName),
			Evidence:         fmt.Sprintf("HTTP %d on %s returned X-Powered-By: %s header.", resp.StatusCode, endpointURL, poweredBy),
			NegativeEvidence: "Framework identifier observed in HTTP response header; no debug interface, stack trace, or unauthenticated data disclosure was demonstrated.",
			Severity:         SeverityInfo,
			Confidence:       ConfidenceHigh,
			Fingerprint:      GenerateFingerprint(CategoryNodeRuntimeExposure, endpointURL, http.MethodGet),
			Classification:   ClassAPI,
			Details: map[string]string{
				"framework":   techName,
				"header_name": "X-Powered-By",
				"http_status": fmt.Sprintf("%d", resp.StatusCode),
			},
			HTTPStatus: resp.StatusCode,
		})
		return findings
	}

	// Suppress generic 4xx/5xx responses and unrelated HTML without Node.js debug evidence
	_ = hasExpressHTMLTemplate
	return nil
}

// isNodeSensitiveError checks if a Node.js error disclosure contains database error keywords, SQL queries, or PII.
func isNodeSensitiveError(body string) bool {
	lower := strings.ToLower(body)

	// Check for sensitive database errors or query statements
	if strings.Contains(lower, "mongoservererror") || strings.Contains(lower, "sequelizedatabaseerror") ||
		strings.Contains(lower, "prismaclient") {
		return true
	}

	// Check for sensitive SQL queries or column keywords in error message
	if strings.Contains(lower, "password") || strings.Contains(lower, "passwd") ||
		strings.Contains(lower, "secret") || strings.Contains(lower, "api_key") ||
		strings.Contains(lower, "bearer ") || strings.Contains(lower, "token") ||
		strings.Contains(lower, "credit_card") || strings.Contains(lower, "ssn") {
		return true
	}

	return false
}
