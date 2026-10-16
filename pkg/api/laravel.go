package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"sort"
	"strings"

	"felix/pkg/secrets"
)

const (
	// MaxLaravelResponseSize enforces a strict 512 KiB wire-read limit for Laravel diagnostic inspection.
	MaxLaravelResponseSize = 512 * 1024
)

// DefaultLaravelCandidatePaths lists standard diagnostic, monitoring, and probe relative paths for Laravel.
var DefaultLaravelCandidatePaths = []string{
	"/_felix_ignition_probe",
	"/_ignition/health-check",
	"/telescope",
	"/telescope/telescope-api/requests",
}

var (
	laravelVersionRegex         = regexp.MustCompile(`(?i)(?:Laravel\s+(?:v|version\s*:?\s*)?([0-9\.]+)|"laravel_version"\s*:\s*"([^"]+)")`)
	phpVersionRegex             = regexp.MustCompile(`(?i)(?:PHP\s+(?:v|version\s*:?\s*)?([0-9\.]+)|"php_version"\s*:\s*"([^"]+)")`)
	laravelTracebackFrameRegex  = regexp.MustCompile(`(?m)(?:File\s+["']|in\s+)?([/\\a-zA-Z0-9_\-\.]+\.php)(?:\s*(?:line|:)\s*(\d+))?`)
	laravelEnvRowRegex          = regexp.MustCompile(`(?i)["']?([A-Za-z0-9_]{3,})["']?\s*(?::|=>|=)\s*["']?([^"',\s\r\n\]}]+)["']?`)
)

// AuditLaravelDiagnostics coordinates safe, bounded assessment of Laravel Ignition and Telescope interfaces.
func AuditLaravelDiagnostics(ctx context.Context, client *Client, targetBaseURL string, candidatePaths []string) []APIFinding {
	var findings []APIFinding
	resolvedCandidates := ResolveLaravelCandidateURLs(targetBaseURL, candidatePaths)

	seenFP := make(map[string]struct{})
	for _, targetURL := range resolvedCandidates {
		// Enforce client scope and exclusion rules before dispatching
		if client.isExcluded != nil && client.isExcluded(targetURL) {
			continue
		}
		if client.isAllowed != nil && !client.isAllowed(targetURL) {
			continue
		}

		endpointFindings := ProbeLaravelEndpoint(ctx, client, targetURL)
		for _, f := range endpointFindings {
			if _, exists := seenFP[f.Fingerprint]; !exists {
				seenFP[f.Fingerprint] = struct{}{}
				findings = append(findings, f)
			}
		}
	}

	return findings
}

// ResolveLaravelCandidateURLs resolves candidate Laravel diagnostic URLs for a target base URL,
// supporting nested application paths, root origin endpoints, and crawled asset hints.
func ResolveLaravelCandidateURLs(targetBaseURL string, customCandidates []string) []string {
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

	// 1. Base URL candidates (handles nested base paths and root targets)
	for _, p := range DefaultLaravelCandidatePaths {
		addURL(baseURL + p)
	}

	// 2. Custom or discovered candidate paths from crawled assets
	for _, cp := range customCandidates {
		clean := strings.TrimSpace(cp)
		if clean == "" {
			continue
		}
		lower := strings.ToLower(clean)
		if strings.Contains(lower, "telescope") || strings.Contains(lower, "ignition") ||
			strings.Contains(lower, "horizon") || strings.Contains(lower, "laravel") {
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

// ProbeLaravelEndpoint probes a candidate URL and evaluates Ignition or Telescope disclosures.
func ProbeLaravelEndpoint(ctx context.Context, client *Client, targetURL string) []APIFinding {
	var findings []APIFinding

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, targetURL, nil)
	if err != nil {
		return nil
	}
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/json;q=0.9,*/*;q=0.8")

	resp, err := client.DoBounded(ctx, req, MaxLaravelResponseSize)
	if err != nil {
		return nil
	}

	lowerURL := strings.ToLower(targetURL)

	// 1. Inspect Ignition Health Check endpoint
	if strings.HasSuffix(lowerURL, "/_ignition/health-check") {
		if f := InspectIgnitionHealthCheck(resp, targetURL); f != nil {
			findings = append(findings, *f)
			return findings
		}
	}

	// 2. Inspect Telescope API endpoint
	if strings.Contains(lowerURL, "/telescope-api/") {
		if f := InspectTelescopeAPI(resp, targetURL); f != nil {
			findings = append(findings, *f)
			return findings
		}
	}

	// 3. Inspect Telescope UI Dashboard endpoint
	if strings.HasSuffix(lowerURL, "/telescope") || strings.HasSuffix(lowerURL, "/telescope/") {
		if f := InspectLaravelTelescope(resp, targetURL); f != nil {
			findings = append(findings, *f)
			return findings
		}
	}

	// 4. Inspect for Laravel Ignition Debug Page (e.g. from /_felix_ignition_probe or standard requests)
	if f := InspectLaravelIgnition(resp, targetURL); f != nil {
		findings = append(findings, *f)
		return findings
	}

	return findings
}

// InspectLaravelIgnition detects Laravel Ignition error/debug pages and Whoops/Laravel tracebacks.
func InspectLaravelIgnition(resp *ProbeResponse, endpointURL string) *APIFinding {
	if resp == nil || len(resp.Body) == 0 {
		return nil
	}

	// Ignition/diagnostic pages are typically returned on HTTP 500, 404, or 400
	if resp.StatusCode != http.StatusInternalServerError &&
		resp.StatusCode != http.StatusNotFound &&
		resp.StatusCode != http.StatusBadRequest {
		return nil
	}

	bodyStr := string(resp.Body)
	lowerBody := strings.ToLower(bodyStr)

	// Direct Ignition structural and frontend markers
	hasDirectIgnition := strings.Contains(lowerBody, "window.data =") ||
		strings.Contains(lowerBody, "window.data=") ||
		strings.Contains(lowerBody, "window.ignition") ||
		strings.Contains(bodyStr, "IGNITION_CONFIG") ||
		strings.Contains(lowerBody, "spatie/laravel-ignition") ||
		strings.Contains(lowerBody, "facade/ignition") ||
		strings.Contains(bodyStr, `id="ignition"`) ||
		strings.Contains(bodyStr, `class="ignition"`) ||
		strings.Contains(bodyStr, "flareapp.io") ||
		(strings.Contains(bodyStr, `id="app"`) && strings.Contains(bodyStr, "data-data=")) ||
		strings.Contains(lowerBody, "<title>ignition</title>")

	// Generic Laravel / Whoops exception markers
	hasWhoopsOrLaravel := strings.Contains(bodyStr, "Whoops! There was an error.") ||
		strings.Contains(bodyStr, "Whoops \\ Exception") ||
		strings.Contains(bodyStr, "Symfony\\Component\\HttpKernel\\Exception") ||
		strings.Contains(bodyStr, "Illuminate\\") ||
		strings.Contains(bodyStr, "vendor/laravel/framework") ||
		strings.Contains(lowerBody, "laravel v") ||
		strings.Contains(lowerBody, "laravel version")

	if !hasDirectIgnition && !hasWhoopsOrLaravel {
		return nil
	}

	// Extract Laravel and PHP versions
	laravelVer := ""
	if m := laravelVersionRegex.FindStringSubmatch(bodyStr); len(m) > 1 {
		laravelVer = strings.TrimSpace(m[1])
		if laravelVer == "" && len(m) > 2 {
			laravelVer = strings.TrimSpace(m[2])
		}
	}

	phpVer := ""
	if m := phpVersionRegex.FindStringSubmatch(bodyStr); len(m) > 1 {
		phpVer = strings.TrimSpace(m[1])
		if phpVer == "" && len(m) > 2 {
			phpVer = strings.TrimSpace(m[2])
		}
	}

	// Extract filesystem paths in stack trace frames
	var exposedPaths []string
	frameMatches := laravelTracebackFrameRegex.FindAllStringSubmatch(bodyStr, -1)
	seenPaths := make(map[string]struct{})
	for _, m := range frameMatches {
		if len(m) > 1 {
			p := strings.TrimSpace(m[1])
			if strings.HasSuffix(p, ".php") && (strings.Contains(p, "/") || strings.Contains(p, "\\")) {
				if _, exists := seenPaths[p]; !exists {
					seenPaths[p] = struct{}{}
					exposedPaths = append(exposedPaths, p)
				}
			}
		}
	}
	sort.Strings(exposedPaths)

	// If no direct Ignition marker and no stack trace paths, suppress generic error page
	if !hasDirectIgnition && len(exposedPaths) == 0 {
		return nil
	}

	// Check for unmasked defensible secrets (e.g. APP_KEY, DB_PASSWORD, AWS credentials)
	hasUnmaskedSecret := false
	var unmaskedSecretKeys []string

	envMatches := laravelEnvRowRegex.FindAllStringSubmatch(bodyStr, -1)
	for _, m := range envMatches {
		if len(m) > 2 {
			k := strings.TrimSpace(m[1])
			v := strings.TrimSpace(m[2])
			if isLaravelSecretKey(k) && (isDefensibleSecretValue(k, v) || (len(v) >= 8 && !secrets.IsPlaceholder(v))) {
				hasUnmaskedSecret = true
				unmaskedSecretKeys = append(unmaskedSecretKeys, k)
			}
		}
	}

	debugModeStatus := "suspected"
	confidence := ConfidenceMedium
	desc := "Laravel framework exception traceback observed (suspected debug mode)"
	if hasDirectIgnition {
		debugModeStatus = "confirmed"
		confidence = ConfidenceHigh
		desc = "Laravel Ignition debug page exposed (APP_DEBUG=true confirmed)"
	}

	// Evaluate severity based on actual sensitivity of disclosed content
	severity := SeverityMedium
	if hasUnmaskedSecret {
		severity = SeverityCritical
	} else if hasDirectIgnition {
		severity = SeverityHigh
	} else if len(exposedPaths) > 1 {
		severity = SeverityMedium
	} else {
		severity = SeverityLow
	}

	// Format evidence cleanly with bounded, redacted strings
	var pathSummary string
	if len(exposedPaths) > 0 {
		sample := exposedPaths
		if len(sample) > 3 {
			sample = sample[:3]
		}
		pathSummary = fmt.Sprintf(" Disclosed %d filesystem path(s) in stack trace: [%s].",
			len(exposedPaths), strings.Join(sample, ", "))
	}

	statusPrefix := "HTTP %d Laravel exception traceback observed exposing internal filesystem paths (suspected debug mode)."
	if hasDirectIgnition {
		statusPrefix = "HTTP %d Laravel Ignition debug page confirmed (APP_DEBUG=true)."
	}
	evidence := fmt.Sprintf(statusPrefix, resp.StatusCode)
	if pathSummary != "" {
		evidence += pathSummary
	}
	if laravelVer != "" {
		evidence += fmt.Sprintf(" Framework: Laravel %s.", laravelVer)
	}
	if phpVer != "" {
		evidence += fmt.Sprintf(" Runtime: PHP %s.", phpVer)
	}
	if hasUnmaskedSecret {
		evidence += fmt.Sprintf(" Unmasked credential(s) observed: [%s] (secret values redacted).",
			strings.Join(unmaskedSecretKeys, ", "))
	}

	var negEv string
	if !hasDirectIgnition {
		negEv = "Traceback observed without official Laravel Ignition developer template; APP_DEBUG=true configuration remains unconfirmed."
	} else if !hasUnmaskedSecret {
		negEv = "Official Laravel Ignition debug page confirmed; no unmasked database passwords or application secrets were detected."
	} else {
		negEv = "All detected credentials and secret values were bounded and redacted."
	}

	details := map[string]string{
		"framework":   "Laravel",
		"debug_mode":  debugModeStatus,
		"http_status": fmt.Sprintf("%d", resp.StatusCode),
	}
	if laravelVer != "" {
		details["laravel_version"] = laravelVer
	}
	if phpVer != "" {
		details["php_version"] = phpVer
	}
	if len(exposedPaths) > 0 {
		details["disclosed_paths_count"] = fmt.Sprintf("%d", len(exposedPaths))
		details["sample_path"] = exposedPaths[0]
	}
	if hasUnmaskedSecret {
		details["unmasked_secrets_count"] = fmt.Sprintf("%d", len(unmaskedSecretKeys))
	}
	if resp.Truncated {
		details["limitations"] = "Response exceeded 512 KiB and was bounded to preserve system resources"
	}

	return &APIFinding{
		Category:         CategoryLaravelIgnitionDebug,
		Endpoint:         endpointURL,
		Method:           http.MethodGet,
		Description:      desc,
		Evidence:         secrets.RedactText(evidence),
		NegativeEvidence: negEv,
		Severity:         severity,
		Confidence:       confidence,
		Fingerprint:      GenerateFingerprint(CategoryLaravelIgnitionDebug, endpointURL, http.MethodGet),
		Classification:   ClassHealth,
		Details:          details,
		HTTPStatus:       resp.StatusCode,
	}
}

// InspectIgnitionHealthCheck evaluates the Ignition /_ignition/health-check endpoint.
func InspectIgnitionHealthCheck(resp *ProbeResponse, endpointURL string) *APIFinding {
	if resp == nil || resp.StatusCode != http.StatusOK || len(resp.Body) == 0 {
		return nil
	}

	bodyStr := string(resp.Body)
	lowerBody := strings.ToLower(bodyStr)

	// Must be genuine Ignition health check JSON
	if !strings.Contains(lowerBody, "can_execute_commands") &&
		!strings.Contains(lowerBody, "health") &&
		!strings.Contains(lowerBody, "ignition") {
		return nil
	}

	canExecute := strings.Contains(lowerBody, `"can_execute_commands":true`) ||
		strings.Contains(lowerBody, `"can_execute_commands": true`)

	severity := SeverityInfo
	desc := "Laravel Ignition health-check diagnostic endpoint reachable"
	ev := fmt.Sprintf("HTTP 200 OK on %s. Laravel Ignition health-check endpoint responded with diagnostic status.", endpointURL)

	if canExecute {
		severity = SeverityHigh
		desc = "Laravel Ignition health-check endpoint reachable with command execution enabled"
		ev = fmt.Sprintf("HTTP 200 OK on %s. Laravel Ignition health-check indicates can_execute_commands: true. Solution execution routes may be active.", endpointURL)
	}

	details := map[string]string{
		"framework":            "Laravel",
		"component":            "Ignition",
		"endpoint":             endpointURL,
		"can_execute_commands": fmt.Sprintf("%t", canExecute),
		"http_status":          "200",
	}

	return &APIFinding{
		Category:         CategoryLaravelIgnitionDebug,
		Endpoint:         endpointURL,
		Method:           http.MethodGet,
		Description:      desc,
		Evidence:         secrets.RedactText(ev),
		NegativeEvidence: "Endpoint probed passively; command execution and solution execution were not invoked.",
		Severity:         severity,
		Confidence:       ConfidenceHigh,
		Fingerprint:      GenerateFingerprint(CategoryLaravelIgnitionDebug, endpointURL, http.MethodGet),
		Classification:   ClassHealth,
		Details:          details,
		HTTPStatus:       http.StatusOK,
	}
}

// InspectLaravelTelescope evaluates access control and disclosure on the /telescope dashboard interface.
func InspectLaravelTelescope(resp *ProbeResponse, endpointURL string) *APIFinding {
	if resp == nil {
		return nil
	}

	// Case 1: Protected by HTTP Status 401 Unauthorized or 403 Forbidden
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		ev := fmt.Sprintf("HTTP %d observed on %s. Laravel Telescope dashboard is protected by authentication gate or access controls.",
			resp.StatusCode, endpointURL)
		negEv := fmt.Sprintf("Authentication challenge or authorization gate active (HTTP %d); unauthenticated access is denied.", resp.StatusCode)
		return &APIFinding{
			Category:         CategoryLaravelTelescopeProtected,
			Endpoint:         endpointURL,
			Method:           http.MethodGet,
			Description:      "Laravel Telescope monitoring dashboard access restricted",
			Evidence:         secrets.RedactText(ev),
			NegativeEvidence: negEv,
			Severity:         SeverityInfo,
			Confidence:       ConfidenceHigh,
			Fingerprint:      GenerateFingerprint(CategoryLaravelTelescopeProtected, endpointURL, http.MethodGet),
			Classification:   ClassAdmin,
			Details: map[string]string{
				"framework":   "Laravel",
				"component":   "Telescope",
				"http_status": fmt.Sprintf("%d", resp.StatusCode),
				"protected":   "true",
			},
			HTTPStatus: resp.StatusCode,
		}
	}

	// Case 2: Protected by Authentication Redirect (e.g. 302 to /login)
	if resp.Redirected {
		redirectURL := strings.ToLower(resp.RedirectURL)
		if strings.Contains(redirectURL, "login") || strings.Contains(redirectURL, "auth") {
			ev := fmt.Sprintf("HTTP %d redirect observed on %s to %s. Laravel Telescope dashboard requires authentication.",
				resp.InitialStatusCode, endpointURL, resp.RedirectURL)
			negEv := "Authentication redirect active; unauthenticated access to monitoring interface is not permitted."
			return &APIFinding{
				Category:         CategoryLaravelTelescopeProtected,
				Endpoint:         endpointURL,
				Method:           http.MethodGet,
				Description:      "Laravel Telescope monitoring dashboard requires authentication (redirect)",
				Evidence:         secrets.RedactText(ev),
				NegativeEvidence: negEv,
				Severity:         SeverityInfo,
				Confidence:       ConfidenceHigh,
				Fingerprint:      GenerateFingerprint(CategoryLaravelTelescopeProtected, endpointURL, http.MethodGet),
				Classification:   ClassAdmin,
				Details: map[string]string{
					"framework":    "Laravel",
					"component":    "Telescope",
					"redirect_url": resp.RedirectURL,
					"http_status":  fmt.Sprintf("%d", resp.InitialStatusCode),
					"protected":    "true",
				},
				HTTPStatus: resp.InitialStatusCode,
			}
		}
	}

	// Case 3: HTTP 200 OK — verify genuine Telescope markers before reporting
	if resp.StatusCode == http.StatusOK && len(resp.Body) > 0 {
		bodyStr := string(resp.Body)
		lowerBody := strings.ToLower(bodyStr)

		isTelescope := strings.Contains(lowerBody, "<title>telescope</title>") ||
			strings.Contains(lowerBody, "<title>laravel telescope</title>") ||
			strings.Contains(bodyStr, "window.Telescope =") ||
			strings.Contains(bodyStr, "window.Telescope=") ||
			strings.Contains(bodyStr, `id="telescope"`) ||
			strings.Contains(bodyStr, "/vendor/telescope/")

		if !isTelescope {
			return nil
		}

		ev := fmt.Sprintf("HTTP 200 OK on %s. Laravel Telescope dashboard interface shell is reachable.", endpointURL)
		negEv := "Dashboard interface shell is reachable, but unauthenticated access to sensitive monitoring records or telemetry was not demonstrated on this endpoint."
		return &APIFinding{
			Category:         CategoryLaravelTelescopeExposed,
			Endpoint:         endpointURL,
			Method:           http.MethodGet,
			Description:      "Laravel Telescope monitoring dashboard reachable (interface shell)",
			Evidence:         secrets.RedactText(ev),
			NegativeEvidence: negEv,
			Severity:         SeverityInfo,
			Confidence:       ConfidenceMedium,
			Fingerprint:      GenerateFingerprint(CategoryLaravelTelescopeExposed, endpointURL, http.MethodGet),
			Classification:   ClassAdmin,
			Details: map[string]string{
				"framework":   "Laravel",
				"component":   "Telescope",
				"http_status": "200",
				"interface":   "dashboard_shell",
			},
			HTTPStatus: http.StatusOK,
		}
	}

	return nil
}

// telescopeAPIResponse represents the JSON payload returned by Telescope Entries API endpoints.
type telescopeAPIResponse struct {
	Entries []map[string]interface{} `json:"entries"`
	Status  string                   `json:"status,omitempty"`
	Total   int                      `json:"total,omitempty"`
}

// InspectTelescopeAPI evaluates Telescope JSON API endpoints (e.g. /telescope/telescope-api/requests).
func InspectTelescopeAPI(resp *ProbeResponse, endpointURL string) *APIFinding {
	if resp == nil {
		return nil
	}

	// 1. Access restricted by HTTP status
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		ev := fmt.Sprintf("HTTP %d observed on %s. Laravel Telescope API access is restricted by authentication gate.",
			resp.StatusCode, endpointURL)
		return &APIFinding{
			Category:         CategoryLaravelTelescopeProtected,
			Endpoint:         endpointURL,
			Method:           http.MethodGet,
			Description:      "Laravel Telescope API access restricted",
			Evidence:         secrets.RedactText(ev),
			NegativeEvidence: fmt.Sprintf("HTTP %d challenge active; unauthenticated API access denied.", resp.StatusCode),
			Severity:         SeverityInfo,
			Confidence:       ConfidenceHigh,
			Fingerprint:      GenerateFingerprint(CategoryLaravelTelescopeProtected, endpointURL, http.MethodGet),
			Classification:   ClassAdmin,
			Details: map[string]string{
				"framework":   "Laravel",
				"component":   "TelescopeAPI",
				"http_status": fmt.Sprintf("%d", resp.StatusCode),
				"protected":   "true",
			},
			HTTPStatus: resp.StatusCode,
		}
	}

	// 2. Redirected to login
	if resp.Redirected {
		redirectURL := strings.ToLower(resp.RedirectURL)
		if strings.Contains(redirectURL, "login") || strings.Contains(redirectURL, "auth") {
			ev := fmt.Sprintf("HTTP %d redirect observed on %s to %s. Laravel Telescope API requires authentication.",
				resp.InitialStatusCode, endpointURL, resp.RedirectURL)
			return &APIFinding{
				Category:         CategoryLaravelTelescopeProtected,
				Endpoint:         endpointURL,
				Method:           http.MethodGet,
				Description:      "Laravel Telescope API requires authentication (redirect)",
				Evidence:         secrets.RedactText(ev),
				NegativeEvidence: "Authentication redirect active; unauthenticated API access denied.",
				Severity:         SeverityInfo,
				Confidence:       ConfidenceHigh,
				Fingerprint:      GenerateFingerprint(CategoryLaravelTelescopeProtected, endpointURL, http.MethodGet),
				Classification:   ClassAdmin,
				Details: map[string]string{
					"framework":    "Laravel",
					"component":    "TelescopeAPI",
					"redirect_url": resp.RedirectURL,
					"http_status":  fmt.Sprintf("%d", resp.InitialStatusCode),
					"protected":    "true",
				},
				HTTPStatus: resp.InitialStatusCode,
			}
		}
	}

	// 3. HTTP 200 OK — inspect API entries
	if resp.StatusCode == http.StatusOK && len(resp.Body) > 0 {
		var apiData telescopeAPIResponse
		if err := json.Unmarshal(resp.Body, &apiData); err != nil {
			return nil
		}

		if len(apiData.Entries) == 0 {
			// API is reachable, but zero entries are recorded
			ev := fmt.Sprintf("HTTP 200 OK on %s. Laravel Telescope API is reachable but contains 0 diagnostic entries.", endpointURL)
			return &APIFinding{
				Category:         CategoryLaravelTelescopeExposed,
				Endpoint:         endpointURL,
				Method:           http.MethodGet,
				Description:      "Laravel Telescope API accessible (zero entries recorded)",
				Evidence:         secrets.RedactText(ev),
				NegativeEvidence: "API is accessible without authentication, but no sensitive monitoring records or telemetry were disclosed.",
				Severity:         SeverityInfo,
				Confidence:       ConfidenceLow,
				Fingerprint:      GenerateFingerprint(CategoryLaravelTelescopeExposed, endpointURL, http.MethodGet),
				Classification:   ClassAdmin,
				Details: map[string]string{
					"framework":   "Laravel",
					"component":   "TelescopeAPI",
					"http_status": "200",
					"entries":     "0",
				},
				HTTPStatus: http.StatusOK,
			}
		}

		// Demonstrated unauthenticated disclosure of active monitoring telemetry
		hasUnmaskedSecret := false
		var secretKeywords []string

		// Traverse entries checking for unmasked secrets in headers or payloads
		rawJSON := string(resp.Body)
		for _, m := range laravelEnvRowRegex.FindAllStringSubmatch(rawJSON, -1) {
			if len(m) > 2 {
				k := strings.TrimSpace(m[1])
				v := strings.TrimSpace(m[2])
				if isLaravelSecretKey(k) && (isDefensibleSecretValue(k, v) || (len(v) >= 8 && !secrets.IsPlaceholder(v))) {
					hasUnmaskedSecret = true
					secretKeywords = append(secretKeywords, k)
				}
			}
		}

		severity := SeverityHigh
		if hasUnmaskedSecret {
			severity = SeverityCritical
		}

		ev := fmt.Sprintf("HTTP 200 OK on %s. Laravel Telescope API disclosed %d active diagnostic record(s). Monitored HTTP requests, queries, and execution metadata exposed.",
			endpointURL, len(apiData.Entries))
		if hasUnmaskedSecret {
			ev += fmt.Sprintf(" Unmasked credential(s) observed in captured telemetry: [%s] (secret values redacted).",
				strings.Join(secretKeywords, ", "))
		}

		details := map[string]string{
			"framework":     "Laravel",
			"component":     "TelescopeAPI",
			"entries_count": fmt.Sprintf("%d", len(apiData.Entries)),
			"http_status":   "200",
		}
		if hasUnmaskedSecret {
			details["unmasked_secrets_count"] = fmt.Sprintf("%d", len(secretKeywords))
		}
		if resp.Truncated {
			details["limitations"] = "Response exceeded 512 KiB and was bounded to preserve system resources"
		}

		return &APIFinding{
			Category:         CategoryLaravelTelescopeData,
			Endpoint:         endpointURL,
			Method:           http.MethodGet,
			Description:      "Laravel Telescope unauthenticated monitoring telemetry disclosure",
			Evidence:         secrets.RedactText(ev),
			NegativeEvidence: "All captured request headers, payloads, and query parameters were bounded and redacted.",
			Severity:         severity,
			Confidence:       ConfidenceHigh,
			Fingerprint:      GenerateFingerprint(CategoryLaravelTelescopeData, endpointURL, http.MethodGet),
			Classification:   ClassAdmin,
			Details:          details,
			HTTPStatus:       http.StatusOK,
		}
	}

	return nil
}

func isLaravelSecretKey(key string) bool {
	lower := strings.ToLower(key)
	return strings.Contains(lower, "password") ||
		strings.Contains(lower, "secret") ||
		strings.Contains(lower, "token") ||
		strings.Contains(lower, "apikey") ||
		strings.Contains(lower, "api_key") ||
		strings.Contains(lower, "authorization") ||
		strings.Contains(lower, "bearer") ||
		strings.Contains(lower, "app_key") ||
		strings.Contains(lower, "app-key") ||
		strings.Contains(lower, "db_password") ||
		strings.Contains(lower, "db_pass") ||
		strings.Contains(lower, "mail_password") ||
		strings.Contains(lower, "redis_password") ||
		strings.Contains(lower, "aws_secret") ||
		strings.Contains(lower, "private_key")
}
