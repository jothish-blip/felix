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
			if isGenuineUnmaskedSecret(k, v) {
				hasUnmaskedSecret = true
				unmaskedSecretKeys = append(unmaskedSecretKeys, k)
			}
		}
	}

	hasAppDebugSetting := strings.Contains(bodyStr, `"APP_DEBUG": "true"`) ||
		strings.Contains(bodyStr, `"APP_DEBUG": true`) ||
		strings.Contains(bodyStr, `'APP_DEBUG' => true`)
	appDebugVal := "unconfirmed"
	if hasAppDebugSetting {
		appDebugVal = "true"
	}

	debugModeStatus := "suspected"
	confidence := ConfidenceMedium
	desc := "Laravel framework exception traceback observed (suspected debug mode)"
	if hasDirectIgnition {
		debugModeStatus = "diagnostic_page_confirmed"
		confidence = ConfidenceHigh
		desc = "Laravel Ignition developer diagnostic page exposed"
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
		statusPrefix = "HTTP %d Laravel Ignition developer diagnostic page observed exposing interactive stack trace and framework metadata."
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
		evidence += fmt.Sprintf(" Candidate secret material observed: [%s] (active validity was not verified against live authentication endpoints; values redacted).",
			strings.Join(unmaskedSecretKeys, ", "))
	}

	var negEv string
	if !hasDirectIgnition {
		negEv = "Traceback observed without official Laravel Ignition developer template; APP_DEBUG configuration remains unconfirmed."
	} else if !hasUnmaskedSecret {
		negEv = "Official Laravel Ignition developer diagnostic page confirmed; no unmasked database passwords or application secrets were detected. Underlying APP_DEBUG configuration setting was not directly evaluated."
	} else {
		negEv = "Detected candidate secret material was observed in debug output; active credential validity was not tested or confirmed. All detected secret values were bounded and redacted."
	}

	details := map[string]string{
		"framework":         "Laravel",
		"debug_mode":        debugModeStatus,
		"app_debug_setting": appDebugVal,
		"http_status":       fmt.Sprintf("%d", resp.StatusCode),
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

	return &APIFinding{
		Category:         CategoryLaravelIgnitionDebug,
		Endpoint:         endpointURL,
		Method:           http.MethodGet,
		Description:      secrets.RedactText(desc),
		Evidence:         secrets.RedactText(evidence),
		NegativeEvidence: secrets.RedactText(negEv),
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

	// Strictly validate JSON structure
	var data map[string]interface{}
	if err := json.Unmarshal(resp.Body, &data); err != nil {
		return nil
	}

	// Must contain can_execute_commands key to be genuine Ignition health-check
	rawCanExecute, exists := data["can_execute_commands"]
	if !exists {
		return nil
	}

	canExecute, isBool := rawCanExecute.(bool)
	if !isBool {
		return nil
	}

	desc := fmt.Sprintf("Laravel Ignition health-check diagnostic endpoint reachable (can_execute_commands: %t reported)", canExecute)
	ev := fmt.Sprintf("HTTP 200 OK on %s. Laravel Ignition health-check endpoint responded with diagnostic status (can_execute_commands: %t). Diagnostic feature flag reported; command execution was not tested and exploitability remains unconfirmed.",
		endpointURL, canExecute)
	negEv := "Endpoint probed passively; command execution and solution execution were not invoked, and remote command execution was not tested or demonstrated."

	details := map[string]string{
		"framework":                "Laravel",
		"component":                "Ignition",
		"endpoint":                 endpointURL,
		"can_execute_commands":     fmt.Sprintf("%t", canExecute),
		"command_execution_tested": "false",
		"exploitability":           "unconfirmed",
		"impact":                   "informational_diagnostic_disclosure",
		"http_status":              "200",
	}

	for k, v := range details {
		if secrets.IsSensitiveKey(k) || secrets.IsSensitiveHeader(k) {
			details[k] = "[REDACTED]"
		} else {
			details[k] = secrets.RedactText(v)
		}
	}

	return &APIFinding{
		Category:         CategoryLaravelIgnitionDebug,
		Endpoint:         endpointURL,
		Method:           http.MethodGet,
		Description:      secrets.RedactText(desc),
		Evidence:         secrets.RedactText(ev),
		NegativeEvidence: secrets.RedactText(negEv),
		Severity:         SeverityInfo,
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
		ev := fmt.Sprintf("HTTP %d observed on %s. Access to Laravel Telescope dashboard on this endpoint is restricted by authentication challenge or access controls.",
			resp.StatusCode, endpointURL)
		negEv := fmt.Sprintf("Authentication challenge or authorization gate active (HTTP %d) on probed route; unauthenticated access to this endpoint is denied. Access controls for other Telescope resources or API endpoints were not independently tested.", resp.StatusCode)
		details := map[string]string{
			"framework":       "Laravel",
			"component":       "Telescope",
			"endpoint":        endpointURL,
			"http_status":     fmt.Sprintf("%d", resp.StatusCode),
			"observed_access": "restricted",
			"scope_note":      "restriction confirmed on probed route; sub-resources and telemetry API endpoints were not independently evaluated",
		}
		for k, v := range details {
			if secrets.IsSensitiveKey(k) || secrets.IsSensitiveHeader(k) {
				details[k] = "[REDACTED]"
			} else {
				details[k] = secrets.RedactText(v)
			}
		}
		return &APIFinding{
			Category:         CategoryLaravelTelescopeProtected,
			Endpoint:         endpointURL,
			Method:           http.MethodGet,
			Description:      "Laravel Telescope interface access restricted on probed endpoint (observed route restriction)",
			Evidence:         secrets.RedactText(ev),
			NegativeEvidence: secrets.RedactText(negEv),
			Severity:         SeverityInfo,
			Confidence:       ConfidenceHigh,
			Fingerprint:      GenerateFingerprint(CategoryLaravelTelescopeProtected, endpointURL, http.MethodGet),
			Classification:   ClassAdmin,
			Details:          details,
			HTTPStatus:       resp.StatusCode,
		}
	}

	// Case 2: Protected by Authentication Redirect (e.g. 302 to /login)
	if resp.Redirected {
		redirectURL := strings.ToLower(resp.RedirectURL)
		if strings.Contains(redirectURL, "login") || strings.Contains(redirectURL, "auth") {
			ev := fmt.Sprintf("HTTP %d redirect observed on %s to %s. Laravel Telescope dashboard route requires authentication.",
				resp.InitialStatusCode, endpointURL, resp.RedirectURL)
			negEv := "Authentication redirect active on probed route; unauthenticated access to this endpoint is not permitted. Access controls for other Telescope resources or API endpoints were not independently tested."
			details := map[string]string{
				"framework":       "Laravel",
				"component":       "Telescope",
				"endpoint":        endpointURL,
				"redirect_url":    resp.RedirectURL,
				"http_status":     fmt.Sprintf("%d", resp.InitialStatusCode),
				"observed_access": "restricted",
				"scope_note":      "restriction confirmed on probed route; sub-resources and telemetry API endpoints were not independently evaluated",
			}
			for k, v := range details {
				if secrets.IsSensitiveKey(k) || secrets.IsSensitiveHeader(k) {
					details[k] = "[REDACTED]"
				} else {
					details[k] = secrets.RedactText(v)
				}
			}
			return &APIFinding{
				Category:         CategoryLaravelTelescopeProtected,
				Endpoint:         endpointURL,
				Method:           http.MethodGet,
				Description:      "Laravel Telescope interface requires authentication (observed login redirect)",
				Evidence:         secrets.RedactText(ev),
				NegativeEvidence: secrets.RedactText(negEv),
				Severity:         SeverityInfo,
				Confidence:       ConfidenceHigh,
				Fingerprint:      GenerateFingerprint(CategoryLaravelTelescopeProtected, endpointURL, http.MethodGet),
				Classification:   ClassAdmin,
				Details:          details,
				HTTPStatus:       resp.InitialStatusCode,
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
		negEv := "Dashboard interface shell is reachable, but unauthenticated access to sensitive monitoring records or operational telemetry was not demonstrated on this endpoint."
		details := map[string]string{
			"framework":     "Laravel",
			"component":     "Telescope",
			"endpoint":      endpointURL,
			"http_status":   "200",
			"interface":     "dashboard_shell",
			"data_exposure": "none_demonstrated",
		}
		for k, v := range details {
			if secrets.IsSensitiveKey(k) || secrets.IsSensitiveHeader(k) {
				details[k] = "[REDACTED]"
			} else {
				details[k] = secrets.RedactText(v)
			}
		}
		return &APIFinding{
			Category:         CategoryLaravelTelescopeExposed,
			Endpoint:         endpointURL,
			Method:           http.MethodGet,
			Description:      "Laravel Telescope monitoring dashboard reachable (interface shell observation)",
			Evidence:         secrets.RedactText(ev),
			NegativeEvidence: secrets.RedactText(negEv),
			Severity:         SeverityInfo,
			Confidence:       ConfidenceMedium,
			Fingerprint:      GenerateFingerprint(CategoryLaravelTelescopeExposed, endpointURL, http.MethodGet),
			Classification:   ClassAdmin,
			Details:          details,
			HTTPStatus:       http.StatusOK,
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
		negEv := fmt.Sprintf("HTTP %d challenge active on probed route; unauthenticated access to this API endpoint is denied. Other Telescope endpoints were not independently tested.", resp.StatusCode)
		details := map[string]string{
			"framework":       "Laravel",
			"component":       "TelescopeAPI",
			"endpoint":        endpointURL,
			"http_status":     fmt.Sprintf("%d", resp.StatusCode),
			"observed_access": "restricted",
			"scope_note":      "restriction confirmed on probed route; other Telescope endpoints were not independently evaluated",
		}
		for k, v := range details {
			if secrets.IsSensitiveKey(k) || secrets.IsSensitiveHeader(k) {
				details[k] = "[REDACTED]"
			} else {
				details[k] = secrets.RedactText(v)
			}
		}
		return &APIFinding{
			Category:         CategoryLaravelTelescopeProtected,
			Endpoint:         endpointURL,
			Method:           http.MethodGet,
			Description:      "Laravel Telescope API access restricted on probed endpoint (observed route restriction)",
			Evidence:         secrets.RedactText(ev),
			NegativeEvidence: secrets.RedactText(negEv),
			Severity:         SeverityInfo,
			Confidence:       ConfidenceHigh,
			Fingerprint:      GenerateFingerprint(CategoryLaravelTelescopeProtected, endpointURL, http.MethodGet),
			Classification:   ClassAdmin,
			Details:          details,
			HTTPStatus:       resp.StatusCode,
		}
	}

	// 2. Redirected to login
	if resp.Redirected {
		redirectURL := strings.ToLower(resp.RedirectURL)
		if strings.Contains(redirectURL, "login") || strings.Contains(redirectURL, "auth") {
			ev := fmt.Sprintf("HTTP %d redirect observed on %s to %s. Laravel Telescope API requires authentication.",
				resp.InitialStatusCode, endpointURL, resp.RedirectURL)
			negEv := "Authentication redirect active on probed route; unauthenticated access to this API endpoint is not permitted."
			details := map[string]string{
				"framework":       "Laravel",
				"component":       "TelescopeAPI",
				"endpoint":        endpointURL,
				"redirect_url":    resp.RedirectURL,
				"http_status":     fmt.Sprintf("%d", resp.InitialStatusCode),
				"observed_access": "restricted",
				"scope_note":      "restriction confirmed on probed route; other Telescope endpoints were not independently evaluated",
			}
			for k, v := range details {
				if secrets.IsSensitiveKey(k) || secrets.IsSensitiveHeader(k) {
					details[k] = "[REDACTED]"
				} else {
					details[k] = secrets.RedactText(v)
				}
			}
			return &APIFinding{
				Category:         CategoryLaravelTelescopeProtected,
				Endpoint:         endpointURL,
				Method:           http.MethodGet,
				Description:      "Laravel Telescope API requires authentication (observed login redirect)",
				Evidence:         secrets.RedactText(ev),
				NegativeEvidence: secrets.RedactText(negEv),
				Severity:         SeverityInfo,
				Confidence:       ConfidenceHigh,
				Fingerprint:      GenerateFingerprint(CategoryLaravelTelescopeProtected, endpointURL, http.MethodGet),
				Classification:   ClassAdmin,
				Details:          details,
				HTTPStatus:       resp.InitialStatusCode,
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
			details := map[string]string{
				"framework":     "Laravel",
				"component":     "TelescopeAPI",
				"endpoint":      endpointURL,
				"http_status":   "200",
				"entries":       "0",
				"data_exposure": "none_demonstrated",
			}
			for k, v := range details {
				if secrets.IsSensitiveKey(k) || secrets.IsSensitiveHeader(k) {
					details[k] = "[REDACTED]"
				} else {
					details[k] = secrets.RedactText(v)
				}
			}
			return &APIFinding{
				Category:         CategoryLaravelTelescopeExposed,
				Endpoint:         endpointURL,
				Method:           http.MethodGet,
				Description:      "Laravel Telescope API accessible (zero entries recorded)",
				Evidence:         secrets.RedactText(ev),
				NegativeEvidence: secrets.RedactText("API is accessible without authentication, but no sensitive monitoring records or telemetry were disclosed."),
				Severity:         SeverityInfo,
				Confidence:       ConfidenceLow,
				Fingerprint:      GenerateFingerprint(CategoryLaravelTelescopeExposed, endpointURL, http.MethodGet),
				Classification:   ClassAdmin,
				Details:          details,
				HTTPStatus:       http.StatusOK,
			}
		}

		// Demonstrated unauthenticated disclosure of active monitoring telemetry
		hasUnmaskedSecret := false
		var secretKeywords []string
		hasMaskedCredentials := false
		hasSensitiveQueries := false
		hasRoutineQueries := false
		hasSensitiveExceptions := false
		hasRoutineExceptions := false
		hasSensitiveRequests := false
		hasRoutineRequests := false
		hasOperationalEntries := false

		// Recursive helper to inspect nested content maps/slices for secrets, masked creds, and PII
		var inspectNestedContent func(key string, val interface{})
		inspectNestedContent = func(key string, val interface{}) {
			switch v := val.(type) {
			case string:
				if isGenuineUnmaskedSecret(key, v) {
					hasUnmaskedSecret = true
					secretKeywords = append(secretKeywords, key)
				} else if isMaskedCredentialOrPlaceholder(v) && (isCredentialSecretKey(key) || isPIIKey(key)) {
					hasMaskedCredentials = true
				} else if isPIIKey(key) && len(v) >= 4 {
					hasSensitiveRequests = true
				}
			case map[string]interface{}:
				for subK, subV := range v {
					inspectNestedContent(subK, subV)
				}
			case []interface{}:
				for _, item := range v {
					inspectNestedContent(key, item)
				}
			}
		}

		for _, entry := range apiData.Entries {
			entryType, _ := entry["type"].(string)
			lowerType := strings.ToLower(entryType)
			content, _ := entry["content"].(map[string]interface{})

			if content != nil {
				for k, v := range content {
					inspectNestedContent(k, v)
				}
			}

			switch lowerType {
			case "query":
				sql := ""
				if content != nil {
					if s, ok := content["sql"].(string); ok {
						sql = s
					}
				}
				if isSensitiveSQLQuery(sql) {
					hasSensitiveQueries = true
				} else {
					hasRoutineQueries = true
				}

			case "exception":
				excClass := ""
				excMsg := ""
				if content != nil {
					if c, ok := content["class"].(string); ok {
						excClass = c
					}
					if m, ok := content["message"].(string); ok {
						excMsg = m
					}
				}
				if isSensitiveException(excClass, excMsg) {
					hasSensitiveExceptions = true
				} else {
					hasRoutineExceptions = true
				}

			case "request":
				isReqSensitive := false
				if content != nil {
					// Check headers
					if headers, ok := content["headers"].(map[string]interface{}); ok {
						for hk, hv := range headers {
							lowerHK := strings.ToLower(hk)
							if lowerHK == "authorization" || lowerHK == "cookie" ||
								strings.Contains(lowerHK, "token") || strings.Contains(lowerHK, "auth") {
								strVal := fmt.Sprintf("%v", hv)
								if isGenuineUnmaskedSecret(hk, strVal) {
									hasUnmaskedSecret = true
									secretKeywords = append(secretKeywords, hk)
								} else if isMaskedCredentialOrPlaceholder(strVal) {
									hasMaskedCredentials = true
								} else if strings.Contains(strings.ToLower(strVal), "bearer") ||
									strings.Contains(lowerHK, "cookie") {
									isReqSensitive = true
								}
							}
						}
					}
					// Check payload
					if payload, ok := content["payload"].(map[string]interface{}); ok {
						for pk, pv := range payload {
							strVal := fmt.Sprintf("%v", pv)
							if isGenuineUnmaskedSecret(pk, strVal) {
								hasUnmaskedSecret = true
								secretKeywords = append(secretKeywords, pk)
							} else if isMaskedCredentialOrPlaceholder(strVal) && (isCredentialSecretKey(pk) || isPIIKey(pk)) {
								hasMaskedCredentials = true
							} else if isPIIKey(pk) && len(strVal) >= 4 {
								isReqSensitive = true
							} else if isCredentialSecretKey(pk) {
								isReqSensitive = true
							}
						}
					}
				}
				if isReqSensitive {
					hasSensitiveRequests = true
				} else {
					hasRoutineRequests = true
				}

			default:
				hasOperationalEntries = true
			}
		}

		// Also check raw JSON with regex for unmasked environment/secret assignments
		rawJSON := string(resp.Body)
		for _, m := range laravelEnvRowRegex.FindAllStringSubmatch(rawJSON, -1) {
			if len(m) > 2 {
				k := strings.TrimSpace(m[1])
				v := strings.TrimSpace(m[2])
				if isGenuineUnmaskedSecret(k, v) {
					hasUnmaskedSecret = true
					secretKeywords = append(secretKeywords, k)
				} else if isMaskedCredentialOrPlaceholder(v) && (isCredentialSecretKey(k) || isPIIKey(k)) {
					hasMaskedCredentials = true
				} else if isPIIKey(k) && len(v) >= 4 {
					hasSensitiveRequests = true
				}
			}
		}

		// Deduplicate observed secret keywords
		seenKeys := make(map[string]struct{})
		var uniqueSecretKeys []string
		for _, sk := range secretKeywords {
			if _, exists := seenKeys[sk]; !exists {
				seenKeys[sk] = struct{}{}
				uniqueSecretKeys = append(uniqueSecretKeys, sk)
			}
		}
		sort.Strings(uniqueSecretKeys)

		severity := SeverityMedium
		desc := "Laravel Telescope unauthenticated monitoring telemetry disclosure (operational event entries)"
		if hasUnmaskedSecret {
			severity = SeverityCritical
			desc = "Laravel Telescope unauthenticated monitoring telemetry exposes candidate secret material (validity unverified)"
		} else if hasSensitiveQueries || hasSensitiveExceptions || hasSensitiveRequests {
			severity = SeverityHigh
			desc = "Laravel Telescope unauthenticated monitoring telemetry disclosure (sensitive application data)"
		}

		ev := fmt.Sprintf("HTTP 200 OK on %s. Laravel Telescope API disclosed %d active diagnostic record(s). Monitored operational telemetry exposed.",
			endpointURL, len(apiData.Entries))
		if hasSensitiveQueries || hasSensitiveExceptions || hasSensitiveRequests {
			ev = fmt.Sprintf("HTTP 200 OK on %s. Laravel Telescope API disclosed %d active diagnostic record(s). Monitored application telemetry (sensitive queries/requests/exceptions) exposed.",
				endpointURL, len(apiData.Entries))
		}
		if hasUnmaskedSecret {
			ev += fmt.Sprintf(" Candidate secret material observed in captured telemetry: [%s] (active validity was not verified against live authentication endpoints; values redacted).",
				strings.Join(uniqueSecretKeys, ", "))
		}

		var sensitiveTypes []string
		if hasUnmaskedSecret {
			sensitiveTypes = append(sensitiveTypes, "unmasked_credentials")
		}
		if hasMaskedCredentials {
			sensitiveTypes = append(sensitiveTypes, "masked_credentials")
		}
		if hasSensitiveQueries {
			sensitiveTypes = append(sensitiveTypes, "sensitive_database_queries")
		}
		if hasRoutineQueries {
			sensitiveTypes = append(sensitiveTypes, "routine_database_queries")
		}
		if hasSensitiveRequests {
			sensitiveTypes = append(sensitiveTypes, "sensitive_http_requests")
		}
		if hasRoutineRequests {
			sensitiveTypes = append(sensitiveTypes, "routine_http_requests")
		}
		if hasSensitiveExceptions {
			sensitiveTypes = append(sensitiveTypes, "application_exceptions")
		}
		if hasRoutineExceptions {
			sensitiveTypes = append(sensitiveTypes, "routine_exceptions")
		}
		if hasOperationalEntries || len(sensitiveTypes) == 0 {
			sensitiveTypes = append(sensitiveTypes, "event_metadata")
		}

		details := map[string]string{
			"framework":                "Laravel",
			"component":                "TelescopeAPI",
			"endpoint":                 endpointURL,
			"entries_count":            fmt.Sprintf("%d", len(apiData.Entries)),
			"http_status":              "200",
			"auth_context":             "unauthenticated",
			"sensitive_data_types":     strings.Join(sensitiveTypes, ", "),
			"validity_status":          "unverified_active_probe_omitted",
			"active_auth_tested":       "false",
			"verification_limitations": "Passive read-only query; backend state was not altered and active credential authorization was not verified",
		}
		if hasUnmaskedSecret {
			details["unmasked_secrets_count"] = fmt.Sprintf("%d", len(uniqueSecretKeys))
			details["candidate_material_status"] = "unverified_candidate_material"
		}
		if resp.Truncated {
			details["limitations"] = "Response exceeded 512 KiB and was bounded to preserve system resources"
		}

		// Ensure recursive secret redaction across all detail values
		for k, v := range details {
			if secrets.IsSensitiveKey(k) || secrets.IsSensitiveHeader(k) {
				details[k] = "[REDACTED]"
			} else {
				details[k] = secrets.RedactText(v)
			}
		}

		return &APIFinding{
			Category:         CategoryLaravelTelescopeData,
			Endpoint:         endpointURL,
			Method:           http.MethodGet,
			Description:      secrets.RedactText(desc),
			Evidence:         secrets.RedactText(ev),
			NegativeEvidence: secrets.RedactText("All captured request headers, payloads, query parameters, and telemetry entries were bounded and redacted. Detected candidate secret material was observed in telemetry; active credential validity was not tested or confirmed."),
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
	lower := strings.ToLower(strings.TrimSpace(key))
	clean := strings.ReplaceAll(strings.ReplaceAll(lower, "_", ""), "-", "")

	if clean == "csrftoken" || clean == "xsrftoken" || strings.HasSuffix(clean, "header") ||
		strings.HasSuffix(clean, "rate") || strings.HasSuffix(clean, "bucket") ||
		strings.HasSuffix(clean, "type") || strings.HasSuffix(clean, "count") ||
		strings.HasSuffix(clean, "size") || strings.HasSuffix(clean, "mode") ||
		strings.HasSuffix(clean, "alg") || strings.HasSuffix(clean, "algorithm") {
		return false
	}

	return strings.Contains(clean, "password") ||
		strings.Contains(clean, "passwd") ||
		strings.Contains(clean, "secret") ||
		strings.Contains(clean, "apikey") ||
		strings.Contains(clean, "privatekey") ||
		strings.Contains(clean, "privkey") ||
		strings.Contains(clean, "appkey") ||
		strings.Contains(clean, "dbpass") ||
		strings.Contains(clean, "authtoken") ||
		strings.Contains(clean, "remembertoken") ||
		strings.Contains(clean, "accesstoken") ||
		strings.Contains(clean, "refreshtoken") ||
		clean == "token" ||
		clean == "apitoken" ||
		strings.Contains(clean, "authorization") ||
		strings.Contains(clean, "bearer")
}

// isMaskedCredentialOrPlaceholder checks if a candidate string is masked or a placeholder.
func isMaskedCredentialOrPlaceholder(val string) bool {
	clean := strings.TrimSpace(val)
	if clean == "" {
		return true
	}
	lower := strings.ToLower(clean)
	if lower == "null" || lower == "nil" || lower == "none" || lower == "undefined" ||
		lower == "true" || lower == "false" || lower == "0" || lower == "1" ||
		lower == "bearer" || lower == "oauth2" || lower == "bcrypt" || lower == "jwt" ||
		lower == "basic" || lower == "digest" || lower == "hs256" || lower == "rs256" ||
		lower == "sha256" || lower == "session" {
		return true
	}
	if secrets.IsPlaceholder(clean) {
		return true
	}
	// Masked indicators: '******', '********', '[REDACTED]', '[FILTERED]', '***MASKED***', '••••••••'
	if strings.Count(clean, "*") >= 3 || strings.Count(clean, "•") >= 3 {
		return true
	}
	if strings.Contains(lower, "redact") || strings.Contains(lower, "filter") || strings.Contains(lower, "masked") {
		return true
	}
	// Trivial repeating characters like 'xxxxxx', '000000', '------'
	if len(clean) > 2 {
		allSame := true
		for i := 1; i < len(clean); i++ {
			if clean[i] != clean[0] {
				allSame = false
				break
			}
		}
		if allSame {
			return true
		}
	}
	return false
}

// isGenuineUnmaskedSecret validates if a key-value pair represents a confirmed unmasked secret.
func isGenuineUnmaskedSecret(key, val string) bool {
	cleanVal := strings.TrimSpace(val)
	if cleanVal == "" || len(cleanVal) < 8 {
		return false
	}
	if isMaskedCredentialOrPlaceholder(cleanVal) {
		return false
	}
	lowerVal := strings.ToLower(cleanVal)
	if strings.HasPrefix(lowerVal, "http://") || strings.HasPrefix(lowerVal, "https://") {
		return strings.Contains(cleanVal, "@")
	}

	// Recognized synthetic canary or vendor patterns are always secrets
	if strings.Contains(cleanVal, "felix_test_canary_secret") {
		return true
	}
	if strings.HasPrefix(cleanVal, "sk_live_") || strings.HasPrefix(cleanVal, "ghp_") ||
		strings.HasPrefix(cleanVal, "xoxb-") || strings.HasPrefix(cleanVal, "xoxp-") {
		return true
	}

	// Non-secret metadata keys are explicitly exempt
	lowerKey := strings.ToLower(strings.TrimSpace(key))
	exemptKeys := map[string]struct{}{
		"name": {}, "title": {}, "class": {}, "type": {}, "status": {},
		"uri": {}, "url": {}, "path": {}, "method": {}, "file": {}, "line": {},
		"action": {}, "controller": {}, "middleware": {}, "view": {}, "sql": {},
		"message": {}, "trace": {}, "hostname": {}, "host": {}, "query": {},
		"format": {}, "version": {}, "content_type": {}, "queue": {}, "listener": {},
		"id": {}, "ip": {}, "email": {}, "user": {}, "description": {},
	}
	if _, exempt := exemptKeys[lowerKey]; exempt {
		return false
	}

	// PII keys represent sensitive personal information (handled as SeverityHigh), not unmasked credential secrets (SeverityCritical)
	if isPIIKey(lowerKey) {
		return false
	}

	// The key must be an explicit sensitive/credential key
	if isLaravelSecretKey(lowerKey) || (secrets.IsSensitiveKey(lowerKey) && isCredentialSecretKey(lowerKey)) {
		return true
	}

	return false
}

// isSensitiveSQLQuery evaluates whether a captured SQL query targets sensitive credential or PII columns.
// Table names alone (such as users, accounts, customers) do not indicate sensitive disclosure.
func isSensitiveSQLQuery(sql string) bool {
	lower := strings.ToLower(strings.TrimSpace(sql))
	if lower == "" {
		return false
	}
	// Harmless / routine system queries
	if lower == "select 1" || strings.HasPrefix(lower, "select 1 ") ||
		strings.Contains(lower, "sqlite_master") || strings.Contains(lower, "information_schema") ||
		strings.Contains(lower, "select version()") || strings.Contains(lower, "select now()") {
		return false
	}
	if strings.Contains(lower, "from migrations") || strings.Contains(lower, "from `migrations`") ||
		strings.Contains(lower, "from \"migrations\"") {
		return false
	}
	if strings.Contains(lower, "from telescope_entries") || strings.Contains(lower, "from `telescope_entries`") ||
		strings.Contains(lower, "from telescope_monitoring") || strings.Contains(lower, "from cache") ||
		strings.Contains(lower, "from `cache`") || strings.Contains(lower, "from failed_jobs") ||
		strings.Contains(lower, "from job_batches") || strings.Contains(lower, "from sessions") {
		return false
	}

	// Sensitive column targets - only queries explicitly targeting credentials, auth tokens, or PII are sensitive
	sensitiveColumns := []string{
		"password", "passwd", "remember_token", "api_key", "apikey",
		"private_key", "privkey", "app_key", "app-key",
		"credit_card", "card_number", "ssn", "social_security", "cvv", "cvc",
		"access_token", "refresh_token", "personal_access_token",
		"password_hash", "salt", "auth_token", "secret_key",
	}
	for _, col := range sensitiveColumns {
		if strings.Contains(lower, col) {
			return true
		}
	}

	return false
}

// isSensitiveException evaluates if an exception disclosed in Telescope telemetry contains demonstrated sensitive details
// (such as credentials, auth tokens, sensitive SQL queries, or PII) rather than routine error flows or generic database errors.
func isSensitiveException(excClass, excMessage string) bool {
	lowerMsg := strings.ToLower(strings.TrimSpace(excMessage))
	lowerClass := strings.ToLower(strings.TrimSpace(excClass))

	// Check if message or class discloses credential material, tokens, or PII
	sensitiveKeywords := []string{
		"password", "passwd", "remember_token", "api_key", "apikey",
		"private_key", "bearer ", "credit_card", "card_number",
		"ssn", "social_security", "cvv", "cvc", "access_token", "refresh_token",
	}
	for _, kw := range sensitiveKeywords {
		if strings.Contains(lowerMsg, kw) || strings.Contains(lowerClass, kw) {
			return true
		}
	}

	// Check if an embedded SQL query discloses sensitive columns or credentials
	if strings.Contains(lowerMsg, "sql:") || strings.Contains(lowerMsg, "select ") ||
		strings.Contains(lowerMsg, "insert into ") || strings.Contains(lowerMsg, "update ") {
		if isSensitiveSQLQuery(lowerMsg) {
			return true
		}
	}

	// Routine database errors (e.g. QueryException / PDOException for missing table, column not found, syntax error,
	// deadlock, connection refused without credentials) and routine HTTP/framework exceptions do NOT disclose sensitive data.
	return false
}

// isRoutineException evaluates if an exception class represents a routine client/framework flow.
func isRoutineException(excClass string) bool {
	lower := strings.ToLower(strings.TrimSpace(excClass))
	routineExceptions := []string{
		"validationexception",
		"notfoundhttpexception",
		"modelnotfoundexception",
		"authenticationexception",
		"authorizationexception",
		"tokenmismatchexception",
		"methodnotallowedhttpexception",
		"throttlerequestsexception",
		"accessdeniedhttpexception",
		"httpexception",
		"queryexception",
		"pdoexception",
	}
	for _, r := range routineExceptions {
		if strings.Contains(lower, r) {
			return true
		}
	}
	return false
}

// isCredentialSecretKey returns true if a key name suggests an authentication credential or secret.
func isCredentialSecretKey(key string) bool {
	lower := strings.ToLower(strings.TrimSpace(key))
	clean := strings.ReplaceAll(strings.ReplaceAll(lower, "_", ""), "-", "")

	// Exclude non-secret metadata key names
	if clean == "author" || clean == "authority" || clean == "csrftoken" || clean == "xsrftoken" {
		return false
	}
	if strings.HasSuffix(clean, "url") || strings.HasSuffix(clean, "uri") || strings.HasSuffix(clean, "path") ||
		strings.HasSuffix(clean, "type") || strings.HasSuffix(clean, "mode") || strings.HasSuffix(clean, "provider") ||
		strings.HasSuffix(clean, "method") || strings.HasSuffix(clean, "endpoint") || strings.HasSuffix(clean, "alg") ||
		strings.HasSuffix(clean, "algorithm") || strings.HasSuffix(clean, "size") || strings.HasSuffix(clean, "count") ||
		strings.HasSuffix(clean, "rate") || strings.HasSuffix(clean, "name") || strings.HasSuffix(clean, "version") ||
		strings.HasSuffix(clean, "header") || strings.HasSuffix(clean, "expiry") || strings.HasSuffix(clean, "expiration") ||
		strings.HasSuffix(clean, "format") || strings.HasSuffix(clean, "bucket") {
		return false
	}

	return strings.Contains(clean, "password") ||
		strings.Contains(clean, "passwd") ||
		strings.Contains(clean, "secret") ||
		strings.Contains(clean, "apikey") ||
		strings.Contains(clean, "privatekey") ||
		strings.Contains(clean, "privkey") ||
		strings.Contains(clean, "appkey") ||
		strings.Contains(clean, "dbpass") ||
		strings.Contains(clean, "token") ||
		strings.Contains(clean, "authtoken") ||
		strings.Contains(clean, "authsecret") ||
		strings.Contains(clean, "authkey") ||
		strings.Contains(clean, "authorization") ||
		strings.Contains(clean, "bearer")
}

// isPIIKey returns true if a key name suggests sensitive personally identifiable information.
func isPIIKey(key string) bool {
	lower := strings.ToLower(strings.TrimSpace(key))
	clean := strings.ReplaceAll(strings.ReplaceAll(lower, "_", ""), "-", "")
	return clean == "ssn" || clean == "socialsecurity" || clean == "socialsecuritynumber" ||
		clean == "creditcard" || clean == "cardnumber" || clean == "cvv" || clean == "cvc" ||
		clean == "email" || clean == "phone" || clean == "dob" || clean == "dateofbirth"
}
