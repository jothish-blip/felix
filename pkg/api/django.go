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
	// MaxDjangoResponseSize enforces a strict 512 KiB wire-read limit for Django diagnostic inspection.
	MaxDjangoResponseSize = 512 * 1024
)

// DefaultDjangoCandidatePaths lists standard diagnostic and discovery probe relative paths for Django.
var DefaultDjangoCandidatePaths = []string{
	"/_felix_django_404_probe",
	"/admin/login/",
	"/api/",
}

var (
	djangoVersionTableRegex = regexp.MustCompile(`(?i)Django Version:\s*</(?:th|td)>\s*<td[^>]*>([^<]+)</td>`)
	djangoVersionTextRegex  = regexp.MustCompile(`(?i)Django Version:\s*([0-9\.]+)`)
	pythonVerTableRegex     = regexp.MustCompile(`(?i)Python Version:\s*</(?:th|td)>\s*<td[^>]*>([^<]+)</td>`)
	pythonVerTextRegex      = regexp.MustCompile(`(?i)Python Version:\s*([0-9\.]+)`)
	pythonExecTableRegex    = regexp.MustCompile(`(?i)Python Executable:\s*</(?:th|td)>\s*<td[^>]*>([^<]+)</td>`)
	tracebackFrameRegex     = regexp.MustCompile(`(?m)File\s+["']([^"']+\.py)["'],\s+line\s+(\d+)`)
	djangoURLConfRegex      = regexp.MustCompile(`(?i)Using the URLconf defined in\s*<code>([^<]+)</code>`)
	djangoURLPatternRegex   = regexp.MustCompile(`(?m)^\s*<li>\s*(?:<code>)?(\^?[a-zA-Z0-9_\-\./\^$\\]+)(?:</code>)?\s*</li>`)
	djangoSettingsRowRegex  = regexp.MustCompile(`(?i)<th[^>]*>([A-Za-z0-9_]{3,})</th>\s*<td[^>]*>(?:<pre[^>]*>)?([^<]+)(?:</pre>)?</td>`)
)

// AuditDjangoDiagnostics coordinates safe, bounded assessment of Django-specific diagnostic and documentation behavior.
func AuditDjangoDiagnostics(ctx context.Context, client *Client, targetBaseURL string, candidatePaths []string) []APIFinding {
	var findings []APIFinding
	resolvedCandidates := ResolveDjangoCandidateURLs(targetBaseURL, candidatePaths)

	for _, targetURL := range resolvedCandidates {
		// Enforce client scope and exclusion rules before dispatching
		if client.isExcluded != nil && client.isExcluded(targetURL) {
			continue
		}
		if client.isAllowed != nil && !client.isAllowed(targetURL) {
			continue
		}

		endpointFindings := ProbeDjangoEndpoint(ctx, client, targetURL)
		findings = append(findings, endpointFindings...)
	}

	return findings
}

// ResolveDjangoCandidateURLs resolves candidate Django diagnostic URLs for a target base URL,
// supporting nested application paths, root origin endpoints, and crawled asset hints.
func ResolveDjangoCandidateURLs(targetBaseURL string, customCandidates []string) []string {
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

	// 1. Base URL candidates (handles nested base paths like /app/_felix_django_404_probe and root targets)
	for _, p := range DefaultDjangoCandidatePaths {
		addURL(baseURL + p)
	}

	// 2. Custom or discovered candidate paths from crawled assets
	for _, cp := range customCandidates {
		clean := strings.TrimSpace(cp)
		if clean == "" {
			continue
		}
		lower := strings.ToLower(clean)
		if strings.Contains(lower, "admin") || strings.Contains(lower, "django") ||
			strings.Contains(lower, "api") || strings.Contains(lower, "rest_framework") {
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

// ProbeDjangoEndpoint probes a candidate URL and evaluates diagnostic or browsable API disclosures.
func ProbeDjangoEndpoint(ctx context.Context, client *Client, targetURL string) []APIFinding {
	var findings []APIFinding

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, targetURL, nil)
	if err != nil {
		return nil
	}
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")

	resp, err := client.DoBounded(ctx, req, MaxDjangoResponseSize)
	if err != nil {
		return nil
	}

	// 1. Inspect for Django Technical 500 Debug Page (DEBUG=True)
	if f := InspectDjangoTechnical500(resp, targetURL); f != nil {
		findings = append(findings, *f)
		return findings
	}

	// 2. Inspect for Django Technical 404 URLconf Pattern Disclosure (DEBUG=True)
	if f := InspectDjangoTechnical404(resp, targetURL); f != nil {
		findings = append(findings, *f)
		return findings
	}

	// 3. Inspect for Django REST Framework (DRF) Browsable API
	if f := InspectDjangoBrowsableAPI(resp, targetURL); f != nil {
		findings = append(findings, *f)
		return findings
	}

	return findings
}

// InspectDjangoTechnical500 detects Django's technical 500 error page generated when DEBUG=True.
// It verifies structural layout and extracts disclosed version, filesystem paths, and configuration metadata.
func InspectDjangoTechnical500(resp *ProbeResponse, endpointURL string) *APIFinding {
	if resp == nil || len(resp.Body) == 0 {
		return nil
	}

	// Technical 500 debug pages are returned on HTTP 500 (or rarely on 400 DisallowedHost in debug mode)
	if resp.StatusCode != http.StatusInternalServerError && resp.StatusCode != http.StatusBadRequest {
		return nil
	}

	bodyStr := string(resp.Body)
	lowerBody := strings.ToLower(bodyStr)

	// Structural markers check: must have Django debug HTML framework structure
	hasSummary := strings.Contains(bodyStr, `<div id="summary">`)
	hasMetaTable := strings.Contains(bodyStr, `<table class="meta"`)
	hasTracebackDiv := strings.Contains(bodyStr, `id="traceback"`)
	hasExplanation := strings.Contains(bodyStr, `<div id="explanation">`)

	if !hasSummary && !hasMetaTable && !hasTracebackDiv && !hasExplanation {
		return nil
	}

	// Corroborating framework markers: require at least two strong indicators
	score := 0
	if strings.Contains(lowerBody, "technical information (for developers)") {
		score++
	}
	if strings.Contains(lowerBody, "django version:") {
		score++
	}
	if strings.Contains(lowerBody, "python executable:") {
		score++
	}
	if strings.Contains(lowerBody, "python path:") {
		score++
	}
	if strings.Contains(lowerBody, "python version:") {
		score++
	}
	if strings.Contains(lowerBody, "request information") {
		score++
	}
	if strings.Contains(bodyStr, "Traceback (most recent call last):") {
		score++
	}
	if strings.Contains(bodyStr, "site-packages/django") || strings.Contains(bodyStr, "django.core.handlers") {
		score++
	}

	if score < 2 {
		return nil
	}

	// Extract Django version
	djangoVersion := ""
	if m := djangoVersionTableRegex.FindStringSubmatch(bodyStr); len(m) > 1 {
		djangoVersion = strings.TrimSpace(m[1])
	} else if m := djangoVersionTextRegex.FindStringSubmatch(bodyStr); len(m) > 1 {
		djangoVersion = strings.TrimSpace(m[1])
	}

	// Extract Python version and executable
	pythonVer := ""
	if m := pythonVerTableRegex.FindStringSubmatch(bodyStr); len(m) > 1 {
		pythonVer = strings.TrimSpace(m[1])
	} else if m := pythonVerTextRegex.FindStringSubmatch(bodyStr); len(m) > 1 {
		pythonVer = strings.TrimSpace(m[1])
	}

	pythonExec := ""
	if m := pythonExecTableRegex.FindStringSubmatch(bodyStr); len(m) > 1 {
		pythonExec = strings.TrimSpace(m[1])
	}

	// Extract traceback filesystem paths
	var exposedPaths []string
	frameMatches := tracebackFrameRegex.FindAllStringSubmatch(bodyStr, -1)
	seenPaths := make(map[string]struct{})
	for _, m := range frameMatches {
		if len(m) > 1 {
			p := strings.TrimSpace(m[1])
			if _, exists := seenPaths[p]; !exists {
				seenPaths[p] = struct{}{}
				exposedPaths = append(exposedPaths, p)
			}
		}
	}
	sort.Strings(exposedPaths)

	// Check for unmasked defensible secrets in the settings or meta table
	hasUnmaskedSecret := false
	var unmaskedSecretKeys []string
	settingMatches := djangoSettingsRowRegex.FindAllStringSubmatch(bodyStr, -1)
	for _, m := range settingMatches {
		if len(m) > 2 {
			k := strings.TrimSpace(m[1])
			v := strings.TrimSpace(m[2])
			// If setting is masked (e.g. '********************' or '******'), skip
			if strings.Count(v, "*") > 4 || strings.Contains(v, "Filtered") {
				continue
			}
			if isDefensibleSecretValue(k, v) {
				hasUnmaskedSecret = true
				unmaskedSecretKeys = append(unmaskedSecretKeys, k)
			}
		}
	}

	// Distinguish confirmed Django technical developer debug page from generic exception traceback
	hasDeveloperTemplate := strings.Contains(lowerBody, "technical information (for developers)") ||
		strings.Contains(bodyStr, `id="settings-meta"`) ||
		(strings.Contains(bodyStr, `<div id="summary">`) && strings.Contains(lowerBody, "django version:") && strings.Contains(lowerBody, "python executable:"))

	debugModeStatus := "suspected"
	confidence := ConfidenceMedium
	desc := "Django framework exception traceback and internal path disclosure (suspected debug mode)"
	if hasDeveloperTemplate {
		debugModeStatus = "confirmed"
		confidence = ConfidenceHigh
		desc = "Django technical 500 debug page exposed (DEBUG=True confirmed)"
	}

	// Evaluate severity based on actual sensitivity of disclosed content
	severity := SeverityMedium
	if hasUnmaskedSecret {
		severity = SeverityCritical
	} else if hasDeveloperTemplate {
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
		pathSummary = fmt.Sprintf(" Disclosed %d filesystem path(s) in traceback: [%s].",
			len(exposedPaths), strings.Join(sample, ", "))
	}

	statusPrefix := "HTTP %d Django exception traceback observed exposing internal filesystem paths (suspected debug mode)."
	if hasDeveloperTemplate {
		statusPrefix = "HTTP %d Django technical 500 debug page confirmed (DEBUG=True)."
	}
	evidence := fmt.Sprintf(statusPrefix, resp.StatusCode)
	if pathSummary != "" {
		evidence += pathSummary
	}
	if djangoVersion != "" {
		evidence += fmt.Sprintf(" Framework: Django %s.", djangoVersion)
	}
	if hasUnmaskedSecret {
		evidence += fmt.Sprintf(" Unmasked credential(s) observed in settings: [%s] (secret values redacted).",
			strings.Join(unmaskedSecretKeys, ", "))
	}

	var negEv string
	if !hasDeveloperTemplate {
		negEv = "Traceback observed without official Django developer template; DEBUG=True configuration remains unconfirmed."
	} else if !hasUnmaskedSecret {
		negEv = "Official Django debug page confirmed; no unmasked passwords or secret keys were detected."
	}

	details := map[string]string{
		"framework":   "Django",
		"debug_mode":  debugModeStatus,
		"http_status": fmt.Sprintf("%d", resp.StatusCode),
	}
	if djangoVersion != "" {
		details["django_version"] = djangoVersion
	}
	if pythonVer != "" {
		details["python_version"] = pythonVer
	}
	if pythonExec != "" {
		details["python_executable"] = secrets.RedactText(pythonExec)
	}
	if len(exposedPaths) > 0 {
		details["path_count"] = fmt.Sprintf("%d", len(exposedPaths))
		details["sample_path"] = secrets.RedactText(exposedPaths[0])
	}
	if resp.Truncated {
		details["limitations"] = "Response exceeded 512 KiB and was bounded to prevent memory exhaustion"
	}

	return &APIFinding{
		Category:         CategoryDjangoDebugMode,
		Endpoint:         endpointURL,
		Method:           http.MethodGet,
		Description:      desc,
		Evidence:         secrets.RedactText(evidence),
		NegativeEvidence: negEv,
		Severity:         severity,
		Confidence:       confidence,
		Fingerprint:      GenerateFingerprint(CategoryDjangoDebugMode, endpointURL, http.MethodGet),
		Classification:   ClassHealth,
		Details:          details,
		HTTPStatus:       resp.StatusCode,
	}
}

// InspectDjangoTechnical404 detects Django's technical 404 URL pattern disclosure page generated when DEBUG=True.
func InspectDjangoTechnical404(resp *ProbeResponse, endpointURL string) *APIFinding {
	if resp == nil || resp.StatusCode != http.StatusNotFound || len(resp.Body) == 0 {
		return nil
	}

	bodyStr := string(resp.Body)
	lowerBody := strings.ToLower(bodyStr)

	// Must be Django technical 404 page
	has404Title := strings.Contains(lowerBody, "page not found (404)")
	hasURLConf := strings.Contains(bodyStr, "Using the URLconf defined in")
	hasPatternsText := strings.Contains(bodyStr, "Django tried these URL patterns, in this order:")

	if !has404Title || !hasURLConf || !hasPatternsText {
		return nil
	}

	// Extract URLconf identifier
	urlconf := ""
	if m := djangoURLConfRegex.FindStringSubmatch(bodyStr); len(m) > 1 {
		urlconf = strings.TrimSpace(m[1])
	}

	// Extract URL patterns
	var patterns []string
	patternMatches := djangoURLPatternRegex.FindAllStringSubmatch(bodyStr, -1)
	seenPatterns := make(map[string]struct{})
	for _, m := range patternMatches {
		if len(m) > 1 {
			pat := strings.TrimSpace(m[1])
			if _, exists := seenPatterns[pat]; !exists {
				seenPatterns[pat] = struct{}{}
				patterns = append(patterns, pat)
			}
		}
	}
	sort.Strings(patterns)

	var patternSummary string
	if len(patterns) > 0 {
		sample := patterns
		if len(sample) > 4 {
			sample = sample[:4]
		}
		patternSummary = fmt.Sprintf(" Disclosed %d internal route pattern(s): [%s].",
			len(patterns), strings.Join(sample, ", "))
	}

	evidence := fmt.Sprintf("HTTP 404 Django technical error page confirmed (DEBUG=True). Using URLconf %q.%s",
		urlconf, patternSummary)

	details := map[string]string{
		"framework":     "Django",
		"debug_mode":    "true",
		"urlconf":       urlconf,
		"pattern_count": fmt.Sprintf("%d", len(patterns)),
		"http_status":   "404",
	}
	if resp.Truncated {
		details["limitations"] = "Response exceeded 512 KiB and was bounded to prevent memory exhaustion"
	}

	return &APIFinding{
		Category:       CategoryDjangoURLConfDisclosure,
		Endpoint:       endpointURL,
		Method:         http.MethodGet,
		Description:    "Django technical 404 page exposed application URLconf routing patterns",
		Evidence:       secrets.RedactText(evidence),
		Severity:       SeverityMedium,
		Confidence:     ConfidenceHigh,
		Fingerprint:    GenerateFingerprint(CategoryDjangoURLConfDisclosure, endpointURL, http.MethodGet),
		Classification: ClassDocumentation,
		Details:        details,
		HTTPStatus:     http.StatusNotFound,
	}
}

// InspectDjangoBrowsableAPI detects the Django REST Framework (DRF) browsable API HTML interface.
func InspectDjangoBrowsableAPI(resp *ProbeResponse, endpointURL string) *APIFinding {
	if resp == nil || resp.StatusCode != http.StatusOK || len(resp.Body) == 0 {
		return nil
	}

	contentType := resp.Header.Get("Content-Type")
	bodyStr := string(resp.Body)

	// Must be an HTML response
	if !strings.Contains(strings.ToLower(contentType), "text/html") &&
		!strings.Contains(bodyStr, "<!DOCTYPE html>") &&
		!strings.Contains(bodyStr, "<html") {
		return nil
	}

	// Must contain Django REST Framework signature
	if !strings.Contains(bodyStr, "Django REST framework") {
		return nil
	}

	// Corroborating DRF UI markers
	hasSourcePage := strings.Contains(bodyStr, `data-target="#sourcePage"`)
	hasResponseInfo := strings.Contains(bodyStr, `class="response-info"`)
	hasAPIView := strings.Contains(bodyStr, `api-view`) || strings.Contains(bodyStr, `name="api-view"`)
	hasBreadcrumb := strings.Contains(bodyStr, `class="breadcrumb"`)

	if !hasSourcePage && !hasResponseInfo && !hasAPIView && !hasBreadcrumb {
		return nil
	}

	evidence := fmt.Sprintf("HTTP 200 OK. Django REST Framework browsable API interface active at %s.", endpointURL)

	details := map[string]string{
		"framework":    "Django",
		"interface":    "Django REST Framework Browsable API",
		"content_type": contentType,
		"http_status":  "200",
	}

	return &APIFinding{
		Category:       CategoryDjangoBrowsableAPI,
		Endpoint:       endpointURL,
		Method:         http.MethodGet,
		Description:    "Django REST Framework browsable API exposed publicly",
		Evidence:       secrets.RedactText(evidence),
		Severity:       SeverityLow,
		Confidence:     ConfidenceHigh,
		Fingerprint:    GenerateFingerprint(CategoryDjangoBrowsableAPI, endpointURL, http.MethodGet),
		Classification: ClassAPI,
		Details:        details,
		HTTPStatus:     http.StatusOK,
	}
}
