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
	// MaxGoResponseSize enforces a strict 512 KiB wire-read limit for Go diagnostic inspection.
	MaxGoResponseSize = 512 * 1024
)

// DefaultGoCandidatePaths lists standard diagnostic and discovery probe relative paths for Go.
var DefaultGoCandidatePaths = []string{
	"/debug/pprof/",
	"/debug/pprof/goroutine",
	"/debug/vars",
	"/_felix_go_probe",
}

var (
	// goPanicHeaderRegex matches Go runtime panic headers
	goPanicHeaderRegex = regexp.MustCompile(`(?m)^(?:panic:\s*(.+)|\[Recovery\]\s+.*panic\s+recovered:\s*(.+)|\[GIN-debug\]\s+.*panic:\s*(.+))`)
	// goGoroutineHeaderRegex matches Go runtime goroutine headers, e.g. "goroutine 1 [running]:"
	goGoroutineHeaderRegex = regexp.MustCompile(`(?m)^goroutine\s+(\d+)\s+\[([^\]]+)\]:`)
	// goCallFrameRegex matches Go function call frames, e.g. "main.main()" or "net/http.(*conn).serve(0xc00008e000)"
	goCallFrameRegex = regexp.MustCompile(`(?m)^([a-zA-Z0-9_\-\./]+)\.([a-zA-Z0-9_\$\.\<\>\*]+)\((0x[0-9a-fA-F]+(?:,\s*0x[0-9a-fA-F]+)*|\.\.\.)?\)`)
	// goSourceLocationRegex matches Go source file paths and line numbers, e.g. "	/go/src/app/main.go:42 +0x12b"
	goSourceLocationRegex = regexp.MustCompile(`(?m)^\s*([a-zA-Z0-9_\-\./\\]+\.go):(\d+)(?:\s+\+0x[0-9a-fA-F]+)?`)
	// goFilePathRegex matches internal absolute filesystem paths for Go applications
	goFilePathRegex = regexp.MustCompile(`(?:^|[\s\("'])(/(?:go/src|home|app|workspace|usr/local/go|var/www)/[a-zA-Z0-9_\-\./\\]+\.(?:go|mod|sum|yaml|json)|[A-Za-z]:\\[a-zA-Z0-9_\-\.\\]+\.(?:go|mod|sum|yaml|json))`)
	// goPprofIndexMarkerRegex verifies official Go net/http/pprof HTML or text index page
	goPprofIndexMarkerRegex = regexp.MustCompile(`(?i)(?:Types of profiles available:|/debug/pprof/heap|/debug/pprof/goroutine|/debug/pprof/block)`)
)

// AuditGoDiagnostics coordinates safe, bounded assessment of Go runtime and framework diagnostic behavior.
func AuditGoDiagnostics(ctx context.Context, client *Client, targetBaseURL string, candidatePaths []string) []APIFinding {
	var findings []APIFinding
	resolvedCandidates := ResolveGoCandidateURLs(targetBaseURL, candidatePaths)

	for _, targetURL := range resolvedCandidates {
		if client.isExcluded != nil && client.isExcluded(targetURL) {
			continue
		}
		if client.isAllowed != nil && !client.isAllowed(targetURL) {
			continue
		}

		endpointFindings := ProbeGoEndpoint(ctx, client, targetURL)
		for _, f := range endpointFindings {
			findings = append(findings, NormalizeFrameworkFinding(f))
		}
	}

	return DeduplicateFrameworkFindings(findings)
}

// ResolveGoCandidateURLs resolves candidate Go diagnostic URLs for a target base URL,
// supporting nested application paths, root origin endpoints, and crawled asset hints.
func ResolveGoCandidateURLs(targetBaseURL string, customCandidates []string) []string {
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

	// 1. Default diagnostic paths (pprof, expvar, and harmless probe)
	for _, p := range DefaultGoCandidatePaths {
		addURL(baseURL + p)
	}

	// 2. Custom or discovered candidate paths from crawled assets
	for _, cp := range customCandidates {
		clean := strings.TrimSpace(cp)
		if clean == "" {
			continue
		}
		lower := strings.ToLower(clean)
		if strings.Contains(lower, "pprof") || strings.Contains(lower, "debug") ||
			strings.Contains(lower, "vars") || strings.Contains(lower, "panic") ||
			strings.Contains(lower, "gin") || strings.Contains(lower, "fiber") ||
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

// ProbeGoEndpoint dispatches a bounded, safe HTTP GET probe to assess Go diagnostic disclosure.
func ProbeGoEndpoint(ctx context.Context, client *Client, targetURL string) []APIFinding {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, targetURL, nil)
	if err != nil {
		return nil
	}
	req.Header.Set("Accept", "text/html,application/json,text/plain,*/*")

	resp, err := client.DoBounded(ctx, req, MaxGoResponseSize)
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

	return InspectGoResponse(resp, targetURL)
}

// InspectGoResponse evaluates HTTP response headers and body for Go runtime, pprof, expvar, and panic indicators.
func InspectGoResponse(resp *ProbeResponse, endpointURL string) []APIFinding {
	if resp == nil {
		return nil
	}

	var findings []APIFinding

	// 1. Inspect Go pprof diagnostic profiling interface (/debug/pprof/*)
	if pprofFinding := InspectGoPprof(resp, endpointURL); pprofFinding != nil {
		findings = append(findings, *pprofFinding)
		return findings
	}

	// 2. Inspect Go expvar runtime variables endpoint (/debug/vars)
	if expvarFinding := InspectGoExpvar(resp, endpointURL); expvarFinding != nil {
		findings = append(findings, *expvarFinding)
		return findings
	}

	// 3. Inspect Go panic / goroutine dump
	if panicFinding := InspectGoPanic(resp, endpointURL); panicFinding != nil {
		findings = append(findings, *panicFinding)
		return findings
	}

	// 4. Inspect Go runtime framework identifying headers (e.g. Server: Fiber)
	if runtimeFinding := InspectGoRuntimeHeader(resp, endpointURL); runtimeFinding != nil {
		findings = append(findings, *runtimeFinding)
		return findings
	}

	return nil
}

// InspectGoPprof checks if an endpoint exposes the Go standard library net/http/pprof interface or goroutine dumps.
func InspectGoPprof(resp *ProbeResponse, endpointURL string) *APIFinding {
	if resp.StatusCode != http.StatusOK {
		return nil
	}

	bodyStr := string(resp.Body)
	lowerBody := strings.ToLower(bodyStr)
	lowerURL := strings.ToLower(endpointURL)

	isPprofRoute := strings.Contains(lowerURL, "/debug/pprof")
	if !isPprofRoute && !goPprofIndexMarkerRegex.MatchString(bodyStr) {
		return nil
	}

	goroutines := goGoroutineHeaderRegex.FindAllString(bodyStr, -1)
	hasGoroutineDump := len(goroutines) > 0 || strings.Contains(bodyStr, "goroutine profile:")
	hasHeapDump := strings.Contains(lowerURL, "heap") && (strings.Contains(bodyStr, "heap profile:") || strings.Contains(bodyStr, "runtime.MemProfile"))
	hasIndexMarkers := goPprofIndexMarkerRegex.MatchString(bodyStr)

	// Case 1: Active operational profiling data exposed (goroutines or heap execution traces) -> SeverityHigh
	if hasGoroutineDump || hasHeapDump {
		desc := "Go runtime goroutine diagnostic execution dump exposed"
		ev := fmt.Sprintf("HTTP 200 OK on %s. Active Go goroutine execution dump disclosed (%d active goroutines observed).",
			endpointURL, len(goroutines))
		if hasHeapDump {
			desc = "Go runtime heap memory profile dump exposed"
			ev = fmt.Sprintf("HTTP 200 OK on %s. Active Go heap memory profile data disclosed without authentication.", endpointURL)
		}

		negEv := "Execution profiling data observed. Binary collection and heap memory downloads were bounded and not stored."

		details := map[string]string{
			"framework":                "Go",
			"component":                "net/http/pprof",
			"endpoint":                 endpointURL,
			"http_status":              "200",
			"interface":                "profiling_data",
			"data_exposure":            "active_execution_traces",
			"auth_context":             "unauthenticated_or_unknown",
			"validity_status":          "unverified_active_probe_omitted",
			"active_auth_tested":       "false",
			"verification_limitations": "Passive read-only query; execution profiling was observed without backend state alteration",
		}
		if hasGoroutineDump {
			details["goroutine_count"] = fmt.Sprintf("%d", len(goroutines))
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
			Category:         CategoryGoPprofExposure,
			Endpoint:         endpointURL,
			Method:           http.MethodGet,
			Description:      secrets.RedactText(desc),
			Evidence:         secrets.RedactText(ev),
			NegativeEvidence: secrets.RedactText(negEv),
			Severity:         SeverityHigh,
			Confidence:       ConfidenceHigh,
			Fingerprint:      GenerateFingerprint(CategoryGoPprofExposure, endpointURL, http.MethodGet),
			Classification:   ClassAdmin,
			Details:          details,
			HTTPStatus:       resp.StatusCode,
		}
	}

	// Case 2: Profiling index / listing page reachable (non-sensitive endpoint inventory listing) -> SeverityLow
	if hasIndexMarkers {
		desc := "Go net/http/pprof diagnostic profiling index reachable (endpoint inventory observation)"
		ev := fmt.Sprintf("HTTP 200 OK on %s. Go net/http/pprof diagnostic profiling index reachable; endpoint lists available profile types (heap, goroutine, block, etc.). Active execution dumps were not returned by this listing.", endpointURL)
		negEv := "Profiling index observed; live memory dumps, CPU execution traces, and binary profiling data were bounded and not executed."

		details := map[string]string{
			"framework":                "Go",
			"component":                "net/http/pprof",
			"endpoint":                 endpointURL,
			"http_status":              "200",
			"interface":                "profiling_index",
			"data_exposure":            "endpoint_inventory_only",
			"auth_context":             "unauthenticated_or_unknown",
			"validity_status":          "unverified_active_probe_omitted",
			"active_auth_tested":       "false",
			"verification_limitations": "Passive read-only query; execution profiling and heap collection were omitted to preserve target performance",
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
			Category:         CategoryGoPprofExposure,
			Endpoint:         endpointURL,
			Method:           http.MethodGet,
			Description:      secrets.RedactText(desc),
			Evidence:         secrets.RedactText(ev),
			NegativeEvidence: secrets.RedactText(negEv),
			Severity:         SeverityLow,
			Confidence:       ConfidenceHigh,
			Fingerprint:      GenerateFingerprint(CategoryGoPprofExposure, endpointURL, http.MethodGet),
			Classification:   ClassAdmin,
			Details:          details,
			HTTPStatus:       resp.StatusCode,
		}
	}

	// Case 3: Ambiguous or minimal response on /debug/pprof route (exposure/impact unverified) -> SeverityInfo, ConfidenceLow
	if isPprofRoute && strings.Contains(lowerBody, "pprof") {
		desc := "Go diagnostic profiling endpoint response ambiguous (exposure and impact unverified)"
		ev := fmt.Sprintf("HTTP 200 OK on %s, but response lacked standard Go net/http/pprof index markers or active profiling data.", endpointURL)
		negEv := "Endpoint is reachable but did not disclose profiling data, index listings, or sensitive diagnostics; impact could not be confirmed."

		details := map[string]string{
			"framework":                "Go",
			"component":                "net/http/pprof",
			"endpoint":                 endpointURL,
			"http_status":              "200",
			"interface":                "ambiguous",
			"data_exposure":            "unverified",
			"classification":           "inconclusive",
			"auth_context":             "unknown",
			"verification_limitations": "Endpoint reachable but response lacked standard index markers or profiling data; impact unverified",
		}
		if resp.Truncated {
			details["limitations"] = "Response exceeded 512 KiB and was bounded to preserve system resources"
		}

		return &APIFinding{
			Category:         CategoryGoPprofExposure,
			Endpoint:         endpointURL,
			Method:           http.MethodGet,
			Description:      secrets.RedactText(desc),
			Evidence:         secrets.RedactText(ev),
			NegativeEvidence: secrets.RedactText(negEv),
			Severity:         SeverityInfo,
			Confidence:       ConfidenceLow,
			Fingerprint:      GenerateFingerprint(CategoryGoPprofExposure, endpointURL, http.MethodGet),
			Classification:   ClassAdmin,
			Details:          details,
			HTTPStatus:       resp.StatusCode,
		}
	}

	return nil
}

// InspectGoExpvar checks if an endpoint exposes the Go standard library expvar metrics and variables (/debug/vars).
func InspectGoExpvar(resp *ProbeResponse, endpointURL string) *APIFinding {
	if resp.StatusCode != http.StatusOK {
		return nil
	}

	lowerURL := strings.ToLower(endpointURL)
	if !strings.HasSuffix(lowerURL, "/debug/vars") && !strings.Contains(lowerURL, "/debug/vars?") {
		return nil
	}

	// Expvar returns JSON containing cmdline and memstats
	var data map[string]interface{}
	if err := json.Unmarshal(resp.Body, &data); err != nil {
		return nil
	}

	_, hasCmdline := data["cmdline"]
	_, hasMemstats := data["memstats"]
	if !hasCmdline && !hasMemstats {
		return nil
	}

	hasUnmaskedSecret := false
	var observedSecretKeys []string
	nodeCount := 0

	// Recursively inspect expvar data for secrets or canary values with bounded depth and node count
	var walkExpvar func(k string, v interface{}, depth int)
	walkExpvar = func(k string, v interface{}, depth int) {
		if depth > 10 || nodeCount > 5000 {
			return
		}
		nodeCount++

		switch val := v.(type) {
		case string:
			if isGenuineUnmaskedSecret(k, val) {
				hasUnmaskedSecret = true
				observedSecretKeys = append(observedSecretKeys, k)
			}
			if strings.Contains(val, "felix_test_canary_secret") {
				hasUnmaskedSecret = true
				observedSecretKeys = append(observedSecretKeys, "canary_secret")
			}
		case map[string]interface{}:
			for subK, subV := range val {
				walkExpvar(subK, subV, depth+1)
			}
		case []interface{}:
			for _, item := range val {
				walkExpvar(k, item, depth+1)
			}
		}
	}
	for k, v := range data {
		walkExpvar(k, v, 0)
	}

	severity := SeverityInfo
	desc := "Go expvar runtime metrics and variables (/debug/vars) publicly accessible"
	if hasUnmaskedSecret {
		severity = SeverityCritical
		desc = "Go expvar runtime variables expose candidate secret material (validity unverified; active authentication not confirmed)"
	}

	ev := fmt.Sprintf("HTTP 200 OK on %s. Go expvar runtime variables (cmdline, memstats) disclosed without authentication.", endpointURL)
	if hasUnmaskedSecret {
		ev += fmt.Sprintf(" Candidate secret material observed: [%s] (active validity was not verified; values redacted).",
			strings.Join(observedSecretKeys, ", "))
	}

	negEv := "Operational metrics observed; all command-line arguments and exported variable values were bounded and redacted. Active credential validity was not tested or verified against backend services."

	details := map[string]string{
		"framework":                "Go",
		"component":                "expvar",
		"endpoint":                 endpointURL,
		"http_status":              "200",
		"validity_status":          "unverified_active_probe_omitted",
		"active_auth_tested":       "false",
		"verification_limitations": "Passive read-only query; backend state was not altered",
	}
	if hasUnmaskedSecret {
		details["unmasked_secrets_count"] = fmt.Sprintf("%d", len(observedSecretKeys))
		details["candidate_material_status"] = "unverified_candidate_material"
		details["credential_validity"] = "unverified"
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
		Category:         CategoryGoVarsExposure,
		Endpoint:         endpointURL,
		Method:           http.MethodGet,
		Description:      secrets.RedactText(desc),
		Evidence:         secrets.RedactText(ev),
		NegativeEvidence: secrets.RedactText(negEv),
		Severity:         severity,
		Confidence:       ConfidenceHigh,
		Fingerprint:      GenerateFingerprint(CategoryGoVarsExposure, endpointURL, http.MethodGet),
		Classification:   ClassAdmin,
		Details:          details,
		HTTPStatus:       resp.StatusCode,
	}
}

// InspectGoPanic evaluates HTTP response body for Go panic traces, goroutine stack dumps, and source file locations.
func InspectGoPanic(resp *ProbeResponse, endpointURL string) *APIFinding {
	bodyStr := string(resp.Body)

	filePaths := goFilePathRegex.FindAllStringSubmatch(bodyStr, -1)
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

	// Go panic stack traces must have goroutine or panic headers, PLUS at least 2 .go source location lines
	hasPanicHeader := goPanicHeaderRegex.MatchString(bodyStr)
	hasGoroutineHeader := len(goGoroutineHeaderRegex.FindAllString(bodyStr, -1)) > 0
	sourceLocations := goSourceLocationRegex.FindAllString(bodyStr, -1)

	hasPanicDump := (hasPanicHeader || hasGoroutineHeader) && len(sourceLocations) >= 2
	hasSourcePathDisclosure := len(uniquePaths) > 0 && (resp.StatusCode >= 400 || strings.Contains(strings.ToLower(bodyStr), "error"))

	if !hasPanicDump && !hasSourcePathDisclosure {
		return nil
	}

	// Check for candidate unmasked secrets in panic output
	hasUnmaskedSecret := false
	var observedSecretKeys []string
	for _, line := range strings.Split(bodyStr, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
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
		if strings.Contains(trimmed, "felix_test_canary_secret") {
			hasUnmaskedSecret = true
			observedSecretKeys = append(observedSecretKeys, "canary_secret")
		}
	}

	// Case 1: Isolated source path disclosure without complete panic dump
	if !hasPanicDump && hasSourcePathDisclosure {
		category := CategoryGoStackTrace
		severity := SeverityLow
		desc := "Go error response exposes internal source filesystem path"
		if hasUnmaskedSecret {
			severity = SeverityCritical
			desc = "Go error response exposes candidate secret material (validity unverified)"
		}

		ev := fmt.Sprintf("HTTP %d on %s disclosed internal Go source path(s): [%s] without a full panic dump.",
			resp.StatusCode, endpointURL, strings.Join(uniquePaths, ", "))
		negEv := "Internal source path observed in error response without complete call stack or panic dump; active credential validity was not tested."

		details := map[string]string{
			"framework":                "Go",
			"component":                "ErrorHandler",
			"endpoint":                 endpointURL,
			"http_status":              fmt.Sprintf("%d", resp.StatusCode),
			"disclosed_paths_count":    fmt.Sprintf("%d", len(uniquePaths)),
			"sample_path":              uniquePaths[0],
			"has_panic_dump":           "false",
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

		return &APIFinding{
			Category:         category,
			Endpoint:         endpointURL,
			Method:           http.MethodGet,
			Description:      secrets.RedactText(desc),
			Evidence:         secrets.RedactText(ev),
			NegativeEvidence: secrets.RedactText(negEv),
			Severity:         severity,
			Confidence:       ConfidenceHigh,
			Fingerprint:      GenerateFingerprint(category, endpointURL, http.MethodGet),
			Classification:   ClassHealth,
			Details:          details,
			HTTPStatus:       resp.StatusCode,
		}
	}

	severity := SeverityMedium
	desc := "Go runtime panic stack trace disclosed via HTTP response"
	if hasUnmaskedSecret {
		severity = SeverityCritical
		desc = "Go runtime panic output exposes candidate secret material (validity unverified)"
	} else if isGoSensitivePanic(bodyStr) {
		severity = SeverityHigh
		desc = "Go runtime panic discloses sensitive database or internal application details"
	} else if len(uniquePaths) > 0 {
		severity = SeverityMedium
		desc = "Go runtime panic stack trace exposes internal filesystem paths and source structure"
	}

	ev := fmt.Sprintf("HTTP %d on %s disclosed Go panic stack trace with %d source location(s).",
		resp.StatusCode, endpointURL, len(sourceLocations))
	if len(uniquePaths) > 0 {
		sample := uniquePaths
		if len(sample) > 3 {
			sample = sample[:3]
		}
		ev += fmt.Sprintf(" Disclosed %d internal path(s): [%s].", len(uniquePaths), strings.Join(sample, ", "))
	}
	if hasUnmaskedSecret {
		ev += fmt.Sprintf(" Candidate secret material observed: [%s] (active validity was not verified; values redacted).",
			strings.Join(observedSecretKeys, ", "))
	}

	negEv := "Runtime panic output observed. Detected candidate diagnostic data was bounded and redacted; active credential validity was not tested."

	details := map[string]string{
		"framework":                "Go",
		"component":                "PanicRecovery",
		"endpoint":                 endpointURL,
		"http_status":              fmt.Sprintf("%d", resp.StatusCode),
		"source_locations_count":   fmt.Sprintf("%d", len(sourceLocations)),
		"validity_status":          "unverified_active_probe_omitted",
		"active_auth_tested":       "false",
		"verification_limitations": "Passive read-only inspection; backend state was not altered and panics were not induced",
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

	for k, v := range details {
		if secrets.IsSensitiveKey(k) || secrets.IsSensitiveHeader(k) {
			details[k] = "[REDACTED]"
		} else {
			details[k] = secrets.RedactText(v)
		}
	}

	return &APIFinding{
		Category:         CategoryGoDebugPanic,
		Endpoint:         endpointURL,
		Method:           http.MethodGet,
		Description:      secrets.RedactText(desc),
		Evidence:         secrets.RedactText(ev),
		NegativeEvidence: secrets.RedactText(negEv),
		Severity:         severity,
		Confidence:       ConfidenceHigh,
		Fingerprint:      GenerateFingerprint(CategoryGoDebugPanic, endpointURL, http.MethodGet),
		Classification:   ClassHealth,
		Details:          details,
		HTTPStatus:       resp.StatusCode,
	}
}

// InspectGoRuntimeHeader checks for Go framework identification headers (Fiber, Echo, etc.).
func InspectGoRuntimeHeader(resp *ProbeResponse, endpointURL string) *APIFinding {
	serverHdr := strings.TrimSpace(resp.Header.Get("Server"))
	lowerServer := strings.ToLower(serverHdr)

	var frameworkName string
	if strings.Contains(lowerServer, "fiber") {
		frameworkName = "Fiber"
	} else if strings.Contains(lowerServer, "echo") {
		frameworkName = "Echo"
	}

	if frameworkName == "" {
		return nil
	}

	// Server header alone is NOT a vulnerability -> SeverityInfo
	return &APIFinding{
		Category:         CategoryGoRuntimeExposure,
		Endpoint:         endpointURL,
		Method:           http.MethodGet,
		Description:      fmt.Sprintf("Go %s framework identified via HTTP Server header", frameworkName),
		Evidence:         fmt.Sprintf("HTTP %d on %s returned Server: %s header.", resp.StatusCode, endpointURL, serverHdr),
		NegativeEvidence: "Framework identifier observed in HTTP response header; no diagnostic interface, panic dump, or unauthenticated data disclosure was demonstrated.",
		Severity:         SeverityInfo,
		Confidence:       ConfidenceHigh,
		Fingerprint:      GenerateFingerprint(CategoryGoRuntimeExposure, endpointURL, http.MethodGet),
		Classification:   ClassAPI,
		Details: map[string]string{
			"framework":   frameworkName,
			"header_name": "Server",
			"http_status": fmt.Sprintf("%d", resp.StatusCode),
		},
		HTTPStatus: resp.StatusCode,
	}
}

// isGoSensitivePanic checks if a Go panic message exposes sensitive database errors, credentials, or PII.
func isGoSensitivePanic(body string) bool {
	lower := strings.ToLower(body)
	if strings.Contains(lower, "sqlstate") || strings.Contains(lower, "pq:") ||
		strings.Contains(lower, "mysql:") || strings.Contains(lower, "gorm:") {
		return true
	}
	if strings.Contains(lower, "password") || strings.Contains(lower, "passwd") ||
		strings.Contains(lower, "secret") || strings.Contains(lower, "api_key") ||
		strings.Contains(lower, "bearer ") || strings.Contains(lower, "token") ||
		strings.Contains(lower, "credit_card") || strings.Contains(lower, "ssn") {
		return true
	}
	return false
}
