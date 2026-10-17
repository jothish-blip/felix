package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"

	"felix/pkg/secrets"
)

const (
	// MaxActuatorResponseSize enforces a strict 512 KiB wire-read limit for Actuator endpoints.
	MaxActuatorResponseSize = 512 * 1024

	// ActuatorVendorContentType defines the Spring Boot Actuator v2/v3 media types.
	ActuatorVendorContentTypeV3 = "application/vnd.spring-boot.actuator.v3+json"
	ActuatorVendorContentTypeV2 = "application/vnd.spring-boot.actuator.v2+json"
	ActuatorVendorContentType   = "application/vnd.spring-boot.actuator+json"
)

// Standard Actuator candidate relative paths for Phase 3.1.
var DefaultActuatorCandidatePaths = []string{
	"/actuator/health",
	"/actuator/env",
	"/actuator/mappings",
}

// ActuatorAccessStatus models the empirical access state of an Actuator endpoint.
type ActuatorAccessStatus string

const (
	ActuatorAccessPublic       ActuatorAccessStatus = "PUBLIC"
	ActuatorAccessRestricted   ActuatorAccessStatus = "RESTRICTED"
	ActuatorAccessNotFound     ActuatorAccessStatus = "NOT_FOUND"
	ActuatorAccessRedirect     ActuatorAccessStatus = "REDIRECT"
	ActuatorAccessInconclusive ActuatorAccessStatus = "INCONCLUSIVE"
	ActuatorAccessUnreachable  ActuatorAccessStatus = "UNREACHABLE"
)

// ActuatorProbeResult captures the bounded assessment telemetry for an Actuator endpoint.
type ActuatorProbeResult struct {
	URL            string               `json:"url"`
	Path           string               `json:"path"`
	Method         string               `json:"method"`
	StatusCode     int                  `json:"status_code"`
	ContentType    string               `json:"content_type"`
	AccessStatus   ActuatorAccessStatus `json:"access_status"`
	AuthState      AuthState            `json:"auth_state"`
	IsGenuine      bool                 `json:"is_genuine"`
	ComponentCount int                  `json:"component_count,omitempty"`
	PropertyCount  int                  `json:"property_count,omitempty"`
	RouteCount     int                  `json:"route_count,omitempty"`
	Limitations    string               `json:"limitations,omitempty"`
	Finding        *APIFinding          `json:"finding,omitempty"`
}

// springHealthResponse models Spring Boot 2.x and 3.x health JSON.
type springHealthResponse struct {
	Status     string                 `json:"status"`
	Components map[string]interface{} `json:"components,omitempty"`
	Details    map[string]interface{} `json:"details,omitempty"`
}

// springEnvResponse models Spring Boot 2.x and 3.x environment JSON.
type springEnvResponse struct {
	ActiveProfiles  []string `json:"activeProfiles,omitempty"`
	Profiles        []string `json:"profiles,omitempty"`
	PropertySources []struct {
		Name       string                 `json:"name"`
		Properties map[string]interface{} `json:"properties"`
	} `json:"propertySources,omitempty"`
}

// springMappingsResponse models Spring Boot 2.x and 3.x mappings JSON.
type springMappingsResponse struct {
	Contexts map[string]struct {
		Mappings struct {
			DispatcherServlets map[string][]struct {
				Handler   string `json:"handler"`
				Predicate string `json:"predicate"`
				Details   *struct {
					RequestMappingConditions *struct {
						Patterns []string `json:"patterns"`
						Methods  []string `json:"methods"`
					} `json:"requestMappingConditions"`
				} `json:"details"`
			} `json:"dispatcherServlets"`
			ServletFilters []interface{} `json:"servletFilters,omitempty"`
			Servlets       []interface{} `json:"servlets,omitempty"`
		} `json:"mappings"`
	} `json:"contexts"`
}

// AuditSpringActuator coordinates bounded, safe assessment of Spring Boot Actuator interfaces.
func AuditSpringActuator(ctx context.Context, client *Client, targetBaseURL string, candidatePaths []string) []APIFinding {
	var findings []APIFinding
	resolvedCandidates := ResolveActuatorCandidateURLs(targetBaseURL, candidatePaths)

	for _, targetURL := range resolvedCandidates {
		// Enforce client scope and exclusion rules before dispatching
		if client.isExcluded != nil && client.isExcluded(targetURL) {
			continue
		}
		if client.isAllowed != nil && !client.isAllowed(targetURL) {
			continue
		}

		result := ProbeActuatorEndpoint(ctx, client, targetURL)
		if result.Finding != nil {
			findings = append(findings, NormalizeFrameworkFinding(*result.Finding))
		}
	}

	return DeduplicateFrameworkFindings(findings)
}

// ResolveActuatorCandidateURLs resolves candidate Actuator URLs for a given target base URL,
// supporting nested application paths, root origin endpoints, and crawled asset hints.
func ResolveActuatorCandidateURLs(targetBaseURL string, customCandidates []string) []string {
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

	// 1. Base URL candidates (handles nested base paths like /app/actuator/... and root targets)
	for _, p := range DefaultActuatorCandidatePaths {
		addURL(baseURL + p)
	}

	// 2. Custom or discovered candidate paths from crawled assets
	for _, cp := range customCandidates {
		clean := strings.TrimSpace(cp)
		if clean == "" {
			continue
		}
		lower := strings.ToLower(clean)
		if !strings.Contains(lower, "actuator") && !strings.Contains(lower, "health") &&
			!strings.Contains(lower, "env") && !strings.Contains(lower, "mappings") {
			continue
		}
		if !strings.HasPrefix(clean, "/") {
			clean = "/" + clean
		}
		addURL(baseURL + clean)
	}

	return candidates
}

// ProbeActuatorEndpoint conducts a bounded GET request to an Actuator candidate endpoint
// and evaluates its disclosure characteristics and access restrictions.
func ProbeActuatorEndpoint(ctx context.Context, client *Client, endpointURL string) ActuatorProbeResult {
	res := ActuatorProbeResult{
		URL:          endpointURL,
		Method:       http.MethodGet,
		AccessStatus: ActuatorAccessInconclusive,
		AuthState:    AuthStateUnknown,
	}

	parsed, err := url.Parse(endpointURL)
	if err == nil {
		res.Path = parsed.Path
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpointURL, nil)
	if err != nil {
		res.AccessStatus = ActuatorAccessUnreachable
		res.Limitations = fmt.Sprintf("failed constructing request: %v", err)
		return res
	}

	// Request vendor media types and standard JSON
	req.Header.Set("Accept", fmt.Sprintf("%s, %s, %s, application/json;q=0.9, */*;q=0.8",
		ActuatorVendorContentTypeV3, ActuatorVendorContentTypeV2, ActuatorVendorContentType))

	// Enforce strict 512 KiB wire limit
	probeResp, err := client.DoBounded(ctx, req, MaxActuatorResponseSize)
	if err != nil {
		if err == ErrRateLimited {
			res.Limitations = "assessment paused: target rate limit encountered (HTTP 429)"
			return res
		}
		if err == ErrResponseTooLarge {
			res.Limitations = "response exceeded 512 KiB wire limit; body read was safely aborted"
			return res
		}
		res.AccessStatus = ActuatorAccessUnreachable
		res.Limitations = fmt.Sprintf("network transport error: %v", err)
		return res
	}

	res.StatusCode = probeResp.StatusCode
	if probeResp.Header != nil {
		res.ContentType = probeResp.Header.Get("Content-Type")
	}

	// 1. Evaluate Authentication & Access Boundaries
	if probeResp.Redirected {
		res.StatusCode = probeResp.InitialStatusCode
		res.AccessStatus = ActuatorAccessRedirect
		res.AuthState = AuthStateRedirect
		res.Limitations = fmt.Sprintf("endpoint redirected to %s (HTTP %d); direct access not verified", probeResp.RedirectURL, probeResp.InitialStatusCode)
		return res
	}

	switch probeResp.StatusCode {
	case http.StatusUnauthorized:
		res.AccessStatus = ActuatorAccessRestricted
		res.AuthState = AuthStateAuthRequired
		res.Limitations = "endpoint returned HTTP 401 Unauthorized; authentication barrier active"
		return res

	case http.StatusForbidden:
		res.AccessStatus = ActuatorAccessRestricted
		res.AuthState = AuthStateForbidden
		res.Limitations = "endpoint returned HTTP 403 Forbidden; authorization barrier active"
		return res

	case http.StatusNotFound:
		res.AccessStatus = ActuatorAccessNotFound
		res.AuthState = AuthStateNotFound
		res.Limitations = "endpoint returned HTTP 404 Not Found"
		return res

	case http.StatusMovedPermanently, http.StatusFound, http.StatusSeeOther,
		http.StatusTemporaryRedirect, http.StatusPermanentRedirect:
		res.AccessStatus = ActuatorAccessRedirect
		res.AuthState = AuthStateRedirect
		loc := ""
		if probeResp.Header != nil {
			loc = probeResp.Header.Get("Location")
		}
		res.Limitations = fmt.Sprintf("endpoint redirected to %s; direct access not verified", loc)
		return res
	}

	// Spring Boot health may return HTTP 503 if components are DOWN
	isHealthPath := strings.HasSuffix(res.Path, "/health") || strings.Contains(res.Path, "/health/")
	if probeResp.StatusCode != http.StatusOK && !(isHealthPath && probeResp.StatusCode == http.StatusServiceUnavailable) {
		res.AccessStatus = ActuatorAccessInconclusive
		res.Limitations = fmt.Sprintf("unexpected HTTP status %d returned", probeResp.StatusCode)
		return res
	}

	// 2. Reject Generic HTML SPA Shells, Proxy Fallbacks, and Error Pages
	lowerBody := strings.ToLower(string(probeResp.Body))
	lowerCT := strings.ToLower(res.ContentType)
	if strings.Contains(lowerCT, "text/html") || strings.Contains(lowerBody, "<html") ||
		strings.Contains(lowerBody, "<!doctype") || strings.Contains(lowerBody, "<head") {
		res.AccessStatus = ActuatorAccessInconclusive
		res.Limitations = "endpoint returned HTML page/SPA shell rather than Actuator JSON"
		return res
	}

	// 3. Dispatch to Specific Actuator Interface Assessor
	switch {
	case strings.HasSuffix(res.Path, "/health") || strings.Contains(res.Path, "/health/"):
		assessHealthEndpoint(&res, probeResp.Body)

	case strings.HasSuffix(res.Path, "/env") || strings.Contains(res.Path, "/env/"):
		assessEnvEndpoint(&res, probeResp.Body)

	case strings.HasSuffix(res.Path, "/mappings") || strings.Contains(res.Path, "/mappings/"):
		assessMappingsEndpoint(&res, probeResp.Body)

	default:
		res.AccessStatus = ActuatorAccessInconclusive
		res.Limitations = "path does not correspond to an audited Phase 3.1 Actuator interface"
	}

	return res
}

// assessHealthEndpoint evaluates `/actuator/health` disclosure.
func assessHealthEndpoint(res *ActuatorProbeResult, body []byte) {
	var health springHealthResponse
	if err := json.Unmarshal(body, &health); err != nil {
		res.AccessStatus = ActuatorAccessInconclusive
		res.Limitations = "response body could not be parsed as valid JSON"
		return
	}

	// Verify genuine Spring Boot health structure
	status := strings.ToUpper(strings.TrimSpace(health.Status))
	if status == "" {
		res.AccessStatus = ActuatorAccessInconclusive
		res.Limitations = "response JSON does not declare a Spring Boot health status property"
		return
	}

	res.IsGenuine = true
	res.AccessStatus = ActuatorAccessPublic
	res.AuthState = AuthStatePublic

	// Check for detailed component or infrastructure telemetry (Spring Boot 2/3 `components`, or Spring Boot 1 `details`)
	var componentNames []string
	if len(health.Components) > 0 {
		for name := range health.Components {
			componentNames = append(componentNames, name)
		}
	} else if len(health.Details) > 0 {
		for name := range health.Details {
			componentNames = append(componentNames, name)
		}
	} else {
		// Check top-level Spring Boot 1.x keys (e.g. diskSpace, db, redis)
		var rawMap map[string]interface{}
		if err := json.Unmarshal(body, &rawMap); err == nil {
			for k := range rawMap {
				if k != "status" {
					componentNames = append(componentNames, k)
				}
			}
		}
	}

	sort.Strings(componentNames)
	res.ComponentCount = len(componentNames)

	if len(componentNames) > 0 {
		// Detailed component or infrastructure information disclosed
		displayComponents := componentNames
		if len(displayComponents) > 6 {
			displayComponents = append(displayComponents[:6], fmt.Sprintf("...+%d more", len(displayComponents)-6))
		}

		evidenceStr := fmt.Sprintf("HTTP %d. Spring Boot Actuator /health exposes detailed internal component telemetry. Status: %s. Components declared: [%s].",
			res.StatusCode, status, strings.Join(displayComponents, ", "))
		evidenceStr = secrets.RedactText(evidenceStr)

		res.Finding = &APIFinding{
			Category:       CategoryActuatorHealthDetailed,
			Endpoint:       res.URL,
			Method:         res.Method,
			Description:    "Spring Boot Actuator health endpoint exposes detailed component and infrastructure telemetry",
			Evidence:       evidenceStr,
			Severity:       SeverityLow,
			Confidence:     ConfidenceHigh,
			Fingerprint:    GenerateFingerprint(CategoryActuatorHealthDetailed, res.URL, res.Method),
			Classification: ClassHealth,
			AuthState:      AuthStatePublic,
			HTTPStatus:     res.StatusCode,
			Details: map[string]string{
				"framework":           "Spring Boot",
				"disclosure_category": "health_detailed",
				"health_status":       status,
				"component_count":     fmt.Sprintf("%d", len(componentNames)),
				"components":          strings.Join(displayComponents, ", "),
				"remediation":         "Set management.endpoint.health.show-details=never in application.properties to restrict component disclosures.",
			},
		}
	} else {
		// Minimal public health information (standard status UP/DOWN)
		evidenceStr := fmt.Sprintf("HTTP %d. Standard operational health status observed: %s (no internal component details exposed).",
			res.StatusCode, status)

		res.Finding = &APIFinding{
			Category:       CategoryHealthExposure,
			Endpoint:       res.URL,
			Method:         res.Method,
			Description:    "Public application health monitoring endpoint",
			Evidence:       evidenceStr,
			Severity:       SeverityInfo,
			Confidence:     ConfidenceHigh,
			Fingerprint:    GenerateFingerprint(CategoryHealthExposure, res.URL, res.Method),
			Classification: ClassHealth,
			AuthState:      AuthStatePublic,
			HTTPStatus:     res.StatusCode,
			Details: map[string]string{
				"framework":           "Spring Boot",
				"disclosure_category": "health_minimal",
				"health_status":       status,
				"remediation":         "Restrict access to internal monitoring endpoints if not intended for public load-balancer probes.",
			},
		}
	}
}

// assessEnvEndpoint evaluates `/actuator/env` disclosure safely.
func assessEnvEndpoint(res *ActuatorProbeResult, body []byte) {
	// Attempt Spring Boot 2.x/3.x structure unmarshal
	var envResp springEnvResponse
	err := json.Unmarshal(body, &envResp)

	var (
		sourceNames      []string
		propertyNames    []string
		sensitiveKeys    []string
		unmaskedSecret   bool
		totalProperties  int
		isConfirmedEnv   bool
	)

	sensitiveKeywords := []string{
		"password", "secret", "key", "token", "credential", "datasource",
		"api_key", "apikey", "private", "jwt", "auth", "admin", "access_key",
		"connection_string", "db_password",
	}

	if err == nil && len(envResp.PropertySources) > 0 {
		isConfirmedEnv = true
		for _, ps := range envResp.PropertySources {
			if ps.Name != "" {
				sourceNames = append(sourceNames, ps.Name)
			}
			for propKey, propVal := range ps.Properties {
				totalProperties++
				propertyNames = append(propertyNames, propKey)
				lowerKey := strings.ToLower(propKey)
				for _, kw := range sensitiveKeywords {
					if strings.Contains(lowerKey, kw) {
						sensitiveKeys = append(sensitiveKeys, propKey)
						break
					}
				}

				// Inspect value safely without retaining it
				valStr := extractPropertyValueString(propVal)
				if valStr != "" && valStr != "******" && valStr != "[PROTECTED]" && valStr != "[SECRET]" && !strings.HasPrefix(valStr, "***") {
					if isDefensibleSecretValue(propKey, valStr) {
						unmaskedSecret = true
					}
				}
			}
		}
	} else {
		// Attempt Spring Boot 1.x flat structure unmarshal
		var flatMap map[string]interface{}
		if errFlat := json.Unmarshal(body, &flatMap); errFlat == nil {
			// Spring Boot 1.x typically has "profiles" array and property keys like "server.port"
			_, hasProfiles := flatMap["profiles"]
			_, hasServerPort := flatMap["server.port"]
			if hasProfiles || hasServerPort || len(flatMap) > 5 {
				for k, v := range flatMap {
					if k == "profiles" || k == "activeProfiles" {
						continue
					}
					isConfirmedEnv = true
					totalProperties++
					propertyNames = append(propertyNames, k)
					lowerKey := strings.ToLower(k)
					for _, kw := range sensitiveKeywords {
						if strings.Contains(lowerKey, kw) {
							sensitiveKeys = append(sensitiveKeys, k)
							break
						}
					}
					valStr := fmt.Sprintf("%v", v)
					if valStr != "" && valStr != "******" && valStr != "[PROTECTED]" && !strings.HasPrefix(valStr, "***") {
						if isDefensibleSecretValue(k, valStr) {
							unmaskedSecret = true
						}
					}
				}
				sourceNames = append(sourceNames, "applicationConfiguration")
			}
		}
	}

	if !isConfirmedEnv || totalProperties == 0 {
		res.AccessStatus = ActuatorAccessInconclusive
		res.Limitations = "response JSON does not declare recognizable Spring Boot environment properties"
		return
	}

	res.IsGenuine = true
	res.AccessStatus = ActuatorAccessPublic
	res.AuthState = AuthStatePublic
	res.PropertyCount = totalProperties

	sort.Strings(sourceNames)
	sort.Strings(propertyNames)
	sort.Strings(sensitiveKeys)

	// Bounded sample formatting (never includes property values)
	displaySources := sourceNames
	if len(displaySources) > 4 {
		displaySources = append(displaySources[:4], fmt.Sprintf("...+%d more", len(displaySources)-4))
	}
	displayProps := propertyNames
	if len(displayProps) > 6 {
		displayProps = append(displayProps[:6], fmt.Sprintf("...+%d more", len(displayProps)-6))
	}

	severity := SeverityLow
	if unmaskedSecret {
		severity = SeverityCritical
	} else if len(sensitiveKeys) > 0 {
		severity = SeverityMedium
	}

	evidenceStr := fmt.Sprintf("HTTP %d OK. Spring Boot Actuator /env disclosed %d environment properties across sources [%s]. Discovered properties: [%s]. Secret values redacted.",
		res.StatusCode, totalProperties, strings.Join(displaySources, ", "), strings.Join(displayProps, ", "))
	evidenceStr = secrets.RedactText(evidenceStr)

	res.Finding = &APIFinding{
		Category:       CategoryActuatorEnv,
		Endpoint:       res.URL,
		Method:         res.Method,
		Description:    "Spring Boot Actuator environment endpoint exposes application configuration properties",
		Evidence:       evidenceStr,
		Severity:       severity,
		Confidence:     ConfidenceHigh,
		Fingerprint:    GenerateFingerprint(CategoryActuatorEnv, res.URL, res.Method),
		Classification: ClassAdmin,
		AuthState:      AuthStatePublic,
		HTTPStatus:     res.StatusCode,
		Details: map[string]string{
			"framework":           "Spring Boot",
			"disclosure_category": "environment_properties",
			"property_count":      fmt.Sprintf("%d", totalProperties),
			"property_sources":    strings.Join(displaySources, ", "),
			"sensitive_keys":      fmt.Sprintf("%d", len(sensitiveKeys)),
			"unmasked_secrets":    fmt.Sprintf("%t", unmaskedSecret),
			"remediation":         "Disable /actuator/env in production (management.endpoints.web.exposure.exclude=env) or require strict administrative authentication.",
		},
	}
}

// extractPropertyValueString safely extracts the string representation of a property value object.
func extractPropertyValueString(val interface{}) string {
	if val == nil {
		return ""
	}
	if str, ok := val.(string); ok {
		return str
	}
	if m, ok := val.(map[string]interface{}); ok {
		if v, exists := m["value"]; exists && v != nil {
			return fmt.Sprintf("%v", v)
		}
	}
	return fmt.Sprintf("%v", val)
}

// assessMappingsEndpoint evaluates `/actuator/mappings` disclosure.
func assessMappingsEndpoint(res *ActuatorProbeResult, body []byte) {
	var mapResp springMappingsResponse
	err := json.Unmarshal(body, &mapResp)

	var (
		discoveredRoutes []string
		sensitiveRoutes  []string
		handlerCount     int
		isConfirmedMap   bool
	)

	sensitiveKeywords := []string{
		"admin", "internal", "management", "actuator", "debug", "upload",
		"backup", "secret", "system", "swagger", "console", "h2-console",
	}

	if err == nil && len(mapResp.Contexts) > 0 {
		for _, ctx := range mapResp.Contexts {
			for _, mappings := range ctx.Mappings.DispatcherServlets {
				for _, m := range mappings {
					handlerCount++
					patterns := extractMappingPatterns(m.Predicate, m.Details)
					for _, pat := range patterns {
						cleanPat := strings.TrimSpace(pat)
						if cleanPat == "" {
							continue
						}
						isConfirmedMap = true
						discoveredRoutes = append(discoveredRoutes, cleanPat)
						lowerPat := strings.ToLower(cleanPat)
						for _, kw := range sensitiveKeywords {
							if strings.Contains(lowerPat, kw) {
								sensitiveRoutes = append(sensitiveRoutes, cleanPat)
								break
							}
						}
					}
				}
			}
		}
	} else {
		// Attempt Spring Boot 1.x flat mappings unmarshal
		var flatMap map[string]interface{}
		if errFlat := json.Unmarshal(body, &flatMap); errFlat == nil {
			for k := range flatMap {
				// Spring Boot 1.x mapping keys formatted as "{[/path],methods=[GET]}"
				if strings.Contains(k, "{[") && strings.Contains(k, "]") {
					isConfirmedMap = true
					handlerCount++
					pat := extractSpring1Pattern(k)
					if pat != "" {
						discoveredRoutes = append(discoveredRoutes, pat)
						lowerPat := strings.ToLower(pat)
						for _, kw := range sensitiveKeywords {
							if strings.Contains(lowerPat, kw) {
								sensitiveRoutes = append(sensitiveRoutes, pat)
								break
							}
						}
					}
				}
			}
		}
	}

	if !isConfirmedMap || len(discoveredRoutes) == 0 {
		res.AccessStatus = ActuatorAccessInconclusive
		res.Limitations = "response JSON does not declare recognizable Spring Boot request mapping definitions"
		return
	}

	res.IsGenuine = true
	res.AccessStatus = ActuatorAccessPublic
	res.AuthState = AuthStatePublic
	res.RouteCount = len(discoveredRoutes)

	// Deduplicate routes
	uniqueRoutes := deduplicateStrings(discoveredRoutes)
	sort.Strings(uniqueRoutes)

	displayRoutes := uniqueRoutes
	if len(displayRoutes) > 6 {
		displayRoutes = append(displayRoutes[:6], fmt.Sprintf("...+%d more", len(displayRoutes)-6))
	}

	severity := SeverityLow
	if len(sensitiveRoutes) > 0 {
		severity = SeverityMedium
	}

	evidenceStr := fmt.Sprintf("HTTP %d OK. Spring Boot Actuator /mappings disclosed %d application routes (%d handlers). Discovered routes: [%s].",
		res.StatusCode, len(uniqueRoutes), handlerCount, strings.Join(displayRoutes, ", "))
	evidenceStr = secrets.RedactText(evidenceStr)

	res.Finding = &APIFinding{
		Category:       CategoryActuatorMappings,
		Endpoint:       res.URL,
		Method:         res.Method,
		Description:    "Spring Boot Actuator mappings endpoint exposes internal application route definitions",
		Evidence:       evidenceStr,
		Severity:       severity,
		Confidence:     ConfidenceHigh,
		Fingerprint:    GenerateFingerprint(CategoryActuatorMappings, res.URL, res.Method),
		Classification: ClassAPI,
		AuthState:      AuthStatePublic,
		HTTPStatus:     res.StatusCode,
		Details: map[string]string{
			"framework":           "Spring Boot",
			"disclosure_category": "route_mappings",
			"route_count":         fmt.Sprintf("%d", len(uniqueRoutes)),
			"handler_count":       fmt.Sprintf("%d", handlerCount),
			"sensitive_routes":    fmt.Sprintf("%d", len(sensitiveRoutes)),
			"sample_routes":       strings.Join(displayRoutes, ", "),
			"remediation":         "Disable /actuator/mappings in production (management.endpoints.web.exposure.exclude=mappings) or place behind administrative authentication.",
		},
	}
}

// extractMappingPatterns parses pattern strings from Spring Boot 2/3 predicate and details objects.
func extractMappingPatterns(predicate string, details interface{}) []string {
	var patterns []string
	if d, ok := details.(*struct {
		RequestMappingConditions *struct {
			Patterns []string `json:"patterns"`
			Methods  []string `json:"methods"`
		} `json:"requestMappingConditions"`
	}); ok && d != nil && d.RequestMappingConditions != nil {
		patterns = append(patterns, d.RequestMappingConditions.Patterns...)
	}

	if len(patterns) == 0 && predicate != "" {
		pat := extractSpring1Pattern(predicate)
		if pat != "" {
			patterns = append(patterns, pat)
		}
	}
	return patterns
}

// extractSpring1Pattern parses `{[/path],methods=[GET]}` pattern strings.
func extractSpring1Pattern(predicate string) string {
	start := strings.Index(predicate, "{[")
	if start == -1 {
		return ""
	}
	end := strings.Index(predicate[start:], "]")
	if end == -1 {
		return ""
	}
	return predicate[start+2 : start+end]
}

func deduplicateStrings(input []string) []string {
	seen := make(map[string]struct{})
	var result []string
	for _, s := range input {
		clean := strings.TrimSpace(s)
		if clean == "" {
			continue
		}
		if _, exists := seen[clean]; !exists {
			seen[clean] = struct{}{}
			result = append(result, clean)
		}
	}
	return result
}

// isDefensibleSecretValue checks if an unmasked property value represents genuine credential evidence.
func isDefensibleSecretValue(key, val string) bool {
	cleanVal := strings.TrimSpace(val)
	if cleanVal == "" || len(cleanVal) < 6 {
		return false
	}
	lowerVal := strings.ToLower(cleanVal)
	// Suppress common non-secret configuration constants and identifiers
	if lowerVal == "true" || lowerVal == "false" || lowerVal == "none" ||
		lowerVal == "null" || lowerVal == "nil" || lowerVal == "default" ||
		lowerVal == "disabled" || lowerVal == "enabled" || lowerVal == "memory" ||
		lowerVal == "jdbc" || lowerVal == "redis" || lowerVal == "hazelcast" {
		return false
	}
	if strings.HasPrefix(lowerVal, "http://") || strings.HasPrefix(lowerVal, "https://") {
		// URLs are not secrets unless they contain user:pass credentials
		return strings.Contains(cleanVal, "@")
	}
	if secrets.IsPlaceholder(cleanVal) {
		return false
	}
	// If the key is an explicit credential field (password, secret, token, apikey, private_key)
	lowerKey := strings.ToLower(key)
	if strings.Contains(lowerKey, "password") || strings.Contains(lowerKey, "secret") ||
		strings.Contains(lowerKey, "token") || strings.Contains(lowerKey, "apikey") ||
		strings.Contains(lowerKey, "private") {
		return len(cleanVal) >= 6
	}
	// For other keys, require high Shannon entropy and minimum length 16
	return len(cleanVal) >= 16 && secrets.ShannonEntropy(cleanVal) >= 3.5
}
