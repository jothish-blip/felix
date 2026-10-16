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
	// MaxFastAPIResponseSize enforces a strict 512 KiB wire-read limit for OpenAPI schema inspection.
	MaxFastAPIResponseSize = 512 * 1024
)

// DefaultFastAPICandidatePaths lists standard candidate documentation and schema paths for FastAPI / OpenAPI.
var DefaultFastAPICandidatePaths = []string{
	"/openapi.json",
	"/docs",
	"/redoc",
}

// AuditFastAPIDocs coordinates safe, bounded assessment of FastAPI/OpenAPI documentation and schema interfaces.
func AuditFastAPIDocs(ctx context.Context, client *Client, targetBaseURL string, candidatePaths []string) []APIFinding {
	var findings []APIFinding
	resolvedCandidates := ResolveFastAPICandidateURLs(targetBaseURL, candidatePaths)

	for _, targetURL := range resolvedCandidates {
		// Enforce client scope and exclusion rules before dispatching
		if client.isExcluded != nil && client.isExcluded(targetURL) {
			continue
		}
		if client.isAllowed != nil && !client.isAllowed(targetURL) {
			continue
		}

		endpointFindings := ProbeFastAPIEndpoint(ctx, client, targetURL)
		findings = append(findings, endpointFindings...)
	}

	return findings
}

// ResolveFastAPICandidateURLs resolves candidate FastAPI documentation URLs for a target base URL,
// supporting nested application paths, root origin endpoints, and crawled asset hints.
func ResolveFastAPICandidateURLs(targetBaseURL string, customCandidates []string) []string {
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

	// 1. Base URL candidates (handles nested base paths like /api/v1/openapi.json and root targets)
	for _, p := range DefaultFastAPICandidatePaths {
		addURL(baseURL + p)
	}

	// 2. Custom or discovered candidate paths from crawled assets
	for _, cp := range customCandidates {
		clean := strings.TrimSpace(cp)
		if clean == "" {
			continue
		}
		lower := strings.ToLower(clean)
		if strings.Contains(lower, "openapi") || strings.Contains(lower, "swagger") ||
			strings.Contains(lower, "docs") || strings.Contains(lower, "redoc") {
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

// ProbeFastAPIEndpoint probes a candidate URL and evaluates OpenAPI schema or interactive documentation.
func ProbeFastAPIEndpoint(ctx context.Context, client *Client, targetURL string) []APIFinding {
	var findings []APIFinding

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, targetURL, nil)
	if err != nil {
		return nil
	}
	req.Header.Set("Accept", "application/json,text/html,application/xhtml+xml,*/*;q=0.8")

	resp, err := client.DoBounded(ctx, req, MaxFastAPIResponseSize)
	if err != nil {
		return nil
	}

	// Check for proper status: non-200 responses (404, 401, 403, 500) do not expose public docs
	if resp.StatusCode != http.StatusOK {
		return nil
	}

	lowerURL := strings.ToLower(targetURL)

	// 1. Inspect for OpenAPI JSON Schema (/openapi.json, /swagger.json, or JSON endpoints)
	if strings.HasSuffix(lowerURL, ".json") || strings.Contains(lowerURL, "openapi") || strings.Contains(lowerURL, "swagger") {
		schemaFindings := InspectOpenAPISchema(resp, targetURL)
		if len(schemaFindings) > 0 {
			findings = append(findings, schemaFindings...)
			return findings
		}
	}

	// 2. Inspect for interactive documentation (/docs or /redoc)
	relPath := "/docs"
	if strings.Contains(lowerURL, "redoc") {
		relPath = "/redoc"
	}
	if f := InspectFastAPIInteractiveDocs(resp, targetURL, relPath); f != nil {
		findings = append(findings, *f)
		return findings
	}

	return findings
}

// InspectOpenAPISchema evaluates a response for genuine OpenAPI specification structure,
// internal route disclosure, and embedded credentials or secret defaults.
func InspectOpenAPISchema(resp *ProbeResponse, endpointURL string) []APIFinding {
	if resp == nil || resp.StatusCode != http.StatusOK || len(resp.Body) == 0 {
		return nil
	}

	bodyStr := string(resp.Body)
	lowerBody := strings.ToLower(bodyStr)

	// Differentiate SPA HTML shells returning HTTP 200 OK for missing JSON routes
	if strings.Contains(lowerBody, "<html") ||
		strings.Contains(lowerBody, "<!doctype") ||
		strings.Contains(lowerBody, `<div id="root"`) ||
		strings.Contains(lowerBody, `<div id="app"`) {
		return nil
	}

	// Unmarshal into generic JSON map
	var schema map[string]interface{}
	if err := json.Unmarshal(resp.Body, &schema); err != nil {
		return nil
	}

	// Validate OpenAPI / Swagger root fields
	openAPIVer := ""
	if v, ok := schema["openapi"].(string); ok {
		openAPIVer = v
	} else if v, ok := schema["swagger"].(string); ok {
		openAPIVer = v
	}
	if openAPIVer == "" {
		return nil // Not an OpenAPI or Swagger schema
	}

	pathsMap, ok := schema["paths"].(map[string]interface{})
	if !ok {
		return nil // Missing "paths" object
	}

	// Extract title and description
	infoTitle := "API"
	if info, ok := schema["info"].(map[string]interface{}); ok {
		if t, ok := info["title"].(string); ok && strings.TrimSpace(t) != "" {
			infoTitle = strings.TrimSpace(t)
		}
	}

	// 1. Analyze routes for sensitive internal or administrative endpoints
	var allRoutes []string
	var sensitiveRoutes []string
	for routePath := range pathsMap {
		cleanRoute := strings.TrimSpace(routePath)
		allRoutes = append(allRoutes, cleanRoute)
		if isSensitiveInternalRoute(cleanRoute) {
			sensitiveRoutes = append(sensitiveRoutes, cleanRoute)
		}
	}
	sort.Strings(allRoutes)
	sort.Strings(sensitiveRoutes)

	// 2. Inspect schema for embedded credentials or secret defaults
	hasSecret, secretKey, _ := findEmbeddedSecretInSchema(schema)

	var findings []APIFinding

	// Finding Case A: Embedded Credentials / Secrets in Schema (Demonstrated Information Disclosure)
	if hasSecret {
		ev := fmt.Sprintf("HTTP 200 OK. FastAPI OpenAPI schema contains unmasked credential for field %q (secret value redacted). Note: Credential validity and active authorization status were not verified.",
			secretKey)
		negEv := "Credential observed in schema definition; active authentication or authorization against backend services was not attempted."
		details := map[string]string{
			"framework":                "FastAPI",
			"openapi_ver":              openAPIVer,
			"api_title":                infoTitle,
			"secret_field":             secretKey,
			"credential_active_status": "unverified",
			"total_routes":             fmt.Sprintf("%d", len(allRoutes)),
			"http_status":              "200",
		}
		if resp.Truncated {
			details["limitations"] = "Schema response exceeded 512 KiB and was bounded to prevent memory exhaustion"
		}

		findings = append(findings, APIFinding{
			Category:         CategoryFastAPISensitiveSchema,
			Endpoint:         endpointURL,
			Method:           http.MethodGet,
			Description:      "FastAPI OpenAPI schema contains embedded credentials or sensitive defaults",
			Evidence:         secrets.RedactText(ev),
			NegativeEvidence: negEv,
			Severity:         SeverityHigh,
			Confidence:       ConfidenceMedium,
			Fingerprint:      GenerateFingerprint(CategoryFastAPISensitiveSchema, endpointURL, http.MethodGet),
			Classification:   ClassDocumentation,
			Details:          details,
			HTTPStatus:       http.StatusOK,
		})
	}

	// Finding Case B: Sensitive / Administrative Route Definitions in Schema (Route Visibility Observation)
	// Route-name visibility alone does not prove unauthorized access, bypass, or vulnerability; classified as INFO.
	if len(sensitiveRoutes) > 0 {
		sample := sensitiveRoutes
		if len(sample) > 4 {
			sample = sample[:4]
		}
		ev := fmt.Sprintf("HTTP 200 OK. FastAPI OpenAPI schema includes %d route definition(s) matching administrative/internal naming conventions: [%s]. Route definitions cataloged from schema; endpoint reachability, authorization enforcement, and access controls were not evaluated (no recursive probing).",
			len(sensitiveRoutes), strings.Join(sample, ", "))
		negEv := "Route existence in schema does not demonstrate unauthorized access, authorization bypass, or reachability."
		details := map[string]string{
			"framework":              "FastAPI",
			"openapi_ver":            openAPIVer,
			"api_title":              infoTitle,
			"sensitive_route_count":  fmt.Sprintf("%d", len(sensitiveRoutes)),
			"sample_sensitive_route": sensitiveRoutes[0],
			"total_routes":           fmt.Sprintf("%d", len(allRoutes)),
			"http_status":            "200",
			"route_visibility_only":  "true",
			"authorization_status":   "unverified",
		}
		if resp.Truncated {
			details["limitations"] = "Schema response exceeded 512 KiB and was bounded to prevent memory exhaustion"
		}

		findings = append(findings, APIFinding{
			Category:         CategoryFastAPISensitivePaths,
			Endpoint:         endpointURL,
			Method:           http.MethodGet,
			Description:      "FastAPI OpenAPI schema contains internal or administrative route definitions (route visibility observation)",
			Evidence:         secrets.RedactText(ev),
			NegativeEvidence: negEv,
			Severity:         SeverityInfo,
			Confidence:       ConfidenceLow,
			Fingerprint:      GenerateFingerprint(CategoryFastAPISensitivePaths, endpointURL, http.MethodGet),
			Classification:   ClassDocumentation,
			Details:          details,
			HTTPStatus:       http.StatusOK,
		})
	}

	// Finding Case C: Standard Public OpenAPI Schema (SeverityInfo - NOT a vulnerability!)
	// When documentation is intentionally public and contains no internal routes or credentials.
	if !hasSecret && len(sensitiveRoutes) == 0 {
		ev := fmt.Sprintf("HTTP 200 OK. Genuine OpenAPI %s specification observed (%d endpoints, title: %q). Public API documentation; no administrative routes or credentials exposed.",
			openAPIVer, len(allRoutes), infoTitle)
		details := map[string]string{
			"framework":    "FastAPI",
			"openapi_ver":  openAPIVer,
			"api_title":    infoTitle,
			"total_routes": fmt.Sprintf("%d", len(allRoutes)),
			"http_status":  "200",
		}
		if resp.Truncated {
			details["limitations"] = "Schema response exceeded 512 KiB and was bounded to prevent memory exhaustion"
		}

		findings = append(findings, APIFinding{
			Category:       CategoryFastAPIDocs,
			Endpoint:       endpointURL,
			Method:         http.MethodGet,
			Description:    "Publicly accessible FastAPI / OpenAPI documentation schema",
			Evidence:       secrets.RedactText(ev),
			Severity:       SeverityInfo,
			Confidence:     ConfidenceHigh,
			Fingerprint:    GenerateFingerprint(CategoryFastAPIDocs, endpointURL, http.MethodGet),
			Classification: ClassDocumentation,
			Details:        details,
			HTTPStatus:     http.StatusOK,
		})
	}

	return findings
}

// InspectFastAPIInteractiveDocs detects FastAPI interactive Swagger UI or ReDoc interfaces.
// Distinguishes genuine documentation pages from generic SPA shells.
func InspectFastAPIInteractiveDocs(resp *ProbeResponse, endpointURL, relPath string) *APIFinding {
	if resp == nil || resp.StatusCode != http.StatusOK || len(resp.Body) == 0 {
		return nil
	}

	contentType := strings.ToLower(resp.Header.Get("Content-Type"))
	bodyStr := string(resp.Body)
	lowerBody := strings.ToLower(bodyStr)

	// Must be an HTML response
	if !strings.Contains(contentType, "text/html") &&
		!strings.Contains(lowerBody, "<!doctype html") &&
		!strings.Contains(lowerBody, "<html") {
		return nil
	}

	isSwaggerUI := strings.Contains(lowerBody, "swagger-ui") || strings.Contains(bodyStr, "SwaggerUIBundle")
	isReDoc := strings.Contains(lowerBody, "<redoc") || strings.Contains(lowerBody, "redoc.standalone.js")
	referencesOpenAPI := strings.Contains(lowerBody, "openapi.json") || strings.Contains(lowerBody, "swagger.json")

	// Must have genuine documentation library markers and schema reference
	if (!isSwaggerUI && !isReDoc) || !referencesOpenAPI {
		return nil
	}

	docType := "Swagger UI"
	if isReDoc {
		docType = "ReDoc"
	}

	evidence := fmt.Sprintf("HTTP 200 OK. FastAPI interactive %s documentation interface active at %s.",
		docType, endpointURL)

	details := map[string]string{
		"framework":    "FastAPI",
		"interface":    docType,
		"content_type": resp.Header.Get("Content-Type"),
		"http_status":  "200",
	}

	// Public documentation is an informational observation, NOT a vulnerability
	return &APIFinding{
		Category:       CategoryFastAPIDocs,
		Endpoint:       endpointURL,
		Method:         http.MethodGet,
		Description:    fmt.Sprintf("Publicly accessible FastAPI interactive documentation (%s)", relPath),
		Evidence:       secrets.RedactText(evidence),
		Severity:       SeverityInfo,
		Confidence:     ConfidenceHigh,
		Fingerprint:    GenerateFingerprint(CategoryFastAPIDocs, endpointURL, http.MethodGet),
		Classification: ClassDocumentation,
		Details:        details,
		HTTPStatus:     http.StatusOK,
	}
}

// isSensitiveInternalRoute evaluates whether a schema path represents an administrative or internal route.
func isSensitiveInternalRoute(routePath string) bool {
	clean := strings.ToLower(strings.TrimSpace(routePath))
	if clean == "" || clean == "/" {
		return false
	}

	// Internal and administrative prefixes
	internalPrefixes := []string{
		"/admin",
		"/internal",
		"/management",
		"/debug",
		"/_debug",
		"/actuator",
		"/system",
		"/private",
		"/server-status",
		"/control",
	}

	for _, pfx := range internalPrefixes {
		if clean == pfx || strings.HasPrefix(clean, pfx+"/") {
			return true
		}
	}

	// Specific operational endpoints
	if clean == "/env" || clean == "/metrics" || strings.HasPrefix(clean, "/config") {
		return true
	}

	return false
}

var descriptionSecretRegex = regexp.MustCompile(`(?i)(?:api[_-]?key|password|webhook[_-]?secret|secret(?:[_-]?token)?|bearer(?:[_-]?token)?|access[_-]?token|auth[_-]?token)\s*[:=]\s*["']?([a-zA-Z0-9_\-\.]{8,})`)

var commonSchemaPlaceholders = map[string]struct{}{
	"string":         {},
	"str":            {},
	"text":           {},
	"password":       {},
	"passwd":         {},
	"pass":           {},
	"secret":         {},
	"token":          {},
	"api_key":        {},
	"apikey":         {},
	"key":            {},
	"admin":          {},
	"user":           {},
	"test":           {},
	"demo":           {},
	"sample":         {},
	"example":        {},
	"placeholder":    {},
	"dummy":          {},
	"your_api_key":   {},
	"your-api-key":   {},
	"yourapikey":     {},
	"your_secret":    {},
	"your-secret":    {},
	"yoursecret":     {},
	"your_token":     {},
	"your-token":     {},
	"yourtoken":      {},
	"null":           {},
	"nil":            {},
	"none":           {},
	"undefined":      {},
	"true":           {},
	"false":          {},
	"0":              {},
	"1":              {},
	"123":            {},
	"12345":          {},
	"123456":         {},
	"test123":        {},
	"admin123":       {},
	"bearer <token>": {},
	"bearer token":   {},
	"bearer":         {},
	"token_here":     {},
	"enter_token":    {},
	"insert_key":     {},
	"changeme":       {},
	"change_me":      {},
	"replace_me":     {},
	"todo":           {},
	"fixme":          {},
	"mysecret":       {},
	"mypassword":     {},
}

func isSchemaPlaceholder(val string) bool {
	clean := strings.TrimSpace(val)
	if clean == "" {
		return true
	}
	lower := strings.ToLower(clean)
	if _, ok := commonSchemaPlaceholders[lower]; ok {
		return true
	}
	if secrets.IsPlaceholder(clean) {
		return true
	}
	// Masked values (e.g. '******', '********', '[FILTERED]', '[REDACTED]')
	if strings.Count(clean, "*") >= 3 || strings.Contains(lower, "filter") || strings.Contains(lower, "redact") {
		return true
	}
	// Trivial repeating characters like 'xxxxxx', 'aaaaaa'
	if len(clean) > 1 {
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

func isDefensibleSchemaSecret(key, val string) bool {
	if isSchemaPlaceholder(val) {
		return false
	}
	cleanVal := strings.TrimSpace(val)
	if len(cleanVal) < 8 {
		return false
	}
	lowerVal := strings.ToLower(cleanVal)
	if strings.HasPrefix(lowerVal, "http://") || strings.HasPrefix(lowerVal, "https://") {
		return strings.Contains(cleanVal, "@")
	}
	lowerKey := strings.ToLower(key)
	if strings.Contains(lowerKey, "password") || strings.Contains(lowerKey, "secret") ||
		strings.Contains(lowerKey, "token") || strings.Contains(lowerKey, "apikey") ||
		strings.Contains(lowerKey, "private") {
		return len(cleanVal) >= 8
	}
	return len(cleanVal) >= 16 && secrets.ShannonEntropy(cleanVal) >= 3.5
}

// findEmbeddedSecretInSchema traverses OpenAPI schema objects looking for unmasked default/example secrets.
func findEmbeddedSecretInSchema(root map[string]interface{}) (bool, string, string) {
	var walk func(node interface{}, currentKey string) (bool, string, string)
	walk = func(node interface{}, currentKey string) (bool, string, string) {
		switch v := node.(type) {
		case map[string]interface{}:
			effectiveKey := currentKey
			if nameStr, ok := v["name"].(string); ok && secrets.IsSensitiveKey(nameStr) {
				effectiveKey = nameStr
			}

			// Check if this map directly defines default, example, or value on a sensitive key
			if secrets.IsSensitiveKey(effectiveKey) {
				for _, secretProp := range []string{"default", "example", "value"} {
					if val, ok := v[secretProp]; ok {
						if strVal, ok := val.(string); ok {
							if isDefensibleSchemaSecret(effectiveKey, strVal) {
								return true, effectiveKey, strVal
							}
						}
					}
				}
			}

			for k, val := range v {
				lowerK := strings.ToLower(k)

				// Check descriptions or summaries for embedded credential patterns
				if lowerK == "description" || lowerK == "summary" {
					if descStr, ok := val.(string); ok {
						if m := descriptionSecretRegex.FindStringSubmatch(descStr); len(m) > 1 {
							cand := m[1]
							if isDefensibleSchemaSecret("description_secret", cand) {
								return true, "description_credential", cand
							}
						}
					}
				}

				subKey := k
				if effectiveKey != "" && (lowerK == "schema" || lowerK == "items" || lowerK == "default" || lowerK == "example") {
					subKey = effectiveKey
				}

				if found, sk, sv := walk(val, subKey); found {
					return true, sk, sv
				}
			}
		case []interface{}:
			for _, item := range v {
				if found, sk, sv := walk(item, currentKey); found {
					return true, sk, sv
				}
			}
		}
		return false, "", ""
	}

	return walk(root, "")
}
