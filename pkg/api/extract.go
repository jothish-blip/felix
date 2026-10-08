package api

import (
	"fmt"
	"net/url"
	"regexp"
	"strings"
)

// DiscoveredEndpoint encapsulates static metadata for an extracted endpoint.
type DiscoveredEndpoint struct {
	Path               string                 `json:"path"`
	RawPath            string                 `json:"raw_path"`
	Method             string                 `json:"method"`
	SourceAsset        string                 `json:"source_asset"`
	LineNumber         int                    `json:"line_number,omitempty"`
	Mechanism          string                 `json:"mechanism"`
	StaticallyResolved bool                   `json:"statically_resolved"`
	Classification     EndpointClassification `json:"classification"`
	AuthState          AuthState              `json:"auth_state,omitempty"`
	HTTPStatus         int                    `json:"http_status,omitempty"`
}

// Regex matchers for JavaScript AST/lexical patterns
var (
	// axios.<method>(url, ...)
	axiosMethodRegex = regexp.MustCompile(`(?i)\baxios\.(get|post|put|delete|patch|options|head)\s*\(\s*["'` + "`" + `]([^"'` + "`" + `\s]+)["'` + "`" + `]`)

	// axios({ url: "...", method: "..." }) or axios.request({ ... })
	axiosReqURLFirstRegex = regexp.MustCompile(`(?i)\baxios(?:\.request)?\s*\(\s*\{[^}]*?\burl\s*:\s*["'` + "`" + `]([^"'` + "`" + `\s]+)["'` + "`" + `](?:[^}]*?\bmethod\s*:\s*["']([A-Za-z]+)["'])?`)
	axiosReqMethodFirstRegex = regexp.MustCompile(`(?i)\baxios(?:\.request)?\s*\(\s*\{[^}]*?\bmethod\s*:\s*["']([A-Za-z]+)["'][^}]*?\burl\s*:\s*["'` + "`" + `]([^"'` + "`" + `\s]+)["'` + "`" + `]`)

	// fetch(url, { method: "..." })
	fetchRegex = regexp.MustCompile(`(?i)\bfetch\s*\(\s*["'` + "`" + `]([^"'` + "`" + `\s]+)["'` + "`" + `](?:\s*,\s*\{[^}]*?\bmethod\s*:\s*["']([A-Za-z]+)["'])?`)

	// Variable assignment for base URLs: const API_BASE = "/api" or "https://target.corp/api"
	constBaseRegex = regexp.MustCompile(`(?i)\b(?:const|let|var)\s+([A-Za-z0-9_$]+)\s*=\s*["']([^"'\s]+)["']`)

	// Concatenation usage: fetch(API_BASE + "/users") or axios.get(BASE + "/users")
	concatCallRegex = regexp.MustCompile(`(?i)\b(?:fetch|axios(?:\.[A-Za-z]+)?)\s*\(\s*([A-Za-z0-9_$]+)\s*\+\s*["'](/[^"'\s]+)["']`)

	// Template literal usage: `/api/users/${id}` or fetch(`${API_BASE}/users`)
	templateLiteralRegex = regexp.MustCompile("`(/[^`\\s]+)`")

	// Direct string literal API paths
	directPathRegex = regexp.MustCompile(`["'](/(?:api|v[0-9]+|graphql)(?:/[a-zA-Z0-9_\-\./{}:]*)?)["']`)

	// Dynamic segment patterns
	dynamicTemplateParamRegex = regexp.MustCompile(`\$\{[^}]+\}`)
	dynamicColonParamRegex    = regexp.MustCompile(`/:[a-zA-Z0-9_]+`)
	dynamicBracketParamRegex  = regexp.MustCompile(`/\[[a-zA-Z0-9_]+\]`)
)

// NormalizeEndpointPath standardizes route syntax, collapses dynamic parameters, and trims trailing slashes.
func NormalizeEndpointPath(rawPath string) (string, bool) {
	clean := strings.TrimSpace(rawPath)
	if clean == "" {
		return "", false
	}

	// Remove query parameters or fragments if present in static literals
	if idx := strings.IndexAny(clean, "?#"); idx != -1 {
		clean = clean[:idx]
	}

	staticallyResolved := true

	// Normalize dynamic segments: ${id} -> {param}, :id -> {param}, [id] -> {param}
	if dynamicTemplateParamRegex.MatchString(clean) {
		clean = dynamicTemplateParamRegex.ReplaceAllString(clean, "{param}")
		staticallyResolved = false
	}
	if dynamicColonParamRegex.MatchString(clean) {
		clean = dynamicColonParamRegex.ReplaceAllString(clean, "/{param}")
		staticallyResolved = false
	}
	if dynamicBracketParamRegex.MatchString(clean) {
		clean = dynamicBracketParamRegex.ReplaceAllString(clean, "/{param}")
		staticallyResolved = false
	}

	// Collapse duplicate slashes: //api//users -> /api/users
	for strings.Contains(clean, "//") {
		clean = strings.ReplaceAll(clean, "//", "/")
	}

	// Canonicalize trailing slash for non-root paths: /api/users/ -> /api/users
	if len(clean) > 1 && strings.HasSuffix(clean, "/") {
		clean = strings.TrimSuffix(clean, "/")
	}

	return clean, staticallyResolved
}

// computeLineNumber calculates the 1-based line number for a byte offset in content.
func computeLineNumber(content []byte, offset int) int {
	if offset < 0 || offset > len(content) {
		return 1
	}
	line := 1
	for i := 0; i < offset; i++ {
		if content[i] == '\n' {
			line++
		}
	}
	return line
}

// ExtractEndpointsFromJS scans a JavaScript asset for static API calls, methods, and route patterns.
func ExtractEndpointsFromJS(sourceAssetURL string, content []byte, targetURL string) []DiscoveredEndpoint {
	var endpoints []DiscoveredEndpoint
	if len(content) == 0 {
		return endpoints
	}

	targetHost := ""
	if parsed, err := url.Parse(targetURL); err == nil {
		targetHost = strings.ToLower(parsed.Hostname())
	}

	text := string(content)
	seen := make(map[string]int) // path -> index in endpoints

	addEndpoint := func(rawPath string, method string, mechanism string, byteOffset int) {
		rawPath = strings.TrimSpace(rawPath)
		if rawPath == "" {
			return
		}

		// Handle absolute URLs: accept only if origin matches targetHost
		if strings.HasPrefix(rawPath, "http://") || strings.HasPrefix(rawPath, "https://") {
			parsedURL, err := url.Parse(rawPath)
			if err != nil {
				return
			}
			if targetHost != "" && !strings.EqualFold(parsedURL.Hostname(), targetHost) {
				// Third-party / out-of-scope origin -> ignore
				return
			}
			rawPath = parsedURL.Path
		}

		// Must begin with slash
		if !strings.HasPrefix(rawPath, "/") {
			return
		}

		// Skip common static false-positive strings
		if strings.HasPrefix(rawPath, "/*") || strings.HasPrefix(rawPath, "//") {
			return
		}
		if len(rawPath) > 120 {
			return
		}

		normPath, staticallyResolved := NormalizeEndpointPath(rawPath)
		if normPath == "" || normPath == "/" {
			return
		}

		cleanMethod := strings.ToUpper(strings.TrimSpace(method))
		if cleanMethod == "" {
			cleanMethod = "UNKNOWN"
		}

		line := computeLineNumber(content, byteOffset)
		classification := ClassifyEndpoint(normPath)

		if idx, exists := seen[normPath]; exists {
			// Update existing record if new match provides higher specificity (e.g. specific HTTP method)
			if endpoints[idx].Method == "UNKNOWN" && cleanMethod != "UNKNOWN" {
				endpoints[idx].Method = cleanMethod
				endpoints[idx].Mechanism = mechanism
				endpoints[idx].LineNumber = line
			}
			return
		}

		seen[normPath] = len(endpoints)
		endpoints = append(endpoints, DiscoveredEndpoint{
			Path:               normPath,
			RawPath:            rawPath,
			Method:             cleanMethod,
			SourceAsset:        sourceAssetURL,
			LineNumber:         line,
			Mechanism:          mechanism,
			StaticallyResolved: staticallyResolved,
			Classification:     classification,
			AuthState:          AuthStateUnknown,
		})
	}

	// 1. axios.<method>(url)
	for _, match := range axiosMethodRegex.FindAllStringSubmatchIndex(text, -1) {
		method := text[match[2]:match[3]]
		rawURL := text[match[4]:match[5]]
		addEndpoint(rawURL, method, "axios", match[0])
	}

	// 2. axios.request({ url: "...", method: "..." })
	for _, match := range axiosReqURLFirstRegex.FindAllStringSubmatchIndex(text, -1) {
		rawURL := text[match[2]:match[3]]
		method := "UNKNOWN"
		if match[4] != -1 && match[5] != -1 {
			method = text[match[4]:match[5]]
		}
		addEndpoint(rawURL, method, "axios_request", match[0])
	}
	for _, match := range axiosReqMethodFirstRegex.FindAllStringSubmatchIndex(text, -1) {
		method := text[match[2]:match[3]]
		rawURL := text[match[4]:match[5]]
		addEndpoint(rawURL, method, "axios_request", match[0])
	}

	// 3. fetch(url, { method: "..." })
	for _, match := range fetchRegex.FindAllStringSubmatchIndex(text, -1) {
		rawURL := text[match[2]:match[3]]
		method := "UNKNOWN"
		if match[4] != -1 && match[5] != -1 {
			method = text[match[4]:match[5]]
		}
		addEndpoint(rawURL, method, "fetch", match[0])
	}

	// 4. Safely resolve constants concatenation: const API_BASE = "/api"; fetch(API_BASE + "/users")
	constants := make(map[string]string)
	for _, match := range constBaseRegex.FindAllStringSubmatch(text, -1) {
		varName := match[1]
		val := match[2]
		if strings.HasPrefix(val, "/") || strings.HasPrefix(val, "http://") || strings.HasPrefix(val, "https://") {
			constants[varName] = val
		}
	}
	for _, match := range concatCallRegex.FindAllStringSubmatchIndex(text, -1) {
		varName := text[match[2]:match[3]]
		subPath := text[match[4]:match[5]]
		if base, ok := constants[varName]; ok {
			combined := fmt.Sprintf("%s%s", strings.TrimRight(base, "/"), subPath)
			addEndpoint(combined, "UNKNOWN", "concatenation", match[0])
		}
	}

	// 5. Template literals with dynamic interpolation: `/api/users/${id}`
	for _, match := range templateLiteralRegex.FindAllStringSubmatchIndex(text, -1) {
		rawURL := text[match[2]:match[3]]
		if strings.Contains(rawURL, "/api") || strings.Contains(rawURL, "/v1") || strings.Contains(rawURL, "/graphql") {
			addEndpoint(rawURL, "UNKNOWN", "template_literal", match[0])
		}
	}

	// 6. Direct string literals
	for _, match := range directPathRegex.FindAllStringSubmatchIndex(text, -1) {
		rawURL := text[match[2]:match[3]]
		addEndpoint(rawURL, "UNKNOWN", "string_literal", match[0])
	}

	return endpoints
}
