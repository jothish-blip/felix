package apisec

import (
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strings"
)

// APIEndpoint represents an analyzed API route.
type APIEndpoint struct {
	Path           string   `json:"path"`
	Method         string   `json:"method"`
	IsObjectRef    bool     `json:"is_object_ref"`    // Path contains identifier e.g. {id} or /123
	IsPrivileged   bool     `json:"is_privileged"`   // Path indicates administrative function (/admin, /manage)
	IsBusinessFlow bool     `json:"is_business_flow"` // Path represents sensitive flow (register, checkout, reset)
	BusinessFlow   string   `json:"business_flow,omitempty"`
	HasURLParam    bool     `json:"has_url_param"`    // Potential SSRF surface
	URLParamName   string   `json:"url_param_name,omitempty"`
	HasPagination  bool     `json:"has_pagination"`   // Potential resource consumption surface
	PaginationParam string  `json:"pagination_param,omitempty"`
	Version        string   `json:"version,omitempty"` // e.g. "v1", "v2"
	Source         string   `json:"source"`           // "discovered", "spec", "js_bundle"
}

// DeclaredSpec represents a client-supplied API inventory or OpenAPI specification.
type DeclaredSpec struct {
	Endpoints map[string]struct{} `json:"endpoints"` // Set of normalized method:path strings
}

// LoadDeclaredSpec parses an OpenAPI JSON or simple newline-delimited endpoint list.
func LoadDeclaredSpec(filePath string) (*DeclaredSpec, error) {
	if filePath == "" {
		return nil, nil
	}
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read API specification %s: %w", filePath, err)
	}

	spec := &DeclaredSpec{Endpoints: make(map[string]struct{})}

	// Try parsing as OpenAPI / Swagger JSON
	var oas struct {
		Paths map[string]map[string]any `json:"paths"`
	}
	if err := json.Unmarshal(data, &oas); err == nil && len(oas.Paths) > 0 {
		for p, methods := range oas.Paths {
			for m := range methods {
				key := fmt.Sprintf("%s:%s", strings.ToUpper(m), normalizePath(p))
				spec.Endpoints[key] = struct{}{}
			}
		}
		return spec, nil
	}

	// Try parsing as JSON array of endpoint strings
	var list []string
	if err := json.Unmarshal(data, &list); err == nil {
		for _, item := range list {
			item = strings.TrimSpace(item)
			if item != "" {
				spec.Endpoints[normalizeEndpointKey(item)] = struct{}{}
			}
		}
		return spec, nil
	}

	// Fallback to line-separated endpoint list
	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line != "" && !strings.HasPrefix(line, "#") {
			spec.Endpoints[normalizeEndpointKey(line)] = struct{}{}
		}
	}

	return spec, nil
}

var (
	objectIDPattern     = regexp.MustCompile(`(?i)/(?:\{[a-z_-]*id\}|:[a-z_-]*id|\d+|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\b`)
	versionPattern      = regexp.MustCompile(`(?i)/(v\d+(?:\.\d+)?)/`)
	privilegedPattern   = regexp.MustCompile(`(?i)/(admin|manage|internal|dashboard|operator|sysadmin|root)/`)
	urlParamRegex       = regexp.MustCompile(`(?i)\b(url|uri|target|dest|destination|callback|webhook|feed|preview|fetch|import|source_url)\b`)
	paginationParamRegex = regexp.MustCompile(`(?i)\b(limit|size|page_size|pageSize|per_page|count|max_results)\b`)
)

// AnalyzeEndpoint extracts security characteristics from a raw URL path and method.
func AnalyzeEndpoint(method, rawPath, source string) APIEndpoint {
	m := strings.ToUpper(strings.TrimSpace(method))
	if m == "" {
		m = "GET"
	}

	ep := APIEndpoint{
		Path:        rawPath,
		Method:      m,
		Source:      source,
		IsObjectRef: objectIDPattern.MatchString(rawPath),
	}

	// Check API Versioning
	if match := versionPattern.FindStringSubmatch(rawPath); len(match) > 1 {
		ep.Version = strings.ToLower(match[1])
	}

	// Check Privileged Functions
	if privilegedPattern.MatchString(rawPath) {
		ep.IsPrivileged = true
	}

	// Check Sensitive Business Flows
	flow := classifyBusinessFlow(rawPath)
	if flow != "" {
		ep.IsBusinessFlow = true
		ep.BusinessFlow = flow
	}

	// Check query parameters for SSRF or pagination
	queryPart := rawPath
	if idx := strings.Index(rawPath, "?"); idx != -1 {
		queryPart = rawPath[idx+1:]
	}

	// Check Potential SSRF URL parameters
	if match := urlParamRegex.FindString(queryPart); match != "" {
		ep.HasURLParam = true
		ep.URLParamName = match
	} else if match := urlParamRegex.FindString(rawPath); match != "" {
		ep.HasURLParam = true
		ep.URLParamName = match
	}

	// Check Potential Resource Consumption pagination parameters
	if match := paginationParamRegex.FindString(queryPart); match != "" {
		ep.HasPagination = true
		ep.PaginationParam = match
	} else if match := paginationParamRegex.FindString(rawPath); match != "" {
		ep.HasPagination = true
		ep.PaginationParam = match
	}

	return ep
}

func classifyBusinessFlow(path string) string {
	lower := strings.ToLower(path)
	switch {
	case strings.Contains(lower, "register") || strings.Contains(lower, "signup"):
		return "USER_REGISTRATION"
	case strings.Contains(lower, "forgot-password") || strings.Contains(lower, "reset-password") || strings.Contains(lower, "recovery"):
		return "PASSWORD_RESET"
	case strings.Contains(lower, "invite") || strings.Contains(lower, "referral"):
		return "INVITATION_REFERRAL"
	case strings.Contains(lower, "checkout") || strings.Contains(lower, "purchase") || strings.Contains(lower, "pay") || strings.Contains(lower, "order"):
		return "CHECKOUT_TRANSACTION"
	case strings.Contains(lower, "feedback") || strings.Contains(lower, "review") || strings.Contains(lower, "comment"):
		return "USER_INTERACTION_FEEDBACK"
	case strings.Contains(lower, "coupon") || strings.Contains(lower, "voucher") || strings.Contains(lower, "discount"):
		return "VOUCHER_REDEMPTION"
	default:
		return ""
	}
}

func normalizePath(p string) string {
	p = strings.TrimSpace(p)
	p = regexp.MustCompile(`\{[^}]+\}`).ReplaceAllString(p, "{id}")
	return strings.ToLower(p)
}

func normalizeEndpointKey(raw string) string {
	parts := strings.Fields(raw)
	if len(parts) >= 2 {
		return fmt.Sprintf("%s:%s", strings.ToUpper(parts[0]), normalizePath(parts[1]))
	}
	return fmt.Sprintf("GET:%s", normalizePath(raw))
}
