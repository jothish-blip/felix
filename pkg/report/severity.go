package report

import (
	"strings"
)

// NormalizeSeverity standardizes severity strings into one of the 5 canonical levels.
func NormalizeSeverity(raw string) string {
	s := strings.ToUpper(strings.TrimSpace(raw))
	switch s {
	case SeverityCritical, "CRIT":
		return SeverityCritical
	case SeverityHigh:
		return SeverityHigh
	case SeverityMedium, "MED", "MODERATE":
		return SeverityMedium
	case SeverityLow:
		return SeverityLow
	case SeverityInfo, "INFORMATIONAL", "NOTE":
		return SeverityInfo
	default:
		return SeverityInfo
	}
}

// MapSeverity applies context-aware defensibility rules to ensure explainable severities.
// It prevents false escalation while guaranteeing high-risk verified exposures are highlighted.
func MapSeverity(category string, rawSeverity string) string {
	cat := strings.ToLower(strings.TrimSpace(category))
	norm := NormalizeSeverity(rawSeverity)

	switch {
	// Privileged cloud keys are always CRITICAL
	case strings.Contains(cat, "service-key"), strings.Contains(cat, "service-role"),
		strings.Contains(cat, "private-key"), strings.Contains(cat, "aws-secret-key"):
		return SeverityCritical

	// Public anon/publishable keys are intentionally client-facing -> INFO
	case strings.Contains(cat, "anon-key"), strings.Contains(cat, "publishable"):
		return SeverityInfo

	// Permissive wildcards without credentials -> INFO
	case cat == "cors-wildcard":
		return SeverityInfo

	// Public documentation -> INFO
	case cat == "api-docs-exposure":
		return SeverityInfo

	// Feature policy & nosniff headers -> INFO
	case cat == "missing-permissions-policy", cat == "missing-x-content-type-options":
		return SeverityInfo

	// Defense-in-depth headers -> LOW
	case cat == "missing-csp", cat == "missing-hsts", cat == "missing-x-frame-options":
		return SeverityLow

	// Source map exposure or discovery -> INFO (source disclosure, not direct vuln)
	case cat == "source-map-exposure", cat == "source-map-discovered":
		return SeverityInfo

	// Discovered components, protected endpoints (401/403/404), and asset inventory -> INFO
	case strings.Contains(cat, "endpoint-discovered"), strings.Contains(cat, "provider-discovered"),
		strings.Contains(cat, "access-denied"), strings.Contains(cat, "endpoint-protected"),
		strings.Contains(cat, "public-endpoint"), strings.Contains(cat, "endpoint-normal"),
		strings.Contains(cat, "introspection-denied"), strings.HasPrefix(cat, "asset-"):
		return SeverityInfo

	// Version control repository exposure -> HIGH
	case cat == "git-metadata-exposure":
		return SeverityHigh

	default:
		return norm
	}
}

// SeverityRank returns an integer order for deterministic sorting (higher is more critical).
func SeverityRank(sev string) int {
	switch NormalizeSeverity(sev) {
	case SeverityCritical:
		return 5
	case SeverityHigh:
		return 4
	case SeverityMedium:
		return 3
	case SeverityLow:
		return 2
	case SeverityInfo:
		return 1
	default:
		return 0
	}
}
