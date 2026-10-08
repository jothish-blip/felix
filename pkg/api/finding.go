package api

import (
	"crypto/sha256"
	"encoding/hex"
	"regexp"
	"strings"
)

// Severity and Confidence ratings for API findings.
const (
	SeverityCritical = "CRITICAL"
	SeverityHigh     = "HIGH"
	SeverityMedium   = "MEDIUM"
	SeverityLow      = "LOW"
	SeverityInfo     = "INFO"

	ConfidenceHigh   = "High"
	ConfidenceMedium = "Medium"
	ConfidenceLow    = "Low"
)

// API finding category identifiers.
const (
	CategoryGraphQLIntrospection = "graphql-introspection"
	CategoryCORSOriginReflection = "cors-origin-reflection"
	CategoryCORSWildcard         = "cors-wildcard"
	CategoryEnvExposure          = "env-exposure"
	CategoryGitExposure          = "git-metadata-exposure"
	CategoryAPIDocsExposure      = "api-docs-exposure"
	CategoryHealthExposure       = "health-endpoint"
	CategoryMetricsExposure      = "metrics-exposure"
	CategoryMissingCSP           = "missing-csp"
	CategoryMissingHSTS          = "missing-hsts"
	CategoryMissingXFrameOptions = "missing-x-frame-options"
	CategoryMissingXContentType  = "missing-x-content-type-options"
	CategoryMissingPermissions         = "missing-permissions-policy"
	CategoryEndpointDiscovered         = "endpoint-discovered"
	CategoryWeakCSP                    = "weak-csp"
	CategoryWeakHSTS                   = "weak-hsts"
	CategoryMissingReferrerPolicy      = "missing-referrer-policy"
	CategoryWeakReferrerPolicy         = "weak-referrer-policy"
	CategoryGraphQLIntrospectionDenied = "graphql-introspection-denied"
	CategoryGraphQLSensitiveSchema     = "graphql-sensitive-schema"
)

// APIFinding represents a verified API security exposure, configuration issue, or hardening observation.
type APIFinding struct {
	Category         string                 `json:"category"`
	Endpoint         string                 `json:"endpoint"`
	Method           string                 `json:"method"`
	Description      string                 `json:"description"`
	Evidence         string                 `json:"evidence"`
	Severity         string                 `json:"severity"`
	Confidence       string                 `json:"confidence"`
	Fingerprint      string                 `json:"fingerprint"`
	Classification   EndpointClassification `json:"classification,omitempty"`
	AuthState        AuthState              `json:"auth_state,omitempty"`
	SourceAsset      string                 `json:"source_asset,omitempty"`
	LineNumber       int                    `json:"line_number,omitempty"`
	Mechanism        string                 `json:"mechanism,omitempty"`
	NegativeEvidence string                 `json:"negative_evidence,omitempty"`
	HTTPStatus       int                    `json:"http_status,omitempty"`
	Details          map[string]string      `json:"details,omitempty"`
}

// GenerateFingerprint generates a stable SHA-256 deduplication fingerprint for the finding.
func GenerateFingerprint(category, endpoint, method string) string {
	h := sha256.New()
	cleanCategory := strings.ToLower(strings.TrimSpace(category))
	cleanMethod := strings.ToUpper(strings.TrimSpace(method))
	cleanEndpoint := strings.ToLower(strings.TrimSpace(endpoint))
	h.Write([]byte(cleanCategory + ":" + cleanMethod + ":" + cleanEndpoint))
	return hex.EncodeToString(h.Sum(nil))
}

var (
	sensitiveAssignRegex = regexp.MustCompile(`(?i)(password|secret|key|token|auth|bearer|credential|api_key|private)\s*[:=]\s*["']?([^\s"'` + "`" + `,;]+)`)
	jwtPatternRegex      = regexp.MustCompile(`\bey[A-Za-z0-9_-]{8,}\.ey[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]+\b`)
)

// RedactEvidence sanitizes evidence strings to prevent leaking credentials or tokens.
func RedactEvidence(input string) string {
	// Redact JWT patterns
	output := jwtPatternRegex.ReplaceAllString(input, "[REDACTED_JWT]")

	// Redact key/secret assignments
	output = sensitiveAssignRegex.ReplaceAllStringFunc(output, func(m string) string {
		parts := strings.SplitN(m, "=", 2)
		if len(parts) == 2 {
			return parts[0] + "=[REDACTED]"
		}
		parts = strings.SplitN(m, ":", 2)
		if len(parts) == 2 {
			return parts[0] + ": [REDACTED]"
		}
		return "[REDACTED]"
	})

	return output
}
