package api

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"

	"felix/pkg/secrets"
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
	CategoryActuatorHealthDetailed     = "actuator-health-detailed"
	CategoryActuatorEnv                = "actuator-env-exposure"
	CategoryActuatorMappings           = "actuator-mappings-exposure"
	CategoryActuatorRestricted         = "actuator-endpoint-restricted"
	CategoryDjangoDebugMode            = "django-debug-mode"
	CategoryDjangoURLConfDisclosure    = "django-urlconf-disclosure"
	CategoryDjangoBrowsableAPI         = "django-browsable-api"
	CategoryFastAPIDocs                = "fastapi-docs-exposure"
	CategoryFastAPISensitivePaths      = "fastapi-sensitive-paths"
	CategoryFastAPISensitiveSchema     = "fastapi-sensitive-schema"
	CategoryLaravelIgnitionDebug      = "laravel-ignition-debug"
	CategoryLaravelTelescopeExposed   = "laravel-telescope-exposure"
	CategoryLaravelTelescopeProtected = "laravel-telescope-restricted"
	CategoryLaravelTelescopeData      = "laravel-telescope-sensitive-data"
	CategoryNodeRuntimeExposure       = "node-runtime-exposure"
	CategoryNodeDebugError            = "node-debug-error"
	CategoryNodeStackTrace            = "node-stack-trace"
	CategoryGoRuntimeExposure         = "go-runtime-exposure"
	CategoryGoDebugPanic              = "go-debug-panic"
	CategoryGoStackTrace              = "go-stack-trace"
	CategoryGoPprofExposure           = "go-pprof-exposure"
	CategoryGoVarsExposure            = "go-vars-exposure"
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
	HTTPStatus            int                    `json:"http_status,omitempty"`
	Details               map[string]string      `json:"details,omitempty"`
	Framework             string                 `json:"framework,omitempty"`
	FrameworkVersion      string                 `json:"framework_version,omitempty"`
	RuleID                string                 `json:"rule_id,omitempty"`
	ContentType           string                 `json:"content_type,omitempty"`
	ClassificationOutcome ClassificationOutcome  `json:"classification_outcome,omitempty"`
	Reachability          ReachabilityStatus     `json:"reachability,omitempty"`
	AuthContext           AuthenticationContext  `json:"auth_context,omitempty"`
	Limitations           []string               `json:"limitations,omitempty"`
	OriginalContext       string                 `json:"original_context,omitempty"`
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

// RedactEvidence sanitizes evidence strings to prevent leaking credentials or tokens.
func RedactEvidence(input string) string {
	return secrets.RedactText(input)
}
