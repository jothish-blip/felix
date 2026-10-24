package api

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"time"
)

// TargetProfile defines the declarative assessment profile for a multi-tenant target environment.
type TargetProfile struct {
	Version          int                    `json:"version" yaml:"version"`
	Target           TargetConfig           `json:"target" yaml:"target"`
	Safety           SafetyConfig           `json:"safety" yaml:"safety"`
	Tenants          []TenantConfig         `json:"tenants" yaml:"tenants"`
	CrossTenantTests CrossTenantTestsConfig `json:"cross_tenant_tests" yaml:"cross_tenant_tests"`
	Monitoring       *MonitoringConfig      `json:"monitoring,omitempty" yaml:"monitoring,omitempty"`
}

// MonitoringConfig configures API-surface temporal drift tracking and instant webhook alerting (P14.5).
type MonitoringConfig struct {
	Enabled           bool                   `json:"enabled" yaml:"enabled"`
	SnapshotDirectory string                 `json:"snapshot_directory,omitempty" yaml:"snapshot_directory,omitempty"`
	RetainSnapshots   int                    `json:"retain_snapshots,omitempty" yaml:"retain_snapshots,omitempty"`
	RetainEvents      int                    `json:"retain_events,omitempty" yaml:"retain_events,omitempty"`
	NotifyOn          []string               `json:"notify_on,omitempty" yaml:"notify_on,omitempty"`
	Webhooks          []MonitorWebhookConfig `json:"webhooks,omitempty" yaml:"webhooks,omitempty"`
}

// MonitorWebhookConfig defines an external alerting destination (Slack, Discord, Teams, generic webhook).
type MonitorWebhookConfig struct {
	ID                string `json:"id" yaml:"id"`
	Provider          string `json:"provider" yaml:"provider"` // "slack", "discord", "teams", "webhook"
	CredentialEnv     string `json:"credential_env" yaml:"credential_env"`
	URL               string `json:"url,omitempty" yaml:"url,omitempty"`
	Enabled           bool   `json:"enabled" yaml:"enabled"`
	AllowInsecureHTTP bool   `json:"allow_insecure_http,omitempty" yaml:"allow_insecure_http,omitempty"`
	AllowLoopback     bool   `json:"allow_loopback,omitempty" yaml:"allow_loopback,omitempty"`
	AllowPrivateIPs   bool   `json:"allow_private_ips,omitempty" yaml:"allow_private_ips,omitempty"`
}

// TargetConfig specifies the scope, target URLs, and allowed communication parameters.
type TargetConfig struct {
	Name           string   `json:"name" yaml:"name"`
	BaseURLs       []string `json:"base_urls" yaml:"base_urls"`
	AllowedHosts   []string `json:"allowed_hosts" yaml:"allowed_hosts"`
	AllowedMethods []string `json:"allowed_methods" yaml:"allowed_methods"`
}

// SafetyConfig declares strict non-destructive bounds and cross-tenant authorization permissions.
type SafetyConfig struct {
	Mode                         string  `json:"mode" yaml:"mode"` // "non_destructive"
	RequireExplicitAuthorization bool    `json:"require_explicit_authorization" yaml:"require_explicit_authorization"`
	AllowCrossTenantChecks       bool    `json:"allow_cross_tenant_checks" yaml:"allow_cross_tenant_checks"`
	MaxRequests                  int     `json:"max_requests" yaml:"max_requests"`
	RequestsPerSecond            float64 `json:"requests_per_second" yaml:"requests_per_second"`
	TimeoutSeconds               int     `json:"timeout_seconds" yaml:"timeout_seconds"`
	FollowRedirects              bool    `json:"follow_redirects" yaml:"follow_redirects"`
}

// TenantConfig defines an authorized test tenant context and its declared test resources.
type TenantConfig struct {
	ID            string            `json:"id" yaml:"id"`
	Identity      string            `json:"identity" yaml:"identity"`
	CredentialEnv string            `json:"credential_env" yaml:"credential_env"`
	Headers       map[string]string `json:"headers,omitempty" yaml:"headers,omitempty"`
	ResourceIDs   []string          `json:"resource_ids" yaml:"resource_ids"`
}

// CrossTenantTestsConfig declares the test matrix for cross-tenant object access evaluations.
type CrossTenantTestsConfig struct {
	Enabled     bool               `json:"enabled" yaml:"enabled"`
	Comparisons []TenantComparison `json:"comparisons" yaml:"comparisons"`
}

// TenantComparison defines an explicit comparison pair between a requesting tenant and an owned resource.
type TenantComparison struct {
	RequesterTenant     string `json:"requester_tenant" yaml:"requester_tenant"`
	ResourceOwnerTenant string `json:"resource_owner_tenant" yaml:"resource_owner_tenant"`
	ResourceID          string `json:"resource_id" yaml:"resource_id"`
	Path                string `json:"path,omitempty" yaml:"path,omitempty"`
	Method              string `json:"method,omitempty" yaml:"method,omitempty"`
	ExpectedMarker      string `json:"expected_marker,omitempty" yaml:"expected_marker,omitempty"`
}

// CrossTenantClassification categorizes the empirical outcome of a cross-tenant authorization probe.
type CrossTenantClassification string

const (
	CrossTenantAuthorizedAccessExpected  CrossTenantClassification = "AUTHORIZED_ACCESS_EXPECTED"
	CrossTenantAccessDeniedObserved      CrossTenantClassification = "ACCESS_DENIED_OBSERVED"
	CrossTenantNotFoundObserved          CrossTenantClassification = "NOT_FOUND_OBSERVED"
	CrossTenantAccessObserved            CrossTenantClassification = "CROSS_TENANT_ACCESS_OBSERVED"
	CrossTenantAuthenticationRequired    CrossTenantClassification = "AUTHENTICATION_REQUIRED"
	CrossTenantRateLimited               CrossTenantClassification = "RATE_LIMITED"
	CrossTenantScopeBlocked              CrossTenantClassification = "SCOPE_BLOCKED"
	CrossTenantUnsafeRouteSkipped        CrossTenantClassification = "UNSAFE_ROUTE_SKIPPED"
	CrossTenantMissingCredential         CrossTenantClassification = "MISSING_CREDENTIAL"
	CrossTenantInconclusive              CrossTenantClassification = "INCONCLUSIVE"
	CrossTenantTransportFailure          CrossTenantClassification = "TRANSPORT_FAILURE"
)

// CrossTenantResult stores the observable evidence and audit trail for a single comparison test.
type CrossTenantResult struct {
	ComparisonID        string                    `json:"comparison_id"`
	RequesterTenant     string                    `json:"requester_tenant"`
	ResourceOwnerTenant string                    `json:"resource_owner_tenant"`
	ResourceID          string                    `json:"resource_id"`
	TargetURL           string                    `json:"target_url"`
	Path                string                    `json:"path"`
	Method              string                    `json:"method"`
	StatusCode          int                       `json:"status_code,omitempty"`
	Classification      CrossTenantClassification `json:"classification"`
	IsBOLAObserved      bool                      `json:"is_bola_observed"`
	Confidence          string                    `json:"confidence"`
	Rationale           string                    `json:"rationale"`
	EvidenceSnippet     string                    `json:"evidence_snippet,omitempty"`
	ExecutionTimestamp  time.Time                 `json:"execution_timestamp"`
	Limitations         string                    `json:"limitations,omitempty"`
}

// CrossTenantReport summarizes the aggregate outcome across all evaluated cross-tenant comparisons.
type CrossTenantReport struct {
	TotalComparisonsConfigured      int                 `json:"total_comparisons_configured"`
	TotalExecuted                   int                 `json:"total_executed"`
	TotalSkipped                    int                 `json:"total_skipped"`
	TotalCrossTenantAccessObserved  int                 `json:"total_cross_tenant_access_observed"`
	TotalAccessDeniedObserved       int                 `json:"total_access_denied_observed"`
	TotalNotFoundObserved           int                 `json:"total_not_found_observed"`
	TotalInconclusive               int                 `json:"total_inconclusive"`
	TotalFailed                     int                 `json:"total_failed"`
	SafetyPolicySummary             string              `json:"safety_policy_summary"`
	Results                         []CrossTenantResult `json:"results"`
	Warnings                        []string            `json:"warnings,omitempty"`
}

// GenerateComparisonID produces a deterministic identifier for a comparison execution.
func GenerateComparisonID(requester, owner, resourceID, path string) string {
	raw := fmt.Sprintf("%s|%s|%s|%s", strings.ToLower(requester), strings.ToLower(owner), resourceID, CanonicalizeRoutePath(path))
	h := sha256.Sum256([]byte(raw))
	return fmt.Sprintf("XTC-%s", hex.EncodeToString(h[:6]))
}
