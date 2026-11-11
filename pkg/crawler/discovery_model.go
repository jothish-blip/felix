package crawler

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/url"
	"strings"
	"time"
)

// AssetClassification classifies the discovery and reachability status of an asset.
type AssetClassification string

const (
	ClassificationConfirmedEndpoint     AssetClassification = "CONFIRMED_ENDPOINT"
	ClassificationStaticAsset           AssetClassification = "STATIC_ASSET"
	ClassificationEndpointCandidate     AssetClassification = "ENDPOINT_CANDIDATE"
	ClassificationObservedForm          AssetClassification = "OBSERVED_FORM"
	ClassificationRedirected            AssetClassification = "REDIRECTED_RESOURCE"
	ClassificationInaccessible          AssetClassification = "INACCESSIBLE_RESOURCE"
	ClassificationOutOfScope            AssetClassification = "OUT_OF_SCOPE"
	ClassificationExcludedDestructive   AssetClassification = "EXCLUDED_DESTRUCTIVE_ACTION"
)

// FormField models an input field within an HTML form.
type FormField struct {
	Name     string `json:"name"`
	Type     string `json:"type,omitempty"`
	Value    string `json:"value,omitempty"`
	Required bool   `json:"required,omitempty"`
}

// ExtractedForm models an HTML form discovered during crawling.
type ExtractedForm struct {
	Action      string      `json:"action"`
	ResolvedURL string      `json:"resolved_url"`
	Method      string      `json:"method"`
	Fields      []FormField `json:"fields"`
}

// DiscoveredResource represents an attack-surface entity discovered during active crawling.
type DiscoveredResource struct {
	ID                 string              `json:"id"`
	URL                string              `json:"url"`
	NormalizedURL      string              `json:"normalized_url"`
	Host               string              `json:"host"`
	Path               string              `json:"path"`
	HTTPMethod         string              `json:"http_method"`
	ContentType        string              `json:"content_type,omitempty"`
	AssetType          AssetType           `json:"asset_type"`
	QueryParams        []string            `json:"query_params,omitempty"`
	PathParams         []string            `json:"path_params,omitempty"`
	FormFields         []FormField         `json:"form_fields,omitempty"`
	SourcePage         string              `json:"source_page,omitempty"`
	DiscoveryMethod    string              `json:"discovery_method"` // HTML_CRAWL, HTML_FORM, JS_BUNDLE, JS_ROUTE_CANDIDATE, STATIC_LINK, SEED
	IdentityContext    string              `json:"identity_context"` // ANONYMOUS, USER_A, USER_B, ADMIN
	StatusCode         int                 `json:"status_code,omitempty"`
	DiscoveredAt       time.Time           `json:"discovered_at"`
	CrawlDepth         int                 `json:"crawl_depth"`
	InScope            bool                `json:"in_scope"`
	Classification     AssetClassification `json:"classification"`
	Confidence         string              `json:"confidence"` // HIGH, MEDIUM, LOW
	AccessibilityState string              `json:"accessibility_state"` // REACHABLE, UNAUTHORIZED_401, FORBIDDEN_403, REDIRECTED, ERROR, EXCLUDED
	ExclusionReason    string              `json:"exclusion_reason,omitempty"`
	Evidence           string              `json:"evidence,omitempty"`
}

// ComputeResourceID produces a deterministic identifier for a discovered resource.
func ComputeResourceID(identity, method, normalizedURL string) string {
	raw := fmt.Sprintf("%s:%s:%s", strings.ToUpper(identity), strings.ToUpper(method), strings.ToLower(normalizedURL))
	sum := sha256.Sum256([]byte(raw))
	return fmt.Sprintf("res_%s", hex.EncodeToString(sum[:10]))
}

// CoverageGapRecord documents an area where full assessment coverage could not be achieved.
type CoverageGapRecord struct {
	Type            string `json:"type"` // AUTH_BLOCKED, BUNDLE_UNRETRIEVABLE, CANDIDATE_UNCONFIRMED, LIMIT_REACHED, SAFETY_EXCLUSION, UNPARSED_CONTENT
	Resource        string `json:"resource"`
	Reason          string `json:"reason"`
	IdentityContext string `json:"identity_context,omitempty"`
}

// DiscoverySummary aggregates discovery metrics across active crawling and bundle analysis.
type DiscoverySummary struct {
	TotalPagesDiscovered       int `json:"total_pages_discovered"`
	TotalConfirmedEndpoints    int `json:"total_confirmed_endpoints"`
	TotalEndpointCandidates    int `json:"total_endpoint_candidates"`
	TotalJavaScriptBundles     int `json:"total_javascript_bundles"`
	TotalFormsAndInputs        int `json:"total_forms_and_inputs"`
	TotalStaticAssets          int `json:"total_static_assets"`
	TotalInaccessibleResources int `json:"total_inaccessible_resources"`
	TotalExcludedResources     int `json:"total_excluded_resources"`
	TotalRequestsMade          int `json:"total_requests_made"`
}

// IdentityRouteObservation records how an endpoint appeared to a specific identity.
type IdentityRouteObservation struct {
	Visible        bool   `json:"visible"`
	StatusCode     int    `json:"status_code"`
	StatusText     string `json:"status_text"`
	Classification string `json:"classification"`
}

// IdentityVisibilityMatrix maps canonical endpoints to visibility states per identity.
type IdentityVisibilityMatrix struct {
	Identities []string                                        `json:"identities"`
	Endpoints  map[string]map[string]IdentityRouteObservation `json:"endpoints"` // routeKey -> identity -> observation
}

// NewIdentityVisibilityMatrix initializes an empty matrix.
func NewIdentityVisibilityMatrix(identities ...string) *IdentityVisibilityMatrix {
	if len(identities) == 0 {
		identities = []string{"ANONYMOUS"}
	}
	return &IdentityVisibilityMatrix{
		Identities: identities,
		Endpoints:  make(map[string]map[string]IdentityRouteObservation),
	}
}

// RecordObservation adds an observation for a route under a specific identity context.
func (m *IdentityVisibilityMatrix) RecordObservation(routeKey, identity string, obs IdentityRouteObservation) {
	if m.Endpoints == nil {
		m.Endpoints = make(map[string]map[string]IdentityRouteObservation)
	}
	if m.Endpoints[routeKey] == nil {
		m.Endpoints[routeKey] = make(map[string]IdentityRouteObservation)
	}
	m.Endpoints[routeKey][identity] = obs
}

// ActiveCrawlResult contains the complete output of an active crawl session.
type ActiveCrawlResult struct {
	Resources          []DiscoveredResource      `json:"resources"`
	Summary            DiscoverySummary          `json:"summary"`
	VisibilityMatrix   *IdentityVisibilityMatrix `json:"visibility_matrix"`
	CoverageGaps       []CoverageGapRecord       `json:"coverage_gaps"`
	AssetsForInventory []Asset                   `json:"assets_for_inventory"`
}

// NormalizeCrawlURL produces a canonical URL string by stripping fragments and standardizing host/scheme.
func NormalizeCrawlURL(rawURL string) (string, error) {
	parsed, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil {
		return "", err
	}
	parsed.Fragment = ""
	parsed.Host = strings.ToLower(parsed.Host)
	parsed.Scheme = strings.ToLower(parsed.Scheme)

	// Strip default ports
	if parsed.Scheme == "http" && strings.HasSuffix(parsed.Host, ":80") {
		parsed.Host = strings.TrimSuffix(parsed.Host, ":80")
	} else if parsed.Scheme == "https" && strings.HasSuffix(parsed.Host, ":443") {
		parsed.Host = strings.TrimSuffix(parsed.Host, ":443")
	}

	if parsed.Path == "" {
		parsed.Path = "/"
	}

	return parsed.String(), nil
}
