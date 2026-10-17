package apk

// EndpointCategory identifies the functional categorization of an identified backend endpoint.
type EndpointCategory string

const (
	CategoryAPI            EndpointCategory = "api"
	CategoryAuthentication EndpointCategory = "authentication"
	CategoryGraphQL        EndpointCategory = "graphql"
	CategoryFirebase       EndpointCategory = "firebase"
	CategoryStorage        EndpointCategory = "storage"
	CategoryCloudService   EndpointCategory = "cloud_service"
	CategoryDatabase       EndpointCategory = "database"
	CategoryDeepLink       EndpointCategory = "deep_link"
	CategoryOther          EndpointCategory = "other"
)

// ReferenceClassification distinguishes directly observed complete endpoints from derived or inferred routes.
type ReferenceClassification string

const (
	ClassificationConfirmedReference ReferenceClassification = "confirmed_reference"
	ClassificationInferredRoute      ReferenceClassification = "inferred_route"
)

// ProvenanceRecord preserves the exact traceability and origin of an endpoint or route discovered in the APK.
type ProvenanceRecord struct {
	APKSHA256        string `json:"apk_sha256,omitempty"`
	APKFileName      string `json:"apk_filename,omitempty"`
	ArtifactType     string `json:"artifact_type"`                // "dex", "manifest", "config", "resource", "javascript"
	ArtifactPath     string `json:"artifact_path"`                // Entry path inside APK (e.g. "classes.dex", "AndroidManifest.xml")
	DEXFile          string `json:"dex_file,omitempty"`           // Specific DEX file name if applicable (e.g. "classes2.dex")
	ComponentContext string `json:"component_context,omitempty"`  // Android component context if applicable (e.g. "activity:com.example.AuthActivity")
	Location         string `json:"location,omitempty"`           // Attribute name, element name, or string index
	AnalysisStage    string `json:"analysis_stage"`               // Analysis phase (e.g. "manifest_analysis", "artifact_intelligence")
	Classification   string `json:"classification"`               // "confirmed_reference" or "inferred_route"
}

// InferredRouteDetails preserves the decomposition and rationale for an inferred route.
type InferredRouteDetails struct {
	BaseURL   string `json:"base_url,omitempty"`
	RoutePath string `json:"route_path,omitempty"`
	Reason    string `json:"reason,omitempty"`
}

// EndpointEntry represents a single normalized, evidence-backed backend endpoint.
type EndpointEntry struct {
	NormalizedURL   string                  `json:"normalized_url"`
	RawURL          string                  `json:"raw_url,omitempty"`
	Scheme          string                  `json:"scheme,omitempty"`
	Host            string                  `json:"host,omitempty"`
	Port            int                     `json:"port,omitempty"`
	Path            string                  `json:"path"`
	RawQuery        string                  `json:"query,omitempty"`
	HostIdentity    string                  `json:"host_identity"` // e.g. "api.example.com", "api.example.com:8443", or "(unresolved)"
	Category        EndpointCategory        `json:"category"`
	Classification  ReferenceClassification `json:"classification"`
	Confidence      string                  `json:"confidence"` // "HIGH", "MEDIUM", "LOW"
	Rationale       string                  `json:"rationale"`
	Provenance      []ProvenanceRecord      `json:"provenance"`
	Evidence        []string                `json:"evidence"`
	AssociatedRules []string                `json:"associated_rules,omitempty"`
	FindingIDs      []string                `json:"finding_ids,omitempty"`
	InferredDetails *InferredRouteDetails   `json:"inferred_details,omitempty"`
}

// HostGroup groups all normalized endpoints sharing a common canonical backend host identity.
type HostGroup struct {
	HostIdentity      string          `json:"host_identity"` // e.g. "api.example.com" or "api.example.com:8443"
	Hostname          string          `json:"hostname"`
	Port              int             `json:"port,omitempty"`
	EndpointCount     int             `json:"endpoint_count"`
	ConfirmedCount    int             `json:"confirmed_count"`
	InferredCount     int             `json:"inferred_count"`
	ServiceIndicators []string        `json:"service_indicators,omitempty"`
	ArtifactOrigins   []string        `json:"artifact_origins"`
	Endpoints         []EndpointEntry `json:"endpoints"`
}

// BackendInventory represents the comprehensive, deduplicated backend inventory synthesized from APK static analysis.
type BackendInventory struct {
	APKSHA256      string           `json:"apk_sha256,omitempty"`
	APKFileName    string           `json:"apk_filename,omitempty"`
	TotalEndpoints int              `json:"total_endpoints"`
	TotalHosts     int              `json:"total_hosts"`
	ConfirmedCount int              `json:"confirmed_count"`
	InferredCount  int              `json:"inferred_count"`
	Categories     map[string]int   `json:"categories"`
	Hosts          []HostGroup      `json:"hosts"`
	Endpoints      []EndpointEntry  `json:"endpoints"`
	Limitations    []string         `json:"limitations,omitempty"`
}
