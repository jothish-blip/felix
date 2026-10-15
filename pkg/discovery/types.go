package discovery

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// AssetType categorizes an entity within the attack-surface inventory.
type AssetType string

const (
	AssetTypeRoot           AssetType = "ORGANIZATION_ROOT"
	AssetTypeDomain         AssetType = "DOMAIN"
	AssetTypeSubdomain      AssetType = "SUBDOMAIN"
	AssetTypeWebService     AssetType = "WEB_SERVICE"
	AssetTypeApplication    AssetType = "APPLICATION"
	AssetTypeAPIService     AssetType = "API_SERVICE"
	AssetTypeEndpoint       AssetType = "ENDPOINT"
	AssetTypeJavaScript     AssetType = "JAVASCRIPT"
	AssetTypeAsset          AssetType = "ASSET"
	AssetTypeParameter      AssetType = "PARAMETER"
	AssetTypeForm           AssetType = "FORM"
	AssetTypeAuthSurface    AssetType = "AUTH_SURFACE"
	AssetTypeCloudService   AssetType = "CLOUD_SERVICE"
	AssetTypeTechnology     AssetType = "TECHNOLOGY"

	// Common Asset Model (Phase 1.2) Core Categories
	AssetTypeHost     AssetType = "HOST"
	AssetTypeService  AssetType = "SERVICE"
	AssetTypeDatabase AssetType = "DATABASE"
	AssetTypeStorage  AssetType = "STORAGE_RESOURCE"
	AssetTypeAPK      AssetType = "APK_ARTIFACT"
)

// RelationType defines the directed relationship between two inventory assets.
type RelationType string

const (
	RelHasSubdomain           RelationType = "HAS_SUBDOMAIN"
	RelExposesService         RelationType = "EXPOSES_SERVICE"
	RelExposesApplication     RelationType = "EXPOSES_APPLICATION"
	RelUsesAPI                RelationType = "USES_API"
	RelLoadsJavaScript        RelationType = "LOADS_JAVASCRIPT"
	RelReferencesEndpoint     RelationType = "REFERENCES_ENDPOINT"
	RelAcceptsParameter       RelationType = "ACCEPTS_PARAMETER"
	RelContainsForm           RelationType = "CONTAINS_FORM"
	RelHasInput               RelationType = "HAS_INPUT"
	RelExposesAuthSurface     RelationType = "EXPOSES_AUTH_SURFACE"
	RelReferencesCloudService RelationType = "REFERENCES_CLOUD_SERVICE"
	RelUsesTechnology         RelationType = "USES_TECHNOLOGY"
	RelResolvedTo             RelationType = "RESOLVED_TO"

	// Common Asset Model (Phase 1.2) Relationships
	RelHostsApplication   RelationType = "HOSTS_APPLICATION"    // Host -> Application
	RelHostsService       RelationType = "HOSTS_SERVICE"        // Host -> Service
	RelExposesEndpoint    RelationType = "EXPOSES_ENDPOINT"     // Application/Service -> Endpoint
	RelUsesDatabase       RelationType = "USES_DATABASE"        // Application/Service -> Database
	RelUsesStorage        RelationType = "USES_STORAGE"         // Application/Service -> Storage
	RelRelatedApplication RelationType = "RELATED_APPLICATION"  // APK -> Application
	RelAssociatedWithHost RelationType = "ASSOCIATED_WITH_HOST" // Application -> Host
)

// ApplicationDetails captures typed metadata for application-level assets.
type ApplicationDetails struct {
	AppType        string   `json:"app_type"`                  // "web", "spa", "api", "mobile_backend"
	RootURL        string   `json:"root_url"`                  // Normalized root URL
	TechStack      []string `json:"tech_stack,omitempty"`      // Frameworks/libraries identified
	AuthMechanisms []string `json:"auth_mechanisms,omitempty"` // Form, OAuth2, JWT, etc.
	Version        string   `json:"version,omitempty"`
}

// HostDetails captures typed metadata for infrastructure and network hosts.
type HostDetails struct {
	Hostname       string   `json:"hostname"`                 // Normalized lowercase hostname or IP
	IPAddresses    []string `json:"ip_addresses,omitempty"`   // Resolved IPv4 and IPv6 addresses
	IsIPv6         bool     `json:"is_ipv6,omitempty"`        // True if primary address is IPv6
	TLSEnabled     bool     `json:"tls_enabled,omitempty"`    // True if TLS/HTTPS supported
	Infrastructure string   `json:"infrastructure,omitempty"` // "cloud", "on-prem", "cdn"
	DNSRecords     []string `json:"dns_records,omitempty"`    // A, AAAA, CNAME values
}

// EndpointDetails captures typed metadata for URLs, routes, and API endpoints.
type EndpointDetails struct {
	URL            string   `json:"url"`                      // Normalized URL (clean, secret-safe)
	HTTPMethod     string   `json:"http_method"`              // GET, POST, PUT, DELETE, etc.
	Path           string   `json:"path"`                     // Normalized URL path
	Classification string   `json:"classification,omitempty"` // "API", "AUTH", "GRAPHQL", "STATIC", "ADMIN"
	Parameters     []string `json:"parameters,omitempty"`     // Parameter names accepted (values omitted)
	Authenticated  bool     `json:"authenticated,omitempty"`  // True if auth required
	HTTPStatus     int      `json:"http_status,omitempty"`    // Last observed status code
	ContentType    string   `json:"content_type,omitempty"`
}

// ServiceDetails captures typed metadata for network and application services.
type ServiceDetails struct {
	ServiceName string `json:"service_name"`        // "http", "https", "grpc", "graphql"
	Port        int    `json:"port"`                // Port number
	Protocol    string `json:"protocol"`            // "tcp", "udp"
	Transport   string `json:"transport,omitempty"` // "http", "https", "tls", "raw"
	Banner      string `json:"banner,omitempty"`    // Redacted service banner
	Version     string `json:"version,omitempty"`
}

// DatabaseDetails captures typed metadata for identifiable database instances and resources.
type DatabaseDetails struct {
	Engine             string `json:"engine"`                         // "firebase_rtdb", "supabase_postgres", "mongodb", "mysql", "redis"
	InstanceName       string `json:"instance_name"`                 // Project ID, database name, or cluster ID
	Host               string `json:"host,omitempty"`                // Hostname or connection address
	Port               int    `json:"port,omitempty"`
	PubliclyAccessible bool   `json:"publicly_accessible,omitempty"` // True if reachable without VPN/private net
	AuthRequired       bool   `json:"auth_required,omitempty"`       // True if authentication is enforced
	Encrypted          bool   `json:"encrypted,omitempty"`
}

// StorageDetails captures typed metadata for object storage, buckets, and containers.
type StorageDetails struct {
	Provider      string `json:"provider"`                 // "aws_s3", "gcp_storage", "azure_blob", "supabase_storage"
	BucketName    string `json:"bucket_name"`              // Bucket, container, or namespace name
	Region        string `json:"region,omitempty"`         // Cloud region if identifiable
	ResourceURL   string `json:"resource_url"`             // Normalized public URL
	PublicListing bool   `json:"public_listing,omitempty"` // True if anonymous directory listing permitted
	PublicRead    bool   `json:"public_read,omitempty"`    // True if objects are anonymously readable
}

// APKDetails captures typed metadata for Android APK artifacts.
type APKDetails struct {
	PackageName string   `json:"package_name"`           // Android package ID (e.g. com.example.app)
	VersionName string   `json:"version_name,omitempty"` // Version string (e.g. 1.0.4)
	VersionCode int      `json:"version_code,omitempty"` // Integer version code
	MinSDK      int      `json:"min_sdk,omitempty"`      // Minimum Android SDK level
	TargetSDK   int      `json:"target_sdk,omitempty"`   // Target Android SDK level
	Permissions []string `json:"permissions,omitempty"`  // Declared Android permissions
	SHA256      string   `json:"sha256,omitempty"`       // File SHA-256 checksum
	FileSize    int64    `json:"file_size,omitempty"`    // Binary size in bytes
	FileName    string   `json:"file_name,omitempty"`    // Original or artifact file name
}

// DiscoveryStatus represents the empirical state of discovery for an asset.
type DiscoveryStatus string

const (
	StatusObserved    DiscoveryStatus = "OBSERVED"     // Directly present in response, asset, or seed list
	StatusInferred    DiscoveryStatus = "INFERRED"     // Derived from a recognizable reference or pattern
	StatusResolved    DiscoveryStatus = "RESOLVED"     // Hostname or identifier resolved successfully via DNS
	StatusReachable   DiscoveryStatus = "REACHABLE"    // Bounded request received an HTTP response
	StatusVerified    DiscoveryStatus = "VERIFIED"     // Explicitly verified via protocol check
	StatusUnavailable DiscoveryStatus = "UNAVAILABLE"  // Check could not complete or host timed out
	StatusOutOfScope  DiscoveryStatus = "OUT_OF_SCOPE" // Discovered reference is outside approved assessment boundaries
)

// Confidence represents the evidential strength of a discovery.
type Confidence string

const (
	ConfidenceHigh   Confidence = "HIGH"
	ConfidenceMedium Confidence = "MEDIUM"
	ConfidenceLow    Confidence = "LOW"
)

// ParamLocation specifies where an input parameter is accepted.
type ParamLocation string

const (
	ParamLocQuery  ParamLocation = "QUERY"
	ParamLocPath   ParamLocation = "PATH"
	ParamLocForm   ParamLocation = "FORM"
	ParamLocBody   ParamLocation = "BODY"
	ParamLocHeader ParamLocation = "HEADER"
	ParamLocCookie ParamLocation = "COOKIE"
)

// Asset represents a single entity in the attack-surface inventory.
type Asset struct {
	ID              string          `json:"id"`
	AssessmentID    string          `json:"assessment_id,omitempty"`
	ExecutionID     string          `json:"execution_id,omitempty"`
	TargetID        string          `json:"target_id,omitempty"`
	Type            AssetType       `json:"asset_type"`
	CanonicalID     string          `json:"canonical_id"`
	ParentID        string          `json:"parent_id,omitempty"`
	DisplayName     string          `json:"display_name"`
	SourceAsset     string          `json:"source_asset,omitempty"`
	DiscoveryMethod string          `json:"discovery_method"`
	DiscoveryStatus DiscoveryStatus `json:"discovery_status"`
	Confidence      Confidence      `json:"confidence"`
	InScope         bool            `json:"in_scope"`
	Metadata        map[string]any  `json:"metadata,omitempty"`
	Evidence        map[string]any  `json:"evidence,omitempty"`
	Fingerprint     string          `json:"fingerprint"`
	FirstSeen       time.Time       `json:"first_seen"`
	LastSeen        time.Time       `json:"last_seen"`

	// Typed details for common asset categories (Phase 1.2)
	Application *ApplicationDetails `json:"application,omitempty"`
	Host        *HostDetails        `json:"host,omitempty"`
	Endpoint    *EndpointDetails    `json:"endpoint,omitempty"`
	Service     *ServiceDetails     `json:"service,omitempty"`
	Database    *DatabaseDetails    `json:"database,omitempty"`
	Storage     *StorageDetails     `json:"storage,omitempty"`
	APK         *APKDetails         `json:"apk,omitempty"`
}

// ComputeStableAssetID produces a deterministic, collision-resistant identifier for an asset
// based on its type and canonical ID. The returned ID has the prefix "ast_".
func ComputeStableAssetID(aType AssetType, canonicalID string) string {
	raw := fmt.Sprintf("%s:%s", aType, strings.ToLower(strings.TrimSpace(canonicalID)))
	sum := sha256.Sum256([]byte(raw))
	return fmt.Sprintf("ast_%s", hex.EncodeToString(sum[:12]))
}

// SyncTypedDetailsToMetadata copies non-nil category details into the generic Metadata map
// ensuring that persistence stores (such as SQLite) retain typed information without schema changes.
func (a *Asset) SyncTypedDetailsToMetadata() {
	if a == nil {
		return
	}
	if a.Metadata == nil {
		a.Metadata = make(map[string]any)
	}

	if a.Application != nil {
		a.Metadata["application"] = a.Application
		if a.Application.RootURL != "" {
			a.Metadata["root_url"] = a.Application.RootURL
		}
	}
	if a.Host != nil {
		a.Metadata["host"] = a.Host
		if a.Host.Hostname != "" {
			a.Metadata["hostname"] = a.Host.Hostname
		}
	}
	if a.Endpoint != nil {
		a.Metadata["endpoint"] = a.Endpoint
		if a.Endpoint.Path != "" {
			a.Metadata["path"] = a.Endpoint.Path
		}
		if a.Endpoint.HTTPMethod != "" {
			a.Metadata["method"] = a.Endpoint.HTTPMethod
		}
		if a.Endpoint.URL != "" {
			a.Metadata["url"] = a.Endpoint.URL
		}
	}
	if a.Service != nil {
		a.Metadata["service"] = a.Service
		if a.Service.Port > 0 {
			a.Metadata["port"] = a.Service.Port
		}
	}
	if a.Database != nil {
		a.Metadata["database"] = a.Database
		if a.Database.Engine != "" {
			a.Metadata["engine"] = a.Database.Engine
		}
	}
	if a.Storage != nil {
		a.Metadata["storage"] = a.Storage
		if a.Storage.BucketName != "" {
			a.Metadata["bucket"] = a.Storage.BucketName
		}
	}
	if a.APK != nil {
		a.Metadata["apk"] = a.APK
		if a.APK.PackageName != "" {
			a.Metadata["package_name"] = a.APK.PackageName
		}
	}
}

// HydrateTypedDetailsFromMetadata re-populates typed detail structures from the generic Metadata map.
func (a *Asset) HydrateTypedDetailsFromMetadata() {
	if a == nil || a.Metadata == nil {
		return
	}

	rawToStruct := func(key string, target any) bool {
		if raw, ok := a.Metadata[key]; ok {
			bytes, err := json.Marshal(raw)
			if err == nil {
				return json.Unmarshal(bytes, target) == nil
			}
		}
		return false
	}

	if a.Application == nil && (a.Type == AssetTypeApplication) {
		var app ApplicationDetails
		if rawToStruct("application", &app) {
			a.Application = &app
		}
	}
	if a.Host == nil && (a.Type == AssetTypeHost || a.Type == AssetTypeDomain || a.Type == AssetTypeSubdomain) {
		var host HostDetails
		if rawToStruct("host", &host) {
			a.Host = &host
		}
	}
	if a.Endpoint == nil && (a.Type == AssetTypeEndpoint) {
		var ep EndpointDetails
		if rawToStruct("endpoint", &ep) {
			a.Endpoint = &ep
		}
	}
	if a.Service == nil && (a.Type == AssetTypeService || a.Type == AssetTypeWebService || a.Type == AssetTypeAPIService) {
		var svc ServiceDetails
		if rawToStruct("service", &svc) {
			a.Service = &svc
		}
	}
	if a.Database == nil && (a.Type == AssetTypeDatabase) {
		var db DatabaseDetails
		if rawToStruct("database", &db) {
			a.Database = &db
		}
	}
	if a.Storage == nil && (a.Type == AssetTypeStorage) {
		var st StorageDetails
		if rawToStruct("storage", &st) {
			a.Storage = &st
		}
	}
	if a.APK == nil && (a.Type == AssetTypeAPK) {
		var apk APKDetails
		if rawToStruct("apk", &apk) {
			a.APK = &apk
		}
	}
}

// ComputeFingerprint generates a stable SHA-256 fingerprint for deduplication.
func (a *Asset) ComputeFingerprint() string {
	raw := fmt.Sprintf("%s|%s|%s", a.Type, strings.ToLower(strings.TrimSpace(a.CanonicalID)), a.AssessmentID)
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}

// Relation represents a directed, evidence-backed edge between two inventory assets.
type Relation struct {
	ID            string       `json:"id"`
	AssessmentID  string       `json:"assessment_id"`
	ExecutionID   string       `json:"execution_id"`
	SourceAssetID string       `json:"source_asset_id"`
	TargetAssetID string       `json:"target_asset_id"`
	RelationType  RelationType `json:"relation_type"`
	Evidence      string       `json:"evidence,omitempty"`
	Confidence    Confidence   `json:"confidence"`
	CreatedAt     time.Time    `json:"created_at"`
}

// ComputeRelationFingerprint generates a stable identifier for a relation.
func ComputeRelationFingerprint(asmID, srcID, tgtID string, relType RelationType) string {
	raw := fmt.Sprintf("%s|%s|%s|%s", asmID, srcID, tgtID, relType)
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:16])
}

// Inventory encapsulates the complete attack-surface graph for an assessment run.
type Inventory struct {
	Assets    []Asset    `json:"assets"`
	Relations []Relation `json:"relations"`

	assetIndex    map[string]int      // canonicalID -> index in Assets
	relationIndex map[string]struct{} // fingerprint -> exists
}

// NewInventory initializes an empty Inventory structure.
func NewInventory() *Inventory {
	return &Inventory{
		Assets:        make([]Asset, 0),
		Relations:     make([]Relation, 0),
		assetIndex:    make(map[string]int),
		relationIndex: make(map[string]struct{}),
	}
}

// AddAsset inserts an asset or updates its LastSeen timestamp and merges metadata if already present.
// Returns the resolved stable ID of the asset.
func (inv *Inventory) AddAsset(a Asset) string {
	if a.CanonicalID != "" {
		a.ID = ComputeStableAssetID(a.Type, a.CanonicalID)
	} else if a.ID == "" {
		a.ID = ComputeStableAssetID(a.Type, a.DisplayName)
	}
	if a.FirstSeen.IsZero() {
		a.FirstSeen = time.Now().UTC()
	}
	if a.LastSeen.IsZero() {
		a.LastSeen = a.FirstSeen
	}
	if a.Fingerprint == "" {
		a.Fingerprint = a.ComputeFingerprint()
	}
	a.SyncTypedDetailsToMetadata()

	key := fmt.Sprintf("%s:%s", a.Type, strings.ToLower(strings.TrimSpace(a.CanonicalID)))
	if idx, exists := inv.assetIndex[key]; exists {
		// Existing asset: update last seen and merge metadata
		inv.Assets[idx].LastSeen = a.LastSeen
		if inv.Assets[idx].DiscoveryStatus == StatusInferred && a.DiscoveryStatus == StatusObserved {
			inv.Assets[idx].DiscoveryStatus = StatusObserved
		}
		if inv.Assets[idx].Application == nil && a.Application != nil {
			inv.Assets[idx].Application = a.Application
		}
		if inv.Assets[idx].Host == nil && a.Host != nil {
			inv.Assets[idx].Host = a.Host
		}
		if inv.Assets[idx].Endpoint == nil && a.Endpoint != nil {
			inv.Assets[idx].Endpoint = a.Endpoint
		}
		if inv.Assets[idx].Service == nil && a.Service != nil {
			inv.Assets[idx].Service = a.Service
		}
		if inv.Assets[idx].Database == nil && a.Database != nil {
			inv.Assets[idx].Database = a.Database
		}
		if inv.Assets[idx].Storage == nil && a.Storage != nil {
			inv.Assets[idx].Storage = a.Storage
		}
		if inv.Assets[idx].APK == nil && a.APK != nil {
			inv.Assets[idx].APK = a.APK
		}
		if inv.Assets[idx].Metadata == nil && a.Metadata != nil {
			inv.Assets[idx].Metadata = a.Metadata
		} else if a.Metadata != nil {
			for k, v := range a.Metadata {
				if _, ok := inv.Assets[idx].Metadata[k]; !ok {
					inv.Assets[idx].Metadata[k] = v
				}
			}
		}
		inv.Assets[idx].SyncTypedDetailsToMetadata()
		return inv.Assets[idx].ID
	}

	inv.assetIndex[key] = len(inv.Assets)
	inv.Assets = append(inv.Assets, a)
	return a.ID
}

// ValidateRelation checks that a relation has non-empty endpoints, is not self-referential,
// has a valid relation type, and satisfies type-compatibility rules if both endpoints exist in the inventory.
func (inv *Inventory) ValidateRelation(r Relation) error {
	if r.SourceAssetID == "" {
		return errors.New("source asset ID cannot be empty")
	}
	if r.TargetAssetID == "" {
		return errors.New("target asset ID cannot be empty")
	}
	if r.SourceAssetID == r.TargetAssetID {
		return errors.New("self-referential relations are prohibited")
	}
	if r.RelationType == "" {
		return errors.New("relation type cannot be empty")
	}

	src := inv.FindByID(r.SourceAssetID)
	tgt := inv.FindByID(r.TargetAssetID)
	if src != nil && tgt != nil {
		switch r.RelationType {
		case RelHostsApplication:
			if src.Type != AssetTypeHost && src.Type != AssetTypeDomain && src.Type != AssetTypeSubdomain {
				return fmt.Errorf("relation %s source must be HOST/DOMAIN, got %s", r.RelationType, src.Type)
			}
			if tgt.Type != AssetTypeApplication && tgt.Type != AssetTypeWebService {
				return fmt.Errorf("relation %s target must be APPLICATION/WEB_SERVICE, got %s", r.RelationType, tgt.Type)
			}
		case RelHostsService:
			if src.Type != AssetTypeHost && src.Type != AssetTypeDomain && src.Type != AssetTypeSubdomain {
				return fmt.Errorf("relation %s source must be HOST/DOMAIN, got %s", r.RelationType, src.Type)
			}
			if tgt.Type != AssetTypeService && tgt.Type != AssetTypeWebService && tgt.Type != AssetTypeAPIService && tgt.Type != AssetTypeDatabase {
				return fmt.Errorf("relation %s target must be SERVICE/DATABASE, got %s", r.RelationType, tgt.Type)
			}
		case RelExposesEndpoint:
			if src.Type != AssetTypeApplication && src.Type != AssetTypeWebService && src.Type != AssetTypeAPIService && src.Type != AssetTypeService && src.Type != AssetTypeHost {
				return fmt.Errorf("relation %s source must be APPLICATION/SERVICE/HOST, got %s", r.RelationType, src.Type)
			}
			if tgt.Type != AssetTypeEndpoint {
				return fmt.Errorf("relation %s target must be ENDPOINT, got %s", r.RelationType, tgt.Type)
			}
		case RelUsesDatabase:
			if src.Type != AssetTypeApplication && src.Type != AssetTypeWebService && src.Type != AssetTypeAPIService && src.Type != AssetTypeService {
				return fmt.Errorf("relation %s source must be APPLICATION/SERVICE, got %s", r.RelationType, src.Type)
			}
			if tgt.Type != AssetTypeDatabase && tgt.Type != AssetTypeCloudService {
				return fmt.Errorf("relation %s target must be DATABASE/CLOUD_SERVICE, got %s", r.RelationType, tgt.Type)
			}
		case RelUsesStorage:
			if src.Type != AssetTypeApplication && src.Type != AssetTypeWebService && src.Type != AssetTypeAPIService && src.Type != AssetTypeService {
				return fmt.Errorf("relation %s source must be APPLICATION/SERVICE, got %s", r.RelationType, src.Type)
			}
			if tgt.Type != AssetTypeStorage && tgt.Type != AssetTypeCloudService {
				return fmt.Errorf("relation %s target must be STORAGE_RESOURCE/CLOUD_SERVICE, got %s", r.RelationType, tgt.Type)
			}
		case RelAssociatedWithHost:
			if tgt.Type != AssetTypeHost && tgt.Type != AssetTypeDomain && tgt.Type != AssetTypeSubdomain {
				return fmt.Errorf("relation %s target must be HOST/DOMAIN, got %s", r.RelationType, tgt.Type)
			}
		}
	}

	return nil
}

// AddRelation records a directed relationship between two assets with deduplication.
func (inv *Inventory) AddRelation(r Relation) {
	if err := inv.ValidateRelation(r); err != nil {
		return
	}
	r.ID = fmt.Sprintf("rel_%s", ComputeRelationFingerprint(r.AssessmentID, r.SourceAssetID, r.TargetAssetID, r.RelationType))
	if r.CreatedAt.IsZero() {
		r.CreatedAt = time.Now().UTC()
	}

	key := fmt.Sprintf("%s->%s:%s", r.SourceAssetID, r.TargetAssetID, r.RelationType)
	if _, exists := inv.relationIndex[key]; exists {
		return
	}

	inv.relationIndex[key] = struct{}{}
	inv.Relations = append(inv.Relations, r)
}

// FindAsset locates an asset by type and canonical ID.
func (inv *Inventory) FindAsset(aType AssetType, canonicalID string) *Asset {
	key := fmt.Sprintf("%s:%s", aType, strings.ToLower(strings.TrimSpace(canonicalID)))
	if idx, exists := inv.assetIndex[key]; exists {
		return &inv.Assets[idx]
	}
	return nil
}

// FindByID locates an asset by its ID.
func (inv *Inventory) FindByID(id string) *Asset {
	for i := range inv.Assets {
		if inv.Assets[i].ID == id {
			return &inv.Assets[i]
		}
	}
	return nil
}

// FilterByType returns all assets matching the given type.
func (inv *Inventory) FilterByType(aType AssetType) []Asset {
	var results []Asset
	for _, a := range inv.Assets {
		if a.Type == aType {
			results = append(results, a)
		}
	}
	return results
}

// InventorySummary aggregates inventory metrics by category.
type InventorySummary struct {
	TotalAssets            int            `json:"total_assets"`
	InScopeAssets          int            `json:"in_scope_assets"`
	OutOfScopeAssets       int            `json:"out_of_scope_assets"`
	TotalRelations         int            `json:"total_relations"`
	DomainsCount           int            `json:"domains_count"`
	SubdomainsCount        int            `json:"subdomains_count"`
	HostsCount             int            `json:"hosts_count"`
	WebServicesCount       int            `json:"web_services_count"`
	ApplicationsCount      int            `json:"applications_count"`
	ServicesCount          int            `json:"services_count"`
	APIServicesCount       int            `json:"api_services_count"`
	EndpointsCount         int            `json:"endpoints_count"`
	DatabasesCount         int            `json:"databases_count"`
	StorageCount           int            `json:"storage_count"`
	APKCount               int            `json:"apk_count"`
	JavaScriptAssetsCount  int            `json:"javascript_assets_count"`
	OtherAssetsCount       int            `json:"other_assets_count"`
	ParametersCount        int            `json:"parameters_count"`
	FormsCount             int            `json:"forms_count"`
	AuthSurfacesCount      int            `json:"auth_surfaces_count"`
	CloudServicesCount     int            `json:"cloud_services_count"`
	TechnologiesCount      int            `json:"technologies_count"`
	CountsByType           map[string]int `json:"counts_by_type"`
}

// Summary calculates high-level attack surface metrics.
func (inv *Inventory) Summary() InventorySummary {
	s := InventorySummary{
		TotalAssets:    len(inv.Assets),
		TotalRelations: len(inv.Relations),
		CountsByType:   make(map[string]int),
	}

	for _, a := range inv.Assets {
		s.CountsByType[string(a.Type)]++
		if a.InScope {
			s.InScopeAssets++
		} else {
			s.OutOfScopeAssets++
		}

		switch a.Type {
		case AssetTypeDomain:
			s.DomainsCount++
		case AssetTypeSubdomain:
			s.SubdomainsCount++
		case AssetTypeHost:
			s.HostsCount++
		case AssetTypeWebService:
			s.WebServicesCount++
		case AssetTypeApplication:
			s.ApplicationsCount++
		case AssetTypeService:
			s.ServicesCount++
		case AssetTypeAPIService:
			s.APIServicesCount++
		case AssetTypeEndpoint:
			s.EndpointsCount++
		case AssetTypeDatabase:
			s.DatabasesCount++
		case AssetTypeStorage:
			s.StorageCount++
		case AssetTypeAPK:
			s.APKCount++
		case AssetTypeJavaScript:
			s.JavaScriptAssetsCount++
		case AssetTypeAsset:
			s.OtherAssetsCount++
		case AssetTypeParameter:
			s.ParametersCount++
		case AssetTypeForm:
			s.FormsCount++
		case AssetTypeAuthSurface:
			s.AuthSurfacesCount++
		case AssetTypeCloudService:
			s.CloudServicesCount++
		case AssetTypeTechnology:
			s.TechnologiesCount++
		}
	}
	return s
}
