package discovery

import (
	"crypto/sha256"
	"encoding/hex"
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
)

// RelationType defines the directed relationship between two inventory assets.
type RelationType string

const (
	RelHasSubdomain            RelationType = "HAS_SUBDOMAIN"
	RelExposesService          RelationType = "EXPOSES_SERVICE"
	RelExposesApplication      RelationType = "EXPOSES_APPLICATION"
	RelUsesAPI                 RelationType = "USES_API"
	RelLoadsJavaScript         RelationType = "LOADS_JAVASCRIPT"
	RelReferencesEndpoint      RelationType = "REFERENCES_ENDPOINT"
	RelAcceptsParameter        RelationType = "ACCEPTS_PARAMETER"
	RelContainsForm            RelationType = "CONTAINS_FORM"
	RelHasInput                RelationType = "HAS_INPUT"
	RelExposesAuthSurface      RelationType = "EXPOSES_AUTH_SURFACE"
	RelReferencesCloudService  RelationType = "REFERENCES_CLOUD_SERVICE"
	RelUsesTechnology          RelationType = "USES_TECHNOLOGY"
	RelResolvedTo              RelationType = "RESOLVED_TO"
)

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
	AssessmentID    string          `json:"assessment_id"`
	ExecutionID     string          `json:"execution_id"`
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
	if a.FirstSeen.IsZero() {
		a.FirstSeen = time.Now().UTC()
	}
	if a.LastSeen.IsZero() {
		a.LastSeen = a.FirstSeen
	}
	if a.Fingerprint == "" {
		a.Fingerprint = a.ComputeFingerprint()
	}

	key := fmt.Sprintf("%s:%s", a.Type, strings.ToLower(strings.TrimSpace(a.CanonicalID)))
	if idx, exists := inv.assetIndex[key]; exists {
		// Existing asset: update last seen and merge metadata
		inv.Assets[idx].LastSeen = a.LastSeen
		if inv.Assets[idx].DiscoveryStatus == StatusInferred && a.DiscoveryStatus == StatusObserved {
			inv.Assets[idx].DiscoveryStatus = StatusObserved
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
		return inv.Assets[idx].ID
	}

	inv.assetIndex[key] = len(inv.Assets)
	inv.Assets = append(inv.Assets, a)
	return a.ID
}

// AddRelation records a directed relationship between two assets with deduplication.
func (inv *Inventory) AddRelation(r Relation) {
	if r.SourceAssetID == "" || r.TargetAssetID == "" || r.SourceAssetID == r.TargetAssetID {
		return
	}
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
	WebServicesCount       int            `json:"web_services_count"`
	ApplicationsCount      int            `json:"applications_count"`
	APIServicesCount       int            `json:"api_services_count"`
	EndpointsCount         int            `json:"endpoints_count"`
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
		case AssetTypeWebService:
			s.WebServicesCount++
		case AssetTypeApplication:
			s.ApplicationsCount++
		case AssetTypeAPIService:
			s.APIServicesCount++
		case AssetTypeEndpoint:
			s.EndpointsCount++
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
