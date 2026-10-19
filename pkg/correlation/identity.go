package correlation

import (
	"crypto/sha256"
	"fmt"
	"net"
	"net/url"
	"path"
	"sort"
	"strings"

	"felix/pkg/discovery"
	"felix/pkg/report"
	"felix/pkg/secrets"
)

// Sensitive query parameter keys that must be redacted in canonical URLs, keys, and display names.
var sensitiveQueryKeys = map[string]struct{}{
	"token":         {},
	"auth":          {},
	"authorization": {},
	"key":           {},
	"apikey":        {},
	"api_key":       {},
	"secret":        {},
	"password":      {},
	"pwd":           {},
	"pass":          {},
	"access_token":  {},
	"refresh_token": {},
	"session":       {},
	"session_id":    {},
	"sessionid":     {},
	"jwt":           {},
	"bearer":        {},
	"sig":           {},
	"signature":     {},
	"client_secret": {},
}

// CanonicalURL represents a thoroughly parsed and normalized URL for deterministic asset identification.
type CanonicalURL struct {
	RawURL          string `json:"raw_url,omitempty"`
	Scheme          string `json:"scheme"`
	Host            string `json:"host"`
	Port            string `json:"port,omitempty"`
	Path            string `json:"path"`
	Query           string `json:"query,omitempty"`            // Canonical identity query (non-reversible secret token hashes)
	DisplayQuery    string `json:"display_query,omitempty"`     // Display-safe query (secrets redacted to "REDACTED")
	Origin          string `json:"origin"`
	Endpoint        string `json:"endpoint"`                    // Canonical identity endpoint URL
	DisplayEndpoint string `json:"display_endpoint,omitempty"` // Display-safe endpoint URL for UI, stories, logs
	IsIPv6          bool   `json:"is_ipv6"`
}

// CanonicalAsset models the resolved entity that a finding demonstrably affects.
type CanonicalAsset struct {
	ID           string              `json:"id"`
	Type         discovery.AssetType `json:"asset_type"`
	CanonicalKey string              `json:"canonical_key"`
	DisplayName  string              `json:"display_name"`
	Scheme       string              `json:"scheme,omitempty"`
	Host         string              `json:"host,omitempty"`
	Port         string              `json:"port,omitempty"`
	Path         string              `json:"path,omitempty"`
	Method       string              `json:"method,omitempty"`
	ResourceID   string              `json:"resource_id,omitempty"`
	TenantID     string              `json:"tenant_id,omitempty"`
	Confidence   string              `json:"confidence"`
	IsExact      bool                `json:"is_exact"`
	Basis        string              `json:"basis"`
	Evidence     string              `json:"evidence,omitempty"`
}

// CanonicalizeURL parses and normalizes a raw URL string according to strict semantic rules:
// - Lowercases scheme and hostname.
// - Strips default ports (80 for http, 443 for https); preserves explicit non-default ports.
// - Trims trailing dots from hostname (e.g. example.com. -> example.com).
// - Normalizes IPv6 representation to canonical format via net.ParseIP.
// - Cleans relative path traversals while preserving distinct endpoints and trailing slashes.
// - Strips client-side fragments (#...).
// - Redacts sensitive query parameter values and sorts remaining parameters deterministically.
// - Never merges different schemes (http vs https) or different effective ports.
func CanonicalizeURL(rawURL string) (*CanonicalURL, error) {
	trimmed := strings.TrimSpace(rawURL)
	if trimmed == "" {
		return nil, fmt.Errorf("empty URL")
	}

	// Prepend scheme if missing
	if !strings.Contains(trimmed, "://") {
		if strings.HasPrefix(trimmed, "//") {
			trimmed = "https:" + trimmed
		} else {
			trimmed = "https://" + trimmed
		}
	}

	u, err := url.Parse(trimmed)
	if err != nil {
		return nil, fmt.Errorf("malformed URL: %w", err)
	}

	// 1. Strip embedded user credentials
	u.User = nil

	// 2. Lowercase scheme
	scheme := strings.ToLower(u.Scheme)
	if scheme != "http" && scheme != "https" {
		// Non-HTTP URI handled by caller or kept as-is
	}

	// 3. Lowercase host and handle trailing dots and ports
	rawHostname := u.Hostname()
	rawPort := u.Port()

	cleanHostname := strings.ToLower(strings.TrimSpace(rawHostname))
	cleanHostname = strings.TrimSuffix(cleanHostname, ".")

	isIPv6 := false
	if ip := net.ParseIP(cleanHostname); ip != nil {
		if ip.To4() == nil {
			isIPv6 = true
			cleanHostname = ip.String() // Canonical IPv6 format
		}
	}

	// Default port handling
	effectivePort := rawPort
	if (scheme == "http" && rawPort == "80") || (scheme == "https" && rawPort == "443") {
		effectivePort = ""
	}

	var formattedHost string
	if effectivePort != "" {
		if isIPv6 && !strings.HasPrefix(cleanHostname, "[") {
			formattedHost = fmt.Sprintf("[%s]:%s", cleanHostname, effectivePort)
		} else {
			formattedHost = net.JoinHostPort(cleanHostname, effectivePort)
		}
	} else {
		if isIPv6 && !strings.HasPrefix(cleanHostname, "[") {
			formattedHost = fmt.Sprintf("[%s]", cleanHostname)
		} else {
			formattedHost = cleanHostname
		}
	}

	if formattedHost == "" {
		return nil, fmt.Errorf("URL has empty host: %q", rawURL)
	}

	// 4. Origin: scheme://formattedHost
	origin := fmt.Sprintf("%s://%s", scheme, formattedHost)

	// 5. Clean path: preserve encoded slashes (%2F) and trailing slashes on non-root paths
	sourcePath := u.Path
	hasEncodedSlash := strings.Contains(u.RawPath, "%2F") || strings.Contains(u.RawPath, "%2f") ||
		strings.Contains(trimmed, "%2F") || strings.Contains(trimmed, "%2f")
	if hasEncodedSlash {
		targetPath := u.RawPath
		if targetPath == "" {
			targetPath = u.EscapedPath()
		}
		masked := strings.ReplaceAll(targetPath, "%2F", "___ESCAPED_SLASH___")
		masked = strings.ReplaceAll(masked, "%2f", "___ESCAPED_SLASH___")
		cleanedMasked := path.Clean(masked)
		sourcePath = strings.ReplaceAll(cleanedMasked, "___ESCAPED_SLASH___", "%2F")
	} else {
		sourcePath = path.Clean(sourcePath)
	}

	cleanPath := sourcePath
	if cleanPath == "." || cleanPath == "" {
		cleanPath = "/"
	} else if strings.HasSuffix(u.Path, "/") && !strings.HasSuffix(cleanPath, "/") {
		cleanPath += "/"
	}

	// 6. Query sanitization & deterministic sorting
	cleanQuery := ""
	displayQuery := ""
	if u.RawQuery != "" {
		q := u.Query()
		var sortedKeys []string
		for k := range q {
			sortedKeys = append(sortedKeys, k)
		}
		sort.Strings(sortedKeys)

		newValues := url.Values{}
		displayValues := url.Values{}
		for _, k := range sortedKeys {
			lowerK := strings.ToLower(k)
			_, isSensitive := sensitiveQueryKeys[lowerK]
			if !isSensitive {
				isSensitive = secrets.IsSensitiveQueryParam(k)
			}

			vals := q[k]
			sort.Strings(vals)
			for _, v := range vals {
				if isSensitive {
					displayValues.Add(k, "REDACTED")
					// For identity, use non-reversible cryptographic hash to avoid collapsing distinct tokens
					if v == "REDACTED" || v == "[REDACTED]" || strings.HasPrefix(v, "REDACTED_") {
						newValues.Add(k, v)
					} else {
						h := sha256.Sum256([]byte(v))
						newValues.Add(k, fmt.Sprintf("REDACTED_%x", h[:6]))
					}
				} else {
					if red := secrets.RedactText(v); red != v {
						displayValues.Add(k, "REDACTED")
						h := sha256.Sum256([]byte(v))
						newValues.Add(k, fmt.Sprintf("REDACTED_%x", h[:6]))
					} else {
						displayValues.Add(k, v)
						newValues.Add(k, v)
					}
				}
			}
		}
		cleanQuery = newValues.Encode()
		displayQuery = displayValues.Encode()
	}

	// 7. Full endpoint URLs (excluding fragment)
	var endpointURL, displayEndpointURL string
	if cleanPath == "/" && cleanQuery == "" {
		endpointURL = origin
		displayEndpointURL = origin
	} else {
		if cleanQuery != "" {
			endpointURL = fmt.Sprintf("%s%s?%s", origin, cleanPath, cleanQuery)
		} else {
			endpointURL = fmt.Sprintf("%s%s", origin, cleanPath)
		}

		if displayQuery != "" {
			displayEndpointURL = fmt.Sprintf("%s%s?%s", origin, cleanPath, displayQuery)
		} else {
			displayEndpointURL = fmt.Sprintf("%s%s", origin, cleanPath)
		}
	}

	return &CanonicalURL{
		RawURL:          trimmed,
		Scheme:          scheme,
		Host:            cleanHostname,
		Port:            effectivePort,
		Path:            cleanPath,
		Query:           cleanQuery,
		DisplayQuery:    displayQuery,
		Origin:          origin,
		Endpoint:        endpointURL,
		DisplayEndpoint: displayEndpointURL,
		IsIPv6:          isIPv6,
	}, nil
}

// ResolveFindingAsset resolves the primary canonical asset affected by a finding.
// It prioritizes explicit inventory bindings, followed by cloud resource IDs,
// mobile APK packages, specific API/Web endpoints, and host/domain assets.
func ResolveFindingAsset(f report.Finding, inv *discovery.Inventory) (*CanonicalAsset, AssetAssociation) {
	// 1. Explicit Inventory Binding
	if f.PrimaryAssetID != "" && inv != nil {
		if matched := inv.FindByID(f.PrimaryAssetID); matched != nil {
			canonKey := matched.CanonicalID
			if canonKey == "" {
				canonKey = matched.DisplayName
			}
			disp := matched.DisplayName
			if disp == "" {
				disp = canonKey
			}
			asset := &CanonicalAsset{
				ID:           matched.ID,
				Type:         matched.Type,
				CanonicalKey: canonKey,
				DisplayName:  disp,
				Confidence:   string(matched.Confidence),
				IsExact:      true,
				Basis:        "EXPLICIT_INVENTORY",
				Evidence:     fmt.Sprintf("Matched inventory asset %s (%s)", matched.ID, matched.Type),
			}
			assoc := AssetAssociation{
				FindingID:    f.ID,
				AssetID:      asset.ID,
				AssetType:    asset.Type,
				CanonicalKey: asset.CanonicalKey,
				DisplayName:  asset.DisplayName,
				Basis:        asset.Basis,
				Confidence:   asset.Confidence,
				IsExact:      asset.IsExact,
				Evidence:     asset.Evidence,
			}
			return asset, assoc
		}
	}

	// 2. Cloud Storage Resource (S3, GCS, Azure Blob)
	if storageAsset, ok := extractCloudStorageAsset(f); ok {
		assoc := AssetAssociation{
			FindingID:    f.ID,
			AssetID:      storageAsset.ID,
			AssetType:    storageAsset.Type,
			CanonicalKey: storageAsset.CanonicalKey,
			DisplayName:  storageAsset.DisplayName,
			Basis:        storageAsset.Basis,
			Confidence:   storageAsset.Confidence,
			IsExact:      storageAsset.IsExact,
			Evidence:     storageAsset.Evidence,
		}
		return storageAsset, assoc
	}

	// 3. Database Resource (Supabase, Firebase, Relational)
	if dbAsset, ok := extractDatabaseAsset(f); ok {
		assoc := AssetAssociation{
			FindingID:    f.ID,
			AssetID:      dbAsset.ID,
			AssetType:    dbAsset.Type,
			CanonicalKey: dbAsset.CanonicalKey,
			DisplayName:  dbAsset.DisplayName,
			Basis:        dbAsset.Basis,
			Confidence:   dbAsset.Confidence,
			IsExact:      dbAsset.IsExact,
			Evidence:     dbAsset.Evidence,
		}
		return dbAsset, assoc
	}

	// 4. Mobile APK Artifact
	if apkAsset, ok := extractAPKAsset(f); ok {
		assoc := AssetAssociation{
			FindingID:    f.ID,
			AssetID:      apkAsset.ID,
			AssetType:    apkAsset.Type,
			CanonicalKey: apkAsset.CanonicalKey,
			DisplayName:  apkAsset.DisplayName,
			Basis:        apkAsset.Basis,
			Confidence:   apkAsset.Confidence,
			IsExact:      apkAsset.IsExact,
			Evidence:     apkAsset.Evidence,
		}
		return apkAsset, assoc
	}

	// 5. Web & API Endpoints
	rawEndpoint := f.Endpoint
	if rawEndpoint == "" {
		rawEndpoint = f.Target
	}

	rawEndpoint = strings.TrimSpace(rawEndpoint)
	if rawEndpoint == "" {
		// Unresolved
		assetID := discovery.ComputeStableAssetID(discovery.AssetTypeAsset, "unresolved")
		unresolvedAsset := &CanonicalAsset{
			ID:           assetID,
			Type:         discovery.AssetTypeAsset,
			CanonicalKey: "unresolved",
			DisplayName:  "Unresolved Asset",
			Confidence:   report.ConfidenceLow,
			IsExact:      false,
			Basis:        "UNRESOLVED_MISSING_TARGET",
			Evidence:     "Finding lacks target and endpoint attributes",
		}
		assoc := AssetAssociation{
			FindingID:    f.ID,
			AssetID:      unresolvedAsset.ID,
			AssetType:    unresolvedAsset.Type,
			CanonicalKey: unresolvedAsset.CanonicalKey,
			DisplayName:  unresolvedAsset.DisplayName,
			Basis:        unresolvedAsset.Basis,
			Confidence:   unresolvedAsset.Confidence,
			IsExact:      false,
			Evidence:     unresolvedAsset.Evidence,
		}
		return unresolvedAsset, assoc
	}

	canonURL, err := CanonicalizeURL(rawEndpoint)
	if err != nil {
		// Malformed URL: record weak unresolved association rather than guessing
		assetID := discovery.ComputeStableAssetID(discovery.AssetTypeAsset, "malformed:"+secrets.SanitizeURL(rawEndpoint))
		malformedAsset := &CanonicalAsset{
			ID:           assetID,
			Type:         discovery.AssetTypeAsset,
			CanonicalKey: "malformed:" + secrets.SanitizeURL(rawEndpoint),
			DisplayName:  secrets.SanitizeURL(rawEndpoint),
			Confidence:   report.ConfidenceLow,
			IsExact:      false,
			Basis:        "UNRESOLVED_MALFORMED_URL",
			Evidence:     fmt.Sprintf("Failed to parse URL %q: %v", secrets.SanitizeURL(rawEndpoint), err),
		}
		assoc := AssetAssociation{
			FindingID:    f.ID,
			AssetID:      malformedAsset.ID,
			AssetType:    malformedAsset.Type,
			CanonicalKey: malformedAsset.CanonicalKey,
			DisplayName:  malformedAsset.DisplayName,
			Basis:        malformedAsset.Basis,
			Confidence:   malformedAsset.Confidence,
			IsExact:      false,
			Evidence:     malformedAsset.Evidence,
		}
		return malformedAsset, assoc
	}

	method := report.NormalizeMethod(f.Method)
	if method == "" {
		method = "GET"
	}

	// Tenant qualifier
	tenantID := ""
	if f.EvidenceDetails.Details != nil {
		tenantID = f.EvidenceDetails.Details["tenant_id"]
		if tenantID == "" {
			tenantID = f.EvidenceDetails.Details["account_id"]
		}
	}

	displayEndpoint := canonURL.DisplayEndpoint
	if displayEndpoint == "" {
		displayEndpoint = canonURL.Endpoint
	}

	// Distinguish endpoint asset vs origin application asset:
	// If the endpoint specifies a non-root path or method, it is primarily an Endpoint asset.
	hasSpecificRoute := canonURL.Path != "" && canonURL.Path != "/"
	if hasSpecificRoute || canonURL.Query != "" {
		canonEndpointKey := fmt.Sprintf("%s:%s", method, canonURL.Endpoint)
		if tenantID != "" {
			canonEndpointKey = fmt.Sprintf("tenant:%s:%s", tenantID, canonEndpointKey)
		}
		endpointAssetID := discovery.ComputeStableAssetID(discovery.AssetTypeEndpoint, canonEndpointKey)
		epAsset := &CanonicalAsset{
			ID:           endpointAssetID,
			Type:         discovery.AssetTypeEndpoint,
			CanonicalKey: canonEndpointKey,
			DisplayName:  fmt.Sprintf("%s %s", method, displayEndpoint),
			Scheme:       canonURL.Scheme,
			Host:         canonURL.Host,
			Port:         canonURL.Port,
			Path:         canonURL.Path,
			Method:       method,
			TenantID:     tenantID,
			Confidence:   report.ConfidenceHigh,
			IsExact:      true,
			Basis:        "EXACT_ENDPOINT",
			Evidence:     fmt.Sprintf("Direct endpoint match: %s %s", method, displayEndpoint),
		}
		assoc := AssetAssociation{
			FindingID:    f.ID,
			AssetID:      epAsset.ID,
			AssetType:    epAsset.Type,
			CanonicalKey: epAsset.CanonicalKey,
			DisplayName:  epAsset.DisplayName,
			Basis:        epAsset.Basis,
			Confidence:   epAsset.Confidence,
			IsExact:      true,
			Evidence:     epAsset.Evidence,
		}
		return epAsset, assoc
	}

	// Root application asset
	appKey := canonURL.Origin
	if tenantID != "" {
		appKey = fmt.Sprintf("tenant:%s:%s", tenantID, canonURL.Origin)
	}
	appAssetID := discovery.ComputeStableAssetID(discovery.AssetTypeApplication, appKey)
	appAsset := &CanonicalAsset{
		ID:           appAssetID,
		Type:         discovery.AssetTypeApplication,
		CanonicalKey: appKey,
		DisplayName:  canonURL.Origin,
		Scheme:       canonURL.Scheme,
		Host:         canonURL.Host,
		Port:         canonURL.Port,
		Path:         "/",
		TenantID:     tenantID,
		Confidence:   report.ConfidenceHigh,
		IsExact:      true,
		Basis:        "CANONICAL_APPLICATION",
		Evidence:     fmt.Sprintf("Origin application match: %s", canonURL.Origin),
	}
	assoc := AssetAssociation{
		FindingID:    f.ID,
		AssetID:      appAsset.ID,
		AssetType:    appAsset.Type,
		CanonicalKey: appAsset.CanonicalKey,
		DisplayName:  appAsset.DisplayName,
		Basis:        appAsset.Basis,
		Confidence:   appAsset.Confidence,
		IsExact:      true,
		Evidence:     appAsset.Evidence,
	}
	return appAsset, assoc
}

// ResolveFindingAffectedAssets generates the complete hierarchy of affected asset IDs
// (e.g., Endpoint -> Application -> Host).
func ResolveFindingAffectedAssets(f report.Finding, primary *CanonicalAsset, inv *discovery.Inventory) []string {
	seen := make(map[string]bool)
	var out []string

	add := func(id string) {
		clean := strings.TrimSpace(id)
		if clean != "" && !seen[clean] {
			seen[clean] = true
			out = append(out, clean)
		}
	}

	// 1. Primary asset
	if primary != nil && primary.ID != "" {
		add(primary.ID)
	}

	// 2. Pre-existing finding affected assets
	for _, id := range f.AffectedAssetIDs {
		add(id)
	}

	// 3. Hierarchical parents
	if primary != nil {
		if primary.TenantID != "" {
			tenantAssetID := discovery.ComputeStableAssetID(discovery.AssetTypeAsset, "tenant:"+primary.TenantID)
			add(tenantAssetID)
		}
		if primary.Type == discovery.AssetTypeEndpoint && primary.Scheme != "" && primary.Host != "" {
			var formattedHost string
			if primary.Port != "" {
				formattedHost = net.JoinHostPort(primary.Host, primary.Port)
			} else {
				formattedHost = primary.Host
			}
			origin := fmt.Sprintf("%s://%s", primary.Scheme, formattedHost)
			appKey := origin
			if primary.TenantID != "" {
				appKey = fmt.Sprintf("tenant:%s:%s", primary.TenantID, origin)
			}
			appID := discovery.ComputeStableAssetID(discovery.AssetTypeApplication, appKey)
			add(appID)

			hostKey := primary.Host
			if primary.TenantID != "" {
				hostKey = fmt.Sprintf("tenant:%s:%s", primary.TenantID, primary.Host)
			}
			hostID := discovery.ComputeStableAssetID(discovery.AssetTypeHost, hostKey)
			add(hostID)
		} else if primary.Type == discovery.AssetTypeApplication && primary.Host != "" {
			hostKey := primary.Host
			if primary.TenantID != "" {
				hostKey = fmt.Sprintf("tenant:%s:%s", primary.TenantID, primary.Host)
			}
			hostID := discovery.ComputeStableAssetID(discovery.AssetTypeHost, hostKey)
			add(hostID)
		}
	}

	sort.Strings(out)
	return out
}

func extractCloudStorageAsset(f report.Finding) (*CanonicalAsset, bool) {
	cat := report.NormalizeCategory(f.Category)
	src := f.Source
	ep := f.Endpoint
	if ep == "" {
		ep = f.Target
	}

	var bucket, provider, tenantID string
	if f.EvidenceDetails.Details != nil {
		bucket = f.EvidenceDetails.Details["bucket"]
		if bucket == "" {
			bucket = f.EvidenceDetails.Details["bucket_name"]
		}
		provider = f.EvidenceDetails.Details["cloud_provider"]
		tenantID = f.EvidenceDetails.Details["tenant_id"]
		if tenantID == "" {
			tenantID = f.EvidenceDetails.Details["account_id"]
		}
	}

	epLower := strings.ToLower(ep)
	if bucket == "" {
		if strings.HasPrefix(epLower, "s3://") {
			parts := strings.Split(strings.TrimPrefix(ep, "s3://"), "/")
			bucket = parts[0]
			provider = "aws_s3"
		} else if strings.HasPrefix(epLower, "gs://") {
			parts := strings.Split(strings.TrimPrefix(ep, "gs://"), "/")
			bucket = parts[0]
			provider = "gcp_storage"
		} else if strings.Contains(epLower, ".s3.amazonaws.com") {
			u, _ := url.Parse(ep)
			if u != nil {
				bucket = strings.TrimSuffix(strings.ToLower(u.Hostname()), ".s3.amazonaws.com")
				provider = "aws_s3"
			}
		} else if strings.Contains(epLower, ".blob.core.windows.net") {
			u, _ := url.Parse(ep)
			if u != nil {
				parts := strings.Split(strings.TrimPrefix(u.Path, "/"), "/")
				if len(parts) > 0 && parts[0] != "" {
					bucket = fmt.Sprintf("%s/%s", u.Hostname(), parts[0])
				} else {
					bucket = u.Hostname()
				}
				provider = "azure_blob"
			}
		}
	}

	isStorage := src == report.SourceCloud ||
		strings.Contains(cat, "s3") ||
		strings.Contains(cat, "blob") ||
		strings.Contains(cat, "gcs") ||
		strings.Contains(cat, "storage") ||
		bucket != ""

	if !isStorage || bucket == "" {
		return nil, false
	}

	if provider == "" {
		provider = "cloud_storage"
	}

	cleanBucket := strings.ToLower(strings.TrimSpace(bucket))
	canonKey := fmt.Sprintf("storage:%s:%s", provider, cleanBucket)
	if tenantID != "" {
		canonKey = fmt.Sprintf("storage:%s:tenant:%s:%s", provider, tenantID, cleanBucket)
	}
	assetID := discovery.ComputeStableAssetID(discovery.AssetTypeStorage, canonKey)

	return &CanonicalAsset{
		ID:           assetID,
		Type:         discovery.AssetTypeStorage,
		CanonicalKey: canonKey,
		DisplayName:  fmt.Sprintf("%s bucket: %s", provider, cleanBucket),
		ResourceID:   cleanBucket,
		TenantID:     tenantID,
		Confidence:   report.ConfidenceHigh,
		IsExact:      true,
		Basis:        "CLOUD_STORAGE_RESOURCE",
		Evidence:     fmt.Sprintf("Identified %s storage resource: %s", provider, cleanBucket),
	}, true
}

func extractDatabaseAsset(f report.Finding) (*CanonicalAsset, bool) {
	cat := report.NormalizeCategory(f.Category)
	ep := f.Endpoint
	if ep == "" {
		ep = f.Target
	}

	var projID, engine, tenantID string
	if f.EvidenceDetails.Details != nil {
		projID = f.EvidenceDetails.Details["project_id"]
		if projID == "" {
			projID = f.EvidenceDetails.Details["database_name"]
		}
		engine = f.EvidenceDetails.Details["database_engine"]
		tenantID = f.EvidenceDetails.Details["tenant_id"]
		if tenantID == "" {
			tenantID = f.EvidenceDetails.Details["account_id"]
		}
	}

	epLower := strings.ToLower(ep)
	if projID == "" {
		if strings.Contains(epLower, ".supabase.co") {
			u, _ := url.Parse(ep)
			if u != nil {
				projID = strings.TrimSuffix(strings.ToLower(u.Hostname()), ".supabase.co")
				engine = "supabase_postgres"
			}
		} else if strings.Contains(epLower, ".firebaseio.com") {
			u, _ := url.Parse(ep)
			if u != nil {
				projID = strings.TrimSuffix(strings.ToLower(u.Hostname()), ".firebaseio.com")
				engine = "firebase_rtdb"
			}
		}
	}

	isDB := strings.Contains(cat, "supabase") ||
		strings.Contains(cat, "firebase") ||
		strings.Contains(cat, "database") ||
		projID != ""

	if !isDB || projID == "" {
		return nil, false
	}

	if engine == "" {
		engine = "database"
	}

	cleanProj := strings.ToLower(strings.TrimSpace(projID))
	canonKey := fmt.Sprintf("database:%s:%s", engine, cleanProj)
	if tenantID != "" {
		canonKey = fmt.Sprintf("database:%s:tenant:%s:%s", engine, tenantID, cleanProj)
	}
	assetID := discovery.ComputeStableAssetID(discovery.AssetTypeDatabase, canonKey)

	return &CanonicalAsset{
		ID:           assetID,
		Type:         discovery.AssetTypeDatabase,
		CanonicalKey: canonKey,
		DisplayName:  fmt.Sprintf("%s instance: %s", engine, cleanProj),
		ResourceID:   cleanProj,
		TenantID:     tenantID,
		Confidence:   report.ConfidenceHigh,
		IsExact:      true,
		Basis:        "DATABASE_RESOURCE",
		Evidence:     fmt.Sprintf("Identified %s database instance: %s", engine, cleanProj),
	}, true
}

func extractAPKAsset(f report.Finding) (*CanonicalAsset, bool) {
	cat := report.NormalizeCategory(f.Category)
	src := f.Source

	var pkgName, tenantID string
	if f.EvidenceDetails.Details != nil {
		pkgName = f.EvidenceDetails.Details["package_name"]
		if pkgName == "" {
			pkgName = f.EvidenceDetails.Details["app_id"]
		}
		tenantID = f.EvidenceDetails.Details["tenant_id"]
		if tenantID == "" {
			tenantID = f.EvidenceDetails.Details["account_id"]
		}
	}

	isAPK := src == "apk" ||
		strings.Contains(cat, "apk") ||
		strings.Contains(cat, "mobile") ||
		pkgName != ""

	if !isAPK || pkgName == "" {
		return nil, false
	}

	cleanPkg := strings.ToLower(strings.TrimSpace(pkgName))
	canonKey := fmt.Sprintf("apk:%s", cleanPkg)
	if tenantID != "" {
		canonKey = fmt.Sprintf("apk:tenant:%s:%s", tenantID, cleanPkg)
	}
	assetID := discovery.ComputeStableAssetID(discovery.AssetTypeAPK, canonKey)

	return &CanonicalAsset{
		ID:           assetID,
		Type:         discovery.AssetTypeAPK,
		CanonicalKey: canonKey,
		DisplayName:  fmt.Sprintf("Android Package: %s", cleanPkg),
		ResourceID:   cleanPkg,
		TenantID:     tenantID,
		Confidence:   report.ConfidenceHigh,
		IsExact:      true,
		Basis:        "APK_PACKAGE",
		Evidence:     fmt.Sprintf("Identified APK package: %s", cleanPkg),
	}, true
}
