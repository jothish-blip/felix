package discovery

import (
	"fmt"
	"net"
	"net/url"
	"path"
	"sort"
	"strings"
	"time"

	"felix/pkg/api"
	"felix/pkg/cloud"
	"felix/pkg/crawler"
	"felix/pkg/secrets"
)

// Sensitive query parameter keys that must be redacted in canonical IDs and display names.
var sensitiveParamKeys = map[string]struct{}{
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

// SanitizeURLForCanonicalID parses, normalizes, strips embedded credentials,
// redacts sensitive query parameters, and sorts remaining query parameters.
func SanitizeURLForCanonicalID(rawURL string) (*url.URL, error) {
	trimmed := strings.TrimSpace(rawURL)
	if trimmed == "" {
		return nil, fmt.Errorf("empty URL")
	}

	// Prepend scheme if missing but looks like host or path
	if !strings.Contains(trimmed, "://") {
		if strings.HasPrefix(trimmed, "//") {
			trimmed = "https:" + trimmed
		} else {
			trimmed = "http://" + trimmed
		}
	}

	u, err := url.Parse(trimmed)
	if err != nil {
		return nil, err
	}

	// 1. Strip user credentials
	u.User = nil

	// 2. Normalize scheme to lowercase
	u.Scheme = strings.ToLower(u.Scheme)

	// 3. Normalize host and strip default ports
	hostname := strings.ToLower(u.Hostname())
	port := u.Port()

	// Strip trailing dot from hostname
	hostname = strings.TrimSuffix(hostname, ".")

	var host string
	if (u.Scheme == "http" && port == "80") || (u.Scheme == "https" && port == "443") {
		host = hostname
	} else if port != "" {
		host = net.JoinHostPort(hostname, port)
	} else {
		host = hostname
	}
	u.Host = host

	// 4. Normalize path: clean relative traversals
	cleanPath := path.Clean(u.Path)
	if cleanPath == "." || cleanPath == "" {
		cleanPath = "/"
	} else if strings.HasSuffix(u.Path, "/") && !strings.HasSuffix(cleanPath, "/") {
		cleanPath += "/"
	}
	u.Path = cleanPath

	// 5. Sanitize and sort query parameters
	if u.RawQuery != "" {
		q := u.Query()
		var sortedKeys []string
		for k := range q {
			sortedKeys = append(sortedKeys, k)
		}
		sort.Strings(sortedKeys)

		newValues := url.Values{}
		for _, k := range sortedKeys {
			lowerK := strings.ToLower(k)
			if _, isSensitive := sensitiveParamKeys[lowerK]; isSensitive {
				newValues.Set(k, "REDACTED")
			} else {
				vals := q[k]
				sort.Strings(vals)
				for _, v := range vals {
					if red := secrets.RedactText(v); red != v {
						newValues.Add(k, "REDACTED")
					} else {
						newValues.Add(k, v)
					}
				}
			}
		}
		u.RawQuery = newValues.Encode()
	}

	// 6. Strip fragment
	u.Fragment = ""

	return u, nil
}

// NormalizeApplicationCanonicalID produces a canonical identifier for an application.
func NormalizeApplicationCanonicalID(rawURLOrHost string) string {
	u, err := SanitizeURLForCanonicalID(rawURLOrHost)
	if err == nil {
		// Base application identity is scheme://host
		return fmt.Sprintf("%s://%s", u.Scheme, u.Host)
	}
	// Fallback to lowercased hostname
	return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(rawURLOrHost), "."))
}

// NormalizeHostCanonicalID normalizes a hostname or IP string into canonical representation.
func NormalizeHostCanonicalID(hostOrIP string) (canonical string, ipStr string, hostname string) {
	trimmed := strings.ToLower(strings.TrimSpace(hostOrIP))

	// Strip URL scheme if present
	if idx := strings.Index(trimmed, "://"); idx != -1 {
		trimmed = trimmed[idx+3:]
	}

	// Strip embedded credentials if user:pass@host
	if idx := strings.LastIndex(trimmed, "@"); idx != -1 {
		trimmed = trimmed[idx+1:]
	}

	// Strip path, query or fragment
	if idx := strings.IndexAny(trimmed, "/?#"); idx != -1 {
		trimmed = trimmed[:idx]
	}

	// Strip port if present
	if h, _, err := net.SplitHostPort(trimmed); err == nil {
		trimmed = h
	}

	// Trim trailing dot
	trimmed = strings.TrimSuffix(trimmed, ".")

	// Parse as IP
	if ip := net.ParseIP(trimmed); ip != nil {
		canonIP := ip.String()
		return canonIP, canonIP, ""
	}

	// Hostname
	return trimmed, "", trimmed
}

// NormalizeEndpointCanonicalID canonicalizes method and URL for an endpoint asset.
func NormalizeEndpointCanonicalID(method, rawURL string) (canonicalID string, cleanPath string, cleanURL string) {
	normMethod := strings.ToUpper(strings.TrimSpace(method))
	if normMethod == "" {
		normMethod = "GET"
	}

	u, err := SanitizeURLForCanonicalID(rawURL)
	if err != nil {
		cleanURL = strings.TrimSpace(rawURL)
		cleanPath = cleanURL
		return fmt.Sprintf("%s:%s", normMethod, cleanURL), cleanPath, cleanURL
	}

	cleanURL = u.String()
	cleanPath = u.Path
	return fmt.Sprintf("%s:%s", normMethod, cleanURL), cleanPath, cleanURL
}

// NormalizeServiceCanonicalID formats a service into host:port/proto canonical identity.
func NormalizeServiceCanonicalID(host string, port int, proto string) string {
	canonHost, _, _ := NormalizeHostCanonicalID(host)
	normProto := strings.ToLower(strings.TrimSpace(proto))
	if normProto == "" {
		normProto = "tcp"
	}
	return fmt.Sprintf("%s:%d/%s", canonHost, port, normProto)
}

// NormalizeDatabaseCanonicalID creates a canonical identifier for a database instance.
func NormalizeDatabaseCanonicalID(engine, host string, port int, dbName string) string {
	canonEngine := strings.ToLower(strings.TrimSpace(engine))
	if canonEngine == "" {
		canonEngine = "database"
	}
	// Strip credentials if embedded in host
	if strings.Contains(host, "@") {
		if idx := strings.LastIndex(host, "@"); idx != -1 {
			host = host[idx+1:]
		}
	}
	canonHost, _, _ := NormalizeHostCanonicalID(host)
	cleanDB := strings.Trim(strings.TrimSpace(dbName), "/")
	if idx := strings.IndexAny(cleanDB, "?#"); idx != -1 {
		cleanDB = cleanDB[:idx]
	}
	if cleanDB != "" {
		return fmt.Sprintf("%s://%s:%d/%s", canonEngine, canonHost, port, cleanDB)
	}
	return fmt.Sprintf("%s://%s:%d", canonEngine, canonHost, port)
}

// NormalizeStorageCanonicalID produces a canonical identifier for a storage bucket/share.
func NormalizeStorageCanonicalID(provider, bucketOrShare string) string {
	canonProv := strings.ToLower(strings.TrimSpace(provider))
	if canonProv == "" {
		canonProv = "storage"
	}
	cleanBucket := strings.Trim(strings.ToLower(strings.TrimSpace(bucketOrShare)), "/")
	if idx := strings.IndexAny(cleanBucket, "?#"); idx != -1 {
		cleanBucket = cleanBucket[:idx]
	}
	if strings.Contains(cleanBucket, "://") {
		if parsed, err := url.Parse(cleanBucket); err == nil && parsed.Host != "" {
			cleanBucket = parsed.Host + strings.TrimRight(parsed.Path, "/")
		}
	}
	return fmt.Sprintf("%s://%s", canonProv, cleanBucket)
}

// NormalizeAPKCanonicalID produces a canonical identifier for an APK mobile artifact.
func NormalizeAPKCanonicalID(pkgName, sha256Hash string) string {
	canonPkg := strings.ToLower(strings.TrimSpace(pkgName))
	canonHash := strings.ToLower(strings.TrimSpace(sha256Hash))
	return fmt.Sprintf("apk:%s:%s", canonPkg, canonHash)
}

// NewApplicationAsset constructs a fully populated, strongly typed Application asset.
func NewApplicationAsset(asmID, execID, targetID, rawURLOrHost string, app ApplicationDetails) Asset {
	canonID := NormalizeApplicationCanonicalID(rawURLOrHost)
	now := time.Now().UTC()

	if app.RootURL == "" {
		app.RootURL = canonID
	}
	if app.AppType == "" {
		app.AppType = "web"
	}

	ast := Asset{
		ID:              ComputeStableAssetID(AssetTypeApplication, canonID),
		AssessmentID:    asmID,
		ExecutionID:     execID,
		TargetID:        targetID,
		Type:            AssetTypeApplication,
		CanonicalID:     canonID,
		DisplayName:     canonID,
		DiscoveryMethod: "TARGET_ANALYSIS",
		DiscoveryStatus: StatusObserved,
		Confidence:      ConfidenceHigh,
		InScope:         true,
		FirstSeen:       now,
		LastSeen:        now,
		Application:     &app,
	}
	ast.Fingerprint = ast.ComputeFingerprint()
	ast.SyncTypedDetailsToMetadata()
	return ast
}

// NewHostAsset constructs a strongly typed Host asset.
func NewHostAsset(asmID, execID, targetID, hostOrIP string, host HostDetails) Asset {
	canonID, ipStr, hostname := NormalizeHostCanonicalID(hostOrIP)
	now := time.Now().UTC()

	if len(host.IPAddresses) == 0 && ipStr != "" {
		host.IPAddresses = []string{ipStr}
	}
	if host.Hostname == "" && hostname != "" {
		host.Hostname = hostname
	}

	ast := Asset{
		ID:              ComputeStableAssetID(AssetTypeHost, canonID),
		AssessmentID:    asmID,
		ExecutionID:     execID,
		TargetID:        targetID,
		Type:            AssetTypeHost,
		CanonicalID:     canonID,
		DisplayName:     canonID,
		DiscoveryMethod: "NETWORK_DISCOVERY",
		DiscoveryStatus: StatusObserved,
		Confidence:      ConfidenceHigh,
		InScope:         true,
		FirstSeen:       now,
		LastSeen:        now,
		Host:            &host,
	}
	ast.Fingerprint = ast.ComputeFingerprint()
	ast.SyncTypedDetailsToMetadata()
	return ast
}

// NewEndpointAsset constructs a strongly typed Endpoint asset.
func NewEndpointAsset(asmID, execID, targetID, method, rawURL string, ep EndpointDetails) Asset {
	canonID, cleanPath, cleanURL := NormalizeEndpointCanonicalID(method, rawURL)
	now := time.Now().UTC()

	if ep.HTTPMethod == "" {
		ep.HTTPMethod = strings.ToUpper(strings.TrimSpace(method))
		if ep.HTTPMethod == "" {
			ep.HTTPMethod = "GET"
		}
	}
	if ep.Path == "" {
		ep.Path = cleanPath
	}
	if ep.URL == "" {
		ep.URL = cleanURL
	}

	displayName := fmt.Sprintf("%s %s", ep.HTTPMethod, ep.Path)
	if ep.Path == "" {
		displayName = cleanURL
	}

	ast := Asset{
		ID:              ComputeStableAssetID(AssetTypeEndpoint, canonID),
		AssessmentID:    asmID,
		ExecutionID:     execID,
		TargetID:        targetID,
		Type:            AssetTypeEndpoint,
		CanonicalID:     canonID,
		DisplayName:     displayName,
		DiscoveryMethod: "API_EXTRACTION",
		DiscoveryStatus: StatusObserved,
		Confidence:      ConfidenceHigh,
		InScope:         true,
		FirstSeen:       now,
		LastSeen:        now,
		Endpoint:        &ep,
	}
	ast.Fingerprint = ast.ComputeFingerprint()
	ast.SyncTypedDetailsToMetadata()
	return ast
}

// NewServiceAsset constructs a strongly typed Service asset.
func NewServiceAsset(asmID, execID, targetID, host string, port int, proto string, svc ServiceDetails) Asset {
	canonID := NormalizeServiceCanonicalID(host, port, proto)
	now := time.Now().UTC()

	if svc.Port == 0 {
		svc.Port = port
	}
	if svc.Protocol == "" {
		svc.Protocol = strings.ToLower(proto)
		if svc.Protocol == "" {
			svc.Protocol = "tcp"
		}
	}
	if svc.ServiceName == "" {
		svc.ServiceName = "service"
	}
	if svc.Banner != "" {
		svc.Banner = secrets.RedactText(svc.Banner)
	}

	displayName := canonID
	if svc.ServiceName != "" && svc.ServiceName != "service" {
		displayName = fmt.Sprintf("%s (%s)", canonID, svc.ServiceName)
	}

	ast := Asset{
		ID:              ComputeStableAssetID(AssetTypeService, canonID),
		AssessmentID:    asmID,
		ExecutionID:     execID,
		TargetID:        targetID,
		Type:            AssetTypeService,
		CanonicalID:     canonID,
		DisplayName:     displayName,
		DiscoveryMethod: "SERVICE_ENUMERATION",
		DiscoveryStatus: StatusObserved,
		Confidence:      ConfidenceHigh,
		InScope:         true,
		FirstSeen:       now,
		LastSeen:        now,
		Service:         &svc,
	}
	ast.Fingerprint = ast.ComputeFingerprint()
	ast.SyncTypedDetailsToMetadata()
	return ast
}

// NewDatabaseAsset constructs a strongly typed Database asset.
func NewDatabaseAsset(asmID, execID, targetID, engine, host string, port int, dbName string, db DatabaseDetails) Asset {
	canonID := NormalizeDatabaseCanonicalID(engine, host, port, dbName)
	now := time.Now().UTC()

	if db.Engine == "" {
		db.Engine = engine
	}
	if db.Port == 0 {
		db.Port = port
	}
	if db.InstanceName == "" {
		db.InstanceName = dbName
	}
	if db.Host == "" {
		db.Host = host
	}

	displayName := canonID

	ast := Asset{
		ID:              ComputeStableAssetID(AssetTypeDatabase, canonID),
		AssessmentID:    asmID,
		ExecutionID:     execID,
		TargetID:        targetID,
		Type:            AssetTypeDatabase,
		CanonicalID:     canonID,
		DisplayName:     displayName,
		DiscoveryMethod: "CLOUD_AUDIT",
		DiscoveryStatus: StatusObserved,
		Confidence:      ConfidenceHigh,
		InScope:         true,
		FirstSeen:       now,
		LastSeen:        now,
		Database:        &db,
	}
	ast.Fingerprint = ast.ComputeFingerprint()
	ast.SyncTypedDetailsToMetadata()
	return ast
}

// NewStorageAsset constructs a strongly typed Storage asset.
func NewStorageAsset(asmID, execID, targetID, provider, bucketOrShare string, st StorageDetails) Asset {
	canonID := NormalizeStorageCanonicalID(provider, bucketOrShare)
	now := time.Now().UTC()

	if st.Provider == "" {
		st.Provider = provider
	}
	if st.BucketName == "" {
		st.BucketName = bucketOrShare
	}

	ast := Asset{
		ID:              ComputeStableAssetID(AssetTypeStorage, canonID),
		AssessmentID:    asmID,
		ExecutionID:     execID,
		TargetID:        targetID,
		Type:            AssetTypeStorage,
		CanonicalID:     canonID,
		DisplayName:     canonID,
		DiscoveryMethod: "CLOUD_AUDIT",
		DiscoveryStatus: StatusObserved,
		Confidence:      ConfidenceHigh,
		InScope:         true,
		FirstSeen:       now,
		LastSeen:        now,
		Storage:         &st,
	}
	ast.Fingerprint = ast.ComputeFingerprint()
	ast.SyncTypedDetailsToMetadata()
	return ast
}

// NewAPKAsset constructs a strongly typed APK / Mobile Artifact asset.
func NewAPKAsset(asmID, execID, targetID, pkgName, sha256Hash string, apk APKDetails) Asset {
	canonID := NormalizeAPKCanonicalID(pkgName, sha256Hash)
	now := time.Now().UTC()

	if apk.PackageName == "" {
		apk.PackageName = pkgName
	}
	if apk.SHA256 == "" {
		apk.SHA256 = sha256Hash
	}

	displayName := fmt.Sprintf("APK: %s (%s)", apk.PackageName, apk.VersionName)
	if apk.VersionName == "" {
		displayName = fmt.Sprintf("APK: %s", apk.PackageName)
	}

	ast := Asset{
		ID:              ComputeStableAssetID(AssetTypeAPK, canonID),
		AssessmentID:    asmID,
		ExecutionID:     execID,
		TargetID:        targetID,
		Type:            AssetTypeAPK,
		CanonicalID:     canonID,
		DisplayName:     displayName,
		DiscoveryMethod: "MOBILE_INTELLIGENCE",
		DiscoveryStatus: StatusObserved,
		Confidence:      ConfidenceHigh,
		InScope:         true,
		FirstSeen:       now,
		LastSeen:        now,
		APK:             &apk,
	}
	ast.Fingerprint = ast.ComputeFingerprint()
	ast.SyncTypedDetailsToMetadata()
	return ast
}

// IngestCrawlerAsset ingests a single crawler asset into the inventory,
// registering it under the common model and creating an endpoint edge if applicable.
func IngestCrawlerAsset(inv *Inventory, asmID, execID, targetID, rootAppID string, crawled crawler.Asset) (assetID string, endpointID string) {
	if inv == nil || crawled.URL == "" {
		return "", ""
	}

	// 1. Register Endpoint asset
	parsed, err := url.Parse(crawled.URL)
	if err == nil && parsed.Scheme != "" && parsed.Host != "" {
		epDetails := EndpointDetails{
			URL:            crawled.URL,
			HTTPMethod:     "GET",
			Path:           parsed.Path,
			Classification: string(crawled.Type),
			ContentType:    crawled.ContentType,
			HTTPStatus:     crawled.StatusCode,
		}
		epAsset := NewEndpointAsset(asmID, execID, targetID, "GET", crawled.URL, epDetails)
		epAsset.InScope = crawled.InScope
		if crawled.StatusCode > 0 {
			epAsset.DiscoveryStatus = StatusObserved
		} else {
			epAsset.DiscoveryStatus = StatusInferred
		}
		endpointID = inv.AddAsset(epAsset)

		if rootAppID != "" && endpointID != "" && rootAppID != endpointID {
			inv.AddRelation(Relation{
				AssessmentID:  asmID,
				ExecutionID:   execID,
				SourceAssetID: rootAppID,
				TargetAssetID: endpointID,
				RelationType:  RelExposesEndpoint,
				Evidence:      "crawler web navigation",
				Confidence:    ConfidenceHigh,
				CreatedAt:     time.Now().UTC(),
			})
		}
	}

	// 2. Register file/resource asset if JavaScript or static file
	aType := AssetTypeAsset
	if crawled.Type == crawler.AssetJavaScript || strings.HasSuffix(crawled.URL, ".js") {
		aType = AssetTypeJavaScript
	}

	rawCanon := crawled.URL
	resAsset := Asset{
		ID:              ComputeStableAssetID(aType, rawCanon),
		AssessmentID:    asmID,
		ExecutionID:     execID,
		TargetID:        targetID,
		Type:            aType,
		CanonicalID:     rawCanon,
		ParentID:        rootAppID,
		DisplayName:     fmt.Sprintf("Asset: %s (%s)", crawled.URL, crawled.Type),
		SourceAsset:     crawled.URL,
		DiscoveryMethod: "CRAWLER",
		DiscoveryStatus: StatusObserved,
		Confidence:      ConfidenceHigh,
		InScope:         crawled.InScope,
		Metadata: map[string]any{
			"url":          crawled.URL,
			"type":         string(crawled.Type),
			"size_bytes":   crawled.Size,
			"content_type": crawled.ContentType,
		},
		Evidence: map[string]any{
			"status_code": crawled.StatusCode,
		},
		FirstSeen: time.Now().UTC(),
		LastSeen:  time.Now().UTC(),
	}
	assetID = inv.AddAsset(resAsset)

	return assetID, endpointID
}

// IngestAPIEndpoints ingests discovered API endpoints from the API auditor into the common inventory.
func IngestAPIEndpoints(inv *Inventory, asmID, execID, targetID, targetURL, rootAppID string, endpoints []api.DiscoveredEndpoint) []string {
	if inv == nil || len(endpoints) == 0 {
		return nil
	}

	parsedBase, _ := url.Parse(targetURL)
	var createdIDs []string

	for _, ep := range endpoints {
		fullURL := ep.Path
		if !strings.HasPrefix(fullURL, "http://") && !strings.HasPrefix(fullURL, "https://") {
			if parsedBase != nil {
				resolved, err := parsedBase.Parse(ep.Path)
				if err == nil {
					fullURL = resolved.String()
				} else {
					fullURL = strings.TrimRight(targetURL, "/") + "/" + strings.TrimLeft(ep.Path, "/")
				}
			} else {
				fullURL = strings.TrimRight(targetURL, "/") + "/" + strings.TrimLeft(ep.Path, "/")
			}
		}

		method := ep.Method
		if method == "" {
			method = "GET"
		}

		epDetails := EndpointDetails{
			URL:            fullURL,
			HTTPMethod:     method,
			Path:           ep.Path,
			Classification: string(ep.Classification),
			Authenticated:  ep.AuthState != "" && ep.AuthState != "UNAUTHENTICATED",
			HTTPStatus:     ep.HTTPStatus,
		}

		ast := NewEndpointAsset(asmID, execID, targetID, method, fullURL, epDetails)
		ast.SourceAsset = ep.SourceAsset
		ast.DiscoveryMethod = "API_DETECTOR"
		if ep.StaticallyResolved {
			ast.Confidence = ConfidenceHigh
		} else {
			ast.Confidence = ConfidenceMedium
		}

		id := inv.AddAsset(ast)
		createdIDs = append(createdIDs, id)

		// Link Application -> Endpoint
		if rootAppID != "" && id != "" && rootAppID != id {
			inv.AddRelation(Relation{
				AssessmentID:  asmID,
				ExecutionID:   execID,
				SourceAssetID: rootAppID,
				TargetAssetID: id,
				RelationType:  RelExposesEndpoint,
				Evidence:      fmt.Sprintf("Discovered in %s (%s)", ep.SourceAsset, ep.Mechanism),
				Confidence:    ast.Confidence,
				CreatedAt:     time.Now().UTC(),
			})
		}
	}

	return createdIDs
}

// IngestCloudServices ingests discovered cloud services from the cloud auditor into the common inventory.
func IngestCloudServices(inv *Inventory, asmID, execID, targetID, rootAppID string, services []cloud.Service) []string {
	if inv == nil || len(services) == 0 {
		return nil
	}

	var createdIDs []string

	for _, svc := range services {
		provStr := string(svc.Provider)

		// Detect if this is a storage resource
		isStorage := false
		bucketName := ""
		if b, ok := svc.Identifiers["bucket"]; ok && b != "" {
			isStorage = true
			bucketName = b
		} else if svc.Provider == cloud.ProviderAWS && strings.Contains(svc.URL, "s3") {
			isStorage = true
			bucketName = svc.URL
		} else if svc.Provider == cloud.ProviderGCP && strings.Contains(svc.URL, "storage") {
			isStorage = true
			bucketName = svc.URL
		}

		if isStorage {
			stDetails := StorageDetails{
				Provider:    provStr,
				BucketName:  bucketName,
				ResourceURL: svc.URL,
			}
			stAsset := NewStorageAsset(asmID, execID, targetID, provStr, bucketName, stDetails)
			stAsset.SourceAsset = svc.Source
			id := inv.AddAsset(stAsset)
			createdIDs = append(createdIDs, id)

			if rootAppID != "" && id != "" && rootAppID != id {
				inv.AddRelation(Relation{
					AssessmentID:  asmID,
					ExecutionID:   execID,
					SourceAssetID: rootAppID,
					TargetAssetID: id,
					RelationType:  RelUsesStorage,
					Evidence:      fmt.Sprintf("Discovered via %s from %s", provStr, svc.Source),
					Confidence:    ConfidenceHigh,
					CreatedAt:     time.Now().UTC(),
				})
			}
			continue
		}

		// Detect if this is a database resource
		isDatabase := false
		if provStr == "supabase" || provStr == "firebase" {
			// Check if identified as database / project
			if strings.Contains(svc.URL, "supabase.co") || strings.Contains(svc.URL, "firebaseio.com") {
				isDatabase = true
			}
		}

		if isDatabase {
			parsed, _ := url.Parse(svc.URL)
			host := svc.URL
			if parsed != nil && parsed.Host != "" {
				host = parsed.Host
			}
			dbDetails := DatabaseDetails{
				Engine:       provStr,
				Host:         host,
				InstanceName: svc.Identifiers["project"],
			}
			dbAsset := NewDatabaseAsset(asmID, execID, targetID, provStr, host, 0, svc.Identifiers["project"], dbDetails)
			dbAsset.SourceAsset = svc.Source
			id := inv.AddAsset(dbAsset)
			createdIDs = append(createdIDs, id)

			if rootAppID != "" && id != "" && rootAppID != id {
				inv.AddRelation(Relation{
					AssessmentID:  asmID,
					ExecutionID:   execID,
					SourceAssetID: rootAppID,
					TargetAssetID: id,
					RelationType:  RelUsesDatabase,
					Evidence:      fmt.Sprintf("Discovered via %s BaaS from %s", provStr, svc.Source),
					Confidence:    ConfidenceHigh,
					CreatedAt:     time.Now().UTC(),
				})
			}
			continue
		}

		// Otherwise, generic cloud service asset
		canonID := svc.CanonicalID()
		ast := Asset{
			ID:              ComputeStableAssetID(AssetTypeCloudService, canonID),
			AssessmentID:    asmID,
			ExecutionID:     execID,
			TargetID:        targetID,
			Type:            AssetTypeCloudService,
			CanonicalID:     canonID,
			DisplayName:     fmt.Sprintf("Cloud Service: %s (%s)", svc.URL, provStr),
			SourceAsset:     svc.Source,
			DiscoveryMethod: "CLOUD_AUDIT",
			DiscoveryStatus: StatusObserved,
			Confidence:      ConfidenceHigh,
			InScope:         true,
			Metadata: map[string]any{
				"provider":    provStr,
				"url":         svc.URL,
				"identifiers": svc.Identifiers,
			},
			FirstSeen: time.Now().UTC(),
			LastSeen:  time.Now().UTC(),
		}
		id := inv.AddAsset(ast)
		createdIDs = append(createdIDs, id)

		if rootAppID != "" && id != "" && rootAppID != id {
			inv.AddRelation(Relation{
				AssessmentID:  asmID,
				ExecutionID:   execID,
				SourceAssetID: rootAppID,
				TargetAssetID: id,
				RelationType:  RelUsesStorage,
				Evidence:      fmt.Sprintf("Discovered %s via %s", provStr, svc.Source),
				Confidence:    ConfidenceHigh,
				CreatedAt:     time.Now().UTC(),
			})
		}
	}

	return createdIDs
}

// IngestAPKArtifact ingests an APK artifact representation into the common inventory.
func IngestAPKArtifact(inv *Inventory, asmID, execID, targetID, rootAppID string, apk APKDetails) string {
	if inv == nil {
		return ""
	}

	apkAsset := NewAPKAsset(asmID, execID, targetID, apk.PackageName, apk.SHA256, apk)
	id := inv.AddAsset(apkAsset)

	if rootAppID != "" && id != "" && rootAppID != id {
		inv.AddRelation(Relation{
			AssessmentID:  asmID,
			ExecutionID:   execID,
			SourceAssetID: rootAppID,
			TargetAssetID: id,
			RelationType:  RelRelatedApplication,
			Evidence:      "Associated mobile application package",
			Confidence:    ConfidenceHigh,
			CreatedAt:     time.Now().UTC(),
		})
	}

	return id
}

// IngestDiscoveredServices ingests standardized DiscoveredService records into the Common Asset Model inventory.
func IngestDiscoveredServices(inv *Inventory, asmID, execID, targetID, rootAppID string, services []cloud.DiscoveredService) []string {
	if inv == nil || len(services) == 0 {
		return nil
	}

	var createdIDs []string
	now := time.Now().UTC()

	for _, ds := range services {
		if ds.Outcome == cloud.OutcomeError {
			continue
		}

		techStr := string(ds.Technology)
		status := StatusInferred
		if ds.Outcome == cloud.OutcomeDetected {
			status = StatusObserved
		} else if ds.Outcome == cloud.OutcomeInconclusive {
			status = StatusUnavailable
		}
		if !ds.InScope {
			status = StatusOutOfScope
		}

		conf := ConfidenceMedium
		if ds.Confidence == "HIGH" || ds.Confidence == "High" {
			conf = ConfidenceHigh
		} else if ds.Confidence == "LOW" || ds.Confidence == "Low" {
			conf = ConfidenceLow
		}

		host := ds.Host
		if host == "" && ds.Endpoint != "" {
			if u, err := url.Parse(ds.Endpoint); err == nil && u.Hostname() != "" {
				host = u.Hostname()
			} else {
				host = ds.Endpoint
			}
		}

		var (
			astID   string
			relType RelationType
		)

		switch ds.Family {
		case cloud.FamilyDirectDatabase, cloud.FamilyFirebase:
			instanceName := ""
			if ds.Metadata != nil {
				if proj, ok := ds.Metadata["project"].(string); ok {
					instanceName = proj
				} else if projID, ok := ds.Metadata["project_id"].(string); ok {
					instanceName = projID
				} else if cluster, ok := ds.Metadata["cluster_name"].(string); ok {
					instanceName = cluster
				}
			}

			dbDetails := DatabaseDetails{
				Engine:             techStr,
				InstanceName:       instanceName,
				Host:               host,
				Port:               ds.Port,
				PubliclyAccessible: ds.PublicAccess,
				AuthRequired:       ds.AuthRequired,
			}

			dbAsset := NewDatabaseAsset(asmID, execID, targetID, techStr, host, ds.Port, instanceName, dbDetails)
			dbAsset.SourceAsset = ds.SourceAsset
			dbAsset.DiscoveryMethod = ds.DetectionMethod
			dbAsset.DiscoveryStatus = status
			dbAsset.Confidence = conf
			dbAsset.InScope = ds.InScope
			dbAsset.Evidence = map[string]any{
				"raw_evidence": ds.Evidence,
				"outcome":      string(ds.Outcome),
				"version":      ds.Version,
				"limitations":  ds.Limitations,
			}
			astID = inv.AddAsset(dbAsset)
			relType = RelUsesDatabase

		case cloud.FamilyObjectStorage:
			bucketName := ""
			if ds.Metadata != nil {
				if b, ok := ds.Metadata["bucket"].(string); ok {
					bucketName = b
				} else if acc, ok := ds.Metadata["account"].(string); ok {
					bucketName = acc
				}
			}
			if bucketName == "" {
				bucketName = ds.Endpoint
			}

			stDetails := StorageDetails{
				Provider:      techStr,
				BucketName:    bucketName,
				ResourceURL:   ds.Endpoint,
				PublicListing: ds.PublicAccess,
				PublicRead:    ds.PublicAccess,
			}

			stAsset := NewStorageAsset(asmID, execID, targetID, techStr, bucketName, stDetails)
			stAsset.SourceAsset = ds.SourceAsset
			stAsset.DiscoveryMethod = ds.DetectionMethod
			stAsset.DiscoveryStatus = status
			stAsset.Confidence = conf
			stAsset.InScope = ds.InScope
			stAsset.Evidence = map[string]any{
				"raw_evidence": ds.Evidence,
				"outcome":      string(ds.Outcome),
				"limitations":  ds.Limitations,
			}
			astID = inv.AddAsset(stAsset)
			relType = RelUsesStorage

		case cloud.FamilyDatabaseAdmin, cloud.FamilyBackendInterface:
			protocol := ds.Protocol
			if protocol == "" {
				if strings.HasPrefix(ds.Endpoint, "https") {
					protocol = "https"
				} else {
					protocol = "http"
				}
			}

			svcDetails := ServiceDetails{
				ServiceName: techStr,
				Port:        ds.Port,
				Protocol:    protocol,
				Version:     ds.Version,
			}

			svcAsset := NewServiceAsset(asmID, execID, targetID, host, ds.Port, protocol, svcDetails)
			if ds.Endpoint != "" {
				svcAsset.CanonicalID = ds.CanonicalID()
			}
			svcAsset.SourceAsset = ds.SourceAsset
			svcAsset.DiscoveryMethod = ds.DetectionMethod
			svcAsset.DiscoveryStatus = status
			svcAsset.Confidence = conf
			svcAsset.InScope = ds.InScope
			svcAsset.Evidence = map[string]any{
				"raw_evidence": ds.Evidence,
				"outcome":      string(ds.Outcome),
				"version":      ds.Version,
				"limitations":  ds.Limitations,
			}
			astID = inv.AddAsset(svcAsset)
			relType = RelExposesService

			// Also link Host -> RelHostsService -> Service if host is known
			if host != "" {
				hostAsset := NewHostAsset(asmID, execID, targetID, host, HostDetails{
					Hostname: host,
				})
				hostID := inv.AddAsset(hostAsset)
				if hostID != "" {
					inv.AddRelation(Relation{
						AssessmentID:  asmID,
						ExecutionID:   execID,
						SourceAssetID: hostID,
						TargetAssetID: astID,
						RelationType:  RelHostsService,
						Evidence:      fmt.Sprintf("Service %s hosted on %s", techStr, host),
						Confidence:    conf,
						CreatedAt:     now,
					})
				}
			}

		default:
			canonID := ds.CanonicalID()
			ast := Asset{
				ID:              ComputeStableAssetID(AssetTypeCloudService, canonID),
				AssessmentID:    asmID,
				ExecutionID:     execID,
				TargetID:        targetID,
				Type:            AssetTypeCloudService,
				CanonicalID:     canonID,
				DisplayName:     fmt.Sprintf("%s (%s)", techStr, ds.Family),
				SourceAsset:     ds.SourceAsset,
				DiscoveryMethod: ds.DetectionMethod,
				DiscoveryStatus: status,
				Confidence:      conf,
				InScope:         ds.InScope,
				Metadata: map[string]any{
					"technology": techStr,
					"family":     string(ds.Family),
					"endpoint":   ds.Endpoint,
					"metadata":   ds.Metadata,
				},
				Evidence: map[string]any{
					"raw_evidence": ds.Evidence,
					"outcome":      string(ds.Outcome),
					"limitations":  ds.Limitations,
				},
				FirstSeen: now,
				LastSeen:  now,
			}
			astID = inv.AddAsset(ast)
			relType = RelUsesStorage
		}

		if astID != "" {
			createdIDs = append(createdIDs, astID)
			if rootAppID != "" && rootAppID != astID {
				inv.AddRelation(Relation{
					AssessmentID:  asmID,
					ExecutionID:   execID,
					SourceAssetID: rootAppID,
					TargetAssetID: astID,
					RelationType:  relType,
					Evidence:      fmt.Sprintf("Discovered %s (%s) via %s", techStr, ds.Family, ds.DetectionMethod),
					Confidence:    conf,
					CreatedAt:     now,
				})
			}
		}
	}

	return createdIDs
}
