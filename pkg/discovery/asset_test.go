package discovery

import (
	"encoding/json"
	"strings"
	"testing"

	"felix/pkg/api"
	"felix/pkg/cloud"
	"felix/pkg/crawler"
)

func TestCoreAssetCategoriesConstructors(t *testing.T) {
	asmID := "asm-test-01"
	execID := "exec-test-01"
	targetID := "tgt-test-01"

	// 1. Application Asset
	appDetails := ApplicationDetails{
		AppType:        "web",
		RootURL:        "https://app.example.com",
		TechStack:      []string{"React", "Node.js"},
		AuthMechanisms: []string{"OAuth2", "JWT"},
		Version:        "2.4.1",
	}
	appAsset := NewApplicationAsset(asmID, execID, targetID, "https://app.example.com:443", appDetails)
	if appAsset.Type != AssetTypeApplication {
		t.Fatalf("expected AssetTypeApplication, got %s", appAsset.Type)
	}
	if appAsset.CanonicalID != "https://app.example.com" {
		t.Fatalf("expected canonical ID https://app.example.com, got %s", appAsset.CanonicalID)
	}
	if !strings.HasPrefix(appAsset.ID, "ast_") {
		t.Fatalf("expected stable ID prefix ast_, got %s", appAsset.ID)
	}
	if appAsset.Application == nil || appAsset.Application.AppType != "web" {
		t.Fatalf("expected Application details to be populated")
	}

	// 2. Host Asset
	hostDetails := HostDetails{
		Hostname:       "app.example.com",
		IPAddresses:    []string{"93.184.216.34"},
		Infrastructure: "cloud",
	}
	hostAsset := NewHostAsset(asmID, execID, targetID, "app.example.com.", hostDetails)
	if hostAsset.Type != AssetTypeHost {
		t.Fatalf("expected AssetTypeHost, got %s", hostAsset.Type)
	}
	if hostAsset.CanonicalID != "app.example.com" {
		t.Fatalf("expected trailing dot stripped, got %s", hostAsset.CanonicalID)
	}
	if hostAsset.Host == nil || hostAsset.Host.Hostname != "app.example.com" {
		t.Fatalf("expected Host details to be populated")
	}

	// 3. Endpoint Asset
	epDetails := EndpointDetails{
		URL:            "https://app.example.com/api/v1/users",
		HTTPMethod:     "GET",
		Path:           "/api/v1/users",
		Classification: "API",
		Authenticated:  true,
		HTTPStatus:     200,
	}
	epAsset := NewEndpointAsset(asmID, execID, targetID, "get", "https://app.example.com:443/api/v1/users", epDetails)
	if epAsset.Type != AssetTypeEndpoint {
		t.Fatalf("expected AssetTypeEndpoint, got %s", epAsset.Type)
	}
	if epAsset.CanonicalID != "GET:https://app.example.com/api/v1/users" {
		t.Fatalf("expected canonical ID GET:https://app.example.com/api/v1/users, got %s", epAsset.CanonicalID)
	}
	if epAsset.Endpoint == nil || !epAsset.Endpoint.Authenticated {
		t.Fatalf("expected Endpoint details to be populated")
	}

	// 4. Service Asset
	svcDetails := ServiceDetails{
		ServiceName: "https",
		Port:        443,
		Protocol:    "tcp",
		Transport:   "tls",
		Banner:      "nginx/1.24.0",
		Version:     "1.24.0",
	}
	svcAsset := NewServiceAsset(asmID, execID, targetID, "app.example.com", 443, "tcp", svcDetails)
	if svcAsset.Type != AssetTypeService {
		t.Fatalf("expected AssetTypeService, got %s", svcAsset.Type)
	}
	if svcAsset.CanonicalID != "app.example.com:443/tcp" {
		t.Fatalf("expected canonical ID app.example.com:443/tcp, got %s", svcAsset.CanonicalID)
	}
	if svcAsset.Service == nil || svcAsset.Service.Banner != "nginx/1.24.0" {
		t.Fatalf("expected Service details to be populated")
	}

	// 5. Database Asset
	dbDetails := DatabaseDetails{
		Engine:             "postgres",
		InstanceName:       "production_users",
		Host:               "db.internal.example.com",
		Port:               5432,
		PubliclyAccessible: false,
		AuthRequired:       true,
		Encrypted:          true,
	}
	dbAsset := NewDatabaseAsset(asmID, execID, targetID, "postgres", "db.internal.example.com", 5432, "production_users", dbDetails)
	if dbAsset.Type != AssetTypeDatabase {
		t.Fatalf("expected AssetTypeDatabase, got %s", dbAsset.Type)
	}
	if dbAsset.CanonicalID != "postgres://db.internal.example.com:5432/production_users" {
		t.Fatalf("expected canonical ID postgres://db.internal.example.com:5432/production_users, got %s", dbAsset.CanonicalID)
	}
	if dbAsset.Database == nil || dbAsset.Database.Engine != "postgres" {
		t.Fatalf("expected Database details to be populated")
	}

	// 6. Storage Asset
	stDetails := StorageDetails{
		Provider:      "aws_s3",
		BucketName:    "prod-customer-backups",
		Region:        "us-east-1",
		PublicListing: false,
		PublicRead:    false,
	}
	stAsset := NewStorageAsset(asmID, execID, targetID, "aws_s3", "prod-customer-backups", stDetails)
	if stAsset.Type != AssetTypeStorage {
		t.Fatalf("expected AssetTypeStorage, got %s", stAsset.Type)
	}
	if stAsset.CanonicalID != "aws_s3://prod-customer-backups" {
		t.Fatalf("expected canonical ID aws_s3://prod-customer-backups, got %s", stAsset.CanonicalID)
	}
	if stAsset.Storage == nil || stAsset.Storage.BucketName != "prod-customer-backups" {
		t.Fatalf("expected Storage details to be populated")
	}

	// 7. APK / Mobile Artifact Asset
	apkDetails := APKDetails{
		PackageName: "com.example.mobileapp",
		VersionName: "1.0.4",
		VersionCode: 104,
		MinSDK:      26,
		TargetSDK:   34,
		Permissions: []string{"android.permission.INTERNET", "android.permission.CAMERA"},
		SHA256:      "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		FileSize:    24500000,
	}
	apkAsset := NewAPKAsset(asmID, execID, targetID, "com.example.mobileapp", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", apkDetails)
	if apkAsset.Type != AssetTypeAPK {
		t.Fatalf("expected AssetTypeAPK, got %s", apkAsset.Type)
	}
	if apkAsset.CanonicalID != "apk:com.example.mobileapp:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" {
		t.Fatalf("expected canonical ID apk:com.example.mobileapp:..., got %s", apkAsset.CanonicalID)
	}
	if apkAsset.APK == nil || apkAsset.APK.VersionCode != 104 {
		t.Fatalf("expected APK details to be populated")
	}
}

func TestCanonicalIdentityNormalization(t *testing.T) {
	// 1. Default port stripping for HTTP and HTTPS
	u1, err := SanitizeURLForCanonicalID("http://EXAMPLE.COM:80/path/test")
	if err != nil || u1.String() != "http://example.com/path/test" {
		t.Fatalf("expected default port 80 stripped, got %v (%s)", err, u1)
	}

	u2, err := SanitizeURLForCanonicalID("https://EXAMPLE.COM:443/path/test")
	if err != nil || u2.String() != "https://example.com/path/test" {
		t.Fatalf("expected default port 443 stripped, got %v (%s)", err, u2)
	}

	// 2. Non-default ports preserved
	u3, err := SanitizeURLForCanonicalID("https://example.com:8443/path")
	if err != nil || u3.String() != "https://example.com:8443/path" {
		t.Fatalf("expected non-default port 8443 preserved, got %v (%s)", err, u3)
	}

	// 3. User credential stripping
	u4, err := SanitizeURLForCanonicalID("https://admin:supersecret@example.com/admin")
	if err != nil || u4.User != nil || strings.Contains(u4.String(), "supersecret") {
		t.Fatalf("expected credentials stripped, got %s", u4)
	}

	// 4. Sensitive query parameter redaction
	u5, err := SanitizeURLForCanonicalID("https://example.com/api?token=secret123&action=view&api_key=xyz987&sort=asc")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	rawQ := u5.RawQuery
	if strings.Contains(rawQ, "secret123") || strings.Contains(rawQ, "xyz987") {
		t.Fatalf("sensitive parameters leaked in URL: %s", rawQ)
	}
	if !strings.Contains(rawQ, "token=REDACTED") || !strings.Contains(rawQ, "api_key=REDACTED") {
		t.Fatalf("expected REDACTED placeholder for sensitive parameters: %s", rawQ)
	}
	if !strings.Contains(rawQ, "action=view") || !strings.Contains(rawQ, "sort=asc") {
		t.Fatalf("non-sensitive parameters lost: %s", rawQ)
	}

	// 5. Query parameters sorted deterministically
	u6a, _ := SanitizeURLForCanonicalID("https://example.com/search?b=2&a=1&c=3")
	u6b, _ := SanitizeURLForCanonicalID("https://example.com/search?c=3&a=1&b=2")
	if u6a.String() != u6b.String() {
		t.Fatalf("expected deterministic query sorting, got %s vs %s", u6a.String(), u6b.String())
	}

	// 6. Fragment stripping
	u7, _ := SanitizeURLForCanonicalID("https://example.com/docs#installation")
	if u7.Fragment != "" || strings.Contains(u7.String(), "#") {
		t.Fatalf("expected fragment stripped, got %s", u7)
	}

	// 7. IPv4 canonicalization
	canonIP4, ip4Str, host4 := NormalizeHostCanonicalID("192.168.1.1:8080")
	if canonIP4 != "192.168.1.1" || ip4Str != "192.168.1.1" || host4 != "" {
		t.Fatalf("expected canonical IPv4 192.168.1.1, got canon=%s, ip=%s, host=%s", canonIP4, ip4Str, host4)
	}

	// 8. IPv6 canonicalization (RFC 5952)
	canonIP6, ip6Str, host6 := NormalizeHostCanonicalID("[2001:0db8:0000:0000:0000:ff00:0042:8329]:443")
	if canonIP6 != "2001:db8::ff00:42:8329" || ip6Str != "2001:db8::ff00:42:8329" || host6 != "" {
		t.Fatalf("expected canonical IPv6 2001:db8::ff00:42:8329, got canon=%s, ip=%s, host=%s", canonIP6, ip6Str, host6)
	}
}

func TestStableDeterministicAssetIDs(t *testing.T) {
	// Stable ID must be identical across multiple calls with same inputs
	id1 := ComputeStableAssetID(AssetTypeHost, "192.168.1.1")
	id2 := ComputeStableAssetID(AssetTypeHost, "192.168.1.1")
	if id1 != id2 {
		t.Fatalf("expected identical IDs for same inputs, got %s vs %s", id1, id2)
	}

	// Different asset types with same canonical ID must have distinct IDs
	hostID := ComputeStableAssetID(AssetTypeHost, "10.0.0.1")
	svcID := ComputeStableAssetID(AssetTypeService, "10.0.0.1")
	if hostID == svcID {
		t.Fatalf("expected distinct IDs across different asset types, got %s", hostID)
	}

	// Case differences in canonical string must normalize to same ID
	idA := ComputeStableAssetID(AssetTypeDomain, "EXAMPLE.COM")
	idB := ComputeStableAssetID(AssetTypeDomain, "example.com")
	if idA != idB {
		t.Fatalf("expected case normalization in stable ID generation, got %s vs %s", idA, idB)
	}
}

func TestInventoryRelationshipsAndValidation(t *testing.T) {
	inv := NewInventory()

	asmID := "asm-rel-01"
	execID := "exec-rel-01"
	targetID := "tgt-rel-01"

	// Create parent Host
	host := NewHostAsset(asmID, execID, targetID, "10.0.0.5", HostDetails{
		Hostname:    "web01.internal",
		IPAddresses: []string{"10.0.0.5"},
	})
	hostID := inv.AddAsset(host)

	// Create Service on Host
	svc := NewServiceAsset(asmID, execID, targetID, "10.0.0.5", 8080, "tcp", ServiceDetails{
		ServiceName: "http",
		Port:        8080,
		Protocol:    "tcp",
	})
	svcID := inv.AddAsset(svc)

	// Create Application
	app := NewApplicationAsset(asmID, execID, targetID, "http://10.0.0.5:8080", ApplicationDetails{
		AppType: "web",
		RootURL: "http://10.0.0.5:8080",
	})
	appID := inv.AddAsset(app)

	// Create Endpoint
	ep := NewEndpointAsset(asmID, execID, targetID, "GET", "http://10.0.0.5:8080/api/status", EndpointDetails{
		URL:        "http://10.0.0.5:8080/api/status",
		HTTPMethod: "GET",
		Path:       "/api/status",
	})
	epID := inv.AddAsset(ep)

	// Create Database
	db := NewDatabaseAsset(asmID, execID, targetID, "postgres", "db.internal", 5432, "appdb", DatabaseDetails{
		Engine:       "postgres",
		Host:         "db.internal",
		InstanceName: "appdb",
	})
	dbID := inv.AddAsset(db)

	// Create Storage
	st := NewStorageAsset(asmID, execID, targetID, "aws_s3", "user-uploads", StorageDetails{
		Provider:   "aws_s3",
		BucketName: "user-uploads",
	})
	stID := inv.AddAsset(st)

	// 1. Valid Relations
	validRelations := []Relation{
		{AssessmentID: asmID, ExecutionID: execID, SourceAssetID: hostID, TargetAssetID: svcID, RelationType: RelHostsService},
		{AssessmentID: asmID, ExecutionID: execID, SourceAssetID: hostID, TargetAssetID: appID, RelationType: RelHostsApplication},
		{AssessmentID: asmID, ExecutionID: execID, SourceAssetID: appID, TargetAssetID: epID, RelationType: RelExposesEndpoint},
		{AssessmentID: asmID, ExecutionID: execID, SourceAssetID: appID, TargetAssetID: dbID, RelationType: RelUsesDatabase},
		{AssessmentID: asmID, ExecutionID: execID, SourceAssetID: appID, TargetAssetID: stID, RelationType: RelUsesStorage},
	}

	for _, r := range validRelations {
		if err := inv.ValidateRelation(r); err != nil {
			t.Fatalf("expected relation %s -> %s (%s) to be valid, got: %v", r.SourceAssetID, r.TargetAssetID, r.RelationType, err)
		}
		inv.AddRelation(r)
	}

	if len(inv.Relations) != 5 {
		t.Fatalf("expected 5 relations added, got %d", len(inv.Relations))
	}

	// 2. Prohibited Self-Referential Relation
	selfRel := Relation{
		AssessmentID:  asmID,
		ExecutionID:   execID,
		SourceAssetID: appID,
		TargetAssetID: appID,
		RelationType:  RelRelatedApplication,
	}
	if err := inv.ValidateRelation(selfRel); err == nil {
		t.Fatalf("expected self-referential relation to be rejected")
	}
	inv.AddRelation(selfRel)
	if len(inv.Relations) != 5 {
		t.Fatalf("expected self-referential relation to not be added, count=%d", len(inv.Relations))
	}

	// 3. Invalid Semantic Combination: Endpoint as source of RelHostsService
	invalidSemanticRel := Relation{
		AssessmentID:  asmID,
		ExecutionID:   execID,
		SourceAssetID: epID,
		TargetAssetID: svcID,
		RelationType:  RelHostsService,
	}
	if err := inv.ValidateRelation(invalidSemanticRel); err == nil {
		t.Fatalf("expected invalid source asset type for RelHostsService to fail validation")
	}

	// 4. Deduplication: Re-adding existing relation must be a no-op
	inv.AddRelation(validRelations[0])
	if len(inv.Relations) != 5 {
		t.Fatalf("expected relation deduplication, got count=%d", len(inv.Relations))
	}
}

func TestIngestionAdapters(t *testing.T) {
	inv := NewInventory()
	asmID := "asm-ingest-01"
	execID := "exec-ingest-01"
	targetID := "tgt-ingest-01"
	rootAppID := "ast-app-root"

	// 1. IngestCrawlerAsset
	crawled := crawler.Asset{
		URL:         "https://example.com/assets/app.js",
		Type:        crawler.AssetJavaScript,
		Size:        10240,
		StatusCode:  200,
		ContentType: "application/javascript",
		InScope:     true,
	}
	resID, epID := IngestCrawlerAsset(inv, asmID, execID, targetID, rootAppID, crawled)
	if resID == "" || epID == "" {
		t.Fatalf("expected non-empty asset and endpoint IDs from crawler ingestion")
	}
	epAsset := inv.FindByID(epID)
	if epAsset == nil || epAsset.Type != AssetTypeEndpoint {
		t.Fatalf("expected crawler asset to create Endpoint asset")
	}

	// 2. IngestAPIEndpoints
	apiEndpoints := []api.DiscoveredEndpoint{
		{
			Path:               "/api/v2/items",
			Method:             "POST",
			SourceAsset:        "https://example.com/assets/app.js",
			Mechanism:          "fetch",
			StaticallyResolved: true,
			Classification:     api.ClassAPI,
			AuthState:          api.AuthStateAuthRequired,
			HTTPStatus:         201,
		},
		{
			Path:               "/graphql",
			Method:             "POST",
			SourceAsset:        "https://example.com/assets/app.js",
			Mechanism:          "apollo",
			StaticallyResolved: true,
			Classification:     api.ClassGraphQL,
		},
	}
	createdEpIDs := IngestAPIEndpoints(inv, asmID, execID, targetID, "https://example.com", rootAppID, apiEndpoints)
	if len(createdEpIDs) != 2 {
		t.Fatalf("expected 2 API endpoint assets created, got %d", len(createdEpIDs))
	}
	ep1 := inv.FindByID(createdEpIDs[0])
	if ep1 == nil || ep1.Endpoint == nil || !ep1.Endpoint.Authenticated {
		t.Fatalf("expected authenticated API endpoint details")
	}

	// 3. IngestCloudServices (Storage & Database)
	cloudServices := []cloud.Service{
		{
			Provider: cloud.ProviderAWS,
			URL:      "https://felix-data-lake.s3.amazonaws.com",
			Source:   "JS Bundle",
			Identifiers: map[string]string{
				"bucket": "felix-data-lake",
			},
		},
		{
			Provider: cloud.ProviderSupabase,
			URL:      "https://xyzcompany.supabase.co",
			Source:   "Env Config",
			Identifiers: map[string]string{
				"project": "xyzcompany",
			},
		},
	}
	createdCloudIDs := IngestCloudServices(inv, asmID, execID, targetID, rootAppID, cloudServices)
	if len(createdCloudIDs) != 2 {
		t.Fatalf("expected 2 cloud assets created, got %d", len(createdCloudIDs))
	}
	stAsset := inv.FindByID(createdCloudIDs[0])
	if stAsset == nil || stAsset.Type != AssetTypeStorage || stAsset.Storage == nil || stAsset.Storage.BucketName != "felix-data-lake" {
		t.Fatalf("expected storage asset with bucket name felix-data-lake")
	}
	dbAsset := inv.FindByID(createdCloudIDs[1])
	if dbAsset == nil || dbAsset.Type != AssetTypeDatabase || dbAsset.Database == nil || dbAsset.Database.InstanceName != "xyzcompany" {
		t.Fatalf("expected database asset with instance name xyzcompany")
	}

	// 4. IngestAPKArtifact
	apkDetails := APKDetails{
		PackageName: "com.example.secureclient",
		VersionName: "3.2.0",
		VersionCode: 320,
		SHA256:      "abcd1234efgh5678",
	}
	apkID := IngestAPKArtifact(inv, asmID, execID, targetID, rootAppID, apkDetails)
	if apkID == "" {
		t.Fatalf("expected non-empty APK asset ID")
	}
	apkAsset := inv.FindByID(apkID)
	if apkAsset == nil || apkAsset.Type != AssetTypeAPK || apkAsset.APK == nil || apkAsset.APK.PackageName != "com.example.secureclient" {
		t.Fatalf("expected APK asset with package name com.example.secureclient")
	}

	// Verify Summary
	summary := inv.Summary()
	if summary.EndpointsCount < 3 {
		t.Fatalf("expected at least 3 endpoints in summary, got %d", summary.EndpointsCount)
	}
	if summary.StorageCount != 1 {
		t.Fatalf("expected 1 storage resource in summary, got %d", summary.StorageCount)
	}
	if summary.DatabasesCount != 1 {
		t.Fatalf("expected 1 database in summary, got %d", summary.DatabasesCount)
	}
	if summary.APKCount != 1 {
		t.Fatalf("expected 1 APK artifact in summary, got %d", summary.APKCount)
	}
}

func TestMetadataSyncAndHydrationRoundTrip(t *testing.T) {
	// Test round-trip persistence simulation (typed struct -> metadata -> JSON -> unmarshal -> hydrate)
	originalDB := NewDatabaseAsset("asm-1", "exec-1", "tgt-1", "postgres", "db.example.internal", 5432, "metrics", DatabaseDetails{
		Engine:             "postgres",
		InstanceName:       "metrics",
		Host:               "db.example.internal",
		Port:               5432,
		PubliclyAccessible: true,
		AuthRequired:       false,
		Encrypted:          true,
	})

	// Ensure SyncTypedDetailsToMetadata wrote to Metadata
	if originalDB.Metadata == nil || originalDB.Metadata["database"] == nil {
		t.Fatalf("expected database struct synced to metadata")
	}

	// Simulate JSON serialization / deserialization as in SQLite store
	blob, err := json.Marshal(originalDB)
	if err != nil {
		t.Fatalf("failed to marshal asset: %v", err)
	}

	var loaded Asset
	if err := json.Unmarshal(blob, &loaded); err != nil {
		t.Fatalf("failed to unmarshal asset: %v", err)
	}

	// Clear typed pointer to simulate cold load from DB
	loaded.Database = nil

	// Hydrate
	loaded.HydrateTypedDetailsFromMetadata()

	if loaded.Database == nil {
		t.Fatalf("expected Database details to be hydrated from metadata")
	}
	if loaded.Database.Engine != "postgres" || loaded.Database.InstanceName != "metrics" || !loaded.Database.PubliclyAccessible {
		t.Fatalf("hydrated database fields mismatch: %+v", loaded.Database)
	}
}

func TestAssetDeduplicationAndDistinctEntities(t *testing.T) {
	inv := NewInventory()
	asmID := "asm-dedup-01"
	execID := "exec-dedup-01"
	tgtID := "tgt-dedup-01"

	// 1. Distinct database instances must not collide
	db1 := NewDatabaseAsset(asmID, execID, tgtID, "postgres", "db1.internal", 5432, "appdb", DatabaseDetails{
		Engine: "postgres", Host: "db1.internal", Port: 5432, InstanceName: "appdb",
	})
	db2 := NewDatabaseAsset(asmID, execID, tgtID, "postgres", "db2.internal", 5432, "appdb", DatabaseDetails{
		Engine: "postgres", Host: "db2.internal", Port: 5432, InstanceName: "appdb",
	})
	idDB1 := inv.AddAsset(db1)
	idDB2 := inv.AddAsset(db2)
	if idDB1 == idDB2 {
		t.Fatalf("expected distinct IDs for databases on different hosts, got %s", idDB1)
	}

	// 2. Distinct storage buckets must not collide
	st1 := NewStorageAsset(asmID, execID, tgtID, "aws_s3", "bucket-alpha", StorageDetails{
		Provider: "aws_s3", BucketName: "bucket-alpha",
	})
	st2 := NewStorageAsset(asmID, execID, tgtID, "aws_s3", "bucket-beta", StorageDetails{
		Provider: "aws_s3", BucketName: "bucket-beta",
	})
	idST1 := inv.AddAsset(st1)
	idST2 := inv.AddAsset(st2)
	if idST1 == idST2 {
		t.Fatalf("expected distinct IDs for distinct buckets, got %s", idST1)
	}

	// 3. Distinct services on same host (ports 80 and 443) must not collide
	svc1 := NewServiceAsset(asmID, execID, tgtID, "app.internal", 80, "tcp", ServiceDetails{
		ServiceName: "http", Port: 80, Protocol: "tcp",
	})
	svc2 := NewServiceAsset(asmID, execID, tgtID, "app.internal", 443, "tcp", ServiceDetails{
		ServiceName: "https", Port: 443, Protocol: "tcp",
	})
	idSvc1 := inv.AddAsset(svc1)
	idSvc2 := inv.AddAsset(svc2)
	if idSvc1 == idSvc2 {
		t.Fatalf("expected distinct IDs for distinct services on same host, got %s", idSvc1)
	}

	// 4. Distinct HTTP methods for same path must not collide
	epGet := NewEndpointAsset(asmID, execID, tgtID, "GET", "https://api.example.com/items", EndpointDetails{
		URL: "https://api.example.com/items", HTTPMethod: "GET", Path: "/items",
	})
	epPost := NewEndpointAsset(asmID, execID, tgtID, "POST", "https://api.example.com/items", EndpointDetails{
		URL: "https://api.example.com/items", HTTPMethod: "POST", Path: "/items",
	})
	idGet := inv.AddAsset(epGet)
	idPost := inv.AddAsset(epPost)
	if idGet == idPost {
		t.Fatalf("expected distinct IDs for distinct HTTP methods on same URL, got %s", idGet)
	}

	// 5. Re-adding an existing asset merges metadata and retains identical ID
	initialLen := len(inv.Assets)
	db1Updated := db1
	db1Updated.Metadata = map[string]any{"cluster": "primary-east"}
	reAddedID := inv.AddAsset(db1Updated)
	if reAddedID != idDB1 {
		t.Fatalf("expected same ID on re-adding existing asset, got %s vs %s", reAddedID, idDB1)
	}
	if len(inv.Assets) != initialLen {
		t.Fatalf("expected asset count unchanged after re-add, got %d vs %d", len(inv.Assets), initialLen)
	}
	retrieved := inv.FindByID(idDB1)
	if retrieved == nil || retrieved.Metadata["cluster"] != "primary-east" {
		t.Fatalf("expected merged metadata on re-added asset")
	}
}

func TestSecurityRedactionInAssetFactory(t *testing.T) {
	// 1. Connection string with embedded credentials stripped
	dbCanon := NormalizeDatabaseCanonicalID("postgres", "postgres:SuperSecretP@ssword!@10.0.0.5", 5432, "customers?sslmode=disable")
	if strings.Contains(dbCanon, "SuperSecret") || strings.Contains(dbCanon, "P@ssword") {
		t.Fatalf("credentials leaked into database canonical ID: %s", dbCanon)
	}
	if !strings.HasPrefix(dbCanon, "postgres://10.0.0.5:5432/customers") {
		t.Fatalf("expected clean database canonical ID, got: %s", dbCanon)
	}

	// 2. Storage presigned URL query signatures stripped
	stCanon := NormalizeStorageCanonicalID("aws_s3", "mybucket?AWSAccessKeyId=AKIAIOSFODNN7EXAMPLE&Signature=vjbyPxybdZaNmGa%2ByT272YEAiv4%3D")
	if strings.Contains(stCanon, "AKIA") || strings.Contains(stCanon, "Signature") {
		t.Fatalf("presigned signature leaked into storage canonical ID: %s", stCanon)
	}
	if stCanon != "aws_s3://mybucket" {
		t.Fatalf("expected aws_s3://mybucket, got: %s", stCanon)
	}

	// 3. Host normalizer stripping scheme, credentials, and paths
	canonHost, ip, hostname := NormalizeHostCanonicalID("https://admin:token123@app.secure.corp:8443/dashboard")
	if strings.Contains(canonHost, "admin") || strings.Contains(canonHost, "token123") || strings.Contains(canonHost, "dashboard") {
		t.Fatalf("credentials or path leaked into host canonical ID: %s", canonHost)
	}
	if canonHost != "app.secure.corp" || hostname != "app.secure.corp" || ip != "" {
		t.Fatalf("expected app.secure.corp, got canon=%s, host=%s, ip=%s", canonHost, hostname, ip)
	}

	// 4. Service banner containing API token redacted
	svc := NewServiceAsset("asm-1", "exec-1", "tgt-1", "10.0.0.1", 22, "tcp", ServiceDetails{
		ServiceName: "ssh",
		Port:        22,
		Protocol:    "tcp",
		Banner:      "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1 token=" + "ghp_" + "ABC1234567890123456789012345678901234567",
	})
	if strings.Contains(svc.Service.Banner, "ghp_") {
		t.Fatalf("secret leaked in service banner: %s", svc.Service.Banner)
	}
	if !strings.Contains(svc.Service.Banner, "[REDACTED]") {
		t.Fatalf("expected [REDACTED] in service banner: %s", svc.Service.Banner)
	}

	// 5. Query parameter value with JWT redacted even if param key is generic
	u, err := SanitizeURLForCanonicalID("https://example.com/callback?state=eyJhYmMiOiJkZWYifQ.eyJhYmMiOiJkZWYifQ.abcdefghij1234567890")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if strings.Contains(u.RawQuery, "eyJhYmM") {
		t.Fatalf("JWT token leaked in query parameter value: %s", u.RawQuery)
	}
	if !strings.Contains(u.RawQuery, "state=REDACTED") {
		t.Fatalf("expected state=REDACTED, got: %s", u.RawQuery)
	}
}

func TestControllerProductionFlowSimulation(t *testing.T) {
	inv := NewInventory()
	asmID := "asm-prod-sim-01"
	execID := "exec-prod-sim-01"
	tgtID := "tgt-prod-sim-01"
	targetURL := "https://production.example.com"

	// 1. Root Application
	rootApp := NewApplicationAsset(asmID, execID, tgtID, targetURL, ApplicationDetails{
		AppType:   "web",
		RootURL:   targetURL,
		TechStack: []string{"Next.js", "PostgreSQL"},
	})
	rootAppID := inv.AddAsset(rootApp)

	// 2. Crawler discovery flow
	crawledAssets := []crawler.Asset{
		{URL: "https://production.example.com/", StatusCode: 200, ContentType: "text/html", InScope: true},
		{URL: "https://production.example.com/static/bundle.js", StatusCode: 200, ContentType: "application/javascript", Type: crawler.AssetJavaScript, InScope: true},
		{URL: "https://production.example.com/static/styles.css", StatusCode: 200, ContentType: "text/css", Type: crawler.AssetStylesheet, InScope: true},
	}
	for _, a := range crawledAssets {
		IngestCrawlerAsset(inv, asmID, execID, tgtID, rootAppID, a)
	}

	// 3. API detector discovery flow
	apiEndpoints := []api.DiscoveredEndpoint{
		{
			Path:               "/api/v1/auth/login",
			Method:             "POST",
			SourceAsset:        "https://production.example.com/static/bundle.js",
			Classification:     api.ClassAuth,
			AuthState:          api.AuthStatePublic,
			HTTPStatus:         200,
			StaticallyResolved: true,
		},
		{
			Path:               "/api/v1/user/profile",
			Method:             "GET",
			SourceAsset:        "https://production.example.com/static/bundle.js",
			Classification:     api.ClassUser,
			AuthState:          api.AuthStateAuthRequired,
			HTTPStatus:         401,
			StaticallyResolved: true,
		},
	}
	IngestAPIEndpoints(inv, asmID, execID, tgtID, targetURL, rootAppID, apiEndpoints)

	// 4. Cloud detector discovery flow
	cloudServices := []cloud.Service{
		{
			Provider: cloud.ProviderAWS,
			URL:      "https://prod-media-assets.s3.amazonaws.com",
			Source:   "Next.js Image Loader",
			Identifiers: map[string]string{
				"bucket": "prod-media-assets",
				"region": "us-east-1",
			},
		},
		{
			Provider: cloud.ProviderSupabase,
			URL:      "https://appdb.supabase.co",
			Source:   "Runtime Config",
			Identifiers: map[string]string{
				"project": "appdb",
			},
		},
	}
	IngestCloudServices(inv, asmID, execID, tgtID, rootAppID, cloudServices)

	// 5. APK / Mobile Artifact flow
	apk := APKDetails{
		PackageName: "com.example.production",
		VersionName: "2.1.0",
		VersionCode: 210,
		SHA256:      "11223344556677889900aabbccddeeff11223344556677889900aabbccddeeff",
	}
	IngestAPKArtifact(inv, asmID, execID, tgtID, rootAppID, apk)

	// 6. Comprehensive Graph Verifications
	summary := inv.Summary()
	if summary.ApplicationsCount < 1 {
		t.Fatalf("expected at least 1 application, got %d", summary.ApplicationsCount)
	}
	if summary.EndpointsCount < 4 { // root + bundle + login + profile
		t.Fatalf("expected at least 4 endpoints, got %d", summary.EndpointsCount)
	}
	if summary.StorageCount != 1 {
		t.Fatalf("expected 1 storage resource, got %d", summary.StorageCount)
	}
	if summary.DatabasesCount != 1 {
		t.Fatalf("expected 1 database resource, got %d", summary.DatabasesCount)
	}
	if summary.APKCount != 1 {
		t.Fatalf("expected 1 APK artifact, got %d", summary.APKCount)
	}
	if summary.TotalRelations < 5 {
		t.Fatalf("expected at least 5 relations, got %d", summary.TotalRelations)
	}

	// Verify all relationships originate from or relate to valid assets
	for _, rel := range inv.Relations {
		if rel.SourceAssetID == "" || rel.TargetAssetID == "" {
			t.Fatalf("empty asset ID in relation: %+v", rel)
		}
		if rel.SourceAssetID == rel.TargetAssetID {
			t.Fatalf("prohibited self-referential relation: %+v", rel)
		}
		if !strings.HasPrefix(rel.ID, "rel_") {
			t.Fatalf("expected deterministic relation ID prefix rel_, got: %s", rel.ID)
		}
	}
}
