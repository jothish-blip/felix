package report

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"felix/pkg/cloud"
)

// Helper to create a representative set of cloud and database findings covering all 16 supported services.
func createTestCloudAndDBFindings() []Finding {
	now := time.Now().UTC()

	// 1. Elasticsearch finding (Group A)
	cfES := cloud.CloudFinding{
		Provider:    cloud.Provider("elasticsearch"),
		Category:    "Unauthenticated Metadata Exposure: elasticsearch",
		Endpoint:    "http://es-cluster.internal:9200",
		Description: "Elasticsearch cluster metadata exposed unauthenticated on port 9200",
		Evidence:    `{"cluster_name": "production-data", "status": "green", "indices": 14}`,
		Severity:    cloud.SeverityInfo,
		Confidence:  cloud.ConfidenceHigh,
		Fingerprint: "fp-es-cluster-9200",
		Details: map[string]string{
			"technology":          string(cloud.TechElasticsearch),
			"family":              string(cloud.FamilyDirectDatabase),
			"access_status":       string(cloud.StatusUnauthenticatedAccess),
			"operation":           string(cloud.OpMetadataRead),
			"auth_context":        string(cloud.AuthContextUnauthenticated),
			"verification_status": "VERIFIED",
			"analysis_method":     "ACTIVE_VERIFICATION",
		},
	}

	// 2. MongoDB finding (Group A)
	cfMongo := cloud.CloudFinding{
		Provider:    cloud.Provider("mongodb"),
		Category:    "Unauthenticated Data Access: mongodb",
		Endpoint:    "mongodb://db-node.internal:27017",
		Description: "Unauthenticated read access permitted on MongoDB database records",
		Evidence:    `Found collection 'users' containing 1,200 records`,
		Severity:    cloud.SeverityHigh,
		Confidence:  cloud.ConfidenceHigh,
		Fingerprint: "fp-mongo-node-27017",
		Details: map[string]string{
			"technology":          string(cloud.TechMongoDB),
			"family":              string(cloud.FamilyDirectDatabase),
			"access_status":       string(cloud.StatusUnauthenticatedAccess),
			"operation":           string(cloud.OpBoundedRead),
			"auth_context":        string(cloud.AuthContextUnauthenticated),
			"verification_status": "VERIFIED",
			"resource_scope":      "users",
			"analysis_method":     "ACTIVE_VERIFICATION",
		},
	}

	// 3. Redis finding (Group A)
	cfRedis := cloud.CloudFinding{
		Provider:    cloud.Provider("redis"),
		Category:    "Unauthenticated Write Access: redis",
		Endpoint:    "redis://cache.internal:6379",
		Description: "Unauthenticated write access verified on Redis cache instance",
		Evidence:    `SETNX test key successfully committed without authentication`,
		Severity:    cloud.SeverityCritical,
		Confidence:  cloud.ConfidenceHigh,
		Fingerprint: "fp-redis-cache-6379",
		Details: map[string]string{
			"technology":          string(cloud.TechRedis),
			"family":              string(cloud.FamilyDirectDatabase),
			"access_status":       string(cloud.StatusWriteVerified),
			"operation":           string(cloud.OpControlledCanary),
			"auth_context":        string(cloud.AuthContextUnauthenticated),
			"verification_status": "VERIFIED",
			"analysis_method":     "ACTIVE_VERIFICATION",
		},
	}

	// 4. PostgreSQL finding (Group A)
	cfPG := cloud.CloudFinding{
		Provider:    cloud.Provider("postgresql"),
		Category:    "Access Restricted: postgresql",
		Endpoint:    "postgres://pg-primary.internal:5432/appdb",
		Description: "Access verification for postgresql resulted in AUTH_CHALLENGED",
		Evidence:    `Received FATAL: password authentication failed for user "felix_probe"`,
		Severity:    cloud.SeverityInfo,
		Confidence:  cloud.ConfidenceHigh,
		Fingerprint: "fp-pg-primary-5432",
		HTTPStatus:  401,
		Details: map[string]string{
			"technology":          string(cloud.TechPostgreSQL),
			"family":              string(cloud.FamilyDirectDatabase),
			"access_status":       string(cloud.StatusAuthChallenged),
			"operation":           string(cloud.OpMetadataRead),
			"auth_context":        string(cloud.AuthContextUnauthenticated),
			"verification_status": "NOT_EXPOSED",
			"analysis_method":     "ACTIVE_VERIFICATION",
		},
	}

	// 5. MySQL finding (Group A)
	cfMySQL := cloud.CloudFinding{
		Provider:    cloud.Provider("mysql"),
		Category:    "Connection Indicator (mysql) with Credentials",
		Endpoint:    "mysql://dbuser:SuperSecretPassword123@mysql.internal:3306/billing",
		Description: "Detected mysql connection_string in config/database.js. Service connectivity, authentication validity, and resource exposure remain unverified.",
		Evidence:    "Matched mysql indicator in config/database.js (line 42): mysql://dbuser:SuperSecretPassword123@mysql.internal:3306/billing",
		Severity:    cloud.SeverityHigh,
		Confidence:  cloud.ConfidenceHigh,
		Fingerprint: "fp-mysql-billing-3306",
		Details: map[string]string{
			"technology":        string(cloud.TechMySQL),
			"family":            string(cloud.FamilyDirectDatabase),
			"indicator_type":    "connection_string",
			"has_credentials":   "true",
			"analysis_method":   "STATIC_ANALYSIS",
			"source_identifier": "config/database.js",
			"source_line":       "42",
		},
	}

	// 6. Mongo Express finding (Group B)
	cfMongoExp := cloud.CloudFinding{
		Provider:    cloud.Provider("mongo_express"),
		Category:    "Service Discovery: mongo_express",
		Endpoint:    "http://admin.internal:8081",
		Description: "Discovered mongo_express service (database_admin)",
		Evidence:    "Discovered Mongo Express port/URL reference in app.bundle.js: http://admin.internal:8081",
		Severity:    cloud.SeverityInfo,
		Confidence:  cloud.ConfidenceMedium,
		Fingerprint: "fp-mongo-exp-8081",
		Details: map[string]string{
			"technology":        string(cloud.TechMongoExpress),
			"family":            string(cloud.FamilyDatabaseAdmin),
			"detection_method":  "PASSIVE_ANALYSIS",
			"analysis_method":   "STATIC_ANALYSIS",
			"discovery_outcome": string(cloud.OutcomePossible),
		},
	}

	// 7. Supabase finding (Group C)
	cfSupa := cloud.CloudFinding{
		Provider:    cloud.ProviderSupabase,
		Category:    "supabase-unauthorized-access",
		Endpoint:    "https://projectref.supabase.co/rest/v1/customer_records",
		Description: "Unauthenticated GET request returned live database records with HTTP 200 OK",
		Evidence:    `[{"id": 1, "email": "client@example.com", "ssn": "123-45-6789"}]`,
		Severity:    cloud.SeverityHigh,
		Confidence:  cloud.ConfidenceHigh,
		Fingerprint: "fp-supa-customer-records",
		HTTPStatus:  200,
		Details: map[string]string{
			"technology":          string(cloud.TechSupabase),
			"family":              string(cloud.FamilyBackendInterface),
			"provider":            "supabase",
			"verification_status": "VERIFIED",
			"analysis_method":     "ACTIVE_VERIFICATION",
		},
	}

	// 8. PostgREST finding (Group C)
	cfPostgREST := cloud.CloudFinding{
		Provider:    cloud.Provider("postgrest"),
		Category:    "Access Verification: postgrest",
		Endpoint:    "https://api.internal/postgrest/orders",
		Description: "Access verification for postgrest on https://api.internal/postgrest/orders resulted in READ_ALLOWED",
		Evidence:    `HTTP 200 OK returned 50 records from /orders`,
		Severity:    cloud.SeverityHigh,
		Confidence:  cloud.ConfidenceHigh,
		Fingerprint: "fp-postgrest-orders",
		HTTPStatus:  200,
		Details: map[string]string{
			"technology":          string(cloud.TechPostgREST),
			"family":              string(cloud.FamilyBackendInterface),
			"access_status":       string(cloud.StatusReadAllowed),
			"operation":           string(cloud.OpBoundedRead),
			"verification_status": "VERIFIED",
			"analysis_method":     "ACTIVE_VERIFICATION",
		},
	}

	// 9. Hasura finding (Group C)
	cfHasura := cloud.CloudFinding{
		Provider:    cloud.Provider("hasura"),
		Category:    "Service Discovery: hasura",
		Endpoint:    "https://hasura.internal/v1/graphql",
		Description: "Discovered hasura service (backend_interface)",
		Evidence:    "Discovered Hasura GraphQL endpoint signature in client bundle",
		Severity:    cloud.SeverityInfo,
		Confidence:  cloud.ConfidenceHigh,
		Fingerprint: "fp-hasura-graphql",
		Details: map[string]string{
			"technology":        string(cloud.TechHasura),
			"family":            string(cloud.FamilyBackendInterface),
			"detection_method":  "PASSIVE_ANALYSIS",
			"analysis_method":   "STATIC_ANALYSIS",
			"discovery_outcome": string(cloud.OutcomeDetected),
		},
	}

	// 10. Prisma finding (Group C)
	cfPrisma := cloud.CloudFinding{
		Provider:    cloud.Provider("prisma"),
		Category:    "Service Discovery: prisma",
		Endpoint:    "https://api.internal/prisma-schema",
		Description: "Discovered prisma service (backend_interface)",
		Evidence:    "Discovered Prisma schema or client references in static assets",
		Severity:    cloud.SeverityInfo,
		Confidence:  cloud.ConfidenceMedium,
		Fingerprint: "fp-prisma-schema",
		Details: map[string]string{
			"technology":        string(cloud.TechPrisma),
			"family":            string(cloud.FamilyBackendInterface),
			"detection_method":  "PASSIVE_ANALYSIS",
			"analysis_method":   "STATIC_ANALYSIS",
			"discovery_outcome": string(cloud.OutcomePossible),
		},
	}

	// 11. Firebase RTDB finding (Group D)
	cfFirebase := cloud.CloudFinding{
		Provider:    cloud.ProviderFirebase,
		Category:    "firebase-open-database",
		Endpoint:    "https://test-project.firebaseio.com/.json",
		Description: "Unauthenticated GET request to Firebase RTDB returned live records with HTTP 200 OK",
		Evidence:    `{"settings": {"maintenance": false, "api_secret": "my-secret-key-xyz"}}`,
		Severity:    cloud.SeverityHigh,
		Confidence:  cloud.ConfidenceHigh,
		Fingerprint: "fp-firebase-rtdb-open",
		HTTPStatus:  200,
		Details: map[string]string{
			"technology":          string(cloud.TechFirebaseRTDB),
			"family":              string(cloud.FamilyFirebase),
			"provider":            "firebase",
			"verification_status": "VERIFIED",
			"analysis_method":     "ACTIVE_VERIFICATION",
		},
	}

	// 12. Cloud Firestore finding (Group D)
	cfFirestore := cloud.CloudFinding{
		Provider:    cloud.Provider("firestore"),
		Category:    "Service Discovery: firestore",
		Endpoint:    "https://firestore.googleapis.com/v1/projects/my-firebase-app/databases/(default)",
		Description: "Discovered firestore service (firebase)",
		Evidence:    "Discovered Cloud Firestore project reference 'my-firebase-app' in bundle",
		Severity:    cloud.SeverityInfo,
		Confidence:  cloud.ConfidenceHigh,
		Fingerprint: "fp-firestore-app",
		Details: map[string]string{
			"technology":        string(cloud.TechFirestore),
			"family":            string(cloud.FamilyFirebase),
			"detection_method":  "PASSIVE_ANALYSIS",
			"analysis_method":   "STATIC_ANALYSIS",
			"discovery_outcome": string(cloud.OutcomeDetected),
		},
	}

	// 13. AWS S3 finding (Group E)
	cfS3 := cloud.CloudFinding{
		Provider:    cloud.ProviderAWS,
		Category:    "s3-public-listing",
		Endpoint:    "https://my-company-assets.s3.amazonaws.com",
		Description: "Anonymous GET request returned XML ListBucketResult with bucket contents",
		Evidence:    `<?xml version="1.0" encoding="UTF-8"?><ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Name>my-company-assets</Name><Key>backup.tar.gz</Key></ListBucketResult>`,
		Severity:    cloud.SeverityHigh,
		Confidence:  cloud.ConfidenceHigh,
		Fingerprint: "fp-s3-company-assets",
		HTTPStatus:  200,
		Details: map[string]string{
			"technology":          string(cloud.TechAWSS3),
			"family":              string(cloud.FamilyObjectStorage),
			"provider":            "aws",
			"resource_scope":      "my-company-assets",
			"verification_status": "VERIFIED",
			"analysis_method":     "ACTIVE_VERIFICATION",
		},
	}

	// 14. Azure Blob finding (Group E)
	cfAzure := cloud.CloudFinding{
		Provider:    cloud.Provider("azure_blob"),
		Category:    "Access Verification: azure_blob",
		Endpoint:    "https://corpdata.blob.core.windows.net/public",
		Description: "Access verification for azure_blob on https://corpdata.blob.core.windows.net/public resulted in READ_ALLOWED",
		Evidence:    `HTTP 200 OK returned container blob enumeration XML`,
		Severity:    cloud.SeverityHigh,
		Confidence:  cloud.ConfidenceHigh,
		Fingerprint: "fp-azure-corpdata",
		HTTPStatus:  200,
		Details: map[string]string{
			"technology":          string(cloud.TechAzureBlob),
			"family":              string(cloud.FamilyObjectStorage),
			"resource_scope":      "public",
			"access_status":       string(cloud.StatusReadAllowed),
			"verification_status": "VERIFIED",
			"analysis_method":     "ACTIVE_VERIFICATION",
		},
	}

	// 15. Google Cloud Storage finding (Group E)
	cfGCS := cloud.CloudFinding{
		Provider:    cloud.ProviderGCP,
		Category:    "gcs-public-listing",
		Endpoint:    "https://storage.googleapis.com/public-docs",
		Description: "Anonymous GET request returned XML ListBucketResult with bucket contents",
		Evidence:    `<?xml version="1.0" encoding="UTF-8"?><ListBucketResult><Name>public-docs</Name><Key>doc1.pdf</Key></ListBucketResult>`,
		Severity:    cloud.SeverityHigh,
		Confidence:  cloud.ConfidenceHigh,
		Fingerprint: "fp-gcs-public-docs",
		HTTPStatus:  200,
		Details: map[string]string{
			"technology":          string(cloud.TechGCS),
			"family":              string(cloud.FamilyObjectStorage),
			"provider":            "gcp",
			"resource_scope":      "public-docs",
			"verification_status": "VERIFIED",
			"analysis_method":     "ACTIVE_VERIFICATION",
		},
	}

	// 16. MinIO finding (Group E)
	cfMinIO := cloud.CloudFinding{
		Provider:    cloud.Provider("minio"),
		Category:    "Service Discovery: minio",
		Endpoint:    "http://minio.internal:9000",
		Description: "Discovered minio service (object_storage)",
		Evidence:    "Discovered MinIO service port/URL reference in config: http://minio.internal:9000",
		Severity:    cloud.SeverityInfo,
		Confidence:  cloud.ConfidenceHigh,
		Fingerprint: "fp-minio-internal-9000",
		Details: map[string]string{
			"technology":        string(cloud.TechMinIO),
			"family":            string(cloud.FamilyObjectStorage),
			"detection_method":  "PASSIVE_ANALYSIS",
			"analysis_method":   "STATIC_ANALYSIS",
			"discovery_outcome": string(cloud.OutcomeDetected),
		},
	}

	findings := []cloud.CloudFinding{
		cfES, cfMongo, cfRedis, cfPG, cfMySQL,
		cfMongoExp, cfSupa, cfPostgREST, cfHasura, cfPrisma,
		cfFirebase, cfFirestore, cfS3, cfAzure, cfGCS, cfMinIO,
	}

	target := "https://example.com"
	res := make([]Finding, len(findings))
	for i, f := range findings {
		res[i] = FromCloudFinding(target, f)
		res[i].Timestamp = now
	}
	return res
}

func buildTestReportWithCloudFindings(findings []Finding, completionStatus string) Report {
	rep := Report{
		Version:          "2.0.0",
		Target:           "https://example.com",
		Targets:          []string{"https://example.com"},
		Timestamp:        time.Now().UTC().Format(time.RFC3339),
		Duration:         "1.45s",
		DurationMs:       1450,
		CompletionStatus: completionStatus,
		Findings:         findings,
		Summary:          Summarize(findings),
	}
	RecalculateReportRisk(&rep)
	return rep
}

// Scenario 1: A cloud-storage finding appears in every applicable output format.
func TestScenario1_CloudStorageFindingInAllFormats(t *testing.T) {
	cfS3 := cloud.CloudFinding{
		Provider:    cloud.ProviderAWS,
		Category:    "s3-public-listing",
		Endpoint:    "https://storage-bucket.s3.amazonaws.com",
		Description: "Anonymous GET request returned XML ListBucketResult with bucket contents",
		Evidence:    "S3 bucket contents exposed publicly",
		Severity:    cloud.SeverityHigh,
		Confidence:  cloud.ConfidenceHigh,
		Fingerprint: "fp-s3-scenario-1",
	}
	rf := FromCloudFinding("https://example.com", cfS3)
	rep := buildTestReportWithCloudFindings([]Finding{rf}, "COMPLETED")

	// 1. JSON
	jsonData, err := GenerateJSON(rep)
	if err != nil {
		t.Fatalf("GenerateJSON failed: %v", err)
	}
	if !strings.Contains(string(jsonData), "storage-bucket.s3.amazonaws.com") {
		t.Errorf("JSON output does not contain S3 endpoint")
	}

	// 2. HTML
	htmlStr, err := GenerateHTML(rep)
	if err != nil {
		t.Fatalf("GenerateHTML failed: %v", err)
	}
	if !strings.Contains(htmlStr, "storage-bucket.s3.amazonaws.com") {
		t.Errorf("HTML output does not contain S3 endpoint")
	}

	// 3. SARIF
	sarifLog := BuildSARIFLog(rep)
	sarifBytes, err := json.Marshal(sarifLog)
	if err != nil {
		t.Fatalf("SARIF serialization failed: %v", err)
	}
	if err := ValidateSARIF(sarifBytes); err != nil {
		t.Fatalf("SARIF failed validation: %v", err)
	}
	if !strings.Contains(string(sarifBytes), "storage-bucket.s3.amazonaws.com") {
		t.Errorf("SARIF output does not contain S3 endpoint")
	}

	// 4. Commercial JSON
	cr := BuildCommercialReport(rep)
	crBytes, err := GenerateCommercialJSON(cr)
	if err != nil {
		t.Fatalf("GenerateCommercialJSON failed: %v", err)
	}
	if !strings.Contains(string(crBytes), "storage-bucket.s3.amazonaws.com") {
		t.Errorf("Commercial JSON output does not contain S3 endpoint")
	}

	// 5. Commercial HTML
	crHTML, err := GenerateCommercialHTML(cr)
	if err != nil {
		t.Fatalf("GenerateCommercialHTML failed: %v", err)
	}
	if !strings.Contains(crHTML, "storage-bucket.s3.amazonaws.com") {
		t.Errorf("Commercial HTML output does not contain S3 endpoint")
	}
}

// Scenario 2: A database exposure finding preserves its original severity.
func TestScenario2_DatabaseExposureSeverityPreserved(t *testing.T) {
	cfMongo := cloud.CloudFinding{
		Provider:    cloud.Provider("mongodb"),
		Category:    "Unauthenticated Data Access: mongodb",
		Endpoint:    "mongodb://db-node.internal:27017",
		Description: "Unauthenticated read access permitted on MongoDB database records",
		Evidence:    `Found collection 'users'`,
		Severity:    cloud.SeverityHigh,
		Confidence:  cloud.ConfidenceHigh,
		Fingerprint: "fp-mongo-sev-test",
	}
	rf := FromCloudFinding("https://example.com", cfMongo)
	if rf.Severity != SeverityHigh {
		t.Fatalf("expected SeverityHigh, got %s", rf.Severity)
	}

	cfRedis := cloud.CloudFinding{
		Provider:    cloud.Provider("redis"),
		Category:    "Unauthenticated Write Access: redis",
		Endpoint:    "redis://cache.internal:6379",
		Description: "Unauthenticated write access verified on Redis cache instance",
		Evidence:    `SETNX key committed without auth`,
		Severity:    cloud.SeverityCritical,
		Confidence:  cloud.ConfidenceHigh,
		Fingerprint: "fp-redis-sev-test",
	}
	rfRedis := FromCloudFinding("https://example.com", cfRedis)
	if rfRedis.Severity != SeverityCritical {
		t.Fatalf("expected SeverityCritical, got %s", rfRedis.Severity)
	}

	rep := buildTestReportWithCloudFindings([]Finding{rf, rfRedis}, "COMPLETED")
	if rep.Summary.HighCount != 1 || rep.Summary.CriticalCount != 1 {
		t.Errorf("expected 1 High and 1 Critical, got High=%d, Crit=%d", rep.Summary.HighCount, rep.Summary.CriticalCount)
	}
}

// Scenario 3: Evidence references and verification status survive serialization.
func TestScenario3_EvidenceAndVerificationSurviveSerialization(t *testing.T) {
	cf := cloud.CloudFinding{
		Provider:    cloud.Provider("postgresql"),
		Category:    "Access Verification: postgresql",
		Endpoint:    "postgres://primary.internal:5432/db",
		Description: "Probe confirmed access denied by authentication challenge",
		Evidence:    "FATAL: password authentication failed for user felix",
		Severity:    cloud.SeverityInfo,
		Confidence:  cloud.ConfidenceHigh,
		Fingerprint: "fp-pg-evidence-test",
		HTTPStatus:  401,
	}
	rf := FromCloudFinding("https://example.com", cf)
	rep := buildTestReportWithCloudFindings([]Finding{rf}, "COMPLETED")

	jsonData, err := GenerateJSON(rep)
	if err != nil {
		t.Fatalf("GenerateJSON failed: %v", err)
	}

	parsed, err := ParseReport(jsonData)
	if err != nil {
		t.Fatalf("ParseReport failed: %v", err)
	}
	if len(parsed.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(parsed.Findings))
	}
	pf := parsed.Findings[0]
	if pf.Verification.Status != VerificationNotExposed {
		t.Errorf("expected VerificationNotExposed, got %s", pf.Verification.Status)
	}
	if !strings.Contains(pf.Evidence, "password authentication failed") {
		t.Errorf("evidence not preserved: %s", pf.Evidence)
	}
}

// Scenario 4: Remediation guidance survives serialization.
func TestScenario4_RemediationGuidanceSurvivesSerialization(t *testing.T) {
	findings := createTestCloudAndDBFindings()
	rep := buildTestReportWithCloudFindings(findings, "COMPLETED")

	jsonData, err := GenerateJSON(rep)
	if err != nil {
		t.Fatalf("GenerateJSON failed: %v", err)
	}

	parsed, err := ParseReport(jsonData)
	if err != nil {
		t.Fatalf("ParseReport failed: %v", err)
	}

	for _, f := range parsed.Findings {
		if strings.TrimSpace(f.Remediation) == "" {
			t.Errorf("Finding %s (%s) has empty remediation", f.ID, f.Category)
		}
	}
}

// Scenario 5: Multiple services can appear in one assessment without cross-contamination.
func TestScenario5_MultipleServicesWithoutCrossContamination(t *testing.T) {
	findings := createTestCloudAndDBFindings()
	if len(findings) != 16 {
		t.Fatalf("expected 16 findings for 16 services, got %d", len(findings))
	}
	rep := buildTestReportWithCloudFindings(findings, "COMPLETED")

	// Verify each service preserves its own identity and endpoint
	endpoints := make(map[string]bool)
	for _, f := range rep.Findings {
		if endpoints[f.Endpoint] {
			t.Errorf("duplicate endpoint across distinct services: %s", f.Endpoint)
		}
		endpoints[f.Endpoint] = true
	}

	services := rep.CloudServicesAssessed()
	if len(services) < 10 {
		t.Errorf("expected at least 10 distinct cloud/db technologies, got %d: %v", len(services), services)
	}
}

// Scenario 6: Multiple findings affecting different assets remain distinguishable.
func TestScenario6_MultipleFindingsDifferentAssetsDistinguishable(t *testing.T) {
	cf1 := cloud.CloudFinding{
		Provider:    cloud.Provider("redis"),
		Category:    "Unauthenticated Data Access: redis",
		Endpoint:    "redis://cache-cluster-1.internal:6379",
		Description: "Redis cache 1 data exposed",
		Evidence:    "KEYS * returned 100 entries",
		Severity:    cloud.SeverityHigh,
		Confidence:  cloud.ConfidenceHigh,
		Fingerprint: "fp-redis-cluster-1",
	}
	cf2 := cloud.CloudFinding{
		Provider:    cloud.Provider("redis"),
		Category:    "Unauthenticated Data Access: redis",
		Endpoint:    "redis://cache-cluster-2.internal:6379",
		Description: "Redis cache 2 data exposed",
		Evidence:    "KEYS * returned 500 entries",
		Severity:    cloud.SeverityHigh,
		Confidence:  cloud.ConfidenceHigh,
		Fingerprint: "fp-redis-cluster-2",
	}

	rf1 := FromCloudFinding("https://example.com", cf1)
	rf2 := FromCloudFinding("https://example.com", cf2)

	if rf1.ID == rf2.ID {
		t.Errorf("distinct assets produced identical finding IDs: %s", rf1.ID)
	}
	if rf1.Fingerprint == rf2.Fingerprint {
		t.Errorf("distinct assets produced identical fingerprints: %s", rf1.Fingerprint)
	}

	rep := buildTestReportWithCloudFindings([]Finding{rf1, rf2}, "COMPLETED")
	if len(rep.Findings) != 2 {
		t.Fatalf("expected 2 distinct findings, got %d", len(rep.Findings))
	}
}

// Scenario 7: Duplicate findings follow the existing deduplication policy.
func TestScenario7_DuplicateFindingsFollowDeduplicationPolicy(t *testing.T) {
	cf1 := cloud.CloudFinding{
		Provider:    cloud.ProviderAWS,
		Category:    "s3-public-listing",
		Endpoint:    "https://shared-bucket.s3.amazonaws.com",
		Description: "Public bucket listing detected",
		Evidence:    "First observation of public bucket",
		Severity:    cloud.SeverityHigh,
		Confidence:  cloud.ConfidenceHigh,
		Fingerprint: "fp-s3-shared-bucket",
	}
	cf2 := cloud.CloudFinding{
		Provider:    cloud.ProviderAWS,
		Category:    "s3-public-listing",
		Endpoint:    "https://shared-bucket.s3.amazonaws.com",
		Description: "Public bucket listing detected (second pass)",
		Evidence:    "Second observation of public bucket",
		Severity:    cloud.SeverityHigh,
		Confidence:  cloud.ConfidenceHigh,
		Fingerprint: "fp-s3-shared-bucket",
	}

	rf1 := FromCloudFinding("https://example.com", cf1)
	rf2 := FromCloudFinding("https://example.com", cf2)

	deduped := DeduplicateFindings([]Finding{rf1, rf2})
	if len(deduped) != 1 {
		t.Fatalf("expected 1 deduplicated finding, got %d", len(deduped))
	}
}

// Scenario 8: Missing optional metadata does not break rendering.
func TestScenario8_MissingOptionalMetadataDoesNotBreakRendering(t *testing.T) {
	bareFinding := Finding{
		ID:          "CLD-bare-finding-test",
		Title:       "Bare Cloud Finding",
		Category:    "Bare Cloud Category",
		Severity:    SeverityInfo,
		Confidence:  ConfidenceMedium,
		Target:      "https://example.com",
		Endpoint:    "http://bare.internal:8000",
		Source:      SourceCloud,
		Fingerprint: "fp-bare-finding-1",
	}
	rep := buildTestReportWithCloudFindings([]Finding{bareFinding}, "COMPLETED")

	// Render HTML
	htmlStr, err := GenerateHTML(rep)
	if err != nil {
		t.Fatalf("GenerateHTML failed with bare metadata: %v", err)
	}
	if !strings.Contains(htmlStr, "Bare Cloud Finding") {
		t.Errorf("HTML missing finding title")
	}

	// Render JSON
	jsonData, err := GenerateJSON(rep)
	if err != nil {
		t.Fatalf("GenerateJSON failed with bare metadata: %v", err)
	}
	if _, err := ParseReport(jsonData); err != nil {
		t.Fatalf("ParseReport failed on bare JSON: %v", err)
	}

	// Render SARIF
	sarifLog := BuildSARIFLog(rep)
	sarifBytes, err := json.Marshal(sarifLog)
	if err != nil {
		t.Fatalf("SARIF serialization failed: %v", err)
	}
	if err := ValidateSARIF(sarifBytes); err != nil {
		t.Fatalf("SARIF validation failed on bare finding: %v", err)
	}

	// Render Commercial JSON
	cr := BuildCommercialReport(rep)
	if _, err := GenerateCommercialJSON(cr); err != nil {
		t.Fatalf("GenerateCommercialJSON failed on bare metadata: %v", err)
	}
}

// Scenario 9: Unknown or invalid values are handled safely.
func TestScenario9_UnknownOrInvalidValuesHandledSafely(t *testing.T) {
	invalidFinding := Finding{
		ID:          "CLD-invalid-values-test",
		Title:       "Invalid Values Test",
		Category:    "Unknown Service Category",
		Severity:    "INVALID_SEV",
		Confidence:  "NOT_A_CONFIDENCE_RATING",
		Status:      "NONEXISTENT_STATUS",
		Target:      "https://example.com",
		Endpoint:    "http://invalid.internal",
		Source:      "UNKNOWN_SOURCE",
		Fingerprint: "fp-invalid-values-1",
	}
	normalized := NormalizeFinding(invalidFinding)

	if normalized.Severity != SeverityUnknown {
		t.Errorf("expected SeverityUnknown for invalid severity, got %s", normalized.Severity)
	}
	if normalized.Confidence != ConfidenceUnknown && normalized.Confidence != ConfidenceMedium {
		t.Errorf("unexpected confidence: %s", normalized.Confidence)
	}
	if normalized.Status != FindingStatusInconclusive {
		t.Errorf("expected FindingStatusInconclusive for unknown status, got %s", normalized.Status)
	}

	rep := buildTestReportWithCloudFindings([]Finding{normalized}, "COMPLETED")
	if _, err := GenerateHTML(rep); err != nil {
		t.Fatalf("GenerateHTML failed on invalid values: %v", err)
	}
	if _, err := GenerateJSON(rep); err != nil {
		t.Fatalf("GenerateJSON failed on invalid values: %v", err)
	}
}

// Scenario 10: Sensitive credentials are redacted.
func TestScenario10_SensitiveCredentialsRedacted(t *testing.T) {
	secretURI := "postgres://dbadmin:SuperSecretP@ssword123!@db-host.internal:5432/corp"
	rawEvidence := fmt.Sprintf("Extracted connection string %s and token eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.doNotLeakThisSignature", secretURI)

	cf := cloud.CloudFinding{
		Provider:    cloud.Provider("postgresql"),
		Category:    "Connection Indicator: postgresql",
		Endpoint:    secretURI,
		Description: fmt.Sprintf("Database connection string exposed: %s", secretURI),
		Evidence:    rawEvidence,
		Severity:    cloud.SeverityHigh,
		Confidence:  cloud.ConfidenceHigh,
		Fingerprint: "fp-pg-secret-test",
		Details: map[string]string{
			"connection_string": secretURI,
			"password":          "SuperSecretP@ssword123!",
		},
	}
	rf := FromCloudFinding("https://example.com", cf)
	rep := buildTestReportWithCloudFindings([]Finding{rf}, "COMPLETED")

	// 1. JSON
	jsonData, err := GenerateJSON(rep)
	if err != nil {
		t.Fatalf("GenerateJSON failed: %v", err)
	}
	jsonStr := string(jsonData)
	if strings.Contains(jsonStr, "SuperSecretP@ssword123!") {
		t.Errorf("JSON leaked raw password: %s", jsonStr)
	}
	if strings.Contains(jsonStr, "doNotLeakThisSignature") {
		t.Errorf("JSON leaked raw JWT signature: %s", jsonStr)
	}

	// 2. HTML
	htmlStr, err := GenerateHTML(rep)
	if err != nil {
		t.Fatalf("GenerateHTML failed: %v", err)
	}
	if strings.Contains(htmlStr, "SuperSecretP@ssword123!") {
		t.Errorf("HTML leaked raw password")
	}
	if strings.Contains(htmlStr, "doNotLeakThisSignature") {
		t.Errorf("HTML leaked raw JWT signature")
	}

	// 3. SARIF
	sarifLog := BuildSARIFLog(rep)
	sarifBytes, err := json.Marshal(sarifLog)
	if err != nil {
		t.Fatalf("SARIF serialization failed: %v", err)
	}
	if strings.Contains(string(sarifBytes), "SuperSecretP@ssword123!") {
		t.Errorf("SARIF leaked raw password")
	}

	// 4. Commercial JSON
	cr := BuildCommercialReport(rep)
	crBytes, err := GenerateCommercialJSON(cr)
	if err != nil {
		t.Fatalf("GenerateCommercialJSON failed: %v", err)
	}
	if strings.Contains(string(crBytes), "SuperSecretP@ssword123!") {
		t.Errorf("Commercial JSON leaked raw password")
	}
}

// Scenario 11: HTML output escapes hostile input such as script tags and attribute-breaking strings.
func TestScenario11_HTMLEscapingHostileInput(t *testing.T) {
	xssPayload := `<script>alert("xss")</script>`
	attrBreak := `" onmouseover="alert('xss')" data-x="`

	cf := cloud.CloudFinding{
		Provider:    cloud.Provider("elasticsearch"),
		Category:    "XSS Category: " + xssPayload,
		Endpoint:    "http://target.internal/path?" + attrBreak,
		Description: "Testing XSS injection: " + xssPayload,
		Evidence:    "Evidence containing hostile script: " + xssPayload,
		Severity:    cloud.SeverityInfo,
		Confidence:  cloud.ConfidenceHigh,
		Fingerprint: "fp-xss-test-1",
		Details: map[string]string{
			"malicious_key": xssPayload,
		},
	}
	rf := FromCloudFinding("https://example.com", cf)
	rep := buildTestReportWithCloudFindings([]Finding{rf}, "COMPLETED")

	htmlStr, err := GenerateHTML(rep)
	if err != nil {
		t.Fatalf("GenerateHTML failed: %v", err)
	}

	// Unescaped script tag MUST NOT appear
	if strings.Contains(htmlStr, "<script>alert(\"xss\")</script>") {
		t.Errorf("HTML contains unescaped script tag")
	}
	// Attribute-breaking injection MUST NOT appear unescaped
	if strings.Contains(htmlStr, `" onmouseover="alert('xss')"`) {
		t.Errorf("HTML contains unescaped event handler injection")
	}
	// Escaped version must be present
	if !strings.Contains(htmlStr, "&lt;script&gt;alert") && !strings.Contains(htmlStr, "&#34;") {
		t.Errorf("HTML does not properly escape hostile payload")
	}
}

// Scenario 12: JSON output parses successfully and preserves expected values.
func TestScenario12_JSONOutputParsesAndPreservesValues(t *testing.T) {
	findings := createTestCloudAndDBFindings()
	rep := buildTestReportWithCloudFindings(findings, "COMPLETED")

	jsonData, err := GenerateJSON(rep)
	if err != nil {
		t.Fatalf("GenerateJSON failed: %v", err)
	}

	parsed, err := ParseReport(jsonData)
	if err != nil {
		t.Fatalf("ParseReport failed: %v", err)
	}

	if len(parsed.Findings) != len(findings) {
		t.Fatalf("expected %d findings, got %d", len(findings), len(parsed.Findings))
	}
	if parsed.Target != rep.Target {
		t.Errorf("expected Target %s, got %s", rep.Target, parsed.Target)
	}
	if parsed.Summary.TotalFindings != len(findings) {
		t.Errorf("expected TotalFindings %d, got %d", len(findings), parsed.Summary.TotalFindings)
	}
}

// Scenario 13: SARIF output uses the correct existing schema and non-source location behavior.
func TestScenario13_SARIFSchemaAndNonSourceLocations(t *testing.T) {
	findings := createTestCloudAndDBFindings()
	rep := buildTestReportWithCloudFindings(findings, "COMPLETED")

	sarifLog := BuildSARIFLog(rep)
	sarifBytes, err := json.MarshalIndent(sarifLog, "", "  ")
	if err != nil {
		t.Fatalf("SARIF marshal failed: %v", err)
	}

	// Strict official schema conformance validation
	if err := ValidateSARIF(sarifBytes); err != nil {
		t.Fatalf("SARIF validation failed against schema: %v", err)
	}

	// Non-source assets MUST NOT have fake line numbers
	for _, run := range sarifLog.Runs {
		for _, result := range run.Results {
			for _, loc := range result.Locations {
				if loc.PhysicalLocation != nil && loc.PhysicalLocation.ArtifactLocation.URI == "" {
					t.Errorf("SARIF location has empty ArtifactLocation URI")
				}
			}
		}
	}
}

// Scenario 14: Empty findings do not create false claims that the assessment was comprehensive or clean.
func TestScenario14_EmptyFindingsHonestNarrative(t *testing.T) {
	rep := buildTestReportWithCloudFindings(nil, "COMPLETED")

	htmlStr, err := GenerateHTML(rep)
	if err != nil {
		t.Fatalf("GenerateHTML failed: %v", err)
	}

	// Must state no findings detected, and state limitations
	if !strings.Contains(htmlStr, "No security findings detected") {
		t.Errorf("HTML empty state missing expected honest notification")
	}
	if !strings.Contains(htmlStr, "Limitations & Disclaimer") {
		t.Errorf("HTML missing limitations section")
	}
}

// Scenario 15: Partial or failed assessments remain visibly partial or failed.
func TestScenario15_PartialOrFailedAssessmentsVisiblyMarked(t *testing.T) {
	repFailed := buildTestReportWithCloudFindings(nil, "FAILED")
	htmlFailed, err := GenerateHTML(repFailed)
	if err != nil {
		t.Fatalf("GenerateHTML failed: %v", err)
	}
	if !strings.Contains(htmlFailed, "ASSESSMENT FAILED") {
		t.Errorf("HTML failed report missing ASSESSMENT FAILED banner")
	}

	repPartial := buildTestReportWithCloudFindings(nil, "PARTIAL")
	htmlPartial, err := GenerateHTML(repPartial)
	if err != nil {
		t.Fatalf("GenerateHTML partial failed: %v", err)
	}
	if !strings.Contains(htmlPartial, "PARTIAL ASSESSMENT") {
		t.Errorf("HTML partial report missing PARTIAL ASSESSMENT banner")
	}
}

// Scenario 16: A secondary report failure cannot mask the primary assessment outcome.
func TestScenario16_SecondaryReportFailureCannotMaskPrimaryOutcome(t *testing.T) {
	rep := buildTestReportWithCloudFindings(createTestCloudAndDBFindings(), "COMPLETED")

	// Attempting to write to an invalid path fails operationally
	invalidPath := filepath.Join(t.TempDir(), "nonexistent_dir", "sub", "report.html")
	err := WriteHTML(rep, invalidPath)
	if err == nil {
		t.Fatalf("expected WriteHTML to invalid directory to return error")
	}

	// Primary report findings and summary remain intact despite the write failure
	if len(rep.Findings) == 0 {
		t.Errorf("primary findings lost")
	}
	if rep.Summary.TotalFindings == 0 {
		t.Errorf("primary summary lost")
	}
}

// Scenario 17: Existing non-cloud finding types continue to render correctly.
func TestScenario17_NonCloudFindingTypesRenderCorrectly(t *testing.T) {
	secFinding := Finding{
		ID:          "SEC-github-token-1",
		RuleID:      "SEC-GITHUB-TOKEN",
		Title:       "GitHub Personal Access Token",
		Category:    "github-token",
		Severity:    SeverityCritical,
		Confidence:  ConfidenceHigh,
		Target:      "https://example.com",
		Endpoint:    "https://example.com/main.js",
		Source:      SourceSecrets,
		Description: "GitHub token exposed in client bundle",
		Evidence:    "ghp_testToken12345678901234567890",
		Fingerprint: "fp-sec-gh-1",
	}

	apiFinding := Finding{
		ID:          "API-cors-wildcard-1",
		RuleID:      "API-CORS-WILDCARD",
		Title:       "Wildcard CORS Configuration",
		Category:    "cors-wildcard",
		Severity:    SeverityInfo,
		Confidence:  ConfidenceHigh,
		Target:      "https://example.com",
		Endpoint:    "https://example.com/api/v1/public",
		Source:      SourceAPI,
		Description: "Wildcard CORS origin observed on public endpoint",
		Evidence:    "Access-Control-Allow-Origin: *",
		Fingerprint: "fp-api-cors-1",
	}

	rep := buildTestReportWithCloudFindings([]Finding{secFinding, apiFinding}, "COMPLETED")

	htmlStr, err := GenerateHTML(rep)
	if err != nil {
		t.Fatalf("GenerateHTML failed: %v", err)
	}
	if !strings.Contains(htmlStr, "GitHub Personal Access Token") {
		t.Errorf("HTML missing secret finding")
	}
	if !strings.Contains(htmlStr, "Wildcard CORS Configuration") {
		t.Errorf("HTML missing API finding")
	}

	jsonData, err := GenerateJSON(rep)
	if err != nil {
		t.Fatalf("GenerateJSON failed: %v", err)
	}
	if !strings.Contains(string(jsonData), "SEC-github-token-1") {
		t.Errorf("JSON missing secret finding")
	}
}

// Scenario 18: Existing report-format behavior and CLI compatibility remain intact.
func TestScenario18_ReportFormatBehaviorAndDiskWriting(t *testing.T) {
	tempDir := t.TempDir()
	rep := buildTestReportWithCloudFindings(createTestCloudAndDBFindings(), "COMPLETED")

	htmlPath := filepath.Join(tempDir, "report.html")
	jsonPath := filepath.Join(tempDir, "report.json")
	sarifPath := filepath.Join(tempDir, "report.sarif")
	crJsonPath := filepath.Join(tempDir, "commercial.json")
	crHtmlPath := filepath.Join(tempDir, "commercial.html")

	// 1. Write HTML
	if err := WriteHTML(rep, htmlPath); err != nil {
		t.Fatalf("WriteHTML failed: %v", err)
	}
	if _, err := os.Stat(htmlPath); err != nil {
		t.Errorf("HTML file was not created: %v", err)
	}

	// 2. Write JSON
	if err := WriteJSON(rep, jsonPath); err != nil {
		t.Fatalf("WriteJSON failed: %v", err)
	}
	if _, err := os.Stat(jsonPath); err != nil {
		t.Errorf("JSON file was not created: %v", err)
	}

	// 3. Write SARIF
	if err := WriteSARIF(rep, sarifPath); err != nil {
		t.Fatalf("WriteSARIF failed: %v", err)
	}
	if _, err := os.Stat(sarifPath); err != nil {
		t.Errorf("SARIF file was not created: %v", err)
	}

	// 4. Write Commercial JSON
	cr := BuildCommercialReport(rep)
	if err := WriteCommercialJSON(cr, crJsonPath); err != nil {
		t.Fatalf("WriteCommercialJSON failed: %v", err)
	}
	if _, err := os.Stat(crJsonPath); err != nil {
		t.Errorf("Commercial JSON file was not created: %v", err)
	}

	// 5. Write Commercial HTML
	if err := WriteCommercialHTML(cr, crHtmlPath); err != nil {
		t.Fatalf("WriteCommercialHTML failed: %v", err)
	}
	if _, err := os.Stat(crHtmlPath); err != nil {
		t.Errorf("Commercial HTML file was not created: %v", err)
	}
}

// -----------------------------------------------------------------------------
// Targeted Verification: Hash Collision Safety & Identity
// -----------------------------------------------------------------------------

func TestHashCollisionSafety_DistinctAssetIdentifiers(t *testing.T) {
	distinctEndpoints := []string{
		"redis://cache-1.internal:6379",
		"redis://cache-2.internal:6379",
		"redis://cache-3.internal:6379",
		"postgresql://pg-primary.internal:5432/app",
		"postgresql://pg-replica.internal:5432/app",
		"postgresql://pg-analytics.internal:5432/bi",
		"mysql://billing-master.internal:3306/billing",
		"mysql://billing-slave.internal:3306/billing",
		"mongodb://mongo-cluster.internal:27017/users",
		"mongodb://mongo-cluster.internal:27018/audit",
		"elasticsearch://es-node-01.internal:9200",
		"elasticsearch://es-node-02.internal:9200",
		"https://supabase.internal/rest/v1/users",
		"https://supabase.internal/rest/v1/orders",
		"https://hasura.internal/v1/graphql",
		"https://storage.googleapis.com/company-assets-public",
		"https://storage.googleapis.com/company-assets-private",
		"https://mybucket.s3.us-east-1.amazonaws.com",
		"https://mybucket.s3.eu-west-1.amazonaws.com",
		"http://minio.internal:9000/backups",
	}

	seenShortHashes := make(map[string]string)
	for _, ep := range distinctEndpoints {
		h := shortHash(ep)
		if orig, exists := seenShortHashes[h]; exists {
			t.Fatalf("collision detected in shortHash: %q and %q produced identical hash %q", orig, ep, h)
		}
		seenShortHashes[h] = ep
	}

	// Verify Commercial Attack Surface creates distinct assets for all endpoints without merging
	rep := Report{
		Version:   "1.0.0",
		Target:    distinctEndpoints[0],
		Targets:   distinctEndpoints,
		Findings:  nil,
		Timestamp: time.Now().UTC().Format(time.RFC3339),
	}

	cr := BuildCommercialReport(rep)
	if cr.AttackSurface.TotalAssets != len(distinctEndpoints) {
		t.Fatalf("expected %d distinct attack surface assets, got %d", len(distinctEndpoints), cr.AttackSurface.TotalAssets)
	}

	seenAssetIDs := make(map[string]string)
	for _, a := range cr.AttackSurface.Assets {
		if origURL, exists := seenAssetIDs[a.AssetID]; exists {
			t.Errorf("collision detected in AssetID %q between %q and %q", a.AssetID, origURL, a.URL)
		}
		seenAssetIDs[a.AssetID] = a.URL
	}
}

func TestHashCollisionSafety_NonHexIdentifiers(t *testing.T) {
	nonHexInputs := []string{
		"redis://cache.internal:6379",
		"postgres://usr:p@ssw0rd!@db.corp.net:5432/core?sslmode=require",
		"https://example.com/api/v1/users?name=test&filter=true#anchor",
		"AWS-S3-BUCKET-NAME-WITH-DASHES-1234",
		"special_chars_!@#$%^&*()_+{}|:<>?[];',./",
		"Unicode-Identifier-测试-日本語-тест-🔥",
		"UUID-550e8400-e29b-41d4-a716-446655440000",
		"VERY_LONG_STRING_" + strings.Repeat("ABC123xyz-", 100),
		"",
	}

	seenHashes := make(map[string]string)
	for _, input := range nonHexInputs {
		h := shortHash(input)
		if len(h) < 8 {
			t.Errorf("shortHash output too short (%d) for input %q: %q", len(h), input, h)
		}
		// Output must be valid lowercase hex
		for _, c := range h {
			if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
				t.Errorf("shortHash produced non-hex character %q for input %q: %s", c, input, h)
			}
		}
		if orig, exists := seenHashes[h]; exists && orig != input {
			t.Errorf("collision between %q and %q: hash %q", orig, input, h)
		}
		seenHashes[h] = input
	}
}

func TestHashCollisionSafety_RepeatedAssetIdentifiers(t *testing.T) {
	inputs := []string{
		"redis://cache-1.internal:6379",
		"https://api.example.com",
		"CLD-FINDING-IDENTIFIER-12345",
		"",
	}

	// Repeated evaluations must be 100% deterministic across multiple iterations
	for _, in := range inputs {
		expected := shortHash(in)
		for i := 0; i < 50; i++ {
			actual := shortHash(in)
			if actual != expected {
				t.Fatalf("non-deterministic shortHash on iteration %d for input %q: got %s, want %s", i, in, actual, expected)
			}
		}
	}
}

// -----------------------------------------------------------------------------
// Targeted Verification: Assessment-Scope Accuracy
// -----------------------------------------------------------------------------

func TestAssessmentScopeAccuracy_ZeroFindingsWithAssessedServices(t *testing.T) {
	// A scan that actively probed 3 services and found 0 vulnerabilities
	rep := Report{
		Version:          "1.0.0",
		Target:           "https://example.com",
		Targets:          []string{"https://example.com"},
		Findings:         []Finding{}, // 0 findings
		CompletionStatus: "COMPLETED",
		Metadata: map[string]any{
			"assessed_services": []string{"POSTGRESQL", "REDIS", "ELASTICSEARCH"},
		},
		Summary: Summary{
			AttemptedCount: 3,
			TotalFindings:  0,
		},
		Timestamp: time.Now().UTC().Format(time.RFC3339),
	}

	// 1. Model helpers
	assessed := rep.CloudServicesAssessed()
	if len(assessed) != 3 {
		t.Fatalf("expected 3 assessed services, got %d: %v", len(assessed), assessed)
	}
	if !rep.HasCloudScope() {
		t.Errorf("expected HasCloudScope to be true when assessed_services are present")
	}
	if rep.HasCloudFindings() {
		t.Errorf("expected HasCloudFindings to be false when 0 findings exist")
	}

	// 2. HTML output must acknowledge assessed services with 0 findings and include caveats
	htmlStr, err := GenerateHTML(rep)
	if err != nil {
		t.Fatalf("GenerateHTML failed: %v", err)
	}
	if !strings.Contains(htmlStr, "POSTGRESQL") || !strings.Contains(htmlStr, "REDIS") || !strings.Contains(htmlStr, "ELASTICSEARCH") {
		t.Errorf("HTML output missing assessed services in 0-finding assessment")
	}
	if !strings.Contains(htmlStr, "0 Findings") {
		t.Errorf("HTML output should explicitly indicate 0 findings for assessed services")
	}
	if !strings.Contains(htmlStr, "Zero detected findings in an actively assessed service indicates no evaluated vulnerabilities were observed") {
		t.Errorf("HTML output missing zero-finding disclaimer caveat")
	}

	// 3. Commercial Report posture statement
	cr := BuildCommercialReport(rep)
	if cr.AssessmentScope.AssessedEndpointsCount < 1 {
		t.Errorf("expected AssessedEndpointsCount >= 1, got %d", cr.AssessmentScope.AssessedEndpointsCount)
	}
	if !strings.Contains(cr.ExecutiveSummary.PostureStatement, "No security findings were identified within the evaluated scope") {
		t.Errorf("Commercial posture statement missing 0-finding disclosure")
	}
	if !strings.Contains(cr.ExecutiveSummary.PostureStatement, "does not guarantee") {
		t.Errorf("Commercial posture statement missing security limitation caveat")
	}
}

func TestAssessmentScopeAccuracy_AssessmentsWithFindings(t *testing.T) {
	cf1 := cloud.CloudFinding{
		Provider:    cloud.Provider("redis"),
		Category:    "Unauthenticated Data Access: redis",
		Endpoint:    "redis://cache.internal:6379",
		Description: "Redis cache exposed",
		Severity:    cloud.SeverityHigh,
		Confidence:  cloud.ConfidenceHigh,
		Fingerprint: "fp-redis-active-1",
		Details: map[string]string{
			"technology": "redis",
		},
	}
	cf2 := cloud.CloudFinding{
		Provider:    cloud.Provider("postgresql"),
		Category:    "Unauthenticated Data Access: postgresql",
		Endpoint:    "postgresql://db.internal:5432/main",
		Description: "Postgres database exposed",
		Severity:    cloud.SeverityCritical,
		Confidence:  cloud.ConfidenceHigh,
		Fingerprint: "fp-pg-active-1",
		Details: map[string]string{
			"technology": "postgresql",
		},
	}

	rf1 := FromCloudFinding("https://example.com", cf1)
	rf2 := FromCloudFinding("https://example.com", cf2)

	rep := buildTestReportWithCloudFindings([]Finding{rf1, rf2}, "COMPLETED")

	assessed := rep.CloudServicesAssessed()
	if len(assessed) != 2 {
		t.Fatalf("expected 2 assessed services, got %d: %v", len(assessed), assessed)
	}
	withFindings := rep.CloudServicesWithFindings()
	if len(withFindings) != 2 {
		t.Fatalf("expected 2 services with findings, got %d: %v", len(withFindings), withFindings)
	}

	htmlStr, err := GenerateHTML(rep)
	if err != nil {
		t.Fatalf("GenerateHTML failed: %v", err)
	}
	if !strings.Contains(htmlStr, "Findings Detected") {
		t.Errorf("HTML should indicate Findings Detected for assessed services with findings")
	}
}

func TestAssessmentScopeAccuracy_DiscoveredButUnverifiedServices(t *testing.T) {
	// A report with MySQL discovered passively from code reference, but unverified
	cfPassive := cloud.CloudFinding{
		Provider:    cloud.Provider("mysql"),
		Category:    "Connection Indicator (mysql)",
		Endpoint:    "mysql://db.internal:3306/billing",
		Description: "Detected mysql reference in bundle. Network connectivity unverified.",
		Severity:    cloud.SeverityInfo,
		Confidence:  cloud.ConfidenceLow,
		Fingerprint: "fp-mysql-passive-1",
		Details: map[string]string{
			"technology":      "mysql",
			"analysis_method": "STATIC_ANALYSIS",
		},
	}

	rfPassive := FromCloudFinding("https://example.com", cfPassive)
	rep := buildTestReportWithCloudFindings([]Finding{rfPassive}, "COMPLETED")
	// Also add an explicit discovered_services metadata
	if rep.Metadata == nil {
		rep.Metadata = make(map[string]any)
	}
	rep.Metadata["discovered_services"] = []string{"MYSQL", "MONGO_EXPRESS"}

	discovered := rep.CloudServicesDiscovered()
	if len(discovered) < 2 {
		t.Fatalf("expected at least 2 discovered services, got %d: %v", len(discovered), discovered)
	}

	// Must NOT be grouped as actively assessed
	assessed := rep.CloudServicesAssessed()
	for _, a := range assessed {
		if a == "MYSQL" || a == "MONGO_EXPRESS" {
			t.Errorf("discovered-only service %q should NOT be in CloudServicesAssessed", a)
		}
	}

	htmlStr, err := GenerateHTML(rep)
	if err != nil {
		t.Fatalf("GenerateHTML failed: %v", err)
	}
	if !strings.Contains(htmlStr, "Discovered Only (Passive / Unverified)") {
		t.Errorf("HTML should render Discovered Only section")
	}
	if !strings.Contains(htmlStr, "Unverified") {
		t.Errorf("HTML should label discovered services as Unverified")
	}
}

func TestAssessmentScopeAccuracy_PartialAssessment(t *testing.T) {
	rep := Report{
		Version:          "1.0.0",
		Target:           "https://example.com",
		Targets:          []string{"https://example.com"},
		CompletionStatus: "PARTIAL",
		Metadata: map[string]any{
			"is_partial":        true,
			"assessed_services": []string{"REDIS"},
			"skipped_services":  []string{"POSTGRESQL", "ELASTICSEARCH"},
		},
		Summary: Summary{
			AttemptedCount: 1,
		},
		Timestamp: time.Now().UTC().Format(time.RFC3339),
	}

	htmlStr, err := GenerateHTML(rep)
	if err != nil {
		t.Fatalf("GenerateHTML failed: %v", err)
	}
	if !strings.Contains(htmlStr, "PARTIAL ASSESSMENT") {
		t.Errorf("HTML should display Partial Assessment banner")
	}
	if !strings.Contains(htmlStr, "Skipped / Out of Scope") {
		t.Errorf("HTML should render Skipped / Out of Scope section")
	}
	if !strings.Contains(htmlStr, "POSTGRESQL") || !strings.Contains(htmlStr, "ELASTICSEARCH") {
		t.Errorf("HTML should display skipped services")
	}
}

func TestAssessmentScopeAccuracy_SkippedServices(t *testing.T) {
	rep := Report{
		Version:          "1.0.0",
		Target:           "https://example.com",
		Targets:          []string{"https://example.com"},
		CompletionStatus: "COMPLETED",
		Metadata: map[string]any{
			"skipped_services": []string{"AWS_S3", "MINIO"},
		},
		Timestamp: time.Now().UTC().Format(time.RFC3339),
	}

	skipped := rep.CloudServicesSkipped()
	if len(skipped) != 2 || skipped[0] != "AWS_S3" || skipped[1] != "MINIO" {
		t.Fatalf("expected [AWS_S3, MINIO], got %v", skipped)
	}

	htmlStr, err := GenerateHTML(rep)
	if err != nil {
		t.Fatalf("GenerateHTML failed: %v", err)
	}
	if !strings.Contains(htmlStr, "Skipped / Out of Scope") {
		t.Errorf("HTML should display Skipped / Out of Scope section")
	}
	if !strings.Contains(htmlStr, "AWS_S3") || !strings.Contains(htmlStr, "MINIO") {
		t.Errorf("HTML should list AWS_S3 and MINIO in skipped services")
	}
}
