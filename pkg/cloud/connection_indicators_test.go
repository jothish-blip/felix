package cloud

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"felix/pkg/crawler"
)

// TestCanarySecretRedaction verifies that sensitive canary credentials never leak into
// sanitized values, source context lines, evidence strings, details, or JSON serializations.
func TestCanarySecretRedaction(t *testing.T) {
	const canaryPass = "TEST_PASSWORD_DO_NOT_LEAK"
	const canaryToken = "TEST_TOKEN_DO_NOT_LEAK"
	const canaryKey = "TEST_SECRET_KEY_DO_NOT_LEAK"

	testCases := []struct {
		name     string
		sourceID string
		input    string
		tech     ServiceTechnology
		canary   string
		hasCreds bool
	}{
		{
			name:     "PostgreSQL URL with Password",
			sourceID: "config/database.yml",
			input:    "url: postgres://dbuser:" + canaryPass + "@postgres.internal:5432/appdb",
			tech:     TechPostgreSQL,
			canary:   canaryPass,
			hasCreds: true,
		},
		{
			name:     "MySQL Go DSN with Password",
			sourceID: ".env",
			input:    "MYSQL_DSN=appuser:" + canaryPass + "@tcp(mysql.internal:3306)/proddb?charset=utf8mb4",
			tech:     TechMySQL,
			canary:   canaryPass,
			hasCreds: true,
		},
		{
			name:     "MongoDB SRV with Encoded Password",
			sourceID: ".env.production",
			input:    "MONGODB_URI=mongodb+srv://admin:" + canaryPass + "@cluster0.mongodb.net/production?retryWrites=true",
			tech:     TechMongoDB,
			canary:   canaryPass,
			hasCreds: true,
		},
		{
			name:     "Redis URI with Password",
			sourceID: "settings.py",
			input:    "REDIS_URL = 'redis://:" + canaryPass + "@redis.internal:6379/0'",
			tech:     TechRedis,
			canary:   canaryPass,
			hasCreds: true,
		},
		{
			name:     "Azure Storage Connection String with AccountKey",
			sourceID: "appsettings.json",
			input:    `DefaultEndpointsProtocol=https;AccountName=prodstore;AccountKey=` + canaryKey + `==;EndpointSuffix=core.windows.net`,
			tech:     TechAzureBlob,
			canary:   canaryKey,
			hasCreds: true,
		},
		{
			name:     "Hasura Admin Secret Assignment",
			sourceID: "docker-compose.yml",
			input:    "HASURA_GRAPHQL_ADMIN_SECRET=" + canaryPass,
			tech:     TechHasura,
			canary:   canaryPass,
			hasCreds: true,
		},
		{
			name:     "MinIO Root Password Assignment",
			sourceID: ".env",
			input:    "MINIO_ROOT_PASSWORD=" + canaryPass,
			tech:     TechMinIO,
			canary:   canaryPass,
			hasCreds: true,
		},
		{
			name:     "Firebase RTDB with Auth Query Parameter",
			sourceID: "client.js",
			input:    "https://auth-project.firebaseio.com/users.json?auth=" + canaryToken,
			tech:     TechFirebaseRTDB,
			canary:   canaryToken,
			hasCreds: true,
		},
		{
			name:     "AWS S3 Presigned URL with Signature",
			sourceID: "bundle.js",
			input:    "https://my-bucket.s3.amazonaws.com/report.pdf?X-Amz-Signature=" + canaryPass,
			tech:     TechAWSS3,
			canary:   canaryPass,
			hasCreds: true,
		},
	}

	detector := NewIndicatorDetector()

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			src := IndicatorSource{
				Identifier: tc.sourceID,
			}
			indicators := detector.DetectIndicators(src, []byte(tc.input))
			if len(indicators) == 0 {
				t.Fatalf("expected at least one indicator detected for %s, got 0", tc.name)
			}

			ind := indicators[0]
			if ind.Technology != tc.tech {
				t.Errorf("expected technology %s, got %s", tc.tech, ind.Technology)
			}
			if ind.HasCredentials != tc.hasCreds {
				t.Errorf("expected has_credentials=%t, got %t", tc.hasCreds, ind.HasCredentials)
			}

			// 1. Assert SanitizedValue does NOT contain the canary secret
			if strings.Contains(ind.SanitizedValue, tc.canary) {
				t.Fatalf("LEAK: SanitizedValue contains canary secret %q: %s", tc.canary, ind.SanitizedValue)
			}

			// 2. Assert Source.ContextLine does NOT contain the canary secret
			if strings.Contains(ind.Source.ContextLine, tc.canary) {
				t.Fatalf("LEAK: Source.ContextLine contains canary secret %q: %s", tc.canary, ind.Source.ContextLine)
			}

			// 3. Assert ToCloudFinding Evidence and Description do NOT contain the canary secret
			finding := ind.ToCloudFinding(true)
			if strings.Contains(finding.Evidence, tc.canary) {
				t.Fatalf("LEAK: Finding.Evidence contains canary secret %q: %s", tc.canary, finding.Evidence)
			}
			if strings.Contains(finding.Description, tc.canary) {
				t.Fatalf("LEAK: Finding.Description contains canary secret %q: %s", tc.canary, finding.Description)
			}

			// 4. Assert Marshaled JSON of ConnectionIndicator does NOT contain the canary secret
			indJSON, err := json.Marshal(ind)
			if err != nil {
				t.Fatalf("failed to marshal ConnectionIndicator to JSON: %v", err)
			}
			if strings.Contains(string(indJSON), tc.canary) {
				t.Fatalf("LEAK: ConnectionIndicator JSON contains canary secret %q: %s", tc.canary, string(indJSON))
			}

			// 5. Assert Marshaled JSON of CloudFinding does NOT contain the canary secret
			findingJSON, err := json.Marshal(finding)
			if err != nil {
				t.Fatalf("failed to marshal CloudFinding to JSON: %v", err)
			}
			if strings.Contains(string(findingJSON), tc.canary) {
				t.Fatalf("LEAK: CloudFinding JSON contains canary secret %q: %s", tc.canary, string(findingJSON))
			}
		})
	}
}

// TestAll16TargetsPositiveDetection asserts positive detection across all 16 target services.
func TestAll16TargetsPositiveDetection(t *testing.T) {
	detector := NewIndicatorDetector()

	targets := []struct {
		name         string
		tech         ServiceTechnology
		family       ServiceFamily
		input        string
		expectedEP   string
		expectedPort int
		indType      IndicatorType
	}{
		// Group A: Direct Databases
		{
			name:         "Elasticsearch HTTP Reference",
			tech:         TechElasticsearch,
			family:       FamilyDirectDatabase,
			input:        "const es = 'http://es-cluster.internal:9200';",
			expectedEP:   "http://es-cluster.internal:9200",
			expectedPort: 9200,
			indType:      IndicatorTypeEndpointReference,
		},
		{
			name:         "MongoDB Connection URI",
			tech:         TechMongoDB,
			family:       FamilyDirectDatabase,
			input:        "mongodb://mongo-host.internal:27017/analytics",
			expectedEP:   "mongo-host.internal:27017",
			expectedPort: 27017,
			indType:      IndicatorTypeConnectionString,
		},
		{
			name:         "Redis Connection URI",
			tech:         TechRedis,
			family:       FamilyDirectDatabase,
			input:        "redis://cache-redis.internal:6379/1",
			expectedEP:   "cache-redis.internal:6379",
			expectedPort: 6379,
			indType:      IndicatorTypeConnectionString,
		},
		{
			name:         "PostgreSQL Connection URI",
			tech:         TechPostgreSQL,
			family:       FamilyDirectDatabase,
			input:        "postgres://app:secret@db.internal:5432/prod_db",
			expectedEP:   "db.internal:5432",
			expectedPort: 5432,
			indType:      IndicatorTypeConnectionString,
		},
		{
			name:         "MySQL Go DSN",
			tech:         TechMySQL,
			family:       FamilyDirectDatabase,
			input:        "appuser:apppass@tcp(mysql-host.internal:3306)/orders_db",
			expectedEP:   "mysql-host.internal:3306",
			expectedPort: 3306,
			indType:      IndicatorTypeConnectionString,
		},

		// Group B: Database Admin
		{
			name:         "Mongo Express Reference",
			tech:         TechMongoExpress,
			family:       FamilyDatabaseAdmin,
			input:        "proxy_pass http://localhost:8081/mongo-express;",
			expectedEP:   "http://localhost:8081",
			expectedPort: 8081,
			indType:      IndicatorTypeEndpointReference,
		},

		// Group C: Backend & Database Interfaces
		{
			name:         "Supabase Project Endpoint",
			tech:         TechSupabase,
			family:       FamilyBackendInterface,
			input:        "const url = 'https://xyzcompany.supabase.co';",
			expectedEP:   "https://xyzcompany.supabase.co",
			expectedPort: 443,
			indType:      IndicatorTypeEndpointReference,
		},
		{
			name:       "PostgREST Database URI Assignment",
			tech:       TechPostgREST,
			family:     FamilyBackendInterface,
			input:      "PGRST_DB_URI=postgres://authenticator:pass@localhost:5432/app",
			expectedEP: "PGRST_DB_URI",
			indType:    IndicatorTypeConnectionString,
		},
		{
			name:       "Hasura GraphQL Endpoint",
			tech:       TechHasura,
			family:     FamilyBackendInterface,
			input:      "https://graphql.example.com/v1/graphql",
			expectedEP: "https://graphql.example.com/v1/graphql",
			indType:    IndicatorTypeEndpointReference,
		},
		{
			name:       "Prisma Schema Datasource Block",
			tech:       TechPrisma,
			family:     FamilyBackendInterface,
			input:      "datasource db {\n  provider = \"postgresql\"\n  url = env(\"DATABASE_URL\")\n}",
			expectedEP: "schema.prisma",
			indType:    IndicatorTypeConfigDatasource,
		},

		// Group D: Firebase Databases
		{
			name:         "Firebase RTDB Reference",
			tech:         TechFirebaseRTDB,
			family:       FamilyFirebase,
			input:        "https://my-app-db.firebaseio.com",
			expectedEP:   "https://my-app-db.firebaseio.com",
			expectedPort: 443,
			indType:      IndicatorTypeEndpointReference,
		},
		{
			name:         "Cloud Firestore Endpoint",
			tech:         TechFirestore,
			family:       FamilyFirebase,
			input:        "https://firestore.googleapis.com/v1/projects/my-project/databases/(default)/documents",
			expectedEP:   "https://firestore.googleapis.com",
			expectedPort: 443,
			indType:      IndicatorTypeEndpointReference,
		},

		// Group E: Cloud Storage
		{
			name:         "AWS S3 URI Reference",
			tech:         TechAWSS3,
			family:       FamilyObjectStorage,
			input:        "s3://corporate-data-lake/raw-events",
			expectedEP:   "https://corporate-data-lake.s3.amazonaws.com",
			expectedPort: 443,
			indType:      IndicatorTypeEndpointReference,
		},
		{
			name:         "Azure Blob Endpoint Reference",
			tech:         TechAzureBlob,
			family:       FamilyObjectStorage,
			input:        "https://enterprisestorage.blob.core.windows.net/backups",
			expectedEP:   "https://enterprisestorage.blob.core.windows.net",
			expectedPort: 443,
			indType:      IndicatorTypeEndpointReference,
		},
		{
			name:         "Google Cloud Storage URI Reference",
			tech:         TechGCS,
			family:       FamilyObjectStorage,
			input:        "gs://ml-training-datasets/v1",
			expectedEP:   "https://storage.googleapis.com/ml-training-datasets",
			expectedPort: 443,
			indType:      IndicatorTypeEndpointReference,
		},
		{
			name:         "MinIO Endpoint Reference",
			tech:         TechMinIO,
			family:       FamilyObjectStorage,
			input:        "minioClient = new Minio.Client({ endPoint: 'http://minio.internal:9000' });",
			expectedEP:   "minio.internal:9000",
			expectedPort: 9000,
			indType:      IndicatorTypeEndpointReference,
		},
	}

	for _, tc := range targets {
		t.Run(tc.name, func(t *testing.T) {
			src := IndicatorSource{Identifier: "test_asset.txt"}
			inds := detector.DetectIndicators(src, []byte(tc.input))
			if len(inds) == 0 {
				t.Fatalf("expected indicator for %s, got 0", tc.name)
			}

			found := false
			for _, ind := range inds {
				if ind.Technology == tc.tech {
					found = true
					if ind.Family != tc.family {
						t.Errorf("expected family %s, got %s", tc.family, ind.Family)
					}
					if ind.Type != tc.indType {
						t.Errorf("expected indicator type %s, got %s", tc.indType, ind.Type)
					}
					if tc.expectedEP != "" && !strings.Contains(ind.Endpoint, tc.expectedEP) {
						t.Errorf("expected endpoint %q, got %q", tc.expectedEP, ind.Endpoint)
					}
					if tc.expectedPort > 0 && ind.Port != tc.expectedPort {
						t.Errorf("expected port %d, got %d", tc.expectedPort, ind.Port)
					}
					break
				}
			}
			if !found {
				t.Fatalf("expected indicator for %s (%s), found: %+v", tc.name, tc.tech, inds)
			}
		})
	}
}

// TestStructuralDSNParsing verifies specific structural edge cases such as JDBC URLs and Go MySQL DSNs.
func TestStructuralDSNParsing(t *testing.T) {
	detector := NewIndicatorDetector()

	t.Run("JDBC PostgreSQL with Query Password", func(t *testing.T) {
		input := "jdbc:postgresql://db.company.com:5432/finance?user=fin_app&password=SUPER_SECRET_FINANCE_KEY"
		src := IndicatorSource{Identifier: "application.properties"}
		inds := detector.DetectIndicators(src, []byte(input))
		if len(inds) == 0 {
			t.Fatalf("expected JDBC indicator, got 0")
		}
		ind := inds[0]
		if ind.Technology != TechPostgreSQL {
			t.Errorf("expected postgresql, got %s", ind.Technology)
		}
		if !ind.HasCredentials {
			t.Errorf("expected has_credentials=true")
		}
		if strings.Contains(ind.SanitizedValue, "SUPER_SECRET_FINANCE_KEY") {
			t.Errorf("LEAK: SanitizedValue contains raw password: %s", ind.SanitizedValue)
		}
		if !strings.HasPrefix(ind.SanitizedValue, "jdbc:postgresql://") {
			t.Errorf("expected jdbc:postgresql prefix preserved, got: %s", ind.SanitizedValue)
		}
	})

	t.Run("MySQL Go DSN with Custom Port and DB", func(t *testing.T) {
		input := `dsn := "root:DB_PASS_SECRET@tcp(192.168.1.100:3307)/store_db?charset=utf8mb4&parseTime=True"`
		src := IndicatorSource{Identifier: "db.go"}
		inds := detector.DetectIndicators(src, []byte(input))
		if len(inds) == 0 {
			t.Fatalf("expected MySQL DSN indicator, got 0")
		}
		ind := inds[0]
		if ind.Technology != TechMySQL {
			t.Errorf("expected mysql, got %s", ind.Technology)
		}
		if ind.Port != 3307 {
			t.Errorf("expected port 3307, got %d", ind.Port)
		}
		if ind.Database != "store_db" {
			t.Errorf("expected database 'store_db', got %s", ind.Database)
		}
		if strings.Contains(ind.SanitizedValue, "DB_PASS_SECRET") {
			t.Errorf("LEAK: SanitizedValue contains raw password: %s", ind.SanitizedValue)
		}
		if !strings.Contains(ind.SanitizedValue, "root:[REDACTED]@tcp(192.168.1.100:3307)/store_db") {
			t.Errorf("unexpected sanitized value: %s", ind.SanitizedValue)
		}
	})
}

// TestSourceAttributionAndLineNumbers verifies accurate file attribution and 1-based line numbers.
func TestSourceAttributionAndLineNumbers(t *testing.T) {
	multilineFile := `# Configuration file
DEBUG=true
DATABASE_URL=postgres://appuser:SecretPass1@postgres:5432/appdb
LOG_LEVEL=info
REDIS_URL=redis://:SecretPass2@redis:6379/0
# End of file`

	detector := NewIndicatorDetector()
	src := IndicatorSource{Identifier: ".env.production"}
	inds := detector.DetectIndicators(src, []byte(multilineFile))

	if len(inds) < 2 {
		t.Fatalf("expected at least 2 indicators, got %d", len(inds))
	}

	// Verify PostgreSQL line attribution
	pgInd := inds[0]
	if pgInd.Technology != TechPostgreSQL {
		t.Errorf("expected first indicator postgresql, got %s", pgInd.Technology)
	}
	if pgInd.Source.LineNumber != 3 {
		t.Errorf("expected line number 3 for postgresql, got %d", pgInd.Source.LineNumber)
	}
	if pgInd.Source.Type != SourceTypeConfigFile {
		t.Errorf("expected SourceTypeConfigFile for .env.production, got %s", pgInd.Source.Type)
	}
	if strings.Contains(pgInd.Source.ContextLine, "SecretPass1") {
		t.Errorf("LEAK: ContextLine contains raw password: %s", pgInd.Source.ContextLine)
	}

	// Verify Redis line attribution
	redisInd := inds[1]
	if redisInd.Technology != TechRedis {
		t.Errorf("expected second indicator redis, got %s", redisInd.Technology)
	}
	if redisInd.Source.LineNumber != 5 {
		t.Errorf("expected line number 5 for redis, got %d", redisInd.Source.LineNumber)
	}
	if strings.Contains(redisInd.Source.ContextLine, "SecretPass2") {
		t.Errorf("LEAK: ContextLine contains raw password: %s", redisInd.Source.ContextLine)
	}
}

// TestClassificationNonConflation verifies that connection indicators are strictly classified
// as STATIC_ANALYSIS with zero network probing, and explicit unverified semantics.
func TestClassificationNonConflation(t *testing.T) {
	detector := NewIndicatorDetector()
	src := IndicatorSource{
		Type:       SourceTypeCodeArtifact,
		Identifier: "src/database.ts",
		LineNumber: 42,
	}
	input := "const db = 'postgres://user:pass@db.example.com:5432/app';"
	inds := detector.DetectIndicators(src, []byte(input))
	if len(inds) == 0 {
		t.Fatalf("expected indicator, got 0")
	}

	ind := inds[0]
	finding := ind.ToCloudFinding(true)

	// Verify static classification
	if finding.HTTPStatus != 0 {
		t.Errorf("expected HTTPStatus=0 for static indicator, got %d", finding.HTTPStatus)
	}
	if finding.HTTPMethod != "" {
		t.Errorf("expected empty HTTPMethod for static indicator, got %q", finding.HTTPMethod)
	}
	if finding.NegativeEvidence == "" {
		t.Errorf("expected explicit NegativeEvidence for static indicator, got empty")
	}
	if !strings.Contains(finding.NegativeEvidence, "Zero active network connections") {
		t.Errorf("expected NegativeEvidence to state zero network connections: %s", finding.NegativeEvidence)
	}
	if finding.Details["analysis_method"] != "STATIC_ANALYSIS" {
		t.Errorf("expected analysis_method=STATIC_ANALYSIS, got %s", finding.Details["analysis_method"])
	}
	if finding.Details["verification_status"] != "UNVERIFIED" {
		t.Errorf("expected verification_status=UNVERIFIED, got %s", finding.Details["verification_status"])
	}
}

// TestNegativeLookalikes verifies that English prose, blog URLs, and SQL statements
// do NOT trigger false positive connection indicators.
func TestNegativeLookalikes(t *testing.T) {
	negatives := []string{
		"We use postgresql for database and redis for caching.",
		"MySQL is an open-source relational database management system.",
		"SELECT * FROM users WHERE active = 1 AND deleted_at IS NULL;",
		"https://github.com/redis/redis/releases/tag/7.0.0",
		"https://blog.example.com/tutorials/how-to-configure-mongodb",
		"const helpText = 'Please contact support if you need minio access.';",
		"http://",
		"postgres://",
		"s3://",
		"DefaultEndpointsProtocol=",
	}

	detector := NewIndicatorDetector()
	src := IndicatorSource{Identifier: "readme.md"}

	for _, neg := range negatives {
		inds := detector.DetectIndicators(src, []byte(neg))
		if len(inds) > 0 {
			t.Errorf("false positive detected for input %q: %+v", neg, inds[0])
		}
	}
}

// TestReDoSAndInputBounds verifies bounded memory and linear-time execution on large inputs.
func TestReDoSAndInputBounds(t *testing.T) {
	detector := NewIndicatorDetector()

	// 1. Long repetitive string
	longLine := "postgres://" + strings.Repeat("a", 8000) + "@example.com:5432/db"
	src := IndicatorSource{Identifier: "test.txt"}

	start := time.Now()
	_ = detector.DetectIndicators(src, []byte(longLine))
	duration := time.Since(start)

	if duration > 100*time.Millisecond {
		t.Errorf("detection took too long (%v), possible ReDoS or backtracking issue", duration)
	}

	// 2. Oversized input (> 5MB)
	largeData := bytes.Repeat([]byte("const x = 1;\n"), 500000) // ~7 MB
	start = time.Now()
	inds := detector.DetectIndicators(src, largeData)
	duration = time.Since(start)

	if duration > 2*time.Second {
		t.Errorf("large input processing took too long (%v)", duration)
	}
	if len(inds) > MaxIndicatorsPerFile {
		t.Errorf("exceeded MaxIndicatorsPerFile limit: got %d", len(inds))
	}
}

// TestDetectorAuditIntegration verifies that cloud.Detector.Audit populates ConnectionIndicators
// in AuditResult and registers the non-conflated CloudFindings.
func TestDetectorAuditIntegration(t *testing.T) {
	d := NewDetector(nil)

	assetContent := `
		const dbUrl = "postgres://usr:SUPER_SECRET_CANARY@pg.internal:5432/app";
		const cache = "redis://:SUPER_SECRET_CANARY@redis.internal:6379";
	`
	assets := []crawler.Asset{
		{
			URL:     "https://target.com/app.bundle.js",
			Content: []byte(assetContent),
			InScope: true,
		},
	}

	res := d.Audit(context.Background(), assets, nil)

	if len(res.ConnectionIndicators) < 2 {
		t.Fatalf("expected at least 2 connection indicators in AuditResult, got %d", len(res.ConnectionIndicators))
	}

	for _, ci := range res.ConnectionIndicators {
		if strings.Contains(ci.SanitizedValue, "SUPER_SECRET_CANARY") {
			t.Fatalf("LEAK: ConnectionIndicator.SanitizedValue contains canary secret: %s", ci.SanitizedValue)
		}
	}

	// Check findings include indicator findings
	foundPG := false
	foundRedis := false
	for _, f := range res.Findings {
		if strings.Contains(f.Category, "Connection Indicator: postgresql") || strings.Contains(f.Category, "Connection Indicator (postgresql)") {
			foundPG = true
		}
		if strings.Contains(f.Category, "Connection Indicator: redis") || strings.Contains(f.Category, "Connection Indicator (redis)") {
			foundRedis = true
		}
	}

	if !foundPG {
		t.Errorf("expected finding for postgresql connection indicator")
	}
	if !foundRedis {
		t.Errorf("expected finding for redis connection indicator")
	}
}
