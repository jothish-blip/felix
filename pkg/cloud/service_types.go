package cloud

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"
)

// ServiceFamily categorizes the service into its architectural grouping.
type ServiceFamily string

const (
	FamilyDirectDatabase   ServiceFamily = "direct_database"
	FamilyDatabaseAdmin    ServiceFamily = "database_admin"
	FamilyBackendInterface ServiceFamily = "backend_interface"
	FamilyFirebase         ServiceFamily = "firebase"
	FamilyObjectStorage    ServiceFamily = "object_storage"
)

// ServiceTechnology identifies the specific technology / product.
type ServiceTechnology string

const (
	// Group A: Direct database & search engines
	TechElasticsearch ServiceTechnology = "elasticsearch"
	TechMongoDB       ServiceTechnology = "mongodb"
	TechRedis         ServiceTechnology = "redis"
	TechPostgreSQL    ServiceTechnology = "postgresql"
	TechMySQL         ServiceTechnology = "mysql"

	// Group B: Database administration interfaces
	TechMongoExpress ServiceTechnology = "mongo_express"

	// Group C: Backend & database interfaces
	TechSupabase  ServiceTechnology = "supabase"
	TechPostgREST ServiceTechnology = "postgrest"
	TechHasura    ServiceTechnology = "hasura"
	TechPrisma    ServiceTechnology = "prisma"

	// Group D: Firebase databases
	TechFirebaseRTDB ServiceTechnology = "firebase_rtdb"
	TechFirestore    ServiceTechnology = "firestore"

	// Group E: Cloud & object storage
	TechAWSS3     ServiceTechnology = "aws_s3"
	TechAzureBlob ServiceTechnology = "azure_blob"
	TechGCS       ServiceTechnology = "gcp_storage"
	TechMinIO     ServiceTechnology = "minio"
)

// DiscoveryOutcome represents the empirical outcome of service discovery.
type DiscoveryOutcome string

const (
	OutcomeDetected     DiscoveryOutcome = "DETECTED"
	OutcomePossible     DiscoveryOutcome = "POSSIBLE"
	OutcomeNotDetected  DiscoveryOutcome = "NOT_DETECTED"
	OutcomeInconclusive DiscoveryOutcome = "INCONCLUSIVE"
	OutcomeError        DiscoveryOutcome = "ERROR"
)

// DiscoveredService captures a standardized, empirical service discovery result across all 16 target services.
type DiscoveredService struct {
	Technology      ServiceTechnology `json:"technology"`
	Family          ServiceFamily     `json:"family"`
	Outcome         DiscoveryOutcome  `json:"outcome"`
	Confidence      string            `json:"confidence"` // HIGH, MEDIUM, LOW
	Endpoint        string            `json:"endpoint"`
	Host            string            `json:"host,omitempty"`
	Port            int               `json:"port,omitempty"`
	Protocol        string            `json:"protocol,omitempty"` // http, https, tcp
	DetectionMethod string            `json:"detection_method"`   // PASSIVE_ANALYSIS, HTTP_PROBE, TCP_PROBE
	Evidence        string            `json:"evidence,omitempty"`
	Version         string            `json:"version,omitempty"`
	AuthRequired    bool              `json:"auth_required"`
	PublicAccess    bool              `json:"public_accessible"`
	Metadata        map[string]any    `json:"metadata,omitempty"`
	Limitations     string            `json:"limitations,omitempty"`
	SourceAsset     string            `json:"source_asset,omitempty"`
	InScope         bool              `json:"in_scope"`
	DiscoveredAt    time.Time         `json:"discovered_at"`
}

// CanonicalID generates a stable, normalized identifier for service deduplication.
func (ds DiscoveredService) CanonicalID() string {
	tech := strings.ToLower(string(ds.Technology))
	if ds.Endpoint != "" {
		cleanEP := strings.ToLower(strings.TrimSpace(ds.Endpoint))
		if parsed, err := url.Parse(cleanEP); err == nil && parsed.Host != "" {
			host := parsed.Host
			// strip standard default ports
			if (parsed.Scheme == "http" && strings.HasSuffix(host, ":80")) ||
				(parsed.Scheme == "https" && strings.HasSuffix(host, ":443")) {
				host = parsed.Hostname()
			}
			cleanEP = fmt.Sprintf("%s://%s%s", parsed.Scheme, host, strings.TrimRight(parsed.Path, "/"))
		}
		return fmt.Sprintf("%s:%s", tech, cleanEP)
	}

	host := strings.ToLower(strings.TrimSpace(ds.Host))
	if ds.Port > 0 {
		return fmt.Sprintf("%s:%s:%d", tech, host, ds.Port)
	}
	return fmt.Sprintf("%s:%s", tech, host)
}

// Fingerprint generates a deterministic SHA-256 hash identifying the discovered service.
func (ds DiscoveredService) Fingerprint() string {
	raw := fmt.Sprintf("%s|%s|%s|%s", ds.Technology, ds.CanonicalID(), ds.Outcome, ds.DetectionMethod)
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:16])
}

// ToLegacyService converts DiscoveredService to legacy Service representation for backward compatibility.
func (ds DiscoveredService) ToLegacyService() Service {
	prov := Provider(ds.Technology)
	switch ds.Technology {
	case TechAWSS3:
		prov = ProviderAWS
	case TechGCS:
		prov = ProviderGCP
	case TechFirebaseRTDB, TechFirestore:
		prov = ProviderFirebase
	case TechSupabase:
		prov = ProviderSupabase
	}

	identifiers := make(map[string]string)
	if ds.Metadata != nil {
		for k, v := range ds.Metadata {
			if s, ok := v.(string); ok && s != "" {
				identifiers[k] = s
			}
		}
	}

	ep := ds.Endpoint
	if ep == "" && ds.Host != "" {
		if ds.Port > 0 {
			ep = net.JoinHostPort(ds.Host, fmt.Sprintf("%d", ds.Port))
		} else {
			ep = ds.Host
		}
	}

	return Service{
		Provider:    prov,
		URL:         ep,
		Source:      ds.SourceAsset,
		Identifiers: identifiers,
	}
}

// ToFinding formats the service discovery outcome as a CloudFinding when appropriate.
func (ds DiscoveredService) ToFinding() (CloudFinding, bool) {
	if ds.Outcome != OutcomeDetected && ds.Outcome != OutcomePossible {
		return CloudFinding{}, false
	}

	endpoint := ds.Endpoint
	if endpoint == "" {
		if ds.Port > 0 {
			endpoint = fmt.Sprintf("%s:%d", ds.Host, ds.Port)
		} else {
			endpoint = ds.Host
		}
	}

	conf := ds.Confidence
	if conf == "" {
		if ds.Outcome == OutcomeDetected {
			conf = ConfidenceHigh
		} else {
			conf = ConfidenceMedium
		}
	}

	if !ds.InScope {
		category := "Discovered Cloud Service (Out of Scope)"
		return CloudFinding{
			Provider:    Provider(ds.Technology),
			Category:    category,
			Endpoint:    endpoint,
			Description: fmt.Sprintf("Discovered %s service reference in client assets; active probing skipped (outside authorized assessment scope)", ds.Technology),
			Evidence:    ds.Evidence,
			Severity:    SeverityInfo,
			Confidence:  ConfidenceHigh,
			Fingerprint: GenerateFingerprint(Provider(ds.Technology), endpoint, category),
			Details: map[string]string{
				"technology":        string(ds.Technology),
				"family":            string(ds.Family),
				"detection_method":  string(ds.DetectionMethod),
				"analysis_method":   "STATIC_ANALYSIS",
				"discovery_outcome": string(ds.Outcome),
				"scope_status":      "OUT_OF_SCOPE",
			},
		}, true
	}

	category := fmt.Sprintf("Service Discovery: %s", ds.Technology)
	desc := fmt.Sprintf("Discovered %s service (%s)", ds.Technology, ds.Family)

	details := map[string]string{
		"technology":        string(ds.Technology),
		"family":            string(ds.Family),
		"detection_method":  string(ds.DetectionMethod),
		"analysis_method":   "STATIC_ANALYSIS",
		"discovery_outcome": string(ds.Outcome),
	}
	if ds.Host != "" {
		details["host"] = ds.Host
	}
	if ds.Port > 0 {
		details["port"] = fmt.Sprintf("%d", ds.Port)
	}
	if ds.Protocol != "" {
		details["protocol"] = ds.Protocol
	}
	if ds.SourceAsset != "" {
		details["source_asset"] = ds.SourceAsset
	}

	return CloudFinding{
		Provider:    Provider(ds.Technology),
		Category:    category,
		Endpoint:    endpoint,
		Description: desc,
		Evidence:    ds.Evidence,
		Severity:    SeverityInfo,
		Confidence:  conf,
		Fingerprint: GenerateFingerprint(Provider(ds.Technology), endpoint, category),
		Details:     details,
	}, true
}
