package cloud

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"regexp"
	"strings"

	"felix/pkg/crawler"
	"felix/pkg/secrets"
)

var (
	// Supabase discovery
	supabaseURLRegex = regexp.MustCompile(`https://([a-zA-Z0-9_\-]+)\.supabase\.co`)
	supabaseEPRegex  = regexp.MustCompile(`/rest/v1/([a-zA-Z0-9_\-]+)`)

	// Firebase discovery
	firebaseIOURLRegex = regexp.MustCompile(`https://([a-zA-Z0-9_\-]+)\.firebaseio\.com`)
	firebaseAppRegex   = regexp.MustCompile(`https://([a-zA-Z0-9_\-]+(?:-default-rtdb)?(?:\.[a-zA-Z0-9_\-]+)?\.firebasedatabase\.app)`)

	// AWS S3 discovery
	s3HostRegex = regexp.MustCompile(`https://([a-zA-Z0-9_\.\-]+)\.s3(?:[.-][a-zA-Z0-9_\-]+)?\.amazonaws\.com(?:/[a-zA-Z0-9_\.\-]*)?`)
	s3PathRegex = regexp.MustCompile(`https://s3(?:[.-][a-zA-Z0-9_\-]+)?\.amazonaws\.com/([a-zA-Z0-9_\.\-]+)(?:/[a-zA-Z0-9_\.\-]*)?`)

	// Google Cloud Storage discovery
	gcsHostRegex = regexp.MustCompile(`https://storage\.googleapis\.com/([a-zA-Z0-9_\.\-]+)(?:/[a-zA-Z0-9_\.\-]*)?`)
	gcsSubRegex  = regexp.MustCompile(`https://([a-zA-Z0-9_\.\-]+)\.storage\.googleapis\.com(?:/[a-zA-Z0-9_\.\-]*)?`)

	// Generic JWT extractor for Supabase keys
	jwtRegex = regexp.MustCompile(`\b(ey[A-Za-z0-9_-]{10,}\.ey[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})\b`)
)

// AuditResult encapsulates discovered cloud services and evaluated risk findings.
type AuditResult struct {
	Services []Service      `json:"services"`
	Findings []CloudFinding `json:"findings"`
}

// Detector identifies cloud vendor configurations and coordinates safe verification.
type Detector struct {
	client *Client
}

// NewDetector initializes a new Cloud & BaaS auditor.
func NewDetector(client *Client) *Detector {
	if client == nil {
		client = NewClient()
	}
	return &Detector{
		client: client,
	}
}

// DiscoverServicesFromContent extracts recognized cloud endpoints from raw text.
func DiscoverServicesFromContent(source string, content []byte) []Service {
	var services []Service
	text := string(content)

	// 1. Supabase
	for _, match := range supabaseURLRegex.FindAllStringSubmatch(text, -1) {
		cleanURL := "https://" + match[1] + ".supabase.co"
		services = append(services, Service{
			Provider: ProviderSupabase,
			URL:      cleanURL,
			Source:   source,
			Identifiers: map[string]string{
				"project": match[1],
			},
		})
	}

	// 2. Firebase
	for _, match := range firebaseIOURLRegex.FindAllStringSubmatch(text, -1) {
		cleanURL := "https://" + match[1] + ".firebaseio.com"
		services = append(services, Service{
			Provider: ProviderFirebase,
			URL:      cleanURL,
			Source:   source,
			Identifiers: map[string]string{
				"project": match[1],
			},
		})
	}
	for _, match := range firebaseAppRegex.FindAllStringSubmatch(text, -1) {
		cleanURL := "https://" + match[1]
		services = append(services, Service{
			Provider: ProviderFirebase,
			URL:      cleanURL,
			Source:   source,
		})
	}

	// 3. AWS S3
	for _, match := range s3HostRegex.FindAllStringSubmatch(text, -1) {
		cleanURL := "https://" + match[1] + ".s3.amazonaws.com"
		services = append(services, Service{
			Provider: ProviderAWS,
			URL:      cleanURL,
			Source:   source,
			Identifiers: map[string]string{
				"bucket": match[1],
			},
		})
	}
	for _, match := range s3PathRegex.FindAllStringSubmatch(text, -1) {
		cleanURL := "https://s3.amazonaws.com/" + match[1]
		services = append(services, Service{
			Provider: ProviderAWS,
			URL:      cleanURL,
			Source:   source,
			Identifiers: map[string]string{
				"bucket": match[1],
			},
		})
	}

	// 4. GCP Cloud Storage
	for _, match := range gcsHostRegex.FindAllStringSubmatch(text, -1) {
		cleanURL := "https://storage.googleapis.com/" + match[1]
		services = append(services, Service{
			Provider: ProviderGCP,
			URL:      cleanURL,
			Source:   source,
			Identifiers: map[string]string{
				"bucket": match[1],
			},
		})
	}
	for _, match := range gcsSubRegex.FindAllStringSubmatch(text, -1) {
		cleanURL := "https://" + match[1] + ".storage.googleapis.com"
		services = append(services, Service{
			Provider: ProviderGCP,
			URL:      cleanURL,
			Source:   source,
			Identifiers: map[string]string{
				"bucket": match[1],
			},
		})
	}

	return services
}

// DiscoverServices scans crawled assets and extracts unique cloud endpoints.
func (d *Detector) DiscoverServices(assets []crawler.Asset) []Service {
	var services []Service
	seen := make(map[string]struct{})

	for _, a := range assets {
		if len(a.Content) == 0 {
			continue
		}
		rawServices := DiscoverServicesFromContent(a.URL, a.Content)
		for _, s := range rawServices {
			id := s.CanonicalID()
			if _, exists := seen[id]; !exists {
				seen[id] = struct{}{}
				services = append(services, s)
			}
		}
	}

	return services
}

// Audit executes safe verification against discovered cloud and BaaS services.
func (d *Detector) Audit(ctx context.Context, assets []crawler.Asset, secretFindings []secrets.SecretFinding) AuditResult {
	services := d.DiscoverServices(assets)

	// Extract candidate REST endpoints and Supabase keys from assets and secret findings
	var (
		supabaseEndpoints []string
		supabaseAnonKey   string
		supabaseServiceKey string
		seenEndpoints     = make(map[string]struct{})
	)

	// Check secret findings for already identified service_role keys
	for _, sf := range secretFindings {
		if sf.Type == secrets.SecretSupabaseServiceKey {
			supabaseServiceKey = sf.Value
		}
	}

	// Scan asset contents for endpoints and tokens
	for _, a := range assets {
		if len(a.Content) == 0 {
			continue
		}
		text := string(a.Content)

		// Candidate REST endpoints
		for _, epMatch := range supabaseEPRegex.FindAllStringSubmatch(text, -1) {
			path := "/rest/v1/" + epMatch[1]
			if _, exists := seenEndpoints[path]; !exists {
				seenEndpoints[path] = struct{}{}
				supabaseEndpoints = append(supabaseEndpoints, path)
			}
		}

		// Inspect JWTs for Supabase keys if not already found
		if supabaseAnonKey == "" || supabaseServiceKey == "" {
			for _, jwtMatch := range jwtRegex.FindAllString(text, -1) {
				parts := strings.Split(jwtMatch, ".")
				if len(parts) == 3 {
					if payloadBytes, err := decodeBase64URL(parts[1]); err == nil {
						var claims map[string]interface{}
						if json.Unmarshal(payloadBytes, &claims) == nil {
							role, _ := claims["role"].(string)
							iss, _ := claims["iss"].(string)
							if strings.Contains(strings.ToLower(iss), "supabase") || strings.Contains(strings.ToLower(jwtMatch), "supabase") {
								if role == "anon" && supabaseAnonKey == "" {
									supabaseAnonKey = jwtMatch
								} else if role == "service_role" && supabaseServiceKey == "" {
									supabaseServiceKey = jwtMatch
								}
							}
						}
					}
				}
			}
		}
	}

	var allFindings []CloudFinding
	seenFindingFPs := make(map[string]struct{})

	// Audit discovered services
	for _, svc := range services {
		var svcFindings []CloudFinding

		switch svc.Provider {
		case ProviderSupabase:
			svcFindings = AuditSupabase(ctx, d.client, svc, supabaseEndpoints, supabaseAnonKey, supabaseServiceKey)
		case ProviderFirebase:
			svcFindings = AuditFirebase(ctx, d.client, svc)
		case ProviderAWS, ProviderGCP:
			svcFindings = AuditStorage(ctx, d.client, svc)
		}

		for _, f := range svcFindings {
			if _, exists := seenFindingFPs[f.Fingerprint]; !exists {
				seenFindingFPs[f.Fingerprint] = struct{}{}
				allFindings = append(allFindings, f)
			}
		}
	}

	// Also handle the case where a Supabase service_role key was found without an explicit supabase URL
	if supabaseServiceKey != "" && len(services) == 0 {
		f := CloudFinding{
			Provider:    ProviderSupabase,
			Category:    "Privileged Credential Exposure",
			Endpoint:    "client-bundle",
			Description: "Privileged Supabase service_role key exposed in client assets",
			Evidence:    "A service_role key was extracted from client-side bundles. This allows full database administration bypassing Row Level Security (RLS). Not tested against live API.",
			Severity:    SeverityCritical,
			Confidence:  ConfidenceHigh,
			Fingerprint: GenerateFingerprint(ProviderSupabase, "client-bundle", "Privileged Credential Exposure"),
		}
		if _, exists := seenFindingFPs[f.Fingerprint]; !exists {
			seenFindingFPs[f.Fingerprint] = struct{}{}
			allFindings = append(allFindings, f)
		}
	}

	return AuditResult{
		Services: services,
		Findings: allFindings,
	}
}

// decodeBase64URL decodes base64url data safely with padding recovery.
func decodeBase64URL(input string) ([]byte, error) {
	data, err := base64.RawURLEncoding.DecodeString(input)
	if err == nil {
		return data, nil
	}
	pad := len(input) % 4
	if pad > 0 {
		input += strings.Repeat("=", 4-pad)
	}
	return base64.URLEncoding.DecodeString(input)
}
