package cloud

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

var (
	// PostgREST indicators
	postgrestErrRegex = regexp.MustCompile(`PGRST\d{3}`)

	// Hasura indicators
	hasuraErrorRegex = regexp.MustCompile(`"code"\s*:\s*"(?:validation-failed|not-found|access-denied)"`)

	// Prisma indicators
	prismaErrorRegex  = regexp.MustCompile(`\b(P200[0-9]|P201[0-9]|P202[0-9]|P203[0-9])\b|Invalid\s+` + "`" + `prisma\.\w+\.\w+\(\)` + "`")
	prismaClientRegex = regexp.MustCompile(`@prisma/client|\.prisma/client|schema\.prisma`)
)

// ExtractBackendTargets inspects content and URLs for backend database interface signatures.
func ExtractBackendTargets(source string, content []byte) []DiscoveredService {
	var results []DiscoveredService
	text := string(content)
	now := time.Now().UTC()

	// 1. Supabase
	for _, match := range supabaseURLRegex.FindAllStringSubmatch(text, -1) {
		cleanURL := "https://" + match[1] + ".supabase.co"
		results = append(results, DiscoveredService{
			Technology:      TechSupabase,
			Family:          FamilyBackendInterface,
			Outcome:         OutcomePossible,
			Confidence:      ConfidenceHigh,
			Endpoint:        cleanURL,
			Host:            match[1] + ".supabase.co",
			Protocol:        "https",
			DetectionMethod: "PASSIVE_ANALYSIS",
			Evidence:        fmt.Sprintf("Discovered Supabase project URL in %s: %s", source, cleanURL),
			Metadata: map[string]any{
				"project": match[1],
			},
			SourceAsset:  source,
			DiscoveredAt: now,
		})
	}

	// 2. Prisma in bundles/source maps
	if prismaClientRegex.Match(content) {
		matchedStr := prismaClientRegex.FindString(text)
		results = append(results, DiscoveredService{
			Technology:      TechPrisma,
			Family:          FamilyBackendInterface,
			Outcome:         OutcomeDetected,
			Confidence:      ConfidenceHigh,
			DetectionMethod: "PASSIVE_ANALYSIS",
			Evidence:        fmt.Sprintf("Discovered Prisma ORM client reference in %s: %q", source, matchedStr),
			Metadata: map[string]any{
				"reference": matchedStr,
			},
			SourceAsset:  source,
			DiscoveredAt: now,
		})
	} else if prismaErrorRegex.Match(content) {
		matchedErr := prismaErrorRegex.FindString(text)
		results = append(results, DiscoveredService{
			Technology:      TechPrisma,
			Family:          FamilyBackendInterface,
			Outcome:         OutcomeDetected,
			Confidence:      ConfidenceHigh,
			DetectionMethod: "PASSIVE_ANALYSIS",
			Evidence:        fmt.Sprintf("Observed Prisma error code in %s: %q", source, matchedErr),
			Metadata: map[string]any{
				"error_code": matchedErr,
			},
			SourceAsset:  source,
			DiscoveredAt: now,
		})
	}

	return results
}

// ProbePostgREST executes safe HTTP verification against a PostgREST candidate endpoint.
func ProbePostgREST(ctx context.Context, client *Client, targetURL string) DiscoveredService {
	parsed, err := url.Parse(targetURL)
	if err != nil {
		return DiscoveredService{
			Technology:   TechPostgREST,
			Family:       FamilyBackendInterface,
			Outcome:      OutcomeError,
			Endpoint:     targetURL,
			Limitations:  fmt.Sprintf("invalid URL: %v", err),
			DiscoveredAt: time.Now().UTC(),
		}
	}

	req, err := http.NewRequestWithContext(ctx, "GET", targetURL, nil)
	if err != nil {
		return DiscoveredService{
			Technology:   TechPostgREST,
			Family:       FamilyBackendInterface,
			Outcome:      OutcomeError,
			Endpoint:     targetURL,
			Limitations:  err.Error(),
			DiscoveredAt: time.Now().UTC(),
		}
	}
	req.Header.Set("Accept", "application/json, application/openapi+json")

	resp, err := client.Do(ctx, req)
	if err != nil {
		return DiscoveredService{
			Technology:      TechPostgREST,
			Family:          FamilyBackendInterface,
			Outcome:         OutcomeInconclusive,
			Endpoint:        targetURL,
			Host:            parsed.Hostname(),
			DetectionMethod: "HTTP_PROBE",
			Limitations:     fmt.Sprintf("connection error: %v", err),
			DiscoveredAt:    time.Now().UTC(),
		}
	}

	rangeUnit := resp.Header.Get("Range-Unit")
	bodyStr := string(resp.Body)

	// PostgREST standard indicator: Range-Unit header is "items"
	if strings.EqualFold(rangeUnit, "items") {
		return DiscoveredService{
			Technology:      TechPostgREST,
			Family:          FamilyBackendInterface,
			Outcome:         OutcomeDetected,
			Confidence:      ConfidenceHigh,
			Endpoint:        targetURL,
			Host:            parsed.Hostname(),
			Protocol:        parsed.Scheme,
			DetectionMethod: "HTTP_PROBE",
			Evidence:        "PostgREST verified via HTTP 'Range-Unit: items' response header",
			Metadata: map[string]any{
				"range_unit": rangeUnit,
			},
			InScope:      true,
			DiscoveredAt: time.Now().UTC(),
		}
	}

	// PostgREST root OpenAPI schema provides "info": { "title": "PostgREST API" }
	if resp.StatusCode == http.StatusOK {
		var openAPI struct {
			Info struct {
				Title       string `json:"title"`
				Description string `json:"description"`
				Version     string `json:"version"`
			} `json:"info"`
			Swagger string `json:"swagger"`
		}
		if json.Unmarshal(resp.Body, &openAPI) == nil {
			if strings.Contains(strings.ToLower(openAPI.Info.Title), "postgrest") ||
				strings.Contains(strings.ToLower(openAPI.Info.Description), "postgrest") {
				return DiscoveredService{
					Technology:      TechPostgREST,
					Family:          FamilyBackendInterface,
					Outcome:         OutcomeDetected,
					Confidence:      ConfidenceHigh,
					Endpoint:        targetURL,
					Host:            parsed.Hostname(),
					Protocol:        parsed.Scheme,
					DetectionMethod: "HTTP_PROBE",
					Version:         openAPI.Info.Version,
					Evidence:        fmt.Sprintf("PostgREST OpenAPI specification discovered: %s", openAPI.Info.Title),
					Metadata: map[string]any{
						"title":   openAPI.Info.Title,
						"version": openAPI.Info.Version,
					},
					InScope:      true,
					DiscoveredAt: time.Now().UTC(),
				}
			}
		}
	}

	// PostgREST JSON Error codes (e.g. PGRST100, PGRST301)
	if postgrestErrRegex.MatchString(bodyStr) {
		errCode := postgrestErrRegex.FindString(bodyStr)
		return DiscoveredService{
			Technology:      TechPostgREST,
			Family:          FamilyBackendInterface,
			Outcome:         OutcomeDetected,
			Confidence:      ConfidenceHigh,
			Endpoint:        targetURL,
			Host:            parsed.Hostname(),
			Protocol:        parsed.Scheme,
			DetectionMethod: "HTTP_PROBE",
			Evidence:        fmt.Sprintf("PostgREST error code signature returned: %s", errCode),
			Metadata: map[string]any{
				"error_code": errCode,
			},
			InScope:      true,
			DiscoveredAt: time.Now().UTC(),
		}
	}

	return DiscoveredService{
		Technology:      TechPostgREST,
		Family:          FamilyBackendInterface,
		Outcome:         OutcomeNotDetected,
		Endpoint:        targetURL,
		Host:            parsed.Hostname(),
		DetectionMethod: "HTTP_PROBE",
		Evidence:        fmt.Sprintf("HTTP status %d returned without PostgREST markers", resp.StatusCode),
		DiscoveredAt:    time.Now().UTC(),
	}
}

// ProbeHasura executes safe HTTP verification against a candidate Hasura GraphQL engine.
func ProbeHasura(ctx context.Context, client *Client, baseURL string) DiscoveredService {
	parsed, err := url.Parse(baseURL)
	if err != nil {
		return DiscoveredService{
			Technology:   TechHasura,
			Family:       FamilyBackendInterface,
			Outcome:      OutcomeError,
			Endpoint:     baseURL,
			Limitations:  fmt.Sprintf("invalid URL: %v", err),
			DiscoveredAt: time.Now().UTC(),
		}
	}

	now := time.Now().UTC()

	// Step 1: Probe /v1/version
	versionURL := fmt.Sprintf("%s://%s/v1/version", parsed.Scheme, parsed.Host)
	reqV, err := http.NewRequestWithContext(ctx, "GET", versionURL, nil)
	if err == nil {
		if respV, err := client.Do(ctx, reqV); err == nil && respV.StatusCode == http.StatusOK {
			var verObj struct {
				Version string `json:"version"`
			}
			if json.Unmarshal(respV.Body, &verObj) == nil && verObj.Version != "" {
				return DiscoveredService{
					Technology:      TechHasura,
					Family:          FamilyBackendInterface,
					Outcome:         OutcomeDetected,
					Confidence:      ConfidenceHigh,
					Endpoint:        baseURL,
					Host:            parsed.Hostname(),
					Protocol:        parsed.Scheme,
					DetectionMethod: "HTTP_PROBE",
					Version:         verObj.Version,
					Evidence:        fmt.Sprintf("Hasura version endpoint (/v1/version) responded 200 OK: %s", verObj.Version),
					Metadata: map[string]any{
						"version": verObj.Version,
					},
					InScope:      true,
					DiscoveredAt: now,
				}
			}
		}
	}

	// Step 2: Probe GraphQL endpoint with empty POST to check Hasura JSON error format
	graphqlURL := fmt.Sprintf("%s://%s/v1/graphql", parsed.Scheme, parsed.Host)
	reqGQL, err := http.NewRequestWithContext(ctx, "POST", graphqlURL, strings.NewReader("{}"))
	if err == nil {
		reqGQL.Header.Set("Content-Type", "application/json")
		if respGQL, err := client.Do(ctx, reqGQL); err == nil {
			bodyStr := string(respGQL.Body)
			hasuraRole := respGQL.Header.Get("x-hasura-role")

			if hasuraRole != "" || (hasuraErrorRegex.MatchString(bodyStr) && strings.Contains(bodyStr, "errors")) {
				return DiscoveredService{
					Technology:      TechHasura,
					Family:          FamilyBackendInterface,
					Outcome:         OutcomeDetected,
					Confidence:      ConfidenceHigh,
					Endpoint:        graphqlURL,
					Host:            parsed.Hostname(),
					Protocol:        parsed.Scheme,
					DetectionMethod: "HTTP_PROBE",
					AuthRequired:    hasuraRole != "anonymous",
					Evidence:        "Hasura GraphQL engine identified via standard error structure or x-hasura-role header",
					InScope:         true,
					DiscoveredAt:    now,
				}
			}
		}
	}

	// Step 3: Probe /healthz
	healthzURL := fmt.Sprintf("%s://%s/healthz", parsed.Scheme, parsed.Host)
	reqH, err := http.NewRequestWithContext(ctx, "GET", healthzURL, nil)
	if err == nil {
		if respH, err := client.Do(ctx, reqH); err == nil && respH.StatusCode == http.StatusOK {
			bodyStr := strings.TrimSpace(string(respH.Body))
			if strings.EqualFold(bodyStr, "OK") || strings.Contains(bodyStr, "alive") {
				// Possible Hasura healthz endpoint (common in Hasura deployments)
				return DiscoveredService{
					Technology:      TechHasura,
					Family:          FamilyBackendInterface,
					Outcome:         OutcomePossible,
					Confidence:      ConfidenceMedium,
					Endpoint:        healthzURL,
					Host:            parsed.Hostname(),
					Protocol:        parsed.Scheme,
					DetectionMethod: "HTTP_PROBE",
					Evidence:        "Candidate Hasura /healthz endpoint returned 200 OK",
					InScope:         true,
					DiscoveredAt:    now,
				}
			}
		}
	}

	return DiscoveredService{
		Technology:      TechHasura,
		Family:          FamilyBackendInterface,
		Outcome:         OutcomeNotDetected,
		Endpoint:        baseURL,
		Host:            parsed.Hostname(),
		DetectionMethod: "HTTP_PROBE",
		Evidence:        "No Hasura GraphQL or version signatures observed",
		DiscoveredAt:    now,
	}
}

// AssessPrisma provides explicit discovery results and empirical limitations for Prisma ORM.
func AssessPrisma(source string, content []byte) DiscoveredService {
	now := time.Now().UTC()
	text := string(content)

	if prismaClientRegex.Match(content) {
		match := prismaClientRegex.FindString(text)
		return DiscoveredService{
			Technology:      TechPrisma,
			Family:          FamilyBackendInterface,
			Outcome:         OutcomeDetected,
			Confidence:      ConfidenceHigh,
			DetectionMethod: "PASSIVE_ANALYSIS",
			Evidence:        fmt.Sprintf("Prisma ORM client reference observed in %s: %q", source, match),
			Metadata: map[string]any{
				"reference": match,
			},
			SourceAsset:  source,
			DiscoveredAt: now,
		}
	}

	if prismaErrorRegex.Match(content) {
		match := prismaErrorRegex.FindString(text)
		return DiscoveredService{
			Technology:      TechPrisma,
			Family:          FamilyBackendInterface,
			Outcome:         OutcomeDetected,
			Confidence:      ConfidenceHigh,
			DetectionMethod: "PASSIVE_ANALYSIS",
			Evidence:        fmt.Sprintf("Prisma specific error code observed in %s: %q", source, match),
			Metadata: map[string]any{
				"error_code": match,
			},
			SourceAsset:  source,
			DiscoveredAt: now,
		}
	}

	return DiscoveredService{
		Technology:      TechPrisma,
		Family:          FamilyBackendInterface,
		Outcome:         OutcomeNotDetected,
		DetectionMethod: "PASSIVE_ANALYSIS",
		Evidence:        "No Prisma ORM artifacts or error signatures observed in assets",
		Limitations:     "Prisma is an internal server-side ORM; black-box discovery requires client bundle traces or leaked error codes (e.g., P2002)",
		SourceAsset:     source,
		DiscoveredAt:    now,
	}
}
