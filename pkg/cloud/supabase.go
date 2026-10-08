package cloud

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"
)

// AuditSupabase audits discovered Supabase infrastructure for unauthorized exposures.
func AuditSupabase(ctx context.Context, client *Client, service Service, candidateEndpoints []string, anonKey, serviceRoleKey string) []CloudFinding {
	var findings []CloudFinding

	// 1. If a privileged service-role key was identified in assets, report CRITICAL immediately.
	// IMPORTANT: Felix MUST NEVER attempt to execute requests using the service_role key.
	if serviceRoleKey != "" {
		findings = append(findings, CloudFinding{
			Provider:         ProviderSupabase,
			Category:         "Privileged Credential Exposure",
			Endpoint:         service.URL,
			Description:      "Privileged Supabase service_role key exposed in client assets",
			Evidence:         "Privileged credential detected statically. No live transmission performed for safety. A service_role key was extracted from client-side bundles allowing full administrative database access bypassing Row Level Security (RLS).",
			Severity:         SeverityCritical,
			Confidence:       ConfidenceHigh,
			HTTPMethod:       "GET",
			HTTPStatus:       0,
			NegativeEvidence: "Privileged credentials were strictly NOT used to probe live cloud infrastructure.",
			Fingerprint:      GenerateFingerprint(ProviderSupabase, service.URL, "Privileged Credential Exposure"),
		})
	}

	// 2. If an anon key was discovered, note it as an INFO finding (expected client-side configuration).
	if anonKey != "" {
		findings = append(findings, CloudFinding{
			Provider:         ProviderSupabase,
			Category:         "Client Configuration",
			Endpoint:         service.URL,
			Description:      "Supabase publishable anon key detected",
			Evidence:         "Public anon key observed in client-accessible assets (expected client-side configuration; authorization governed by Row Level Security).",
			Severity:         SeverityInfo,
			Confidence:       ConfidenceHigh,
			HTTPMethod:       "GET",
			HTTPStatus:       0,
			NegativeEvidence: "Public client configuration only; no privileged credential exposure or unauthorized data access demonstrated.",
			Fingerprint:      GenerateFingerprint(ProviderSupabase, service.URL, "Client Configuration"),
		})
	}

	// 3. Authorization verification on discovered candidate resources
	baseURL := strings.TrimRight(service.URL, "/")

	// Deduplicate candidate endpoints
	seenEndpoints := make(map[string]struct{})
	for _, ep := range candidateEndpoints {
		cleanEP := strings.TrimSpace(ep)
		if cleanEP == "" {
			continue
		}
		if !strings.HasPrefix(cleanEP, "/") {
			cleanEP = "/" + cleanEP
		}
		if _, exists := seenEndpoints[cleanEP]; !exists {
			seenEndpoints[cleanEP] = struct{}{}
		}
	}

	for ep := range seenEndpoints {
		targetURL := baseURL + ep
		// Append limit=1 to avoid dumping data
		if strings.Contains(targetURL, "?") {
			targetURL += "&limit=1"
		} else {
			targetURL += "?limit=1"
		}

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, targetURL, nil)
		if err != nil {
			continue
		}

		req.Header.Set("Accept", "application/json")
		if anonKey != "" {
			req.Header.Set("apikey", anonKey)
			req.Header.Set("Authorization", "Bearer "+anonKey)
		}

		resp, err := client.Do(ctx, req)
		if err != nil {
			if err == ErrRateLimited {
				// Stop testing on rate limit
				break
			}
			continue
		}

		// Authorization verification:
		// 401 or 403 means RLS/Authorization correctly blocks access -> Expected secure state.
		if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
			continue
		}

		// 200 OK: Inspect if actual database records were returned
		if resp.StatusCode == http.StatusOK {
			var records []map[string]interface{}
			if err := json.Unmarshal(resp.Body, &records); err == nil && len(records) > 0 {
				// Collect field names from first record without storing record values
				var fields []string
				for k := range records[0] {
					fields = append(fields, k)
				}
				sort.Strings(fields)

				findings = append(findings, CloudFinding{
					Provider:         ProviderSupabase,
					Category:         "Unauthorized Data Exposure",
					Endpoint:         service.URL + ep,
					Description:      fmt.Sprintf("Public read access allowed on Supabase resource %s", ep),
					Evidence: fmt.Sprintf("HTTP 200 OK. Returned %d record(s). Observed fields: [%s] (record contents redacted)",
						len(records), strings.Join(fields, ", ")),
					Severity:         SeverityHigh,
					Confidence:       ConfidenceHigh,
					HTTPMethod:       http.MethodGet,
					HTTPStatus:       resp.StatusCode,
					NegativeEvidence: "",
					Details: map[string]string{
						"record_count": fmt.Sprintf("%d", len(records)),
						"fields":       strings.Join(fields, ", "),
					},
					Fingerprint: GenerateFingerprint(ProviderSupabase, service.URL+ep, "Unauthorized Data Exposure"),
				})
			}
		}
	}

	return findings
}
