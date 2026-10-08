package cloud

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"
)

// AuditFirebase audits discovered Firebase Realtime Database endpoints.
func AuditFirebase(ctx context.Context, client *Client, service Service) []CloudFinding {
	var findings []CloudFinding

	baseURL := strings.TrimRight(service.URL, "/")
	probeURL := baseURL + "/.json?shallow=true&limitToFirst=1"

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, probeURL, nil)
	if err != nil {
		return findings
	}
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(ctx, req)
	if err != nil {
		return findings
	}

	// 401 Unauthorized or 403 Forbidden: Firebase security rules properly block access
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return findings
	}

	// 200 OK: Database allows unauthenticated access
	if resp.StatusCode == http.StatusOK {
		var topLevelKeys []string
		var jsonObj map[string]interface{}
		if err := json.Unmarshal(resp.Body, &jsonObj); err == nil {
			for k := range jsonObj {
				topLevelKeys = append(topLevelKeys, k)
			}
			sort.Strings(topLevelKeys)
		}

		keySummary := "none"
		if len(topLevelKeys) > 0 {
			keySummary = strings.Join(topLevelKeys, ", ")
		}

		findings = append(findings, CloudFinding{
			Provider:         ProviderFirebase,
			Category:         "Unauthenticated Database Access",
			Endpoint:         service.URL,
			Description:      "Firebase Realtime Database allows unauthenticated public read access",
			Evidence: fmt.Sprintf("HTTP 200 OK. Public JSON returned (%d bytes). Top-level keys: [%s] (database values redacted)",
				len(resp.Body), keySummary),
			Severity:         SeverityHigh,
			Confidence:       ConfidenceHigh,
			HTTPMethod:       http.MethodGet,
			HTTPStatus:       resp.StatusCode,
			NegativeEvidence: "",
			Details: map[string]string{
				"top_level_keys": keySummary,
				"payload_bytes":  fmt.Sprintf("%d", len(resp.Body)),
			},
			Fingerprint: GenerateFingerprint(ProviderFirebase, service.URL, "Unauthenticated Database Access"),
		})
	}

	return findings
}
