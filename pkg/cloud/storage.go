package cloud

import (
	"context"
	"fmt"
	"net/http"
	"strings"
)

// AuditStorage audits AWS S3 and Google Cloud Storage buckets for anonymous listing.
func AuditStorage(ctx context.Context, client *Client, service Service) []CloudFinding {
	var findings []CloudFinding

	baseURL := strings.TrimRight(service.URL, "/")
	probeURL := baseURL
	if strings.Contains(baseURL, "?") {
		probeURL += "&max-keys=1"
	} else {
		probeURL += "/?max-keys=1"
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, probeURL, nil)
	if err != nil {
		return findings
	}

	resp, err := client.Do(ctx, req)
	if err != nil {
		return findings
	}

	// 403 Forbidden or 401 Unauthorized: Listing disabled -> Secure state
	if resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusUnauthorized {
		return findings
	}

	// 200 OK: Check if an XML ListBucketResult was returned
	bodyStr := string(resp.Body)
	isListingXML := strings.Contains(bodyStr, "<ListBucketResult") ||
		strings.Contains(bodyStr, "<Bucket") ||
		strings.Contains(bodyStr, "<Contents>")

	if resp.StatusCode == http.StatusOK && isListingXML {
		providerName := "AWS S3"
		if service.Provider == ProviderGCP {
			providerName = "Google Cloud Storage"
		}

		findings = append(findings, CloudFinding{
			Provider:         service.Provider,
			Category:         "Anonymous Bucket Listing",
			Endpoint:         service.URL,
			Description:      fmt.Sprintf("%s storage bucket permits anonymous object listing", providerName),
			Evidence: fmt.Sprintf("HTTP 200 OK. Public ListBucketResult observed (%d bytes). Object listing is publicly readable (file contents not downloaded).",
				len(resp.Body)),
			Severity:         SeverityMedium,
			Confidence:       ConfidenceHigh,
			HTTPMethod:       http.MethodGet,
			HTTPStatus:       resp.StatusCode,
			NegativeEvidence: "Object listing is publicly readable; file contents were not downloaded.",
			Details: map[string]string{
				"storage_provider": providerName,
				"payload_bytes":    fmt.Sprintf("%d", len(resp.Body)),
			},
			Fingerprint: GenerateFingerprint(service.Provider, service.URL, "Anonymous Bucket Listing"),
		})
	}

	return findings
}
