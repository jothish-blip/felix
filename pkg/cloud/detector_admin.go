package cloud

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

var (
	mongoExpressTitleRegex = regexp.MustCompile(`(?i)<title>\s*Mongo\s+Express\s*</title>`)
	mongoExpressURLRegex   = regexp.MustCompile(`https?://[a-zA-Z0-9_\.\-]+:8081(?:/[a-zA-Z0-9_\.\-]*)?`)
)

// ExtractAdminTargets inspects content and URLs for database administration interfaces.
func ExtractAdminTargets(source string, content []byte) []DiscoveredService {
	var results []DiscoveredService
	text := string(content)
	now := time.Now().UTC()

	// Mongo Express candidate endpoints
	for _, match := range mongoExpressURLRegex.FindAllString(text, -1) {
		results = append(results, DiscoveredService{
			Technology:      TechMongoExpress,
			Family:          FamilyDatabaseAdmin,
			Outcome:         OutcomePossible,
			Confidence:      ConfidenceMedium,
			Endpoint:        match,
			Protocol:        "http",
			DetectionMethod: "PASSIVE_ANALYSIS",
			Evidence:        fmt.Sprintf("Discovered Mongo Express port/URL reference in %s: %s", source, match),
			SourceAsset:     source,
			DiscoveredAt:    now,
		})
	}

	return results
}

// ProbeMongoExpress executes safe HTTP verification against a candidate Mongo Express endpoint.
func ProbeMongoExpress(ctx context.Context, client *Client, targetURL string) DiscoveredService {
	parsed, err := url.Parse(targetURL)
	if err != nil {
		return DiscoveredService{
			Technology:   TechMongoExpress,
			Family:       FamilyDatabaseAdmin,
			Outcome:      OutcomeError,
			Endpoint:     targetURL,
			Limitations:  fmt.Sprintf("invalid URL: %v", err),
			DiscoveredAt: time.Now().UTC(),
		}
	}

	req, err := http.NewRequestWithContext(ctx, "GET", targetURL, nil)
	if err != nil {
		return DiscoveredService{
			Technology:   TechMongoExpress,
			Family:       FamilyDatabaseAdmin,
			Outcome:      OutcomeError,
			Endpoint:     targetURL,
			Limitations:  err.Error(),
			DiscoveredAt: time.Now().UTC(),
		}
	}

	resp, err := client.Do(ctx, req)
	if err != nil {
		return DiscoveredService{
			Technology:      TechMongoExpress,
			Family:          FamilyDatabaseAdmin,
			Outcome:         OutcomeInconclusive,
			Endpoint:        targetURL,
			Host:            parsed.Hostname(),
			DetectionMethod: "HTTP_PROBE",
			Limitations:     fmt.Sprintf("connection error: %v", err),
			DiscoveredAt:    time.Now().UTC(),
		}
	}

	bodyStr := string(resp.Body)
	authHdr := resp.Header.Get("WWW-Authenticate")
	cookieHdr := resp.Header.Get("Set-Cookie")

	// 1. Unauthenticated Exposed Mongo Express UI (HTTP 200)
	if resp.StatusCode == http.StatusOK {
		hasTitle := mongoExpressTitleRegex.MatchString(bodyStr)
		hasBrand := strings.Contains(bodyStr, "Mongo Express") || strings.Contains(bodyStr, "mongo-express")
		if hasTitle || (hasBrand && strings.Contains(bodyStr, "Database")) {
			return DiscoveredService{
				Technology:      TechMongoExpress,
				Family:          FamilyDatabaseAdmin,
				Outcome:         OutcomeDetected,
				Confidence:      ConfidenceHigh,
				Endpoint:        targetURL,
				Host:            parsed.Hostname(),
				Port:            8081,
				Protocol:        parsed.Scheme,
				DetectionMethod: "HTTP_PROBE",
				AuthRequired:    false,
				PublicAccess:    false,
				Evidence:        "Mongo Express admin dashboard exposed without authentication; page title and markup confirmed",
				Limitations:     "Admin dashboard presence confirmed; database management authentication and CRUD authorization require Phase 2.2 verification",
				InScope:         true,
				DiscoveredAt:    time.Now().UTC(),
			}
		}
	}

	// 2. Authenticated Mongo Express Instance (HTTP 401)
	if resp.StatusCode == http.StatusUnauthorized {
		lowerAuth := strings.ToLower(authHdr)
		if strings.Contains(lowerAuth, "mongo-express") || strings.Contains(lowerAuth, "mongo express") || strings.Contains(cookieHdr, "mongo-express") {
			return DiscoveredService{
				Technology:      TechMongoExpress,
				Family:          FamilyDatabaseAdmin,
				Outcome:         OutcomeDetected,
				Confidence:      ConfidenceHigh,
				Endpoint:        targetURL,
				Host:            parsed.Hostname(),
				Port:            8081,
				Protocol:        parsed.Scheme,
				DetectionMethod: "HTTP_PROBE",
				AuthRequired:    true,
				PublicAccess:    false,
				Evidence:        fmt.Sprintf("Mongo Express authentication challenge observed: %s", authHdr),
				InScope:         true,
				DiscoveredAt:    time.Now().UTC(),
			}
		}
	}

	return DiscoveredService{
		Technology:      TechMongoExpress,
		Family:          FamilyDatabaseAdmin,
		Outcome:         OutcomeNotDetected,
		Endpoint:        targetURL,
		Host:            parsed.Hostname(),
		DetectionMethod: "HTTP_PROBE",
		Evidence:        fmt.Sprintf("HTTP status %d returned without Mongo Express signatures", resp.StatusCode),
		DiscoveredAt:    time.Now().UTC(),
	}
}
