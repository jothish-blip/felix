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
	firestoreProjectRegex = regexp.MustCompile(`["']?projectId["']?\s*:\s*["']([a-zA-Z0-9_\-]+)["']`)
	firestoreLibRegex     = regexp.MustCompile(`@firebase/firestore|firebase/firestore|firestore\.googleapis\.com`)
)

// ExtractFirebaseTargets inspects content for Firebase Realtime Database and Cloud Firestore references.
func ExtractFirebaseTargets(source string, content []byte) []DiscoveredService {
	var results []DiscoveredService
	text := string(content)
	now := time.Now().UTC()

	// 1. Firebase RTDB (.firebaseio.com)
	for _, match := range firebaseIOURLRegex.FindAllStringSubmatch(text, -1) {
		cleanURL := "https://" + match[1] + ".firebaseio.com"
		results = append(results, DiscoveredService{
			Technology:      TechFirebaseRTDB,
			Family:          FamilyFirebase,
			Outcome:         OutcomePossible,
			Confidence:      ConfidenceHigh,
			Endpoint:        cleanURL,
			Host:            match[1] + ".firebaseio.com",
			Protocol:        "https",
			DetectionMethod: "PASSIVE_ANALYSIS",
			Evidence:        fmt.Sprintf("Discovered Firebase RTDB URL in %s: %s", source, cleanURL),
			Metadata: map[string]any{
				"project": match[1],
			},
			SourceAsset:  source,
			DiscoveredAt: now,
		})
	}

	// 2. Firebase RTDB (.firebasedatabase.app)
	for _, match := range firebaseAppRegex.FindAllStringSubmatch(text, -1) {
		cleanURL := "https://" + match[1]
		results = append(results, DiscoveredService{
			Technology:      TechFirebaseRTDB,
			Family:          FamilyFirebase,
			Outcome:         OutcomePossible,
			Confidence:      ConfidenceHigh,
			Endpoint:        cleanURL,
			Host:            match[1],
			Protocol:        "https",
			DetectionMethod: "PASSIVE_ANALYSIS",
			Evidence:        fmt.Sprintf("Discovered Firebase RTDB app URL in %s: %s", source, cleanURL),
			SourceAsset:     source,
			DiscoveredAt:    now,
		})
	}

	// 3. Cloud Firestore via project ID and library reference
	if firestoreLibRegex.Match(content) {
		for _, match := range firestoreProjectRegex.FindAllStringSubmatch(text, -1) {
			projectID := match[1]
			cleanURL := fmt.Sprintf("https://firestore.googleapis.com/v1/projects/%s/databases/(default)/documents", projectID)
			results = append(results, DiscoveredService{
				Technology:      TechFirestore,
				Family:          FamilyFirebase,
				Outcome:         OutcomePossible,
				Confidence:      ConfidenceHigh,
				Endpoint:        cleanURL,
				Host:            "firestore.googleapis.com",
				Protocol:        "https",
				DetectionMethod: "PASSIVE_ANALYSIS",
				Evidence:        fmt.Sprintf("Discovered Cloud Firestore project (%s) with Firestore client in %s", projectID, source),
				Metadata: map[string]any{
					"project_id": projectID,
				},
				SourceAsset:  source,
				DiscoveredAt: now,
			})
		}
	}

	return results
}

// ProbeFirebaseRTDB executes safe HTTP verification against a Firebase RTDB instance without data enumeration.
func ProbeFirebaseRTDB(ctx context.Context, client *Client, baseURL string) DiscoveredService {
	cleanBase := strings.TrimRight(baseURL, "/")
	probeURL := cleanBase + "/.json"

	parsed, err := url.Parse(cleanBase)
	if err != nil {
		return DiscoveredService{
			Technology:   TechFirebaseRTDB,
			Family:       FamilyFirebase,
			Outcome:      OutcomeError,
			Endpoint:     baseURL,
			Limitations:  fmt.Sprintf("invalid URL: %v", err),
			DiscoveredAt: time.Now().UTC(),
		}
	}

	req, err := http.NewRequestWithContext(ctx, "HEAD", probeURL, nil)
	if err != nil {
		return DiscoveredService{
			Technology:   TechFirebaseRTDB,
			Family:       FamilyFirebase,
			Outcome:      OutcomeError,
			Endpoint:     baseURL,
			Limitations:  err.Error(),
			DiscoveredAt: time.Now().UTC(),
		}
	}

	resp, err := client.Do(ctx, req)
	if err != nil {
		// Fallback to GET without enumeration if transport restricts HEAD
		reqGET, errGET := http.NewRequestWithContext(ctx, "GET", probeURL, nil)
		if errGET != nil {
			return DiscoveredService{
				Technology:      TechFirebaseRTDB,
				Family:          FamilyFirebase,
				Outcome:         OutcomeInconclusive,
				Endpoint:        cleanBase,
				Host:            parsed.Hostname(),
				DetectionMethod: "HTTP_PROBE",
				Limitations:     fmt.Sprintf("connection error: %v", err),
				DiscoveredAt:    time.Now().UTC(),
			}
		}
		resp, err = client.Do(ctx, reqGET)
		if err != nil {
			return DiscoveredService{
				Technology:      TechFirebaseRTDB,
				Family:          FamilyFirebase,
				Outcome:         OutcomeInconclusive,
				Endpoint:        cleanBase,
				Host:            parsed.Hostname(),
				DetectionMethod: "HTTP_PROBE",
				Limitations:     fmt.Sprintf("connection error: %v", err),
				DiscoveredAt:    time.Now().UTC(),
			}
		}
	}

	bodyStr := string(resp.Body)

	// 1. Root responded 200 OK
	if resp.StatusCode == http.StatusOK {
		return DiscoveredService{
			Technology:      TechFirebaseRTDB,
			Family:          FamilyFirebase,
			Outcome:         OutcomeDetected,
			Confidence:      ConfidenceHigh,
			Endpoint:        cleanBase,
			Host:            parsed.Hostname(),
			Protocol:        parsed.Scheme,
			DetectionMethod: "HTTP_PROBE",
			AuthRequired:    false,
			PublicAccess:    false, // Non-enumerating probe; public data boundary verification deferred to Phase 2.2
			Evidence:        "Firebase Realtime Database root responded 200 OK to non-enumerating probe",
			Limitations:     "Root endpoint accessible without auth challenge; detailed key/path read boundaries deferred to Phase 2.2",
			InScope:         true,
			DiscoveredAt:    time.Now().UTC(),
		}
	}

	// 2. Protected Firebase RTDB (HTTP 401 or 403 Permission Denied)
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden || strings.Contains(bodyStr, "Permission denied") {
		return DiscoveredService{
			Technology:      TechFirebaseRTDB,
			Family:          FamilyFirebase,
			Outcome:         OutcomeDetected,
			Confidence:      ConfidenceHigh,
			Endpoint:        cleanBase,
			Host:            parsed.Hostname(),
			Protocol:        parsed.Scheme,
			DetectionMethod: "HTTP_PROBE",
			AuthRequired:    true,
			PublicAccess:    false,
			Evidence:        "Firebase Realtime Database confirmed: root endpoint requires authorization (HTTP 401/403)",
			Limitations:     "Root endpoint requires authorization; granular path rule coverage requires Phase 2.2 verification",
			InScope:         true,
			DiscoveredAt:    time.Now().UTC(),
		}
	}

	// 3. Database not found (HTTP 404)
	if resp.StatusCode == http.StatusNotFound && strings.Contains(bodyStr, "not found") {
		return DiscoveredService{
			Technology:      TechFirebaseRTDB,
			Family:          FamilyFirebase,
			Outcome:         OutcomeNotDetected,
			Endpoint:        cleanBase,
			Host:            parsed.Hostname(),
			DetectionMethod: "HTTP_PROBE",
			Evidence:        "Firebase database does not exist (HTTP 404 Not Found)",
			DiscoveredAt:    time.Now().UTC(),
		}
	}

	return DiscoveredService{
		Technology:      TechFirebaseRTDB,
		Family:          FamilyFirebase,
		Outcome:         OutcomePossible,
		Confidence:      ConfidenceMedium,
		Endpoint:        cleanBase,
		Host:            parsed.Hostname(),
		DetectionMethod: "HTTP_PROBE",
		Evidence:        fmt.Sprintf("Firebase host responded with HTTP status %d", resp.StatusCode),
		DiscoveredAt:    time.Now().UTC(),
	}
}

// ProbeFirestore executes safe HTTP verification against a candidate Cloud Firestore project without document enumeration.
func ProbeFirestore(ctx context.Context, client *Client, projectID string) DiscoveredService {
	// Query database resource metadata endpoint instead of enumerating documents collection
	endpointURL := fmt.Sprintf("https://firestore.googleapis.com/v1/projects/%s/databases/(default)", projectID)
	req, err := http.NewRequestWithContext(ctx, "GET", endpointURL, nil)
	if err != nil {
		return DiscoveredService{
			Technology:   TechFirestore,
			Family:       FamilyFirebase,
			Outcome:      OutcomeError,
			Endpoint:     endpointURL,
			Limitations:  err.Error(),
			DiscoveredAt: time.Now().UTC(),
		}
	}

	resp, err := client.Do(ctx, req)
	if err != nil {
		return DiscoveredService{
			Technology:      TechFirestore,
			Family:          FamilyFirebase,
			Outcome:         OutcomeInconclusive,
			Endpoint:        endpointURL,
			Host:            "firestore.googleapis.com",
			DetectionMethod: "HTTP_PROBE",
			Limitations:     fmt.Sprintf("connection error: %v", err),
			DiscoveredAt:    time.Now().UTC(),
		}
	}

	bodyStr := string(resp.Body)

	// 1. Cloud Firestore Database Metadata Accessible (HTTP 200)
	if resp.StatusCode == http.StatusOK {
		return DiscoveredService{
			Technology:      TechFirestore,
			Family:          FamilyFirebase,
			Outcome:         OutcomeDetected,
			Confidence:      ConfidenceHigh,
			Endpoint:        endpointURL,
			Host:            "firestore.googleapis.com",
			Protocol:        "https",
			DetectionMethod: "HTTP_PROBE",
			AuthRequired:    false,
			PublicAccess:    false, // Database metadata accessibility does not prove document collections are public
			Evidence:        fmt.Sprintf("Cloud Firestore project %q database metadata responded 200 OK", projectID),
			Metadata: map[string]any{
				"project_id": projectID,
			},
			Limitations:  "Database metadata accessible; document read boundary verification deferred to Phase 2.2",
			InScope:      true,
			DiscoveredAt: time.Now().UTC(),
		}
	}

	// 2. Authenticated/Protected Cloud Firestore (HTTP 403 PERMISSION_DENIED)
	if resp.StatusCode == http.StatusForbidden && (strings.Contains(bodyStr, "PERMISSION_DENIED") || strings.Contains(bodyStr, "Missing or insufficient permissions")) {
		return DiscoveredService{
			Technology:      TechFirestore,
			Family:          FamilyFirebase,
			Outcome:         OutcomeDetected,
			Confidence:      ConfidenceHigh,
			Endpoint:        endpointURL,
			Host:            "firestore.googleapis.com",
			Protocol:        "https",
			DetectionMethod: "HTTP_PROBE",
			AuthRequired:    true,
			PublicAccess:    false,
			Evidence:        fmt.Sprintf("Cloud Firestore project %q confirmed: PERMISSION_DENIED received on database metadata", projectID),
			Metadata: map[string]any{
				"project_id": projectID,
			},
			Limitations:  "Probed database metadata requires authorization; collection-level rule coverage deferred to Phase 2.2",
			InScope:      true,
			DiscoveredAt: time.Now().UTC(),
		}
	}

	// 3. Project or database does not exist
	if resp.StatusCode == http.StatusNotFound {
		return DiscoveredService{
			Technology:      TechFirestore,
			Family:          FamilyFirebase,
			Outcome:         OutcomeNotDetected,
			Endpoint:        endpointURL,
			Host:            "firestore.googleapis.com",
			DetectionMethod: "HTTP_PROBE",
			Evidence:        fmt.Sprintf("Cloud Firestore database not found for project %q (HTTP 404)", projectID),
			DiscoveredAt:    time.Now().UTC(),
		}
	}

	return DiscoveredService{
		Technology:      TechFirestore,
		Family:          FamilyFirebase,
		Outcome:         OutcomePossible,
		Confidence:      ConfidenceMedium,
		Endpoint:        endpointURL,
		Host:            "firestore.googleapis.com",
		DetectionMethod: "HTTP_PROBE",
		Evidence:        fmt.Sprintf("Cloud Firestore endpoint responded with HTTP status %d", resp.StatusCode),
		DiscoveredAt:    time.Now().UTC(),
	}
}
