package discovery

import (
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"
)

var (
	// Regex clues for single-page application framework roots
	reactRootRegex    = regexp.MustCompile(`(?i)<(?:div|main)[^>]+id=["'](?:root|app|__next)["']`)
	nextDataRegex     = regexp.MustCompile(`(?i)<script[^>]+id=["']__NEXT_DATA__["']`)
	nuxtDataRegex     = regexp.MustCompile(`(?i)<script[^>]+id=["']__NUXT__["']`)
	angularRootRegex  = regexp.MustCompile(`(?i)<app-root|<[^>]+ng-version`)
	vueRootRegex      = regexp.MustCompile(`(?i)data-v-[a-zA-Z0-9]+`)
	spaRouteRegex     = regexp.MustCompile(`(?:path|to)=["'](/[a-zA-Z0-9_\-\./:]*)["']`)
)

// AppClue records empirical signals pointing to a distinct web application.
type AppClue struct {
	PathPrefix  string
	Name        string
	Framework   string
	IsSPA       bool
	Confidence  Confidence
	Evidence    string
}

// ApplicationExtractor analyzes HTML, scripts, and endpoints to identify distinct web applications.
type ApplicationExtractor struct{}

// NewApplicationExtractor creates an ApplicationExtractor instance.
func NewApplicationExtractor() *ApplicationExtractor {
	return &ApplicationExtractor{}
}

// DiscoverApplications detects root and sub-applications from page content and crawled paths.
func (ae *ApplicationExtractor) DiscoverApplications(
	inv *Inventory,
	asmID, execID, targetID string,
	serviceAssetID, rawTargetURL string,
	htmlContent string,
	discoveredPaths []string,
) []string {
	var appIDs []string

	parsed, err := url.Parse(rawTargetURL)
	if err != nil || parsed.Host == "" {
		return appIDs
	}

	host := strings.ToLower(parsed.Hostname())
	scheme := strings.ToLower(parsed.Scheme)
	port := parsed.Port()
	if port == "" {
		if scheme == "https" {
			port = "443"
		} else {
			port = "80"
		}
	}

	origin := fmt.Sprintf("%s://%s:%s", scheme, host, port)

	// 1. Identify primary/root application
	framework := "Standard Web"
	isSPA := false
	evidence := "Primary web target entry point"

	if nextDataRegex.MatchString(htmlContent) {
		framework = "Next.js"
		isSPA = true
		evidence = "Found Next.js __NEXT_DATA__ SSR/SPA bootstrap container"
	} else if nuxtDataRegex.MatchString(htmlContent) {
		framework = "Nuxt.js"
		isSPA = true
		evidence = "Found Nuxt.js __NUXT__ bootstrap container"
	} else if reactRootRegex.MatchString(htmlContent) {
		framework = "React"
		isSPA = true
		evidence = "Found React root container <div id='root|app'>"
	} else if angularRootRegex.MatchString(htmlContent) {
		framework = "Angular"
		isSPA = true
		evidence = "Found Angular <app-root> or ng-version attribute"
	} else if vueRootRegex.MatchString(htmlContent) {
		framework = "Vue.js"
		isSPA = true
		evidence = "Found Vue.js scoped component attributes (data-v-*)"
	}

	rootCanonical := origin + "/"
	rootApp := Asset{
		ID:              uuid.New().String(),
		AssessmentID:    asmID,
		ExecutionID:     execID,
		TargetID:        targetID,
		Type:            AssetTypeApplication,
		CanonicalID:     rootCanonical,
		ParentID:        serviceAssetID,
		DisplayName:     fmt.Sprintf("%s (%s)", host, framework),
		DiscoveryMethod: "HTML_ANALYSIS",
		DiscoveryStatus: StatusObserved,
		Confidence:      ConfidenceHigh,
		InScope:         true,
		Metadata: map[string]any{
			"origin":      origin,
			"path_prefix": "/",
			"framework":   framework,
			"is_spa":      isSPA,
		},
		Evidence: map[string]any{
			"detection_clue": evidence,
			"target_url":     rawTargetURL,
		},
		FirstSeen: time.Now().UTC(),
		LastSeen:  time.Now().UTC(),
	}
	rootAppID := inv.AddAsset(rootApp)
	appIDs = append(appIDs, rootAppID)

	// Link WebService -> Root Application
	if serviceAssetID != "" {
		inv.AddRelation(Relation{
			ID:            uuid.New().String(),
			AssessmentID:  asmID,
			ExecutionID:   execID,
			SourceAssetID: serviceAssetID,
			TargetAssetID: rootAppID,
			RelationType:  RelExposesApplication,
			Evidence:      fmt.Sprintf("%s hosts primary application at %s", serviceAssetID, rootCanonical),
			Confidence:    ConfidenceHigh,
		})
	}

	// 2. Discover distinct sub-applications by inspecting common path prefixes with dedicated entry points
	// We avoid inventing boundaries on arbitrary routes; we look for distinct realms (admin, api, portal, auth, app)
	distinctPrefixes := map[string]string{
		"/admin":   "Admin Portal",
		"/portal":  "Customer Portal",
		"/app":     "Core Web App",
		"/api":     "API Gateway",
		"/console": "Management Console",
	}

	seenPrefixes := make(map[string]struct{})
	for _, p := range discoveredPaths {
		cleanP := strings.ToLower(p)
		for prefix, appName := range distinctPrefixes {
			if strings.HasPrefix(cleanP, prefix) && (len(cleanP) == len(prefix) || cleanP[len(prefix)] == '/') {
				if _, exists := seenPrefixes[prefix]; !exists {
					seenPrefixes[prefix] = struct{}{}

					subCanonical := origin + prefix
					subApp := Asset{
						ID:              uuid.New().String(),
						AssessmentID:    asmID,
						ExecutionID:     execID,
						TargetID:        targetID,
						Type:            AssetTypeApplication,
						CanonicalID:     subCanonical,
						ParentID:        serviceAssetID,
						DisplayName:     fmt.Sprintf("%s - %s", host, appName),
						DiscoveryMethod: "ROUTE_ANALYSIS",
						DiscoveryStatus: StatusInferred,
						Confidence:      ConfidenceMedium,
						InScope:         true,
						Metadata: map[string]any{
							"origin":      origin,
							"path_prefix": prefix,
							"realm":       appName,
						},
						Evidence: map[string]any{
							"trigger_path": p,
							"matched":      prefix,
						},
						FirstSeen: time.Now().UTC(),
						LastSeen:  time.Now().UTC(),
					}
					subID := inv.AddAsset(subApp)
					appIDs = append(appIDs, subID)

					if serviceAssetID != "" {
						inv.AddRelation(Relation{
							ID:            uuid.New().String(),
							AssessmentID:  asmID,
							ExecutionID:   execID,
							SourceAssetID: serviceAssetID,
							TargetAssetID: subID,
							RelationType:  RelExposesApplication,
							Evidence:      fmt.Sprintf("Distinct route prefix %s exposed on %s", prefix, origin),
							Confidence:    ConfidenceMedium,
						})
					}
				}
			}
		}
	}

	return appIDs
}
