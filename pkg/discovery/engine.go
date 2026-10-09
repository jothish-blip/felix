package discovery

import (
	"context"
	"crypto/x509"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"felix/pkg/crawler"
	"github.com/google/uuid"
)

// Config configures the Unified Attack-Surface Intelligence Engine.
type Config struct {
	Concurrency int
	Timeout     time.Duration
	MaxAssets   int
}

// Engine coordinates domain, application, API, form, authentication, cloud, and technology discovery.
type Engine struct {
	cfg      Config
	domainExt *DomainExtractor
	appExt   *ApplicationExtractor
	formExt  *FormExtractor
	paramExt *ParameterExtractor
	authExt  *AuthSurfaceExtractor
	techExt  *TechnologyExtractor
	jsExt    *JavaScriptExtractor
}

// NewEngine creates and initializes a unified discovery Engine instance.
func NewEngine(cfg Config) *Engine {
	if cfg.Timeout <= 0 {
		cfg.Timeout = 10 * time.Second
	}
	if cfg.Concurrency <= 0 {
		cfg.Concurrency = 5
	}

	return &Engine{
		cfg:      cfg,
		domainExt: NewDomainExtractor(cfg.Timeout),
		appExt:   NewApplicationExtractor(),
		formExt:  NewFormExtractor(),
		paramExt: NewParameterExtractor(),
		authExt:  NewAuthSurfaceExtractor(),
		techExt:  NewTechnologyExtractor(),
		jsExt:    NewJavaScriptExtractor(),
	}
}

// AnalyzeTarget executes the complete attack-surface discovery pipeline against a target.
func (e *Engine) AnalyzeTarget(
	ctx context.Context,
	asmID, execID, targetID, targetURL string,
	htmlContent string,
	respHeader http.Header,
	certs []*x509.Certificate,
	crawledAssets []crawler.Asset,
	isScopeAllowed func(string) bool,
) *Inventory {
	inv := NewInventory()

	parsedTarget, err := url.Parse(targetURL)
	if err != nil {
		return inv
	}

	// 1. Domain, Subdomain & Web Service Establishment
	domainID, hostID, serviceID := e.domainExt.ProcessTargetHost(ctx, inv, asmID, execID, targetID, targetURL, true)

	// 2. Passive TLS Certificate SAN Hostname Intelligence
	if len(certs) > 0 {
		sans := ExtractSANHostnames(certs)
		for _, san := range sans {
			if !strings.EqualFold(san, parsedTarget.Hostname()) {
				e.domainExt.IngestDiscoveredHost(ctx, inv, asmID, execID, targetID, san, targetURL, "TLS_SAN_CERTIFICATE", isScopeAllowed, domainID)
			}
		}
	}

	// 3. Collect all discovered paths and URLs from crawled assets and HTML links
	var discoveredPaths []string
	seenPaths := make(map[string]struct{})
	for _, a := range crawledAssets {
		if parsed, err := url.Parse(a.URL); err == nil && parsed.Path != "" {
			cleanP := parsed.Path
			if _, exists := seenPaths[cleanP]; !exists {
				seenPaths[cleanP] = struct{}{}
				discoveredPaths = append(discoveredPaths, cleanP)
			}
		}
	}
	if htmlContent != "" {
		linkHrefRegex := regexp.MustCompile(`(?i)<a[^>]+href=["']([^"'#\s]+)["']`)
		matches := linkHrefRegex.FindAllStringSubmatch(htmlContent, -1)
		for _, m := range matches {
			if len(m) > 1 {
				rawHref := m[1]
				if strings.HasPrefix(rawHref, "/") {
					cleanP := rawHref
					if idx := strings.IndexAny(cleanP, "?#"); idx != -1 {
						cleanP = cleanP[:idx]
					}
					if _, exists := seenPaths[cleanP]; !exists {
						seenPaths[cleanP] = struct{}{}
						discoveredPaths = append(discoveredPaths, cleanP)
					}
				}
			}
		}
	}

	// 4. Hostnames discovered in HTML content
	if htmlContent != "" {
		htmlHosts := ExtractHostnamesFromContent(htmlContent)
		for _, h := range htmlHosts {
			if !strings.EqualFold(h, parsedTarget.Hostname()) {
				e.domainExt.IngestDiscoveredHost(ctx, inv, asmID, execID, targetID, h, targetURL, "HTML_CONTENT", isScopeAllowed, domainID)
			}
		}
	}

	// 5. Application Discovery (Root & Sub-Applications)
	appIDs := e.appExt.DiscoverApplications(inv, asmID, execID, targetID, serviceID, targetURL, htmlContent, discoveredPaths)
	rootAppID := ""
	if len(appIDs) > 0 {
		rootAppID = appIDs[0]
	}

	// 6. Technology Intelligence (Headers, Cookies, HTML Markup)
	techs := e.techExt.ExtractTechnologies(respHeader, htmlContent)
	if len(techs) > 0 {
		e.techExt.IngestTechnologies(inv, asmID, execID, targetID, rootAppID, techs)
	}

	// 7. HTML Form Discovery & Input Parameters
	forms := e.formExt.ExtractForms(htmlContent, parsedTarget)
	if len(forms) > 0 {
		e.formExt.IngestForms(inv, asmID, execID, targetID, rootAppID, forms)

		// 8. Authentication Surface Discovery from Forms
		formAuthSurfaces := e.authExt.ExtractFromForms(forms)
		if len(formAuthSurfaces) > 0 {
			e.authExt.IngestAuthSurfaces(inv, asmID, execID, targetID, rootAppID, formAuthSurfaces)
		}
	}

	// 9. JavaScript Intelligence, API Endpoints, Parameters & Cloud Services
	var allEndpoints []string
	for _, asset := range crawledAssets {
		if asset.Type == crawler.AssetJavaScript || strings.HasSuffix(asset.URL, ".js") {
			_, epIDs := e.jsExt.IngestJavaScriptAsset(inv, asmID, execID, targetID, rootAppID, asset.URL, asset.Content, targetURL, e.paramExt)
			allEndpoints = append(allEndpoints, epIDs...)

			// Check for OAuth / OIDC configs in JS
			jsAuthSurfaces := e.authExt.ExtractFromJS(string(asset.Content), asset.URL)
			if len(jsAuthSurfaces) > 0 {
				e.authExt.IngestAuthSurfaces(inv, asmID, execID, targetID, rootAppID, jsAuthSurfaces)
			}
		} else {
			// Record other assets (Stylesheets, Manifests, Source Maps)
			otherAsset := Asset{
				ID:              uuid.New().String(),
				AssessmentID:    asmID,
				ExecutionID:     execID,
				TargetID:        targetID,
				Type:            AssetTypeAsset,
				CanonicalID:     asset.URL,
				ParentID:        rootAppID,
				DisplayName:     fmt.Sprintf("Asset: %s (%s)", asset.URL, asset.Type),
				SourceAsset:     targetURL,
				DiscoveryMethod: "HTML_OR_NETWORK_CRAWL",
				DiscoveryStatus: StatusObserved,
				Confidence:      ConfidenceHigh,
				InScope:         asset.InScope,
				Metadata: map[string]any{
					"url":          asset.URL,
					"type":         string(asset.Type),
					"size_bytes":   asset.Size,
					"content_type": asset.ContentType,
				},
				Evidence: map[string]any{
					"status_code": asset.StatusCode,
				},
				FirstSeen: time.Now().UTC(),
				LastSeen:  time.Now().UTC(),
			}
			inv.AddAsset(otherAsset)
		}
	}

	// 10. Check all discovered paths for authentication routes
	for _, p := range discoveredPaths {
		if authType, isAuth := ClassifyAuthRoute(p); isAuth {
			e.authExt.IngestAuthSurfaces(inv, asmID, execID, targetID, rootAppID, []DiscoveredAuthSurface{
				{
					SurfaceType: authType,
					Identifier:  p,
					Method:      "GET",
					Source:      "ROUTE_NAMING",
					Observed:    true,
					Evidence:    fmt.Sprintf("Discovered application path %s matches authentication taxonomy", p),
				},
			})
		}
	}

	// 11. Group API Endpoints under API Service if multiple API routes exist
	apiRoutesCount := 0
	for _, a := range inv.Assets {
		if a.Type == AssetTypeEndpoint && (strings.Contains(a.CanonicalID, "/api") || strings.Contains(a.CanonicalID, "/v1") || strings.Contains(a.CanonicalID, "/v2") || strings.Contains(a.CanonicalID, "/graphql")) {
			apiRoutesCount++
		}
	}

	if apiRoutesCount > 0 {
		apiServiceCanonical := fmt.Sprintf("%s://%s/api", parsedTarget.Scheme, parsedTarget.Host)
		apiServiceAsset := Asset{
			ID:              uuid.New().String(),
			AssessmentID:    asmID,
			ExecutionID:     execID,
			TargetID:        targetID,
			Type:            AssetTypeAPIService,
			CanonicalID:     apiServiceCanonical,
			ParentID:        rootAppID,
			DisplayName:     fmt.Sprintf("API Service: %s (%d endpoints)", parsedTarget.Host, apiRoutesCount),
			SourceAsset:     targetURL,
			DiscoveryMethod: "API_ROUTE_AGGREGATION",
			DiscoveryStatus: StatusInferred,
			Confidence:      ConfidenceHigh,
			InScope:         true,
			Metadata: map[string]any{
				"base_url":        apiServiceCanonical,
				"endpoints_count": apiRoutesCount,
			},
			Evidence: map[string]any{
				"routes_count": apiRoutesCount,
			},
			FirstSeen: time.Now().UTC(),
			LastSeen:  time.Now().UTC(),
		}
		apiServiceID := inv.AddAsset(apiServiceAsset)

		// Link Application USES_API APIService
		if rootAppID != "" {
			inv.AddRelation(Relation{
				ID:            uuid.New().String(),
				AssessmentID:  asmID,
				ExecutionID:   execID,
				SourceAssetID: rootAppID,
				TargetAssetID: apiServiceID,
				RelationType:  RelUsesAPI,
				Evidence:      fmt.Sprintf("Application references %d API routes under %s", apiRoutesCount, apiServiceCanonical),
				Confidence:    ConfidenceHigh,
			})
		}
	}

	_ = hostID
	return inv
}
