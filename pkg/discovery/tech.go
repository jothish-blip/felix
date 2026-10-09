package discovery

import (
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"
)

// TechCategory classifies the functional tier of a discovered technology.
type TechCategory string

const (
	TechCategoryWebServer      TechCategory = "WEB_SERVER"
	TechCategoryBackendRuntime TechCategory = "BACKEND_RUNTIME"
	TechCategoryFramework      TechCategory = "FRAMEWORK"
	TechCategoryFrontendUI     TechCategory = "FRONTEND_UI"
	TechCategoryCMS            TechCategory = "CMS"
	TechCategoryCDN            TechCategory = "CDN_PROXY"
	TechCategoryLanguage       TechCategory = "LANGUAGE"
)

// DiscoveredTechnology captures a recognized framework, runtime, server, or library.
type DiscoveredTechnology struct {
	Name            string       `json:"name"`
	Category        TechCategory `json:"category"`
	Version         string       `json:"version,omitempty"`
	VersionObserved bool         `json:"version_observed"`
	Confidence      Confidence   `json:"confidence"`
	Source          string       `json:"source"` // HTTP_HEADER, HTML_META, SCRIPT_PATH, COOKIE, DOM_MARKUP
	Evidence        string       `json:"evidence"`
}

// TechSignature defines a pattern check against headers, HTML, or cookies.
type TechSignature struct {
	Name       string
	Category   TechCategory
	HeaderKey  string
	HeaderRx   *regexp.Regexp
	HTMLRx     *regexp.Regexp
	CookieName string
	VersionRx  *regexp.Regexp
}

var techSignatures = []TechSignature{
	// Next.js
	{
		Name:     "Next.js",
		Category: TechCategoryFramework,
		HTMLRx:   regexp.MustCompile(`(?i)(?:__NEXT_DATA__|/_next/static)`),
	},
	// Nuxt.js
	{
		Name:     "Nuxt.js",
		Category: TechCategoryFramework,
		HTMLRx:   regexp.MustCompile(`(?i)(?:__NUXT__|/_nuxt/)`),
	},
	// React
	{
		Name:     "React",
		Category: TechCategoryFrontendUI,
		HTMLRx:   regexp.MustCompile(`(?i)(?:data-reactroot|react\.production\.min\.js|react-dom)`),
	},
	// Angular
	{
		Name:      "Angular",
		Category:  TechCategoryFrontendUI,
		HTMLRx:    regexp.MustCompile(`(?i)(?:<app-root|ng-version=["']([^"']+)["'])`),
		VersionRx: regexp.MustCompile(`(?i)ng-version=["']([^"']+)["']`),
	},
	// Vue.js
	{
		Name:     "Vue.js",
		Category: TechCategoryFrontendUI,
		HTMLRx:   regexp.MustCompile(`(?i)(?:data-v-[a-zA-Z0-9]+|vue\.runtime|vue\.global)`),
	},
	// Express.js
	{
		Name:       "Express.js",
		Category:   TechCategoryBackendRuntime,
		HeaderKey:  "x-powered-by",
		HeaderRx:   regexp.MustCompile(`(?i)express`),
		CookieName: "connect.sid",
	},
	// Django
	{
		Name:       "Django",
		Category:   TechCategoryBackendRuntime,
		CookieName: "csrftoken",
	},
	// Laravel
	{
		Name:       "Laravel",
		Category:   TechCategoryBackendRuntime,
		CookieName: "laravel_session",
	},
	// Ruby on Rails
	{
		Name:       "Ruby on Rails",
		Category:   TechCategoryBackendRuntime,
		CookieName: "_rails_session",
	},
	// ASP.NET
	{
		Name:       "ASP.NET",
		Category:   TechCategoryBackendRuntime,
		HeaderKey:  "x-powered-by",
		HeaderRx:   regexp.MustCompile(`(?i)asp\.net`),
		CookieName: "asp.net_sessionid",
	},
	// PHP
	{
		Name:      "PHP",
		Category:  TechCategoryLanguage,
		HeaderKey: "x-powered-by",
		HeaderRx:  regexp.MustCompile(`(?i)php(?:/([0-9\.]+))?`),
		VersionRx: regexp.MustCompile(`(?i)php/([0-9\.]+)`),
	},
	// Nginx
	{
		Name:      "Nginx",
		Category:  TechCategoryWebServer,
		HeaderKey: "server",
		HeaderRx:  regexp.MustCompile(`(?i)nginx(?:/([0-9\.]+))?`),
		VersionRx: regexp.MustCompile(`(?i)nginx/([0-9\.]+)`),
	},
	// Apache HTTP Server
	{
		Name:      "Apache",
		Category:  TechCategoryWebServer,
		HeaderKey: "server",
		HeaderRx:  regexp.MustCompile(`(?i)apache(?:/([0-9\.]+))?`),
		VersionRx: regexp.MustCompile(`(?i)apache/([0-9\.]+)`),
	},
	// Cloudflare
	{
		Name:      "Cloudflare",
		Category:  TechCategoryCDN,
		HeaderKey: "server",
		HeaderRx:  regexp.MustCompile(`(?i)cloudflare`),
	},
	// WordPress
	{
		Name:      "WordPress",
		Category:  TechCategoryCMS,
		HTMLRx:    regexp.MustCompile(`(?i)(?:/wp-content/|/wp-includes/|<meta[^>]+generator=["']WordPress(?:\s+([0-9\.]+))?["'])`),
		VersionRx: regexp.MustCompile(`(?i)generator=["']WordPress\s+([0-9\.]+)["']`),
	},
	// Tailwind CSS
	{
		Name:     "Tailwind CSS",
		Category: TechCategoryFrontendUI,
		HTMLRx:   regexp.MustCompile(`(?i)(?:tailwind(?:\.min)?\.css)`),
	},
	// Bootstrap
	{
		Name:      "Bootstrap",
		Category:  TechCategoryFrontendUI,
		HTMLRx:    regexp.MustCompile(`(?i)(?:bootstrap(?:\.min)?\.css)`),
		VersionRx: regexp.MustCompile(`(?i)bootstrap/([0-9\.]+)/`),
	},
}

// TechnologyExtractor passively analyzes HTTP responses and HTML markup for technology fingerprints.
type TechnologyExtractor struct{}

// NewTechnologyExtractor creates a TechnologyExtractor instance.
func NewTechnologyExtractor() *TechnologyExtractor {
	return &TechnologyExtractor{}
}

// ExtractTechnologies inspects HTTP headers and HTML body content for observable technologies.
func (te *TechnologyExtractor) ExtractTechnologies(headers http.Header, htmlContent string) []DiscoveredTechnology {
	var results []DiscoveredTechnology
	seen := make(map[string]struct{})

	for _, sig := range techSignatures {
		var matched bool
		var evidence string
		var source string
		var version string

		// 1. Check HTTP Headers
		if sig.HeaderKey != "" && headers != nil {
			val := headers.Get(sig.HeaderKey)
			if val != "" && sig.HeaderRx != nil && sig.HeaderRx.MatchString(val) {
				matched = true
				source = "HTTP_HEADER"
				evidence = fmt.Sprintf("Header %s: %s", sig.HeaderKey, val)
				if sig.VersionRx != nil {
					if m := sig.VersionRx.FindStringSubmatch(val); len(m) > 1 {
						version = m[1]
					}
				}
			}
		}

		// 2. Check Cookies in Set-Cookie header
		if !matched && sig.CookieName != "" && headers != nil {
			for _, sc := range headers.Values("Set-Cookie") {
				if strings.Contains(strings.ToLower(sc), strings.ToLower(sig.CookieName)) {
					matched = true
					source = "COOKIE"
					evidence = fmt.Sprintf("Observed session/csrf cookie name %s", sig.CookieName)
					break
				}
			}
		}

		// 3. Check HTML markup
		if !matched && sig.HTMLRx != nil && htmlContent != "" {
			if sig.HTMLRx.MatchString(htmlContent) {
				matched = true
				source = "HTML_MARKUP"
				evidence = fmt.Sprintf("Recognized markup signature for %s in page body", sig.Name)
				if sig.VersionRx != nil {
					if m := sig.VersionRx.FindStringSubmatch(htmlContent); len(m) > 1 {
						version = m[1]
					}
				}
			}
		}

		if matched {
			if _, exists := seen[sig.Name]; !exists {
				seen[sig.Name] = struct{}{}
				results = append(results, DiscoveredTechnology{
					Name:            sig.Name,
					Category:        sig.Category,
					Version:         version,
					VersionObserved: version != "",
					Confidence:      ConfidenceHigh,
					Source:          source,
					Evidence:        evidence,
				})
			}
		}
	}

	return results
}

// IngestTechnologies registers discovered technologies as inventory assets and links them to the application.
func (te *TechnologyExtractor) IngestTechnologies(
	inv *Inventory,
	asmID, execID, targetID string,
	appAssetID string,
	techs []DiscoveredTechnology,
) []string {
	var techIDs []string

	for _, t := range techs {
		canonicalID := fmt.Sprintf("%s:%s", t.Category, strings.ToLower(t.Name))

		asset := Asset{
			ID:              uuid.New().String(),
			AssessmentID:    asmID,
			ExecutionID:     execID,
			TargetID:        targetID,
			Type:            AssetTypeTechnology,
			CanonicalID:     canonicalID,
			ParentID:        appAssetID,
			DisplayName:     fmt.Sprintf("%s (%s)", t.Name, t.Category),
			SourceAsset:     t.Source,
			DiscoveryMethod: t.Source,
			DiscoveryStatus: StatusObserved,
			Confidence:      t.Confidence,
			InScope:         true,
			Metadata: map[string]any{
				"name":             t.Name,
				"category":         string(t.Category),
				"version":          t.Version,
				"version_observed": t.VersionObserved,
			},
			Evidence: map[string]any{
				"evidence": t.Evidence,
				"source":   t.Source,
			},
			FirstSeen: time.Now().UTC(),
			LastSeen:  time.Now().UTC(),
		}
		tID := inv.AddAsset(asset)
		techIDs = append(techIDs, tID)

		// Link Application USES_TECHNOLOGY Technology
		if appAssetID != "" {
			inv.AddRelation(Relation{
				ID:            uuid.New().String(),
				AssessmentID:  asmID,
				ExecutionID:   execID,
				SourceAssetID: appAssetID,
				TargetAssetID: tID,
				RelationType:  RelUsesTechnology,
				Evidence:      t.Evidence,
				Confidence:    t.Confidence,
			})
		}
	}

	return techIDs
}
