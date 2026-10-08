package api

import (
	"encoding/json"
	"net/url"
	"regexp"
	"strings"
)

// Regex matchers for SPA route declarations and config keys
var (
	// Configuration variables: NEXT_PUBLIC_API_URL = "...", VITE_API_URL = "...", API_URL = "...", etc.
	spaConfigKeyRegex = regexp.MustCompile(`(?i)\b(?:NEXT_PUBLIC_|VITE_|REACT_APP_)?(?:API_URL|BASE_URL|API_BASE|BACKEND_URL|SERVER_URL)\s*[:=]\s*["']([^"'\s]+)["']`)

	// SPA route declarations: path: "/users", path: '/admin', { path: "/dashboard" }
	spaRoutePathRegex = regexp.MustCompile(`(?i)\bpath\s*:\s*["'](/[^"'\s]+)["']`)

	// Next.js page / build manifest references: "/_next/data/..." or "/_next/static/..."
	nextDataRouteRegex = regexp.MustCompile(`["'](/_next/data/[^"'\s]+\.json)["']`)
)

// RawSourceMap minimal unmarshaling structure to extract original sources.
type RawSourceMap struct {
	Version        int      `json:"version"`
	Sources        []string `json:"sources"`
	SourcesContent []string `json:"sourcesContent"`
}

// DiscoverSPARoutes extracts framework routes, configuration URLs, and router declarations from JS assets.
func DiscoverSPARoutes(sourceAssetURL string, content []byte, targetURL string) []DiscoveredEndpoint {
	var endpoints []DiscoveredEndpoint
	if len(content) == 0 {
		return endpoints
	}

	targetHost := ""
	if parsed, err := url.Parse(targetURL); err == nil {
		targetHost = strings.ToLower(parsed.Hostname())
	}

	text := string(content)
	seen := make(map[string]struct{})

	addRoute := func(rawPath string, mechanism string, offset int) {
		rawPath = strings.TrimSpace(rawPath)
		if rawPath == "" {
			return
		}

		// Handle absolute URLs matching targetHost
		if strings.HasPrefix(rawPath, "http://") || strings.HasPrefix(rawPath, "https://") {
			parsedURL, err := url.Parse(rawPath)
			if err != nil {
				return
			}
			if targetHost != "" && !strings.EqualFold(parsedURL.Hostname(), targetHost) {
				return
			}
			rawPath = parsedURL.Path
		}

		if !strings.HasPrefix(rawPath, "/") {
			return
		}

		normPath, staticallyResolved := NormalizeEndpointPath(rawPath)
		if normPath == "" || normPath == "/" {
			return
		}

		if _, exists := seen[normPath]; exists {
			return
		}
		seen[normPath] = struct{}{}

		endpoints = append(endpoints, DiscoveredEndpoint{
			Path:               normPath,
			RawPath:            rawPath,
			Method:             "UNKNOWN",
			SourceAsset:        sourceAssetURL,
			LineNumber:         computeLineNumber(content, offset),
			Mechanism:          mechanism,
			StaticallyResolved: staticallyResolved,
			Classification:     ClassifyEndpoint(normPath),
			AuthState:          AuthStateUnknown,
		})
	}

	// 1. SPA Config declarations (NEXT_PUBLIC_API_URL, VITE_API_URL, etc.)
	for _, match := range spaConfigKeyRegex.FindAllStringSubmatchIndex(text, -1) {
		val := text[match[2]:match[3]]
		addRoute(val, "spa_config", match[0])
	}

	// 2. SPA Route path declarations (React Router / Vue Router / Angular)
	for _, match := range spaRoutePathRegex.FindAllStringSubmatchIndex(text, -1) {
		val := text[match[2]:match[3]]
		addRoute(val, "spa_router", match[0])
	}

	// 3. Next.js data routes
	for _, match := range nextDataRouteRegex.FindAllStringSubmatchIndex(text, -1) {
		val := text[match[2]:match[3]]
		addRoute(val, "nextjs_data", match[0])
	}

	return endpoints
}

// ExtractEndpointsFromSourceMap unmarshals recovered source files in a source map and extracts endpoints.
func ExtractEndpointsFromSourceMap(mapAssetURL string, mapContent []byte, targetURL string) []DiscoveredEndpoint {
	var endpoints []DiscoveredEndpoint
	if len(mapContent) == 0 {
		return endpoints
	}

	var sm RawSourceMap
	if err := json.Unmarshal(mapContent, &sm); err != nil {
		return endpoints
	}

	seen := make(map[string]struct{})

	for i, srcContent := range sm.SourcesContent {
		if srcContent == "" {
			continue
		}
		sourceName := mapAssetURL
		if i < len(sm.Sources) && sm.Sources[i] != "" {
			sourceName = sm.Sources[i]
		}

		rawBytes := []byte(srcContent)
		extracted := ExtractEndpointsFromJS(sourceName, rawBytes, targetURL)
		for _, ep := range extracted {
			ep.Mechanism = "source_map"
			if _, exists := seen[ep.Path]; !exists {
				seen[ep.Path] = struct{}{}
				endpoints = append(endpoints, ep)
			}
		}
	}

	return endpoints
}
