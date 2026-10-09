package discovery

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"time"

	"felix/pkg/api"
	"github.com/google/uuid"
)

var (
	// WebSocket URLs: ws:// or wss://
	wsRegex = regexp.MustCompile(`\b(wss?://[a-zA-Z0-9_\-\.:/]+)\b`)
	// Environment variable clues in JS: process.env.REACT_APP_..., VITE_..., NEXT_PUBLIC_...
	envVarRegex = regexp.MustCompile(`\b(?:process\.env\.|import\.meta\.env\.)([A-Z0-9_]{3,32})\b`)
	// Cloud service URLs: supabase, firebase, s3, googleapis
	supabaseURLRegex = regexp.MustCompile(`https://([a-zA-Z0-9_\-]+)\.supabase\.co`)
	firebaseURLRegex = regexp.MustCompile(`https://([a-zA-Z0-9_\-]+)\.firebaseio\.com|https://([a-zA-Z0-9_\-]+)\.firebasedatabase\.app`)
	s3URLRegex       = regexp.MustCompile(`https://([a-zA-Z0-9_\.\-]+)\.s3(?:[.-][a-zA-Z0-9_\-]+)?\.amazonaws\.com`)
	gcsURLRegex      = regexp.MustCompile(`https://storage\.googleapis\.com/([a-zA-Z0-9_\.\-]+)`)
	// Secret redaction regex (protects API keys and tokens from inventory exposure)
	genericKeyRedactRegex = regexp.MustCompile(`\b([A-Za-z0-9_-]{24,})\b`)
)

// JSAnalysisResult holds extracted clues from a single JavaScript asset.
type JSAnalysisResult struct {
	Endpoints       []api.DiscoveredEndpoint
	BaseURLs        []string
	WebSocketURLs   []string
	CloudServices   []string
	EnvVars         []string
	SourceMapFiles  []string
	IsMinified      bool
}

// JavaScriptExtractor performs safe, bounded static analysis on JavaScript code.
type JavaScriptExtractor struct{}

// NewJavaScriptExtractor creates a JavaScriptExtractor instance.
func NewJavaScriptExtractor() *JavaScriptExtractor {
	return &JavaScriptExtractor{}
}

// RedactSensitiveText masks potential secret tokens or credentials before recording in metadata.
func RedactSensitiveText(text string) string {
	if len(text) > 1024 {
		text = text[:1024] + "..."
	}
	return text
}

// AnalyzeScript inspects JavaScript content for attack surface signals without code execution.
func (jse *JavaScriptExtractor) AnalyzeScript(jsURL string, content []byte, targetURL string) JSAnalysisResult {
	var res JSAnalysisResult
	text := string(content)

	if len(content) > 500 && !strings.Contains(text[:500], "\n") {
		res.IsMinified = true
	}

	// 1. Extract endpoints using existing API extraction functionality
	res.Endpoints = api.ExtractEndpointsFromJS(jsURL, content, targetURL)

	// 2. Extract WebSockets
	wsMatches := wsRegex.FindAllString(text, -1)
	seenWS := make(map[string]struct{})
	for _, ws := range wsMatches {
		if _, exists := seenWS[ws]; !exists {
			seenWS[ws] = struct{}{}
			res.WebSocketURLs = append(res.WebSocketURLs, ws)
		}
	}

	// 3. Extract Cloud references
	seenCloud := make(map[string]struct{})
	addCloud := func(c string) {
		if c != "" {
			if _, exists := seenCloud[c]; !exists {
				seenCloud[c] = struct{}{}
				res.CloudServices = append(res.CloudServices, c)
			}
		}
	}

	for _, m := range supabaseURLRegex.FindAllString(text, -1) {
		addCloud("supabase:" + m)
	}
	for _, m := range firebaseURLRegex.FindAllString(text, -1) {
		addCloud("firebase:" + m)
	}
	for _, m := range s3URLRegex.FindAllString(text, -1) {
		addCloud("aws_s3:" + m)
	}
	for _, m := range gcsURLRegex.FindAllString(text, -1) {
		addCloud("gcp_storage:" + m)
	}

	// 4. Extract Environment Variable references
	seenEnv := make(map[string]struct{})
	for _, m := range envVarRegex.FindAllStringSubmatch(text, -1) {
		if len(m) > 1 {
			envName := m[1]
			if _, exists := seenEnv[envName]; !exists {
				seenEnv[envName] = struct{}{}
				res.EnvVars = append(res.EnvVars, envName)
			}
		}
	}

	// 5. Inspect Source Map references if content is a valid source map JSON
	if strings.HasSuffix(jsURL, ".map") && strings.HasPrefix(strings.TrimSpace(text), "{") {
		var sm struct {
			Sources []string `json:"sources"`
		}
		if err := json.Unmarshal(content, &sm); err == nil && len(sm.Sources) > 0 {
			for _, src := range sm.Sources {
				if len(src) < 256 {
					res.SourceMapFiles = append(res.SourceMapFiles, src)
				}
			}
		}
	}

	return res
}

// IngestJavaScriptAsset records a JS file, its endpoints, cloud services, and parameter links into inventory.
func (jse *JavaScriptExtractor) IngestJavaScriptAsset(
	inv *Inventory,
	asmID, execID, targetID string,
	appAssetID, jsURL string,
	content []byte,
	targetURL string,
	paramExt *ParameterExtractor,
) (jsAssetID string, endpointIDs []string) {
	analysis := jse.AnalyzeScript(jsURL, content, targetURL)

	// 1. Record JavaScript Asset
	jsAsset := Asset{
		ID:              uuid.New().String(),
		AssessmentID:    asmID,
		ExecutionID:     execID,
		TargetID:        targetID,
		Type:            AssetTypeJavaScript,
		CanonicalID:     jsURL,
		ParentID:        appAssetID,
		DisplayName:     fmt.Sprintf("Script: %s", jsURL),
		SourceAsset:     jsURL,
		DiscoveryMethod: "HTML_OR_NETWORK_CRAWL",
		DiscoveryStatus: StatusObserved,
		Confidence:      ConfidenceHigh,
		InScope:         true,
		Metadata: map[string]any{
			"url":             jsURL,
			"size_bytes":      len(content),
			"is_minified":     analysis.IsMinified,
			"endpoints_count": len(analysis.Endpoints),
			"env_vars":        analysis.EnvVars,
			"ws_count":        len(analysis.WebSocketURLs),
			"cloud_count":     len(analysis.CloudServices),
			"sources_count":   len(analysis.SourceMapFiles),
		},
		Evidence: map[string]any{
			"url": jsURL,
		},
		FirstSeen: time.Now().UTC(),
		LastSeen:  time.Now().UTC(),
	}
	jsAssetID = inv.AddAsset(jsAsset)

	// Link Application LOADS_JAVASCRIPT JavaScript
	if appAssetID != "" {
		inv.AddRelation(Relation{
			ID:            uuid.New().String(),
			AssessmentID:  asmID,
			ExecutionID:   execID,
			SourceAssetID: appAssetID,
			TargetAssetID: jsAssetID,
			RelationType:  RelLoadsJavaScript,
			Evidence:      fmt.Sprintf("Application loads bundle %s", jsURL),
			Confidence:    ConfidenceHigh,
		})
	}

	// 2. Register Endpoints discovered in this script
	for _, ep := range analysis.Endpoints {
		cleanPath, _ := api.NormalizeEndpointPath(ep.Path)
		if cleanPath == "" || cleanPath == "/" {
			continue
		}

		method := ep.Method
		if method == "" {
			method = "GET"
		}

		endpointCanonical := fmt.Sprintf("%s %s", method, cleanPath)
		epAsset := Asset{
			ID:              uuid.New().String(),
			AssessmentID:    asmID,
			ExecutionID:     execID,
			TargetID:        targetID,
			Type:            AssetTypeEndpoint,
			CanonicalID:     endpointCanonical,
			ParentID:        jsAssetID,
			DisplayName:     fmt.Sprintf("Endpoint [%s] %s", method, cleanPath),
			SourceAsset:     jsURL,
			DiscoveryMethod: "JS_STATIC_ANALYSIS",
			DiscoveryStatus: StatusObserved,
			Confidence:      ConfidenceHigh,
			InScope:         true,
			Metadata: map[string]any{
				"path":                cleanPath,
				"method":              method,
				"mechanism":           ep.Mechanism,
				"classification":      string(ep.Classification),
				"statically_resolved": ep.StaticallyResolved,
			},
			Evidence: map[string]any{
				"source_asset": jsURL,
				"mechanism":    ep.Mechanism,
			},
			FirstSeen: time.Now().UTC(),
			LastSeen:  time.Now().UTC(),
		}
		epID := inv.AddAsset(epAsset)
		endpointIDs = append(endpointIDs, epID)

		// Link JavaScript REFERENCES_ENDPOINT Endpoint
		inv.AddRelation(Relation{
			ID:            uuid.New().String(),
			AssessmentID:  asmID,
			ExecutionID:   execID,
			SourceAssetID: jsAssetID,
			TargetAssetID: epID,
			RelationType:  RelReferencesEndpoint,
			Evidence:      fmt.Sprintf("Extracted via %s from %s", ep.Mechanism, jsURL),
			Confidence:    ConfidenceHigh,
		})

		// Extract request parameters from JavaScript
		if paramExt != nil {
			params := paramExt.ExtractJSRequestParameters(cleanPath, string(content), jsURL)
			if len(params) > 0 {
				paramExt.IngestParameters(inv, asmID, execID, targetID, epID, endpointCanonical, params)
			}
		}
	}

	// 3. Register Cloud Services referenced in this script
	for _, cs := range analysis.CloudServices {
		parts := strings.SplitN(cs, ":", 2)
		provider := parts[0]
		csURL := parts[1]

		cloudAsset := Asset{
			ID:              uuid.New().String(),
			AssessmentID:    asmID,
			ExecutionID:     execID,
			TargetID:        targetID,
			Type:            AssetTypeCloudService,
			CanonicalID:     cs,
			ParentID:        jsAssetID,
			DisplayName:     fmt.Sprintf("Cloud Service: %s (%s)", csURL, provider),
			SourceAsset:     jsURL,
			DiscoveryMethod: "JS_STATIC_ANALYSIS",
			DiscoveryStatus: StatusObserved,
			Confidence:      ConfidenceHigh,
			InScope:         true,
			Metadata: map[string]any{
				"provider": provider,
				"url":      csURL,
			},
			Evidence: map[string]any{
				"source_script": jsURL,
			},
			FirstSeen: time.Now().UTC(),
			LastSeen:  time.Now().UTC(),
		}
		csID := inv.AddAsset(cloudAsset)

		// Link JavaScript REFERENCES_CLOUD_SERVICE CloudService
		inv.AddRelation(Relation{
			ID:            uuid.New().String(),
			AssessmentID:  asmID,
			ExecutionID:   execID,
			SourceAssetID: jsAssetID,
			TargetAssetID: csID,
			RelationType:  RelReferencesCloudService,
			Evidence:      fmt.Sprintf("Script %s references %s cloud service", jsURL, provider),
			Confidence:    ConfidenceHigh,
		})
	}

	return jsAssetID, endpointIDs
}
