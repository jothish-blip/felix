package api

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"

	"felix/pkg/crawler"
)

// AuditResult summarizes the operations and discoveries of the API intelligence engine.
type AuditResult struct {
	EndpointsScanned    int                  `json:"endpoints_scanned"`
	DiscoveredEndpoints []DiscoveredEndpoint `json:"discovered_endpoints,omitempty"`
	GraphQLCount        int                  `json:"graphql_count"`
	ActuatorCount       int                  `json:"actuator_count,omitempty"`
	DjangoCount         int                  `json:"django_count,omitempty"`
	FastAPICount        int                  `json:"fastapi_count,omitempty"`
	LaravelCount        int                  `json:"laravel_count,omitempty"`
	NodeCount           int                  `json:"node_count,omitempty"`
	GoCount             int                  `json:"go_count,omitempty"`
	SensitiveCount      int                  `json:"sensitive_count"`
	CORSCount           int                  `json:"cors_count"`
	HeaderCount         int                  `json:"header_count"`
	Findings            []APIFinding         `json:"findings"`
}

// DetectorOptions configures optional scope authorization and exclusion filters for API auditing.
type DetectorOptions struct {
	IsAllowed  func(string) bool
	IsExcluded func(string) bool
}

// Detector coordinates modern API discovery, SPA analysis, GraphQL auditing, CORS analysis, and posture verification.
type Detector struct {
	client     *Client
	isAllowed  func(string) bool
	isExcluded func(string) bool
	mu         sync.RWMutex
}

// NewDetector initializes a new Engine 4 API auditor instance with optional scope filters.
func NewDetector(client *Client, opts ...DetectorOptions) *Detector {
	if client == nil {
		client = NewClient()
	}
	d := &Detector{
		client: client,
	}
	if len(opts) > 0 {
		d.isAllowed = opts[0].IsAllowed
		d.isExcluded = opts[0].IsExcluded
	}
	return d
}

// ExtractAllEndpoints discovers, normalizes, deduplicates, and classifies endpoints across all crawled assets.
func (d *Detector) ExtractAllEndpoints(targetURL string, assets []crawler.Asset) []DiscoveredEndpoint {
	var all []DiscoveredEndpoint
	seenIndex := make(map[string]int) // path -> index in all

	parsedTarget, err := url.Parse(targetURL)
	if err != nil {
		return all
	}
	targetHost := strings.ToLower(parsedTarget.Hostname())

	processEndpoints := func(rawList []DiscoveredEndpoint) {
		for _, ep := range rawList {
			cleanPath, _ := NormalizeEndpointPath(ep.Path)
			if cleanPath == "" || cleanPath == "/" {
				continue
			}

			if idx, exists := seenIndex[cleanPath]; exists {
				// Merge: if existing method is UNKNOWN and new has specific method, upgrade method
				if all[idx].Method == "UNKNOWN" && ep.Method != "UNKNOWN" {
					all[idx].Method = ep.Method
				}
				// Upgrade classification if existing is UNKNOWN
				if all[idx].Classification == ClassUnknown && ep.Classification != ClassUnknown {
					all[idx].Classification = ep.Classification
				}
				continue
			}

			ep.Path = cleanPath
			if ep.Classification == "" || ep.Classification == ClassUnknown {
				ep.Classification = ClassifyEndpoint(cleanPath)
			}
			seenIndex[cleanPath] = len(all)
			all = append(all, ep)
		}
	}

	for _, a := range assets {
		if len(a.Content) == 0 {
			continue
		}

		// 1. Source maps
		if a.Type == crawler.AssetSourceMap || a.IsSourceMap || strings.HasSuffix(a.URL, ".map") {
			smEndpoints := ExtractEndpointsFromSourceMap(a.URL, a.Content, targetURL)
			processEndpoints(smEndpoints)
			continue
		}

		// 2. JavaScript assets and manifest files
		if a.Type == crawler.AssetJavaScript || strings.HasSuffix(a.URL, ".js") ||
			strings.HasSuffix(a.URL, ".mjs") || a.Type == crawler.AssetManifest {
			jsEndpoints := ExtractEndpointsFromJS(a.URL, a.Content, targetURL)
			processEndpoints(jsEndpoints)

			spaEndpoints := DiscoverSPARoutes(a.URL, a.Content, targetURL)
			processEndpoints(spaEndpoints)
		}

		// 3. Inspect if a.URL itself is an API route on target host
		if parsedA, err := url.Parse(a.URL); err == nil {
			if strings.EqualFold(parsedA.Hostname(), targetHost) {
				p := parsedA.Path
				if strings.HasPrefix(p, "/api") || strings.HasPrefix(p, "/graphql") || strings.HasPrefix(p, "/v1") {
					cleanPath, _ := NormalizeEndpointPath(p)
					if cleanPath != "" && cleanPath != "/" {
						if _, exists := seenIndex[cleanPath]; !exists {
							seenIndex[cleanPath] = len(all)
							all = append(all, DiscoveredEndpoint{
								Path:               cleanPath,
								RawPath:            p,
								Method:             "GET",
								SourceAsset:        a.URL,
								Mechanism:          "crawled_url",
								StaticallyResolved: true,
								Classification:     ClassifyEndpoint(cleanPath),
								AuthState:          AuthStateUnknown,
							})
						}
					}
				}
			}
		}
	}

	return all
}

// DiscoverCandidateEndpoints extracts relative API paths from assets within target origin scope.
func (d *Detector) DiscoverCandidateEndpoints(targetURL string, assets []crawler.Asset) []string {
	discovered := d.ExtractAllEndpoints(targetURL, assets)
	var paths []string
	for _, ep := range discovered {
		paths = append(paths, ep.Path)
		if len(paths) >= 40 {
			break // bound discovery list for downstream targeted auditors
		}
	}
	return paths
}

// Audit executes the comprehensive modern API audit pipeline against a target.
func (d *Detector) Audit(ctx context.Context, targetURL string, assets []crawler.Asset) AuditResult {
	d.mu.RLock()
	client := d.client
	d.mu.RUnlock()

	parsedTarget, err := url.Parse(targetURL)
	if err != nil {
		return AuditResult{}
	}
	originURL := strings.TrimRight(parsedTarget.Scheme+"://"+parsedTarget.Host, "/")
	targetPath := strings.TrimRight(parsedTarget.Path, "/")
	if targetPath == "/" {
		targetPath = ""
	}
	baseURL := originURL + targetPath

	resolveEndpointURL := func(path string) string {
		clean := path
		if !strings.HasPrefix(clean, "/") {
			clean = "/" + clean
		}
		if targetPath != "" {
			if strings.HasPrefix(clean, targetPath+"/") || clean == targetPath {
				return originURL + clean
			}
			return baseURL + clean
		}
		return originURL + clean
	}

	// 1. Discover, extract, and classify all endpoints across JS/SPA assets and source maps
	discoveredEndpoints := d.ExtractAllEndpoints(targetURL, assets)

	// Build candidate paths list, filtering out any endpoints excluded or outside authorized scope
	var candidatePaths []string
	var graphQLCandidates []string
	for _, ep := range discoveredEndpoints {
		fullURL := resolveEndpointURL(ep.Path)
		if d.isExcluded != nil && d.isExcluded(fullURL) {
			continue
		}
		if d.isAllowed != nil && !d.isAllowed(fullURL) {
			continue
		}
		// If ep.Path has targetPath prefix, strip it for relative concatenation with baseURL in sub-auditors
		cleanCandidate := ep.Path
		if targetPath != "" && strings.HasPrefix(cleanCandidate, targetPath+"/") {
			cleanCandidate = strings.TrimPrefix(cleanCandidate, targetPath)
		}
		candidatePaths = append(candidatePaths, cleanCandidate)
		if strings.Contains(strings.ToLower(ep.Path), "graphql") {
			graphQLCandidates = append(graphQLCandidates, cleanCandidate)
		}
	}

	var (
		allFindings []APIFinding
		seenFP      = make(map[string]struct{})
	)

	addFindings := func(findings []APIFinding) {
		for _, f := range findings {
			norm := NormalizeFrameworkFinding(f)
			if _, exists := seenFP[norm.Fingerprint]; !exists {
				seenFP[norm.Fingerprint] = struct{}{}
				allFindings = append(allFindings, norm)
			}
		}
	}

	// 2. Audit GraphQL Introspection
	graphQLFindings := AuditGraphQL(ctx, client, baseURL, graphQLCandidates)
	addFindings(graphQLFindings)

	// 3. Audit Spring Boot Actuator Endpoints (/actuator/health, /actuator/env, /actuator/mappings)
	actuatorFindings := AuditSpringActuator(ctx, client, baseURL, candidatePaths)
	addFindings(actuatorFindings)

	// 4. Audit Django Diagnostic Interfaces (technical 500, technical 404, DRF browsable API)
	djangoFindings := AuditDjangoDiagnostics(ctx, client, baseURL, candidatePaths)
	addFindings(djangoFindings)

	// 5. Audit FastAPI Documentation & OpenAPI Schema (/openapi.json, /docs, /redoc)
	fastapiFindings := AuditFastAPIDocs(ctx, client, baseURL, candidatePaths)
	addFindings(fastapiFindings)

	// 6. Audit Laravel Ignition & Telescope Diagnostic Interfaces
	laravelFindings := AuditLaravelDiagnostics(ctx, client, baseURL, candidatePaths)
	addFindings(laravelFindings)

	// 7. Audit Node.js Runtime & Framework Diagnostic Interfaces
	nodeFindings := AuditNodeDiagnostics(ctx, client, baseURL, candidatePaths)
	addFindings(nodeFindings)

	// 8. Audit Go Runtime & Framework Diagnostic Interfaces (pprof, expvar, panics)
	goFindings := AuditGoDiagnostics(ctx, client, baseURL, candidatePaths)
	addFindings(goFindings)

	// Track endpoints that already have documentation findings to prevent duplicate reporting
	docEndpoints := make(map[string]struct{})
	for _, f := range fastapiFindings {
		docEndpoints[f.Endpoint] = struct{}{}
	}

	// 6. Audit Sensitive Endpoints (git, env, openapi, metrics, health)
	sensitiveFindings := AuditSensitiveEndpoints(ctx, client, baseURL, candidatePaths)
	var filteredSensitive []APIFinding
	for _, f := range sensitiveFindings {
		if f.Category == CategoryAPIDocsExposure {
			if _, exists := docEndpoints[f.Endpoint]; exists {
				continue // Suppress duplicate generic docs finding when specialized FastAPI/OpenAPI audit already reported it
			}
		}
		filteredSensitive = append(filteredSensitive, f)
	}
	addFindings(filteredSensitive)

	// 4. Audit CORS on target base and initial API paths
	var corsFindings []APIFinding
	var corsTargets []string
	if (d.isExcluded == nil || !d.isExcluded(baseURL)) && (d.isAllowed == nil || d.isAllowed(baseURL)) {
		corsTargets = append(corsTargets, baseURL)
	}
	for _, p := range candidatePaths {
		fullURL := resolveEndpointURL(p)
		if d.isExcluded != nil && d.isExcluded(fullURL) {
			continue
		}
		if d.isAllowed != nil && !d.isAllowed(fullURL) {
			continue
		}
		corsTargets = append(corsTargets, fullURL)
		if len(corsTargets) >= 4 {
			break // bound CORS probes to 4 representative endpoints
		}
	}
	for _, ct := range corsTargets {
		cf := AuditCORS(ctx, client, ct)
		corsFindings = append(corsFindings, cf...)
	}
	addFindings(corsFindings)

	// 5. Audit Defensive Security Headers on target
	headerFindings := AuditSecurityHeaders(ctx, client, targetURL)
	addFindings(headerFindings)

	// 6. Safe Authentication-State Reasoning on candidate endpoints
	// Bounded to at most 25 endpoints to preserve fast, non-destructive execution
	probedCount := 0
	for i := range discoveredEndpoints {
		ep := &discoveredEndpoints[i]
		if probedCount >= 25 {
			break
		}

		// Only probe statically resolved endpoints without un-substituted placeholders
		if !ep.StaticallyResolved || strings.Contains(ep.Path, "{param}") {
			continue
		}

		probeURL := resolveEndpointURL(ep.Path)
		if d.isExcluded != nil && d.isExcluded(probeURL) {
			continue
		}
		if d.isAllowed != nil && !d.isAllowed(probeURL) {
			continue
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, probeURL, nil)
		if err != nil {
			continue
		}
		req.Header.Set("Accept", "*/*")

		resp, err := client.Do(ctx, req)
		if err != nil {
			if err == ErrRateLimited {
				break
			}
			continue
		}
		probedCount++

		obs := ReasonAuthState(resp.StatusCode, resp.Header, resp.Body)
		ep.AuthState = obs.State
		ep.HTTPStatus = resp.StatusCode

		// Do not flood findings register with 404s (non-existent routes)
		// Discovery != Vulnerability, and non-existent endpoints are not security findings.
		if obs.State == AuthStateNotFound {
			continue
		}

		// Suppress informational findings for generic public HTML pages / SPA shells
		// unless the endpoint is classified as sensitive (e.g., Admin, Payment, Auth).
		if obs.IsHTMLShell && ep.Classification != ClassAdmin && ep.Classification != ClassPayment && ep.Classification != ClassAuth {
			continue
		}

		// Record informational inventory finding for discovered endpoint
		// (Discovery and Classification are NEVER vulnerabilities by themselves)
		findingMethod := ep.Method
		if findingMethod == "UNKNOWN" {
			findingMethod = "GET"
		}

		invFinding := APIFinding{
			Category:       CategoryEndpointDiscovered,
			Endpoint:       probeURL,
			Method:         findingMethod,
			Description:    fmt.Sprintf("Discovered %s endpoint: %s (%s)", ep.Classification, ep.Path, obs.State),
			Evidence:       obs.Reason,
			Severity:       SeverityInfo,
			Confidence:     ConfidenceHigh,
			Fingerprint:    GenerateFingerprint(CategoryEndpointDiscovered, probeURL, findingMethod),
			Classification: ep.Classification,
			AuthState:      obs.State,
			SourceAsset:    ep.SourceAsset,
			LineNumber:     ep.LineNumber,
			Mechanism:      ep.Mechanism,
		}
		addFindings([]APIFinding{invFinding})
	}

	totalAudited := 1 + len(candidatePaths) + len(DefaultSensitivePaths) + len(DefaultActuatorCandidatePaths) + len(DefaultDjangoCandidatePaths) + len(DefaultFastAPICandidatePaths) + len(DefaultLaravelCandidatePaths) + len(DefaultNodeCandidatePaths) + len(DefaultGoCandidatePaths)

	return AuditResult{
		EndpointsScanned:    totalAudited,
		DiscoveredEndpoints: discoveredEndpoints,
		GraphQLCount:        len(graphQLFindings),
		ActuatorCount:       len(actuatorFindings),
		DjangoCount:         len(djangoFindings),
		FastAPICount:        len(fastapiFindings),
		LaravelCount:        len(laravelFindings),
		NodeCount:           len(nodeFindings),
		GoCount:             len(goFindings),
		SensitiveCount:      len(filteredSensitive),
		CORSCount:           len(corsFindings),
		HeaderCount:         len(headerFindings),
		Findings:            allFindings,
	}
}
