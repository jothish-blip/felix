package mobile

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/url"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"felix/pkg/correlation"
	"felix/pkg/discovery"
	"felix/pkg/report"
)

// EndpointSource identifies the origin of a discovered backend endpoint.
type EndpointSource string

const (
	EndpointSourceManifest       EndpointSource = "MANIFEST"
	EndpointSourceDEXString      EndpointSource = "DEX_STRING"
	EndpointSourceDEXCode        EndpointSource = "DEX_CODE"
	EndpointSourceRuntimeNetwork EndpointSource = "RUNTIME_NETWORK"
	EndpointSourceRuntimeAPI     EndpointSource = "RUNTIME_API"
	EndpointSourceBackendScan    EndpointSource = "BACKEND_SCAN"
)

// EndpointEvidenceStatus classifies evidentiary support for an endpoint.
type EndpointEvidenceStatus string

const (
	EndpointStatusObserved  EndpointEvidenceStatus = "OBSERVED"
	EndpointStatusStatic    EndpointEvidenceStatus = "STATICALLY_EXTRACTED"
	EndpointStatusCandidate EndpointEvidenceStatus = "CANDIDATE"
	EndpointStatusConfirmed EndpointEvidenceStatus = "CONFIRMED"
)

// MatchConfidence represents the strength of static-to-runtime endpoint correlation.
type MatchConfidence string

const (
	MatchConfidenceExact   MatchConfidence = "HIGH"
	MatchConfidencePartial MatchConfidence = "MEDIUM"
	MatchConfidenceLow     MatchConfidence = "LOW"
)

// BackendEndpoint represents a normalized backend communication surface discovered
// via static analysis, runtime instrumentation, or backend scanning.
type BackendEndpoint struct {
	RawURL        string                 `json:"raw_url"`
	NormalizedURL string                 `json:"normalized_url"`
	Scheme        string                 `json:"scheme"`           // "http", "https"
	Host          string                 `json:"host"`             // e.g. "10.0.2.2", "api.example.com"
	Port          int                    `json:"port"`             // e.g. 8888, 80, 443
	Path          string                 `json:"path"`             // e.g. "/login"
	Method        string                 `json:"method,omitempty"` // "GET", "POST", etc.
	Parameters    []string               `json:"parameters,omitempty"`
	Source        EndpointSource         `json:"source"`
	Status        EndpointEvidenceStatus `json:"status"`
	PackageName   string                 `json:"package_name,omitempty"`
	Provenance    string                 `json:"provenance,omitempty"` // code location, class#method, or hook event
	Timestamp     *time.Time             `json:"timestamp,omitempty"`
	IsCleartext   bool                   `json:"is_cleartext"`
	Metadata      map[string]string      `json:"metadata,omitempty"`
}

// CanonicalKey returns a deterministic identifier for the endpoint based on scheme, host, port, path, and method.
func (e *BackendEndpoint) CanonicalKey() string {
	if e == nil {
		return ""
	}
	m := strings.ToUpper(strings.TrimSpace(e.Method))
	if m == "" {
		m = "ANY"
	}
	cleanHost := strings.ToLower(strings.TrimSpace(e.Host))
	cleanPath := path.Clean("/" + strings.TrimPrefix(e.Path, "/"))
	if cleanPath == "." {
		cleanPath = "/"
	}
	return fmt.Sprintf("%s://%s:%d%s#%s", strings.ToLower(e.Scheme), cleanHost, e.Port, cleanPath, m)
}

// CorrelatedEndpoint associates a static endpoint with its runtime observation and confidence.
type CorrelatedEndpoint struct {
	CanonicalKey      string           `json:"canonical_key"`
	Host              string           `json:"host"`
	Port              int              `json:"port"`
	Scheme            string           `json:"scheme"`
	Path              string           `json:"path"`
	Method            string           `json:"method"`
	StaticEndpoint    *BackendEndpoint `json:"static_endpoint,omitempty"`
	RuntimeEndpoint   *BackendEndpoint `json:"runtime_endpoint,omitempty"`
	Confidence        MatchConfidence  `json:"confidence"`
	IsObservedRuntime bool             `json:"is_observed_runtime"`
	IsStaticExtracted bool             `json:"is_static_extracted"`
	PackageName       string           `json:"package_name"`
	CorrelatedAt      time.Time        `json:"correlated_at"`
}

// CorrelatedFinding synthesizes a multi-layer mobile-to-backend security relationship.
type CorrelatedFinding struct {
	ID                string                `json:"id"`
	RuleID            string                `json:"rule_id"`
	Title             string                `json:"title"`
	PackageName       string                `json:"package_name"`
	Host              string                `json:"host"`
	Endpoint          string                `json:"endpoint"`
	Method            string                `json:"method,omitempty"`
	Severity          string                `json:"severity"` // CRITICAL, HIGH, MEDIUM, LOW, INFO
	Confidence        string                `json:"confidence"`
	VerificationState FindingClassification `json:"verification_state"` // CONFIRMED, POTENTIAL, INFO
	OriginalFindingID string                `json:"original_finding_id,omitempty"`
	SourceEngine      string                `json:"source_engine,omitempty"`
	StaticEvidence    string                `json:"static_evidence,omitempty"`
	RuntimeEvidence   string                `json:"runtime_evidence,omitempty"`
	BackendEvidence   string                `json:"backend_evidence,omitempty"`
	Explanation       string                `json:"explanation"`
	Remediation       string                `json:"remediation"`
	Limitations       string                `json:"limitations,omitempty"`
	Timestamp         time.Time             `json:"timestamp"`
}

// ComputeCorrelatedFindingID deterministically hashes the finding components.
func ComputeCorrelatedFindingID(pkgName, ruleID, host, path, method string) string {
	raw := fmt.Sprintf("correlate:%s:%s:%s:%s:%s", pkgName, ruleID, host, path, strings.ToUpper(method))
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:16])
}

// ToFinding converts a CorrelatedFinding into a standardized FELIX report.Finding.
func (cf *CorrelatedFinding) ToFinding() *report.Finding {
	if cf == nil {
		return nil
	}
	verStatus := report.VerificationNotVerified
	if cf.VerificationState == ClassificationConfirmed {
		verStatus = report.VerificationVerified
	} else if cf.VerificationState == ClassificationPotential {
		verStatus = report.VerificationDetected
	}

	src := cf.SourceEngine
	if src == "" {
		src = "pkg/mobile/correlator.go"
	}

	return &report.Finding{
		ID:          cf.ID,
		RuleID:      cf.RuleID,
		Title:       cf.Title,
		Category:    "MOBILE-BACKEND-CORRELATION",
		Severity:    cf.Severity,
		Confidence:  cf.Confidence,
		Target:      cf.PackageName,
		Endpoint:    fmt.Sprintf("%s%s", cf.Host, cf.Endpoint),
		Method:      cf.Method,
		Description: cf.Explanation,
		Evidence:    fmt.Sprintf("Static: %s | Runtime: %s | Backend: %s", cf.StaticEvidence, cf.RuntimeEvidence, cf.BackendEvidence),
		EvidenceDetails: report.EvidenceDetails{
			Location:         fmt.Sprintf("%s%s", cf.Host, cf.Endpoint),
			Observation:      cf.RuntimeEvidence,
			ExpectedBehavior: "Secured transport and authorized backend communication",
			ObservedBehavior: cf.Explanation,
			DetectionMethod:  "MOBILE_TO_BACKEND_CORRELATION",
		},
		Verification: report.VerificationRecord{
			Status: verStatus,
		},
		Provenance: &report.EvidenceProvenance{
			EvidenceID:   cf.ID,
			EvidenceType: "mobile_backend_correlation",
			SourceEngine: src,
			RuleID:       cf.RuleID,
			FindingID:    cf.OriginalFindingID,
			CollectedAt:  cf.Timestamp,
		},
		Source:      src,
		Remediation: cf.Remediation,
	}
}

// MobileBackendGraphEdge represents a directed relationship between graph nodes.
type MobileBackendGraphEdge struct {
	ID               string                      `json:"id"`
	SourceID         string                      `json:"source_id"`
	TargetID         string                      `json:"target_id"`
	Type             correlation.RelationshipType `json:"type"`
	ValidationStatus correlation.ValidationStatus `json:"validation_status"`
	Confidence       string                      `json:"confidence"`
	Evidence         string                      `json:"evidence,omitempty"`
}

// MobileBackendGraphNode represents a node in the mobile-to-backend security graph.
type MobileBackendGraphNode struct {
	ID          string              `json:"id"`
	Type        discovery.AssetType `json:"type"` // AssetTypeApplication, AssetTypeHost, AssetTypeEndpoint, AssetTypeVulnerability
	DisplayName string              `json:"display_name"`
	PackageName string              `json:"package_name,omitempty"`
	Host        string              `json:"host,omitempty"`
	Endpoint    string              `json:"endpoint,omitempty"`
	Attributes  map[string]string   `json:"attributes,omitempty"`
}

// MobileBackendGraph structures the multi-layer relationships between mobile packages,
// endpoints, runtime observations, backend hosts, and security findings.
type MobileBackendGraph struct {
	mu        sync.RWMutex
	PackageID string                             `json:"package_id"`
	Nodes     map[string]*MobileBackendGraphNode `json:"nodes"`
	Edges     []*MobileBackendGraphEdge          `json:"edges"`
	Adjacency map[string][]string                `json:"adjacency"` // SourceID -> []TargetID
}

// NewMobileBackendGraph initializes an empty security graph for a package.
func NewMobileBackendGraph(pkgID string) *MobileBackendGraph {
	return &MobileBackendGraph{
		PackageID: pkgID,
		Nodes:     make(map[string]*MobileBackendGraphNode),
		Edges:     make([]*MobileBackendGraphEdge, 0),
		Adjacency: make(map[string][]string),
	}
}

// AddNode adds a node to the graph in a thread-safe manner.
func (g *MobileBackendGraph) AddNode(node *MobileBackendGraphNode) {
	if node == nil || node.ID == "" {
		return
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	g.Nodes[node.ID] = node
}

// AddEdge adds a directed edge between two existing nodes.
func (g *MobileBackendGraph) AddEdge(sourceID, targetID string, relType correlation.RelationshipType, status correlation.ValidationStatus, confidence, evidence string) {
	g.mu.Lock()
	defer g.mu.Unlock()

	if _, ok := g.Nodes[sourceID]; !ok {
		return
	}
	if _, ok := g.Nodes[targetID]; !ok {
		return
	}

	edgeID := fmt.Sprintf("%s->%s:%s", sourceID, targetID, relType)
	for _, e := range g.Edges {
		if e.ID == edgeID {
			return // duplicate edge
		}
	}

	edge := &MobileBackendGraphEdge{
		ID:               edgeID,
		SourceID:         sourceID,
		TargetID:         targetID,
		Type:             relType,
		ValidationStatus: status,
		Confidence:       confidence,
		Evidence:         evidence,
	}
	g.Edges = append(g.Edges, edge)
	g.Adjacency[sourceID] = append(g.Adjacency[sourceID], targetID)
}

// ToAttackGraph converts the mobile backend graph into a standard correlation.AttackGraph.
func (g *MobileBackendGraph) ToAttackGraph() *correlation.AttackGraph {
	g.mu.RLock()
	defer g.mu.RUnlock()

	var normalizedFindings []correlation.NormalizedFinding
	var relationships []correlation.Relationship

	for _, node := range g.Nodes {
		nf := correlation.NormalizedFinding{
			ID:                 node.ID,
			OriginalID:         node.ID,
			Title:              node.DisplayName,
			Target:             node.Host,
			Endpoint:           node.Endpoint,
			Host:               node.Host,
			Path:               node.Endpoint,
			Confidence:         "HIGH",
			Score:              50,
			AssetType:          node.Type,
			VerificationStatus: report.VerificationVerified,
		}
		if node.Type == discovery.AssetTypeApplication {
			nf.Category = "mobile-application"
			nf.NormalizedCategory = "mobile-application"
			nf.IsEntrypoint = true
		} else if node.Type == discovery.AssetTypeEndpoint {
			nf.Category = "api-endpoint"
			nf.NormalizedCategory = "api-endpoint"
		} else {
			nf.Category = "mobile-finding"
			nf.NormalizedCategory = "mobile-finding"
		}
		normalizedFindings = append(normalizedFindings, nf)
	}

	for _, edge := range g.Edges {
		rel := correlation.Relationship{
			ID:               edge.ID,
			SourceFindingID: edge.SourceID,
			TargetFindingID: edge.TargetID,
			SourceTitle:      g.Nodes[edge.SourceID].DisplayName,
			TargetTitle:      g.Nodes[edge.TargetID].DisplayName,
			Type:             edge.Type,
			ValidationStatus: edge.ValidationStatus,
			Confidence:       edge.Confidence,
			EvidenceReferences: []string{edge.Evidence},
			Explanation:      fmt.Sprintf("Mobile-to-backend relationship %s connecting %s to %s", edge.Type, edge.SourceID, edge.TargetID),
		}
		relationships = append(relationships, rel)
	}

	return correlation.NewAttackGraph(normalizedFindings, relationships)
}

// -----------------------------------------------------------------------------
// Endpoint Normalization Engine
// -----------------------------------------------------------------------------

var (
	// Schemas and third-party SDK prefixes to suppress during static DEX string extraction
	suppressedSchemaPrefixes = []string{
		"http://schemas.android.com",
		"http://www.w3.org",
		"http://xml.org",
		"http://schema.org",
		"http://java.sun.com",
		"http://apache.org",
		"https://plus.google.com",
		"http://plus.google.com",
		"https://googleads.",
		"http://googleads.",
		"https://www.google",
		"http://www.google",
		"https://google.",
		"http://google.",
		"https://goo.gl",
		"http://goo.gl",
		"https://twitter.com",
		"https://facebook.com",
		"https://www.facebook.com",
		"https://login.live.com",
		"https://login.yahoo.com",
		"https://linkedin.com",
		"https://www.linkedin.com",
		"https://paypal.com",
		"https://www.paypal.com",
	}

	// Known relative API route prefix patterns in decompiled bytecode
	apiRouteRegex = regexp.MustCompile(`^/(?:api|v[0-9]+|login|devlogin|auth|user|users|account|accounts|transfer|dotransfer|changepassword|password|logout|oauth|token|debug|admin|health|status|ping|config)(?:/|[?#].*)?$`)
)

// NormalizeEndpoint parses, sanitizes, and normalizes an input URL or route string.
func NormalizeEndpoint(rawInput string, defaultMethod string) (*BackendEndpoint, error) {
	trimmed := strings.TrimSpace(rawInput)
	if trimmed == "" {
		return nil, fmt.Errorf("empty endpoint input")
	}

	// Reject binary or unprintable garbage
	for i := 0; i < len(trimmed); i++ {
		if trimmed[i] < 32 && trimmed[i] != '\t' && trimmed[i] != '\n' && trimmed[i] != '\r' {
			return nil, fmt.Errorf("endpoint contains unprintable control character at index %d", i)
		}
	}

	cleanMethod := strings.ToUpper(strings.TrimSpace(defaultMethod))
	if cleanMethod == "" {
		cleanMethod = "GET"
	}

	var parsed *url.URL
	var err error
	var isRelative bool

	if strings.HasPrefix(trimmed, "http://") || strings.HasPrefix(trimmed, "https://") {
		parsed, err = url.Parse(trimmed)
		if err != nil {
			return nil, fmt.Errorf("invalid absolute URL %q: %w", trimmed, err)
		}
	} else if strings.HasPrefix(trimmed, "/") {
		// Relative route without host
		isRelative = true
		parsed, err = url.Parse(trimmed)
		if err != nil {
			return nil, fmt.Errorf("invalid relative route %q: %w", trimmed, err)
		}
	} else if strings.Contains(trimmed, "://") {
		// Other protocol scheme (ftp, content, file, etc.)
		parsed, err = url.Parse(trimmed)
		if err != nil {
			return nil, fmt.Errorf("invalid URI %q: %w", trimmed, err)
		}
	} else {
		// Check if it is a host:port pattern without scheme (e.g. "10.0.2.2:8888/login")
		if strings.Contains(trimmed, ".") || strings.Contains(trimmed, ":") {
			candidate := "http://" + trimmed
			if p, err2 := url.Parse(candidate); err2 == nil && p.Host != "" {
				parsed = p
			}
		}
		if parsed == nil {
			// Treat as relative route by adding leading slash
			isRelative = true
			parsed, err = url.Parse("/" + trimmed)
			if err != nil {
				return nil, fmt.Errorf("cannot parse endpoint %q: %w", trimmed, err)
			}
		}
	}

	scheme := strings.ToLower(parsed.Scheme)
	if scheme == "" && !isRelative {
		scheme = "http"
	}

	rawHost := parsed.Hostname()
	rawPort := parsed.Port()

	port := 0
	if rawPort != "" {
		if p, errAtoi := strconv.Atoi(rawPort); errAtoi == nil && p > 0 && p <= 65535 {
			port = p
		}
	}
	if port == 0 && scheme != "" {
		if scheme == "http" {
			port = 80
		} else if scheme == "https" {
			port = 443
		}
	}

	// Normalize Path: collapse repeated slashes, strip fragment
	cleanPath := path.Clean("/" + strings.TrimPrefix(parsed.Path, "/"))
	if cleanPath == "." || cleanPath == "" {
		cleanPath = "/"
	}

	// Extract sorted query parameter names, redacting values if present
	var paramNames []string
	if parsed.RawQuery != "" {
		queryValues := parsed.Query()
		for k := range queryValues {
			paramNames = append(paramNames, k)
		}
		sort.Strings(paramNames)
	}

	// Form normalized canonical URL
	var normURL string
	if isRelative {
		normURL = cleanPath
	} else {
		cleanHost := strings.ToLower(rawHost)
		hostWithPort := cleanHost
		if (scheme == "http" && port != 80 && port != 0) || (scheme == "https" && port != 443 && port != 0) {
			hostWithPort = fmt.Sprintf("%s:%d", cleanHost, port)
		}
		normURL = fmt.Sprintf("%s://%s%s", scheme, hostWithPort, cleanPath)
	}

	isCleartext := scheme == "http"

	return &BackendEndpoint{
		RawURL:        rawInput,
		NormalizedURL: normURL,
		Scheme:        scheme,
		Host:          strings.ToLower(rawHost),
		Port:          port,
		Path:          cleanPath,
		Method:        cleanMethod,
		Parameters:    paramNames,
		Source:        EndpointSourceBackendScan,
		Status:        EndpointStatusCandidate,
		IsCleartext:   isCleartext,
		Metadata:      make(map[string]string),
	}, nil
}

// -----------------------------------------------------------------------------
// Static Endpoint Extraction Engine
// -----------------------------------------------------------------------------

// ExtractStaticEndpoints harvests backend endpoints from the Android manifest and DEX bytecode.
func ExtractStaticEndpoints(manifest *AndroidMetadata, dexResult *DEXAnalysisResult) []BackendEndpoint {
	endpoints := make([]BackendEndpoint, 0)
	seenKeys := make(map[string]bool)

	pkgName := ""
	if manifest != nil {
		pkgName = manifest.PackageName
	}

	// 1. Harvest from AndroidManifest intent filters and schemes
	if manifest != nil {
		for _, comp := range manifest.Components {
			for _, filter := range comp.IntentFilters {
				for _, scheme := range filter.DataSchemes {
					lowerScheme := strings.ToLower(strings.TrimSpace(scheme))
					if lowerScheme == "http" || lowerScheme == "https" {
						ep := BackendEndpoint{
							RawURL:        fmt.Sprintf("%s://*", lowerScheme),
							NormalizedURL: fmt.Sprintf("%s://*", lowerScheme),
							Scheme:        lowerScheme,
							Path:          "/*",
							Method:        "ANY",
							Source:        EndpointSourceManifest,
							Status:        EndpointStatusStatic,
							PackageName:   pkgName,
							Provenance:    fmt.Sprintf("Manifest:%s (IntentFilter Scheme)", comp.Name),
							IsCleartext:   lowerScheme == "http",
							Metadata: map[string]string{
								"component": comp.Name,
							},
						}
						key := ep.CanonicalKey()
						if !seenKeys[key] {
							seenKeys[key] = true
							endpoints = append(endpoints, ep)
						}
					}
				}
			}
		}
	}

	// 2. Harvest from DEX bytecode string pool
	if dexResult != nil {
		for _, dexFile := range dexResult.DEXFiles {
			if dexFile == nil || dexFile.DEX == nil {
				continue
			}

			// First, locate any candidate base URLs in the DEX file
			var baseURLs []string
			for _, strItem := range dexFile.DEX.Strings {
				val := strings.TrimSpace(strItem.Value)
				if val == "" {
					continue
				}

				if strings.HasPrefix(val, "http://") || strings.HasPrefix(val, "https://") {
					// Check suppressed namespaces
					suppressed := false
					for _, sup := range suppressedSchemaPrefixes {
						if strings.HasPrefix(val, sup) {
							suppressed = true
							break
						}
					}
					if !suppressed {
						baseURLs = append(baseURLs, val)
						if ep, err := NormalizeEndpoint(val, "GET"); err == nil {
							ep.Source = EndpointSourceDEXString
							ep.Status = EndpointStatusStatic
							ep.PackageName = pkgName
							ep.Provenance = fmt.Sprintf("DEX:%s (StringPool index %d)", dexFile.EntryName, strItem.Index)
							key := ep.CanonicalKey()
							if !seenKeys[key] {
								seenKeys[key] = true
								endpoints = append(endpoints, *ep)
							}
						}
					}
				}
			}

			// Second, locate candidate API routes and associate with identified base URLs
			for _, strItem := range dexFile.DEX.Strings {
				val := strings.TrimSpace(strItem.Value)
				if val == "" {
					continue
				}

				if apiRouteRegex.MatchString(val) {
					// Route found (e.g. "/login", "/changepassword", "/devlogin")
					routeEp, err := NormalizeEndpoint(val, "GET")
					if err == nil {
						routeEp.Source = EndpointSourceDEXString
						routeEp.Status = EndpointStatusStatic
						routeEp.PackageName = pkgName
						routeEp.Provenance = fmt.Sprintf("DEX:%s (StringPool index %d)", dexFile.EntryName, strItem.Index)

						key := routeEp.CanonicalKey()
						if !seenKeys[key] {
							seenKeys[key] = true
							endpoints = append(endpoints, *routeEp)
						}

						// If base URLs exist (e.g. http://10.0.2.2:8888), synthesize composite endpoints
						for _, base := range baseURLs {
							combined := strings.TrimRight(base, "/") + routeEp.Path
							if compEp, err2 := NormalizeEndpoint(combined, "GET"); err2 == nil {
								compEp.Source = EndpointSourceDEXCode
								compEp.Status = EndpointStatusCandidate
								compEp.PackageName = pkgName
								compEp.Provenance = fmt.Sprintf("DEX:%s (Composite Base+Route)", dexFile.EntryName)
								compKey := compEp.CanonicalKey()
								if !seenKeys[compKey] {
									seenKeys[compKey] = true
									endpoints = append(endpoints, *compEp)
								}
							}
						}
					}
				}
			}
		}
	}

	return endpoints
}

// -----------------------------------------------------------------------------
// Runtime Endpoint Ingestion Engine
// -----------------------------------------------------------------------------

// IngestRuntimeEndpoints extracts and normalizes network communication events
// captured during Frida dynamic instrumentation sessions.
func IngestRuntimeEndpoints(events []RuntimeEvent) []BackendEndpoint {
	endpoints := make([]BackendEndpoint, 0)
	seenKeys := make(map[string]bool)

	for _, evt := range events {
		if evt.Type != EventTypeNetwork && evt.Type != EventTypeAPI {
			continue
		}
		if evt.Details == nil {
			continue
		}

		rawURL, _ := evt.Details["url"].(string)

		protocol, _ := evt.Details["protocol"].(string)
		if protocol == "" {
			protocol, _ = evt.Details["scheme"].(string)
		}
		if protocol == "" && rawURL != "" {
			if u, err := url.Parse(rawURL); err == nil && u.Scheme != "" {
				protocol = strings.ToLower(u.Scheme)
			}
		}
		if protocol == "" {
			protocol = "http"
		}

		host, _ := evt.Details["host"].(string)
		portNum := 0
		if pVal, ok := evt.Details["port"]; ok {
			switch p := pVal.(type) {
			case int:
				portNum = p
			case float64:
				portNum = int(p)
			case string:
				portNum, _ = strconv.Atoi(p)
			}
		}

		pathStr, _ := evt.Details["path"].(string)
		if pathStr == "" {
			pathStr = "/"
		}

		method, _ := evt.Details["method"].(string)
		if method == "" {
			method = "GET"
		}

		cleartext := false
		if ct, ok := evt.Details["cleartext"].(bool); ok {
			cleartext = ct
		} else if strings.ToLower(protocol) == "http" {
			cleartext = true
		}

		if rawURL == "" && host != "" {
			if (strings.ToLower(protocol) == "http" && portNum == 80) || (strings.ToLower(protocol) == "https" && portNum == 443) || portNum == 0 {
				rawURL = fmt.Sprintf("%s://%s%s", protocol, host, pathStr)
			} else {
				rawURL = fmt.Sprintf("%s://%s:%d%s", protocol, host, portNum, pathStr)
			}
		}

		ep, err := NormalizeEndpoint(rawURL, method)
		if err != nil {
			continue
		}

		ts := evt.Timestamp
		ep.Timestamp = &ts
		ep.Source = EndpointSourceRuntimeNetwork
		ep.Status = EndpointStatusObserved
		ep.PackageName = evt.PackageName
		ep.Provenance = fmt.Sprintf("FridaHook:%s#%s (Event %s)", evt.Class, evt.Method, evt.ID)
		ep.IsCleartext = cleartext

		key := ep.CanonicalKey()
		if !seenKeys[key] {
			seenKeys[key] = true
			endpoints = append(endpoints, *ep)
		}
	}

	return endpoints
}

// -----------------------------------------------------------------------------
// Static-to-Runtime Endpoint Correlator
// -----------------------------------------------------------------------------

// CorrelateEndpoints associates static endpoints with runtime observations.
func CorrelateEndpoints(pkgName string, staticEndpoints []BackendEndpoint, runtimeEndpoints []BackendEndpoint) []CorrelatedEndpoint {
	correlated := make([]CorrelatedEndpoint, 0)
	matchedRuntimeIndices := make(map[int]bool)
	now := time.Now().UTC()

	// 1. Process static endpoints and attempt matching with runtime observations
	for _, s := range staticEndpoints {
		var bestMatch *BackendEndpoint
		var bestConfidence MatchConfidence
		matchRuntimeIdx := -1

		sCleanPath := path.Clean("/" + strings.TrimPrefix(s.Path, "/"))

		for rIdx, r := range runtimeEndpoints {
			rCleanPath := path.Clean("/" + strings.TrimPrefix(r.Path, "/"))

			// Match 1: Exact Host + Path + Method
			if s.Host != "" && strings.EqualFold(s.Host, r.Host) && (s.Port == 0 || s.Port == r.Port) && sCleanPath == rCleanPath {
				if s.Method != "" && s.Method != "ANY" && strings.EqualFold(s.Method, r.Method) {
					bestMatch = &runtimeEndpoints[rIdx]
					bestConfidence = MatchConfidenceExact
					matchRuntimeIdx = rIdx
					break
				} else {
					// Path and host match, method unspecified in static
					bestMatch = &runtimeEndpoints[rIdx]
					bestConfidence = MatchConfidenceExact
					matchRuntimeIdx = rIdx
				}
			} else if s.Host == "" && sCleanPath == rCleanPath && sCleanPath != "/" {
				// Relative route match (e.g. "/login" static matches runtime endpoint with path "/login")
				bestMatch = &runtimeEndpoints[rIdx]
				if s.Method != "" && s.Method != "ANY" && strings.EqualFold(s.Method, r.Method) {
					bestConfidence = MatchConfidenceExact
				} else if s.Method == "" || s.Method == "ANY" {
					bestConfidence = MatchConfidenceExact
				} else {
					bestConfidence = MatchConfidencePartial
				}
				matchRuntimeIdx = rIdx
			} else if s.Host != "" && strings.EqualFold(s.Host, r.Host) && (sCleanPath == "/" || sCleanPath == "/*") {
				// Base URL match
				if bestMatch == nil {
					bestMatch = &runtimeEndpoints[rIdx]
					bestConfidence = MatchConfidencePartial
					matchRuntimeIdx = rIdx
				}
			}
		}

		sCopy := s
		ce := CorrelatedEndpoint{
			Host:              s.Host,
			Port:              s.Port,
			Scheme:            s.Scheme,
			Path:              s.Path,
			Method:            s.Method,
			StaticEndpoint:    &sCopy,
			IsStaticExtracted: true,
			PackageName:       pkgName,
			CorrelatedAt:      now,
		}

		if bestMatch != nil {
			rCopy := *bestMatch
			ce.RuntimeEndpoint = &rCopy
			ce.Confidence = bestConfidence
			ce.IsObservedRuntime = true
			if ce.Host == "" {
				ce.Host = bestMatch.Host
			}
			if ce.Port == 0 {
				ce.Port = bestMatch.Port
			}
			if ce.Scheme == "" {
				ce.Scheme = bestMatch.Scheme
			}
			if ce.Method == "" || ce.Method == "ANY" {
				ce.Method = bestMatch.Method
			}
			matchedRuntimeIndices[matchRuntimeIdx] = true
		} else {
			ce.Confidence = MatchConfidenceLow
			ce.IsObservedRuntime = false
		}

		ce.CanonicalKey = fmt.Sprintf("%s://%s:%d%s#%s", strings.ToLower(ce.Scheme), strings.ToLower(ce.Host), ce.Port, ce.Path, strings.ToUpper(ce.Method))
		correlated = append(correlated, ce)
	}

	// 2. Add runtime-only endpoints (not discovered through static extraction)
	for rIdx, r := range runtimeEndpoints {
		if matchedRuntimeIndices[rIdx] {
			continue
		}
		rCopy := r
		ce := CorrelatedEndpoint{
			CanonicalKey:      r.CanonicalKey(),
			Host:              r.Host,
			Port:              r.Port,
			Scheme:            r.Scheme,
			Path:              r.Path,
			Method:            r.Method,
			RuntimeEndpoint:   &rCopy,
			Confidence:        MatchConfidenceExact, // Confirmed observed at runtime
			IsObservedRuntime: true,
			IsStaticExtracted: false,
			PackageName:       pkgName,
			CorrelatedAt:      now,
		}
		correlated = append(correlated, ce)
	}

	// Deterministic sort: Confidence desc, Host asc, Path asc, Method asc
	sort.Slice(correlated, func(i, j int) bool {
		confWeight := map[MatchConfidence]int{MatchConfidenceExact: 3, MatchConfidencePartial: 2, MatchConfidenceLow: 1}
		if confWeight[correlated[i].Confidence] != confWeight[correlated[j].Confidence] {
			return confWeight[correlated[i].Confidence] > confWeight[correlated[j].Confidence]
		}
		if correlated[i].Host != correlated[j].Host {
			return correlated[i].Host < correlated[j].Host
		}
		if correlated[i].Path != correlated[j].Path {
			return correlated[i].Path < correlated[j].Path
		}
		return correlated[i].Method < correlated[j].Method
	})

	return correlated
}

// -----------------------------------------------------------------------------
// Backend Security Finding Correlator
// -----------------------------------------------------------------------------

// CorrelateWithBackendFindings connects mobile endpoint observations with backend security intelligence.
func CorrelateWithBackendFindings(
	pkgName string,
	endpoints []CorrelatedEndpoint,
	backendFindings []correlation.NormalizedFinding,
	staticFindings []MobileFinding,
) []CorrelatedFinding {
	findings := make([]CorrelatedFinding, 0)
	seenFindingIDs := make(map[string]bool)
	now := time.Now().UTC()

	// 1. Cleartext Communication Correlation
	for _, ep := range endpoints {
		isCleartext := ep.Scheme == "http" || (ep.RuntimeEndpoint != nil && ep.RuntimeEndpoint.IsCleartext) || (ep.StaticEndpoint != nil && ep.StaticEndpoint.IsCleartext)
		if isCleartext && ep.Host != "" && ep.Host != "*" {
			fID := ComputeCorrelatedFindingID(pkgName, "MOBILE-BACKEND-CLEARTEXT-COMMUNICATION", ep.Host, ep.Path, ep.Method)
			if !seenFindingIDs[fID] {
				seenFindingIDs[fID] = true

				verState := ClassificationPotential
				sev := "MEDIUM"
				var runtimeEv string
				if ep.IsObservedRuntime {
					verState = ClassificationConfirmed
					if ep.RuntimeEndpoint != nil && ep.RuntimeEndpoint.Provenance != "" {
						runtimeEv = fmt.Sprintf("Observed %s request to http://%s:%d%s via %s", ep.Method, ep.Host, ep.Port, ep.Path, ep.RuntimeEndpoint.Provenance)
					} else {
						runtimeEv = fmt.Sprintf("Observed %s request to http://%s:%d%s during dynamic execution", ep.Method, ep.Host, ep.Port, ep.Path)
					}
				} else {
					runtimeEv = "No runtime cleartext traffic observed during test window"
				}

				staticEv := "Static endpoint extraction identified HTTP URL in DEX string pool"
				if ep.StaticEndpoint != nil {
					staticEv = fmt.Sprintf("Discovered in %s: %s", ep.StaticEndpoint.Provenance, ep.StaticEndpoint.RawURL)
				}

				// If sensitive path (login, transfer, password), elevate severity
				lowerPath := strings.ToLower(ep.Path)
				if strings.Contains(lowerPath, "login") || strings.Contains(lowerPath, "password") || strings.Contains(lowerPath, "transfer") {
					sev = "HIGH"
				}

				findings = append(findings, CorrelatedFinding{
					ID:                fID,
					RuleID:            "MOBILE-BACKEND-CLEARTEXT-COMMUNICATION",
					Title:             fmt.Sprintf("[Mobile-to-Backend] Cleartext HTTP Communication to %s%s", ep.Host, ep.Path),
					PackageName:       pkgName,
					Host:              ep.Host,
					Endpoint:          ep.Path,
					Method:            ep.Method,
					Severity:          sev,
					Confidence:        "HIGH",
					VerificationState: verState,
					OriginalFindingID: "RUNTIME-CLEARTEXT-HTTP",
					SourceEngine:      "pkg/mobile (Frida Dynamic Instrumentation Engine)",
					StaticEvidence:    staticEv,
					RuntimeEvidence:   runtimeEv,
					BackendEvidence:   fmt.Sprintf("Target backend host %s accepts plaintext HTTP traffic on port %d", ep.Host, ep.Port),
					Explanation:       fmt.Sprintf("Application package %s communicates with backend host %s using unencrypted HTTP protocol. All requests, headers, and credentials are susceptible to network sniffing and Machine-in-the-Middle (MitM) interception.", pkgName, ep.Host),
					Remediation:       "Enforce TLS 1.2+ encryption for all mobile backend endpoints and declare cleartextTrafficPermitted=false in Android Network Security Config.",
					Timestamp:         now,
				})
			}
		}
	}

	// 2. Correlation with Backend Assessment Findings
	appBackendHosts := make(map[string]bool)
	for _, ep := range endpoints {
		if ep.Host != "" && ep.Host != "*" && !strings.Contains(ep.Host, "google") && !strings.Contains(ep.Host, "facebook") {
			appBackendHosts[strings.ToLower(ep.Host)] = true
		}
	}

	for _, ep := range endpoints {
		for _, bf := range backendFindings {
			if bf.Host == "" && bf.Endpoint == "" {
				continue
			}

			// Reject unrelated findings that do not match the target backend host
			hostMatches := false
			if ep.Host != "" && bf.Host != "" {
				if strings.EqualFold(ep.Host, bf.Host) || strings.Contains(bf.Host, ep.Host) || strings.Contains(ep.Host, bf.Host) {
					hostMatches = true
				}
			} else if ep.Host == "" && bf.Host != "" {
				if appBackendHosts[strings.ToLower(bf.Host)] {
					hostMatches = true
				}
			}

			// If host doesn't match and backend finding has an absolute URL target, test host extraction
			if !hostMatches && bf.Target != "" {
				if u, err := url.Parse(bf.Target); err == nil && u.Hostname() != "" {
					if ep.Host != "" && strings.EqualFold(ep.Host, u.Hostname()) {
						hostMatches = true
					} else if ep.Host == "" && appBackendHosts[strings.ToLower(u.Hostname())] {
						hostMatches = true
					}
				}
			}

			if !hostMatches {
				continue // strictly reject unrelated domain findings
			}

			// Check path match
			epCleanPath := path.Clean("/" + strings.TrimPrefix(ep.Path, "/"))
			bfCleanPath := path.Clean("/" + strings.TrimPrefix(bf.Path, "/"))
			if bfCleanPath == "." || bfCleanPath == "" {
				bfCleanPath = path.Clean("/" + strings.TrimPrefix(bf.Endpoint, "/"))
			}

			pathMatches := false
			if epCleanPath != "/" && bfCleanPath != "/" {
				if epCleanPath == bfCleanPath || strings.HasPrefix(epCleanPath, bfCleanPath) || strings.HasPrefix(bfCleanPath, epCleanPath) {
					pathMatches = true
				}
			} else if epCleanPath == "/" && bfCleanPath == "/" {
				pathMatches = true
			}

			catLower := strings.ToLower(bf.Category + " " + bf.NormalizedCategory)
			titleLower := strings.ToLower(bf.Title)

			targetHost := ep.Host
			if targetHost == "" {
				targetHost = bf.Host
			}

			// 2A. Exposed Sensitive Endpoint Correlation
			if pathMatches && (strings.Contains(catLower, "exposure") || strings.Contains(catLower, "route") || strings.Contains(catLower, "debug") || strings.Contains(catLower, "actuator") || strings.Contains(titleLower, "exposed") || strings.Contains(titleLower, "backdoor")) {
				ruleID := "MOBILE-BACKEND-EXPOSED-ENDPOINT"
				fID := ComputeCorrelatedFindingID(pkgName, ruleID, targetHost, ep.Path, bf.ID)
				if !seenFindingIDs[fID] {
					seenFindingIDs[fID] = true
					verState := ClassificationPotential
					if ep.IsObservedRuntime && (bf.VerificationStatus == report.VerificationVerified || bf.IsVerified) {
						verState = ClassificationConfirmed
					}
					findings = append(findings, CorrelatedFinding{
						ID:                fID,
						RuleID:            ruleID,
						Title:             fmt.Sprintf("[Mobile-to-Backend] Mobile Access to Exposed Backend Endpoint %s%s", targetHost, ep.Path),
						PackageName:       pkgName,
						Host:              targetHost,
						Endpoint:          ep.Path,
						Method:            ep.Method,
						Severity:          bf.Severity,
						Confidence:        "HIGH",
						VerificationState: verState,
						OriginalFindingID: bf.ID,
						SourceEngine:      bf.Source,
						StaticEvidence:    fmt.Sprintf("Endpoint %s referenced in mobile codebase", ep.Path),
						RuntimeEvidence:   fmt.Sprintf("Observed runtime communication: %t", ep.IsObservedRuntime),
						BackendEvidence:   fmt.Sprintf("Backend finding [%s]: %s (Engine: %s, Status: %s, Evidence: %s)", bf.ID, bf.Title, bf.Source, bf.VerificationStatus, RedactSecret(bf.EvidenceSummary)),
						Explanation:       fmt.Sprintf("Application package %s communicates with exposed or administrative backend route %s on host %s. Backend assessment verified this endpoint is publicly accessible.", pkgName, ep.Path, targetHost),
						Remediation:       "Restrict or remove development/administrative endpoints in production environments.",
						Timestamp:         now,
					})
				}
			}

			// 2B. Authorization / BOLA Correlation
			if pathMatches && (strings.Contains(catLower, "bola") || strings.Contains(catLower, "auth") || strings.Contains(catLower, "idor") || strings.Contains(catLower, "privilege") || strings.Contains(titleLower, "authorization") || strings.Contains(titleLower, "broken auth")) {
				ruleID := "MOBILE-BACKEND-AUTHORIZATION-CORRELATION"
				fID := ComputeCorrelatedFindingID(pkgName, ruleID, targetHost, ep.Path, bf.ID)
				if !seenFindingIDs[fID] {
					seenFindingIDs[fID] = true
					verState := ClassificationPotential
					if ep.IsObservedRuntime && (bf.VerificationStatus == report.VerificationVerified || bf.IsVerified) {
						verState = ClassificationConfirmed
					}
					findings = append(findings, CorrelatedFinding{
						ID:                fID,
						RuleID:            ruleID,
						Title:             fmt.Sprintf("[Mobile-to-Backend] Authorization Vulnerability on Mobile API Route %s%s", targetHost, ep.Path),
						PackageName:       pkgName,
						Host:              targetHost,
						Endpoint:          ep.Path,
						Method:            ep.Method,
						Severity:          "HIGH",
						Confidence:        "HIGH",
						VerificationState: verState,
						OriginalFindingID: bf.ID,
						SourceEngine:      bf.Source,
						StaticEvidence:    fmt.Sprintf("Endpoint %s utilized by mobile client", ep.Path),
						RuntimeEvidence:   fmt.Sprintf("Runtime invocation verified: %t", ep.IsObservedRuntime),
						BackendEvidence:   fmt.Sprintf("Backend vulnerability [%s]: %s (Engine: %s, Status: %s, Evidence: %s)", bf.ID, bf.Title, bf.Source, bf.VerificationStatus, RedactSecret(bf.EvidenceSummary)),
						Explanation:       fmt.Sprintf("Mobile application endpoint %s on backend %s lacks adequate object-level authorization or authentication enforcement. Attackers can manipulate requests to tamper with unauthorized accounts or records.", ep.Path, targetHost),
						Remediation:       "Implement strict server-side authorization checks verifying user ownership of target resources.",
						Timestamp:         now,
					})
				}
			}
		}
	}

	// 3. Credential & Secret Correlation (Hardcoded secrets in DEX matching backend auth requirements)
	for _, sf := range staticFindings {
		if sf.RuleID == "STATIC-HARDCODED-SECRET" || sf.RuleID == "STATIC-CBC-KEY" || strings.Contains(sf.RuleID, "SECRET") {
			for _, ep := range endpoints {
				if ep.Host != "" && ep.Host != "*" {
					ruleID := "MOBILE-BACKEND-CREDENTIAL-EXPOSURE"
					fID := ComputeCorrelatedFindingID(pkgName, ruleID, ep.Host, sf.ComponentOrKey, sf.ID)
					if !seenFindingIDs[fID] {
						seenFindingIDs[fID] = true
						findings = append(findings, CorrelatedFinding{
							ID:                fID,
							RuleID:            ruleID,
							Title:             fmt.Sprintf("[Mobile-to-Backend] Leaked Backend Secret Discovered in Codebase (%s)", sf.ComponentOrKey),
							PackageName:       pkgName,
							Host:              ep.Host,
							Endpoint:          ep.Path,
							Severity:          sf.Severity,
							Confidence:        "HIGH",
							VerificationState: sf.Classification,
							OriginalFindingID: sf.ID,
							SourceEngine:      "pkg/mobile/secrets.go (DEX Bytecode Harvester)",
							StaticEvidence:    fmt.Sprintf("Extracted secret at %s: %s", sf.ComponentOrKey, RedactSecret(sf.ObservedValue)),
							RuntimeEvidence:   "Static DEX extraction confirmed cryptographic material or authentication secret",
							BackendEvidence:   fmt.Sprintf("Backend service at %s uses shared authentication credentials", ep.Host),
							Explanation:       fmt.Sprintf("Hardcoded cryptographic secret or API token %q found embedded within %s. Exposure allows attackers to forge requests or authenticate directly against backend APIs.", sf.ComponentOrKey, sf.EvidenceSource),
							Remediation:       "Store all backend API secrets and master keys in secure backend key management services (KMS) or Android Keystore, never embedded in client binaries.",
							Timestamp:         now,
						})
					}
					break // correlate once per secret
				}
			}
		}
	}

	// 4. Cloud Resource Exposure Correlation
	for _, sf := range staticFindings {
		if strings.Contains(sf.ObservedValue, ".amazonaws.com") || strings.Contains(sf.ObservedValue, ".firebaseio.com") || strings.Contains(sf.ObservedValue, ".blob.core.windows.net") {
			ruleID := "MOBILE-BACKEND-CLOUD-EXPOSURE"
			fID := ComputeCorrelatedFindingID(pkgName, ruleID, "cloud", sf.ComponentOrKey, sf.ID)
			if !seenFindingIDs[fID] {
				seenFindingIDs[fID] = true
				findings = append(findings, CorrelatedFinding{
					ID:                fID,
					RuleID:            ruleID,
					Title:             fmt.Sprintf("[Mobile-to-Backend] Cloud Storage Reference Exposed in Mobile Package (%s)", sf.ComponentOrKey),
					PackageName:       pkgName,
					Host:              "cloud-storage",
					Endpoint:          sf.ComponentOrKey,
					Severity:          "HIGH",
					Confidence:        "HIGH",
					VerificationState: ClassificationConfirmed,
					StaticEvidence:    fmt.Sprintf("Extracted cloud resource: %s", RedactSecret(sf.ObservedValue)),
					RuntimeEvidence:   "Static DEX discovery of cloud infrastructure endpoint",
					BackendEvidence:   "Direct cloud asset linkage identified in mobile binary",
					Explanation:       fmt.Sprintf("Target mobile application directly references cloud storage asset %q. Misconfigured access controls on cloud buckets expose internal data to unauthorized download.", sf.ObservedValue),
					Remediation:       "Enforce authenticated backend proxying for cloud object storage and restrict public bucket permissions.",
					Timestamp:         now,
				})
			}
		}
	}

	return findings
}

// -----------------------------------------------------------------------------
// Unified Mobile-to-Backend Security Graph Builder
// -----------------------------------------------------------------------------

// BuildMobileBackendGraph constructs a directed relationship graph connecting mobile package,
// static/runtime endpoints, backend hosts, and security findings.
func BuildMobileBackendGraph(
	pkgName string,
	endpoints []CorrelatedEndpoint,
	correlatedFindings []CorrelatedFinding,
	backendFindings []correlation.NormalizedFinding,
) *MobileBackendGraph {
	g := NewMobileBackendGraph(pkgName)

	// 1. Mobile Application Root Node
	appNodeID := fmt.Sprintf("app:%s", pkgName)
	g.AddNode(&MobileBackendGraphNode{
		ID:          appNodeID,
		Type:        discovery.AssetTypeApplication,
		DisplayName: fmt.Sprintf("Android App (%s)", pkgName),
		PackageName: pkgName,
		Attributes: map[string]string{
			"platform": "android",
			"package":  pkgName,
		},
	})

	// Track hosts and endpoints added to graph
	hostNodeIDs := make(map[string]string)

	for _, ep := range endpoints {
		if ep.Host == "" || ep.Host == "*" {
			continue
		}

		// 2. Backend Host Node
		hostKey := fmt.Sprintf("%s:%d", ep.Host, ep.Port)
		hostNodeID, exists := hostNodeIDs[hostKey]
		if !exists {
			hostNodeID = fmt.Sprintf("host:%s", hostKey)
			hostNodeIDs[hostKey] = hostNodeID
			g.AddNode(&MobileBackendGraphNode{
				ID:          hostNodeID,
				Type:        discovery.AssetTypeHost,
				DisplayName: fmt.Sprintf("Backend Host (%s)", hostKey),
				Host:        ep.Host,
				Attributes: map[string]string{
					"scheme": ep.Scheme,
					"host":   ep.Host,
					"port":   strconv.Itoa(ep.Port),
				},
			})

			// Edge: App -> Backend Host (RelReaches)
			g.AddEdge(appNodeID, hostNodeID, correlation.RelReaches, correlation.ValidationConfirmed, "HIGH", fmt.Sprintf("Mobile app communicates with host %s", hostKey))
		}

		// 3. API Endpoint Node
		if ep.Path != "" && ep.Path != "/*" {
			epNodeID := fmt.Sprintf("endpoint:%s%s#%s", hostKey, ep.Path, ep.Method)
			g.AddNode(&MobileBackendGraphNode{
				ID:          epNodeID,
				Type:        discovery.AssetTypeEndpoint,
				DisplayName: fmt.Sprintf("%s %s", ep.Method, ep.Path),
				Host:        ep.Host,
				Endpoint:    ep.Path,
				Attributes: map[string]string{
					"path":            ep.Path,
					"method":          ep.Method,
					"observed_runtime": strconv.FormatBool(ep.IsObservedRuntime),
					"static_extracted": strconv.FormatBool(ep.IsStaticExtracted),
					"confidence":      string(ep.Confidence),
				},
			})

			// Edge: Backend Host -> API Endpoint (RelExposes)
			g.AddEdge(hostNodeID, epNodeID, correlation.RelExposes, correlation.ValidationConfirmed, string(ep.Confidence), fmt.Sprintf("Host exposes endpoint %s", ep.Path))

			// Edge: If observed at runtime, App -> Endpoint (RelReaches)
			if ep.IsObservedRuntime {
				g.AddEdge(appNodeID, epNodeID, correlation.RelReaches, correlation.ValidationConfirmed, "HIGH", "Observed runtime API request")
			}
		}
	}

	// 4. Correlated Security Finding Nodes
	for _, cf := range correlatedFindings {
		findingNodeID := fmt.Sprintf("finding:%s", cf.ID)
		g.AddNode(&MobileBackendGraphNode{
			ID:          findingNodeID,
			Type:        discovery.AssetTypeEndpoint,
			DisplayName: cf.Title,
			Host:        cf.Host,
			Endpoint:    cf.Endpoint,
			Attributes: map[string]string{
				"rule_id":            cf.RuleID,
				"severity":           cf.Severity,
				"confidence":         cf.Confidence,
				"verification_state": string(cf.VerificationState),
			},
		})

		// Edge connecting Endpoint -> Finding
		hostKey := cf.Host
		epNodeID := fmt.Sprintf("endpoint:%s%s#%s", hostKey, cf.Endpoint, cf.Method)
		if _, ok := g.Nodes[epNodeID]; ok {
			g.AddEdge(epNodeID, findingNodeID, correlation.RelEnables, correlation.ValidationConfirmed, cf.Confidence, cf.Explanation)
		} else if hostID, okHost := hostNodeIDs[hostKey]; okHost {
			g.AddEdge(hostID, findingNodeID, correlation.RelExposes, correlation.ValidationConfirmed, cf.Confidence, cf.Explanation)
		} else {
			g.AddEdge(appNodeID, findingNodeID, correlation.RelSharesRootCause, correlation.ValidationConfirmed, cf.Confidence, cf.Explanation)
		}
	}

	return g
}

// ToDAGAttackGraph converts a MobileBackendGraph into a correlation.DAGAttackGraph,
// enabling cross-layer shortest attack-path calculation and cycle validation.
func (g *MobileBackendGraph) ToDAGAttackGraph(rejectCycles bool) (*correlation.DAGAttackGraph, error) {
	g.mu.RLock()
	defer g.mu.RUnlock()

	dag := correlation.NewDAGAttackGraph(rejectCycles)

	// Sort node IDs for deterministic construction
	nodeIDs := make([]string, 0, len(g.Nodes))
	for id := range g.Nodes {
		nodeIDs = append(nodeIDs, id)
	}
	sort.Strings(nodeIDs)

	for _, id := range nodeIDs {
		node := g.Nodes[id]
		dagNodeType := correlation.NodeTypeFinding
		isEntrypoint := false
		isCritical := false
		sev := report.SeverityMedium
		conf := "HIGH"
		verStatus := report.VerificationDetected

		if node.Attributes != nil {
			if s, ok := node.Attributes["severity"]; ok && s != "" {
				sev = s
			}
			if c, ok := node.Attributes["confidence"]; ok && c != "" {
				conf = c
			}
			if v, ok := node.Attributes["verification_state"]; ok && v != "" {
				verStatus = report.VerificationStatus(v)
			}
		}

		if sev == report.SeverityCritical || strings.Contains(strings.ToLower(node.DisplayName), "database") || strings.Contains(strings.ToLower(node.DisplayName), "admin") {
			isCritical = true
		}

		switch node.Type {
		case discovery.AssetTypeApplication:
			dagNodeType = correlation.NodeTypeApplication
			isEntrypoint = true
		case discovery.AssetTypeHost:
			dagNodeType = correlation.NodeTypeComponent
		case discovery.AssetTypeEndpoint:
			if strings.HasPrefix(node.ID, "finding:") {
				dagNodeType = correlation.NodeTypeFinding
			} else {
				dagNodeType = correlation.NodeTypeRoute
			}
		}

		if strings.Contains(strings.ToLower(node.DisplayName), "secret") || strings.Contains(strings.ToLower(node.DisplayName), "credential") {
			dagNodeType = correlation.NodeTypeCredential
		}

		dagNode := &correlation.DAGNode{
			ID:                 node.ID,
			Type:               dagNodeType,
			Title:              node.DisplayName,
			Severity:           sev,
			Confidence:         conf,
			VerificationStatus: verStatus,
			SourceEngine:       "ENGINE_6_MOBILE",
			AssetAssociation:   node.Host,
			IsCriticalAsset:    isCritical,
			IsEntrypoint:       isEntrypoint,
			Attributes:         node.Attributes,
		}

		_ = dag.AddNode(dagNode)
	}

	for _, edge := range g.Edges {
		srcNode, srcOk := dag.Nodes[edge.SourceID]
		tgtNode, tgtOk := dag.Nodes[edge.TargetID]
		if !srcOk || !tgtOk {
			continue
		}

		dagEdgeType := correlation.DAGEdgeSequenceTransition
		ruleCode := correlation.RuleCOR01
		if edge.Type == correlation.RelReaches {
			ruleCode = correlation.RuleCOR01
		} else if edge.Type == correlation.RelExposes {
			ruleCode = correlation.RuleCOR02
		} else if edge.Type == correlation.RelEnables {
			ruleCode = correlation.RuleCOR03
		}

		if srcNode.Type == correlation.NodeTypeCredential && tgtNode.Type == correlation.NodeTypeRoute {
			dagEdgeType = correlation.DAGEdgeCredToRoute
			ruleCode = correlation.RuleCOR02
		}

		weight := correlation.CalculateEdgeCost(srcNode, tgtNode, edge.Confidence)

		dagEdge := &correlation.DAGEdge{
			ID:                 edge.ID,
			SourceID:           edge.SourceID,
			TargetID:           edge.TargetID,
			Type:               dagEdgeType,
			RuleCode:           ruleCode,
			Confidence:         edge.Confidence,
			Weight:             weight,
			Explanation:        edge.Evidence,
			ValidationStatus:   edge.ValidationStatus,
		}
		_ = dag.AddEdge(dagEdge)
	}

	dag.Validation = dag.Validate()
	if rejectCycles && dag.Validation.HasCycle {
		return dag, fmt.Errorf("cycle detected in mobile-backend graph: %s", strings.Join(dag.Validation.CycleNodes, ", "))
	}

	return dag, nil
}
