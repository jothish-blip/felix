package cloud

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"

	"felix/pkg/crawler"
)

// ServiceDiscoveryEngine orchestrates universal service discovery across all 16 mandatory service targets.
type ServiceDiscoveryEngine struct {
	client     *Client
	isAllowed  func(string) bool
	isExcluded func(string) bool
}

// NewServiceDiscoveryEngine initializes a new engine with the provided safe probe client.
func NewServiceDiscoveryEngine(client *Client, isAllowed func(string) bool, isExcluded ...func(string) bool) *ServiceDiscoveryEngine {
	if client == nil {
		client = NewClient()
	}
	var excl func(string) bool
	if len(isExcluded) > 0 {
		excl = isExcluded[0]
	}
	return &ServiceDiscoveryEngine{
		client:     client,
		isAllowed:  isAllowed,
		isExcluded: excl,
	}
}

// DiscoverServices analyzes crawled assets and probes candidate targets across all 16 services.
func (e *ServiceDiscoveryEngine) DiscoverServices(ctx context.Context, assets []crawler.Asset) []DiscoveredService {
	var candidates []DiscoveredService
	seenCandidates := make(map[string]struct{})

	addCandidate := func(s DiscoveredService) {
		id := s.CanonicalID()
		if _, exists := seenCandidates[id]; !exists {
			seenCandidates[id] = struct{}{}
			candidates = append(candidates, s)
		}
	}

	// 1. Passive extraction across all assets
	for _, a := range assets {
		if len(a.Content) == 0 {
			continue
		}

		// Group A: Direct database & search
		for _, s := range ExtractDatabaseTargets(a.URL, a.Content) {
			addCandidate(s)
		}

		// Group B: Database admin interfaces
		for _, s := range ExtractAdminTargets(a.URL, a.Content) {
			addCandidate(s)
		}

		// Group C: Backend & database interfaces
		for _, s := range ExtractBackendTargets(a.URL, a.Content) {
			addCandidate(s)
		}

		// Group D: Firebase databases
		for _, s := range ExtractFirebaseTargets(a.URL, a.Content) {
			addCandidate(s)
		}

		// Group E: Cloud & object storage
		for _, s := range ExtractStorageTargets(a.URL, a.Content) {
			addCandidate(s)
		}
	}

	// 2. Active verification for candidates
	var results []DiscoveredService
	var mu sync.Mutex

	// Bounded worker pool for parallel safe probing
	sem := make(chan struct{}, 8)
	var wg sync.WaitGroup

	for _, cand := range candidates {
		candCopy := cand
		wg.Add(1)

		go func() {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-ctx.Done():
				return
			}

			verified := e.VerifyCandidate(ctx, candCopy)
			mu.Lock()
			results = append(results, verified)
			mu.Unlock()
		}()
	}

	wg.Wait()
	return results
}

// VerifyCandidate runs the appropriate targeted safe probe for a discovered candidate service.
func (e *ServiceDiscoveryEngine) VerifyCandidate(ctx context.Context, cand DiscoveredService) DiscoveredService {
	probeTarget := cand.Endpoint
	if probeTarget == "" && cand.Host != "" {
		if cand.Port > 0 {
			probeTarget = fmt.Sprintf("%s:%d", cand.Host, cand.Port)
		} else {
			probeTarget = cand.Host
		}
	}

	// Scope validation check before network transmission
	if e.isExcluded != nil && (e.isExcluded(probeTarget) || e.isExcluded(cand.Host)) {
		cand.InScope = false
		cand.Limitations = "probe blocked: target matches exclusion rule"
		return cand
	}

	if e.isAllowed != nil && !e.isAllowed(probeTarget) && !e.isAllowed(cand.Host) && !e.isAllowed("http://"+probeTarget) && !e.isAllowed("https://"+probeTarget) {
		cand.InScope = false
		cand.Limitations = "probe skipped: target outside authorized assessment scope"
		return cand
	}

	cand.InScope = true

	switch cand.Technology {
	case TechElasticsearch:
		target := cand.Endpoint
		if target == "" {
			target = fmt.Sprintf("http://%s:%d/", cand.Host, cand.Port)
		}
		res := ProbeElasticsearch(ctx, e.client, target)
		return mergeMetadata(cand, res)

	case TechMongoDB:
		res := ProbeMongoDB(ctx, e.client, cand.Host, cand.Port)
		return mergeMetadata(cand, res)

	case TechRedis:
		res := ProbeRedis(ctx, e.client, cand.Host, cand.Port)
		return mergeMetadata(cand, res)

	case TechPostgreSQL:
		res := ProbePostgreSQL(ctx, e.client, cand.Host, cand.Port)
		return mergeMetadata(cand, res)

	case TechMySQL:
		res := ProbeMySQL(ctx, e.client, cand.Host, cand.Port)
		return mergeMetadata(cand, res)

	case TechMongoExpress:
		res := ProbeMongoExpress(ctx, e.client, cand.Endpoint)
		return mergeMetadata(cand, res)

	case TechSupabase:
		return e.probeSupabase(ctx, cand)

	case TechPostgREST:
		res := ProbePostgREST(ctx, e.client, cand.Endpoint)
		return mergeMetadata(cand, res)

	case TechHasura:
		res := ProbeHasura(ctx, e.client, cand.Endpoint)
		return mergeMetadata(cand, res)

	case TechPrisma:
		// Prisma is an embedded ORM layer; preservation of passive evidence
		return cand

	case TechFirebaseRTDB:
		res := ProbeFirebaseRTDB(ctx, e.client, cand.Endpoint)
		return mergeMetadata(cand, res)

	case TechFirestore:
		projectID := ""
		if cand.Metadata != nil {
			if pid, ok := cand.Metadata["project_id"].(string); ok {
				projectID = pid
			}
		}
		if projectID == "" {
			cand.Limitations = "missing projectId for Firestore REST probe"
			return cand
		}
		res := ProbeFirestore(ctx, e.client, projectID)
		return mergeMetadata(cand, res)

	case TechAWSS3:
		res := ProbeAWSS3(ctx, e.client, cand.Endpoint)
		return mergeMetadata(cand, res)

	case TechAzureBlob:
		res := ProbeAzureBlob(ctx, e.client, cand.Endpoint)
		return mergeMetadata(cand, res)

	case TechGCS:
		res := ProbeGCS(ctx, e.client, cand.Endpoint)
		return mergeMetadata(cand, res)

	case TechMinIO:
		res := ProbeMinIO(ctx, e.client, cand.Endpoint)
		return mergeMetadata(cand, res)

	default:
		cand.Limitations = fmt.Sprintf("unsupported technology: %s", cand.Technology)
		return cand
	}
}

// probeSupabase executes safe verification on candidate Supabase project root and /rest/v1/ endpoint.
func (e *ServiceDiscoveryEngine) probeSupabase(ctx context.Context, cand DiscoveredService) DiscoveredService {
	cleanURL := strings.TrimRight(cand.Endpoint, "/")
	parsed, err := url.Parse(cleanURL)
	if err != nil {
		cand.Outcome = OutcomeError
		cand.Limitations = err.Error()
		return cand
	}

	// Safe probe to /rest/v1/
	req, err := http.NewRequestWithContext(ctx, "GET", cleanURL+"/rest/v1/", nil)
	if err != nil {
		cand.Outcome = OutcomeError
		cand.Limitations = err.Error()
		return cand
	}

	resp, err := e.client.Do(ctx, req)
	if err != nil {
		cand.Outcome = OutcomeInconclusive
		cand.Limitations = fmt.Sprintf("probe connection error: %v", err)
		return cand
	}

	cand.DetectionMethod = "HTTP_PROBE"
	cand.Protocol = "https"
	cand.Host = parsed.Hostname()

	// Supabase REST endpoints return 401 with {"message":"Invalid API key"} or OpenAPI spec
	bodyStr := string(resp.Body)
	gatewayMode := resp.Header.Get("sb-gateway-mode")
	isSupabase := strings.Contains(bodyStr, "Invalid API key") ||
		strings.Contains(bodyStr, "JWSError") ||
		gatewayMode != "" ||
		strings.Contains(parsed.Host, "supabase.co")

	if isSupabase {
		cand.Outcome = OutcomeDetected
		cand.Confidence = ConfidenceHigh
		cand.AuthRequired = resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden
		cand.PublicAccess = false
		cand.Evidence = fmt.Sprintf("Supabase REST gateway verified (HTTP %d)", resp.StatusCode)
		cand.Limitations = "Supabase REST gateway presence confirmed; table access policies (RLS) require Phase 2.2 verification"
	}

	return cand
}

// mergeMetadata combines original candidate metadata with probe results.
func mergeMetadata(cand, res DiscoveredService) DiscoveredService {
	if res.Outcome != "" {
		cand.Outcome = res.Outcome
	}
	if res.Confidence != "" {
		cand.Confidence = res.Confidence
	}
	if res.DetectionMethod != "" {
		cand.DetectionMethod = res.DetectionMethod
	}
	if res.Version != "" {
		cand.Version = res.Version
	}
	if res.Evidence != "" {
		cand.Evidence = res.Evidence
	}
	if res.Limitations != "" {
		cand.Limitations = res.Limitations
	}
	cand.AuthRequired = res.AuthRequired
	cand.PublicAccess = res.PublicAccess

	if cand.Metadata == nil {
		cand.Metadata = make(map[string]any)
	}
	if res.Metadata != nil {
		for k, v := range res.Metadata {
			cand.Metadata[k] = v
		}
	}
	return cand
}
