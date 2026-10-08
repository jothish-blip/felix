package api

import (
	"context"
	"net/url"
	"regexp"
	"strings"
	"sync"

	"felix/pkg/crawler"
)

var (
	apiPathRegex = regexp.MustCompile(`["'](/(?:api|v[0-9]+|graphql)(?:/[a-zA-Z0-9_\-\./]*)?)["']`)
)

// AuditResult summarizes the operations and discoveries of the API intelligence engine.
type AuditResult struct {
	EndpointsScanned int           `json:"endpoints_scanned"`
	GraphQLCount     int           `json:"graphql_count"`
	SensitiveCount   int           `json:"sensitive_count"`
	CORSCount        int           `json:"cors_count"`
	HeaderCount      int           `json:"header_count"`
	Findings         []APIFinding  `json:"findings"`
}

// Detector coordinates modern API discovery, GraphQL auditing, CORS analysis, and posture verification.
type Detector struct {
	client *Client
	mu     sync.RWMutex
}

// NewDetector initializes a new Engine 4 API auditor instance.
func NewDetector(client *Client) *Detector {
	if client == nil {
		client = NewClient()
	}
	return &Detector{
		client: client,
	}
}

// DiscoverCandidateEndpoints extracts relative API paths from assets within target origin scope.
func (d *Detector) DiscoverCandidateEndpoints(targetURL string, assets []crawler.Asset) []string {
	var endpoints []string
	seen := make(map[string]struct{})

	parsedTarget, err := url.Parse(targetURL)
	if err != nil {
		return endpoints
	}
	targetHost := strings.ToLower(parsedTarget.Hostname())

	for _, a := range assets {
		if len(a.Content) == 0 {
			continue
		}

		text := string(a.Content)
		matches := apiPathRegex.FindAllStringSubmatch(text, -1)
		for _, m := range matches {
			path := m[1]
			// Basic sanitization
			if strings.Contains(path, "//") || strings.Contains(path, " ") {
				continue
			}
			if len(path) > 80 {
				continue
			}

			if _, exists := seen[path]; !exists {
				seen[path] = struct{}{}
				endpoints = append(endpoints, path)
				if len(endpoints) >= 25 {
					// Bound discovery to prevent excessive enumeration
					break
				}
			}
		}

		// Also check if a.URL itself is an API endpoint on the target host
		if parsedA, err := url.Parse(a.URL); err == nil {
			if strings.ToLower(parsedA.Hostname()) == targetHost {
				p := parsedA.Path
				if strings.HasPrefix(p, "/api") || strings.HasPrefix(p, "/graphql") || strings.HasPrefix(p, "/v1") {
					if _, exists := seen[p]; !exists {
						seen[p] = struct{}{}
						endpoints = append(endpoints, p)
					}
				}
			}
		}

		if len(endpoints) >= 25 {
			break
		}
	}

	return endpoints
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
	baseURL := strings.TrimRight(parsedTarget.Scheme+"://"+parsedTarget.Host, "/")

	// 1. Discover candidate API endpoints from assets
	candidatePaths := d.DiscoverCandidateEndpoints(targetURL, assets)

	// Filter GraphQL specific paths
	var graphQLCandidates []string
	for _, p := range candidatePaths {
		if strings.Contains(strings.ToLower(p), "graphql") {
			graphQLCandidates = append(graphQLCandidates, p)
		}
	}

	var (
		allFindings []APIFinding
		seenFP      = make(map[string]struct{})
	)

	addFindings := func(findings []APIFinding) {
		for _, f := range findings {
			if _, exists := seenFP[f.Fingerprint]; !exists {
				seenFP[f.Fingerprint] = struct{}{}
				allFindings = append(allFindings, f)
			}
		}
	}

	// 2. Audit GraphQL Introspection
	graphQLFindings := AuditGraphQL(ctx, client, baseURL, graphQLCandidates)
	addFindings(graphQLFindings)

	// 3. Audit Sensitive Endpoints (git, env, openapi, metrics)
	sensitiveFindings := AuditSensitiveEndpoints(ctx, client, baseURL, candidatePaths)
	addFindings(sensitiveFindings)

	// 4. Audit CORS on target base and initial API paths
	var corsFindings []APIFinding
	corsTargets := []string{baseURL}
	for _, p := range candidatePaths {
		corsTargets = append(corsTargets, baseURL+p)
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

	totalAudited := 1 + len(candidatePaths) + len(DefaultSensitivePaths)

	return AuditResult{
		EndpointsScanned: totalAudited,
		GraphQLCount:     len(graphQLFindings),
		SensitiveCount:   len(sensitiveFindings),
		CORSCount:        len(corsFindings),
		HeaderCount:      len(headerFindings),
		Findings:         allFindings,
	}
}
