package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"
)

// DefaultGraphQLCandidatePaths contains common GraphQL route paths.
var DefaultGraphQLCandidatePaths = []string{
	"/graphql",
	"/api/graphql",
	"/v1/graphql",
}

type introspectionResponse struct {
	Data struct {
		Schema struct {
			Types []struct {
				Name string `json:"name"`
			} `json:"types"`
		} `json:"__schema"`
	} `json:"data"`
}

// AuditGraphQL tests candidate GraphQL endpoints for introspection exposure.
func AuditGraphQL(ctx context.Context, client *Client, targetBaseURL string, candidatePaths []string) []APIFinding {
	var findings []APIFinding
	baseURL := strings.TrimRight(targetBaseURL, "/")

	seen := make(map[string]struct{})
	var paths []string
	for _, p := range candidatePaths {
		cleanP := strings.TrimSpace(p)
		if cleanP == "" {
			continue
		}
		if !strings.HasPrefix(cleanP, "/") {
			cleanP = "/" + cleanP
		}
		if _, exists := seen[cleanP]; !exists {
			seen[cleanP] = struct{}{}
			paths = append(paths, cleanP)
		}
	}
	if len(paths) == 0 {
		paths = DefaultGraphQLCandidatePaths
	}

	introQueryJSON := []byte(`{"query":"{ __schema { types { name } } }"}`)

	for _, p := range paths {
		endpointURL := baseURL + p

		// 1. Safe GET probe first
		getURL := endpointURL + "?query=%7B__schema%7Btypes%7Bname%7D%7D%7D"
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, getURL, nil)
		if err != nil {
			continue
		}
		req.Header.Set("Accept", "application/json")

		resp, err := client.Do(ctx, req)
		if err != nil {
			if err == ErrRateLimited {
				break
			}
			continue
		}

		// If 405 Method Not Allowed or 400 Bad Request, fall back to safe POST with JSON body
		if resp.StatusCode == http.StatusMethodNotAllowed || resp.StatusCode == http.StatusBadRequest {
			postReq, err := http.NewRequestWithContext(ctx, http.MethodPost, endpointURL, bytes.NewReader(introQueryJSON))
			if err == nil {
				postReq.Header.Set("Content-Type", "application/json")
				postReq.Header.Set("Accept", "application/json")
				if postResp, postErr := client.Do(ctx, postReq); postErr == nil {
					resp = postResp
				}
			}
		}

		// Protected or non-existent endpoints create no findings
		if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusNotFound {
			continue
		}

		// Evaluate response for GraphQL introspection schema
		if resp.StatusCode == http.StatusOK {
			var ir introspectionResponse
			if err := json.Unmarshal(resp.Body, &ir); err == nil && len(ir.Data.Schema.Types) > 0 {
				typeCount := len(ir.Data.Schema.Types)

				// Identify potentially sensitive schema types without claiming exploitability
				sensitiveKeywords := []string{
					"admin", "user", "account", "payment", "billing", "password", "token", "secret", "internal", "auth",
				}
				var sensitiveIndicators []string
				for _, t := range ir.Data.Schema.Types {
					tLower := strings.ToLower(t.Name)
					if strings.HasPrefix(tLower, "__") {
						continue // skip internal meta types
					}
					for _, kw := range sensitiveKeywords {
						if strings.Contains(tLower, kw) {
							sensitiveIndicators = append(sensitiveIndicators, t.Name)
							break
						}
					}
				}
				sort.Strings(sensitiveIndicators)

				indicatorSummary := "none"
				if len(sensitiveIndicators) > 0 {
					if len(sensitiveIndicators) > 6 {
						indicatorSummary = strings.Join(sensitiveIndicators[:6], ", ") + fmt.Sprintf(" ... +%d more", len(sensitiveIndicators)-6)
					} else {
						indicatorSummary = strings.Join(sensitiveIndicators, ", ")
					}
				}

				ev := fmt.Sprintf("HTTP 200 OK. Introspection query succeeded (%d types observed). Full schema dump omitted.", typeCount)
				if len(sensitiveIndicators) > 0 {
					ev = fmt.Sprintf("HTTP 200 OK. Introspection query succeeded (%d types observed; sensitive schema indicators: [%s]). Full schema dump omitted.",
						typeCount, indicatorSummary)
				}

				findings = append(findings, APIFinding{
					Category:         CategoryGraphQLIntrospection,
					Endpoint:         endpointURL,
					Method:           http.MethodGet,
					Description:      "GraphQL endpoint has public introspection enabled",
					Evidence:         ev,
					Severity:         SeverityLow,
					Confidence:       ConfidenceHigh,
					HTTPStatus:       resp.StatusCode,
					NegativeEvidence: "Full schema dump omitted to preserve audit bounds; operations not exploited.",
					Details: map[string]string{
						"type_count":           fmt.Sprintf("%d", typeCount),
						"sensitive_indicators": indicatorSummary,
					},
					Fingerprint: GenerateFingerprint(CategoryGraphQLIntrospection, endpointURL, http.MethodGet),
				})
			}
		}
	}

	return findings
}
