package cloud

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// VerifySupabaseAccess evaluates Supabase REST interface reachability, RLS policies, and bounded test table reads.
func VerifySupabaseAccess(
	ctx context.Context,
	client *Client,
	targetURL string,
	cred *CredentialProfile,
	resConfig *TestResourceConfig,
) AccessVerificationRecord {
	now := time.Now().UTC()
	record := AccessVerificationRecord{
		Target:              targetURL,
		Technology:          TechSupabase,
		Family:              FamilyBackendInterface,
		Status:              StatusAccessInconclusive,
		Decision:            DecisionInconclusive,
		AuthContext:         AuthContextUnauthenticated,
		Operation:           OpMetadataRead,
		ErrorClassification: ErrClassNone,
		VerifiedAt:          now,
	}

	cleanURL := strings.TrimRight(targetURL, "/")
	if !strings.HasPrefix(cleanURL, "http://") && !strings.HasPrefix(cleanURL, "https://") {
		cleanURL = "https://" + cleanURL
	}

	// 1. Unauthenticated Gateway probe (/rest/v1/)
	req, err := http.NewRequestWithContext(ctx, "GET", cleanURL+"/rest/v1/", nil)
	if err != nil {
		record.Status = StatusAccessInconclusive
		record.Decision = DecisionError
		record.Limitations = fmt.Sprintf("failed to construct request: %v", err)
		return record
	}

	resp, err := client.Do(ctx, req)
	if err != nil {
		classifyClientError(&record, err)
		return record
	}

	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		record.Status = StatusAuthChallenged
		record.Decision = DecisionDenied
		record.Evidence = fmt.Sprintf("Supabase REST gateway requires authentication credentials (HTTP %d)", resp.StatusCode)
	} else if resp.StatusCode == http.StatusOK {
		record.Status = StatusServiceReachable
		record.Decision = DecisionAllowed
		record.Evidence = "Supabase REST gateway reachable (HTTP 200)"
		record.Limitations = "REST gateway reachability confirmed; table read access governed by Row Level Security (RLS) requires bounded resource verification"
	}

	// 2. Credential verification if provided
	apiKey := ""
	if cred != nil {
		record.AuthContext = AuthContextAuthenticated
		record.CredentialUsed = true
		if cred.Secret != "" {
			apiKey = cred.Secret
		} else if cred.Headers != nil && cred.Headers["apikey"] != "" {
			apiKey = cred.Headers["apikey"]
		}

		if apiKey != "" {
			authReq, err := http.NewRequestWithContext(ctx, "GET", cleanURL+"/rest/v1/", nil)
			if err == nil {
				authReq.Header.Set("apikey", apiKey)
				authReq.Header.Set("Authorization", "Bearer "+apiKey)
				authResp, err := client.Do(ctx, authReq)
				if err == nil {
					if authResp.StatusCode == http.StatusOK {
						record.Status = StatusAuthenticatedAccess
						record.Decision = DecisionAllowed
						record.Evidence = "Supplied API key successfully accepted by Supabase REST gateway"
					} else {
						record.Status = StatusAuthChallenged
						record.Decision = DecisionDenied
						record.Evidence = fmt.Sprintf("Supplied API key rejected by Supabase REST gateway (HTTP %d)", authResp.StatusCode)
					}
				}
			}
		}
	}

	// 3. Bounded Table Read (if a synthetic test table is explicitly configured)
	if resConfig != nil && strings.TrimSpace(resConfig.ResourceID) != "" {
		testTable := strings.Trim(resConfig.ResourceID, "/")
		record.Operation = OpBoundedRead
		record.ResourceScope = testTable

		tableURL := fmt.Sprintf("%s/rest/v1/%s?select=*&limit=1", cleanURL, url.PathEscape(testTable))
		tblReq, err := http.NewRequestWithContext(ctx, "GET", tableURL, nil)
		if err != nil {
			record.Limitations = fmt.Sprintf("failed to construct table request: %v", err)
			return record
		}

		if apiKey != "" {
			tblReq.Header.Set("apikey", apiKey)
			tblReq.Header.Set("Authorization", "Bearer "+apiKey)
		}

		tblResp, err := client.Do(ctx, tblReq)
		if err != nil {
			classifyClientError(&record, err)
			return record
		}

		if tblResp.StatusCode == http.StatusOK {
			record.Status = StatusReadAllowed
			record.Decision = DecisionAllowed
			record.Evidence = fmt.Sprintf("Bounded read on Supabase table %q succeeded (HTTP 200)", testTable)
			if record.AuthContext == AuthContextUnauthenticated {
				record.FindingSuitable = true
				record.Evidence = fmt.Sprintf("Unauthenticated public read permitted on Supabase table %q (Row Level Security disabled or permissive)", testTable)
			}
		} else if tblResp.StatusCode == http.StatusUnauthorized || tblResp.StatusCode == http.StatusForbidden {
			record.Status = StatusReadDenied
			record.Decision = DecisionDenied
			record.Evidence = fmt.Sprintf("Read on Supabase table %q denied by Row Level Security (HTTP %d)", testTable, tblResp.StatusCode)
		} else {
			record.Status = StatusAccessInconclusive
			record.Decision = DecisionInconclusive
			record.Evidence = fmt.Sprintf("Unexpected response from Supabase table %q: HTTP %d", testTable, tblResp.StatusCode)
		}
	}

	return record
}

// VerifyPostgRESTAccess evaluates PostgREST reachability, OpenAPI schema vs data access, and bounded table queries.
func VerifyPostgRESTAccess(
	ctx context.Context,
	client *Client,
	targetURL string,
	cred *CredentialProfile,
	resConfig *TestResourceConfig,
) AccessVerificationRecord {
	now := time.Now().UTC()
	record := AccessVerificationRecord{
		Target:              targetURL,
		Technology:          TechPostgREST,
		Family:              FamilyBackendInterface,
		Status:              StatusAccessInconclusive,
		Decision:            DecisionInconclusive,
		AuthContext:         AuthContextUnauthenticated,
		Operation:           OpMetadataRead,
		ErrorClassification: ErrClassNone,
		VerifiedAt:          now,
	}

	cleanURL := strings.TrimRight(targetURL, "/")
	if !strings.HasPrefix(cleanURL, "http://") && !strings.HasPrefix(cleanURL, "https://") {
		cleanURL = "http://" + cleanURL
	}

	// 1. Root OpenAPI schema probe
	req, err := http.NewRequestWithContext(ctx, "GET", cleanURL+"/", nil)
	if err != nil {
		record.Status = StatusAccessInconclusive
		record.Decision = DecisionError
		record.Limitations = fmt.Sprintf("failed to construct request: %v", err)
		return record
	}
	req.Header.Set("Accept", "application/openapi+json, application/json")

	resp, err := client.Do(ctx, req)
	if err != nil {
		classifyClientError(&record, err)
		return record
	}

	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		record.Status = StatusAuthChallenged
		record.Decision = DecisionDenied
		record.Evidence = fmt.Sprintf("PostgREST root returned authentication challenge (HTTP %d)", resp.StatusCode)
	} else if resp.StatusCode == http.StatusOK {
		record.Status = StatusServiceReachable
		record.Decision = DecisionAllowed
		record.Evidence = "PostgREST root reachable (HTTP 200)"
		record.Limitations = "OpenAPI root schema visibility does not confirm unrestricted table data access"
	}

	// 2. Credential verification if provided
	token := ""
	if cred != nil {
		record.AuthContext = AuthContextAuthenticated
		record.CredentialUsed = true
		token = cred.Secret

		if token != "" {
			authReq, err := http.NewRequestWithContext(ctx, "GET", cleanURL+"/", nil)
			if err == nil {
				authReq.Header.Set("Authorization", "Bearer "+token)
				authResp, err := client.Do(ctx, authReq)
				if err == nil && authResp.StatusCode == http.StatusOK {
					record.Status = StatusAuthenticatedAccess
					record.Decision = DecisionAllowed
					record.Evidence = "PostgREST accepted configured JWT authorization token"
				}
			}
		}
	}

	// 3. Bounded Resource Read (if a synthetic test resource is configured)
	if resConfig != nil && strings.TrimSpace(resConfig.ResourceID) != "" {
		testResource := strings.Trim(resConfig.ResourceID, "/")
		record.Operation = OpBoundedRead
		record.ResourceScope = testResource

		resURL := fmt.Sprintf("%s/%s?limit=1", cleanURL, url.PathEscape(testResource))
		rReq, err := http.NewRequestWithContext(ctx, "GET", resURL, nil)
		if err == nil {
			if token != "" {
				rReq.Header.Set("Authorization", "Bearer "+token)
			}
			rResp, err := client.Do(ctx, rReq)
			if err != nil {
				classifyClientError(&record, err)
				return record
			}

			if rResp.StatusCode == http.StatusOK {
				record.Status = StatusReadAllowed
				record.Decision = DecisionAllowed
				record.Evidence = fmt.Sprintf("Bounded read on PostgREST resource %q succeeded (HTTP 200)", testResource)
				if record.AuthContext == AuthContextUnauthenticated {
					record.FindingSuitable = true
				}
			} else if rResp.StatusCode == http.StatusUnauthorized || rResp.StatusCode == http.StatusForbidden {
				record.Status = StatusReadDenied
				record.Decision = DecisionDenied
				record.Evidence = fmt.Sprintf("Read on PostgREST resource %q denied (HTTP %d)", testResource, rResp.StatusCode)
			}
		}
	}

	return record
}

// VerifyHasuraAccess evaluates Hasura GraphQL engine reachability, least-privilege identity, and bounded queries.
func VerifyHasuraAccess(
	ctx context.Context,
	client *Client,
	targetURL string,
	cred *CredentialProfile,
	resConfig *TestResourceConfig,
) AccessVerificationRecord {
	now := time.Now().UTC()
	record := AccessVerificationRecord{
		Target:              targetURL,
		Technology:          TechHasura,
		Family:              FamilyBackendInterface,
		Status:              StatusAccessInconclusive,
		Decision:            DecisionInconclusive,
		AuthContext:         AuthContextUnauthenticated,
		Operation:           OpMetadataRead,
		ErrorClassification: ErrClassNone,
		VerifiedAt:          now,
	}

	cleanURL := strings.TrimRight(targetURL, "/")
	if !strings.HasPrefix(cleanURL, "http://") && !strings.HasPrefix(cleanURL, "https://") {
		cleanURL = "http://" + cleanURL
	}

	// Helper to apply configured credentials without elevating privileges
	applyAuthHeaders := func(req *http.Request) {
		if cred == nil {
			return
		}
		if cred.Secret != "" {
			// Check if explicitly configured as admin secret in headers; otherwise default to least-privilege Bearer token
			if cred.Headers != nil && cred.Headers["x-hasura-admin-secret"] != "" {
				req.Header.Set("x-hasura-admin-secret", cred.Headers["x-hasura-admin-secret"])
			} else {
				req.Header.Set("Authorization", "Bearer "+cred.Secret)
			}
		}
		if cred.Role != "" {
			req.Header.Set("X-Hasura-Role", cred.Role)
		}
		if cred.Headers != nil {
			for k, v := range cred.Headers {
				if strings.ToLower(k) != "x-hasura-admin-secret" || cred.Secret == "" {
					req.Header.Set(k, v)
				}
			}
		}
	}

	// 1. Unauthenticated GraphQL probe (schema introspection check)
	queryBody := []byte(`{"query":"query { __typename }"}`)
	req, err := http.NewRequestWithContext(ctx, "POST", cleanURL+"/v1/graphql", bytes.NewReader(queryBody))
	if err != nil {
		record.Status = StatusAccessInconclusive
		record.Decision = DecisionError
		record.Limitations = fmt.Sprintf("failed to construct request: %v", err)
		return record
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(ctx, req)
	if err != nil {
		classifyClientError(&record, err)
		return record
	}

	bodyStr := string(resp.Body)
	if resp.StatusCode == http.StatusUnauthorized || strings.Contains(bodyStr, "x-hasura-admin-secret") || strings.Contains(bodyStr, "missing-authentication-token") {
		record.Status = StatusAuthChallenged
		record.Decision = DecisionDenied
		record.Evidence = "Hasura requires authentication credentials or role authorization"
	} else if resp.StatusCode == http.StatusOK && strings.Contains(bodyStr, "__typename") && !strings.Contains(bodyStr, `"errors"`) {
		record.Status = StatusServiceReachable
		record.Decision = DecisionAllowed
		record.Evidence = "Hasura GraphQL endpoint reachable; responded to schema introspection query"
		record.Limitations = "Root introspection response confirms engine presence; application data permissions require bounded query verification"
	}

	// 2. Least-privilege credential verification if provided
	if cred != nil && (cred.Secret != "" || len(cred.Headers) > 0 || cred.Role != "") {
		record.AuthContext = AuthContextAuthenticated
		record.CredentialUsed = true

		authReq, err := http.NewRequestWithContext(ctx, "POST", cleanURL+"/v1/graphql", bytes.NewReader(queryBody))
		if err == nil {
			authReq.Header.Set("Content-Type", "application/json")
			applyAuthHeaders(authReq)
			authResp, err := client.Do(ctx, authReq)
			if err == nil {
				authBody := string(authResp.Body)
				if authResp.StatusCode == http.StatusOK && strings.Contains(authBody, "__typename") && !strings.Contains(authBody, `"errors"`) {
					record.Status = StatusAuthenticatedAccess
					record.Decision = DecisionAllowed
					record.Evidence = "Supplied identity credentials accepted by Hasura GraphQL engine"
				} else if authResp.StatusCode == http.StatusUnauthorized || authResp.StatusCode == http.StatusForbidden {
					record.Status = StatusAuthChallenged
					record.Decision = DecisionDenied
					record.Evidence = fmt.Sprintf("Supplied Hasura credentials rejected (HTTP %d)", authResp.StatusCode)
				}
			}
		}
	}

	// 3. Bounded Test Query (if a synthetic test field is configured)
	if resConfig != nil && strings.TrimSpace(resConfig.ResourceID) != "" {
		testField := resConfig.ResourceID
		record.Operation = OpBoundedRead
		record.ResourceScope = testField

		bQuery := fmt.Sprintf(`{"query":"query { %s { __typename } }"}`, testField)
		bReq, err := http.NewRequestWithContext(ctx, "POST", cleanURL+"/v1/graphql", strings.NewReader(bQuery))
		if err == nil {
			bReq.Header.Set("Content-Type", "application/json")
			if record.AuthContext == AuthContextAuthenticated {
				applyAuthHeaders(bReq)
			}
			bResp, err := client.Do(ctx, bReq)
			if err != nil {
				classifyClientError(&record, err)
				return record
			}

			bBody := string(bResp.Body)
			// GraphQL validation errors, permission errors, or missing fields must NOT be classified as data access
			hasErrors := strings.Contains(bBody, `"errors"`) || bResp.StatusCode != http.StatusOK
			hasData := strings.Contains(bBody, fmt.Sprintf(`"%s"`, testField)) && strings.Contains(bBody, `"data"`)

			if !hasErrors && hasData {
				record.Status = StatusReadAllowed
				record.Decision = DecisionAllowed
				record.Evidence = fmt.Sprintf("Bounded GraphQL query on test field %q succeeded with data response", testField)
				if record.AuthContext == AuthContextUnauthenticated {
					record.FindingSuitable = true
				}
			} else {
				record.Status = StatusReadDenied
				record.Decision = DecisionDenied
				record.Evidence = fmt.Sprintf("Query on %q denied or restricted by Hasura permissions/schema", testField)
			}
		}
	}

	return record
}

// VerifyPrismaAccess reports explicit architectural boundaries for Prisma ORM.
func VerifyPrismaAccess(
	ctx context.Context,
	client *Client,
	targetURL string,
	cred *CredentialProfile,
	resConfig *TestResourceConfig,
) AccessVerificationRecord {
	now := time.Now().UTC()
	record := AccessVerificationRecord{
		Target:              targetURL,
		Technology:          TechPrisma,
		Family:              FamilyBackendInterface,
		Status:              StatusVerificationSkipped,
		Decision:            DecisionSkipped,
		AuthContext:         AuthContextNotApplicable,
		Operation:           OpProtocolProbe,
		ErrorClassification: ErrClassUnsupported,
		VerifiedAt:          now,
		Limitations:         "Prisma is an internal application ORM layer without a direct public network protocol; direct network access verification is unsupported without an authorized application test endpoint",
		Evidence:            "Direct network probe intentionally skipped: Prisma does not expose a standalone database protocol listener",
	}

	// If an authorized application test endpoint is explicitly configured in resConfig
	if resConfig != nil && strings.TrimSpace(resConfig.ResourceID) != "" {
		record.Status = StatusAccessInconclusive
		record.Decision = DecisionInconclusive
		record.Operation = OpBoundedRead
		record.ResourceScope = resConfig.ResourceID
		record.Limitations = fmt.Sprintf("Application test endpoint %q provided for Prisma-backed service, but generic blackbox verification is inconclusive without service-specific endpoint contract", resConfig.ResourceID)
	}

	return record
}
