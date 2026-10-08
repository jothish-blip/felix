package api

import (
	"context"
	"fmt"
	"net/http"
	"strings"
)

const testProbeOrigin = "https://felix.invalid"

// AuditCORS conservatively evaluates Cross-Origin Resource Sharing configuration on an endpoint.
func AuditCORS(ctx context.Context, client *Client, endpointURL string) []APIFinding {
	var findings []APIFinding

	// Probe with test Origin header
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpointURL, nil)
	if err != nil {
		return findings
	}
	req.Header.Set("Origin", testProbeOrigin)

	resp, err := client.Do(ctx, req)
	if err != nil {
		return findings
	}

	acao := strings.TrimSpace(resp.Header.Get("Access-Control-Allow-Origin"))
	acac := strings.TrimSpace(resp.Header.Get("Access-Control-Allow-Credentials"))

	// If GET did not return CORS headers, attempt standard preflight OPTIONS probe
	if acao == "" {
		optsReq, err := http.NewRequestWithContext(ctx, http.MethodOptions, endpointURL, nil)
		if err == nil {
			optsReq.Header.Set("Origin", testProbeOrigin)
			optsReq.Header.Set("Access-Control-Request-Method", "GET")
			if optsResp, optsErr := client.Do(ctx, optsReq); optsErr == nil {
				acao = strings.TrimSpace(optsResp.Header.Get("Access-Control-Allow-Origin"))
				acac = strings.TrimSpace(optsResp.Header.Get("Access-Control-Allow-Credentials"))
			}
		}
	}

	// 1. Arbitrary Origin Reflection + Credentials Allowed -> High Severity
	if strings.EqualFold(acao, testProbeOrigin) && strings.EqualFold(acac, "true") {
		findings = append(findings, APIFinding{
			Category:    CategoryCORSOriginReflection,
			Endpoint:    endpointURL,
			Method:      http.MethodGet,
			Description: "CORS configuration reflects arbitrary Origin with credentials allowed",
			Evidence: fmt.Sprintf("Supplied Origin: %s. Response returned Access-Control-Allow-Origin: %s, Access-Control-Allow-Credentials: true",
				testProbeOrigin, acao),
			Severity:    SeverityHigh,
			Confidence:  ConfidenceHigh,
			Fingerprint: GenerateFingerprint(CategoryCORSOriginReflection, endpointURL, "CORS_CREDS"),
		})
		return findings
	}

	// 2. Arbitrary Origin Reflection without Credentials -> Low Severity
	if strings.EqualFold(acao, testProbeOrigin) {
		findings = append(findings, APIFinding{
			Category:    CategoryCORSOriginReflection,
			Endpoint:    endpointURL,
			Method:      http.MethodGet,
			Description: "CORS configuration reflects arbitrary Origin without credentials",
			Evidence: fmt.Sprintf("Supplied Origin: %s. Response returned Access-Control-Allow-Origin: %s",
				testProbeOrigin, acao),
			Severity:    SeverityLow,
			Confidence:  ConfidenceHigh,
			Fingerprint: GenerateFingerprint(CategoryCORSOriginReflection, endpointURL, "CORS_REFLECT"),
		})
		return findings
	}

	// 3. Wildcard ACAO (*) -> Informational
	if acao == "*" {
		findings = append(findings, APIFinding{
			Category:    CategoryCORSWildcard,
			Endpoint:    endpointURL,
			Method:      http.MethodGet,
			Description: "CORS policy permits wildcard (*) origin",
			Evidence:    "Response returned Access-Control-Allow-Origin: *",
			Severity:    SeverityInfo,
			Confidence:  ConfidenceHigh,
			Fingerprint: GenerateFingerprint(CategoryCORSWildcard, endpointURL, "CORS_WILDCARD"),
		})
	}

	return findings
}
