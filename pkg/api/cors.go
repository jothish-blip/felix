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

	usedMethod := http.MethodGet
	statusCode := resp.StatusCode

	// If GET did not return CORS headers, attempt standard preflight OPTIONS probe
	if acao == "" {
		optsReq, err := http.NewRequestWithContext(ctx, http.MethodOptions, endpointURL, nil)
		if err == nil {
			optsReq.Header.Set("Origin", testProbeOrigin)
			optsReq.Header.Set("Access-Control-Request-Method", "GET")
			if optsResp, optsErr := client.Do(ctx, optsReq); optsErr == nil {
				acao = strings.TrimSpace(optsResp.Header.Get("Access-Control-Allow-Origin"))
				acac = strings.TrimSpace(optsResp.Header.Get("Access-Control-Allow-Credentials"))
				usedMethod = http.MethodOptions
				statusCode = optsResp.StatusCode
			}
		}
	}

	// Case 1: No CORS header present (acao == "")
	// Normal, secure browser behavior. Not a vulnerability.
	if acao == "" {
		return findings
	}

	// Case 5: Origin allowlist enforced (server returned an allowlisted origin, not our probe)
	if !strings.EqualFold(acao, testProbeOrigin) && acao != "*" {
		// Server returned a specific origin without reflecting arbitrary origin -> secure allowlist behavior
		return findings
	}

	// Case 4: Arbitrary Origin Reflection + Credentials Allowed -> High Severity
	if strings.EqualFold(acao, testProbeOrigin) && strings.EqualFold(acac, "true") {
		findings = append(findings, APIFinding{
			Category:    CategoryCORSOriginReflection,
			Endpoint:    endpointURL,
			Method:      usedMethod,
			Description: "CORS configuration reflects arbitrary Origin with credentials allowed",
			Evidence: fmt.Sprintf("Supplied Origin: %s. Response returned Access-Control-Allow-Origin: %s, Access-Control-Allow-Credentials: true (HTTP %d %s). Rationale: Permits cross-origin credentialed access from arbitrary domains.",
				testProbeOrigin, acao, statusCode, usedMethod),
			Severity:         SeverityHigh,
			Confidence:       ConfidenceHigh,
			HTTPStatus:       statusCode,
			NegativeEvidence: "",
			Details: map[string]string{
				"origin": testProbeOrigin,
				"acao":   acao,
				"acac":   "true",
				"method": usedMethod,
			},
			Fingerprint: GenerateFingerprint(CategoryCORSOriginReflection, endpointURL, "CORS_CREDS"),
		})
		return findings
	}

	// Case 3: Arbitrary Origin Reflection without Credentials -> Low Severity
	if strings.EqualFold(acao, testProbeOrigin) {
		findings = append(findings, APIFinding{
			Category:    CategoryCORSOriginReflection,
			Endpoint:    endpointURL,
			Method:      usedMethod,
			Description: "CORS configuration reflects arbitrary Origin without credentials",
			Evidence: fmt.Sprintf("Supplied Origin: %s. Response returned Access-Control-Allow-Origin: %s (HTTP %d %s). Rationale: Origin is reflected, but credentials cannot be sent without Access-Control-Allow-Credentials: true.",
				testProbeOrigin, acao, statusCode, usedMethod),
			Severity:         SeverityLow,
			Confidence:       ConfidenceHigh,
			HTTPStatus:       statusCode,
			NegativeEvidence: "Access-Control-Allow-Credentials header was absent or false; browsers will not permit credentialed access.",
			Details: map[string]string{
				"origin": testProbeOrigin,
				"acao":   acao,
				"acac":   acac,
				"method": usedMethod,
			},
			Fingerprint: GenerateFingerprint(CategoryCORSOriginReflection, endpointURL, "CORS_REFLECT"),
		})
		return findings
	}

	// Case 2: Wildcard ACAO (*) -> Informational
	if acao == "*" {
		findings = append(findings, APIFinding{
			Category:    CategoryCORSWildcard,
			Endpoint:    endpointURL,
			Method:      usedMethod,
			Description: "CORS policy permits wildcard (*) origin",
			Evidence: fmt.Sprintf("Supplied Origin: %s. Response returned Access-Control-Allow-Origin: * (HTTP %d %s). Rationale: Wildcard origin permits unauthenticated cross-origin resource sharing.",
				testProbeOrigin, statusCode, usedMethod),
			Severity:         SeverityInfo,
			Confidence:       ConfidenceHigh,
			HTTPStatus:       statusCode,
			NegativeEvidence: "Access-Control-Allow-Credentials header was absent. Credentialed cross-origin exposure was not demonstrated.",
			Details: map[string]string{
				"origin": testProbeOrigin,
				"acao":   "*",
				"acac":   acac,
				"method": usedMethod,
			},
			Fingerprint: GenerateFingerprint(CategoryCORSWildcard, endpointURL, "CORS_WILDCARD"),
		})
	}

	return findings
}
