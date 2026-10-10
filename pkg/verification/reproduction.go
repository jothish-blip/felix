package verification

import (
	"fmt"
	"net/url"
	"strings"

	"felix/pkg/report"
)

// BuildReproductionContext generates safe, actionable reproduction steps and a sanitized curl command.
func BuildReproductionContext(
	f report.Finding,
	targetURL string,
	policyID string,
	status report.VerificationStatus,
	expected string,
	observed string,
	preconditions []string,
	limitations []string,
) ReproductionContext {
	endpoint := f.Endpoint
	if endpoint == "" {
		endpoint = targetURL
	}
	if !strings.HasPrefix(endpoint, "http://") && !strings.HasPrefix(endpoint, "https://") {
		base := strings.TrimRight(targetURL, "/")
		ep := strings.TrimLeft(endpoint, "/")
		endpoint = fmt.Sprintf("%s/%s", base, ep)
	}

	method := f.Method
	if method == "" {
		method = f.EvidenceDetails.HTTPMethod
	}
	if method == "" {
		method = "GET"
	}

	// Redacted headers & params
	cleanHeaders := make(map[string]string)
	if f.EvidenceDetails.Details != nil {
		for k, v := range f.EvidenceDetails.Details {
			kl := strings.ToLower(k)
			if strings.Contains(kl, "header") || strings.Contains(kl, "auth") || strings.Contains(kl, "cookie") {
				cleanHeaders[k] = report.SanitizeEvidence(v)
			}
		}
	}

	cleanParams := make(map[string]string)
	if u, err := url.Parse(endpoint); err == nil {
		q := u.Query()
		for k, vals := range q {
			if len(vals) > 0 {
				cleanParams[k] = report.SanitizeEvidence(vals[0])
			}
		}
	}

	// Safe curl command with credentials redacted
	curlCmd := buildSafeCurl(method, endpoint, cleanHeaders)

	// Determine reproducibility tier
	var reproState string
	switch status {
	case StatusVerified:
		reproState = "REPRODUCED"
	case StatusNotExposed:
		reproState = "EVIDENCE_COLLECTED"
	case StatusDetected:
		reproState = "CANDIDATE"
	default:
		reproState = "NOT_REPRODUCIBLE"
	}

	// Build step-by-step reproduction guide
	var steps []string
	steps = append(steps, fmt.Sprintf("1. Target environment setup: verify reachability to %s", targetURL))
	if len(preconditions) > 0 {
		for _, p := range preconditions {
			steps = append(steps, fmt.Sprintf("   - Precondition: %s", p))
		}
	}
	steps = append(steps, fmt.Sprintf("2. Dispatch safe probe via %s to %s", method, endpoint))
	steps = append(steps, fmt.Sprintf("   Execute: %s", curlCmd))
	steps = append(steps, fmt.Sprintf("3. Expected secure behavior: %s", expected))
	steps = append(steps, fmt.Sprintf("4. Observed result: %s", observed))
	steps = append(steps, fmt.Sprintf("5. Verification conclusion: %s under policy %s", status, policyID))

	return ReproductionContext{
		Target:            targetURL,
		Endpoint:          endpoint,
		Method:            method,
		Headers:           cleanHeaders,
		Params:            cleanParams,
		Preconditions:     preconditions,
		ExpectedBehavior:  expected,
		ObservedBehavior:  observed,
		ReproductionSteps: steps,
		SafeCurlCommand:   curlCmd,
		Reproducibility:   reproState,
		Limitations:       limitations,
	}
}

func buildSafeCurl(method, endpoint string, headers map[string]string) string {
	var parts []string
	parts = append(parts, "curl", "-s", "-i", "-X", method)

	for k, v := range headers {
		kl := strings.ToLower(k)
		if strings.Contains(kl, "auth") || strings.Contains(kl, "token") || strings.Contains(kl, "cookie") || strings.Contains(kl, "secret") {
			parts = append(parts, "-H", fmt.Sprintf("\"%s: [REDACTED]\"", k))
		} else {
			parts = append(parts, "-H", fmt.Sprintf("\"%s: %s\"", k, report.SanitizeEvidence(v)))
		}
	}

	// Add user-agent header
	parts = append(parts, "-H", "\"User-Agent: Felix-Security-Audit/2.0\"")
	parts = append(parts, fmt.Sprintf("\"%s\"", endpoint))

	return strings.Join(parts, " ")
}
