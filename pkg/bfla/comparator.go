package bfla

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

// ResponseData captures essential elements of an HTTP response for BFLA comparison.
type ResponseData struct {
	StatusCode int
	Header     http.Header
	Body       []byte
	URL        string
}

// ComparisonResult encapsulates the outcome of differential authorization analysis.
type ComparisonResult struct {
	State           VerificationState
	Severity        string
	Confidence      string
	EvidenceSummary string
	EvidenceDetails map[string]string
}

// DynamicFieldsToStrip defines transient non-semantic fields that should be ignored
// during JSON response comparison.
var DynamicFieldsToStrip = map[string]bool{
	"timestamp":    true,
	"created_at":   true,
	"createdat":    true,
	"updated_at":   true,
	"updatedat":    true,
	"server_time":  true,
	"servertime":   true,
	"date":         true,
	"request_id":   true,
	"requestid":    true,
	"trace_id":     true,
	"traceid":      true,
	"span_id":      true,
	"spanid":       true,
	"nonce":        true,
	"_t":           true,
	"generation":   true,
	"execution_ms": true,
}

// StripDynamicFields recursively removes dynamic transient fields from a parsed JSON structure.
func StripDynamicFields(v interface{}) interface{} {
	switch val := v.(type) {
	case map[string]interface{}:
		clean := make(map[string]interface{})
		for k, item := range val {
			lk := strings.ToLower(k)
			if DynamicFieldsToStrip[lk] {
				continue
			}
			clean[k] = StripDynamicFields(item)
		}
		return clean
	case []interface{}:
		clean := make([]interface{}, len(val))
		for i, item := range val {
			clean[i] = StripDynamicFields(item)
		}
		return clean
	default:
		return v
	}
}

// IsHTMLOrLoginPage detects whether a response is an HTML document or a generic login/error challenge.
func IsHTMLOrLoginPage(resp ResponseData) bool {
	ct := strings.ToLower(resp.Header.Get("Content-Type"))
	bodyStr := strings.ToLower(string(resp.Body))

	if strings.Contains(ct, "text/html") {
		return true
	}
	if strings.Contains(bodyStr, "<!doctype html") || strings.Contains(bodyStr, "<html") {
		return true
	}
	if strings.Contains(bodyStr, "login") && (strings.Contains(bodyStr, "password") || strings.Contains(bodyStr, "<form")) {
		return true
	}
	if strings.Contains(bodyStr, "please sign in") || strings.Contains(bodyStr, "authentication required") {
		return true
	}
	return false
}

// IsGenericErrorJSON checks whether a 200 OK response is actually an application-level error payload.
func IsGenericErrorJSON(body []byte) bool {
	var m map[string]interface{}
	if err := json.Unmarshal(body, &m); err != nil {
		return false
	}

	for k, v := range m {
		lk := strings.ToLower(k)
		if lk == "error" || lk == "err" || lk == "errors" || lk == "fault" {
			return true
		}
		if lk == "message" || lk == "msg" || lk == "detail" || lk == "reason" {
			if s, ok := v.(string); ok {
				ls := strings.ToLower(s)
				if strings.Contains(ls, "access denied") ||
					strings.Contains(ls, "unauthorized") ||
					strings.Contains(ls, "forbidden") ||
					strings.Contains(ls, "permission") ||
					strings.Contains(ls, "not permitted") ||
					strings.Contains(ls, "invalid role") ||
					strings.Contains(ls, "privilege") {
					return true
				}
			}
		}
	}
	return false
}

// IsEmptyResponse checks whether a response has an empty body or empty JSON container ({}, []).
func IsEmptyResponse(body []byte) bool {
	trimmed := bytes.TrimSpace(body)
	if len(trimmed) == 0 {
		return true
	}
	if bytes.Equal(trimmed, []byte("{}")) || bytes.Equal(trimmed, []byte("[]")) || bytes.Equal(trimmed, []byte("null")) {
		return true
	}
	return false
}

// HasPrivilegedIndicators checks if a response body exhibits signs of administrative or privileged data.
func HasPrivilegedIndicators(body []byte) bool {
	lower := strings.ToLower(string(body))
	privilegedKeywords := []string{
		"admin", "administrator", "role", "roles", "privilege",
		"internal", "metrics", "stats", "audit", "system", "config",
		"settings", "users", "deleted", "restarted", "shutdown",
		"permission", "superadmin", "operator", "root",
	}
	for _, kw := range privilegedKeywords {
		if strings.Contains(lower, kw) {
			return true
		}
	}
	return false
}

// CompareFunctionAccess evaluates whether a lower-privilege test response indicates Broken Function Level Authorization (BFLA).
func CompareFunctionAccess(baseline, testResp ResponseData, policy FunctionPolicy, allowedRole, testedRole, testedAlias string) ComparisonResult {
	details := make(map[string]string)
	details["policy_id"] = policy.FunctionID
	details["endpoint"] = policy.Path
	details["method"] = policy.Method
	details["allowed_role"] = allowedRole
	details["tested_role"] = testedRole
	details["tested_alias"] = testedAlias
	details["baseline_status"] = fmt.Sprintf("%d", baseline.StatusCode)
	details["test_status"] = fmt.Sprintf("%d", testResp.StatusCode)

	// 1. Validate baseline response if positive control was required
	if policy.PositiveControlRequired {
		if baseline.StatusCode < 200 || baseline.StatusCode >= 300 {
			return ComparisonResult{
				State:           StateInconclusive,
				Severity:        "INFO",
				Confidence:      "LOW",
				EvidenceSummary: fmt.Sprintf("Positive control failed: allowed role %s received status %d on %s %s; unable to establish valid privileged baseline", allowedRole, baseline.StatusCode, policy.Method, policy.Path),
				EvidenceDetails: details,
			}
		}
		if IsEmptyResponse(baseline.Body) {
			return ComparisonResult{
				State:           StateInconclusive,
				Severity:        "INFO",
				Confidence:      "LOW",
				EvidenceSummary: fmt.Sprintf("Positive control failed: allowed role %s received empty body on %s %s; cannot verify privileged output", allowedRole, policy.Method, policy.Path),
				EvidenceDetails: details,
			}
		}
	}

	// 2. Evaluate test response HTTP status code
	// If 401 Unauthorized, 403 Forbidden, or 404 Not Found (restricted function hidden/isolated) -> correctly denied
	if testResp.StatusCode == http.StatusUnauthorized || testResp.StatusCode == http.StatusForbidden || testResp.StatusCode == http.StatusNotFound {
		return ComparisonResult{
			State:           StateNotVulnerable,
			Severity:        "INFO",
			Confidence:      "CONFIRMED",
			EvidenceSummary: fmt.Sprintf("Access correctly denied for role %s with status %d (authorized role received %d)", testedRole, testResp.StatusCode, baseline.StatusCode),
			EvidenceDetails: details,
		}
	}

	// If redirect -> check if redirecting to login or auth challenge
	if testResp.StatusCode >= 300 && testResp.StatusCode < 400 {
		loc := testResp.Header.Get("Location")
		lowLoc := strings.ToLower(loc)
		if strings.Contains(lowLoc, "login") || strings.Contains(lowLoc, "auth") || strings.Contains(lowLoc, "signin") || strings.Contains(lowLoc, "challenge") {
			return ComparisonResult{
				State:           StateNotVulnerable,
				Severity:        "INFO",
				Confidence:      "CONFIRMED",
				EvidenceSummary: fmt.Sprintf("Access correctly redirected to authentication/authorization challenge (%s) with status %d", loc, testResp.StatusCode),
				EvidenceDetails: details,
			}
		}
	}

	// Check if response is HTML or generic login page
	if IsHTMLOrLoginPage(testResp) {
		return ComparisonResult{
			State:           StateNotVulnerable,
			Severity:        "INFO",
			Confidence:      "CONFIRMED",
			EvidenceSummary: fmt.Sprintf("Response returned HTML login or challenge page for role %s despite status %d; function not executed", testedRole, testResp.StatusCode),
			EvidenceDetails: details,
		}
	}

	// Check if response is generic application-level error JSON
	if IsGenericErrorJSON(testResp.Body) {
		return ComparisonResult{
			State:           StateNotVulnerable,
			Severity:        "INFO",
			Confidence:      "CONFIRMED",
			EvidenceSummary: fmt.Sprintf("Response returned application-level authorization error payload for role %s despite HTTP status %d", testedRole, testResp.StatusCode),
			EvidenceDetails: details,
		}
	}

	// Check if response is empty
	if IsEmptyResponse(testResp.Body) {
		return ComparisonResult{
			State:           StateInconclusive,
			Severity:        "INFO",
			Confidence:      "LOW",
			EvidenceSummary: fmt.Sprintf("Response for role %s returned empty body with status %d; insufficient evidence of function execution", testedRole, testResp.StatusCode),
			EvidenceDetails: details,
		}
	}

	// 3. Evaluate Protected Response Marker if specified
	if policy.ProtectedResponseMarker != "" {
		if strings.Contains(string(testResp.Body), policy.ProtectedResponseMarker) {
			details["marker_matched"] = policy.ProtectedResponseMarker
			severity := "HIGH"
			if policy.Category == CategoryBFLAWriteMutation || policy.Category == CategoryBFLAAdminEndpoint {
				severity = "HIGH"
			}
			return ComparisonResult{
				State:           StateVerified,
				Severity:        severity,
				Confidence:      "CONFIRMED",
				EvidenceSummary: fmt.Sprintf("Privileged function executed by lower-privilege role %s; response contained designated protected marker %q (HTTP %d)", testedRole, policy.ProtectedResponseMarker, testResp.StatusCode),
				EvidenceDetails: details,
			}
		}

		// Status 200 without designated marker -> candidate, not verified
		return ComparisonResult{
			State:           StateCandidate,
			Severity:        "MEDIUM",
			Confidence:      "POSSIBLE",
			EvidenceSummary: fmt.Sprintf("Lower-privilege role %s received status %d on %s %s, but response did not contain designated protected marker %q", testedRole, testResp.StatusCode, policy.Method, policy.Path, policy.ProtectedResponseMarker),
			EvidenceDetails: details,
		}
	}

	// 4. Differential JSON / Content Comparison when no marker is configured
	var baselineJSON, testJSON interface{}
	errBase := json.Unmarshal(baseline.Body, &baselineJSON)
	errTest := json.Unmarshal(testResp.Body, &testJSON)

	if errBase == nil && errTest == nil {
		cleanBase := StripDynamicFields(baselineJSON)
		cleanTest := StripDynamicFields(testJSON)

		baseBytes, _ := json.Marshal(cleanBase)
		testBytes, _ := json.Marshal(cleanTest)

		if bytes.Equal(baseBytes, testBytes) {
			// If identical, verify whether this payload contains privileged indicators
			if HasPrivilegedIndicators(testResp.Body) {
				return ComparisonResult{
					State:           StateVerified,
					Severity:        "HIGH",
					Confidence:      "CONFIRMED",
					EvidenceSummary: fmt.Sprintf("Lower-privilege role %s received privileged response matching authorized role %s (status %d)", testedRole, allowedRole, testResp.StatusCode),
					EvidenceDetails: details,
				}
			}
			// Identical but no privileged indicators -> potential public static endpoint
			return ComparisonResult{
				State:           StateInconclusive,
				Severity:        "INFO",
				Confidence:      "LOW",
				EvidenceSummary: fmt.Sprintf("Both authorized role %s and lower-privilege role %s received identical non-privileged response; function may be public or static", allowedRole, testedRole),
				EvidenceDetails: details,
			}
		}
	}

	// If status is 2xx and response contains privileged indicators
	if testResp.StatusCode >= 200 && testResp.StatusCode < 300 {
		if HasPrivilegedIndicators(testResp.Body) {
			return ComparisonResult{
				State:           StateVerified,
				Severity:        "HIGH",
				Confidence:      "CONFIRMED",
				EvidenceSummary: fmt.Sprintf("Lower-privilege role %s accessed function with HTTP %d containing privileged administrative indicators", testedRole, testResp.StatusCode),
				EvidenceDetails: details,
			}
		}

		return ComparisonResult{
			State:           StateCandidate,
			Severity:        "MEDIUM",
			Confidence:      "POSSIBLE",
			EvidenceSummary: fmt.Sprintf("Lower-privilege role %s received HTTP %d on restricted function %s %s without confirmed privileged markers", testedRole, testResp.StatusCode, policy.Method, policy.Path),
			EvidenceDetails: details,
		}
	}

	// Any other status code
	return ComparisonResult{
		State:           StateInconclusive,
		Severity:        "INFO",
		Confidence:      "LOW",
		EvidenceSummary: fmt.Sprintf("Unexpected status code %d returned for lower-privilege role %s; inconclusive authorization outcome", testResp.StatusCode, testedRole),
		EvidenceDetails: details,
	}
}

// CompareMethodBypass evaluates whether an alternate HTTP method bypassed authorization after a primary method was denied.
func CompareMethodBypass(primaryResp, altResp ResponseData, policy FunctionPolicy, allowedRole, testedRole, testedAlias, altMethod string) ComparisonResult {
	details := make(map[string]string)
	details["policy_id"] = policy.FunctionID
	details["endpoint"] = policy.Path
	details["primary_method"] = policy.Method
	details["alternate_method"] = altMethod
	details["allowed_role"] = allowedRole
	details["tested_role"] = testedRole
	details["tested_alias"] = testedAlias
	details["primary_status"] = fmt.Sprintf("%d", primaryResp.StatusCode)
	details["alternate_status"] = fmt.Sprintf("%d", altResp.StatusCode)

	// If alternate method was denied with 401, 403, 404, or 405 -> authorization consistently enforced
	if altResp.StatusCode == http.StatusUnauthorized || altResp.StatusCode == http.StatusForbidden ||
		altResp.StatusCode == http.StatusNotFound || altResp.StatusCode == http.StatusMethodNotAllowed {
		return ComparisonResult{
			State:           StateNotVulnerable,
			Severity:        "INFO",
			Confidence:      "CONFIRMED",
			EvidenceSummary: fmt.Sprintf("Authorization consistently enforced; primary method %s denied (HTTP %d) and alternate method %s denied (HTTP %d)", policy.Method, primaryResp.StatusCode, altMethod, altResp.StatusCode),
			EvidenceDetails: details,
		}
	}

	// Check if alternate response is redirect to login / challenge
	if altResp.StatusCode >= 300 && altResp.StatusCode < 400 {
		loc := altResp.Header.Get("Location")
		lowLoc := strings.ToLower(loc)
		if strings.Contains(lowLoc, "login") || strings.Contains(lowLoc, "auth") || strings.Contains(lowLoc, "signin") || strings.Contains(lowLoc, "challenge") {
			return ComparisonResult{
				State:           StateNotVulnerable,
				Severity:        "INFO",
				Confidence:      "CONFIRMED",
				EvidenceSummary: fmt.Sprintf("Alternate method %s correctly redirected to auth challenge (%s) with status %d", altMethod, loc, altResp.StatusCode),
				EvidenceDetails: details,
			}
		}
	}

	// Check HTML login page or generic error JSON
	if IsHTMLOrLoginPage(altResp) {
		return ComparisonResult{
			State:           StateNotVulnerable,
			Severity:        "INFO",
			Confidence:      "CONFIRMED",
			EvidenceSummary: fmt.Sprintf("Alternate method %s returned HTML challenge page (HTTP %d); function not executed", altMethod, altResp.StatusCode),
			EvidenceDetails: details,
		}
	}
	if IsGenericErrorJSON(altResp.Body) {
		return ComparisonResult{
			State:           StateNotVulnerable,
			Severity:        "INFO",
			Confidence:      "CONFIRMED",
			EvidenceSummary: fmt.Sprintf("Alternate method %s returned application error payload (HTTP %d); function not executed", altMethod, altResp.StatusCode),
			EvidenceDetails: details,
		}
	}

	// Empty body -> inconclusive
	if IsEmptyResponse(altResp.Body) {
		return ComparisonResult{
			State:           StateInconclusive,
			Severity:        "INFO",
			Confidence:      "LOW",
			EvidenceSummary: fmt.Sprintf("Alternate method %s returned empty body (HTTP %d); insufficient evidence of function execution", altMethod, altResp.StatusCode),
			EvidenceDetails: details,
		}
	}

	// If alternate method returned 2xx:
	// A 2xx response alone NEVER confirms BFLA without evidence of privileged execution!
	if altResp.StatusCode >= 200 && altResp.StatusCode < 300 {
		if policy.ProtectedResponseMarker != "" {
			if strings.Contains(string(altResp.Body), policy.ProtectedResponseMarker) {
				details["marker_matched"] = policy.ProtectedResponseMarker
				return ComparisonResult{
					State:           StateVerified,
					Severity:        "HIGH",
					Confidence:      "CONFIRMED",
					EvidenceSummary: fmt.Sprintf("BFLA Method Bypass verified: primary method %s was denied (HTTP %d), but alternate method %s successfully executed privileged function confirmed by protected marker %q (HTTP %d)", policy.Method, primaryResp.StatusCode, altMethod, policy.ProtectedResponseMarker, altResp.StatusCode),
					EvidenceDetails: details,
				}
			}
			// 2xx without protected marker -> CANDIDATE
			return ComparisonResult{
				State:           StateCandidate,
				Severity:        "MEDIUM",
				Confidence:      "POSSIBLE",
				EvidenceSummary: fmt.Sprintf("Primary method %s was denied (HTTP %d), and alternate method %s returned HTTP %d, but response did not contain designated protected marker %q; function execution unconfirmed", policy.Method, primaryResp.StatusCode, altMethod, altResp.StatusCode, policy.ProtectedResponseMarker),
				EvidenceDetails: details,
			}
		}

		// When no marker configured, require privileged indicators
		if HasPrivilegedIndicators(altResp.Body) {
			return ComparisonResult{
				State:           StateVerified,
				Severity:        "HIGH",
				Confidence:      "CONFIRMED",
				EvidenceSummary: fmt.Sprintf("BFLA Method Bypass verified: primary method %s was denied (HTTP %d), but alternate method %s returned HTTP %d with confirmed privileged administrative data", policy.Method, primaryResp.StatusCode, altMethod, altResp.StatusCode),
				EvidenceDetails: details,
			}
		}

		return ComparisonResult{
			State:           StateCandidate,
			Severity:        "MEDIUM",
			Confidence:      "POSSIBLE",
			EvidenceSummary: fmt.Sprintf("Primary method %s was denied (HTTP %d), and alternate method %s returned HTTP %d without confirmed privileged indicators; function execution unconfirmed", policy.Method, primaryResp.StatusCode, altMethod, altResp.StatusCode),
			EvidenceDetails: details,
		}
	}

	return ComparisonResult{
		State:           StateInconclusive,
		Severity:        "INFO",
		Confidence:      "LOW",
		EvidenceSummary: fmt.Sprintf("Alternate method %s returned unexpected status %d; inconclusive authorization outcome", altMethod, altResp.StatusCode),
		EvidenceDetails: details,
	}
}
