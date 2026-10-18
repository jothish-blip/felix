package bola

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

// ResponseData captures essential elements of an HTTP response for BOLA comparison.
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
// during JSON response comparison while strictly preserving object IDs and ownership markers.
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

// StripDynamicFields recursively removes dynamic transient fields from a parsed JSON structure
// while strictly preserving object identifiers, user IDs, and ownership keys.
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

// CompareRead compares the baseline response (from owner) against the test response (from non-owner).
func CompareRead(baseline, cross ResponseData, obj ObjectIdentifier, ownerAlias, accessorAlias string) ComparisonResult {
	details := make(map[string]string)
	details["owner_alias"] = ownerAlias
	details["accessor_alias"] = accessorAlias
	details["object_id"] = obj.ID
	details["object_type"] = obj.Type
	details["baseline_status"] = fmt.Sprintf("%d", baseline.StatusCode)
	details["cross_status"] = fmt.Sprintf("%d", cross.StatusCode)

	// 1. Check if baseline itself is valid
	if baseline.StatusCode < 200 || baseline.StatusCode >= 300 {
		return ComparisonResult{
			State:           StateInconclusive,
			Severity:        "INFO",
			Confidence:      "LOW",
			EvidenceSummary: fmt.Sprintf("Baseline owner request failed with status %d; unable to establish valid baseline for object %s", baseline.StatusCode, obj.ID),
			EvidenceDetails: details,
		}
	}
	if IsEmptyResponse(baseline.Body) {
		return ComparisonResult{
			State:           StateInconclusive,
			Severity:        "INFO",
			Confidence:      "LOW",
			EvidenceSummary: fmt.Sprintf("Baseline owner request returned empty body; cannot verify object %s content", obj.ID),
			EvidenceDetails: details,
		}
	}

	// 2. Check non-owner response status
	// If 401 Unauthorized, 403 Forbidden, or 404 Not Found -> correctly denied or object isolated
	if cross.StatusCode == http.StatusUnauthorized || cross.StatusCode == http.StatusForbidden || cross.StatusCode == http.StatusNotFound {
		return ComparisonResult{
			State:           StateNotVulnerable,
			Severity:        "INFO",
			Confidence:      "CONFIRMED",
			EvidenceSummary: fmt.Sprintf("Access correctly denied for non-owner %s with status %d (baseline was %d)", accessorAlias, cross.StatusCode, baseline.StatusCode),
			EvidenceDetails: details,
		}
	}

	// If redirect -> check if redirecting to login/auth
	if cross.StatusCode >= 300 && cross.StatusCode < 400 {
		loc := cross.Header.Get("Location")
		if strings.Contains(strings.ToLower(loc), "login") || strings.Contains(strings.ToLower(loc), "auth") {
			return ComparisonResult{
				State:           StateNotVulnerable,
				Severity:        "INFO",
				Confidence:      "CONFIRMED",
				EvidenceSummary: fmt.Sprintf("Non-owner request redirected to authentication (%s); access prevented", loc),
				EvidenceDetails: details,
			}
		}
		return ComparisonResult{
			State:           StateInconclusive,
			Severity:        "INFO",
			Confidence:      "LOW",
			EvidenceSummary: fmt.Sprintf("Non-owner request resulted in redirect (%d to %s); inconclusive", cross.StatusCode, loc),
			EvidenceDetails: details,
		}
	}

	// If server error 5xx
	if cross.StatusCode >= 500 {
		return ComparisonResult{
			State:           StateInconclusive,
			Severity:        "INFO",
			Confidence:      "LOW",
			EvidenceSummary: fmt.Sprintf("Non-owner request caused server error (%d); inconclusive", cross.StatusCode),
			EvidenceDetails: details,
		}
	}

	// 3. Status is 200/2xx: A 200 OK status alone MUST NEVER confirm BOLA!
	// Check if cross response is an HTML page or login form (false-positive defense)
	if IsHTMLOrLoginPage(cross) {
		return ComparisonResult{
			State:           StateNotVulnerable,
			Severity:        "INFO",
			Confidence:      "CONFIRMED",
			EvidenceSummary: fmt.Sprintf("Non-owner received generic HTML or login page (status %d); protected object was not disclosed", cross.StatusCode),
			EvidenceDetails: details,
		}
	}

	// Check if cross response is empty
	if IsEmptyResponse(cross.Body) {
		return ComparisonResult{
			State:           StateNotVulnerable,
			Severity:        "INFO",
			Confidence:      "HIGH",
			EvidenceSummary: fmt.Sprintf("Non-owner received empty response (status %d); no object data disclosed", cross.StatusCode),
			EvidenceDetails: details,
		}
	}

	// Check if cross response matches public static content (e.g. static JSON or generic message)
	crossStr := string(cross.Body)
	if strings.Contains(crossStr, `"message":"unauthorized"`) || strings.Contains(crossStr, `"error":"unauthorized"`) || strings.Contains(crossStr, `"error":"forbidden"`) {
		return ComparisonResult{
			State:           StateNotVulnerable,
			Severity:        "INFO",
			Confidence:      "CONFIRMED",
			EvidenceSummary: fmt.Sprintf("Non-owner received 200 OK with explicit authorization denial error payload; access prevented"),
			EvidenceDetails: details,
		}
	}

	// 4. Inspect content and structural match
	// Check if the requested object ID is actually in the response
	containsObjectID := strings.Contains(crossStr, obj.ID)

	// Check if protected marker data is present
	containsProtectedData := false
	if obj.ProtectedData != "" && strings.Contains(crossStr, obj.ProtectedData) {
		containsProtectedData = true
	}

	// Check JSON structural similarity
	var baseJSON, crossJSON interface{}
	baseParsed := json.Unmarshal(baseline.Body, &baseJSON) == nil
	crossParsed := json.Unmarshal(cross.Body, &crossJSON) == nil

	if baseParsed && crossParsed {
		cleanBase := StripDynamicFields(baseJSON)
		cleanCross := StripDynamicFields(crossJSON)

		baseBytes, _ := json.Marshal(cleanBase)
		crossBytes, _ := json.Marshal(cleanCross)

		// If normalized payloads match and contain the object ID -> VERIFIED BOLA!
		if bytes.Equal(baseBytes, crossBytes) && (containsObjectID || containsProtectedData) {
			details["match_type"] = "exact_normalized_json_match"
			return ComparisonResult{
				State:           StateVerified,
				Severity:        "HIGH",
				Confidence:      "CONFIRMED",
				EvidenceSummary: fmt.Sprintf("BOLA verified: non-owner %s accessed owner %s's object %s and received identical protected object payload", accessorAlias, ownerAlias, obj.ID),
				EvidenceDetails: details,
			}
		}

		// Check if cross response contains the core object data fields from baseline
		if containsObjectID || containsProtectedData {
			details["match_type"] = "partial_protected_object_match"
			return ComparisonResult{
				State:           StateVerified,
				Severity:        "HIGH",
				Confidence:      "CONFIRMED",
				EvidenceSummary: fmt.Sprintf("BOLA verified: non-owner %s received object %s containing owner %s's protected data", accessorAlias, obj.ID, ownerAlias),
				EvidenceDetails: details,
			}
		}
	} else {
		// Non-JSON responses
		if containsObjectID || containsProtectedData {
			details["match_type"] = "raw_object_marker_match"
			return ComparisonResult{
				State:           StateVerified,
				Severity:        "HIGH",
				Confidence:      "CONFIRMED",
				EvidenceSummary: fmt.Sprintf("BOLA verified: non-owner %s received payload containing owner %s's object identifier %s", accessorAlias, ownerAlias, obj.ID),
				EvidenceDetails: details,
			}
		}
	}

	// 5. If 200 OK was received but object ID and protected data are absent
	details["discrepancy"] = "200 OK received but response does not contain owner's object ID or protected data"
	return ComparisonResult{
		State:           StateCandidate,
		Severity:        "LOW",
		Confidence:      "LOW",
		EvidenceSummary: fmt.Sprintf("Non-owner received status %d but response did not demonstrably disclose owner %s's object %s (candidate/inconclusive)", cross.StatusCode, ownerAlias, obj.ID),
		EvidenceDetails: details,
	}
}

// CompareWrite evaluates state-changing requests (PUT, POST, PATCH, DELETE) for BOLA.
func CompareWrite(cross ResponseData, obj ObjectIdentifier, ownerAlias, accessorAlias string, stateChangingAllowed bool) ComparisonResult {
	details := make(map[string]string)
	details["owner_alias"] = ownerAlias
	details["accessor_alias"] = accessorAlias
	details["object_id"] = obj.ID
	details["cross_status"] = fmt.Sprintf("%d", cross.StatusCode)

	if !stateChangingAllowed {
		return ComparisonResult{
			State:           StateSkipped,
			Severity:        "INFO",
			Confidence:      "LOW",
			EvidenceSummary: "State-changing BOLA tests require explicit opt-in (--allow-state-changing) and test policy; skipped safely",
			EvidenceDetails: details,
		}
	}

	// Correctly denied
	if cross.StatusCode == http.StatusUnauthorized || cross.StatusCode == http.StatusForbidden || cross.StatusCode == http.StatusNotFound {
		return ComparisonResult{
			State:           StateNotVulnerable,
			Severity:        "INFO",
			Confidence:      "CONFIRMED",
			EvidenceSummary: fmt.Sprintf("State modification correctly denied for non-owner %s with status %d", accessorAlias, cross.StatusCode),
			EvidenceDetails: details,
		}
	}

	// False positive check on login/error page
	if IsHTMLOrLoginPage(cross) {
		return ComparisonResult{
			State:           StateNotVulnerable,
			Severity:        "INFO",
			Confidence:      "CONFIRMED",
			EvidenceSummary: fmt.Sprintf("Non-owner received HTML/login page during mutation attempt (status %d); modification prevented", cross.StatusCode),
			EvidenceDetails: details,
		}
	}

	// Mutation accepted (200 OK, 201 Created, 204 No Content)
	if cross.StatusCode >= 200 && cross.StatusCode < 300 {
		return ComparisonResult{
			State:           StateVerified,
			Severity:        "CRITICAL",
			Confidence:      "CONFIRMED",
			EvidenceSummary: fmt.Sprintf("BOLA Write Mutation verified: non-owner %s successfully mutated owner %s's object %s (status %d)", accessorAlias, ownerAlias, obj.ID, cross.StatusCode),
			EvidenceDetails: details,
		}
	}

	return ComparisonResult{
		State:           StateInconclusive,
		Severity:        "LOW",
		Confidence:      "LOW",
		EvidenceSummary: fmt.Sprintf("Unexpected status %d during state modification test; inconclusive", cross.StatusCode),
		EvidenceDetails: details,
	}
}
