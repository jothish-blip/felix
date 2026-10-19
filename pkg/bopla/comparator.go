package bopla

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
)

// ExtractProperty extracts a value from a nested JSON structure using a property path.
// Supports dot notation ("user.profile.role") and array indexing ("roles[0].level").
func ExtractProperty(data any, path string) (any, bool) {
	if data == nil || path == "" {
		return nil, false
	}

	tokens := parsePropertyTokens(path)
	if len(tokens) == 0 {
		return nil, false
	}

	curr := data
	for _, tok := range tokens {
		switch tok.kind {
		case tokenKey:
			m, ok := curr.(map[string]any)
			if !ok {
				return nil, false
			}
			val, exists := m[tok.name]
			if !exists {
				// Case-insensitive lookup fallback
				foundCI := false
				for k, v := range m {
					if strings.EqualFold(k, tok.name) {
						val = v
						foundCI = true
						break
					}
				}
				if !foundCI {
					return nil, false
				}
			}
			curr = val
		case tokenIndex:
			slice, ok := curr.([]any)
			if !ok || tok.index < 0 || tok.index >= len(slice) {
				return nil, false
			}
			curr = slice[tok.index]
		}
	}
	return curr, true
}

type tokenKind int

const (
	tokenKey tokenKind = iota
	tokenIndex
)

type propToken struct {
	kind  tokenKind
	name  string
	index int
}

func parsePropertyTokens(path string) []propToken {
	var tokens []propToken
	parts := strings.Split(path, ".")

	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}

		for len(p) > 0 {
			openBracket := strings.Index(p, "[")
			if openBracket == -1 {
				tokens = append(tokens, propToken{kind: tokenKey, name: p})
				break
			}

			if openBracket > 0 {
				keyName := p[:openBracket]
				tokens = append(tokens, propToken{kind: tokenKey, name: keyName})
			}

			closeBracket := strings.Index(p[openBracket:], "]")
			if closeBracket == -1 {
				// Malformed bracket, treat rest as key
				tokens = append(tokens, propToken{kind: tokenKey, name: p[openBracket:]})
				break
			}
			closeBracket += openBracket

			idxStr := p[openBracket+1 : closeBracket]
			idx, err := strconv.Atoi(idxStr)
			if err == nil {
				tokens = append(tokens, propToken{kind: tokenIndex, index: idx})
			}
			p = p[closeBracket+1:]
		}
	}
	return tokens
}

// IsPropertyEqual compares two values for semantic equality across common JSON scalar types.
func IsPropertyEqual(a, b any) bool {
	if a == nil && b == nil {
		return true
	}
	if a == nil || b == nil {
		return false
	}

	// Exact type match
	if a == b {
		return true
	}

	// String comparison
	strA := fmt.Sprintf("%v", a)
	strB := fmt.Sprintf("%v", b)
	if strings.EqualFold(strings.TrimSpace(strA), strings.TrimSpace(strB)) {
		return true
	}

	// Numeric comparison (JSON numbers decode as float64)
	numA, errA := toFloat(a)
	numB, errB := toFloat(b)
	if errA == nil && errB == nil {
		return numA == numB
	}

	// Boolean comparison
	boolA, errA := toBool(a)
	boolB, errB := toBool(b)
	if errA == nil && errB == nil {
		return boolA == boolB
	}

	return false
}

func toFloat(val any) (float64, error) {
	switch v := val.(type) {
	case float64:
		return v, nil
	case float32:
		return float64(v), nil
	case int:
		return float64(v), nil
	case int64:
		return float64(v), nil
	case string:
		return strconv.ParseFloat(strings.TrimSpace(v), 64)
	default:
		return 0, fmt.Errorf("not a float")
	}
}

func toBool(val any) (bool, error) {
	switch v := val.(type) {
	case bool:
		return v, nil
	case string:
		return strconv.ParseBool(strings.TrimSpace(v))
	default:
		return 0 != 0, fmt.Errorf("not a bool")
	}
}

// IsMasked verifies if a property value satisfies a masking expectation.
func IsMasked(val any, maskPattern string) bool {
	if val == nil {
		return true
	}
	s := strings.TrimSpace(fmt.Sprintf("%v", val))
	if maskPattern != "" && strings.Contains(s, maskPattern) {
		return true
	}
	// Common masking patterns
	if strings.Contains(s, "****") || strings.Contains(s, "***") || strings.Contains(s, "xxxx") ||
		strings.Contains(s, "[REDACTED]") || strings.Contains(s, "[MASKED]") || strings.Contains(s, "[HIDDEN]") {
		return true
	}
	return false
}

// IsHTMLOrLoginPage detects whether a response is an HTML page or login challenge.
func IsHTMLOrLoginPage(resp ResponseData) bool {
	for k, vals := range resp.Header {
		if strings.EqualFold(k, "Content-Type") {
			for _, v := range vals {
				if strings.Contains(strings.ToLower(v), "text/html") {
					return true
				}
			}
		}
	}
	low := strings.ToLower(string(resp.Body))
	return strings.Contains(low, "<!doctype html") ||
		strings.Contains(low, "<html") ||
		strings.Contains(low, "<form") && strings.Contains(low, "password")
}

// IsGenericErrorJSON checks if the response body is a standard API error object.
func IsGenericErrorJSON(body []byte) bool {
	if len(body) == 0 {
		return false
	}
	var data map[string]any
	if err := json.Unmarshal(body, &data); err != nil {
		return false
	}
	for k, v := range data {
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

// IsEmptyResponse returns true if response body is empty or whitespace only.
func IsEmptyResponse(body []byte) bool {
	return len(strings.TrimSpace(string(body))) == 0
}

// ComparePropertyRead evaluates unauthorized read access against an authorized baseline and policy.
func ComparePropertyRead(baseline, testResp ResponseData, policy PropertyPolicy, allowedRole, testedRole, testedAlias string) ComparisonResult {
	details := make(map[string]string)
	details["policy_id"] = policy.PropertyID
	details["endpoint"] = policy.Endpoint
	details["property_path"] = policy.PropertyPath
	details["allowed_role"] = allowedRole
	details["tested_role"] = testedRole
	details["tested_alias"] = testedAlias
	details["expected_access"] = string(policy.ExpectedAccess)
	details["baseline_status"] = fmt.Sprintf("%d", baseline.StatusCode)
	details["test_status"] = fmt.Sprintf("%d", testResp.StatusCode)

	// Step 1: Baseline Verification
	if baseline.StatusCode < 200 || baseline.StatusCode >= 300 {
		return ComparisonResult{
			State:           StateInconclusive,
			Severity:        "INFO",
			Confidence:      "LOW",
			EvidenceSummary: fmt.Sprintf("Authorized baseline did not return HTTP 200 (HTTP %d); cannot establish property presence", baseline.StatusCode),
			EvidenceDetails: details,
		}
	}

	var baseData any
	if err := json.Unmarshal(baseline.Body, &baseData); err != nil {
		return ComparisonResult{
			State:           StateInconclusive,
			Severity:        "INFO",
			Confidence:      "LOW",
			EvidenceSummary: "Authorized baseline returned non-JSON body; cannot parse object properties",
			EvidenceDetails: details,
		}
	}

	baseVal, baseFound := ExtractProperty(baseData, policy.PropertyPath)
	if !baseFound {
		return ComparisonResult{
			State:           StateInconclusive,
			Severity:        "INFO",
			Confidence:      "LOW",
			EvidenceSummary: fmt.Sprintf("Authorized baseline does not expose property %q; baseline property presence unconfirmed", policy.PropertyPath),
			EvidenceDetails: details,
		}
	}
	details["baseline_property_present"] = "true"

	// Step 2: Test Response Evaluation
	// If test response was denied with standard authorization rejection:
	if testResp.StatusCode == http.StatusUnauthorized || testResp.StatusCode == http.StatusForbidden ||
		testResp.StatusCode == http.StatusNotFound || testResp.StatusCode == http.StatusMethodNotAllowed {
		return ComparisonResult{
			State:           StateNotVulnerable,
			Severity:        "INFO",
			Confidence:      "CONFIRMED",
			EvidenceSummary: fmt.Sprintf("Access denied (HTTP %d); protected property %q not disclosed to role %s", testResp.StatusCode, policy.PropertyPath, testedRole),
			EvidenceDetails: details,
		}
	}

	// Check login/challenge redirect
	if testResp.StatusCode >= 300 && testResp.StatusCode < 400 {
		loc := testResp.Header["Location"]
		if len(loc) > 0 && (strings.Contains(strings.ToLower(loc[0]), "login") || strings.Contains(strings.ToLower(loc[0]), "auth")) {
			return ComparisonResult{
				State:           StateNotVulnerable,
				Severity:        "INFO",
				Confidence:      "CONFIRMED",
				EvidenceSummary: fmt.Sprintf("Redirected to auth challenge (%s); protected property %q not disclosed", loc[0], policy.PropertyPath),
				EvidenceDetails: details,
			}
		}
	}

	// Check HTML login page or generic error JSON
	if IsHTMLOrLoginPage(testResp) {
		return ComparisonResult{
			State:           StateNotVulnerable,
			Severity:        "INFO",
			Confidence:      "CONFIRMED",
			EvidenceSummary: fmt.Sprintf("Endpoint returned HTML login challenge (HTTP %d); protected property %q not disclosed", testResp.StatusCode, policy.PropertyPath),
			EvidenceDetails: details,
		}
	}
	if IsGenericErrorJSON(testResp.Body) {
		return ComparisonResult{
			State:           StateNotVulnerable,
			Severity:        "INFO",
			Confidence:      "CONFIRMED",
			EvidenceSummary: fmt.Sprintf("Endpoint returned error JSON (HTTP %d); protected property %q not disclosed", testResp.StatusCode, policy.PropertyPath),
			EvidenceDetails: details,
		}
	}

	// Empty body -> Inconclusive
	if IsEmptyResponse(testResp.Body) {
		return ComparisonResult{
			State:           StateInconclusive,
			Severity:        "INFO",
			Confidence:      "LOW",
			EvidenceSummary: fmt.Sprintf("Endpoint returned empty body (HTTP %d); insufficient evidence of property exposure", testResp.StatusCode),
			EvidenceDetails: details,
		}
	}

	// Step 3: Test Body JSON Parsing & Property Extraction
	var testData any
	if err := json.Unmarshal(testResp.Body, &testData); err != nil {
		return ComparisonResult{
			State:           StateInconclusive,
			Severity:        "INFO",
			Confidence:      "LOW",
			EvidenceSummary: "Test identity received non-JSON response body; cannot parse object properties",
			EvidenceDetails: details,
		}
	}

	testVal, testFound := ExtractProperty(testData, policy.PropertyPath)
	if !testFound {
		// Property was omitted from test identity's response!
		return ComparisonResult{
			State:           StateNotVulnerable,
			Severity:        "INFO",
			Confidence:      "CONFIRMED",
			EvidenceSummary: fmt.Sprintf("Authorization enforced: protected property %q was omitted from response for unauthorized role %s", policy.PropertyPath, testedRole),
			EvidenceDetails: details,
		}
	}

	// Step 4: Policy Enforcement Evaluation
	// Property IS present in test identity's response!
	switch policy.ExpectedAccess {
	case ExpectedMasked:
		if IsMasked(testVal, policy.MaskPattern) {
			details["masked_value"] = fmt.Sprintf("%v", testVal)
			return ComparisonResult{
				State:           StateNotVulnerable,
				Severity:        "INFO",
				Confidence:      "CONFIRMED",
				EvidenceSummary: fmt.Sprintf("Authorization enforced: property %q was properly masked (%v) for role %s", policy.PropertyPath, testVal, testedRole),
				EvidenceDetails: details,
			}
		}
		// Unmasked disclosure!
		details["exposed_value_redacted"] = RedactValue(testVal)
		return ComparisonResult{
			State:           StateVerified,
			Severity:        "HIGH",
			Confidence:      "CONFIRMED",
			EvidenceSummary: fmt.Sprintf("BOPLA Excessive Data Exposure verified: property %q was expected to be masked (%q) but was exposed in unmasked cleartext (%s) to unauthorized role %s", policy.PropertyPath, policy.MaskPattern, RedactValue(testVal), testedRole),
			EvidenceDetails: details,
		}

	case ExpectedOmitted, ExpectedAuthorizedOnly:
		// If testVal is explicit null and baseline was not null, server withheld the value
		if testVal == nil && baseVal != nil {
			return ComparisonResult{
				State:           StateNotVulnerable,
				Severity:        "INFO",
				Confidence:      "CONFIRMED",
				EvidenceSummary: fmt.Sprintf("Authorization enforced: property %q value was withheld (null) for unauthorized role %s", policy.PropertyPath, testedRole),
				EvidenceDetails: details,
			}
		}

		// If protected response marker configured, verify presence
		if policy.ProtectedResponseMarker != "" {
			if !strings.Contains(string(testResp.Body), policy.ProtectedResponseMarker) {
				return ComparisonResult{
					State:           StateCandidate,
					Severity:        "MEDIUM",
					Confidence:      "POSSIBLE",
					EvidenceSummary: fmt.Sprintf("Property %q was present, but protected marker %q was not found in response; property exposure unconfirmed", policy.PropertyPath, policy.ProtectedResponseMarker),
					EvidenceDetails: details,
				}
			}
		}

		details["exposed_value_redacted"] = RedactValue(testVal)
		return ComparisonResult{
			State:           StateVerified,
			Severity:        "HIGH",
			Confidence:      "CONFIRMED",
			EvidenceSummary: fmt.Sprintf("BOPLA Property Read verified: unauthorized role %s received protected property %q (value: %s)", testedRole, policy.PropertyPath, RedactValue(testVal)),
			EvidenceDetails: details,
		}

	default:
		// Default rule: compare against baseline
		if IsPropertyEqual(testVal, baseVal) {
			details["exposed_value_redacted"] = RedactValue(testVal)
			return ComparisonResult{
				State:           StateVerified,
				Severity:        "HIGH",
				Confidence:      "CONFIRMED",
				EvidenceSummary: fmt.Sprintf("BOPLA Property Read verified: unauthorized role %s received restricted property %q matching authorized baseline", testedRole, policy.PropertyPath),
				EvidenceDetails: details,
			}
		}
		return ComparisonResult{
			State:           StateCandidate,
			Severity:        "MEDIUM",
			Confidence:      "POSSIBLE",
			EvidenceSummary: fmt.Sprintf("Property %q was present in response with different value; exposure unconfirmed", policy.PropertyPath),
			EvidenceDetails: details,
		}
	}
}

// ComparePropertyMutation evaluates unauthorized write or mass-assignment modification.
func ComparePropertyMutation(baseline, mutationResp, readBackResp ResponseData, policy PropertyPolicy, allowedRole, testedRole, testedAlias string) ComparisonResult {
	details := make(map[string]string)
	details["policy_id"] = policy.PropertyID
	details["endpoint"] = policy.Endpoint
	details["property_path"] = policy.PropertyPath
	details["allowed_role"] = allowedRole
	details["tested_role"] = testedRole
	details["tested_alias"] = testedAlias
	details["mutation_status"] = fmt.Sprintf("%d", mutationResp.StatusCode)
	details["readback_status"] = fmt.Sprintf("%d", readBackResp.StatusCode)

	// Step 1: Rejection Status Check
	if mutationResp.StatusCode == http.StatusBadRequest ||
		mutationResp.StatusCode == http.StatusUnauthorized ||
		mutationResp.StatusCode == http.StatusForbidden ||
		mutationResp.StatusCode == http.StatusNotFound ||
		mutationResp.StatusCode == http.StatusMethodNotAllowed ||
		mutationResp.StatusCode == http.StatusUnprocessableEntity {
		return ComparisonResult{
			State:           StateNotVulnerable,
			Severity:        "INFO",
			Confidence:      "CONFIRMED",
			EvidenceSummary: fmt.Sprintf("Server rejected unauthorized property mutation with HTTP %d", mutationResp.StatusCode),
			EvidenceDetails: details,
		}
	}

	if IsHTMLOrLoginPage(mutationResp) || IsGenericErrorJSON(mutationResp.Body) {
		return ComparisonResult{
			State:           StateNotVulnerable,
			Severity:        "INFO",
			Confidence:      "CONFIRMED",
			EvidenceSummary: fmt.Sprintf("Server rejected unauthorized property mutation with application error (HTTP %d)", mutationResp.StatusCode),
			EvidenceDetails: details,
		}
	}

	// Step 2: 2xx Status Handling & Read-Back Verification
	if mutationResp.StatusCode >= 200 && mutationResp.StatusCode < 300 {
		// A 2xx response or echoed payload alone NEVER confirms BOPLA mutation!
		if readBackResp.StatusCode == 0 {
			return ComparisonResult{
				State:           StateCandidate,
				Severity:        "MEDIUM",
				Confidence:      "POSSIBLE",
				EvidenceSummary: fmt.Sprintf("Server returned HTTP %d to mutation request, but independent read-back was not available; property persistence unconfirmed", mutationResp.StatusCode),
				EvidenceDetails: details,
			}
		}

		if readBackResp.StatusCode < 200 || readBackResp.StatusCode >= 300 {
			return ComparisonResult{
				State:           StateCandidate,
				Severity:        "MEDIUM",
				Confidence:      "POSSIBLE",
				EvidenceSummary: fmt.Sprintf("Server returned HTTP %d to mutation request, but read-back failed with HTTP %d; property persistence unconfirmed", mutationResp.StatusCode, readBackResp.StatusCode),
				EvidenceDetails: details,
			}
		}

		var readBackData any
		if err := json.Unmarshal(readBackResp.Body, &readBackData); err != nil {
			return ComparisonResult{
				State:           StateCandidate,
				Severity:        "MEDIUM",
				Confidence:      "POSSIBLE",
				EvidenceSummary: fmt.Sprintf("Server returned HTTP %d to mutation, but read-back returned non-JSON body; persistence unconfirmed", mutationResp.StatusCode),
				EvidenceDetails: details,
			}
		}

		readBackVal, found := ExtractProperty(readBackData, policy.PropertyPath)
		if !found {
			return ComparisonResult{
				State:           StateCandidate,
				Severity:        "MEDIUM",
				Confidence:      "POSSIBLE",
				EvidenceSummary: fmt.Sprintf("Server returned HTTP %d to mutation, but property %q was not found in read-back", mutationResp.StatusCode, policy.PropertyPath),
				EvidenceDetails: details,
			}
		}

		// Check if property actually modified to the unauthorized mutation value
		if IsPropertyEqual(readBackVal, policy.MutationValue) {
			details["persisted_value_redacted"] = RedactValue(readBackVal)
			return ComparisonResult{
				State:           StateVerified,
				Severity:        "HIGH",
				Confidence:      "CONFIRMED",
				EvidenceSummary: fmt.Sprintf("BOPLA Property Mutation verified: unauthorized role %s modified protected property %q to %q (HTTP %d), confirmed persisted via independent read-back", testedRole, policy.PropertyPath, RedactValue(policy.MutationValue), mutationResp.StatusCode),
				EvidenceDetails: details,
			}
		}

		// Server returned 200, but read-back shows property was NOT changed (safely ignored/discarded)
		return ComparisonResult{
			State:           StateNotVulnerable,
			Severity:        "INFO",
			Confidence:      "CONFIRMED",
			EvidenceSummary: fmt.Sprintf("Server returned HTTP %d to mutation request, but safely ignored unauthorized property %q; read-back confirmed property remained %v", mutationResp.StatusCode, policy.PropertyPath, readBackVal),
			EvidenceDetails: details,
		}
	}

	return ComparisonResult{
		State:           StateInconclusive,
		Severity:        "INFO",
		Confidence:      "LOW",
		EvidenceSummary: fmt.Sprintf("Mutation request returned unexpected status HTTP %d; inconclusive authorization outcome", mutationResp.StatusCode),
		EvidenceDetails: details,
	}
}
