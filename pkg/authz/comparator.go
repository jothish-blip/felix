package authz

import (
	"encoding/json"
	"fmt"
	"strings"
)

// ResponseData holds the essential parsed data from an HTTP transaction.
type ResponseData struct {
	StatusCode int
	Body       []byte
	Headers    map[string]string
}

// Comparator evaluates test execution outcomes against baseline expectations.
type Comparator struct{}

// NewComparator creates an authorization response comparator.
func NewComparator() *Comparator {
	return &Comparator{}
}

// Compare evaluates a test response against the baseline and authorization policy.
func (c *Comparator) Compare(
	tc *AuthzTestCase,
	testResp *ResponseData,
	baselineResp *ResponseData,
	res *TestResource,
) *AuthzTestResult {
	result := &AuthzTestResult{
		TestCaseID:       tc.ID,
		Category:         tc.Category,
		Endpoint:         tc.Endpoint,
		Method:           tc.Method,
		PrimaryIdentity:  tc.PrimaryIdentity,
		BaselineIdentity: tc.BaselineIdentity,
		TargetResource:   tc.TargetResource,
		ObservedStatus:   testResp.StatusCode,
	}

	if baselineResp != nil {
		result.BaselineStatus = baselineResp.StatusCode
	}

	// 1. Evaluate BOLA / IDOR Tests
	if tc.Category == CategoryBOLA {
		c.evaluateBOLA(tc, testResp, baselineResp, res, result)
		return result
	}

	// 2. Evaluate BFLA Tests
	if tc.Category == CategoryBFLA {
		c.evaluateBFLA(tc, testResp, baselineResp, result)
		return result
	}

	// 3. Evaluate BOPLA Property Exposure Tests
	if tc.Category == CategoryBOPLAExposure {
		c.evaluateBOPLAExposure(tc, testResp, result)
		return result
	}

	// 4. Evaluate BOPLA Property Modification Tests
	if tc.Category == CategoryBOPLAModification {
		c.evaluateBOPLAModification(tc, testResp, result)
		return result
	}

	// 5. Evaluate Cross-Tenant / Horizontal Escalation Tests
	if tc.Category == CategoryHorizontalEsc {
		c.evaluateHorizontalEsc(tc, testResp, baselineResp, res, result)
		return result
	}

	return result
}

func (c *Comparator) evaluateBOLA(
	tc *AuthzTestCase,
	testResp *ResponseData,
	baselineResp *ResponseData,
	res *TestResource,
	result *AuthzTestResult,
) {
	// Baseline or Shared resource access
	if tc.ExpectedResult == ExpectedAllow {
		if testResp.StatusCode == 200 {
			result.VerificationState = StateNotVulnerable
			result.EvidenceSummary = fmt.Sprintf("Authorized access succeeded as expected (HTTP 200) for %q", tc.PrimaryIdentity)
		} else {
			result.VerificationState = StateInconclusive
			result.EvidenceSummary = fmt.Sprintf("Baseline request returned HTTP %d (expected 200); target may be down or require different auth", testResp.StatusCode)
		}
		return
	}

	// Cross-user test: Expected DENY
	if testResp.StatusCode == 401 || testResp.StatusCode == 403 || testResp.StatusCode == 404 {
		result.VerificationState = StateNotVulnerable
		result.EvidenceSummary = fmt.Sprintf("Access correctly denied (HTTP %d) when unauthorized identity %q accessed %q",
			testResp.StatusCode, tc.PrimaryIdentity, tc.TargetResource)
		return
	}

	// If server responded with HTTP 200, perform deep response analysis
	if testResp.StatusCode == 200 {
		trimmedBody := strings.TrimSpace(string(testResp.Body))

		// False-positive check 1: Empty body or trivial "{}"
		if trimmedBody == "" || trimmedBody == "{}" || trimmedBody == "[]" {
			result.VerificationState = StateCandidate
			result.EvidenceSummary = fmt.Sprintf("HTTP 200 returned but response payload was empty; unverified whether data is protected")
			return
		}

		// False-positive check 2: Generic error message disguised as HTTP 200
		lowerBody := strings.ToLower(trimmedBody)
		if strings.Contains(lowerBody, "access denied") || strings.Contains(lowerBody, "unauthorized") ||
			strings.Contains(lowerBody, "permission denied") || strings.Contains(lowerBody, "not found") {
			result.VerificationState = StateNotVulnerable
			result.EvidenceSummary = fmt.Sprintf("Application-level denial detected in HTTP 200 body ('%s')", truncateString(trimmedBody, 80))
			return
		}

		// Verification: Does the response disclose the target resource's data?
		hasResourceID := tc.TargetResource != "" && strings.Contains(trimmedBody, tc.TargetResource)
		hasOwnerMarker := res != nil && res.OwnerAlias != "" && strings.Contains(trimmedBody, res.OwnerAlias)

		if hasResourceID || hasOwnerMarker || (baselineResp != nil && len(baselineResp.Body) > 10 && strings.Contains(trimmedBody, string(baselineResp.Body[:min(len(baselineResp.Body), 30)]))) {
			result.VerificationState = StateVerified
			result.DisclosedData = true
			result.EvidenceSummary = fmt.Sprintf("CONFIRMED BOLA/IDOR: Identity %q successfully retrieved private %s %q belonging to %q (HTTP 200 with resource data)",
				tc.PrimaryIdentity, resType(res), tc.TargetResource, resOwner(res))
			result.CorrelatedCategory = CategoryHorizontalEsc
		} else {
			result.VerificationState = StateCandidate
			result.EvidenceSummary = fmt.Sprintf("Endpoint returned HTTP 200 but returned data does not unambiguously match private resource %q", tc.TargetResource)
		}
		return
	}

	result.VerificationState = StateInconclusive
	result.EvidenceSummary = fmt.Sprintf("Ambiguous response status HTTP %d during cross-user access test", testResp.StatusCode)
}

func (c *Comparator) evaluateBFLA(
	tc *AuthzTestCase,
	testResp *ResponseData,
	baselineResp *ResponseData,
	result *AuthzTestResult,
) {
	if tc.ExpectedResult == ExpectedAllow {
		if testResp.StatusCode == 200 || testResp.StatusCode == 204 {
			result.VerificationState = StateNotVulnerable
			result.EvidenceSummary = fmt.Sprintf("Authorized role access succeeded as expected (HTTP %d)", testResp.StatusCode)
		} else {
			result.VerificationState = StateInconclusive
			result.EvidenceSummary = fmt.Sprintf("Baseline admin request returned HTTP %d (expected 200)", testResp.StatusCode)
		}
		return
	}

	// Expected DENY
	if testResp.StatusCode == 401 || testResp.StatusCode == 403 || testResp.StatusCode == 404 {
		result.VerificationState = StateNotVulnerable
		result.EvidenceSummary = fmt.Sprintf("Function access correctly denied (HTTP %d) for unprivileged identity %q",
			testResp.StatusCode, tc.PrimaryIdentity)
		return
	}

	if testResp.StatusCode == 200 || testResp.StatusCode == 201 || testResp.StatusCode == 204 {
		trimmedBody := strings.TrimSpace(string(testResp.Body))
		lowerBody := strings.ToLower(trimmedBody)

		if strings.Contains(lowerBody, "access denied") || strings.Contains(lowerBody, "forbidden") {
			result.VerificationState = StateNotVulnerable
			result.EvidenceSummary = "Application-level denial message returned in response body"
			return
		}

		result.VerificationState = StateVerified
		result.EvidenceSummary = fmt.Sprintf("CONFIRMED BFLA: Unprivileged identity %q successfully invoked restricted function %s (HTTP %d)",
			tc.PrimaryIdentity, tc.Endpoint, testResp.StatusCode)
		result.CorrelatedCategory = CategoryVerticalEsc
		return
	}

	result.VerificationState = StateInconclusive
	result.EvidenceSummary = fmt.Sprintf("Inconclusive HTTP %d response during function-level access test", testResp.StatusCode)
}

func (c *Comparator) evaluateBOPLAExposure(
	tc *AuthzTestCase,
	testResp *ResponseData,
	result *AuthzTestResult,
) {
	if testResp.StatusCode != 200 {
		result.VerificationState = StateNotVulnerable
		result.EvidenceSummary = fmt.Sprintf("Endpoint returned HTTP %d; no properties exposed", testResp.StatusCode)
		return
	}

	// Check if JSON body exposes the sensitive property key
	var data any
	if err := json.Unmarshal(testResp.Body, &data); err != nil {
		result.VerificationState = StateInconclusive
		result.EvidenceSummary = "Non-JSON response received during property-exposure evaluation"
		return
	}

	if jsonContainsProperty(data, tc.PropertyKey) {
		result.VerificationState = StateVerified
		result.DisclosedData = true
		result.EvidenceSummary = fmt.Sprintf("CONFIRMED BOPLA (Exposure): Sensitive property %q was exposed in response body to unauthorized identity %q",
			tc.PropertyKey, tc.PrimaryIdentity)
	} else {
		result.VerificationState = StateNotVulnerable
		result.EvidenceSummary = fmt.Sprintf("Sensitive property %q was omitted or redacted from response", tc.PropertyKey)
	}
}

func (c *Comparator) evaluateBOPLAModification(
	tc *AuthzTestCase,
	testResp *ResponseData,
	result *AuthzTestResult,
) {
	// Standard rejection status codes
	if testResp.StatusCode == 400 || testResp.StatusCode == 401 || testResp.StatusCode == 403 ||
		testResp.StatusCode == 422 || testResp.StatusCode == 405 {
		result.VerificationState = StateNotVulnerable
		result.EvidenceSummary = fmt.Sprintf("Unauthorized property modification rejected by server (HTTP %d)", testResp.StatusCode)
		return
	}

	if testResp.StatusCode == 200 || testResp.StatusCode == 201 || testResp.StatusCode == 204 {
		// Verify whether the modified property was actually reflected/accepted
		var data any
		if err := json.Unmarshal(testResp.Body, &data); err == nil {
			if jsonHasPropertyValue(data, tc.PropertyKey, tc.PropertyValue) {
				result.VerificationState = StateVerified
				result.PropertyModified = true
				result.EvidenceSummary = fmt.Sprintf("CONFIRMED BOPLA (Modification): Unauthorized modification of protected property %q to %q succeeded (HTTP %d with property accepted)",
					tc.PropertyKey, tc.PropertyValue, testResp.StatusCode)
				result.CorrelatedCategory = CategoryVerticalEsc
				return
			}
		}

		result.VerificationState = StateCandidate
		result.EvidenceSummary = fmt.Sprintf("Server returned HTTP %d to modification request; unverified whether forbidden change took effect", testResp.StatusCode)
		return
	}

	result.VerificationState = StateInconclusive
	result.EvidenceSummary = fmt.Sprintf("Inconclusive HTTP %d response during property modification test", testResp.StatusCode)
}

func (c *Comparator) evaluateHorizontalEsc(
	tc *AuthzTestCase,
	testResp *ResponseData,
	baselineResp *ResponseData,
	res *TestResource,
	result *AuthzTestResult,
) {
	c.evaluateBOLA(tc, testResp, baselineResp, res, result)
	if result.VerificationState == StateVerified {
		result.EvidenceSummary = fmt.Sprintf("CONFIRMED HORIZONTAL ESCALATION: Identity %q breached tenant/isolation boundary accessing %q (HTTP 200)",
			tc.PrimaryIdentity, tc.TargetResource)
	}
}

func jsonContainsProperty(v any, key string) bool {
	switch val := v.(type) {
	case map[string]any:
		for k, item := range val {
			if strings.EqualFold(k, key) {
				return true
			}
			if jsonContainsProperty(item, key) {
				return true
			}
		}
	case []any:
		for _, item := range val {
			if jsonContainsProperty(item, key) {
				return true
			}
		}
	}
	return false
}

func jsonHasPropertyValue(v any, key, targetVal string) bool {
	switch val := v.(type) {
	case map[string]any:
		for k, item := range val {
			if strings.EqualFold(k, key) {
				strVal := fmt.Sprintf("%v", item)
				if strings.EqualFold(strVal, targetVal) {
					return true
				}
			}
			if jsonHasPropertyValue(item, key, targetVal) {
				return true
			}
		}
	case []any:
		for _, item := range val {
			if jsonHasPropertyValue(item, key, targetVal) {
				return true
			}
		}
	}
	return false
}

func resType(res *TestResource) string {
	if res == nil || res.Type == "" {
		return "resource"
	}
	return res.Type
}

func resOwner(res *TestResource) string {
	if res == nil || res.OwnerAlias == "" {
		return "another user"
	}
	return res.OwnerAlias
}

func truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
