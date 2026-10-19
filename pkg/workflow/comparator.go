package workflow

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"felix/pkg/secrets"
)

// IsHTMLOrLoginPage detects whether a response is an HTML page or authentication challenge.
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
		(strings.Contains(low, "<form") && strings.Contains(low, "password"))
}

// IsGenericErrorJSON checks whether a 200 OK response is actually an application-level error payload.
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
					strings.Contains(ls, "prerequisite") ||
					strings.Contains(ls, "not permitted") ||
					strings.Contains(ls, "invalid state") ||
					strings.Contains(ls, "precondition") ||
					strings.Contains(ls, "conflict") ||
					strings.Contains(ls, "already processed") ||
					strings.Contains(ls, "already completed") ||
					strings.Contains(ls, "token expired") ||
					strings.Contains(ls, "token invalid") ||
					strings.Contains(ls, "invalid token") {
					return true
				}
			}
		}
	}
	return false
}

// IsEmptyResponse returns true if the response body is empty or whitespace only.
func IsEmptyResponse(body []byte) bool {
	return len(bytes.TrimSpace(body)) == 0
}

// ExtractProperty retrieves a nested field from unmarshaled JSON using dot notation and array indices.
func ExtractProperty(data any, path string) (any, bool) {
	if data == nil || path == "" {
		return nil, false
	}

	parts := strings.Split(path, ".")
	curr := data

	for _, part := range parts {
		if strings.Contains(part, "[") && strings.HasSuffix(part, "]") {
			bracketIdx := strings.Index(part, "[")
			key := part[:bracketIdx]
			idxStr := part[bracketIdx+1 : len(part)-1]
			idx, err := strconv.Atoi(idxStr)
			if err != nil {
				return nil, false
			}

			if key != "" {
				m, ok := curr.(map[string]any)
				if !ok {
					return nil, false
				}
				curr, ok = m[key]
				if !ok {
					return nil, false
				}
			}

			arr, ok := curr.([]any)
			if !ok || idx < 0 || idx >= len(arr) {
				return nil, false
			}
			curr = arr[idx]
			continue
		}

		m, ok := curr.(map[string]any)
		if !ok {
			return nil, false
		}
		val, ok := m[part]
		if !ok {
			// Case-insensitive fallback
			found := false
			for k, v := range m {
				if strings.EqualFold(k, part) {
					curr = v
					found = true
					break
				}
			}
			if !found {
				return nil, false
			}
		} else {
			curr = val
		}
	}

	return curr, true
}

// IsPropertyEqual compares two property values with type coercion.
func IsPropertyEqual(val1, val2 any) bool {
	if val1 == nil && val2 == nil {
		return true
	}
	if val1 == nil || val2 == nil {
		return false
	}
	s1 := strings.TrimSpace(fmt.Sprintf("%v", val1))
	s2 := strings.TrimSpace(fmt.Sprintf("%v", val2))
	return strings.EqualFold(s1, s2)
}

// RedactValue safely redacts sensitive values.
func RedactValue(val any) string {
	if val == nil {
		return "null"
	}
	s := fmt.Sprintf("%v", val)
	return secrets.RedactText(s)
}

// -------------------------------------------------------------------------
// Category A: Missing Prerequisite & Step Circumvention
// -------------------------------------------------------------------------

// ComparePrerequisiteSkipping evaluates whether a later step succeeded without fulfilling prerequisites.
func ComparePrerequisiteSkipping(legitimateBaseline, skipResp, readBackResp ResponseData, wf Workflow, step Step, allowedRole, testedRole string) ComparisonResult {
	details := make(map[string]string)
	details["workflow_id"] = wf.ID
	details["step_id"] = step.ID
	details["endpoint"] = step.Endpoint
	details["method"] = step.Method
	details["required_prerequisites"] = strings.Join(step.Preconditions, ", ")
	details["skip_status"] = fmt.Sprintf("%d", skipResp.StatusCode)
	details["readback_status"] = fmt.Sprintf("%d", readBackResp.StatusCode)

	// Step 1: Rejection Status -> NOT_VULNERABLE
	if skipResp.StatusCode == http.StatusBadRequest ||
		skipResp.StatusCode == http.StatusUnauthorized ||
		skipResp.StatusCode == http.StatusForbidden ||
		skipResp.StatusCode == http.StatusNotFound ||
		skipResp.StatusCode == http.StatusConflict ||
		skipResp.StatusCode == http.StatusPreconditionFailed ||
		skipResp.StatusCode == http.StatusPreconditionRequired ||
		skipResp.StatusCode == http.StatusUnprocessableEntity ||
		IsHTMLOrLoginPage(skipResp) ||
		IsGenericErrorJSON(skipResp.Body) {
		return ComparisonResult{
			State:           StateNotVulnerable,
			Severity:        "INFO",
			Confidence:      "CONFIRMED",
			EvidenceSummary: fmt.Sprintf("Workflow prerequisite properly enforced: server rejected step %q (HTTP %d) when predecessor prerequisite was omitted", step.ID, skipResp.StatusCode),
			EvidenceDetails: details,
		}
	}

	// Step 2: 2xx Response Handling
	if skipResp.StatusCode >= 200 && skipResp.StatusCode < 300 {
		// A 2xx response alone without independent read-back proof is CANDIDATE (never VERIFIED)
		if readBackResp.StatusCode == 0 {
			return ComparisonResult{
				State:           StateCandidate,
				Severity:        "MEDIUM",
				Confidence:      "POSSIBLE",
				EvidenceSummary: fmt.Sprintf("Server returned HTTP %d to circumvention attempt on step %q, but independent read-back was not available; state transition unconfirmed", skipResp.StatusCode, step.ID),
				EvidenceDetails: details,
			}
		}

		if readBackResp.StatusCode < 200 || readBackResp.StatusCode >= 300 {
			return ComparisonResult{
				State:           StateCandidate,
				Severity:        "MEDIUM",
				Confidence:      "POSSIBLE",
				EvidenceSummary: fmt.Sprintf("Server returned HTTP %d to circumvention attempt, but read-back failed with HTTP %d; transition unconfirmed", skipResp.StatusCode, readBackResp.StatusCode),
				EvidenceDetails: details,
			}
		}

		var readBackData any
		if err := json.Unmarshal(readBackResp.Body, &readBackData); err != nil {
			return ComparisonResult{
				State:           StateCandidate,
				Severity:        "MEDIUM",
				Confidence:      "POSSIBLE",
				EvidenceSummary: fmt.Sprintf("Server returned HTTP %d, but read-back body was non-JSON; prerequisite bypass unconfirmed", skipResp.StatusCode),
				EvidenceDetails: details,
			}
		}

		// If verification property configured, check if fulfilled/granted
		if step.VerificationProperty != "" {
			val, found := ExtractProperty(readBackData, step.VerificationProperty)
			if found {
				isVerified := false
				if step.ExpectedVerifiedValue != nil {
					isVerified = IsPropertyEqual(val, step.ExpectedVerifiedValue)
				} else {
					s := strings.ToLower(strings.TrimSpace(fmt.Sprintf("%v", val)))
					isVerified = s != "" && s != "false" && s != "0" && s != "null" && s != "<nil>"
				}
				if isVerified {
					details["persisted_value"] = RedactValue(val)
					return ComparisonResult{
						State:           StateVerified,
						Severity:        "HIGH",
						Confidence:      "CONFIRMED",
						EvidenceSummary: fmt.Sprintf("Workflow Circumvention verified: step %q succeeded (HTTP %d) without completing required prerequisite %v; confirmed granted via read-back (%s=%v)", step.ID, skipResp.StatusCode, step.Preconditions, step.VerificationProperty, val),
						EvidenceDetails: details,
					}
				}
			}

			// Read-back showed prerequisite was NOT bypassed (server safely treated operation as incomplete)
			return ComparisonResult{
				State:           StateNotVulnerable,
				Severity:        "INFO",
				Confidence:      "CONFIRMED",
				EvidenceSummary: fmt.Sprintf("Server returned HTTP %d to step %q, but read-back confirmed prerequisite transition was not fulfilled (%s=%v)", skipResp.StatusCode, step.ID, step.VerificationProperty, val),
				EvidenceDetails: details,
			}
		}

		// If no specific property configured but read-back succeeded
		return ComparisonResult{
			State:           StateCandidate,
			Severity:        "MEDIUM",
			Confidence:      "POSSIBLE",
			EvidenceSummary: fmt.Sprintf("Server returned HTTP %d to step %q without prerequisite %v, but verification property was not configured; prerequisite bypass unconfirmed", skipResp.StatusCode, step.ID, step.Preconditions),
			EvidenceDetails: details,
		}
	}

	return ComparisonResult{
		State:           StateInconclusive,
		Severity:        "INFO",
		Confidence:      "LOW",
		EvidenceSummary: fmt.Sprintf("Step %q returned unexpected HTTP %d; inconclusive prerequisite outcome", step.ID, skipResp.StatusCode),
		EvidenceDetails: details,
	}
}

// -------------------------------------------------------------------------
// Category B: Invalid Ordering & State Transitions
// -------------------------------------------------------------------------

// CompareInvalidOrdering evaluates whether an out-of-order or prohibited state transition succeeded.
func CompareInvalidOrdering(baseline, orderResp, readBackResp ResponseData, wf Workflow, step Step, prohibitedTransition Transition) ComparisonResult {
	details := make(map[string]string)
	details["workflow_id"] = wf.ID
	details["step_id"] = step.ID
	details["endpoint"] = step.Endpoint
	details["from_state"] = prohibitedTransition.FromState
	details["to_state"] = prohibitedTransition.ToState
	details["order_status"] = fmt.Sprintf("%d", orderResp.StatusCode)
	details["readback_status"] = fmt.Sprintf("%d", readBackResp.StatusCode)

	if orderResp.StatusCode == http.StatusBadRequest ||
		orderResp.StatusCode == http.StatusUnauthorized ||
		orderResp.StatusCode == http.StatusForbidden ||
		orderResp.StatusCode == http.StatusNotFound ||
		orderResp.StatusCode == http.StatusConflict ||
		orderResp.StatusCode == http.StatusPreconditionFailed ||
		orderResp.StatusCode == http.StatusUnprocessableEntity ||
		IsHTMLOrLoginPage(orderResp) ||
		IsGenericErrorJSON(orderResp.Body) {
		return ComparisonResult{
			State:           StateNotVulnerable,
			Severity:        "INFO",
			Confidence:      "CONFIRMED",
			EvidenceSummary: fmt.Sprintf("Prohibited state transition properly blocked: server rejected transition from %s to %s with HTTP %d", prohibitedTransition.FromState, prohibitedTransition.ToState, orderResp.StatusCode),
			EvidenceDetails: details,
		}
	}

	if orderResp.StatusCode >= 200 && orderResp.StatusCode < 300 {
		if readBackResp.StatusCode == 0 {
			return ComparisonResult{
				State:           StateCandidate,
				Severity:        "MEDIUM",
				Confidence:      "POSSIBLE",
				EvidenceSummary: fmt.Sprintf("Server returned HTTP %d to out-of-order step %q, but read-back verification was not available; transition unconfirmed", orderResp.StatusCode, step.ID),
				EvidenceDetails: details,
			}
		}

		var readBackData any
		if err := json.Unmarshal(readBackResp.Body, &readBackData); err != nil {
			return ComparisonResult{
				State:           StateCandidate,
				Severity:        "MEDIUM",
				Confidence:      "POSSIBLE",
				EvidenceSummary: fmt.Sprintf("Server returned HTTP %d to prohibited transition, but read-back body was non-JSON", orderResp.StatusCode),
				EvidenceDetails: details,
			}
		}

		// Check state property
		stateProp := step.VerificationProperty
		if stateProp == "" {
			stateProp = "status"
		}
		currentVal, found := ExtractProperty(readBackData, stateProp)
		if found && IsPropertyEqual(currentVal, prohibitedTransition.ToState) {
			details["observed_state"] = fmt.Sprintf("%v", currentVal)
			return ComparisonResult{
				State:           StateVerified,
				Severity:        "HIGH",
				Confidence:      "CONFIRMED",
				EvidenceSummary: fmt.Sprintf("Prohibited State Transition verified: entity transitioned from %s to %s (HTTP %d), confirmed persisted via read-back (%s=%v)", prohibitedTransition.FromState, prohibitedTransition.ToState, orderResp.StatusCode, stateProp, currentVal),
				EvidenceDetails: details,
			}
		}

		return ComparisonResult{
			State:           StateNotVulnerable,
			Severity:        "INFO",
			Confidence:      "CONFIRMED",
			EvidenceSummary: fmt.Sprintf("Server returned HTTP %d to out-of-order step %q, but read-back confirmed prohibited transition did not occur (state remains %v)", orderResp.StatusCode, step.ID, currentVal),
			EvidenceDetails: details,
		}
	}

	return ComparisonResult{
		State:           StateInconclusive,
		Severity:        "INFO",
		Confidence:      "LOW",
		EvidenceSummary: fmt.Sprintf("Out-of-order transition attempt returned unexpected HTTP %d", orderResp.StatusCode),
		EvidenceDetails: details,
	}
}

// -------------------------------------------------------------------------
// Category C: Replay, Duplicate Execution & Idempotency
// -------------------------------------------------------------------------

// CompareReplay evaluates whether replaying a single-use action caused duplicate execution.
func CompareReplay(firstResp, secondResp, counterReadBack ResponseData, wf Workflow, step Step, initialCounter, finalCounter int) ComparisonResult {
	details := make(map[string]string)
	details["workflow_id"] = wf.ID
	details["step_id"] = step.ID
	details["endpoint"] = step.Endpoint
	details["first_status"] = fmt.Sprintf("%d", firstResp.StatusCode)
	details["second_status"] = fmt.Sprintf("%d", secondResp.StatusCode)
	details["initial_counter"] = fmt.Sprintf("%d", initialCounter)
	details["final_counter"] = fmt.Sprintf("%d", finalCounter)

	// Rejection of second request -> NOT_VULNERABLE
	if secondResp.StatusCode == http.StatusBadRequest ||
		secondResp.StatusCode == http.StatusUnauthorized ||
		secondResp.StatusCode == http.StatusForbidden ||
		secondResp.StatusCode == http.StatusConflict ||
		secondResp.StatusCode == http.StatusGone ||
		secondResp.StatusCode == http.StatusPreconditionFailed ||
		secondResp.StatusCode == http.StatusUnprocessableEntity ||
		IsGenericErrorJSON(secondResp.Body) {
		return ComparisonResult{
			State:           StateNotVulnerable,
			Severity:        "INFO",
			Confidence:      "CONFIRMED",
			EvidenceSummary: fmt.Sprintf("Replay protection enforced: server rejected duplicate execution of single-use step %q with HTTP %d", step.ID, secondResp.StatusCode),
			EvidenceDetails: details,
		}
	}

	// If counter read-back was available
	if counterReadBack.StatusCode >= 200 && counterReadBack.StatusCode < 300 {
		// If final counter equals initialCounter + 1, side effect executed exactly once (idempotent duplicate request)
		if finalCounter == initialCounter+1 {
			return ComparisonResult{
				State:           StateNotVulnerable,
				Severity:        "INFO",
				Confidence:      "CONFIRMED",
				EvidenceSummary: fmt.Sprintf("Idempotent handling confirmed: repeated request on step %q returned HTTP %d, but counter confirmed side effect executed only once (counter: %d -> %d)", step.ID, secondResp.StatusCode, initialCounter, finalCounter),
				EvidenceDetails: details,
			}
		}

		// If final counter > initialCounter + 1, duplicate execution proven!
		if finalCounter > initialCounter+1 {
			return ComparisonResult{
				State:           StateVerified,
				Severity:        "HIGH",
				Confidence:      "CONFIRMED",
				EvidenceSummary: fmt.Sprintf("Duplicate Execution verified: replaying single-use step %q executed the underlying operation twice (HTTP %d, counter incremented from %d to %d)", step.ID, secondResp.StatusCode, initialCounter, finalCounter),
				EvidenceDetails: details,
			}
		}
	}

	// Repeated 200 response without counter proof is CANDIDATE (never VERIFIED)
	if secondResp.StatusCode >= 200 && secondResp.StatusCode < 300 {
		return ComparisonResult{
			State:           StateCandidate,
			Severity:        "MEDIUM",
			Confidence:      "POSSIBLE",
			EvidenceSummary: fmt.Sprintf("Single-use step %q returned HTTP %d to repeated request, but counter verification was unavailable; duplicate execution unconfirmed", step.ID, secondResp.StatusCode),
			EvidenceDetails: details,
		}
	}

	return ComparisonResult{
		State:           StateInconclusive,
		Severity:        "INFO",
		Confidence:      "LOW",
		EvidenceSummary: fmt.Sprintf("Replay test returned unexpected status HTTP %d", secondResp.StatusCode),
		EvidenceDetails: details,
	}
}

// -------------------------------------------------------------------------
// Category D: Token & Workflow-State Continuity
// -------------------------------------------------------------------------

// CompareTokenContinuity evaluates whether reusing an invalidated or foreign token was accepted.
func CompareTokenContinuity(validResp, reusedResp, verifyResp ResponseData, wf Workflow, step Step, tokenName string) ComparisonResult {
	details := make(map[string]string)
	details["workflow_id"] = wf.ID
	details["step_id"] = step.ID
	details["token_name"] = tokenName
	details["reused_status"] = fmt.Sprintf("%d", reusedResp.StatusCode)
	details["verify_status"] = fmt.Sprintf("%d", verifyResp.StatusCode)

	if reusedResp.StatusCode == http.StatusBadRequest ||
		reusedResp.StatusCode == http.StatusUnauthorized ||
		reusedResp.StatusCode == http.StatusForbidden ||
		reusedResp.StatusCode == http.StatusNotFound ||
		reusedResp.StatusCode == http.StatusGone ||
		reusedResp.StatusCode == http.StatusConflict ||
		IsGenericErrorJSON(reusedResp.Body) {
		return ComparisonResult{
			State:           StateNotVulnerable,
			Severity:        "INFO",
			Confidence:      "CONFIRMED",
			EvidenceSummary: fmt.Sprintf("Workflow token continuity properly enforced: server rejected consumed/invalidated token %q on step %q with HTTP %d", tokenName, step.ID, reusedResp.StatusCode),
			EvidenceDetails: details,
		}
	}

	if reusedResp.StatusCode >= 200 && reusedResp.StatusCode < 300 {
		if verifyResp.StatusCode >= 200 && verifyResp.StatusCode < 300 {
			if step.VerificationProperty != "" {
				var verifyData any
				if err := json.Unmarshal(verifyResp.Body, &verifyData); err == nil {
					val, found := ExtractProperty(verifyData, step.VerificationProperty)
					if found {
						isVerified := false
						if step.ExpectedVerifiedValue != nil {
							isVerified = IsPropertyEqual(val, step.ExpectedVerifiedValue)
						} else {
							s := strings.ToLower(strings.TrimSpace(fmt.Sprintf("%v", val)))
							isVerified = s != "" && s != "false" && s != "0" && s != "null" && s != "<nil>"
						}
						if isVerified {
							details["persisted_value"] = RedactValue(val)
							return ComparisonResult{
								State:           StateVerified,
								Severity:        "HIGH",
								Confidence:      "CONFIRMED",
								EvidenceSummary: fmt.Sprintf("Workflow Token Reuse verified: server accepted consumed or foreign token %q on step %q (HTTP %d), confirmed persisted via independent verification (%s=%v)", tokenName, step.ID, reusedResp.StatusCode, step.VerificationProperty, val),
								EvidenceDetails: details,
							}
						}
					}
					return ComparisonResult{
						State:           StateNotVulnerable,
						Severity:        "INFO",
						Confidence:      "CONFIRMED",
						EvidenceSummary: fmt.Sprintf("Server accepted token request with HTTP %d, but independent verification showed token side effect was not applied (%s)", reusedResp.StatusCode, step.VerificationProperty),
						EvidenceDetails: details,
					}
				}
			}

			return ComparisonResult{
				State:           StateCandidate,
				Severity:        "MEDIUM",
				Confidence:      "POSSIBLE",
				EvidenceSummary: fmt.Sprintf("Server accepted consumed or foreign token %q on step %q (HTTP %d), but verification property was not configured; token reuse unconfirmed", tokenName, step.ID, reusedResp.StatusCode),
				EvidenceDetails: details,
			}
		}

		return ComparisonResult{
			State:           StateCandidate,
			Severity:        "MEDIUM",
			Confidence:      "POSSIBLE",
			EvidenceSummary: fmt.Sprintf("Server returned HTTP %d to reused token %q on step %q, but independent verification was unavailable; token persistence unconfirmed", reusedResp.StatusCode, tokenName, step.ID),
			EvidenceDetails: details,
		}
	}

	return ComparisonResult{
		State:           StateInconclusive,
		Severity:        "INFO",
		Confidence:      "LOW",
		EvidenceSummary: fmt.Sprintf("Token continuity check returned unexpected status HTTP %d", reusedResp.StatusCode),
		EvidenceDetails: details,
	}
}

// -------------------------------------------------------------------------
// Category E: Identity & Ownership Continuity
// -------------------------------------------------------------------------

// CompareIdentityContinuity evaluates whether an unauthorized identity continued another identity's workflow.
func CompareIdentityContinuity(ownerResp, nonOwnerResp, verifyResp ResponseData, wf Workflow, step Step, ownerRole, intruderRole string) ComparisonResult {
	details := make(map[string]string)
	details["workflow_id"] = wf.ID
	details["step_id"] = step.ID
	details["owner_role"] = ownerRole
	details["intruder_role"] = intruderRole
	details["non_owner_status"] = fmt.Sprintf("%d", nonOwnerResp.StatusCode)
	details["verify_status"] = fmt.Sprintf("%d", verifyResp.StatusCode)

	if nonOwnerResp.StatusCode == http.StatusBadRequest ||
		nonOwnerResp.StatusCode == http.StatusUnauthorized ||
		nonOwnerResp.StatusCode == http.StatusForbidden ||
		nonOwnerResp.StatusCode == http.StatusNotFound ||
		IsGenericErrorJSON(nonOwnerResp.Body) {
		return ComparisonResult{
			State:           StateNotVulnerable,
			Severity:        "INFO",
			Confidence:      "CONFIRMED",
			EvidenceSummary: fmt.Sprintf("Workflow ownership continuity enforced: non-owner role %s was denied access to step %q with HTTP %d", intruderRole, step.ID, nonOwnerResp.StatusCode),
			EvidenceDetails: details,
		}
	}

	if nonOwnerResp.StatusCode >= 200 && nonOwnerResp.StatusCode < 300 {
		if verifyResp.StatusCode >= 200 && verifyResp.StatusCode < 300 {
			if step.VerificationProperty != "" {
				var verifyData any
				if err := json.Unmarshal(verifyResp.Body, &verifyData); err == nil {
					val, found := ExtractProperty(verifyData, step.VerificationProperty)
					if found {
						isVerified := false
						if step.ExpectedVerifiedValue != nil {
							isVerified = IsPropertyEqual(val, step.ExpectedVerifiedValue)
						} else {
							s := strings.ToLower(strings.TrimSpace(fmt.Sprintf("%v", val)))
							isOwner := strings.EqualFold(s, strings.ToLower(strings.TrimSpace(ownerRole)))
							isIntruder := strings.EqualFold(s, strings.ToLower(strings.TrimSpace(intruderRole)))
							if isIntruder {
								isVerified = true
							} else if isOwner {
								isVerified = false
							} else {
								isVerified = s != "" && s != "false" && s != "0" && s != "null" && s != "<nil>"
							}
						}
						if isVerified {
							details["persisted_value"] = RedactValue(val)
							return ComparisonResult{
								State:           StateVerified,
								Severity:        "HIGH",
								Confidence:      "CONFIRMED",
								EvidenceSummary: fmt.Sprintf("Workflow Ownership Violation verified: non-owner role %s successfully advanced owner's workflow on step %q (HTTP %d), confirmed persisted via independent verification (%s=%v)", intruderRole, step.ID, nonOwnerResp.StatusCode, step.VerificationProperty, val),
								EvidenceDetails: details,
							}
						}
					}
					return ComparisonResult{
						State:           StateNotVulnerable,
						Severity:        "INFO",
						Confidence:      "CONFIRMED",
						EvidenceSummary: fmt.Sprintf("Server returned HTTP %d to non-owner request, but independent verification showed ownership violation was not persisted (%s)", nonOwnerResp.StatusCode, step.VerificationProperty),
						EvidenceDetails: details,
					}
				}
			}

			return ComparisonResult{
				State:           StateCandidate,
				Severity:        "MEDIUM",
				Confidence:      "POSSIBLE",
				EvidenceSummary: fmt.Sprintf("Non-owner role %s received HTTP %d on step %q, but verification property was not configured; ownership takeover unconfirmed", intruderRole, nonOwnerResp.StatusCode, step.ID),
				EvidenceDetails: details,
			}
		}

		return ComparisonResult{
			State:           StateCandidate,
			Severity:        "MEDIUM",
			Confidence:      "POSSIBLE",
			EvidenceSummary: fmt.Sprintf("Non-owner role %s received HTTP %d on step %q, but independent verification was unconfirmed", intruderRole, nonOwnerResp.StatusCode, step.ID),
			EvidenceDetails: details,
		}
	}

	return ComparisonResult{
		State:           StateInconclusive,
		Severity:        "INFO",
		Confidence:      "LOW",
		EvidenceSummary: fmt.Sprintf("Ownership continuity check returned unexpected status HTTP %d", nonOwnerResp.StatusCode),
		EvidenceDetails: details,
	}
}

// -------------------------------------------------------------------------
// Category F: Concurrent Transition & Race Condition Integrity
// -------------------------------------------------------------------------

// CompareConcurrentTransition evaluates whether bounded concurrent requests caused duplicate execution.
func CompareConcurrentTransition(responses []ResponseData, counterReadBack ResponseData, wf Workflow, step Step, initialCounter, finalCounter, attemptedRequests int) ComparisonResult {
	details := make(map[string]string)
	details["workflow_id"] = wf.ID
	details["step_id"] = step.ID
	details["attempted_requests"] = fmt.Sprintf("%d", attemptedRequests)
	details["initial_counter"] = fmt.Sprintf("%d", initialCounter)
	details["final_counter"] = fmt.Sprintf("%d", finalCounter)

	// If counter read-back is available
	if counterReadBack.StatusCode >= 200 && counterReadBack.StatusCode < 300 {
		if finalCounter > initialCounter+1 {
			return ComparisonResult{
				State:           StateVerified,
				Severity:        "HIGH",
				Confidence:      "CONFIRMED",
				EvidenceSummary: fmt.Sprintf("Concurrent Race Condition verified: %d simultaneous requests on single-use step %q caused duplicate execution (counter incremented from %d to %d)", attemptedRequests, step.ID, initialCounter, finalCounter),
				EvidenceDetails: details,
			}
		}
		if finalCounter == initialCounter+1 {
			return ComparisonResult{
				State:           StateNotVulnerable,
				Severity:        "INFO",
				Confidence:      "CONFIRMED",
				EvidenceSummary: fmt.Sprintf("Atomic transition enforced: %d concurrent requests on step %q resulted in exactly one execution (counter incremented from %d to %d)", attemptedRequests, step.ID, initialCounter, finalCounter),
				EvidenceDetails: details,
			}
		}
	}

	// Count successful 2xx responses
	successCount := 0
	for _, r := range responses {
		if r.StatusCode >= 200 && r.StatusCode < 300 && !IsGenericErrorJSON(r.Body) {
			successCount++
		}
	}

	if successCount > 1 {
		return ComparisonResult{
			State:           StateCandidate,
			Severity:        "MEDIUM",
			Confidence:      "POSSIBLE",
			EvidenceSummary: fmt.Sprintf("Concurrent execution: %d of %d simultaneous requests returned HTTP 2xx, but counter proof was unavailable; race condition unconfirmed", successCount, attemptedRequests),
			EvidenceDetails: details,
		}
	}

	return ComparisonResult{
		State:           StateNotVulnerable,
		Severity:        "INFO",
		Confidence:      "CONFIRMED",
		EvidenceSummary: fmt.Sprintf("Concurrency integrity enforced: exactly %d of %d requests succeeded; race condition prevented", successCount, attemptedRequests),
		EvidenceDetails: details,
	}
}
