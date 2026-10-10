package verification

import (
	"fmt"
	"strings"
	"sync"
)

// SafetyDecision types.
const (
	DecisionAllowed          = "ALLOWED"
	DecisionBlocked          = "BLOCKED"
	DecisionReadOnlyFallback = "READ_ONLY_FALLBACK"
)

// SafetyChecker enforces scope, authorization, non-destructive boundaries, and request quotas.
type SafetyChecker struct {
	mu                  sync.Mutex
	isAuthorized        bool
	inScopeFunc         func(string) bool
	isExcludedFunc      func(string) bool
	allowStateChanging  bool
	maxRequestsPerTarget int
	requestCounts       map[string]int
}

// SafetyOptions configures safety enforcement.
type SafetyOptions struct {
	IsAuthorized         bool
	InScopeFunc          func(string) bool
	IsExcludedFunc       func(string) bool
	AllowStateChanging   bool
	MaxRequestsPerTarget int
}

// NewSafetyChecker constructs a new SafetyChecker.
func NewSafetyChecker(opts SafetyOptions) *SafetyChecker {
	maxReqs := opts.MaxRequestsPerTarget
	if maxReqs <= 0 {
		maxReqs = 20
	}
	return &SafetyChecker{
		isAuthorized:         opts.IsAuthorized,
		inScopeFunc:          opts.InScopeFunc,
		isExcludedFunc:       opts.IsExcludedFunc,
		allowStateChanging:   opts.AllowStateChanging,
		maxRequestsPerTarget: maxReqs,
		requestCounts:        make(map[string]int),
	}
}

// SafetyDecisionResult records the outcome of an active verification safety audit.
type SafetyDecisionResult struct {
	Allowed     bool   `json:"allowed"`
	Decision    string `json:"decision"`
	BlockReason string `json:"block_reason,omitempty"`
}

// Check evaluates whether a verification check may safely proceed.
func (sc *SafetyChecker) Check(targetURL, endpoint, method string, isStateChanging bool) SafetyDecisionResult {
	if sc == nil {
		return SafetyDecisionResult{
			Allowed:     true,
			Decision:    DecisionAllowed,
		}
	}

	sc.mu.Lock()
	defer sc.mu.Unlock()

	// 1. Authorization check
	if !sc.isAuthorized {
		return SafetyDecisionResult{
			Allowed:     false,
			Decision:    DecisionBlocked,
			BlockReason: "Assessment authorization is missing, expired, pending, or revoked (safety fail-closed)",
		}
	}

	// 2. Scope check
	evalURL := endpoint
	if evalURL == "" {
		evalURL = targetURL
	}
	if sc.isExcludedFunc != nil && sc.isExcludedFunc(evalURL) {
		return SafetyDecisionResult{
			Allowed:     false,
			Decision:    DecisionBlocked,
			BlockReason: fmt.Sprintf("Target URL '%s' is explicitly excluded by assessment scope rules", evalURL),
		}
	}
	if sc.inScopeFunc != nil && !sc.inScopeFunc(evalURL) {
		return SafetyDecisionResult{
			Allowed:     false,
			Decision:    DecisionBlocked,
			BlockReason: fmt.Sprintf("Target URL '%s' is outside authorized assessment boundaries", evalURL),
		}
	}

	// 3. State-changing / non-destructive check
	mUpper := strings.ToUpper(method)
	isMutation := isStateChanging || mUpper == "POST" || mUpper == "PUT" || mUpper == "DELETE" || mUpper == "PATCH"
	if isMutation && !sc.allowStateChanging {
		return SafetyDecisionResult{
			Allowed:     false,
			Decision:    DecisionBlocked,
			BlockReason: fmt.Sprintf("State-changing operation (%s) blocked by default non-destructive audit policy", mUpper),
		}
	}

	// 4. Quota / rate limit check
	sc.requestCounts[targetURL]++
	if sc.requestCounts[targetURL] > sc.maxRequestsPerTarget {
		return SafetyDecisionResult{
			Allowed:     false,
			Decision:    DecisionBlocked,
			BlockReason: fmt.Sprintf("Target request quota exceeded (%d probes dispatched)", sc.maxRequestsPerTarget),
		}
	}

	return SafetyDecisionResult{
		Allowed:  true,
		Decision: DecisionAllowed,
	}
}
