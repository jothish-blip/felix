package verification

import (
	"fmt"
	"strings"
	"testing"
)

// TestSafetyChecker_Passive_EnforcesAuthorization verifies that CheckPassive
// fails closed if assessment authorization is absent or false.
func TestSafetyChecker_Passive_EnforcesAuthorization(t *testing.T) {
	checker := NewSafetyChecker(SafetyOptions{
		IsAuthorized:         false,
		MaxRequestsPerTarget: 100,
	})

	decision := checker.CheckPassive("http://127.0.0.1:3000", "http://127.0.0.1:3000/api/Users")
	if decision.Allowed {
		t.Errorf("expected CheckPassive to block unauthorized assessment, but got Allowed=true")
	}
	if decision.Decision != DecisionBlocked {
		t.Errorf("expected DecisionBlocked, got %s", decision.Decision)
	}
	if !strings.Contains(decision.BlockReason, "safety fail-closed") {
		t.Errorf("expected block reason to indicate fail-closed authorization, got %q", decision.BlockReason)
	}
}

// TestSafetyChecker_Passive_EnforcesScope verifies that CheckPassive enforces
// both explicit exclusion and allowable scope boundaries.
func TestSafetyChecker_Passive_EnforcesScope(t *testing.T) {
	inScope := func(u string) bool {
		return strings.Contains(u, "127.0.0.1:3000")
	}
	isExcluded := func(u string) bool {
		return strings.Contains(u, "/admin") || strings.Contains(u, "production.local")
	}

	checker := NewSafetyChecker(SafetyOptions{
		IsAuthorized:         true,
		InScopeFunc:          inScope,
		IsExcludedFunc:       isExcluded,
		MaxRequestsPerTarget: 100,
	})

	// 1. Authorized in-scope target -> Allowed
	res1 := checker.CheckPassive("http://127.0.0.1:3000", "http://127.0.0.1:3000/api/Challenges")
	if !res1.Allowed || res1.Decision != DecisionAllowed {
		t.Errorf("expected in-scope target to be allowed, got: %+v", res1)
	}

	// 2. Out-of-scope target -> Blocked
	res2 := checker.CheckPassive("http://192.168.1.50:8080", "http://192.168.1.50:8080/api")
	if res2.Allowed || res2.Decision != DecisionBlocked {
		t.Errorf("expected out-of-scope target to be blocked, got: %+v", res2)
	}
	if !strings.Contains(res2.BlockReason, "outside authorized assessment boundaries") {
		t.Errorf("unexpected block reason for out-of-scope: %q", res2.BlockReason)
	}

	// 3. Excluded path on in-scope host -> Blocked
	res3 := checker.CheckPassive("http://127.0.0.1:3000", "http://127.0.0.1:3000/admin/settings")
	if res3.Allowed || res3.Decision != DecisionBlocked {
		t.Errorf("expected excluded target to be blocked, got: %+v", res3)
	}
	if !strings.Contains(res3.BlockReason, "explicitly excluded") {
		t.Errorf("unexpected block reason for excluded path: %q", res3.BlockReason)
	}
}

// TestSafetyChecker_Passive_DoesNotConsumeQuota verifies that passive checks
// never increment active probe quotas.
func TestSafetyChecker_Passive_DoesNotConsumeQuota(t *testing.T) {
	checker := NewSafetyChecker(SafetyOptions{
		IsAuthorized:         true,
		MaxRequestsPerTarget: 2, // Very tight quota
	})

	target := "http://127.0.0.1:3000"

	// Dispatch 10 passive checks
	for i := 0; i < 10; i++ {
		res := checker.CheckPassive(target, fmt.Sprintf("%s/route-%d", target, i))
		if !res.Allowed {
			t.Fatalf("passive check %d unexpectedly blocked: %+v", i, res)
		}
	}

	// Active check 1 -> should succeed (quota 1/2)
	act1 := checker.Check(target, target+"/probe-1", "GET", false)
	if !act1.Allowed {
		t.Fatalf("active check 1 unexpectedly blocked: %+v", act1)
	}

	// Active check 2 -> should succeed (quota 2/2)
	act2 := checker.Check(target, target+"/probe-2", "GET", false)
	if !act2.Allowed {
		t.Fatalf("active check 2 unexpectedly blocked: %+v", act2)
	}

	// Active check 3 -> should be blocked (quota 3/2 exceeds 2)
	act3 := checker.Check(target, target+"/probe-3", "GET", false)
	if act3.Allowed || act3.Decision != DecisionBlocked {
		t.Fatalf("active check 3 should be blocked by quota, got: %+v", act3)
	}
	if !strings.Contains(act3.BlockReason, "quota exceeded") {
		t.Errorf("expected quota exceeded block reason, got: %q", act3.BlockReason)
	}

	// Passive check 11 -> should still succeed because passive does not check or increment probe quota!
	res11 := checker.CheckPassive(target, target+"/route-11")
	if !res11.Allowed {
		t.Errorf("passive check after quota exhaustion should still be allowed, got: %+v", res11)
	}
}

// TestSafetyChecker_Quota100_DoesNotWeakenSafetyControls verifies that sizing
// the default quota to 100 requests does not weaken authorization, boundary, or mutation enforcement.
func TestSafetyChecker_Quota100_DoesNotWeakenSafetyControls(t *testing.T) {
	inScope := func(u string) bool {
		return strings.HasPrefix(u, "http://127.0.0.1:8080")
	}

	checker := NewSafetyChecker(SafetyOptions{
		IsAuthorized:         true,
		InScopeFunc:          inScope,
		AllowStateChanging:   false,
		MaxRequestsPerTarget: 100,
	})

	// 1. Unauthorized host is blocked immediately on request #1 despite 100-request quota
	outOfScope := checker.Check("http://10.0.0.1:9000", "http://10.0.0.1:9000/api", "GET", false)
	if outOfScope.Allowed || outOfScope.Decision != DecisionBlocked {
		t.Errorf("100-request quota allowed out-of-scope target: %+v", outOfScope)
	}

	// 2. State-changing POST mutation is blocked immediately on request #1
	postBlocked := checker.Check("http://127.0.0.1:8080", "http://127.0.0.1:8080/api/delete", "POST", true)
	if postBlocked.Allowed || postBlocked.Decision != DecisionBlocked {
		t.Errorf("100-request quota allowed state-changing POST mutation: %+v", postBlocked)
	}

	// 3. Active requests are strictly counted and bounded at exactly 100
	target := "http://127.0.0.1:8080"
	for i := 1; i <= 100; i++ {
		res := checker.Check(target, fmt.Sprintf("%s/get-%d", target, i), "GET", false)
		if !res.Allowed {
			t.Fatalf("request %d of 100 should be allowed, got blocked: %+v", i, res)
		}
	}

	// Request 101 must be strictly blocked
	res101 := checker.Check(target, target+"/get-101", "GET", false)
	if res101.Allowed || res101.Decision != DecisionBlocked {
		t.Fatalf("request 101 must be blocked by quota, got: %+v", res101)
	}
}
