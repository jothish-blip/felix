package workflow

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"felix/pkg/auth"
)

func testApprovedAuth() *auth.AuthorizationRecord {
	past := time.Now().UTC().Add(-1 * time.Hour)
	future := time.Now().UTC().Add(24 * time.Hour)
	return &auth.AuthorizationRecord{
		ID:                  "auth-workflow-test",
		AuthorizingParty:    "Chief Information Security Officer",
		AuthorizationMethod: "Written",
		Status:              "APPROVED",
		ValidFrom:           &past,
		ValidUntil:          &future,
	}
}

// 1. Graph validation: Valid linear workflow
func TestWorkflow_ValidateWorkflow_ValidLinear(t *testing.T) {
	wf := Workflow{
		ID:   "checkout-flow",
		Name: "Order Checkout Flow",
		Steps: []Step{
			{ID: "cart", Name: "Add to Cart", Endpoint: "/cart", Method: "POST"},
			{ID: "shipping", Name: "Enter Shipping", Endpoint: "/shipping", Method: "POST", Preconditions: []string{"cart"}},
			{ID: "payment", Name: "Pay Order", Endpoint: "/pay", Method: "POST", Preconditions: []string{"shipping"}},
		},
	}
	if err := ValidateWorkflow(wf); err != nil {
		t.Fatalf("expected valid workflow, got error: %v", err)
	}
}

// 2. Graph validation: Valid branching workflow
func TestWorkflow_ValidateWorkflow_ValidBranching(t *testing.T) {
	wf := Workflow{
		ID:   "approval-flow",
		Name: "Multi-branch Approval Flow",
		Steps: []Step{
			{ID: "submit", Name: "Submit Request", Endpoint: "/submit", Method: "POST"},
			{ID: "review-a", Name: "Review Branch A", Endpoint: "/review-a", Method: "POST", Preconditions: []string{"submit"}},
			{ID: "review-b", Name: "Review Branch B", Endpoint: "/review-b", Method: "POST", Preconditions: []string{"submit"}},
			{ID: "finalize", Name: "Finalize Approval", Endpoint: "/finalize", Method: "POST", Preconditions: []string{"review-a", "review-b"}},
		},
	}
	if err := ValidateWorkflow(wf); err != nil {
		t.Fatalf("expected valid branching workflow, got error: %v", err)
	}
}

// 3. Graph validation: Rejects malformed workflows (empty ID, no steps, duplicate ID, empty endpoint)
func TestWorkflow_ValidateWorkflow_MalformedRejections(t *testing.T) {
	cases := []struct {
		name string
		wf   Workflow
	}{
		{"empty-id", Workflow{ID: "", Steps: []Step{{ID: "s1", Endpoint: "/s1", Method: "GET"}}}},
		{"no-steps", Workflow{ID: "wf1", Steps: []Step{}}},
		{"empty-step-id", Workflow{ID: "wf1", Steps: []Step{{ID: "", Endpoint: "/s1", Method: "GET"}}}},
		{"dup-step-id", Workflow{ID: "wf1", Steps: []Step{
			{ID: "s1", Endpoint: "/s1", Method: "GET"},
			{ID: "s1", Endpoint: "/s2", Method: "GET"},
		}}},
		{"empty-endpoint", Workflow{ID: "wf1", Steps: []Step{{ID: "s1", Endpoint: "", Method: "GET"}}}},
		{"self-prereq", Workflow{ID: "wf1", Steps: []Step{{ID: "s1", Endpoint: "/s1", Method: "GET", Preconditions: []string{"s1"}}}}},
		{"unknown-prereq", Workflow{ID: "wf1", Steps: []Step{{ID: "s1", Endpoint: "/s1", Method: "GET", Preconditions: []string{"nonexistent"}}}}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := ValidateWorkflow(tc.wf); err == nil {
				t.Fatalf("expected validation error for case %q, but got nil", tc.name)
			}
		})
	}
}

// 4. Graph validation: Dependency cycle detection
func TestWorkflow_ValidateWorkflow_CycleDetection(t *testing.T) {
	// A -> B -> A
	cyclicWf := Workflow{
		ID:   "cyclic-wf",
		Name: "Cyclic Workflow",
		Steps: []Step{
			{ID: "stepA", Endpoint: "/stepA", Method: "POST", Preconditions: []string{"stepB"}},
			{ID: "stepB", Endpoint: "/stepB", Method: "POST", Preconditions: []string{"stepA"}},
		},
	}
	err := ValidateWorkflow(cyclicWf)
	if err == nil {
		t.Fatalf("expected cycle detection error, got nil")
	}
	if !strings.Contains(strings.ToLower(err.Error()), "cycl") {
		t.Errorf("expected cycle detection in error, got: %v", err)
	}

	// Indirect cycle: A -> B -> C -> A
	indirectCyclicWf := Workflow{
		ID:   "indirect-cycle",
		Name: "Indirect Cyclic Workflow",
		Steps: []Step{
			{ID: "step1", Endpoint: "/step1", Method: "POST", Preconditions: []string{"step3"}},
			{ID: "step2", Endpoint: "/step2", Method: "POST", Preconditions: []string{"step1"}},
			{ID: "step3", Endpoint: "/step3", Method: "POST", Preconditions: []string{"step2"}},
		},
	}
	err2 := ValidateWorkflow(indirectCyclicWf)
	if err2 == nil {
		t.Fatalf("expected indirect cycle detection error, got nil")
	}

	// Permitted cycle when AllowLoops is true
	indirectCyclicWf.AllowLoops = true
	if err3 := ValidateWorkflow(indirectCyclicWf); err3 != nil {
		t.Errorf("expected cycle to be permitted with AllowLoops=true, got: %v", err3)
	}
}

// 5. Category A: WORKFLOW-PREREQUISITE-SKIP properly enforced -> NOT_VULNERABLE
func TestWorkflow_PrerequisiteSkip_Enforced_NotVulnerable(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/order/complete" {
			// Missing prerequisite verification
			w.WriteHeader(http.StatusPreconditionFailed)
			fmt.Fprint(w, `{"error":"prerequisite payment not completed"}`)
			return
		}
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `{"status":"ok"}`)
	}))
	defer ts.Close()

	engine := NewEngine(nil, DefaultConfig())
	actx := &AssessmentContext{
		AssessmentID:         "asm-prereq-01",
		ExecutionID:          "exec-01",
		BaseURL:              ts.URL,
		Authorization:        testApprovedAuth(),
		AllowStateChangingTests:   true,
		SyntheticFixture:     true,
		
		Workflows: []Workflow{
			{
				ID:   "wf-order",
				Name: "Order Workflow",
				Steps: []Step{
					{ID: "step1", Name: "Create Cart", Endpoint: "/cart", Method: "POST"},
					{
						ID:                   "step2",
						Name:                 "Complete Order",
						Endpoint:             "/order/complete",
						Method:               "POST",
						Preconditions:        []string{"step1"},
						VerificationEndpoint: "/order/status",
						VerificationProperty: "completed",
					},
				},
				CategoriesToAssess: []Category{CategoryPrerequisiteSkipping},
			},
		},
		Identities: DefaultIdentities(),
	}

	results, summary, err := engine.Assess(context.Background(), actx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if results[0].VerificationState != StateNotVulnerable {
		t.Errorf("expected NOT_VULNERABLE, got %s (evidence: %s)", results[0].VerificationState, results[0].EvidenceSummary)
	}
	if summary.NotVulnerableCount != 1 {
		t.Errorf("expected 1 not vulnerable in summary, got %d", summary.NotVulnerableCount)
	}
}

// 6. Category A: WORKFLOW-PREREQUISITE-SKIP verified via authoritative read-back -> VERIFIED
func TestWorkflow_PrerequisiteSkip_Circumvented_Verified(t *testing.T) {
	var orderCompleted int32
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/order/complete":
			// Flawed server accepts completion even without cart!
			atomic.StoreInt32(&orderCompleted, 1)
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, `{"status":"completed","order_id":"123"}`)
		case "/order/status":
			w.WriteHeader(http.StatusOK)
			if atomic.LoadInt32(&orderCompleted) == 1 {
				fmt.Fprint(w, `{"completed":true,"order_id":"123"}`)
			} else {
				fmt.Fprint(w, `{"completed":false}`)
			}
		default:
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, `{"status":"ok"}`)
		}
	}))
	defer ts.Close()

	engine := NewEngine(nil, DefaultConfig())
	actx := &AssessmentContext{
		AssessmentID:         "asm-prereq-02",
		ExecutionID:          "exec-02",
		BaseURL:              ts.URL,
		Authorization:        testApprovedAuth(),
		AllowStateChangingTests:   true,
		SyntheticFixture:     true,
		
		Workflows: []Workflow{
			{
				ID:   "wf-order-bypass",
				Name: "Bypass Prerequisite Order",
				Steps: []Step{
					{ID: "cart", Name: "Cart Step", Endpoint: "/cart", Method: "POST"},
					{
						ID:                   "complete",
						Name:                 "Complete Step",
						Endpoint:             "/order/complete",
						Method:               "POST",
						Preconditions:        []string{"cart"},
						VerificationEndpoint: "/order/status",
						VerificationProperty: "completed",
					},
				},
				CategoriesToAssess: []Category{CategoryPrerequisiteSkipping},
			},
		},
		Identities: DefaultIdentities(),
	}

	results, summary, err := engine.Assess(context.Background(), actx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if results[0].VerificationState != StateVerified {
		t.Errorf("expected VERIFIED, got %s (evidence: %s)", results[0].VerificationState, results[0].EvidenceSummary)
	}
	if results[0].Finding == nil {
		t.Fatal("expected report.Finding to be attached to VERIFIED result")
	}
	if summary.VerifiedCount != 1 {
		t.Errorf("expected 1 verified in summary, got %d", summary.VerifiedCount)
	}
}

// 7. Category A: 2xx response without read-back proof yields CANDIDATE (never VERIFIED)
func TestWorkflow_PrerequisiteSkip_EchoOnly_Candidate(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		// Returns 200 without read-back confirmation configured
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `{"success":true,"message":"accepted for processing"}`)
	}))
	defer ts.Close()

	engine := NewEngine(nil, DefaultConfig())
	actx := &AssessmentContext{
		AssessmentID:         "asm-prereq-03",
		ExecutionID:          "exec-03",
		BaseURL:              ts.URL,
		Authorization:        testApprovedAuth(),
		AllowStateChangingTests:   true,
		SyntheticFixture:     true,
		
		Workflows: []Workflow{
			{
				ID:   "wf-order-candidate",
				Name: "Order Candidate",
				Steps: []Step{
					{ID: "cart", Name: "Cart Step", Endpoint: "/cart", Method: "POST"},
					{
						ID:            "complete",
						Name:          "Complete Step",
						Endpoint:      "/order/complete",
						Method:        "POST",
						Preconditions: []string{"cart"},
						// No independent read-back endpoint configured!
					},
				},
				CategoriesToAssess: []Category{CategoryPrerequisiteSkipping},
			},
		},
		Identities: DefaultIdentities(),
	}

	results, _, err := engine.Assess(context.Background(), actx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if results[0].VerificationState != StateCandidate {
		t.Errorf("expected CANDIDATE when read-back is absent, got %s", results[0].VerificationState)
	}
}

// 8. Category B: WORKFLOW-INVALID-ORDER enforced -> NOT_VULNERABLE
func TestWorkflow_InvalidOrdering_Enforced_NotVulnerable(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/orders/transition" {
			var body map[string]string
			json.NewDecoder(r.Body).Decode(&body)
			if body["action"] == "complete" && body["current_state"] == "cancelled" {
				w.WriteHeader(http.StatusConflict)
				fmt.Fprint(w, `{"error":"cannot transition from cancelled to complete"}`)
				return
			}
		}
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `{"state":"cancelled"}`)
	}))
	defer ts.Close()

	engine := NewEngine(nil, DefaultConfig())
	actx := &AssessmentContext{
		AssessmentID:         "asm-order-01",
		ExecutionID:          "exec-01",
		BaseURL:              ts.URL,
		Authorization:        testApprovedAuth(),
		AllowStateChangingTests:   true,
		SyntheticFixture:     true,
		
		Workflows: []Workflow{
			{
				ID:           "order-lifecycle",
				Name:         "Order State Lifecycle",
				States:       []string{"created", "cancelled", "completed"},
				InitialState: "created",
				ProhibitedTransitions: []Transition{
					{FromState: "cancelled", ToState: "completed", StepID: "transition-step", Action: "complete", IsProhibited: true},
				},
				Steps: []Step{
					{
						ID:                   "transition-step",
						Name:                 "Execute Transition",
						Endpoint:             "/orders/transition",
						Method:               "POST",
						Payload:              `{"current_state":"cancelled","action":"complete"}`,
						VerificationEndpoint: "/orders/state",
						VerificationProperty: "state",
						ExpectedVerifiedValue: "completed",
					},
				},
				CategoriesToAssess: []Category{CategoryInvalidOrdering},
			},
		},
		Identities: DefaultIdentities(),
	}

	results, summary, err := engine.Assess(context.Background(), actx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if results[0].VerificationState != StateNotVulnerable {
		t.Errorf("expected NOT_VULNERABLE, got %s (evidence: %s)", results[0].VerificationState, results[0].EvidenceSummary)
	}
	if summary.NotVulnerableCount != 1 {
		t.Errorf("expected summary NotVulnerableCount 1, got %d", summary.NotVulnerableCount)
	}
}

// 9. Category B: WORKFLOW-INVALID-ORDER prohibited transition verified via read-back -> VERIFIED
func TestWorkflow_InvalidOrdering_Circumvented_Verified(t *testing.T) {
	currentState := "cancelled"
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/orders/transition":
			currentState = "completed" // Prohibited transition allowed!
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, `{"status":"success","state":"completed"}`)
		case "/orders/state":
			w.WriteHeader(http.StatusOK)
			fmt.Fprintf(w, `{"state":"%s"}`, currentState)
		}
	}))
	defer ts.Close()

	engine := NewEngine(nil, DefaultConfig())
	actx := &AssessmentContext{
		AssessmentID:         "asm-order-02",
		ExecutionID:          "exec-02",
		BaseURL:              ts.URL,
		Authorization:        testApprovedAuth(),
		AllowStateChangingTests:   true,
		SyntheticFixture:     true,
		
		Workflows: []Workflow{
			{
				ID:   "order-lifecycle-bypass",
				Name: "Order State Lifecycle Bypass",
				ProhibitedTransitions: []Transition{
					{FromState: "cancelled", ToState: "completed", StepID: "transition-step", Action: "complete", IsProhibited: true},
				},
				Steps: []Step{
					{
						ID:                   "transition-step",
						Name:                 "Execute Transition",
						Endpoint:             "/orders/transition",
						Method:               "POST",
						Payload:              `{"current_state":"cancelled","action":"complete"}`,
						VerificationEndpoint: "/orders/state",
						VerificationProperty: "state",
						ExpectedVerifiedValue: "completed",
					},
				},
				CategoriesToAssess: []Category{CategoryInvalidOrdering},
			},
		},
		Identities: DefaultIdentities(),
	}

	results, _, err := engine.Assess(context.Background(), actx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if results[0].VerificationState != StateVerified {
		t.Errorf("expected VERIFIED, got %s (evidence: %s)", results[0].VerificationState, results[0].EvidenceSummary)
	}
}

// 10. Category C: WORKFLOW-REPLAY-DUPLICATE enforced -> NOT_VULNERABLE
func TestWorkflow_Replay_Enforced_NotVulnerable(t *testing.T) {
	var executionCount int32
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/coupon/redeem":
			c := atomic.AddInt32(&executionCount, 1)
			if c == 1 {
				w.WriteHeader(http.StatusOK)
				fmt.Fprint(w, `{"redeemed":true}`)
			} else {
				w.WriteHeader(http.StatusConflict)
				fmt.Fprint(w, `{"error":"coupon already redeemed"}`)
			}
		case "/coupon/balance":
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, `{"redemption_count":1}`)
		}
	}))
	defer ts.Close()

	engine := NewEngine(nil, DefaultConfig())
	actx := &AssessmentContext{
		AssessmentID:         "asm-replay-01",
		ExecutionID:          "exec-01",
		BaseURL:              ts.URL,
		Authorization:        testApprovedAuth(),
		AllowStateChangingTests:   true,
		SyntheticFixture:     true,
		
		Workflows: []Workflow{
			{
				ID:   "coupon-flow",
				Name: "Coupon Redemption Flow",
				Steps: []Step{
					{
						ID:                   "redeem",
						Name:                 "Redeem Coupon",
						Endpoint:             "/coupon/redeem",
						Method:               "POST",
						IsSingleUse:          true,
						VerificationEndpoint: "/coupon/balance",
						VerificationProperty: "redemption_count",
					},
				},
				CategoriesToAssess: []Category{CategoryReplayIdempotency},
			},
		},
		Identities: DefaultIdentities(),
	}

	results, summary, err := engine.Assess(context.Background(), actx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if results[0].VerificationState != StateNotVulnerable {
		t.Errorf("expected NOT_VULNERABLE, got %s (evidence: %s)", results[0].VerificationState, results[0].EvidenceSummary)
	}
	if summary.NotVulnerableCount != 1 {
		t.Errorf("expected 1 not vulnerable in summary, got %d", summary.NotVulnerableCount)
	}
}

// 11. Category C: WORKFLOW-REPLAY-DUPLICATE verified via counter proof -> VERIFIED
func TestWorkflow_Replay_DuplicateExecution_Verified(t *testing.T) {
	var count int32
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/coupon/redeem":
			atomic.AddInt32(&count, 1)
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, `{"redeemed":true}`)
		case "/coupon/balance":
			w.WriteHeader(http.StatusOK)
			fmt.Fprintf(w, `{"redemption_count":%d}`, atomic.LoadInt32(&count))
		}
	}))
	defer ts.Close()

	engine := NewEngine(nil, DefaultConfig())
	actx := &AssessmentContext{
		AssessmentID:         "asm-replay-02",
		ExecutionID:          "exec-02",
		BaseURL:              ts.URL,
		Authorization:        testApprovedAuth(),
		AllowStateChangingTests:   true,
		SyntheticFixture:     true,
		
		Workflows: []Workflow{
			{
				ID:   "coupon-replay-flaw",
				Name: "Coupon Replay Flaw",
				Steps: []Step{
					{
						ID:                   "redeem",
						Name:                 "Redeem Coupon",
						Endpoint:             "/coupon/redeem",
						Method:               "POST",
						IsSingleUse:          true,
						VerificationEndpoint: "/coupon/balance",
						VerificationProperty: "redemption_count",
					},
				},
				CategoriesToAssess: []Category{CategoryReplayIdempotency},
			},
		},
		Identities: DefaultIdentities(),
	}

	results, _, err := engine.Assess(context.Background(), actx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if results[0].VerificationState != StateVerified {
		t.Errorf("expected VERIFIED, got %s (evidence: %s)", results[0].VerificationState, results[0].EvidenceSummary)
	}
}

// 12. Category C: Replay 200 OK without counter proof yields CANDIDATE (never VERIFIED)
func TestWorkflow_Replay_200NoCounter_Candidate(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		// Always returns 200, but no read-back verification endpoint configured
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `{"status":"ok"}`)
	}))
	defer ts.Close()

	engine := NewEngine(nil, DefaultConfig())
	actx := &AssessmentContext{
		AssessmentID:         "asm-replay-03",
		ExecutionID:          "exec-03",
		BaseURL:              ts.URL,
		Authorization:        testApprovedAuth(),
		AllowStateChangingTests:   true,
		SyntheticFixture:     true,
		
		Workflows: []Workflow{
			{
				ID:   "coupon-no-counter",
				Name: "Coupon Without Read-back",
				Steps: []Step{
					{
						ID:          "redeem",
						Name:        "Redeem Step",
						Endpoint:    "/coupon/redeem",
						Method:      "POST",
						IsSingleUse: true,
					},
				},
				CategoriesToAssess: []Category{CategoryReplayIdempotency},
			},
		},
		Identities: DefaultIdentities(),
	}

	results, _, err := engine.Assess(context.Background(), actx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if results[0].VerificationState != StateCandidate {
		t.Errorf("expected CANDIDATE when counter proof is absent, got %s", results[0].VerificationState)
	}
}

// 13. Category D: WORKFLOW-TOKEN-REUSE properly enforced -> NOT_VULNERABLE
func TestWorkflow_TokenReuse_Enforced_NotVulnerable(t *testing.T) {
	tokenConsumed := false
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		token := r.Header.Get("X-Workflow-Token")
		if token == "" {
			// Step 1: Issue token
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, `{"token":"tok_valid_123"}`)
			return
		}
		if !tokenConsumed {
			// Step 2: First consumption
			tokenConsumed = true
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, `{"consumed":true}`)
			return
		}
		// Step 3: Reused token rejected!
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprint(w, `{"error":"token already consumed"}`)
	}))
	defer ts.Close()

	engine := NewEngine(nil, DefaultConfig())
	actx := &AssessmentContext{
		AssessmentID:         "asm-tok-01",
		ExecutionID:          "exec-01",
		BaseURL:              ts.URL,
		Authorization:        testApprovedAuth(),
		AllowStateChangingTests:   true,
		SyntheticFixture:     true,
		
		Workflows: []Workflow{
			{
				ID:   "token-flow",
				Name: "Token Continuity Flow",
				Steps: []Step{
					{
						ID:                "consume",
						Name:              "Consume Token",
						Endpoint:          "/token/action",
						Method:            "POST",
						ExtractTokenField: "token",
						InjectTokenHeader: "X-Workflow-Token",
					},
				},
				CategoriesToAssess: []Category{CategoryTokenContinuity},
			},
		},
		Identities: DefaultIdentities(),
	}

	results, summary, err := engine.Assess(context.Background(), actx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if results[0].VerificationState != StateNotVulnerable {
		t.Errorf("expected NOT_VULNERABLE, got %s (evidence: %s)", results[0].VerificationState, results[0].EvidenceSummary)
	}
	if summary.NotVulnerableCount != 1 {
		t.Errorf("expected 1 not vulnerable in summary, got %d", summary.NotVulnerableCount)
	}
}

// 14. Category D: WORKFLOW-TOKEN-REUSE circumvented and verified -> VERIFIED
func TestWorkflow_TokenReuse_Circumvented_Verified(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/token/action":
			// Server accepts reuse!
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, `{"token":"tok_fixed_123","status":"accepted"}`)
		case "/token/verify":
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, `{"valid":true}`)
		}
	}))
	defer ts.Close()

	engine := NewEngine(nil, DefaultConfig())
	actx := &AssessmentContext{
		AssessmentID:         "asm-tok-02",
		ExecutionID:          "exec-02",
		BaseURL:              ts.URL,
		Authorization:        testApprovedAuth(),
		AllowStateChangingTests:   true,
		SyntheticFixture:     true,
		
		Workflows: []Workflow{
			{
				ID:   "token-reuse-vuln",
				Name: "Token Reuse Vulnerable Flow",
				Steps: []Step{
					{
						ID:                   "consume",
						Name:                 "Consume Step",
						Endpoint:             "/token/action",
						Method:               "POST",
						ExtractTokenField:    "token",
						InjectTokenHeader:    "X-Workflow-Token",
						VerificationEndpoint: "/token/verify",
						VerificationProperty: "valid",
					},
				},
				CategoriesToAssess: []Category{CategoryTokenContinuity},
			},
		},
		Identities: DefaultIdentities(),
	}

	results, _, err := engine.Assess(context.Background(), actx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if results[0].VerificationState != StateVerified {
		t.Errorf("expected VERIFIED, got %s (evidence: %s)", results[0].VerificationState, results[0].EvidenceSummary)
	}
}

// 15. Category E: WORKFLOW-IDENTITY-MISMATCH properly enforced -> NOT_VULNERABLE
func TestWorkflow_IdentityContinuity_Enforced_NotVulnerable(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		authHdr := r.Header.Get("Authorization")
		if strings.Contains(authHdr, "token_attacker") {
			w.WriteHeader(http.StatusForbidden)
			fmt.Fprint(w, `{"error":"principal mismatch: not the workflow owner"}`)
			return
		}
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `{"status":"created","owner":"owner_user"}`)
	}))
	defer ts.Close()

	engine := NewEngine(nil, DefaultConfig())
	actx := &AssessmentContext{
		AssessmentID:         "asm-ident-01",
		ExecutionID:          "exec-01",
		BaseURL:              ts.URL,
		Authorization:        testApprovedAuth(),
		AllowStateChangingTests:   true,
		SyntheticFixture:     true,
		
		Workflows: []Workflow{
			{
				ID:        "transfer-flow",
				Name:      "Funds Transfer Flow",
				OwnerRole: "owner",
				Steps: []Step{
					{
						ID:                   "step1",
						Name:                 "Transfer Action",
						Endpoint:             "/transfer/finalize",
						Method:               "POST",
						VerificationEndpoint: "/transfer/status",
						VerificationProperty: "owner",
					},
				},
				CategoriesToAssess: []Category{CategoryIdentityContinuity},
			},
		},
		Identities: []TestIdentity{
			{Alias: "owner_user", Role: "owner", Headers: map[string]string{"Authorization": "Bearer token_owner"}},
			{Alias: "attacker_user", Role: "attacker", Headers: map[string]string{"Authorization": "Bearer token_attacker"}},
		},
	}

	results, summary, err := engine.Assess(context.Background(), actx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if results[0].VerificationState != StateNotVulnerable {
		t.Errorf("expected NOT_VULNERABLE, got %s (evidence: %s)", results[0].VerificationState, results[0].EvidenceSummary)
	}
	if summary.NotVulnerableCount != 1 {
		t.Errorf("expected 1 not vulnerable in summary, got %d", summary.NotVulnerableCount)
	}
}

// 16. Category E: WORKFLOW-IDENTITY-MISMATCH non-owner unauthorized access -> VERIFIED
func TestWorkflow_IdentityContinuity_Circumvented_Verified(t *testing.T) {
	transferredOwner := ""
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/transfer/finalize":
			authHdr := r.Header.Get("Authorization")
			if strings.Contains(authHdr, "token_attacker") {
				transferredOwner = "attacker" // Cross-principal takeover allowed!
			} else {
				transferredOwner = "owner"
			}
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, `{"status":"finalized"}`)
		case "/transfer/status":
			w.WriteHeader(http.StatusOK)
			fmt.Fprintf(w, `{"status":"finalized","transferred_to":"%s"}`, transferredOwner)
		}
	}))
	defer ts.Close()

	engine := NewEngine(nil, DefaultConfig())
	actx := &AssessmentContext{
		AssessmentID:         "asm-ident-02",
		ExecutionID:          "exec-02",
		BaseURL:              ts.URL,
		Authorization:        testApprovedAuth(),
		AllowStateChangingTests:   true,
		SyntheticFixture:     true,
		
		Workflows: []Workflow{
			{
				ID:        "transfer-bypass",
				Name:      "Funds Transfer Bypass",
				OwnerRole: "owner",
				Steps: []Step{
					{
						ID:                   "step1",
						Name:                 "Transfer Action",
						Endpoint:             "/transfer/finalize",
						Method:               "POST",
						VerificationEndpoint: "/transfer/status",
						VerificationProperty: "transferred_to",
					},
				},
				CategoriesToAssess: []Category{CategoryIdentityContinuity},
			},
		},
		Identities: []TestIdentity{
			{Alias: "owner_user", Role: "owner", Headers: map[string]string{"Authorization": "Bearer token_owner"}},
			{Alias: "attacker_user", Role: "attacker", Headers: map[string]string{"Authorization": "Bearer token_attacker"}},
		},
	}

	results, _, err := engine.Assess(context.Background(), actx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if results[0].VerificationState != StateVerified {
		t.Errorf("expected VERIFIED, got %s (evidence: %s)", results[0].VerificationState, results[0].EvidenceSummary)
	}
}

// 17. Category F: WORKFLOW-CONCURRENT-RACE properly enforced -> NOT_VULNERABLE
func TestWorkflow_ConcurrentRace_Enforced_NotVulnerable(t *testing.T) {
	var activeTransitions int32
	var completedCount int32
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/claim/reward":
			// Atomic guard: only 1 claim permitted
			if atomic.CompareAndSwapInt32(&activeTransitions, 0, 1) {
				atomic.AddInt32(&completedCount, 1)
				w.WriteHeader(http.StatusOK)
				fmt.Fprint(w, `{"claimed":true}`)
			} else {
				w.WriteHeader(http.StatusConflict)
				fmt.Fprint(w, `{"error":"reward already claimed"}`)
			}
		case "/claim/count":
			w.WriteHeader(http.StatusOK)
			fmt.Fprintf(w, `{"count":%d}`, atomic.LoadInt32(&completedCount))
		}
	}))
	defer ts.Close()

	engine := NewEngine(nil, DefaultConfig())
	actx := &AssessmentContext{
		AssessmentID:         "asm-race-01",
		ExecutionID:          "exec-01",
		BaseURL:              ts.URL,
		Authorization:        testApprovedAuth(),
		AllowStateChangingTests:   true,
		SyntheticFixture:     true,
		
		Workflows: []Workflow{
			{
				ID:   "race-atomic",
				Name: "Atomic Race Guarded Flow",
				Steps: []Step{
					{
						ID:                   "claim",
						Name:                 "Claim Reward",
						Endpoint:             "/claim/reward",
						Method:               "POST",
						IsSingleUse:          true,
						IsStateChanging:      true,
						VerificationEndpoint: "/claim/count",
						VerificationProperty: "count",
					},
				},
				CategoriesToAssess: []Category{CategoryConcurrentTransition},
			},
		},
		Identities: DefaultIdentities(),
	}

	results, summary, err := engine.Assess(context.Background(), actx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if results[0].VerificationState != StateNotVulnerable {
		t.Errorf("expected NOT_VULNERABLE, got %s (evidence: %s)", results[0].VerificationState, results[0].EvidenceSummary)
	}
	if summary.NotVulnerableCount != 1 {
		t.Errorf("expected 1 not vulnerable in summary, got %d", summary.NotVulnerableCount)
	}
}

// 18. Category F: WORKFLOW-CONCURRENT-RACE race condition duplicate execution -> VERIFIED
func TestWorkflow_ConcurrentRace_DuplicateExecution_Verified(t *testing.T) {
	var count int32
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/claim/reward":
			time.Sleep(10 * time.Millisecond) // Simulate non-atomic window
			atomic.AddInt32(&count, 1)
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, `{"claimed":true}`)
		case "/claim/count":
			w.WriteHeader(http.StatusOK)
			fmt.Fprintf(w, `{"count":%d}`, atomic.LoadInt32(&count))
		}
	}))
	defer ts.Close()

	engine := NewEngine(nil, DefaultConfig())
	actx := &AssessmentContext{
		AssessmentID:         "asm-race-02",
		ExecutionID:          "exec-02",
		BaseURL:              ts.URL,
		Authorization:        testApprovedAuth(),
		AllowStateChangingTests:   true,
		SyntheticFixture:     true,
		
		Workflows: []Workflow{
			{
				ID:   "race-flaw",
				Name: "Flawed Non-atomic Workflow",
				Steps: []Step{
					{
						ID:                   "claim",
						Name:                 "Claim Step",
						Endpoint:             "/claim/reward",
						Method:               "POST",
						IsSingleUse:          true,
						IsStateChanging:      true,
						VerificationEndpoint: "/claim/count",
						VerificationProperty: "count",
					},
				},
				CategoriesToAssess: []Category{CategoryConcurrentTransition},
			},
		},
		Identities: DefaultIdentities(),
	}

	results, _, err := engine.Assess(context.Background(), actx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if results[0].VerificationState != StateVerified {
		t.Errorf("expected VERIFIED, got %s (evidence: %s)", results[0].VerificationState, results[0].EvidenceSummary)
	}
}

// 19. Mutation Safety: Blocked by default (0 network requests dispatched, SKIPPED)
func TestWorkflow_MutationSafety_BlockedByDefault(t *testing.T) {
	var requestDispatched int32
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&requestDispatched, 1)
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	engine := NewEngine(nil, DefaultConfig())
	actx := &AssessmentContext{
		AssessmentID:       "asm-safe-01",
		ExecutionID:        "exec-01",
		BaseURL:            ts.URL,
		Authorization:      testApprovedAuth(),
		AllowStateChangingTests: false, // DEFAULT: false
		SyntheticFixture:   false, // DEFAULT: false
		Workflows: []Workflow{
			{
				ID:   "mutating-flow",
				Name: "Mutating Flow",
				Steps: []Step{
					{ID: "step1", Endpoint: "/mutate", Method: "POST", IsStateChanging: true},
				},
				CategoriesToAssess: []Category{CategoryReplayIdempotency},
			},
		},
		Identities: DefaultIdentities(),
	}

	results, summary, err := engine.Assess(context.Background(), actx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if atomic.LoadInt32(&requestDispatched) != 0 {
		t.Fatalf("expected 0 requests dispatched when mutation disabled, got %d", requestDispatched)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if results[0].VerificationState != StateSkipped {
		t.Errorf("expected SKIPPED state, got %s", results[0].VerificationState)
	}
	if summary.BlockedCount != 1 {
		t.Errorf("expected 1 blocked count, got %d", summary.BlockedCount)
	}
}

// 20. Mutation Safety: Blocked without synthetic fixture
func TestWorkflow_MutationSafety_BlockedWithoutSyntheticFixture(t *testing.T) {
	var requestDispatched int32
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&requestDispatched, 1)
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	engine := NewEngine(nil, DefaultConfig())
	actx := &AssessmentContext{
		AssessmentID:       "asm-safe-02",
		ExecutionID:        "exec-02",
		BaseURL:            ts.URL,
		Authorization:      testApprovedAuth(),
		AllowStateChangingTests: true,
		SyntheticFixture:   false, // Missing synthetic fixture!
		Workflows: []Workflow{
			{
				ID:   "mutating-flow",
				Name: "Mutating Flow",
				Steps: []Step{
					{ID: "step1", Endpoint: "/mutate", Method: "POST", IsStateChanging: true},
				},
				CategoriesToAssess: []Category{CategoryConcurrentTransition},
			},
		},
		Identities: DefaultIdentities(),
	}

	results, _, err := engine.Assess(context.Background(), actx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if atomic.LoadInt32(&requestDispatched) != 0 {
		t.Fatalf("expected 0 requests dispatched without synthetic fixture, got %d", requestDispatched)
	}
	if len(results) != 1 || results[0].VerificationState != StateSkipped {
		t.Errorf("expected SKIPPED when synthetic fixture missing")
	}
}

// 21. Mutation Safety: Blocked on arbitrary production target even if both flags are true
func TestWorkflow_MutationSafety_BlockedOnProductionTarget(t *testing.T) {
	engine := NewEngine(nil, DefaultConfig())
	actx := &AssessmentContext{
		AssessmentID:         "asm-safe-03",
		ExecutionID:          "exec-03",
		BaseURL:              "https://api.production-enterprise.com",
		Authorization:        testApprovedAuth(),
		AllowStateChangingTests:   true,
		SyntheticFixture:     true,
		 // Not an isolated fixture target!
		Workflows: []Workflow{
			{
				ID:   "mutating-flow",
				Name: "Mutating Flow",
				Steps: []Step{
					{ID: "step1", Endpoint: "/purge", Method: "POST", IsStateChanging: true},
				},
				CategoriesToAssess: []Category{CategoryReplayIdempotency},
			},
		},
		Identities: DefaultIdentities(),
	}

	results, _, err := engine.Assess(context.Background(), actx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(results) != 1 || results[0].VerificationState != StateSkipped {
		t.Fatalf("expected SKIPPED for non-isolated target, got %s", results[0].VerificationState)
	}
	if !strings.Contains(results[0].EvidenceSummary, "synthetic fixture") {
		t.Errorf("expected fixture boundary warning in evidence summary, got: %s", results[0].EvidenceSummary)
	}
}

// 22. Zero automatic retries on mutation failure
func TestWorkflow_MutationSafety_ZeroAutomaticRetries(t *testing.T) {
	var requestCount int32
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&requestCount, 1)
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprint(w, `{"error":"internal database timeout"}`)
	}))
	defer ts.Close()

	engine := NewEngine(nil, DefaultConfig())
	actx := &AssessmentContext{
		AssessmentID:         "asm-retry-01",
		ExecutionID:          "exec-01",
		BaseURL:              ts.URL,
		Authorization:        testApprovedAuth(),
		AllowStateChangingTests:   true,
		SyntheticFixture:     true,
		
		Workflows: []Workflow{
			{
				ID:   "single-attempt-flow",
				Name: "Single Attempt Flow",
				Steps: []Step{
					{ID: "step1", Endpoint: "/action", Method: "POST", IsStateChanging: true},
				},
				CategoriesToAssess: []Category{CategoryReplayIdempotency},
			},
		},
		Identities: DefaultIdentities(),
	}

	results, _, err := engine.Assess(context.Background(), actx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Initial baseline request failed (500), so replay step was never retried or attempted
	if count := atomic.LoadInt32(&requestCount); count > 1 {
		t.Fatalf("expected at most 1 request on failure (zero retries), got %d", count)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
}

// 23. Scope exclusion blocks dispatch
func TestWorkflow_Scope_Excluded(t *testing.T) {
	var requestDispatched int32
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&requestDispatched, 1)
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	engine := NewEngine(nil, DefaultConfig())
	actx := &AssessmentContext{
		AssessmentID:  "asm-scope-01",
		ExecutionID:   "exec-01",
		BaseURL:       ts.URL,
		Authorization: testApprovedAuth(),
		IsExcluded: func(target string) bool {
			return strings.Contains(target, "/admin")
		},
		Workflows: []Workflow{
			{
				ID:   "admin-wf",
				Name: "Admin Workflow",
				Steps: []Step{
					{ID: "s0", Endpoint: "/login", Method: "POST"},
					{ID: "admin-step", Endpoint: "/admin/config", Method: "GET", Preconditions: []string{"s0"}},
				},
				CategoriesToAssess: []Category{CategoryPrerequisiteSkipping},
			},
		},
		Identities: DefaultIdentities(),
	}

	results, _, err := engine.Assess(context.Background(), actx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if atomic.LoadInt32(&requestDispatched) != 0 {
		t.Fatalf("expected 0 requests dispatched when excluded by scope, got %d", requestDispatched)
	}
	if len(results) != 1 || results[0].VerificationState != StateSkipped {
		t.Errorf("expected SKIPPED when excluded by scope rules")
	}
}

// 24. Request budget enforcement
func TestWorkflow_RequestBudget_Enforced(t *testing.T) {
	var count int32
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&count, 1)
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `{"status":"ok"}`)
	}))
	defer ts.Close()

	engine := NewEngine(nil, DefaultConfig())
	var budgetCounter int32
	actx := &AssessmentContext{
		AssessmentID:       "asm-budget-01",
		ExecutionID:        "exec-01",
		BaseURL:            ts.URL,
		Authorization:      testApprovedAuth(),
		MaxRequests:        2,
		DispatchedRequests: &budgetCounter,
		Workflows: []Workflow{
			{
				ID:   "wf-multi",
				Name: "Multi Step Flow",
				Steps: []Step{
					{ID: "s1", Endpoint: "/s1", Method: "GET"},
					{ID: "s2", Endpoint: "/s2", Method: "GET", Preconditions: []string{"s1"}},
					{ID: "s3", Endpoint: "/s3", Method: "GET", Preconditions: []string{"s2"}},
					{ID: "s4", Endpoint: "/s4", Method: "GET", Preconditions: []string{"s3"}},
				},
				CategoriesToAssess: []Category{CategoryPrerequisiteSkipping},
			},
		},
		Identities: DefaultIdentities(),
	}

	_, _, _ = engine.Assess(context.Background(), actx)
	if atomic.LoadInt32(&budgetCounter) > 2 {
		t.Fatalf("request budget was exceeded: dispatched %d, limit 2", budgetCounter)
	}
}

// 25. Cross-origin redirect credential stripping
func TestWorkflow_Redirect_CredentialStripping(t *testing.T) {
	var credentialLeaked int32
	otherServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "" || r.Header.Get("Cookie") != "" {
			atomic.StoreInt32(&credentialLeaked, 1)
		}
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `{"status":"redirected"}`)
	}))
	defer otherServer.Close()

	mainServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, otherServer.URL+"/landing", http.StatusFound)
	}))
	defer mainServer.Close()

	engine := NewEngine(nil, DefaultConfig())
	actx := &AssessmentContext{
		AssessmentID:         "asm-redir-01",
		ExecutionID:          "exec-01",
		BaseURL:              mainServer.URL,
		Authorization:        testApprovedAuth(),
		AllowStateChangingTests:   true,
		SyntheticFixture:     true,
		
		Workflows: []Workflow{
			{
				ID:   "redirect-wf",
				Name: "Redirect Workflow",
				Steps: []Step{
					{ID: "step1", Endpoint: "/login-redir", Method: "POST"},
				},
				CategoriesToAssess: []Category{CategoryReplayIdempotency},
			},
		},
		Identities: []TestIdentity{
			{
				Alias:   "user1",
				Role:    "user",
				Headers: map[string]string{"Authorization": "Bearer secret_user_token"},
				Cookies: map[string]string{"session_id": "secret_sess"},
			},
		},
	}

	_, _, err := engine.Assess(context.Background(), actx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if atomic.LoadInt32(&credentialLeaked) == 1 {
		t.Fatalf("security violation: sensitive credentials leaked across origin redirect")
	}
}

// 26. Dry-run planning mode: 0 network requests dispatched
func TestWorkflow_Plan_DryRunZeroRequests(t *testing.T) {
	var requestDispatched int32
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&requestDispatched, 1)
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	engine := NewEngine(nil, DefaultConfig())
	actx := &AssessmentContext{
		AssessmentID:  "asm-plan-01",
		ExecutionID:   "exec-01",
		BaseURL:       ts.URL,
		Authorization: testApprovedAuth(),
		Workflows:     DefaultWorkflows(),
		Identities:    DefaultIdentities(),
	}

	plan, err := engine.Plan(context.Background(), actx)
	if err != nil {
		t.Fatalf("unexpected error during planning: %v", err)
	}
	if atomic.LoadInt32(&requestDispatched) != 0 {
		t.Fatalf("expected 0 requests in dry-run plan mode, got %d", requestDispatched)
	}
	if plan.TotalPlannedChecks == 0 {
		t.Fatalf("expected non-zero planned checks, got 0")
	}
	if plan.TotalWorkflows != len(DefaultWorkflows()) {
		t.Errorf("expected %d workflows planned, got %d", len(DefaultWorkflows()), plan.TotalWorkflows)
	}
}
